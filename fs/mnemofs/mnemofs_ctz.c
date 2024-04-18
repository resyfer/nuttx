/****************************************************************************
 * fs/mnemofs/mnemofs_ctz.c
 * This contains the logic behind file (and directory file) handling.
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

#include <assert.h>
#include <fcntl.h>
#include <nuttx/kmalloc.h>
#include <sys/stat.h>

#include "mnemofs.h"

/* TODO: Should point and read use the blkoffset?? */

/****************************************************************************
 *
 * Files in mnemofs are arranged similar to reversed linked lists. This helps
 * in combating the Copy-On-Write problem in a straightforward linked list,
 * where any new node at end of the linked list (file append), would mean the
 * original last element would have to be updated to point to the new node,
 * which would mean in CoW, there will be a copy of it, and the original
 * second last element would have to be updated to point to this copy instead
 * and this goes on till it reached the head.
 *
 * This would increase the file read times to O(n^2). Inspired from littlefs,
 * CTZ lists are used instead to reduce this to O(nlog2(n)). This would also
 * imply that block `n` ends with `log2(n)` pointers. As shown by the
 * littlefs's arguments, this is pretty small compared to real life page
 * page sizes, which ties in neatly with every CTZ block being a page in
 * the flash.
 *
 *                                                        File Ptr
 *                                                            |
 *                                                            V
 * +------+   +------+   +------+   +------+   +------+   +------+
 * |      |<--|      |---|      |---|      |---|      |   |      |
 * | Node |<--| Node |---| Node |<--| Node |---| Node |   | Node |
 * |  0   |<--|  1   |<--|  2   |<--|  3   |<--|  4   |<--|  5   |
 * +------+   +------+   +------+   +------+   +------+   +------+
 *
 ****************************************************************************/

#define MFS_CTZ_PTRSZ   (sizeof(mfs_t))
#define MFS_CTZ_NPTROFF(sb, idx) (MFS_PGSZ(sb) - ((MFS_CTZ_PTRSZ) * ((idx) + 1))) /* Get start point of `idx`th CTZ ptr.*/


/* mfs_ctz_nptrl: Count of pointers from the index to left, including it.*/
/* Counts left from current index. Can change the index using ctz_point. */
mfs_t mfs_ctz_nptrl(FAR struct mfs_ctz_s * const l) {
  mfs_t c = 0;
  mfs_t idx;

  idx = l->idx_c;
  while(idx >= 0) {
    c += idx;
  }
  return c;
}

/* Gives the number of pointers in current index. */
/* Counts left from current index. Can change the index using ctz_point. */
mfs_t mfs_ctz_nptrc(FAR struct mfs_ctz_s * const l) {
  mfs_t ret = 0;
  ret = mnemofs_ctz(l->idx_c) + 1;
  return ret;
}


/* ctz_init: Initialize a CTZ Skip list. This needs to be done for any use
of ctz list outside of this file. */
/* The last_pg and last_idx is received from the directory entry of this
file. */
/* The list always points to the last CTZ block at the start. */
/* Don't want to put the code in header file, so no inline here. Trust is
on the compiler to optimize it enough. */
/* TODO: sz. We get this from the directory ancestor. */
void mfs_ctz_init(const mfs_t last_pg, const mfs_t last_idx, mfs_t sz,
                  FAR struct mfs_ctz_s * const l)
{
  *l = (struct mfs_ctz_s) {
    .idx_c = last_idx,
    .idx_e = last_idx,
    .pg_c = last_pg,
    .pg_e = last_pg,
    .sz = sz,
  };

  nxmutex_init(&l->l_lock);
}

void mfs_ctz_destroy(FAR struct mfs_ctz_s *l) {
  nxmutex_destroy(&l->l_lock);
}

/* mfs_point is the father of mfs_next and mfs_prev. */
/* Follows the principle that less generalize functions call the more
generalized functions. */
int mfs_ctz_point(FAR const struct mfs_sb_info * const sb,
                  FAR struct mfs_ctz_s * const l, mfs_t idx)
{
  int ret = OK;
  mfs_t tmp;
  mfs_t tmp2;
  struct mfs_ctz_s tmp_l = *l;


  if(predict_false(idx > l->idx_e)) {
    ret = -EINVAL;
    goto errout;
  }

  if(predict_false(idx == l->idx_c)) {
    goto errout;
  }

  if(predict_false(idx == l->idx_c - 1)) {

    /* Last pointer points to previous.*/

    mnemofs_read_mfs_t(&tmp, l->pg_c, MFS_CTZ_NPTROFF(sb, 0));
    l->pg_c = tmp;
    l->idx_c--;
  }

  /*
    Traversal from one point to another in CTZ list efficiently follows a
    greedy pattern.

    From the start, the goal is to reach that node with the highest count of
    trailing zeroes (ctz) in its index which falls between the source and
    target. This is the rising phase.

    From there, we start taking the longest stride we can take that doesn't
    overshoot the target, till we reach the target. This is the falling phase.

    An interesting thing to note is that due to the greedy nature, the srides
    follow a strict monotonic decrease during falling phase, and thus,
    not all possible stride lengths need to be examined.

    Further, in the rising phase, since it's a greedy algorithm, to reach the
    node with highest ctz in between source and target, at every step we keep
    finding the highest ctz we can go to. This goes on till we do not
    overshoot the target. We want to find the node that satifies the
    condition of being BETWEEN the source and target. eg. Suppose an index
    with binary 10110100 (180) wants to reach 0. At max it can reach
    10110000 (176) by subtracting 100 (4) in a single step. Similarly from
    here it can go to 10100000 (160), by subtracting 10000 (16), and then to
    10000000 (128) by removing 100000 (32), and then to 00000000 (0) by
    removing 10000000 (0).
  */

  /* It's faster to start traversal again from last to reach the desired
  location instead of calculations that derive the common ancestor, etc. */

  tmp_l.idx_c = tmp_l.idx_e;
  tmp_l.pg_c = tmp_l.pg_e;

  /* Rising Phse */

  tmp = 0;
  while(tmp_l.idx_c != 0 && (tmp2 = tmp_l.idx_c - (1 << tmp)) > idx) {

    DEBUGASSERT(tmp_l.idx_c >= idx);

    /* No wrap around of value. */

    mnemofs_read_mfs_t(&tmp_l.pg_c, tmp_l.pg_c, MFS_CTZ_NPTROFF(sb, tmp));
    tmp_l.idx_c = tmp2;

    /* Next iteration */

    tmp = mnemofs_ctz(tmp_l.idx_c);
  }

  DEBUGASSERT(tmp_l.idx_c != 0 || (tmp_l.idx_c == 0 && idx == 0));

  /* Falling Phase */

  while(tmp_l.idx_c != idx) {

    DEBUGASSERT(tmp_l.idx_c >= idx);

    /* No wrap around of value. */

    while(tmp_l.idx_c != 0 && (tmp_l.idx_c - (1 << tmp)) < idx) {
      tmp--; /* Strict monotonic decrease */
    }

    mnemofs_read_mfs_t(&tmp_l.pg_c, tmp_l.pg_c, MFS_CTZ_NPTROFF(sb, tmp));
    tmp_l.idx_c = tmp_l.idx_c - (1 << tmp);
  }
errout:
  return ret;
}

int mfs_ctz_prev(FAR const struct mfs_sb_info * const sb,
                  FAR struct mfs_ctz_s * const l)
{
  return mfs_ctz_point(sb, l, l->idx_c - 1);
}

int mfs_ctz_next(FAR const struct mfs_sb_info * const sb,
                  FAR struct mfs_ctz_s * const l)
{
  return mfs_ctz_point(sb, l, l->idx_c + 1);
}

/*
  Size of data (not considering any metadata offsets, only pointers)
  = Sigma{i = 0..n}(pg - ptr(ctz(i) + 1))
  = (pg - ptr) * n - Sigma{i = 0..n}(ctz(n) + 1)

  As pointed by OEISF and littlefs, this becomes:
  = (pg - ptr) * n - 2*n + popcount(n)

  where pg is the size of 1 page (CTZ Block) and ptr is size of a pointer
  (MFS_CTZ_PTRSZ).
*/
int mfs_ctz_offinfo(FAR const struct mfs_sb_info * const sb,
                    FAR struct mfs_ctz_s * const l, mfs_t off, mfs_t *idx,
                    mfs_off_t *blkoff)
{
  /* TODO: Get O(1) formula for this. */
  return 0;
}

int mfs_ctz_offpoint(FAR const struct mfs_sb_info * const sb,
                    FAR struct mfs_ctz_s * const l, mfs_t off,
                    mfs_off_t *blkoff)
{
  mfs_t idx;
  int ret = OK;

  ret = mfs_ctz_offinfo(sb, l, off, &idx, blkoff);
  if(predict_false(ret < 0)) {
    goto errout;
  }

  ret = mfs_ctz_point(sb, l, idx);
  if(ret < 0) {
    goto errout;
  }

errout:
  return ret;
}

/* Assumes buf is MFS_PGSZ in length atleast */
/* Copies the pointer info of an idx to the end of the buf. */
/* TODO: Think about counting references */
int mfs_ctz_cpyblkptrs(FAR const struct mfs_sb_info * const sb,
                      FAR struct mfs_ctz_s * const l, const mfs_t idx,
                      FAR char * const buf)
{
  int ret = OK;
  mfs_t nptr_sz;

  ret = mfs_ctz_point(sb, l, idx);
  if(predict_false(ret < 0)) {
    goto errout;
  }

  nptr_sz = MFS_CTZ_PTRSZ * mfs_ctz_nptrc(l);

  ret = mnemofs_read_page(buf + MFS_PGSZ(sb) - nptr_sz, nptr_sz, l->pg_c,
                          MFS_PGSZ(sb) - nptr_sz);
  if(ret < 0) {
    goto errout;
  }

errout:
  return ret;
}

/* Theoretical block size */
mfs_t mfs_ctz_blksz(FAR const struct mfs_sb_info * const sb, mfs_t idx)
{
  /* WARNING!!! This is an independent function and re-implements how to
  count the block size. Any changes to block size counting method needs to
  be updated here as well. */
  return MFS_PGSZ(sb) - (MFS_CTZ_PTRSZ * (mnemofs_ctz(idx) + 1));
}

/* Returns length read. */
mfs_t mfs_ctz_rd(FAR const struct mfs_sb_info * const sb,
               FAR const struct mfs_ctz_s * const l, const mfs_t off,
               FAR char * const buf, mfs_t len)
{

  mfs_off_t blkoff;
  struct mfs_ctz_s ctz_tmp = *l; /* This should not be a problem, we're just reading. */
  mfs_t tmp2;
  mfs_t ret = 0;
  FAR char * buf_tmp = buf;

  memset(buf, 0, len); /* This will take care of "holes" for len > l->size */

  if(predict_false(off >= l->sz)) {
    goto errout;
  }

  if(predict_false(off + len >= l->sz)) {
    len = l->sz;
  }

  mfs_ctz_offpoint(sb, &ctz_tmp, off, &blkoff);

  /* TODO: Later, make this read backwards. This will be much faster than
  trying to find the index again and again. */

  while(len >= 0) {
    tmp2 = mfs_ctz_blksz(sb, l->idx_c);
    if(predict_false(blkoff != 0)) {
      tmp2 -= blkoff;
    }

    ret = mnemofs_read_page(buf_tmp, MFS_MIN(tmp2, len), l->pg_c, blkoff);
    if(ret < 0) {
      goto errout;
    }
    buf_tmp += ret;
    mfs_ctz_next(sb, &ctz_tmp);

    if(predict_false(blkoff != 0)) {
      blkoff = 0;
    }
  }

errout:
  return buf_tmp - buf;
}

/* Replaces `ilen` bytes of file from `off` offset and puts `flen` bytes. */
/* Updates file size */
/* Also handles holes. Just insert null values. No optimization. */
/* Handle the case where off > l->sz as well as off + len > l->sz */
/* DOES NOT AND SHOULD NOT UPDATE l EVEN FOR OPTIMIZATION */
mfs_t mfs_ctz_upd(FAR const struct mfs_sb_info * const sb,
                  FAR const struct mfs_ctz_s * l, const mfs_t off,
                  const mfs_t ilen, const mfs_t flen,
                  FAR const char * const buf)
{
  /* TODO */
  return 0;
}

/* Returns Final length of the file */
/* Unlike POSIX truncate, this actually just shortens the file
at the desired location. Uses ctz_upd internally. */
mfs_t mfs_ctz_trunc(FAR const struct mfs_sb_info * const sb,
                    FAR const struct mfs_ctz_s * l, const mfs_t len)
{
  if(len > MFS_CTZ_SZ(l)) {
    return MFS_CTZ_SZ(l);
  }

  return mfs_ctz_upd(sb, l, len, MFS_CTZ_SZ(l) - len, 0, NULL);
}

/* DOES NOT AND SHOULD NOT UPDATE l EVEN FOR OPTIMIZATION */
mfs_t mfs_ctz_wr(FAR const struct mfs_sb_info * const sb,
                FAR const struct mfs_ctz_s * l, const mfs_t off,
                FAR const char * const buf, const mfs_t len)
{
  return mfs_ctz_upd(sb, l, off, len, len, buf);
}