/****************************************************************************
 * fs/mnemofs/mnemofs_file.c
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

/* TODO: How to represent empty files. */

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <assert.h>
#include <fcntl.h>
#include <nuttx/kmalloc.h>
#include <sys/stat.h>

#include "mnemofs.h"

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
 * An extra modification to this design is made that the last node (CTZ
 * block) will contain, in its *first two bytes* (first 16 bits), the actual
 * amount of data written in that last CTZ block in bytes. This would mean
 * the number of bytes in a block has to be in range [0, 65535], which would
 * mean a page size of 524280 bits, or around 64 kiB, which is unlikely for
 * a NAND flash in the foreseeable future.
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

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/
#define ROUND_UP_8(x)     ((x + 7) & ~7) /* https://stackoverflow.com/a/1766566/14369307 */
#define CTZ_PTR_SIZE(sb)  ROUND_UP_8(sb->pg_sz)
#define LAST_BLK_OFF_SZ(sb)  2 /* The offset at which last block of CTZ starts, to store metadata. */
#define FIRST_BLK_OFF_SZ(sb)  0 /* The offset at which first block of CTZ starts, to store metadata. */
/* TODO: Creation time needs to be put here. So find out how much space timestamp takes.
Similarly modification time needs to be put at the end as well.*/

#define LAST_BLK_SIZE_OFF 0

/****************************************************************************
 * Private Types
 ****************************************************************************/

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

static mfs_t ctz_nptr(FAR const struct mnemofs_ctz_s * const l);
static void ctz_off2blk(FAR const struct mnemofs_sb_info *sb, mfs_off_t off,
                        struct mnemofs_ctz_s *l, mfs_off_t *l_off);
static mfs_t ctz_blk2pg(struct mnemofs_sb_info *sb,
                        const struct mnemofs_ctz_s * const l, const mfs_t idx);
static ssize_t ctz_blk_rd(struct mnemofs_sb_info *sb,
                          const struct mnemofs_ctz_s * const l, char *buf,
                          const mfs_t idx, ssize_t off);
static void ctz_blk_frd(struct mnemofs_sb_info *sb,
                        const struct mnemofs_ctz_s * const l, const mfs_t idx,
                        char *buf);
static int ctz_append_data(struct mnemofs_sb_info *sb, struct mnemofs_ctz_s * const l,
                            const char *buf, ssize_t len);
static uint16_t ctz_blksz(struct mnemofs_sb_info *sb,
                          const struct mnemofs_ctz_s * const l, const mfs_t idx);
static inline uint16_t ctz_lastblksz(const struct mnemofs_ctz_s * const l);

static int file_append(struct mnemofs_sb_info *sb, struct mnemofs_file *f, const char *buf, ssize_t len);
static int search_open_files(struct mnemofs_sb_info *sb, FAR const char *relpath);
static ssize_t file_size(struct mnemofs_sb_info *sb,
                          const struct mnemofs_ctz_s * const l);

/****************************************************************************
 * Name: ctz_nptrs
 *
 * Description:
 *   This gives a count of the number of pointers in total among the blocks
 *   in the CTZ skip list, which starts at `blk_idx`. This includes the
 *   last CTZ block.
 *
 *   This calculates it on the fact that every CTZ block has a pointer for
 *   every x such that 2^x divides it (and the pointer points to n - 2^x
 *   block). This count can be found just from the block number (block index)
 *   in the following manner:
 *
 *   Suppose the current block is 5, which is 101 in binary. This means that
 *   till this block (including it), there are 101 (5) blocks that are
 *   diviside by 2^0. Right shift shows that till this block there are 10 (2)
 *   blocks that are divisible by 2^1, so on. So the number of pointer till
 *   this block is 5 + 2 + 1 = 8 pointers.
 *
 * Input Parameters:
 *   blk_idx - Index of the CTZ block in the CTZ skip list (0-indexing).
 *
 * Returned Value:
 *   A 32-bit value containing the total number of CTZ pointers that would be
 *   there in the block itself and the blocks on the left (lower index) of
 *   the block.
 *
 ****************************************************************************/

static mfs_t ctz_nptr(FAR const struct mnemofs_ctz_s * const l)
{
  mfs_t c;
  mfs_t idx = l->idx;

  c = 0;
  while(idx)
  {
    c += idx;
    idx >>= 1;
  }
  return c;
}

/****************************************************************************
 * Name: ctz_off2blk
 *
 * Description:
 *   Converts a CTZ skip list represented file's offset into it's CTZ block
 *   number/index (0-indexing) and the offset in that CTZ block.
 *
 *   These offsets can then be used directly with a low level read/write
 *   function into the NAND flash to retrieve the data.
 *
 *   The formula comes by solving this mathematical equation:
 *
 *        ( x                                        )
 *        ( __                                       )
 *    y = ( \                                        ) + c
 *        ( /   (pg_sz) - (ptr_sz) * (log2(k) + 1)   )
 *        ( --                                       )
 *        ( k = 0                                    )
 *
 *    where c < (pg_sz - (ptr_sz) * (log2(x) + 1)).
 *
 *    such that x is the index (0-indexing) of the block that contains the
 *    offset (y) we're looking for. This also assumes log2(0) = -1.
 *
 *    y = (pg_sz - ptr_sz) * x + 2 * (ptr_sz) - (log2(x) + log2(x + 1)) + c
 *    under the given assumption.
 *
 *    Thus we need to find x such that y (offset) behaves like
 *    f(x) < y <= f(x + 1). This x is the index of the block we're looking
 *    for.
 *
 * Input Parameters:
 *   sb            - Superblock representation in-memory.
 *   off           - Offset of the file in bytes.
 *   ctz_start_idx - Index of the last (start) CTZ block in this list.
 *   ctz_blk       - Function-filled return value of the CTZ Block index.
 *   ctz_blk_off   - Function-filled return value of the offset in CTZ Block.
 *
 * Returned Value:
 *   Return parameters `ctz_blk` and `ctz_blk_off` are used.
 *
 * Assumptions/Limitations:
 *   - Assumes a positive offset.
 *   - Assumes a valid offset.
 *   - Assumes 32 bit (4 byte) pointers for CTZ blocks.
 *   - Assumes pointers in CTZ blocks are at the very end.
 *   - The CTZ list is as compact as it can be. Only has an offset at the
 *     start of first block, and at the start of last block, and everything
 *     else is data and pointers. The last block may have some space between
 *     data and pointers.
 *
 ****************************************************************************/

static void ctz_off2blk(FAR const struct mnemofs_sb_info *sb, mfs_off_t off,
                        struct mnemofs_ctz_s *l, mfs_off_t *l_off)
{
  mfs_t blk_tsz = 0; /* Total size of the blocks before the block x (0-indexing for x) */
  mfs_t tmp;
  uint8_t next_log = 0;
  uint8_t cur_log = 0;
  uint16_t x = 0;

  off += FIRST_BLK_OFF_SZ(sb); /* Take into consideration the start offset. */

  /* Block 0 has no pointers. */
  if(off < sb->pg_sz) {
    goto end;
  }

  /* For preventing repetiitve calculation*/
  cur_log = -1; /* mnemofs_log2(0) = -1 */
  next_log = 0; /* mnemofs_log2(1) = 0 */

  while(1) {
    x++;
    cur_log = next_log;
    next_log = mnemofs_log2(x + 1);
    tmp = ((sb->pg_sz - CTZ_PTR_SIZE(sb)) * x)
          + (CTZ_PTR_SIZE(sb) * 2)
          - (cur_log + next_log);
    if(tmp > off) {
      goto end;
      break;
    }
    blk_tsz = tmp;
  }

end:
  l->idx = x;
  *l_off = off - blk_tsz;

  /* If we're on the last CTZ block, then add the last block offset to
  calculate offset. Given the assumption that it is a valid offset, this
  operation would not need to check if this goes outside of the data area
  of the block, or even into a non-existent next block. */
  /* TODO: Check if this function should not assume valid offset. */
  if(l->idx == l->last_idx) {
    *l_off += LAST_BLK_OFF_SZ(sb);
  }
}

/****************************************************************************
 * Name: ctz_blk2pg
 *
 * Description:
 *   This finds the page number of a CTZ block given it's index, and the list
 *   it belongs to.
 *
 *   The search is divided into two phases: rising and falling, and is a
 *   greedy search.
 *
 *   The rising part consists of finding the index between the start and
 *   target that has the most number of trailing zeroes. If we are on `n`th
 *   block, then the block connected to `n`th block with highest trailing
 *   zeroes has the index (n - (1 << ctz(n))) and this becomes the new `n`.
 *   We stop when the index would become lower than the target if this
 *   operation was carried out again. Thus, we enter the falling phase.
 *   We save the last value of (1 << ctz(n)) as, say, `d`. `d` here is a
 *   multiple of 2.
 *
 *   The falling phase is where we check greedily if we can get as close to
 *   the target as possible, while satifying current >= target condition.
 *   We want to get the largest value of 2^x for which (n - 2^x) satisfies
 *   the condition. We'll call this 2^x as `k`. The value of `k` goes from
 *   `d` to 0, finding the suitable (n - k) block index. If found, this
 *   (n - k) becomes the new `n`. Due to the greedy nature of this algorithm,
 *   the value of `k` will be monotically decreasing stritcly.
 *
 * Input Parameters:
 *   sb           - Superblock representation in-memory.
 *   start_pg     - The last page (start page) of CTZ block.
 *   start_idx    - The last index (start index) of CTZ block.
 *   blk_idx      - Index of the desired block.
 *
 * Returned Value:
 *   Page number of the desired CTZ block.
 *
 * Assumptions/Limitations:
 *   - The greedy hypothesis is correct.
 *   - 32 bit (4 byte) CTZ block pointers.
 *
 ****************************************************************************/

static mfs_t ctz_blk2pg(struct mnemofs_sb_info *sb,
                        const struct mnemofs_ctz_s * const l, const mfs_t idx)
{

  mfs_t diff = 1;
  mfs_t cur_idx = l->last_idx;
  mfs_t cur_pg = l->last_pg;
  mfs_t tmp; /* Just a temporary variable used for various purposes. */
  uint8_t rising = 1;

  DEBUGASSERT(l->idx >= 0);
  DEBUGASSERT(l->idx <= l->last_idx);

  if(predict_false(l->idx == l->last_idx)) {
    goto end;
  }

  /* while(cur_idx != l->idx) : Doing the below just to be sure.*/
  while(cur_idx > l->idx) {
    if(rising) {
      /* Rising */

      tmp = mnemofs_ctz(cur_idx);
      diff = 1 << tmp;
      if(predict_false(cur_idx - diff == l->idx)) {

        tmp = sb->pg_sz - (CTZ_PTR_SIZE(sb) * (tmp + 1));
        mnemofs_read_page((char *)&cur_pg, CTZ_PTR_SIZE(sb), cur_pg, tmp);
        /* cur_idx = l->idx; */
        goto end;

      } else if (predict_true(cur_idx - diff < l->idx)) {
        DEBUGASSERT(cur_idx > l->idx);

        tmp = sb->pg_sz - (CTZ_PTR_SIZE(sb) * (tmp + 1));
        mnemofs_read_page((char *)&cur_pg, CTZ_PTR_SIZE(sb), cur_pg, tmp);
        cur_idx -= diff;
        continue;
      } else {
        rising = 0; /* Now we're on the falling edge of curve. */
        continue;
      }

    } else {
      /* Falling */

      /* Initial cur_idx - diff will always be < l->idx, which is why we're
      at the falling phase. */
      DEBUGASSERT(cur_idx - diff < l->idx);

      while(predict_true(diff && cur_idx - (diff >> 1) > l->idx)) {
        diff >>= 1;
      }

      tmp = sb->pg_sz - (CTZ_PTR_SIZE(sb) * (mnemofs_log2(diff) + 1));
      mnemofs_read_page((char *)&cur_pg, CTZ_PTR_SIZE(sb), cur_pg, tmp);
      cur_idx -= diff;
    }
  }

end:
  return cur_pg;
}

/****************************************************************************
 * Name: ctz_blk_rd
 *
 * Description:
 *   Reads the on-flash data corresponding to the CTZ block with given
 *   block index belonging to the provided CTZ skip list. This will read
 *   in the data stored in the block starting from offset `off` to the end.
 *   This does not include metadata related to the CTZ skip list, nor the
 *   spare area some NAND flashes have.
 *
 * Input Parameters:
 *   sb          - Superblock representation in-memory.
 *   start_pg    - The page number belonging to the last CTZ block (which
 *                 represents the start of the list in a reverse way).
 *   start_idx   - The index of the last CTZ block.
 *   blk_idx     - The index of the required CTZ block.
 *   off         - Offset inside the CTZ block where read should start.
 *   buf         - Buffer to be populated.
 *
 * Returned Value:
 *   The number of bytes read from the CTZ block.
 *
 * Assumptions/Limitations:
 *   - 32 bit (4 byte) pointers to pages.
 *   - log2(0) = -1.
 *   - Each CTZ block is a page.
 *
 ****************************************************************************/

static ssize_t ctz_blk_rd(struct mnemofs_sb_info *sb,
                          const struct mnemofs_ctz_s * const l, char *buf,
                          const mfs_t idx, ssize_t off)
{
  uint32_t pg;
  uint32_t len;

  pg = ctz_blk2pg(sb, l, idx);
  len = sb->pg_sz - CTZ_PTR_SIZE(sb) * (mnemofs_log2(l->idx) + 1);

  if(predict_false(l->idx == 0)) {
    /* First block */
    off += FIRST_BLK_OFF_SZ(sb);
    len -= FIRST_BLK_OFF_SZ(sb);
  } else if (predict_false(l->idx == l->last_idx)) {
    /* Last block */
    off += LAST_BLK_OFF_SZ(sb);
    len -= LAST_BLK_OFF_SZ(sb);
  }

  return mnemofs_read_page(buf, len, pg, off);
}


/****************************************************************************
 * Name: ctz_blk_frd
 *
 * Description:
 *   Reads an entire (full read) CTZ block including metadata and pointers.
 *
 * Input Parameters:
 *   sb         - Superblock representation in-memory.
 *   start_pg   - The page number of the last CTZ block.
 *   start_idx  - The index of the last CTZ block.
 *   blk_idx    - The index of the CTZ block to be duplicated.
 *   buf        - Buffer to populate with block contents.
 *
 * Assumptions/Limitations:
 *  - `start_pg`, `start_idx` and `blk_idx` are valid.
 *  - `buf` is atleast `sb->pg_sz` in size.
 *
 ****************************************************************************/

static void ctz_blk_frd(struct mnemofs_sb_info *sb,
                        const struct mnemofs_ctz_s * const l, const mfs_t idx,
                        char *buf)
{
  int pg = ctz_blk2pg(sb, l, idx);
  mnemofs_read_page(buf, sb->pg_sz, pg, 0);
}

/****************************************************************************
 * Name: ctz_blksize
 *
 * Description:
 *   Gets the size of the data in the `blk_idx`th block of the CTZ list.
 *
 *   This is the theoretical size, and not the amount of data written in the
 *   block. This assumes the journal and commits will compact everything.
 *
 * Input Parameters:
 *   sb         - Superblock representation in-memory.
 *   start_idx  - The index of the last CTZ block.
 *   blk_idx    - The index of the CTZ block to be duplicated.
 *
 * Returned Value:
 *   The size of the data in the last block of the CTZ list.
 *
 * Assumptions/Limitations:
 *  - `start_pg` and `start_idx` belong to a valid file.
 *  - Size of a block can be represented in 16 bits (2 bytes).
 *
 ****************************************************************************/

static uint16_t ctz_blksz(struct mnemofs_sb_info *sb,
                          const struct mnemofs_ctz_s * const l, const mfs_t idx)
{
  int sz = sb->pg_sz - (CTZ_PTR_SIZE(sb) * (mnemofs_log2(idx) + 1));

  if(predict_false(l->last_idx == idx)) {
    sz -= LAST_BLK_OFF_SZ(sb);
  } else if (predict_false(l->last_idx == 0)) {
    sz -= FIRST_BLK_OFF_SZ(sb);
  }

  return sz;
}

/****************************************************************************
 * Name: ctz_lastblksz
 *
 * Description:
 *   Gets the size of written data in the last block of the CTZ list.
 *
 * Input Parameters:
 *   start_pg   - The page number of the last CTZ block.
 *   start_idx  - The index of the last CTZ block.
 *
 * Returned Value:
 *   The size of the data in the last block of the CTZ list.
 *
 * Assumptions/Limitations:
 *  - `start_pg` and `start_idx` belong to a valid file.
 *  - Size of a block can be represented in 16 bits (2 bytes).
 *
 ****************************************************************************/

static inline uint16_t ctz_lastblksz(const struct mnemofs_ctz_s * const l)
{
  uint16_t last_off;
  mnemofs_read_page((char *) &last_off, sizeof(last_off), l->last_pg,
                    LAST_BLK_SIZE_OFF);
  return last_off;
}

/* NOTE: This will be used for the on-flash update operation, which comes when
journal is being committed to the flash. */
static int ctz_append_data(struct mnemofs_sb_info *sb, struct mnemofs_ctz_s * const l,
                            const char *buf, ssize_t len)
{
  int ret = OK;
  char *old_blk_buf = NULL;
  char *new_blk_buf = NULL;
  ssize_t sz;
  ssize_t tsz; /* Theoretical size */
  uint8_t new_blk = 1;
  uint32_t pg;
  uint32_t tmp;
  uint32_t tmp2;
  uint32_t i;

  /* TODO: Check the case where the list is empty. */
  /* TODO: Check all return values. */

  nxmutex_lock(&sb->fs_lock);

  /* Check if new block has to be appended */

  sz = ctz_lastblksz(l);
  tsz = ctz_blksz(sb, l, l->last_idx);
  if(sz + len < tsz) {
    new_blk = 0;
  }

  /* Copy the last block. */

  old_blk_buf = kmm_zalloc(sb->pg_sz);
  if(!old_blk_buf) {
    ret = -ENOMEM;
    goto errout_with_lock;
  }
  ctz_blk_frd(sb, l, l->last_idx, old_blk_buf);

  /* Update blocks. */

  if(!new_blk) {
    /* Add data inside last block. */

    DEBUGASSERT(((uint64_t) sz) + len < UINT32_MAX);

    memcpy(old_blk_buf + LAST_BLK_OFF_SZ(sb) + sz, buf, len);

    sz += len;
    memcpy(old_blk_buf + LAST_BLK_SIZE_OFF, &sz, sizeof(sz));
    // TODO: mnemofs_write_data(old_blk_buf, )
  } else {

    /* Compact last block, and append a new block. */

    /* Update original last block. */

    tsz = ctz_blksz(sb,
                    &(const struct mnemofs_ctz_s) {.last_idx = l->last_idx + 1},
                    l->last_idx);
    memmove(old_blk_buf, old_blk_buf + LAST_BLK_OFF_SZ(sb), sz);
    memcpy(old_blk_buf + sz, buf, tsz-sz);
    /* No need to copy pointers, they stay the same. */
    pg = mnemofs_get_pg();
    mnemofs_write_page(old_blk_buf, sb->pg_sz, pg, 0);

    /* Create new last block. */

    new_blk_buf = kmm_zalloc(sb->pg_sz);
    if(!new_blk_buf) {
      ret = -ENOMEM;
      goto errout_with_old_buf;
    }

    buf += (tsz - sz);
    tsz = ctz_blksz(sb,
                    &(const struct mnemofs_ctz_s) {.last_idx = l->last_idx + 1},
                    l->last_idx + 1);
    tmp = mnemofs_log2(l->last_idx + 1) + 1;
    for(i = 0; i < tmp; i++) {
      tmp2 = ctz_blk2pg(sb, l, l->last_idx - (1 << tmp) - 1);

      memcpy(new_blk_buf - (sb->pg_sz - (CTZ_PTR_SIZE(sb) * (i + 1))),
      &tmp2,
      CTZ_PTR_SIZE(sb));
    }

    l->last_idx++;
    pg = mnemofs_get_pg();
    l->last_pg = pg;
    mnemofs_write_page(new_blk_buf, sb->pg_sz, pg, 0);
  }

  kmm_free(new_blk_buf);

errout_with_old_buf:
  kmm_free(old_blk_buf);

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);
  return ret;
}

/****************************************************************************
 * Name: file_size
 *
 * Description:
 *   Gets the size of a file in bytes..
 *
 * Input Parameters:
 *   sb         - Superblock representation in-memory.
 *   start_pg   - The page number of the last CTZ block.
 *   start_idx  - The index of the last CTZ block.
 *
 * Returned Value:
 *   The file size in bytes.
 *
 * Assumptions/Limitations:
 *  - `start_pg` and `start_idx` belong to a valid file.
 *  - 32 bit (4 byte) pointers to CTZ blocks.
 *
 ****************************************************************************/

static ssize_t file_size(struct mnemofs_sb_info *sb,
                          const struct mnemofs_ctz_s * const l)
{

  ssize_t size = 0;

  /* Previous Blocks */

  if(predict_true(l->last_idx != 0)) {
    /* Total page size */

    size += sb->pg_sz * (l->last_idx);

    /* Removing pointers */

    size -= CTZ_PTR_SIZE(sb) *
            ctz_nptr(&(const struct mnemofs_ctz_s) {.idx = l->last_idx - 1});

    size -= FIRST_BLK_OFF_SZ(sb);
  }

  /* Last block */
  size += ctz_lastblksz(l);

  return size;
}

/* Returns size read or error */
mfs_off_t __mnemofs_file_read(struct mnemofs_sb_info *sb, struct mnemofs_file *f, mfs_off_t off, char *buf, ssize_t len) {

  mfs_off_t pg_off; /* ctz_blk_off and pg_off are same here */
  mfs_t ret = OK;
  char *tmp_buf = buf;

  /* Initial position */

  ctz_off2blk(sb, off, &f->l, &pg_off);

  while(len > 0) {
    ret = ctz_blk_rd(sb, &f->l, tmp_buf, f->l.idx, 0);
    if(ret < 0) {
      goto errout;
    }
    len -= ret;
    tmp_buf += ret;
    if(f->l.idx + 1 <= f->l.last_idx) {
      f->l.idx++; /* Next Block */
    }
  }

errout:
  return ret >= 0 ? tmp_buf - buf : ret;
}

/* TODO: This for now contains the actual append operation. Later on, that
will be split from this, and this will just contain the code to add a cache/journal
entry for appending of file. */
static int file_append(struct mnemofs_sb_info *sb, struct mnemofs_file *f, const char *buf, ssize_t len) {
  return ctz_append_data(sb, &f->l, buf, len);
}

/* Enter off as f->f_size to append at end. */
/* TODO: Make a macro for off to be excluded. */
/* TODO: Updates the file's size as well. */
/* This handles the off > size case. */
int __mnemofs_file_insert(struct mnemofs_sb_info *sb, struct mnemofs_file *f, const char *buf, ssize_t len, off_t off) {
  int ret = OK;

  /* TODO: Think about off > f-f_size and the entire HOLE situation. */
  if(off == f->size) {
    return file_append(sb, f, buf, len);
  }

  struct mnemofs_file temp_f;
  memcpy(&temp_f, f, sizeof(struct mnemofs_file));

  /* TODO: Mark the pages from [off, FILE_END] for deletion */
  temp_f.size = off;
  ret = file_append(sb, &temp_f, buf, len);
  if(ret < 0) {
    goto errout;
  }

  /* TODO: Manage the upcoming blocks that fall outside of the update range,
  such that if, say, there is a string abcdefghijk, and I try to write xyz at index
  3, the result is abcxyzghijk and not abcxyz.
  
  abcxyz is what the current implementation line below does. CHANGE IT!!!!
  */
  memcpy(f, &temp_f, sizeof(struct mnemofs_file));

  /* TODO: Upon update, add a journal log that mentions that the file's start block
  has changed, and thus, its direntry needs to be updated. */
  /* TODO: If the file is a directory, then the update need to be notified to its
  parent when the journal is being committed, which is what this function will be
  when its written in a separate function from this one.*/

errout:
  return ret;
}

/* Replace `dst_len` worth of bytes at `off` with `src_len` worth of bytes in file `f` */
/* TODO: Updates the file's size as well. */
int __mnemofs_file_update(struct mnemofs_file *f, const char *buf, ssize_t src_len, ssize_t off, ssize_t dst_len) {
  return OK;
}

/* TODO: Updates the file's size as well. */
int __mnemofs_file_delete(struct mnemofs_file *f, ssize_t off, ssize_t len) {
  return __mnemofs_file_update(f, NULL, 0, off, len);
}

//------------------------------------------------

/* Open files in mnemofs */
struct mnemofs_file_info { /* TODO: Remove the duplicated from dir_f and this struct. Maintain one source of truth. */
  struct mnemofs_file_info *prev; /* Previous entry in doubly linked list.*/
  struct mnemofs_file_info *next; /* Next entry in doubly linked list.*/
  int oflags;
  mode_t mode;
  struct mnemofs_file ff;
};

/* FUTURE TODO: Since the LRU is a doubly linked list, keep a doubly linked list with separate
pointers for an open file as well. This way, the updates to a file can be traversed even without
traversing the LRU.
*/

/* Keep a global LRU for all updates. */
// 0 - Not found, 1 - Found
/* Almost duplicate of search_open_dirs */
static int search_open_files(struct mnemofs_sb_info *sb, FAR const char *relpath) {

  uint8_t hash;
  struct mnemofs_file_info *head;
  int ret = 0;
  int lock = 0;

  if(!sb->d_s) {
    goto out;
  }

  hash = mnemofs_calc_str_hash(relpath, strlen(relpath));

  /* Only lock and unlock if we're the ones locking this, not the parent function. */
  if(!nxmutex_is_locked(&sb->fs_lock)) {
    nxmutex_lock(&sb->fs_lock);
    lock = 1;
  }

  for(head = sb->f_s; head != sb->f_e; head = head->next) {
    if(head->ff.hash == hash) {
      /* Hash collision */
      if(!strncmp(relpath, head->ff.path, head->ff.pathlen)) {
        /* Found the path */
        ret = 1;
        goto out_with_lock;
      }
    }
  }

out_with_lock:
  if(lock) {
    nxmutex_unlock(&sb->fs_lock);
  }

out:
  return ret;
}

int __mnemofs_open(struct file *fp, FAR const char *relpath, int oflags, mode_t mode) {

  int ret = OK;
  struct mnemofs_file_info *fi;
  struct mnemofs_direntry_info parent, child;
  const int pathlen = strlen(relpath);
  struct mnemofs_sb_info *sb;
  struct inode *inode;

  inode = fp->f_inode;
  sb = inode->i_private;

  nxmutex_lock(&sb->fs_lock);

  memcpy(&parent, sb->root, sizeof(parent));

  ret = search_direntries_r(&parent, &child, relpath, pathlen);
  if(ret != MNEMOFS_DIR_SEARCH_OK) {
    ret = -ENOENT;
    goto errout_with_lock;
  } else {
    ret = OK;
  }

  /* FUTURE TODO: mnemofs doesn't support anything other than directories and links yet. */
  if(!S_ISREG(child.mode)) {
    ret = -EISDIR;
    goto errout_with_lock;
  }

  fi = kmm_zalloc(sizeof(*fi));
  if(!fi) {
    ret = -ENOMEM;
    goto errout_with_lock;
  }

  fi->ff.pathlen = pathlen;
  fi->ff.path = kmm_zalloc(pathlen);
  if(!fi->ff.path) {
    ret = -ENOMEM;
    goto errout_with_ff;
  }
  memcpy(&fi->ff.path, relpath, pathlen);

  /* Turns out you don't need to check for multiple file descriptors.
  Source: https://stackoverflow.com/a/5284108/14369307
  Also TODO: dup shares the same file pointer, so affecting affects both.
  */

  fi->prev = NULL; /* Will be set later with mutex */
  fi->next = NULL;
  fi->ff.hash = mnemofs_calc_str_hash(fi->ff.path, fi->ff.pathlen);
  fi->ff.off = 0;
  fi->ff.l.last_pg = child.dir_f.l.last_pg;
  fi->ff.l.last_idx = child.dir_f.l.last_idx;
  fi->ff.l.idx = 0;
  fi->mode = mode;
  fi->ff.size = file_size(sb, &fi->ff.l);

  /* TODO: Remember to add a functionality to update the start_pg and start_idx
  to ALL open file descriptors / pointers when the file updates. */

  /* Append at the end of list of open files. */
  if(sb->f_e == NULL /* && sb->f_start == NULL */) {
    sb->f_s = fi;
    sb->f_e = fi;
  } else {
    sb->f_e->next = fi;
    fi->prev = sb->f_e;
    sb->f_e = fi;
  }

  /*
  TODO: Keep in mind the new CTZ block may be in the journal
  or the LRU as well as the flash, that is upto the lowest level function to find out,
  not the higher functions. The lowest level read operation will read out the block from LRU.
  */

  /*
    TODO: fi->oflags ????
  */

  fp->f_priv = fi;

  return OK;

errout_with_ff:
  kmm_free(fi);

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);

  return ret;
}

// TODO: Get return value of ALL LOCKS AND UNLOCKS.
int __mnemofs_close(struct file *fp) {

  int ret = OK;
  struct inode *inode;
  struct mnemofs_sb_info *sb;
  struct mnemofs_file_info *fi;

  inode = fp->f_inode;
  sb = inode->i_private;
  fi = fp->f_priv;

  nxmutex_lock(&sb->fs_lock);

  /* TODO: Debug assert to check if dir is not NULL */

  if(sb->f_s == fi && sb->f_e == fi /* && ff->prev == NULL && ff->next == NULL */) {
    sb->f_s = NULL;
    sb->f_e = NULL;
  } else {

    /* Taking care of terminal nodes preculiarities. */
    if (sb->f_s == fi) {
      sb->f_s = fi->next;
    } else if (sb->f_e == fi) {
      sb->f_e = fi->prev;
    }

    fi->prev->next = fi->next;
    fi->next->prev = fi->prev;
  }

  /* As this mentions, no need to fsync after close:
  https://stackoverflow.com/a/15348491/14369307 */

  nxmutex_unlock(&sb->fs_lock);

  return ret;
}

ssize_t __mnemofs_read(FAR struct file *fp, FAR char *buf, size_t buflen) {

  int ret = OK;
  struct inode *inode;
  struct mnemofs_sb_info *sb;
  struct mnemofs_file_info *fi;
  struct mnemofs_file ff;
  ssize_t len;

  inode = fp->f_inode;
  sb = inode->i_private;
  fi = fp->f_priv;

  nxmutex_lock(&sb->fs_lock);

  ff = fi->ff;

  len = __mnemofs_file_read(sb, &ff, ff.off, buf, buflen);
  if(len < 0) {
    /* TODO: What if off > size? */
    ret = len;
    goto errout_with_lock;
  } else if (len == 0) {
    /* TODO: EOF */
  }

  fi->ff.off += len;

  nxmutex_unlock(&sb->fs_lock);
  return len;

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);

  return ret;
}

ssize_t __mnemofs_write(FAR struct file *fp, FAR const char *buf, size_t buflen) {

  int ret = OK;
  struct inode *inode;
  struct mnemofs_sb_info *sb;
  struct mnemofs_file_info *fi;
  ssize_t len;
  ssize_t off;

  /* TODO: Debug Assert for fp. */

  inode = fp->f_inode;
  sb = inode->i_private;
  fi = fp->f_priv;
  off = (fi->mode & O_APPEND) ? fi->ff.size : fi->ff.off;

  if(fi->mode & O_WRONLY) {
    ret = -EBADF;
    goto errout;
  }

  nxmutex_lock(&sb->fs_lock);

  len = __mnemofs_file_insert(sb, &fi->ff, buf, buflen, off);
  if(len <= 0) {
    ret = len;
    goto errout_with_lock;
  }

  nxmutex_unlock(&sb->fs_lock);
  return len;

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);

errout:
  return ret;
}

off_t __mnemofs_seek(FAR struct file *fp, off_t off, int whence) {

  off_t ret = 0;
  struct inode *inode;
  struct mnemofs_sb_info *sb;
  struct mnemofs_file_info *fi;
  off_t old_off;

  /* TODO: Debug Assert for fp. */

  if(off == 0) {
    goto errout;
  }

  inode = fp->f_inode;
  sb = inode->i_private;
  fi = fp->f_priv;

  nxmutex_lock(&sb->fs_lock);

  old_off = off;

  switch(whence) {

    case SEEK_SET:
      fi->ff.off = off;
      break;

    case SEEK_CUR:
      fi->ff.off += off;
      break;

    case SEEK_END:
      fi->ff.off = fi->ff.size + off;
      break;
  }

  ret = fi->ff.off;

  if(fi->ff.off < 0 && off < 0) {
    fi->ff.off = old_off;
  } else if (fi->ff.off < old_off && off > 0) {
    /* Offset overflow cases. */
    ret = -EOVERFLOW;
  }

  nxmutex_unlock(&sb->fs_lock);

errout:
  return ret;
}