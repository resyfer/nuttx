/****************************************************************************
 * fs/mnemofs_new/mnemofs_dir.c
 *
 * SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
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
 * Alternatively, the contents of this file may be used under the terms of
 * the BSD-3-Clause license:
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2024 Saurav Pal
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of its contributors may
 *    be used to endorse or promote products derived from this software
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include "mnemofs.h"
#include <assert.h>
#include <errno.h>
#include <fixedmath.h>
#include <limits.h>
#include <nuttx/compiler.h>
#include <nuttx/list.h>
#include <string.h>
#include <time.h>
#include "fs_heap.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/****************************************************************************
 * Private Types
 ****************************************************************************/

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

static int deser_pointer(FAR const mfs_sb_s *sb, FAR const char *buf,
                         FAR mfs_pgloc_t *pgloc);
static void ser_pointer(FAR const mfs_sb_s *sb, FAR char *buf,
                        FAR mfs_pgloc_t *pgloc);
static int deser_dirent(FAR mfs_sb_s *sb, FAR const char *buf,
                        FAR mfs_dirent_s *dirent);
static void ser_dirent(FAR mfs_sb_s *sb, FAR char *buf,
                       FAR const mfs_dirent_s * const dirent);

/****************************************************************************
 * Private Data
 ****************************************************************************/

/****************************************************************************
 * Public Data
 ****************************************************************************/

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static int
deser_pointer(FAR const mfs_sb_s *sb, FAR const char *buf,
              FAR mfs_pgloc_t *pgloc)
{
  int   ret = OK;
  mfs_t pg;

  memcpy(&pg, buf, 4);
  *pgloc = mfs_util_pg_to_pgloc(sb, pg);

  if (pgloc->blk == 0)
    {
      ret = -ENOENT;
    }

  return ret;
}

static void
ser_pointer(FAR const mfs_sb_s *sb, FAR char *buf, FAR mfs_pgloc_t *pgloc)
{
  mfs_t pg;
  pg = mfs_util_pgloc_to_pg(sb, pgloc);
  memcpy(buf, &pg, 4);
}

static void
ser_dirent(FAR mfs_sb_s *sb, FAR char *buf,
           FAR const mfs_dirent_s * const dirent)
{
  mfs_t chksm;
  mfs_t pg;

  chksm = mfs_util_calc_chksm(dirent->name, NAME_MAX);
  pg    = mfs_util_pgloc_to_pg(sb, &dirent->pg);

  memcpy(buf +  0, &chksm,           4);
  memcpy(buf +  4, &dirent->mode,    4);
  memcpy(buf +  8, &dirent->st_ctim, sizeof(struct timespec));
  memcpy(buf + 16, &dirent->st_mtim, sizeof(struct timespec));
  memcpy(buf + 24, &dirent->sz,      4);
  memcpy(buf + 28, &pg,              4);
  memcpy(buf + 32, &dirent->name,    NAME_MAX);
}

static int
deser_dirent(FAR mfs_sb_s *sb, FAR const char *buf, FAR mfs_dirent_s *dirent)
{
  int ret = OK;
  mfs_t pg;
  mfs_t chksm;

  memcpy(&dirent->name_chksm, buf +  0, 4);
  memcpy(&dirent->mode,       buf +  4, 4);
  memcpy(&dirent->st_ctim,    buf +  8, sizeof(struct timespec));
  memcpy(&dirent->st_mtim,    buf + 16, sizeof(struct timespec));
  memcpy(&dirent->sz,         buf + 24, 4);
  memcpy(&pg,                 buf + 28, 4);
  memcpy(&dirent->name,       buf + 32, NAME_MAX);

  chksm = mfs_util_calc_chksm(dirent->name, NAME_MAX);
  if (dirent->name_chksm != chksm)
    {
      ret = -EINVAL;
      goto errout;
    }

  dirent->pg = mfs_util_pg_to_pgloc(sb, pg);
  return OK;

errout:
  memset(dirent, 0, sizeof(mfs_dirent_s));
  return ret;
}

int
dir_travel(FAR mfs_sb_s *sb, const mfs_t s_idx, FAR mfs_pgloc_t *s_pg,
           const mfs_t d_idx, FAR mfs_pgloc_t *d_pg)
{
  int ret = OK;
  return ret;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

void
mfs_dir_init(const mfs_pgloc_t *pg, FAR mfs_dir_s *dir)
{
  dir->idx       = -2;
  dir->b.blk     = pg->blk;
  dir->b.blk_off = pg->blk_off;
  dir->b.pg_off  = 0;
}

int
mfs_dir_rdnadv(FAR mfs_sb_s *sb, FAR const mfs_dir_s *o_dir,
               FAR mfs_dirent_s *dirent, FAR mfs_dir_s *n_dir)
{
  int         ret                 = OK;
  char        buf[MFS_DIRENT_SZ];
  mfs_dir_s   _dir;
  mfs_pgloc_t pg;

  DEBUGASSERT(MFS_PGSZ(sb) % MFS_DIRENT_SZ == 0);

  memset(buf, 0, MFS_DIRENT_SZ);
  _dir = *o_dir;

  if (_dir.idx == -2)
    {
      /* TODO */

      goto errout;
    }
  else if (_dir.idx == -1)
    {
      /* TODO */

      goto errout;
    }

  /* Final 64 bytes (MFS_DIRENT_SZ) are kept reserved for pointer to next.
   * If the current pointer points to a pointer, then move to that block.
   */

  if (_dir.b.pg_off == MFS_PGSZ(sb) - MFS_DIRENT_SZ)
    {
      ret = mfs_rw_pgrdoff(sb, &_dir.b, buf, MFS_DIRENT_SZ);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      ret = deser_pointer(sb, buf, &pg);
      if (predict_false(ret == -EINVAL))
        {
          goto errout;
        }

      _dir.b.blk     = pg.blk;
      _dir.b.blk_off = pg.blk_off;
      _dir.b.pg_off  = 0;

      memset(buf, 0, MFS_DIRENT_SZ);
    }

  /*  direntry */

  ret = mfs_rw_pgrdoff(sb, &_dir.b, buf, MFS_DIRENT_SZ);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  ret = deser_dirent(sb, buf, dirent);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  _dir.b.pg_off += MFS_DIRENT_SZ;

  _dir.idx++;
  *n_dir = _dir;
  return OK;

errout:
  return ret;
}

int
mfs_dir_get_from_path(FAR mfs_sb_s *sb, FAR char *path,
                      FAR mfs_path_s *p)
{
  int            ret            = OK;
  char           *rest          = path;
  char           *token;
  char           name[NAME_MAX];
  mfs_t          len;
  mfs_t          chksm;
  mfs_dir_s      _dir1;
  mfs_dir_s      _dir2;
  mfs_path_s     *dir_list;
  mfs_pgloc_t    pg;
  mfs_dirent_s   _dirent;

  if (path == NULL || !(token = strtok_r(rest, "/", &rest)))
    {
      goto errout;
    }

  len = strlen(token);
  memcpy(name, token, len);
  chksm = mfs_util_calc_chksm(name, NAME_MAX);

  dir_list = fs_heap_zalloc(sizeof(mfs_path_s));
  if (predict_false(dir_list == NULL))
    {
      ret = -ENOMEM;
      goto errout;
    }

  /* Iterate directory */

  pg = (list_peek_tail_type(&p->list, mfs_path_s, list))->pg;

  mfs_dir_init(&pg, &_dir1);
  _dir1.idx = 0; /* We don't need . & .. here. */
  while (true)
    {
      ret = mfs_dir_rdnadv(sb, &_dir1, &_dirent, &_dir2);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      if (_dirent.name_chksm == chksm)
        {
          if (!memcmp(_dirent.name, token, MFS_MIN(NAME_MAX, len)))
            {
              dir_list->idx    = _dir1.idx;
              dir_list->pg     = _dirent.pg;
              dir_list->dirent = _dirent;

              /* The index stored in the element in the list previous to the
               * current node is the index at which the current element's
               * direntry was found in previous entry's directory.
               */

              list_add_tail(&p->list, &dir_list->list);
              return mfs_dir_get_from_path(sb, rest, p);
            }
          else
            {
              /* Doesn't match */
            }
        }
      else
        {
          _dir1 = _dir2;
          break;
        }
    }

errout:
  return ret;
}

int
mfs_dir_append(FAR mfs_sb_s *sb, FAR mfs_path_s *dir_list,
               FAR mfs_dirent_s *dirent)
{
  int         ret                = OK;
  mfs_t       i;
  mfs_t       pg;
  mfs_t       idx;
  mfs_t       off;
  mfs_bloc_t  b;
  mfs_path_s  *parent;
  mfs_pgloc_t o_pg;
  mfs_pgloc_t n_pg_p;
  mfs_pgloc_t n_pg_n;
  char        buf[MFS_DIRENT_SZ];
  const mfs_t n_dirent_per_pg     = (MFS_PGSZ(sb) / MFS_DIRENT_SZ) - 1;

  /* The directory where it is to be appended is the tail of the dir_list. */

  parent = list_peek_tail_type(&dir_list->list, mfs_path_s, list);
  DEBUGASSERT(parent != NULL);

  /* COPY PREVIOUS PAGES */

  idx = parent->dirent.sz / n_dirent_per_pg;
  off = (parent->dirent.sz % n_dirent_per_pg) * MFS_DIRENT_SZ;

  /* Allocate first page. */

  ret = mfs_alloc_getfreepg(sb, &n_pg_p);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  /* TODO: n_pgloc_p is the new location of the directory, and needs to be
   * used to provide updated location for the bubble up operation.
   */

  o_pg = parent->pg;
  for (i = 0; i < idx; i++)
    {
      /* Assign next page */

      ret       = mfs_alloc_getfreepg(sb, &n_pg_n);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      /* Copy contents from old page. */

      ret       = mfs_rw_pgrd(sb, &o_pg, NULL, 0);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      pg        = mfs_util_pgloc_to_pg(sb, &n_pg_p);
      ret       = mfs_rw_rd_cpy_to_wr(sb, pg);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      /* Write next pointer */

      memset(buf, 0, MFS_DIRENT_SZ);
      ser_pointer(sb, buf, &n_pg_n);

      b.blk     = n_pg_p.blk;
      b.blk_off = n_pg_p.blk_off;
      b.pg_off  = MFS_PGSZ(sb) - MFS_DIRENT_SZ;

      ret       = mfs_rw_pgwroff(sb, &b, buf, MFS_DIRENT_SZ);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      /* Next iteration */

      n_pg_p    = n_pg_n;
      ret       = dir_travel(sb, i, &o_pg, i + 1, &o_pg);
      if (predict_false(ret < 0))
        {
          goto errout;
        }
    }

  /* CURRENT PAGE */

  /* Copy old content */

  ret       = mfs_rw_pgrd(sb, &o_pg, NULL, 0);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  pg        = mfs_util_pgloc_to_pg(sb, &n_pg_p);
  ret       = mfs_rw_rd_cpy_to_wr(sb, pg);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  /* Write new direntry */

  memset(buf, 0, MFS_DIRENT_SZ);
  ser_dirent(sb, buf, dirent);

  b.blk     = n_pg_p.blk;
  b.blk_off = n_pg_p.blk_off;
  b.pg_off  = off;

  ret       = mfs_rw_pgwroff(sb, &b, buf, MFS_DIRENT_SZ);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  /* TODO: Directory size has increased by MFS_DIRENT_SZ. */

  /* TODO: Bubble up. */

errout:
  return ret;
}

int
mfs_dir_rm(FAR mfs_sb_s *sb, FAR mfs_path_s *dir_list, FAR mfs_t dirent_idx)
{
  int         ret                = OK;
  char        buf[MFS_DIRENT_SZ];
  mfs_t       idx;
  mfs_t       off;
  mfs_t       i;
  mfs_t       pg;
  mfs_t       n_pg;
  mfs_bloc_t  b1;
  mfs_bloc_t  b2;
  mfs_path_s  *parent;
  mfs_pgloc_t o_pg;
  mfs_pgloc_t n_pg_p;
  mfs_pgloc_t n_pg_n;
  const mfs_t n_dirent_per_pg    = (MFS_PGSZ(sb) / MFS_DIRENT_SZ) - 1;

  /* The directory where it is to be appended is the tail of the dir_list. */

  parent = list_peek_tail_type(&dir_list->list, mfs_path_s, list);
  DEBUGASSERT(parent != NULL);

  /* COPY PREVIOUS PAGES */

  n_pg = parent->dirent.sz / (MFS_PGSZ(sb) - MFS_DIRENT_SZ);
  idx  = dirent_idx / n_dirent_per_pg;
  off  = (dirent_idx % n_dirent_per_pg) * MFS_DIRENT_SZ;

  /* Allocate first page. */

  ret = mfs_alloc_getfreepg(sb, &n_pg_p);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  /* TODO: n_pgloc_p is the new location of the directory, and needs to be
   * used to provide updated location for the bubble up operation.
   */

  o_pg = parent->pg;
  for (i = 0; i < idx; i++)
    {
      /* Assign next page */

      ret = mfs_alloc_getfreepg(sb, &n_pg_n);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      /* Copy contents from old page. */

      ret = mfs_rw_pgrd(sb, &o_pg, NULL, 0);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      pg  = mfs_util_pgloc_to_pg(sb, &n_pg_p);
      ret = mfs_rw_rd_cpy_to_wr(sb, pg);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      /* Write next pointer */

      memset(buf, 0, MFS_DIRENT_SZ);
      ser_pointer(sb, buf, &n_pg_n);

      b1.blk     = n_pg_p.blk;
      b1.blk_off = n_pg_p.blk_off;
      b1.pg_off  = MFS_PGSZ(sb) - MFS_DIRENT_SZ;

      ret        = mfs_rw_pgwroff(sb, &b1, buf, MFS_DIRENT_SZ);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      /* Next iteration */

      n_pg_p = n_pg_n;
      ret    = dir_travel(sb, i, &o_pg, i + 1, &o_pg);
      if (predict_false(ret < 0))
        {
          goto errout;
        }
    }

  /* CURRENT PAGE */

  ret = mfs_rw_pgrd(sb, &o_pg, NULL, 0);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  pg  = mfs_util_pgloc_to_pg(sb, &n_pg_p);
  ret = mfs_rw_rd_cpy_to_wr(sb, pg);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  mfs_rw_del_n_wrbuf(sb, off, MFS_DIRENT_SZ);

  /* SHIFT DIRENTRIES IN NEXT PAGES */

  for (i = idx + 1; i < n_pg; i++)
    {
      b1.blk     = n_pg_p.blk;
      b1.blk_off = n_pg_p.blk_off;
      b1.pg_off  = MFS_PGSZ(sb) - 2 * MFS_DIRENT_SZ;

      ret = dir_travel(sb, i - 1, &o_pg, i, &o_pg);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      b2.blk     = o_pg.blk;
      b2.blk_off = o_pg.blk_off;
      b2.pg_off  = 0;

      memset(buf, 0, MFS_DIRENT_SZ);
      ret = mfs_rw_pgrdoff(sb, &b2, buf, MFS_DIRENT_SZ);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      ret = mfs_rw_pgwroff(sb, &b1, buf, MFS_DIRENT_SZ);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      /* Next Pointer. */

      b1.pg_off = MFS_PGSZ(sb) - MFS_DIRENT_SZ;

      ret = mfs_alloc_getfreepg(sb, &n_pg_n);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      memset(buf, 0, MFS_DIRENT_SZ);
      ser_pointer(sb, buf, &n_pg_n);

      ret = mfs_rw_pgwroff(sb, &b1, buf, MFS_DIRENT_SZ);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      /* Next block */

      n_pg_p = n_pg_n;

      b1.blk     = n_pg_p.blk;
      b1.blk_off = n_pg_p.blk_off;
      b1.pg_off  = 0;

      pg  = mfs_util_pgloc_to_pg(sb, &n_pg_p);
      ret = mfs_rw_rd_cpy_to_wr(sb, pg);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      mfs_rw_del_n_wrbuf(sb, 0, MFS_DIRENT_SZ);
    }

  /* TODO: Directory size has decreased by MFS_DIRENT_SZ. */

  /* TODO: Bubble up. */

errout:
  return ret;
}

int
mfs_dir_dirent_upd(FAR mfs_sb_s *sb, FAR mfs_path_s *dir_list,
                   FAR mfs_t dirent_idx, FAR mfs_dirent_s *dirent)
{
  int         ret                = OK;
  mfs_t       i;
  mfs_t       pg;
  mfs_t       idx;
  mfs_t       off;
  mfs_bloc_t  b;
  mfs_path_s  *parent;
  mfs_pgloc_t o_pg;
  mfs_pgloc_t n_pg_p;
  mfs_pgloc_t n_pg_n;
  char        buf[MFS_DIRENT_SZ];
  const mfs_t n_dirent_per_pg     = (MFS_PGSZ(sb) / MFS_DIRENT_SZ) - 1;

  /* The directory where it is to be appended is the tail of the dir_list. */

  parent = list_peek_tail_type(&dir_list->list, mfs_path_s, list);
  DEBUGASSERT(parent != NULL);

  /* COPY PREVIOUS PAGES */

  idx  = dirent_idx / n_dirent_per_pg;
  off  = (dirent_idx % n_dirent_per_pg) * MFS_DIRENT_SZ;

  /* Allocate first page. */

  ret = mfs_alloc_getfreepg(sb, &n_pg_p);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  /* TODO: n_pgloc_p is the new location of the directory, and needs to be
   * used to provide updated location for the bubble up operation.
   */

  o_pg = parent->pg;
  for (i = 0; i < idx; i++)
    {
      /* Assign next page */

      ret       = mfs_alloc_getfreepg(sb, &n_pg_n);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      /* Copy contents from old page. */

      ret       = mfs_rw_pgrd(sb, &o_pg, NULL, 0);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      pg        = mfs_util_pgloc_to_pg(sb, &n_pg_p);
      ret       = mfs_rw_rd_cpy_to_wr(sb, pg);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      /* Write next pointer */

      memset(buf, 0, MFS_DIRENT_SZ);
      ser_pointer(sb, buf, &n_pg_n);

      b.blk     = n_pg_p.blk;
      b.blk_off = n_pg_p.blk_off;
      b.pg_off  = MFS_PGSZ(sb) - MFS_DIRENT_SZ;

      ret       = mfs_rw_pgwroff(sb, &b, buf, MFS_DIRENT_SZ);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      /* Next iteration */

      n_pg_p    = n_pg_n;
      ret       = dir_travel(sb, i, &o_pg, i + 1, &o_pg);
      if (predict_false(ret < 0))
        {
          goto errout;
        }
    }

  /* CURRENT PAGE */

  /* Copy old content */

  ret       = mfs_rw_pgrd(sb, &o_pg, NULL, 0);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  pg        = mfs_util_pgloc_to_pg(sb, &n_pg_p);
  ret       = mfs_rw_rd_cpy_to_wr(sb, pg);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  /* Write new direntry */

  memset(buf, 0, MFS_DIRENT_SZ);
  ser_dirent(sb, buf, dirent);

  b.blk     = n_pg_p.blk;
  b.blk_off = n_pg_p.blk_off;
  b.pg_off  = off;

  ret       = mfs_rw_pgwroff(sb, &b, buf, MFS_DIRENT_SZ);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  /* Write pointer */

  ret       = dir_travel(sb, idx, &o_pg, idx + 1, &o_pg);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  memset(buf, 0, MFS_DIRENT_SZ);
  ser_pointer(sb, buf, &o_pg);

  b.pg_off  = MFS_PGSZ(sb) - MFS_DIRENT_SZ;
  ret       = mfs_rw_pgwroff(sb, &b, buf, MFS_DIRENT_SZ);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  /* TODO: Directory size has increased by MFS_DIRENT_SZ. */

  /* TODO: Bubble up. */

errout:
  return ret;
}
