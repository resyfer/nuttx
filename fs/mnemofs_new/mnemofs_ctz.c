/****************************************************************************
 * fs/mnemofs_new/mnemofs_ctz.c
 * CTZ list functions for mnemofs.
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

#include "fs_heap.h"
#include "mnemofs.h"
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/****************************************************************************
 * Private Types
 ****************************************************************************/

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

/****************************************************************************
 * Private Data
 ****************************************************************************/

/****************************************************************************
 * Public Data
 ****************************************************************************/

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Public Functions
 ****************************************************************************/

static inline mfs_t
ctz(const uint32_t x)
{
  if (predict_false(x == 0))
    {
      /* Special case, since we're using this for the CTZ skip list. The 0th
       * block has no pointers.
       */

      return 0;
    }

  return __builtin_ctz(x);
}

static inline mfs_t
clz(const uint32_t x)
{
  if (predict_false(x == UINT32_MAX))
    {
      /* Special case, since we're using this for the CTZ skip list. The 0th
       * block has no pointers.
       */

      return 0;
    }

  return __builtin_clz(x);
}

static inline mfs_t popcnt(mfs_t x)
{
  return __builtin_popcount(x);
}

static mfs_t
ctz_idx_nptrs(const mfs_t idx)
{
  mfs_t ret;
  ret = (idx == 0) ? 0 : ctz(idx) + 1;
  return ret;
}

/* The size of data in B that can be fit inside a CTZ block at index `idx` */

static mfs_t
ctz_idxdatasz(FAR const mfs_sb_s * sb, const mfs_t idx)
{
  mfs_t ret;
  ret = MFS_PGSZ(sb) - (ctz_idx_nptrs(idx) * MFS_LOGPGSZ);
  return ret;
}

static void
mfs_ctz_idx_from_off(FAR const mfs_sb_s *sb, const mfs_t off,
                     FAR mfs_t *pg_off, FAR mfs_t *idx)
{
  const mfs_t wb  = sizeof(mfs_t);
  const mfs_t den = MFS_PGSZ(sb) - 2 * wb;

  if (off < den)
    {
      *idx = 0;

      if (pg_off != NULL)
        {
          *pg_off = off;
        }

      return;
    }

  *idx = (off - wb * (__builtin_popcount((off / den) - 1) + 2)) / den;

  if (pg_off != NULL)
    {
      *pg_off = off - den * (*idx) - wb * __builtin_popcount(*idx)
                  - (ctz_idx_nptrs(*idx) * wb);
    }

  return;
}

mfs_t
msb_idx(mfs_t n)
{
  return clz(n);
}

int
mfs_ctz_travel(FAR const mfs_sb_s * const sb, const mfs_t s_idx,
               FAR const mfs_pgloc_t *s_pg, const mfs_t d_idx,
               FAR mfs_pgloc_t *d_pg)
{
  char  buf[5];
  mfs_t idx;
  mfs_t pow;
  mfs_t diff;
  mfs_t max_pow;
  mfs_bloc_t b;
  int ret = OK;
  mfs_t pg;

  d_pg->blk     = 0;
  d_pg->blk_off = 0;
  buf[4]        = 0;

  /* Rising phase. */

  max_pow   = (sizeof(mfs_t) * 8) - clz(s_idx ^ d_idx);
  idx       = s_idx;
  pow       = 1;
  b.blk     = s_pg->blk;
  b.blk_off = s_pg->blk_off;

  for (pow = ctz(idx); pow < max_pow - 1; pow = ctz(idx))
    {
      b.pg_off = MFS_PGSZ(sb) - (4 * pow);
      ret = mfs_rw_pgrdoff(sb, &b, buf, 4);
      if (ret < 0)
        {
          goto errout;
        }

      pg        = strtoll(buf, NULL, 2);
      b.blk     = pg / MFS_PGINBLK(sb);
      b.blk_off = pg % MFS_PGINBLK(sb);

      idx -= (1 << pow);

      if (pg == 0)
        {
          goto errout;
        }
    }

  if (idx == d_idx)
    {
      ret = -EINVAL;
      return pg;
    }

  /* Falling phase. */

  diff = idx - d_idx;

  for (pow = msb_idx(diff); diff != 0; pow = msb_idx(diff))
    {
      b.pg_off = MFS_PGSZ(sb) - (4 * pow);
      ret = mfs_rw_pgrdoff(sb, &b, buf, 4);
      if (ret < 0)
        {
          goto errout;
        }

      pg        = strtoll(buf, NULL, 2);
      b.blk     = pg / MFS_PGINBLK(sb);
      b.blk_off = pg % MFS_PGINBLK(sb);

      idx  -= (1 << pow);
      diff -= (1 << pow);

      if (pg == 0)
        {
          ret = -EINVAL;
          goto errout;
        }
    }

  d_pg->blk = b.blk;
  d_pg->blk_off = b.blk_off;

  return OK;

errout:
  return ret;
}

mfs_t
ctz_nptrs(const mfs_t idx)
{
  if (idx == 0)
    {
      return 0;
    }

  return ctz(idx) + 1;
}

/* This assumes the index we are asking for  */

int
apply_ctzptrs(FAR mfs_sb_s *sb, FAR mfs_ctz_s *ctz, const mfs_t idx,
              FAR char *pg_buf)
{
  int ret = OK;
  mfs_t s_idx;
  mfs_t n_ptrs;
  mfs_t *mfs_pg_buf = (mfs_t *) pg_buf;
  mfs_pgloc_t pg;

  mfs_ctz_idx_from_off(sb, ctz->sz - 1, NULL, &s_idx);

  n_ptrs = ctz_nptrs(idx);

  for (mfs_t i = 0; i < n_ptrs; i++)
    {
      DEBUGASSERT(idx >= pow(2, i));

      ret = mfs_ctz_travel(sb, s_idx, &ctz->e_pg, idx - pow(2, i), &pg);
      if (ret < 0)
        {
          goto errout;
        }

      *(mfs_pg_buf - i - 1) = pg.blk * MFS_PGINBLK(sb) + pg.blk_off;
    }

errout:
  return ret;
}

int
mfs_ctz_wroff(FAR mfs_sb_s *sb, FAR const char *buf, const mfs_t n_buf,
              const mfs_t off, FAR const mfs_ctz_s *o_ctz,
              FAR mfs_ctz_s *n_ctz)
{
  int ret = OK;
  mfs_t s_idx;
  mfs_t e_idx;
  mfs_pgloc_t s_pg;
  mfs_pgloc_t d_pg;
  mfs_t pg_off;
  char *pg_buf = NULL;
  mfs_t buf_idx = 0;
  mfs_t rem;
  mfs_t data_sz;
  mfs_ctz_s ctz;

  ctz = *o_ctz;

  if (o_ctz->sz == 0)
    {
      /* TODO:
       * Here, the CTZ is not written yet, but the first page is allocated.
       */

      return OK;
    }

  /* Write to a CTZ at an offset, effectively updating it and set new ctz
   * pointer (n_ctz).
   */

  mfs_ctz_idx_from_off(sb, o_ctz->sz - 1, NULL, &s_idx);
  mfs_ctz_idx_from_off(sb, off, &pg_off, &e_idx);

  s_pg = ctz.e_pg;
  ret = mfs_ctz_travel(sb, s_idx, &s_pg, e_idx, &d_pg);
  if (ret < 0)
    {
      goto errout;
    }

  pg_buf = fs_heap_zalloc(MFS_PGSZ(sb));
  if (pg_buf == NULL)
    {
      ret = -EINVAL;
      goto errout;
    }

  if (pg_off != 0)
    {
      memcpy(pg_buf, buf, MFS_PGSZ(sb));
      buf_idx += MFS_PGSZ(sb);
      e_idx++;

      ret = mfs_alloc_getfreepg(sb, &s_pg);
      if (ret < 0)
        {
          goto errout;
        }

      ret = mfs_rw_pgwr(sb, &s_pg, pg_buf, MFS_PGSZ(sb));
      if (ret < 0)
        {
          goto errout;
        }

      ctz.sz += MFS_PGSZ(sb);
      ctz.e_pg = s_pg;
    }

  while (buf_idx < n_buf)
    {
      memset(pg_buf, 0, MFS_PGSZ(sb));

      rem = n_buf - buf_idx;
      data_sz = ctz_idxdatasz(sb, e_idx);

      ret = apply_ctzptrs(sb, &ctz, e_idx, pg_buf);
      if (ret < 0)
        {
          goto errout;
        }

      ret = mfs_alloc_getfreepg(sb, &s_pg);
      if (ret < 0)
        {
          goto errout;
        }

      memcpy(pg_buf, buf + buf_idx, data_sz < rem ? data_sz : rem);

      ret = mfs_rw_pgwr(sb, &s_pg, pg_buf, MFS_PGSZ(sb));
      if (ret < 0)
        {
          goto errout;
        }

      ctz.sz += data_sz < rem ? data_sz : rem;
      ctz.e_pg = s_pg;
    }

  *n_ctz = ctz;

  return OK;

errout:

  /* TODD: To be safe, mark for free all the pages allocated. */

  fs_heap_free(pg_buf);
  return ret;
}

int
mfs_ctz_rdoff(FAR mfs_sb_s *sb, FAR char *buf, mfs_t n_buf, const mfs_t off,
              FAR const mfs_ctz_s *ctz)
{
  int ret = OK;
  mfs_bloc_t b;
  mfs_t idx;
  mfs_t s_idx;
  mfs_pgloc_t pg;
  mfs_t buf_idx = 0;
  mfs_t n_ptrs;
  mfs_t rem;
  mfs_t sz;

  mfs_ctz_idx_from_off(sb, ctz->sz - 1, &b.pg_off, &s_idx);
  mfs_ctz_idx_from_off(sb, off, &b.pg_off, &idx);

  /* TODO: Read in opposite, this will save search time. */

  while (buf_idx < n_buf)
    {
      ret = mfs_ctz_travel(sb, s_idx, &ctz->e_pg, idx, &pg);
      if (ret < 0)
        {
          goto errout;
        }

      b.blk = pg.blk;
      b.blk_off = pg.blk_off;

      n_ptrs = ctz_idx_nptrs(n_ptrs);
      sz = ctz_idxdatasz(sb, idx);

      if (rem <= sz)
        {
          ret = mfs_rw_pgrdoff(sb, &b, buf + buf_idx, rem);
          rem = 0;
        }
      else
        {
          ret = mfs_rw_pgrdoff(sb, &b, buf + buf_idx, sz);
          rem -= sz;
        }

      if (ret < 0)
        {
          goto errout;
        }

      idx++;
      b.pg_off = 0; /* Only valid for first page in CTZ. */
    }

  return OK;

errout:
  return ret;
}

int
mfs_ctz_off2idx(const mfs_t sz, FAR mfs_t *idx)
{
  /* TODO */

  /* Calculate Index of last page from size. */

  return 0;
}
