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

#include "mnemofs.h"
#include <assert.h>
#include <math.h>
#include <nuttx/compiler.h>
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

static inline mfs_t ctz(const uint32_t x);

static inline mfs_t clz(const uint32_t x);

static inline mfs_t popcnt(mfs_t x);

static mfs_t ctz_idx_nptrs(const mfs_t idx);

static mfs_t ctz_idxdatasz(FAR const mfs_sb_s * sb, const mfs_t idx);

static void mfs_ctz_idx_from_off(FAR const mfs_sb_s *sb, const mfs_t off,
                                 FAR mfs_t *pg_off, FAR mfs_t *idx);

static int apply_ctzptrs(FAR mfs_sb_s *sb, FAR mfs_ctz_s *ctz,
                         const mfs_t idx, FAR char *pg_buf);

static mfs_t msb_idx(mfs_t x);

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
 * Name: ctz
 *
 * Description:
 *   Calculate CTZ of a number.
 *
 * Input Parameters:
 *   x - Number
 *
 * Returned Value:
 *   CTZ of the given number
 *
 * Assumptions/Limitations:
 *   - x is a natural number.
 *
 ****************************************************************************/

static inline mfs_t
ctz(const uint32_t x)
{
  DEBUGASSERT(x != 0);
  return __builtin_ctz(x);
}

/****************************************************************************
 * Name: clz
 *
 * Description:
 *   Calculate CLZ of a number.
 *
 * Input Parameters:
 *   x - Number
 *
 * Returned Value:
 *   CLZ of the given number
 *
 * Assumptions/Limitations:
 *   - x does not have all bits set.
 *
 ****************************************************************************/

static inline mfs_t
clz(const uint32_t x)
{
  return x == UINT32_MAX ? 32 : __builtin_clz(x);
}

/****************************************************************************
 * Name: popcnt
 *
 * Description:
 *   Calculate popcount of a number.
 *
 * Input Parameters:
 *   x - Number
 *
 * Returned Value:
 *   Popcount of the given number
 *
 ****************************************************************************/

static inline mfs_t
popcnt(mfs_t x)
{
  return __builtin_popcount(x);
}

/****************************************************************************
 * Name: ctz_idx_nptrs
 *
 * Description:
 *   Number of pointers a page at an index will have in a CTZ.
 *
 * Input Parameters:
 *   idx - Page index
 *
 * Returned Value:
 *   Number of pointers.
 *
 ****************************************************************************/

static mfs_t
ctz_idx_nptrs(const mfs_t idx)
{
  return (idx == 0) ? 0 : ctz(idx) + 1;
}

/****************************************************************************
 * Name: ctz_idxdatasz
 *
 * Description:
 *   Size available for storing data in a CTZ page at an index.
 *
 * Input Parameters:
 *   sb  - Superblock
 *   idx - Page index
 *
 * Returned Value:
 *   Data size
 *
 ****************************************************************************/

static mfs_t
ctz_idxdatasz(FAR const mfs_sb_s * sb, const mfs_t idx)
{
  return MFS_PGSZ(sb) - (ctz_idx_nptrs(idx) * MFS_LOGPGSZ);
}

/****************************************************************************
 * Name: mfs_ctz_idx_from_off
 *
 * Description:
 *   Calculate the index of a CTZ page from the offset into the data.
 *
 * Input Parameters:
 *   sb     - Superblock
 *   off    - Data offset
 *   pg_off - Offset into the page.
 *   idx    - Index of the CTZ page.
 *
 ****************************************************************************/

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

/****************************************************************************
 * Name: apply_ctzptrs
 *
 * Description:
 *   Apply all the pointers a block at a particular index in the CTZ skip
 *   list will have to the buffer.
 *
 *   NOTE: If the last index is idx in CTZ, this function can only work with
 *   values from [0, idx + 1].
 *
 * Input Parameters:
 *   sb     - Superblock
 *   ctz    - CTZ Skip List
 *   idx    - Index of the CTZ page.
 *   pg_buf - Buffer.
 *
 ****************************************************************************/

static int
apply_ctzptrs(FAR mfs_sb_s *sb, FAR mfs_ctz_s *ctz, const mfs_t idx,
              FAR char *pg_buf)
{
  int ret = OK;
  mfs_t s_idx;
  mfs_t n_ptrs;
  mfs_t *mfs_pg_buf = (mfs_t *) pg_buf;
  mfs_pgloc_t pg;

  mfs_ctz_idx_from_off(sb, ctz->sz - 1, NULL, &s_idx);

  DEBUGASSERT(idx <= s_idx + 1);

  n_ptrs = ctz_idx_nptrs(idx);

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

/****************************************************************************
 * Name: msb_idx
 *
 * Description:
 *   Index of the most significant bit of a number.
 *
 * Input Parameters:
 *   x - Number.
 *
 ****************************************************************************/

static mfs_t
msb_idx(mfs_t x)
{
  return 32 - clz(x) - 1;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int
mfs_ctz_travel(FAR mfs_sb_s * const sb, const mfs_t s_idx,
               FAR const mfs_pgloc_t *s_pg, const mfs_t d_idx,
               FAR mfs_pgloc_t *d_pg)
{
  int        ret      = OK;
  char       buf[5];
  mfs_t      pg;
  mfs_t      idx;
  mfs_t      pow;
  mfs_t      diff;
  mfs_t      max_pow;
  mfs_bloc_t b;

  if (predict_false(s_idx == d_idx))
    {
      *d_pg = *s_pg;
      return ret;
    }

  d_pg->blk     = 0;
  d_pg->blk_off = 0;
  buf[4]        = 0;

  /* Rising phase. */

  max_pow   = 32 - clz(s_idx ^ d_idx);
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

      memcpy(&pg, buf, 4);

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

  d_pg->blk     = b.blk;
  d_pg->blk_off = b.blk_off;

  return OK;

errout:
  return ret;
}

int
mfs_ctz_wroff(FAR mfs_sb_s *sb, FAR const char *buf, const mfs_t n_buf,
              const mfs_t off, FAR const mfs_ctz_s *o_ctz,
              FAR mfs_ctz_s *n_ctz)
{
  int         ret               = OK;
  bool        alloc             = true;
  mfs_t       idx;
  mfs_t       s_off;
  mfs_t       e_off;
  mfs_t       s_idx;
  mfs_t       e_ctz_idx;
  mfs_t       e_buf_idx;
  mfs_t       data_sz;
  mfs_t       n_blks;
  mfs_t       buf_idx           = 0;
  mfs_t       sz;
  mfs_ctz_s   ctz;
  mfs_pgloc_t pg;
  const mfs_t n_pg_buf          = MFS_PGSZ(sb);
  char        pg_buf[n_pg_buf];

  ctz = *o_ctz;

  /* If ctz sz is 0, then page is not written to. */

  if (ctz.sz == 0)
    {
      alloc = false;
    }

  mfs_ctz_idx_from_off(sb, off, &s_off,  &s_idx);
  mfs_ctz_idx_from_off(sb, off + n_buf, &e_off,  &e_buf_idx);
  mfs_ctz_idx_from_off(sb, ctz.sz - 1, NULL, &e_ctz_idx);

  idx = s_idx;

  /* PRE BUFFER (consider s_off) */

  if (s_off != 0)
    {
      memset(pg_buf, 0, n_pg_buf);

      /* Get location in old CTZ. */

      mfs_ctz_travel(sb, e_ctz_idx, &o_ctz->e_pg, s_idx, &pg);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      /* Read entire page. */

      ret = mfs_rw_pgrd(sb, &pg, pg_buf, n_pg_buf);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      /* Allocate new page for update. */

      if (!alloc)
        {
          ret = mfs_alloc_getfreepg(sb, &pg);
          if (predict_false(ret < 0))
            {
              goto errout;
            }

          alloc = true;
        }

      /* Copy the update. */

      data_sz = ctz_idxdatasz(sb, s_idx);
      sz = MFS_MIN(data_sz - s_off, n_buf);
      memcpy(pg_buf + s_off, buf, sz);

      if (sz)
        {
          DEBUGPANIC();
          goto errout;
        }

      idx++;
      buf_idx += sz;
      ctz.sz += sz;
      ctz.e_pg = pg;
    }

  /* BUFFER (neither consider s_off nor e_off) */

  if (e_off != 0 && e_ctz_idx >= e_buf_idx)
    {
      /* We will handle last blk specially as it needs information from
       * old CTZ.
       */

      n_blks = e_buf_idx - idx - 1;
    }
  else
    {
      n_blks = e_buf_idx - idx;
    }

  for (mfs_t i = 0; i < n_blks; i++)
    {
      memset(pg_buf, 0, n_pg_buf);

      /* Allocate new page for udpate. */

      if (!alloc)
        {
          ret = mfs_alloc_getfreepg(sb, &pg);
          if (predict_false(ret < 0))
            {
              goto errout;
            }

          alloc = true;
        }

      ret = apply_ctzptrs(sb, &ctz, idx, pg_buf);
      if (predict_false(ret < 0))
        {
          mfs_alloc_markpgfree(sb, &pg);
          goto errout;
        }

      /* Copy buffer data */

      data_sz = ctz_idxdatasz(sb, idx);
      sz = MFS_MIN(data_sz, n_buf - buf_idx);
      memcpy(pg_buf, buf + buf_idx, sz);

      if (sz)
        {
          DEBUGPANIC();
          goto errout;
        }

      /* Write */

      ret = mfs_rw_pgwr(sb, &pg, pg_buf, n_pg_buf);
      if (predict_false(ret < 0))
        {
          mfs_alloc_markpgfree(sb, &pg);
          goto errout;
        }

      idx++;
      buf_idx += sz;
      ctz.sz += sz;
      ctz.e_pg = pg;
    }

  /* BUFFER (consider e_off) */

  if (e_off != 0 && e_ctz_idx >= e_buf_idx)
    {
      memset(pg_buf, 0, n_pg_buf);

      /* Read old data. */

      ret = mfs_ctz_travel(sb, s_idx, &o_ctz->e_pg, idx, &pg);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      ret = mfs_rw_pgrd(sb, &pg, pg_buf, n_pg_buf);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      /* Allocate new page for udpate. */

      if (!alloc)
        {
          ret = mfs_alloc_getfreepg(sb, &pg);
          if (predict_false(ret < 0))
            {
              goto errout;
            }

          alloc = true;
        }

      ret = apply_ctzptrs(sb, &ctz, idx, pg_buf);
      if (predict_false(ret < 0))
        {
          mfs_alloc_markpgfree(sb, &pg);
          goto errout;
        }

      /* Apply new data */

      data_sz = ctz_idxdatasz(sb, idx);
      sz = MFS_MIN(data_sz, n_buf - buf_idx);
      memcpy(pg_buf, buf + buf_idx, sz);

      if (sz)
        {
          DEBUGPANIC();
          goto errout;
        }

      idx++;
      buf_idx += sz;
      ctz.sz += sz;
      ctz.e_pg = pg;
    }

  /* POST BUFFER */

  if (e_ctz_idx > e_buf_idx)
    {
      n_blks = e_ctz_idx - idx;

      for (mfs_t i = 0; i < n_blks; i++)
        {
          ret = mfs_ctz_travel(sb, s_idx, &o_ctz->e_pg, idx, &pg);
          if (predict_false(ret < 0))
            {
              goto errout;
            }

          ret = mfs_rw_pgrd(sb, &pg, pg_buf, n_pg_buf);
          if (predict_false(ret < 0))
            {
              goto errout;
            }

          if (!alloc)
            {
              ret = mfs_alloc_getfreepg(sb, &pg);
              if (predict_false(ret < 0))
                {
                  goto errout;
                }

              alloc = true;
            }

          ret = apply_ctzptrs(sb, &ctz, idx, pg_buf);
          if (predict_false(ret < 0))
            {
              mfs_alloc_markpgfree(sb, &pg);
              goto errout;
            }

          idx++;
          buf_idx += n_pg_buf;
          ctz.sz  += n_pg_buf;
          ctz.e_pg = pg;
        }
    }

  *n_ctz = ctz;
  return OK;

  /* NOTE: This does NOT update the journal. */

errout:

  /* TODD: To be safe, mark for free all the pages allocated. */

  return ret;
}

int
mfs_ctz_rdoff(FAR mfs_sb_s *sb, FAR char *buf, mfs_t n_buf, const mfs_t off,
              FAR const mfs_ctz_s *ctz)
{
  int         ret     = OK;
  mfs_t       idx;
  mfs_t       s_idx;
  mfs_t       buf_idx = 0;
  mfs_t       n_ptrs;
  mfs_t       rem;
  mfs_t       sz;
  mfs_bloc_t  b;
  mfs_pgloc_t pg;

  mfs_ctz_idx_from_off(sb, ctz->sz - 1, &b.pg_off, &s_idx);
  mfs_ctz_idx_from_off(sb, off, &b.pg_off, &idx);

  /* TODO: Read in opposite, this will save search time. */

  while (buf_idx < n_buf)
    {
      ret = mfs_ctz_travel(sb, s_idx, &ctz->e_pg, idx, &pg);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      b.blk     = pg.blk;
      b.blk_off = pg.blk_off;

      n_ptrs = ctz_idx_nptrs(n_ptrs);
      sz     = ctz_idxdatasz(sb, idx);

      if (rem <= sz)
        {
          ret      = mfs_rw_pgrdoff(sb, &b, buf + buf_idx, rem);
          buf_idx += rem;
          rem      = 0;
        }
      else
        {
          ret      = mfs_rw_pgrdoff(sb, &b, buf + buf_idx, sz);
          buf_idx += sz;
          rem     -= sz;
        }

      if (predict_false(ret < 0))
        {
          goto errout;
        }

      idx++;
      b.pg_off = 0; /* Only valid for first page that's read in CTZ. */
    }

  return OK;

errout:
  return ret;
}

void
mfs_ctz_off2idx(FAR const mfs_sb_s *sb, const mfs_t off, FAR mfs_t *idx,
                FAR mfs_t *pgoff)
{
  mfs_t       _idx;
  const mfs_t wb  = sizeof(mfs_t);
  const mfs_t den = MFS_PGSZ(sb) - 2 * wb;

  if (off < den)
    {
      *idx = 0;
      *pgoff = off;
      return;
    }

  if (predict_true(idx != NULL))
    {
      _idx   = (off - wb * (popcnt((off / den) - 1) + 2)) / den;
      *idx   = _idx;
    }

  if (predict_true(idx != NULL && pgoff != NULL))
    {
      *pgoff = off
               - den * (_idx)
               - (wb * popcnt(_idx))
               - ((ctz_idx_nptrs(_idx) * wb));
    }
}
