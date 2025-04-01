/****************************************************************************
 * fs/mnemofs_new/mnemofs_mb.c
 * Master block functions for mnemofs.
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

static void ser_mn(FAR char *buf, FAR const mfs_ctz_s *root);

static int deser_mn(FAR const char *buf, FAR mfs_ctz_s *root);

static int rd_mn(FAR const mfs_sb_s *sb, FAR const mfs_pgloc_t *pg,
                 FAR mfs_ctz_s *root);

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
 * Name: ser_mn
 *
 * Description:
 *   Serialize master node.
 *
 * Input Parameters:
 *   buf  - Buffer to serialize to.
 *   root - Root CTZ
 *
 ****************************************************************************/

static void
ser_mn(FAR char *buf, FAR const mfs_ctz_s *root)
{
  mfs_t mb_magic;
  mfs_t mb_chksm;
  mfs_t mn_chksm;

  mb_magic = MFS_MB_MAGIC;
  mb_chksm = MFS_MB_CHKSM;

  memcpy(buf +  0, &mb_magic,  4);
  memcpy(buf +  4, &mb_chksm,  4);
  memcpy(buf +  8, root     , 12);

  mn_chksm = mfs_calc_chksm(buf, 20);
  memcpy(buf + 20, &mn_chksm,  4);
}

/****************************************************************************
 * Name: deser_mn
 *
 * Description:
 *   Deserialize master node.
 *
 * Input Parameters:
 *   buf  - Buffer to deserialize from.
 *   root - Root CTZ
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if not.
 *
 ****************************************************************************/

static int
deser_mn(FAR const char *buf, FAR mfs_ctz_s *root)
{
  int       ret       = OK;
  mfs_t     mb_magic;
  mfs_t     mb_chksm;
  mfs_t     mn_chksm;
  mfs_t     _mn_chksm;
  mfs_ctz_s _root;

  memcpy(&mb_magic, buf +  0,  4);
  memcpy(&mb_chksm, buf +  4,  4);
  memcpy(&_root   , buf +  8, 12);

  _mn_chksm = mfs_calc_chksm(buf, 20);
  memcpy(&mn_chksm, buf + 20,  4);

  if (mb_magic != MFS_MB_MAGIC || mb_chksm != MFS_MB_CHKSM ||
      mn_chksm != _mn_chksm)
    {
      ret = -EINVAL;
      goto errout;
    }

  if (root != NULL)
    {
      *root = _root;
    }

errout:
  return ret;
}

/****************************************************************************
 * Name: rd_mn
 *
 * Description:
 *   Read a master node entry.
 *
 * Input Parameters:
 *   sb   - Superblock
 *   pg   - Page location of master node
 *   root - Root CTZ
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if not.
 *
 ****************************************************************************/

static int
rd_mn(FAR const mfs_sb_s *sb, FAR const mfs_pgloc_t *pg, FAR mfs_ctz_s *root)
{
  int         ret         = OK;
  const mfs_t n_buf       = MFS_MN_SZ;
  char        buf[n_buf];

  memset(buf, 0, n_buf);

  ret = mfs_rw_pgrd(sb, pg, buf, n_buf);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  ret = deser_mn(buf, root);

errout:
  return ret;
}

/****************************************************************************
 * Name: fmt_with_root
 *
 * Description:
 *   Format master nodes with a specific root being the first entry.
 *
 * Input Parameters:
 *   sb   - Superblock
 *   mb1  - Master block 1
 *   mb2  - Master block 2
 *   root - Root CTZ
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if not.
 *
 ****************************************************************************/

static int
fmt_with_root(FAR mfs_sb_s *sb, const mfs_t mb1, const mfs_t mb2,
              FAR const mfs_ctz_s *root)
{
  int         ret   = OK;
  mfs_pgloc_t pg;
  const mfs_t n_buf = MFS_MN_SZ;
  char        buf[n_buf];

  memset(buf, 0, n_buf);

  DEBUGASSERT(root != NULL);

  ser_mn(buf, root);

  /* Block 1 */

  pg.blk     = mb1;
  pg.blk_off = 0;
  ret        = mfs_rw_pgwr(sb, &pg, buf, n_buf);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  /* Block 2 */

  pg.blk     = mb2;
  ret        = mfs_rw_pgwr(sb, &pg, buf, n_buf);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  MFS_MB(sb).mb1      = mb1;
  MFS_MB(sb).mb2      = mb2;
  MFS_MB(sb).next_idx = 1;

errout:
  return ret;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int
mfs_mb_fmt(FAR mfs_sb_s *sb, const mfs_t mb1, const mfs_t mb2)
{
  int         ret         = OK;
  mfs_ctz_s   root;

  root.sz = 0;
  ret     = mfs_alloc_getfreepg(sb, &root.e_pg);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  ret = fmt_with_root(sb, mb1, mb2, &root);

errout:
  return ret;
}

int
mfs_mb_init(FAR mfs_sb_s *sb, const mfs_t mb1, const mfs_t mb2)
{
  int ret = 0;
  mfs_t idx = 0;
  mfs_pgloc_t pg;

  while (idx < MFS_PGINBLK(sb))
    {
      pg.blk     = mb1;
      pg.blk_off = idx;

      ret        = rd_mn(sb, &pg, NULL);
      if (predict_false(ret < 0))
        {
          pg.blk = mb2;
          ret    = rd_mn(sb, &pg, NULL);

          if (predict_false(ret < 0))
            {
              break;
            }
        }

      idx++;
    }

  DEBUGASSERT(idx != 0);

  MFS_MB(sb).mb1      = mb1;
  MFS_MB(sb).mb2      = mb2;
  MFS_MB(sb).next_idx = idx;

  return 0;
}

int
mfs_mb_rd(FAR const mfs_sb_s *sb, FAR mfs_ctz_s *root)
{
  int ret = OK;
  mfs_pgloc_t pg;
  const mfs_t n_buf = MFS_MN_SZ;
  char buf[n_buf];
  mfs_ctz_s _root;

  memset(buf, 0, n_buf);

  DEBUGASSERT(MFS_MB(sb).next_idx != 0);

  pg.blk_off = MFS_MB(sb).next_idx - 1;
  pg.blk     = MFS_MB(sb).mb1;

  ret = rd_mn(sb, &pg, &_root);
  if (predict_false(ret < 0))
    {
      /* Try second copy of root in MB 2. */

      pg.blk = MFS_MB(sb).mb2;
      ret = rd_mn(sb, &pg, &_root);
      if (predict_false(ret < 0))
        {
          goto errout;
        }
    }

  *root = _root;
  return OK;

errout:
  return ret;
}

int
mfs_mb_wr(FAR mfs_sb_s *sb, FAR const mfs_ctz_s *ctz)
{
  int ret1 = OK;
  int ret2 = OK;
  const mfs_t n_buf = MFS_MN_SZ;
  char buf[n_buf];
  mfs_pgloc_t pg;

  if (mfs_mb_isfull(sb))
    {
      /* TODO: Signals journal flush, but it should have already happened
       * before this point.
       */

      ret1 = -EINVAL; /* Temporary */
      goto errout;
    }

  memset(buf, 0, n_buf);
  ser_mn(buf, ctz);

  /* MB 1 */

  pg.blk     = MFS_MB(sb).mb1;
  pg.blk_off = MFS_MB(sb).next_idx;

  ret1 = mfs_rw_pgwr(sb, &pg, buf, n_buf);

  /* MB 2 */

  pg.blk      = MFS_MB(sb).mb2;
  ret2 = mfs_rw_pgwr(sb, &pg, buf, n_buf);

  if (ret1 != OK && ret2 != OK)
    {
      return ret1;
    }
  else if (ret1 != OK)
    {
      return ret1;
    }
  else if (ret2 != OK)
    {
      return ret2;
    }
  else
    {
      return OK;
    }

errout:
  return ret1;
}

bool
mfs_mb_isfull(FAR mfs_sb_s *sb)
{
  return MFS_MB(sb).next_idx == MFS_PGINBLK(sb);
}

int
mfs_mb_flush(FAR mfs_sb_s *sb, FAR const mfs_ctz_s *ctz)
{
  int   ret = OK;
  mfs_t mb1;
  mfs_t mb2;

  if (!mfs_mb_isfull(sb))
    {
      /* In case the call happens without checking. */

      goto errout;
    }

  ret = mfs_mb_allocblks(sb, &mb1, &mb2);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  ret = fmt_with_root(sb, mb1, mb2, ctz);
  if (predict_false(ret < 0))
    {
      mfs_mb_freeblks(sb, mb1, mb2);
      goto errout;
    }

errout:
  return ret;
}

int
mfs_mb_allocblks(FAR mfs_sb_s *sb, FAR mfs_t *mb1, FAR mfs_t *mb2)
{
  int ret = OK;

  ret = mfs_alloc_getfreeblk(sb, mb1);
  if (ret < 0)
    {
      *mb1 = 0;
      *mb2 = 0;
      goto errout;
    }

  ret = mfs_alloc_getfreeblk(sb, mb2);
  if (ret < 0)
    {
      *mb2 = 0;
      goto errout_with_mb1;
    }

  return OK;

errout_with_mb1:
  mfs_alloc_markblkfree(sb, *mb1);
  *mb2 = 0;

errout:
  *mb1 = 0;
  return ret;
}

int
mfs_mb_freeblks(FAR mfs_sb_s *sb, FAR const mfs_t mb1, FAR const mfs_t mb2)
{
  int ret = OK;

  if (mb1 != 0)
    {
      ret = mfs_alloc_markblkfree(sb, mb1);
      if (ret < 0)
        {
          goto errout;
        }
    }

  if (mb2 != 0)
    {
      ret = mfs_alloc_markblkfree(sb, mb2);
      if (ret < 0)
        {
          goto errout;
        }
    }

errout:
  return ret;
}
