/****************************************************************************
 * fs/mnemofs_new/mnemofs_rw.c
 * Raw rw functions for mnemofs.
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

#include <assert.h>
#include <nuttx/compiler.h>
#include <stdbool.h>
#include <nuttx/mtd/mtd.h>
#include <string.h>

#include "mnemofs.h"

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

int
mfs_rw_isbad(FAR const mfs_sb_s * sb, mfs_t blk)
{
  if (predict_false(blk > MFS_NBLKS(sb)))
    {
      return -EINVAL;
    }

  return MTD_ISBAD(MFS_MTD(sb), blk);
}

int
mfs_rw_markbad(FAR mfs_sb_s * sb, mfs_t blk)
{
  mfs_t pg;

  if (predict_false(blk > MFS_NBLKS(sb)))
    {
      return -EINVAL;
    }

  pg = blk * MFS_PGINBLK(sb);

  if (MFS_RW(sb).wr_pg == pg)
    {
      MFS_RW(sb).wr_pg = 0;
    }
  else if (MFS_RW(sb).rd_pg == pg)
    {
      MFS_RW(sb).rd_pg = 0;
    }

  return MTD_MARKBAD(MFS_MTD(sb), blk);
}

int
mfs_rw_pgrdoff(FAR mfs_sb_s * sb, FAR const mfs_bloc_t *b, FAR char *buf,
               const mfs_t n_buf)
{
  int   ret      = OK;
  mfs_t page;
  mfs_pgloc_t pg;

  pg.blk     = b->blk;
  pg.blk_off = b->blk_off;
  page       = mfs_util_pgloc_to_pg(sb, &pg);
  if (page >= sb->n_blks * sb->n_pg_in_blk)
    {
      ret = -EINVAL;
      goto errout;
    }

  DEBUGASSERT(MFS_RW(sb).rd_pg == 0 || MFS_RW(sb).wr_pg == 0 ||
              (MFS_RW(sb).rd_pg != MFS_RW(sb).wr_pg));

  if (page != MFS_RW(sb).rd_pg)
    {
      ret  = MTD_BREAD(MFS_MTD(sb), page, 1, MFS_RW(sb).rd_buf);
      if (ret != 0)
        {
          goto errout;
        }

      MFS_RW(sb).rd_pg = page;
    }

  memcpy(buf + b->pg_off, MFS_RW(sb).rd_buf,
         MFS_MIN(n_buf, MFS_PGSZ(sb) - b->pg_off));

errout:
  return ret;
}

int
mfs_rw_pgrd(FAR mfs_sb_s * sb, FAR const mfs_pgloc_t *pg, FAR char *buf,
            const mfs_t n_buf)
{
  mfs_bloc_t b;

  b.blk     = pg->blk;
  b.blk_off = pg->blk_off;
  b.pg_off  = 0;

  return mfs_rw_pgrdoff(sb, &b, buf, n_buf);
}

int
mfs_rw_pgwroff(FAR mfs_sb_s * sb, FAR const mfs_bloc_t *b,
               FAR const char *buf, const mfs_t n_buf)
{
  int   ret      = OK;
  mfs_t page;
  mfs_pgloc_t pg;

  pg.blk     = b->blk;
  pg.blk_off = b->blk_off;

  page       = mfs_util_pgloc_to_pg(sb, &pg);
  if (page >= MFS_NBLKS(sb) * MFS_PGINBLK(sb))
    {
      ret = -EINVAL;
      goto errout;
    }

  DEBUGASSERT(MFS_RW(sb).rd_pg == 0 || MFS_RW(sb).wr_pg == 0 ||
              (MFS_RW(sb).rd_pg != MFS_RW(sb).wr_pg));

  if (page != MFS_RW(sb).wr_pg)
    {
      ret  = MTD_BWRITE(MFS_MTD(sb), page, 1, MFS_RW(sb).wr_buf);
      if (ret != 0)
        {
          goto errout;
        }

      MFS_RW(sb).wr_pg = page;
    }

  memcpy(MFS_RW(sb).wr_buf + b->pg_off, buf,
         MFS_MIN(n_buf, MFS_PGSZ(sb) - b->pg_off));

errout:
  return ret;
}

int
mfs_rw_pgwr(FAR mfs_sb_s * sb, FAR const mfs_pgloc_t *pg,
            FAR const char *buf, const mfs_t n_buf)
{
  mfs_bloc_t b;

  b.blk     = pg->blk;
  b.blk_off = pg->blk_off;
  b.pg_off  = 0;

  return mfs_rw_pgwroff(sb, &b, buf, n_buf);
}

int
mfs_rw_blkerase(FAR mfs_sb_s * sb, const mfs_t blk)
{
  mfs_t pg;

  if (predict_false(blk > MFS_NBLKS(sb)))
    {
      return -EINVAL;
    }

  pg = blk * MFS_PGINBLK(sb);

  if (MFS_RW(sb).wr_pg == pg)
    {
      MFS_RW(sb).wr_pg = 0;
    }
  else if (MFS_RW(sb).rd_pg == pg)
    {
      MFS_RW(sb).rd_pg = 0;
    }

  return MTD_ERASE(MFS_MTD(sb), blk, 1);
}
