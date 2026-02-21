/****************************************************************************
 * fs/mnemofs_new/mnemofs_new_rw.c
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

#include <nuttx/config.h>

#include <sys/types.h>
#include <sys/statfs.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <debug.h>

#include <nuttx/kmalloc.h>
#include <nuttx/fs/fs.h>
#include <nuttx/fs/ioctl.h>
#include <nuttx/mtd/mtd.h>

#include "fs_heap.h"
#include "mnemofs_new.h"

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

int mfs_new_bad_blk_check(FAR const struct mfs_new_sb_s * const sb, mfs_t blk)
{
  if (!mfs_new_blk_range_check(sb, blk))
    {
      return -EINVAL;
    }

  return MTD_ISBAD(mfs_new_mtd(sb), blk);
}

int mfs_new_bad_blk_mark(FAR const struct mfs_new_sb_s * const sb, mfs_t blk)
{
  if (!mfs_new_blk_range_check(sb, blk))
    {
      return -EINVAL;
    }

  return MTD_MARKBAD(mfs_new_mtd(sb), blk);
}

ssize_t mfs_new_wr_pg(FAR const struct mfs_new_sb_s * const sb, mfs_t blk, mfs_t pg,
                       FAR const char *data, const size_t size)
{
  int ret = OK;
  mfs_t abs_pg;

  MFS_NEW_TRACE_LOG("Entry");

  if (!mfs_new_blk_range_check(sb, blk))
    {
      ret = -EINVAL;
      MFS_NEW_TRACE_LOG("Block out of range. Blk: %d, Total Blocks: %d", blk, mfs_new_n_blk(sb));
      goto errout;
    }

  if (!mfs_new_pg_range_check(sb, pg))
    {
      ret = -EINVAL;
      MFS_NEW_TRACE_LOG("Page out of range. Page: %d, Total Pages in Block: %d", pg, mfs_new_n_pg_in_blk(sb));
      goto errout;
    }

  /* Calculate absolute page location. */

  abs_pg = 0;
  abs_pg += mfs_new_n_pg_in_blk(sb) * blk;

  // Multiplication Overflow check

  if (mfs_new_n_pg_in_blk(sb) != 0 &&
      abs_pg / mfs_new_n_pg_in_blk(sb) != blk)
    {
      ret = -EINVAL;
      MFS_NEW_TRACE_LOG("Page location out of representation limits. Page (In Block): %d, Block: %d, N Pages Per Block: %d", pg, blk, mfs_new_n_pg_in_blk(sb));
      goto errout;
    }

  if (abs_pg > UINT32_MAX - pg)
    {
      ret = -EINVAL;
      MFS_NEW_TRACE_LOG("Page location out of representation limits. Page (In Block): %d, Block: %d, N Pages Per Block: %d", pg, blk, mfs_new_n_pg_in_blk(sb));
      goto errout;
    }

  memcpy(mfs_new_rw_buff(sb), data, mfs_new_pg_sz(sb));
  MFS_NEW_TRACE_LOG("Copied data %p to RW buffer %p", data, mfs_new_rw_buff(sb));

  ret = MTD_BWRITE(mfs_new_mtd(sb), abs_pg, 1, mfs_new_rw_buff(sb));
  if (predict_false(ret < 0))
    {
      MFS_NEW_TRACE_LOG("Could not write to absolute page '%d'. Return code: %d", abs_pg, ret);
      goto errout_with_reset;
    }

errout_with_reset:
    memset(mfs_new_rw_buff(sb), 0, mfs_new_pg_sz(sb));

errout:
  MFS_NEW_TRACE_LOG("Exit | Ret: %d", ret);
  return ret;
}

ssize_t mfs_new_rd_pg(FAR const struct mfs_new_sb_s * const sb, mfs_t blk, mfs_t pg,
                       FAR char * const data)
{
  int ret = OK;
  mfs_t abs_pg;

  MFS_NEW_TRACE_LOG("Entry");

  if (!mfs_new_blk_range_check(sb, blk))
    {
      ret = -EINVAL;
      MFS_NEW_LOG("Block out of range. Blk: %d, Total Blocks: %d", blk, mfs_new_n_blk(sb));
      goto errout;
    }

  if (!mfs_new_pg_range_check(sb, pg))
    {
      ret = -EINVAL;
      MFS_NEW_LOG("Page out of range. Page: %d, Total Pages in Block: %d", pg, mfs_new_n_pg_in_blk(sb));
      goto errout;
    }

  /* Calculate absolute page location. */

  abs_pg = 0;
  abs_pg += mfs_new_n_pg_in_blk(sb) * blk;

  // Multiplication Overflow check

  if (mfs_new_n_pg_in_blk(sb) != 0 &&
      abs_pg / mfs_new_n_pg_in_blk(sb) != blk)
    {
      ret = -EINVAL;
      MFS_NEW_LOG("Page location out of representation limits. Page (In Block): %d, Block: %d, N Pages Per Block: %d", pg, blk, mfs_new_n_pg_in_blk(sb));
      goto errout;
    }

  if (abs_pg > UINT32_MAX - pg)
    {
      ret = -EINVAL;
      MFS_NEW_LOG("Page location out of representation limits. Page (In Block): %d, Block: %d, N Pages Per Block: %d", pg, blk, mfs_new_n_pg_in_blk(sb));
      goto errout;
    }

  ret = MTD_BREAD(mfs_new_mtd(sb), abs_pg, 1, mfs_new_rw_buff(sb));
  if (predict_false(ret < 0))
    {
      MFS_NEW_LOG("Could not read from absolute page '%d'. Return code: %d", abs_pg, ret);
      goto errout_with_reset;
    }

  memcpy(data, mfs_new_rw_buff(sb), mfs_new_pg_sz(sb));
  MFS_NEW_TRACE_LOG("Copied data %p from RW buffer %p", data, mfs_new_rw_buff(sb));

errout_with_reset:
  memset(mfs_new_rw_buff(sb), 0, mfs_new_pg_sz(sb));

errout:
  MFS_NEW_TRACE_LOG("Exit | Ret: %d", ret);
  return ret;
}

ssize_t mfs_new_erase_blk(FAR const struct mfs_new_sb_s * const sb, mfs_t blk)
{
  return mfs_new_erase_blks_n(sb, blk, 1);
}

ssize_t mfs_new_erase_blks_n(FAR const struct mfs_new_sb_s * const sb, const off_t blk,
                            const size_t n)
{
  if (!mfs_new_blk_range_check(sb, blk) || !mfs_new_blk_range_check(sb, blk + n - 1))
    {
      MFS_NEW_TRACE_LOG("Invalid erase for block %d and number %d. Available blocks %d.", blk, n, mfs_new_n_blk(sb));
      return -EINVAL;
    }

  return (MTD_ERASE(mfs_new_mtd(sb), blk, n) == n) ? 0 : -EINVAL;
}

// TODO: The functions above read one page at a time. Write a function that reads across pages
// and from offsets.
