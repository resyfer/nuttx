/****************************************************************************
 * fs/mnemofs_new/mnemofs_jrnl.c
 * Journal functions for mnemofs.
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
#include <cerrno>
#include <nuttx/fs/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

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

static int jrnl_mv(FAR mfs_sb_s *sb);
static bool is_new_blk_req(FAR mfs_sb_s *sb);
static int add_blk(FAR mfs_sb_s *sb);
static bool is_log_blk(FAR mfs_sb_s *sb, FAR const mfs_pgloc_t *pg);

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
 * Name: jrnl_mv
 *
 * Description:s
 *   Move the journal when it's time to flush.
 *
 * Input Parameters:
 *   sb - Superblock
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if not.
 *
 * Assumptions/Limitations:
 *   - The journal needs to be full.
 *   - If the journal is full AND the master node is full, then this function
 *     should FOLLOW master block move.
 *
 ****************************************************************************/

static int
jrnl_mv(FAR mfs_sb_s *sb)
{
  /* TODO */

  return 0;
}

/****************************************************************************
 * Name: jrnl_fmt_pg0
 *
 * Description:
 *   Format the page 0 of a journal.
 *
 * Input Parameters:
 *   sb - Superblock
 *   pg - Page 0 of the journal
 *   mb1 - Master Block 1
 *   mb2 - Master Block 2
 *   rev - Revision
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if not.
 *
 * Assumptions/Limitations:
 *   - This is used during the process of formatting a new journal.
 *
 ****************************************************************************/

static int
jrnl_fmt_pg0(FAR mfs_sb_s *sb, FAR mfs_pgloc_t *pg, const mfs_t mb1,
             const mfs_t mb2, const mfs_t rev)
{
  int ret = OK;
  const mfs_t n_buf = 80;
  char buf[n_buf];

  memset(buf, 0, n_buf);

  sprintf(buf, "%08X%08X" \
               "%08X%08X" \
               "%08X%08X" \
               "%08X%08X" \
               "%08X%08X",
               MFS_JRNL_MAGIC, MFS_JRNL_CHKSM,
               rev, MFS_BLKSZ(sb),
               sb->n_blks, MFS_PGINBLK(sb),
               mb1, mb2,
               MFS_JRNL_MAGIC, MFS_JRNL_CHKSM);

  ret = mfs_rw_pgwr(sb, pg, buf, n_buf);

  return ret;
}

/****************************************************************************
 * Name: get_jrnl_rev
 *
 * Description:
 *   Get the revision number of a journal once its location has been
 *   identified.
 *
 * Input Parameters:
 *   sb - Superblock
 *   blk - Journal header block.
 *   rev - Revision
 *
 * Returned Value:
 *   - 0 if OK
 *   - 1 if not a valid journal block.
 *   - negative if errors.
 *
 * Assumptions/Limitations:
 *   - This is used during the process of initializing journal.
 *
 ****************************************************************************/

static int
get_jrnl_rev(FAR mfs_sb_s *sb, const mfs_t blk, FAR mfs_t *rev)
{
  int ret = OK;
  mfs_pgloc_t pg;
  mfs_t magic1;
  mfs_t chksm1;
  mfs_t magic2;
  mfs_t chksm2;
  const mfs_t n_buf = 80;
  char buf[n_buf];
  mfs_t _rev;

  pg.blk = blk;
  pg.blk_off = 0;

  memset(buf, 0, n_buf);

  ret = mfs_rw_pgrd(sb, &pg, buf, n_buf);
  if (ret < 0)
    {
      goto errout;
    }

  sscanf(buf + 0, "%08X", &magic1);
  sscanf(buf + 8, "%08X", &chksm1);
  sscanf(buf + 16, "%08X", &_rev);
  sscanf(buf + 64, "%08X", &magic2);
  sscanf(buf + 72, "%08X", &chksm2);

  if (magic1 == MFS_JRNL_MAGIC && chksm1 == MFS_JRNL_CHKSM &&
    magic2 == MFS_JRNL_MAGIC && chksm2 == MFS_JRNL_CHKSM)
    {
      ret = 1;
      goto errout;
    }

  *rev = _rev;

  return OK;

errout:
  return ret;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int
mfs_jrnl_rd(FAR const mfs_sb_s *sb, char *buf, mfs_t n_buf,
            FAR const mfs_ctz_s *ctz)
{
  /* TODO */

  return 0;
}

int
mfs_jrnl_wr(FAR mfs_sb_s *sb, FAR const char *buf, mfs_t n_buf,
            FAR mfs_ctz_s *ctz)
{
  /* TODO */

  return 0;
}

bool
mfs_jrnl_isflushreq(FAR mfs_sb_s *sb, mfs_t new_log_sz)
{
  /* Logs are appended by a byte-long checksum, so (new_log_sz + 1) */

  /* TODO */

  return false;
}

/* The journal contains logs with just old CTZ, new CTZ, and parent's CTZ
 * at the time of writing the log. Following this, each log is appended
 * by a checksum of the log. Total this will be 32 bytes.
 *
 * Multiple logs are present in a block, and there is a mechanism to group
 * logs in memory before writing them. Worst case scenario, we have a power
 * failure and we lose a page worth of logs.
 *
 * The journal will be traversed with the assumption that every parent
 * in the actual fs tree doesn't know about any update to its children. So,
 * logs will be flushed according to depth and parent.
 *
 * When the journal is going through the first flush iteration and log with
 * highest depth is noted. Once we know the highest depth of change, we
 * find its siblings according to depth and parent. Siblings have same
 * depth and parent. Once we find the updated siblings, we update the
 * parent with the updated locations of its children, and then add a log
 * in the journal to mark the new parent's location.
 *
 * If we have multiple logs with same depth but different parent, we do
 * the same process for them as well. This is what I call the horizontal
 * movement.
 *
 * Now we iterate the journal again for a depth less than previous, and
 * perform the same action on every log. One of these logs will be the
 * parent we had updated previously. I call this the vertical movement.
 *
 * We go on till the depth eventually becomes 0 and we have reached the
 * root. Since we know root has no sibling, and has no parent, we update
 * the "parent of root" by writing a new master block to both master nodes.
 * This will effectively shift the entire file system. Since we have
 * written the update, the file system will effectively shift.
 *
 * The master node is full before we can add it, then new master blocks
 * will be written, and a new empty journal is written with the updated
 * master block location and updated time stamp.
 *
 * If the master node is not full, a new empty journal is written but with
 * the same master block locations.
 *
 * Once this is done, then the new file system is effectively the updated
 * file system. The time stamp on journal ensures no ambiguity during
 * initialization, and it's the duty of the initialization process to use
 * the latest one.
 *
 * The allocator is then signalled to erase any block it can erase as we
 * no longer need the old file system present on the device. It's fine if
 * there is a powerloss before the erase happens as we put timestamps on
 * the journal. Once the journal is determined, the entire file system is
 * determined.
 *
 * Since the flush operation puts more logs, there is a page in journal
 * header reserved to serve as a pointer to another block that contains
 * more block numbers for log blocks.
 */

int
mfs_jrnl_clearold(FAR mfs_sb_s *sb, const mfs_t o_blk)
{
  int ret = OK;

  /* TODO */

  /* This is used when we see multiple (at max 2) instances of journal
   * on the device, and we want to remove the older one.
   */

  return OK;
}

int
mfs_jrnl_fmt(FAR mfs_sb_s *sb)
{
  int ret = OK;
  mfs_t jrnl_hd;
  mfs_t mb1;
  mfs_t mb2;
  mfs_pgloc_t jrnl_pg0;
  const mfs_t log_sz = 32;

  ret = mfs_alloc_getfreeblk(sb, &mb1);
  if (ret < 0)
    {
      goto errout;
    }

  ret = mfs_alloc_getfreeblk(sb, &mb2);
  if (ret < 0)
    {
      goto errout_with_mb1;
    }

  ret = mfs_alloc_getfreeblk(sb, &jrnl_hd);
  if (ret < 0)
    {
      goto errout_with_mb2;
    }

  jrnl_pg0.blk = jrnl_hd;
  jrnl_pg0.blk_off = 0;

  /* Format the master blocks. */

  ret = mfs_mb_fmt(sb, mb1, mb2);
  if (ret < 0)
    {
      goto errout_with_mb2;
    }

  /* Write the first page of the journal */

  ret = jrnl_fmt_pg0(sb, &jrnl_pg0, mb1, mb2, 0);
  if (ret < 0)
    {
      goto errout_with_jrnl_hd;
    }

  MFS_JRNL(sb).n_blks = MFS_JRNL_NBLKS;
  MFS_JRNL(sb).n_logs = 0;
  MFS_JRNL(sb).jrnl_hd = jrnl_hd;
  MFS_JRNL(sb).t_logs = (MFS_JRNL(sb).n_blks * MFS_BLKSZ(sb)) / log_sz;
  MFS_JRNL(sb).rev = 0;

  return OK;

errout_with_jrnl_hd:
  mfs_alloc_markblkfree(sb, jrnl_hd);

errout_with_mb2:
  mfs_alloc_markblkfree(sb, mb2);

errout_with_mb1:
  mfs_alloc_markblkfree(sb, mb1);

errout:
  return ret;
}

int
mfs_jrnl_latest(FAR mfs_sb_s *sb, FAR mfs_t *blk, FAR mfs_t *rev)
{
  int ret = OK;
  mfs_t latest_rev = 0;
  mfs_t latest_blk = 0; /* Blk 0 is reserved so this is safe. */
  mfs_t _rev = 0;

  for (mfs_t b = 0; b < sb->n_blks; b++)
    {
      ret = get_jrnl_rev(sb, b, &_rev);
      if (ret != OK)
        {
          continue;
        }

      if (latest_blk != 0 && latest_rev + 1 == _rev)
        {
          /* This means rev is the latest one. So we clear the old
           * and update.
           */

          ret = mfs_jrnl_clearold(sb, latest_blk);
          if (ret == OK)
            {
              latest_blk = b;
              latest_rev = _rev;
            }
        }

      _rev = 0;
    }

  *blk = latest_blk;
  *rev = _rev;

  if (latest_blk == 0)
    {
      return -EINVAL;
    }
  else
    {
      return OK;
    }
}

int
mfs_jrnl_init(FAR mfs_sb_s *sb, mfs_t blk, mfs_t rev)
{
  int ret = OK;
  mfs_t magic1;
  mfs_t chksm1;
  mfs_t magic2;
  mfs_t chksm2;
  mfs_t mb1;
  mfs_t mb2;
  mfs_t _rev;
  mfs_t blk_sz;
  mfs_t n_blks;
  mfs_t pg_in_blk;
  const mfs_t n_buf = 80;
  char buf[n_buf];
  mfs_pgloc_t pg;

  /* We should have already verified that the journal header has proper
   * ending magic and checksum by now by getting the block number and
   * the revision.
   */

  memset(buf, 0, n_buf);

  pg.blk = blk;
  pg.blk_off = 0;
  ret = mfs_rw_pgrd(sb, &pg, buf, n_buf);
  if (ret < 0)
    {
      goto errout;
    }

  sscanf(buf, "%08X%08X" \
              "%08X%08X" \
              "%08X%08X" \
              "%08X%08X" \
              "%08X%08X",
              &magic1, &chksm1,
              &_rev, &blk_sz,
              &n_blks, &pg_in_blk,
              &mb1, &mb2,
              &magic2, &chksm2);

  DEBUGASSERT(magic1 == MFS_JRNL_MAGIC);
  DEBUGASSERT(chksm1 == MFS_JRNL_CHKSM);
  DEBUGASSERT(_rev == rev);
  DEBUGASSERT(blk_sz == MFS_BLKSZ(sb));
  DEBUGASSERT(n_blks == sb->n_blks);
  DEBUGASSERT(pg_in_blk == MFS_PGINBLK(sb));
  DEBUGASSERT(magic2 == MFS_JRNL_MAGIC);
  DEBUGASSERT(chksm2 == MFS_JRNL_CHKSM);

  sb->mb1 = mb1;
  sb->mb2 = mb2;

  return OK;

errout:
  return ret;
}
