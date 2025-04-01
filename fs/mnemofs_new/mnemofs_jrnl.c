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
#include <nuttx/compiler.h>
#include <nuttx/fs/fs.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "fs_heap.h"
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

static void ser_jrnl_log(FAR char *buf, FAR const mfs_ctz_s *o_ctz,
                         FAR const mfs_ctz_s *n_ctz,
                         FAR const mfs_ctz_s *p_ctz, FAR const mfs_t depth);

static int deser_jrnl_log(FAR const char *buf, FAR mfs_ctz_s *o_ctz,
                          FAR mfs_ctz_s *n_ctz, FAR mfs_ctz_s *p_ctz,
                          FAR mfs_t *depth);

static void ser_jrnl_blkentry(FAR char *buf, const mfs_t blk);

static int deser_jrnl_blkentry(FAR const char *buf, FAR mfs_t *blk);

/* Normal */

static int jrnl_log_wr(FAR mfs_sb_s *sb, FAR const mfs_ctz_s *o_ctz,
                       FAR const mfs_ctz_s *n_ctz,
                       FAR const mfs_ctz_s *p_ctz, FAR const mfs_t depth);

static int jrnl_log_rd(FAR mfs_sb_s *sb, const mfs_t log_idx,
                       FAR mfs_ctz_s *o_ctz, FAR mfs_ctz_s *n_ctz,
                       FAR mfs_ctz_s *p_ctz, FAR mfs_t *depth);

static int jrnl_blk_add(FAR mfs_sb_s *sb, FAR mfs_t *blk);

static int jrnl_blk_entry_rd(FAR mfs_sb_s *sb, const mfs_t idx,
                             FAR mfs_t *blk);

static int jrnl_blk_entry_wr(FAR mfs_sb_s *sb, const mfs_t blk);

static int jrnl_fmt_pg0(FAR mfs_sb_s *sb, FAR const mfs_pgloc_t *hdr,
                        const mfs_t mb1, const mfs_t mb2, const mfs_t rev);

static int get_jrnl_rev_frm_dev(FAR mfs_sb_s *sb, const mfs_t blk,
                                FAR mfs_t *rev);

static int max_jrnl_log_depth(FAR mfs_sb_s *sb, FAR mfs_t * depth);

/* Flush */

static int jrnl_flush_ext_loc(FAR mfs_sb_s *sb, FAR mfs_t *blk);

static int jrnl_flush_log_wr(FAR mfs_sb_s *sb, FAR const mfs_ctz_s *o_ctz,
                             FAR const mfs_ctz_s *n_ctz,
                             FAR const mfs_ctz_s *p_ctz,
                             FAR const mfs_t depth);

static int jrnl_flush_log_rd(FAR mfs_sb_s *sb, const mfs_t log_idx,
                             FAR mfs_ctz_s *o_ctz, FAR mfs_ctz_s *n_ctz,
                             FAR mfs_ctz_s *p_ctz, FAR mfs_t *depth);

static int jrnl_flush_blk_entry_rd(FAR mfs_sb_s *sb, const mfs_t idx,
                                   FAR mfs_t *blk);

static int jrnl_flush_blk_entry_wr(FAR mfs_sb_s *sb, const mfs_t blk);

static int add_flush_ext(FAR mfs_sb_s *sb);

static int jrnl_flush_blk_add(FAR mfs_sb_s *sb, FAR mfs_t *blk);

static int rm_flush_ext(void);

static int rm_old_flush_ext(FAR mfs_sb_s *sb, const mfs_t flash_hdr);

static int jrnl_rd_mb_frm_loc(FAR mfs_sb_s *sb, const mfs_t jrnl_hdr_blk,
                              FAR mfs_t *mb1, FAR mfs_t *mb2);

static int flush_dir(FAR mfs_sb_s *sb, FAR mfs_ctz_s *ctz,
                     FAR mfs_ctz_s *p_ctz);

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
 * Description:
 *   Moves the current journal to a new location, calls a flush on master
 *   blocks if needed, marks the old journal for erasure, and updates the
 *   superblock state to point to the new journal.
 *
 * Input Parameters:
 *   sb - Superblock
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if not.
 *
 * Assumptions/Limitations:
 *   - The journal has already been flushed.
 *
 ****************************************************************************/

static int
jrnl_mv(FAR mfs_sb_s *sb)
{
  int         ret       = OK;
  bool        fmt_mb    = false;
  mfs_t       mb1;
  mfs_t       mb2;
  mfs_t       rev;
  mfs_t       jrnl_hd;
  mfs_t       o_jrnl_hd;
  mfs_ctz_s   root;
  mfs_pgloc_t jrnl_pg0;

  rev       = MFS_JRNL(sb).rev + 1;
  o_jrnl_hd = MFS_JRNL(sb).jrnl_hd;

  /* Are the MBs full and need formatting? */

  fmt_mb  = mfs_mb_isfull(sb);
  if (fmt_mb)
    {
      ret = mfs_mb_flush(sb, &root);
      if (ret < 0)
        {
          goto errout_with_mb;
        }
    }

  mb1 = MFS_MB(sb).mb1;
  mb2 = MFS_MB(sb).mb2;

  /* Write new journal header */

  ret     = mfs_alloc_getfreeblk(sb, &jrnl_hd);
  if (ret < 0)
    {
      goto errout_with_mb;
    }

  jrnl_pg0.blk      = jrnl_hd;
  jrnl_pg0.blk_off  = 0;

  ret     = jrnl_fmt_pg0(sb, &jrnl_pg0, mb1, mb2, rev);
  if (ret < 0)
    {
      goto errout_with_jrnl_hd;
    }

  MFS_JRNL(sb).jrnl_pg_buf = fs_heap_zalloc(MFS_PGSZ(sb));
  if (MFS_JRNL(sb).jrnl_pg_buf == NULL)
    {
      ret = -ENOMEM;
      goto errout_with_jrnl_hd;
    }

  /* Updating journal state BEFORE clearing the old journal. */

  MFS_JRNL(sb).n_logs          = 0;
  MFS_JRNL(sb).jrnl_hd         = jrnl_hd;
  MFS_JRNL(sb).rev             = rev;
  MFS_JRNL(sb).jrnl_pg_buf_idx = 0;
  MFS_JRNL(sb).jrnl_wr_idx     = 0;
  MFS_JRNL(sb).flush_hdr       = 0;
  MFS_JRNL(sb).flush_n_blks    = 0;
  MFS_JRNL(sb).flush_n_logs    = 0;
  MFS_JRNL(sb).flush_n_blks    = 0;
  MFS_JRNL(sb).flush_wr_idx    = 0;

  /* Clear old journal and it's flush extension if it exists. */

  ret     = mfs_jrnl_clearold(sb, o_jrnl_hd);

  /* While it would be a waste of space if the journal failed to clear,
   * it's not like retrying will help it. The init process will ensure only
   * the latest journal is selected.
   */

  return ret;

errout_with_jrnl_hd:
  mfs_alloc_markblkfree(sb, jrnl_hd);

errout_with_mb:
  if (fmt_mb)
    {
      mfs_alloc_markblkfree(sb, mb2);
      mfs_alloc_markblkfree(sb, mb1);
    }

  return ret;
}

/****************************************************************************
 * Name: ser_jrnl_log
 *
 * Description:
 *   Serialize a journal log into a buffer.
 *
 * Input Parameters:
 *   buf   - Buffer
 *   o_ctz - Old CTZ
 *   n_ctz - New CTZ
 *   p_ctz - Parent CTZ
 *   depth - Depth
 *
 ****************************************************************************/

static void
ser_jrnl_log(FAR char *buf, FAR const mfs_ctz_s *o_ctz,
             FAR const mfs_ctz_s *n_ctz, FAR const mfs_ctz_s *p_ctz,
             FAR const mfs_t depth)
{
  mfs_t chksm;

  memset(buf, 0, MFS_JRNL_LOGSZ);

  memcpy(buf +  0,  o_ctz, 12);
  memcpy(buf + 16,  n_ctz, 12);
  memcpy(buf + 32,  p_ctz, 12);
  memcpy(buf + 48, &depth,  4);

  chksm = mfs_calc_chksm(buf, 48);
  memcpy(buf + 48, &chksm,  4);
}

/****************************************************************************
 * Name: deser_jrnl_log
 *
 * Description:
 *   Deserializes a journal log from a buffer.
 *
 * Input Parameters:
 *   buf   - Buffer
 *   o_ctz - Old CTZ
 *   n_ctz - New CTZ
 *   p_ctz - Parent CTZ
 *   depth - Depth
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if not.
 *
 ****************************************************************************/

static int
deser_jrnl_log(FAR const char *buf, FAR mfs_ctz_s *o_ctz,
               FAR mfs_ctz_s *n_ctz, FAR mfs_ctz_s *p_ctz, FAR mfs_t *depth)
{
  mfs_t  chksm;
  mfs_t _chksm;

  if (o_ctz != NULL)
    {
      memcpy(o_ctz , buf +  0, 12);
    }

  if (n_ctz != NULL)
    {
      memcpy(n_ctz , buf + 16, 12);
    }

  if (p_ctz != NULL)
    {
      memcpy(p_ctz , buf + 32, 12);
    }

  if (depth != NULL)
    {
      memcpy(depth , buf + 48,  4);
    }

  _chksm = mfs_calc_chksm(buf, 52);
  memcpy(&chksm, buf + 48,  4);

  return _chksm == chksm ? OK : -EINVAL;
}

/****************************************************************************
 * Name: ser_jrnl_blkentry
 *
 * Description:
 *   Serialize contents of a journal block entry to a buffer.
 *
 * Input Parameters:
 *   buf - Buffer.
 *   blk - Block location for the block entry.
 *
 * Assumptions/Limitations:
 *   - Assumes journal has already been initialized/formatted.
 *   - This does not work for block entries for the flush extension.
 *
 ****************************************************************************/

static void
ser_jrnl_blkentry(FAR char *buf, const mfs_t blk)
{
  mfs_t       log_chksm;
  const mfs_t n_buf      = MFS_JRNL_BLKENTRYSZ;
  const mfs_t magic      = MFS_JRNL_MAGIC;
  const mfs_t jrnl_chksm = MFS_JRNL_CHKSM;

  memset(buf, 0, n_buf);

  memcpy(buf +  0,      &magic, 4);
  memcpy(buf +  4, &jrnl_chksm, 4);
  memcpy(buf +  8,        &blk, 4);

  log_chksm = mfs_calc_chksm(buf, n_buf - 4);
  memcpy(buf + 12,  &log_chksm, 4);
}

/****************************************************************************
 * Name: deser_jrnl_blkentry
 *
 * Description:
 *   Deserialize contents of a journal block entry from a buffer.
 *
 * Input Parameters:
 *   buf - Buffer.
 *   blk - Block location for the block entry.
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if not.
 *
 * Assumptions/Limitations:
 *   - Assumes journal has already been initialized/formatted.
 *   - This does not work for block entries for the flush extension.
 *
 ****************************************************************************/

static int
deser_jrnl_blkentry(FAR const char *buf, FAR mfs_t *blk)
{
  mfs_t magic;
  mfs_t chksm;
  mfs_t _blk;
  mfs_t log_chksm;
  mfs_t _log_chksm;

  memcpy(&magic     , buf +  0, 4);
  memcpy(&chksm     , buf +  4, 4);
  memcpy(&_blk      , buf +  8, 4);
  memcpy(&_log_chksm, buf + 12, 4);

  if (magic != MFS_JRNL_MAGIC || chksm != MFS_JRNL_CHKSM)
    {
      return -EINVAL;
    }

  log_chksm = mfs_calc_chksm(buf, 12);

  if (_log_chksm != log_chksm)
    {
      return -EINVAL;
    }

  *blk = _blk;
  return OK;
}

/* Normal Journal */

/****************************************************************************
 * Name: jrnl_log_wr
 *
 * Description:
 *   Append a journal log.
 *
 * Input Parameters:
 *   sb    - Superblock
 *   o_ctz - Old CTZ
 *   n_ctz - New CTZ
 *   p_ctz - Parent CTZ
 *   depth - Depth
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if not.
 *
 * Assumptions/Limitations:
 *   - Assumes journal has already been initialized/formatted.
 *
 ****************************************************************************/

static int
jrnl_log_wr(FAR mfs_sb_s *sb, FAR const mfs_ctz_s *o_ctz,
            FAR const mfs_ctz_s *n_ctz, FAR const mfs_ctz_s *p_ctz,
            FAR const mfs_t depth)
{
  int         ret         = OK;
  mfs_t       blk_idx;
  mfs_t       blk_off;
  mfs_pgloc_t pg;
  const mfs_t n_buf       = MFS_JRNL_LOGSZ;
  char        buf[n_buf];

  /* If journal is full, flush it first. */

  blk_idx = MFS_JRNL(sb).jrnl_wr_idx / MFS_PGINBLK(sb);
  blk_off = MFS_JRNL(sb).jrnl_wr_idx % MFS_PGINBLK(sb);

  if (blk_idx == MFS_JRNL(sb).n_blks)
    {
      ret = mfs_jrnl_flush(sb);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      /* Reset after flush. */

      blk_idx = 0;
      blk_off = 0;
    }

  /* Write journal buffer if it's full. */

  if (MFS_JRNL(sb).jrnl_pg_buf_idx == MFS_PGSZ(sb))
    {
      /* Get write location. */

      pg.blk_off = blk_off;

      if (blk_off == 0)
        {
          /* This means a new block needs to be added to the journal. */

          ret = jrnl_blk_add(sb, &pg.blk);
          if (ret < 0)
            {
              goto errout;
            }
        }
      else
        {
          ret = jrnl_blk_entry_rd(sb, blk_idx, &pg.blk);
          if (predict_false(ret < 0))
            {
              goto errout;
            }
        }

      /* Write */

      ret = mfs_rw_pgwr(sb, &pg, MFS_JRNL(sb).jrnl_pg_buf, MFS_PGSZ(sb));
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      /* Reset journal buffer */

      memset(MFS_JRNL(sb).jrnl_pg_buf, 0, MFS_PGSZ(sb));
    }

  /* Append log to journal buffer. */

  ser_jrnl_log(buf, o_ctz, n_ctz, p_ctz, depth);
  memcpy(MFS_JRNL(sb).jrnl_pg_buf + MFS_JRNL(sb).jrnl_pg_buf_idx,
         buf, n_buf);
  MFS_JRNL(sb).jrnl_pg_buf_idx += n_buf;
  MFS_JRNL(sb).n_logs++;

errout:
  return ret;
}

/****************************************************************************
 * Name: jrnl_log_rd
 *
 * Description:
 *   Read a log from journal from an index.
 *
 * Input Parameters:
 *   sb      - Superblock
 *   log_idx - Index of the log.
 *   o_ctz   - Old CTZ
 *   n_ctz   - New CTZ
 *   p_ctz   - Parent CTZ
 *   depth   - Depth
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if not.
 *
 * Assumptions/Limitations:
 *   - Assumes journal has already been initialized/formatted.
 *
 ****************************************************************************/

static int
jrnl_log_rd(FAR mfs_sb_s *sb, const mfs_t log_idx,
            FAR mfs_ctz_s *o_ctz, FAR mfs_ctz_s *n_ctz,
            FAR mfs_ctz_s *p_ctz, FAR mfs_t *depth)
{
  int         ret          = OK;
  mfs_t       blk_idx;
  mfs_bloc_t  b;
  const mfs_t logs_per_blk = MFS_BLKSZ(sb) / MFS_JRNL_LOGSZ;
  const mfs_t logs_per_pg  = MFS_PGSZ(sb) / MFS_JRNL_LOGSZ;
  const mfs_t n_buf        = MFS_JRNL_LOGSZ;
  char        buf[n_buf];

  blk_idx   = log_idx / logs_per_blk;
  b.blk_off = (log_idx % logs_per_blk) / logs_per_pg;
  b.pg_off  = ((log_idx % logs_per_blk) % logs_per_pg) * MFS_JRNL_LOGSZ;

  /* Fetch from journal buffer if idx falls in it. */

  if (blk_idx == MFS_JRNL(sb).jrnl_wr_idx)
    {
      ret = deser_jrnl_log(MFS_JRNL(sb).jrnl_pg_buf + b.pg_off, o_ctz, n_ctz,
                           p_ctz, depth);
      goto errout;
    }

  /* Fetch journal log from device. */

  ret = jrnl_blk_entry_rd(sb, blk_idx, &b.blk);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  memset(buf, 0, n_buf);
  ret = mfs_rw_pgrdoff(sb, &b, buf, n_buf);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  ret = deser_jrnl_log(buf, o_ctz, n_ctz, p_ctz, depth);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  return OK;

errout:
  return ret;
}

/****************************************************************************
 * Name: jrnl_blk_add
 *
 * Description:
 *   Add a block to the journal.
 *
 * Input Parameters:
 *   sb      - Superblock
 *   log_idx - Index of the log.
 *   o_ctz   - Old CTZ
 *   n_ctz   - New CTZ
 *   p_ctz   - Parent CTZ
 *   depth   - Depth
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if not.
 *
 * Assumptions/Limitations:
 *   - Assumes journal has already been initialized/formatted.
 *
 ****************************************************************************/

static int
jrnl_blk_add(FAR mfs_sb_s *sb, FAR mfs_t *blk)
{
  int   ret   = OK;
  mfs_t _blk;

  ret  = mfs_alloc_getfreeblk(sb, &_blk);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  ret  = jrnl_blk_entry_wr(sb, _blk);
  if (predict_false(ret < 0))
    {
      goto errout_with_blk;
    }

  *blk = _blk;
  return OK;

errout_with_blk:
  mfs_alloc_markblkfree(sb, _blk);

errout:
  *blk = 0;
  return ret;
}

/****************************************************************************
 * Name: jrnl_blk_entry_rd
 *
 * Description:
 *   Read a block entry from journal.
 *
 * Input Parameters:
 *   sb  - Superblock
 *   idx - Block entry
 *   blk - Block number
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if not.
 *
 * Assumptions/Limitations:
 *   - Assumes journal has already been initialized/formatted.
 *
 ****************************************************************************/

static int
jrnl_blk_entry_rd(FAR mfs_sb_s *sb, const mfs_t idx, FAR mfs_t *blk)
{
  int         ret         = OK;
  mfs_pgloc_t pg;
  const mfs_t n_buf       = MFS_JRNL_BLKENTRYSZ;
  char        buf[n_buf];

  memset(buf, 0, n_buf);

  pg.blk     = MFS_JRNL(sb).jrnl_hd;
  pg.blk_off = idx + 1;              /* 1 for pg 0 */

  ret = mfs_rw_pgrd(sb, &pg, buf, n_buf);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  ret = deser_jrnl_blkentry(buf, blk);

errout:
  return ret;
}

/****************************************************************************
 * Name: jrnl_blk_entry_wr
 *
 * Description:
 *   Write a block entry to the journal at the back of already written block
 *   entries.
 *
 * Input Parameters:
 *   sb  - Superblock
 *   blk - Block number
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if not.
 *
 * Assumptions/Limitations:
 *   - Assumes journal has already been initialized/formatted.
 *
 ****************************************************************************/

static int
jrnl_blk_entry_wr(FAR mfs_sb_s *sb, const mfs_t blk)
{
  int         ret         = OK;
  mfs_pgloc_t pg;
  const mfs_t n_buf       = MFS_JRNL_BLKENTRYSZ;
  char        buf[n_buf];

  memset(buf, 0, n_buf);
  ser_jrnl_blkentry(buf, blk);

  pg.blk     = MFS_JRNL(sb).jrnl_hd;
  pg.blk_off = MFS_JRNL(sb).jrnl_wr_idx + 1; /* 1 for pg 0 */

  if (predict_false(pg.blk_off == MFS_PGINBLK(sb) - 1))
    {
      /* Reserved for flush extension entry. */

      /* This should not be used in ANY case, as the flush should happen
       * before this.
       */

      ret = -EINVAL;
      goto errout;
    }

  ret = mfs_rw_pgwr(sb, &pg, buf, n_buf);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  MFS_JRNL(sb).jrnl_wr_idx++;

errout:
  return ret;
}

/****************************************************************************
 * Name: jrnl_fmt_pg0
 *
 * Description:
 *   Format the page 0 of a journal. Takes in all the parameters needed to be
 *   written to the journal header and writes them.
 *
 *   Once you write the pg0 of a journal, the journal now exists on the disk
 *   and any later init process will pick the latest of the journals (and
 *   remove old ones).
 *
 * Input Parameters:
 *   sb  - Superblock
 *   pg0 - page 0 of the journal
 *   mb1 - Master Block 1
 *   mb2 - Master Block 2
 *   rev - Revision number of header
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if not.
 *
 * Assumptions/Limitations:
 *   - This is used during the process of creating a new journal, and is used
 *     either during the format process or journal move process.
 *
 ****************************************************************************/

static int
jrnl_fmt_pg0(FAR mfs_sb_s *sb, FAR const mfs_pgloc_t *pg0, const mfs_t mb1,
             const mfs_t mb2, const mfs_t rev)
{
  int         ret         = OK;
  mfs_t       magic;
  mfs_t       chksm;
  const mfs_t n_buf       = MFS_JRNL_PG0SZ;
  char        buf[n_buf];

  memset(buf, 0, n_buf);

  magic = MFS_JRNL_MAGIC;
  chksm = MFS_JRNL_CHKSM;

  memcpy(buf +  0,           &magic, 4);
  memcpy(buf +  4,           &chksm, 4);
  memcpy(buf +  8,             &rev, 4);
  memcpy(buf + 12,   &MFS_BLKSZ(sb), 4);
  memcpy(buf + 16,      &sb->n_blks, 4);
  memcpy(buf + 20, &MFS_PGINBLK(sb), 4);
  memcpy(buf + 24,             &mb1, 4);
  memcpy(buf + 28,             &mb2, 4);
  memcpy(buf + 32,           &magic, 4);
  memcpy(buf + 36,           &chksm, 4);

  ret   = mfs_rw_pgwr(sb, pg0, buf, n_buf);
  return ret;
}

/****************************************************************************
 * Name: get_jrnl_rev_frm_dev
 *
 * Description:
 *   Get the revision number of a journal from the journal's location.
 *
 * Input Parameters:
 *   sb  - Superblock
 *   blk - Journal header block.
 *   rev - Revision
 *
 * Returned Value:
 *   - 0 if OK.
 *   - 1 if not a valid journal block.
 *   - negative if errors.
 *
 * Assumptions/Limitations:
 *   - Assumes journal has already been initialized/formatted.
 *
 ****************************************************************************/

static int
get_jrnl_rev_frm_dev(FAR mfs_sb_s *sb, const mfs_t blk, FAR mfs_t *rev)
{
  int         ret         = OK;
  mfs_t       _rev;
  mfs_t       magic1;
  mfs_t       chksm1;
  mfs_t       magic2;
  mfs_t       chksm2;
  mfs_pgloc_t pg;
  const mfs_t n_buf       = MFS_JRNL_PG0SZ;
  char        buf[n_buf];

  pg.blk     = blk;
  pg.blk_off = 0;

  memset(buf, 0, n_buf);

  ret  = mfs_rw_pgrd(sb, &pg, buf, n_buf);
  if (ret < 0)
    {
      goto errout;
    }

  memcpy(&magic1, buf +  0, 4);
  memcpy(&chksm1, buf +  4, 4);
  memcpy(&_rev  , buf +  8, 4);
  memcpy(&magic2, buf + 32, 4);
  memcpy(&chksm2, buf + 36, 4);

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
 * Name: max_jrnl_log_depth
 *
 * Description:
 *   Maximum depth across all present journal logs.
 *
 * Input Parameters:
 *   sb    - Superblock
 *   depth - Journal log's location
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if errors.
 *
 * Assumptions/Limitations:
 *   - Assumes journal header has already been initialized/formatted.
 *   - Does not include the flush extension logs (maximum depth of flush
 *     extension logs will be lesser than journal logs).
 *
 ****************************************************************************/

static int
max_jrnl_log_depth(FAR mfs_sb_s *sb, FAR mfs_t * depth)
{
  int        ret     = OK;
  mfs_t      _depth;
  mfs_t      m_depth = 0; /* Root is at 0 depth. */
  mfs_ctz_s  o_ctz;
  mfs_ctz_s  n_ctz;
  mfs_ctz_s  p_ctz;
  mfs_t log_idx = 0;

  while (true)
    {
      ret = jrnl_log_rd(sb, log_idx, &o_ctz, &n_ctz, &p_ctz, &_depth);
      if (ret == 1)
        {
          /* Log out of bounds. */

          ret = OK;
          break;
        }
      else if (ret < 0)
        {
          goto errout;
        }

      log_idx++;
      m_depth = (_depth > m_depth) ? _depth : m_depth;
    }

  *depth = m_depth;

  return OK;

errout:
  return ret;
}

/* Flush Extension */

/****************************************************************************
 * Name: jrnl_flush_ext_loc
 *
 * Description:
 *   Get the location of current journal's flush extension.
 *
 * Input Parameters:
 *   sb  - Superblock
 *   blk - Block number of flush extension.
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if not.
 *
 * Assumptions/Limitations:
 *   - Assumes journal has already been initialized/formatted.
 *
 ****************************************************************************/

static int
jrnl_flush_ext_loc(FAR mfs_sb_s *sb, FAR mfs_t *blk)
{
  int         ret         = OK;
  mfs_pgloc_t pg;
  const mfs_t n_buf       = MFS_JRNL_BLKENTRYSZ;
  char        buf[n_buf];

  pg.blk     = MFS_JRNL(sb).jrnl_hd;
  pg.blk_off = MFS_PGINBLK(sb) - 1;

  ret = mfs_rw_pgrd(sb, &pg, buf, n_buf);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  ret = deser_jrnl_blkentry(buf, blk);

errout:
  return ret;
}

/****************************************************************************
 * Name: jrnl_flush_log_wr
 *
 * Description:
 *   Append a journal flush log.
 *
 * Input Parameters:
 *   sb    - Superblock
 *   o_ctz - Old CTZ
 *   n_ctz - New CTZ
 *   p_ctz - Parent CTZ
 *   depth - Depth
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if not.
 *
 * Assumptions/Limitations:
 *   - Assumes journal has already been initialized/formatted.
 *
 ****************************************************************************/

static int
jrnl_flush_log_wr(FAR mfs_sb_s *sb, FAR const mfs_ctz_s *o_ctz,
                  FAR const mfs_ctz_s *n_ctz, FAR const mfs_ctz_s *p_ctz,
                  FAR const mfs_t depth)
{
  /* TODO: Ensure the journal buffer is emptied before the flush operation.
   * as writing the flush logs use the same mechanism.
   */

  int         ret         = OK;
  mfs_t       blk_idx;
  mfs_t       blk_off;
  mfs_pgloc_t pg;
  const mfs_t n_buf       = MFS_JRNL_LOGSZ;
  char        buf[n_buf];

  blk_idx = MFS_JRNL(sb).flush_wr_idx / MFS_PGINBLK(sb);
  blk_off = MFS_JRNL(sb).flush_wr_idx % MFS_PGINBLK(sb);

  /* If flush extension is full, and we need more space, throw an error for
   * now.
   */

  if (blk_idx == MFS_JRNL(sb).flush_n_blks)
    {
      ret = -EINVAL;
      goto errout;
    }

  /* Write journal buffer if it's full. */

  if (MFS_JRNL(sb).jrnl_pg_buf_idx == MFS_PGSZ(sb))
    {
      /* Get write location. */

      pg.blk_off = blk_off;

      if (blk_off == 0)
        {
          /* This means a new block needs to be added to the flush
           * extension.
           */

          ret = jrnl_flush_blk_add(sb, &pg.blk);
          if (predict_false(ret < 0))
            {
              goto errout;
            }
        }
      else
        {
          ret = jrnl_flush_blk_entry_rd(sb, blk_idx, &pg.blk);
          if (predict_false(ret < 0))
            {
              goto errout;
            }
        }

      /* Write */

      ret = mfs_rw_pgwr(sb, &pg, MFS_JRNL(sb).jrnl_pg_buf, MFS_PGSZ(sb));
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      /* Reset journal buffer */

      memset(MFS_JRNL(sb).jrnl_pg_buf, 0, MFS_PGSZ(sb));
    }

  /* Append log to journal buffer. */

  ser_jrnl_log(buf, o_ctz, n_ctz, p_ctz, depth);
  memcpy(MFS_JRNL(sb).jrnl_pg_buf + MFS_JRNL(sb).jrnl_pg_buf_idx,
         buf, n_buf);
  MFS_JRNL(sb).jrnl_pg_buf_idx += n_buf;
  MFS_JRNL(sb).flush_n_logs++;

errout:
  return ret;
}

/****************************************************************************
 * Name: jrnl_flush_log_rd
 *
 * Description:
 *   Read a flush log from journal from an index.
 *
 * Input Parameters:
 *   sb      - Superblock
 *   log_idx - Index of the log.
 *   o_ctz   - Old CTZ
 *   n_ctz   - New CTZ
 *   p_ctz   - Parent CTZ
 *   depth   - Depth
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if not.
 *
 * Assumptions/Limitations:
 *   - Assumes journal has already been initialized/formatted.
 *
 ****************************************************************************/

static int
jrnl_flush_log_rd(FAR mfs_sb_s *sb, const mfs_t log_idx,
                  FAR mfs_ctz_s *o_ctz, FAR mfs_ctz_s *n_ctz,
                  FAR mfs_ctz_s *p_ctz, FAR mfs_t *depth)
{
  int         ret          = OK;
  mfs_t       blk_idx;
  mfs_bloc_t  b;
  const mfs_t logs_per_blk = MFS_BLKSZ(sb) / MFS_JRNL_LOGSZ;
  const mfs_t logs_per_pg  = MFS_PGSZ(sb) / MFS_JRNL_LOGSZ;
  const mfs_t n_buf        = MFS_JRNL_LOGSZ;
  char        buf[n_buf];

  blk_idx   = log_idx / logs_per_blk;
  b.blk_off = (log_idx % logs_per_blk) / logs_per_pg;
  b.pg_off  = ((log_idx % logs_per_blk) % logs_per_pg) * MFS_JRNL_LOGSZ;

  /* Fetch from journal buffer if idx falls in it. */

  if (blk_idx == MFS_JRNL(sb).flush_wr_idx)
    {
      ret = deser_jrnl_log(MFS_JRNL(sb).jrnl_pg_buf + b.pg_off, o_ctz, n_ctz,
                           p_ctz, depth);
      goto errout;
    }

  /* Fetch journal log from device. */

  ret = jrnl_flush_blk_entry_rd(sb, blk_idx, &b.blk);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  memset(buf, 0, n_buf);
  ret = mfs_rw_pgrdoff(sb, &b, buf, n_buf);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  ret = deser_jrnl_log(buf, o_ctz, n_ctz, p_ctz, depth);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  return OK;

errout:
  return ret;
}

/****************************************************************************
 * Name: jrnl_flush_blk_entry_rd
 *
 * Description:
 *   Read a flush block entry from journal.
 *
 * Input Parameters:
 *   sb  - Superblock
 *   idx - Block entry
 *   blk - Block number
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if not.
 *
 * Assumptions/Limitations:
 *   - Assumes journal has already been initialized/formatted.
 *
 ****************************************************************************/

static int
jrnl_flush_blk_entry_rd(FAR mfs_sb_s *sb, const mfs_t idx, FAR mfs_t *blk)
{
  int         ret         = OK;
  mfs_pgloc_t pg;
  const mfs_t n_buf       = MFS_JRNL_BLKENTRYSZ;
  char        buf[n_buf];

  memset(buf, 0, n_buf);

  pg.blk     = MFS_JRNL(sb).jrnl_hd;
  pg.blk_off = idx;

  ret = mfs_rw_pgrd(sb, &pg, buf, n_buf);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  ret = deser_jrnl_blkentry(buf, blk);

errout:
  return ret;
}

/****************************************************************************
 * Name: jrnl_flush_blk_entry_wr
 *
 * Description:
 *   Write a flush block entry to the journal at the back of already written
 *   block entries.
 *
 * Input Parameters:
 *   sb  - Superblock
 *   blk - Block number
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if not.
 *
 * Assumptions/Limitations:
 *   - Assumes journal has already been initialized/formatted.
 *
 ****************************************************************************/

static int
jrnl_flush_blk_entry_wr(FAR mfs_sb_s *sb, const mfs_t blk)
{
  int         ret         = OK;
  mfs_pgloc_t pg;
  const mfs_t n_buf       = MFS_JRNL_BLKENTRYSZ;
  char        buf[n_buf];

  memset(buf, 0, n_buf);
  ser_jrnl_blkentry(buf, blk);

  pg.blk     = MFS_JRNL(sb).jrnl_hd;
  pg.blk_off = MFS_JRNL(sb).flush_wr_idx;

  ret = mfs_rw_pgwr(sb, &pg, buf, n_buf);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  MFS_JRNL(sb).flush_wr_idx++;

errout:
  return ret;
}

/****************************************************************************
 * Name: add_flush_ext
 *
 * Description:
 *   Writes the flush extension header to a journal and updates the
 *   superblock state to reflect it.
 *
 * Input Parameters:
 *   sb - Superblock
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if errors.
 *
 * Assumptions/Limitations:
 *   - Assumes journal header has already been initialized/formatted.
 *   - Does not include the flush extension logs (maximum depth of flush
 *     extension logs will be lesser than journal logs).
 *
 ****************************************************************************/

static int
add_flush_ext(FAR mfs_sb_s *sb)
{
  int         ret             = OK;
  mfs_t       jrnl_flush_ext;
  mfs_pgloc_t pg;
  const mfs_t n_buf           = MFS_JRNL_BLKENTRYSZ;
  char        buf[n_buf];

  if (MFS_JRNL(sb).flush_hdr != 0)
    {
      ret = -EINVAL;
      goto errout;
    }

  ret        = mfs_alloc_getfreeblk(sb, &jrnl_flush_ext);
  if (ret < 0)
    {
      goto errout;
    }

  pg.blk     = MFS_JRNL(sb).jrnl_hd;
  pg.blk_off = MFS_PGINBLK(sb) - 1;

  memset(buf, 0, n_buf);

  ser_jrnl_blkentry(buf, jrnl_flush_ext);

  ret        = mfs_rw_pgwr(sb, &pg, buf, n_buf);
  if (ret < 0)
    {
      goto errout_with_flush_ext;
    }

  MFS_JRNL(sb).flush_hdr    = jrnl_flush_ext;
  MFS_JRNL(sb).flush_n_logs = 0;
  MFS_JRNL(sb).flush_n_blks = MFS_PGINBLK(sb);
  MFS_JRNL(sb).flush_t_logs = (MFS_JRNL(sb).flush_n_blks * MFS_PGSZ(sb)) /
                              MFS_JRNL_LOGSZ;

  return OK;

errout_with_flush_ext:
  mfs_alloc_markblkfree(sb, jrnl_flush_ext);

errout:
  return ret;
}

/****************************************************************************
 * Name: jrnl_flush_blk_add
 *
 * Description:
 *   Add a flush block to the journal.
 *
 * Input Parameters:
 *   sb      - Superblock
 *   log_idx - Index of the log.
 *   o_ctz   - Old CTZ
 *   n_ctz   - New CTZ
 *   p_ctz   - Parent CTZ
 *   depth   - Depth
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if not.
 *
 * Assumptions/Limitations:
 *   - Assumes journal has already been initialized/formatted.
 *
 ****************************************************************************/

static int
jrnl_flush_blk_add(FAR mfs_sb_s *sb, FAR mfs_t *blk)
{
  int   ret   = OK;
  mfs_t _blk;

  ret  = mfs_alloc_getfreeblk(sb, &_blk);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  ret  = jrnl_flush_blk_entry_wr(sb, _blk);
  if (predict_false(ret < 0))
    {
      goto errout_with_blk;
    }

  *blk = _blk;
  return OK;

errout_with_blk:
  mfs_alloc_markblkfree(sb, _blk);

errout:
  *blk = 0;
  return ret;
}

static int
rm_flush_ext(void)
{
  int ret = OK;

  return ret;
}

/****************************************************************************
 * Name: rm_old_flush_ext
 *
 * Description:
 *   Removes the flush extension pointed to by the old journals. Marks all
 *   the blocks pointed by the extension for erasure.
 *
 * Input Parameters:
 *   sb        - Superblock
 *   flash_blk - Flush extension header
 *
 * Returned Value:
 *   - 0 if OK.
 *   - 1 if not a valid journal block entry.
 *   - negative if errors.
 *
 * Assumptions/Limitations:
 *   - Assumes journal has already been initialized/formatted.
 *
 ****************************************************************************/

static int
rm_old_flush_ext(FAR mfs_sb_s *sb, const mfs_t flash_blk)
{
  int         ret       = OK;
  mfs_t       blk;
  const mfs_t n_entries = MFS_PGINBLK(sb);

  for (mfs_t off = 0; off < n_entries; off++)
    {
      ret = jrnl_blk_entry_rd(sb, off, &blk);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      ret = mfs_alloc_markblkfree(sb, blk);
      if (predict_false(ret < 0))
        {
          goto errout;
        }
    }

  ret = mfs_alloc_markblkfree(sb, flash_blk);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  return OK;

errout:

  /* TODO: To be extra safe, waive off any marked-for-erase blocks. */

  return ret;
}

/****************************************************************************
 * Name: jrnl_rd_mb_frm_loc
 *
 * Description:
 *   Get master block locations from the pg0 of a journal from the location
 *   of the journal on the device.
 *
 * Input Parameters:
 *   sb           - Superblock
 *   jrnl_hdr_blk - Journal location
 *   mb1          - Master Block 1
 *   mb2          - Master Block 2
 *
 * Returned Value:
 *   - 0 if OK.
 *   - 1 if not a valid journal block entry.
 *   - negative if errors.
 *
 * Assumptions/Limitations:
 *   - Assumes journal has already been initialized/formatted.
 *
 ****************************************************************************/

static int
jrnl_rd_mb_frm_loc(FAR mfs_sb_s *sb, const mfs_t jrnl_hdr_blk,
                   FAR mfs_t *mb1, FAR mfs_t *mb2)
{
  int         ret      = OK;
  mfs_t       _mb1;
  mfs_t       _mb2;
  mfs_t       _chksm1;
  mfs_t       _chksm2;
  mfs_t       _magic1;
  mfs_t       _magic2;
  mfs_pgloc_t pg;
  const mfs_t n_buf    = MFS_JRNL_PG0SZ;
  char        buf[n_buf];

  memset(buf, 0, n_buf);

  ret = mfs_rw_pgrd(sb, &pg, buf, n_buf);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  memcpy(&_magic1, buf +  0, 4);
  memcpy(&_chksm1, buf +  4, 4);
  memcpy(&_mb1   , buf + 24, 4);
  memcpy(&_mb2   , buf + 28, 4);
  memcpy(&_magic2, buf + 32, 4);
  memcpy(&_chksm2, buf + 36, 4);

  if (_magic1 != MFS_JRNL_MAGIC || _magic2 != MFS_JRNL_MAGIC ||
      _chksm1 != MFS_JRNL_CHKSM || _chksm2 != MFS_JRNL_CHKSM)
    {
      goto errout;
    }

  *mb1 = _mb1;
  *mb2 = _mb2;

  return ret;

errout:
  return ret;
}

/****************************************************************************
 * Name: flush_dir
 *
 * Description:
 *   Flushes the directory recursively.
 *
 * Input Parameters:
 *   sb    - Superblock
 *   ctz   - Directory CTZ
 *   p_ctz - Parent Directory CTZ
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if errors.
 *
 * Assumptions/Limitations:
 *   - Assumes journal header has already been initialized/formatted.
 *   - Does not include the flush extension logs (maximum depth of flush
 *     extension logs will be lesser than journal logs).
 *
 ****************************************************************************/

static int
flush_dir(FAR mfs_sb_s *sb, FAR mfs_ctz_s *ctz, FAR mfs_ctz_s *p_ctz)
{
  int ret = OK;

  /* IMPORTANT TODO */

  return ret;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int
mfs_jrnl_updatectz(FAR mfs_sb_s *sb, FAR mfs_ctz_s *ctz,
                   FAR mfs_ctz_s *p_ctz)
{
  int ret = OK;

  /* IMPORTANT TODO */

  return ret;
}

int
mfs_jrnl_clearold(FAR mfs_sb_s *sb, const mfs_t o_blk)
{
  int         ret           = OK;
  mfs_t       blk;
  mfs_t       mb1;
  mfs_t       mb2;
  mfs_t       flash_ext_blk;
  mfs_pgloc_t pg;

  /* Remove flash extension. */

  ret = jrnl_flush_ext_loc(sb, &flash_ext_blk);
  if (predict_false(ret == 0))
    {
      ret = rm_old_flush_ext(sb, flash_ext_blk);
      if (ret < 0)
        {
          goto errout;
        }
    }
  else
    {
      /* Flash extension is not present. */
    }

  /* Remove the journal. */

  for (mfs_t i = 0; i < MFS_PGINBLK(sb) - 1; i++)
    {
      pg.blk_off = i;

      ret = jrnl_blk_entry_rd(sb, i, &blk);
      if (predict_false(ret < 0))
        {
          goto errout;
        }

      ret = mfs_alloc_markblkfree(sb, blk);
      if (predict_false(ret < 0))
        {
          goto errout;
        }
    }

  /* Clear associated master blocks. */

  ret = jrnl_rd_mb_frm_loc(sb, o_blk, &mb1, &mb2);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  ret = mfs_mb_freeblks(sb, mb1, mb2);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  /* Clear the journal header. */

  ret = mfs_alloc_markblkfree(sb, o_blk);
  if (predict_false(ret < 0))
    {
      goto errout;
    }

  return OK;

errout:

  /* TODO: To be extra safe, waive off any marked-for-erase blocks. */

  return ret;
}

int
mfs_jrnl_fmt(FAR mfs_sb_s *sb)
{
  int         ret       = OK;
  mfs_t       jrnl_hd;
  mfs_t       mb1;
  mfs_t       mb2;
  mfs_pgloc_t jrnl_pg0;
  const mfs_t log_sz    = MFS_JRNL_LOGSZ;

  ret = mfs_mb_allocblks(sb, &mb1, &mb2);
  if (ret < 0)
    {
      goto errout;
    }

  DEBUGASSERT(mb1 != 0);
  DEBUGASSERT(mb2 != 0);

  ret = mfs_alloc_getfreeblk(sb, &jrnl_hd);
  if (ret < 0)
    {
      goto errout_with_mb;
    }

  jrnl_pg0.blk      = jrnl_hd;
  jrnl_pg0.blk_off  = 0;

  /* Format the master blocks. */

  ret = mfs_mb_fmt(sb, mb1, mb2);
  if (ret < 0)
    {
      goto errout_with_jrnl_hd;
    }

  /* Write the header of the journal */

  ret = jrnl_fmt_pg0(sb, &jrnl_pg0, mb1, mb2, 0);
  if (ret < 0)
    {
      goto errout_with_jrnl_hd;
    }

  MFS_JRNL(sb).rev          = 0;
  MFS_JRNL(sb).n_blks       = MFS_PGSZ(sb) - 2;
  MFS_JRNL(sb).n_logs       = 0;
  MFS_JRNL(sb).jrnl_hd      = jrnl_hd;
  MFS_JRNL(sb).t_logs       = (MFS_JRNL(sb).n_blks * MFS_BLKSZ(sb)) / log_sz;
  MFS_JRNL(sb).flush_wr_idx = 0;
  MFS_JRNL(sb).flush_n_logs = 0;
  MFS_JRNL(sb).flush_t_logs = 0;
  MFS_JRNL(sb).flush_n_blks = MFS_JRNL(sb).n_blks + 2;
  MFS_JRNL(sb).flush_hdr    = 0;

  MFS_JRNL(sb).jrnl_pg_buf_idx = 0;
  MFS_JRNL(sb).jrnl_pg_buf     = fs_heap_zalloc(MFS_PGSZ(sb));
  if (MFS_JRNL(sb).jrnl_pg_buf == NULL)
    {
      ret = -ENOMEM;
      goto errout_with_jrnl_hd;
    }

  return OK;

errout_with_jrnl_hd:
  mfs_alloc_markblkfree(sb, jrnl_hd);

errout_with_mb:
  mfs_alloc_markblkfree(sb, mb2);
  mfs_alloc_markblkfree(sb, mb1);

errout:
  return ret;
}

int
mfs_jrnl_latest(FAR mfs_sb_s *sb, FAR mfs_t *blk, FAR mfs_t *rev)
{
  int   ret        = OK;
  mfs_t l_rev      = 0;
  mfs_t latest_blk = 0; /* Blk 0 is reserved so this is safe. */
  mfs_t _rev       = 0;

  for (mfs_t b = 0; b < sb->n_blks; b++)
    {
      ret = get_jrnl_rev_frm_dev(sb, b, &_rev);
      if (ret != OK)
        {
          continue;
        }

      if (latest_blk != 0 && l_rev + 1 == _rev)
        {
          /* This means rev is the latest one. So we clear the old
           * and update.
           */

          ret = mfs_jrnl_clearold(sb, latest_blk);
          if (ret == OK)
            {
              latest_blk = b;
              l_rev = _rev;
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
mfs_jrnl_init(FAR mfs_sb_s *sb, mfs_t blk)
{
  int         ret         = OK;
  mfs_t       idx;
  mfs_t       mb1;
  mfs_t       mb2;
  mfs_t       _rev;
  mfs_t       magic1;
  mfs_t       chksm1;
  mfs_t       magic2;
  mfs_t       chksm2;
  mfs_t       blk_sz;
  mfs_t       n_blks;
  mfs_t       pg_in_blk;
  const mfs_t n_buf       = MFS_JRNL_PG0SZ;
  const mfs_t log_sz      = MFS_JRNL_LOGSZ;
  char        buf[n_buf];
  mfs_pgloc_t pg;

  /* We should have already verified that the journal header has proper
   * ending magic and checksum by now by getting the block number and
   * the revision.
   */

  memset(buf, 0, n_buf);

  pg.blk      = blk;
  pg.blk_off  = 0;

  ret = mfs_rw_pgrd(sb, &pg, buf, n_buf);
  if (ret < 0)
    {
      goto errout;
    }

  memcpy(&magic1    , buf +  0, 4);
  memcpy(&chksm1    , buf +  4, 4);
  memcpy(&_rev      , buf +  8, 4);
  memcpy(&blk_sz    , buf + 12, 4);
  memcpy(&n_blks    , buf + 16, 4);
  memcpy(&pg_in_blk , buf + 20, 4);
  memcpy(&mb1       , buf + 24, 4);
  memcpy(&mb2       , buf + 28, 4);
  memcpy(&magic2    , buf + 32, 4);
  memcpy(&chksm2    , buf + 36, 4);

  if (magic1 != MFS_JRNL_MAGIC || chksm1 != MFS_JRNL_CHKSM ||
      magic2 != MFS_JRNL_MAGIC || chksm2 != MFS_JRNL_CHKSM)
    {
      ret = -EINVAL;
      goto errout;
    }

  MFS_MB(sb).mb1  = mb1;
  MFS_MB(sb).mb2  = mb2;
  sb->blk_sz      = blk_sz;
  sb->n_blks      = n_blks;
  sb->n_pg_in_blk = pg_in_blk;

  /* Get the count of valid journal logs on the device. */

  MFS_JRNL(sb).jrnl_hd = blk;

  idx = 0;
  while (true)
    {
      ret = jrnl_log_rd(sb, idx, NULL, NULL, NULL, NULL);
      if (ret != OK)
        {
          break;
        }

      idx++;
    }

  MFS_JRNL(sb).n_logs       = idx + 1;
  MFS_JRNL(sb).n_blks       = MFS_PGSZ(sb) - 2;
  MFS_JRNL(sb).t_logs       = (MFS_JRNL(sb).n_blks * MFS_BLKSZ(sb)) / log_sz;
  MFS_JRNL(sb).rev          = _rev;
  MFS_JRNL(sb).flush_wr_idx = 0;
  MFS_JRNL(sb).flush_n_logs = 0;
  MFS_JRNL(sb).flush_t_logs = 0;
  MFS_JRNL(sb).flush_n_blks = MFS_JRNL(sb).n_blks + 2;
  MFS_JRNL(sb).flush_hdr    = 0;

  return OK;

errout:
  return ret;
}

int
mfs_jrnl_flush(FAR mfs_sb_s *sb)
{
  int       ret       = OK;
  mfs_t     l_depth   = 0;  /* Root is at 0 depth. */
  char      *log_bm;
  char      *flush_bm;
  mfs_ctz_s root_ctz;
  mfs_ctz_s mn_ctz;         /* All 0 */

  /* Scan for largest depth */

  ret      = max_jrnl_log_depth(sb, &l_depth);
  if (ret < 0)
    {
      goto errout;
    }

  /* Add flush extension. */

  ret      = add_flush_ext(sb);
  if (ret < 0)
    {
      goto errout;
    }

  /* Allocate bitmaps for normal and flush logs. */

  log_bm   = fs_heap_zalloc(MFS_CEILDIV(MFS_JRNL(sb).t_logs, 8));
  if (log_bm == NULL)
    {
      ret = -EINVAL;
      goto errout_with_flush_ext;
    }

  flush_bm = fs_heap_zalloc(MFS_CEILDIV(MFS_JRNL(sb).flush_t_logs, 8));
  if (flush_bm == NULL)
    {
      ret = -EINVAL;
      goto errout_with_log_bm;
    }

  /* Traverse the entire tree in a post-fix manner updating the tree. */

  ret      = mfs_mb_rd(sb, &root_ctz);
  if (ret < 0)
    {
      goto errout_with_flush_bm;
    }

  mn_ctz.e_pg.blk     = 0;
  mn_ctz.e_pg.blk_off = 0;
  mn_ctz.sz           = 0;

  ret      = flush_dir(sb, &root_ctz, &mn_ctz);
  if (ret < 0)
    {
      goto errout_with_flush_bm;
    }

  ret      = jrnl_mv(sb);
  if (ret < 0)
    {
      goto errout_with_flush_bm;
    }

  return OK;

errout_with_flush_bm:
  fs_heap_free(flush_bm);

errout_with_log_bm:
  fs_heap_free(log_bm);

errout_with_flush_ext:
  rm_old_flush_ext(sb, MFS_JRNL(sb).flush_hdr);

errout:
  return ret;
}
