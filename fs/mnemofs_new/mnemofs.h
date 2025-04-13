/****************************************************************************
 * fs/mnemofs_new/mnemofs.h
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

#ifndef __FS_MNEMOFS_NEW_MNEMOFS_H
#define __FS_MNEMOFS_NEW_MNEMOFS_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/fs/fs.h>
#include <nuttx/list.h>
#include <nuttx/mtd/mtd.h>
#include <stdint.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define MFS_JRNL_MAGIC        0xBB9CDF70U
#define MFS_JRNL_CHKSM        -(MFS_JRNL_MAGIC)
#define MFS_JRNL_PG0SZ        80
#define MFS_JRNL_LOGSZ        64
#define MFS_JRNL_BLKENTRYSZ   16
#define MFS_MN_SZ             24

#define MFS_MB_MAGIC    0xE9861B66U
#define MFS_MB_CHKSM    -(MFS_MB_MAGIC)

#define MFS_MTD(sb)     ((sb)->drv->u.i_mtd)
#define MFS_JRNL(sb)    ((sb)->jrnl)
#define MFS_MB(sb)      ((sb)->mb)
#define MFS_PGSZ(sb)    ((sb)->pg_sz)
#define MFS_BLKSZ(sb)   ((sb)->blk_sz)
#define MFS_PGINBLK(sb) ((sb)->n_pg_in_blk)
#define MFS_NBLKS(sb)   ((sb)->n_blks)
#define MFS_RW(sb)      ((sb)->rw)
#define MFS_LOGPGSZ     4

#define MFS_CEILDIV(n, d)     (((n) + (d) - 1) / (d))
#define MFS_BM_SET(bm, idx)   ((bm)[(idx) / 8] |= (1 << ((idx) % 8)))
#define MFS_BM_UNSET(bm, idx) ((bm)[(idx) / 8] &= ~(1 << ((idx) % 8)))
#define MFS_MIN(a, b)         ((a) < (b) ? (a) : (b))

/****************************************************************************
 * Public Types
 ****************************************************************************/

typedef uint32_t mfs_t;

typedef struct
{
  mfs_t n_blks;          /* Excluding header and MBs */
  mfs_t n_logs;          /* Number of logs already added. */
  mfs_t jrnl_hd;
  mfs_t t_logs;          /* Log capacity in jrnl. */
  mfs_t rev;
  mfs_t flush_hdr;       /* Location of flush extension. */
  mfs_t flush_n_blks;
  mfs_t flush_n_logs;
  mfs_t flush_t_logs;
  mfs_t flush_wr_idx;
  char *jrnl_pg_buf;
  mfs_t jrnl_pg_buf_idx;
  mfs_t jrnl_wr_idx;
} mfs_jrnl_s;

typedef struct
{
  mfs_t next_idx;
  mfs_t mb1;
  mfs_t mb2;
} mfs_mb_s;

typedef struct
{
  FAR uint8_t *wr_buf;
  FAR uint8_t *rd_buf;
  mfs_t wr_pg;
  mfs_t rd_pg;
} mfs_rw_s;

/* Superblock */

typedef struct
{
  FAR struct inode *drv;
  mfs_jrnl_s        jrnl;
  mfs_mb_s          mb;
  mfs_t             pg_sz;
  mfs_t             blk_sz;
  mfs_t             n_pg_in_blk;
  mfs_t             n_blks;
  mfs_rw_s          rw;
} mfs_sb_s;

/* Byte Location */

typedef struct
{
  mfs_t blk;
  mfs_t blk_off;  /* Page */
  mfs_t pg_off;   /* Byte in page */
} mfs_bloc_t;

/* Page Location */

typedef struct
{
  mfs_t blk;
  mfs_t blk_off; /* Page */
} mfs_pgloc_t;

typedef struct
{
  mfs_pgloc_t e_pg; /* Location of last page. */
  mfs_t sz;         /* Size of CTZ. TODO: Change this to last index. */
} mfs_ctz_s;

/* Open directory structure */

typedef struct
{
} mfs_dir_s;

/* Direntry structure. */

typedef struct
{
} mfs_dirent_s;

/* Open file structure. */

typedef struct
{
} mfs_file_s;

/****************************************************************************
 * Public Data
 ****************************************************************************/

#ifdef __cplusplus
#define EXTERN extern "C"
extern "C"
{
#else
#define EXTERN extern
#endif

/****************************************************************************
 * Inline Functions
 ****************************************************************************/

/****************************************************************************
 * Public Function Prototypes
 ****************************************************************************/

/* mnemofs_alloc.c */

int mfs_alloc_getfreepg(FAR const mfs_sb_s *sb, FAR mfs_pgloc_t *pg);
int mfs_alloc_getfreeblk(FAR const mfs_sb_s *sb, FAR mfs_t *blk);
int mfs_alloc_markpgfree(FAR mfs_sb_s *sb, FAR const mfs_pgloc_t *pg);
int mfs_alloc_markpgused(FAR mfs_sb_s *sb, FAR const mfs_pgloc_t *pg);
int mfs_alloc_markblkfree(FAR mfs_sb_s *sb, FAR mfs_t blk);
int mfs_alloc_markblkused(FAR mfs_sb_s *sb, FAR mfs_t blk);
int mfs_alloc_init(FAR mfs_sb_s *sb);
int mfs_alloc_fmt(FAR mfs_sb_s *sb);
int mfs_alloc_flush(FAR mfs_sb_s *sb);

/* mnemofs_ctz.c */

int mfs_ctz_travel(FAR mfs_sb_s * const sb, const mfs_t s_idx,
                   FAR const mfs_pgloc_t *s_pg, const mfs_t d_idx,
                   FAR mfs_pgloc_t *d_pg);
int mfs_ctz_wroff(FAR mfs_sb_s *sb, FAR const char *buf, const mfs_t n_buf,
                  const mfs_t off, FAR const mfs_ctz_s *o_ctz,
                  FAR mfs_ctz_s *n_ctz);
int mfs_ctz_rdoff(FAR mfs_sb_s *sb, FAR char *buf, mfs_t n_buf,
                  const mfs_t off, FAR const mfs_ctz_s *ctz);

/* mnemofs_rw.c */

int mfs_rw_isbad(FAR const mfs_sb_s * sb, mfs_t blk);
int mfs_rw_markbad(FAR mfs_sb_s * sb, mfs_t blk);
int mfs_rw_pgrdoff(FAR mfs_sb_s * sb, FAR const mfs_bloc_t *b, FAR char *buf,
                   const mfs_t n_buf);
int mfs_rw_pgrd(FAR mfs_sb_s * sb, FAR const mfs_pgloc_t *pg, FAR char *buf,
                const mfs_t n_buf);
int mfs_rw_pgwroff(FAR mfs_sb_s * sb, FAR const mfs_bloc_t *b,
                   FAR const char *buf, const mfs_t n_buf);
int mfs_rw_pgwr(FAR mfs_sb_s * sb, FAR const mfs_pgloc_t *pg,
                FAR const char *buf, const mfs_t n_buf);
int mfs_rw_blkerase(FAR mfs_sb_s * sb, const mfs_t blk);

/* mnemofs_util.c */

mfs_pgloc_t mfs_util_pg_to_pgloc(FAR const mfs_sb_s *sb, const mfs_t pg);
mfs_t mfs_util_pgloc_to_pg(FAR const mfs_sb_s *sb,
                           FAR const mfs_pgloc_t *pgloc);

#undef EXTERN
#ifdef __cplusplus
}
#endif

#endif /* __FS_MNEMOFS_NEW_MNEMOFS_H */
