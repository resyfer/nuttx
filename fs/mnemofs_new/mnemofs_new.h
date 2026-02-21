/****************************************************************************
 * fs/mnemofs_new/mnemofs_new.h
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

#ifndef __FS_MNEMOFS_MNEMOFS_NEW_H
#define __FS_MNEMOFS_MNEMOFS_NEW_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <debug.h>
#include <nuttx/fs/fs.h>
#include <nuttx/list.h>
#include <nuttx/list_type.h>
#include <nuttx/mtd/mtd.h>
#include <string.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define MFS_MAGIC        0xDCD4D8E9
#define MFS_DIRENT_MAGIC 0x428ECA94
#define MFS_DIR_MAGIC    0x42D1D894

#define MFS_NEW_LOG(fmt, ...)          finfo(fmt, ##__VA_ARGS__ )

#ifdef CONFIG_MNEMOFS_NEW_EXTRA_DEBUG
#define MFS_NEW_TRACE_LOG(fmt, ...)    MFS_NEW_LOG(fmt, ##__VA_ARGS__)
#else
#define MFS_NEW_TRACE_LOG(fmt, ...)    { }
#endif

#define MFS_NEW_STRLITCMP(a, lit)      strncmp(a, lit, strlen(lit))

#define MFS_NEW_MN(sb)      ((sb)->mn)
#define MFS_NEW_FSLOCK(sb)  ((sb)->fs_lock)
#define MFS_NEW_OFS(sb)  ((sb)->o_fds)

#define MFS_NEW_TRACE_LOG_DIRENT(dirent)  (mfs_new_log_trace_dirent(dirent))
#define MFS_NEW_TRACE_LOG_CTZ(ctz)  (mfs_new_log_trace_ctz(ctz))
#define MFS_NEW_TRACE_LOG_FSDIRENT(fsdirent)  (mfs_new_log_trace_fsdirent(fsdirent))
#define MFS_NEW_TRACE_LOG_OF(of) (mfs_new_log_trace_of(of))

/****************************************************************************
 * Public Types
 ****************************************************************************/

typedef uint32_t  mfs_t;

struct mfs_new_sb_s
{
  FAR struct inode        *drv;
  mutex_t                 fs_lock;
  mfs_t                   n_blk;
  mfs_t                   n_pg_in_blk;
  mfs_t                   pg_sz;
  mfs_t                   blk_sz;
  mfs_t mn;
  mfs_t nand_sb; // On device block number. Will be the first non-bad block.
  mfs_t nand_sb_rev_no; // Revision number, essentially page number inside the sb block.
  FAR uint8_t             *rw_buf;
  mfs_t root_blk;
  struct list_node o_fds;
};

struct mfs_new_loc_s
{
  mfs_t blk;
  mfs_t pg;
  mfs_t off;
};

struct mfs_new_pg_loc_s
{
  mfs_t blk;
  mfs_t pg;
};

struct mfs_new_ctz_s
{
  mfs_t sz;
  struct mfs_new_pg_loc_s loc;
};

struct mfs_new_jrnl_ent_s
{
  struct mfs_new_loc_s old_loc;
  struct mfs_new_loc_s new_loc;
  mfs_t chksm;
};

struct mfs_new_dir_rev_s
{
  mfs_t magic;
  mfs_t dir_magic;
  struct mfs_new_ctz_s ctz;
  mfs_t p_loc; // Parent dir location
  mfs_t chksm;
};

struct mfs_new_dir_entry_s
{
  mfs_t magic;  // MFS_DIRENT_MAGIC
  mfs_t ctz_sz;
  uid_t owner;
  gid_t group;
  mfs_t p_blk; // Parent's block number
  struct mfs_new_pg_loc_s loc; // For dirs, pg = 0
  time_t acc_time;
  time_t mod_time;
  time_t cr_time;
  mfs_t name_hash;
  uint16_t perms;
  uint8_t name_len;
  FAR char* name;
  uint16_t chksm;
};

/* This is for *dir VFS methods. */

struct mfs_new_fsdirent_s
{
  struct fs_dirent_s    base; /* VFS directory structure */
  struct mfs_new_ctz_s dir_ctz;
  mfs_t off;
  mfs_t dir_blk;
  uint8_t idx; /* 0 for ., 1 for .., 2 for others. */
};

struct mfs_new_ofd_comm_s
{
  int oflags;
  mfs_t off;
  struct mfs_new_ctz_s ctz;
  mfs_t p_blk;
  uint8_t refcount;
};

struct mfs_new_ofd_s
{
  struct list_node list;
  FAR struct mfs_new_ofd_comm_s *com;
};

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

static inline_function uint8_t *
mfs_new_rw_buff(FAR const struct mfs_new_sb_s * const sb)
{
  return sb->rw_buf;
}

static inline_function mfs_t
mfs_new_n_blk(FAR const struct mfs_new_sb_s * const sb)
{
  return sb->n_blk;
}

static inline_function mfs_t
mfs_new_n_pg_in_blk(FAR const struct mfs_new_sb_s * const sb)
{
  return sb->n_pg_in_blk;
}

static inline_function mfs_t
mfs_new_blk_sz(FAR const struct mfs_new_sb_s * const sb)
{
  return sb->blk_sz;
}

static inline_function mfs_t
mfs_new_pg_sz(FAR const struct mfs_new_sb_s * const sb)
{
  return sb->pg_sz;
}

static inline_function mfs_t
mfs_new_root_blk(FAR const struct mfs_new_sb_s * const sb)
{
  return sb->root_blk;
}

static inline_function bool
mfs_new_blk_range_check(FAR const struct mfs_new_sb_s * const sb, mfs_t blk)
{
  return predict_true(blk < mfs_new_n_blk(sb));
}

static inline_function bool
mfs_new_pg_range_check(FAR const struct mfs_new_sb_s * const sb, mfs_t pg)
{
  return predict_true(pg < mfs_new_n_pg_in_blk(sb));
}

static inline_function bool
mfs_new_pg_off_range_check(FAR const struct mfs_new_sb_s * const sb, mfs_t pg_off)
{
  return predict_true(pg_off < mfs_new_pg_sz(sb));
}

static inline_function struct inode *
mfs_new_drv(FAR const struct mfs_new_sb_s * const sb)
{
  return sb->drv;
}

static inline_function struct mtd_dev_s *
mfs_new_mtd(FAR const struct mfs_new_sb_s * const sb)
{
  return sb->drv->u.i_mtd;
}

static inline_function int
mfs_new_str_litcmp(const char *str, const char *lit)
{
  return strncmp(str, lit, strlen(lit));
}

static inline_function void
mfs_new_log_trace_dirent(FAR const struct mfs_new_dir_entry_s *dirent)
{
  // TODO
}

static inline_function void
mfs_new_log_trace_ctz(FAR const struct mfs_new_ctz_s * const ctz)
{
  // TODO
}

static inline_function void
mfs_new_log_trace_fsdirent(FAR const struct mfs_new_fsdirent_s * const fsdirent)
{
  // TODO
}

static inline_function void
mfs_new_log_trace_of(FAR const struct mfs_new_ofd_s * const of)
{
  // TODO
}

static inline_function mfs_t
mfs_new_ctz_sz(FAR const struct mfs_new_ctz_s * const ctz)
{
  return ctz->sz;
}

static inline_function size_t
mfs_new_dirent_sz(FAR const struct mfs_new_dir_entry_s *dirent)
{
  return sizeof(struct mfs_new_dir_entry_s) - sizeof(char *) + dirent->name_len;
}

/****************************************************************************
 * Public Function Prototypes
 ****************************************************************************/

/* mnemofs_new_rw.c */

int mfs_new_bad_blk_check(FAR const struct mfs_new_sb_s * const sb, mfs_t blk);
int mfs_new_bad_blk_mark(FAR const struct mfs_new_sb_s * const sb, mfs_t blk);
ssize_t mfs_new_wr_pg(FAR const struct mfs_new_sb_s * const sb, mfs_t blk, mfs_t pg,
                       FAR const char *data, const size_t size);
ssize_t mfs_new_rd_pg(FAR const struct mfs_new_sb_s * const sb, mfs_t blk, mfs_t pg,
                       FAR char * const data);
ssize_t mfs_new_erase_blk(FAR const struct mfs_new_sb_s * const sb, mfs_t blk);
ssize_t mfs_new_erase_blks_n(FAR const struct mfs_new_sb_s * const sb, const off_t blk, const size_t n);

/* mnemofs_new_format.c */

int mfs_new_fmt(FAR struct mfs_new_sb_s * const sb);
bool mfs_new_check_fmt(FAR const struct mfs_new_sb_s * const sb, FAR mfs_t * const mn_blk);

/* mnemofs_new_mn.c */

int mfs_new_mn_fmt(FAR const struct mfs_new_sb_s * sb, const mfs_t mn_blk);
int mfs_new_mn_init(FAR const struct mfs_new_sb_s * sb, const mfs_t mn_blk);

/* mnemofs_new_blkalloc.c */

int mfs_new_blkalloc_reset(FAR const struct mfs_new_sb_s * sb);
int mfs_new_get_pg(FAR const struct mfs_new_sb_s * const sb, FAR struct mfs_new_pg_loc_s * const pg);
int mfs_new_get_blk(FAR const struct mfs_new_sb_s * const sb, FAR mfs_t * const blk);
int mfs_new_sched_blk_erase(FAR const struct mfs_new_sb_s * const sb, mfs_t blk);

/* mnemofs_new_sb.c */

int mfs_new_nand_sb_fmt(FAR struct mfs_new_sb_s * const sb, mfs_t mn_loc);
bool mfs_new_nand_sb_check(FAR const struct mfs_new_sb_s * const sb, FAR mfs_t *mn_loc, FAR mfs_t *rev_no);

/* mnemofs_new_dir.c */

int mfs_new_dir_init(FAR const struct mfs_new_sb_s * const sb, const mfs_t dir_blk);
int mfs_new_get_latest_dir_rev(FAR const struct mfs_new_sb_s * const sb, const mfs_t dir_blk, FAR mfs_t *rev_no, FAR struct mfs_new_ctz_s *dir_ctz);
int mfs_new_get_dirent_from_off(FAR const struct mfs_new_sb_s * const sb, const struct mfs_new_ctz_s dir_ctz, const mfs_t off, FAR struct mfs_new_dir_entry_s *dirent);
int mfs_new_upd_dirent_at_off(FAR struct mfs_new_sb_s * const sb, FAR struct mfs_new_ctz_s *dir_ctz, const mfs_t off, FAR const struct mfs_new_dir_entry_s * const dirent);
void mfs_new_dirent_free(FAR struct mfs_new_dir_entry_s * dirent);
int mfs_new_path_traversal(FAR struct mfs_new_sb_s * const sb, FAR const char * relpath, FAR struct mfs_new_dir_entry_s *dirent);
int mfs_new_dirent_is_dir(FAR const struct mfs_new_dir_entry_s *dirent);

/* mnemofs_new_util.c */

bool mfs_new_item_from_path(FAR const char *relpath, FAR char* item, FAR const char **next);
mfs_t mfs_new_str_hash(FAR const char* str);

/* mnemofs_new_file.c */

int mfs_new_file_truncate(FAR struct mfs_new_sb_s * const sb, const mfs_t p_blk, const struct mfs_new_ctz_s ctz, const mfs_t sz);

#undef EXTERN
#ifdef __cplusplus
}
#endif

#endif /* __FS_MNEMOFS_MNEMOFS_H */
