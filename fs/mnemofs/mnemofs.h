/****************************************************************************
 * fs/mnemofs/mnemofs.h
 * Mnemofs:  Filesystem optimized for NAND Solid State Device storages.
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
 ****************************************************************************/

/* TODO:::::::::::::::: ALL POINTERS NEED A "FAR" BEFORE THEM. */

#ifndef __FS_MNEMOFS_MNEMOFS_H
#define __FS_MNEMOFS_MNEMOFS_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <stddef.h>
#include <nuttx/fs/fs.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define MNEMOFS_JRNL_MAGIC  "-mnemoj-"
#define MNEMOFS_MASTER_MAGIC  "-mnemon-"

#define MNEMOFS_JOURNAL_N 20 /* TODO: option based on mount (saved into superblock )*/
#define MNEMOFS_BLK_T_PG(sb, blk) ((blk) << sb->log_pg_in_blk)
#define MNEMOFS_PG_T_BLK(sb, pg) ((pg) >> sb->log_pg_in_blk)
#define MNEMOFS_BLK_START(sb, pg) (MNEMOFS_BLK_T_PG(sb, MNEMOFS_PG_T_BLK(sb, pg)))
#define MNEMOFS_BLK_END(sb, pg) (MNEMOFS_BLK_START(sb, pg) + sb->pg_in_blk - 1)

#define MNEMOFS_SB(mountpt) ((struct mnemofs_sb_info *) (mountpt)->i_private) /* TODO: Add mountpt->i_private to contain mnemofs_sb_info. */

struct direntry_info;

struct mnemofs_sb_info {
  uint8_t pg_sz;
  uint8_t pg_in_blk;
  uint8_t log_pg_in_blk;
  uint8_t jrnl_blks;
  uint32_t master_node;
  struct inode root_ino;
  struct mnemofs_file *f_start;
  struct mnemofs_file *f_end;
  struct mnemofs_dir *d_start;
  struct mnemofs_dir *d_end;
  struct direntry_info *root; /* TODO: Initialize */
};

/* Open files */
struct mnemofs_file {
  struct mnemofs_file *next;
  uint32_t pg_start; /* Page corresponding to the last CTZ block */
  uint32_t start_blk; /* CTZ Blk Number (ie. index) of the last blk */
  ssize_t f_size; /* File size in bytes */
};

/* Open directory */
struct mnemofs_dir {
  struct mnemofs_dir *prev;
  struct mnemofs_dir *next;
  uint8_t pathlen;
  char *path;
  uint32_t pg_start; /* Page corresponding to the last CTZ block */
  uint32_t start_blk; /* CTZ Blk Number (ie. index) of the last blk */
  ssize_t off; /* Current offset in bytes */
};

enum {
  MNEMOFS_FILE,
  MNEMOFS_DIR,
};

/* mnemofs_nand.c */

int mnemofs_write_data(char *data, uint64_t datalen, uint32_t page, uint8_t off);
int mnemofs_read_data(char *data, uint64_t datalen, uint32_t page, uint8_t off);

/* mnemofs_blk_alloc.c */

uint32_t mnemofs_get_blk(void);
uint32_t mnemofs_get_pg(void);
int mnemofs_blk_mark_full(uint32_t blk);

/* mnemofs_journal.c */

enum {
  LOG_FILE,
  LOG_DIR,
  LOG_MASTER,
  LOG_MAX,
};

/* mnemofs_master.c */

void init_master(uint32_t mb0, uint32_t mb1);
int save_master_log(uint32_t new_mb);
int get_master(char *data, int data_len);

/* mnemofs_util.c */

uint8_t mnemofs_chksm(char *data, int data_len);
uint8_t mnemofs_two_x(uint32_t num);
uint8_t mnemofs_log2(uint32_t num);

/* mnemofs_dir.c */

int mnemofs_create_dir(struct mnemofs_sb_info *sb, FAR const char *path, mode_t mode);

int __mnemofs_opendir(struct mnemofs_sb_info *info,  FAR const char *relpath, FAR struct fs_dirent_s **dir);

/* mnemofs_file.c */

int __mnemofs_file_read(struct mnemofs_sb_info *sb, struct mnemofs_file *f, off_t off, char *buf, ssize_t len);
int __mnemofs_file_insert(struct mnemofs_file *f, const char *buf, ssize_t len, off_t off);

#endif /* __FS_MNEMOFS_MNEMOFS_H */
