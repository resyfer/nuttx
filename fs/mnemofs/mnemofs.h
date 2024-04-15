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

#define MNEMOFS_PC_SZ 10
#define MNEMOFS_MAX_ARGS 4 /* mnemofs_open */

#define MNEMOFS_SB(mountpt) ((struct mfs_sb_info *) (mountpt)->i_private) /* TODO: Add mountpt->i_private to contain mnemofs_sb_info. */
#define MFS_PGSZ(sb)  (sb->pg_sz)
#define MFS_MIN(a, b) (((a) < (b)) ? (a) : (b))

typedef uint32_t  mfs_t;
typedef int32_t  mfs_off_t;

struct mnemofs_direntry_info;

struct mfs_sb_info {
  mutex_t fs_lock;
  const uint8_t pg_sz; /* In bytes */
  uint8_t log_pg_sz;
  uint8_t log_pg_in_blk;
  uint8_t pg_in_blk;
  uint8_t jrnl_blks;
  uint32_t master_node;
  struct inode root_ino;
  struct mnemofs_file_info *f_s;
  struct mnemofs_file_info *f_e;
  struct mnemofs_fs_dirent *d_s; /* Start of open dirs */
  struct mnemofs_fs_dirent *d_e; /* End of open dirs */
  struct mnemofs_direntry_info *root; /* TODO: Initialize */
};

struct mnemofs_ctz_s {
  mfs_t last_pg;
  mfs_t last_idx;
  mfs_t idx; /* Current index */
};

enum {
  MNEMOFS_FILE,
  MNEMOFS_DIR,
};

/* Open files & Directories */

/* TODO: Remove mnemofs_dir and just make it duplicate of mnemofs_file */
struct mnemofs_file {
  uint8_t pathlen;
  const char *path; /* Depends if it's the entire path or just the file system name.*/
  uint8_t hash;
  struct mnemofs_ctz_s l;
  ssize_t off; /* Current offset in bytes */
  ssize_t size; /* TODO: Make a function to extract this. */
};

/* mnemofs_nand.c */

ssize_t mnemofs_write_page(char *data, uint64_t datalen, uint32_t page, uint8_t off);
ssize_t mnemofs_write_data(char *data, uint64_t datalen, uint32_t page, uint8_t off);
ssize_t mnemofs_write_mfs_t(mfs_t *data, uint32_t page, uint8_t off);
ssize_t mnemofs_write_data_szoff(char *data, uint64_t datalen, uint32_t page, uint8_t off);
ssize_t mnemofs_read_data(char *data, uint64_t datalen, uint32_t page, uint8_t off);
ssize_t mnemofs_read_data_szoff(char *data, uint64_t datalen, uint32_t page, uint8_t off);
ssize_t mnemofs_read_page(char *data, uint64_t datalen, uint32_t page, uint8_t off);
ssize_t mnemofs_read_mfs_t(mfs_t *data, uint32_t page, uint8_t off);

/* mnemofs_blk_alloc.c */

uint32_t mnemofs_get_blk(void);
uint32_t mnemofs_get_pg(void);
int mnemofs_blk_mark_full(uint32_t blk);
int mnemofs_pg_mrkdlt(mfs_t pg);

/* mnemofs_journal.c */

enum {
  LOG_FILE,
  LOG_DIR,
  LOG_MASTER,
  LOG_MAX,
};

/* mnemofs_master.c */

void init_master(uint32_t mb0, uint32_t mb1);
int save_master_log(struct mfs_sb_info *sb, uint32_t new_master);
int32_t get_master_blk(struct mfs_sb_info *sb);
int get_master(char *data, int data_len);

/* mnemofs_util.c */

uint8_t mnemofs_chksm(char *data, int data_len);
uint8_t mnemofs_two_x(uint32_t num);
uint8_t mnemofs_log2(uint32_t num);
uint8_t mnemofs_calc_str_hash(FAR const char *str, ssize_t len);

/* mnemofs_dir.c */

/* Direntry in memory */
struct mnemofs_direntry_info { /* TODO: Remove the duplicated from dir_f and this struct. Maintain one source of truth. */
  /* TODO: dir_f.off will be set after journal is written. This is offset of this dirent in its parent's dirent file, */
  FAR const char *parent_path; /* Maybe NULL for ROOT */
  ssize_t parent_pathlen; /* TODO: This is supposed to be the entire path till parent. Contemplate if it is required or not. */
  mode_t mode;
  struct mnemofs_file dir_f; /* Directory file. TODO: Initialize this. */
};

enum MNEMOFS_DIR_SEARCH_ERR {
  MNEMOFS_DIR_SEARCH_OK,
  MNEMOFS_DIR_SEARCH_NOT_FOUND,
  MNEMOFS_DIR_SEARCH_INVALID_PARENT,
};

enum MNEMOFS_READDIR {
  MNEMOFS_READDIR_SELF = -2,
  MNEMOFS_READDIR_PARENT = -1,
  MNEMOFS_READDIR_CHILDREN = 0, /* >= 0 */
};

int __mnemofs_mkdir(struct mfs_sb_info *sb, FAR const char *path, mode_t mode);
int __mnemofs_opendir(struct mfs_sb_info *info,  FAR const char *relpath, FAR struct fs_dirent_s **dir);
int __mnemofs_closedir(struct mfs_sb_info *sb, FAR struct fs_dirent_s *dir);
int __mnemofs_rewinddir(struct mfs_sb_info *sb, FAR struct fs_dirent_s *dir);
int __mnemofs_readdir(struct mfs_sb_info *sb, FAR struct fs_dirent_s *dir, FAR struct dirent *entry);
int __mnemofs_unlink(FAR struct mfs_sb_info *sb, FAR const char *relpath);
int __mnemofs_rmdir(struct mfs_sb_info *sb, FAR const char *relpath);
int __mnemofs_mv(struct mfs_sb_info *sb, FAR const char *oldrelpath, FAR const char *newrelpath);
int search_direntries_r(struct mnemofs_direntry_info *parent, struct mnemofs_direntry_info *child, FAR const char *path, ssize_t pathlen);

/* mnemofs_file.c */

mfs_off_t __mnemofs_file_read(struct mfs_sb_info *sb, struct mnemofs_file *f, mfs_off_t off, char *buf, ssize_t len);
int __mnemofs_file_insert(struct mfs_sb_info *sb, struct mnemofs_file *f, const char *buf, ssize_t len, off_t off);
int __mnemofs_file_delete(struct mnemofs_file *f, ssize_t off, ssize_t len);
int __mnemofs_file_update(struct mnemofs_file *f, const char *buf, ssize_t src_len, ssize_t off, ssize_t dst_len);

int __mnemofs_open(struct file *fp, FAR const char *relpath, int oflags, mode_t mode);
int __mnemofs_close(struct file *fp);
ssize_t __mnemofs_read(FAR struct file *fp, FAR char *buf, size_t buflen);
ssize_t __mnemofs_write(FAR struct file *fp, FAR const char *buf, size_t buflen);
off_t __mnemofs_seek(FAR struct file *fp, off_t off, int whence);
int __mnemofs_truncate(FAR struct file *fp, mfs_off_t len);

/* Inline helper functions */

/* TODO: Make log2 use this probably?  Or use leading zeroes.*/
inline mfs_t mnemofs_ctz(const uint32_t x) {
  if(predict_false(x == 0)) {
    /* Special case, since we're using this for the CTZ skip list. The 0th
    block has no pointers. */
    return 0;
  }

#if defined(__GNUC__)
  return __builtin_ctz(x);
#else
  uint32_t c;
  /* Credits:
  http://graphics.stanford.edu/~seander/bithacks.html#ZerosOnRightBinSearch
  */
  if (x & 0x1)
  {
    // special case for odd x (assumed to happen half of the time)
    c = 0;
  }
  else
  {
    c = 1;
    if ((x & 0xffff) == 0) 
    {
      x >>= 16;
      c += 16;
    }
    if ((x & 0xff) == 0) 
    {
      x >>= 8;
      c += 8;
    }
    if ((x & 0xf) == 0) 
    {
      x >>= 4;
      c += 4;
    }
    if ((x & 0x3) == 0) 
    {
      x >>= 2;
      c += 2;
    }
    c -= x & 0x1;
  }
  return c;
#endif
}

mfs_t mfs_popcnt(mfs_t x) {
#if defined(__GNUC__)
  return __builtin_popcount(x);
#else
  /* http://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetKernighan */
  mfs_t c;
  for (c = 0; x; c++)
  {
    x &= x - 1;
  }

#endif
}


/* mnemofs_ctz.c */

/* Think about ownerships. This is CoW, so whatever changes will happen to
the copy, but later on, they get saved to the flash. */
struct mfs_ctz_s {
  mfs_t pg_e; /* End page */
  mfs_t pg_c; /* Current Page */
  mfs_t idx_e; /* End Index */
  mfs_t idx_c; /* Current Index */
  mfs_t sz; /* Current size of file */
  mutex_t l_lock; /* List lock */
};

/* TODO: list lock. */
/* TODO: Remove access to functions that will not lock the list lock. */
mfs_t mfs_ctz_nptrl(FAR struct mfs_ctz_s * const l);
mfs_t mfs_ctz_nptrc(FAR struct mfs_ctz_s * const l);
void mfs_ctz_init(const mfs_t last_pg, const mfs_t last_idx, mfs_t sz,
                  FAR struct mfs_ctz_s * const l);
int mfs_ctz_point(FAR const struct mfs_sb_info * const sb,
                  FAR struct mfs_ctz_s * const l, mfs_t idx);
int mfs_ctz_prev(FAR const struct mfs_sb_info * const sb,
                  FAR struct mfs_ctz_s * const l);
int mfs_ctz_next(FAR const struct mfs_sb_info * const sb,
                  FAR struct mfs_ctz_s * const l);
int mfs_ctz_offinfo(FAR const struct mfs_sb_info * const sb,
                    FAR struct mfs_ctz_s * const l, mfs_t n, mfs_t *idx,
                    mfs_off_t *off);
int mfs_ctz_offpoint(FAR const struct mfs_sb_info * const sb,
                    FAR struct mfs_ctz_s * const l, mfs_t n, mfs_off_t *off);
int mfs_ctz_cpyblkptrs(FAR const struct mfs_sb_info * const sb,
                      FAR struct mfs_ctz_s * const l, const mfs_t idx,
                      FAR char * const buf);
mfs_t mfs_ctz_blksz(FAR const struct mfs_sb_info * const sb, mfs_t idx);
mfs_t mfs_ctz_rd(FAR const struct mfs_sb_info * const sb,
               FAR const struct mfs_ctz_s * const l, const mfs_t off,
               FAR char * const buf, mfs_t len);
mfs_t mfs_ctz_upd(FAR const struct mfs_sb_info * const sb,
                  FAR const struct mfs_ctz_s * l, const mfs_t off,
                  const mfs_t ilen, const mfs_t flen,
                  FAR const char * const buf);
mfs_t mfs_ctz_trunc(FAR const struct mfs_sb_info * const sb,
                    FAR const struct mfs_ctz_s * l, const mfs_t len);
mfs_t mfs_ctz_wr(FAR const struct mfs_sb_info * const sb,
                FAR const struct mfs_ctz_s * l, const mfs_t off,
                FAR const char * const buf, const mfs_t len);

#endif /* __FS_MNEMOFS_MNEMOFS_H */
