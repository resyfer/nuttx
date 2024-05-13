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
#include <nuttx/list.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define MNEMOFS_JRNL_MAGIC  "-mfs!j!-"
#define MNEMOFS_MASTER_MAGIC  "-mfs!m!-"

#define MNEMOFS_JOURNAL_N 20 /* TODO: option based on mount (saved into superblock )*/
#define MFS_BLK2PG(sb, blk) ((blk) << sb->log_pg_in_blk)
#define MFS_PG2BLK(sb, pg) ((pg) >> sb->log_pg_in_blk)
#define MNEMOFS_BLK_START(sb, pg) (MNEMOFS_BLK_T_PG(sb, MNEMOFS_PG_T_BLK(sb, pg)))
#define MNEMOFS_BLK_END(sb, pg) (MNEMOFS_BLK_START(sb, pg) + sb->pg_in_blk - 1)

#define MNEMOFS_PC_SZ 10
#define MNEMOFS_MAX_ARGS 4 /* mnemofs_open */
#define MFS_EMPTY_CTZ 0 /* Use for last_pg, other fields can be whatever. */

#define MFS_SB(mountpt) ((struct mfs_sb_info *) (mountpt)->i_private) /* TODO: Add mountpt->i_private to contain mnemofs_sb_info. */
#define MFS_PGSZ(sb)  ((sb)->pg_sz)
#define MFS_MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MFS_OFILES(sb)  ((sb)->f)
#define MFS_ODIRS(sb)  ((sb)->d)
#define MFS_JRNL(sb)  ((sb)->j)
#define MFS_ROOT(sb)    ((sb)->root)

typedef uint32_t  mfs_t;
typedef int32_t  mfs_off_t;

struct mnemofs_direntry_info;
struct mfs_finfo;
struct mfs_blkallc;


struct mfs_dentry {
  mode_t mode;
  mfs_t last_idx;
  mfs_t last_pg;
  mfs_t sz;
  mfs_t c_off; /* Current offset in the directory file where this dentry is
                  situated. */
  /* Probably needs a length. */
};

struct mfs_jrnl_state {
  uint8_t n_blks; /* Does not consider master blocks. */
  FAR mfs_t *idxarr;
  mfs_t wr_s_pg; /* Writeable area start page */
  mfs_t wr_s_blkidx; /* Writeable area start page */
  mfs_t c_blkidx; /* Index of current block in idxarr */
  mfs_t c_pg; /* Current page */
  mfs_t c_pgoff; /* Current page offset */
};

struct mfs_sb_info {
  mutex_t fs_lock;
  const uint8_t pg_sz; /* In bytes */
  const uint16_t blk_sz; /* In bytes */
  uint8_t log_blk_sz;
  uint8_t log_pg_sz;
  uint8_t log_pg_in_blk;
  uint8_t pg_in_blk;
  uint8_t j_nblks;
  mfs_t master_node;
  struct inode root_ino;
  struct list_node f; /* Open files */
  struct list_node d; /* Open directories */
  struct list_node j; /* Journal (in-memory)*/
  struct mfs_jrnl_state j_state; /* Journal State */
  struct mfs_dentry root;
  struct mfs_blkallc *blkallc;
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

uint32_t mfs_get_blk(FAR struct mfs_sb_info * const sb);
uint32_t mnemofs_get_pg(FAR struct mfs_sb_info * const sb);
int mnemofs_blk_mark_full(FAR struct mfs_sb_info * const sb, uint32_t blk);
int mnemofs_pg_mrkdlt(FAR struct mfs_sb_info * const sb, mfs_t pg);

/* mnemofs_journal.c */
int mfs_jrnl_fmt(FAR struct mfs_sb_info * const sb);

/* mnemofs_master.c */

void init_master(uint32_t mb0, uint32_t mb1);
int save_master_log(struct mfs_sb_info *sb, uint32_t new_master);
int32_t get_master_blk(struct mfs_sb_info *sb);
int get_master(char *data, int data_len);

/* mnemofs_util.c */

uint8_t mnemofs_chksm(char *data, int data_len);
uint8_t mnemofs_two_x(uint32_t num);
uint8_t mnemofs_log2(uint32_t num);
uint8_t mfs_strhash(FAR const char *str, ssize_t len);
uint8_t mfs_path_hash(FAR const char *relpath, const mfs_t pathlen,
                      FAR uint8_t * hasharr);
void mfs_h2ben(FAR const uint8_t * const dt, ssize_t size,
                FAR uint8_t * const bebuf);
uint8_t mfs_fsobj_pathcount(FAR const char * const path, const mfs_t pathlen);

/* Swapping around once again */
void mfs_be2hn(FAR const uint8_t * const dt, ssize_t size,
                FAR uint8_t * const bebuf)
{
  mfs_h2ben(dt, size, bebuf);
}

uint8_t mfs_fsobj(FAR const char * const path, FAR const char ** start,
                  FAR const char ** next);

char *mfs_fsobj_last(FAR const char * const path, const mfs_t pathlen);

/* Inline helper functions */

/* TODO: Make log2 use this probably?  Or use leading zeroes.*/
inline mfs_t mfs_ctz(const uint32_t x) {
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

/* This is how it will be stored on flash. */
struct mfs_ctz_store_s {
  mfs_t pg_e;
  mfs_t idx_e;
};

/* TODO: list lock. */
/* TODO: Remove access to functions that will not lock the list lock. */

#define MFS_CTZ_SZ(l)     ((l)->sz)

mfs_t mfs_ctz_nptrl(FAR struct mfs_ctz_s * const l);
mfs_t mfs_ctz_nptrc(FAR struct mfs_ctz_s * const l);
void mfs_ctz_init(const mfs_t last_pg, const mfs_t last_idx, mfs_t sz,
                  FAR struct mfs_ctz_s * const l);
void mfs_ctz_destroy(FAR struct mfs_ctz_s *l);
int mfs_ctz_point(FAR const struct mfs_sb_info * const sb,
                  FAR struct mfs_ctz_s * const l, mfs_t idx);
int mfs_ctz_prev(FAR const struct mfs_sb_info * const sb,
                  FAR struct mfs_ctz_s * const l);
int mfs_ctz_next(FAR const struct mfs_sb_info * const sb,
                  FAR struct mfs_ctz_s * const l);
int mfs_ctz_offinfo(FAR const struct mfs_sb_info * const sb,
                    FAR struct mfs_ctz_s * const l, mfs_t off, mfs_t *idx,
                    mfs_off_t *blkoff);
int mfs_ctz_offpoint(FAR const struct mfs_sb_info * const sb,
                    FAR struct mfs_ctz_s * const l, mfs_t off,
                    mfs_off_t *blkoff);
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
mfs_t mfs_ctz_del(FAR const struct mfs_sb_info * const sb,
                  FAR const struct mfs_ctz_s * l, const mfs_t off,
                  const mfs_t len);
mfs_t mfs_ctz_trunc(FAR const struct mfs_sb_info * const sb,
                    FAR const struct mfs_ctz_s * l, const mfs_t len);
mfs_t mfs_ctz_wr(FAR const struct mfs_sb_info * const sb,
                FAR const struct mfs_ctz_s * l, const mfs_t off,
                FAR const char * const buf, const mfs_t len);

/* mnemofs_file.c */

#define MFS_DENTRY_LEN(dentry)  (sizeof(dentry)) /* TODO: For now this. */

struct mfs_finfo {
  // struct mfs_finfo *prev;
  // struct mfs_finfo *next;
  struct list_node list; /* TODO: Check if we need another list, specifically for this file.*/
  // mfs_t *path; /* An array of 32-bit integers, representing the page number of the last CTZ block of that file system object. This helps in tracking the file. */
  // mfs_t pathlen; /* TODO: Check if path and pathlen are required. */
  /* Last entry in path is page number for current file. */
  mode_t mode;
  struct mfs_ctz_s ctz; /* List */
  mfs_off_t ctz_blkoff;
  mfs_t off; /* This stands for offset for children (readdir into ctz)*/

  /* TODO: Implement the below. */

  uint8_t path_hash; /* Hash of the entire path. */
  uint8_t *path; /* An array of hashes of each item in the hierarchy to a path. */
  uint8_t pathlen; /* Only 255 items in path. YAY! A another limit has been imposed! */

  /* TODO: Add all metadata here. */
};

uint8_t mfs_f_probeopen(FAR const struct mfs_sb_info * const sb,
                        FAR const char *relpath, const mfs_t pathlen);
int mfs_f_open(FAR struct file * const fp, FAR const char *relpath,
                const int oflags, const mode_t mode);
int mfs_f_close(FAR const struct file * const fp);
ssize_t mfs_f_rd(FAR const struct file * const fp, FAR char * const buf,
                const size_t buflen);
ssize_t mfs_f_wr(FAR const struct file * const fp, FAR const char * const buf,
                const size_t buflen);
off_t mfs_f_seek(FAR const struct file * const fp, const off_t off,
                const int whence);
int mfs_f_trunc(FAR const struct file * const fp, const off_t len);

/* mnemofs_dir.c */

enum MFS_READDIR {
  MFS_READDIR_SELF = -2,
  MFS_READDIR_PARENT = -1,
  MFS_READDIR_CHILDREN = 0, /* >= 0 */
};

struct mfs_dinfo {
  struct fs_dirent_s base;
  struct list_node list;
  mode_t mode;
  struct mfs_ctz_s ctz;
  mfs_off_t ctz_blkoff;
  mfs_off_t off; /* Unlike a regular file, this counter needs to be -2 at
                    start for . and .. */ /* This stands for offset for
                    children (readdir into ctz)*/

  /* TODO: Implement the below. */

  uint8_t path_hash; /* Hash of the entire path. */
  uint8_t *path; /* An array of hashes of each item in the hierarchy to a path. */
  uint8_t pathlen; /* Only 255 items in path. YAY! A another limit has been imposed! */

  /* TODO: Add all metadata here. */
};

int mfs_probe_direntries_r(FAR const struct mfs_sb_info * const sb,
                            FAR struct mfs_dentry *parent,
                            FAR struct mfs_dentry *child,
                            FAR const char *relpath, const mfs_t pathlen,
                            FAR uint8_t * hasharr);
int mfs_d_create(FAR struct mfs_sb_info * const sb,
                FAR const char * const relpath, const mode_t mode);
int mfs_d_open(FAR struct mfs_sb_info * const sb,
              FAR const char * const relpath,
              FAR struct fs_dirent_s ** const dir);
int mfs_d_close(FAR struct mfs_sb_info * const sb,
                FAR const struct fs_dirent_s * const dir);
int mfs_d_rewind(FAR struct mfs_sb_info * const sb,
                FAR const struct fs_dirent_s * const dir);
int mfs_d_rd(FAR struct mfs_sb_info * const sb,
              FAR const struct fs_dirent_s * const dir,
              FAR struct dirent * const entry);
int mfs_d_unlink(FAR struct mfs_sb_info * const sb,
                FAR const char * const relpath);
int mfs_d_rm(FAR struct mfs_sb_info * const sb,
            FAR const char * const relpath);
int mfs_d_mv(FAR struct mfs_sb_info * const sb,
            FAR const char * const oldrelpath,
            FAR const char * const newrelpath);
int mfs_d_stat(FAR struct mfs_sb_info * const sb, FAR const char * relpath,
                FAR struct stat *buf);

#endif /* __FS_MNEMOFS_MNEMOFS_H */
