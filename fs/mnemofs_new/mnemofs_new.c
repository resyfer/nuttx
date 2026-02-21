/****************************************************************************
 * fs/mnemofs_new/mnemofs_new.c
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

#include <nuttx/mutex.h>
#include <sys/types.h>
#include <sys/statfs.h>
#include <sys/stat.h>

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

#include <fs_heap.h>
#include <mnemofs_new/mnemofs_new.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/****************************************************************************
 * Private Types
 ****************************************************************************/

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

static int mnemofs_new_open(FAR struct file *filep, FAR const char *relpath,
                     int oflags, mode_t mode);
static int mnemofs_new_close(FAR struct file *filep);
static ssize_t mnemofs_new_read(FAR struct file *filep, FAR char *buffer,
                         size_t buflen);
static ssize_t mnemofs_new_write(FAR struct file *filep, FAR const char *buffer,
                          size_t buflen);
static off_t mnemofs_new_seek(FAR struct file *filep, off_t offset, int whence);
static int mnemofs_new_ioctl(FAR struct file *filep, int cmd, unsigned long arg);
static int mnemofs_new_truncate(FAR struct file *filep, off_t length);
static int mnemofs_new_sync(FAR struct file *filep);
static int mnemofs_new_dup(FAR const struct file *oldp, FAR struct file *newp);
static int mnemofs_new_fstat(FAR const struct file *filep, FAR struct stat *buf);
static int mnemofs_new_opendir(FAR struct inode *mountpt, FAR const char *relpath,
                        FAR struct fs_dirent_s **dir);
static int mnemofs_new_closedir(FAR struct inode *mountpt,
                         FAR struct fs_dirent_s *dir);
static int mnemofs_new_readdir(FAR struct inode *mountpt,
                        FAR struct fs_dirent_s *dir,
                        FAR struct dirent *entry);
static int mnemofs_new_rewinddir(FAR struct inode *mountpt,
                          FAR struct fs_dirent_s *dir);
static int mnemofs_new_bind(FAR struct inode *driver, FAR const void *data,
                     FAR void **handle);
static int mnemofs_new_unbind(FAR void *handle, FAR struct inode **driver,
                       unsigned int flags);
static int mnemofs_new_statfs(FAR struct inode *mountpt, FAR struct statfs *buf);
static int mnemofs_new_unlink(FAR struct inode *mountpt, FAR const char *relpath);
static int mnemofs_new_mkdir(FAR struct inode *mountpt, FAR const char *relpath,
                      mode_t mode);
static int mnemofs_new_rmdir(FAR struct inode *mountpt, FAR const char *relpath);
static int mnemofs_new_rename(FAR struct inode *mountpt,
                       FAR const char *oldrelpath,
                       FAR const char *newrelpath);
static int mnemofs_new_stat(FAR struct inode *mountpt, FAR const char *relpath,
                     FAR struct stat *buf);

/****************************************************************************
 * Private Data
 ****************************************************************************/

/****************************************************************************
 * Public Data
 ****************************************************************************/

const struct mountpt_operations g_mnemofs_new_operations =
{
  mnemofs_new_open,      /* open */
  mnemofs_new_close,     /* close */
  mnemofs_new_read,      /* read */
  mnemofs_new_write,     /* write */
  mnemofs_new_seek,      /* seek */
  mnemofs_new_ioctl,     /* ioctl */
  NULL,                  /* mmap */
  mnemofs_new_truncate,  /* truncate */
  NULL,                  /* poll */
  NULL,                  /* readv */
  NULL,                  /* writev */

  mnemofs_new_sync,      /* sync */
  mnemofs_new_dup,       /* dup */
  mnemofs_new_fstat,     /* fstat */
  NULL,                  /* fchstat */

  mnemofs_new_opendir,   /* opendir */
  mnemofs_new_closedir,  /* closedir */
  mnemofs_new_readdir,   /* readdir */
  mnemofs_new_rewinddir, /* rewinddir */

  mnemofs_new_bind,      /* bind */
  mnemofs_new_unbind,    /* unbind */
  mnemofs_new_statfs,    /* statfs */

  mnemofs_new_unlink,    /* unlink */
  mnemofs_new_mkdir,     /* mkdir */
  mnemofs_new_rmdir,     /* rmdir */
  mnemofs_new_rename,    /* rename */
  mnemofs_new_stat,      /* stat */
  NULL                   /* chstat */
};

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static int mnemofs_new_open(FAR struct file *filep, FAR const char *relpath,
                          int oflags, mode_t mode)
{
  int                           ret       = OK;
  FAR struct mfs_new_sb_s       *sb;
  struct mfs_new_dir_entry_s    dirent;
  FAR struct inode *inode;
  FAR struct mfs_new_ofd_s *of;
  FAR struct mfs_new_ofd_comm_s *of_com;

  MFS_NEW_TRACE_LOG("Entry.");

  inode = filep->f_inode;
  DEBUGASSERT(inode != NULL);
  sb    = inode->i_private;
  MFS_NEW_TRACE_LOG("Sb obtained at %p", sb);
  DEBUGASSERT(sb != NULL);

  ret = nxmutex_lock(&MFS_NEW_FSLOCK(sb));
  if (predict_false(ret != OK))
    {
      MFS_NEW_LOG("Failed to acquire fs mutex.");
      goto errout;
    }

  MFS_NEW_TRACE_LOG("Locked.");

  ret = mfs_new_path_traversal(sb, relpath, &dirent);
  if (predict_false(ret != OK))
    {
      MFS_NEW_LOG("Could not traverse the path.");
      goto errout_with_lock;
    }

  MFS_NEW_TRACE_LOG_DIRENT(&dirent);

  ret = mfs_new_dirent_is_dir(&dirent);
  if (ret == 1)
    {
      MFS_NEW_LOG("Path points to a directory.");
      ret = -EISDIR;
      goto errout_with_dirent;
    }
  else if (predict_false(ret < 0))
    {
      MFS_NEW_LOG("Problems faced while obtaining path item.");
      goto errout_with_lock;
    }

  of = fs_heap_zalloc(sizeof(struct mfs_new_ofd_s));
  if (predict_false(of == NULL))
  {
    MFS_NEW_LOG("No memory left to allocate open file descriptor.");
    ret = -ENOMEM;
    goto errout_with_dirent;
  }

  MFS_NEW_TRACE_LOG("Open file descriptor allocated at %p", of);

  of_com = fs_heap_zalloc(sizeof(struct mfs_new_ofd_comm_s));
  if (predict_false(of_com == NULL))
  {
    MFS_NEW_LOG("No memory left to allocate open file descriptor's common segment.");
    goto errout_with_of;
  }

  MFS_NEW_TRACE_LOG("Open file descriptor's common segment allocated at %p", of_com);

  of->com = of_com;
  of_com->refcount++;
  of_com->oflags = oflags;
  of_com->ctz.sz = dirent.ctz_sz;
  of_com->ctz.loc = dirent.loc;
  of_com->p_blk = dirent.p_blk;

  /* Offset flags */

  MFS_NEW_TRACE_LOG("Open flags at set at %x", oflags);

  if ((oflags & (O_TRUNC | O_WRONLY)) == (O_TRUNC | O_WRONLY) ||
    (oflags & (O_TRUNC | O_RDWR)) == (O_TRUNC | O_RDWR))
    {
      /* File is truncated to size 0. If write and truncate are mentioned only
       * then it's truncated. Else, the truncate flag is ignored.
       */

      ret = mfs_new_file_truncate(sb, of_com->p_blk, of_com->ctz, 0);
      if (predict_false(ret < 0))
      {
        goto errout_with_of_com;
      }

      MFS_NEW_TRACE_LOG("File truncated to size 0.");
    }

  if ((oflags & O_APPEND) != 0)
    {
      of_com->off = of_com->ctz.sz;
      MFS_NEW_TRACE_LOG("File offset set to %u", of_com->off);
    }

  MFS_NEW_TRACE_LOG_OF(of);

  list_add_tail(&MFS_NEW_OFS(sb), &of->list);
  MFS_NEW_TRACE_LOG("Open file descriptor added to the open file list.");
  MFS_NEW_TRACE_LOG("Open file list items: %lu", list_length(&MFS_NEW_OFS(sb)));

  filep->f_priv = of;

  nxmutex_unlock(&MFS_NEW_FSLOCK(sb));
  MFS_NEW_TRACE_LOG("Unlocked.");

  MFS_NEW_TRACE_LOG("Exit | Return %d", ret);
  return ret;

errout_with_of_com:
  fs_heap_free(of_com);
  MFS_NEW_TRACE_LOG("Open file descriptor's common segment freed.");

errout_with_of:
  fs_heap_free(of);
  MFS_NEW_TRACE_LOG("Open file descriptor freed.");

errout_with_dirent:
  mfs_new_dirent_free(&dirent);
  MFS_NEW_TRACE_LOG("dirent freed.");

errout_with_lock:
  nxmutex_unlock(&MFS_NEW_FSLOCK(sb));
  MFS_NEW_TRACE_LOG("Unlocked.");

errout:
  MFS_NEW_TRACE_LOG("Exit | Return %d", ret);
  return ret;
}

static int mnemofs_new_close(FAR struct file *filep)
{
  int                           ret       = OK;
  FAR struct mfs_new_sb_s       *sb;
  FAR struct inode *inode;
  FAR struct mfs_new_ofd_s *of;
  FAR struct mfs_new_ofd_comm_s *of_com;

  MFS_NEW_TRACE_LOG("Entry.");

  inode = filep->f_inode;
  DEBUGASSERT(inode != NULL);
  sb    = inode->i_private;
  MFS_NEW_TRACE_LOG("Sb obtained at %p", sb);
  DEBUGASSERT(sb != NULL);

  ret = nxmutex_lock(&MFS_NEW_FSLOCK(sb));
  if (predict_false(ret != OK))
    {
      MFS_NEW_LOG("Failed to acquire fs mutex.");
      goto errout;
    }

  MFS_NEW_TRACE_LOG("Locked.");

  of = filep->f_priv;
  of_com = of->com;

  of->com = NULL;
  of_com->refcount--;

  fs_heap_free(of);
  MFS_NEW_TRACE_LOG("Open file descriptor freed.");

  if (of_com->refcount == 0)
  {
    fs_heap_free(of_com);
    MFS_NEW_TRACE_LOG("Open file descriptor's common segment freed.");
  }

  nxmutex_unlock(&MFS_NEW_FSLOCK(sb));
  MFS_NEW_TRACE_LOG("Unlocked.");

  MFS_NEW_TRACE_LOG("Exit | Return %d", ret);
  return ret;

errout:
  MFS_NEW_TRACE_LOG("Exit | Return %d", ret);
  return ret;
}

static ssize_t mnemofs_new_read(FAR struct file *filep, FAR char *buffer,
                              size_t buflen)
{
  return -ENOSYS;
}

static ssize_t mnemofs_new_write(FAR struct file *filep, FAR const char *buffer,
                               size_t buflen)
{
  return -ENOSYS;
}

static off_t mnemofs_new_seek(FAR struct file *filep, off_t offset, int whence)
{
  return -ENOSYS;
}

static int mnemofs_new_ioctl(FAR struct file *filep, int cmd, unsigned long arg)
{
  return -ENOSYS;
}


static int mnemofs_new_truncate(FAR struct file *filep, off_t length)
{
  return -ENOSYS;
}

static int mnemofs_new_sync(FAR struct file *filep)
{
  return -ENOSYS;
}

static int mnemofs_new_dup(FAR const struct file *oldp, FAR struct file *newp)
{
  int                           ret       = OK;
  FAR struct mfs_new_sb_s       *sb;
  FAR struct inode *inode;
  FAR struct mfs_new_ofd_s *old_of;
  FAR struct mfs_new_ofd_s *new_of;
  FAR struct mfs_new_ofd_comm_s *of_com;

  MFS_NEW_TRACE_LOG("Entry.");

  inode = oldp->f_inode;
  DEBUGASSERT(inode != NULL);
  sb    = inode->i_private;
  MFS_NEW_TRACE_LOG("Sb obtained at %p", sb);
  DEBUGASSERT(sb != NULL);

  ret = nxmutex_lock(&MFS_NEW_FSLOCK(sb));
  if (predict_false(ret != OK))
    {
      MFS_NEW_LOG("Failed to acquire fs mutex.");
      goto errout;
    }

  MFS_NEW_TRACE_LOG("Locked.");

  old_of = oldp->f_priv;

  MFS_NEW_TRACE_LOG("Old file descriptor.");
  MFS_NEW_TRACE_LOG_OF(old_of);

  of_com = old_of->com;

  new_of = fs_heap_zalloc(sizeof(struct mfs_new_ofd_s));
  if (predict_false(new_of == NULL))
  {
    MFS_NEW_LOG("Could not allocated new file descriptor.");
    goto errout_with_lock;
  }

  MFS_NEW_TRACE_LOG("Allocated new file descriptor.");

  new_of->com = of_com;
  of_com->refcount++;
  list_initialize(&new_of->list);

  MFS_NEW_TRACE_LOG("New file descriptor.");
  MFS_NEW_TRACE_LOG_OF(new_of);

  list_add_tail(&MFS_NEW_OFS(sb), &new_of->list);
  MFS_NEW_TRACE_LOG("Added new file descriptor to open file list.");

  newp->f_priv = new_of;

  nxmutex_unlock(&MFS_NEW_FSLOCK(sb));
  MFS_NEW_TRACE_LOG("Unlocked.");

  MFS_NEW_TRACE_LOG("Exit | Return %d", ret);
  return ret;

errout_with_lock:
  nxmutex_unlock(&MFS_NEW_FSLOCK(sb));
  MFS_NEW_TRACE_LOG("Unlocked.");

errout:
  MFS_NEW_TRACE_LOG("Exit | Return %d", ret);
  return ret;
}

static int mnemofs_new_fstat(FAR const struct file *filep, FAR struct stat *buf)
{
  return -ENOSYS;
}

static int mnemofs_new_opendir(FAR struct inode *mountpt,
                               FAR const char *relpath,
                               FAR struct fs_dirent_s **dir)
{
  int                           ret       = OK;
  struct mfs_new_ctz_s          dir_ctz;
  FAR struct mfs_new_sb_s       *sb;
  struct mfs_new_dir_entry_s    dirent;
  FAR struct mfs_new_fsdirent_s *fsdirent;

  MFS_NEW_TRACE_LOG("Entry.");

  DEBUGASSERT(mountpt != NULL);
  sb = mountpt->i_private;
  MFS_NEW_TRACE_LOG("Sb obtained at %p.", sb);
  DEBUGASSERT(sb != NULL);

  ret = nxmutex_lock(&MFS_NEW_FSLOCK(sb));
  if (predict_false(ret != OK))
    {
      MFS_NEW_LOG("Failed to acquire fs mutex.");
      goto errout;
    }

  MFS_NEW_TRACE_LOG("Locked.");

  ret = mfs_new_path_traversal(sb, relpath, &dirent);
  if (predict_false(ret != OK))
    {
      MFS_NEW_LOG("Could not traverse the path.");
      goto errout_with_lock;
    }

  MFS_NEW_TRACE_LOG_DIRENT(&dirent);

  ret = mfs_new_dirent_is_dir(&dirent);
  if (ret == 0)
    {
      MFS_NEW_LOG("Openddir item is not a directory.");
      ret = -ENOTDIR;
      goto errout_with_dirent;
    }
  else if (predict_false(ret < 0))
    {
      MFS_NEW_LOG("Problem finding path item type.");
      goto errout_with_lock;
    }

  MFS_NEW_TRACE_LOG("Path item is a directory.");

  fsdirent = fs_heap_zalloc(sizeof(*fsdirent));
  if (predict_false(fsdirent == NULL))
    {
      MFS_NEW_LOG("No memory left.");
      ret = -ENOMEM;
      goto errout_with_dirent;
    }

  MFS_NEW_TRACE_LOG("fsdirent allocated at %p", fsdirent);

  DEBUGASSERT(dirent.loc.pg == 0);

  ret = mfs_new_get_latest_dir_rev(sb, dirent.loc.blk, NULL, &dir_ctz);
  if (predict_false(ret != OK))
    {
      MFS_NEW_LOG("Problems with getting the latest directory revision.");
      goto errout_with_fsdirent;
    }

  MFS_NEW_TRACE_LOG_CTZ(&dir_ctz);

  fsdirent->off = 0;
  fsdirent->idx = 0;
  fsdirent->dir_ctz = dir_ctz;
  fsdirent->dir_blk = dirent.loc.blk;

  MFS_NEW_TRACE_LOG_FSDIRENT(fsdirent);

  *dir = (FAR struct fs_dirent_s *) fsdirent;

  mfs_new_dirent_free(&dirent);
  MFS_NEW_TRACE_LOG("dirent freed.");

  nxmutex_unlock(&MFS_NEW_FSLOCK(sb));
  MFS_NEW_TRACE_LOG("Unlocked.");

  MFS_NEW_TRACE_LOG("Exit | Return %d", ret);
  return ret;

errout_with_fsdirent:
  fs_heap_free(fsdirent);
  MFS_NEW_TRACE_LOG("fsdirent freed.");

errout_with_dirent:
  mfs_new_dirent_free(&dirent);
  MFS_NEW_TRACE_LOG("dirent freed.");

errout_with_lock:
  nxmutex_unlock(&MFS_NEW_FSLOCK(sb));
  MFS_NEW_TRACE_LOG("Unlocked.");

errout:
  MFS_NEW_TRACE_LOG("Exit | Return %d", ret);
  return ret;
}

static int mnemofs_new_closedir(FAR struct inode *mountpt,
                              FAR struct fs_dirent_s *dir)
{
  int                       ret       = OK;
  struct mfs_new_fsdirent_s *fsdirent = (struct mfs_new_fsdirent_s *) dir;
  FAR struct mfs_new_sb_s   *sb;

  MFS_NEW_TRACE_LOG("Entry.");

  DEBUGASSERT(mountpt != NULL);
  sb  = mountpt->i_private;
  MFS_NEW_TRACE_LOG("Sb obtained at %p.", sb);
  DEBUGASSERT(sb != NULL);

  ret = nxmutex_lock(&MFS_NEW_FSLOCK(sb));
  if (predict_false(ret != OK))
    {
      MFS_NEW_LOG("Failed to acquire fs mutex.");
      goto errout;
    }

  MFS_NEW_TRACE_LOG("Locked.");

  fs_heap_free(fsdirent);
  MFS_NEW_TRACE_LOG("fsdirent freed.");

  nxmutex_unlock(&MFS_NEW_FSLOCK(sb));
  MFS_NEW_TRACE_LOG("Unlocked.");

  MFS_NEW_TRACE_LOG("Exit | Return %d", ret);
  return ret;

errout:
  MFS_NEW_TRACE_LOG("Exit | Return %d", ret);
  return ret;
}

static int mnemofs_new_readdir(FAR struct inode *mountpt,
                             FAR struct fs_dirent_s *dir,
                             FAR struct dirent *entry)
{
  int                       ret       = OK;
  struct mfs_new_fsdirent_s *fsdirent = (struct mfs_new_fsdirent_s *) dir;
  FAR struct mfs_new_sb_s   *sb;
  struct mfs_new_dir_entry_s dirent;

  MFS_NEW_TRACE_LOG("Entry.");

  DEBUGASSERT(mountpt != NULL);
  sb  = mountpt->i_private;
  MFS_NEW_TRACE_LOG("Sb obtained at %p.", sb);
  DEBUGASSERT(sb != NULL);

  ret = nxmutex_lock(&MFS_NEW_FSLOCK(sb));
  if (predict_false(ret != OK))
    {
      MFS_NEW_LOG("Failed to acquire fs mutex.");
      goto errout;
    }

  MFS_NEW_TRACE_LOG_FSDIRENT(fsdirent);

  if (fsdirent->idx == 0)
    {
      /* . */

      MFS_NEW_TRACE_LOG("Reading '.'");
      snprintf(entry->d_name, NAME_MAX + 1, ".");
      entry->d_type = DTYPE_DIRECTORY;
      fsdirent->idx++;
      goto errout_with_lock;
    }
  else if (fsdirent->idx == 1)
    {
      /* .. */

      MFS_NEW_TRACE_LOG("Reading '..'");
      snprintf(entry->d_name, NAME_MAX + 1, "..");
      entry->d_type = DTYPE_DIRECTORY;
      fsdirent->idx++;
      goto errout_with_lock;
    }

  MFS_NEW_TRACE_LOG("Reading fsdirent.");
  MFS_NEW_TRACE_LOG_FSDIRENT(fsdirent);

  ret = mfs_new_get_dirent_from_off(sb, fsdirent->dir_ctz, fsdirent->off, &dirent);
  if (predict_false(ret != OK))
  {
    MFS_NEW_TRACE_LOG("Problem getting direntry");
    goto errout_with_lock;
  }

  entry->d_type = (mfs_new_dirent_is_dir(&dirent)) ? DTYPE_DIRECTORY : DTYPE_FILE;
  snprintf(entry->d_name, NAME_MAX + 1, "%s", dirent.name);
  fsdirent->off += mfs_new_dirent_sz(&dirent);

  MFS_NEW_TRACE_LOG_FSDIRENT(fsdirent);

  mfs_new_dirent_free(&dirent);
  MFS_NEW_TRACE_LOG("dirent freed.");

  nxmutex_unlock(&MFS_NEW_FSLOCK(sb));
  MFS_NEW_TRACE_LOG("Unlocked.");

  MFS_NEW_TRACE_LOG("Exit | Return %d", ret);
  return ret;

errout_with_lock:
  nxmutex_unlock(&MFS_NEW_FSLOCK(sb));
  MFS_NEW_TRACE_LOG("Unlocked.");

errout:
  MFS_NEW_TRACE_LOG("Exit | Return %d", ret);
  return ret;
}

static int mnemofs_new_rewinddir(FAR struct inode *mountpt,
                               FAR struct fs_dirent_s *dir)
{
  int                       ret       = OK;
  struct mfs_new_fsdirent_s *fsdirent = (struct mfs_new_fsdirent_s *) dir;
  FAR struct mfs_new_sb_s   *sb;

  MFS_NEW_TRACE_LOG("Entry.");

  DEBUGASSERT(mountpt != NULL);
  sb  = mountpt->i_private;
  MFS_NEW_TRACE_LOG("Sb obtained at %p.", sb);
  DEBUGASSERT(sb != NULL);

  ret = nxmutex_lock(&MFS_NEW_FSLOCK(sb));
  if (predict_false(ret != OK))
    {
      MFS_NEW_LOG("Failed to acquire fs mutex.");
      goto errout;
    }

  MFS_NEW_TRACE_LOG_FSDIRENT(fsdirent);

  fsdirent->idx = 0;
  fsdirent->off = 0;

  MFS_NEW_TRACE_LOG_FSDIRENT(fsdirent);

  nxmutex_unlock(&MFS_NEW_FSLOCK(sb));
  MFS_NEW_TRACE_LOG("Unlocked.");

errout:
  MFS_NEW_TRACE_LOG("Exit | Return %d", ret);
  return ret;
}

static int mnemofs_new_bind(FAR struct inode *driver, FAR const void *data,
                          FAR void **handle)
{
  FAR struct mfs_new_sb_s *sb = NULL;
  int ret = OK;
  struct mtd_geometry_s geo;

  MFS_NEW_TRACE_LOG("Entry.");

  sb = fs_heap_malloc(sizeof(struct mfs_new_sb_s));
  if (!sb)
    {
      MFS_NEW_LOG("Could not allocate superblock.");
      ret = -ENOMEM;
      goto errout;
    }

  MFS_NEW_TRACE_LOG("Superblock allocated at %p.", sb);

  MTD_IOCTL(driver->u.i_mtd, MTDIOC_GEOMETRY, (unsigned long) &geo);

  memset(sb, 0, sizeof(struct mfs_new_sb_s));
  MFS_NEW_TRACE_LOG("Initialized superblock.");
  MFS_NEW_TRACE_LOG("Superblock: %p", sb);
  sb->drv = driver;
  MFS_NEW_TRACE_LOG("\tDriver: %p", sb->drv);
  sb->pg_sz = geo.blocksize;
  MFS_NEW_TRACE_LOG("\tPage Size: %u", sb->pg_sz);
  sb->blk_sz = geo.erasesize;
  MFS_NEW_TRACE_LOG("\tBlock Size: %u", sb->blk_sz);
  sb->n_blk = geo.neraseblocks;
  MFS_NEW_TRACE_LOG("\tNo. of Blocks: %u", sb->n_blk);
  sb->n_pg_in_blk = mfs_new_blk_sz(sb) / mfs_new_pg_sz(sb);
  MFS_NEW_TRACE_LOG("\tNo. of Pages per Block: %u", sb->n_pg_in_blk);

  nxmutex_init(&sb->fs_lock);
  MFS_NEW_TRACE_LOG("Initialized superblock file system lock.");

  list_initialize(&sb->o_fds);
  MFS_NEW_TRACE_LOG("Initialized list of open file descriptors.");

  if (data == NULL || !mfs_new_str_litcmp(data, "") || !mfs_new_str_litcmp(data, "autoformat"))
    {
      MFS_NEW_LOG("Doing an autoformat.");
      if (mfs_new_check_fmt(sb, &MFS_NEW_MN(sb)))
        {
          MFS_NEW_LOG("Device already formatted with mnemofs.");
          MFS_NEW_TRACE_LOG("Superblock:");
          MFS_NEW_TRACE_LOG("\tMaster Node: %d.", MFS_NEW_MN(sb));
        }
      else
        {
          MFS_NEW_TRACE_LOG("Device not formatted with mnemofs.");
          ret = mfs_new_fmt(sb);
          if (predict_false(ret != 0))
            {
              MFS_NEW_LOG("Error formatting with mnemofs.");
              goto errout_with_sb;
            }

          MFS_NEW_TRACE_LOG("Format done.");
        }
    }
  else if (!mfs_new_str_litcmp(data, "format"))
  {
    MFS_NEW_LOG("Doing a format.");
    ret = mfs_new_fmt(sb);
    if (predict_false(ret != 0))
      {
        MFS_NEW_LOG("Error formatting with mnemofs.");
        goto errout_with_sb;
      }

    MFS_NEW_TRACE_LOG("Format done.");
  }
  else {
    MFS_NEW_LOG("Unknown option: '%s'. Exitting...", (char *) data);
    goto errout_with_sb;
  }

  *handle = (FAR void *) sb;
  MFS_NEW_TRACE_LOG("Exit | Return: %d.", ret);
  return ret;

errout_with_sb:
  nxmutex_destroy(&sb->fs_lock);
  MFS_NEW_TRACE_LOG("Destroyed superblock file system lock.");

  fs_heap_free(sb);
  sb = NULL;
  MFS_NEW_TRACE_LOG("Freed superblock.");

errout:
  MFS_NEW_LOG("Exit | Return: %d.", ret);
  return ret;
}

static int mnemofs_new_unbind(FAR void *handle, FAR struct inode **driver,
                            unsigned int flags)
{
  FAR struct mfs_new_sb_s *sb = (FAR struct mfs_new_sb_s *) handle;

  MFS_NEW_TRACE_LOG("Entry.");

  *driver = sb->drv;

  nxmutex_destroy(&sb->fs_lock);
  MFS_NEW_TRACE_LOG("Destroyed superblock file system lock.");

  fs_heap_free(sb);
  MFS_NEW_TRACE_LOG("Freed superblock.");

  MFS_NEW_TRACE_LOG("Exit.");
  return OK;
}

static int mnemofs_new_statfs(FAR struct inode *mountpt, FAR struct statfs *buf)
{
  return -ENOSYS;
}

static int mnemofs_new_unlink(FAR struct inode *mountpt, FAR const char *relpath)
{
  return -ENOSYS;
}

static int mnemofs_new_mkdir(FAR struct inode *mountpt, FAR const char *relpath,
                           mode_t mode)
{
  return -ENOSYS;
}

static int mnemofs_new_rmdir(FAR struct inode *mountpt, FAR const char *relpath)
{
  return -ENOSYS;
}

static int mnemofs_new_rename(FAR struct inode *mountpt,
                            FAR const char *oldrelpath,
                            FAR const char *newrelpath)
{
  return -ENOSYS;
}

static int mnemofs_new_stat(FAR struct inode *mountpt, FAR const char *relpath,
                          FAR struct stat *buf)
{
  return -ENOSYS;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/
