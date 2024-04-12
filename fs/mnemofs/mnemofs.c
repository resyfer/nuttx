/****************************************************************************
 * fs/mnemofs/mnemofs.c
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

/****************************************************************************
 * Included Files
 ****************************************************************************/
#include <stdio.h>

#include <nuttx/fs/fs.h>
#include <nuttx/kmalloc.h>
#include <nuttx/mtd/mtd.h>

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

static int mnemofs_bind(FAR struct inode *blkdriver, FAR const void *data,
                        FAR void** handle);
static int mnemofs_unbind(FAR void *handle, FAR struct inode **blkdriver,
                          unsigned int flags);
static int mnemofs_statfs(FAR struct inode *mountpt, FAR struct statfs *buf);

static int mnemofs_unlink(FAR struct inode *mountpt, FAR const char *relpath);
static int mnemofs_mkdir(FAR struct inode *mountpt, FAR const char *relpath,
                          mode_t mode);
static int mnemofs_rmdir(FAR struct inode *mountpt, FAR const char *relpath);
static int mnemofs_rename(FAR struct inode *mountpt,
                          FAR const char *oldrelpath,
                          FAR const char *newrelpath);
static int mnemofs_stat(FAR struct inode *mountpt, FAR const char *relpath,
                          FAR struct stat *buf);

static int mnemofs_opendir(FAR struct inode *mountpt, FAR const char *relpath,
                            FAR struct fs_dirent_s **dir);
static int mnemofs_closedir(FAR struct inode *mountpt,
                            FAR struct fs_dirent_s *dir);
static int mnemofs_readdir(FAR struct inode *mountpt,
                            FAR struct fs_dirent_s *dir,
                            FAR struct dirent *entry);
static int mnemofs_rewinddir(FAR struct inode *mountpt,
                              FAR struct fs_dirent_s *dir);
static int mnemofs_open(FAR struct file *filep, FAR const char *relpath,
                 int oflags, mode_t mode);
static int mnemofs_close(FAR struct file *filep);
static ssize_t mnemofs_read(FAR struct file *filep, FAR char *buffer, size_t buflen);
static ssize_t mnemofs_write(FAR struct file *filep, FAR const char *buffer, size_t buflen);
static off_t mnemofs_seek(FAR struct file *filep, off_t offset, int whence);
static int mnemofs_ioctl(FAR struct file *filep, int cmd, unsigned long arg);
static int mnemofs_truncate(FAR struct file *filep, off_t length);

/****************************************************************************
 * Private Data
 ****************************************************************************/

/****************************************************************************
 * Public Data
 ****************************************************************************/

const struct mountpt_operations g_mnemofs_operations =
{
  mnemofs_open, /* open */
  mnemofs_close, /* close */
  mnemofs_read, /* read */
  mnemofs_write, /* write */
  mnemofs_seek, /* seek */
  mnemofs_ioctl, /* ioctl */
  NULL, /* mmap */
  mnemofs_truncate, /* truncate */
  NULL, /* poll */

  NULL, /* sync */
  NULL, /* dup */
  NULL, /* fstat */
  NULL, /* fchstat */

  mnemofs_opendir, /* opendir */
  mnemofs_closedir, /* closedir */
  mnemofs_readdir, /* readdir */
  mnemofs_rewinddir, /* rewinddir */

  mnemofs_bind, /* bind */
  mnemofs_unbind, /* unbind */
  mnemofs_statfs, /* statfs */

  mnemofs_unlink, /* unlink */
  mnemofs_mkdir, /* mkdir */
  mnemofs_rmdir, /* rmdir */
  mnemofs_rename, /* rename */
  mnemofs_stat, /* stat */
  NULL  /* chstat */
};

/* Volume Ops */

static int mnemofs_bind(FAR struct inode *blkdriver, FAR const void *data,
                        FAR void** handle)
{
  /* TODO: mountpt->i_private needs to have the sb_info */
  /* TODO */

  return OK;
}

static int mnemofs_unbind(FAR void *handle, FAR struct inode **blkdriver,
                          unsigned int flags)
{
  /* TODO */
  return OK;
}

static int mnemofs_statfs(FAR struct inode *mountpt, FAR struct statfs *buf)
{
  /* TODO */
  return OK;
}

/* Path Ops */

static int mnemofs_unlink(FAR struct inode *mountpt, FAR const char *relpath)
{
  return __mnemofs_unlink(MNEMOFS_SB(mountpt), relpath);
}

static int mnemofs_mkdir(FAR struct inode *mountpt, FAR const char *relpath,
                          mode_t mode)
{
  return __mnemofs_mkdir(MNEMOFS_SB(mountpt), relpath, mode);
}

static int mnemofs_rmdir(FAR struct inode *mountpt, FAR const char *relpath)
{
  return __mnemofs_rmdir(MNEMOFS_SB(mountpt), relpath);
}

static int mnemofs_rename(FAR struct inode *mountpt,
                          FAR const char *oldrelpath,
                          FAR const char *newrelpath)
{
  return __mnemofs_mv(MNEMOFS_SB(mountpt), oldrelpath, newrelpath);
}

static int mnemofs_stat(FAR struct inode *mountpt, FAR const char *relpath,
                          FAR struct stat *buf)
{
  /* TODO */
  return OK;
}

/* Dir Ops */

static int mnemofs_opendir(FAR struct inode *mountpt, FAR const char *relpath,
                            FAR struct fs_dirent_s **dir)
{
  return __mnemofs_opendir(MNEMOFS_SB(mountpt), relpath, dir);
}

static int mnemofs_closedir(FAR struct inode *mountpt,
                            FAR struct fs_dirent_s *dir)
{
  return __mnemofs_closedir(MNEMOFS_SB(mountpt), dir);
}

static int mnemofs_readdir(FAR struct inode *mountpt,
                            FAR struct fs_dirent_s *dir,
                            FAR struct dirent *entry)
{
  return __mnemofs_readdir(MNEMOFS_SB(mountpt), dir, entry);
}

static int mnemofs_rewinddir(FAR struct inode *mountpt,
                              FAR struct fs_dirent_s *dir)
{
  return __mnemofs_rewinddir(MNEMOFS_SB(mountpt), dir);
}

/*TODO: Macro for the typecast.*/
/*TODO: For now, filep->i_priv is SB. */
static int mnemofs_open(FAR struct file *filep, FAR const char *relpath, int oflags, mode_t mode) {
  return __mnemofs_open(filep, relpath, oflags, mode);
}

static int mnemofs_close(FAR struct file *filep) {
  return __mnemofs_close(filep);
}

static ssize_t mnemofs_read(FAR struct file *filep, FAR char *buffer, size_t buflen) {
  return __mnemofs_read(filep, buffer, buflen);
}

static ssize_t mnemofs_write(FAR struct file *filep, FAR const char *buffer, size_t buflen) {
  return __mnemofs_write(filep, buffer, buflen);
}

static off_t mnemofs_seek(FAR struct file *filep, off_t offset, int whence) {
  return __mnemofs_seek(filep, offset, whence);
}

static int mnemofs_ioctl(FAR struct file *filep, int cmd, unsigned long arg) {
  /* TODO */
  return OK;
}

static int mnemofs_truncate(FAR struct file *filep, off_t length) {
  /* TODO */
  return OK;
}