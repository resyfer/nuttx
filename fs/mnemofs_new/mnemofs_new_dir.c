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

#include <errno.h>
#include <nuttx/compiler.h>
#include <nuttx/config.h>
#include <fs_heap.h>
#include <mnemofs_new/mnemofs_new.h>
#include <nuttx/mtd/mtd.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/****************************************************************************
 * Private Types
 ****************************************************************************/

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

static int path_traversal_r(FAR const struct mfs_new_sb_s * const sb, FAR const char *relpath, const struct mfs_new_ctz_s dir_ctz, FAR struct mfs_new_dir_entry_s *dirent);
static int dir_is_fmt_needed(FAR const struct mfs_new_sb_s * const sb, const mfs_t dir_blk);

/****************************************************************************
 * Private Data
 ****************************************************************************/

/****************************************************************************
 * Public Data
 ****************************************************************************/

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static int path_traversal_r(FAR const struct mfs_new_sb_s * const sb,
                            FAR const char *relpath,
                            const struct mfs_new_ctz_s dir_ctz,
                            FAR struct mfs_new_dir_entry_s *dirent)
{
  int                        tmp;
  int                        ret                = OK;
  bool                       recursion_needed   = false;
  char                       item[PATH_MAX];
  mfs_t                      off                = 0;
  mfs_t                      item_name_hash     = 0;
  const char                 *item_next         = NULL;
  struct mfs_new_ctz_s       tmp_ctz;
  struct mfs_new_dir_entry_s _dirent;

  // TODO: Support . and ..

  MFS_NEW_TRACE_LOG("Entry.");

  recursion_needed = mfs_new_item_from_path(relpath, item, &item_next);
  MFS_NEW_TRACE_LOG("Recursion needed: %d", recursion_needed);

  item_name_hash = mfs_new_str_hash(item);
  MFS_NEW_TRACE_LOG("Item name hash obtained: %u", item_name_hash);

  while (off < mfs_new_ctz_sz(&dir_ctz)) {
    MFS_NEW_TRACE_LOG("Checking at offset '%u'", off);

    ret = mfs_new_get_dirent_from_off(sb, dir_ctz, off, &_dirent);
    if (predict_false(ret != OK))
    {
      MFS_NEW_LOG("Could not read dirent from offset '%u' from CTZ '%p'", off, &dir_ctz);
      MFS_NEW_TRACE_LOG_CTZ(&dir_ctz);
      goto errout;
    }

    MFS_NEW_TRACE_LOG("Obtained dirent for '%.*s'", _dirent.name_len, _dirent.name);
    MFS_NEW_TRACE_LOG_DIRENT(&_dirent);

    // Hash check shortcircuits the check
    if (_dirent.name_hash == item_name_hash && !strncmp(item, _dirent.name, _dirent.name_len))
    {
      MFS_NEW_TRACE_LOG("Found dirent at off '%u'", off);
      break;
    }

    MFS_NEW_TRACE_LOG("Advancing offset by %lu", mfs_new_dirent_sz(&_dirent));
    off += mfs_new_dirent_sz(&_dirent);
  }

  MFS_NEW_TRACE_LOG("Obtained dirent for path item.");

  // Check if it needs further recursion, and if it's possible to do so.
  if (recursion_needed)
    {
      /* Check if the current item is a directory and allows recursive travel into it. */
      tmp = mfs_new_dirent_is_dir(&_dirent);

      if (tmp == 0)
        {
          /* A file in middle of path. Can't proceed further. */
          MFS_NEW_LOG("Item '%s' is not a directory.", item);
          ret = -ENOTDIR;
          goto errout;
        }
      else
        {
          MFS_NEW_LOG("Could not check if item is a directory.");
          ret = tmp;
          goto errout;
        }

      ret = mfs_new_get_latest_dir_rev(sb, _dirent.blk, NULL, &tmp_ctz);
      if (predict_false(ret != OK))
        {
          MFS_NEW_LOG("Could not get the next item CTZ.");
          goto errout;
        }

      ret = path_traversal_r(sb, item_next, tmp_ctz, dirent);
      if (predict_false(ret != OK))
        {
          MFS_NEW_LOG("Error in recursion through the path.");
          goto errout;
        }
    }
  else
    {
      MFS_NEW_TRACE_LOG("Dirent found.");
      MFS_NEW_TRACE_LOG_DIRENT(&_dirent);
      *dirent = _dirent;
    }

  MFS_NEW_TRACE_LOG("Exit | Return %d", ret);
  return ret;

errout:
  MFS_NEW_TRACE_LOG("Exit | Return %d", ret);
  mfs_new_dirent_free(&_dirent);
  return ret;
}

// 0 - No, 1 - yes, < 0 - error
static int dir_is_fmt_needed(FAR const struct mfs_new_sb_s * const sb, const mfs_t dir_blk)
{
  int ret = OK;
  mfs_t rev_no;

  ret = mfs_new_get_latest_dir_rev(sb, dir_blk, &rev_no, NULL);
  if (predict_false(ret != OK))
  {
    goto errout;
  }

  ret = rev_no == mfs_new_n_pg_in_blk(sb) - 1;

  MFS_NEW_TRACE_LOG("Exit | Return %d", ret);
  return ret;

errout:
  return ret;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

// Dir structure:
// Block -> Page -> Multiple revisions of dir

int mfs_new_dir_init(FAR const struct mfs_new_sb_s * const sb, const mfs_t dir_blk)
{
  // TODO
  return OK;
}

int mfs_new_get_latest_dir_rev(FAR const struct mfs_new_sb_s * const sb, const mfs_t dir_blk, FAR mfs_t *rev_no, FAR struct mfs_new_ctz_s *dir_ctz)
{
  // TODO
  return OK;
}

int mfs_new_get_dirent_from_off(FAR const struct mfs_new_sb_s * const sb, const struct mfs_new_ctz_s dir_ctz, const mfs_t off, FAR struct mfs_new_dir_entry_s *dirent)
{
  // TODO
  return OK;
}

int mfs_new_upd_dirent_at_off(FAR struct mfs_new_sb_s * const sb, FAR struct mfs_new_ctz_s *dir_ctz, const mfs_t off, FAR const struct mfs_new_dir_entry_s * const dirent)
{
  // TODO
  // TODO: Add a method to shift n bytes from an offset in a CTZ list
  // TODO: This adds a new dir rev, and sets the new dir_ctz
  // TODO: This also checks for the need to format (as we add a revision)...use dir_is_fmt_needed
  return OK;
}

void mfs_new_dirent_free(FAR struct mfs_new_dir_entry_s * dirent)
{
  // TODO
}

int mfs_new_path_traversal(FAR struct mfs_new_sb_s * const sb, FAR const char * relpath, FAR struct mfs_new_dir_entry_s *dirent)
{
  int ret = OK;
  mfs_t root_blk;
  struct mfs_new_ctz_s root_ctz;
  struct mfs_new_dir_entry_s _dirent;

  MFS_NEW_TRACE_LOG("Entry.");

  memset(dirent, 0, sizeof(struct mfs_new_dir_entry_s));

  root_blk = mfs_new_root_blk(sb);
  MFS_NEW_TRACE_LOG("Root found at '%u' block.", root_blk);

  ret = mfs_new_get_latest_dir_rev(sb, root_blk, NULL, &root_ctz);
  if (predict_false(ret != OK))
  {
    MFS_NEW_LOG("Could not get latest root.");
    goto errout;
  }

  MFS_NEW_TRACE_LOG("Got latest root CTZ.");
  MFS_NEW_TRACE_LOG_CTZ(&root_ctz);

  ret = path_traversal_r(sb, relpath, root_ctz, &_dirent);
  if (predict_false(ret != OK))
  {
    MFS_NEW_LOG("Could not find entry for '%s'.", relpath);
    goto errout;
  }

  assert(dirent != NULL);
  MFS_NEW_TRACE_LOG("Direntry found for '%s'.", relpath);
  MFS_NEW_TRACE_LOG_DIRENT(&_dirent);

  *dirent = _dirent;

  MFS_NEW_TRACE_LOG("Exit | Return %d", ret);
  return ret;

errout:
  MFS_NEW_TRACE_LOG("Exit | Return %d", ret);
  return ret;
}

int mfs_new_dirent_is_dir(FAR const struct mfs_new_dir_entry_s *dirent)
{
  // 0 - No, 1 - Yes, < 0 - Error
  return 0;
}
