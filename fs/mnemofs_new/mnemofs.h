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

#define MFS_JRNL_NBLKS        20 /* TODO: Get from Kconfig */
#define MFS_JRNL_MAGIC        0xBB9CDF70U
#define MFS_JRNL_CHKSM        -(MFS_JRNL_MAGIC)
#define MFS_JRNL_LOGSZ        64
#define MFS_JRNL_BLKENTRYSZ   32

#define MFS_MB_MAGIC    0xE9861B66U
#define MFS_MB_CHKSM    -(MFS_MB_MAGIC)

#define MFS_JRNL(sb)    ((sb)->jrnl)
#define MFS_PGSZ(sb)    ((sb)->pg_sz)
#define MFS_BLKSZ(sb)    ((sb)->blk_sz)
#define MFS_PGINBLK(sb) ((sb)->n_pg_in_blk)

/****************************************************************************
 * Public Types
 ****************************************************************************/

typedef uint32_t mfs_t;

typedef struct
{
  mfs_t n_blks;   /* Excluding header and MBs */
  mfs_t n_logs;   /* Number of logs already added. */
  mfs_t jrnl_hd;
  mfs_t t_logs;   /* Log capacity in jrnl. */
  mfs_t rev;
} mfs_jrnl_s;

/* Superblock */

typedef struct
{
  mfs_jrnl_s  jrnl;
  mfs_t       pg_sz;
  mfs_t       blk_sz;
  mfs_t       n_pg_in_blk;
  mfs_t       n_blks;
  mfs_t       mb1;
  mfs_t       mb2;
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
  mfs_t sz;         /* Size of CTZ. */
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

/* mnemofs_rw.c */

/****************************************************************************
 * Name: mfs_rw_isbad
 *
 * Description:
 *   Check if a block is a bad block.
 *
 * Input Parameters:
 *   sb - Superblock
 *   blk - The block
 *
 * Returned Value:
 *   - 0 if not a bad block.
 *   - 1 if a bad block
 *   - negative if error.
 *
 ****************************************************************************/

int mfs_rw_isbad(FAR const mfs_sb_s * sb, mfs_t blk);

/****************************************************************************
 * Name: mfs_rw_markbad
 *
 * Description:
 *   Mark a block as bad block.
 *
 * Input Parameters:
 *   sb - Superblock
 *   blk - The block
 *
 * Returned Value:
 *   - 0 if not a bad block.
 *   - negative if error.
 *
 * Assumptions/Limitations:
 *   A newly-formed bad block is identified by the fact that the written data
 *   is not the same as the post-write read data. Only then should this
 *   function be used to mark the block as bad.
 *
 ****************************************************************************/

int mfs_rw_markbad(FAR const mfs_sb_s * sb, mfs_t blk);

/****************************************************************************
 * Name: mfs_rw_pgrd
 *
 * Description:
 *   Read a page.
 *
 * Input Parameters:
 *   sb - Superblock
 *   pg - The page
 *   buf - The read buffer
 *   n_buf - Length of buf
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if error.
 *
 ****************************************************************************/

int mfs_rw_pgrd(FAR const mfs_sb_s * sb, FAR const mfs_pgloc_t *pg,
                FAR char *buf, const mfs_t n_buf);

/****************************************************************************
 * Name: mfs_rw_pgrdoff
 *
 * Description:
 *   Read a buffer from an offset into a page.
 *
 * Input Parameters:
 *   sb - Superblock
 *   b - Byte location
 *   buf - The read buffer
 *   n_buf - Length of buf
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if error.
 *
 ****************************************************************************/

int mfs_rw_pgrdoff(FAR const mfs_sb_s * sb, FAR const mfs_bloc_t *b,
                   FAR char *buf, const mfs_t n_buf);

/****************************************************************************
 * Name: mfs_rw_pgwr
 *
 * Description:
 *   Write to a page.
 *
 * Input Parameters:
 *   sb - Superblock
 *   pg - The page
 *   buf - The write buffer
 *   n_buf - Length of buf
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if error.
 *
 ****************************************************************************/

int mfs_rw_pgwr(FAR mfs_sb_s * sb, FAR const mfs_pgloc_t *pg,
                FAR const char *buf, const mfs_t n_buf);

/****************************************************************************
 * Name: mfs_rw_pgwroff
 *
 * Description:
 *   Write a buffer to an offset into a page.
 *
 * Input Parameters:
 *   sb - Superblock
 *   b - Byte location
 *   buf - The read buffer
 *   n_buf - Length of buf
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if error.
 *
 * Assumptions/Limitations:
 *   - Assumes the rest of the page will be empty as that's how NAND works.
 *
 ****************************************************************************/

int mfs_rw_pgwroff(FAR mfs_sb_s * sb, FAR const mfs_bloc_t *b,
                   FAR const char *buf, const mfs_t n_buf);

/****************************************************************************
 * Name: mfs_rw_blker
 *
 * Description:
 *   Erase a block.
 *
 * Input Parameters:
 *   sb - Superblock
 *   blk - The block
 *
 * Returned Value:
 *   - 0 if OK.
 *   - negative if error.
 *
 ****************************************************************************/

int mfs_rw_blker(FAR mfs_sb_s * sb, const mfs_t blk);

/* mnemofs_ctz.c */

/****************************************************************************
 * Name: mfs_ctz_wr
 *
 * Description:
 *   Write a buffer in the form of a CTZ, and provide the CTZ pointer.
 *
 * Input Parameters:
 *   sb - Superblock
 *   buf - The write buffer
 *   n_buf - Length of buf
 *   ctz - The pointer to CTZ list
 *
 * Returned Value:
 *   - 0 if not a bad block.
 *   - negative if error.
 *
 ****************************************************************************/

int mfs_ctz_wr(FAR mfs_sb_s *sb, FAR const char *buf, mfs_t n_buf,
               FAR mfs_ctz_s *ctz);

/****************************************************************************
 * Name: mfs_ctz_rd
 *
 * Description:
 *   Read the data from a CTZ into a buffer.
 *
 * Input Parameters:
 *   sb - Superblock
 *   buf - The write buffer
 *   n_buf - Length of buf
 *   ctz - CTZ list
 *
 * Returned Value:
 *   - 0 if not a bad block.
 *   - negative if error.
 *
 ****************************************************************************/

int mfs_ctz_rd(FAR const mfs_sb_s *sb, FAR char *buf, mfs_t n_buf,
               FAR const mfs_ctz_s *ctz);

/****************************************************************************
 * Name: mfs_ctz_jump
 *
 * Description:
 *   Provide the page details of the byte at a particular offset from the
 *   start in the CTZ list.
 *
 * Input Parameters:
 *   sb - Superblock
 *   off - Offset
 *   pg - Page
 *
 * Returned Value:
 *   - 0 if not a bad block.
 *   - negative if error.
 *
 ****************************************************************************/

int mfs_ctz_jump(FAR const mfs_sb_s *sb, mfs_t off, FAR mfs_pgloc_t *pg);

/****************************************************************************
 * Name: mfs_ctz_wroff
 *
 * Description:
 *   Update a CTZ with a buffer at a particular offset from start.
 *
 *   Due to the way CTZ lists are, the pages that come before the offset's
 *   page will not be touched. However, all the following pages will have to
 *   be updated.
 *
 * Input Parameters:
 *   sb - Superblock
 *   off - Offset
 *   o_ctz - Original CTZ
 *   n_ctz - Pointer to new CTZ
 *
 * Returned Value:
 *   - 0 if not a bad block.
 *   - negative if error.
 *
 ****************************************************************************/

int mfs_ctz_wroff(FAR mfs_sb_s *sb, FAR char *buf, mfs_t n_buf,
                  FAR const mfs_ctz_s *o_ctz, FAR mfs_ctz_s *n_ctz);

/****************************************************************************
 * Name: mfs_ctz_off2idx
 *
 * Description:
 *   Get the index of the page in the CTZ list from the offset from start.
 *
 *   Can be used to find the total number of pages in the list by providing
 *   (sz - 1) as offset.
 *
 * Input Parameters:
 *   off - Offset
 *   idx - Index of page.
 *
 * Returned Value:
 *   - 0 if not a bad block.
 *   - negative if error.
 *
 ****************************************************************************/

int mfs_ctz_off2idx(const mfs_t off, FAR mfs_t *idx);

/* mnemofs_alloc.c */

/****************************************************************************
 * Name: mfs_alloc_getfreepg
 *
 * Description:
 *   Provide a free page, and mark it as being in use.
 *
 * Input Parameters:
 *   sb - Superblock
 *   pg - The provided page
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if not.
 *
 * Assumptions/Limitations:
 *   - Assumes Allocator is already initialized.
 *
 ****************************************************************************/

int mfs_alloc_getfreepg(FAR const mfs_sb_s *sb, FAR mfs_pgloc_t *pg);

/****************************************************************************
 * Name: mfs_alloc_getfreeblk
 *
 * Description:
 *   Provide a free block, and mark it as being in use.
 *
 * Input Parameters:
 *   sb - Superblock
 *   blk - The provided block
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if not.
 *
 * Assumptions/Limitations:
 *   - Assumes Allocator is already initialized.
 *
 ****************************************************************************/

int mfs_alloc_getfreeblk(FAR const mfs_sb_s *sb, FAR mfs_t *blk);

/****************************************************************************
 * Name: mfs_alloc_markpgfree
 *
 * Description:
 *   Mark an in-use page as free.
 *
 * Input Parameters:
 *   sb - Superblock
 *   pg - The page
 *
 * Returned Value:
 *   - 0 if OK
 *   - 1 if already free.
 *   - negative if error.
 *
 * Assumptions/Limitations:
 *   - Assumes Allocator is already initialized.
 *
 ****************************************************************************/

int mfs_alloc_markpgfree(FAR mfs_sb_s *sb, FAR const mfs_pgloc_t *pg);

/****************************************************************************
 * Name: mfs_alloc_markpgused
 *
 * Description:
 *   Mark a page as used.
 *
 * Input Parameters:
 *   sb - Superblock
 *   pg - The page
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if error.
 *
 * Assumptions/Limitations:
 *   - Use this only during initialization where the on-device data is read.
 *
 ****************************************************************************/

int mfs_alloc_markpgused(FAR mfs_sb_s *sb, FAR const mfs_pgloc_t *pg);

/****************************************************************************
 * Name: mfs_alloc_markblkfree
 *
 * Description:
 *   Mark an in-use block as free.
 *
 * Input Parameters:
 *   sb - Superblock
 *   pg - The provided page number
 *
 * Returned Value:
 *   - 0 if OK
 *   - 1 if already free.
 *   - negative if error.
 *
 * Assumptions/Limitations:
 *   - Assumes Allocator is already initialized.
 *
 ****************************************************************************/

int mfs_alloc_markblkfree(FAR mfs_sb_s *sb, FAR mfs_t blk);

/****************************************************************************
 * Name: mfs_alloc_markblkused
 *
 * Description:
 *   Mark a block as used.
 *
 * Input Parameters:
 *   sb - Superblock
 *   blk - The block number
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if error.
 *
 * Assumptions/Limitations:
 *   - Use this only during initialization where the on-device data is read.
 *
 ****************************************************************************/

int mfs_alloc_markblkused(FAR mfs_sb_s *sb, FAR mfs_t blk);

/****************************************************************************
 * Name: mfs_alloc_init
 *
 * Description:
 *   Traverse the entire tree and check all pages that are full. Use bitmap
 *   to check what pages are full. The compression ratio is basically
 *   (8 * pg_sz):1 as 1 byte can hold 8 bits for each page.
 *
 * Input Parameters:
 *   sb - Superblock
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if not.
 *
 * Assumptions/Limitations:
 *   - This should only be done before master node is initialized (traverse
 *     the tree), and the journal (as it takes space) and the pages need to
 *     be noted.
 *   - This belongs to the *_init group of functions, which are supposed to
 *     be used only in cases where the device is already formatted with
 *     mnemofs and the on-device data needs to be read and initialized.
 *
 ****************************************************************************/

int mfs_alloc_init(FAR mfs_sb_s *sb);

/****************************************************************************
 * Name: mfs_alloc_fmt
 *
 * Description:
 *   Format the block allocator.
 *
 * Input Parameters:
 *   sb - Superblock
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if error.
 *
 * Assumptions/Limitations:
 *   - This should only be done before master node and journal are formatted.
 *   - This belongs to the *_fmt group of functions, which are supposed to be
 *     used only in cases where the device is needs a clean format.
 *
 ****************************************************************************/

int mfs_alloc_fmt(FAR mfs_sb_s *sb);

/****************************************************************************
 * Name: mfs_alloc_flush
 *
 * Description:
 *   Erase all the blocks that can be freed.
 *
 * Input Parameters:
 *   sb - Superblock
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if error.
 *
 * Assumptions/Limitations:
 *   - Since this will remove written data, and our file system is
 *     Copy-On-Write, this should be run only after and immmediately after
 *     the new master node is written. Only then it's guaranteed we don't
 *     need the old data.
 *
 ****************************************************************************/

int mfs_alloc_flush(FAR mfs_sb_s *sb);

/* mnemofs_jrnl.c */

/****************************************************************************
 * Name: mfs_jrnl_rd
 *
 * Description:
 *   Read data in a CTZ list and apply updates from the journal to it.
 *
 * Input Parameters:
 *   sb - Superblock
 *   buf - Read buffer
 *   n_buf - Size of buf
 *   ctz - CTZ list
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if error.
 *
 * Assumptions/Limitations:
 *   - This should only be done after journal is initialized/formatted.
 *
 ****************************************************************************/

int mfs_jrnl_rd(FAR const mfs_sb_s *sb, FAR char *buf, mfs_t n_buf,
                FAR const mfs_ctz_s *ctz);

/****************************************************************************
 * Name: mfs_jrnl_wr
 *
 * Description:
 *   Write data in the form of a CTZ list through the journal.
 *
 *   If the journal is not full, this will just add a log into the journal.
 *   If it is full, it will flush the journal and then write it as a log to
 *   the journal.
 *
 * Input Parameters:
 *   sb - Superblock
 *   buf - Write buffer
 *   n_buf - Size of buf
 *   ctz - CTZ list
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if error.
 *
 * Assumptions/Limitations:
 *   - This should only be done after journal is initialized/formatted.
 *
 ****************************************************************************/

int mfs_jrnl_wr(FAR mfs_sb_s *sb, FAR const char *buf, mfs_t n_buf,
                FAR mfs_ctz_s *ctz);

/****************************************************************************
 * Name: mfs_jrnl_latest
 *
 * Description:
 *   Search the latest location of the journal on the device. Also clears
 *   any left over journals (due to some kind of mid-flush powerloss).
 *
 * Input Parameters:
 *   sb - Superblock
 *   blk - Journal header block.
 *   rev - Revision
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if error.
 *
 * Assumptions/Limitations:
 *   - This is used during the process of initializing journal.
 *
 ****************************************************************************/

int
mfs_jrnl_latest(FAR mfs_sb_s *sb, FAR mfs_t *blk, FAR mfs_t *rev);

/****************************************************************************
 * Name: mfs_jrnl_fmt
 *
 * Description:
 *   Format a journal.
 *
 * Input Parameters:
 *   sb - Superblock
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if error.
 *
 * Assumptions/Limitations:
 *   - This should only be done before master node is formatted.
 *   - This belongs to the *_fmt group of functions, which are supposed to be
 *     used only in cases where the device is needs a clean format.
 *
 ****************************************************************************/

int mfs_jrnl_fmt(FAR mfs_sb_s *sb);

/****************************************************************************
 * Name: mfs_jrnl_init
 *
 * Description:
 *   Intiialize a journal by reading it from the device.
 *
 * Input Parameters:
 *   sb - Superblock
 *   blk - First block of journal
 *   blk - Revision number of journal
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if error.
 *
 * Assumptions/Limitations:
 *   - This belongs to the *_init group of functions, which are supposed to
 *     be used only in cases where the device is already formatted with
 *     mnemofs and the on-device data needs to be read and initialized.
 *   - The latest journal has already been found and the revision number
 *     obtained.
 *
 ****************************************************************************/

int mfs_jrnl_init(FAR mfs_sb_s *sb, mfs_t blk, mfs_t rev);

/****************************************************************************
 * Name: mfs_jrnl_flush
 *
 * Description:
 *   Flush the journal when it is full.
 *
 * Input Parameters:
 *   sb - Superblock
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if error.
 *
 * Assumptions/Limitations:
 *   - The journal will also move.
 *   - If the master blocks are already full as well, then the journal AND
 *     the master blocks will move. If not, then only the journal moves.
 *
 ****************************************************************************/

int mfs_jrnl_flush(FAR mfs_sb_s *sb);

/****************************************************************************
 * Name: mfs_jrnl_isflushreq
 *
 * Description:
 *   Is the journal full.
 *
 * Input Parameters:
 *   sb         - Superblock
 *   new_log_sz - Size of the log to be added
 *
 * Returned Value:
 *   Boolean if the journal requires a flush.
 *
 ****************************************************************************/

bool mfs_jrnl_isflushreq(FAR mfs_sb_s *sb, mfs_t new_log_sz);

/* mnemofs_mb.c */

/****************************************************************************
 * Name: mfs_mb_getroot
 *
 * Description:
 *   Get the page containing the root of the file system.
 *
 *   The root is synonymous with the master node, and that's present in the
 *   last-written master node to the master block. Both master blocks have
 *   identical blocks (unless power failure prevents write to both, in which
 *   case, the power up intiialization should fix it).
 *
 * Input Parameters:
 *   sb - Superblock
 *   pg - The page
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if error.
 *
 ****************************************************************************/

int mfs_mb_getroot(FAR const mfs_sb_s *sb, FAR mfs_pgloc_t *pg);

/****************************************************************************
 * Name: mfs_mb_fmt
 *
 * Description:
 *   Format master blocks.
 *
 *   The master blocks contain master nodes, which contain the information
 *   needed by in-memory superblock. This also includes the root of the
 *   file system.
 *
 *   The moment the format is done, a new master node will be added and
 *   the file system root pointer will point to a page which is empty
 *   and has not been written in. This is the same process as any empty
 *   item which is added to the fs.
 *
 * Input Parameters:
 *   sb - Superblock
 *   mb1 - Master Block 1
 *   mb2 - Master Block 2
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if error.
 *
 * Assumptions/Limitations:
 *   - The superblock's struct is basically missing a lot of information
 *     before this, so it's adivsable to use this function as quickly as
 *     possible.
 *   - This belongs to the *_fmt group of functions, which are supposed to be
 *     used only in cases where the device is needs a clean format.
 *
 ****************************************************************************/

int mfs_mb_fmt(FAR mfs_sb_s *sb, const mfs_t mb1, const mfs_t mb2);

/****************************************************************************
 * Name: mfs_mb_init
 *
 * Description:
 *   Format master blocks.
 *
 *   The moment the format is done, a new master node will be added and
 *   the file system root pointer will point to a page which is empty
 *   and has not been written in. This is the same process as any empty
 *   item which is added to the fs.
 *
 *   If both master blocks have unequal number of writes (they can differ by
 *   at max 1), then the one with more has the latest master node.
 *
 * Input Parameters:
 *   sb - Superblock
 *   mb1 - Master Block 1
 *   mb2 - Master Block 2
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if error.
 *
 * Assumptions/Limitations:
 *   - The superblock's struct is basically missing a lot of information
 *     before this, so it's adivsable to use this function as quickly as
 *     possible.
 *   - This belongs to the *_init group of functions, which are supposed to
 *     be used only in cases where the device is already formatted with
 *     mnemofs and the on-device data needs to be read and initialized.
 *
 ****************************************************************************/

int mfs_mb_init(FAR mfs_sb_s *sb, const mfs_t mb1, const mfs_t mb2);

/****************************************************************************
 * Name: mfs_mb_mv
 *
 * Description:
 *   Move master blocks.
 *
 * Input Parameters:
 *   sb - Superblock
 *   mb1 - Master Block 1
 *   mb2 - Master Block 2
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if error.
 *
 * Assumptions/Limitations:
 *   - The superblock's struct is basically missing a lot of information
 *     before this, so it's adivsable to use this function as quickly as
 *     possible.
 *   - This belongs to the *_init group of functions, which are supposed to
 *     be used only in cases where the device is already formatted with
 *     mnemofs and the on-device data needs to be read and initialized.
 *
 ****************************************************************************/

int mfs_mb_mv(FAR mfs_sb_s *sb, FAR mfs_t *mb1, FAR mfs_t *mb2);

/****************************************************************************
 * Name: mfs_mb_wr
 *
 * Description:
 *   Write a master node (and thus superblock) to the latest available place
 *   for the master node.
 *
 * Input Parameters:
 *   sb - Superblock
 *   pg - Page
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if error.
 *
 ****************************************************************************/

int mfs_mb_wr(FAR mfs_sb_s *sb, mfs_pgloc_t *pg);

/* mnemofs_dir.c */

/****************************************************************************
 * Name: mfs_dir_init
 *
 * Description:
 *   Initialize an open directory for traversal.
 *
 * Input Parameters:
 *   sb - Superblock
 *   ctz - CTZ list containing the directory
 *   dir - Open directory iterator
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if error.
 *
 ****************************************************************************/

int mfs_dir_init(FAR const mfs_sb_s *sb, FAR const mfs_ctz_s *ctz,
                 FAR mfs_dir_s *dir);

/****************************************************************************
 * Name: mfs_dir_rddirent
 *
 * Description:
 *   Read direntry currently pointed by the iterator.
 *
 * Input Parameters:
 *   sb - Superblock
 *   dir - Open directory iterator
 *   dirent - Direntry information
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if error.
 *
 ****************************************************************************/

int mfs_dir_rddirent(FAR const mfs_sb_s *sb, FAR const mfs_dir_s *dir,
                     FAR mfs_dirent_s *dirent);

/****************************************************************************
 * Name: mfs_dir_rddirentadv
 *
 * Description:
 *   Read direntry currently pointed by the iterator and advance it to next
 *   direntry.
 *
 * Input Parameters:
 *   sb - Superblock
 *   dir - Open directory iterator
 *   dirent - Direntry information
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if error.
 *
 ****************************************************************************/

int mfs_dir_rddirentadv(FAR const mfs_sb_s *sb, FAR mfs_dir_s *dir,
                        FAR mfs_dirent_s *dirent);

/****************************************************************************
 * Name: mfs_dir_unlinkdirent
 *
 * Description:
 *   Unlink a direntry.
 *
 * Input Parameters:
 *   sb - Superblock
 *   dir - Open directory iterator
 *   dirent - Direntry information
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if error.
 *
 ****************************************************************************/

int mfs_dir_unlinkdirent(FAR const mfs_sb_s *sb, FAR mfs_dir_s *dir,
                         FAR const mfs_dirent_s *dirent);

/****************************************************************************
 * Name: mfs_dir_appenddirent
 *
 * Description:
 *   Append a direntry to a directory.
 *
 * Input Parameters:
 *   sb - Superblock
 *   dir - Open directory iterator
 *   dirent - Direntry information
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if error.
 *
 ****************************************************************************/

int mfs_dir_appenddirent(FAR const mfs_sb_s *sb, FAR mfs_dir_s *dir,
                         FAR const mfs_dirent_s * dirent);

/****************************************************************************
 * Name: mfs_dir_isdirend
 *
 * Description:
 *   Check if iterator is pointing to the end of the directory.
 *
 * Input Parameters:
 *   sb - Superblock
 *   dir - Open directory iterator
 *
 * Returned Value:
 *   Boolean if the directory iterator has reached the end or not.
 *
 ****************************************************************************/

bool mfs_dir_isdirend(FAR const mfs_sb_s *sb, FAR mfs_dir_s *dir);

/* mnemofs_sb.c */

/****************************************************************************
 * Name: mfs_sb_init
 *
 * Description:
 *   Initialize the superblock.
 *
 * Input Parameters:
 *   sb - Superblock
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if error.
 *
 * Assumptions/Limitations:
 *   - This belongs to the *_init group of functions, which are supposed to
 *     be used only in cases where the device is already formatted with
 *     mnemofs and the on-device data needs to be read and initialized.
 *
 ****************************************************************************/

int mfs_sb_init(FAR mfs_sb_s *sb);

/* mnemofs_util.c */

/****************************************************************************
 * Name: mfs_calc_chksm16
 *
 * Description:
 *   Calculate 16-bit checksum.
 *
 * Input Parameters:
 *   buf - Buffer
 *   n_buf - Size of buffer
 *
 * Returned Value:
 *   Checksum
 *
 ****************************************************************************/

uint16_t mfs_calc_chksm16(FAR char *buf, const mfs_t n_buf);

#undef EXTERN
#ifdef __cplusplus
}
#endif

#endif /* __FS_MNEMOFS_NEW_MNEMOFS_H */
