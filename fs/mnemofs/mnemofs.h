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

#ifndef __FS_MNEMOFS_MNEMOFS_H
#define __FS_MNEMOFS_MNEMOFS_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <stddef.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define MFS_LOG_BLOCKS_PER_CHUNK    (16)
#define MFS_BLOCKS_PER_CHUNK        (1 << MFS_LOG_BLOCKS_PER_CHUNK)

// TODO: File structure according to NuttX standard

/* Super block */
struct mfs_sb_disk_s
{
};

struct mfs_sb_info_s
{
  //TODO: mutex_t fs_lock;

  FAR struct inode *blkdrv;
  // FAR struct mtd_geometry_s fs_geo;
  uint32_t n_chunks; /* Chunks are 1 << 31 B in size approx */
  uint32_t n_pages_per_block; /* 1 << 5 or 1 << 6 usually */
  uint32_t n_page_size;

  struct mfs_sb_disk_s sb_disk;
};

/* Chunk */
struct mfs_chunk_disk_s
{
  
};

/* Block */
struct mfs_block_disk_s
{
  union
  {
    struct mfs_block_disk_s *block;
    uint8_t __res1[64];
  };

  union
  {
    struct mfs_chunk_disk_s *chunk;
    uint8_t __res2[64];
  };
};

struct mfs_block_info_s
{
};

#endif /* __FS_MNEMOFS_MNEMOFS_H */