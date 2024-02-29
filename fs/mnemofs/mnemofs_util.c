/****************************************************************************
 * fs/mnemofs/mnemofs_util.c
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

#include <stddef.h>
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

/****************************************************************************
 * Private Data
 ****************************************************************************/

// static inline uint32_t chunk_to_block(FAR const struct mfs_sb_info_s *sb,
//                                       const uint32_t chunk)
// {
//   return (chunk << MFS_LOG_BLOCKS_PER_CHUNK) * sb->n_pages_per_block;
// }

// static inline uint32_t block_to_chunk(FAR const struct mfs_sb_info_s *sb,
//                                       const uint32_t block)
// {
//   return block >> MFS_LOG_BLOCKS_PER_CHUNK;
// }

// static inline uint32_t chunk_to_page(FAR const struct mfs_sb_info_s *sb,
//                                       const uint32_t chunk)
// {
//   return chunk_to_block(sb, chunk) * sb->n_pages_per_block;
// }

// static inline uint32_t page_to_chunk(FAR const struct mfs_sb_info_s *sb,
//                                       const uint32_t page)
// {
//   return block_to_chunk(sb, page / sb->n_pages_per_block);
// }

// static inline uint32_t block_to_page(FAR const struct mfs_sb_info_s *sb,
//                                       const uint32_t block)
// {
//   return block * sb->n_pages_per_block;
// }

// static inline uint32_t page_to_block(FAR const struct mfs_sb_info_s *sb,
//                                       const uint32_t page)
// {
//   return page / sb->n_pages_per_block;
// }


/****************************************************************************
 * Public Data
 ****************************************************************************/
