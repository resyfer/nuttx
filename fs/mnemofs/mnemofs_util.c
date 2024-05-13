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
#include <sys/endian.h>

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

uint8_t chksm(char *data, int data_len) {
  int c = 0;
  int i = 0;

  for(; i < data_len; i++) {
    c += data[i];
    c %= (1 << 8);
  }
  
  return c;
}

/* Highest 2^x dividing num */
uint8_t mnemofs_two_x(uint32_t num) {
  uint32_t pow = ((num) & (~(num - 1)));
  int c = 0;
  /* TODO: Use include/nuttx/lib/math.h as an option if proper header is set. */
  while(pow) {
    c++;
    pow >>= 1;
  }

  return c - 1;
}

/* Returns a -1 for num == 0. This "feature" has been used in the code, as is
essential. */
uint8_t mnemofs_log2(uint32_t num) {
  uint8_t c = 0;
  while(num) {
    c++;
    num>>=1;
  }
  return c - 1;
}

/* Get if file or directory (or maybe link later)*/
uint8_t mnemofs_get_type(mode_t mode) {
  /* TODO */
  return OK;
}

uint8_t mfs_strhash(FAR const char *str, ssize_t len) {
  ssize_t l = 0;
  ssize_t r = len - 1;
  uint16_t hash = 0;

  while(l <= r) {
    hash += str[l] * str[r] * l * r;
    l++;
    r--;
    hash %= (1 << 8);
  }

  return hash % (1 << 8);
}

/* Saves a datatype from CPU to Big Endian */
void mfs_h2ben(FAR const uint8_t * const dt, ssize_t size,
                FAR uint8_t * const bebuf)
{
#if BYTE_ORDER == LITTLE_ENDIAN
  uint8_t i;
  for(i = 0; i < size; i++) {
    bebuf[i] = dt[size - 1 - i];
  }
#elif
  memcpy(lebuf, dt, size);
#endif
}

/* Sets next to point to the start of the next fs object in path and return
len eg. if path is abcd/e/fgh, then it will return 4 and set pointer to e. */
/* IMP: Return type imposes a condition that each FS object must be max 255 */
/* It can be the case that path is /abcd/e/fgh/ and this, start here will be
at 'a' and next will be at 'e', and the returned value would be 4.
*/

/* For the last element, next will point outside the range of path */
uint8_t mfs_fsobj(FAR const char * const path, FAR const char ** start,
                  FAR const char ** next)
{
  FAR const char * tmp = path;
  uint8_t ret = 0;

  if(predict_false(!tmp)) {
    goto end;
  }

  while(*tmp && *tmp == '/') tmp++;

  *start = tmp;

  while(*tmp && *tmp != '/') {
    tmp++;
    ret++;
  }

  *next = tmp++;
end:
  return ret;
}

/* Get the hash of th very last FS object in path */
char *mfs_fsobj_last(FAR const char * const path, const mfs_t pathlen)
{
  /* TODO */
  return NULL;
}

/* Returns number of FS objects in the path. Doesn't check for the
validity. */
/* YAY! Another restriction on number of elements possible in path.
Is changeable. */
/* Counts windows of text that are separated by a / */
uint8_t mfs_fsobj_pathcount(FAR const char * const path, const mfs_t pathlen)
{
  uint8_t ret = 0;
  mfs_t i = 0;
  uint8_t window = false;
  while(i < pathlen)
  {
    if(window && path[i] == '/') {
      window = false;
      ret++;
    } else if (!window && path[i] != '/') {
      window = true;
    }
  }

  if(window) {
    ret++;
  }

  return ret;
}

/* Returns length of hasharr*/
uint8_t mfs_path_hash(FAR const char *relpath, const mfs_t pathlen,
                      FAR uint8_t * hasharr)
{
  FAR const char *start = relpath;
  FAR const char *next = NULL;
  uint8_t hasharr_idx = 0; /* Assumed uint8_t as length due to mfs_fsobj_pathcount */
  mfs_off_t ret = 0;

  while(start < relpath + pathlen) {
    ret = mfs_fsobj(start, &start, &next);
    if(ret < 0) {
      return 0;
    }

    hasharr[hasharr_idx++] = mfs_strhash(start, ret);

    start = next;
  }

  return hasharr_idx;
}