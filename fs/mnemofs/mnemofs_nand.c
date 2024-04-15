/****************************************************************************
 * fs/mnemofs/mnemofs_nand.c
 * NAND operations of mnemofs.
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

/****************************************************************************
 * Public Data
 ****************************************************************************/

/* TODO: Write operations would have a system where they can change the page
number if they found it out to be a bad block. */

/* TODO:::: I have an idea where page 0 would memset a pagelength in buffer to 0
instead of the actual buffer. */
/* TODO:::: Similarly, if someone tries to write to page 0, create a new block
for it. Also create an internal function, so that superblocks can be rewritten
when desired (I don't plan to update superblocks). */
ssize_t mnemofs_write_page(char *data, uint64_t datalen, uint32_t page, uint8_t off) {
  /* TODO */ /* Cache */
  return 0;
}

/* Returns the length of the data read (incase it runs out of space) */
ssize_t mnemofs_write_data(char *data, uint64_t datalen, uint32_t page, uint8_t off) {
  /* TODO */ /* Cache */
  return 0;
};

/* Handles endianness */
ssize_t mnemofs_write_mfs_t(mfs_t *data, uint32_t page, uint8_t off) {
  return 0;
}

/* Size offset. Mention the size in the first sb->log_pg_sz bits of page*/
/* Returns the length of the data read (incase it runs out of space) */
ssize_t mnemofs_write_data_szoff(char *data, uint64_t datalen, uint32_t page, uint8_t off) {
  /* TODO */ /* Internally use mnemofs_write_data */
  return 0;
};

/* TODO:::: I have an idea where page 0 would memset a pagelength in buffer to 0
instead of the actual buffer. */
/* TODO:::: Similarly, if someone tries to write to page 0, create a new block
for it. Also create an internal function, so that superblocks can be rewritten
when desired (I don't plan to update superblocks). */
/* Reads data, regardless if it was written in or not. */
/* Returns length read. It doesn't extend past the page. */
ssize_t mnemofs_read_page(char *data, uint64_t datalen, uint32_t page, uint8_t off) {
  /* TODO */ /* Cache */
  return 0;
}

/* Returns the length of the data read (incase it runs out of space) */
ssize_t mnemofs_read_data(char *data, uint64_t datalen, uint32_t page, uint8_t off) {
  /* TODO */ /* Cache */
  return 0;
};

/* Returns the length of the data read (incase it runs out of space) */
/* Handles endianness */
ssize_t mnemofs_read_mfs_t(mfs_t *data, uint32_t page, uint8_t off) {
  /* TODO */ /* Cache */
  return 0;
};

/* Size offset. Mention the size in the first sb->log_pg_sz bits of page */
/* Returns the length of the data read (incase it runs out of space) */
ssize_t mnemofs_read_data_szoff(char *data, uint64_t datalen, uint32_t page, uint8_t off) {
  /* TODO */ /* Internally use mnemofs_write_data */
  return 0;
};