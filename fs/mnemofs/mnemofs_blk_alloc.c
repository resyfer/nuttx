/****************************************************************************
 * fs/mnemofs/mnemofs_blk_alloc.c
 * Block ALlocator for mnemofs
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

#include <nuttx/mtd/nand.h>

#include "mnemofs.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/****************************************************************************
 * Private Types
 ****************************************************************************/

enum chk_color {
  RED,
  BLACK
};

struct chk_node {
  uint8_t   color: 1;
  uint8_t   __res1: 1;
  uint16_t  chk_no: 14;
  uint16_t  chk_wear;
  
  uint8_t   __res2: 1;
  uint16_t chk_rb_left: 14;
  uint8_t   __res3: 1;
  uint16_t chk_rb_right: 14;
  
  uint8_t   __res4: 1;
  uint16_t chk_hp_left: 14;
  uint8_t   __res5: 1;
  uint16_t chk_hp_right: 14;
};

struct blk_allc {
  struct chk_node *free;
  struct chk_node *part;
  struct chk_node *full;
};

// TODO: Use this.
// static struct blk_allc alloc;

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

/****************************************************************************
 * Private Data
 ****************************************************************************/

/****************************************************************************
 * Public Data
 ****************************************************************************/


/* Initializes the block allocator and required memory */
int mnemofs_blk_alloc_init(void)
{
  /* TODO */
  return OK;
}

/* Free memory of block allocator. */
int mnemofs_blk_alloc_exit(void)
{
  /* TODO */
  return OK;
}

/* TODO: Mark that the block is being used to write on it. mutex. */
uint32_t mnemofs_get_blk(void) {
  /* TODO */
  return 0;
}

uint32_t mnemofs_get_pg(void) {
  /* TODO */
  return 0;
}

/* TODO: Mark that a block is full. Mostly used when block is written fully.
This is useful especially for master nodes and journal nodes. */
int mnemofs_blk_mark_full(uint32_t blk) {
  return OK;
}

/* Mark page for deletion */
/* TODO: Implementation */
/* TODO: Mutex */
int mnemofs_pg_dlt(uint32_t pg) {
  return OK;
}

int mnemofs_pg_mrkdlt(mfs_t pg) {
  return OK;
}