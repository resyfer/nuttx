/****************************************************************************
 * fs/mnemofs/mnemofs_journal.c
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

#include <nuttx/kmalloc.h>

#include "mnemofs.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/****************************************************************************
 * Private Types
 ****************************************************************************/

/* UPDATE: Master block pointers will be stored in the last page of first block
right after the pointer to next node in the block. */
struct jrnl_info {
  uint32_t  head_pg; /* Journal Head */
  uint32_t  rem_blks; /* Remaining blocks left after block with index excluding master blocks */
  uint32_t  idx_page; /* Page no. where to insert next log */
  uint32_t  mb_1; /* Master Block 1 */
  uint32_t  mb_2; /* Master Block 1 */
};

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

/****************************************************************************
 * Private Data
 ****************************************************************************/

static struct jrnl_info jrnl; /* TODO: Move this info SB to allow multiple mounts*/

/****************************************************************************
 * Public Data
 ****************************************************************************/


/* TODO: Testing */
/* TODO: Later make this private, and then allow different "save_log" funtions
like "save_log_file" or "save_log_dir" according to need, and then they
will internally call "save_log" and then send the required "data" according
to the various strucutures. */

/* Saves a log of a certain type to the journal by attaching the type, the
length of the actual data, and then the actual data's checksum. This final
data is then rounded off to the nearest higher page size. */
static int save_log(struct mnemofs_sb_info *sb, char *data, uint16_t data_len, uint8_t type) {

  /* TODO: Think about endianess when logs are saved to journal */

  int i;
  int len;
  uint8_t chksum;
  int ret = OK;

  /* TODO: Return error if type is for updating master */

  /* Checksum */
  chksum = mnemofs_chksm(data, data_len);

  len = sizeof(LOG_MAX) + sizeof(data_len) + data_len + sizeof(chksum);

  /* Round off to nearest page size */
  if(len % sb->pg_sz != 0) {
    len += (sb->pg_sz - (len % sb->pg_sz));
  }

  char* data_log = kmm_zalloc(len);
  if(!data_log) {
    ret = -ENOMEM;
    goto errout;
  }

  /* TODO: Ensure if, say, type is 3, and LOG_MAX is 7, then type is written
      as 011 and not just 11 */

  /* Serialize, Store & Update Head */

  /* TODO: Find a way to reduce the pluses. */
  memcpy(data_log, &type, sizeof(LOG_MAX));
  memcpy(data_log + sizeof(LOG_MAX), &data_len, sizeof(data_len));
  memcpy(data_log + sizeof(LOG_MAX) + sizeof(data_len), data, data_len);
  memcpy(data_log + sizeof(LOG_MAX) + sizeof(data_len) + data_len, &chksum, sizeof(chksum));

  /* If space required is more than size available in journal */
  if(len > (jrnl.rem_blks * (sb->pg_in_blk - 1) + ((sb->pg_in_blk - 1) - jrnl.idx_page)) * sb->pg_sz) {
    ret = -ENOMEM;
    goto errout_with_log;
  }

  i = 0;
  while(i < len) {

    uint8_t rem_pgs = (sb->pg_in_blk - 1) - jrnl.idx_page; /* TODO: Assert that RHS is of uint8_t */
    uint32_t capacity = rem_pgs * sb->pg_sz;

    if(len <= capacity) {
      mnemofs_write_data(data_log + i, len, jrnl.idx_page, 0);
      /* TODO: If j is needed later, then update j here */
      break;
    } else {
      mnemofs_write_data(data_log + i, capacity, jrnl.idx_page, 0);
      len -= capacity;
      i += capacity;
      mnemofs_read_data((char *) &jrnl.idx_page,
                        sb->pg_sz, jrnl.idx_page + rem_pgs, 0);
      jrnl.rem_blks--;
    }
  }

errout_with_log:
  kmm_free(data_log);

errout:
  return ret;
}

/* NOTE: This sets up an empty journal */
/* TODO: Read journal from the flash (another function)*/
/* This does not care if another journal already exists. Its job is to allocate
space for a new journal, set up its circular linked list pointers, and return
the master block numbers via the parameters. */
/* NOTE: THIS DOES NOT INITIALIZE master blocks. Use init_master for that. */
/* TODO: Testing */
int init_empty_jrnl(struct mnemofs_sb_info *sb, uint32_t *jrnl_blk, uint32_t *master_blk0, uint32_t *master_blk1) {
  /* TODO: endianes. */
  int i;
  int ret = OK;
  int page = 0;
  uint32_t blk0;
  uint32_t blk1;
  uint32_t mb0;
  uint32_t mb1;
  char *data = NULL;
  uint32_t next_blk;
  uint32_t prev_blk;

  /* Since superblock occupies the block 0 (if not a bad block), this
  will essentially serve like a -1 or a NULL in other cases, since this
  is an unsigned 32 bit integer. */
  *master_blk0 = 0;
  *master_blk1 = 0;

  /* Head of the journal */
  blk0 = mnemofs_get_blk();
  blk1 = mnemofs_get_blk();

  /* Master blocks */
  mb0 = mnemofs_get_blk();
  mb1 = mnemofs_get_blk();

  /* Marking full at start won't be a problem. Power loss won't be
  a problem as marking full will only be for the block allocator, and it is
  NOT TO BE WRITTEN TO THE FLASH. Flash writing of this data will be done
  as per mnemofs_write_data. */
  mnemofs_blk_mark_full(blk0);
  mnemofs_blk_mark_full(blk1);
  mnemofs_blk_mark_full(mb0);
  mnemofs_blk_mark_full(mb1);

  /* Block 1 is special case: it needs 3 pointers in last page */
  data = kmm_zalloc(sb->pg_sz);
  if(!data) {
    ret = -ENOMEM;
    goto errout;
  }

  memcpy(data, &blk1, sizeof(uint32_t));
  memcpy(data + sizeof(uint32_t), &mb0, sizeof(uint32_t));
  memcpy(data + 2 * sizeof(uint32_t), &mb1, sizeof(uint32_t));

  page = MNEMOFS_BLK_T_PG(sb, blk0) + (sb->pg_in_blk - 1);
  ret = mnemofs_write_data(data, 3 * sizeof(uint32_t), page, 0);
  if(ret < 0) {
    goto errout_with_data;
  }

  /* Rest of the blocks */
  prev_blk = blk1;
  for(i = 2; i < sb->jrnl_blks; i++) {
    next_blk = mnemofs_get_blk();
    page = MNEMOFS_BLK_T_PG(sb, prev_blk) + (sb->pg_in_blk - 1);
    ret = mnemofs_write_data((char *) &next_blk, sizeof(uint32_t), page, 0);
    if(ret < 0) {
      goto errout_with_data;
    }

    mnemofs_blk_mark_full(prev_blk);
    prev_blk = next_blk;
  }

  /* Master blocks */

  page = MNEMOFS_BLK_T_PG(sb, prev_blk) + (sb->pg_in_blk - 1);
  ret = mnemofs_write_data((char *) &mb0, sizeof(uint32_t), page, 0);
  mnemofs_blk_mark_full(prev_blk);
  prev_blk = mb0;

  page = MNEMOFS_BLK_T_PG(sb, prev_blk) + (sb->pg_in_blk - 1);
  ret = mnemofs_write_data((char *) &mb1, sizeof(uint32_t), page, 0);
  mnemofs_blk_mark_full(prev_blk);
  prev_blk = mb1;

  /* Circular Linked List */

  page = MNEMOFS_BLK_T_PG(sb, prev_blk) + (sb->pg_in_blk - 1);
  ret = mnemofs_write_data((char *) &blk0, sizeof(uint32_t), page, 0);
  mnemofs_blk_mark_full(prev_blk);

  *master_blk0 = mb0;
  *master_blk1 = mb1;

errout_with_data:
  kmm_free(data);

errout:
  return ret;
}

/* TODO: testing */
/* TODO: Add condiiton for moving journal. Porbably in a different function */
int move_journal(struct mnemofs_sb_info *sb) {
  /* TODO: endianes. */
  int ret = OK;
  char *data = NULL;
  uint32_t mb0;
  uint32_t mb1;
  uint32_t jrnl_blk;

  init_empty_jrnl(sb, &jrnl_blk, &mb0, &mb1);

  /* TODO: mutex */

  /* Master block contents */
  data = kmm_zalloc(sb->pg_sz);
  if(!data) {
    ret = -ENOMEM;
    goto errout;
  }

  ret = get_master(data, sb->pg_sz);
  if(ret < 0) {
    goto errout_with_data;
  }

  init_master(mb0, mb1);

  /* TODO: Since we updated the new master blocks above, we'll be updating the
  master node to point to the new journal, and thus, also put a new log
  for the master node update in the NEW master blocks. */

  /* TODO: debug assert to ensure wear levels is way lesser than no. of pages
  in a block, just to be sure. */

errout_with_data:
  kmm_free(data);

errout:
  return ret;
}

struct jrnl_itr {
  uint32_t pg;
};

struct jrnl_itr jrnl_itr_init(void) {
  struct jrnl_itr itr;
  itr.pg = jrnl.head_pg;
  return itr;
}

/* 0 if OK, 1 if cycled back to the head page. */
int jrnl_itr_next(struct mnemofs_sb_info *sb, struct jrnl_itr *itr) {
  int ret = OK;

  if(itr->pg == MNEMOFS_BLK_END(sb, itr->pg)) {
    /* TODO: Think about endiannes. */
    ret = mnemofs_read_data((char *) &itr->pg, sizeof(itr->pg),
                              MNEMOFS_BLK_END(sb, itr->pg), 0);
  } else {
    itr->pg++;
  }

  return ret;
}