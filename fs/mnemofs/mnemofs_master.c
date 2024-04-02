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

#include <nuttx/kmalloc.h>

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

/* TODO: Only one main master block. Another will be a duplicate.

  REASON: The master block gets updated when journal is emptied or moved.
  The contents is very small. There are 4 wear levels. So, at any given time,
  the maximum master block logs available will be only 1.

  NEED TO EXPLORE: There should be a copy of master block. This will be an
  exact duplicate. The duplicate will have one less than or the same no. of
  logs in case of a power loss, which is easy to rectify.

*/

enum {
  MB_PRIM,
  MB_SEC,
};

static uint32_t mb_pg_idx; /* TODO: Initialize */
static uint32_t blks[2]; /* TODO: Initialize */

/****************************************************************************
 * Public Data
 ****************************************************************************/

/* Save Master Node */
int save_master_log(uint32_t new_master) {
  int ret;
  char *data;
  int chksum;
  int len;

  ret = OK;
  data = NULL;
  chksum = mnemofs_chksm((char *) &new_master, sizeof(new_master));
  len = sizeof(new_master) + sizeof(chksum);

  if(mb_pg_idx == mnemofs_sb.pg_in_blk - 1) {
    /* TODO: unlikely */
    /* TODO: Move the journal, the master block is full. */
    /* TODO: Better return error code */
    return 1;
  }

  data = kmm_zalloc(len);

  memcpy(data, &new_master, sizeof(new_master));
  memcpy(data + sizeof(new_master), &chksum, sizeof(chksum));
  
  /* master block logs are 40 bits in size, which is way less
  than usual page size. */

  ret = mnemofs_write_data(data, len, MNEMOFS_BLK_T_PG(blks[MB_PRIM]) + mb_pg_idx, 0);
  if(ret < 0) {
    goto errout_with_data;
  }
  
  mb_pg_idx++;
  
  ret = mnemofs_write_data(data, len, MNEMOFS_BLK_T_PG(blks[MB_SEC]) + mb_pg_idx, 0);
  if(ret < 0) {
    goto errout_with_data;
  }

errout_with_data:

  kmm_free(data);
  return ret;
}

int32_t get_master_blk(void) {
  /* TODO: Unlikely that there is no idx - 1 log, since mount or moving the
  journal adds atleast one log, and the pointer points to the next page.*/

  int ret = OK;
  char *data = kmm_zalloc(mnemofs_sb.pg_sz);
  if(!data) {
    ret = -ENOMEM;
    goto errout;
  }

  ret = mnemofs_read_data(data, mnemofs_sb.pg_sz,
                      MNEMOFS_BLK_T_PG(blks[MB_PRIM]) + (mb_pg_idx - 1), 0);
  if(ret < 0) {
    goto errout_with_data;
  }

  /* First 32 bits are for the master block number */
  memcpy(&ret, data, sizeof(uint32_t));

  /* TODO: Endianess */

errout_with_data:
  kmm_free(data);

errout:
  return ret;
}

/* TODO: To be used at bind (mount) inside init_journal code and during journal
move. */

/* NOTE: This does not allocate the blocks, but
* just the block numbers. It requires two blocks
* that have been allocated */
void init_master(uint32_t mb0, uint32_t mb1) {
  mb_pg_idx = 0;
  blks[MB_PRIM] = mb0;
  blks[MB_SEC] = mb1;
}

int get_master(char *data, int data_len) {
  /* TODO */
  return 0;
}