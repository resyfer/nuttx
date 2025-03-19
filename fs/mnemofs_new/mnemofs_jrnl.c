/****************************************************************************
 * fs/mnemofs_new/mnemofs_jrnl.c
 * Journal functions for mnemofs.
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

static int mfs_jrnl_mv(FAR mfs_sb_s *sb);

/****************************************************************************
 * Private Data
 ****************************************************************************/

/****************************************************************************
 * Public Data
 ****************************************************************************/

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name:mfs_jrnl_mv
 *
 * Description:
 *   Move the journal when it's time to flush.
 *
 * Input Parameters:
 *   sb - Superblock
 *
 * Returned Value:
 *   - 0 if OK
 *   - negative if not.
 *
 * Assumptions/Limitations:
 *   - The journal needs to be full.
 *   - If the journal is full AND the master node is full, then this function
 *     should FOLLOW master block move.
 *
 ****************************************************************************/

static int
mfs_jrnl_mv(FAR mfs_sb_s *sb)
{
  /* TODO */

  return 0;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int
mfs_jrnl_rd(FAR const mfs_sb_s *sb, char *buf, mfs_t n_buf,
            FAR const mfs_ctz_s *ctz)
{
  /* TODO */

  return 0;
}

int
mfs_jrnl_wr(FAR mfs_sb_s *sb, FAR const char *buf, mfs_t n_buf,
            FAR mfs_ctz_s *ctz)
{
  /* TODO */

  return 0;
}

int
mfs_jrnl_fmt(FAR mfs_sb_s *sb, mfs_t mb1, mfs_t mb2)
{
  /* TODO */

  /* Clean format journal. For this the master block numbers need to be
   * provided and they are supposed to be clean formatted too.
   */

  return 0;
}

int
mfs_jrnl_init(FAR mfs_sb_s *sb, mfs_t blk)
{
  /* TODO */

  /* Initialize already written journal by reading it. */

  return 0;
}

bool
mfs_jrnl_isflushreq(FAR mfs_sb_s *sb)
{
  /* TODO */

  /* Is flush required. */

  return false;
}

int
mfs_jrnl_flush(FAR mfs_sb_s *sb)
{
  /* TODO */

  /* Flush and move journal, and even master block if necessary. */

  return 0;
}
