#include <nuttx/mtd/nand.h>

#include "mnemofs.h"

typedef void mfs_clist; /* TODO: Replace with a proper type */

enum chk_color {
  RED = 0,
  BLACK = 1,
};

/* Chunks are 2^14 blocks. */
#define MFS_LOG_CHKPBLK    (14) /* Chunks Per Block*/
#define MFS_CHKSPBLK       (1 << MFS_LOG_CHKPBLK)
#define MFS_CHK2BLK(chk)   ((chk) << MFS_LOG_CHKPBLK)
#define MFS_BLK2CHK(blk)   ((blk) >> MFS_LOG_CHKPBLK)

/* Let's use a splay tree */
/* TODO: Need to think more about managing bad blocks. */
struct mfs_blkallc_nd {
  struct mfs_blkallc_nd *rst; /* Right Splay Tree*/
  struct mfs_blkallc_nd *lst; /* Left Splay Tree*/
  struct mfs_blkallc_nd *pst; /* Parent Splay Tree*/
  struct mfs_blkallc_nd *rh; /* Right Heap */
  struct mfs_blkallc_nd *lh; /* Left Heap */
  struct mfs_blkallc_nd *ph; /* Parent Heap */
  struct mfs_blkallc_nd *founder; /* The member of the block allocator this node belongs to now. */
  mfs_clist *bad;
  mfs_clist *wearh;
  mfs_clist *wearl;

  /* Data */
  uint16_t chk; /* Chunk Number */
  uint16_t twear;
};

struct mfs_blkallc {
  struct mfs_blkallc_nd *free; /* Free */
  struct mfs_blkallc_nd *pfree; /* Partially Free */
  struct mfs_blkallc_nd *alloc; /* Allocated */
};

/* Compression */

uint32_t mfs_c_find(mfs_clist *l, uint32_t x) {
  /* TODO */
  return 0;
}

void mfs_c_rem(mfs_clist *l, uint32_t x) {
  /* TODO */

}

void mfs_c_ins(mfs_clist *l, uint32_t x) {
  /* TODO */

}

uint8_t mfs_c_get(mfs_clist *l, uint32_t x) {
  /* TODO */
  return 0;
}



















/* Initializes the block allocator and required memory */
int mnemofs_blk_alloc_init(FAR struct mfs_sb_info * const sb)
{
  /* TODO */
  return OK;
}

/* Free memory of block allocator. */
int mnemofs_blk_alloc_exit(FAR struct mfs_sb_info * const sb)
{
  /* TODO */
  return OK;
}

/* TODO: Mark that the block is being used to write on it. mutex. */
uint32_t mfs_get_blk(FAR struct mfs_sb_info * const sb) {
  /* TODO */
  return 0;
}

uint32_t mnemofs_get_pg(FAR struct mfs_sb_info * const sb) {
  /* TODO */
  return 0;
}

/* TODO: Mark that a block is full. Mostly used when block is written fully.
This is useful especially for master nodes and journal nodes. */
int mnemofs_blk_mark_full(FAR struct mfs_sb_info * const sb, uint32_t blk) {
  return OK;
}

/* Mark page for deletion */
/* TODO: Implementation */
/* TODO: Mutex */
int mnemofs_pg_dlt(FAR struct mfs_sb_info * const sb, uint32_t pg) {
  return OK;
}

int mnemofs_pg_mrkdlt(FAR struct mfs_sb_info * const sb, mfs_t pg) {
  return OK;
}