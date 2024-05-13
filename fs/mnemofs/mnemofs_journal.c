#include <nuttx/kmalloc.h>
#include <nuttx/list.h>
#include <endian.h>

#include "mnemofs.h"

/* UPDATE: Master block pointers will be stored in the last page of first block
right after the pointer to next node in the block. */
// struct jrnl_info {
//   uint32_t  head_pg; /* Journal Head */
//   uint32_t  rem_blks; /* Remaining blocks left after block with index excluding master blocks */
//   uint32_t  idx_page; /* Page no. where to insert next log */
//   uint32_t  mb_1; /* Master Block 1 */
//   uint32_t  mb_2; /* Master Block 1 */
// };


//----------------------------------------------------------------------------

/*
  Journal will have `sb->jrnl_nblks + 2` blocks.
  
  The first block will start with a byte-long magic number that identifies a
  journal of mnemofs.

  Then another byte will be used to write the number of blocks in the journal.
  This is done so that, if the journal is found during mount, it will be
  quick to point to the master node as well.
  NOTE: This count will NOT include the 2 master blocks.
  
  Then the next `(sb->jrnl_nblks + 2) * sizeof(mfs_t)` bytes will be used to
  store an array of block numbers. These block numbers are of each of the
  blocks of the journal. This is called the journal index array. If the array
  extends to be partially occupying a page, then the rest of the page is left
  unused.

  Then all the rest of the pages that are part of the journal are writeable
  for the logs except the master blocks.

  Advantages of journal index array over a singly linked list:
    - Multiple block numbers can be stored together. In singly linked list,
      there was only one block number in the last page of the block, which
      wasted a lot of space.
    - Page caching can cache the array as it is used often, and then
      traversal would be quicker.
    - While mounting, if journal is reached first during scan of the device,
      to get the root node, all that is required is to scan the second byte
      to get the array size, and then jump to the array, get the master block
      locations, find the most recent master block and then we have the
      master node. This removes the problem of reaching the master node
      through linked list traversal, which would be slower due to less
      probability of caching.
    - The entire journal moves together, so there is no reason for linked
      list except to not deal with the contrainst of having contiguous block
      problems like uneven wear which might lead to bad blocks right inside
      the journal among other things, etc.
*/

/*
  Journal log on flash:

  struct mfs_jrnl_log {
    mfs_t depth; // FS object count in pathlen
    struct mfs_ctz_store_s path[depth];
    struct mfs_ctz_store_s new;
    uint8_t hash;
  };

  path[depth-1] will give the old location.
*/

/* In-memory journal */
struct mfs_jrnl_info {
  struct list_node list;
  mfs_t depth;
  FAR struct mfs_ctz_store_s *path;
  struct mfs_ctz_store_s new;
};

/* For on-flash */
#define MFS_J_DEPTH_OFF(node)  (0)
#define MFS_J_PATH_OFF(node)   (MFS_J_DEPTH_OFF(node) + sizeof(mfs_t))
#define MFS_J_NEW_OFF(node)    (MFS_J_PATH_OFF(node) + \
                               (node->depth * sizeof(struct mfs_ctz_store_s)))

/* Format a device with a journal */
int mfs_jrnl_fmt(FAR struct mfs_sb_info * const sb)
{

  int ret = OK;
  const uint8_t n_blks = sb->j_nblks; /* Not counting master blocks. */
  uint8_t idxarr_idx = 0;
  mfs_t *idxarr = NULL;
  mfs_t tmp;
  char *buf = NULL;
  const int idxarr_sz = (n_blks + 2) * sizeof(mfs_t);
  const int buf_sz = idxarr_sz + 2;
  int i;
  mfs_t wr_s_pg; /* Start page of writeable area */
  mfs_t wr_s_blkidx; /* Index in idxarr of start of writeable area */

  idxarr = kmm_zalloc(idxarr_sz);
  if(!idxarr) {
    ret = -ENOMEM;
    goto errout;
  }

  buf = kmm_zalloc(buf_sz);
  if(!buf) {
    ret = -ENOMEM;
    goto errout_with_idxarr;
  }

  nxmutex_lock(&sb->fs_lock);
  for(idxarr_idx = 0; idxarr_idx < n_blks + 2; idxarr_idx++) {
    tmp = mfs_get_blk(sb);
    if(tmp == 0) {
      ret = -ENOMEM;
      goto errout_with_lock;
    }

    idxarr[idxarr_idx] = tmp;
  }

  memcpy(buf, MNEMOFS_JRNL_MAGIC, 1);
  memcpy(buf + 1, &idxarr_idx, 1);
  memcpy(buf + 2, idxarr, idxarr_sz);

  nxmutex_lock(&sb->fs_lock);  
  if(predict_true(sb->blk_sz >= buf_sz)) {
    mnemofs_write_data(buf, buf_sz, MFS_BLK2PG(sb, idxarr[0]), 0);
    wr_s_pg = MFS_BLK2PG(sb, idxarr[0]) +
              ((buf_sz + (sb->pg_sz - 1))/sb->pg_sz); /* ceil */
    wr_s_blkidx = 0;
  } else {
    /* Split between journal blocks if the array is bigger than a block. */
    tmp = 0;
    i = 0;
    wr_s_pg = MFS_BLK2PG(sb, idxarr[i]);
    wr_s_blkidx = 0;
    while(i < n_blks) {
      if(predict_true(tmp + sb->blk_sz < buf_sz)) {
        tmp += mnemofs_write_data(buf + tmp, sb->blk_sz, wr_s_pg++, 0);
      } else {
        tmp += mnemofs_write_data(buf + tmp, buf_sz - tmp, wr_s_pg++, 0);
        break;
      }
      
      if(wr_s_pg - idxarr[i] == sb->pg_in_blk) {
        i++;
        wr_s_pg = MFS_BLK2PG(sb, idxarr[i]);
      }
    }
      
    if(wr_s_pg - idxarr[i] == sb->pg_in_blk) {
      i++;
      wr_s_pg = MFS_BLK2PG(sb, idxarr[i]);
    }
    wr_s_blkidx = i;

    /* TODO: Asserts. wr_s_pg needs to work properly. Also, at this point, it
    needs to point to a valid location where writes can be made. If not such
    location is found, errout out before this point. */

    /* If this is true, the journal has not enough space. */

    if(i == n_blks && tmp < buf_sz) {
      ret = -ENOMEM;
      goto errout_with_lock;
    }
  }

  kmm_free(buf);
  sb->j_state.n_blks = n_blks;
  sb->j_state.idxarr = idxarr; /* Ownership transferred to sb */
  sb->j_state.wr_s_pg = wr_s_pg;
  sb->j_state.wr_s_blkidx = wr_s_blkidx;
  sb->j_state.c_blkidx = wr_s_blkidx;
  sb->j_state.c_pg = wr_s_pg;
  sb->j_state.c_pgoff = 0;

  nxmutex_unlock(&sb->fs_lock);
  return ret;

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);

  kmm_free(buf);

errout_with_idxarr:
  kmm_free(idxarr);

errout:
  return ret;
}

/* Read and initialize journal from the flash. */
/* Provides information for the location of the latest master node. */
int mfs_jrnl_init(FAR struct mfs_sb_info * const sb, mfs_t blk,
                  mfs_t *master_node)
{
  int ret = OK;

  /*!!!!!!!!!!!!!! TODO !!!!!!!!!!!!!*/

  return ret;
}