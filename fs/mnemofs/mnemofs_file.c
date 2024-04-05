/**NOTE:::::::::::::: Each file page stores how many bytes are written in it in
the first sb->log_pg_sz */

#include "mnemofs.h"

static uint32_t ptrs_lft(uint32_t blk);
static void ctz_off2blk(struct mnemofs_sb_info *sb, off_t off, uint32_t *ctz_blk, uint32_t *ctz_blk_off);
static int ctz_read_blk(uint32_t pg_start, uint32_t start_blk, uint32_t blk, char *buf, off_t off, ssize_t len);
static int __file_append(struct mnemofs_file *f, const char *buf, ssize_t len);

#define FULL_CTZ_BLK -1

/* Number of pointers in total on the CTZ blocks on left of the block number
given, including the block. */
static uint32_t ptrs_lft(uint32_t blk) {
  uint32_t c = 0;

  while(blk) {
    c += blk;
    blk >>= 1;
  }
  return blk;
}

/* Convert offset from the start of CTZ list to block number, and offset. */
/* NOTE: The name CTZ blocks are used to preserve the terminology. In mnemofs,
each CTZ block is infact just a page. */
static void ctz_off2blk(struct mnemofs_sb_info *sb, off_t off, uint32_t *ctz_blk, uint32_t *ctz_blk_off) {

  /* :::::::ERROR::::::: */
  /* The calculation in this funcion is no longer valid. A page is the smallest writable unit,
  and it may be that not all of the page is written. Thus, there needs to be
  16 bits at start to denote how much of it is already written. */
  /* :::::::ERROR::::::: */

  /* TODO: Input SB as a parameter */
  /* TODO: Testing */

  const uint32_t pg_sz = sb->pg_sz;
  const uint32_t ptr_sz = 32; /* Taking 32 bit pointers in CTZ skip list. */
  uint32_t rem = 0;
  uint32_t blk_no = 0;
  uint32_t blk_no_log = 0;
  uint32_t blk_ptr_size = 0;

  /* off = sigma(512 - 32log2(i)) + c (i = [0, k)); c < 512 - log2(k)*/

  blk_no = off / pg_sz;
  blk_no_log = mnemofs_log2(blk_no);
  blk_ptr_size = (blk_no_log + 1) * ptr_sz;
  off += (ptrs_lft(blk_no) * ptr_sz) - blk_ptr_size; /* Add pointer offsets of only the blocks on the left, not current block */

  while(1) {
    rem = off - (blk_no * pg_sz);

    if(rem < 512 - blk_ptr_size) {
      *ctz_blk = blk_no;
      *ctz_blk_off = rem;
      break;
    }

    off += blk_ptr_size;
    blk_no++;
    blk_no_log = mnemofs_log2(blk_no);
    blk_ptr_size = (blk_no_log + 1) * ptr_sz;
  }
}

/* CTZ block is of page size, so provide a page size length for buffer to be sure,
and if not, just calculate the length from (pg_sz - ptr_size * (log2(blk) + 1))*/
/* Returns the length of the buf read (without pointers) */
/* Assumes each CTZ block is a page on-flash. */
/* pg_start is the page number of the last block of the CTZ list. */
/* start_idx is the CTZ blk number of the last page (CTZ block) */
/* TODO: len is maxlen */
static int ctz_read_blk(uint32_t pg_start, uint32_t start_blk, uint32_t blk, char *buf, off_t off, ssize_t len) {
  /* TODO */
  /* NOTE: Keep in mind not all of the page will be filled. Check the
  first 16 bits for the size written to the block.*/
  return 0;
}

/* NOTE: This will be used for the on-flash update operation, which comes when
journal is being committed to the flash. */
static int ctz_append_data(uint32_t *pg_start, uint32_t *start_blk, const char *buf, ssize_t len) {
  return OK;
}

int __mnemofs_file_read(struct mnemofs_sb_info *sb, struct mnemofs_file *f, off_t off, char *buf, ssize_t len) {

  /* TODO: Input SB as a parameter, not global */
  /* TODO: If len is FULL_CTZ_BLK, then read the entire page (CTZ block) from the offset. except the pointers. */

  uint32_t ctz_blk;
  uint32_t pg_off; /* ctz_blk_off and pg_off are same here */
  uint32_t ret = OK;

  /* Initial position */

  /* :::::::ERROR::::::: */
  /* Check in the function */
  ctz_off2blk(sb, off, &ctz_blk, &pg_off);
  /* :::::::ERROR::::::: */

  while(len > 0) {
    ret = ctz_read_blk(f->start_pg, f->start_idx, ctz_blk, buf, 0, FULL_CTZ_BLK);
    if(ret < 0) {
      goto errout;
    }
    len -= ret;
    buf += ret;
    ctz_blk++; /* Next Block */
  }

errout:
  return ret >= 0 ? OK : ret;
}

/* TODO: This for now contains the actual append operation. Later on, that
will be split from this, and this will just contain the coe to add a cache/journal
entry for appending of file. */
static int __file_append(struct mnemofs_file *f, const char *buf, ssize_t len) {
  return ctz_append_data(&f->start_pg, &f->start_idx, buf, len);
}

/* Enter off as f->f_size to append at end. */
int __mnemofs_file_insert(struct mnemofs_file *f, const char *buf, ssize_t len, off_t off) {
  int ret = OK;

  /* TODO: Think about off > f-f_size and the entire HOLE situation. */
  if(off == f->f_size) {
    return __file_append(f, buf, len);
  }

  struct mnemofs_file temp_f;
  memcpy(&temp_f, f, sizeof(struct mnemofs_file));

  /* TODO: Mark the pages from [off, FILE_END] for deletion */
  temp_f.f_size = off;
  ret = __file_append(&temp_f, buf, len);
  if(ret < 0) {
    goto errout;
  }

  /* TODO: Manage the upcoming blocks that fall outside of the update range,
  such that if, say, there is a string abcdefghijk, and I try to write xyz at index
  3, the result is abcxyzghijk and not abcxyz.
  
  abcxyz is what the current implementation line below does. CHANGE IT!!!!
  */
  memcpy(f, &temp_f, sizeof(struct mnemofs_file));

  /* TODO: Upon update, add a journal log that mentions that the file's start block
  has changed, and thus, its direntry needs to be updated. */
  /* TODO: If the file is a directory, then the update need to be notified to its
  parent when the journal is being committed, which is what this function will be
  when its written in a separate function from this one.*/

errout:
  return ret;
}