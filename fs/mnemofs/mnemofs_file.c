#include <sys/stat.h>
#include <nuttx/kmalloc.h>
#include <fcntl.h>

#include "mnemofs.h"

static uint32_t ptrs_lft(uint32_t blk);
static void ctz_off2blk(struct mnemofs_sb_info *sb, off_t off, uint32_t *ctz_blk, uint32_t *ctz_blk_off);
static int ctz_read_blk(uint32_t start_pg, uint32_t start_idx, uint32_t blk, char *buf, off_t off, ssize_t len);
static int file_append(struct mnemofs_file *f, const char *buf, ssize_t len);
static int search_open_files(struct mnemofs_sb_info *sb, FAR const char *relpath);
static ssize_t file_size(uint32_t start_pg, uint32_t start_blk);

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
  /* Update to the latest representation. */
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
static int ctz_read_blk(uint32_t start_pg, uint32_t start_idx, uint32_t blk, char *buf, off_t off, ssize_t len) {
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

static ssize_t file_size(uint32_t start_pg, uint32_t start_blk) {
  /* TODO: Read the first 32 bytes from the last CTZ block. That gives the current size. */
  return 0;
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
static int file_append(struct mnemofs_file *f, const char *buf, ssize_t len) {
  return ctz_append_data(&f->start_pg, &f->start_idx, buf, len);
}

/* Enter off as f->f_size to append at end. */
/* TODO: Make a macro for off to be excluded. */
/* TODO: Updates the file's size as well. */
/* This handles the off > size case. */
int __mnemofs_file_insert(struct mnemofs_file *f, const char *buf, ssize_t len, off_t off) {
  int ret = OK;

  /* TODO: Think about off > f-f_size and the entire HOLE situation. */
  if(off == f->size) {
    return file_append(f, buf, len);
  }

  struct mnemofs_file temp_f;
  memcpy(&temp_f, f, sizeof(struct mnemofs_file));

  /* TODO: Mark the pages from [off, FILE_END] for deletion */
  temp_f.size = off;
  ret = file_append(&temp_f, buf, len);
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

/* Replace `dst_len` worth of bytes at `off` with `src_len` worth of bytes in file `f` */
/* TODO: Updates the file's size as well. */
int __mnemofs_file_update(struct mnemofs_file *f, const char *buf, ssize_t src_len, ssize_t off, ssize_t dst_len) {
  return OK;
}

/* TODO: Updates the file's size as well. */
int __mnemofs_file_delete(struct mnemofs_file *f, ssize_t off, ssize_t len) {
  return __mnemofs_file_update(f, NULL, 0, off, len);
}

//------------------------------------------------

/* Open files in mnemofs */
struct mnemofs_file_info { /* TODO: Remove the duplicated from dir_f and this struct. Maintain one source of truth. */
  struct mnemofs_file_info *prev; /* Previous entry in doubly linked list.*/
  struct mnemofs_file_info *next; /* Next entry in doubly linked list.*/
  int oflags;
  mode_t mode;
  struct mnemofs_file ff;
};

/* FUTURE TODO: Since the LRU is a doubly linked list, keep a doubly linked list with separate
pointers for an open file as well. This way, the updates to a file can be traversed even without
traversing the LRU.
*/

/* Keep a global LRU for all updates. */
// 0 - Not found, 1 - Found
/* Almost duplicate of search_open_dirs */
static int search_open_files(struct mnemofs_sb_info *sb, FAR const char *relpath) {

  uint8_t hash;
  struct mnemofs_file_info *head;
  int ret = 0;
  int lock = 0;

  if(!sb->d_start) {
    goto out;
  }

  hash = mnemofs_calc_str_hash(relpath, strlen(relpath));

  /* Only lock and unlock if we're the ones locking this, not the parent function. */
  if(!nxmutex_is_locked(&sb->fs_lock)) {
    nxmutex_lock(&sb->fs_lock);
    lock = 1;
  }


  for(head = sb->f_start; head != sb->f_end; head = head->next) {
    if(head->ff.hash == hash) {
      /* Hash collision */
      if(!strncmp(relpath, head->ff.path, head->ff.pathlen)) {
        /* Found the path */
        ret = 1;
        goto out_with_lock;
      }
    }
  }

out_with_lock:
  if(lock) {
    nxmutex_unlock(&sb->fs_lock);
  }

out:
  return ret;
}

int __mnemofs_open(struct file *fp, FAR const char *relpath, int oflags, mode_t mode) {

  int ret = OK;
  struct mnemofs_file_info *fi;
  struct mnemofs_direntry_info parent, child;
  const int pathlen = strlen(relpath);
  struct mnemofs_sb_info *sb;
  struct inode *inode;

  inode = fp->f_inode;
  sb = inode->i_private;

  nxmutex_lock(&sb->fs_lock);

  memcpy(&parent, sb->root, sizeof(parent));

  ret = search_direntries_r(&parent, &child, relpath, pathlen);
  if(ret != MNEMOFS_DIR_SEARCH_OK) {
    ret = -ENOENT;
    goto errout_with_lock;
  } else {
    ret = OK;
  }

  /* FUTURE TODO: mnemofs doesn't support anything other than directories and links yet. */
  if(!S_ISREG(child.mode)) {
    ret = -EISDIR;
    goto errout_with_lock;
  }

  fi = kmm_zalloc(sizeof(*fi));
  if(!fi) {
    ret = -ENOMEM;
    goto errout_with_lock;
  }

  fi->ff.pathlen = pathlen;
  fi->ff.path = kmm_zalloc(pathlen);
  if(!fi->ff.path) {
    ret = -ENOMEM;
    goto errout_with_ff;
  }
  memcpy(&fi->ff.path, relpath, pathlen);

  /* Turns out you don't need to check for multiple file descriptors.
  Source: https://stackoverflow.com/a/5284108/14369307
  Also TODO: dup shares the same file pointer, so affecting affects both.
  */

  fi->prev = NULL; /* Will be set later with mutex */
  fi->next = NULL;
  fi->ff.hash = mnemofs_calc_str_hash(fi->ff.path, fi->ff.pathlen);
  fi->ff.off = 0;
  fi->ff.start_pg = child.dir_f.start_pg;
  fi->ff.start_idx = child.dir_f.start_idx;
  fi->mode = mode;
  fi->ff.size = file_size(fi->ff.start_pg, fi->ff.start_idx);

  /* TODO: Remember to add a functionality to update the start_pg and start_idx
  to ALL open file descriptors / pointers when the file updates. */

  /* Append at the end of list of open files. */
  if(sb->f_end == NULL /* && sb->f_start == NULL */) {
    sb->f_start = fi;
    sb->f_end = fi;
  } else {
    sb->f_end->next = fi;
    fi->prev = sb->f_end;
    sb->f_end = fi;
  }

  /*
  TODO: Keep in mind the new CTZ block may be in the journal
  or the LRU as well as the flash, that is upto the lowest level function to find out,
  not the higher functions. The lowest level read operation will read out the block from LRU.
  */

  /*
    TODO: fi->oflags ????
  */

  fp->f_priv = fi;

  return OK;

errout_with_ff:
  kmm_free(fi);

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);

  return ret;
}

// TODO: Get return value of ALL LOCKS AND UNLOCKS.
int __mnemofs_close(struct file *fp) {

  int ret = OK;
  struct inode *inode;
  struct mnemofs_sb_info *sb;
  struct mnemofs_file_info *fi;

  inode = fp->f_inode;
  sb = inode->i_private;
  fi = fp->f_priv;

  nxmutex_lock(&sb->fs_lock);

  /* TODO: Debug assert to check if dir is not NULL */

  if(sb->f_start == fi && sb->f_end == fi /* && ff->prev == NULL && ff->next == NULL */) {
    sb->f_start = NULL;
    sb->f_end = NULL;
  } else {

    /* Taking care of terminal nodes preculiarities. */
    if (sb->f_start == fi) {
      sb->f_start = fi->next;
    } else if (sb->f_end == fi) {
      sb->f_end = fi->prev;
    }

    fi->prev->next = fi->next;
    fi->next->prev = fi->prev;
  }

  /* As this mentions, no need to fsync after close:
  https://stackoverflow.com/a/15348491/14369307 */

  nxmutex_unlock(&sb->fs_lock);

  return ret;
}

ssize_t __mnemofs_read(FAR struct file *fp, FAR char *buf, size_t buflen) {

  int ret = OK;
  struct inode *inode;
  struct mnemofs_sb_info *sb;
  struct mnemofs_file_info *fi;
  struct mnemofs_file ff;
  ssize_t len;

  inode = fp->f_inode;
  sb = inode->i_private;
  fi = fp->f_priv;

  nxmutex_lock(&sb->fs_lock);

  /* Initialize only the useful ff fields. */
  ff.off = fi->ff.off;
  ff.start_pg = fi->ff.start_pg;
  ff.start_idx = fi->ff.start_idx;

  len = __mnemofs_file_read(sb, &ff, ff.off, buf, buflen);
  if(len < 0) {
    /* TODO: What if off > size? */
    ret = len;
    goto errout_with_lock;
  } else if (len == 0) {
    /* TODO: EOF */
  }

  fi->ff.off += len;

  nxmutex_unlock(&sb->fs_lock);
  return len;

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);

  return ret;
}

ssize_t __mnemofs_write(FAR struct file *fp, FAR const char *buf, size_t buflen) {

  int ret = OK;
  struct inode *inode;
  struct mnemofs_sb_info *sb;
  struct mnemofs_file_info *fi;
  ssize_t len;
  ssize_t off;

  /* TODO: Debug Assert for fp. */

  inode = fp->f_inode;
  sb = inode->i_private;
  fi = fp->f_priv;
  off = (fi->mode & O_APPEND) ? fi->ff.size : fi->ff.off;

  if(fi->mode & O_WRONLY) {
    ret = -EBADF;
    goto errout;
  }

  nxmutex_lock(&sb->fs_lock);

  len = __mnemofs_file_insert(&fi->ff, buf, buflen, off);
  if(len <= 0) {
    ret = len;
    goto errout_with_lock;
  }

  nxmutex_unlock(&sb->fs_lock);
  return len;

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);

errout:
  return ret;
}

off_t __mnemofs_seek(FAR struct file *fp, off_t off, int whence) {

  off_t ret = 0;
  struct inode *inode;
  struct mnemofs_sb_info *sb;
  struct mnemofs_file_info *fi;
  off_t old_off;

  /* TODO: Debug Assert for fp. */

  if(off == 0) {
    goto errout;
  }

  inode = fp->f_inode;
  sb = inode->i_private;
  fi = fp->f_priv;

  nxmutex_lock(&sb->fs_lock);

  old_off = off;

  switch(whence) {

    case SEEK_SET:
      fi->ff.off = off;
      break;

    case SEEK_CUR:
      fi->ff.off += off;
      break;

    case SEEK_END:
      fi->ff.off = fi->ff.size + off;
      break;
  }

  ret = fi->ff.off;

  if(fi->ff.off < 0 && off < 0) {
    fi->ff.off = old_off;
  } else if (fi->ff.off < old_off && off > 0) {
    /* Offset overflow cases. */
    ret = -EOVERFLOW;
  }

  nxmutex_unlock(&sb->fs_lock);

errout:
  return ret;
}