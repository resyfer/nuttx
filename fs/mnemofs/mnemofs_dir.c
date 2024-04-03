#include <string.h>
#include <nuttx/fs/fs.h>
#include <nuttx/kmalloc.h>
#include <sys/stat.h>

#include "mnemofs.h"

enum DIR_SEARCH_ERR {
  DIR_SEARCH_OK,
  DIR_SEARCH_NOT_FOUND,
  DIR_SEARCH_INVALID_PARENT,
};

struct mnemofs_fs_dirent {
  struct fs_dirent_s base;
  struct {
    struct mnemofs_dir *d;
  } dir;
};

#define FILE_END  -1

/* Direntry in memory */
struct direntry_info {
  uint8_t hash;
  FAR const char *parent_path; /* Maybe NULL for ROOT */
  ssize_t parent_pathlen;
  FAR const char *name;
  ssize_t namelen;
  uint32_t pg;
  off_t off; /* TODO: This will be set after journal is written. */
  mode_t mode;
  struct mnemofs_file dir_f; /* Directory file */
};

/* Direntry on disk. This is just for reference. */
// struct direntry {
//   uint32_t pg;
//   uint32_t start_pg; /* Page number of CTZ list start. For dir this is the start of their direntries, for files this is the file start */
//   uint8_t  type;
//   uint8_t namelen; /* Just the strlen */
//   char name[namelen];
// };
#define DIRENT_PG_OFF 0
#define DIRENT_START_PG 32
#define DIRENT_TYPE_OFF 64
#define DIRENT_NAMELEN_OFF  72
#define DIRENT_NAME_OFF     90
#define DIRENT_SIZE(namelen)   (DIRENT_NAME_OFF + (namelen)) /* TODO: Round off to nearest 4 byte boundary */

static ssize_t find_name_len(FAR const char *path);
static uint8_t calc_name_hash(FAR const char *path, ssize_t len);
static int search_direntries(struct direntry_info *parent, struct direntry_info *child, FAR const char *name, ssize_t namelen);
static int search_direntries_r(struct direntry_info *parent, struct direntry_info *child, FAR const char *path, ssize_t pathlen);

/* Like strtok, but does not change string. */
static ssize_t find_name_len(FAR const char *path) {
  int i;
  for(i = 0; path[i] != 0 && path[i] != '/'; i++);
  return i;
}

static uint8_t calc_name_hash(FAR const char *path, ssize_t len) {
  ssize_t l = 0;
  ssize_t r = len - 1;
  uint16_t hash = 0;

  while(l <= r) {
    hash += path[l] * path[r] * l * r;
    l++;
    r--;
    hash %= (1 << 8);
  }

  return hash % (1 << 8);
}

/* Denotes the pg and off as 0 if error. */
/* Only searches immediate child */
static int search_direntries(struct direntry_info *parent, struct direntry_info *child, FAR const char *name, ssize_t namelen) {
  struct direntry_info ret = {0};

  ret.hash = calc_name_hash(name, namelen);
  ret.name = name;
  ret.namelen = namelen;
  ret.parent_path = parent->name; /* TODO: FULL PATH of parent by appending parent's parent path and name. */ /* TODO: Copy the path, not reference */
  ret.parent_pathlen = parent->namelen; /* TODO: Same parent treatment. */
  /* TODO: add the ret.dir_f properties here after search */

  /* TODO: Implement files, use inner implementation function to read the file data */

  /* Use calc_name_hash & strcmp for hash collisions */
  memcpy(parent, &ret, sizeof(ret));
  return DIR_SEARCH_OK;
}

/* Recursive search (Iterative) */
/* TODO: Error system like 0 - Found an entry, 1 - No entry at that location, 2 - Parent not found (ie. search stopped midway) */
static int search_direntries_r(struct direntry_info *parent, struct direntry_info *child, FAR const char *path, ssize_t pathlen) {
  return DIR_SEARCH_OK;
}

int mnemofs_create_dir(struct mnemofs_sb_info *sb, FAR const char *path, mode_t mode) {
  /* TODO: Add sb as a parameter*/

  FAR const char *name = path;
  ssize_t namelen = -1; /* It is set to -1 for the first pass */
  struct direntry_info cur_dir;
  struct direntry_info tmp;
  int ret = OK;
  char *buf = NULL;

  /* Root is cur_dir */
  /* TODO: Create a macro for this, or store in SB. */
  /* TODO: Initialize this in SB */
  // cur_dir.hash = calc_name_hash("/", 1); /* TODO: check if `path` contains `/` in first character */
  // cur_dir.name = "/";
  // cur_dir.namelen = 1;
  // cur_dir.pg = sb->master_node;
  // cur_dir.off = 0;
  // cur_dir.parent_path = NULL;
  // cur_dir.parent_pathlen = 0;
  // cur_dir.mode = 0777; /* TOD: verify root's mode. */

  memcpy(&cur_dir, sb->root, sizeof(cur_dir));

  while(1) {

    /* TODO: we know this should not fail, but MAYBE. So debug assert. */
    if(*(name + namelen) == '\0') {
      /* Exact match found */
      ret = -EEXIST;
      goto errout;
    }

    /* TODO: Support links and redirection */
    if(!S_ISDIR(cur_dir.mode)) {
      ret = -ENOTDIR;
      goto errout;
    }

    name = name + namelen + 1;
    namelen = find_name_len(name);
    ret = search_direntries(&cur_dir, &tmp, name, namelen);
    /* TODO: Check for return values. */
    if(tmp.pg == 0 && tmp.off == 0) {
      /* Not found, so we're good, and move on to creating it. */
      /* TODO: WARNING: This point might not be the final directory path
      we want. This might be a parent in the path that has not been created
      yet. */
      break;
    }

    cur_dir = tmp;
  }

  /* NOTE: There doesn't seem to be any function that allocated inode
  numbers? Or does it even look like inodes are required here. */

  /* cur_dir has the parent under which directory is supposed to be created. */

  /* tmp.hash: Already done by search_direntries */
  tmp.mode = mode;
  /* tmp.name: Already done by search_direntries */
  /* tmp.off: To be created when journal is written. */
  /* tmp.parent_path: Already done by search_direntries */
  /* tmp.parent_pathlen: Already done by search_direntries */

  /* TODO: Add a directory entry save log in journal */
  /* TODO: Journal, when writing direntry changes, will write them like files. */

  /* Save the on-flash direntry representation to parent directory. */
  tmp.dir_f.f_size = 0;
  tmp.dir_f.pg_start = 0; /* TODO: ENUM for empty file for start */
  tmp.dir_f.start_blk = -1; /* TODO: Empty CTZ list enum */

  buf = kmm_zalloc(DIRENT_SIZE(tmp.namelen));
  if(!buf) {
    ret = -ENOMEM;
    goto errout;
  }

  /* TODO: Think about endiannes */
  /* This is for the child. The values written in it for now are garbage,
  but they signify an empty directory. */
  const uint8_t type = MNEMOFS_DIR;

  memcpy(buf + DIRENT_PG_OFF, &tmp.dir_f.pg_start, sizeof(tmp.dir_f.pg_start));
  memcpy(buf + DIRENT_START_PG, &tmp.dir_f.start_blk, sizeof(tmp.dir_f.start_blk));
  memcpy(buf + DIRENT_TYPE_OFF, &type, sizeof(type));
  memcpy(buf + DIRENT_NAMELEN_OFF, &tmp.namelen, sizeof(tmp.namelen));
  memcpy(buf + DIRENT_NAME_OFF, tmp.name, namelen);

  /* Insert at end */
  ret = __mnemofs_file_insert(&cur_dir.dir_f, buf, DIRENT_SIZE(tmp.namelen), tmp.dir_f.f_size);
  if(ret < 0) {
    goto errout_with_buf;
  }

errout_with_buf:
  kmm_free(buf);

errout:
  return ret;
}

//---------------------------------

/* TODO: THER IS INCONSISTENT DEPICTION OF DIR GOING ON. THIS IS STEMMING FROM EITHER REQUIRING SIZE OF THE DIRECTORY ENTRY FILE,
OR NOT REQUIRING IT. NEED TO THINK ABOUT THIS WELL. KEEPING A SIZE FOR DIR WOULD MEAN UPDATING THE PARENT'S DIRENTRY EVERYTIME THERE
IS AN ADDITION. BUT THIS WOULD ALSO BE A USUAL CASE AS ANY ADDITION MOVES THE LAST BLOCK OF THE CTZ, AND THUS THE PARENT NEEDS TO BE
UPDATED ANYWAY.


SO ADD SIZE LATER.*/
int __mnemofs_opendir(struct mnemofs_sb_info *sb,  FAR const char *relpath, FAR struct fs_dirent_s **dir) {

  int ret = OK;
  struct mnemofs_dir *d;
  struct direntry_info parent, child;
  unsigned long pathlen;
  struct mnemofs_fs_dirent *fdir;

  pathlen = strlen(relpath);

  /* Check Directory */
  ret = search_direntries_r(&parent, &child, relpath, pathlen);
  if(ret == DIR_SEARCH_INVALID_PARENT) {
    ret = -ENOENT;
    goto errout;
  } else if (ret == DIR_SEARCH_NOT_FOUND) {
    ret = -ENOENT;
  }

  if(!S_ISDIR(child.mode)) {
    ret = -ENOTDIR;
    goto errout;
  }

  /* We have directory, open it */
  d = kmm_zalloc(sizeof(*d));
  if(!d) {
    ret = -ENOMEM;
    goto errout;
  }

  d->pathlen = pathlen;
  d->path = kmm_zalloc(d->pathlen);
  if(!d->path) {
    ret = -ENOMEM;
    goto errout_with_d;
  }

  /* Get fdir mem */
  fdir = kmm_zalloc(sizeof(*fdir));
  if(!fdir) {
    ret = -ENOMEM;
    goto errout_with_path;
  }

  strncpy(d->path, relpath, d->pathlen);
  d->prev = NULL; /* Will be set later with mutex */
  d->next = NULL;
  d->off = 0;
  d->pg_start = child.dir_f.pg_start;
  d->start_blk = child.dir_f.start_blk;

  /* Add to list of open dirs (Add mutex here later) */
  /* TODO: Check if sb->d_end is NULL. */
  d->prev = sb->d_end;
  sb->d_end->next = d;
  sb->d_end = d;

  /* fdir */
  fdir->dir.d = d;
  *dir = &fdir->base;

  return ret;

errout_with_path:
  kmm_free(d->path);

errout_with_d:
  kmm_free(d);

errout:
  return ret;
}