#include <string.h>
#include <nuttx/fs/fs.h>
#include <nuttx/kmalloc.h>
#include <sys/stat.h>

#include "mnemofs.h"

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
static struct direntry_info search_direntries(struct direntry_info parent, FAR const char *name, ssize_t namelen);

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
static struct direntry_info search_direntries(struct direntry_info parent, FAR const char *name, ssize_t namelen) {
  struct direntry_info ret = {0};

  ret.hash = calc_name_hash(name, namelen);
  ret.name = name;
  ret.namelen = namelen;
  ret.parent_path = parent.name; /* TODO: FULL PATH of parent by appending parent's parent path and name. */
  ret.parent_pathlen = parent.namelen; /* TODO: Same parent treatment. */
  /* TODO: add the ret.dir_f properties here after search */

  /* TODO: Implement files, use inner implementation function to read the file data */

  /* Use calc_name_hash & strcmp for hash collisions */
  return ret;
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
  cur_dir.hash = calc_name_hash("/", 1); /* TODO: check if `path` contains `/` in first character */
  cur_dir.name = "/";
  cur_dir.namelen = 1;
  cur_dir.pg = sb->master_node;
  cur_dir.off = 0;
  cur_dir.parent_path = NULL;
  cur_dir.parent_pathlen = 0;
  cur_dir.mode = 0777; /* TOD: verify root's mode. */

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
    tmp = search_direntries(cur_dir, name, namelen);
    if(tmp.pg == 0 && tmp.off == 0) {
      /* Not found, so we're good, and move on to creating it. */
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

  ret = __mnemofs_file_insert(&cur_dir.dir_f, buf, DIRENT_SIZE(tmp.namelen), cur_dir.dir_f.f_size);
  if(ret < 0) {
    goto errout_with_buf;
  }

errout_with_buf:
  kmm_free(buf);

errout:
  return ret;
}