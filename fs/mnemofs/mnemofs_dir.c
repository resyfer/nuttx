#include <string.h>
#include <nuttx/fs/fs.h>
#include <nuttx/kmalloc.h>
#include <sys/stat.h>

#include "mnemofs.h"

enum MNEMOFS_DIR_SEARCH_ERR {
  MNEMOFS_DIR_SEARCH_OK,
  MNEMOFS_DIR_SEARCH_NOT_FOUND,
  MNEMOFS_DIR_SEARCH_INVALID_PARENT,
};

enum MNEMOFS_READDIR {
  MNEMOFS_READDIR_SELF = -2,
  MNEMOFS_READDIR_PARENT = -1,
  MNEMOFS_READDIR_CHILDREN = 0, /* >= 0 */
};

struct mnemofs_fs_dirent {
  struct fs_dirent_s base; /* Start is kept same for VFS */
  struct mnemofs_fs_dirent *prev; /* Previous entry in doubly linked list.*/
  struct mnemofs_fs_dirent *next; /* Next entry in doubly linked list.*/
  off_t off; /* Offset of the file. */
  uint32_t start_pg; /* Last CTZ block (CTZ start) page number. */
  uint32_t start_idx; /* Last CTZ block (CTZ start) index. */
  /* Grouping the below and up together for caches.*/
  uint8_t hash; /* pathlen hash for the same reason as direntries have it, for search for when if dir is busy or not while open. */
  uint32_t pathlen; 
  char *path; /* Entire relpath to dir from mount */
};

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
//   char name[namelen]; /* Can be max NAME_MAX */
// };
#define DIRENT_PG_OFF 0
#define DIRENT_START_PG 4
#define DIRENT_TYPE_OFF 8
#define DIRENT_NAMELEN_OFF  9
#define DIRENT_NAME_OFF     10
#define DIRENT_SIZE(namelen)   ((DIRENT_NAME_OFF) + (namelen)) /* TODO: Round off to nearest 4 byte boundary */
#define DIRENT_MAX_SIZE   ((DIRENT_NAME_OFF) + (NAME_MAX)) /* TODO: Round off to nearest 4 byte boundary */

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
  return MNEMOFS_DIR_SEARCH_OK;
}

/* Recursive search (Iterative) */
/* TODO: Error system like 0 - Found an entry, 1 - No entry at that location, 2 - Parent not found (ie. search stopped midway) */
static int search_direntries_r(struct direntry_info *parent, struct direntry_info *child, FAR const char *path, ssize_t pathlen) {
  return MNEMOFS_DIR_SEARCH_OK;
}

int __mnemofs_mkdir(struct mnemofs_sb_info *sb, FAR const char *path, mode_t mode) {
  /* TODO: Add sb as a parameter*/

  FAR const char *name = path;
  ssize_t namelen = -1; /* It is set to -1 for the first pass */
  struct direntry_info cur_dir;
  struct direntry_info tmp;
  int ret = OK;
  char *buf = NULL;

  /* TODO: Ensure size of the path is less than NAME_MAX */

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
  tmp.dir_f.size = 0;
  tmp.dir_f.start_pg = 0; /* TODO: ENUM for empty file for start */
  tmp.dir_f.start_idx = -1; /* TODO: Empty CTZ list enum */

  buf = kmm_zalloc(DIRENT_SIZE(tmp.namelen));
  if(!buf) {
    ret = -ENOMEM;
    goto errout;
  }

  /* TODO: Think about endiannes */
  /* This is for the child. The values written in it for now are garbage,
  but they signify an empty directory. */
  const uint8_t type = MNEMOFS_DIR;

  memcpy(buf + DIRENT_PG_OFF, &tmp.dir_f.start_pg, sizeof(tmp.dir_f.start_pg));
  memcpy(buf + DIRENT_START_PG, &tmp.dir_f.start_idx, sizeof(tmp.dir_f.start_idx));
  memcpy(buf + DIRENT_TYPE_OFF, &type, sizeof(type));
  memcpy(buf + DIRENT_NAMELEN_OFF, &tmp.namelen, sizeof(tmp.namelen));
  memcpy(buf + DIRENT_NAME_OFF, tmp.name, namelen);

  /* Insert at end */
  ret = __mnemofs_file_insert(&cur_dir.dir_f, buf, DIRENT_SIZE(tmp.namelen), tmp.dir_f.size);
  if(ret < 0) {
    goto errout_with_buf;
  }

errout_with_buf:
  kmm_free(buf);

errout:
  return ret;
}

//---------------------------------

// 0 - Not found, 1 - Found
int search_open_dirs(struct mnemofs_sb_info *sb, FAR const char *relpath) {

  uint8_t hash;
  struct mnemofs_fs_dirent *head;
  int ret = 0;
  int lock = 0;

  if(!sb->d_start) {
    goto out;
  }

  hash = calc_name_hash(relpath, strlen(relpath));

  /* Only lock and unlock if we're the ones locking this, not the parent function. */
  if(!nxmutex_is_locked(&sb->d_lock)) {
    nxmutex_lock(&sb->d_lock);
    lock = 1;
  }


  for(head = sb->d_start; head != sb->d_end; head = head->next) {
    if(head->hash == hash) {
      /* Hash collision */
      if(!strncmp(relpath, head->path, head->pathlen)) {
        /* Found the path */
        ret = 1;
        goto out_with_lock;
      }
    }
  }

out_with_lock:
  if(lock) {
    nxmutex_unlock(&sb->d_lock);
  }

out:
  return ret;
}

int __mnemofs_opendir(struct mnemofs_sb_info *sb, FAR const char *relpath, FAR struct fs_dirent_s **dir) {

  int ret = OK;
  struct direntry_info parent, child;
  const unsigned long pathlen = strlen(relpath);
  struct mnemofs_fs_dirent *fdir;

  /* Get fdir mem */
  /* Since malloc is costly if held up by a lock, we will malloc here,
  even if it means using a free for incorrect cases. */

  fdir = kmm_zalloc(sizeof(*fdir));
  if(!fdir) {
    ret = -ENOMEM;
    goto errout;
  }

  /* Check Directory */

  /* Mutex here instead of later as there might be a case where the
  directory tree changes after search.*/

  nxmutex_lock(&sb->d_lock);

  ret = search_direntries_r(&parent, &child, relpath, pathlen);
  if(ret != MNEMOFS_DIR_SEARCH_OK) {
    ret = -ENOENT;
    goto errout_with_lock;
  }

  if(!S_ISDIR(child.mode)) {
    ret = -ENOTDIR;
    goto errout;
  }

  /* We have the directory now. */

  fdir->pathlen = pathlen;
  fdir->path = kmm_zalloc(pathlen);
  if(!fdir->path) {
    ret = -ENOMEM;
    goto errout_with_lock;
  }

  /* Turns out you don't need to check if a directory is already open:
    https://stackoverflow.com/a/1743037/14369307
  */
  fdir->prev = NULL; /* Will be set later with mutex */
  fdir->next = NULL;
  fdir->off = MNEMOFS_READDIR_SELF; /* -2 for . && -1 for .. && then the actual offset starts for reads. */
  fdir->start_pg = child.dir_f.start_pg;
  fdir->start_idx = child.dir_f.start_idx;
  /* We can attach these last two values here instead of a direntry without the
  fear of maintaining multiple sources of truth, as any change to this directory will
  not be allowed if it is open. */

  /* Append at end of list of open dirs */

  if(sb->d_end == NULL /* && sb->d_start == NULL */) {
    sb->d_start = fdir;
    sb->d_end = fdir;
  } else {
    sb->d_end->next = fdir;
    fdir->prev = sb->d_end;
    sb->d_end = fdir;
  }

  /* fdir */
  *dir = (struct fs_dirent_s *) fdir;

  nxmutex_unlock(&sb->d_lock);
  return OK;

// errout_with_path:
//   kmm_free(fdir->path);

errout_with_lock:
  nxmutex_unlock(&sb->d_lock);

// errout_with_fdir:
  kmm_free(fdir);

errout:
  return ret;
}

/* TODO: Check if SB is even required. */
int __mnemofs_closedir(struct mnemofs_sb_info *sb, FAR struct fs_dirent_s *dir) {
  struct mnemofs_fs_dirent *fdir;

  fdir = (struct mnemofs_fs_dirent *) dir;

  nxmutex_lock(&sb->d_lock);

  /* TODO: Debug assert to check if dir is not NULL */

  if(sb->d_start == fdir && sb->d_end == fdir /* && fdir->prev == NULL && fdir->next == NULL */) {
    sb->d_start = NULL;
    sb->d_end = NULL;
  } else {

    /* Taking care of terminal nodes preculiarities. */
    if (sb->d_start == fdir) {
      sb->d_start = fdir->next;
    } else if (sb->d_end == fdir) {
      sb->d_end = fdir->prev;
    }

    fdir->prev->next = fdir->next;
    fdir->next->prev = fdir->prev;
  }

  nxmutex_unlock(&sb->d_lock);

  kmm_free(fdir->path);
  kmm_free(fdir);

  return OK;
}

int __mnemofs_rewinddir(struct mnemofs_sb_info *sb, FAR struct fs_dirent_s *dir) {
  nxmutex_lock(&sb->d_lock);

  ((struct mnemofs_fs_dirent *) dir)->off = MNEMOFS_READDIR_SELF;

  nxmutex_unlock(&sb->d_lock);
  return 0;
}

int __mnemofs_readdir(struct mnemofs_sb_info *sb, FAR struct fs_dirent_s *dir, FAR struct dirent *entry) {

  struct mnemofs_fs_dirent *fdir = (struct mnemofs_fs_dirent *) dir;
  ssize_t len;
  char buf[DIRENT_NAME_OFF]; /* On-flash dir entry except name. */
  uint8_t namelen;
  uint8_t type;
  struct mnemofs_file df;
  int ret = OK;

  nxmutex_lock(&sb->d_lock);

  /* The first two cases are  . && .. */
  if(fdir->off == MNEMOFS_READDIR_SELF) {
    memcpy(entry->d_name, ".", 2);
    fdir->off++;
    goto errout_with_lock;
  } else if(fdir->off == MNEMOFS_READDIR_PARENT) {
    memcpy(entry->d_name, "..", 3);
    fdir->off++;
    goto errout_with_lock;
  }

  /* Initialize only the useful df fields. */
  /* TODO: Ensure size is not required here. */
  df.off = fdir->off;
  df.start_pg = fdir->start_pg;
  df.start_idx = fdir->start_idx;

  /* Get the rest of the data first, then get the name from the namelen. This would make
  us read twice, but NAND flash sequential reads are pretty fast. Since this is under a lock,
  this will most likely be a sequential read, unless a journal write happens in this time. */
  /* TODO: A lock for during journal writes. We only want to perform operations before or after
  it. */

  len = __mnemofs_file_read(sb, &df, df.off, buf, DIRENT_NAME_OFF);
  if(len < 0) {
    /* No more direntries remaining. */
    goto errout_with_lock;
  }

  memcpy(&namelen, buf + DIRENT_NAMELEN_OFF, sizeof(namelen));
  memcpy(&type, buf + DIRENT_TYPE_OFF, sizeof(type));
  
  len = __mnemofs_file_read(sb, &df, df.off + DIRENT_NAME_OFF, entry->d_name, namelen);
  if(len < 0) {
    /* No more direntries remaining. */
    goto errout_with_lock;
  }

  /* TODO: We KNOW len == namelen, still, a debug assert to check.*/

  fdir->off += DIRENT_NAME_OFF + namelen;

  entry->d_type = type;

  /* TODO: Address the end-of-direntries case. */

errout_with_lock:
  nxmutex_unlock(&sb->d_lock);

  return ret;
}