#include <string.h>
#include <nuttx/fs/fs.h>
#include <nuttx/kmalloc.h>
#include <sys/stat.h>

#include "mnemofs.h"

struct mnemofs_fs_dirent {
  struct fs_dirent_s base; /* Start is kept same for VFS */
  struct mnemofs_fs_dirent *prev; /* Previous entry in doubly linked list.*/
  struct mnemofs_fs_dirent *next; /* Next entry in doubly linked list.*/
  off_t off; /* Offset of the file. */
  struct mnemofs_ctz_s l;
  /* TODO: Grouping the below and up together for caches.*/
  uint8_t hash; /* pathlen hash for the same reason as direntries have it, for search for when if dir is busy or not while open. */
  uint32_t pathlen; 
  char *path; /* Entire relpath to dir from mount */
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

static ssize_t get_cur_name_len(FAR const char *path);
static int search_direntries(struct mnemofs_direntry_info *parent, struct mnemofs_direntry_info *child, FAR const char *name, ssize_t namelen);
static int search_open_dirs(struct mnemofs_sb_info *sb, FAR const char *relpath);

/* Like strtok, but does not change string. Gives the name till the next '\' or '\0' */
static ssize_t get_cur_name_len(FAR const char *path) {
  int i;
  for(i = 0; path[i] != 0 && path[i] != '/'; i++);
  return i;
}

/* TODO: Special case for . and .. */
/* Denotes the pg and off as 0 if error. */
/* Only searches immediate child */
/* TODO: Error system like 0 - Found an entry, 1 - No entry at that location, 2 - Parent not found (ie. search stopped midway) */
static int search_direntries(struct mnemofs_direntry_info *parent, struct mnemofs_direntry_info *child, FAR const char *name, ssize_t namelen) {
  struct mnemofs_direntry_info ret = {0};

  ret.dir_f.hash = mnemofs_calc_str_hash(name, namelen);
  ret.dir_f.path = name;
  ret.dir_f.pathlen = namelen;
  ret.parent_path = parent->dir_f.path; /* TODO: FULL PATH of parent by appending parent's parent path and name. */ /* TODO: Copy the path, not reference */
  ret.parent_pathlen = parent->dir_f.pathlen; /* TODO: Same parent treatment. */
  /* TODO: add the ret.dir_f properties here after search */

  /* TODO: Implement files, use inner implementation function to read the file data */

  /* TODO: child.off has to be added HERE. This refers to the offset in the direntry file. */

  /* Use calc_name_hash & strcmp for hash collisions */
  memcpy(parent, &ret, sizeof(ret));
  return MNEMOFS_DIR_SEARCH_OK;
}

/* TODO: Special case for . and .. */
/* Recursive search (Iterative) */
/* TODO: Error system like 0 - Found an entry, 1 - No entry at that location, 2 - Parent not found (ie. search stopped midway) */
/* If a file or directory is asked, and it is found, put it in child, corresponding to the last iteration of the directory tree. */
int search_direntries_r(struct mnemofs_direntry_info *parent, struct mnemofs_direntry_info *child, FAR const char *path, ssize_t pathlen) {
  return MNEMOFS_DIR_SEARCH_OK;
}

//---------------------------------

// 0 - Not found, 1 - Found
static int search_open_dirs(struct mnemofs_sb_info *sb, FAR const char *relpath) {

  uint8_t hash;
  struct mnemofs_fs_dirent *head;
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
    nxmutex_unlock(&sb->fs_lock);
  }

out:
  return ret;
}

int __mnemofs_opendir(struct mnemofs_sb_info *sb, FAR const char *relpath, FAR struct fs_dirent_s **dir) {

  int ret = OK;
  struct mnemofs_direntry_info parent, child;
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

  nxmutex_lock(&sb->fs_lock);

  ret = search_direntries_r(&parent, &child, relpath, pathlen);
  if(ret != MNEMOFS_DIR_SEARCH_OK) {
    ret = -ENOENT;
    goto errout_with_lock;
  } else {
    ret = OK;
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
  memcpy(fdir->path, relpath, pathlen);

  /* Turns out you don't need to check if a directory is already open:
    https://stackoverflow.com/a/1743037/14369307
  */
  fdir->prev = NULL; /* Will be set later with mutex */
  fdir->next = NULL;
  fdir->hash = mnemofs_calc_str_hash(fdir->path, fdir->pathlen);
  fdir->off = MNEMOFS_READDIR_SELF; /* -2 for . && -1 for .. && then the actual offset starts for reads. */
  fdir->l.last_pg = child.dir_f.l.last_pg;
  fdir->l.last_idx = child.dir_f.l.last_idx;
  fdir->l.idx = 0;
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

  nxmutex_unlock(&sb->fs_lock);
  return OK;

// errout_with_path:
//   kmm_free(fdir->path);

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);

// errout_with_fdir:
  kmm_free(fdir);

errout:
  return ret;
}

/* TODO: Check if SB is even required. */
int __mnemofs_closedir(struct mnemofs_sb_info *sb, FAR struct fs_dirent_s *dir) {
  struct mnemofs_fs_dirent *fdir;

  fdir = (struct mnemofs_fs_dirent *) dir;

  nxmutex_lock(&sb->fs_lock);

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

  nxmutex_unlock(&sb->fs_lock);

  kmm_free(fdir->path);
  kmm_free(fdir);

  return OK;
}

int __mnemofs_rewinddir(struct mnemofs_sb_info *sb, FAR struct fs_dirent_s *dir) {
  nxmutex_lock(&sb->fs_lock);

  ((struct mnemofs_fs_dirent *) dir)->off = MNEMOFS_READDIR_SELF;

  nxmutex_unlock(&sb->fs_lock);
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

  nxmutex_lock(&sb->fs_lock);

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
  df.off = fdir->off;
  df.l = fdir->l;

  /* Get the rest of the data first, then get the name from the namelen. This would make
  us read twice, but NAND flash sequential reads are pretty fast. Since this is under a lock,
  this will most likely be a sequential read, unless a journal write happens in this time. */
  /* TODO: A lock for during journal writes. We only want to perform operations before or after
  it. */

  len = __mnemofs_file_read(sb, &df, df.off, buf, DIRENT_NAME_OFF);
  if(len < 0) {
    /* No more direntries remaining. */
    /* TODO: Check if error value needs to be set. */
    goto errout_with_lock;
  }

  memcpy(&namelen, buf + DIRENT_NAMELEN_OFF, sizeof(namelen));
  memcpy(&type, buf + DIRENT_TYPE_OFF, sizeof(type));
  
  len = __mnemofs_file_read(sb, &df, df.off + DIRENT_NAME_OFF, entry->d_name, namelen);
  if(len <= 0) {
    /* No more direntries remaining. */
    goto errout_with_lock;
  }

  /* TODO: We KNOW len == namelen, still, a debug assert to check.*/

  fdir->off += DIRENT_NAME_OFF + namelen;

  entry->d_type = type;

  /* TODO: Address the end-of-direntries case. */

  nxmutex_unlock(&sb->fs_lock);
  return len;

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);

  return ret;
}

//----------------------------------------------------------------------------

/* Path Ops */

/* This waits for the delete, which is probably not what UNIX wanted.
UNIX meant to unlink the file, and the file is later removed,
presumably when no other processes are using it. */
/* TODO: If a directory becomes empty (apart from . and ..), then set the
directory's dirent_info.pg to 0 to denote an empty directory. */
int __mnemofs_unlink(FAR struct mnemofs_sb_info *sb, FAR const char *relpath) {
  struct mnemofs_direntry_info parent, child;
  const int pathlen = strlen(relpath);
  int ret = OK;

  /* TODO: This lock only prevents for directory changes. Think if it was a file.
  Probably needs a mutex for path related ops, or something like that or multiple
  locks.*/
  nxmutex_lock(&sb->fs_lock);

  ret = search_open_dirs(sb, relpath);
  if(ret) {
    ret = -EBUSY;
    goto errout_with_lock;
  } else {
    ret = OK;
  }

  memcpy(&parent, sb->root, sizeof(parent));
  ret = search_direntries_r(&parent, &child, relpath, pathlen);
  if(ret != MNEMOFS_DIR_SEARCH_OK) {
    ret = -ENOENT;
    goto errout_with_lock;
  } else {
    ret = OK;
  }

  /* TODO: Check if unlink functions actually return this. */
  if(S_ISDIR(child.mode)) {
    ret = -EISDIR;
    goto errout_with_lock;
  }

  /* TODO: Here we have `child` being a file. Search the open files,
  and/or use a mutex or semaphore in the file's open structure.*/

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);

  return ret;
}

int __mnemofs_mkdir(struct mnemofs_sb_info *sb, FAR const char *path, mode_t mode) {

  FAR const char *name = path;
  ssize_t namelen = -1; /* It is set to -1 for the first pass */
  struct mnemofs_direntry_info cur_dir;
  struct mnemofs_direntry_info tmp;
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
  // cur_dir.mode = 0777; /* TODO: verify root's mode. */

  memcpy(&cur_dir, sb->root, sizeof(cur_dir));

  while(1) {

    /* TODO: we know this should not fall out of bounds, but MAYBE. So debug assert. */
    if(*(name + namelen) == '\0') {
      /* Exact match found */
      ret = -EEXIST;
      goto errout;
    }

    /* FUTURE TODO: Support links and redirection.*/
    if(!S_ISDIR(cur_dir.mode)) {
      ret = -ENOTDIR;
      goto errout;
    }

    name += namelen + 1; /* +1 is for skipping the '\'. Since we've reached this
    point, we know the string does not end on name + namelen + 1, but rather also has
    atleast 1 file system object after it.*/
    namelen = get_cur_name_len(name);
    ret = search_direntries(&cur_dir, &tmp, name, namelen);

    if(ret == MNEMOFS_DIR_SEARCH_NOT_FOUND) {
      /* Not found, so we're good, and move on to creating it. */
      ret = OK;
      break;
    } else if (ret == MNEMOFS_DIR_SEARCH_OK) {
      /* Found a file system object at that path. */
      ret = -EEXIST;
      goto errout;
    } else /* if (ret == MNEMOFS_DIR_SEARCH_INVALID_PARENT) */ {
      /* One of the parents does not exist in the path. */
      ret = -ENOENT;
      goto errout;
    }

    memcpy(&cur_dir, &tmp, sizeof(tmp));
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
  tmp.dir_f.l.idx = 0;
  tmp.dir_f.l.last_pg = 0; /* TODO: ENUM for empty file for start */
  tmp.dir_f.l.last_idx = -1; /* TODO: Empty CTZ list enum */

  buf = kmm_zalloc(DIRENT_SIZE(tmp.dir_f.pathlen));
  if(!buf) {
    ret = -ENOMEM;
    goto errout;
  }

  /* TODO: Think about endiannes */
  /* This is for the child. The values written in it for now are garbage,
  but they signify an empty directory. */
  const uint8_t type = MNEMOFS_DIR;

  memcpy(buf + DIRENT_PG_OFF, &tmp.dir_f.l.last_pg, sizeof(tmp.dir_f.l.last_pg));
  memcpy(buf + DIRENT_START_PG, &tmp.dir_f.l.last_idx, sizeof(tmp.dir_f.l.last_idx));
  memcpy(buf + DIRENT_TYPE_OFF, &type, sizeof(type));
  memcpy(buf + DIRENT_NAMELEN_OFF, &tmp.dir_f.pathlen, sizeof(tmp.dir_f.pathlen));
  memcpy(buf + DIRENT_NAME_OFF, tmp.dir_f.path, namelen);

  /* Insert at end */
  ret = __mnemofs_file_insert(sb, &cur_dir.dir_f, buf, DIRENT_SIZE(tmp.dir_f.pathlen), tmp.dir_f.size);
  if(ret < 0) {
    goto errout_with_buf;
  }
  /* TODO: Increment the tmp.dir_f.size */

errout_with_buf:
  kmm_free(buf);

errout:
  return ret;
}

int __mnemofs_rmdir(struct mnemofs_sb_info *sb, FAR const char *relpath) {

  /* TODO: Look for the EINVAL condition from the man page. */

  int ret = OK;
  struct mnemofs_direntry_info parent, child;
  const int pathlen = strlen(relpath);

  nxmutex_lock(&sb->fs_lock);

  memcpy(&parent, sb->root, sizeof(parent));

  ret = search_open_dirs(sb, relpath);
  if(ret) {
    ret = -EBUSY;
    goto errout_with_lock;
  }

  ret = search_direntries_r(&parent, &child, relpath, pathlen);
  if(ret != MNEMOFS_DIR_SEARCH_OK) {
    ret = -ENOENT;
    goto errout_with_lock;
  } else {
    ret = OK;
  }

  if(!S_ISDIR(child.mode)) {
    ret = -ENOTDIR;
    goto errout_with_lock;
  }

  if(child.dir_f.l.last_pg != 0 /* && child.dir_f.off != 0 */) {
    ret = -ENOTEMPTY;
    goto errout_with_lock;
  }

  /* TODO: Make the DIRENT_NAME_OFF + child.namelen into a macro. */
  /* Insert into parent's direntry file */
  ret = __mnemofs_file_delete(&parent.dir_f, child.dir_f.off, DIRENT_NAME_OFF + child.dir_f.pathlen);
  if(ret) {
    goto errout_with_lock;
  }

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);

  return ret;
}

/* Move File. */
int __mnemofs_mv(struct mnemofs_sb_info *sb, FAR const char *oldrelpath, FAR const char *newrelpath) {

  struct mnemofs_direntry_info old_parent, old_child, new_parent, new_child;
  int ret = OK;
  const int oldpathlen = strlen(oldrelpath);
  const int newpathlen = strlen(newrelpath);
  int is_dir = 0;

  /* TODO: Imp from man page:
    - Newpath gets replaced even if it exists.
      Solution: Flag by default is RENAME_NOREPLACE, so -EEXIST if already exists.
    - Directory change needs to be reflected in its parentpath, etc.
  */

  /* TODO: Again lock is only for dir */
  nxmutex_lock(&sb->fs_lock);

  /* Old */
  memcpy(&old_parent, sb->root, sizeof(old_parent));
  ret = search_direntries_r(&old_parent, &old_child, oldrelpath, oldpathlen);
  if(ret != MNEMOFS_DIR_SEARCH_OK) {
    ret = -ENOENT; /* TODO: Confirm that if path cannot be reached, ie. parent is not available, this is the same error.*/
    goto errout_with_lock;
  } else {
    ret = OK;
  }

  if(S_ISDIR(old_child.mode)) {
    is_dir = 1; /* Special case. */
  }

  /* New */
  memcpy(&new_parent, sb->root, sizeof(new_parent));
  ret = search_direntries_r(&new_parent, &new_child, newrelpath, newpathlen);
  /*
    Problem: POSIX says newpath gets replaced even if it exists.
    Solution: Flag by default is RENAME_NOREPLACE, so -EEXIST if already exists.

    TODO: Check other implementations. Or else it will be a long code.
  */
  if(ret != MNEMOFS_DIR_SEARCH_OK) {
    ret = -EEXIST;
    goto errout_with_lock;
  } else {
    ret = OK;
  }

  /* Insert new entry */
  /* new_child.hash: Already done by search_direntries */
  new_child.mode = old_child.mode;
  /* new_child.name: Already done by search_direntries */
  /* new_child.off: To be created when journal is written. */
  /* new_child.parent_path: Already done by search_direntries */
  /* new_child.parent_pathlen: Already done by search_direntries */

  /* Save the on-flash direntry representation to parent directory. */
  new_child.dir_f.size = 0;
  new_child.dir_f.l.idx = 0; /* TODO: ENUM for empty file for start */
  new_child.dir_f.l.last_pg = 0; /* TODO: ENUM for empty file for start */
  new_child.dir_f.l.last_idx = -1; /* TODO: Empty CTZ list enum */
  /* These upper entries are same as in __mnemofs_mkdir */

  ret = __mnemofs_file_insert(sb, &new_parent.dir_f, (const char *) &new_child, DIRENT_NAME_OFF + new_child.dir_f.pathlen, new_parent.dir_f.off);
  if(ret < 0) {
    goto errout_with_lock;
  }

  /* Delete from old parent's direntry file.*/
  ret =  __mnemofs_file_delete(&old_parent.dir_f, old_child.dir_f.off, DIRENT_NAME_OFF + old_child.dir_f.pathlen);
  if(ret < 0) {
    goto errout_with_lock;
    /* TODO: Error condition to reverse the previous insert. The only problem is, this function will be effectively
    just adding a log in the journal. This would mean the journal will have to have a new entry that creates a new
    directory in the same place. */
  }

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);

  return ret;
}