#include <string.h>
#include <nuttx/kmalloc.h>
#include <sys/stat.h>
#include <sys/endian.h>

#include "mnemofs.h"

/*
The structure of a dentry on-flash

struct direntry {
  mfs_t  last_pg;
  mfs_t  last_idx;
  mode_t st_mode;
  off_t  st_size;
  struct timespec st_ctim;
  struct timespec st_mtim;
  struct timespec st_atim;
  uint8_t hash; // Hash of just the name
  mfs_t namelen;
  char name[namelen];
};

*/

#define MFS_DIRENT_LPG_OFF  (0)
#define MFS_DIRENT_LIDX_OFF (MFS_DIRENT_LPG_OFF + sizeof(mfs_t))
#define MFS_DIRENT_MODE_OFF (MFS_DIRENT_LIDX_OFF + sizeof(mfs_t))
#define MFS_DIRENT_SZ_OFF (MFS_DIRENT_MODE_OFF + sizeof(mode_t))
#define MFS_DIRENT_CTIM_OFF (MFS_DIRENT_SZ_OFF + sizeof(off_t))
#define MFS_DIRENT_MTIM_OFF (MFS_DIRENT_CTIM_OFF + sizeof(struct timespec))
#define MFS_DIRENT_ATIM_OFF (MFS_DIRENT_MTIM_OFF + sizeof(struct timespec))
#define MFS_DIRENT_HASH_OFF (MFS_DIRENT_ATIM_OFF + sizeof(struct timespec))
#define MFS_DIRENT_NAMELEN_OFF (MFS_DIRENT_HASH_OFF + sizeof(uint8_t))
#define MFS_DIRENT_NAME_OFF (MFS_DIRENT_NAMELEN_OFF + sizeof(mfs_t))
#define MFS_DIRENT_SIZE(namelen)     (MFS_DIRENT_NAME_OFF + (namelen))

enum {
  MFS_DIRENT_PATHINVAL = -1,
  MFS_NOCHILD = -2,
};

/* Allocates an array and returns the length of the hash array. If hasharr
is NULL, don't bother with creating the hash array. */
/* Returns an 8-bit integer if successful, negative for errors.*/
/* Needs to be called inside a locked environment. */
/* Set length of hasharr before hand using mfs_fsobj_pathcount */
int mfs_probe_direntries_r(FAR const struct mfs_sb_info * const sb,
                          FAR struct mfs_dentry *parent,
                          FAR struct mfs_dentry *child,
                          FAR const char *relpath, const mfs_t pathlen,
                          FAR uint8_t * hasharr)
{
  FAR char buf[MFS_DIRENT_NAME_OFF] = {0};
  FAR const char *start = relpath;
  FAR const char *next = NULL;
  int ret = 0;
  mfs_t off;
  FAR struct mfs_ctz_s ctz;
  uint8_t last = 0;
  mfs_t namelen;
  uint8_t childhash; /* Hash from stored data */
  uint8_t pathhash; /* Hash of the fs object from the path */
  FAR char * name = NULL;
  uint8_t hasharr_idx = 0; /* Assumed uint8_t as length due to mfs_fsobj_pathcount */

  while(start < relpath + pathlen) {

    off = 0;
    ret = mfs_fsobj(start, &start, &next);
    last = (next >= relpath + pathlen);
    pathhash = mfs_strhash(start, ret);
    hasharr[hasharr_idx++] = pathhash; /* Duplicate part as mfs_path_hash
    for optimization. */
    mfs_ctz_init(parent->last_pg, parent->last_pg, parent->sz, &ctz);
    
    while(1) {
      if(mfs_ctz_rd(sb, &ctz, off, buf, MFS_DIRENT_NAME_OFF) == 0) {
        if(last) {
          return MFS_NOCHILD;
        } else {
          return MFS_DIRENT_PATHINVAL;
        }
      }

      memcpy(&childhash, buf + MFS_DIRENT_HASH_OFF, sizeof(childhash));

      memcpy(&namelen, buf + MFS_DIRENT_NAMELEN_OFF, sizeof(namelen));
      namelen = betoh32(namelen);

      /* If hashes match then get the name and match string */

      if(pathhash == childhash) {

        name = kmm_zalloc(namelen);
        memcpy(name, buf + MFS_DIRENT_NAME_OFF, namelen);

        ret = strncmp(name, start, namelen);

        free(name);
        name = NULL;

        if(ret == 0 && last) {
          return ret;
        } else {
          break;
        }
      }

      off += MFS_DIRENT_NAME_OFF + namelen;
    }

    mfs_ctz_destroy(&ctz);
    start = next;
  };

  return 0;
}

/* 0 - If not found, 1 - found. Checks if a dir with path is open. */
/* FUTURE TODO: This assumes that a combo of the hash of the entire path
and a hash of each element name in the path (along with the order they
come in) will have an astronomically low chance of being coincidental. */
uint8_t mfs_d_probeopen(FAR const struct mfs_sb_info * const sb,
                        FAR const char *relpath, const mfs_t pathlen)
{
  const uint8_t path_hash = mfs_strhash(relpath, pathlen);
  FAR uint8_t *hasharr = NULL;
  uint8_t hashlen;
  FAR struct mfs_dinfo *entry = NULL;
  uint8_t i;

  list_for_every_entry(&sb->d, entry, struct mfs_dinfo, list) {
    if(entry->path_hash == path_hash) {
      if(!hasharr) {
        hashlen = mfs_path_hash(relpath, pathlen, hasharr);
      }

      if(entry->pathlen != hashlen) {
        continue;
      }

      for(i = 0; i < hashlen; i++) {
        if(entry->path[i] != hasharr[i]) {
          goto next;
        }
      }

      /* If we're here, we know we got a match. */
      free(hasharr);
      return 1;

next:;
    }
  }

  free(hasharr);
  hasharr = NULL;
  return 0;
}

int mfs_d_create(FAR struct mfs_sb_info * const sb,
                FAR const char * const relpath, const mode_t mode)
{
  /* TODO: POSIX Says -1 is returned on error and errno is set. */

  int ret = OK;
  const mfs_t pathlen = strlen(relpath);
  struct mfs_dentry parent;
  struct mfs_dentry child;
  FAR char *buf = NULL;
  uint8_t hash;
  struct mfs_ctz_s ctz;
  mfs_t tmp;
  uint8_t tmpbuf[sizeof(struct timespec)] = {0};
  FAR char * name = NULL;
  FAR struct mfs_dinfo *entry = NULL;
  mfs_t namelen;

  nxmutex_lock(&sb->fs_lock);

  parent = MFS_ROOT(sb);
  ret = mfs_probe_direntries_r(sb, &parent, &child, relpath, pathlen, NULL);
  if(ret == MFS_NOCHILD) {
    /* OK */
  } else if (ret == MFS_DIRENT_PATHINVAL) {
    ret = -ENOENT;
    goto errout_with_lock;
  } else {
    ret = -EEXIST;
    goto errout_with_lock;
  }

  /* Append at end of parent's directory file. */

  name = mfs_fsobj_last(relpath, pathlen);
  namelen = pathlen - (name - relpath);
  buf = kmm_malloc(MFS_DIRENT_SIZE(namelen));
  if(!buf) {
    ret = -ENOMEM;
    goto errout_with_lock;
  }

  hash = mfs_strhash(name, namelen);

  tmp = htobe32(MFS_EMPTY_CTZ);
  memcpy(buf + MFS_DIRENT_LPG_OFF, &tmp, sizeof(mfs_t));
  memcpy(buf + MFS_DIRENT_LIDX_OFF, &tmp, sizeof(mfs_t)); /* printing 0 here as well */

  /* FUTURE TODO: Mode here is unsigned int. This might be a problem for
  cases where unsigned int size changes. Also endianness conversion assumes
  it to be 32 bits. */
  tmp = htobe32(mode);
  memcpy(buf + MFS_DIRENT_MODE_OFF, &tmp, sizeof(mode_t));
  tmp = 0;
  memcpy(buf + MFS_DIRENT_SZ_OFF, &tmp, sizeof(off_t));

  // TODO: use mfs_h2ben and tmpbuf
  // memcpy(buf + MFS_DIRENT_CTIM_OFF, 0, );
  // memcpy(buf + MFS_DIRENT_MTIM_OFF, 0, );
  // memcpy(buf + MFS_DIRENT_CTIM_OFF, 0, );

  memcpy(buf + MFS_DIRENT_HASH_OFF, &hash, sizeof(uint8_t));

  tmp = htobe32(namelen);
  memcpy(buf + MFS_DIRENT_NAMELEN_OFF, &tmp, sizeof(mfs_t));

  memcpy(buf + MFS_DIRENT_HASH_OFF, name, namelen);

  mfs_ctz_init(parent.last_pg, parent.last_idx, parent.sz, &ctz);
  mfs_ctz_wr(sb, &ctz, parent.sz, buf, MFS_DIRENT_SIZE(pathlen)); /* TODO: namelen */

  /* TODO: Since we're updating a single directory file, it's parent needs
  to be updated as well, and so on till the root. When the journal
  implementation is finished, add logs for all of this.
  
  This is to be done for all updates as well. */

  /*
    Untested theory: No need to update open directories' offsets. The write
    will update offsets.
  */

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);
  return ret;
}

int mfs_d_open(FAR struct mfs_sb_info * const sb,
              FAR const char * const relpath,
              FAR struct fs_dirent_s ** const dir)
{

  int ret = OK;
  const mfs_t pathlen = strlen(relpath);
  FAR struct mfs_dinfo *di;
  struct mfs_dentry parent;
  struct mfs_dentry child;
  FAR uint8_t *hasharr = NULL;

  di = kmm_zalloc(sizeof(*di));
  if(!di) {
    ret = -ENOMEM;
    goto errout;
  }

  hasharr = kmm_zalloc(mfs_fsobj_pathcount(relpath, pathlen));
  if(!hasharr) {
    ret = -ENOMEM;
    goto errout_with_di;
  }

  nxmutex_lock(&sb->fs_lock);

  parent = MFS_ROOT(sb);
  ret = mfs_probe_direntries_r(sb, &parent, &child, relpath, pathlen,
                              hasharr);
  if(ret < 0) {
    ret = -ENOENT;
    goto errout_with_lock;
  }

  if(!S_ISDIR(child.mode)) {
    ret = -ENOTDIR;
    goto errout_with_hasharr;
  }

  di->mode = child.mode;
  di->pathlen = ret; /* Assuming ret has not changed till here */
  di->path = hasharr;
  di->path_hash = mfs_strhash(relpath, pathlen);
  mfs_ctz_init(child.last_pg, child.last_idx, child.sz, &di->ctz);
  list_add_tail(&MFS_ODIRS(sb), &di->list);

  *dir = (struct fs_dirent_s *) di;

  nxmutex_lock(&sb->fs_lock);
  return OK;

errout_with_hasharr:
  kmm_free(hasharr);
  hasharr = NULL;

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);

errout_with_di:
  kmm_free(di);
  di = NULL;

errout:
  return ret;
}

int mfs_d_close(FAR struct mfs_sb_info * const sb,
                FAR const struct fs_dirent_s * const dir)
{
  int ret = OK;
  FAR struct mfs_dinfo * const di = (struct mfs_dinfo * const) dir;

  nxmutex_lock(&sb->fs_lock);

  list_delete(&di->list);
  mfs_ctz_destroy(&di->ctz);
  free(di->path);
  di->path = NULL;

  nxmutex_unlock(&sb->fs_lock);

  return ret;
}

int mfs_d_rewind(FAR struct mfs_sb_info * const sb,
                FAR const struct fs_dirent_s * const dir)
{
  FAR struct mfs_dinfo * const di = (struct mfs_dinfo * const) dir;
  nxmutex_lock(&sb->fs_lock);
  di->off = MFS_READDIR_SELF;
  nxmutex_unlock(&sb->fs_lock);
  return OK;
}

int mfs_d_rd(FAR struct mfs_sb_info * const sb,
              FAR const struct fs_dirent_s * const dir,
              FAR struct dirent * const entry)
{
  int ret = OK;
  FAR struct mfs_dinfo * const di = (struct mfs_dinfo * const) dir;
  mfs_t namelen;
  mfs_t tmp;
  mode_t mode;

  nxmutex_lock(&sb->fs_lock);

  if(di->off == MFS_READDIR_SELF) {
    memcpy(entry->d_name, ".", 2);
    di->off++;
    goto errout_with_lock;
  } else if(di->off == MFS_READDIR_PARENT) {
    memcpy(entry->d_name, "..", 3);
    di->off++;
    mfs_ctz_offpoint(sb, &di->ctz, 0, &di->ctz_blkoff);
    goto errout_with_lock;
  }

  /* Currently only supports files and directories. */

  /* FUTURE TODO: Mode here is unsigned int. This might be a problem for
  cases where unsigned int size changes. Also endianness conversion assumes
  it to be 32 bits. */

  /* TODO: Error handling is poor in below code till end. */

  mfs_ctz_rd(sb, &di->ctz, di->off + MFS_DIRENT_MODE_OFF,
            (char *) &tmp, sizeof(mode_t));
  mode = betoh32(tmp);
  if(S_ISDIR(mode)) {
    entry->d_type = DTYPE_DIRECTORY;
  } else {
    entry->d_type = DTYPE_FILE;
  }

  mfs_ctz_rd(sb, &di->ctz, di->off + MFS_DIRENT_NAMELEN_OFF,
              (char *) &tmp, sizeof(mfs_t));
  namelen = betoh32(tmp);
  tmp = mfs_ctz_rd(sb, &di->ctz, di->off + MFS_DIRENT_NAME_OFF,
                  entry->d_name, namelen);

  ret = mfs_ctz_offpoint(sb, &di->ctz, di->off + MFS_DIRENT_NAME_OFF + tmp,
                        &di->ctz_blkoff);
  if(ret < 0) {
    goto errout_with_lock;
  }

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);
  return ret;
}

/* Same code as rmdir except this gives an error for path referring to a dir. */
int mfs_d_unlink(FAR struct mfs_sb_info * const sb,
                FAR const char * const relpath)
{
  int ret = OK;
  const mfs_t pathlen = strlen(relpath);
  struct mfs_dentry parent;
  struct mfs_dentry child;
  FAR struct mfs_ctz_s ctz;

  nxmutex_lock(&sb->fs_lock);

  parent = MFS_ROOT(sb);
  ret = mfs_probe_direntries_r(sb, &parent, &child, relpath, pathlen, NULL);
  if(ret < 0) {
    ret = -ENOENT;
    goto errout_with_lock;
  }

  /* mnemofs only supports dirs and regular files currently. */
  if(!S_ISREG(child.mode)) {
    ret = -EISDIR;
    goto errout_with_lock;
  }

  /* No probe open for file as POSIX allows files that are open to be
  unlinked. The file will be "deleted" when it's not in use. */

  /* Remove from parent's directory file. */

  mfs_ctz_init(parent.last_pg, parent.last_idx, parent.sz, &ctz);
  mfs_ctz_del(sb, &ctz, child.c_off, MFS_DENTRY_LEN(child));
  mfs_ctz_destroy(&ctz);

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);
  return ret;
}

/*
  There is a problem in having direntries in a "directory file". The simple
  case being that if a direntry is deleted or unlinked, all the direntries
  coming after it will be shifted left (left to right file). Let's say that
  direntries (which may be a file or a directory) are opened. While opening,
  if information like what offset in the parent directory file they start
  from is saved in the opened file/dir's structure, then any unlink or rm
  will need to update these information.

  There are some solutions to this problem, but this one has been chosen:

  Iterate through all open files and directories searching for all the
  sibling direntries that have been opened, and updating their offsets. This
  is a very valid solution when the number of open direntries are limited.
  This can be improved further at the cost of space by not just calculating
  a hash for the name of the direntry, but one for the entire path. But then
  even more space is required to save the path as well.
*/

int mfs_d_rm(FAR struct mfs_sb_info * const sb,
            FAR const char * const relpath)
{
  int ret = OK;
  const mfs_t pathlen = strlen(relpath);
  struct mfs_dentry parent;
  struct mfs_dentry child;
  FAR struct mfs_ctz_s ctz;

  nxmutex_lock(&sb->fs_lock);

  parent = MFS_ROOT(sb);
  ret = mfs_probe_direntries_r(sb, &parent, &child, relpath, pathlen, NULL);
  if(ret < 0) {
    ret = -ENOENT;
    goto errout_with_lock;
  }

  if(!S_ISDIR(child.mode)) {
    ret = -ENOTDIR;
    goto errout_with_lock;
  }

  if(mfs_d_probeopen(sb, relpath, pathlen)) {
    ret = -EBUSY;
    goto errout_with_lock;
  }

  if(child.sz != 0) {
    ret = -ENOTEMPTY;
    goto errout_with_lock;
  }

  /* Remove from parent's directory file. */

  mfs_ctz_init(parent.last_pg, parent.last_idx, parent.sz, &ctz);
  mfs_ctz_del(sb, &ctz, child.c_off, MFS_DENTRY_LEN(child));

  /* TODO: Update the offsets of the open files and directories coming after
  this. */

  mfs_ctz_destroy(&ctz);

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);
  return ret;
}

int mfs_d_mv(FAR struct mfs_sb_info * const sb,
            FAR const char * const oldrelpath,
            FAR const char * const newrelpath)
{

  struct mfs_dentry oldparent;
  struct mfs_dentry oldchild;
  struct mfs_dentry newparent;
  struct mfs_dentry newchild;
  struct mfs_ctz_s oldctz;
  struct mfs_ctz_s newctz;
  const mfs_t oldpathlen = strlen(oldrelpath);
  int ret = OK;
  uint8_t replace = 0;
  char *buf = NULL;

  nxmutex_lock(&sb->fs_lock);

  if(mfs_d_probeopen(sb, oldrelpath, oldpathlen) ||
    mfs_f_probeopen(sb, oldrelpath, oldpathlen)) {
    ret = -EBUSY; /* POSIX allows this. No renaming while open.*/
    goto errout_with_lock;
  }

  oldparent = MFS_ROOT(sb);
  ret = mfs_probe_direntries_r(sb, &oldparent, &oldchild, oldrelpath,
                              oldpathlen, NULL);
  if(ret < 0) {
    ret = -ENOENT;
    goto errout_with_lock;
  }

  newparent = MFS_ROOT(sb);
  ret = mfs_probe_direntries_r(sb, &newparent, &newchild, oldrelpath,
                              oldpathlen, NULL);
  /* Existing file will be replaced. */
  if(ret >= 0) {
    if(S_ISDIR(newchild.mode)) {
      ret = -EISDIR;
      goto errout_with_lock;
    } else {
      replace = 1; /* Need to replace original. */
    }
  } else if(ret == MFS_DIRENT_PATHINVAL) {
    ret = -ENOENT;
    goto errout_with_lock;
  }

  /* We're fine here. */
  buf = kmm_zalloc(MFS_DENTRY_LEN(newchild));
  if(!buf) {
    ret = -ENOMEM;
    goto errout_with_lock;
  }

  /* TODO: Endianness */
  memcpy(buf, &newchild, MFS_DENTRY_LEN(newchild)); /* TODO: If a name is put
                                                    into the direntry, it
                                                    needs to be put into
                                                    buffer properly.*/

  mfs_ctz_init(oldparent.last_pg, oldparent.last_idx, oldparent.sz, &oldctz);
  mfs_ctz_init(newparent.last_pg, newparent.last_idx, newparent.sz, &newctz);
  mfs_ctz_del(sb, &oldctz, oldchild.c_off, MFS_DENTRY_LEN(oldchild));

  /* TODO: If not replaced, the new file is appended, not updated. */
  mfs_ctz_upd(sb, &newctz, newchild.c_off, 0, MFS_DENTRY_LEN(newchild), buf);


  /* TODO: Update the offsets of the open files and directories coming after
  this in both old path and new path (new path will be appended if not
  being replaced). */

  mfs_ctz_destroy(&oldctz);
  mfs_ctz_destroy(&newctz);

errout_with_lock:
  kmm_free(buf);
  buf = NULL;
  nxmutex_unlock(&sb->fs_lock);
  return ret;
}

int mfs_d_stat(FAR struct mfs_sb_info * const sb, FAR const char * relpath,
                FAR struct stat *buf)
{
  int ret = OK;
  const mfs_t pathlen = strlen(relpath);
  struct mfs_dentry parent;
  struct mfs_dentry child;
  FAR struct mfs_ctz_s ctz;
  mfs_t tmp;

  nxmutex_lock(&sb->fs_lock);

  parent = MFS_ROOT(sb);
  ret = mfs_probe_direntries_r(sb, &parent, &child, relpath, pathlen, NULL);
  if(ret < 0) {
    ret = -ENOENT;
    goto errout_with_lock;
  }

  mfs_ctz_init(parent.last_pg, parent.last_idx, parent.sz, &ctz);

  mfs_ctz_rd(sb, &ctz, child.c_off + MFS_DIRENT_MODE_OFF,
            (char *) &buf->st_mode, sizeof(mode_t));

  mfs_ctz_rd(sb, &ctz, child.c_off + MFS_DIRENT_SZ_OFF,
            (char *) &tmp, sizeof(mfs_t));
  buf->st_size = tmp;

  /* TODO: Check if timestamps are saved on-flash in struct timespec */
  mfs_ctz_rd(sb, &ctz, child.c_off + MFS_DIRENT_CTIM_OFF,
            (char *) &buf->st_ctim, sizeof(struct timespec));
  mfs_ctz_rd(sb, &ctz, child.c_off + MFS_DIRENT_MTIM_OFF,
            (char *) &buf->st_mtim, sizeof(struct timespec));
  mfs_ctz_rd(sb, &ctz, child.c_off + MFS_DIRENT_ATIM_OFF,
            (char *) &buf->st_atim, sizeof(struct timespec));

  /* TODO: Does it need to be the actual count?? or does block here refer
  to the page of flash? */
  // buf->st_blksize = sb->pg_in_blk * sb->pg_sz;
  // buf->st_blocks

  mfs_ctz_destroy(&ctz);

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);
  return ret;
}