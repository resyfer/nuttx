#include <string.h>
#include <nuttx/kmalloc.h>
#include <sys/stat.h>

#include "mnemofs.h"

#define MFS_DIRENT_TYPE_OFF 10      /* TODO: Decide structure of direntry. Keep name at last. */
#define MFS_DIRENT_NAMELEN_OFF 10   /* TODO: Decide structure of direntry. Keep name at last. */
#define MFS_DIRENT_NAME_OFF 10      /* TODO: Decide structure of direntry. Keep name at last. */

/* Allocates an array and returns the length of the hash array. If hasharr
is NULL, don't bother with creating the hash array. */
enum {
  MFS_DIRENT_PATHINVAL = -1,
  MFS_NOCHILD = -2,
};

/* Returns an 8-bit integer if successful, negative for errors.*/
int16_t mfs_probe_direntries_r(FAR struct mfs_dentry *parent,
                            FAR struct mfs_dentry *child,
                            FAR const char *relpath, const mfs_t pathlen,
                            FAR uint8_t ** hasharr)
{
  /* TODO */
  return 0;
}

/* 0 - If not found, 1 - found. Checks if a dir with path is open. */
int mfs_d_probeopen(FAR const char *relpath, const mfs_t pathlen) {
  /* TODO */
  return 0;
}

int mfs_d_create(FAR const struct mfs_sb_info * const sb,
                FAR const char * const path, const mode_t mode)
{
  /* TODO */
  return OK;
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

  nxmutex_lock(&sb->fs_lock);

  parent = MFS_ROOT(sb);
  ret = mfs_probe_direntries_r(&parent, &child, relpath, pathlen, &hasharr);
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

  *dir = (struct fs_dirent_s *) di; /* TODO: Check if const is valid. */

  nxmutex_lock(&sb->fs_lock);
  return OK;

errout_with_hasharr:
  kmm_free(hasharr);

errout_with_lock:
  nxmutex_lock(&sb->fs_lock);
  kmm_free(di);

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

  /* TODO: Endianness */
  /* TODO: Reading mode from flash is weird. The flash would only store
  its permissions, not the way it should be used. Need to look into this
  further. */
  tmp = mfs_ctz_rd(sb, &di->ctz, di->off + MFS_DIRENT_TYPE_OFF,
                  (char *) &entry->d_type, sizeof(mode_t));
  tmp = mfs_ctz_rd(sb, &di->ctz, di->off + MFS_DIRENT_NAMELEN_OFF,
                  (char *) &namelen, sizeof(mfs_t));
  tmp = mfs_ctz_rd(sb, &di->ctz, di->off + MFS_DIRENT_NAME_OFF,
                  entry->d_name, tmp);

  ret = mfs_ctz_offpoint(sb, &di->ctz, di->off + MFS_DIRENT_NAME_OFF + tmp,
                        &di->ctz_blkoff);
  if(ret < 0) {
    goto errout_with_lock;
  }

  /* TODO: Think about terminating case. */

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);
  return ret;
}

int mfs_d_unlink(FAR struct mfs_sb_info * const sb,
                FAR const char * const relpath)
{
  /* TODO: Think about a suitable way to remove the link, but not delete
  the file data immediate, but delete it when no references to it are open.
  This would be so much easier with inode numbers. */

  /* TODO: Add an offset in parent directory's directory file (offset of
  current file/directory's direntry). This will be for both the file and
  the directory. */

  /* TODO: Add another field named siblings, which will also be a doubly
  linked list. This will be an ordered linked list, according to ID of the
  direntry (add ID feature as well). This will be in ascending order of ID
  (simiilar to how they will be in flash) such that when let's say ID `x` is
  unlink-ed or rm-edm all the following IDs in that list will have their
  CTZ list offsets updated as well. Let's say the size of `x`th directory
  was `n`, then all the IDs from `x+1` to `x+max_id_in_dir` will have their
  offsets reduced by `n`.
  
  It's only the open directories and files that need this change. Rest
  would be fine as they would read updated values. */
  return OK;
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
  ret = mfs_probe_direntries_r(&parent, &child, relpath, pathlen, NULL);
  if(ret < 0) {
    ret = -ENOENT;
    goto errout_with_lock;
  }

  if(!S_ISDIR(child.mode)) {
    ret = -ENOTDIR;
    goto errout_with_lock;
  }

  if(mfs_d_probeopen(relpath, pathlen)) {
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

errout_with_lock:
  nxmutex_lock(&sb->fs_lock);
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

  if(mfs_d_probeopen(oldrelpath, oldpathlen)) {
    ret = -EBUSY; /* POSIX allows this. No renaming while open.*/
    goto errout_with_lock;
  }

  oldparent = MFS_ROOT(sb);
  ret = mfs_probe_direntries_r(&oldparent, &oldchild, oldrelpath,
                              oldpathlen, NULL);
  if(ret < 0) {
    ret = -ENOENT;
    goto errout_with_lock;
  }

  newparent = MFS_ROOT(sb);
  ret = mfs_probe_direntries_r(&newparent, &newchild, oldrelpath,
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
  mfs_ctz_upd(sb, &newctz, newchild.c_off, 0, MFS_DENTRY_LEN(newchild), buf);

errout_with_lock:
  kmm_free(buf);
  nxmutex_lock(&sb->fs_lock);
  return ret;
}