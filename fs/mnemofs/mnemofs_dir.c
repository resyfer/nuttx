#include <string.h>
#include <nuttx/kmalloc.h>
#include <sys/stat.h>

#include "mnemofs.h"

#define MFS_DIRENT_TYPE_OFF 10      /* TODO: Decide structure of direntry. Keep name at last. */
#define MFS_DIRENT_NAMELEN_OFF 10   /* TODO: Decide structure of direntry. Keep name at last. */
#define MFS_DIRENT_NAME_OFF 10      /* TODO: Decide structure of direntry. Keep name at last. */

int mfs_probe_direntries_r(FAR struct mfs_dentry *parent,
                            FAR struct mfs_dentry *child,
                            FAR const char *relpath, const mfs_t pathlen)
{
  /* TODO */
  return OK;
}

int mfs_d_create(FAR const struct mfs_sb_info * const sb,
                FAR const char * const path, const mode_t mode)
{
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

  di = kmm_zalloc(sizeof(*di));
  if(!di) {
    ret = -ENOMEM;
    goto errout;
  }

  nxmutex_lock(&sb->fs_lock);

  ret = mfs_probe_direntries_r(&parent, &child, relpath, pathlen);
  if(ret != OK) {
    ret = -ENOENT;
    goto errout_with_lock;
  }

  if(!S_ISDIR(child.mode)) {
    ret = -ENOTDIR;
    goto errout_with_lock;
  }

  di->mode = child.mode;
  mfs_ctz_init(child.last_pg, child.last_idx, child.sz, &di->ctz);
  list_add_tail(&MFS_ODIRS(sb), &di->list);

  *dir = (struct fs_dirent_s *) di; /* TODO: Check if const is valid. */

  nxmutex_lock(&sb->fs_lock);
  return OK;

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

  nxmutex_unlock(&sb->fs_lock);

  return ret;
}

int mfs_d_rewind(FAR struct mfs_sb_info * const sb,
                FAR const struct fs_dirent_s * const dir)
{
  FAR struct mfs_dinfo * const di = (struct mfs_dinfo * const) dir;
  nxmutex_lock(&sb->fs_lock);
  di->childoff = MFS_READDIR_SELF;
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

  if(di->childoff == MFS_READDIR_SELF) {
    memcpy(entry->d_name, ".", 2);
    di->childoff++;
    goto errout_with_lock;
  } else if(di->childoff == MFS_READDIR_PARENT) {
    memcpy(entry->d_name, "..", 3);
    di->childoff++;
    mfs_ctz_offpoint(sb, &di->ctz, 0, &di->ctz_blkoff);
    goto errout_with_lock;
  }

  /* TODO: Endianness */
  /* TODO: Reading mode from flash is weird. The flash would only store
  its permissions, not the way it should be used. Need to look into this
  further. */
  tmp = mfs_ctz_rd(sb, &di->ctz, di->childoff + MFS_DIRENT_TYPE_OFF,
                  (char *) &entry->d_type, sizeof(mode_t));
  tmp = mfs_ctz_rd(sb, &di->ctz, di->childoff + MFS_DIRENT_NAMELEN_OFF,
                  (char *) &namelen, sizeof(mfs_t));
  tmp = mfs_ctz_rd(sb, &di->ctz, di->childoff + MFS_DIRENT_NAME_OFF,
                  entry->d_name, tmp);

  ret = mfs_ctz_offpoint(sb, &di->ctz, di->childoff + MFS_DIRENT_NAME_OFF + tmp,
                        &di->ctz_blkoff);
  if(ret < 0) {
    goto errout_with_lock;
  }

  /* TODO: Think about terminating case. */

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);
  return OK;
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

/* TODO: Think about the benefits of dentry ID and if it's really needed. */
int mfs_d_rm(FAR struct mfs_sb_info * const sb,
            FAR const char * const relpath)
{
  /* TODO */
  return OK;
}

int mfs_d_mv(FAR struct mfs_sb_info * const sb,
            FAR const char * const oldrelpath,
            FAR const char * const newrelpath)
{
  /* TODO */
  return OK;
}