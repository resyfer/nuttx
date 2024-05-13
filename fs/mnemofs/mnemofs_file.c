#include <sys/stat.h>
#include <nuttx/kmalloc.h>
#include <fcntl.h>

#include "mnemofs.h"

#define MFS_FPTOI(fp)   ((fp)->f_inode)
#define MFS_ITOSB(i)    ((i)->i_private)
#define MFS_FPTOFINFO(fp) ((struct mfs_finfo *) (fp)->f_priv)

/* mfs_f_wmd: Give buffer, give metadata stuff, get buffer with
written metadata stuff. */

/* mfs_f_ioctl */

/* mfs_f_dup */

/* mfs_f_fstat */

/* TODO: Get return values of all locks and unlocks. */


/* 0 - If not found, 1 - found. Checks if a dir with path is open. */
/* TODO: This assumes that a combo of the hash of the entire path
and a hash of each element name in the path (along with the order they
come in) will have an astronomically low chance of being coincidental. */
uint8_t mfs_f_probeopen(FAR const struct mfs_sb_info * const sb,
                        FAR const char *relpath, const mfs_t pathlen)
{
  const uint8_t path_hash = mfs_strhash(relpath, pathlen);
  uint8_t *hasharr = NULL;
  uint8_t hashlen;
  FAR struct mfs_finfo *entry = NULL;
  uint8_t i;

  list_for_every_entry(&MFS_OFILES(sb), entry, struct mfs_finfo, list) {
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
  return 0;
}

/* Opens files. Adds an entry to the list of open files,
even if it is already open. Starts from offset 0. */
int mfs_f_open(FAR struct file * const fp, FAR const char *relpath,
                const int oflags, const mode_t mode)
{
  int ret = OK;
  const mfs_t pathlen = strlen(relpath);
  FAR const struct inode * const i = MFS_FPTOI(fp);
  FAR struct mfs_sb_info * const sb = MFS_ITOSB(i);
  FAR struct mfs_finfo *fi;
  struct mfs_dentry parent;
  struct mfs_dentry child;
  FAR uint8_t *hasharr = NULL;

  nxmutex_lock(&sb->fs_lock);

  ret = mfs_probe_direntries_r(sb, &parent, &child, relpath, pathlen, hasharr);
  if(ret != OK) {
    ret = -ENOENT;
    goto errout_with_lock;
  }

  if(!S_ISREG(child.mode)) {
    ret = -EISDIR;
    goto errout_with_hasharr;
  }

  fi = kmm_zalloc(sizeof(*fi));
  if(!fi) {
    ret = -ENOMEM;
    goto errout_with_hasharr;
  }

  fi->mode = mode;
  fi->pathlen = ret; /* Assuming ret has not changed till here. */
  fi->path = hasharr;
  fi->path_hash = mfs_strhash(relpath, pathlen);
  /* Not required. zalloc. */
  /* fi->ctz_blkoff = 0; */
  /* fi->childoff = 0; */
  mfs_ctz_init(child.last_pg, child.last_idx, child.sz, &fi->ctz);
  list_add_tail(&MFS_OFILES(sb), &fi->list);

  /* TODO: oflags?? */

  fp->f_priv = fi;

errout_with_hasharr:
  kmm_free(hasharr);

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);

  return ret;
}

int mfs_f_close(FAR const struct file * const fp)
{
  int ret = OK;
  FAR const struct inode * const i = MFS_FPTOI(fp);
  FAR struct mfs_sb_info * const sb = MFS_ITOSB(i);
  FAR struct mfs_finfo * const fi = MFS_FPTOFINFO(fp);

  nxmutex_lock(&sb->fs_lock);

  list_delete(&fi->list);
  mfs_ctz_destroy(&fi->ctz);

  nxmutex_unlock(&sb->fs_lock);
  return ret;
}

ssize_t mfs_f_rd(FAR const struct file * const fp, FAR char * const buf,
                const size_t buflen)
{
  ssize_t ret = OK;
  FAR const struct inode * const i = MFS_FPTOI(fp);
  FAR struct mfs_sb_info * const sb = MFS_ITOSB(i);
  FAR struct mfs_finfo * const fi = MFS_FPTOFINFO(fp);

  nxmutex_lock(&sb->fs_lock);

  /* mfs_ctz_rd will take care of off > l->size or off + buflen > l->size */

  fi->off += mfs_ctz_rd(sb, &fi->ctz, fi->ctz_blkoff, buf, buflen);
  ret = mfs_ctz_offpoint(sb, &fi->ctz, fi->off, &fi->ctz_blkoff);
  if(ret < 0) {
    goto errout_with_lock;
  }

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);
  return ret;
}

ssize_t mfs_f_wr(FAR const struct file * const fp, FAR const char * const buf,
                const size_t buflen)
{
  ssize_t ret = OK;
  FAR const struct inode * const i = MFS_FPTOI(fp);
  FAR struct mfs_sb_info * const sb = MFS_ITOSB(i);
  FAR struct mfs_finfo * const fi = MFS_FPTOFINFO(fp);
  
  if(fi->mode & O_WRONLY) {
    ret = -EBADF;
    goto errout;
  }

  nxmutex_lock(&sb->fs_lock);

  /* mfs_ctz_wr will take care of off > l->size or off + buflen > l->size */

  fi->off += mfs_ctz_wr(sb, &fi->ctz, fi->ctz_blkoff, buf, buflen);
  ret = mfs_ctz_offpoint(sb, &fi->ctz, fi->off, &fi->ctz_blkoff);
  if(ret < 0) {
    goto errout_with_lock;
  }

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);

errout:
  return ret;
}

off_t mfs_f_seek(FAR const struct file * const fp, const off_t off,
                const int whence)
{
  off_t ret = OK;
  FAR const struct inode * const i = MFS_FPTOI(fp);
  FAR struct mfs_sb_info * const sb = MFS_ITOSB(i);
  FAR struct mfs_finfo * const fi = MFS_FPTOFINFO(fp);

  if(off == 0) {
    goto errout;
  }

  nxmutex_lock(&sb->fs_lock);

  ret = fi->off;

  switch(whence) {

    case SEEK_SET:
      ret = off;
      break;

    case SEEK_CUR:
      ret += off;
      break;

    case SEEK_END:
      ret = MFS_CTZ_SZ(&fi->ctz) + off;
      break;
    
    default:
      ret = -EINVAL;
      goto errout_with_lock;

    /* SEEK_DATA and SEEK_HOLE are proposed for the next POSIX Revision 8. */
  }

  /* Check for wrap around */

  if((off > 0 && ret < fi->off) || (off < 0 && ret <= 0)) {
    ret = -EOVERFLOW;
    goto errout_with_lock;
  } else {
    /* Looks alright? */
    fi->off = ret;
  }

  nxmutex_lock(&sb->fs_lock);

errout_with_lock:
  nxmutex_unlock(&sb->fs_lock);

errout:
  return ret;
}

int mfs_f_trunc(FAR const struct file * const fp, const off_t len)
{
  int ret = OK;
  FAR const struct inode * const i = MFS_FPTOI(fp);
  FAR struct mfs_sb_info * const sb = MFS_ITOSB(i);
  FAR struct mfs_finfo * const fi = MFS_FPTOFINFO(fp);
  char *tmpbuf = NULL;
  mfs_t tmp = 0;
  
  if(predict_false(!(fi->mode & O_WRONLY))) {
    ret = -EBADF;
    goto errout;
  }

  if(predict_false(len < 0)) {
    ret = -EINVAL;
    goto errout;
  }

  nxmutex_lock(&sb->fs_lock);

  /* Imp: POSIX does not change the file offset. */

  if(len < MFS_CTZ_SZ(&fi->ctz)) {
    mfs_ctz_trunc(sb, &fi->ctz, len);
  } else {
    tmp = fi->off + len - MFS_CTZ_SZ(&fi->ctz);
    tmpbuf = kmm_zalloc(tmp);
    mfs_ctz_wr(sb, &fi->ctz, MFS_CTZ_SZ(&fi->ctz), tmpbuf, tmp);
  }

  nxmutex_unlock(&sb->fs_lock);

errout:
  free(tmpbuf);
  return ret;
}

/* Updates journal about a move by making an entry for each item in the
path. Most probably from the bottom of the tree to the top.

TODO: Think on this.*/
int mfs_f_updfpos(FAR const char * const relpath, const mfs_t relpathlen,
                  const mfs_t new_lastpg)
{
  return 0;
}