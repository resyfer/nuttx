/* Producer Consumer, mainly the consumer part. */

#include <nuttx/kthread.h>
#include <nuttx/kmalloc.h>

#include "mnemofs.h"

void mnemofs_consumer(struct mnemofs_sb_info *sb) {

  struct mfs_task *task;
  int i;

  for(;;) {
    sem_wait(&sb->full);
    nxmutex_lock(&sb->pc_lock);

    task = sb->pc_e;

    if(sb->pc_s == sb->pc_e) {
      sb->pc_s = NULL;
      sb->pc_e = NULL;
    } else {
      sb->pc_e = sb->pc_e->prev;
      sb->pc_e->next = NULL;
    }

    switch(task->type) {
      case MNEMOFS_OPEN:
        __mnemofs_open((struct file *) task->args[0],
                      (const char *) task->args[1],
                      *((int*) task->args[2]),
                      *((mode_t *) task->args[3]));
        break;

      case MNEMOFS_CLOSE:
        __mnemofs_close((struct file *) task->args[0]);
        break;

      case MNEMOFS_READ:
        __mnemofs_read((struct file *) task->args[0],
                      (char *) task->args[1],
                      *((size_t*) task->args[2]));
        break;

      case MNEMOFS_WRITE:
        __mnemofs_write((struct file *) task->args[0],
                      (const char *) task->args[1],
                      *((size_t*) task->args[2]));
        break;

      case MNEMOFS_SEEK:
        __mnemofs_seek((struct file *) task->args[0],
                      *((off_t*) task->args[1]),
                      *((int*) task->args[2]));
        break;

      case MNEMOFS_IOCTL:
        /* TODO */
        break;

      case MNEMOFS_TRUNCATE:
        /* TODO */
        break;

      case MNEMOFS_OPENDIR:
        __mnemofs_opendir((struct mnemofs_sb_info *) task->args[0],
                          (const char*) task->args[1],
                          (struct fs_dirent_s**) task->args[2]);
        break;

      case MNEMOFS_CLOSEDIR:
        __mnemofs_closedir((struct mnemofs_sb_info *) task->args[0],
                            (struct fs_dirent_s*) task->args[1]);
        break;

      case MNEMOFS_READDIR:
        __mnemofs_readdir((struct mnemofs_sb_info *) task->args[0],
                          (struct fs_dirent_s*) task->args[1],
                          (struct dirent *) task->args[2]);
        break;

      case MNEMOFS_REWINDDIR:
        __mnemofs_rewinddir((struct mnemofs_sb_info *) task->args[0],
                            (struct fs_dirent_s*) task->args[1]);
        break;
      
      case MNEMOFS_UNBIND:
        /* TODO */
        break;

      case MNEMOFS_STATFS:
        /* TODO */
        break;

      case MNEMOFS_UNLINK:
        __mnemofs_unlink((struct mnemofs_sb_info *) task->args[0],
                          (const char*) task->args[1]);
        break;

      case MNEMOFS_MKDIR:
        __mnemofs_mkdir((struct mnemofs_sb_info *) task->args[0],
                          (const char*) task->args[1],
                          *((mode_t*) task->args[2]));
        break;

      case MNEMOFS_RMDIR:
        __mnemofs_rmdir((struct mnemofs_sb_info *) task->args[0],
                          (const char*) task->args[1]);
        break;

      case MNEMOFS_RENAME:
        __mnemofs_mv((struct mnemofs_sb_info *) task->args[0],
                      (const char*) task->args[1],
                      (const char*) task->args[2]);
        break;

      case MNEMOFS_STAT:
        /* TODO */
        break;

    }

    for(i = 0; i < MNEMOFS_MAX_ARGS; i++) {
      kmm_free(task->args[i]);
    }

    nxmutex_unlock(&sb->pc_lock);
    sem_post(&sb->empty);
  }
}

// TODO: A similar structure (without the loop) needs to be implemented for
// every VFS-exposed method.
// void mnemofs_producer(struct mnemofs_sb_info *sb, struct mfs_task *task) {

//   for(;;) {
//     sem_wait(&sb->empty);
//     nxmutex_lock(&sb->pc_lock);

//     nxmutex_unlock(&sb->pc_lock);
//     sem_post(&sb->full);
//   }
// }