#include <nuttx/mtd/nand.h>

#include "mnemofs.h"

/* Slightly modified rand implementation based on the POSIX implementation
mentioned in rand(3) man page. O(1). */
mfs_t mfs_rand(uint8_t hash) {
  hash = hash * 1103515245 + 12345;
  return ((mfs_t)(hash/65536) % 32768);
}














/* TODO: Mark that the block is being used to write on it. mutex. */
uint32_t mfs_get_blk(FAR struct mfs_sb_info * const sb) {
  /* TODO */
  return 0;
}