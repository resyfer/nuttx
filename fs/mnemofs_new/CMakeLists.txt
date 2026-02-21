# ##############################################################################
# fs/mnemofs_new/CMakeLists.txt
#
# ##############################################################################

if(CONFIG_FS_MNEMOFS_NEW)
  target_sources(
    fs
    PRIVATE mnemofs_new_format.c mnemofs_new_blkalloc.c mnemofs_new_mn.c mnemofs_new_rw.c mnemofs_new_util.c mnemofs_new_sb.c mnemofs_new_ctz.c mnemofs_new_lru.c mnemofs_new_file.c mnemofs_new_dir.c mnemofs_new.c)
endif()
