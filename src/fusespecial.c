#include "fusespecial.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <limits.h>
#include <assert.h>

/**
 * @file fusespecial.c
 * @author Benjamin Carter, Towhildul Islam, Sohaib
 * @brief These are all the FUSE operators for directory / symlink operations.
 * @version 0.1
 * @date 2025-11-14
 * 
 * @copyright Copyright (c) 2025
 * 
 */

 /* Directory Operations */
int frostbyte_mkdir(const char *path, mode_t mode)
{
    printf("L3 (FUSE): frost_mkdir('%s', mode %o) called.\n", path, mode);
    
    // struct fuse_context *ctx = fuse_get_context();
    
    // --- Call the iNode layer's create function (L2) ---
    uint32_t inode = 0;
    int r = inode_create(path, mode | S_IFDIR, &inode);
    return r;
} 
int frostbyte_rmdir(const char *path)
{
    printf("L3 (FUSE): frost_rmdir('%s') called.\n", path);
    
    // --- Call the iNode layer's rmdir function (L2) ---
    return inode_rmdir(path);
}

int frostbyte_opendir(const char *path, struct fuse_file_info *fi)
{
    printf("frostbyte_opendir(path=\"%s\")\n", path);
    print_fuse_info(fi);
    return 0;
}

int frostbyte_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                      off_t offset, struct fuse_file_info *fi,
                      enum fuse_readdir_flags flags)
{
    (void) offset;
    (void) fi;
    (void) flags;
    printf("L3 (FUSE): frost_readdir('%s') called.\n", path);

    // --- 1. Find the iNode for the directory path (L2) ---
    int inum = inode_find_by_path(path);
    if (inum < 0) {
        return inum;
    }

    // --- 2. Call the iNode layer's readdir function (L2) ---
    return inode_readdir(inum, buf, filler);
}

int frostbyte_releasedir(const char *path, struct fuse_file_info *fi)
{
    printf("frostbyte_releasedir(path=\"%s\")\n", path);
    print_fuse_info(fi);
    return 0;
}

int frostbyte_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi)
{
    printf("frostbyte_fsyncdir(path=\"%s\", datasync=%d)\n", path, datasync);
    print_fuse_info(fi);
    return 0;
}

int frostbyte_add_readdir_entry(void *buf, const char *name,
                const struct stat *stbuf, off_t off,
                enum fuse_fill_dir_flags flags)
{
    printf("frostbyte_add_readdir_entry(name=\"%s\", off=%ld, flags=%d)\n",
           name, (long)off, flags);
    if (stbuf != NULL) {
        printf("  with stat: mode=%o, size=%ld\n", stbuf->st_mode, (long)stbuf->st_size);
    } else {
        printf("  with stat: NULL\n");
    }
    return 0;
}

/* Link Operations */

int frostbyte_readlink(const char *path, char *buf, size_t size)
{
    printf("frostbyte_readlink(path=\"%s\", buf=%p, size=%zu)\n",
           path, (void*)buf, size);
    return 0;
}   

int frostbyte_symlink(const char *target, const char *linkpath)
{
    printf("frostbyte_symlink(target=\"%s\", linkpath=\"%s\")\n",
           target, linkpath);
    return 0;
}   

int frostbyte_hardlink(const char *oldpath, const char *newpath)
{
    printf("frostbyte_hardlink(oldpath=\"%s\", newpath=\"%s\")\n",
           oldpath, newpath);
    return 0;
}

