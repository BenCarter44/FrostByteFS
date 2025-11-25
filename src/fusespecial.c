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
    uint64_t inode = 0;
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
    int r = fsync_disk();
    if(r < 0)
    {
        return -EIO;
    }
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

int frostbyte_symlink(const char *target, const char *linkpath)
{
    printf("L3: frostbyte_symlink target='%s' linkpath='%s'\n", target, linkpath);
    
    uint64_t inum = 0;
    // 1. Create inode with S_IFLNK
    int res = inode_create(linkpath, S_IFLNK | 0777, &inum);
    if (res != 0) return res;

    // 2. Write the target path into the inode's data
    // (Symlinks store the path string as their "file content")
    size_t len = strlen(target);
    ssize_t written = inode_write(inum, target, len, 0);
    
    if (written < 0) return (int)written;
    return 0;
}

int frostbyte_readlink(const char *path, char *buf, size_t size)
{
    printf("L3: frostbyte_readlink path='%s'\n", path);
    
    uint64_t inum = inode_find_by_path(path);
    if ((int)inum < 0) return (int)inum;

    // 1. Read the data (the target path)
    ssize_t bytes = inode_read(inum, buf, size - 1, 0);
    if (bytes < 0) return (int)bytes;

    // 2. Null terminate
    buf[bytes] = '\0';
    return 0;
}

int frostbyte_hardlink(const char *oldpath, const char *newpath)
{
    printf("L3: frostbyte_hardlink old='%s' new='%s'\n", oldpath, newpath);
    
    // 1. Find inode of old file
    int inum = inode_find_by_path(oldpath);
    if (inum < 0) return inum;

    // 2. Call inode layer helper
    return inode_link((uint64_t)inum, newpath);
}

