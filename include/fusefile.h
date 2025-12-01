/**
 * @file fusefile.h
 * @author Benjamin Carter, Towhidul Islam, Sohaib
 * @brief This file handles all the file-related callbacks.
 * @version 0.1
 * @date 2025-11-18
 * 
 * @copyright Copyright (c) 2025
 * 
 */
#ifndef FUSE_FILE_H
#define FUSE_FILE_H

#include "inode.h"
#include "error.h"

/* Callbacks necessary for files */

// Creating / Deleting / Open / Close

int frostbyte_open(const char* path, struct fuse_file_info* finfo);
int frostbyte_unlink(const char* path);
int frostbyte_rename(const char* path_old, const char* path_new, unsigned int flags);
int frostbyte_flush(const char* path, struct fuse_file_info* finfo);
int frostbyte_release(const char* path, struct fuse_file_info* finfo);
int frostbyte_create(const char* path, mode_t fmode, struct fuse_file_info* finfo);
// int frostbyte_mknod(const char* path, mode_t fmode, dev_t fdev);
int frostbyte_fsync(const char* path, int fint, struct fuse_file_info* finfo);


// Attributes
int frostbyte_getattr(const char* path, struct stat* fstat, struct fuse_file_info* finfo);
int frostbyte_chmod(const char* path, mode_t fmode, struct fuse_file_info* finfo);
int frostbyte_chown(const char* path, uid_t user, gid_t group, struct fuse_file_info* finfo);
int frostbyte_setxattr(const char* path, const char* key, const char* val, size_t len, int fint);
int frostbyte_getxattr(const char* path, const char* key, char* val, size_t len);
int frostbyte_listxattr(const char* path, char* val, size_t len);
int frostbyte_removexattr(const char* path, const char* key);
// int frostbyte_check_access(const char* path, int perm);
// int* frostbyte_statx(const char* path, int flags, int mask, struct statx* stxbuf, struct fuse_file_info* finfo);

// Data
int frostbyte_truncate(const char* path, off_t offset, struct fuse_file_info* finfo);
int frostbyte_read(const char* path, char* buffer, size_t len, off_t offset, struct fuse_file_info* finfo);
int frostbyte_write(const char* path, const char* buffer, size_t len, off_t offset, struct fuse_file_info* finfo);
// int frostbyte_map_raw(const char* path, size_t blocksize, uint64_t *idx);
// int frostbyte_write_buffer(const char* path, struct fuse_bufvec* buf, off_t offset, struct fuse_file_info* finfo);
// int frostbyte_read_buffer(const char* path, struct fuse_bufvec** buf, size_t size, off_t offset, struct fuse_file_info* finfo);

// int frostbyte_allocate(const char* path, int len, off_t offset, off_t offset2, struct fuse_file_info* finfo);
// ssize_t frostbyte_copy_file_range(const char *path_in,
//                 struct fuse_file_info *fi_in,
//                 off_t offset_in, const char *path_out,
//                 struct fuse_file_info *fi_out,
//                 off_t offset_out, size_t size, int flags);


int frostbyte_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi);
int frostbyte_link(const char* oldpath, const char* newpath);

void print_fuse_info(struct fuse_file_info* finfo);
#endif