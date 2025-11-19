#ifndef INODE_H
#define INODE_H

#define FUSE_USE_VERSION 31
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>
#include <inttypes.h>
#include "error.h"


#define _FILE_OFFSET_BITS 64

#define MAX_FILENAME_LENGTH 255


int return_root_inode();
int get_inode_given_name(uint32_t inode, char* buffer);
int is_inode_a_directory(uint32_t inode);
int inode_create(uint32_t parentnode, const char* path);
int inode_open(uint32_t inode);
int inode_unlink(uint32_t inode);
int inode_create_file(uint32_t inode);
int inode_chown(uint32_t inode, uid_t user, gid_t group);
int inode_rename(uint32_t inode, const char* name);
int inode_fstat(uint32_t inode, struct stat* stdbuf);
int inode_chmod(uint32_t inode, mode_t fmode);
int inode_setxattr(uint32_t inode, const char* key, const char* val, size_t len, int fint);
int inode_getxattr(uint32_t inode, const char* key, const char* val, size_t len);
int inode_listxattr(uint32_t inode, char* val, size_t len);
int inode_removexattr(uint32_t inode, const char* key);

#endif