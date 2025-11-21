#ifndef FROST_INODE_H_
#define FROST_INODE_H_

#include "allocator.h" // Include our Layer 1 API
#include "error.h"

#include <time.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>
#include <inttypes.h>



// --- iNode Definitions ---

#define INODE_SIZE 128
#define INODES_PER_BLOCK (BYTES_PER_BLOCK / INODE_SIZE)
#define MAX_INODES 1000000
#define INODE_BITMAP_BLOCKS (uint32_t)((MAX_INODES / (BYTES_PER_BLOCK * 8)) + 1)
#define INODE_TABLE_START_BLOCK INODE_BITMAP_BLOCKS

#define NUM_DIRECT_BLOCKS 12
#define POINTERS_PER_BLOCK (BYTES_PER_BLOCK / sizeof(uint32_t))

struct inode {
    mode_t mode;        // 4 bytes
    uid_t uid;          // 4 bytes
    gid_t gid;          // 4 bytes
    nlink_t nlink;      // 4 bytes
    off_t size;         // 8 bytes
    time_t atime;       // 8 bytes
    time_t mtime;       // 8 bytes
    time_t ctime;       // 8 bytes

    uint32_t direct_blocks[NUM_DIRECT_BLOCKS]; // 48 bytes
    uint32_t single_indirect;  // 4 bytes
    uint32_t double_indirect;  // 4 bytes
    uint32_t triple_indirect;  // 4 bytes

    char padding[20];          // total 128 bytes
};

#define _FILE_OFFSET_BITS 64

#define MAX_FILENAME_LEN 255


// --- iNode Layer API ---

/**
 * @brief Formats the iNode system if disk is unformatted.
 * Creates the inode bitmap and the root directory (inode 0).
 *
 * @param max_inodes Total number of inodes supported by filesystem.
 * @return 0 on success or negative errno on failure.
 */
int format_inodes();

/**
 * @brief Set up inode locks.
 * 
 * @return int 
 */
void inode_global_init();



/**
 * @brief Find inode number for absolute path (returns >=0 or negative errno)
 */
int inode_find_by_path(const char *path);

/**
 * @brief Create a new file or directory.
 * Automatically sets uid/gid to current user.
 * @param path Absolute path of new file/dir.
 * @param mode File mode (use S_IFREG or S_IFDIR | perms).
 * @param out_inum [out] Returns created inode number.
 */
int inode_create(const char *path, mode_t mode, uint32_t *out_inum);
// 
ssize_t inode_read(uint32_t inum, void *buf, size_t size, off_t offset);
ssize_t inode_write(uint32_t inum, const void *buf, size_t size, off_t offset);
int inode_readdir(uint32_t inum, void *buf, fuse_fill_dir_t filler);

int inode_unlink(const char *path);
int inode_truncate(uint32_t inum, off_t size);

// New helpers to read/write the inode structs themselves
int inode_read_from_disk(uint32_t inum, struct inode *out);
int inode_write_to_disk(uint32_t inum, const struct inode *node);


// New helpers to be implemented ..... 
int return_root_inode(); // done, just returns 0

// int inode_rename(uint32_t inode, const char *to);
int inode_rename(const char *from, const char *to);
int inode_chown(uint32_t inode, uid_t user, gid_t group);
int inode_chmod(uint32_t inode, mode_t fmode);

int inode_rmdir(const char *path);
int inode_setxattr(uint32_t inode, const char* key, const char* val, size_t len, int fint);
int inode_getxattr(uint32_t inode, const char* key, const char* val, size_t len);
int inode_listxattr(uint32_t inode, char* val, size_t len);
int inode_removexattr(uint32_t inode, const char* key);

int inode_link(uint32_t inum, const char *newpath);

#endif