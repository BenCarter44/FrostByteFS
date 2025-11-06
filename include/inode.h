#ifndef FROST_INODE_H_
#define FROST_INODE_H_

#define FUSE_USE_VERSION 31

#include <time.h>
#include <sys/stat.h>
#include <fuse.h>
#include <stdint.h>
#include "allocator.h" // Include our new Layer 1 API

// --- iNode Definitions ---

#define INODE_SIZE 128 // As specified in allocator.h comments
#define INODES_PER_BLOCK (BYTES_PER_BLOCK / INODE_SIZE) // 4096 / 128 = 32

// We need an inode bitmap. Let's place it in the first blocks
// of the iNode region.
// 1 block = 4096 bytes * 8 bits/byte = 32,768 inodes
// 1,000,000 inodes / 32,768 = ~31 blocks
#define INODE_BITMAP_BLOCKS 31 

// Block number *within the iNode region* where inodes start
#define INODE_TABLE_START_BLOCK INODE_BITMAP_BLOCKS

// --- iNode Structure (128 bytes) ---

#define NUM_DIRECT_BLOCKS 12
#define POINTERS_PER_BLOCK (BYTES_PER_BLOCK / sizeof(uint32_t)) // 1024

struct inode {
    mode_t mode;        // 4 bytes
    uid_t uid;          // 4 bytes
    gid_t gid;          // 4 bytes
    nlink_t nlink;      // 4 bytes
    off_t size;         // 8 bytes
    time_t atime;       // 8 bytes
    time_t mtime;       // 8 bytes
    time_t ctime;       // 8 bytes
    
    // Pointers: 12 (direct) + 1 (single) + 1 (double) + 1 (triple) = 15
    // 15 * 4 bytes = 60 bytes
    uint32_t direct_blocks[NUM_DIRECT_BLOCKS]; // 48 bytes
    uint32_t single_indirect; // 4 bytes
    uint32_t double_indirect; // 4 bytes
    uint32_t triple_indirect; // 4 bytes

    // Total: 108 bytes. 20 bytes padding.
    char padding[20];
};

// --- iNode Layer API ---

/**
 * @brief Initializes the iNode system if disk is unformatted.
 * Creates the inode bitmap and the root directory (inode 0).
 */
void inode_init_root_if_needed();

// The rest of the API remains the same,
// but their implementation in inode.c will be completely different.

int inode_find_by_path(const char *path);
int inode_create(const char *path, mode_t mode, uid_t uid, gid_t gid);
int inode_read(int inum, char *buf, size_t size, off_t offset);
int inode_write(int inum, const char *buf, size_t size, off_t offset);
int inode_readdir(int inum, void *buf, fuse_fill_dir_t filler);
int inode_unlink(const char *path);
int inode_rmdir(const char *path);
int inode_truncate(int inum, off_t size);
int inode_rename(const char *from, const char *to);

// New helpers to read/write the inode structs themselves
void inode_read_from_disk(int inum, struct inode *node);
void inode_write_to_disk(int inum, struct inode *node);

#endif // FROST_INODE_H_