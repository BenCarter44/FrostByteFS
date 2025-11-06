/*
 * Layer 3: FUSE Callbacks
 * This file translates FUSE operations into calls to Layer 2 (iNode).
 * It manages the disk lifecycle (open/close).
 */

#include "callbacks.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Include the new Layer 1 headers
#include "rawdisk.h"
#include "allocator.h"
#include "inode.h"

// Define the global options struct
struct options options;

/*
 * FUSE Callback Implementations
 */

/**
 * @brief Called on filesystem mount.
 * Opens the disk and initializes the filesystem if it's new.
 */
void *frost_init(struct fuse_conn_info *conn,
                        struct fuse_config *cfg)
{
    (void) conn;
    cfg->kernel_cache = 1;

    // Get the disk path string from fuse_main's private_data
    char *disk_path = (char*) fuse_get_context()->private_data;

    printf("L3 (FUSE): frost_init() called.\n");
    printf("L3 (FUSE): Opening disk: %s\n", disk_path);

    // --- 1. Open the disk (L1) ---
    if (open_disk(disk_path) != 0) {
        fprintf(stderr, "FATAL: Failed to open disk image: %s\n", disk_path);
        exit(1); // Cannot continue if disk won't open
    }

    // --- 2. Check if disk is formatted (L1) ---
    if (!allocator_check_valid_super_block()) {
        printf("L3 (FUSE): Unformatted disk. Formatting...\n");

        // Format Layer 1 (Allocator)
        format_super_block();
        clear_ref_blocks();
        clear_inode_blocks(); // This just clears the iNode *region*

        printf("L3 (FUSE): Formatting Layer 2 (iNode system)...\n");
        
        // Initialize Layer 2 (iNode system)
        inode_init_root_if_needed();

        printf("L3 (FUSE): Format complete.\n");
    } else {
        printf("L3 (FUSE): Disk mounted successfully.\n");
    }

    return NULL; // No private data needed for other callbacks
}

/**
 * @brief Called on filesystem unmount.
 * Closes the disk.
 */
void frost_destroy(void *private_data)
{
    (void) private_data;
    printf("L3 (FUSE): frost_destroy() called. Closing disk.\n");
    
    // --- Close the disk (L1) ---
    close_disk();
}

/**
 * @brief Get attributes (metadata) for a file or directory.
 */
int frost_getattr(const char *path, struct stat *stbuf,
                         struct fuse_file_info *fi)
{
    (void) fi;
    printf("L3 (FUSE): frost_getattr('%s') called.\n", path);

    // --- 1. Find the iNode for the path (L2) ---
    int inum = inode_find_by_path(path);
    if (inum < 0) {
        return inum; // Return error (e.g., -ENOENT)
    }

    // --- 2. Get the iNode struct from disk (L2) ---
    struct inode node;
    inode_read_from_disk(inum, &node);

    // --- 3. Copy stats from iNode to stbuf ---
    memset(stbuf, 0, sizeof(struct stat));
    stbuf->st_mode = node.mode;
    stbuf->st_nlink = node.nlink;
    stbuf->st_uid = node.uid;
    stbuf->st_gid = node.gid;
    stbuf->st_size = node.size;
    stbuf->st_ino = inum;
    stbuf->st_atime = node.atime;
    stbuf->st_mtime = node.mtime;
    stbuf->st_ctime = node.ctime;

    return 0; // Success
}

/**
 * @brief Read the contents of a directory.
 */
int frost_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
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

/**
 * @brief Open a file.
 */
int frost_open(const char *path, struct fuse_file_info *fi)
{
    printf("L3 (FUSE): frost_open('%s') called.\n", path);
    
    // Just check if the file exists.
    // Permissions are checked by the kernel based on getattr()
    int inum = inode_find_by_path(path);
    if (inum < 0) {
        return inum;
    }

    // We can store the inum in fi->fh (file handle)
    // for faster read/write, but it's not required.
    // fi->fh = inum;

    return 0; // Success
}

/**
 * @brief Read data from an open file.
 */
int frost_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi)
{
    // (void) fi; // If we used fi->fh, we'd use it here
    printf("L3 (FUSE): frost_read('%s', size %ld, offset %ld) called.\n", path, size, offset);

    // --- 1. Find the iNode (L2) ---
    int inum = inode_find_by_path(path);
    if (inum < 0) {
        return inum;
    }

    // --- 2. Call the iNode layer's read function (L2) ---
    return inode_read(inum, buf, size, offset);
}

/**
 * @brief Write data to an open file.
 */
int frost_write(const char *path, const char *buf, size_t size,
                       off_t offset, struct fuse_file_info *fi)
{
    // (void) fi;
    printf("L3 (FUSE): frost_write('%s', size %ld, offset %ld) called.\n", path, size, offset);

    // --- 1. Find the iNode (L2) ---
    int inum = inode_find_by_path(path);
    if (inum < 0) {
        return inum;
    }

    // --- 2. Call the iNode layer's write function (L2) ---
    return inode_write(inum, buf, size, offset);
}

/**
 * @brief Create a new file.
 */
int frost_create(const char *path, mode_t mode,
                        struct fuse_file_info *fi)
{
    (void) fi;
    printf("L3 (FUSE): frost_create('%s', mode %o) called.\n", path, mode);

    // Get context for UID/GID
    struct fuse_context *ctx = fuse_get_context();
    
    // --- 1. Call the iNode layer's create function (L2) ---
    return inode_create(path, mode | S_IFREG, ctx->uid, ctx->gid);
}

/**
 * @brief Truncate (change the size of) a file.
 */
int frost_truncate(const char *path, off_t size,
                          struct fuse_file_info *fi)
{
    (void) fi;
    printf("L3 (FUSE): frost_truncate('%s', size %ld) called.\n", path, size);

    // --- 1. Find the iNode (L2) ---
    int inum = inode_find_by_path(path);
    if (inum < 0) {
        return inum;
    }
    
    // --- 2. Call the iNode layer's truncate function (L2) ---
    return inode_truncate(inum, size);
}

/**
 * @brief Create a new directory.
 */
int frost_mkdir(const char *path, mode_t mode)
{
    printf("L3 (FUSE): frost_mkdir('%s', mode %o) called.\n", path, mode);
    
    struct fuse_context *ctx = fuse_get_context();
    
    // --- Call the iNode layer's create function (L2) ---
    return inode_create(path, mode | S_IFDIR, ctx->uid, ctx->gid);
}

/**
 * @brief Delete a file.
 */
int frost_unlink(const char *path)
{
    printf("L3 (FUSE): frost_unlink('%s') called.\n", path);
    
    // --- Call the iNode layer's unlink function (L2) ---
    return inode_unlink(path);
}

/**
 * @brief Delete an empty directory.
 */
int frost_rmdir(const char *path)
{
    printf("L3 (FUSE): frost_rmdir('%s') called.\n", path);
    
    // --- Call the iNode layer's rmdir function (L2) ---
    return inode_rmdir(path);
}

/**
 * @brief Rename a file or directory.
 */
int frost_rename(const char *from, const char *to, unsigned int flags)
{
    (void) flags; // We don't support RENAME_EXCHANGE etc. yet
    printf("L3 (FUSE): frost_rename('%s' -> '%s') called.\n", from, to);
    
    // --- Call the iNode layer's rename function (L2) ---
    return inode_rename(from, to);
}


/*
 * Define the FUSE operations struct.
 */
const struct fuse_operations frost_oper = {
    .init         = frost_init,
    .destroy      = frost_destroy,
    .getattr      = frost_getattr,
    .readdir      = frost_readdir,
    .open         = frost_open,
    .read         = frost_read,
    .write        = frost_write,
    .create       = frost_create,
    .truncate     = frost_truncate,
    .mkdir        = frost_mkdir,
    .unlink       = frost_unlink,
    .rmdir        = rmdir,
    .rename       = frost_rename,
};