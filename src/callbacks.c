/*
 * This file contains the implementations for the FUSE callbacks
 * for the 'frost' filesystem.
 */

#include "include/callbacks.h"

// Define the global options struct
struct options options;

/*
 * FUSE Callback Implementations
 */

static void *frost_init(struct fuse_conn_info *conn,
                        struct fuse_config *cfg)
{
    (void) conn;
    cfg->kernel_cache = 1;

    /* Test setting flags the old way */
    fuse_set_feature_flag(conn, FUSE_CAP_ASYNC_READ);
    fuse_unset_feature_flag(conn, FUSE_CAP_ASYNC_READ);

    return NULL;
}

static int frost_getattr(const char *path, struct stat *stbuf,
                         struct fuse_file_info *fi)
{
    (void) fi;
    int res = 0;

    memset(stbuf, 0, sizeof(struct stat));
    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    }
    else {
        // write only file
        stbuf->st_mode = S_IFREG | 0666;
        stbuf->st_nlink = 1;
        stbuf->st_size = 0;
    }

    return res;
}

static int frost_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi,
                         enum fuse_readdir_flags flags)
{
    (void) offset;
    (void) fi;
    (void) flags;

    if (strcmp(path, "/") != 0)
        return -ENOENT;

    filler(buf, ".", NULL, 0, FUSE_FILL_DIR_DEFAULTS);
    filler(buf, "..", NULL, 0, FUSE_FILL_DIR_DEFAULTS);

    return 0;
}

static int frost_open(const char *path, struct fuse_file_info *fi)
{
    if ((fi->flags & O_ACCMODE) == O_RDONLY)
        return -ENOENT;

    return 0;
}

static int frost_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi)
{
    (void) path;
    (void) buf;
    (void) size;
    (void) offset;
    (void) fi;
    
    // No files are readable
    return -ENOENT;
}

static int frost_write(const char *path, const char *buf, size_t size,
                       off_t offset, struct fuse_file_info *fi)
{
    (void) offset;
    (void) fi;

    // if (strcmp(path+1, options.filename) == 0 || strcmp(path, "/extra_file.txt") == 0)
    //     return -EACCES;

    printf("[WRITE] To file %s: %.*s\n", path, (int)size, buf);
    fflush(stdout);

    return size;
}

static int frost_create(const char *path, mode_t mode,
                        struct fuse_file_info *fi)
{
    (void) mode;
    (void) fi;

    printf("[CREATE] File %s created with mode %o\n", path, mode);
    fflush(stdout);

    return 0;
}

static int frost_truncate(const char *path, off_t size, struct fuse_file_info *fi)
{
    (void) size;
    (void) fi;

    printf("[TRUNCATE] File %s truncated\n", path);
    fflush(stdout);
    return 0;

}

/*
 * Define the FUSE operations struct.
 * This struct maps our callback functions to the
 * operations FUSE understands.
 */
const struct fuse_operations frost_oper = {
    .init         = frost_init,
    .getattr      = frost_getattr,
    .readdir      = frost_readdir,
    .open         = frost_open,
    .read         = frost_read,
    .write        = frost_write,
    .create       = frost_create,
    .truncate     = frost_truncate,
};
