#ifndef FUSE_SPECIAL_H
#define FUSE_SPECIAL_H

#include "fusefile.h"

/* Directories */

int frostbyte_mkdir(const char *path, mode_t mode);
int frostbyte_rmdir(const char *path, mode_t mode);
int frostbyte_opendir(const char *path, struct fuse_file_info *fi);
int frostbyte_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                      off_t offset, struct fuse_file_info *fi,
                      enum fuse_readdir_flags flags);
int frostbyte_releasedir(const char *path, struct fuse_file_info *fi);
int frostbyte_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi);

// for *fuse_fill_dir_t
int frostbyte_add_readdir_entry(void *buf, const char *name,
				const struct stat *stbuf, off_t off,
				enum fuse_fill_dir_flags flags);

/* Links */
int frostbyte_readlink(const char *path, char *buf, size_t size);
int frostbyte_symlink(const char *target, const char *linkpath);

int frostbyte_hardlink(const char *oldpath, const char *newpath);


#endif