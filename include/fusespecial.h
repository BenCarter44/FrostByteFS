/**
 * @file fusespecial.h
 * @author Benjamin Carter, Towhidul Islam, Sohaib
 * @brief Handles directory and link callbacks
 * @version 0.1
 * @date 2025-12-02
 * 
 * @copyright Copyright (c) 2025 Benjamin Carter, Towhidul Islam, Sohaib
 * 
 */
#define FUSE_SPECIAL_H

#include "fusefile.h"

/* Directories */

int frostbyte_mkdir(const char *path, mode_t mode);
int frostbyte_rmdir(const char *path);
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