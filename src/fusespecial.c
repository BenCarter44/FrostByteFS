#include "fusespecial.h"
/**
 * @file fusedirectory.c
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2025-11-14
 * 
 * @copyright Copyright (c) 2025
 * 
 */

 /* Directory Operations */
int frostbyte_mkdir(const char *path, mode_t mode)
{
    printf("frostbyte_mkdir(path=\"%s\", mode=%o)\n", path, mode);
    return 0;
} 
int frostbyte_rmdir(const char *path)
{
    printf("frostbyte_rmdir(path=\"%s\")\n", path);
    return 0;
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
    printf("frostbyte_readdir(path=\"%s\", offset=%ld, flags=%d)\n",
           path, (long)offset, flags);
    print_fuse_info(fi);
    return 0;
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

