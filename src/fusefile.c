#include "fusefile.h"
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


 /* Private Functions */
void print_fuse_info(struct fuse_file_info* finfo)
{
    if(finfo == NULL)
    {
        printf("Fuse Info NULL\n");
        return;
    }
    printf("Fuse INFO -------------\n");
    printf(" Flags: \t%d\n",finfo->flags);
    printf(" Write Page: \t%u\n",finfo->writepage);
    printf(" Direct IO: \t%u\n",finfo->direct_io);
    printf(" Keep Cache: \t%u\n",finfo->keep_cache);
    printf(" Flush: \t%u\n",finfo->flush);
    printf(" NonSeek: \t%u\n",finfo->nonseekable);
    printf(" FlockRelease: \t%u\n",finfo->flock_release);
    printf(" CacheReadDir: \t%u\n",finfo->cache_readdir);
    printf(" NoFlush: \t%u\n",finfo->noflush);
    printf(" PDirectWrite: \t%u\n",finfo->parallel_direct_writes);
    printf(" FH: \t%" PRIu64 "\n",finfo->fh);
    printf(" LockOwner: \t%" PRIu64 "\n",finfo->lock_owner);
    printf(" PollEvt: \t%u\n",finfo->poll_events);
    printf(" BackingID: \t%d\n",finfo->backing_id);
    printf(" ComptFlag: \t%" PRIu64 "\n",finfo->compat_flags);
    printf("------------------\n");
}


/* ----------------------------- File Ops ----------------------------- */

int frostbyte_open(const char* path, struct fuse_file_info* finfo) 
{
    printf("frostbyte_open(path=\"%s\")\n", path);
    print_fuse_info(finfo);
    return 0;
}

int frostbyte_unlink(const char* path) 
{
    printf("frostbyte_unlink(path=\"%s\")\n", path);
    return 0;
}

int frostbyte_rename(const char* path_old, const char* path_new, unsigned int flags) 
{
    printf("frostbyte_rename(old=\"%s\", new=\"%s\", flags=%u)\n",
           path_old, path_new, flags);
    return 0;
}

int frostbyte_flush(const char* path, struct fuse_file_info* finfo) 
{
    printf("frostbyte_flush(path=\"%s\")\n", path);
    print_fuse_info(finfo);
    return 0;
}

int frostbyte_release(const char* path, struct fuse_file_info* finfo) 
{
    printf("frostbyte_release(path=\"%s\")\n", path);
    print_fuse_info(finfo);
    return 0;
}

int frostbyte_create(const char* path, mode_t fmode, struct fuse_file_info* finfo) 
{
    printf("frostbyte_create(path=\"%s\", mode=%o)\n", path, fmode);
    print_fuse_info(finfo);
    return 0;
}

int frostbyte_mknod(const char* path, mode_t fmode, dev_t fdev) 
{
    printf("frostbyte_mknod(path=\"%s\", mode=%o, dev=%lu)\n",
           path, fmode, (unsigned long)fdev);
    return 0;
}

int frostbyte_fsync(const char* path, int fint, struct fuse_file_info* finfo) 
{
    printf("frostbyte_fsync(path=\"%s\", fint=%d)\n", path, fint);
    print_fuse_info(finfo);
    return 0;
}


/* ----------------------------- Attributes ----------------------------- */

int frostbyte_getattr(const char* path, struct stat* fstat, struct fuse_file_info* finfo) 
{
    printf("frostbyte_getattr(path=\"%s\", stat=%p)\n", path, (void*)fstat);
    print_fuse_info(finfo);
    return 0;
}

int frostbyte_chmod(const char* path, mode_t fmode, struct fuse_file_info* finfo) 
{
    printf("frostbyte_chmod(path=\"%s\", mode=%o)\n", path, fmode);
    print_fuse_info(finfo);
    return 0;
}

int frostbyte_chown(const char* path, uid_t user, gid_t group, struct fuse_file_info* finfo) 
{
    printf("frostbyte_chown(path=\"%s\", uid=%u, gid=%u)\n",
           path, (unsigned int)user, (unsigned int)group);
    print_fuse_info(finfo);
    return 0;
}

int frostbyte_setxattr(const char* path, const char* key, const char* val, size_t len, int fint) 
{
    printf("frostbyte_setxattr(path=\"%s\", key=\"%s\", val=\"%s\", len=%zu, fint=%d)\n",
           path, key, val, len, fint);
    return 0;
}

int frostbyte_getxattr(const char* path, const char* key, char* val, size_t len) 
{
    printf("frostbyte_getxattr(path=\"%s\", key=\"%s\", val=%p, len=%zu)\n",
           path, key, (void*)val, len);
    return 0;
}

int frostbyte_listxattr(const char* path, char* val, size_t len) 
{
    printf("frostbyte_listxattr(path=\"%s\", val=%p, len=%zu)\n",
           path, (void*)val, len);
    return 0;
}

int frostbyte_removexattr(const char* path, const char* key) 
{
    printf("frostbyte_removexattr(path=\"%s\", key=\"%s\")\n",
           path, key);
    return 0;
}

int frostbyte_check_access(const char* path, int perm) 
{
    printf("frostbyte_check_access(path=\"%s\", perm=%d)\n", path, perm);
    return 0;
}

// int frostbyte_statx(const char* path, int flags, int mask, struct statx* stxbuf, struct fuse_file_info* finfo) 
// {
//     printf("frostbyte_statx(path=\"%s\", flags=%d, mask=%d, stxbuf=%p)\n",
//            path, flags, mask, (void*)stxbuf);
//     print_fuse_info(finfo);
//     return 0;
// }


/* ----------------------------- Data I/O ----------------------------- */

int frostbyte_truncate(const char* path, off_t offset, struct fuse_file_info* finfo) 
{
    printf("frostbyte_trucate(path=\"%s\", offset=%ld)\n",
           path, (long)offset);
    print_fuse_info(finfo);
    return 0;
}

int frostbyte_read(const char* path, char* buffer, size_t len, off_t offset, struct fuse_file_info* finfo) 
{
    printf("frostbyte_read(path=\"%s\", buffer=%p, len=%zu, offset=%ld)\n",
           path, (void*)buffer, len, offset);
    print_fuse_info(finfo);
    return 0;
}

int frostbyte_write(const char* path, const char* buffer, size_t len,
                    off_t offset, struct fuse_file_info* finfo) {
    printf("frostbyte_write(path=\"%s\", buffer=%p, len=%zu, offset=%ld)\n",
           path, (void*)buffer, len, (long)offset);
    print_fuse_info(finfo);
    return 0;
}

int frostbyte_map_raw(const char* path, size_t blocksize, uint64_t *idx) 
{
    printf("frostbyte_map_raw(path=\"%s\", blocksize=%zu, idx=%p)\n",
           path, blocksize, (void*)idx);
    return 0;
}

int frostbyte_allocate(const char* path, int len, off_t offset,
                       off_t offset2, struct fuse_file_info* finfo) 
{
    printf("frostbyte_allocate(path=\"%s\", len=%d, offset=%ld, offset2=%ld)\n",
           path, len, (long)offset, (long)offset2);
    print_fuse_info(finfo);
    return 0;
}

ssize_t frostbyte_copy_file_range(const char *path_in,
                                  struct fuse_file_info *fi_in,
                                  off_t offset_in,
                                  const char *path_out,
                                  struct fuse_file_info *fi_out,
                                  off_t offset_out,
                                  size_t size,
                                  int flags) 
{
    printf("frostbyte_copy_file_range(path_in=\"%s\", offset_in=%ld, path_out=\"%s\", "
           "offset_out=%ld, size=%zu, flags=%d)\n",
           path_in, (long)offset_in,
           path_out, (long)offset_out,
           size, flags);

    print_fuse_info(fi_in);
    print_fuse_info(fi_out);

    return 0;
}
