#include "rawdisk.h"
#include <fcntl.h>

// private variables.
static char* disk_name = NULL;
static int disk_fd = 0;

#ifdef USE_KERNEL_CACHE
static uint64_t changes = 0;
#endif

int create_buffer(void** buffer)
{
    int r = posix_memalign(buffer, BYTES_PER_BLOCK, BYTES_PER_BLOCK);
    memset(*(buffer), 0, BYTES_PER_BLOCK);
    if(r != 0)
    {
        return -RAW_BUFFER_ERROR;
    }
    return 0;
}

int free_buffer(void* buffer)
{
    if(buffer == NULL) { return -1;}
    free(buffer);
    return 0;
}


int open_disk(const char* path)
{
#ifndef USE_KERNEL_CACHE
    int fd = open(path, O_RDWR | O_DIRECT);
#else
    int fd = open(path, O_RDWR);
#endif
    if(fd < 0)
    {
        return -RAW_DISK_ERROR_SYSTEM; 
    }
    disk_fd = fd;
    disk_name = strdup(path);
    if (disk_name == NULL) {
        close(fd);
        return -RAW_DISK_ERROR_SYSTEM;
    }
    return 0;
}

int fsync_disk()
{
#ifdef USE_KERNEL_CACHE
    if(disk_name == NULL)
    {
        return -RAW_DISK_ERROR_UNOPENED;
    }
    if(fsync(disk_fd) < 0)
    {
        return -RAW_DISK_ERROR_SYSTEM;
    }
#endif
    return 0;
}

int close_disk()
{
    if(disk_name == NULL)
    {
        return -RAW_DISK_ERROR_UNOPENED;
    }

    free(disk_name);
    disk_name = NULL;
    close(disk_fd);
    return 0;
}

int read_block_raw(uint8_t* buffer, uint64_t block_number)
{
    if(disk_name == NULL)
    {
        return -RAW_DISK_ERROR_UNOPENED;
    }

    if(block_number > DISK_SIZE_IN_BLOCKS - 1)
    {
        return -RAW_DISK_ERROR_OUT_OF_BOUNDS;
    }
    off_t offset = (off_t)block_number * (off_t)BYTES_PER_BLOCK;
    ssize_t ret = pread(disk_fd, buffer, BYTES_PER_BLOCK, offset);
    if (ret < 0)
    {
        return -RAW_DISK_ERROR_SYSTEM;
    }
    return 0;
}

int write_block_raw(const uint8_t* buffer, uint64_t block_number)
{
    if(disk_name == NULL)
    {
        return -RAW_DISK_ERROR_UNOPENED;
    }

    if(block_number > DISK_SIZE_IN_BLOCKS - 1)
    {
        return -RAW_DISK_ERROR_OUT_OF_BOUNDS;
    }
    off_t offset = (off_t)block_number * (off_t)BYTES_PER_BLOCK;
    ssize_t ret = pwrite(disk_fd, buffer, BYTES_PER_BLOCK, offset);
    if (ret < 0)
    {
        return -RAW_DISK_ERROR_SYSTEM;
    }

#ifdef USE_KERNEL_CACHE
    changes += 1;
    if(changes > FSYNC_CYCLES)
    {
        changes = 0;
        fsync_disk();
    }
#endif


    return 0;
}
