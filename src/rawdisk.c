#include "rawdisk.h"

// private variables.
static char* disk_name = NULL;
static int disk_fd = 0;


int create_buffer(void** buffer)
{
    int r = posix_memalign(buffer, BYTES_PER_BLOCK, BYTES_PER_BLOCK);
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


int open_disk(char* path)
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
    disk_name = (char*)malloc(sizeof(char) * strlen(path));
    disk_fd = fd;
    memcpy(disk_name, path, strlen(path)); // copy to local var
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

int read_block_raw(uint8_t* buffer, uint32_t block_number)
{
    if(disk_name == NULL)
    {
        return -RAW_DISK_ERROR_UNOPENED;
    }

    if(block_number > DISK_SIZE_IN_BLOCKS - 1)
    {
        return -RAW_DISK_ERROR_OUT_OF_BOUNDS;
    }
    int ret = pread(disk_fd, buffer, BYTES_PER_BLOCK, block_number * BYTES_PER_BLOCK);
    if(ret < 0)
    {
        return -RAW_DISK_ERROR_SYSTEM;
    }
    return 0;
}

int write_block_raw(const uint8_t* buffer, uint32_t block_number)
{
    if(disk_name == NULL)
    {
        return -RAW_DISK_ERROR_UNOPENED;
    }

    if(block_number > DISK_SIZE_IN_BLOCKS - 1)
    {
        return -RAW_DISK_ERROR_OUT_OF_BOUNDS;
    }
    int ret = pwrite(disk_fd, buffer, BYTES_PER_BLOCK, block_number * BYTES_PER_BLOCK);
    if(ret < 0)
    {
        return -RAW_DISK_ERROR_SYSTEM;
    }
    return 0;
}
