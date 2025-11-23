/**
 * @file rawdisk.h
 * @author Benjamin Carter (benjamincarter@ucsb.edu)
 * @brief This covers all direct operations to the disk device.
 * @version 0.1
 * @date 2025-10-22
 * 
 * @copyright Copyright (c) 2025
 * 
 */

#ifndef RAW_DISK_H
#define RAW_DISK_H

#define _GNU_SOURCE
#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 12)
#include <fuse.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/file.h>
#include <string.h>

#include "error.h"

// Uncomment below to use the kernel caching on reads/writes.
#define USE_KERNEL_CACHE   
#define FSYNC_CYCLES 500000

#define DISK_SIZE_IN_BLOCKS 13107200
#define BYTES_PER_BLOCK 4096

int create_buffer(void** buffer);
int free_buffer(void* buffer);

int open_disk(const char* disk_name);
int close_disk();

int read_block_raw(uint8_t* buffer, uint64_t block_number);
int write_block_raw(const uint8_t* buffer, uint64_t block_number);

int fsync_disk();


#endif