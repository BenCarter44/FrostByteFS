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

#include "libraries.h"

#define DISK_SIZE_IN_BLOCKS 13107200
#define BYTES_PER_BLOCK 4096

#define RAW_DISK_ERROR_UNOPENED 1
#define RAW_DISK_ERROR_OUT_OF_BOUNDS 2
#define RAW_DISK_ERROR_SYSTEM 3


int open_disk(char* disk_name);
int close_disk();

int read_block_raw(char* buffer, unsigned int block_number);
int write_block_raw(char* buffer, unsigned int block_number);

const char* raw_disk_error_to_string(int err);


#endif