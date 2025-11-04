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

#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/file.h>

#include "error.h"

#define DISK_SIZE_IN_BLOCKS 13107200
#define BYTES_PER_BLOCK 4096



int open_disk(char* disk_name);
int close_disk();

int read_block_raw(uint8_t* buffer, uint32_t block_number);
int write_block_raw(uint8_t* buffer, uint32_t block_number);



#endif