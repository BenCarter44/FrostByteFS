/**
 * @file allocator.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2025-11-04
 * 
 * @copyright Copyright (c) 2025
 * 
 */

#ifndef ALLOCATOR_H
#define ALLOCATOR_H

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>

#include "rawdisk.h"

/////////////////////////////////////////////////
// Disk Format
/////////////////////////////////////////////////

// 0 block - super block
// 1 - n   - ref blocks (byte per data block)
// INODES  - 31250 I
// data blocks.


// Calc number of blocks:
#define INODE_BLOCKS (uint64_t)31250 // supports 1 million 128 byte INODES
#define REF_BLOCKS  (uint64_t)(1 + (DISK_SIZE_IN_BLOCKS - 1 - INODE_BLOCKS) / BYTES_PER_BLOCK)
#define DATA_BLOCKS (uint64_t)(DISK_SIZE_IN_BLOCKS - 1 - INODE_BLOCKS - REF_BLOCKS)


// Layout
#define SUPER_BLOCK 0
#define REFERENCE_BASE_BLOCK 1
#define INODE_BASE_BLOCK (REFERENCE_BASE_BLOCK + REF_BLOCKS)
#define DATA_BASE_BLOCK (INODE_BASE_BLOCK + INODE_BLOCKS)



// functions to access individual layers.
int get_super_block(uint8_t* buffer);

void init_allocator();


// public: for data blocks: COPY ON WRITE
int write_to_next_free_block(const uint8_t* buffer, uint64_t* block_number);
int read_data_block(uint8_t* buffer, uint64_t block_number);
int free_data_block(uint64_t block_number);


// passthrough with bounds checking
int read_inode_block(uint8_t* buffer, uint64_t inode_block_number);
int write_inode_block(const uint8_t* buffer, uint64_t inode_block_number);

// for formatting
int format_super_block();
int clear_ref_blocks();
int clear_inode_blocks();

// check valid super block
bool allocator_check_valid_super_block();



#endif