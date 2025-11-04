#include "allocator.h"

#define REF_IS_NON_EXISTANT 255
#define REF_IS_FULL 254

// private: do static here:
static int increment_reference(int8_t value, uint32_t reference_number);

static int fetch_data_block(uint8_t* buffer, uint32_t reference_block_number);
static int write_data_block(uint8_t* buffer, uint32_t reference_block_number);

int increment_reference(int8_t value, uint32_t reference_number)
{
    if(reference_number >= REF_BLOCKS * BYTES_PER_BLOCK)
    {
        return -ALLOCATOR_OUT_OF_BOUNDS;
    }
    uint8_t buffer[BYTES_PER_BLOCK];
    uint32_t index = reference_number / BYTES_PER_BLOCK;
    int ret = read_block_raw(&buffer, REFERENCE_BASE_BLOCK + index);
    if(ret < 0)
    {
        return ret;
    }
    buffer[reference_number % BYTES_PER_BLOCK] += value;
    int ret = write_block_raw(&buffer, REFERENCE_BASE_BLOCK + index);
    if(ret < 0)
    {
        return ret;
    }
    return 0;
}

int fetch_data_block(uint8_t* buffer, uint32_t reference_block_number)
{
    if(reference_block_number >= DATA_BLOCKS * BYTES_PER_BLOCK)
    {
        return -ALLOCATOR_OUT_OF_BOUNDS;
    }
    int ret = read_block_raw(&buffer, DATA_BASE_BLOCK + reference_block_number);
    if(ret < 0)
    {
        return ret;
    }
    return 0;
}

int write_data_block(uint8_t* buffer, uint32_t reference_block_number)
{
    if(reference_block_number >= DATA_BLOCKS * BYTES_PER_BLOCK)
    {
        return -ALLOCATOR_OUT_OF_BOUNDS;
    }
    int ret = write_block_raw(&buffer, DATA_BASE_BLOCK + reference_block_number);
    if(ret < 0)
    {
        return ret;
    }
    return 0;
}

// passthrough INODE blocks.
int read_inode_block(uint8_t* buffer, uint32_t reference_block_number)
{
    if(reference_block_number >= INODE_BLOCKS * BYTES_PER_BLOCK)
    {
        return -ALLOCATOR_OUT_OF_BOUNDS;
    }
    int ret = read_block_raw(&buffer, INODE_BASE_BLOCK + reference_block_number);
    if(ret < 0)
    {
        return ret;
    }
    return 0;
}

int write_inode_block(uint8_t* buffer, uint32_t reference_block_number)
{
    if(reference_block_number >= INODE_BLOCKS * BYTES_PER_BLOCK)
    {
        return -ALLOCATOR_OUT_OF_BOUNDS;
    }
    int ret = write_block_raw(&buffer, INODE_BASE_BLOCK + reference_block_number);
    if(ret < 0)
    {
        return ret;
    }
    return 0;
}


// ///////////////////////////////////////
// Public methods.

int get_super_block(uint8_t* buffer)
{
    return read_block_raw(buffer, SUPER_BLOCK);
}

// Read given data block.
int read_data_block(uint8_t* buffer, uint32_t block_number)
{
    // check if in use!
    uint32_t index = block_number / BYTES_PER_BLOCK;
    read_block_raw(buffer, REFERENCE_BASE_BLOCK + index);
    uint8_t value = buffer[block_number % BYTES_PER_BLOCK];
    if(value > 0 && value != REF_IS_NON_EXISTANT)
    {
        // good. overwrite buffer
        return fetch_data_block(buffer, block_number);
    }
    return -ALLOCATOR_READ_ON_FREE;
}

// Mark data block as free. 
int free_data_block(uint32_t block_number)
{
    // check if in use!
    uint8_t buffer[BYTES_PER_BLOCK];
    uint32_t index = block_number / BYTES_PER_BLOCK;
    read_block_raw(buffer, REFERENCE_BASE_BLOCK + index);
    uint8_t value = buffer[block_number % BYTES_PER_BLOCK];
    if(value > 0 && value != REF_IS_NON_EXISTANT)
    {
        // good. overwrite buffer
        buffer[block_number % BYTES_PER_BLOCK] -= 1;
        return write_block_raw(&buffer, REFERENCE_BASE_BLOCK + index);
    }
    return -ALLOCATOR_READ_ON_FREE;
}


static int search_for_next_free_block(uint32_t* block_number)
{
    // slow simple way....
    // scan entire reference list to find the first 0.
    // later.... I can cache this.
    uint8_t buffer[BYTES_PER_BLOCK];
    for(uint32_t block_index = 0; block_index < REF_BLOCKS; block_index++)
    {
        int ret = read_block_raw(buffer, REFERENCE_BASE_BLOCK + block_index);
        if(ret < 0)
        {
            return ret;
        }
        for(uint32_t byte_index = 0; byte_index < BYTES_PER_BLOCK; byte_index++)
        {
            uint8_t ref_count = buffer[byte_index];
            if(ref_count == 0) // 254 is full. 255 is invalid
            {
                // is free! 
                *(block_number) = byte_index + block_index * BYTES_PER_BLOCK;
                return 0;
            }
        }
    }
    return -ALLOCATOR_OUT_OF_SPACE;
}


// Copy on write.... write to next free block
// ASSUMES NO INTERRUPTIONS.... ATOMIC!
int write_to_next_free_block(uint8_t* buffer, uint32_t* block_number)
{
    // requires atomic operations!

    int ret = search_for_next_free_block(block_number);
    if(ret < 0)
    {
        return ret;
    }

    // write data and then increment ref.
    ret = write_data_block(buffer, block_number);
    if(ret < 0)
    {
        return ret;
    }

    ret = increment_reference(1, block_number); // increment by 1
    return 0;
}
