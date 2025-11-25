#include "allocator.h"
#include <stdio.h>
#include <inttypes.h>
#include <openssl/sha.h>

#define REF_IS_NON_EXISTANT 255
#define REF_IS_FULL 254

pthread_mutex_t* allocator_lock;

void init_allocator()
{
    allocator_lock = calloc(1, sizeof(pthread_mutex_t));
    pthread_mutex_init(allocator_lock, NULL);
}

static uint64_t speed_free = 0;

void gdb_break_alloc()
{
    return;
}

// private: do static here:
static int increment_reference(int8_t value, uint64_t reference_number);

static int fetch_data_block(uint8_t* buffer, uint64_t reference_block_number);
static int write_data_block(const uint8_t* buffer, uint64_t reference_block_number);

int increment_reference(int8_t value, uint64_t reference_number)
{
    if(reference_number >= REF_BLOCKS * BYTES_PER_BLOCK)
    {
        return -ALLOCATOR_OUT_OF_BOUNDS;
    }

    uint8_t* buffer;
    create_buffer((void**)&buffer);

    uint64_t index = reference_number / BYTES_PER_BLOCK;
    int ret = read_block_raw(buffer, REFERENCE_BASE_BLOCK + index);
    if(ret < 0)
    {   
        free_buffer(buffer);
        return ret;
    }
    buffer[reference_number % BYTES_PER_BLOCK] += value;
    ret = write_block_raw(buffer, REFERENCE_BASE_BLOCK + index);
    free_buffer(buffer);
    if(ret < 0)
    {
        return ret;
    }
    return 0;
}

int fetch_data_block(uint8_t* buffer, uint64_t reference_block_number)
{
    if(reference_block_number >= DATA_BLOCKS * BYTES_PER_BLOCK)
    {
        return -ALLOCATOR_OUT_OF_BOUNDS;
    }
    int ret = read_block_raw(buffer, DATA_BASE_BLOCK + reference_block_number);
    if(ret < 0)
    {
        return ret;
    }
    return 0;
}

int write_data_block(const uint8_t* buffer, uint64_t reference_block_number)
{
    printf("\033[92;1mWrite block: %" PRIu64 "\033[0m\n",reference_block_number);
    if(reference_block_number >= DATA_BLOCKS * BYTES_PER_BLOCK)
    {
        return -ALLOCATOR_OUT_OF_BOUNDS;
    }
    int ret = write_block_raw(buffer, DATA_BASE_BLOCK + reference_block_number);
    if(ret < 0)
    {
        return ret;
    }
    return 0;
}

// passthrough INODE blocks.
int read_inode_block(uint8_t* buffer, uint64_t reference_block_number)
{
    if(reference_block_number >= INODE_BLOCKS * BYTES_PER_BLOCK)
    {
        return -ALLOCATOR_OUT_OF_BOUNDS;
    }
    pthread_mutex_lock(allocator_lock);
    int ret = read_block_raw(buffer, INODE_BASE_BLOCK + reference_block_number);
    pthread_mutex_unlock(allocator_lock);
    if(ret < 0)
    {
        return ret;
    }
    return 0;
}

int write_inode_block(const uint8_t* buffer, uint64_t reference_block_number)
{
    pthread_mutex_lock(allocator_lock);
    if(reference_block_number >= INODE_BLOCKS * BYTES_PER_BLOCK)
    {
        pthread_mutex_unlock(allocator_lock);
        return -ALLOCATOR_OUT_OF_BOUNDS;
    }
    int ret = write_block_raw(buffer, INODE_BASE_BLOCK + reference_block_number);
    pthread_mutex_unlock(allocator_lock);
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
int read_data_block(uint8_t* buffer, uint64_t block_number)
{
    if(block_number == 0)
    {
        memset(buffer, 0, BYTES_PER_BLOCK);
        return 0;
    }
    pthread_mutex_lock(allocator_lock);
    // check if in use!
    uint64_t index = block_number / BYTES_PER_BLOCK;
    read_block_raw(buffer, REFERENCE_BASE_BLOCK + index);
    uint8_t value = buffer[block_number % BYTES_PER_BLOCK];
    if(value > 0 && value != REF_IS_NON_EXISTANT)
    {
        // good. overwrite buffer
        int r = fetch_data_block(buffer, block_number);
        pthread_mutex_unlock(allocator_lock);
        return r;
    }
    pthread_mutex_unlock(allocator_lock);

    if(value == REF_IS_NON_EXISTANT)
    {
        return -ALLOCATOR_OUT_OF_BOUNDS;
    }
    return -ALLOCATOR_READ_ON_FREE;
}

// Mark data block as free. 

int free_data_block(uint64_t block_number)
{
    printf("\033[96;1mFree block:  %" PRIu64 "\033[0m\n",block_number);
    if(block_number == 1)
    {
        gdb_break_alloc();
    }
    if(block_number == 0)
    {
        // ignore. 0 block is null block.
        return 0;
    }
    // check if in use!
    pthread_mutex_lock(allocator_lock);
    uint8_t* buffer;
    create_buffer((void**)&buffer);

    uint64_t index = block_number / BYTES_PER_BLOCK;
    read_block_raw(buffer, REFERENCE_BASE_BLOCK + index);
    uint8_t value = buffer[block_number % BYTES_PER_BLOCK];
    if(value > 0 && value != REF_IS_NON_EXISTANT)
    {
        // good. overwrite buffer
        buffer[block_number % BYTES_PER_BLOCK] -= 1;
        if(buffer[block_number % BYTES_PER_BLOCK] == 0 && speed_free > block_number)
        {
            // now free!
            speed_free = block_number;
        }
        int r = write_block_raw(buffer, REFERENCE_BASE_BLOCK + index);
        free_buffer(buffer);
        pthread_mutex_unlock(allocator_lock);
        return r;
    }
    free_buffer(buffer);
    pthread_mutex_unlock(allocator_lock);
    return -ALLOCATOR_DOUBLE_FREE;
}

static int get_block_ref_count(uint64_t block_number)
{
    uint8_t* buffer;
    create_buffer((void**)&buffer);
    int ret = read_block_raw(buffer, REFERENCE_BASE_BLOCK + block_number / BYTES_PER_BLOCK);
    if(ret < 0)
    {
        free_buffer(buffer);
        return ret;
    }
    uint64_t byte_index = block_number % BYTES_PER_BLOCK;
    uint8_t out = buffer[byte_index];
    free_buffer(buffer);
    return out;
}

static int set_hash(uint8_t* hash, uint64_t index)
{
    uint8_t* buffer;
    create_buffer((void**)&buffer);
    int ret = read_block_raw(buffer, HASH_BASE_BLOCK + (index * HASH_SIZE) / BYTES_PER_BLOCK);
    if(ret < 0)
    {
        free_buffer(buffer);
        return ret;
    }
    uint32_t byte_index = (uint64_t)(index * HASH_SIZE) % BYTES_PER_BLOCK;
    
    memcpy(&buffer[byte_index],hash,HASH_SIZE);
    
    ret = write_block_raw(buffer, HASH_BASE_BLOCK + (index * HASH_SIZE) / BYTES_PER_BLOCK);
    free_buffer(buffer);
    return ret;
}

static int compare_hash_block(uint8_t* hash, const uint8_t* buffer, uint64_t block_number)
{
    // first see if hashes are the same.
    uint8_t* scratch;
    create_buffer((void**)&scratch);
    int ret = read_block_raw(scratch, HASH_BASE_BLOCK + (block_number * HASH_SIZE) / BYTES_PER_BLOCK);
    if(ret < 0)
    {
        free_buffer(scratch);
        return ret;
    }
    uint32_t byte_index = (uint64_t)(block_number * HASH_SIZE) % BYTES_PER_BLOCK;
    for(int i = 0; i < HASH_SIZE; i++)
    {
        if(scratch[byte_index] != hash[i])
        {
            free_buffer(scratch);
            return 0;
        }
    }

#ifndef IGNORE_HASH_COLLISIONS
    // hashes are the same. Compare actual buffer
    read_block_raw(scratch, DATA_BASE_BLOCK + block_number);
    for(int i = 0; i < BYTES_PER_BLOCK; i++)
    {
        if(scratch[byte_index] != buffer[i])
        {
            free_buffer(scratch);
            return 0;
        }
    }
#endif
    free_buffer(scratch);
    return 1;
}

// Copy on write.... write to next free block
// ASSUMES NO INTERRUPTIONS.... ATOMIC!
int write_to_next_free_block(const uint8_t* buffer, uint64_t* block_number)
{
    // requires atomic operations!

    // calc block hash.
    uint8_t hash[HASH_SIZE];
    SHA256(buffer, BYTES_PER_BLOCK,hash);
    
    
    // sort as hash list. 
    uint64_t short_hash = ((uint64_t*)hash)[0];
    uint64_t key = short_hash % DATA_BLOCKS;
    pthread_mutex_lock(allocator_lock);
    
    // check if free.
    uint8_t ref_count = get_block_ref_count(key);
    if(ref_count == 0)
    {
        // free! This is the block!
        write_data_block(buffer, *block_number);
        increment_reference(1, key);
        set_hash(hash, key);
        pthread_mutex_unlock(allocator_lock);
        *block_number = key;
        return 0;
    }

    // not free. Is it equal?
    if(ref_count < REF_IS_FULL && compare_hash_block(hash, buffer, key))
    {
        // it is equal and references are remaining!
        increment_reference(1, key);
        pthread_mutex_unlock(allocator_lock);
        *block_number = key;
        return 0;
    }

    // nope. Not free, not equal. Hash collision. Just try the next block.
    uint64_t finish = key;
    while(true)
    {
        key = (key + 1) % DATA_BLOCKS;
        uint8_t ref_count = get_block_ref_count(key);
        if(ref_count == 0)
        {
            write_data_block(buffer, *block_number);
            increment_reference(1, key);
            set_hash(hash, key);
            pthread_mutex_unlock(allocator_lock);
            *block_number = key;
            return 0;
        }
        // not free. Is it the same?
        if(ref_count < REF_IS_FULL && compare_hash_block(hash, buffer, key))
        {
            // it is the same!
            increment_reference(1, key);
            pthread_mutex_unlock(allocator_lock);
            *block_number = key;
            return 0;
        }
        // nope. keep going
        if(key == finish)
        {
            break;
        }
    }
    return -ALLOCATOR_OUT_OF_SPACE;
}


// formatting operations

static void clear_buffer(uint8_t* buffer)
{
    for(unsigned int i = 0; i < BYTES_PER_BLOCK; i++)
    {
        buffer[i] = 0;
    }
}


int format_super_block()
{
    uint8_t* buffer;
    create_buffer((void**)&buffer);
    clear_buffer(buffer);
    buffer[BYTES_PER_BLOCK-4] = 0xFB;
    buffer[BYTES_PER_BLOCK-3] = 0xF5;
    buffer[BYTES_PER_BLOCK-2] = 0xFB;
    buffer[BYTES_PER_BLOCK-1] = 0xF5;
    write_block_raw(buffer, SUPER_BLOCK);
    free_buffer(buffer);
    return 0;
}

bool allocator_check_valid_super_block()
{
    uint8_t* buffer;
    create_buffer((void**)&buffer);
    int r = read_block_raw(buffer, SUPER_BLOCK);
    
    // print here.
    bool out = r == 0 && (buffer[BYTES_PER_BLOCK-4] == 0xFB &&
                buffer[BYTES_PER_BLOCK-3] == 0xF5 && 
                buffer[BYTES_PER_BLOCK-2] == 0xFB && 
                buffer[BYTES_PER_BLOCK-1] == 0xF5);
    free_buffer(buffer);
    return out;
}

int clear_ref_blocks()
{
    uint8_t* buffer;
    create_buffer((void**)&buffer);
    clear_buffer(buffer);
    for(uint64_t i = 0; i < REF_BLOCKS; i++)
    {
        printf("Ref block: %" PRIu64 " / %" PRIu64"   \r", i, REF_BLOCKS);
        fflush(stdout);
        int ret = write_block_raw(buffer, REFERENCE_BASE_BLOCK + i);
        if(ret < 0)
        {
            free_buffer(buffer);
            return ret;
        }
    }
    printf("\n");
    // write invalid.
    int overflow = (BYTES_PER_BLOCK * REF_BLOCKS) - DATA_BLOCKS;
    // three overflow.

    // set buffer to all 255
    for(uint64_t i = 0; i < BYTES_PER_BLOCK; i++)
    {
        buffer[BYTES_PER_BLOCK - i - 1] = REF_IS_NON_EXISTANT;
    }
    int counter = 0;
    while(overflow >= BYTES_PER_BLOCK)
    {
        int ret = write_block_raw(buffer, REFERENCE_BASE_BLOCK + REF_BLOCKS - 1 - counter);
        if(ret < 0)
        {   
            free_buffer(buffer);
            return ret;
        }   
        overflow -= BYTES_PER_BLOCK;
        counter++;
    }
    
    clear_buffer(buffer);
    for(uint64_t i = 0; i < overflow; i++)
    {
        buffer[BYTES_PER_BLOCK - i - 1] = REF_IS_NON_EXISTANT;
    }
    int ret = write_block_raw(buffer, REFERENCE_BASE_BLOCK + REF_BLOCKS - 1 - counter);
    free_buffer(buffer);
    return ret;
}

int clear_inode_blocks()
{
    uint8_t* buffer;
    create_buffer((void**)&buffer);
    clear_buffer(buffer);
    for(uint64_t i = 0; i < INODE_BLOCKS; i++)
    {
        printf("INode Block: %" PRIu64 " / %" PRIu64 "  \r", i, INODE_BLOCKS);
        fflush(stdout);
        int ret = write_block_raw(buffer, INODE_BASE_BLOCK + i);
        if(ret < 0)
        {
            free_buffer(buffer);
            return ret;
        }
    }
    printf("\n");
    free_buffer(buffer);
    return 0;
}


int clear_hash_blocks()
{
    uint8_t* buffer;
    create_buffer((void**)&buffer);
    clear_buffer(buffer);
    for(uint64_t i = 0; i < HASH_BLOCKS; i++)
    {
        printf("Hash Block: %" PRIu64 " / %" PRIu64 "  \r", i, HASH_BLOCKS);
        fflush(stdout);
        int ret = write_block_raw(buffer, HASH_BASE_BLOCK + i);
        if(ret < 0)
        {
            free_buffer(buffer);
            return ret;
        }
    }
    printf("\n");
    free_buffer(buffer);
    return 0;
}
