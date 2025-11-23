#include "allocator.h"

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
    if(reference_block_number == 0)
    {
        bool trigger = true;
        for(int i = 128; i < 256; i++)
        {
            if(buffer[i] != 0) { trigger = false; break; }
        }
        if(trigger) { gdb_break_alloc(); }
    }
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


static int search_for_next_free_block(uint64_t* block_number)
{
    // slow simple way....
    // scan entire reference list to find the first 0.
    // later.... I can cache this.
    uint8_t* buffer;
    create_buffer((void**)&buffer);
    bool first_time = true;
    for(uint64_t block_index = speed_free / BYTES_PER_BLOCK; block_index < REF_BLOCKS; block_index++)
    {
        int ret = read_block_raw(buffer, REFERENCE_BASE_BLOCK + block_index);
        if(ret < 0)
        {
            free_buffer(buffer);
            return ret;
        }
        uint64_t start = 0;
        if(first_time)
        {
            start = speed_free % BYTES_PER_BLOCK;
            first_time = false;
        }
        for(uint64_t byte_index = start; byte_index < BYTES_PER_BLOCK; byte_index++)
        {
            uint8_t ref_count = buffer[byte_index];
            if(ref_count == 0) // 254 is full. 255 is invalid
            {
                // is free! 
                *(block_number) = byte_index + block_index * BYTES_PER_BLOCK;
                speed_free = *(block_number);
                free_buffer(buffer);
                return 0;
            }
        }
    }
    free_buffer(buffer);
    return -ALLOCATOR_OUT_OF_SPACE;
}


// Copy on write.... write to next free block
// ASSUMES NO INTERRUPTIONS.... ATOMIC!
int write_to_next_free_block(const uint8_t* buffer, uint64_t* block_number)
{
    // requires atomic operations!
    pthread_mutex_lock(allocator_lock);

    int ret = search_for_next_free_block(block_number);
    if(ret < 0)
    {
        pthread_mutex_unlock(allocator_lock);
        return ret;
    }

    // write data and then increment ref.
    ret = write_data_block(buffer, *block_number);
    if(ret < 0)
    {
        pthread_mutex_unlock(allocator_lock);
        return ret;
    }

    ret = increment_reference(1, *block_number); // increment by 1
    pthread_mutex_unlock(allocator_lock);
    return 0;
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
        printf("Ref block: %u / %u   \r", i, REF_BLOCKS);
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
        printf("INode Block: %u  / %u \r", i, INODE_BLOCKS);
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
