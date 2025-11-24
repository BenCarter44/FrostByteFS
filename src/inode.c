/* 
 * Layer 2: inode management with CoW pointer-tree, directories,
 * and indirect addressing (direct / single / double / triple).
 *
 * todo: 
 *  allocator lock
 *  lock on inode bitmap block (atomic update on inode bitmap)
 *  handle extended attributes overflow (instead padding use inline or pointer address as inode fields)
 */

#define _POSIX_C_SOURCE 200809L
#include "inode.h"
#include "allocator.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <limits.h>
#include <libgen.h>
#include <assert.h>

#ifndef MAX_FILENAME_LEN
#error "MAX_FILENAME_LEN must be defined in inode.h"
#endif


// Global per-inode locking structure. Must be initialized at mount time.
static pthread_mutex_t *inode_locks = NULL;
static uint64_t g_max_inodes = 0;

int64_t inline return_root_inode()
{
    return 1;
}

void inode_global_init() {
    uint64_t max_inodes = MAX_INODES;
    if (inode_locks != NULL && g_max_inodes == max_inodes) {
        return;
    }

    if (inode_locks) {
        for (uint64_t i = 0; i < g_max_inodes; ++i) {
            pthread_mutex_destroy(&inode_locks[i]);
        }

        free(inode_locks);
    }

    inode_locks = calloc(max_inodes, sizeof(pthread_mutex_t));

    if (!inode_locks) {
        perror("inode_global_init: calloc failed");
        exit(1);
    }

    for (uint64_t i = 0; i < max_inodes; ++i) {
        pthread_mutex_init(&inode_locks[i], NULL);
    }

    g_max_inodes = max_inodes;
}

static inline void inode_lock(uint64_t inum) {
    if (inode_locks && inum < g_max_inodes) {
        pthread_mutex_lock(&inode_locks[inum]);
    }
}

static inline void inode_unlock(uint64_t inum) {
    if (inode_locks && inum < g_max_inodes) {
        pthread_mutex_unlock(&inode_locks[inum]);
    }
}

/* Helpers for pointer arithmetic */
static inline uint64_t u64_pow(uint32_t base, uint32_t exp) {
    uint64_t r = 1;

    for (uint32_t i = 0; i < exp; ++i) {
        r *= base;
    }

    return r;
}

/* Forward declarations for internal helpers */
// static uint32_t set_block_recursive(uint32_t old_blocknum, uint32_t level,
//                                     uint64_t logical_index, uint32_t new_data_block,
//                                     uint8_t *scratch);

static int inode_read_from_disk_private(uint64_t inum, struct inode *out);
static int inode_write_to_disk_private(uint64_t inum, const struct inode *node);
static ssize_t inode_read_private(uint64_t inum, void *buf, size_t size, off_t offset);
static ssize_t inode_write_private(uint64_t inum, const void *buf, size_t size, off_t offset);
int inode_truncate_private(uint64_t inum, off_t newsize);

/* -------------------------
 * Basic inode read/write
 * ------------------------- */

int inode_read_from_disk(uint64_t inum, struct inode *out)
{
    inode_lock(inum);
    int r = inode_read_from_disk_private(inum, out);
    inode_unlock(inum);
    return r;
}

static int inode_read_from_disk_private(uint64_t inum, struct inode *out) {
    uint64_t block_num = INODE_TABLE_START_BLOCK + (inum / INODES_PER_BLOCK);
    uint64_t idx = inum % INODES_PER_BLOCK;

    uint8_t *buf;
    create_buffer((void**)&buf);
    
    if (!buf) {
        memset(out, 0, sizeof(*out));
        return -INODE_BUFFER_ALLOCATION_FAILED;
    }

    int ret = read_inode_block(buf, block_num);

    if (ret != 0) {
        memset(out, 0, sizeof(*out));
        free(buf);
        return ret;
    }

    memcpy(out, buf + idx * sizeof(struct inode), sizeof(struct inode));
    free(buf);

    return 0;
}

int inode_write_to_disk(uint64_t inum, const struct inode *node)
{
    inode_lock(inum);
    int r = inode_write_to_disk_private(inum, node);
    inode_unlock(inum);
    return r;
}


static int inode_write_to_disk_private(uint64_t inum, const struct inode *node) {
    uint64_t block_num = INODE_TABLE_START_BLOCK + (inum / INODES_PER_BLOCK);
    uint64_t idx = inum % INODES_PER_BLOCK;

    uint8_t *buf;
    create_buffer((void**)&buf);
    
    if (!buf) {
        return -INODE_BUFFER_ALLOCATION_FAILED;
    }
    
    // todo: should be continued or return error code
    if (read_inode_block(buf, block_num) != 0) {
        // If we cannot read, try to zero buffer (new FS) and continue
        memset(buf, 0, BYTES_PER_BLOCK);
    }

    memcpy(((uint8_t*)buf) + idx * sizeof(struct inode), node, sizeof(struct inode));

    int rc = 0;
    rc = write_inode_block(buf, block_num);

    free_buffer(buf);

    return rc;
}


/* -------------------------
 * Inode bitmap allocation
 * ------------------------- */

int inode_alloc(uint64_t *out_inum) {
    uint8_t *bytes;
    create_buffer((void**)&bytes);

    if (!bytes) {
        return -INODE_BUFFER_ALLOCATION_FAILED;
    }

    // Scan inode bitmap blocks
    // bitmap region is first blocks of inode region
    for (uint64_t b = 0; b < INODE_BITMAP_BLOCKS; ++b) {
        uint64_t blocknum = b;

        int ret = read_inode_block(bytes, blocknum);

        if (ret != 0) {
            free(bytes);
            return ret;
        }

        for (uint64_t byte = 0; byte < BYTES_PER_BLOCK; ++byte) {
            if (bytes[byte] == 0xFF) {
                continue;
            }
            
            for (int bit = 0; bit < 8; ++bit) {
                if (!(bytes[byte] & (1u << bit))) {
                    // allocate this inode
                    bytes[byte] |= (1u << bit);

                    ret = write_inode_block(bytes, blocknum);

                    if (ret != 0) {
                        free(bytes);
                        return -ret;
                    }

                    uint64_t bit_index = (b * BYTES_PER_BLOCK * 8) + (byte * 8) + bit;
                    *out_inum = bit_index;
                    // zero the inode struct on disk
                    struct inode empty = {0};
                    inode_write_to_disk_private(*out_inum, &empty);
                    free(bytes);

                    return 0;
                }
            }
            
        }
    }

    free(bytes);

    //todo: add proper error code
    return -ENOSPC;
}

int inode_free(uint64_t inum) {
    uint8_t *buf;
    create_buffer((void**)&buf);
    
    if (!buf) {
        return -INODE_BUFFER_ALLOCATION_FAILED;
    }

    uint64_t bit = inum;
    uint64_t b = bit / (BYTES_PER_BLOCK*8);
    uint64_t byte_idx = (bit % (BYTES_PER_BLOCK*8)) / 8;
    uint64_t bit_in_byte = bit % 8;

    int ret = read_inode_block(buf, b);

    if (ret != 0) { 
        free(buf); 
        return ret; 
    }

    // clear out data blocks.
    inode_truncate_private(inum, 0); 

    buf[byte_idx] &= ~(1u << bit_in_byte);
    // TODO: Need to call free_data_block() for all data blocks!
    ret = write_inode_block(buf, b);

    if (ret != 0) { 
        free(buf); 
        return ret; 
    }

    free(buf);
    return 0;
}

/* -------------------------
 * Indirect addressing helpers
 * ------------------------- */
/**
 *  Map logical block (as visible in single indirect address) from table block
 */
int single_indirect_address(uint64_t logical_block, uint64_t datatable, uint64_t* out_datablock)
{
    uint64_t *scratch;
    create_buffer((void**)&scratch);
    int r = read_data_block((uint8_t*)scratch, datatable);
    if(r < 0)
    {
        free(scratch);
        return r;
    }
    *out_datablock = scratch[logical_block];
    free(scratch);
    return 0;
}

int double_indirect_address(uint64_t logical_block, uint64_t datatable, uint64_t* out_datablock)
{
    // logical block 55:
    uint64_t row_index = logical_block / POINTERS_PER_BLOCK;

    uint64_t *scratch;
    create_buffer((void**)&scratch);
    int r = read_data_block((uint8_t*)scratch, datatable);
    if(r < 0)
    {
        free(scratch);
        return r;
    }
    uint64_t row_datatable = scratch[row_index];
    free(scratch);
    return single_indirect_address(logical_block % POINTERS_PER_BLOCK, row_datatable, out_datablock);
}

int triple_indirect_address(uint64_t logical_block, uint64_t datatable, uint64_t* out_datablock)
{
    uint64_t row_index = logical_block / (POINTERS_PER_BLOCK * POINTERS_PER_BLOCK);
    uint64_t *scratch;
    create_buffer((void**)&scratch);
    int r = read_data_block((uint8_t*)scratch, datatable);
    if(r < 0)
    {
        free(scratch);
        return r;
    }
    uint64_t matrix_datatable = scratch[row_index];
    free(scratch);
    return double_indirect_address(logical_block % (POINTERS_PER_BLOCK * POINTERS_PER_BLOCK), matrix_datatable, out_datablock);
}

int single_indirect_address_edit(uint64_t logical_block, uint64_t datatable, uint64_t out_datablock, uint64_t* new_datatable)
{
    uint64_t *scratch;
    create_buffer((void**)&scratch);
    int r = read_data_block((uint8_t*)scratch, datatable);
    if(r < 0)
    {
        free(scratch);
        return r;
    }
    if(scratch[logical_block] > 0)
    {
        // free old data block.
        assert(free_data_block(scratch[logical_block]) == 0);
    }
    scratch[logical_block] = out_datablock;
    // Save
    r = write_to_next_free_block((uint8_t*)scratch, new_datatable);
    free(scratch);
    if(r < 0)
    {
        return r;
    }

    // free former data table.
    if(datatable)
    {
        assert(free_data_block(datatable) == 0);
    }

    return 0;
}

int double_indirect_address_edit(uint64_t logical_block, uint64_t datatable, uint64_t out_datablock, uint64_t* new_datatable)
{
    uint64_t row_index = logical_block / POINTERS_PER_BLOCK;
    uint64_t *scratch;
    create_buffer((void**)&scratch);
    int r = read_data_block((uint8_t*)scratch, datatable);
    if(r < 0)
    {
        free(scratch);
        return r;
    }
    uint64_t row_datatable = scratch[row_index];

    // update the table
    uint64_t updated_single_table = 0;
    r = single_indirect_address_edit(logical_block % POINTERS_PER_BLOCK, row_datatable, out_datablock, &updated_single_table);
    if(r < 0)
    {
        free(scratch);
        return r;
    }
    // replace entry with this new value.
    scratch[row_index] = updated_single_table;
    // save
    r = write_to_next_free_block((uint8_t*)scratch, new_datatable);
    free(scratch);
    if(r < 0)
    {
        return r;
    }

    // free former data table.
    if(datatable)
    {
        assert(free_data_block(datatable) == 0);
    }
    return 0;
}

int triple_indirect_address_edit(uint64_t logical_block, uint64_t datatable, uint64_t out_datablock, uint64_t* new_datatable)
{

    uint64_t row_index = logical_block / (POINTERS_PER_BLOCK * POINTERS_PER_BLOCK);
    uint64_t *scratch;
    create_buffer((void**)&scratch);
    int r = read_data_block((uint8_t*)scratch, datatable);
    if(r < 0)
    {
        free(scratch);
        return r;
    }
    uint64_t matrix_datatable = scratch[row_index];

    // update the table
    uint64_t updated_matrix = 0;
    r = double_indirect_address_edit(logical_block % (POINTERS_PER_BLOCK * POINTERS_PER_BLOCK), matrix_datatable, out_datablock, &updated_matrix);
    if(r < 0)
    {
        free(scratch);
        return r;
    }
    
    scratch[row_index] = updated_matrix;
    // save
    r = write_to_next_free_block((uint8_t*)scratch, new_datatable);
    free(scratch);
    if(r < 0)
    {
        return r;
    }
    
    // free former data table.
    if(datatable)
    {
        assert(free_data_block(datatable) == 0);
    }
    return 0;
}



/*
 * inode_get_block_num:
 *   Map a logical block index (0-based) to a physical block number or 0 if hole.
 *   Returns 0 if not allocated or negative errno if read error (we return 0
 *   for "no block" and reserve errors for write operations).
 */
uint64_t inode_get_block_num(const struct inode *node, uint64_t logical_block) {
    // Direct blocks
    if (logical_block < NUM_DIRECT_BLOCKS) {
        return node->direct_blocks[logical_block];
    }

    uint8_t *scratch;
    create_buffer((void**)&scratch);

    logical_block -= NUM_DIRECT_BLOCKS;

    // int ret = 0;

    // Single indirect
    if (logical_block < (uint64_t)POINTERS_PER_BLOCK) {
        if(!node->single_indirect)
        {
            free(scratch);
            return 0;
        }
        uint64_t out = 0;
        single_indirect_address(logical_block, node->single_indirect, &out);
        free(scratch);
        return out;
    }

    logical_block -= (uint64_t)POINTERS_PER_BLOCK;

    // Double indirect
    uint64_t dbl_range = (uint64_t)POINTERS_PER_BLOCK * POINTERS_PER_BLOCK;

    if (logical_block < dbl_range) {
        uint64_t db = node->double_indirect;
        if(!db)
        {
            free(scratch);
            return 0;
        }
        uint64_t out = 0;
        double_indirect_address(logical_block, node->double_indirect, &out);
        free(scratch);
        return out;
    }

    logical_block -= dbl_range;

    // Triple indirect
    uint64_t tpl_range = (uint64_t)POINTERS_PER_BLOCK * POINTERS_PER_BLOCK * POINTERS_PER_BLOCK;

    if (logical_block < tpl_range) {
        uint64_t tb = node->triple_indirect;
        if(!tb)
        {
            free(scratch);
            return 0;
        }
        uint64_t out = 0;
        triple_indirect_address(logical_block, node->triple_indirect, &out);
        free(scratch);
        return out;
    }

    // Out of supported size
    return -INODE_OUT_OF_SUPPORTED_SIZE;
}

/*
 * set_block_recursive:
 *   Create/update pointer blocks recursively (CoW) to point logical_index at new_data_block.
 *
 * Parameters:
 *   - old_blocknum: existing pointer-block (0 if none)
 *   - level: how many pointer levels remain to reach data blocks:
 *       level=1 => this block's entries point to data blocks.
 *       level=2 => this block's entries point to level=1 pointer blocks.
 *       etc.
 *   - logical_index: index within the entire subtree of this level.
 *   - new_data_block: physical data block to set at leaf
 *   - scratch: buffer of BYTES_PER_BLOCK provided by caller
 *
 * Returns:
 *   - new pointer-block physical number (>=1) on success
 *   - error code from allocator for read/write error
 *
 * Behavior:
 *   - Read old pointer block if present into scratch.
 *   - Recurse down to create/modify child blocks, writing new pointer blocks via
 *     write_to_next_free_block (CoW).
 *   - Free old pointer-block after successfully writing new one.
 */
/*
static uint64_t set_block_recursive(uint64_t old_blocknum, uint64_t level,
                                    uint64_t logical_index, uint64_t new_data_block,
                                    uint8_t *scratch)
{
    int ret = 0;
    uint64_t *ptrs = (uint64_t*)scratch;

    if (old_blocknum != 0) {
        ret = read_data_block(scratch, old_blocknum);
        if (ret != 0) return ret;

    } else {
        memset(scratch, 0, BYTES_PER_BLOCK);
    }

    if (level == 1) {
        if (logical_index >= POINTERS_PER_BLOCK) return 0;
        ptrs[logical_index] = new_data_block;

    } else {
        // compute index of the child pointer at this level and the remainder
        uint64_t subtree_size = u64_pow(POINTERS_PER_BLOCK, level - 1);
        uint64_t idx = (uint64_t)(logical_index / subtree_size);
        uint64_t remainder = logical_index % subtree_size;

        uint64_t child_old = ptrs[idx];
        uint64_t child_new = set_block_recursive(child_old, level - 1, remainder, new_data_block, scratch);

        // note: we reuse scratch for children as recursive call writes/read into it and returns
        if (child_new == 0 && child_old != 0) {
            // child update failed (I/O)
            return -INODE_CHILD_UPDATE_FAILED;
        }

        ptrs[idx] = child_new;
    }

    // write updated pointer block to a new physical block (CoW)
    uint64_t new_blocknum = 0;

    ret = write_to_next_free_block((const uint8_t*)ptrs, &new_blocknum);
    if (ret != 0) return ret;

    // Free old pointer block after successful write (decrement refcount)
    if (old_blocknum != 0) {
        free_data_block(old_blocknum);
    }

    return new_blocknum;
}
*/

/*
 * inode_set_block_num:
 *   Public wrapper to set logical_block -> new_physical_block in the inode's
 *   pointer tree. This performs CoW of pointer blocks and frees old data blocks
 *   when appropriate (for direct blocks we free the old block immediately).
 *
 *   Returns 0 on success or negative errno.
 */
uint64_t inode_set_block_num(uint64_t inum, struct inode *node,
                        uint64_t logical_block, uint64_t new_physical_block)
{
    uint8_t *scratch;
    create_buffer((void**)&scratch);
    if (!scratch) return -INODE_BUFFER_ALLOCATION_FAILED;

    int rc = 0;
    int ret = 0;

    if (logical_block < NUM_DIRECT_BLOCKS) {
        uint64_t old = node->direct_blocks[logical_block];
        node->direct_blocks[logical_block] = new_physical_block;

        if (old) {
            // Free old data block (decrement refcount)
            ret = free_data_block(old);
            if (ret != 0) rc = ret;
        }

        free(scratch);
        return rc;
    }

    logical_block -= NUM_DIRECT_BLOCKS;

    // single
    if (logical_block < (uint64_t)POINTERS_PER_BLOCK) {
        uint64_t new_datatable = 0;
        single_indirect_address_edit(logical_block, node->single_indirect, new_physical_block, &new_datatable);
        node->single_indirect = new_datatable;
        free(scratch);
        return rc;
    }

    logical_block -= (uint64_t)POINTERS_PER_BLOCK;

    // double
    uint64_t dbl_range = (uint64_t)POINTERS_PER_BLOCK * POINTERS_PER_BLOCK;

    if (logical_block < dbl_range) {
        uint64_t new_datatable = 0;
        double_indirect_address_edit(logical_block, node->double_indirect, new_physical_block, &new_datatable);
        node->double_indirect = new_datatable;
        free(scratch);
        return rc;
    }

    logical_block -= dbl_range;

    // triple
    uint64_t tpl_range = (uint64_t)POINTERS_PER_BLOCK * POINTERS_PER_BLOCK * POINTERS_PER_BLOCK;

    if (logical_block < tpl_range) {
        uint64_t new_datatable = 0;
        triple_indirect_address_edit(logical_block, node->triple_indirect, new_physical_block, &new_datatable);
        node->triple_indirect = new_datatable;
        free(scratch);
        return rc;
    }

    free(scratch);
    return -INODE_OUT_OF_SUPPORTED_SIZE; // file too big
}


/* -------------------------
 * Truncate helpers
 * ------------------------- */

/*
 * inode_truncate(inum, newsize)
 *   Supports both grow and shrink.
 *   If shrinking: zeroes tail of last kept block (CoW) and frees later blocks.
 */
int inode_truncate(uint64_t inum, off_t newsize) {
    inode_lock(inum);
    int r = inode_truncate_private(inum, newsize);
    inode_unlock(inum);
    return r;
}
int inode_truncate_private(uint64_t inum, off_t newsize) {
    if (newsize < 0) return -EINVAL;

    struct inode node;
    inode_read_from_disk_private(inum, &node);

    int64_t oldsize = node.size;

    if ((off_t)oldsize == newsize) { 
        return 0; 
    }

    node.size = newsize;

    if (newsize > oldsize) {
        // growing: allocate zero-filled blocks up to newsize (sparse handling allowed)
        // We choose not to pre-allocate blocks for holes; writes will allocate.
        node.size = newsize;
        node.mtime = node.ctime = time(NULL);
        inode_write_to_disk_private(inum, &node);
        return 0;
    }

    // truncate, size decreasing.


    // All blocks after *newsize* are to be chopped off. 
    // Go backwards.
    
    while(oldsize > (int64_t)newsize) {
        uint64_t logical_block = oldsize / BYTES_PER_BLOCK;

        // remove logical block from list (auto frees block). Go backwards! 32812
        if(node.triple_indirect && logical_block >= NUM_DIRECT_BLOCKS + POINTERS_PER_BLOCK + POINTERS_PER_BLOCK * INODES_PER_BLOCK)
        {
            uint64_t triple_adjust = logical_block - NUM_DIRECT_BLOCKS - POINTERS_PER_BLOCK - POINTERS_PER_BLOCK * INODES_PER_BLOCK;
            uint64_t new_data_table = 0;
            assert(triple_indirect_address_edit(triple_adjust,node.triple_indirect, 0, &new_data_table) == 0);
            node.triple_indirect = new_data_table;
        }
        else if(node.double_indirect && logical_block >= NUM_DIRECT_BLOCKS + POINTERS_PER_BLOCK)
        {
            if(node.triple_indirect)
            {
                assert(free_data_block(node.triple_indirect) == 0);
                node.triple_indirect = 0;
            }
            uint64_t double_adjust = logical_block - NUM_DIRECT_BLOCKS - POINTERS_PER_BLOCK;
            uint64_t new_data_table = 0;
            assert(double_indirect_address_edit(double_adjust,node.double_indirect, 0, &new_data_table)  == 0);
            node.double_indirect = new_data_table;
        }
        else if(node.single_indirect && logical_block >= NUM_DIRECT_BLOCKS)
        {
            if(node.double_indirect)
            {
                assert(free_data_block(node.double_indirect) == 0);
                node.double_indirect = 0;
            }
            uint64_t single_adjust = logical_block - NUM_DIRECT_BLOCKS;
            uint64_t new_data_table = 0;
            assert(single_indirect_address_edit(single_adjust,node.single_indirect, 0, &new_data_table) == 0);
            node.single_indirect = new_data_table;
        }
        else if(logical_block < NUM_DIRECT_BLOCKS && node.direct_blocks[logical_block])
        {  
            if(node.single_indirect)
            {
                assert(free_data_block(node.single_indirect) == 0);
                node.single_indirect = 0;
            }
            if(node.direct_blocks[logical_block])
            {
                assert(free_data_block(node.direct_blocks[logical_block]) == 0);
            }
            node.direct_blocks[logical_block] = 0;
        }
        oldsize -= BYTES_PER_BLOCK;
    }
        
    return inode_write_to_disk_private(inum, &node);
}



/* -------------------------
 * File read / write
 * ------------------------- */

ssize_t inode_read(uint64_t inum, void *buf, size_t size, off_t offset)
{
    inode_lock(inum);
    ssize_t r = inode_read_private(inum, buf, size, offset);
    inode_unlock(inum);
    return r;
}

static ssize_t inode_read_private(uint64_t inum, void *buf, size_t size, off_t offset) {
    if (size == 0) return 0;

    if (offset < 0) return -EINVAL;

    struct inode node;
    inode_read_from_disk_private(inum, &node);

    uint64_t file_size = node.size;

    if ((uint64_t)offset >= file_size) { 
        return 0; 
    }

    // clamp size by file bounds
    if ((uint64_t)offset + size > file_size) {
        size = (size_t)(file_size - offset);
    }

    uint8_t *scratch;
    create_buffer((void**)&scratch);

    if (!scratch) { 
        return -ENOMEM; 
    }

    size_t bytes_left = size;
    size_t copied = 0;
    uint64_t cur_offset = (uint64_t)offset;

    while (bytes_left > 0) {
        uint64_t lblock = cur_offset / BYTES_PER_BLOCK;
        uint64_t phy = inode_get_block_num(&node, lblock);
        size_t block_off = (size_t)(cur_offset % BYTES_PER_BLOCK);
        size_t to_copy = BYTES_PER_BLOCK - block_off;

        if (to_copy > bytes_left) {
            to_copy = bytes_left;
        }

        if (phy == 0) {
            // hole -> zero
            memset((uint8_t*)buf + copied, 0, to_copy);

        } else {
            if (read_data_block(scratch, phy) != 0) {
                free(scratch);

                return -EIO;
            }

            memcpy((uint8_t*)buf + copied, scratch + block_off, to_copy);
        }

        bytes_left -= to_copy;
        copied += to_copy;
        cur_offset += to_copy;
    }

    // todo: comment this to make read faster??
    node.atime = time(NULL);
    inode_write_to_disk_private(inum, &node);

    free(scratch);

    return (ssize_t)copied;
}

/*
 * inode_write:
 *   CoW semantics: for every data-block modified, we read existing block (if any),
 *   merge new bytes, write new data block via write_to_next_free_block, update
 *   inode pointer tree via inode_set_block_num (which will allocate new pointer
 *   blocks CoW style), then free the old data block.
 */
ssize_t inode_write(uint64_t inum, const void *buf, size_t size, off_t offset) {
    inode_lock(inum);
    ssize_t r = inode_write_private(inum, buf, size, offset);
    inode_unlock(inum);
    return r;
}

static ssize_t inode_write_private(uint64_t inum, const void *buf, size_t size, off_t offset) {
    if (size == 0) {
        return 0;
    }

    if (offset < 0) {
        return -EINVAL;
    }

    struct inode node;

    inode_read_from_disk_private(inum, &node);

    uint8_t *scratch;
    create_buffer((void**)&scratch);

    if (!scratch) { 
        return -ENOMEM; 
    }

    size_t bytes_left = size;
    size_t written = 0;
    uint64_t cur_offset = (uint64_t)offset;

    while (bytes_left > 0) {
        uint64_t lblock = cur_offset / BYTES_PER_BLOCK;
        size_t block_off = (size_t)(cur_offset % BYTES_PER_BLOCK);
        size_t to_write = BYTES_PER_BLOCK - block_off;

        if (to_write > bytes_left) {
            to_write = bytes_left;
        }

        // Read old block if present
        uint64_t old_phy = inode_get_block_num(&node, lblock);

        if (old_phy != 0) {
            if (read_data_block(scratch, old_phy) != 0) {
                free(scratch);
                return -EIO;
            }

        } else {
            memset(scratch, 0, BYTES_PER_BLOCK);
        }

        // Merge new data into buffer
        memcpy(scratch + block_off, (const uint8_t*)buf + written, to_write);

        // Write the merged block to a new physical block (CoW)
        uint64_t new_phy = 0;

        if (write_to_next_free_block(scratch, &new_phy) != 0) {
            free(scratch);
            return -EIO;
        }

        // Update pointer tree (this will free old pointer blocks via CoW inside)
        if (inode_set_block_num(inum, &node, lblock, new_phy) != 0) {
            // free the new block we allocated since we failed to update pointers
            free_data_block(new_phy);
            free(scratch);

            return -EIO;
        }

        written += to_write;
        bytes_left -= to_write;
        cur_offset += to_write;

        // todo: write inode every time for crash consistency ??? (slow)
    }

    // Update size and timestamps
    if ((uint64_t)(offset + (off_t)written) > node.size) {
        node.size = offset + (off_t)written;
    }

    node.mtime = node.ctime = time(NULL);
    inode_write_to_disk_private(inum, &node);

    free(scratch);
    return (ssize_t)written;
}

/* -------------------------
 * Directory helpers
 * ------------------------- */

static inline uint64_t dir_entries_per_block(void) {
    return BYTES_PER_BLOCK / sizeof(directory_entry);
}

/*
 * inode_find_dirent: find a child by name within a directory inode.
 * Returns child's inum on success, -ENOENT if not found, or negative errno.
 */
int inode_find_dirent(uint64_t dir_inum, const char *name) {
    
    // Just read the directory as a standard file.
    struct inode node;
    inode_read_from_disk_private(dir_inum, &node);

    if (!S_ISDIR(node.mode)) {
        return -ENOTDIR;
    }

    uint8_t *scratch = (uint8_t*)malloc(node.size); 
    memset(scratch,0,node.size);
    inode_read_private(dir_inum, scratch, node.size, 0);
    directory_entry* list = (directory_entry*)scratch;

    uint64_t index = 0;
    while(list[index].is_valid == 1)
    {
        if(list[index].inum != 0 && strncmp(list[index].name, name, MAX_FILENAME_LEN) == 0)
        {
            // match!
            int out = (int)list[index].inum;
            free(scratch);
            return out;
        }
        index++;
    }
    free(scratch);
    return -ENOENT;
}

/*
 * inode_add_dirent: add a dir entry (name->inum) to parent directory.
 * Returns 0 on success, negative errno on failure.
 */
int inode_add_dirent(uint64_t parent_inum, directory_entry* entry) {
    if(entry == NULL) {
        return -ENOTDIR;
    }
    
    if (strlen(entry->name) > MAX_FILENAME_LEN) {
        return -ENAMETOOLONG;
    }

    
    // Just read the directory as a standard file. Add to it. 
    struct inode node;
    inode_read_from_disk_private(parent_inum, &node);

    if (!S_ISDIR(node.mode)) {
        return -ENOTDIR;
    }

    uint8_t *scratch = (uint8_t*)malloc(node.size + 2 * sizeof(directory_entry)); 
    memset(scratch,0,node.size + 2 * sizeof(directory_entry));
    inode_read_private(parent_inum, scratch, node.size, 0);

    directory_entry* list = (directory_entry*)scratch;


    uint64_t index = 0;
    while(list[index].is_valid == 1)
    {
        index++;
    }
    entry->is_valid = 1;
    memcpy((void*)&list[index],(void*)entry,sizeof(directory_entry));
    index++;
    list[index].name[0] = 0;
    list[index].inum = 0;
    list[index].is_valid = 0;
    index++;
    // inode_truncate_private(parent_inum, 0);
    inode_write_private(parent_inum, (void*)list, index * sizeof(directory_entry), 0);
    
    free(scratch);
    return 0;
}

/*
 * inode_remove_dirent: remove an entry by name.
 * Returns 0 on success or -ENOENT if not found.
 */
int inode_remove_dirent(uint64_t parent_inum, directory_entry* entry) {
    if(entry == NULL) {
        return -ENOTDIR;
    }
    
    if (strlen(entry->name) > MAX_FILENAME_LEN) {
        return -ENAMETOOLONG;
    }

    
    // Just read the directory as a standard file. Remove to it. 
    struct inode node;
    inode_read_from_disk_private(parent_inum, &node);

    if (!S_ISDIR(node.mode)) {
        return -ENOTDIR;
    }

    uint8_t *scratch = (uint8_t*)malloc(node.size + 2 * sizeof(directory_entry)); 
    memset(scratch,0,node.size + 2 * sizeof(directory_entry));
    inode_read_private(parent_inum, scratch, node.size, 0);

    directory_entry* list = (directory_entry*)scratch;
    directory_entry* new_list = (directory_entry*)malloc(node.size + 2 * sizeof(directory_entry));
    memset((void*)new_list,0,node.size + 2 * sizeof(directory_entry));

    uint64_t new_list_index = 0;

    int is_found = 0;

    uint64_t index = 0;
    while(list[index].is_valid == 1)
    {
        if(list[index].inum == entry->inum && strncmp(list[index].name, entry->name, MAX_FILENAME_LEN) == 0)
        {
            // found! Remove!
            is_found = 1;
        }
        else
        {
            // copy!
            memcpy((void*)&new_list[new_list_index], (void*)&list[index], sizeof(directory_entry));
            new_list_index += 1;
        }
        index++;
    }
    new_list[new_list_index].name[0] = 0;
    new_list[new_list_index].inum = 0;
    new_list[new_list_index].is_valid = 0;
    new_list_index++;
    // inode_truncate_private(parent_inum, 0);
    inode_write_private(parent_inum, (void*)new_list, new_list_index * sizeof(directory_entry), 0);
    
    free(scratch);
    free(new_list);

    if (is_found == 1) return 0;
    else return -ENOENT;
}

/* -------------------------
 * High-level operations
 * ------------------------- */

/*
 * inode_create: create file or directory at path.
 * Mode determines file/dir type.
 */
int64_t inode_create(const char *path, mode_t mode, uint64_t *out_inum) {
    if (!path || path[0] != '/') return -EINVAL;
    if (strcmp(path, "/") == 0) return -EEXIST;

    // Duplicate path for dirname/basename
    char *pathdup = strdup(path);
    char *pathdup2 = strdup(path);

    if (!pathdup) {
        return -ENOMEM;
    }

    char *dirpart = dirname(pathdup);
    char *basepart = basename(pathdup2);

    // Find parent inode
    int parent_inum = inode_find_by_path(dirpart);

    if (parent_inum < 0) { 
        free(pathdup); 
        free(pathdup2);
        return parent_inum; 
    }

    inode_lock(parent_inum);
    // Ensure parent is directory
    struct inode parent;
    inode_read_from_disk_private((uint64_t)parent_inum, &parent);

    if (!S_ISDIR(parent.mode)) { 
        inode_unlock(parent_inum);
        free(pathdup); 
        free(pathdup2);
        return -ENOTDIR; 
    }

    // Ensure name not exists
    int exists = inode_find_dirent((uint64_t)parent_inum, basepart);

    if (exists >= 0) { 
        free(pathdup); 
        free(pathdup2);
        inode_unlock(parent_inum);
        return -EEXIST; 
    }

    // allocate inode
    uint64_t new_inum;
    if (inode_alloc(&new_inum) != 0) { 
        free(pathdup); 
        free(pathdup2);
        return -ENOSPC; 
    }

    // initialize inode struct
    struct inode node;
    memset(&node, 0, sizeof(node));
    node.mode = mode;
    node.uid = getuid();
    node.gid = getgid();
    node.nlink = S_ISDIR(mode) ? 2 : 1; // dir has . and ..
    node.size = 0;
    node.atime = node.mtime = node.ctime = time(NULL);

    // write inode
    if (inode_write_to_disk_private(new_inum, &node) != 0)
    {
        inode_free(new_inum);
        free(pathdup);
        free(pathdup2);
        inode_unlock(parent_inum);
        return -EIO;
    }

    // if directory, create '.' and '..' entries
    if (S_ISDIR(mode)) {
        // create one data block and add '.' and '..'
            uint8_t *scratch;
            create_buffer((void**)&scratch);

        if (!scratch) { 
            inode_free(new_inum); 
            free(pathdup); 
            free(pathdup2);
            inode_unlock(parent_inum);
            return -ENOMEM; 
        }

        memset(scratch, 0, BYTES_PER_BLOCK);

        directory_entry *ents = (directory_entry*)scratch;

        ents[0].inum = new_inum;
        strncpy(ents[0].name, ".", MAX_FILENAME_LEN); ents[0].name[MAX_FILENAME_LEN] = '\0';
        ents[1].inum = parent_inum;
        strncpy(ents[1].name, "..", MAX_FILENAME_LEN); ents[1].name[MAX_FILENAME_LEN] = '\0';

        uint64_t blocknum = 0;

        if (write_to_next_free_block(scratch, &blocknum) != 0) {
            free(scratch); 
            inode_free(new_inum); 
            free(pathdup); 
            free(pathdup2);
            inode_unlock(parent_inum);
            return -EIO;
        }

        // set as direct block 0
        inode_lock(new_inum);
        inode_read_from_disk_private(new_inum, &node);
        node.direct_blocks[0] = blocknum;
        node.size = BYTES_PER_BLOCK;
        inode_write_to_disk_private(new_inum, &node);
        inode_unlock(new_inum);
        free(scratch);

        // increment parent link count
        parent.nlink++;
        inode_write_to_disk_private(parent_inum, &parent);
    }

    // add dirent to parent
    directory_entry ent;
    ent.inum = new_inum; 
    strncpy(ent.name, basepart, MAX_FILENAME_LEN);

    if (inode_add_dirent((uint64_t)parent_inum, &ent) != 0) {
        // cleanup: remove inode and its blocks
        inode_free(new_inum);
        free(pathdup);
        free(pathdup2);
        inode_unlock(parent_inum);
        return -EIO;
    }

    *out_inum = new_inum;
    free(pathdup);
    free(pathdup2);
    inode_unlock(parent_inum);
    return 0;
}

/*
 * inode_unlink: remove file (non-directory).
 */
int inode_unlink(const char *path) {
    if (!path || strcmp(path, "/") == 0) return -EINVAL;
    char *dup = strdup(path);
    if (!dup) return -ENOMEM;
    char *dup2 = strdup(path);
    if (!dup2) return -ENOMEM;
    char *dirpart = dirname(dup);
    char *basepart = basename(dup2);

    int parent = inode_find_by_path(dirpart);
    if (parent < 0) { free(dup); free(dup2); return parent; }

    int target = inode_find_dirent((uint64_t)parent, basepart);
    if (target < 0) { free(dup); free(dup2); return -ENOENT; }

    inode_lock(parent);

    directory_entry entry_of_file;
    entry_of_file.inum = target;
    strncpy(entry_of_file.name, basepart, MAX_FILENAME_LEN);

    struct inode node;
    inode_read_from_disk_private((uint64_t)target, &node);
    if (S_ISDIR(node.mode)) { free(dup); free(dup2); return -EISDIR; }

    // Remove from parent dir
    if (inode_remove_dirent((uint64_t)parent, &entry_of_file) != 0) { free(dup); free(dup2); return -EIO; }

    // Decrement link and possibly free inode
    inode_lock((uint64_t)target);
    inode_read_from_disk_private((uint64_t)target, &node);
    if (node.nlink > 0) 
    {
        node.nlink--;
    }
    if (node.nlink > 0) {
        inode_write_to_disk_private((uint64_t)target, &node);
        inode_unlock((uint64_t)target);
        inode_unlock(parent);
        free(dup); free(dup2);
        return 0;
    }

    // free all blocks and inode
    // inode_truncate_private(target,0);
    inode_write_to_disk_private((uint64_t)target, &node);
    inode_unlock((uint64_t)target);

    inode_free((uint64_t)target);
    free(dup); free(dup2);
    inode_unlock(parent);
    return 0;
}

/*
 * inode_readdir: iterates directory entries and calls filler for each.
 * The caller should pass a fuse_fill_dir_t like pointer or similar callback.
 *
 * Here we define a simple filler prototype:
 *   typedef int (*filler_t)(void *buf, const char *name, const struct stat *stbuf, off_t off);
 * The actual FUSE callback returns 1 to stop or 0 to continue; adapt accordingly.
 */
int inode_readdir(uint64_t dir_inum, void *buf, fuse_fill_dir_t filler) {
    
    // There is a compiler error here. 
    
    struct inode node;
    inode_lock(dir_inum);
    inode_read_from_disk_private(dir_inum, &node);

    if (!S_ISDIR(node.mode)) {
        inode_unlock(dir_inum);
        return -ENOTDIR;
    }

    uint8_t *scratch = (uint8_t*)malloc(node.size); 
    memset(scratch,0,node.size);
    inode_read_private(dir_inum, scratch, node.size, 0);
    directory_entry* list = (directory_entry*)scratch;

    uint64_t index = 0;
    while(list[index].is_valid == 1)
    {
        if (list[index].inum != 0) {
            if ((*filler)(buf, list[index].name, NULL, 0, 0)) {
                free(scratch);
                inode_unlock(dir_inum);
                return 0;
            }
        }
        index++;
    }
    inode_unlock(dir_inum);
    free(scratch);
    return 0;
}

/*
 * inode_find_by_path: resolves an absolute path to an inode number.
 * Returns inum >= 0 on success or negative error.
 */
int64_t inode_find_by_path(const char *path) {
    if (!path || path[0] != '/') {
        return -EINVAL;
    }

    if (strcmp(path, "/") == 0) {
        return return_root_inode(); // root
    }

    // duplicate path for strtok
    char *dup = strdup(path);

    if (!dup) {
        return -ENOMEM;
    }

    char *saveptr = NULL;
    char *token = strtok_r(dup, "/", &saveptr);
    int cur_inum = return_root_inode();

    while (token) {
        struct inode node;
        inode_read_from_disk_private((uint64_t)cur_inum, &node);

        if (!S_ISDIR(node.mode)) { 
            free(dup); 
            return -ENOTDIR; 
        }
        inode_lock(cur_inum);
        int next = inode_find_dirent((uint64_t)cur_inum, token);
        inode_unlock(cur_inum);

        if (next < 0) { 
            free(dup); 
            return -ENOENT; 
        }

        cur_inum = next;
        token = strtok_r(NULL, "/", &saveptr);
    }

    free(dup);
    
    return cur_inum;
}



/*
 * format_inodes:
 *   Zero out inode-bitmap region and create root inode if not present.
 *   This function also initializes inode_global_init if locks not set.
 */
int format_inodes() {
    // Ensure locks exist
    inode_global_init();

    // Check bitmap for inode 0
    uint8_t *buf;
    create_buffer((void**)&buf);

    if (!buf) {
        return -ENOMEM;
    }

    // uint64_t bitmap_blocknum = INODE_TABLE_START_BLOCK; // first bitmap block


    // treat as fresh fs: zero out bitmap blocks
    memset(buf, 0, BYTES_PER_BLOCK);

    for (uint64_t b = 0; b < INODE_BITMAP_BLOCKS; ++b) {
        if (write_inode_block(buf, b) != 0) {
            free(buf); 
            return -EIO;
        }
    }

    // allocate inode 0 by setting bit 0
    // ((uint8_t*)buf)[0] |= 1u;

    // if (write_inode_block(buf, 0) != 0) { 
    //     free(buf); 
    //     return -EIO; 
    // }

    // create root inode structure

    struct inode root;
    memset(&root, 0, sizeof(root));
    root.mode = S_IFDIR | 0755;
    root.uid = getuid(); 
    root.gid = getgid();
    root.nlink = 2;
    root.size = BYTES_PER_BLOCK;
    root.atime = root.mtime = root.ctime = time(NULL);

    // allocate a data block for root dir contents
    uint8_t *scratch;
    create_buffer((void**)&scratch);

    if (!scratch) { 
        free(buf); 
        return -ENOMEM; 
    }


    directory_entry root_ent[3];
    root_ent[0].inum = return_root_inode();
    root_ent[0].is_valid = 1;
    strncpy(root_ent[0].name, ".", MAX_FILENAME_LEN); 

    root_ent[1].inum = return_root_inode();
    root_ent[1].is_valid = 1;
    strncpy(root_ent[1].name, "..", MAX_FILENAME_LEN); 

    root_ent[2].inum = return_root_inode();
    root_ent[2].is_valid = 0;

    // tell allocator that root has been allocated
    uint64_t out_num = 19;
    inode_alloc(&out_num); // to mark 0 as used.
    inode_alloc(&out_num); // to get inode 1 for root.
    if(out_num != return_root_inode())
    {
        free(scratch);
        free(buf);
        return -EIO;        
    }
    memcpy(scratch, root_ent, sizeof(directory_entry) * 3);
    uint64_t datablock_number = 0;
    // write directory_entry into data block
    write_to_next_free_block(scratch, &datablock_number); // to get 0
    if(write_to_next_free_block(scratch, &datablock_number) != 0 || datablock_number != 1)
    {
        free(scratch); 
        free(buf); 
        return -EIO;  
    }

    // write inode
    root.direct_blocks[0] = datablock_number;
    root.size = sizeof(directory_entry) * 3;
    inode_write_to_disk_private(return_root_inode(), &root);
    free(scratch);
    free(buf);

    // test
    int a = inode_find_dirent(return_root_inode(), "..");
    printf("Found: %d\n", a);

    return 0;
}


/* -------------------------
 * Ownership and Permissions
 * ------------------------- */

int inode_chown(uint64_t inode, uid_t user, gid_t group) {
    inode_lock(inode);
    
    struct inode node;

    if (inode_read_from_disk_private(inode, &node) != 0) {
        inode_unlock(inode);
        return -EIO;
    }

    // Change ownership
    if (user != (uid_t)-1) node.uid = user;
    if (group != (gid_t)-1) node.gid = group;

    node.ctime = time(NULL);

    int ret = inode_write_to_disk_private(inode, &node);
    inode_unlock(inode);

    return ret;
}

int inode_chmod(uint64_t inode, mode_t fmode) {
    inode_lock(inode);
    
    struct inode node;

    if (inode_read_from_disk_private(inode, &node) != 0) {
        inode_unlock(inode);

        return -EIO;
    }

    // Only change permissions bits, preserve file type bits
    // S_IFMT is the bitmask for the file type bit field
    node.mode = (node.mode & S_IFMT) | (fmode & ~S_IFMT);
    node.ctime = time(NULL);

    int ret = inode_write_to_disk_private(inode, &node);
    inode_unlock(inode);

    return ret;
}

/* -------------------------
 * Directory Removal / Rename
 * ------------------------- */

/* Helper to check if directory is empty (ignoring . and ..) */
static int is_dir_empty(uint64_t dir_inum) {

    // Just read the directory as a standard file. Add to it. 
    struct inode node;
    inode_read_from_disk_private(dir_inum, &node);

    if (!S_ISDIR(node.mode)) {
        return -ENOTDIR;
    }

    uint8_t *scratch = (uint8_t*)malloc(node.size + 2 * sizeof(directory_entry)); 
    memset(scratch,0,node.size + 2 * sizeof(directory_entry));

    inode_read_private(dir_inum, scratch, node.size, 0);

    directory_entry* list = (directory_entry*)scratch;

    uint64_t index = 0;
    while(list[index].is_valid == 1)
    {
        index++;
        if(strncmp(list[index].name,".",2) != 0 && 
            strncmp(list[index].name,"..",3) != 0 )
        {
            // something else!
            free(scratch);
            return 0;
        }
    }
    free(scratch);
    return 1; // Empty
}

int inode_rmdir(const char *path) {
    if (!path || strcmp(path, "/") == 0) return -EINVAL;

    char *dup = strdup(path);
    if (!dup) return -ENOMEM;
    char *dup2 = strdup(path);
    if (!dup2) return -ENOMEM;
    char *dirpart = dirname(dup);
    char *basepart = basename(dup2);

    int parent_inum = inode_find_by_path(dirpart);
    if (parent_inum < 0) { free(dup); free(dup2); return parent_inum; }

    // Check if target exists in parent
    inode_lock(parent_inum);
    int target_inum = inode_find_dirent((uint64_t)parent_inum, basepart);
    
    if (target_inum < 0) { 
        inode_unlock(parent_inum);
        free(dup); free(dup2);
        return -ENOENT;
    }

    inode_lock(target_inum);
    struct inode target_node;
    inode_read_from_disk_private((uint64_t)target_inum, &target_node);

    if (!S_ISDIR(target_node.mode)) {
        inode_unlock(target_inum);
        inode_unlock(parent_inum);
        free(dup); free(dup2);
        return -ENOTDIR;
    }

    // Check if empty
    int empty = is_dir_empty((uint64_t)target_inum);
    if (empty < 0) { 
        inode_unlock(target_inum);
        inode_unlock(parent_inum);
        free(dup); free(dup2);
        return empty;
    } // Error checking
    if (empty == 0) {
        inode_unlock(target_inum);
        inode_unlock(parent_inum);
        free(dup); free(dup2);
        return -ENOTEMPTY;
    }

    // Remove from parent
    directory_entry dent;
    dent.inum = target_inum;
    strncpy(dent.name, basepart, MAX_FILENAME_LEN);

    int ret = inode_remove_dirent((uint64_t)parent_inum, &dent);
    if (ret != 0) {         
        inode_unlock(target_inum);
        inode_unlock(parent_inum);
        free(dup); free(dup2);
        return ret;
    }

    // Decrement parent nlink (removing ".." from child)
    // inode_lock((uint64_t)parent_inum);
    struct inode parent_node;
    inode_read_from_disk_private((uint64_t)parent_inum, &parent_node);
    if (parent_node.nlink > 2)
    {
        parent_node.nlink--;
    }
    inode_write_to_disk_private((uint64_t)parent_inum, &parent_node);

    // Free target inode and blocks   
    inode_free((uint64_t)target_inum);

    free(dup); free(dup2);
    inode_unlock(target_inum);
    inode_unlock(parent_inum);
    return 0;
}

/*
 * inode_rename: moves a file or directory from one path to another.
 *
 * 1. Updates the '..' entry if a directory is moved.
 * 2. Prevents moving a directory into its own subdirectory.
 * 3. Handles nlink updates for parents.
 */
// Helper: Comparator for qsort (Updated to uint64_t)
static int cmp_u64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t*)a;
    uint64_t vb = *(const uint64_t*)b;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

// Helper: Lock unique inums sorted (Updated to uint64_t)
static uint32_t lock_inums_sorted(uint64_t *inums, uint32_t count) {
    if (!inums || count == 0) return 0;
    qsort(inums, count, sizeof(uint64_t), cmp_u64);
    
    uint32_t write = 0;
    for (uint32_t i = 0; i < count; ++i) {
        // Skip 0 (invalid inode) and duplicates
        if (inums[i] == 0) continue; 
        if (write == 0 || inums[i] != inums[write-1]) {
            inums[write++] = inums[i];
        }
    }
    
    for (uint32_t i = 0; i < write; ++i) {
        // Assuming inode_lock takes uint64_t based on previous files
        inode_lock(inums[i]);
    }
    return write;
}

static void unlock_inums_sorted(uint64_t *inums, uint32_t count) {
    if (!inums) return;
    for (int i = (int)count - 1; i >= 0; --i) {
        inode_unlock(inums[i]);
    }
}

int inode_rename(const char *from, const char *to) {
    if (!from || !to) return -EINVAL;

    int ret = 0;
    char *from_dup = NULL, *to_dup = NULL;
    char *from_dup2 = NULL, *to_dir_dup2 = NULL, *to_base_dup2 = NULL;
    char *from_dir = NULL, *from_base = NULL;
    char *to_dir = NULL, *to_base = NULL;
    uint8_t *scratch = NULL;

    uint64_t from_parent_inum = 0;
    uint64_t to_parent_inum = 0;
    int64_t target_inum = -1; 

    // 1. Basic checks
    if (strcmp(from, to) == 0) return -EINVAL;

    // 2. Allocations
    from_dup = strdup(from);
    to_dup = strdup(to);
    from_dup2 = strdup(from);
    to_dir_dup2 = strdup(to);
    to_base_dup2 = strdup(to);

    if (!from_dup || !to_dup || !from_dup2 || !to_dir_dup2 || !to_base_dup2) { 
        ret = -ENOMEM; goto cleanup; 
    }

    from_dir = dirname(from_dup);
    from_base = basename(from_dup2);
    to_dir = dirname(to_dir_dup2);
    to_base = basename(to_base_dup2);

    // 3. Resolve Parents (No Locks yet)
    int64_t f_pi = inode_find_by_path(from_dir);
    if (f_pi < 0) { ret = (int)f_pi; goto cleanup; }
    from_parent_inum = (uint64_t)f_pi;

    int64_t t_pi = inode_find_by_path(to_dir);
    if (t_pi < 0) { ret = (int)t_pi; goto cleanup; }
    to_parent_inum = (uint64_t)t_pi;

    // 4. Find Target (No Locks yet)
    // We need to know the target inum to include it in the lock list
    // Note: We are reading from_parent without a lock here. This is a race condition,
    // but unavoidable if we want to sort locks to prevent deadlocks. 
    // We will RE-VERIFY target after locking.
    target_inum = inode_find_dirent(from_parent_inum, from_base);
    if (target_inum < 0) { ret = -ENOENT; goto cleanup; }

    // 5. Loop Detection (Moving dir into its own child)
    if (target_inum >= 0) {
        struct inode walk_node;
        uint64_t cur = to_parent_inum;
        
        while (cur != 0 && cur != (uint64_t)target_inum) {
            if (cur == return_root_inode()) break; 

            if (inode_read_from_disk_private(cur, &walk_node) != 0) { ret = -EIO; goto cleanup; }
            
            // Read ".." from block 0
            uint64_t phy = inode_get_block_num(&walk_node, 0);
            
            uint64_t parent_inum = 0;
            if (phy != 0) {
                if (!scratch) { create_buffer((void**)&scratch); if(!scratch) { ret = -ENOMEM; goto cleanup; } }
                
                if (read_data_block(scratch, phy) != 0) { ret = -EIO; goto cleanup; }
                
                directory_entry *ents = (directory_entry*)scratch;
                
                for (uint64_t i = 0; i < dir_entries_per_block(); ++i) {
                    if (ents[i].is_valid && strcmp(ents[i].name, "..") == 0) { 
                        parent_inum = ents[i].inum; 
                        break; 
                    }
                }
            }
            
            if (parent_inum == (uint64_t)target_inum) { ret = -EINVAL; goto cleanup; }
            if (parent_inum == 0 || parent_inum == cur) break; // reached top or error
            cur = parent_inum;
        }
    }

    // 6. SORTED LOCKING (Deadlock Fix)
    uint64_t locks[3];
    locks[0] = from_parent_inum;
    locks[1] = to_parent_inum;
    locks[2] = (target_inum >= 0) ? (uint64_t)target_inum : 0; // Don't lock if target invalid

    uint32_t lock_count = lock_inums_sorted(locks, 3);

    // 7. Re-Validation (Critical after locking)
    // Check if target is still there
    int64_t re_target = inode_find_dirent(from_parent_inum, from_base);
    if (re_target < 0 || re_target != target_inum) { ret = -ENOENT; goto locked_cleanup; }

    // Check if dest exists
    int dest_exists = inode_find_dirent(to_parent_inum, to_base);
    if (dest_exists >= 0) { ret = -EEXIST; goto locked_cleanup; }

    // 8. Perform Rename Operations
    
    // A. Add to new parent
    directory_entry new_val;
    memset(&new_val, 0, sizeof(new_val));
    new_val.inum = (uint64_t)target_inum;
    new_val.is_valid = 1;
    strncpy(new_val.name, to_base, MAX_FILENAME_LEN);
    // strncpy pads with nulls, but manual set is safe
    new_val.name[MAX_FILENAME_LEN] = '\0'; 

    ret = inode_add_dirent(to_parent_inum, &new_val);
    if (ret != 0) goto locked_cleanup;

    // B. Remove from old parent
    directory_entry old_val;
    memset(&old_val, 0, sizeof(old_val));
    old_val.inum = (uint64_t)target_inum;
    strncpy(old_val.name, from_base, MAX_FILENAME_LEN);
    old_val.name[MAX_FILENAME_LEN] = '\0';

    ret = inode_remove_dirent(from_parent_inum, &old_val);
    if (ret != 0) {
        // Rollback: remove the entry we just added
        inode_remove_dirent(to_parent_inum, &new_val);
        goto locked_cleanup;
    }

    // C. Update ".." if Directory
    struct inode target_node;
    if (inode_read_from_disk_private((uint64_t)target_inum, &target_node) != 0) { ret = -EIO; goto locked_cleanup; }

    if (S_ISDIR(target_node.mode) && from_parent_inum != to_parent_inum) {
        struct inode from_p_node, to_p_node;
        inode_read_from_disk_private(from_parent_inum, &from_p_node);
        inode_read_from_disk_private(to_parent_inum, &to_p_node);

        if (from_p_node.nlink > 0) from_p_node.nlink--;
        to_p_node.nlink++;

        inode_write_to_disk_private(from_parent_inum, &from_p_node);
        inode_write_to_disk_private(to_parent_inum, &to_p_node);

        // Update ".." inside the moved directory
        if (!scratch) create_buffer((void**)&scratch);
        
        // FIX: Signature match
        uint64_t old_phy_blk = inode_get_block_num(&target_node, 0); 
        
        if (old_phy_blk != 0) {
            if (read_data_block(scratch, old_phy_blk) != 0) { ret = -EIO; goto locked_cleanup; }

            directory_entry *ents = (directory_entry*)scratch;
            int updated = 0;
            for (uint64_t i = 0; i < dir_entries_per_block(); ++i) {
                if (ents[i].is_valid && strcmp(ents[i].name, "..") == 0) {
                    ents[i].inum = to_parent_inum;
                    updated = 1;
                    break;
                }
            }

            if (updated) {
                uint64_t new_phy_blk = 0;
                
                if (write_to_next_free_block(scratch, &new_phy_blk) != 0) { ret = -EIO; goto locked_cleanup; }

                // FIX: inode_set_block_num in inode.c ALREADY frees the old block.
                // Do NOT call free_data_block(old_phy_blk) here manually.
                if (inode_set_block_num((uint64_t)target_inum, &target_node, 0, new_phy_blk) != 0) {
                    free_data_block(new_phy_blk); // free new one if set failed
                    ret = -EIO; goto locked_cleanup;
                }

                inode_write_to_disk_private((uint64_t)target_inum, &target_node);
            }
        }
    }

    ret = 0;

locked_cleanup:
    unlock_inums_sorted(locks, lock_count);

cleanup:
    if (from_dup) free(from_dup);
    if (to_dup) free(to_dup);
    if (from_dup2) free(from_dup2);
    if (to_dir_dup2) free(to_dir_dup2);
    if (to_base_dup2) free(to_base_dup2);
    if (scratch) free(scratch);
    return ret;
}


/* -------------------------
 * Extended Attributes (xattr)
 * * Implementation:
 * We repurpose the first 4 bytes of 'padding' in struct inode to store
 * a pointer to a single block containing all xattrs.
 * Block format: [Total Size (4b)] [Entry1] [Entry2] ...
 * Entry format: [KeyLen (1b)] [Key String] [ValLen (4b)] [Value Bytes]
 * ------------------------- */

// Helper to get/set the xattr block number from padding
static uint64_t get_xattr_block_num(const struct inode *node) {
    uint64_t block_num;
    memcpy(&block_num, &node->extended_attributes, sizeof(uint64_t));
    return block_num;
}

static void set_xattr_block_num(struct inode *node, uint64_t block_num) {
    memcpy(&node->extended_attributes, &block_num, sizeof(uint64_t));
}

int inode_setxattr(uint64_t inode, const char* key, const char* val, size_t len, int flags) {
    if (strlen(key) > 255) return -ENAMETOOLONG;

    inode_lock(inode);
    struct inode node;
    inode_read_from_disk_private(inode, &node);

    uint64_t blk = get_xattr_block_num(&node);
    uint8_t *buffer;
    create_buffer((void**)&buffer);
    if (!buffer) { inode_unlock(inode); return -ENOMEM; }
    memset(buffer, 0, BYTES_PER_BLOCK);

    if (blk != 0) {
        if (read_data_block(buffer, blk) != 0) {
            free(buffer); inode_unlock(inode); return -EIO;
        }
    }

    // Simple implementation: Linear scan. 
    // We reconstruct the block in a temp buffer to handle add/replace
    uint8_t *new_buf;
    create_buffer((void**)&new_buf);
    if (!new_buf) { free(buffer); inode_unlock(inode); return -ENOMEM; }
    memset(new_buf, 0, BYTES_PER_BLOCK);

    uint64_t old_offset = 4; // skip size header
    uint64_t new_offset = 4;
    uint64_t total_data_size = *((uint64_t*)buffer);
    // int found = 0;

    // Copy existing entries, skipping if we match key
    while (old_offset < total_data_size + 4 && old_offset < BYTES_PER_BLOCK) {
        uint8_t key_len = buffer[old_offset];
        char *curr_key = (char*)(buffer + old_offset + 1);
        uint64_t val_len = *((uint64_t*)(buffer + old_offset + 1 + key_len));
        uint64_t entry_size = 1 + key_len + 4 + val_len;

        if (strncmp(curr_key, key, key_len) == 0 && strlen(key) == key_len) {
            // found = 1;
            // Skip this entry (we will append new version later)
        } else {
            // Keep this entry
            if (new_offset + entry_size > BYTES_PER_BLOCK) {
                free(buffer); free(new_buf); inode_unlock(inode); return -ENOSPC;
            }
            memcpy(new_buf + new_offset, buffer + old_offset, entry_size);
            new_offset += entry_size;
        }
        old_offset += entry_size;
    }

    // Append new entry
    uint8_t klen = (uint8_t)strlen(key);
    uint64_t vlen = (uint64_t)len;
    uint64_t new_entry_size = 1 + klen + 4 + vlen;

    // todo: ?? think about extending into multiple block
    if (new_offset + new_entry_size > BYTES_PER_BLOCK) {
        free(buffer); free(new_buf); inode_unlock(inode); return -ENOSPC;
    }

    new_buf[new_offset] = klen;
    memcpy(new_buf + new_offset + 1, key, klen);
    memcpy(new_buf + new_offset + 1 + klen, &vlen, 4);
    memcpy(new_buf + new_offset + 1 + klen + 4, val, vlen);
    new_offset += new_entry_size;

    // Update total size
    *((uint64_t*)new_buf) = new_offset - 4;

    // Write to disk (CoW)
    uint64_t new_blk_phy = 0;
    if (write_to_next_free_block(new_buf, &new_blk_phy) != 0) {
        free(buffer); free(new_buf); inode_unlock(inode); return -EIO;
    }

    // Free old block
    if (blk != 0) free_data_block(blk);

    // Update inode padding
    set_xattr_block_num(&node, new_blk_phy);
    inode_write_to_disk_private(inode, &node);

    free(buffer);
    free(new_buf);
    inode_unlock(inode);
    return 0;
}

int inode_getxattr(uint64_t inode, const char* key, const char* val, size_t len) {
    inode_lock(inode);
    struct inode node;
    inode_read_from_disk_private(inode, &node);

    uint64_t blk = get_xattr_block_num(&node);
    if (blk == 0) { inode_unlock(inode); return -ENODATA; }

    uint8_t *buffer;
    create_buffer((void**)&buffer);
    if (!buffer) { inode_unlock(inode); return -ENOMEM; }

    if (read_data_block(buffer, blk) != 0) {
        free(buffer); inode_unlock(inode); return -EIO;
    }

    uint64_t offset = 4;
    uint64_t total_size = *((uint64_t*)buffer);

    while (offset < total_size + 4 && offset < BYTES_PER_BLOCK) {
        uint8_t key_len = buffer[offset];
        char *curr_key = (char*)(buffer + offset + 1);
        uint64_t val_len = *((uint64_t*)(buffer + offset + 1 + key_len));
        
        if (strncmp(curr_key, key, key_len) == 0 && strlen(key) == key_len) {
            // Found
            if (len == 0) {
                // Query size
                free(buffer); inode_unlock(inode); return (int)val_len;
            }
            if (len < val_len) {
                free(buffer); inode_unlock(inode); return -ERANGE;
            }
            memcpy((void*)val, buffer + offset + 1 + key_len + 4, val_len);
            free(buffer); inode_unlock(inode);
            return (int)val_len;
        }
        offset += (1 + key_len + 4 + val_len);
    }

    free(buffer);
    inode_unlock(inode);
    return -ENODATA;
}

int inode_listxattr(uint64_t inode, char* val, size_t len) {
    inode_lock(inode);
    struct inode node;
    inode_read_from_disk_private(inode, &node);

    uint64_t blk = get_xattr_block_num(&node);
    if (blk == 0) { inode_unlock(inode); return 0; }

    uint8_t *buffer;
    create_buffer((void**)&buffer);
    if (!buffer) { inode_unlock(inode); return -ENOMEM; }
    if (read_data_block(buffer, blk) != 0) {
        free(buffer); inode_unlock(inode); return -EIO;
    }

    uint64_t offset = 4;
    uint64_t total_size = *((uint64_t*)buffer);
    size_t required_len = 0;

    // First pass: calculate size
    uint64_t temp_off = 4;
    while (temp_off < total_size + 4) {
        uint8_t klen = buffer[temp_off];
        uint64_t vlen = *((uint64_t*)(buffer + temp_off + 1 + klen));
        required_len += klen + 1; // +1 for null terminator
        temp_off += (1 + klen + 4 + vlen);
    }

    if (len == 0) {
        free(buffer); inode_unlock(inode); return (int)required_len;
    }
    if (len < required_len) {
        free(buffer); inode_unlock(inode); return -ERANGE;
    }

    // Second pass: copy keys
    char *dest = val;
    while (offset < total_size + 4) {
        uint8_t klen = buffer[offset];
        memcpy(dest, buffer + offset + 1, klen);
        dest[klen] = '\0';
        dest += (klen + 1);
        uint64_t vlen = *((uint64_t*)(buffer + offset + 1 + klen));
        offset += (1 + klen + 4 + vlen);
    }

    free(buffer);
    inode_unlock(inode);
    return (int)required_len;
}

int inode_removexattr(uint64_t inode, const char* key) {
    inode_lock(inode);
    struct inode node;
    inode_read_from_disk_private(inode, &node);

    uint64_t blk = get_xattr_block_num(&node);
    if (blk == 0) { inode_unlock(inode); return -ENODATA; }

    uint8_t *buffer;
    create_buffer((void**)&buffer);
    if (!buffer) { inode_unlock(inode); return -ENOMEM; }
    if (read_data_block(buffer, blk) != 0) {
        free(buffer); inode_unlock(inode); return -EIO;
    }

    uint8_t *new_buf;
    create_buffer((void**)&new_buf); 
    
    if (!new_buf) { free(buffer); inode_unlock(inode); return -ENOMEM; }
    memset(new_buf, 0, BYTES_PER_BLOCK);

    uint64_t old_offset = 4;
    uint64_t new_offset = 4;
    uint64_t total_data_size = *((uint64_t*)buffer);
    int found = 0;

    while (old_offset < total_data_size + 4) {
        uint8_t key_len = buffer[old_offset];
        char *curr_key = (char*)(buffer + old_offset + 1);
        uint64_t val_len = *((uint64_t*)(buffer + old_offset + 1 + key_len));
        uint64_t entry_size = 1 + key_len + 4 + val_len;

        if (strncmp(curr_key, key, key_len) == 0 && strlen(key) == key_len) {
            found = 1;
            // Skip -> removes it
        } else {
            memcpy(new_buf + new_offset, buffer + old_offset, entry_size);
            new_offset += entry_size;
        }
        old_offset += entry_size;
    }

    if (!found) {
        free(buffer); free(new_buf); inode_unlock(inode); return -ENODATA;
    }

    *((uint64_t*)new_buf) = new_offset - 4;

    uint64_t new_blk_phy = 0;
    if (write_to_next_free_block(new_buf, &new_blk_phy) != 0) {
        free(buffer); free(new_buf); inode_unlock(inode); return -EIO;
    }

    free_data_block(blk);
    set_xattr_block_num(&node, new_blk_phy);
    inode_write_to_disk_private(inode, &node);

    free(buffer);
    free(new_buf);
    inode_unlock(inode);
    return 0;
}


int inode_link(uint64_t src_inum, const char *newpath) {
    // 1. Parse newpath parent/base
    char *dup = strdup(newpath);
    char *dup2 = strdup(newpath);
    char *dir = dirname(dup);
    char *base = basename(dup2);
    
    int parent_inum = inode_find_by_path(dir);
    if (parent_inum < 0) { free(dup); free(dup2); return parent_inum; }

    // 2. Increment Link Count on Source
    inode_lock(src_inum);
    struct inode node;
    inode_read_from_disk_private(src_inum, &node);
    node.nlink++;
    node.ctime = time(NULL);
    inode_write_to_disk_private(src_inum, &node);
    inode_unlock(src_inum);

    // 3. Add directory entry
    directory_entry ent;
    ent.inum = src_inum;
    strncpy(ent.name, base, MAX_FILENAME_LEN);
    int res = inode_add_dirent(parent_inum, &ent);
    
    if (res != 0) {
        // Rollback link count if add_dirent fails
        inode_lock(src_inum);
        inode_read_from_disk_private(src_inum, &node);
        node.nlink--;
        inode_write_to_disk_private(src_inum, &node);
        inode_unlock(src_inum);
    }
    
    free(dup); free(dup2);
    return res;
}