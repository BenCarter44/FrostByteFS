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

// Directory entry stored in a directory data block.
// Keep size fixed to pack nicely into BYTES_PER_BLOCK.
typedef struct directory_entry {
    uint32_t inum;
    char name[MAX_FILENAME_LEN + 1];
    int is_valid;
} directory_entry;

// Global per-inode locking structure. Must be initialized at mount time.
static pthread_mutex_t *inode_locks = NULL;
static uint32_t g_max_inodes = 0;

int inline return_root_inode()
{
    return 1;
}

void inode_global_init() {
    uint32_t max_inodes = MAX_INODES;
    if (inode_locks != NULL && g_max_inodes == max_inodes) {
        return;
    }

    if (inode_locks) {
        for (uint32_t i = 0; i < g_max_inodes; ++i) {
            pthread_mutex_destroy(&inode_locks[i]);
        }

        free(inode_locks);
    }

    inode_locks = calloc(max_inodes, sizeof(pthread_mutex_t));

    if (!inode_locks) {
        perror("inode_global_init: calloc failed");
        exit(1);
    }

    for (uint32_t i = 0; i < max_inodes; ++i) {
        pthread_mutex_init(&inode_locks[i], NULL);
    }

    g_max_inodes = max_inodes;
}

static inline void inode_lock(uint32_t inum) {
    if (inode_locks && inum < g_max_inodes) {
        pthread_mutex_lock(&inode_locks[inum]);
    }
}

static inline void inode_unlock(uint32_t inum) {
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
static uint32_t set_block_recursive(uint32_t old_blocknum, uint32_t level,
                                    uint64_t logical_index, uint32_t new_data_block,
                                    uint8_t *scratch);

static int inode_truncate_recursive(uint32_t blocknum, uint32_t level, uint64_t *blocks_to_free, uint8_t *scratch);

static int inode_read_from_disk_private(uint32_t inum, struct inode *out);
static int inode_write_to_disk_private(uint32_t inum, const struct inode *node);
static ssize_t inode_read_private(uint32_t inum, void *buf, size_t size, off_t offset);
static ssize_t inode_write_private(uint32_t inum, const void *buf, size_t size, off_t offset);
int inode_truncate_private(uint32_t inum, off_t newsize);

/* -------------------------
 * Basic inode read/write
 * ------------------------- */

int inode_read_from_disk(uint32_t inum, struct inode *out)
{
    inode_lock(inum);
    int r = inode_read_from_disk_private(inum, out);
    inode_unlock(inum);
    return r;
}

static int inode_read_from_disk_private(uint32_t inum, struct inode *out) {
    uint32_t block_num = INODE_TABLE_START_BLOCK + (inum / INODES_PER_BLOCK);
    uint32_t idx = inum % INODES_PER_BLOCK;

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

int inode_write_to_disk(uint32_t inum, const struct inode *node)
{
    inode_lock(inum);
    int r = inode_write_to_disk_private(inum, node);
    inode_unlock(inum);
    return r;
}


static int inode_write_to_disk_private(uint32_t inum, const struct inode *node) {
    uint32_t block_num = INODE_TABLE_START_BLOCK + (inum / INODES_PER_BLOCK);
    uint32_t idx = inum % INODES_PER_BLOCK;

    uint8_t *buf;
    create_buffer((void**)&buf);
    
    if (!buf) {
        return -INODE_BUFFER_ALLOCATION_FAILED;
    }
    
    // todo: should be continued or return error code
    printf("Save INODE blk read: %u\n", block_num);
    if (read_inode_block(buf, block_num) != 0) {
        // If we cannot read, try to zero buffer (new FS) and continue
        memset(buf, 0, BYTES_PER_BLOCK);
    }

    memcpy(((uint8_t*)buf) + idx * sizeof(struct inode), node, sizeof(struct inode));

    int rc = 0;
    printf("Read INODE blk: %u\n", block_num);
    rc = write_inode_block(buf, block_num);

    free_buffer(buf);

    return rc;
}


/* -------------------------
 * Inode bitmap allocation
 * ------------------------- */

int inode_alloc(uint32_t *out_inum) {
    uint8_t *bytes;
    create_buffer((void**)&bytes);

    if (!bytes) {
        return -INODE_BUFFER_ALLOCATION_FAILED;
    }

    // Scan inode bitmap blocks
    // bitmap region is first blocks of inode region
    for (uint32_t b = 0; b < INODE_BITMAP_BLOCKS; ++b) {
        uint32_t blocknum = b;

        int ret = read_inode_block(bytes, blocknum);

        if (ret != 0) {
            free(bytes);
            return ret;
        }

        for (uint32_t byte = 0; byte < BYTES_PER_BLOCK; ++byte) {
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

                    uint32_t bit_index = (b * BYTES_PER_BLOCK * 8) + (byte * 8) + bit;
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

int inode_free(uint32_t inum) {
    uint8_t *buf;
    create_buffer((void**)&buf);
    
    if (!buf) {
        return -INODE_BUFFER_ALLOCATION_FAILED;
    }

    uint32_t bit = inum;
    uint32_t b = bit / (BYTES_PER_BLOCK*8);
    uint32_t byte_idx = (bit % (BYTES_PER_BLOCK*8)) / 8;
    uint32_t bit_in_byte = bit % 8;

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

/*
 * inode_get_block_num:
 *   Map a logical block index (0-based) to a physical block number or 0 if hole.
 *   Returns 0 if not allocated or negative errno if read error (we return 0
 *   for "no block" and reserve errors for write operations).
 */
uint32_t inode_get_block_num(const struct inode *node, uint64_t logical_block, uint8_t *scratch) {
    // Direct blocks
    if (logical_block < NUM_DIRECT_BLOCKS) {
        return node->direct_blocks[logical_block];
    }

    logical_block -= NUM_DIRECT_BLOCKS;

    int ret = 0;

    // Single indirect
    if (logical_block < (uint64_t)POINTERS_PER_BLOCK) {
        uint32_t sb = node->single_indirect;

        if (!sb) return 0;

        ret = read_data_block(scratch, sb);
        if (ret != 0) return ret;

        uint32_t *ptrs = (uint32_t*)scratch;

        return ptrs[logical_block];
    }

    logical_block -= (uint64_t)POINTERS_PER_BLOCK;

    // Double indirect
    uint64_t dbl_range = (uint64_t)POINTERS_PER_BLOCK * POINTERS_PER_BLOCK;

    if (logical_block < dbl_range) {
        uint32_t db = node->double_indirect;

        if (!db) return 0;

        ret = read_data_block(scratch, db);
        if (ret != 0) return ret;

        uint32_t *level1 = (uint32_t*)scratch;
        uint32_t idx1 = (uint32_t)(logical_block / POINTERS_PER_BLOCK);
        uint32_t idx2 = (uint32_t)(logical_block % POINTERS_PER_BLOCK);
        uint32_t level1_block = level1[idx1];

        if (!level1_block) return 0;

        ret = read_data_block(scratch, level1_block);
        if (ret != 0) return ret;

        uint32_t *level0 = (uint32_t*)scratch;
        return level0[idx2];
    }

    logical_block -= dbl_range;

    // Triple indirect
    uint64_t tpl_range = (uint64_t)POINTERS_PER_BLOCK * POINTERS_PER_BLOCK * POINTERS_PER_BLOCK;

    if (logical_block < tpl_range) {
        uint32_t tb = node->triple_indirect;
        if (!tb) return 0;

        // level 2 block
        ret = read_data_block(scratch, tb);
        if (ret != 0) return ret;

        uint32_t *lvl2 = (uint32_t*)scratch;
        uint64_t per_lvl2 = (uint64_t)POINTERS_PER_BLOCK * POINTERS_PER_BLOCK;
        uint32_t i2 = (uint32_t)(logical_block / per_lvl2);
        uint64_t rem = logical_block % per_lvl2;
        uint32_t lvl1_block = lvl2[i2];
        if (!lvl1_block) return 0;

        ret = read_data_block(scratch, lvl1_block);
        if (ret != 0) return ret;

        uint32_t *lvl1 = (uint32_t*)scratch;
        uint32_t i1 = (uint32_t)(rem / POINTERS_PER_BLOCK);
        uint32_t i0 = (uint32_t)(rem % POINTERS_PER_BLOCK);
        uint32_t lvl0_block = lvl1[i1];
        if (!lvl0_block) return 0;

        ret = read_data_block(scratch, lvl0_block);
        if (ret != 0) return ret;

        uint32_t *lvl0 = (uint32_t*)scratch;
        return lvl0[i0];
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
static uint32_t set_block_recursive(uint32_t old_blocknum, uint32_t level,
                                    uint64_t logical_index, uint32_t new_data_block,
                                    uint8_t *scratch)
{
    int ret = 0;
    uint32_t *ptrs = (uint32_t*)scratch;

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
        uint32_t idx = (uint32_t)(logical_index / subtree_size);
        uint64_t remainder = logical_index % subtree_size;

        uint32_t child_old = ptrs[idx];
        uint32_t child_new = set_block_recursive(child_old, level - 1, remainder, new_data_block, scratch);

        // note: we reuse scratch for children as recursive call writes/read into it and returns
        if (child_new == 0 && child_old != 0) {
            // child update failed (I/O)
            return -INODE_CHILD_UPDATE_FAILED;
        }

        ptrs[idx] = child_new;
    }

    // write updated pointer block to a new physical block (CoW)
    uint32_t new_blocknum = 0;

    ret = write_to_next_free_block((const uint8_t*)ptrs, &new_blocknum);
    if (ret != 0) return ret;

    // Free old pointer block after successful write (decrement refcount)
    if (old_blocknum != 0) {
        free_data_block(old_blocknum);
    }

    return new_blocknum;
}

/*
 * inode_set_block_num:
 *   Public wrapper to set logical_block -> new_physical_block in the inode's
 *   pointer tree. This performs CoW of pointer blocks and frees old data blocks
 *   when appropriate (for direct blocks we free the old block immediately).
 *
 *   Returns 0 on success or negative errno.
 */
int inode_set_block_num(uint32_t inum, struct inode *node,
                        uint64_t logical_block, uint32_t new_physical_block)
{
    uint8_t *scratch;
    create_buffer((void**)&scratch);
    if (!scratch) return -INODE_BUFFER_ALLOCATION_FAILED;

    int rc = 0;
    int ret = 0;

    if (logical_block < NUM_DIRECT_BLOCKS) {
        uint32_t old = node->direct_blocks[logical_block];
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
        uint32_t old_ptr = node->single_indirect;
        uint32_t new_ptr = set_block_recursive(old_ptr, 1, logical_block, new_physical_block, scratch);

        if (new_ptr <= 0) rc = new_ptr;
        else node->single_indirect = new_ptr;

        free(scratch);
        return rc;
    }

    logical_block -= (uint64_t)POINTERS_PER_BLOCK;

    // double
    uint64_t dbl_range = (uint64_t)POINTERS_PER_BLOCK * POINTERS_PER_BLOCK;

    if (logical_block < dbl_range) {
        uint32_t old_ptr = node->double_indirect;
        uint32_t new_ptr = set_block_recursive(old_ptr, 2, logical_block, new_physical_block, scratch);

        if (new_ptr <= 0) rc = new_ptr;
        else node->double_indirect = new_ptr;

        free(scratch);
        return rc;
    }

    logical_block -= dbl_range;

    // triple
    uint64_t tpl_range = (uint64_t)POINTERS_PER_BLOCK * POINTERS_PER_BLOCK * POINTERS_PER_BLOCK;

    if (logical_block < tpl_range) {
        uint32_t old_ptr = node->triple_indirect;
        uint32_t new_ptr = set_block_recursive(old_ptr, 3, logical_block, new_physical_block, scratch);

        if (new_ptr <= 0) rc = new_ptr;
        else node->triple_indirect = new_ptr;

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
 * inode_truncate_recursive:
 *   Frees all data blocks (and intermediate pointer blocks) under a pointer block at a given level.
 *
 * Parameters:
 *   - blocknum: physical block number of this pointer block
 *   - level: indirection level (1 = points directly to data blocks)
 *   - blocks_to_free: pointer to a counter of how many data blocks to free
 *   - scratch: temporary buffer (BYTES_PER_BLOCK)
 *
 * Returns:
 *   0 on success, negative errno on error.
 */
static int inode_truncate_recursive(uint32_t blocknum, uint32_t level,
                                    uint64_t *blocks_to_free, uint8_t *scratch)
{
    if (blocknum == 0 || *blocks_to_free == 0)
        return 0;  // nothing to do

    int ret = read_data_block(scratch, blocknum);
    if (ret != 0)
        return ret;

    uint32_t *ptrs = (uint32_t*)scratch;

    if (level == 1) {
        // This level points directly to data blocks
        for (uint32_t i = 0; i < POINTERS_PER_BLOCK && *blocks_to_free > 0; ++i) {
            if (ptrs[i] != 0) {
                free_data_block(ptrs[i]);

                ptrs[i] = 0;
                (*blocks_to_free)--;  // decrement global counter
            }
        }
    } else {
        // This level points to lower-level pointer blocks
        for (uint32_t i = 0; i < POINTERS_PER_BLOCK && *blocks_to_free > 0; ++i) {
            if (ptrs[i] != 0) {
                // Recursively free all blocks under this subtree
                ret = inode_truncate_recursive(ptrs[i], level - 1, blocks_to_free, scratch);
                if (ret != 0) return ret;

                // After all children freed, free this child pointer block
                free_data_block(ptrs[i]);
                ptrs[i] = 0;
            }
        }
    }

    // Optionally, write updated pointer block back to disk if you want consistency
    // write_data_block(scratch, blocknum);

    return 0;
}


/*
 * inode_truncate(inum, newsize)
 *   Supports both grow and shrink.
 *   If shrinking: zeroes tail of last kept block (CoW) and frees later blocks.
 */
int inode_truncate(uint32_t inum, off_t newsize) {
    inode_lock(inum);
    int r = inode_truncate_private(inum, newsize);
    inode_unlock(inum);
    return r;
}
int inode_truncate_private(uint32_t inum, off_t newsize) {
    if (newsize < 0) return -EINVAL;

    int ret = 0;
    struct inode node;
    inode_read_from_disk_private(inum, &node);

    uint64_t oldsize = node.size;

    if ((off_t)oldsize == newsize) { 
        return 0; 
    }

    uint8_t *scratch;
    create_buffer((void**)&scratch);

    if (!scratch) { 
        return -INODE_BUFFER_ALLOCATION_FAILED; 
    }

    if (newsize > oldsize) {
        // growing: allocate zero-filled blocks up to newsize (sparse handling allowed)
        // We choose not to pre-allocate blocks for holes; writes will allocate.
        node.size = newsize;
        node.mtime = node.ctime = time(NULL);
        inode_write_to_disk_private(inum, &node);
        free(scratch);
        return 0;
    }

    // shrinking
    uint64_t keep_bytes = (uint64_t)newsize;
    uint64_t keep_blocks = (keep_bytes + BYTES_PER_BLOCK - 1) / BYTES_PER_BLOCK; // ceil
    uint64_t old_blocks = (oldsize + BYTES_PER_BLOCK - 1) / BYTES_PER_BLOCK;

    if (keep_blocks == old_blocks) {
        // file shrunk within the last block -> zero tail bytes in last block (CoW)
        if (keep_bytes % BYTES_PER_BLOCK == 0) {
            // exactly on block boundary => nothing to keep in last block

        } else {
            uint64_t last_logical = (keep_blocks == 0) ? 0 : (keep_blocks - 1);
            // Read existing last block (if any), zero tail, write to new block (CoW), update pointers
            uint32_t old_phy = inode_get_block_num(&node, last_logical, scratch);
            
            uint8_t *blockbuf = scratch;
            memset(blockbuf, 0, BYTES_PER_BLOCK);

            if (old_phy != 0) {
                ret = read_data_block(blockbuf, old_phy);

                if (ret != 0) {
                    free(scratch);
                    return ret;
                }
            }

            // zero tail
            uint32_t keep_off = (uint32_t)(keep_bytes % BYTES_PER_BLOCK);

            if (keep_off == 0) keep_off = BYTES_PER_BLOCK; // keep entire block

            if (keep_off < BYTES_PER_BLOCK) {
                memset(blockbuf + keep_off, 0, BYTES_PER_BLOCK - keep_off);
            }

            // write new block and update pointer tree
            uint32_t new_phy = 0;

            ret = write_to_next_free_block(blockbuf, &new_phy);

            if (ret != 0) {
                free(scratch);
                return ret;
            }

            ret = inode_set_block_num(inum, &node, last_logical, new_phy);

            if (ret != 0) {
                // If inode_set_block_num failed, free the new block we allocated
                free_data_block(new_phy);
                free(scratch);
                return ret;
            }

            // write inode to persist pointer change
            node.size = newsize;
            node.mtime = node.ctime = time(NULL);

            inode_write_to_disk_private(inum, &node);
            free(scratch);
            return 0;
        }
    }

    // General case: free all blocks >= keep_blocks
    uint64_t to_free_blocks = (old_blocks > keep_blocks) ? (old_blocks - keep_blocks) : 0;

    // 1) If keep_blocks == 0, we must free direct blocks and all indirect trees
    // For direct blocks: free entries with index >= keep_blocks
    for (uint64_t i = keep_blocks; i < NUM_DIRECT_BLOCKS && to_free_blocks > 0; ++i) {
        uint32_t old_phy = node.direct_blocks[i];

        if (old_phy != 0) {
            free_data_block(old_phy);

            node.direct_blocks[i] = 0;
            to_free_blocks--;
        }
    }

    // 2) For single/double/triple indirect, compute how many blocks remain in each region
    // We'll free subtrees as needed using inode_truncate_recursive.

    // SINGLE
    if (to_free_blocks > 0) {
        uint64_t single_total = POINTERS_PER_BLOCK;
        // which logical blocks correspond to single region start?
        uint64_t first_single = NUM_DIRECT_BLOCKS;

        if (keep_blocks <= first_single) {
            // entire single region freed
            if (node.single_indirect) {
                uint64_t blocks_sub = to_free_blocks;

                ret = inode_truncate_recursive(node.single_indirect, 1, &blocks_sub, scratch);

                if (ret != 0) {
                    free(scratch);
                    return ret;
                }

                free_data_block(node.single_indirect);

                node.single_indirect = 0;

                // adjust to_free_blocks
                if (to_free_blocks >= single_total) {
                    to_free_blocks -= single_total;

                } else {
                    to_free_blocks = 0;
                }
            }

        } else {
            // partial free: free entries with index >= keep_blocks-first_single
            uint64_t keep_in_single = (keep_blocks > first_single) ? (keep_blocks - first_single) : 0;

            if (keep_in_single < single_total && node.single_indirect) {
                // Read pointer block
                ret = read_data_block(scratch, node.single_indirect);

                if (ret != 0) {
                    free(scratch);
                    return ret;
                }

                uint32_t *ptrs = (uint32_t*)scratch;

                for (uint32_t i = (uint32_t)keep_in_single; i < POINTERS_PER_BLOCK && to_free_blocks > 0; ++i) {
                    if (ptrs[i]) {
                        free_data_block(ptrs[i]);

                        ptrs[i] = 0;
                        to_free_blocks--;
                    }
                }

                // write updated pointer block CoW style: write new pointer block and free old
                uint32_t newptr = 0;

                ret = write_to_next_free_block(scratch, &newptr);

                if (ret != 0) {
                    free(scratch);
                    return ret;
                }

                free_data_block(node.single_indirect);
                node.single_indirect = newptr;
            }
        }
    }

    // DOUBLE
    if (to_free_blocks > 0) {
        uint64_t first_double = NUM_DIRECT_BLOCKS + POINTERS_PER_BLOCK;
        uint64_t double_total = (uint64_t)POINTERS_PER_BLOCK * POINTERS_PER_BLOCK;

        if (keep_blocks <= first_double) {
            // free entire double region
            if (node.double_indirect) {
                uint64_t blocks_sub = to_free_blocks;

                if (inode_truncate_recursive(node.double_indirect, 2, &blocks_sub, scratch) != 0) {
                    free(scratch);
                    return -EIO;
                }

                free_data_block(node.double_indirect);
                node.double_indirect = 0;
                if (to_free_blocks >= double_total) {
                    to_free_blocks -= double_total;

                } else {
                    to_free_blocks = 0;
                }
            }
        } else {
            // partial
            uint64_t keep_in_double = (keep_blocks > first_double) ? (keep_blocks - first_double) : 0;

            if (keep_in_double < double_total && node.double_indirect) {
                // iterate over level1 pointers and free children as needed
                if (read_data_block(scratch, node.double_indirect) != 0) {
                    free(scratch);
                    return -EIO;
                }

                uint32_t *l1 = (uint32_t*)scratch;

                for (uint32_t idx = 0; idx < POINTERS_PER_BLOCK && to_free_blocks > 0; ++idx) {
                    uint64_t chunk_start = (uint64_t)idx * POINTERS_PER_BLOCK;
                    uint64_t chunk_end = chunk_start + POINTERS_PER_BLOCK;

                    if (keep_in_double >= chunk_end) continue; // this chunk wholly kept

                    if (l1[idx]) {
                        // compute how many in this chunk to free
                        uint64_t keep_here = 0;

                        if (keep_in_double > chunk_start) {
                            keep_here = keep_in_double - chunk_start;
                        }

                        uint64_t to_free_here = (uint64_t)POINTERS_PER_BLOCK - keep_here;

                        if (to_free_here > 0) {
                            uint64_t blocks_sub = to_free_here;

                            if (inode_truncate_recursive(l1[idx], 1, &blocks_sub, scratch) != 0) {
                                free(scratch);
                                return -EIO;
                            }

                            // After freeing children, free the child pointer block
                            free_data_block(l1[idx]);
                            l1[idx] = 0;
                            
                            if (to_free_blocks >= blocks_sub) {
                                to_free_blocks -= blocks_sub;

                            } else {
                                to_free_blocks = 0;
                            }
                        }
                    }
                }

                // write updated level1 pointer block CoW style
                uint32_t new_l1 = 0;

                if (write_to_next_free_block(scratch, &new_l1) != 0) {
                    free(scratch);
                    return -EIO;
                }

                free_data_block(node.double_indirect);
                node.double_indirect = new_l1;
            }
        }
    }

    // TRIPLE
    if (to_free_blocks > 0) {
        uint64_t first_triple = NUM_DIRECT_BLOCKS + POINTERS_PER_BLOCK + (uint64_t)POINTERS_PER_BLOCK * POINTERS_PER_BLOCK;
        uint64_t triple_total = (uint64_t)POINTERS_PER_BLOCK * POINTERS_PER_BLOCK * POINTERS_PER_BLOCK;
        
        if (keep_blocks <= first_triple) {
            if (node.triple_indirect) {
                uint64_t blocks_sub = to_free_blocks;

                if (inode_truncate_recursive(node.triple_indirect, 3, &blocks_sub, scratch) != 0) {
                    free(scratch);
                    return -EIO;
                }

                free_data_block(node.triple_indirect);
                node.triple_indirect = 0;

                if (to_free_blocks >= triple_total) {
                    to_free_blocks -= triple_total;
                } else {
                    to_free_blocks = 0;
                }
            }

        } else {
            // partial: similar to double but one more level; implement to free appropriate subtrees.
            // For brevity and clarity: use a simple approach: iterate triple-level entries and free subtrees whose ranges are > keep.
            if (node.triple_indirect) {
                if (read_data_block(scratch, node.triple_indirect) != 0) {
                    free(scratch);
                    return -EIO;
                }

                uint32_t *l2 = (uint32_t*)scratch;
                uint64_t per_l2 = (uint64_t)POINTERS_PER_BLOCK * POINTERS_PER_BLOCK;
                uint64_t keep_in_triple = (keep_blocks > first_triple) ? (keep_blocks - first_triple) : 0;

                for (uint32_t i2 = 0; i2 < POINTERS_PER_BLOCK && to_free_blocks > 0; ++i2) {
                    uint64_t chunk_start = (uint64_t)i2 * per_l2;
                    uint64_t chunk_end = chunk_start + per_l2;

                    if (keep_in_triple >= chunk_end) continue; // keep entire chunk

                    if (l2[i2]) {
                        // compute how many to free in this chunk
                        uint64_t keep_here = 0;

                        if (keep_in_triple > chunk_start) {
                            keep_here = keep_in_triple - chunk_start;
                        }

                        uint64_t to_free_here = per_l2 - keep_here;

                        if (to_free_here > 0) {
                            uint64_t blocks_sub = to_free_here;

                            if (inode_truncate_recursive(l2[i2], 2, &blocks_sub, scratch) != 0) {
                                free(scratch);
                                return -EIO;
                            }

                            free_data_block(l2[i2]);
                            l2[i2] = 0;

                            if (to_free_blocks >= blocks_sub) {
                                to_free_blocks -= blocks_sub;

                            } else {
                                to_free_blocks = 0;
                            }
                        }
                    }
                }

                // write updated level2 block CoW style
                uint32_t new_l2 = 0;

                if (write_to_next_free_block(scratch, &new_l2) != 0) {
                    free(scratch);
                    return -EIO;
                }

                free_data_block(node.triple_indirect);
                node.triple_indirect = new_l2;
            }
        }
    }

    // update size & timestamps
    node.size = newsize;
    node.mtime = node.ctime = time(NULL);
    inode_write_to_disk_private(inum, &node);

    free(scratch);
    return 0;
}



/* -------------------------
 * File read / write
 * ------------------------- */

ssize_t inode_read(uint32_t inum, void *buf, size_t size, off_t offset)
{
    inode_lock(inum);
    ssize_t r = inode_read_private(inum, buf, size, offset);
    inode_unlock(inum);
    return r;
}

static ssize_t inode_read_private(uint32_t inum, void *buf, size_t size, off_t offset) {
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
        uint32_t phy = inode_get_block_num(&node, lblock, scratch);
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
ssize_t inode_write(uint32_t inum, const void *buf, size_t size, off_t offset) {
    inode_lock(inum);
    ssize_t r = inode_write_private(inum, buf, size, offset);
    inode_unlock(inum);
    return r;
}

static ssize_t inode_write_private(uint32_t inum, const void *buf, size_t size, off_t offset) {
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
        uint32_t old_phy = inode_get_block_num(&node, lblock, scratch);

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
        uint32_t new_phy = 0;

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

static inline uint32_t dir_entries_per_block(void) {
    return BYTES_PER_BLOCK / sizeof(directory_entry);
}

/*
 * inode_find_dirent: find a child by name within a directory inode.
 * Returns child's inum on success, -ENOENT if not found, or negative errno.
 */
int inode_find_dirent(uint32_t dir_inum, const char *name) {
    
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
            free(scratch);
            return (int)list[index].inum;
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
int inode_add_dirent(uint32_t parent_inum, directory_entry* entry) {
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
    inode_truncate_private(parent_inum, 0);
    inode_write_private(parent_inum, (void*)list, index * sizeof(directory_entry), 0);
    
    free(scratch);
    return 0;
}

/*
 * inode_remove_dirent: remove an entry by name.
 * Returns 0 on success or -ENOENT if not found.
 */
int inode_remove_dirent(uint32_t parent_inum, directory_entry* entry) {
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

    uint32_t new_list_index = 0;

    uint64_t index = 0;
    while(list[index].is_valid == 1)
    {
        if(list[index].inum == entry->inum && strncmp(list[index].name, entry->name, MAX_FILENAME_LEN) == 0)
        {
            // found! Remove!
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
    inode_truncate_private(parent_inum, 0);
    inode_write_private(parent_inum, (void*)new_list, new_list_index * sizeof(directory_entry), 0);
    
    free(scratch);
    return -ENOENT;
}

/* -------------------------
 * High-level operations
 * ------------------------- */

/*
 * inode_create: create file or directory at path.
 * Mode determines file/dir type.
 */
int inode_create(const char *path, mode_t mode, uint32_t *out_inum) {
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
    inode_read_from_disk_private((uint32_t)parent_inum, &parent);

    if (!S_ISDIR(parent.mode)) { 
        inode_unlock(parent_inum);
        free(pathdup); 
        free(pathdup2);
        return -ENOTDIR; 
    }

    // Ensure name not exists
    int exists = inode_find_dirent((uint32_t)parent_inum, basepart);

    if (exists >= 0) { 
        free(pathdup); 
        free(pathdup2);
        inode_unlock(parent_inum);
        return -EEXIST; 
    }

    // allocate inode
    uint32_t new_inum;
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

        uint32_t blocknum = 0;

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

    if (inode_add_dirent((uint32_t)parent_inum, &ent) != 0) {
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

    int target = inode_find_dirent((uint32_t)parent, basepart);
    if (target < 0) { free(dup); free(dup2); return -ENOENT; }

    inode_lock(parent);

    directory_entry entry_of_file;
    entry_of_file.inum = target;
    strncpy(entry_of_file.name, basepart, MAX_FILENAME_LEN);

    struct inode node;
    inode_read_from_disk_private((uint32_t)target, &node);
    if (S_ISDIR(node.mode)) { free(dup); free(dup2); return -EISDIR; }

    // Remove from parent dir
    if (inode_remove_dirent((uint32_t)parent, &entry_of_file) != 0) { free(dup); free(dup2); return -EIO; }

    // Decrement link and possibly free inode
    inode_lock((uint32_t)target);
    inode_read_from_disk_private((uint32_t)target, &node);
    if (node.nlink > 0) 
    {
        node.nlink--;
    }
    if (node.nlink > 0) {
        inode_write_to_disk_private((uint32_t)target, &node);
        inode_unlock((uint32_t)target);
        inode_unlock(parent);
        free(dup); free(dup2);
        return 0;
    }

    // free all blocks and inode
    uint64_t total_blocks = (node.size + BYTES_PER_BLOCK - 1) / BYTES_PER_BLOCK;
    // free direct
    for (uint32_t i = 0; i < NUM_DIRECT_BLOCKS && total_blocks > 0; ++i) {
        if (node.direct_blocks[i]) { free_data_block(node.direct_blocks[i]); node.direct_blocks[i] = 0; total_blocks--; }
    }
    // free single
    if (node.single_indirect && total_blocks > 0) {
        uint64_t blocks_sub = total_blocks;
        inode_truncate_recursive(node.single_indirect, 1, &blocks_sub, NULL);
        free_data_block(node.single_indirect);
        node.single_indirect = 0;
        if (blocks_sub > total_blocks) blocks_sub = total_blocks;
        total_blocks = (total_blocks > blocks_sub) ? (total_blocks - blocks_sub) : 0;
    }
    // free double
    if (node.double_indirect && total_blocks > 0) {
        uint64_t blocks_sub = total_blocks;
        inode_truncate_recursive(node.double_indirect, 2, &blocks_sub, NULL);
        free_data_block(node.double_indirect);
        node.double_indirect = 0;
        if (blocks_sub > total_blocks) blocks_sub = total_blocks;
        total_blocks = (total_blocks > blocks_sub) ? (total_blocks - blocks_sub) : 0;
    }
    // free triple
    if (node.triple_indirect && total_blocks > 0) {
        uint64_t blocks_sub = total_blocks;
        inode_truncate_recursive(node.triple_indirect, 3, &blocks_sub, NULL);
        free_data_block(node.triple_indirect);
        node.triple_indirect = 0;
        if (blocks_sub > total_blocks) blocks_sub = total_blocks;
        total_blocks = (total_blocks > blocks_sub) ? (total_blocks - blocks_sub) : 0;
    }

    inode_write_to_disk_private((uint32_t)target, &node);
    inode_unlock((uint32_t)target);

    inode_free((uint32_t)target);
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
int inode_readdir(uint32_t dir_inum, void *buf, fuse_fill_dir_t filler) {
    
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
int inode_find_by_path(const char *path) {
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
        inode_read_from_disk_private((uint32_t)cur_inum, &node);

        if (!S_ISDIR(node.mode)) { 
            free(dup); 
            return -ENOTDIR; 
        }
        inode_lock(cur_inum);
        int next = inode_find_dirent((uint32_t)cur_inum, token);
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

    // uint32_t bitmap_blocknum = INODE_TABLE_START_BLOCK; // first bitmap block


    // treat as fresh fs: zero out bitmap blocks
    memset(buf, 0, BYTES_PER_BLOCK);

    for (uint32_t b = 0; b < INODE_BITMAP_BLOCKS; ++b) {
        if (write_inode_block(buf, INODE_TABLE_START_BLOCK + b) != 0) {
            free(buf); 
            return -EIO;
        }
    }

    // allocate inode 0 by setting bit 0
    ((uint8_t*)buf)[0] |= 1u;

    if (write_inode_block(buf, INODE_TABLE_START_BLOCK) != 0) { 
        free(buf); 
        return -EIO; 
    }

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
    uint32_t out_num = 19;
    inode_alloc(&out_num); // to mark 0 as used.
    inode_alloc(&out_num); // to get inode 1 for root.
    if(out_num != return_root_inode())
    {
        free(scratch);
        free(buf);
        return -EIO;        
    }
    memcpy(scratch, root_ent, sizeof(directory_entry) * 3);
    uint32_t datablock_number = 0;
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

int inode_chown(uint32_t inode, uid_t user, gid_t group) {
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

int inode_chmod(uint32_t inode, mode_t fmode) {
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
static int is_dir_empty(uint32_t dir_inum) {

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
    int target_inum = inode_find_dirent((uint32_t)parent_inum, basepart);
    
    if (target_inum < 0) { 
        inode_unlock(parent_inum);
        free(dup); free(dup2);
        return -ENOENT;
    }

    inode_lock(target_inum);
    struct inode target_node;
    inode_read_from_disk_private((uint32_t)target_inum, &target_node);

    if (!S_ISDIR(target_node.mode)) {
        inode_unlock(target_inum);
        inode_unlock(parent_inum);
        free(dup); free(dup2);
        return -ENOTDIR;
    }

    // Check if empty
    int empty = is_dir_empty((uint32_t)target_inum);
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

    int ret = inode_remove_dirent((uint32_t)parent_inum, &dent);
    if (ret != 0) {         
        inode_unlock(target_inum);
        inode_unlock(parent_inum);
        free(dup); free(dup2);
        return ret;
    }

    // Decrement parent nlink (removing ".." from child)
    inode_lock((uint32_t)parent_inum);
    struct inode parent_node;
    inode_read_from_disk_private((uint32_t)parent_inum, &parent_node);
    if (parent_node.nlink > 2)
    {
        parent_node.nlink--;
    }
    inode_write_to_disk_private((uint32_t)parent_inum, &parent_node);

    // Free target inode and blocks
    // Recycled logic from inode_unlink cleanup
    uint64_t total_blocks = (target_node.size + BYTES_PER_BLOCK - 1) / BYTES_PER_BLOCK;
    for (uint32_t i = 0; i < NUM_DIRECT_BLOCKS && total_blocks > 0; ++i) {
        if (target_node.direct_blocks[i]) { free_data_block(target_node.direct_blocks[i]); total_blocks--; }
    }
    // (Simplified: assume small dirs for rmdir, full recursion is in inode_truncate)
    if (target_node.single_indirect) {
        uint64_t sub = total_blocks;
        inode_truncate_recursive(target_node.single_indirect, 1, &sub, NULL);
        free_data_block(target_node.single_indirect);
    }
    
    inode_free((uint32_t)target_inum);

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
int inode_rename(const char *from, const char *to) {
    int ret = 0;
    char *from_dup = NULL, *to_dup = NULL;
    char *from_dup2 = NULL;
    char *from_dir = NULL, *from_base = NULL;
    char *to_dir_dup = NULL, *to_base_dup = NULL;
    char *to_dir = NULL, *to_base = NULL;
    uint8_t *scratch = NULL;

    // 1. Basic Argument Validation
    if (!from || !to) {
        return -EINVAL;
    }

    // 2. Loop Detection (Prevent moving /A into /A/B)
    // A simple string prefix check handles the most common cases.
    size_t from_len = strlen(from);

    if (strncmp(from, to, from_len) == 0 && to[from_len] == '/') {
        return -EINVAL;
    }

    // 3. Parse Paths
    from_dup = strdup(from);
    to_dup = strdup(to);
    from_dup2 = strdup(from);

    if (!from_dup || !to_dup) { 
        ret = -ENOMEM; 
        goto cleanup; 
    }

    from_dir = dirname(from_dup);
    from_base = basename(from_dup2);

    // Need separate duplicate for destination dirname/basename calls
    to_dir_dup = strdup(to);
    to_base_dup = strdup(to);

    if (!to_dir_dup || !to_base_dup) { 
        ret = -ENOMEM; 
        goto cleanup; 
    }

    to_dir = dirname(to_dir_dup);
    to_base = basename(to_base_dup);

    // 4. Resolve Parent Inodes
    int from_parent_inum = inode_find_by_path(from_dir);
    int to_parent_inum = inode_find_by_path(to_dir);

    if (from_parent_inum < 0) { 
        ret = from_parent_inum; 
        goto cleanup; 
    }

    if (to_parent_inum < 0) { 
        ret = to_parent_inum; 
        goto cleanup; 
    }

    inode_lock(from_parent_inum);
    inode_lock(to_parent_inum);

    // 5. Find Source Inode
    int target_inum = inode_find_dirent((uint32_t)from_parent_inum, from_base);

    if (target_inum < 0) { 
        ret = -ENOENT; 
        inode_unlock(to_parent_inum);
        inode_unlock(from_parent_inum);
        goto cleanup; 
    }

    // 6. Check Destination status
    int dest_exists = inode_find_dirent((uint32_t)to_parent_inum, to_base);
    
    // Standard POSIX behavior requires atomic replacement, but for this 
    // filesystem implementation, we fail if destination exists to avoid 
    // complex transaction rollback logic.
    if (dest_exists >= 0) {
        ret = -EEXIST;
        inode_unlock(to_parent_inum);
        inode_unlock(from_parent_inum);
        goto cleanup;
    }

    inode_lock(target_inum);
    inode_lock(dest_exists);

    // 7. Add Link to New Parent
    directory_entry new_val;
    new_val.inum = target_inum;
    strncpy(new_val.name, to_base, MAX_FILENAME_LEN);

    ret = inode_add_dirent((uint32_t)to_parent_inum, &new_val);

    if (ret != 0)
    {
        inode_unlock(dest_exists);
        inode_unlock(target_inum);
        inode_unlock(to_parent_inum);
        inode_unlock(from_parent_inum);
        goto cleanup;
    }
    // 8. Remove Link from Old Parent
    directory_entry old_val;
    old_val.inum = target_inum;
    strncpy(old_val.name, from_base, MAX_FILENAME_LEN);
    ret = inode_remove_dirent((uint32_t)from_parent_inum, &old_val);

    if (ret != 0) {
        // CRITICAL ERROR: We added to new but failed to remove from old.
        // Ideally, we should try to undo the add_dirent here.
        // For this implementation, we return the error.
        // todo: ??
        inode_unlock(dest_exists);
        inode_unlock(target_inum);
        inode_unlock(to_parent_inum);
        inode_unlock(from_parent_inum);
        goto cleanup;
    }

    // 9. Handle Directory Specific Updates (The Fix)
    struct inode target_node;

    if (inode_read_from_disk_private((uint32_t)target_inum, &target_node) != 0) {
        ret = -EIO; 
        inode_unlock(dest_exists);
        inode_unlock(target_inum);
        inode_unlock(to_parent_inum);
        inode_unlock(from_parent_inum);
        goto cleanup;
    }

    if (S_ISDIR(target_node.mode)) {
        // If we moved to a different directory, we must update '..'
        if (from_parent_inum != to_parent_inum) {
            
            // A. Update Parent Link Counts
            // Old parent loses a link (the ".." from the child is gone)
            // inode_lock((uint32_t)from_parent_inum);

            struct inode from_p_node;
            inode_read_from_disk_private((uint32_t)from_parent_inum, &from_p_node);

            if (from_p_node.nlink > 2) {
                from_p_node.nlink--;
            }

            inode_write_to_disk_private((uint32_t)from_parent_inum, &from_p_node);

            // inode_unlock((uint32_t)from_parent_inum);

            // New parent gains a link
            // inode_lock((uint32_t)to_parent_inum);

            struct inode to_p_node;
            inode_read_from_disk_private((uint32_t)to_parent_inum, &to_p_node);
            to_p_node.nlink++;
            inode_write_to_disk_private((uint32_t)to_parent_inum, &to_p_node);

            // inode_unlock((uint32_t)to_parent_inum);

            // B. Update the ".." entry inside the target directory
            create_buffer((void**)&scratch);
            

            if (!scratch) { 
                ret = -ENOMEM; 
                inode_unlock(dest_exists);
                inode_unlock(target_inum);
                inode_unlock(to_parent_inum);
                inode_unlock(from_parent_inum);
                goto cleanup; 
            }

            // The "." and ".." entries are created in the first block (logical 0)
            uint32_t old_phy_blk = inode_get_block_num(&target_node, 0, scratch);
            
            if (old_phy_blk != 0) {
                // Read the directory data block
                if (read_data_block(scratch, old_phy_blk) != 0) {
                    ret = -EIO; 
                    inode_unlock(dest_exists);
                    inode_unlock(target_inum);
                    inode_unlock(to_parent_inum);
                    inode_unlock(from_parent_inum);
                    goto cleanup;
                }

                directory_entry *ents = (directory_entry*)scratch;
                int updated = 0;

                // Find ".." and update it
                for (uint32_t i = 0; i < dir_entries_per_block(); ++i) {
                    if (ents[i].inum != 0 && strcmp(ents[i].name, "..") == 0) {
                        ents[i].inum = (uint32_t)to_parent_inum;
                        updated = 1;
                        break;
                    }
                }

                if (updated) {
                    // CoW: Write modified buffer to a new block
                    uint32_t new_phy_blk = 0;
                    if (write_to_next_free_block(scratch, &new_phy_blk) != 0) {
                        ret = -EIO; 
                        inode_unlock(dest_exists);
                        inode_unlock(target_inum);
                        inode_unlock(to_parent_inum);
                        inode_unlock(from_parent_inum);
                        goto cleanup;
                    }

                    // Update the inode's pointer tree
                    if (inode_set_block_num((uint32_t)target_inum, &target_node, 0, new_phy_blk) != 0) {
                        free_data_block(new_phy_blk); // Rollback
                        ret = -EIO; 
                        inode_unlock(dest_exists);
                        inode_unlock(target_inum);
                        inode_unlock(to_parent_inum);
                        inode_unlock(from_parent_inum);
                        goto cleanup;
                    }

                    // Persist the modified inode (which now points to the new block)
                    inode_write_to_disk_private((uint32_t)target_inum, &target_node);
                    
                    // Note: The old physical block refcount decrement is handled by inode_set_block_num
                    // (assuming your CoW logic there correctly calls free_data_block on the old pointer)
                }
            }
        }
    }
    inode_unlock(dest_exists);
    inode_unlock(target_inum);
    inode_unlock(to_parent_inum);
    inode_unlock(from_parent_inum);

    ret = 0;

cleanup:
    if(from_dup2) free(from_dup2);
    if (from_dup) free(from_dup);
    if (to_dup) free(to_dup);
    if (to_dir_dup) free(to_dir_dup);
    if (to_base_dup) free(to_base_dup);
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
static uint32_t get_xattr_block_num(const struct inode *node) {
    uint32_t block_num;
    memcpy(&block_num, node->padding, sizeof(uint32_t));
    return block_num;
}

static void set_xattr_block_num(struct inode *node, uint32_t block_num) {
    memcpy(node->padding, &block_num, sizeof(uint32_t));
}

int inode_setxattr(uint32_t inode, const char* key, const char* val, size_t len, int flags) {
    if (strlen(key) > 255) return -ENAMETOOLONG;

    inode_lock(inode);
    struct inode node;
    inode_read_from_disk_private(inode, &node);

    uint32_t blk = get_xattr_block_num(&node);
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

    uint32_t old_offset = 4; // skip size header
    uint32_t new_offset = 4;
    uint32_t total_data_size = *((uint32_t*)buffer);
    // int found = 0;

    // Copy existing entries, skipping if we match key
    while (old_offset < total_data_size + 4 && old_offset < BYTES_PER_BLOCK) {
        uint8_t key_len = buffer[old_offset];
        char *curr_key = (char*)(buffer + old_offset + 1);
        uint32_t val_len = *((uint32_t*)(buffer + old_offset + 1 + key_len));
        uint32_t entry_size = 1 + key_len + 4 + val_len;

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
    uint32_t vlen = (uint32_t)len;
    uint32_t new_entry_size = 1 + klen + 4 + vlen;

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
    *((uint32_t*)new_buf) = new_offset - 4;

    // Write to disk (CoW)
    uint32_t new_blk_phy = 0;
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

int inode_getxattr(uint32_t inode, const char* key, const char* val, size_t len) {
    inode_lock(inode);
    struct inode node;
    inode_read_from_disk_private(inode, &node);

    uint32_t blk = get_xattr_block_num(&node);
    if (blk == 0) { inode_unlock(inode); return -ENODATA; }

    uint8_t *buffer;
    create_buffer((void**)&buffer);
    if (!buffer) { inode_unlock(inode); return -ENOMEM; }

    if (read_data_block(buffer, blk) != 0) {
        free(buffer); inode_unlock(inode); return -EIO;
    }

    uint32_t offset = 4;
    uint32_t total_size = *((uint32_t*)buffer);

    while (offset < total_size + 4 && offset < BYTES_PER_BLOCK) {
        uint8_t key_len = buffer[offset];
        char *curr_key = (char*)(buffer + offset + 1);
        uint32_t val_len = *((uint32_t*)(buffer + offset + 1 + key_len));
        
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

int inode_listxattr(uint32_t inode, char* val, size_t len) {
    inode_lock(inode);
    struct inode node;
    inode_read_from_disk_private(inode, &node);

    uint32_t blk = get_xattr_block_num(&node);
    if (blk == 0) { inode_unlock(inode); return 0; }

    uint8_t *buffer;
    create_buffer((void**)&buffer);
    if (!buffer) { inode_unlock(inode); return -ENOMEM; }
    if (read_data_block(buffer, blk) != 0) {
        free(buffer); inode_unlock(inode); return -EIO;
    }

    uint32_t offset = 4;
    uint32_t total_size = *((uint32_t*)buffer);
    size_t required_len = 0;

    // First pass: calculate size
    uint32_t temp_off = 4;
    while (temp_off < total_size + 4) {
        uint8_t klen = buffer[temp_off];
        uint32_t vlen = *((uint32_t*)(buffer + temp_off + 1 + klen));
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
        uint32_t vlen = *((uint32_t*)(buffer + offset + 1 + klen));
        offset += (1 + klen + 4 + vlen);
    }

    free(buffer);
    inode_unlock(inode);
    return (int)required_len;
}

int inode_removexattr(uint32_t inode, const char* key) {
    inode_lock(inode);
    struct inode node;
    inode_read_from_disk_private(inode, &node);

    uint32_t blk = get_xattr_block_num(&node);
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

    uint32_t old_offset = 4;
    uint32_t new_offset = 4;
    uint32_t total_data_size = *((uint32_t*)buffer);
    int found = 0;

    while (old_offset < total_data_size + 4) {
        uint8_t key_len = buffer[old_offset];
        char *curr_key = (char*)(buffer + old_offset + 1);
        uint32_t val_len = *((uint32_t*)(buffer + old_offset + 1 + key_len));
        uint32_t entry_size = 1 + key_len + 4 + val_len;

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

    *((uint32_t*)new_buf) = new_offset - 4;

    uint32_t new_blk_phy = 0;
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


int inode_link(uint32_t src_inum, const char *newpath) {
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