/**
 * @file test_inode.c
 * @brief Unit tests for inode layer
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "allocator.h"
#include "inode.h"

void test_inode_init_root() {
    printf("Running test_inode_init_root...\n");

    assert(format_super_block() == 0);
    assert(clear_ref_blocks() == 0);
    assert(clear_inode_blocks() == 0);

    assert(inode_init_root_if_needed(1000000) == 0);

    struct inode root;
    inode_read_from_disk(0, &root);

    assert(S_ISDIR(root.mode));
    assert(root.nlink >= 1);
    assert(root.size == 0);

    printf("Root inode initialized successfully.\n");
}

void test_inode_create_and_rw() {
    printf("Running test_inode_create_and_rw...\n");

    uint32_t inum;
    assert(inode_create("/fileA.txt", S_IFREG | 0644, &inum) == 0);
    assert(inum > 0);

    const char *data = "Hello FrostFS!";
    assert(inode_write(inum, data, strlen(data), 0) == (ssize_t)strlen(data));

    char buf[64];
    memset(buf, 0, sizeof(buf));
    assert(inode_read(inum, buf, sizeof(buf), 0) == (ssize_t)strlen(data));
    assert(strcmp(buf, data) == 0);

    printf("Create + RW test passed.\n");
}

void test_inode_indirect_blocks() {
    printf("Running test_inode_indirect_blocks...\n");

    uint32_t inum;
    assert(inode_create("/largefile", S_IFREG | 0644, &inum) == 0);

    // Write data that spans more than 12 direct blocks
    char data[BYTES_PER_BLOCK];
    memset(data, 'A', sizeof(data));

    size_t total_blocks = NUM_DIRECT_BLOCKS + 8; // force indirect use
    for (size_t i = 0; i < total_blocks; i++) {
        assert(inode_write(inum, data, sizeof(data), i * BYTES_PER_BLOCK) == BYTES_PER_BLOCK);
    }

    struct inode node;
    inode_read_from_disk(inum, &node);
    assert(node.single_indirect != 0);

    printf("Indirect addressing verified.\n");
}

void test_inode_truncate() {
    printf("Running test_inode_truncate...\n");

    uint32_t inum;
    assert(inode_create("/fileB", S_IFREG | 0644, &inum) == 0);

    char data[4096];
    memset(data, 'B', sizeof(data));
    for (int i = 0; i < 5; i++)
        inode_write(inum, data, sizeof(data), i * sizeof(data));

    struct inode node;
    inode_read_from_disk(inum, &node);
    assert(node.size == 5 * 4096);

    assert(inode_truncate(inum, 4096) == 0);
    inode_read_from_disk(inum, &node);
    assert(node.size == 4096);

    printf("Truncate test passed.\n");
}

int main() {
    printf("==== FrostFS Inode Unit Tests ====\n");

    test_inode_init_root();
    test_inode_create_and_rw();
    test_inode_indirect_blocks();
    test_inode_truncate();

    printf("All inode tests passed successfully.\n");
    return 0;
}
