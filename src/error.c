/**
 * @file error.c
 * @author Benjamin Carter, Towhidul Islam, Sohaib
 * @brief Error Codes for custom errors in the lower layers.
 * @version 0.1
 * @date 2025-12-02
 * 
 * @copyright Copyright (c) 2025 Benjamin Carter, Towhidul Islam, Sohaib
 * 
 */
#include "error.h"

const char* raw_disk_error_to_string(int err) {
    switch (err) {
        case -RAW_DISK_ERROR_UNOPENED:
            return "RAW_DISK_ERROR_UNOPENED: Disk not opened";
        case -RAW_DISK_ERROR_OUT_OF_BOUNDS:
            return "RAW_DISK_ERROR_OUT_OF_BOUNDS: Access beyond disk size";
        case -RAW_DISK_ERROR_SYSTEM:
            return "RAW_DISK_ERROR_SYSTEM: Underlying system I/O error";
        case -RAW_BUFFER_ERROR:
            return "RAW BUFFER ERROR";
        case 0:
            return "RAW_DISK: OK";
        default:
            return "UNKNOWN_ERROR: Unrecognized raw disk error code";
    }
}

const char* allocator_error_to_string(int err) {
    switch (err) {
        case -ALLOCATOR_READ_ON_FREE:
            return "ALLOCATOR_READ_ON_FREE: Trying to read a block that is free";
        case -ALLOCATOR_OUT_OF_SPACE:
            return "ALLOCATOR_OUT_OF_SPACE: No more available blocks!";
        case -ALLOCATOR_DOUBLE_FREE:
            return "ALLOCATOR_DOUBLE_FREE: Trying to free a freed block";
        case -ALLOCATOR_OUT_OF_BOUNDS:
            return "ALLOCATOR_OUT_OF_BOUNDS: Attempting to access block out of bounds";
        case 0:
            return "ALLOCATOR: OK";
        default:
            return raw_disk_error_to_string(err);
    }
}

const char* file_layer_error_to_string(int err) {
    switch (err) {
        case -FILE_NOT_FOUND:
            return "FILE_NOT_FOUND: File not found";
        case 0:
            return "File Layer: OK";
        default:
            return "File Layer: Unknown Error";
    }
}

const char* inode_error_to_string(int err) {
    switch (err) {
        case -INODE_BUFFER_ALLOCATION_FAILED:
            return "INODE_BUFFER_ALLOCATION_FAILED: Trying to allocate a buffer of a block size in memory";
        case 0:
            return "INODE: OK";
        default:
            return allocator_error_to_string(err);
    }
}