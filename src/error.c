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
            return "ALLOCATOR_READ_ON_FREE: Disk not opened";
        case -ALLOCATOR_OUT_OF_SPACE:
            return "ALLOCATOR_OUT_OF_SPACE: Access beyond disk size";
        case -ALLOCATOR_DOUBLE_FREE:
            return "ALLOCATOR_DOUBLE_FREE: Underlying system I/O error";
        case -ALLOCATOR_OUT_OF_BOUNDS:
            return "ALLOCATOR_OUT_OF_BOUNDS: Underlying system I/O error";
        case 0:
            return "ALLOCATOR: OK";
        default:
            return raw_disk_error_to_string(err);
    }
}