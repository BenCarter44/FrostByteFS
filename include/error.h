#ifndef ERROR_CODES_H
#define ERROR_CODES


// Raw disk
#define RAW_DISK_ERROR_UNOPENED 1
#define RAW_DISK_ERROR_OUT_OF_BOUNDS 2
#define RAW_DISK_ERROR_SYSTEM 3
#define RAW_BUFFER_ERROR 8
const char* raw_disk_error_to_string(int err);

// Allocator Errors
#define ALLOCATOR_READ_ON_FREE 4
#define ALLOCATOR_OUT_OF_SPACE 5
#define ALLOCATOR_DOUBLE_FREE 6
#define ALLOCATOR_OUT_OF_BOUNDS 7
const char* allocator_error_to_string(int err);


#endif