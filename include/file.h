#ifndef FROSTBYTE_FILE_H
#define FROSTBYTE_FILE_H
#include "inode.h"

typedef struct FrostByteFile_t{
    uint32_t inode;

} FrostByteFile;


// FrostByteFile* file_create_new(uint32_t inode);

// // int file_set_access(FrostByteFile* file, int flags);
// // // must check if inode still exists on editing!


// // int file_copy_file_range(FrostByteFile* file_in, off_t offset_in, FrostByteFile* file_out, off_t offset_out, size_t size);

// int file_close(FrostByteFile* file);
#endif