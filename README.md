# FrostByteFS
A FUSE file system implementation

By Ben Carter, Towhid Islam, and Sohaib  -- 2025

---

This is a inode-based filesystem designed for copy-on-write.
It is broken into 4 layers:
1. rawdisk -- raw disk I/O
2. allocator -- in charge of allocating new data blocks and freeing data blocks
3. inodes -- implementation of inodes
4. fuse interface

It is designed for copy-on-write, where each data block can be shared by multiple
inodes when a data block will have the same contents. There is a reference
counting region to keep track of if blocks are free or not.

**Important notes:**
1. This project requires the libfuse 3.17 release (so later than the one from apt).
    We compiled libfuse from source.
2. The size of the disk, the number of inodes, and other parameters are hardcoded.
    See `rawdisk.h`, `allocator.h`, and `inode.h` to set values to your disk.
3. It by default uses the kernel for caching (eg. not DIRECT_IO).
    To disable this, comment out `USE_KERNEL_CACHE` in `rawdisk.h`
4. True copy-on-write is not currently implemented, due to running out of time. Instead,
    the allocator assumes each block will be unique (so the reference counts are just 0 or 1).


**Compiling:**
- Assure libfuse 3.17 is installed and accessible.
- To compile the filesystem, use `make` in the root directory of this repo.
- To compile the tests, use `make` in the `tests` directory.
