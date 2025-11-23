/*
 * This file contains the main() function for the 'frost' filesystem.
 * It handles command-line option parsing and starting the FUSE main loop.
 */

#ifndef COMPILE_FOR_TESTS
#include "fusefile.h"
#include "fusespecial.h"
#include "allocator.h"

#include <sys/statvfs.h>

void* frost_init(struct fuse_conn_info *conn,
                        struct fuse_config *cfg)
{
    (void) conn;
    cfg->kernel_cache = 1;

    // Get the disk path string from fuse_main's private_data
    const char *disk_path = "/dev/vdb"; // (char*) fuse_get_context()->private_data;

    printf("L3 (FUSE): frost_init() called.\n");
    printf("L3 (FUSE): Opening disk: %s\n", disk_path);

    // --- 1. Open the disk (L1) ---
    int result = open_disk(disk_path);
    if (result != 0) {
        fprintf(stderr, "Error: %s \n",raw_disk_error_to_string(result));
        fprintf(stderr, "FATAL: Failed to open disk image: %s\n", disk_path);
        exit(1); // Cannot continue if disk won't open
    }
    init_allocator();
    // --- 2. Check if disk is formatted (L1) ---
    if (!allocator_check_valid_super_block()) {
        printf("L3 (FUSE): Unformatted disk. Formatting...\n");

        // Format Layer 1 (Allocator)
        format_super_block();
        clear_ref_blocks();
        clear_inode_blocks(); // This just clears the iNode *region*

        printf("L3 (FUSE): Formatting Layer 2 (iNode system)...\n");
        
        // Initialize Layer 2 (iNode system)
        format_inodes();

        printf("L3 (FUSE): Format complete.\n");
    } else {
        printf("L3 (FUSE): Disk mounted successfully.\n");
        inode_global_init();
    }

    return NULL; // No private data needed for other callbacks
}

void frost_destroy(void *private_data)
{
    printf("FrostByteFS is being unmounted. Cleaning up...\n");
    // --- Close the disk (L1) ---
    close_disk();
}

int frost_statfs(const char *path, struct statvfs *stbuf)
{
    (void) path;
    printf("L3 (FUSE): frost_statfs() called.\n");

    // 1. Initialize the structure to zero
    memset(stbuf, 0, sizeof(struct statvfs));

    // 2. Fill with basic constants based on your allocator headers
    stbuf->f_bsize = BYTES_PER_BLOCK;   // Filesystem block size (4096)
    stbuf->f_frsize = BYTES_PER_BLOCK;  // Fragment size (4096)
    stbuf->f_blocks = DISK_SIZE_IN_BLOCKS; // Total blocks in FS
    stbuf->f_bfree = DISK_SIZE_IN_BLOCKS / 2; // Dummy value: Free blocks
    stbuf->f_bavail = DISK_SIZE_IN_BLOCKS / 2; // Dummy value: Available for non-root
    
    stbuf->f_files = MAX_INODES;       // Total inodes
    stbuf->f_ffree = MAX_INODES / 2;   // Dummy value: Free inodes
    stbuf->f_favail = MAX_INODES / 2;  // Dummy value: Available inodes
    
    stbuf->f_namemax = MAX_FILENAME_LEN; // Max filename length

    return 0;
}

// See: https://github.com/libfuse/libfuse/blob/master/include/fuse.h 
const struct fuse_operations frost_oper = {
    .init         = frost_init,
    .statfs      =  frost_statfs,
    .destroy      = frost_destroy,
    // dir
    .mkdir        = frostbyte_mkdir,
    .rmdir        = frostbyte_rmdir,
    .opendir      = frostbyte_opendir,
    .readdir      = frostbyte_readdir,
    .releasedir   = frostbyte_releasedir,
    .fsyncdir     = frostbyte_fsyncdir,
    .symlink      = frostbyte_symlink,
    .readlink     = frostbyte_readlink, 
    // file
    .open         = frostbyte_open,
    .unlink       = frostbyte_unlink,
    .rename       = frostbyte_rename,
    .flush        = frostbyte_flush,
    .release      = frostbyte_release,
    .create       = frostbyte_create,
    // .mknod        = frostbyte_mknod,
    .fsync        = frostbyte_fsync,
    // attr
    .getattr      = frostbyte_getattr,
    .chmod        = frostbyte_chmod,
    .chown        = frostbyte_chown,
    .setxattr     = frostbyte_setxattr,
    .getxattr     = frostbyte_getxattr,
    .listxattr    = frostbyte_listxattr,
    .removexattr  = frostbyte_removexattr,
    // .access       = frostbyte_check_access,
    // data
    .truncate     = frostbyte_truncate,
    .read         = frostbyte_read,
    .write        = frostbyte_write,
    // .bmap    = frostbyte_map_raw,
    // .fallocate     = frostbyte_allocate,
    .copy_file_range = frostbyte_copy_file_range,
    .utimens = frostbyte_utimens,
    .link = frostbyte_link

};


struct options {
int show_help;
};
struct options options;




// Define the option-parsing macro
#define OPTION(t, p)                                \
    { t, offsetof(struct options, p), 1 }

// Define the option specification
static const struct fuse_opt option_spec[] = {
    OPTION("-h", show_help),
    OPTION("--help", show_help),
    FUSE_OPT_END
};

// Help function specific to this main file
static void show_help(const char *progname)
{
    printf("usage: %s [options] <mountpoint>\n\n", progname);
    printf("Filesystem is a write-only example.\n"
           "Files created will be printed to stdout.\n"
           "\n");
}

int main(int argc, char *argv[])
{
    int ret;
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

   
    /* Set defaults -- we have to use strdup so that
       fuse_opt_parse can free the defaults if other
       values are specified */
    // Note: 'options' is the global struct from callbacks.c
    // No defaults needed anymore

    /* Parse options */
    if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
        return 1;

    fuse_opt_add_arg(&args, "-o");
    fuse_opt_add_arg(&args, "default_permissions");

    /* When --help is specified, first print our own file-system
       specific help text, then signal fuse_main to show
       additional help (by adding `--help` to the options again)
       without usage: line (by setting argv[0] to the empty
       string) */
    if (options.show_help) {
        show_help(argv[0]);
        int a = fuse_opt_add_arg(&args, "--help");
        assert(a == 0);
        args.argv[0][0] = '\0';
    }

    /*
     * Call the FUSE main loop.
     * 'frost_oper' is the global struct from callbacks.c
     */

    ret = fuse_main(args.argc, args.argv, &frost_oper, NULL);
    fuse_opt_free_args(&args);
    return ret;
}

#endif