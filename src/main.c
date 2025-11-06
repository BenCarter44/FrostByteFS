/*
 * This file contains the main() function for the 'frost' filesystem.
 * It manually extracts the disk image path and lets fuse_main()
 * handle all other FUSE-specific options.
 */
#ifndef COMPILE_FOR_TESTS

#include "callbacks.h"

// Help function
static void show_help(const char *progname)
{
    printf("usage: %s [options] <mountpoint> <disk_image>\n\n", progname);
    printf("Filesystem options:\n"
           "    -h   --help    Show this help message\n"
           "\n");
}

int main(int argc, char *argv[])
{
    // --- 1. Manual check for -h or --help ---
    // We do this first, before any other logic.
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            show_help(argv[0]);
            
            // We still pass --help to fuse_main to show its help too
            struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
            assert(fuse_opt_add_arg(&args, "--help") == 0);
            args.argv[0][0] = '\0';
            
            // Note: We don't pass private_data here
            int ret = fuse_main(args.argc, args.argv, &frost_oper, NULL);
            fuse_opt_free_args(&args);
            return ret;
        }
    }

    // --- 2. Check for minimum argument count ---
    // We need at least 3 args total:
    // 1. ./frost
    // 2. <mountpoint>
    // 3. <disk_image>
    // FUSE options like -f, -d, -s are extra.
    if (argc < 3) {
        show_help(argv[0]);
        return 1;
    }

    // --- 3. Extract the disk_path ---
    // We assume the disk_image is the *very last* argument
    char *disk_path = argv[argc - 1];

    // --- 4. Remove disk_path from argc ---
    // We simply tell fuse_main that argc is one smaller.
    // It will parse all options and the mountpoint,
    // and stop before it ever sees the disk_image argument.
    argc--;

    // --- 5. Call fuse_main ---
    // 'frost_oper' is the global struct from callbacks.c
    // 'disk_path' is passed as 'private_data' to our frost_init function.
    // fuse_main will now correctly parse -f, -d, -s, and the mountpoint.
    return fuse_main(argc, argv, &frost_oper, disk_path);
}

#endif
