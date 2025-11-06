/*
 * This file contains the main() function for the 'frost' filesystem.
 * It handles command-line option parsing, extracting the disk image path,
 * and starting the FUSE main loop.
 */

#include "callbacks.h" // This will include "inode.h"

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
    printf("usage: %s [options] <mountpoint> <disk_image>\n\n", progname);
    printf("Filesystem options:\n"
           "    -h   --help    Show this help message\n"
           "\n");
}

int main(int argc, char *argv[])
{
    int ret;
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    // Note: 'options' is the global struct from callbacks.c
    // We don't need to set defaults for it here.

    /* Parse our custom options (-h, --help) */
    if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
        return 1;

    /*
     * After fuse_opt_parse, args.argv contains the program name
     * and all *non-option* arguments.
     *
     * We expect 3 arguments left:
     * args.argv[0] = program name (e.g., "./frost")
     * args.argv[1] = mountpoint (e.g., "mnt")
     * args.argv[2] = disk image (e.g., "frost.img")
     *
     * FUSE options (like -f, -d) are passed through in args
     * and will be handled by fuse_main.
     */
    
    // Check for --help
    if (options.show_help) {
        show_help(argv[0]);
        // This tells fuse_main to print *its* help too
        assert(fuse_opt_add_arg(&args, "--help") == 0);
        args.argv[0][0] = '\0';
    }

    // Check for the correct number of non-option arguments
    if (args.argc != 3) {
        if (!options.show_help) { // Don't print help twice
            show_help(args.argv[0]);
        }
        fuse_opt_free_args(&args);
        return 1;
    }

    // Get the disk path from the last argument
    char *disk_path = args.argv[2];
    
    // *** THIS IS THE CRITICAL FIX ***
    // Remove the disk_path argument from the list
    // so fuse_main() doesn't see it.
    args.argc--;

    /*
     * Call the FUSE main loop.
     * 'frost_oper' is the global struct from callbacks.c
     * 'disk_path' is passed as 'private_data' to our frost_init function.
     */
    ret = fuse_main(args.argc, args.argv, &frost_oper, disk_path);
    
    fuse_opt_free_args(&args);
    return ret;
}

