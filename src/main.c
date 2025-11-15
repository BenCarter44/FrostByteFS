/*
 * This file contains the main() function for the 'frost' filesystem.
 * It handles command-line option parsing and starting the FUSE main loop.
 */
#ifdef COMPILE_FOR_TESTS 

#include "callbacks.h"

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

    /* When --help is specified, first print our own file-system
       specific help text, then signal fuse_main to show
       additional help (by adding `--help` to the options again)
       without usage: line (by setting argv[0] to the empty
       string) */
    if (options.show_help) {
        show_help(argv[0]);
        assert(fuse_opt_add_arg(&args, "--help") == 0);
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
