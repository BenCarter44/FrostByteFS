/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file GPL2.txt.
*/

/** @file
 *
 * minimal example filesystem using high-level API
 *
 * Compile with:
 *
 *     gcc -Wall hello.c `pkg-config fuse3 --cflags --libs` -o hello
 *
 * ## Source code ##
 * \include hello.c
 */


#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>

/*
 * Command line options
 *
 * We can't set default values for the char* fields here because
 * fuse_opt_parse would attempt to free() them when the user specifies
 * different values on the command line.
 */
static struct options {
	const char *filename;
	const char *contents;
	int show_help;
} options;

#define OPTION(t, p)                           \
    { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
	OPTION("--name=%s", filename),
	OPTION("--contents=%s", contents),
	OPTION("-h", show_help),
	OPTION("--help", show_help),
	FUSE_OPT_END
};

static void *hello_init(struct fuse_conn_info *conn,
			struct fuse_config *cfg)
{
	(void) conn;
	cfg->kernel_cache = 1;

	/* Test setting flags the old way */
	fuse_set_feature_flag(conn, FUSE_CAP_ASYNC_READ);
	fuse_unset_feature_flag(conn, FUSE_CAP_ASYNC_READ);

	return NULL;
}

static int hello_getattr(const char *path, struct stat *stbuf,
			 struct fuse_file_info *fi)
{
	(void) fi;
	int res = 0;

	memset(stbuf, 0, sizeof(struct stat));
	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else if (strcmp(path+1, options.filename) == 0) {
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = strlen(options.contents);
	} else if (strcmp(path, "/extra_file.txt") == 0) {
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = strnlen("This is an extra file.\n", 1024);
	}
	else
		res = -ENOENT;

	return res;
}

static int hello_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi,
			 enum fuse_readdir_flags flags)
{
	(void) offset;
	(void) fi;
	(void) flags;

	if (strcmp(path, "/") != 0)
		return -ENOENT;

	filler(buf, ".", NULL, 0, FUSE_FILL_DIR_DEFAULTS);
	filler(buf, "..", NULL, 0, FUSE_FILL_DIR_DEFAULTS);
	filler(buf, options.filename, NULL, 0, FUSE_FILL_DIR_DEFAULTS);
	filler(buf, "extra_file.txt", NULL, 0, FUSE_FILL_DIR_DEFAULTS);

	return 0;
}

static int hello_open(const char *path, struct fuse_file_info *fi)
{

	if ((fi->flags & O_ACCMODE) == O_WRONLY) {
		// if ((strcmp(path+1, options.filename) == 0) || (strcmp(path, "/extra_file.txt") == 0))
		// 	return -EACCES;
		return 0;
	}

	if ((strcmp(path+1, options.filename) != 0) && (strcmp(path, "/extra_file.txt") != 0))
		return -ENOENT;

	if ((fi->flags & O_ACCMODE) != O_RDONLY)
		return -EACCES;


	return 0;
}

static int hello_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	size_t len;
	(void) fi;
	if(strcmp(path+1, options.filename) == 0)
	{
		len = strlen(options.contents);
		if (offset < len) {
			if (offset + size > len)
			size = len - offset;
			memcpy(buf, options.contents + offset, size);
		} else
			size = 0;
	
		return size;
	} else if (strcmp(path, "/extra_file.txt") == 0) {
		const char *extra_contents = "This is an extra file.\n";
		len = strnlen(extra_contents, 1024);
		if (offset < len) {
			if (offset + size > len)
				size = len - offset;
			memcpy(buf, extra_contents + offset, size);
		} else
			size = 0;

		return size;
	}
	return -ENOENT;
}

static int hello_write(const char *path, const char *buf, size_t size,
		       off_t offset, struct fuse_file_info *fi)
{
	(void) offset;
	(void) fi;

	// if (strcmp(path+1, options.filename) == 0 || strcmp(path, "/extra_file.txt") == 0)
	// 	return -EACCES;

	printf("[WRITE] To file %s: %.*s\n", path, (int)size, buf);
    fflush(stdout);

	return size;
}

static int hello_create(const char *path, mode_t mode,
						struct fuse_file_info *fi)
{
	(void) mode;
	(void) fi;

	printf("[CREATE] File %s created with mode %o\n", path, mode);
	fflush(stdout);

	return 0;
}

static int hello_truncate(const char *path, off_t size, struct fuse_file_info *fi)
{
    (void) size;
    (void) fi;

	printf("[TRUNCATE] File %s truncated\n", path);
	fflush(stdout);
	return 0;

}

static const struct fuse_operations hello_oper = {
	.init           = hello_init,
	.getattr	= hello_getattr,
	.readdir	= hello_readdir,
	.open		= hello_open,
	.read		= hello_read,
	.write 	    = hello_write,
	.create     = hello_create,
	.truncate   = hello_truncate,
};

static void show_help(const char *progname)
{
	printf("usage: %s [options] <mountpoint>\n\n", progname);
	printf("File-system specific options:\n"
	       "    --name=<s>          Name of the \"hello\" file\n"
	       "                        (default: \"hello\")\n"
	       "    --contents=<s>      Contents \"hello\" file\n"
	       "                        (default \"Hello, World!\\n\")\n"
	       "\n");
}

int main(int argc, char *argv[])
{
	int ret;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	/* Set defaults -- we have to use strdup so that
	   fuse_opt_parse can free the defaults if other
	   values are specified */
	options.filename = strdup("hello");
	options.contents = strdup("Hello World!\n");

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

	ret = fuse_main(args.argc, args.argv, &hello_oper, NULL);
	fuse_opt_free_args(&args);
	return ret;
}