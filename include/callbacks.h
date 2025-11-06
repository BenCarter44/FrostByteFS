#ifndef FROST_CALLBACKS_H_
#define FROST_CALLBACKS_H_

/*

This file contains the primary definitions and function prototypes

for the 'frost' FUSE filesystem.
*/

// Define FUSE_USE_VERSION before including fuse.h
#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>

#include "inode.h"

/*

Command line options

We can't set default values for the char* fields here because

fuse_opt_parse would attempt to free() them when the user specifies

different values on the command line.
*/
struct options {
int show_help;
};

/*

Global 'options' struct.

This is defined in callbacks.c and declared 'extern' here

so it can be accessed by main.c.
*/
extern struct options options;

/*

Global 'frost_oper' struct.

This is defined in callbacks.c and declared 'extern' here

so it can be passed to fuse_main() in main.c.
*/
extern const struct fuse_operations frost_oper;

/*

FUSE Callback Function Prototypes

These are the functions that FUSE will call to handle

filesystem operations.
*/

void *frost_init(struct fuse_conn_info *conn,
struct fuse_config *cfg);

int frost_getattr(const char *path, struct stat *stbuf,
struct fuse_file_info *fi);

int frost_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
off_t offset, struct fuse_file_info *fi,
enum fuse_readdir_flags flags);

int frost_open(const char *path, struct fuse_file_info *fi);

int frost_read(const char *path, char *buf, size_t size, off_t offset,
struct fuse_file_info *fi);

int frost_write(const char *path, const char *buf, size_t size,
off_t offset, struct fuse_file_info *fi);

int frost_create(const char *path, mode_t mode,
struct fuse_file_info *fi);

int frost_truncate(const char *path, off_t size,
struct fuse_file_info *fi);

// --- ADD: New prototypes for a functional filesystem ---

int frost_mkdir(const char *path, mode_t mode);

int frost_unlink(const char *path);

int frost_rmdir(const char *path);

int frost_rename(const char *from, const char *to, unsigned int flags);

#endif // FROST_CALLBACKS_H_