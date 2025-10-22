/**
 * Manages local state of the file system (high level), the state of the fuse runtime
 */

#ifndef RUNTIME_H
#define RUNTIME_H

#include "libraries.h"
#include "inode.h"


struct lo_inode {
	struct lo_inode *next; /* protected by lo->mutex */
	struct lo_inode *prev; /* protected by lo->mutex */
	int fd;
	ino_t ino;
	dev_t dev;
	uint64_t refcount; /* protected by lo->mutex */
};


struct lo_data {
	pthread_mutex_t mutex;
	int debug;
	int writeback;
	int flock;
	int xattr;
	char *source;
	double timeout;
	int cache;
	int timeout_set;
	struct lo_inode root; /* protected by lo->mutex */
};


enum {
	CACHE_NEVER,
	CACHE_NORMAL,
	CACHE_ALWAYS,
};

// local functions
struct lo_inode *lo_inode(fuse_req_t req, fuse_ino_t ino);
struct lo_inode *create_new_inode(int fd, struct fuse_entry_param *e, struct lo_data* lo);
void unref_inode(struct lo_data *lo, struct lo_inode *inode, uint64_t n);


// functions


struct lo_data *lo_data(fuse_req_t req);

int lo_fd(fuse_req_t req, fuse_ino_t ino);
bool lo_debug(fuse_req_t req);


void lo_init(void *userdata, struct fuse_conn_info *conn);
void lo_destroy(void *userdata);


struct lo_inode *lo_find(struct lo_data *lo, struct stat *st);

struct lo_dirp *lo_dirp(struct fuse_file_info *fi);








#endif