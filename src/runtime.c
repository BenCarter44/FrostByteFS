
#include "runtime.h"



struct lo_inode *lo_find(struct lo_data *lo, struct stat *st)
{
	struct lo_inode *p;
	struct lo_inode *ret = NULL;

	pthread_mutex_lock(&lo->mutex);
	for (p = lo->root.next; p != &lo->root; p = p->next) {
		if (p->ino == st->st_ino && p->dev == st->st_dev) {
			assert(p->refcount > 0);
			ret = p;
			ret->refcount++;
			break;
		}
	}
	pthread_mutex_unlock(&lo->mutex);
	return ret;
}


struct lo_data *lo_data(fuse_req_t req)
{
	return (struct lo_data *) fuse_req_userdata(req);
}


int lo_fd(fuse_req_t req, fuse_ino_t ino)
{
	return lo_inode(req, ino)->fd;
}

bool lo_debug(fuse_req_t req)
{
	return lo_data(req)->debug != 0;
}

void lo_init(void *userdata,
		    struct fuse_conn_info *conn)
{
	struct lo_data *lo = (struct lo_data *)userdata;
	bool has_flag;

	if (lo->writeback) {
		has_flag = fuse_set_feature_flag(conn, FUSE_CAP_WRITEBACK_CACHE);
		if (lo->debug && has_flag)
			fuse_log(FUSE_LOG_DEBUG,
				 "lo_init: activating writeback\n");
	}
	if (lo->flock && conn->capable & FUSE_CAP_FLOCK_LOCKS) {
		has_flag = fuse_set_feature_flag(conn, FUSE_CAP_FLOCK_LOCKS);
		if (lo->debug && has_flag)
			fuse_log(FUSE_LOG_DEBUG,
				 "lo_init: activating flock locks\n");
	}

	/* Disable the receiving and processing of FUSE_INTERRUPT requests */
	conn->no_interrupt = 1;
}

void lo_destroy(void *userdata)
{
	struct lo_data *lo = (struct lo_data*) userdata;

	while (lo->root.next != &lo->root) {
		struct lo_inode* next = lo->root.next;
		lo->root.next = next->next;
		close(next->fd);
		free(next);
	}
}



struct lo_dirp *lo_dirp(struct fuse_file_info *fi)
{
	return (struct lo_dirp *) (uintptr_t) fi->fh;
}



// local functions
struct lo_inode *lo_inode(fuse_req_t req, fuse_ino_t ino)
{
	if (ino == FUSE_ROOT_ID)
		return &lo_data(req)->root;
	else
		return (struct lo_inode *) (uintptr_t) ino;
}


struct lo_inode *create_new_inode(int fd, struct fuse_entry_param *e, struct lo_data* lo)
{
	struct lo_inode *inode = NULL;
	struct lo_inode *prev, *next;
	
	inode = calloc(1, sizeof(struct lo_inode));
	if (!inode)
		return NULL;

	inode->refcount = 1;
	inode->fd = fd;
	inode->ino = e->attr.st_ino;
	inode->dev = e->attr.st_dev;

	pthread_mutex_lock(&lo->mutex);
	prev = &lo->root;
	next = prev->next;
	next->prev = inode;
	inode->next = next;
	inode->prev = prev;
	prev->next = inode;
	pthread_mutex_unlock(&lo->mutex);
	return inode;
}


void unref_inode(struct lo_data *lo, struct lo_inode *inode, uint64_t n)
{
	if (!inode)
		return;

	pthread_mutex_lock(&lo->mutex);
	assert(inode->refcount >= n);
	inode->refcount -= n;
	if (!inode->refcount) {
		struct lo_inode *prev, *next;

		prev = inode->prev;
		next = inode->next;
		next->prev = prev;
		prev->next = next;

		pthread_mutex_unlock(&lo->mutex);
		close(inode->fd);
		free(inode);

	} else {
		pthread_mutex_unlock(&lo->mutex);
	}
}
