#ifndef CALLBACKS_H
#define CALLBACKS_H

#include "libraries.h"
#include "runtime.h"
#include "inode.h"
#include "passthrough_helpers.h"






struct lo_inode *lo_inode(fuse_req_t req, fuse_ino_t ino);
void unref_inode(struct lo_data *lo, struct lo_inode *inode, uint64_t n);
struct lo_inode *create_new_inode(int fd, struct fuse_entry_param *e, struct lo_data* lo);


void lo_lookup(fuse_req_t req, fuse_ino_t parent, const char *name);
void lo_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode);
void lo_mknod(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, dev_t rdev);
void lo_symlink(fuse_req_t req, const char *link,
		       fuse_ino_t parent, const char *name);
void lo_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t parent,
		    const char *name);
void lo_unlink(fuse_req_t req, fuse_ino_t parent, const char *name);
void lo_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name);
void lo_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
		      fuse_ino_t newparent, const char *newname,
		      unsigned int flags);
void lo_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup);
void lo_forget_multi(fuse_req_t req, size_t count,
				struct fuse_forget_data *forgets);
void lo_getattr(fuse_req_t req, fuse_ino_t ino,
			     struct fuse_file_info *fi);
void lo_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
		       int valid, struct fuse_file_info *fi);
void lo_readlink(fuse_req_t req, fuse_ino_t ino);
void lo_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
void lo_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
		       off_t offset, struct fuse_file_info *fi);
void lo_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size,
			   off_t offset, struct fuse_file_info *fi);
void lo_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
void lo_fsyncdir(fuse_req_t req, fuse_ino_t ino, int datasync,
			struct fuse_file_info *fi);
void lo_create(fuse_req_t req, fuse_ino_t parent, const char *name,
						      mode_t mode, struct fuse_file_info *fi);
void lo_tmpfile(fuse_req_t req, fuse_ino_t parent,
		      mode_t mode, struct fuse_file_info *fi);
void lo_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
void lo_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
void lo_flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
void lo_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
		     struct fuse_file_info *fi);
void lo_read(fuse_req_t req, fuse_ino_t ino, size_t size,
		    off_t offset, struct fuse_file_info *fi);
void lo_write_buf(fuse_req_t req, fuse_ino_t ino,
			 struct fuse_bufvec *in_buf, off_t off,
			 struct fuse_file_info *fi);
void lo_statfs(fuse_req_t req, fuse_ino_t ino);
void lo_fallocate(fuse_req_t req, fuse_ino_t ino, int mode,
			 off_t offset, off_t length, struct fuse_file_info *fi);
void lo_flock(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi,
		     int op);
void lo_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
			size_t size);
void lo_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size);
void lo_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
			const char *value, size_t size, int flags);
void lo_removexattr(fuse_req_t req, fuse_ino_t ino, const char *name);

#ifdef HAVE_COPY_FILE_RANGE
void lo_copy_file_range(fuse_req_t req, fuse_ino_t ino_in, off_t off_in,
			       struct fuse_file_info *fi_in,
			       fuse_ino_t ino_out, off_t off_out,
			       struct fuse_file_info *fi_out, size_t len,
			       int flags);
#endif

void lo_lseek(fuse_req_t req, fuse_ino_t ino, off_t off, int whence,
		     struct fuse_file_info *fi);



#endif