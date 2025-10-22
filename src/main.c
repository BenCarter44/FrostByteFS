

#include "main.h"

// based from passthrough_ll.c but organized.

static const struct fuse_lowlevel_ops lo_oper = {
	.init		= lo_init, // in runtime
	.destroy	= lo_destroy, // in runtime
	.lookup		= lo_lookup, 
	.mkdir		= lo_mkdir,
	.mknod		= lo_mknod,
	.symlink	= lo_symlink,
	.link		= lo_link,
	.unlink		= lo_unlink,
	.rmdir		= lo_rmdir,
	.rename		= lo_rename,
	.forget		= lo_forget,
	.forget_multi	= lo_forget_multi,
	.getattr	= lo_getattr,
	.setattr	= lo_setattr,
	.readlink	= lo_readlink,
	.opendir	= lo_opendir,
	.readdir	= lo_readdir,
	.readdirplus	= lo_readdirplus,
	.releasedir	= lo_releasedir,
	.fsyncdir	= lo_fsyncdir,
	.create		= lo_create,
	.tmpfile	= lo_tmpfile,
	.open		= lo_open,
	.release	= lo_release,
	.flush		= lo_flush,
	.fsync		= lo_fsync,
	.read		= lo_read,
	.write_buf      = lo_write_buf,
	.statfs		= lo_statfs,
	.fallocate	= lo_fallocate,
	.flock		= lo_flock,
	.getxattr	= lo_getxattr,
	.listxattr	= lo_listxattr,
	.setxattr	= lo_setxattr,
	.removexattr	= lo_removexattr,
#ifdef HAVE_COPY_FILE_RANGE
	.copy_file_range = lo_copy_file_range,
#endif
	.lseek		= lo_lseek,
};



int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_session *se;
	struct fuse_cmdline_opts opts;
	struct fuse_loop_config *config;
	struct lo_data lo = { .debug = 0,
	                      .writeback = 0 };
	int ret = -1;

	/* Don't mask creation mode, kernel already did that */
	umask(0);

	pthread_mutex_init(&lo.mutex, NULL);
	lo.root.next = lo.root.prev = &lo.root;
	lo.root.fd = -1;
	lo.cache = CACHE_NORMAL;

	if (fuse_parse_cmdline(&args, &opts) != 0)
		return 1;
	if (opts.show_help) {
		printf("usage: %s [options] <mountpoint>\n\n", argv[0]);
		fuse_cmdline_help();
		fuse_lowlevel_help();
		passthrough_ll_help();
		ret = 0;
		goto err_out1;
	} else if (opts.show_version) {
		printf("FUSE library version %s\n", fuse_pkgversion());
		fuse_lowlevel_version();
		ret = 0;
		goto err_out1;
	}

	if(opts.mountpoint == NULL) {
		printf("usage: %s [options] <mountpoint>\n", argv[0]);
		printf("       %s --help\n", argv[0]);
		ret = 1;
		goto err_out1;
	}

	if (parse_commandline(&args, &lo, NULL)== -1)
		return 1;

	lo.debug = opts.debug;
	lo.root.refcount = 2;
	if (lo.source) {
		struct stat stat;
		int res;

		res = lstat(lo.source, &stat);
		if (res == -1) {
			fuse_log(FUSE_LOG_ERR, "failed to stat source (\"%s\"): %m\n",
				 lo.source);
			exit(1);
		}
		if (!S_ISDIR(stat.st_mode)) {
			fuse_log(FUSE_LOG_ERR, "source is not a directory\n");
			exit(1);
		}

	} else {
		lo.source = strdup("/");
		if(!lo.source) {
			fuse_log(FUSE_LOG_ERR, "fuse: memory allocation failed\n");
			exit(1);
		}
	}
	if (!lo.timeout_set) {
		switch (lo.cache) {
		case CACHE_NEVER:
			lo.timeout = 0.0;
			break;

		case CACHE_NORMAL:
			lo.timeout = 1.0;
			break;

		case CACHE_ALWAYS:
			lo.timeout = 86400.0;
			break;
		}
	} else if (lo.timeout < 0) {
		fuse_log(FUSE_LOG_ERR, "timeout is negative (%lf)\n",
			 lo.timeout);
		exit(1);
	}

	lo.root.fd = open(lo.source, O_PATH);
	if (lo.root.fd == -1) {
		fuse_log(FUSE_LOG_ERR, "open(\"%s\", O_PATH): %m\n",
			 lo.source);
		exit(1);
	}

	se = fuse_session_new(&args, &lo_oper, sizeof(lo_oper), &lo);
	if (se == NULL)
	    goto err_out1;

	if (fuse_set_signal_handlers(se) != 0)
	    goto err_out2;

	if (fuse_session_mount(se, opts.mountpoint) != 0)
	    goto err_out3;

	fuse_daemonize(opts.foreground);

	/* Block until ctrl+c or fusermount -u */
	if (opts.singlethread)
		ret = fuse_session_loop(se);
	else {
		config = fuse_loop_cfg_create();
		fuse_loop_cfg_set_clone_fd(config, opts.clone_fd);
		fuse_loop_cfg_set_max_threads(config, opts.max_threads);
		ret = fuse_session_loop_mt(se, config);
		fuse_loop_cfg_destroy(config);
		config = NULL;
	}

	fuse_session_unmount(se);
err_out3:
	fuse_remove_signal_handlers(se);
err_out2:
	fuse_session_destroy(se);
err_out1:
	free(opts.mountpoint);
	fuse_opt_free_args(&args);

	if (lo.root.fd >= 0)
		close(lo.root.fd);

	free(lo.source);
	return ret ? 1 : 0;
}
