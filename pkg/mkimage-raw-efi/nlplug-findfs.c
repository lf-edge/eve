/*
 * Copy me if you can.
 * by 20h
 *
 * Copyright (c) 2015 Natanael Copa <ncopa@alpinelinux.org>
 * Copyright (c) 2016 Timo Teräs <timo.teras@iki.fi>
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <fnmatch.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <stdint.h>

#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <linux/netlink.h>

#include <libkmod.h>
#include <blkid.h>
#include <libcryptsetup.h>

#include "arg.h"

#define MAX_EVENT_TIMEOUT	5000
#define DEFAULT_EVENT_TIMEOUT	250
/* usb mass storage needs 1 sec to settle */
#define USB_STORAGE_TIMEOUT	1000

#define FOUND_DEVICE	0x1
#define FOUND_BOOTREPO	0x2
#define FOUND_APKOVL	0x4

#define LVM_PATH	"/sbin/lvm"
#define MDADM_PATH	"/sbin/mdadm"
#define ZPOOL_PATH	"/usr/sbin/zpool"

static int dodebug;
static char *default_envp[2];
char *argv0;
static int use_mdadm, use_lvm, use_zpool;

#if defined(DEBUG)
#include <stdarg.h>
static void dbg(const char *fmt, ...)
{
	va_list fmtargs;
	if (!dodebug)
		return;

	flockfile(stderr);
	fprintf(stderr, "%s: ", argv0);
	va_start(fmtargs, fmt);
	vfprintf(stderr, fmt, fmtargs);
	va_end(fmtargs);
	fprintf(stderr, "\n");
	funlockfile(stderr);
}
#else
#define dbg(...)
#endif

#define envcmp(env, key) (strncmp(env, key "=", strlen(key "=")) == 0)

#ifndef container_of
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})
#endif

struct list_head {
	struct list_head *next, *prev;
};
#define LIST_INITIALIZER(l) (struct list_head){ .next = &l, .prev = &l }

static inline void list_init(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void __list_add(struct list_head *new, struct list_head *prev,
			      struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head * prev, struct list_head * next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = NULL;
	entry->prev = NULL;
}

static inline int list_hashed(const struct list_head *n)
{
	return n->next != n && n->next != NULL;
}

static inline int list_empty(const struct list_head *n)
{
	return !list_hashed(n);
}

#define list_next(ptr, type, member) \
	(list_hashed(ptr) ? container_of((ptr)->next,type,member) : NULL)

#define list_entry(ptr, type, member) container_of(ptr,type,member)

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = list_entry(pos->member.next, typeof(*pos), member))

static char **clone_array(char *const *const a)
{
	size_t i, s;
	char **c, *p;

	if (!a) return 0;

	s = sizeof(char*);
	for (i = 0; a[i]; i++)
		s += sizeof(char*) + strlen(a[i]) + 1;
	c = malloc(s);
	p = (char*)(c + i + 1);
	for (i = 0; a[i]; i++) {
		c[i] = p;
		p += sprintf(p, "%s", a[i]) + 1;
	}
	c[i] = 0;
	return c;
}

struct spawn_task {
	struct list_head node;
	void (*done)(void *ctx, int status);
	pid_t pid;
	void *ctx;
	char **argv, **envp;
};

#define SPAWNMGR_PID_HASH_SIZE 32
struct spawn_manager {
	int num_running;
	int max_running;
	struct list_head queue;
	struct list_head running[SPAWNMGR_PID_HASH_SIZE];
};

static struct spawn_manager spawnmgr;

static void dbgT(struct spawn_task *task, const char *fmt, ...)
{
#if defined(DEBUG)
	va_list fmtargs;
	int i;

	if (!dodebug)
		return;

	flockfile(stderr);
	fprintf(stderr, "%s: [%d] ", argv0, task->pid);
	va_start(fmtargs, fmt);
	vfprintf(stderr, fmt, fmtargs);
	va_end(fmtargs);
	for (i = 0; task->argv[i]; i++)
		fprintf(stderr, " %s", task->argv[i]);
	if (task->envp) {
		fprintf(stderr, ":");
		for (i = 1; task->envp[i]; i++)
			fprintf(stderr, " %s", task->envp[i]);
	}
	fprintf(stderr, "\n");
	funlockfile(stderr);
#endif
}

static void spawn_init(struct spawn_manager *mgr)
{
	int i;

	mgr->max_running = sysconf(_SC_NPROCESSORS_ONLN);
	list_init(&mgr->queue);
	for (i = 0; i < SPAWNMGR_PID_HASH_SIZE; i++)
		list_init(&mgr->running[i]);

	dbg("max_running=%d", mgr->max_running);
}

static void spawn_task_done(struct spawn_task *task, int status)
{
	if (task->done) task->done(task->ctx, status);
	list_del(&task->node);
	free(task->argv);
	free(task->envp);
	free(task);
}

static void spawn_execute(struct spawn_manager *mgr, struct spawn_task *task)
{
	pid_t pid;

	if (!(pid = fork())) {
		execve(task->argv[0], task->argv, task->envp ? task->envp : default_envp);
		err(127, task->argv[0]);
	}
	if (pid < 0)
		err(1, "fork");

	task->pid = pid;
	list_add_tail(&task->node, &mgr->running[pid % SPAWNMGR_PID_HASH_SIZE]);
	mgr->num_running++;

	dbgT(task, "spawned (%d running):", mgr->num_running);
}

static void spawn_command_cb(struct spawn_manager *mgr, char **argv, char **envp, void (*done)(void *, int), void *ctx)
{
	struct spawn_task *task;

	task = malloc(sizeof *task);
	if (!task) return;
	*task = (struct spawn_task) {
		.done = done,
		.node = LIST_INITIALIZER(task->node),
		.argv = clone_array(argv),
		.envp = clone_array(envp),
		.ctx  = ctx,
	};

	if (mgr->num_running < mgr->max_running)
		spawn_execute(mgr, task);
	else
		list_add_tail(&task->node, &mgr->queue);
}

static void spawn_command(struct spawn_manager *mgr, char **argv, char **envp)
{
	spawn_command_cb(mgr, argv, envp, 0, 0);
}

static void spawn_reap(struct spawn_manager *mgr, pid_t pid, int status)
{
	struct spawn_task *task;

	list_for_each_entry(task, &mgr->running[pid % SPAWNMGR_PID_HASH_SIZE], node) {
		if (task->pid == pid)
			goto found;
	}
	dbg("pid %d not found", pid);
	return;

found:
	mgr->num_running--;
	dbgT(task, "reaped (%d running):", mgr->num_running);
	spawn_task_done(task, status);

	if (!list_empty(&mgr->queue) && mgr->num_running < mgr->max_running) {
		struct spawn_task *task = list_next(&mgr->queue, struct spawn_task, node);
		list_del(&task->node);
		spawn_execute(mgr, task);
	}
}

static int spawn_active(struct spawn_manager *mgr)
{
	return mgr->num_running || !list_empty(&mgr->queue);
}

struct cryptdev {
	char *device;
	char *name;
	char *key;
	char devnode[256];
};

struct cryptconf {
	struct cryptdev data;
	struct cryptdev header;
	size_t payload_offset;
	pthread_t tid;
	pthread_mutex_t mutex;
	uint32_t flags;
};

struct ueventconf {
	char **program_argv;
	char *search_device;
	blkid_cache blkid_cache;
	struct cryptconf crypt;
	char *subsystem_filter;
	int modalias_count;
	int fork_count;
	char *bootrepos;
	char *apkovls;
	int timeout;
	int usb_storage_timeout;
	int uevent_timeout;
	int efd;
	int found;

	int running_threads;

	pthread_mutex_t trigger_mutex;
	pthread_cond_t trigger_cond;
	struct list_head trigger_list;

	int cryptsetup_running;
};

struct uevent {
	struct ueventconf *conf;
	int ref;
	size_t bufsize;
	char *message;
	char *subsystem;
	char *action;
	char *modalias;
	char *devname;
	char *devpath;
	char *major;
	char *minor;
	char devnode[256];
	char *envp[64];
	char buf[];
};

static struct uevent *uevent_ref(struct uevent *ev)
{
	ev->ref++;
	return ev;
}

static void uevent_unref(struct uevent *ev)
{
	ev->ref--;
	if (ev->ref != 0) return;
	free(ev);
}

static void sighandler(int sig)
{
	switch (sig) {
	case SIGHUP:
	case SIGINT:
	case SIGQUIT:
	case SIGABRT:
	case SIGTERM:
		exit(0);
	default:
		break;
	}
}

static void initsignals(void)
{
	signal(SIGHUP, sighandler);
	signal(SIGINT, sighandler);
	signal(SIGQUIT, sighandler);
	signal(SIGABRT, sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGCHLD, sighandler);
	signal(SIGPIPE, SIG_IGN);
}

static int init_netlink_socket(void)
{
	struct sockaddr_nl nls;
	int fd, slen;

	memset(&nls, 0, sizeof(nls));
	nls.nl_family = AF_NETLINK;
	nls.nl_pid = getpid();
	nls.nl_groups = -1;

	fd = socket(PF_NETLINK, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
		    NETLINK_KOBJECT_UEVENT);
	if (fd < 0)
		err(1, "socket");

	/* kernel will not create events bigger than 16kb, but we need
	   buffer up all events during coldplug */
	slen = 512*1024;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &slen,
				sizeof(slen)) < 0) {
		err(1, "setsockopt");
	}
	slen = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &slen,
				sizeof(slen)) < 0) {
		err(1, "setsockopt");
	}

	if (bind(fd, (void *)&nls, sizeof(nls)))
		err(1, "bind");

	return fd;
}

static int load_kmod(const char *modalias, char *driver, size_t len)
{
	static struct kmod_ctx *ctx = NULL;
	struct kmod_list *list = NULL;
	struct kmod_list *node;
	int r, count=0;

	if (driver) driver[0] = 0;

	if (ctx == NULL) {
		dbg("initializing kmod");
		ctx = kmod_new(NULL, NULL);
		if (ctx == NULL)
			return -1;
		kmod_set_log_fn(ctx, NULL, NULL);
		r = kmod_load_resources(ctx);
	}

	r = kmod_module_new_from_lookup(ctx, modalias, &list);
	if (r < 0) {
		dbg("alias '%s' lookup failure: %d", modalias, r);
		return r;
	}

	kmod_list_foreach(node, list) {
		struct kmod_module *mod = kmod_module_get_module(node);
		const char *fmt;
		r = kmod_module_probe_insert_module(mod,
						    KMOD_PROBE_APPLY_BLACKLIST,
						    NULL, NULL, NULL, NULL);
		if (r == 0) {
			fmt = "module '%s' inserted";
			count++;
		} else if (r == KMOD_PROBE_APPLY_BLACKLIST) {
			fmt = "module '%s' is blacklisted";
		} else {
			fmt = "module '%s' failed";
		}
		dbg(fmt, kmod_module_get_name(mod));
		if (driver) strlcpy(driver, kmod_module_get_name(mod), len);
		kmod_module_unref(mod);
	}
	kmod_module_unref_list(list);
	return count;
}

static void start_mdadm(char *devnode)
{
	char *mdadm_argv[] = {
		MDADM_PATH,
		"--incremental",
		"--quiet",
		devnode,
		NULL
	};
	if (use_mdadm)
		spawn_command(&spawnmgr, mdadm_argv, 0);
}

static void start_lvm2(char *devnode)
{
	char *lvm2_argv[] = {
		LVM_PATH, "vgchange",
		"--activate" , "ay", "--noudevsync", "--sysinit", "-q", "-q",
		NULL
	};
	if (use_lvm)
		spawn_command(&spawnmgr, lvm2_argv, 0);
}

static void start_zpool(char *uuid) {
	char *zpool_argv[] = {
		ZPOOL_PATH, "import", uuid,
		NULL
	};
	if (use_zpool && uuid)
		spawn_command(&spawnmgr, zpool_argv, 0);
}

static int read_pass(char *pass, size_t pass_size)
{
	struct termios old_flags, new_flags;
	int r;

	tcgetattr(STDIN_FILENO, &old_flags);
	new_flags = old_flags;
	new_flags.c_lflag &= ~ECHO;
	new_flags.c_lflag |= ECHONL;

	if (isatty(STDIN_FILENO)) {
		r = tcsetattr(STDIN_FILENO, TCSANOW, &new_flags);
		if (r < 0) {
			warn("tcsetattr");
			return r;
		}
	}// else {
	//	fprintf(stderr, "The program isn't executed in a TTY, the echo-disabling has been skipped.\n");
	//}

	if (fgets(pass, pass_size, stdin) == NULL) {
		warn("fgets");
		return -1;
	}
	pass[strlen(pass) - 1] = '\0';

	if (isatty(STDIN_FILENO)) {
		if (tcsetattr(STDIN_FILENO, TCSANOW, &old_flags) < 0) {
			warn("tcsetattr");
		}
	}// else {
	//	fprintf(stderr, "The program isn't executed in a TTY, the echo-reenabling has been skipped.\n");
	//}

	return 0;
}

static void notify_main(struct ueventconf *conf)
{
	uint64_t one = 1;
	write(conf->efd, &one, sizeof one);
}

static void *cryptsetup_thread(void *data)
{
	struct ueventconf *c = (struct ueventconf *)data;
	const char *data_devnode, *header_devnode;
	struct crypt_params_luks1 param_struct;
	struct crypt_params_luks1 *params = NULL;
	struct crypt_device *cd;
	int r, passwd_tries = 5;

	data_devnode = header_devnode = c->crypt.data.devnode;

	if(c->crypt.header.devnode[0] != '\0') {
		params = &param_struct;
		params->hash = NULL; /* No way of finding this */
		params->data_alignment = c->crypt.payload_offset; /* Memset did set that to 0, so default is 0 */
		params->data_device = c->crypt.data.devnode;
		header_devnode = c->crypt.header.devnode;
	}

	r = crypt_init(&cd, header_devnode);
	if (r < 0) {
		warnx("crypt_init(%s)", header_devnode);
		goto notify_out;
	}

	r = crypt_load(cd, CRYPT_LUKS, params);
	if (r < 0) {
		warnx("crypt_load(%s)", data_devnode);
		goto free_out;
	}

	r = crypt_set_data_device(cd, data_devnode);
	if (r < 0) {
		warnx("crypt_set_data_device(%s)", data_devnode);
		goto free_out;
	}

	struct stat st;
	if (!stat(c->crypt.data.key, &st)) {
		pthread_mutex_lock(&c->crypt.mutex);
		r = crypt_activate_by_keyfile(cd, c->crypt.data.name,
					      CRYPT_ANY_SLOT,
					      c->crypt.data.key, st.st_size,
					      c->crypt.flags);
		pthread_mutex_unlock(&c->crypt.mutex);
		if (r >= 0)
			goto free_out;
	}

	while (passwd_tries > 0) {
		char pass[1024];

		printf("Enter passphrase for %s: ", c->crypt.data.devnode);
		fflush(stdout);

		if (read_pass(pass, sizeof(pass)) < 0)
			goto free_out;
		passwd_tries--;

		pthread_mutex_lock(&c->crypt.mutex);
		r = crypt_activate_by_passphrase(cd, c->crypt.data.name,
						 CRYPT_ANY_SLOT,
						 pass, strlen(pass),
						 c->crypt.flags);
		pthread_mutex_unlock(&c->crypt.mutex);
		memset(pass, 0, sizeof(pass)); /* wipe pass after use */

		if (r >= 0)
			goto free_out;
		printf("No key available with this passphrase.\n");
	}
	printf("Mounting %s failed, amount of tries exhausted.\n", c->crypt.data.devnode);

free_out:
	crypt_free(cd);
notify_out:
	c->cryptsetup_running = 0;
	notify_main(c);
	return NULL;
}

static void start_thread(struct ueventconf *conf, void *(*thread_main)(void *))
{
	pthread_t tid;
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (pthread_create(&tid, &attr, thread_main, conf) != 0)
		err(1, "failed to create thread");
	pthread_attr_destroy(&attr);
}

static void start_cryptsetup(struct ueventconf *conf)
{
	if(conf->crypt.header.devnode[0] != '\0') {
		dbg("starting cryptsetup %s -> %s (header: %s)",
		    conf->crypt.data.devnode, conf->crypt.data.name,
		    conf->crypt.header.devnode);
	} else {
		dbg("starting cryptsetup %s -> %s", conf->crypt.data.devnode,
		    conf->crypt.data.name);
	}
	load_kmod("dm-crypt", NULL, 0);
	conf->cryptsetup_running = 1;
	conf->running_threads = 1;
	start_thread(conf, cryptsetup_thread);
}

static int is_mounted(const char *devnode) {
	char line[PATH_MAX];
	FILE *f = fopen("/proc/mounts", "r");
	int r = 0;
	if (f == NULL)
		return 0;
	while (fgets(line, sizeof(line), f) != NULL) {
		strtok(line, " ");
		if (strcmp(devnode, line) == 0) {
			r = 1;
			break;
		}
	}
	fclose(f);
	return r;
}

struct recurse_opts {
	size_t pathlen;
	char path[PATH_MAX], *filename;
	int is_dir;
	int matchdepth;
	int curdepth, maxdepth;
	void (*callback)(struct recurse_opts *opts, void *userdata);
	void *userdata;
};

static int recurse_push(struct recurse_opts *opts, size_t *oldlen, const char *path)
{
	size_t pathlen = strlen(path);
	if (opts->pathlen + 1 + pathlen + 1 >= sizeof opts->path)
		return 0;
	*oldlen = opts->pathlen;
	opts->path[opts->pathlen++] = '/';
	strcpy(&opts->path[opts->pathlen], path);
	opts->pathlen += strlen(path);
	return 1;
}

static void recurse_pop(struct recurse_opts *opts, size_t len)
{
	opts->pathlen = len;
	opts->path[len] = 0;
}

static void do_recurse_dir(struct recurse_opts *opts)
{
	size_t oldlen;
	struct dirent *entry;
	DIR *d;
	int is_dir;

	d = opendir(opts->path);
	if (!d) return;

	while ((entry = readdir(d)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0)
			continue;

		if (!recurse_push(opts, &oldlen, entry->d_name))
			continue;

		if (entry->d_type == DT_UNKNOWN) {
			/* some filesystems like iso9660 does not support
			   the d_type so we use lstat */
			struct stat st;
			if (lstat(opts->path, &st) < 0) {
				dbg("%s: %s", opts->path, strerror(errno));
				goto next;
			}
			is_dir = S_ISDIR(st.st_mode);
		} else
			is_dir = entry->d_type & DT_DIR;

		if (opts->matchdepth == 0 || opts->matchdepth == opts->curdepth) {
			opts->filename = &opts->path[oldlen+1];
			opts->is_dir = is_dir;
			opts->callback(opts, opts->userdata);
		}

		if (is_dir && opts->curdepth < opts->maxdepth) {
			opts->curdepth++;
			do_recurse_dir(opts);
			opts->curdepth--;
		}
next:
		recurse_pop(opts, oldlen);
	}
	closedir(d);
}

static void recurse_dir(struct recurse_opts *opts)
{
	opts->pathlen = strlen(opts->path);
	opts->curdepth = 1;
	do_recurse_dir(opts);
}

struct trigger_entry {
	struct list_head node;
	int max_depth;
	char pathname[];
};

static void trigger_uevent_cb(struct recurse_opts *opts, void *data)
{
	size_t oldlen;
	int fd;

	if (!recurse_push(opts, &oldlen, "uevent"))
		return;

	fd = open(opts->path, O_WRONLY | O_CLOEXEC);
	if (fd >= 0) {
		write(fd, "add", 3);
		close(fd);
	}
	recurse_pop(opts, oldlen);
}

static void trigger_path(struct ueventconf *conf, char *path, char *subdir, int max_depth)
{
	struct trigger_entry *e;
	size_t pathlen = strlen(path);

	e = malloc(pathlen + (subdir ? strlen(subdir) : 0) + 1 + sizeof *e);
	if (!e) return;

	list_init(&e->node);
	e->max_depth = max_depth;
	strcpy(e->pathname, path);
	if (subdir) strcpy(&e->pathname[pathlen], subdir);

	pthread_mutex_lock(&conf->trigger_mutex);
	conf->running_threads = 1;
	list_add_tail(&e->node, &conf->trigger_list);
	pthread_cond_signal(&conf->trigger_cond);
	pthread_mutex_unlock(&conf->trigger_mutex);
}

static void *trigger_thread(void *data)
{
	struct ueventconf *conf = data;
	struct recurse_opts opts;
	struct trigger_entry *entry = NULL;

	while (1) {
		pthread_mutex_lock(&conf->trigger_mutex);
		if (entry) {
			list_del(&entry->node);
			free(entry);
		}
		entry = list_next(&conf->trigger_list, struct trigger_entry, node);
		while (!entry) {
			notify_main(conf);
			pthread_cond_wait(&conf->trigger_cond, &conf->trigger_mutex);
			entry = list_next(&conf->trigger_list, struct trigger_entry, node);
		}
		pthread_mutex_unlock(&conf->trigger_mutex);

		opts = (struct recurse_opts) {
			.callback = trigger_uevent_cb,
			.userdata = entry,
			.maxdepth = entry->max_depth,
			.matchdepth = entry->max_depth,
		};
		snprintf(opts.path, sizeof opts.path, "/sys%s", entry->pathname);
		dbg("trigger_thread: scanning %s", opts.path);

		recurse_dir(&opts);
	}

	return NULL;
}

static void append_line(const char *outfile, const char *data)
{
	int fd;
	if (outfile == 0) return;
	fd = open(outfile, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC);
	if (fd == -1)
		err(1, "%s", outfile);
	write(fd, data, strlen(data));
	write(fd, "\n", 1);
	close(fd);
}

struct scandevctx {
	struct ueventconf *conf;
	int found;
};

static void scandev_cb(struct recurse_opts *opts, void *data)
{
	struct scandevctx *ctx = data;
	struct ueventconf *conf = ctx->conf;

	if (opts->is_dir) {
		size_t oldlen;
		int ok = 0;
		if (recurse_push(opts, &oldlen, ".boot_repository")) {
			ok = access(opts->path, F_OK) == 0;
			recurse_pop(opts, oldlen);
		}
		if (ok) {
			dbg("added boot repository %s to %s", opts->path, conf->bootrepos);
			append_line(conf->bootrepos, opts->path);
			ctx->found |= FOUND_BOOTREPO;
		}
	} else if (fnmatch("*.apkovl.tar.gz*", opts->filename, 0) == 0) {
		dbg("found apkovl %s", opts->path);
		append_line(conf->apkovls, opts->path);
		ctx->found |= FOUND_APKOVL;
	}
}

static int scandev(struct ueventconf *conf, const char *devnode, const char *type)
{
	struct scandevctx ctx = {
		.conf = conf,
	};
	struct recurse_opts opts = {
		.maxdepth = 1,
		.callback = scandev_cb,
		.userdata = &ctx,
	};
	char *devname;
	int r;

	/* skip already mounted devices */
	if (is_mounted(devnode)) {
		dbg("%s is mounted (%s). skipping", devnode, type);
		return 0;
	}
	devname = strrchr(devnode, '/');
	if (!devname)
		return 0;

	snprintf(opts.path, sizeof opts.path, "/media%s", devname);
	dbg("mounting %s on %s (%s)", devnode, opts.path, type);
	mkdir(opts.path, 0755);

	r = mount(devnode, opts.path, type, MS_RDONLY, NULL);
	if (r < 0) {
		dbg("Failed to mount %s on %s: %s",
		    devnode, opts.path, strerror(errno));
		return 0;
	}

	recurse_dir(&opts);

	if (ctx.found == 0)
		umount(opts.path);

	return ctx.found;
}

static int is_same_device(const struct uevent *ev, const char *nodepath)
{
	struct stat st;
	unsigned int maj, min;
	if (stat(nodepath, &st) < 0)
		return 0;

	if (ev->major == NULL || ev->minor == NULL)
		return 0;

	maj = atoi(ev->major);
	min = atoi(ev->minor);
	return S_ISBLK(st.st_mode) && makedev(maj, min) == st.st_rdev;
}

static void founddev(struct ueventconf *conf, int found)
{
	conf->found |= found;
	if ((found & FOUND_DEVICE)
	    || ((found & FOUND_BOOTREPO) &&
		(found & FOUND_APKOVL))) {
		/* we have found everything we need, so no
		   no need to wait for anything new event */
		if (conf->timeout)
			dbg("FOUND! setting timeout to 0");
		conf->timeout = 0;
		conf->usb_storage_timeout= 0;
	} else if ((found & FOUND_BOOTREPO) && conf->timeout) {
		/* we have found boot repo, but not apkovl
		   we reduce timeout to default timeout */
		if (conf->timeout != conf->uevent_timeout)
			dbg("Setting timeout to %d", conf->uevent_timeout);
		conf->timeout = conf->uevent_timeout;
	}
}

static int is_zfs_pool(const char *path, const char *label)
{
	char pool_name[256];
	char *p;
	snprintf(pool_name, sizeof(pool_name), "%s", path);
	if ((p = strchr(pool_name, '/')))
		*p = '\0';
	return strcmp(label, pool_name) == 0 ? FOUND_DEVICE : 0;
}

static int searchdev(struct uevent *ev, const char *searchdev, int scanbootmedia)
{
	struct ueventconf *conf = ev->conf;
	char *type = NULL, *label = NULL, *uuid = NULL;
	int rc = 0;

	if (searchdev == NULL && !scanbootmedia)
		return 0;

	if (searchdev && (strcmp(ev->devname, searchdev) == 0
			  || strcmp(ev->devnode, searchdev) == 0
	                  || is_same_device(ev, searchdev))) {
		return FOUND_DEVICE;
	}

	if (conf->blkid_cache == NULL)
		blkid_get_cache(&conf->blkid_cache, NULL);

	type = blkid_get_tag_value(conf->blkid_cache, "TYPE", ev->devnode);
	uuid = blkid_get_tag_value(conf->blkid_cache, "UUID", ev->devnode);
	label = blkid_get_tag_value(conf->blkid_cache, "LABEL", ev->devnode);

	if (searchdev != NULL) {
		if (strncmp("LABEL=", searchdev, 6) == 0) {
			if (label && strcmp(label, searchdev+6) == 0)
				rc = FOUND_DEVICE;
		} else if (strncmp("UUID=", searchdev, 5) == 0) {
			if (uuid && strcmp(uuid, searchdev+5) == 0)
				rc = FOUND_DEVICE;
		}
	}

	dbg("searchdev: dev='%s' type='%s' label='%s' uuid='%s'",
		ev->devnode, type, label, uuid);

	if (!rc && type) {
		if (strcmp("linux_raid_member", type) == 0) {
			start_mdadm(ev->devnode);
		} else if (strcmp("LVM2_member", type) == 0) {
			start_lvm2(ev->devnode);
		} else if (strcmp("zfs_member", type) == 0) {
			start_zpool(uuid);
			if (searchdev != NULL && label != NULL
			    && strncmp("ZFS=", searchdev, 4) == 0) {
				rc = is_zfs_pool(&searchdev[4], label);
			}
		} else if (scanbootmedia) {
			rc = scandev(conf, ev->devnode, type);
		}
	}

	if (type)
		free(type);
	if (label)
		free(label);
	if (uuid)
		free(uuid);

	return rc;
}

/* search for crypt.data and crypt.header.
   returns true if we are ready to start cryptsetup. */
static int search_cryptdevs(struct uevent *ev, struct cryptconf *crypt)
{
	if (crypt->data.devnode[0] == '\0' && searchdev(ev, crypt->data.device, 0)) {
		strncpy(crypt->data.devnode,
			crypt->data.device[0] == '/' ? crypt->data.device : ev->devnode,
			sizeof(crypt->data.devnode));
		/* if we don't have header or header is found, then we are
		   ready to start crypsetup */
		return (crypt->header.device == NULL)
			|| (crypt->header.devnode[0] != '\0');
	}

	if (crypt->header.device == NULL)
		return 0;

	if (crypt->header.devnode[0] == '\0' && searchdev(ev, crypt->header.device, 0)) {
		strncpy(crypt->header.devnode,
			crypt->header.device[0] == '/' ? crypt->header.device : ev->devnode,
			sizeof(crypt->header.devnode));
		/* if we also have found data dev, then we are ready to
		   start cryptsetup */
		return crypt->data.devnode[0] != '\0';
	}
	return 0;
}

static void uevent_handle(struct uevent *ev)
{
	struct ueventconf *conf = ev->conf;
	int found;

	if (!ev->subsystem || strcmp(ev->subsystem, "block") != 0)
		return;

	if (strcmp(ev->action, "add") != 0 &&
	    strcmp(ev->action, "change") != 0)
		return;

	snprintf(ev->devnode, sizeof(ev->devnode), "/dev/%s", ev->devname);
	pthread_mutex_lock(&conf->crypt.mutex);
	found = searchdev(ev, conf->search_device, (conf->apkovls || conf->bootrepos));
	pthread_mutex_unlock(&conf->crypt.mutex);
	if (found) {
		founddev(conf, found);
	} else if (search_cryptdevs(ev, &conf->crypt)) {
		start_cryptsetup(conf);
	}
}

static void uevent_mdev_done_cb(void *ctx, int status)
{
	struct uevent *ev = ctx;
	uevent_handle(ev);
	uevent_unref(ev);
}

static void uevent_dispatch(struct uevent *ev)
{
	struct ueventconf *conf = ev->conf;
	int add;

	if (conf->subsystem_filter && ev->subsystem
	    && strcmp(ev->subsystem, conf->subsystem_filter) != 0) {
		dbg("subsystem '%s' filtered out (by '%s').",
		    ev->subsystem, conf->subsystem_filter);
		return;
	}

	if (ev->action == NULL)
		return;

	dbg("uevent: action='%s' subsystem='%s' devname='%s' devpath='%s'",
		ev->action, ev->subsystem, ev->devname, ev->devpath);

	add = strcmp(ev->action, "add") == 0;

	if (add && ev->subsystem && strcmp(ev->subsystem, "bus") == 0) {
		trigger_path(conf, ev->devpath, "/devices", 1);
	} else if (add && ev->modalias) {
		char buf[128];
		load_kmod(ev->modalias, buf, sizeof buf);
		conf->modalias_count++;
		/* increase timeout so usb drives gets time to settle */
		if (strcmp(buf, "usb_storage") == 0)
			conf->usb_storage_timeout = USB_STORAGE_TIMEOUT;

	} else if (ev->devname) {
		if (conf->program_argv[0] != NULL) {
			spawn_command_cb(&spawnmgr, conf->program_argv, ev->envp,
					 uevent_mdev_done_cb, uevent_ref(ev));
			conf->fork_count++;
		} else {
			uevent_handle(ev);
		}
	}
}

static void uevent_process(char *buf, const size_t len, struct ueventconf *conf)
{
	struct uevent *ev;
	int i, nenvp, slen = 0;
	char *key, *value;

	ev = malloc(len + sizeof *ev);
	if (!ev) return;

	memset(ev, 0, sizeof *ev);
	memcpy(ev->buf, buf, len);
	ev->ref = 1;
	ev->conf = conf;
	ev->bufsize = len;

	nenvp = sizeof(default_envp) / sizeof(default_envp[0]) - 1;
	memcpy(&ev->envp, default_envp, nenvp * sizeof(default_envp[0]));

	for (i = 0; i < len; i += slen + 1) {
		key = ev->buf + i;
		value = strchr(key, '=');
		slen = strlen(ev->buf + i);

		if (i == 0 && slen != 0) {
			/* first line, the message */
			ev->message = key;
			continue;
		}

		if (!slen || !value)
			continue;

		value++;
		if (envcmp(key, "MODALIAS")) {
			ev->modalias = value;
		} else if (envcmp(key, "ACTION")) {
			ev->action = value;
		} else if (envcmp(key, "SUBSYSTEM")) {
			ev->subsystem = value;
		} else if (envcmp(key, "DEVNAME")) {
			ev->devname = value;
		} else if (envcmp(key, "DEVPATH")) {
			ev->devpath = value;
		} else if (envcmp(key, "MAJOR")) {
			ev->major = value;
		} else if (envcmp(key, "MINOR")) {
			ev->minor = value;
		}

		if (!envcmp(key, "PATH"))
			ev->envp[nenvp++]= key;
	}
	ev->envp[nenvp++] = 0;

	uevent_dispatch(ev);
	uevent_unref(ev);
}

static void usage(int rc)
{
	printf("coldplug system til given device is found\n"
	"usage: %s [options] DEVICE\n"
	"\n"
	"options:\n"
	" -a OUTFILE      add paths to found apkovls to OUTFILE\n"
	" -b OUTFILE      add found boot repositories to OUTFILE\n"
	" -c CRYPTDEVICE  run cryptsetup luksOpen when CRYPTDEVICE is found\n"
	" -h              show this help\n"
	" -H HEADERDEVICE use HEADERDEVICE as the LUKS header\n"
	" -k CRYPTKEY     path to keyfile\n"
	" -m CRYPTNAME    use CRYPTNAME name for crypto device mapping\n"
	" -o OFFSET       cryptsetup payload offset\n"
	" -D              allow discards on crypto device\n"
	" -d              enable debugging ouput\n"
	" -f SUBSYSTEM    filter subsystem\n"
	" -p PROGRAM      use PROGRAM as handler for every event with DEVNAME\n"
	" -t TIMEOUT      timeout after TIMEOUT milliseconds without uevents\n"
	"\n", argv0);

	exit(rc);
}

static int regular_file(const char *path)
{
	struct stat st;
	int r = stat(path, &st);
	return r == -1 ? 0 : S_ISREG(st.st_mode);
}

int main(int argc, char *argv[])
{
	struct pollfd fds[3];
	int numfds = 3;
	int r;
	struct ueventconf conf;
	int event_count = 0;
	size_t total_bytes = 0;
	int not_found_is_ok = 0;
	char *program_argv[2] = {0,0};
	sigset_t sigchldmask;

	for (r = 0; environ[r]; r++) {
		if (envcmp(environ[r], "PATH"))
			default_envp[0] = environ[r];
	}

	spawn_init(&spawnmgr);

	memset(&conf, 0, sizeof(conf));
	pthread_mutex_init(&conf.trigger_mutex, NULL);
	pthread_cond_init(&conf.trigger_cond, NULL);
	list_init(&conf.trigger_list);
	pthread_mutex_init(&conf.crypt.mutex, NULL);

	conf.program_argv = program_argv;
	conf.timeout = MAX_EVENT_TIMEOUT;
	conf.usb_storage_timeout = 0;
	conf.uevent_timeout = DEFAULT_EVENT_TIMEOUT;
	use_lvm = access(LVM_PATH, X_OK) == 0;
	use_mdadm = access(MDADM_PATH, X_OK) == 0;
	use_zpool = access(ZPOOL_PATH, X_OK) == 0;

	argv0 = strrchr(argv[0], '/');
	if (argv0++ == NULL)
		argv0 = argv[0];

	ARGBEGIN {
	case 'a':
		conf.apkovls = EARGF(usage(1));;
		break;
	case 'b':
		conf.bootrepos = EARGF(usage(1));
		break;
	case 'c':
		conf.crypt.data.device = EARGF(usage(1));
		break;
	case 'H':
		conf.crypt.header.device = EARGF(usage(1));
		/* the header may be in a regular file and not a device */
		if (regular_file(conf.crypt.header.device)) {
			snprintf(conf.crypt.header.devnode,
				sizeof(conf.crypt.header.devnode),
				"%s", conf.crypt.header.device);
		}
		break;
	case 'h':
		usage(0);
		break;
	case 'k':
		conf.crypt.data.key = EARGF(usage(1));
		break;
	case 'm':
		conf.crypt.data.name = EARGF(usage(1));
		break;
	case 'n':
		not_found_is_ok = 1;
		break;
	case 'D':
		conf.crypt.flags |= CRYPT_ACTIVATE_ALLOW_DISCARDS;
		break;
	case 'd':
		dodebug = 1;
		break;
	case 'f':
		conf.subsystem_filter = EARGF(usage(1));
		break;
	case 'o':
		if(sscanf(EARGF(usage(1)), "%zu", &conf.crypt.payload_offset) != 1)
			err(1, "sscanf");
		break;
	case 'p':
		conf.program_argv[0] = EARGF(usage(1));
		break;
	case 't':
		conf.uevent_timeout = atoi(EARGF(usage(1)));
		break;
	default:
		usage(1);
	} ARGEND;

	if (argc > 0)
		conf.search_device = argv[0];

	initsignals();
	sigemptyset(&sigchldmask);
	sigaddset(&sigchldmask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &sigchldmask, NULL);

	fds[0].fd = init_netlink_socket();
	fds[0].events = POLLIN;

	fds[1].fd = signalfd(-1, &sigchldmask, SFD_NONBLOCK|SFD_CLOEXEC);
	fds[1].events = POLLIN;

	fds[2].fd = eventfd(0, EFD_CLOEXEC);
	fds[2].events = POLLIN;
	conf.efd = fds[2].fd;

	trigger_path(&conf, "/bus", NULL, 1);
	trigger_path(&conf, "/class", NULL, 2);
	start_thread(&conf, trigger_thread);

	while (1) {
		int t = conf.timeout + conf.usb_storage_timeout;
		r = poll(fds, numfds, (spawn_active(&spawnmgr) || conf.running_threads) ? -1 : t);
		if (r == -1) {
			if (errno == EINTR || errno == ERESTART)
				continue;
			err(1, "poll");
		}
		if (r == 0) {
			dbg("exit due to timeout (%i)", t);
			break;
		}

		if (fds[0].revents & POLLIN) {
			size_t len;
			struct iovec iov;
			char cbuf[CMSG_SPACE(sizeof(struct ucred))];
			char buf[16384];
			struct cmsghdr *chdr;
			struct ucred *cred;
			struct msghdr hdr;
			struct sockaddr_nl cnls;

			iov.iov_base = &buf;
			iov.iov_len = sizeof(buf);
			memset(&hdr, 0, sizeof(hdr));
			hdr.msg_iov = &iov;
			hdr.msg_iovlen = 1;
			hdr.msg_control = cbuf;
			hdr.msg_controllen = sizeof(cbuf);
			hdr.msg_name = &cnls;
			hdr.msg_namelen = sizeof(cnls);

			len = recvmsg(fds[0].fd, &hdr, 0);
			if (len < 0) {
				if (errno == EINTR)
					continue;
				err(1, "recvmsg");
			}
			if (len < 32 || len >= sizeof(buf))
				continue;

			total_bytes += len;
			chdr = CMSG_FIRSTHDR(&hdr);
			if (chdr == NULL || chdr->cmsg_type != SCM_CREDENTIALS)
				continue;

			/* filter out messages that are not from root or kernel */
			cred = (struct ucred *)CMSG_DATA(chdr);
			if (cred->uid != 0 || cnls.nl_pid > 0)
				continue;

			event_count++;
			uevent_process(buf, len, &conf);
		}

		if (fds[0].revents & POLLHUP) {
			dbg("parent hung up\n");
			break;
		}

		if (fds[1].revents & POLLIN) {
			struct signalfd_siginfo fdsi;
			pid_t pid;
			int status;

			while (read(fds[1].fd, &fdsi, sizeof fdsi) > 0)
				;
			while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
				spawn_reap(&spawnmgr, pid, status);
		}

		if (fds[2].revents & POLLIN) {
			uint64_t val = 0;
			if (read(fds[2].fd, &val, sizeof(val)) < 0)
				warn("eventfd");
			pthread_mutex_lock(&conf.trigger_mutex);
			conf.running_threads = !list_empty(&conf.trigger_list)
				|| conf.cryptsetup_running;
			pthread_mutex_unlock(&conf.trigger_mutex);
		}
	}
	close(fds[2].fd);

	pthread_mutex_destroy(&conf.crypt.mutex);
	pthread_mutex_destroy(&conf.trigger_mutex);
	pthread_cond_destroy(&conf.trigger_cond);
	if (conf.blkid_cache) blkid_put_cache(conf.blkid_cache);

	dbg("modaliases: %i, forks: %i, events: %i, total bufsize: %zu",
		conf.modalias_count,
		conf.fork_count,
		event_count, total_bytes);

	return conf.found || not_found_is_ok ? 0 : 1;
}
