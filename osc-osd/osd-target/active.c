/*
 * OSD extension for supporting active kernel execution.
 *
 * TODO:
 * . callback implementation (might be unnecessary?)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <dlfcn.h>
#include <unistd.h>
#include <signal.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include <endian.h>

/** quick workaround of active exectuion */
#include <sys/wait.h>

#include "osd-util.h"
#include "osd-sense.h"
#include "target-sense.h"
#include "list.h"
#include "active.h"
#include "task.h"

#define	QTIME_TRACE		1

#define DEFAULT_IDLE_SLEEP	5000	/** in usec */
#define DEFAULT_ACTIVE_WORKERS	1

struct active_task;

static int num_active_workers = DEFAULT_ACTIVE_WORKERS;
static pthread_t active_workers[DEFAULT_ACTIVE_WORKERS];

static const int initial_descriptors = 100;

static uint64_t wait_time;

#ifdef QTIME_TRACE
#include <sys/time.h>

static FILE *qlog;

static pthread_mutex_t qlog_lock = PTHREAD_MUTEX_INITIALIZER;

static inline void qtrace(struct active_task *task, char *str)
{
	struct timeval t;

	if (!qlog)
		return;

	gettimeofday(&t, NULL);

	pthread_mutex_lock(&qlog_lock);
	fprintf(qlog, "%llu.%llu\t: %llu %s\n", t.tv_sec, t.tv_usec, task->id, str);
	pthread_mutex_unlock(&qlog_lock);
}

#endif

/**
 * simple tasks queues and accessors.
 */
enum {
	TQ_WAIT		= 0,
	TQ_FREE,

	N_TQS
};

static struct list_head __tq[N_TQS];
static pthread_mutex_t __tql[N_TQS];

static inline void active_task_lock(struct active_task *task)
{
	pthread_mutex_lock(&task->lock);
}

static inline void active_task_unlock(struct active_task *task)
{
	pthread_mutex_unlock(&task->lock);
}

static inline struct active_task *tq_fetch(int i)
{
	struct list_head *q = &__tq[i];
	struct active_task *t = NULL;

	pthread_mutex_lock(&__tql[i]);
	if (list_empty(q))
		goto out;

	t = list_first_entry(q, struct active_task, list);
	list_del(&t->list);

out:
	pthread_mutex_unlock(&__tql[i]);
	return t;
}

static inline void tq_append(int i, struct active_task *task)
{
	pthread_mutex_lock(&__tql[i]);
	list_add_tail(&task->list, &__tq[i]);
	pthread_mutex_unlock(&__tql[i]);
}

static inline void active_task_set_status(struct active_task *task, int status)
{
	pthread_mutex_lock(&task->lock);

	task->status = status;
	switch (status) {
	case ACTIVE_TASK_WAITING: break;
	case ACTIVE_TASK_RUNNING: break;
	case ACTIVE_TASK_COMPLETE: break;
	default: break;
	}

	pthread_mutex_unlock(&task->lock);
}

static inline void active_task_free(struct active_task *task)
{
	pthread_mutex_destroy(&task->lock);
	tq_append(TQ_FREE, task);
}

static inline void active_task_clear(struct active_task *task)
{
	memset(task, 0, sizeof(*task));
	pthread_mutex_init(&task->lock, NULL);
}

static struct active_task *alloc_active_task(struct osd_device *osd,
				uint64_t pid, uint64_t oid,
				struct kernel_execution_params *params)
{
	int ret;
	struct active_task *task = NULL;
	struct db_context *dbc = osd->dbc;

	task = tq_fetch(TQ_FREE);
	if (!task) {
		task = malloc(sizeof(*task));
		if (!task)
			goto out;
	}

	active_task_clear(task);

	task->pid = pid;
	task->oid = oid;
	task->input_cid = params->input_cid;
	task->output_cid = params->output_cid;
	task->osd = osd;
	task->args = params->args;

	ret = task_insert(dbc, task);
	if (ret) {
		tq_append(TQ_FREE, task);
		task = NULL;
	}

out:
	return task;
}

static inline int open_objects(struct osd_device *osd, uint64_t pid,
				uint64_t len, uint64_t *olist, int *fdlist,
				int flags, int mode)
{
	int fd;
	uint32_t i;
	char pathbuf[MAXNAMELEN];

	if (!olist || !fdlist)
		return -EINVAL;

	for (i = 0; i < len; i++) {
		dfile_name(pathbuf, osd->root, pid, olist[i]);
		fd = open(pathbuf, flags, mode);
		if (fd < 0)
			goto rollback;

		fdlist[i] = fd;
	}

	return 0;

rollback:
	while (--i >= 0)
		close(fdlist[i]);

	return -errno;
}

static inline int open_input_objects(struct osd_device *osd, uint64_t pid,
			uint64_t len, uint64_t *olist, int *fdlist)
{
	return open_objects(osd, pid, len, olist, fdlist, O_RDONLY, 0);
}

static inline int open_output_objects(struct osd_device *osd, uint64_t pid,
			uint64_t len, uint64_t *olist, int *fdlist)
{
	return open_objects(osd, pid, len, olist, fdlist,
				O_CREAT|O_WRONLY|O_TRUNC, 0600);
}

static inline void close_objects(uint32_t n, int *fdlist)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		(void) close(fdlist[i]);
}

struct param_list {
	struct param_list *next;
	char param[0];
};

char **get_argv(char *args)
{
	char **argv;
	char *pos;
	int i, count;
	struct param_list *plist = NULL, *current, *prev;

	if (!args)
		return NULL;

	while ((pos = strsep(&args, " "))) {
		current = malloc(sizeof(*current) + strlen(pos));
		assert(current);
		current->next = NULL;
		strcpy(current->param, pos);

		if (!plist)
			plist = current;
		else
			prev->next = current;

		prev = current;
		count++;
	}

	argv = malloc(sizeof(*argv) * (count + 1));
	assert(argv);

	argv[count] = NULL;

	i = 0;
	current = plist;

	while (current) {
		argv[i++] = strdup(current->param);
		prev = current;
		current = current->next;
		free(prev);
	}

	return argv;
}

#define PATHDB_ROOTNAME		"ns"

/** TODO: place these into a right header file. */
#define	ANFS_APAGE_FS_DATA	0x10005
#define	ANFS_ATTR_NSPATH	1

static const uint64_t default_pid = 0x22222;

static inline void get_dfile_name(char *path, const char *root, uint64_t oid)
{
	if (!oid)
		sprintf(path, "%s/%s/%02x", root, "dfiles",
			(uint8_t)(oid & 0xFFUL));
	else
		sprintf(path, "%s/%s/%02x/%llx.%llx", root, "dfiles",
			(uint8_t)(oid & 0xFFUL), llu(default_pid), llu(oid));
}

/** check if the given path exists and is a valid directory.
 * NOTE: returns 0 if invalid, 1 if valid.
 */
static inline int valid_directory(const char *path)
{
	struct stat stbuf;

	if (stat(path, &stbuf) < 0)
		return 0;

	return S_ISDIR(stbuf.st_mode) ? 1 : 0;
}

/** create all intermediate directories along with the path */
static int create_dirs(const char *osdroot, const char *fullpath)
{
	int ret = 0;
	mode_t mode = 0;
	char *current, *pos, *path = strdup(fullpath);

	if (!path)
		return -ENOMEM;

	pos = &path[strlen(osdroot)];
	while (*pos++ == '/')
		;

	while ((current = strchr(pos, '/')) != NULL) {
		*current = '\0';

		if (!valid_directory(path)) {
			/** we need to create this directory */
			mode = umask(0);
			ret = mkdir(path, 0755);
			umask(mode);
			if (ret)
				goto out;
		}

		*current = '/';
		pos++;
	}

out:
	free(path);
	return ret;
}

static int create_link(const char *root, const char *path, const uint64_t oid)
{
	int ret;
	char obj_path[2048];

	get_dfile_name(obj_path, root, oid);
	ret = symlink(obj_path, path);
	if (ret < 0 && errno != EEXIST)
		return -errno;
	return 0;
}

static char nspathbuf[MAXNAMELEN];

static int create_nspath(struct osd_device *osd, uint64_t pid, uint64_t oid)
{
	int ret, len;
	char *path;
	uint64_t used_outlen;

	len = sprintf(nspathbuf, "%s/ns", osd->root);
	path = &nspathbuf[len];

	ret = attr_get_val(osd->dbc, pid, oid, ANFS_APAGE_FS_DATA,
			ANFS_ATTR_NSPATH, MAXNAMELEN-len, path, &used_outlen);
	if (ret)
		return ret;
	path[used_outlen] = '\0';

	ret = create_dirs(osd->root, nspathbuf);
	if (ret)
		return ret;

	ret = create_link(osd->root, nspathbuf, oid);
	return ret;
}

static int prepare_files(struct active_task *task)
{
	int ret = 0, len;
	uint64_t i, iolen, oolen;
	uint64_t *iolist, *oolist;
	struct osd_device *osd = task->osd;

	ret = coll_get_full_obj_list(osd->dbc, task->pid, task->input_cid,
				&iolist, &iolen);
	if (ret)
		goto out;
	ret = coll_get_full_obj_list(osd->dbc, task->pid, task->output_cid,
				&oolist, &oolen);
	if (ret)
		goto out_free_ic;

	ret = create_nspath(osd, task->pid, task->oid);
	if (ret)
		goto out_free_oc;

	/** input objects */
	for (i = 0; i < iolen; i++) {
		ret = create_nspath(osd, task->pid, iolist[i]);
		if (ret)
			goto out_free_oc;
	}

	/** output objects */
	for (i = 0; i < oolen; i++) {
		ret = create_nspath(osd, task->pid, oolist[i]);
		if (ret)
			goto out_free_oc;
	}

out_free_oc:
	free(oolist);
out_free_ic:
	free(iolist);
out:
	return ret;
}

/** new implementation of active processing.
 * because of the difficulties of spawning a process in multi-threaded, now we
 * use a dedicated server process (active-server), which uses a shared mapped
 * file for communication.
 */

struct active_request {
	int ready;
	int result;
	char command[0];
};

static struct active_request *serv_req;

static int run_task(struct active_task *task)
{
	int ret = 0;

	active_task_set_status(task, ACTIVE_TASK_RUNNING);

	ret = prepare_files(task);
	if (ret)
		return ret;

	strcpy(serv_req->command, task->args);
	serv_req->ready = 1;

	while (serv_req->ready)
		;

	task->ret = serv_req->result;

	return 0;
}

#if 0
/** quick workaround for the evaluation
 * it just forks the process according to the string arguments.
 *
 * update: to launch the bash script, now using popen instead of the fork.
 */
static int run_task(struct active_task *task)
{
	int ret = 0, pid;
	FILE *pipe;
	char command[2048];
	char linebuf[1024];

	active_task_set_status(task, ACTIVE_TASK_RUNNING);

	ret = prepare_files(task);
	if (ret)
		return ret;

	/** the executable is a symlink, use '.' */
	sprintf(command, "%s", task->args);
	//sprintf(command, ". %s", task->args);


	ret = system(command);
#if 0
	pipe = popen(command, "r");
	while (fgets(linebuf, 1024, pipe))
		;	/** just consume the outputs */
	ret = pclose(pipe);
#endif
	task->ret = ret;

#ifdef	QTIME_TRACE
	qtrace(task, "== task execution");
	qtrace(task, strerror(ret));
#endif

	return 0;
}
#endif

/** fix the exofs metadata */
#define EXOFS_IDATA		5

struct exofs_fcb {
	__le64  i_size;			/* Size of the file */
	__le16  i_mode;         	/* File mode */
	__le16  i_links_count;  	/* Links count */
	__le32  i_uid;          	/* Owner Uid */
	__le32  i_gid;          	/* Group Id */
	__le32  i_atime;        	/* Access time */
	__le32  i_ctime;        	/* Creation time */
	__le32  i_mtime;        	/* Modification time */
	__le32  i_flags;        	/* File flags (unused for now)*/
	__le32  i_generation;   	/* File version (for NFS) */
	__le32  i_data[EXOFS_IDATA];	/* Short symlink names and device #s */
};

#define OSD_APAGE_APP_DEFINED_FIRST	0x00010000
#define EXOFS_APAGE_FS_DATA		(OSD_APAGE_APP_DEFINED_FIRST + 3)
#define EXOFS_ATTR_INODE_DATA		1

static int update_output_exofs_inodes(struct active_task *task)
{
	int ret;
	uint64_t i;
	uint32_t used_outlen = 0;
	struct osd_device *osd = task->osd;
	struct exofs_fcb fcb;
	char pathbuf[MAXNAMELEN];
	struct stat stbuf;

	for (i = 0; i < task->output_len; i++) {
		dfile_name(pathbuf, osd->root, task->pid,
				task->output_objs[i]);
		ret = stat(pathbuf, &stbuf);
		if (ret < 0)
			continue;	/** TODO: handle error! */

		ret = attr_get_val(osd->dbc, task->pid, task->output_objs[i],
				EXOFS_APAGE_FS_DATA, EXOFS_ATTR_INODE_DATA,
				sizeof(fcb), (void *) &fcb, &used_outlen);

		if (ret != OSD_OK || sizeof(fcb) != used_outlen)
			continue;	/** TODO: handle error! */

		fcb.i_size = htole64(stbuf.st_size);
		fcb.i_atime = htole32(stbuf.st_atime);
		fcb.i_mtime = htole32(stbuf.st_mtime);

		ret = attr_set_attr(osd->dbc, task->pid, task->output_objs[i],
				EXOFS_APAGE_FS_DATA, EXOFS_ATTR_INODE_DATA,
				(void *) &fcb, sizeof(fcb));

		if (ret != OSD_OK) {
			/** TODO: handle error! */
		}
	}

	return ret;
}

static int truncate_output_objects(struct active_task *task)
{
	int ret;
	int fd;
	uint64_t i;
	char pathbuf[MAXNAMELEN];
	struct osd_device *osd = task->osd;

	for (i = 0; i < task->input_len; i++) {
		dfile_name(pathbuf, osd->root, task->pid,
				task->output_objs[i]);
		ret = truncate(pathbuf, (off_t) 0);
		if (ret < 0) {
			/** handle some errors here? */
			ret = errno;
			break;
		}
	}

	return ret;
}

static int active_task_complete(struct active_task *task)
{
	int ret;

	/**
	 * current osd emulator doesn't put the object length into the attr db
	 * but it relies on underlying filesystem (e.g. ext3) to keep track of
	 * it. but for exofs, we need to fix its inode directly.
	 * XXX; the better option is to modify the exofs to reflect the object
	 * size correctly.
	 */
	if (task->ret)
		ret = truncate_output_objects(task);	/** task fail */
	else
		ret = update_output_exofs_inodes(task);

#ifdef QTIME_TRACE
	qtrace(task, "complete.");
#endif

	ret = task_update_status_complete(task->osd->dbc, task->id, task->ret);
	if (ret) {
		osd_info("updating task status to db failed: "
			 "tid=%llu, ret=%d\n", task->id, ret);
	}

	ret = update_output_exofs_inodes(task);
	if (ret) {
		/** shit */
	}

	if (task->input_objs)
		free(task->input_objs);
	if (task->output_objs)
		free(task->output_objs);


	tq_append(TQ_FREE, task);

	return 0;
}

/**
 * active_thread_func
 *
 * @arg		[unused]
 *
 * Main loop of working threads. All threads should run on the same cpu. We use
 * the last one here.
 */
static void *active_thread_func(void *arg)
{
	int ret = 0;
	cpu_set_t cpu_mask;
	long n_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	struct active_task *task = NULL;
	pid_t pid = syscall(SYS_gettid);

	/** first of all, set the cpu affinity */
	CPU_ZERO(&cpu_mask);
	CPU_SET(n_cpus - 1, &cpu_mask);
	ret = sched_setaffinity(0, sizeof(cpu_mask), &cpu_mask);

	while (1) {
		task = tq_fetch(TQ_WAIT);

		if (!task) {
			usleep(DEFAULT_IDLE_SLEEP);
			continue;
		}

#ifdef QTIME_TRACE
		qtrace(task, "start");
#endif

		ret = task_update_status_begin(task->osd->dbc, task->id);
		if (ret) {
			/** damn,.. what shall we do?? */
			osd_info("updating task status to db failed: "
				 "tid=%llu, ret=%d\n", task->id, ret);
			tq_append(TQ_WAIT, task);
			usleep(DEFAULT_IDLE_SLEEP*5);
			continue;
		}

		ret = run_task(task);
		osd_info("task execution: %llu", llu(task->id));
		if (task->callback)
			(*task->callback)(task, task->callback_arg);

#if 0
		wait_time -= task->runtime;
		update_wait_time();
#endif

	active_task_complete(task);
	}

	return (void *) 0;
}

int osd_init_active_threads(int count)
{
	int ret = 0;
	int i;
	int shmid;
	void *mem;
	struct active_task *tasks = NULL;

	if (count > 0)
		num_active_workers = count;

	for (i = 0; i < N_TQS; i++) {
		INIT_LIST_HEAD(&__tq[i]);
		pthread_mutex_init(&__tql[i], NULL);
	}

	tasks = calloc(initial_descriptors, sizeof(*tasks));
	if (tasks)
		for (i = 0; i < initial_descriptors; i++)
			tq_append(TQ_FREE, &tasks[i]);

	for (i = 0; i < num_active_workers; i++) {
		ret = pthread_create(&active_workers[i], NULL,
					active_thread_func, NULL);
		if (ret)
			goto out;
	}

        shmid = open("/tmp/activerequest", O_RDWR);
        if (shmid < 0) {
                perror("open");
                ret = -errno;
                goto out;
        }

        mem = mmap(NULL, 1024, PROT_READ|PROT_WRITE, MAP_SHARED, shmid, 0);
        if (mem == (void *) -1) {
                perror("mmap");
                ret = -errno;
                goto out;
        }

	serv_req = (struct active_request *) mem;

#ifdef QTIME_TRACE
	qlog = fopen("/tmp/afe_qlog", "w");
	if (qlog)
		setvbuf(qlog, NULL, _IONBF, 0);
#endif

	return ret;

out:
	for ( ; i >= 0; i--)
		pthread_cancel(active_workers[i]);

	return ret;
}

void osd_exit_active_threads(void)
{
	int i;

	munmap((void *) serv_req, 1024);

#ifdef QTIME_TRACE
	if (qlog)
		fclose(qlog);
#endif

	for (i = 0; i < num_active_workers; i++)
		pthread_cancel(active_workers[i]);
	for (i = 0; i < num_active_workers; i++)
		pthread_join(active_workers[i], NULL);

#if 0
	/** TODO: space for on-going job descriptors will be lost. have to
	 * re-write the thread terminating. */
	clear_jobs();
#endif
}

int osd_submit_active_task(struct osd_device *osd, uint64_t pid, uint64_t oid,
		struct kernel_execution_params *params, uint8_t *sense)
{
	int ret;
	struct active_task *task = NULL;
	uint64_t runtime;

	assert(osd && sense && params);
	if (!(pid >= USEROBJECT_PID_LB && oid >= USEROBJECT_OID_LB))
		goto out_cdb_err;

	task = alloc_active_task(osd, pid, oid, params);
	if (!task)
		goto out_hw_err;

	osd_info("task submitted: id = %llu, kernel = (%llu, %llu)",
			llu(task->id), llu(pid), llu(oid));

	active_task_set_status(task, ACTIVE_TASK_WAITING);
	tq_append(TQ_WAIT, task);
#ifdef QTIME_TRACE
	qtrace(task, "arrived");
#endif

	return sense_build_sdd_csi(sense, OSD_SSK_VENDOR_SPECIFIC,
			OSD_ASC_SUBMITTED_TASK_ID, pid, oid, task->id);

out_hw_err:
	return sense_header_build(sense, sizeof(sense), OSD_SSK_HARDWARE_ERROR,
			OSD_ASC_SYSTEM_RESOURCE_FAILURE, 0);
out_cdb_err:
	return sense_build_sdd(sense, OSD_SSK_ILLEGAL_REQUEST,
			OSD_ASC_INVALID_FIELD_IN_CDB, pid, oid);
}

/**
 * TODO: this function should query to database to fetch the task statistics
 */
int osd_query_active_task(struct osd_device *osd, uint64_t pid, uint64_t tid,
			uint64_t *outlen, uint8_t *outdata, uint8_t *sense)
{
	int ret;
	struct active_task_status task, *ts;

	assert(osd && outlen && outdata && sense);

	memset(&task, 0, sizeof(task));
	ret = task_get_status(osd->dbc, tid, &task);
	if (ret)
		goto out_cdb_err;

	if (task.start == 0)
		task.status = ACTIVE_TASK_WAITING;
	else if (task.complete == 0)
		task.status = ACTIVE_TASK_RUNNING;
	else
		task.status = ACTIVE_TASK_COMPLETE;

	ts = (struct active_task_status *) outdata;
	set_htonl(&ts->status, task.status);
	set_htonl(&ts->ret, task.ret);
	set_htonll(&ts->submit, task.submit);
	set_htonll(&ts->start, task.start);
	set_htonll(&ts->complete, task.complete);

	*outlen = sizeof(*ts);
	return OSD_OK;

out_cdb_err:
	return sense_build_sdd(sense, OSD_SSK_ILLEGAL_REQUEST,
			OSD_ASC_INVALID_FIELD_IN_CDB, pid, tid);
}

