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
#include <unistd.h>
#include <fcntl.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include <endian.h>

#include "osd-util.h"
#include "osd-sense.h"
#include "target-sense.h"
#include "list.h"
#define	__USE_HASH_LOCKS__
#include "simhash.h"
#include "active.h"

#define DEFAULT_IDLE_SLEEP	5000	/** in usec */
#define DEFAULT_ACTIVE_WORKERS	1

enum {
	ACTIVE_TASK_WAITING	= 0,
	ACTIVE_TASK_RUNNING,
	ACTIVE_TASK_COMPLETE,
};

struct active_task;
typedef	void (*active_task_callback_t) (struct active_task *task, void *arg);

struct active_task {
	uint64_t pid;			/* kernel object */
	uint64_t oid;
	uint64_t input_cid;		/* input/output collection id */
	uint64_t output_cid;
	const char *args;

	uint64_t *input_objs;		/* those fields are set by run_task */
	uint64_t *output_objs;		/* and freed by active_task_complete */
	uint64_t input_len;
	uint64_t output_len;

	struct osd_device *osd;
	int status;			/* task status */
	int ret;			/* task exit code (0: success) */
	uint64_t id;			/* task id */
	struct list_head list;
	void *callback_arg;
	active_task_callback_t callback;

	uint64_t submit;		/* task submitted time */
	uint64_t begin;			/* task execution time */
	uint64_t complete;		/* task completion time */

	int synced;			/* db synced? */

	pthread_mutex_t lock;
};

/**
 * structure to reply client's query
 */
struct active_task_status {
	uint32_t status;
	uint32_t ret;
	uint64_t submit;
	uint64_t complete;
} __attribute__((packed));

static int num_active_workers = DEFAULT_ACTIVE_WORKERS;
static pthread_t active_workers[DEFAULT_ACTIVE_WORKERS];
static pthread_t active_cleaner;

static hash_table_t *task_hash;

static const int initial_descriptors = 20;

/**
 * task id counter
 */
static uint64_t id_counter = 1;
static pthread_mutex_t counter_lock;

static inline uint64_t active_task_next_id(void)
{
	uint64_t ret;

	pthread_mutex_lock(&counter_lock);
	ret = id_counter++;
	pthread_mutex_unlock(&counter_lock);

	return ret;
}

/**
 * simple tasks queues and accessors.
 */
enum {
	TQ_WAIT		= 0,
	TQ_COMPLETE,
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
	uint64_t *ts = NULL;

	pthread_mutex_lock(&task->lock);

	task->status = status;
	switch (status) {
	case ACTIVE_TASK_WAITING: ts = &task->submit; break;
	case ACTIVE_TASK_RUNNING: ts = &task->begin; break;
	case ACTIVE_TASK_COMPLETE: ts = &task->complete; break;
	default: break;
	}
	if (ts)
		*ts = active_now();

	pthread_mutex_unlock(&task->lock);
}

static inline void active_task_free(struct active_task *task)
{
	tq_append(TQ_FREE, task);
}

static inline void active_task_clear(struct active_task *task)
{
	memset(task, 0, sizeof(*task));
	pthread_mutex_init(&task->lock, NULL);
}

static struct active_task *active_task_hash_search(uint64_t tid)
{
	return (struct active_task *) hash_find(task_hash, (void *) &tid,
						sizeof(tid));

#if 0
	struct active_task *task = NULL;
	char buf[32];

	sprintf(buf, "%llx", tid);

	pthread_mutex_lock(&task_hash_lock);
	task = (struct active_task *) afs_hash_search(task_hash, buf);
	pthread_mutex_unlock(&task_hash_lock);

	return task;
#endif
}

/** returns 1 on success */
static int active_task_hash_insert(struct active_task *task)
{
	if (!task)
		return -EINVAL;

	return hash_insert(task_hash, &task->id, sizeof(task->id), task);
}

static struct active_task *alloc_active_task(struct osd_device *osd,
				uint64_t pid, uint64_t oid,
				struct kernel_execution_params *params)
{
	struct active_task *task = NULL;

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
	task->status = ACTIVE_TASK_WAITING;
	task->args = params->args;

	task->id = active_task_next_id();
	task->submit = active_now();

	/** returns 1 on success */
	active_task_hash_insert(task);
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

static int run_task(struct active_task *task)
{
	int ret = 0;
	int *fdp;
	void *dh;
	uint64_t iolen, oolen;
	uint64_t *iolist, *oolist;
	char pathbuf[MAXNAMELEN];
	struct active_params param;
	struct osd_device *osd = task->osd;
	active_kernel_t active_kernel;

	active_task_set_status(task, ACTIVE_TASK_RUNNING);

	if (task->output_cid == 0)	/* sliently skip this */
		return 0;

	dfile_name(pathbuf, osd->root, task->pid, task->oid);
	dh = dlopen(pathbuf, RTLD_LAZY);
	if (!dh)
		return -EINVAL;
	dlerror();

	ret = coll_get_full_obj_list(osd->dbc, task->pid, task->input_cid,
				&iolist, &iolen);
	if (ret)
		goto out_close_dl;

	ret = coll_get_full_obj_list(osd->dbc, task->pid, task->output_cid,
				&oolist, &oolen);
	if (ret)
		goto out_free_ic;

	param.n_infiles = iolen;
	param.n_outfiles = oolen;
	param.args = task->args;

	fdp = calloc(param.n_infiles + param.n_outfiles, sizeof(int));
	if (!fdp) {
		ret = -ENOMEM;
		goto out_free_oc;
	}

	param.fdin = fdp;
	param.fdout = &param.fdin[param.n_infiles];

	ret = open_input_objects(task->osd, task->pid, iolen, iolist,
				param.fdin);
	if (ret)
		goto out_free_fdp;

	ret = open_output_objects(task->osd, task->pid, oolen, oolist,
				param.fdout);
	if (ret)
		goto out_close_io;

	*(void **) (&active_kernel) = dlsym(dh, "execute_kernel");
	if (NULL != dlerror()) {
		ret = errno;
		goto out_close_oo;
	}

	ret = (*active_kernel) (&param);
	task->ret = ret;

	close_objects(param.n_outfiles, param.fdout);
	close_objects(param.n_infiles, param.fdin);
	if (fdp)
		free(fdp);
	dlclose(dh);

	task->input_len = iolen;	/** store the object lists */
	task->output_len = oolen;
	task->input_objs = iolist;
	task->output_objs = oolist;

	return 0;	/** success */


out_close_oo:
	close_objects(param.n_outfiles, param.fdout);
out_close_io:
	close_objects(param.n_infiles, param.fdin);
out_free_fdp:
	if (fdp)
		free(fdp);
out_free_oc:
	free(oolist);
out_free_ic:
	free(iolist);
out_close_dl:
	dlclose(dh);

	return ret;	/** fail */
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

/** ugly hack to work around the exofs */

#if 0
typedef uint64_t __le64;
typedef uint16_t __le16;
typedef uint32_t __le32;
#endif

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
		ret = update_output_exofs_inodes(task);	/** task success */

	active_task_set_status(task, ACTIVE_TASK_COMPLETE);
	tq_append(TQ_COMPLETE, task);

	return 0;
}

/**
 * TODO!!,
 *
 * sync db and free the task descriptors..
 */

static int active_task_sync_db(struct active_task *task)
{
	return -ENOSYS;
}

/**
 * this function returns task descriptor with lock held.
 */
static inline struct active_task *active_task_find_locked(uint64_t tid)
{
	struct active_task *task;

	task = active_task_hash_search(tid);
	if (task)
		pthread_mutex_lock(&task->lock);

	return task;
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

		ret = run_task(task);
		if (task->callback)
			(*task->callback)(task, task->callback_arg);

		active_task_complete(task);
	}

	return (void *) 0;
}

/**
 * active_cleaner_func periodically checks completed tasks (TQ_COMPLETE) and
 * sync the task status onto database.
 *
 * @arg: unused.
 */
static void *active_cleaner_func(void *arg)
{
	int ret = 0;
	cpu_set_t cpu_mask;
	uint64_t now;
	long n_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	struct active_task *task = NULL;
	pid_t pid = syscall(SYS_gettid);

	/** first of all, set the cpu affinity */
	CPU_ZERO(&cpu_mask);
	CPU_SET(n_cpus - 2, &cpu_mask);
	ret = sched_setaffinity(0, sizeof(cpu_mask), &cpu_mask);

	while (1) {
		task = tq_fetch(TQ_COMPLETE);
		if (!task)
			usleep(5000);

		now = active_now();

#if 0
		if (task->synced) {
			ret = active_task_sync_db(task);
			if (ret)
				tq_append(TQ_COMPLETE, task);
			else {
				active_task_free(task);
			}

			/** more than 20 mins passed? */
			if (task->complete < now + 1200)
				active_task_free(task);
		}
		else {
#if 0
			ret = active_task_sync_db(task);
			task->synced = ret ? 0 : 1;
#endif

			tq_append(TQ_COMPLETE, task);
		}
#endif
	}

	return (void *) 0;
}

int osd_init_active_threads(int count)
{
	int ret = 0;
	int i;
	struct active_task *tasks = NULL;

	if (count > 0)
		num_active_workers = count;

	for (i = 0; i < N_TQS; i++) {
		INIT_LIST_HEAD(&__tq[i]);
		pthread_mutex_init(&__tql[i], NULL);
	}

	task_hash = create_hash_table(100);
	if (!task_hash)
		return -ENOMEM;

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

	pthread_mutex_init(&counter_lock, NULL);

#if 0
	ret = pthread_create(&active_cleaner, NULL, active_cleaner_func, NULL);
	if (!ret)
		goto out;
#endif

	return ret;

out:
	destroy_hash_table(task_hash);

	for ( ; i >= 0; i--)
		pthread_cancel(active_workers[i]);

	return ret;
}

void osd_exit_active_threads(void)
{
	int i;

	return;

	pthread_cancel(active_cleaner);
	pthread_join(active_cleaner, NULL);

	for (i = 0; i < num_active_workers; i++)
		pthread_cancel(active_workers[i]);
	for (i = 0; i < num_active_workers; i++)
		pthread_join(active_workers[i], NULL);

	destroy_hash_table(task_hash);

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

	assert(osd && sense && params);
	if (!(pid >= USEROBJECT_PID_LB && oid >= USEROBJECT_OID_LB))
		goto out_cdb_err;

	task = alloc_active_task(osd, pid, oid, params);
	if (!task)
		goto out_hw_err;

#if 0
	osd_warning("\n == execute_kernel ==\n"
		    "task   = { %llu }\n"
		    "kernel = { %llu, %llu }\n"
		    "input  = { %llu }\n"
		    "output = { %llu }\n"
		    "args   = { %s }\n",
		    llu(task->id),
		    llu(pid), llu(oid),
		    llu(params->input_cid),
		    llu(params->output_cid),
		    llu(params->args));
#endif

	tq_append(TQ_WAIT, task);

	return sense_build_sdd_csi(sense, OSD_SSK_VENDOR_SPECIFIC,
			OSD_ASC_SUBMITTED_TASK_ID, pid, oid, task->id);

out_hw_err:
	return sense_header_build(sense, sizeof(sense), OSD_SSK_HARDWARE_ERROR,
			OSD_ASC_SYSTEM_RESOURCE_FAILURE, 0);
out_cdb_err:
	return sense_build_sdd(sense, OSD_SSK_ILLEGAL_REQUEST,
			OSD_ASC_INVALID_FIELD_IN_CDB, pid, oid);
}

int osd_query_active_task(struct osd_device *osd, uint64_t pid, uint64_t tid,
			uint64_t *outlen, uint8_t *outdata, uint8_t *sense)
{
	struct active_task *task = NULL;
	struct active_task_status *ts;

	assert(osd && outlen && outdata && sense);

	task = active_task_find_locked(tid);
	if (!task)
		goto out_cdb_err;

	ts = (struct active_task_status *) outdata;
	set_htonl(&ts->status, task->status);
	set_htonl(&ts->ret, task->ret);
	set_htonll(&ts->submit, task->submit);
	set_htonll(&ts->complete, task->complete);

	/**
	 * XXX:
	 * we currently assume that querying completed tasks implicitly mean
	 * that the task record can be discarded.
	 */
	if (task->complete)
		task->synced = 1;

	active_task_unlock(task);

	*outlen = sizeof(*ts);
	return OSD_OK;

out_cdb_err:
	return sense_build_sdd(sense, OSD_SSK_ILLEGAL_REQUEST,
			OSD_ASC_INVALID_FIELD_IN_CDB, pid, tid);
}

