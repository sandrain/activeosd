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

#include "osd-util.h"
#include "osd-sense.h"
#include "target-sense.h"
#include "list.h"
#include "simplehash.h"
#include "active.h"

#define DEFAULT_IDLE_SLEEP	5000	/** in usec */
#define DEFAULT_ACTIVE_WORKERS	1

enum {
	ACTIVE_TASK_WAITING	= 0,
	ACTIVE_TASK_RUNNING,
	ACTIVE_TASK_COMPLETE,
};

struct active_task {
	struct active_task_req req;

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

static afs_htable __task_hash, *task_hash;
static pthread_mutex_t task_hash_lock;

static uint32_t id_counter = 0;		/** access with lock_free hold */
static const int initial_descriptors = 20;

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

static int active_task_hash_insert(struct active_task *task)
{
	int ret;
	char buf[32];

	sprintf(buf, "%x", task->id);

	pthread_mutex_lock(&task_hash_lock);
	ret = afs_hash_insert(task_hash, buf, task);
	pthread_mutex_unlock(&task_hash_lock);

	return ret;
}

static struct active_task *active_task_hash_search(uint64_t tid)
{
	struct active_task *task = NULL;
	char buf[32];

	sprintf(buf, "%x", tid);

	pthread_mutex_lock(&task_hash_lock);
	task = (struct active_task *) afs_hash_search(task_hash, buf);
	pthread_mutex_unlock(&task_hash_lock);

	return task;
}

static struct active_task *alloc_active_task(struct active_task_req *req)
{
	struct active_task *task = NULL;

	task = tq_fetch(TQ_FREE);
	if (!task) {
		task = malloc(sizeof(*task));
		if (!task)
			goto out;
	}

	active_task_clear(task);

	task->id = active_now();
	task->req = *req;

	active_task_hash_insert(task);

out:
	return task;
}

static int open_objects(struct osd_device *osd, struct active_obj_list *olist,
			int *fdlist, int flags, int mode)
{
	int fd;
	uint32_t i;
	uint32_t count;
	uint64_t pid;
	char pathbuf[MAXNAMELEN];

	if (!olist || !fdlist)
		return EINVAL;

	pid = olist->pid;
	count = olist->num_entries;

	for (i = 0; i < count; i++) {
		dfile_name(pathbuf, osd->root, pid, olist->oids[i]);
		fd = open(pathbuf, flags, mode);
		if (fd < 0)
			goto rollback;

		fdlist[i] = fd;
	}

	return 0;

rollback:
	while (--i >= 0)
		fdlist[i];

	return errno;
}

static inline int open_input_objects(struct osd_device *osd,
				struct active_obj_list *olist, int *fdlist)
{
	return open_objects(osd, olist, fdlist, O_RDONLY, 0);
}

static inline int open_output_objects(struct osd_device *osd,
				struct active_obj_list *olist, int *fdlist)
{
	return open_objects(osd, olist, fdlist, O_CREAT|O_EXCL|O_TRUNC, 0600);
}

static inline void close_objects(uint32_t n, int *fdlist)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		(void) close(fdlist[i]);
}

static int run_task(struct active_task *task)
{
	int ret;
	int *fdp;
	void *dh;
	char pathbuf[MAXNAMELEN];
	struct active_params param;
	struct osd_device *osd = task->osd;
	struct active_task_req *req = &task->req;
	active_kernel_t active_kernel;

	active_task_set_status(task, ACTIVE_TASK_RUNNING);

	dfile_name(pathbuf, osd->root, req->k_pid, req->k_oid);
	dh = dlopen(pathbuf, RTLD_LAZY);
	if (!dh)
		return EINVAL;
	dlerror();

	param.n_infiles = req->input.num_entries;
	param.n_outfiles = req->output.num_entries;
	param.args = req->args.args;

	fdp = calloc(param.n_infiles + param.n_outfiles, sizeof(int));
	if (!fdp) {
		ret = ENOMEM;
		goto out_close_dl;
	}

	param.fdin = fdp;
	param.fdout = &param.fdin[param.n_infiles];

	ret = open_input_objects(task->osd, &req->input, param.fdin);
	if (ret)
		goto out_close_objs;
	ret = open_output_objects(task->osd, &req->output, param.fdout);
	if (ret)
		goto out_close_objs;

	*(void **) (&active_kernel) = dlsym(dh, "execute_kernel");
	if (NULL != dlerror()) {
		ret = errno;
		goto out_close_objs;
	}

	ret = (*active_kernel) (&param);
	task->ret = ret;

	ret = 0;	/** success */

out_close_objs:
	close_objects(req->output.num_entries, param.fdout);
	close_objects(req->input.num_entries, param.fdin);

	free(fdp);

out_close_dl:
	dlclose(dh);

	return ret;
}

static int active_task_complete(struct active_task *task)
{
	struct active_task_req *req = &task->req;

	if (req->input.oids)
		free(req->input.oids);
	if (req->output.oids)
		free(req->output.oids);
	if (req->args.args)
		free((void *) req->args.args);

	active_task_set_status(task, ACTIVE_TASK_COMPLETE);
	tq_append(TQ_COMPLETE, task);

	/**
	 * current osd emulator doesn't put the object length into the attr db
	 * but it relies on underlying filesystem (ext3) to keep track of it.
	 * and the output objects are required to be created prior to the
	 * kernel execution. hence, we don't need to update the metadata here.
	 */
}

/**
 * TODO!!,
 *
 * sync db and free the task descriptors..
 */

static int active_task_sync_db(struct active_task *task)
{
	return ENOSYS;
}

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
		if (!ret && task->callback)
			(*task->callback)(task->ret, task->callback_arg);

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

		if (task->synced) {
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

	task_hash = afs_hash_init(100, &__task_hash);
	if (!task_hash)
		return -ENOMEM;
	pthread_mutex_init(&task_hash_lock, NULL);

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

	ret = pthread_create(&active_cleaner, NULL, active_cleaner_func, NULL);
	if (!ret)
		goto out;

	return ret;

out:
	afs_hash_exit(task_hash);

	for ( ; i >= 0; i--)
		pthread_cancel(active_workers[i]);

	return ret;
}

void osd_exit_active_threads(void)
{
	int i;

	pthread_cancel(active_cleaner);
	pthread_join(active_cleaner, NULL);

	for (i = 0; i < num_active_workers; i++)
		pthread_cancel(active_workers[i]);
	for (i = 0; i < num_active_workers; i++)
		pthread_join(active_workers[i], NULL);

	afs_hash_exit(task_hash);

#if 0
	/** TODO: space for on-going job descriptors will be lost. have to
	 * re-write the thread terminating. */
	clear_jobs();
#endif
}

static int validate_params(struct active_task_req *req)
{
	uint32_t i;
	uint64_t tmp;

	if (!(req->k_pid >= USEROBJECT_PID_LB
			&& req->k_oid >= USEROBJECT_OID_LB))
	{
		return -1;
	}

	for (i = 0; i < req->input.num_entries; i++) {
		tmp = req->input.oids[i];
		if (tmp < USEROBJECT_OID_LB)
			return -1;
		if (tmp == req->k_oid)
			return -1;
	}

	for (i = 0; i < req->output.num_entries; i++) {
		tmp = req->input.oids[i];
		if (tmp < USEROBJECT_OID_LB)
			return -1;
		if (tmp == req->k_oid)
			return -1;
	}

	return 0;
}

int osd_submit_active_task(struct osd_device *osd,
			struct active_task_req *req, uint64_t *tid,
			uint8_t *sense)
{
	struct active_task *task = NULL;

	assert(osd && sense && req);

	if (validate_params(req) < 0)
		goto out_cdb_err;

	task = alloc_active_task(req);
	task->osd = osd;

	active_task_set_status(task, ACTIVE_TASK_WAITING);
	tq_append(TQ_WAIT, task);

	*tid = task->id;
	return sense_build_sdd_csi(sense, OSD_SSK_VENDOR_SPECIFIC,
				OSD_ASC_SUBMITTED_TASK_ID,
				req->k_pid, req->k_oid, task->id);

out_cdb_err:
	return sense_build_sdd(sense, OSD_SSK_ILLEGAL_REQUEST,
			      OSD_ASC_INVALID_FIELD_IN_CDB,
			      req->k_pid, req->k_oid);
}

int osd_query_active_task(struct osd_device *osd, uint64_t tid,
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
			OSD_ASC_INVALID_FIELD_IN_CDB, task->req.k_pid, tid);
}

