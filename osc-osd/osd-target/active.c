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
#include "active.h"
#include "task.h"

#define DEFAULT_IDLE_SLEEP	5000	/** in usec */
#define DEFAULT_ACTIVE_WORKERS	1

struct active_task;

static int num_active_workers = DEFAULT_ACTIVE_WORKERS;
static pthread_t active_workers[DEFAULT_ACTIVE_WORKERS];

static const int initial_descriptors = 20;

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

static int run_task(struct active_task *task)
{
	int ret = 0;
	int *fdp = NULL;
	void *dh;
	uint64_t iolen, oolen;
	uint64_t *iolist, *oolist;
	char pathbuf[MAXNAMELEN];
	char *dlerr;
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
	if (NULL != (dlerr = dlerror())) {
		ret = errno;
		osd_info("failed to find execute kernel: %s (%d)\n",
				dlerr, errno);
		goto out_close_oo;
	}

	osd_info("task is being executed: %llu", llu(task->id));

	ret = (*active_kernel) (&param);
	if (NULL != (dlerr = dlerror())) {
		ret = errno;
		osd_info("failed to execute execute_kernel: %s (%d)\n",
				dlerr, errno);
		goto out_close_oo;
	}
	task->ret = ret;

	close_objects(param.n_outfiles, param.fdout);
	close_objects(param.n_infiles, param.fdin);

	active_kernel = NULL;
	dlclose(dh);

	if (fdp)
		free(fdp);

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

static int active_task_complete(struct active_task *task)
{
	int ret;

	if (task->ret)
		ret = truncate_output_objects(task);	/** task fail */

	ret = task_update_status_complete(task->osd->dbc, task->id, task->ret);
	if (ret) {
		osd_info("updating task status to db failed: "
			 "tid=%llu, ret=%d\n", task->id, ret);
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
		osd_info("task execution successful: %llu", llu(task->id));
		if (task->callback)
			(*task->callback)(task, task->callback_arg);

		active_task_complete(task);
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

	return ret;

out:
	for ( ; i >= 0; i--)
		pthread_cancel(active_workers[i]);

	return ret;
}

void osd_exit_active_threads(void)
{
	int i;

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

