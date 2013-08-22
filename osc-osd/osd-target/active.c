/*
 * OSD extension for supporting active kernel execution.
 *
 * TODO:
 * . proper cdb, return handling.
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
#include <linux/types.h>
#include <arpa/inet.h>

#include "osd-util.h"
#include "osd-sense.h"
#include "target-sense.h"
#include "list.h"
#include "active.h"

#define DEFAULT_IDLE_SLEEP	5000	/** in usec */
#define DEFAULT_ACTIVE_WORKERS	2

#if 0
static const char *md = "md";
static const char *dbname = "osd.db";
static const char *stranded = "stranded";
static const char *dfiles = "dfiles";
#endif

struct active_job {
#if 0
	struct osd_device *osd;
	uint64_t id;		/* job id */
	uint64_t pid;		/* partition id */
	uint64_t in;		/* input object */
	uint64_t out;		/* output object */
	uint64_t kernel;	/* kernel object */
	uint64_t result;	/* result object size */
	int status;		/* 0 means success */

	active_callback_t callback;
	void *arg;
#endif
	struct osd_device *osd;
	uint64_t id;
	struct list_head list;
	struct active_kernel_job desc;
};

static int num_active_workers = DEFAULT_ACTIVE_WORKERS;
static pthread_t active_workers[DEFAULT_ACTIVE_WORKERS];

static pthread_mutex_t alock = PTHREAD_MUTEX_INITIALIZER;
static LIST_HEAD(active_job_list);

static pthread_mutex_t elock = PTHREAD_MUTEX_INITIALIZER;
static LIST_HEAD(completed_job_list);

static pthread_mutex_t flock = PTHREAD_MUTEX_INITIALIZER;
static LIST_HEAD(free_job_list);
static uint32_t id_counter = 0;	/** access with flock hold */


static void queue_active_job(struct active_job *job)
{
	pthread_mutex_lock(&alock);
	list_add_tail(&job->list, &active_job_list);
	pthread_mutex_unlock(&alock);
}

static struct active_job *fetch_active_job(void)
{
	struct active_job *job = NULL;

	pthread_mutex_lock(&alock);

	if (list_empty(&active_job_list))
		goto out;

	job = list_first_entry(&active_job_list, struct active_job, list);
	list_del(&job->list);

out:
	pthread_mutex_unlock(&alock);
	return job;
}

static struct active_job *alloc_active_job(void)
{
	struct active_job *job = NULL;

	pthread_mutex_lock(&flock);

	if (list_empty(&free_job_list))
		job = malloc(sizeof(*job));
	else {
		job = list_first_entry(&free_job_list, struct active_job,
					list);
		list_del(&job->list);
	}

	job->id = id_counter++;
	if (id_counter < 0)
		id_counter = 0;

	/* TODO: we have to make sure that the id is not used by any existing
	 * jobs. (completed_list)
	 */

out:
	pthread_mutex_unlock(&flock);
	return job;
}

static void complete_active_job(struct active_job *job)
{
	pthread_mutex_lock(&elock);
	list_add(&job->list, &completed_job_list);
	pthread_mutex_unlock(&elock);
}

static void free_active_job(struct active_job *job)
{
	memset(job, 0, sizeof(*job));

	pthread_mutex_lock(&flock);
	list_add(&job->list, &free_job_list);
	pthread_mutex_unlock(&flock);
}

static struct active_job *job_completed(uint64_t id)
{
	struct active_job *tmp, *ret = NULL;

	pthread_mutex_lock(&elock);
	list_for_each_entry(tmp, &completed_job_list, list) {
		if (tmp->id == id) {
			list_del(&tmp->list);
			ret = tmp;
			break;
		}
	}
	pthread_mutex_unlock(&elock);

	return ret;

}

static void clear_jobs(void)
{
	struct active_job *tmp;

	while (!list_empty(&active_job_list)) {
		tmp = fetch_active_job();
		free(tmp);
	}

	while (!list_empty(&free_job_list)) {
		tmp = alloc_active_job();
		free(tmp);
	}
}

#if 0
static void dump_job(struct active_job *job)
{
	pid_t pid;
	char fname[64];
	FILE *fp;

	pid = syscall(SYS_gettid);

	sprintf(fname, "/tmp/execute-%lu", (unsigned int) pid);

	fp = fopen(fname, "a");

	fprintf(fp, "thread        = %lu\n"
		    "job id        = %lu\n"
		    "pid           = 0x%x\n"
		    "input object  = 0x%x\n"
		    "output object = 0x%x\n"
		    "kernel object = 0x%x\n",
		    (unsigned int) pid, job->id,
		    job->pid, job->in, job->out, job->kernel);

	fclose(fp);
}
#endif

static int run_kernel(struct active_job *job)
{
	int ret = 0;
	FILE *fin, *fout;
	char path[MAXNAMELEN];
	void *dh;
	uint64_t len = 0;
	active_kernel_t active_kernel;
	struct active_kernel_job *desc = &job->desc;
	struct osd_device *osd = job->osd;
	uint64_t pid = desc->pid;
	uint64_t in = desc->input;
	uint64_t out = desc->output;
	uint64_t kernel = desc->kernel;

	dfile_name(path, osd->root, pid, kernel);
	dh = dlopen(path, RTLD_LAZY);
	if (!dh) {
		ret = -1;
		goto err_1;
	}

	dlerror();	/** clear exising errors: necessary?? */

	dfile_name(path, osd->root, pid, in);
	fin = fopen(path, "r+");
	if (!fin) {
		ret = -2;
		goto err_1;
	}

	dfile_name(path, osd->root, pid, out);
	fout = fopen(path, "w+");
	if (!fout) {
		ret = -3;
		goto err_2;
	}

	*(void **) (&active_kernel) = dlsym(dh, "execute_kernel");
	if (dlerror() != NULL) {
		ret = -4;
		goto err_3;
	}

	ret = (*active_kernel)(fin, fout, &len, desc->arg_kernel);
	desc->status = ret;
#if 0
	if (!ret)
		desc->result = len;
	job->status = ret;
#endif

err_4:
	fclose(fout);
err_3:
	fclose(fin);
err_2:
	dlclose(dh);
err_1:
	return ret;
}

/**
 * active_thread
 *
 * @arg		[unused]
 *
 * Main loop of working threads. All threads should run on the same cpu. We use
 * the last one here.
 */
static void *active_thread(void *arg)
{
	int ret = 0;
	cpu_set_t cpu_mask;
	long n_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	struct active_job *job = NULL;
	pid_t pid = syscall(SYS_gettid);

	/** first of all, set the cpu affinity */
	CPU_ZERO(&cpu_mask);
	CPU_SET(n_cpus - 1, &cpu_mask);
	ret = sched_setaffinity(0, sizeof(cpu_mask), &cpu_mask);

#if 0
	fprintf(stderr, "\n*** %lu (cpu %ld): running working function..\n",
			(unsigned int) pid, n_cpus - 1);
#endif

	while (1) {
		usleep(DEFAULT_IDLE_SLEEP);
		job = fetch_active_job();

		if (!job) {
			usleep(DEFAULT_IDLE_SLEEP);
			continue;
		}

		//dump_job(job);

		ret = run_kernel(job);
		if (!ret) {
			struct active_kernel_job *desc = &job->desc;
			if (desc->callback)
				(*desc->callback)(desc->arg_callback);
		}

		complete_active_job(job);
	}

	return (void *)0;
}

int osd_init_active_threads(int count)
{
	int ret = 0;
	int i;

	if (count > 0)
		num_active_workers = count;

	for (i = 0; i < num_active_workers; i++) {
		ret = pthread_create(&active_workers[i], NULL,
					active_thread, NULL);
		if (ret)
			goto out;
	}

#if 0
	fprintf(stderr, "\n*** %d active threads created\n", num_active_workers);
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

	for (i = 0; i < num_active_workers; i++)
		pthread_cancel(active_workers[i]);
	for (i = 0; i < num_active_workers; i++)
		pthread_join(active_workers[i], NULL);

	/** TODO: space for on-going job descriptors will be lost. have to
	 * re-write the thread terminating. */
	clear_jobs();
}

/** submit a job and return. the active kernel is executed asynchronously. */
#if 0
int osd_submit_active_job_callback(struct osd_device *osd, uint64_t pid,
		uint64_t in, uint64_t out, uint64_t kernel, uint8_t *sense,
		active_callback_t func, void *arg)
{
	struct active_job *job = alloc_active_job();

	assert(osd && osd->root && osd->dbc && sense);

	job->osd = osd;
	job->pid = pid;
	job->in = in;
	job->out = out;
	job->kernel = kernel;
	job->callback = func;
	job->result = 0;
	job->arg = arg;

	if (!(pid >= USEROBJECT_PID_LB && in >= USEROBJECT_OID_LB
			&& out >= USEROBJECT_OID_LB
			&& kernel >= USEROBJECT_OID_LB))
		goto out_cdb_err;

	if (in == out || out == kernel || kernel == in)
		goto out_cdb_err;

	queue_active_job(job);

	/** TODO: change this to conform a standard protocol. */
	*((uint32_t *) sense) = htonl(job->id);

	return OSD_OK;

out_cdb_err:
	return sense_build_sdd(sense, OSD_SSK_ILLEGAL_REQUEST,
			      OSD_ASC_INVALID_FIELD_IN_CDB, pid, in);
}
#endif

int osd_submit_active_kernel(struct osd_device *osd,
			struct active_kernel_job *job_desc, uint8_t *sense)
{
	struct active_job *job = alloc_active_job();

	assert(osd && osd->root && osd->dbc && job_desc);

	if (!(job_desc->pid >= USEROBJECT_PID_LB
			&& job_desc->input >= USEROBJECT_OID_LB
			&& job_desc->output >= USEROBJECT_OID_LB
			&& job_desc->kernel >= USEROBJECT_OID_LB))
		goto out_cdb_err;

	job->osd = osd;
	job->desc = *job_desc;
	queue_active_job(job);

	*((uint32_t *) sense) = htonl(job->id);

	return OSD_OK;

out_cdb_err:
	return sense_build_sdd(sense, OSD_SSK_ILLEGAL_REQUEST,
			      OSD_ASC_INVALID_FIELD_IN_CDB,
			      job_desc->pid, job_desc->input);
}

int osd_query_active_job(struct osd_device *osd, uint64_t pid,
			uint64_t oid, uint64_t job_id, uint8_t *sense)
{
	struct active_job *job = job_completed(job_id);

	if (job) {
		set_htonll(sense, 0);
		free_active_job(job);
	}
	else
		set_htonll(sense, -1);

	return OSD_OK;
}


