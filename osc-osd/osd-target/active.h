/*
 * OSD extension for supporting active kernel execution.
 */
#ifndef	__ACTIVE_H
#define	__ACTIVE_H

#include <stdio.h>
#include <stdint.h>
#include <sys/time.h>
#include <unistd.h>
#include "list.h"
#include "osd-types.h"

/**
 * the active kernel function prototype.
 *
 * eventually, the kernel function should be able to work with multiple # of
 * input objects and output objects.
 */

struct active_params {
	uint32_t n_infiles;
	uint32_t n_outfiles;
	int *fdin;
	int *fdout;
	const char *args;
};

typedef int (*active_kernel_t) (struct active_params *);

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

	pthread_mutex_t lock;

#if 1
	uint64_t runtime;
#endif
};

/**
 * structure to reply client's query
 */
struct active_task_status {
	uint32_t status;
	uint32_t ret;
	uint64_t submit;
	uint64_t start;
	uint64_t complete;
} __attribute__((packed));


/** change these functions' attributes to constructor/destructor? */
/** for @count, pass '0' to use default number of threads. */

extern int osd_init_active_threads(int count);
extern void osd_exit_active_threads(void);

#if 0
struct active_task_req {
	uint64_t k_pid;			/* kernel object */
	uint64_t k_oid;

	struct active_obj_list input;
	struct active_obj_list output;
	struct active_args args;
};
#endif

extern int osd_submit_active_task(struct osd_device *osd, uint64_t pid,
		uint64_t oid, struct kernel_execution_params *params,
		uint8_t *sense);

extern int osd_query_active_task(struct osd_device *osd, uint64_t pid,
		uint64_t tid, uint64_t *outlen, uint8_t *outdata,
		uint8_t *sense);

#define	DFILE_NAME		"dfiles"

/**
 * TODO: Merge this with one in osd.c
 */
static inline void dfile_name(char *path, const char *root,
				  uint64_t pid, uint64_t oid)
{
	if (!oid)
		sprintf(path, "%s/%s/%02x", root, DFILE_NAME,
			(uint8_t)(oid & 0xFFUL));
	else
		sprintf(path, "%s/%s/%02x/%llx.%llx", root, DFILE_NAME,
			(uint8_t)(oid & 0xFFUL), llu(pid), llu(oid));
}

static inline uint64_t active_now(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	return (uint64_t) tv.tv_sec;
}

#endif	/** __ACTIVE_H */

