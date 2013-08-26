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
typedef	void (*active_task_callback_t) (int ret, void *arg);

/** change these functions' attributes to constructor/destructor? */
/** for @count, pass '0' to use default number of threads. */

extern int osd_init_active_threads(int count);
extern void osd_exit_active_threads(void);

struct active_task_req {
	uint64_t k_pid;			/* kernel object */
	uint64_t k_oid;

	struct active_obj_list input;
	struct active_obj_list output;
	struct active_args args;
};

extern int osd_submit_active_task(struct osd_device *osd,
				struct active_task_req *req, uint64_t *tid,
				uint8_t *sense);

extern int osd_query_active_task(struct osd_device *osd, uint64_t tid,
			uint64_t *outlen, uint8_t *outdata, uint8_t *sense);

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

