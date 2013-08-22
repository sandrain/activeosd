/*
 * OSD extension for supporting active kernel execution.
 */
#ifndef	__ACTIVE_H
#define	__ACTIVE_H

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include "list.h"
#include "osd-types.h"

/**
 * The active kernel function prototype.
 *
 * @in:	Byte stream of input object
 * @out: Byte stream of output object
 * @len: [OUT] The amount of data written to out object. This should set by the
 * kernel function.
 *
 * The kernel function should return 0 on success, <0 otherwise.
 */
typedef int (*active_kernel_t) (FILE *in, FILE *out, uint64_t *len, void *arg);

typedef	void (*active_callback_t) (void *);

/** change these functions' attributes to constructor/destructor? */
/** for @count, pass '0' to use default number of threads. */
extern int osd_init_active_threads(int count);
extern void osd_exit_active_threads(void);

#if 0
extern int osd_submit_active_job(struct osd_device *osd, uint64_t pid,
				uint64_t in, uint64_t out, uint64_t kernel,
				uint8_t *sense);
#define osd_submit_active_job(osd, pid, in, out, kernel, sense) \
	osd_submit_active_job_callback(osd, pid, in, out, kernel, sense, \
				NULL, NULL)

/** TODO: efine some record structure here. too many arguments. */
extern int osd_submit_active_job_callback(struct osd_device *osd, uint64_t pid,
			uint64_t in, uint64_t out, uint64_t kernel,
			uint8_t *sense, active_callback_t func, void *arg);
#endif

extern int osd_query_active_job(struct osd_device *osd, uint64_t pid,
				uint64_t oid, uint64_t job, uint8_t *sense);

struct active_kernel_job {
	uint64_t pid;
	uint64_t input;
	uint64_t output;
	uint64_t kernel;

	int status;
	void *arg_kernel;

	void *arg_callback;
	active_callback_t callback;
};

extern int osd_submit_active_kernel(struct osd_device *osd,
			struct active_kernel_job *job, uint8_t *sense);


/**
 * I/O interface for active jobs. (implemented in active-io.c)
 * The write policy is write-though. All buffers are kept clean.
 *
 * NOTE: This I/O routines don't check the existence of objects being used. The
 * caller is responsible for checking it.
 */

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

#if 0
#define	AOBJ_RD			1
#define	AOBJ_WR			2
#define	AOBJ_RDWR		3

extern int active_open_object(struct osd_device *osd,
				uint64_t pid, uint64_t oid, int mode);

extern int active_close_object(int handle);

extern int active_read_object(int handle, void *buf, size_t len, off_t offset);

extern int active_write_object(int handle, const void *buf, size_t len,
				off_t offset);
#endif

#endif	/** __ACTIVE_H */

