/* Copyright (C) 2013	 - Hyogi Sim <hyogi@cs.vt.edu>
 * 
 * Please refer to COPYING for the license.
 * ---------------------------------------------------------------------------
 * Task execution related record access methods.
 */
#ifndef	__TASK_H
#define	__TASK_H

#include <sqlite3.h>
#include "osd-types.h"
#include "active.h"

int task_initialize(struct db_context *dbc);

int task_finalize(struct db_context *dbc);

/** task->id is set after inserting to db */
int task_insert(struct db_context *dbc, struct active_task *task);

int task_delete(struct db_context *dbc, const uint64_t tid);

int task_get_status(struct db_context *dbc, const uint64_t tid,
			struct active_task_status *task);

/** updates timestamp for the given task */
int task_update_status_begin(struct db_context *dbc, const uint64_t tid);

/** update timestamp, ret for the given task */
int task_update_status_complete(struct db_context *dbc, const uint64_t tid,
				const int ret);

#endif

