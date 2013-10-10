/* Copyright (C) 2013	 - Hyogi Sim <hyogi@cs.vt.edu>
 * 
 * Please refer to COPYING for the license.
 * ---------------------------------------------------------------------------
 * Task table implementation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sqlite3.h>
#include <assert.h>
#include <sys/time.h>

#include "osd.h"
#include "osd-util/osd-util.h"
#include "task.h"
#include "db.h"

static const char *task_tab_name = "task";

struct task_tab {
	char *name;
	sqlite3_stmt *insert;		/* insert: task submitted */
	sqlite3_stmt *delete;		/* remove the entry */
	sqlite3_stmt *get_status;	/* retrieve status */
	sqlite3_stmt *update_begin;	/* update: task is being executed */
	sqlite3_stmt *update_complete;	/* update: execution completed */
};

int task_initialize(struct db_context *dbc)
{
	int ret = 0;
	int sqlret = 0;
	char SQL[MAXSQLEN];

	if (dbc == NULL || dbc->db == NULL) {
		ret = -EINVAL;
		goto out;
	}

	if (dbc->task != NULL) {
		if (strcmp(dbc->task->name, task_tab_name) != 0) {
			ret = -EINVAL;
			goto out;
		} else {
			task_finalize(dbc);
		}
	}

	dbc->task = Calloc(1, sizeof(*dbc->task));
	if (!dbc->task) {
		ret = -ENOMEM;
		goto out;
	}
	
	dbc->task->name = strdup(task_tab_name); 
	if (!dbc->task->name) {
		ret = -ENOMEM;
		goto out;
	}

	sprintf(SQL, "INSERT INTO %s (pid,oid,icid,ocid,submit,args) "
			"VALUES (?,?,?,?,?,?);", dbc->task->name);
	ret = sqlite3_prepare(dbc->db, SQL, -1, &dbc->task->insert, NULL);
	if (ret != SQLITE_OK)
		goto out_finalize_insert;

	sprintf(SQL, "DELETE FROM %s WHERE tid=?;", dbc->task->name);
	ret = sqlite3_prepare(dbc->db, SQL, -1, &dbc->task->delete, NULL);
	if (ret != SQLITE_OK)
		goto out_finalize_delete;

	sprintf(SQL, "SELECT submit,begin,complete,ret FROM %s WHERE tid=?;",
			dbc->task->name);
	ret = sqlite3_prepare(dbc->db, SQL, -1, &dbc->task->get_status, NULL);
	if (ret != SQLITE_OK)
		goto out_finalize_get_status;

	sprintf(SQL, "UPDATE %s SET begin=? WHERE tid=?;", dbc->task->name);
	ret = sqlite3_prepare(dbc->db, SQL, -1, &dbc->task->update_begin,
				NULL);
	if (ret != SQLITE_OK)
		goto out_finalize_update_begin;

	sprintf(SQL, "UPDATE %s SET complete=?,ret=? WHERE tid=?;",
			dbc->task->name);
	ret = sqlite3_prepare(dbc->db, SQL, -1, &dbc->task->update_complete,
				NULL);
	if (ret != SQLITE_OK)
		goto out_finalize_update_complete;

	ret = OSD_OK;
	goto out;

out_finalize_update_complete:
	db_sqfinalize(dbc->db, dbc->task->update_complete, SQL);
	SQL[0] = '\0';
out_finalize_update_begin:
	db_sqfinalize(dbc->db, dbc->task->update_begin, SQL);
	SQL[0] = '\0';
out_finalize_get_status:
	db_sqfinalize(dbc->db, dbc->task->get_status, SQL);
	SQL[0] = '\0';
out_finalize_delete:
	db_sqfinalize(dbc->db, dbc->task->delete, SQL);
	SQL[0] = '\0';
out_finalize_insert:
	db_sqfinalize(dbc->db, dbc->task->insert, SQL);
	SQL[0] = '\0';
	ret = -EIO;
out:
	return ret;
}

int task_finalize(struct db_context *dbc)
{
	if (!dbc || !dbc->task)
		return OSD_ERROR;

	sqlite3_finalize(dbc->task->insert);
	sqlite3_finalize(dbc->task->delete);
	sqlite3_finalize(dbc->task->update_begin);
	sqlite3_finalize(dbc->task->update_complete);
	free(dbc->task->name);
	free(dbc->task);
	dbc->task = NULL;

	return OSD_OK;
}

/** task->id is set after inserting to db */
int task_insert(struct db_context *dbc, struct active_task *task)
{
	int ret, bound;
	sqlite3_stmt *stmt;

	assert(dbc && dbc->db && dbc->task && dbc->task->insert && task);

	stmt = dbc->task->insert;
	ret = 0;
	ret |= sqlite3_bind_int64(stmt, 1, task->pid);
	ret |= sqlite3_bind_int64(stmt, 2, task->oid);
	ret |= sqlite3_bind_int64(stmt, 3, task->input_cid);
	ret |= sqlite3_bind_int64(stmt, 4, task->output_cid);
	ret |= sqlite3_bind_int64(stmt, 5, active_now());
	ret |= sqlite3_bind_text(stmt, 6, task->args ? task->args : "",
				-1, SQLITE_STATIC);

	/**
	 * because we need to retrieve the inserted id, we cannot use the
	 * helper function, db_exec_dms
	 */
	bound = (ret == SQLITE_OK);
	if (!bound) {
		error_sql(dbc->db, "%s: bind failed", __func__);
		goto out_reset;
	}

	do {
		ret = sqlite3_step(stmt);
	} while (ret == SQLITE_BUSY);

	task->id = sqlite3_last_insert_rowid(dbc->db);

out_reset:
	ret = db_reset_stmt(dbc, stmt, bound, __func__);
	return ret;
}

int task_delete(struct db_context *dbc, const uint64_t tid)
{
	int ret = 0;

	assert(dbc && dbc->db && dbc->task && dbc->task->delete);

repeat:
	ret = 0;
	ret |= sqlite3_bind_int64(dbc->task->delete, 1, tid);
	ret = db_exec_dms(dbc, dbc->task->delete, ret, __func__);
	if (ret == OSD_REPEAT)
		goto repeat;

	return ret;
}

int task_get_status(struct db_context *dbc, const uint64_t tid,
			struct active_task_status *task)
{
	int ret = 0, bound;
	sqlite3_stmt *stmt;

	assert(dbc && dbc->db && dbc->task && dbc->task->get_status && task);

	stmt = dbc->task->get_status;
	ret = sqlite3_bind_int64(stmt, 1, tid);
	bound = (ret == SQLITE_OK);
	if (!bound) {
		error_sql(dbc->db, "%s: bind failed", __func__);
		goto out_reset;
	}

	do {
		ret = sqlite3_step(stmt);
	} while (ret == SQLITE_BUSY);

	if (ret != SQLITE_ROW) {
		ret = -EIO;
		goto out_reset;
	}

	task->submit = sqlite3_column_int64(stmt, 0);
	task->start = sqlite3_column_int64(stmt, 1);
	task->complete = sqlite3_column_int64(stmt, 2);
	task->ret = sqlite3_column_int(stmt, 3);

	ret = OSD_OK;
out_reset:
	ret = db_reset_stmt(dbc, stmt, bound, __func__);
	return ret;
}

/** updates timestamp for the given task */
int task_update_status_begin(struct db_context *dbc, const uint64_t tid)
{
	int ret = 0, bound;
	sqlite3_stmt *stmt;

	assert(dbc && dbc->db && dbc->task && dbc->task->update_begin);

	stmt = dbc->task->update_begin;
	ret |= sqlite3_bind_int64(stmt, 1, active_now());
	ret |= sqlite3_bind_int64(stmt, 2, tid);
	bound = (ret == SQLITE_OK);
	if (!bound) {
		error_sql(dbc->db, "%s: bind failed", __func__);
		goto out_reset;
	}

	do {
		ret = sqlite3_step(stmt);
	} while (ret == SQLITE_BUSY);

out_reset:
	ret = db_reset_stmt(dbc, stmt, bound, __func__);
	return ret;
}

/** update timestamp, ret for the given task */
int task_update_status_complete(struct db_context *dbc, const uint64_t tid,
				const int ret_status)
{
	int ret = 0, bound;
	sqlite3_stmt *stmt;

	assert(dbc && dbc->db && dbc->task && dbc->task->update_complete);

	stmt = dbc->task->update_complete;
	ret |= sqlite3_bind_int64(stmt, 1, active_now());
	ret |= sqlite3_bind_int(stmt, 2, ret_status);
	ret |= sqlite3_bind_int64(stmt, 3, tid);
	bound = (ret == SQLITE_OK);
	if (!bound) {
		error_sql(dbc->db, "%s: bind failed", __func__);
		goto out_reset;
	}

	do {
		ret = sqlite3_step(stmt);
	} while (ret == SQLITE_BUSY);

out_reset:
	ret = db_reset_stmt(dbc, stmt, bound, __func__);
	return ret;
}

