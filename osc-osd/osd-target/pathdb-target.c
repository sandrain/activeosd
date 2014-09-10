#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pathdb-target.h"

enum {
	PATHDB_STMT_MYINDEX = 0,
	PATHDB_STMT_SEARCH_OID,
	PATHDB_STMT_SEARCH_RUNTIME,
	PATHDB_STMT_SEARCH_PATH,
#ifdef ANFS_PATHDB_DEBUG
	PATHDB_STMT_SEARCH_INO,
	PATHDB_STMT_SEARCH_NSPATH,
#endif
	PATHDB_STMTS
};

static const char *sqls[] = {
	"SELECT osd FROM anfs_hostname WHERE host=?",
	"SELECT oid FROM anfs_nspath WHERE nspath=?",
	"SELECT runtime FROM anfs_nspath WHERE oid=?",
	"SELECT n.nspath FROM anfs_nspath n, anfs_oids o "
		"WHERE n.ino=o.ino AND osd=? AND oid=?",
	"select ino from anfs_oids where osd=? and oid=?",
	"select nspath from anfs_nspath where ino=?",
	0
};

static inline sqlite3_stmt *stmt_get(struct afs_pathdb *self, int index)
{
	return self->stmts[index];
}

#ifndef llu
#define llu(x)		((unsigned long long) (x))
#endif

static int set_index(struct afs_pathdb *self)
{
	int ret;
	char name[32];
	sqlite3_stmt *stmt = stmt_get(self, PATHDB_STMT_MYINDEX);

	ret = gethostname(name, 32);
	if (ret)
		return -errno;

	ret = sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
	if (ret) {
		ret = -EIO;
		goto out;
	}

	do {
		ret = sqlite3_step(stmt);
	} while (ret == SQLITE_BUSY);

	if (ret != SQLITE_ROW) {
		ret = ret == SQLITE_DONE ? -ENOENT : -EIO;
		goto out;
	}

	ret = sqlite3_column_int(stmt, 0);

out:
	sqlite3_reset(stmt);
	return ret;
}

static inline int check_index(struct afs_pathdb *self)
{
	int ret = 0;

	if (self->osd >= 0)
		return 0;

	ret = set_index(self);
	if (ret < 0)
		return ret;
	self->osd = ret;

	return 0;
}

int afs_pathdb_init(struct afs_pathdb *self, const char *dbfile)
{
	int i, ret;
	sqlite3_stmt **stmts = NULL;

	if (!self)
		return -EINVAL;

	ret = sqlite3_open(dbfile, &self->conn);
	if (ret) {
		ret = -EIO;
		goto out;
	}
	self->dbfile = dbfile;

	stmts = calloc(sizeof(*stmts), PATHDB_STMTS);
	if (stmts == NULL) {
		ret = -ENOMEM;
		goto out_close;
	}

	for (i = 0; i < PATHDB_STMTS; i++) {
		ret = sqlite3_prepare(self->conn, sqls[i], -1,
					&stmts[i], NULL);
		if (ret != SQLITE_OK) {
			fputs(sqlite3_errmsg(self->conn), stderr);
			goto out_prepare_sql;
		}
	}

	self->stmts = stmts;
	self->osd = -1;
#ifdef	ANFS_PATHDB_DEBUG
	self->log = fopen("/tmp/pathdb.log", "a");
	if (self->log) {
		setvbuf(self->log, NULL, _IONBF, 0);
		fprintf(self->log, "\n#######################################"
				"\n%s (dbfile=%s)\n", __func__, dbfile);
	}
#endif

	return sqlite3_enable_shared_cache(1);

out_prepare_sql:
	for (--i ; i >= 0; i--)
		sqlite3_finalize(stmts[i]);
	free(stmts);
out_close:
	sqlite3_close(self->conn);
out:
	return ret;
}

int afs_pathdb_exit(struct afs_pathdb *self)
{
	int ret = 0;

	if (self) {
		if (self->stmts) {
			int i;

			for (i = 0; i < PATHDB_STMTS; i++)
				sqlite3_finalize(self->stmts[i]);

			free(self->stmts);
		}

		if (self->conn)
			ret = sqlite3_close(self->conn);
	}
#ifdef	ANFS_PATHDB_DEBUG
	fprintf(self->log, "%s: close the log stream..\n", __func__);
	if (self->log)
		fclose(self->log);
#endif

	return ret;
}

int afs_pathdb_search_path(struct afs_pathdb *self, uint64_t oid, char **path)
{
	int ret;
	sqlite3_stmt *stmt;
	const char *tmp;

#ifdef ANFS_PATHDB_DEBUG
	fprintf(self->log, "%s (osd=%d, oid=%llu (0x%llx))\n", __func__,
				self->osd, llu(oid), llu(oid));
#endif
	check_index(self);

	stmt = stmt_get(self, PATHDB_STMT_SEARCH_PATH);
	ret = sqlite3_bind_int(stmt, 1, self->osd);
	ret |= sqlite3_bind_int64(stmt, 2, oid);
	if (ret) {
		ret = -EIO;
		goto out;
	}

	do {
		ret = sqlite3_step(stmt);
	} while (ret == SQLITE_BUSY);

	if (ret != SQLITE_ROW) {
#ifdef ANFS_PATHDB_DEBUG
		if (ret == SQLITE_DONE)
			fprintf(self->log, "%s (q1): path not found\n",
					__func__);
		else
			fprintf(self->log, "%s (q1): %s\n", __func__,
					sqlite3_errmsg(self->conn));
#endif
		ret = ret == SQLITE_DONE ? -ENOENT : -EIO;
		goto out;
	}

	tmp = (const char *) sqlite3_column_text(stmt, 0);
#ifdef ANFS_PATHDB_DEBUG
	fprintf(self->log, "%s (oid=%llu) = %s\n", __func__, llu(oid), tmp);
#endif
	*path = strdup(tmp);
	ret = 0;
out:
	sqlite3_reset(stmt);
	return ret;
}

#define PATHDB_ROOTNAME		"ns"

#define	llu(x)		((unsigned long long) (x))

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
static int create_dirs(struct afs_pathdb *self, const char *osdroot,
			const char *fullpath)
{
	int ret = 0;
	mode_t mode = 0;
	char *current, *pos, *path = strdup(fullpath);

	if (!path)
		return -ENOMEM;

#ifdef ANFS_PATHDB_DEBUG
	fprintf(self->log, "%s (osdroot=%s, fullpath=%s)\n", __func__,
				osdroot, fullpath);
#endif

	pos = &path[strlen(osdroot)];
	while (*pos++ == '/')
		;

	while ((current = strchr(pos, '/')) != NULL) {
		*current = '\0';

		if (!valid_directory(path)) {
			/** we need to create this directory */
			mode = umask(0);
			ret = mkdir(path, 0755);
#ifdef ANFS_PATHDB_DEBUG
			fprintf(self->log, "%s creates directory %s\n",
					__func__, path);
#endif
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
	char obj_path[2048];

	get_dfile_name(obj_path, root, oid);

	return symlink(obj_path, path);
}

#define	PATHDB_PATHMAX		2048

int afs_pathdb_create_entry(struct afs_pathdb *self, char *root, uint64_t oid)
{
	int ret = 0;
	char nspath[PATHDB_PATHMAX];
	char *path = NULL;

#ifdef ANFS_PATHDB_DEBUG
	fprintf(self->log, "%s (root=%s, oid=%llu)\n", __func__,
				root, llu(oid));
#endif

	/**
	 * hs: as we are moving to the exofs backend in the initiator, we have
	 * to allow for creation of objects without having actual paths (e.g.
	 * superblock)
	 */
	ret = afs_pathdb_search_path(self, oid, &path);
	if (ret)
		return 0;	/** silently allow to create the objects */

	/** the path from the db always comes with the leading '/' */
	sprintf(nspath, "%s/%s%s", root, PATHDB_ROOTNAME, path);

#ifdef ANFS_PATHDB_DEBUG
	fprintf(self->log, "create pathdb dir: %s/%S%S\n",
				root, PATHDB_ROOTNAME, path);
#endif

	ret = create_dirs(self, root, nspath);
	if (ret)
		goto out;

	ret = create_link(root, nspath, oid);
out:
	return ret;
}

