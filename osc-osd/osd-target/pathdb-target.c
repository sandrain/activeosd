#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pathdb-target.h"

enum {
	PATHDB_STMT_SEARCH_PATH	= 0,
	PATHDB_STMT_SEARCH_OID,
	PATHDB_STMT_SEARCH_RUNTIME,

	PATHDB_STMTS
};

static const char *sqls[] = {
	"SELECT nspath FROM afs_nspath WHERE pid=? AND oid=?",
	"SELECT pid,oid FROM afs_nspath WHERE nspath=?",
	"SELECT runtime FROM afs_nspath WHERE pid=? AND oid=?"
};

static inline sqlite3_stmt *stmt_get(struct afs_pathdb *self, int index)
{
	return self->stmts[index];
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
	return 0;

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

	return ret;
}

int afs_pathdb_search_path(struct afs_pathdb *self, uint64_t pid, uint64_t oid,
			char **nspath)
{
	int ret;
	sqlite3_stmt *stmt;
	const char *tmp;

	if (!self || !nspath)
		return -EINVAL;

	stmt = stmt_get(self, PATHDB_STMT_SEARCH_PATH);
	ret = sqlite3_bind_int64(stmt, 1, pid);
	ret |= sqlite3_bind_int64(stmt, 2, oid);
	if (ret) {
		ret = -EIO;
		goto out;
	}

	do {
		ret = sqlite3_step(stmt);
	} while (ret == SQLITE_BUSY);

	if (ret == SQLITE_DONE) {
		ret = -ENOENT;
		goto out;
	}

	if (ret != SQLITE_ROW) {
		ret = -EIO;
		fprintf(stderr, "%s\n", sqlite3_errmsg(self));
		goto out;
	}

	tmp = (const char *) sqlite3_column_text(stmt, 0);
	*nspath = strdup(tmp);
	ret = 0;
out:
	sqlite3_reset(stmt);
	return ret;
}

int afs_pathdb_search_oid(struct afs_pathdb *self, const char *path,
			uint64_t *pid, uint64_t *oid)
{
	int ret;
	sqlite3_stmt *stmt;

	if (!self || !pid || !oid)
		return -EINVAL;

	stmt = stmt_get(self, PATHDB_STMT_SEARCH_OID);
	ret = sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
	if (ret) {
		ret = -EIO;
		goto out;
	}

	do {
		ret = sqlite3_step(stmt);
	} while (ret == SQLITE_BUSY);

	if (ret == SQLITE_DONE) {
		ret = -ENOENT;
		goto out;
	}

	if (ret != SQLITE_ROW) {
		ret = -EIO;
		goto out;
	}

	*pid = sqlite3_column_int64(stmt, 0);
	*oid = sqlite3_column_int64(stmt, 1);
	ret = 0;
out:
	sqlite3_reset(stmt);
	return ret;
}

#define PATHDB_ROOTNAME		"ns"

#define	llu(x)		((unsigned long long) (x))

static inline void get_dfile_name(char *path, const char *root,
				  uint64_t pid, uint64_t oid)
{
	if (!oid)
		sprintf(path, "%s/%s/%02x", root, "dfiles",
			(uint8_t)(oid & 0xFFUL));
	else
		sprintf(path, "%s/%s/%02x/%llx.%llx", root, "dfiles",
			(uint8_t)(oid & 0xFFUL), llu(pid), llu(oid));
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
static int create_dirs(const char *osdroot, const char *fullpath)
{
	int ret = 0;
	mode_t mode = 0;
	char *current, *pos, *path = strdup(fullpath);

	if (!path)
		return -ENOMEM;

	pos = &path[strlen(osdroot)];
	while (*pos++ == '/')
		;

	while ((current = strchr(pos, '/')) != NULL) {
		*current = '\0';

		if (!valid_directory(path)) {
			/** we need to create this directory */
			mode = umask(0);
			ret = mkdir(path, 0755);
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

static int create_link(const char *root, const char *path,
			const uint64_t pid, const uint64_t oid)
{
	char obj_path[2048];

	get_dfile_name(obj_path, root, pid, oid);

	return symlink(obj_path, path);
}

#define	PATHDB_PATHMAX		2048

int afs_pathdb_create_entry(struct afs_pathdb *self, char *root,
			uint64_t pid, uint64_t oid)
{
	int ret = 0;
	char nspath[PATHDB_PATHMAX];
	char *path = NULL;

	/**
	 * hs: as we are moving to the exofs backend in the initiator, we have
	 * to allow for creation of objects without having actual paths (e.g.
	 * superblock)
	 */

	ret = afs_pathdb_search_path(self, pid, oid, &path);
	if (ret)
		return 0;	/** silently allow to create the objects */

	/** the path from the db always comes with the leading '/' */
	sprintf(nspath, "%s/%s%s", root, PATHDB_ROOTNAME, path);

	ret = create_dirs(root, nspath);
	if (ret)
		goto out;

	ret = create_link(root, nspath, pid, oid);
out:
	return ret;
}

/**
 * come back here, only if we really need to implemente the followings.
 */

int afs_pathdb_update_entry(struct afs_pathdb *self, char *root,
			uint64_t pid, uint64_t oid)
{
	int ret = 0;

	return ret;
}


int afs_pathdb_remove_entry(struct afs_pathdb *self, char *root,
			uint64_t pid, uint64_t oid)
{
	int ret = 0;

	return ret;
}

#if 1
/** the errors are not critical here. just set the runtime zero */
int afs_pathdb_get_runtime(struct afs_pathdb *self, uint64_t *runtime /* out */,
				uint64_t pid, uint64_t oid)
{
	int ret;
	sqlite3_stmt *stmt;

	if (!self || !pid || !oid)
		return -EINVAL;

	stmt = stmt_get(self, PATHDB_STMT_SEARCH_RUNTIME);
	ret = sqlite3_bind_int64(stmt, 1, pid);
	ret |= sqlite3_bind_int64(stmt, 2, oid);
	if (ret) {
		ret = -EIO;
		goto out;
	}

	do {
		ret = sqlite3_step(stmt);
	} while (ret == SQLITE_BUSY);

	if (ret == SQLITE_DONE) {
		ret = -ENOENT;
		goto out;
	}

	if (ret != SQLITE_ROW) {
		ret = -EIO;
		goto out;
	}

	*runtime = sqlite3_column_int64(stmt, 0);
	ret = 0;
out:
	sqlite3_reset(stmt);
	return ret;
}
#endif

