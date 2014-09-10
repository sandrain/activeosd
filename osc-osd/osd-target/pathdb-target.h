#ifndef	__PATHDB_TARGET_H__
#define	__PATHDB_TARGET_H__

#include <stdio.h>
#include <stdint.h>
#include <sqlite3.h>

#define	ANFS_PATHDB_DEBUG	1

struct afs_pathdb {
	sqlite3 *conn;
	int osd;	/** my index */
	int status;
	sqlite3_stmt **stmts;
	const char *dbfile;
	char sqlbuf[2048];
#ifdef	ANFS_PATHDB_DEBUG
	FILE *log;
#endif
};

int afs_pathdb_init(struct afs_pathdb *self, const char *dbfile);

int afs_pathdb_exit(struct afs_pathdb *self);

int afs_pathdb_search_path(struct afs_pathdb *self, uint64_t oid, char **path);

int afs_pathdb_create_entry(struct afs_pathdb *self, char *root, uint64_t oid);

#endif	/** __PATHDB_TARGET_H__ */

