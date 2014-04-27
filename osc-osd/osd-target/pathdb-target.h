#ifndef	__PATHDB_TARGET_H__
#define	__PATHDB_TARGET_H__

#include <stdint.h>
#include <sqlite3.h>

struct afs_pathdb {
	sqlite3 *conn;
	int status;
	sqlite3_stmt **stmts;
	char sqlbuf[2048];
};

int afs_pathdb_init(struct afs_pathdb *self, const char *dbfile);

int afs_pathdb_exit(struct afs_pathdb *self);

/**
 * 
 *
 * @self
 * @pid
 * @oid
 * @nspath [out]: caller should free this.
 *
 * 
 */
int afs_pathdb_search_path(struct afs_pathdb *self, uint64_t pid, uint64_t oid,
			char **nspath);

/**
 * 
 *
 * @self
 * @path
 * @pid [out]
 * @oid [out]
 *
 * 
 */
int afs_pathdb_search_oid(struct afs_pathdb *self, const char *path,
			uint64_t *pid, uint64_t *oid);

#define PATHDB_BASEDIR		

int afs_pathdb_create_entry(struct afs_pathdb *self, char *root,
			uint64_t pid, uint64_t oid);

int afs_pathdb_update_entry(struct afs_pathdb *self, char *root,
			uint64_t pid, uint64_t oid);

#endif	/** __PATHDB_TARGET_H__ */

