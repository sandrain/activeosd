/* Copyright (C) 2013	 - Hyogi Sim <hyogi@cs.vt.edu>
 * 
 * Please refer to COPYING for the license.
 * ---------------------------------------------------------------------------
 * some utility functions.
 */
#ifndef	__SIMPLEHASH_H__
#define	__SIMPLEHASH_H__

/**
 * simple hash table wrapper using std hsearch.
 */
#include <errno.h>
#include <string.h>
#include <search.h>

typedef	struct hsearch_data	afs_htable;

static inline afs_htable *afs_hash_init(size_t nel, afs_htable *htab)
{
	memset(htab, 0, sizeof(*htab));

	return hcreate_r(nel, htab) ? htab : NULL;
}

static inline void afs_hash_exit(afs_htable *htab)
{
	hdestroy_r(htab);
}

static inline int afs_hash_insert(afs_htable *htab, const char *key, void *val)
{
	ENTRY e, *tmp;

	e.key = (char *) key;
	e.data = val;

	return hsearch_r(e, ENTER, &tmp, htab) ? 0 : errno;
}

static inline void *afs_hash_search(afs_htable *htab, const char *key)
{
	int ret;
	ENTRY e, *tmp = NULL;

	e.key = (char *) key;
	e.data = NULL;

	ret = hsearch_r(e, FIND, &tmp, htab);

	return tmp ? tmp->data : NULL;

#if 0
	return hsearch_r(e, FIND, &tmp, htab) ? tmp->data : NULL;
#endif
}

#endif	/** __SIMPLEHASH_H__ */

