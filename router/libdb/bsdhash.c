/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *
 *	Copyright 1996-2002 Matti Aarnio
 */

/* LINTLIBRARY */

#include "mailer.h"

#include "sleepycatdb.h"
#ifdef HAVE_DB

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif


#include <sys/file.h>
#include "search.h"
#include "io.h"
#include "libz.h"
#include "libc.h"
#include "libsh.h"

extern int errno;
extern int deferit;

/*
 * Flush buffered information from this database, close any file descriptors.
 */

void
close_bhash(sip,comment)
	search_info *sip;
	const char *comment;
{
	ZSleepyPrivate *prv;

	if (*(sip->dbprivate) == NULL )
		return;

	prv = *(sip->dbprivate);

	SLEEPYCATDBCLOSE(prv->db);

	zsleepyprivatefree(prv);

	sip->dbprivate = NULL;
}


static DB * open_bhash __((search_info *, int, const char *));
static DB *
open_bhash(sip, roflag, comment)
	search_info *sip;
	int roflag;
	const char *comment;
{
	int i;
	ZSleepyPrivate **prvp = (ZSleepyPrivate **)sip->dbprivate;
	DB *db = NULL;

	if (sip->cfgfile) {
		/* read the related configuration file, e.g.
		   information about environment, etc.. */
	}

	if (sip->file == NULL)
		return NULL;



	if (*prvp && roflag != (*prvp)->roflag)
 		close_bhash(sip,"open_bhash");

	if (*prvp) db = (*prvp)->db;

	if (db == NULL) {

	    *prvp = zsleepyprivateinit(sip->file, sip->cfgfile, DB_HASH);
	    if (!*prvp) return NULL; /* URGH!! Out of memory! */

	    for (i = 0; i < 3; ++i) {

		int err;
	        err = zsleepyprivateopen(*prvp, roflag, 0644);
		db = (*prvp)->db;

		if (db != NULL)  break;

		sleep(1); /* Open failed, retry after a moment */
	    }
	    if (db == NULL) {
		++deferit;
		v_set(DEFER, DEFER_IO_ERROR);
		fprintf(stderr, "%s: cannot open %s!\n",
			comment, sip->file);
		return NULL;
	    }
	}

	if (db != NULL) {

	    /* Prepare for  modp_bhash()  tests. */

	    struct stat stbuf;
	    int fd = -1, err = 0;

#if defined(HAVE_DB2) || defined(HAVE_DB3) || defined(HAVE_DB4)
	    err = (db->fd)(db, &fd);
	    if (fstat(fd, &stbuf) < 0) {
		fprintf(stderr, "open_bhash: cannot fstat(\"%s\"(%d))!  err=%d/%s (%s/%s)\n",
			sip->file, fd, err, errno,
			db_strerror(err), strerror(errno));
		return 0;
	    }
#else
	    fd = (db->fd)(db);
	    if (fstat(fd, &stbuf) < 0) {
		fprintf(stderr, "open_bhash: cannot fstat(\"%s\"/%d))!  err=%d (%s)\n",
			sip->file, fd, errno, strerror(errno));
		return 0;
	    }
#endif

	    (*prvp)->mtime = stbuf.st_mtime;

	}

	return db;
}


/*
 * Search a B-TREE format database for a key pair.
 */

conscell *
search_bhash(sip)
	search_info *sip;
{
	DB *db;
	DBT val, key;
	int retry, rc;

	retry = 0;
#if 0
reopen:
#endif
	db = open_bhash(sip, O_RDONLY, "search_bhash");
	if (db == NULL)
	  return NULL; /* Huh! */

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	key.data = (void*)sip->key;
	key.size = strlen(sip->key) + 1;

#ifdef DB_INIT_TXN
	rc = (db->get)(db, NULL, &key, &val, 0);
#else
	rc = (db->get)(db, &key, &val, 0);
#endif
	if (rc != 0) {

#if 0 /* SleepyCat's DB 2.x leaks memory mappings when opening...
	 at least the version at glibc 2.1.1 */

		if (!retry && rc < 0) {
			close_bhash(sip,"search_bhash");
			++retry;
			goto reopen;
		}
#endif
		return NULL;
	}
	return newstring(dupnstr(val.data, val.size), val.size);
}


/*
 * Add the indicated key/value pair to the database.
 */

int
add_bhash(sip, value)
	search_info *sip;
	const char *value;
{
	DB *db;
	DBT val, key;
	int rc;

	db = open_bhash(sip, O_RDWR, "add_bhash");
	if (db == NULL)
		return EOF;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	key.data = (void*)sip->key;
	key.size = strlen(sip->key) + 1;

	val.data = (void*)value;
	val.size = strlen(value)+1;
#ifdef DB_INIT_TXN
	rc = (db->put)(db, NULL, &key, &val, 0);
	/* Emulate BSD DB 1.85 behaviour */
	if (rc != 0)
	  rc = -1;
#else
	rc = (db->put)(db, &key, &val, 0);
#endif
	if (rc < 0) {
		++deferit;
		v_set(DEFER, DEFER_IO_ERROR);
		fprintf(stderr, "add_bhash: cannot store (\"%s\",\"%s\")\n",
				sip->key, value);
		return EOF;
	}
	return 0;
}

/*
 * Remove the indicated key from the database.
 */

int
remove_bhash(sip)
	search_info *sip;
{
	DB *db;
	DBT key;
	int rc;

	db = open_bhash(sip, O_RDWR, "remove_bhash");
	if (db == NULL)
		return EOF;

	memset(&key, 0, sizeof(key));

	key.data = (void*)sip->key;
	key.size = strlen(sip->key) + 1;
#ifdef DB_INIT_TXN
	rc = (db->del)(db, NULL, &key, 0);
#else
	rc = (db->del)(db, &key, 0);
#endif
	if (rc < 0) {
		++deferit;
		v_set(DEFER, DEFER_IO_ERROR);
		fprintf(stderr, "remove_bhash: cannot remove \"%s\"\n",
				sip->key);
		return EOF;
	}
	return 0;
}

/*
 * Print the database.
 */

void
print_bhash(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	DB *db;
	DBT key, val;
	int rc;
#if defined(HAVE_DB2) || defined(HAVE_DB3) || defined(HAVE_DB4)
	DBC *curs;

	db = open_bhash(sip, O_RDONLY, "print_bhash");
	if (db == NULL)
		return;

#ifdef HAVE_DB_CURSOR4
	rc = (db->cursor)(db, NULL, &curs, 0);
#else
	rc = (db->cursor)(db, NULL, &curs);
#endif

	memset(&val, 0, sizeof(val));
	memset(&key, 0, sizeof(key));

	if (rc == 0 && curs)
	  rc = (curs->c_get)(curs, &key, &val, DB_FIRST);
	for ( ; rc == 0 ; ) {
		if (val.data == NULL)
			continue;
		if (*(char*)val.data == '\0')
			fprintf(outfp, "%s\n", key.data);
		else
			fprintf(outfp, "%s\t%s\n", key.data, val.data);

		memset(&val, 0, sizeof(val));
		memset(&key, 0, sizeof(key));

		rc = (curs->c_get)(curs, &key, &val, DB_NEXT);
	}
	(curs->c_close)(curs);
#else

	db = open_bhash(sip, O_RDONLY, "print_bhash");
	if (db == NULL)
		return;

	memset(&val, 0, sizeof(val));
	memset(&key, 0, sizeof(key));

	rc = (db->seq)(db, &key, &val, R_FIRST);
	for ( ; rc == 0 ; ) {
		if (val.data == NULL)
			continue;
		if (*(char*)val.data == '\0')
			fprintf(outfp, "%s\n", key.data);
		else
			fprintf(outfp, "%s\t%s\n", key.data, val.data);

		memset(&val, 0, sizeof(val));
		memset(&key, 0, sizeof(key));

		rc = (db->seq)(db, &key, &val, R_NEXT);
	}
#endif
	fflush(outfp);
}

/*
 * Count the database.
 */

void
count_bhash(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	DB *db;
	DBT key, val;
	int cnt = 0;
	int rc;
#if defined(HAVE_DB2) || defined(HAVE_DB3) || defined(HAVE_DB4)
	DBC *curs;

	db = open_bhash(sip, O_RDONLY, "count_bhash");

	if (db != NULL) {
#ifdef HAVE_DB_CURSOR4
	  rc = (db->cursor)(db, NULL, &curs, 0);
#else
	  rc = (db->cursor)(db, NULL, &curs);
#endif

	  memset(&val, 0, sizeof(val));
	  memset(&key, 0, sizeof(key));

	  if (rc == 0 && curs)
	    rc = (curs->c_get)(curs, &key, &val, DB_FIRST);
	  while (rc == 0) {
	    if (val.data == NULL) /* ???? When this would happen ? */
	      continue;
	    ++cnt;

	    memset(&val, 0, sizeof(val));
	    memset(&key, 0, sizeof(key));

	    rc = (curs->c_get)(curs, &key, &val, DB_NEXT);
	  }
	}
	(curs->c_close)(curs);
#else
	db = open_bhash(sip, O_RDONLY, "count_bhash");
	if (db != NULL) {

	  memset(&val, 0, sizeof(val));
	  memset(&key, 0, sizeof(key));

	  rc = (db->seq)(db, &key, &val, R_FIRST);
	  while (rc == 0) {
	    if (val.data == NULL) /* ???? When this would happen ? */
	      continue;
	    ++cnt;
	    rc = (db->seq)(db, &key, &val, R_NEXT);
	  }
	}
#endif
	fprintf(outfp,"%d\n",cnt);
	fflush(outfp);
}

/*
 * Print the uid of the owner of the database.  Note that for db-style
 * databases there are several files involved so picking one of them for
 * security purposes is very dubious.
 */

void
owner_bhash(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	DB *db;
	struct stat stbuf;
	int fd;

	db = open_bhash(sip, O_RDONLY, "owner_bhash");
	if (db == NULL)
		return;

	/* There are timing hazards, when the internal fd is not
	   available for probing.. */
#if defined(HAVE_DB2) || defined(HAVE_DB3) || defined(HAVE_DB4)
	(db->fd)(db, &fd);
#else
	fd = (db->fd)(db);
#endif
	if (fstat(fd, &stbuf) < 0) {
		fprintf(stderr, "owner_bhash: cannot fstat(\"%s\")!\n",
				sip->file);
		return;
	}
	fprintf(outfp, "%d\n", stbuf.st_uid);
	fflush(outfp);
}

int
modp_bhash(sip)
	search_info *sip;
{
	DB *db;
	struct stat stbuf;
	int rval, fd = -1, err = 0;
	int roflag = O_RDONLY;

	ZSleepyPrivate **prvp = (ZSleepyPrivate **)sip->dbprivate;
	if (*prvp) roflag = (*prvp)->roflag;

	if (roflag != O_RDONLY) return 0; /* We are a WRITER ??
					     Of course it changes.. */

	db = open_bhash(sip, roflag, "owner_bhash"); /* if it isn't open.. */
	if (db == NULL) return 0;

#if defined(HAVE_DB2) || defined(HAVE_DB3) || defined(HAVE_DB4)
	err = (db->fd)(db, &fd);
#else
	fd = (db->fd)(db);
#endif
	if (fstat(fd, &stbuf) < 0) {
		fprintf(stderr, "modp_bhash: cannot fstat(\"%s\"(%d))! err=%d\n",
				sip->file, fd, err);
		return 0;
	}
	if (stbuf.st_nlink == 0)
		return 1;	/* Unlinked underneath of us! */
	

	rval = (stbuf.st_mtime != (*prvp)->mtime || stbuf.st_nlink != 1);

	(*prvp)->mtime = stbuf.st_mtime;


	return rval;
}
#endif	/* HAVE_DB */
