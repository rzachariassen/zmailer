/*
 *      A component of ZMailer
 *
 *	Copyright 1996-2003 Matti Aarnio
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

#include <errno.h>

extern int errno;
extern int deferit;

/*
 * Flush buffered information from this database, close any file descriptors.
 */

void
close_btree(sip,comment)
	search_info *sip;
	const char *comment;
{
	ZSleepyPrivate *prv;

	if (*(sip->dbprivate) == NULL )
	  return;

	prv = *(sip->dbprivate);

	SLEEPYCATDBCLOSE(prv->db);

	zsleepyprivatefree(prv);

	*(sip->dbprivate) = NULL;
}


static ZSleepyPrivate * open_btree __((search_info *, int, const char *));
static ZSleepyPrivate *
open_btree(sip, roflag, comment)
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
		/* Doing that (too) in  zsleepyprivateinit()  below */
	}

	if (sip->file == NULL)
		return NULL;



	if (*prvp && roflag != (*prvp)->roflag)
 		close_btree(sip,"open_btree");

	if (*prvp) db = (*prvp)->db;

	if (db == NULL) {

	    char *phase = "";
	    /* Three attempts to open it.. */
	    for (i = 0; i < 3; ++i) {

		int err;

		*prvp = zsleepyprivateinit(sip->file, sip->cfgfile,
					   DB_BTREE);

		if (!*prvp) break; /* URGH!! Out of memory! */

	        err = zsleepyprivateopen(*prvp, roflag, 0644, &phase);
		db = (*prvp)->db;

		if (db)  break;

		if (*prvp)
		  zsleepyprivatefree(*prvp);
		*prvp = NULL;

		sleep(1); /* Open failed, retry after a moment */
	    }

	    /* Still failed ?? */
	    if (db == NULL) {
		++deferit;
		v_set(DEFER, DEFER_IO_ERROR);
		fprintf(stderr, "%s: cannot open%s %s!\n",
			comment, phase, sip->file);

		if (*prvp)
		  zsleepyprivatefree(*prvp);

		return NULL;
	    }
	}


	/* Got it open ? */

	if (db != NULL) {

	    /* Prepare for  modp_btree()  tests. */

	    struct stat stbuf;
	    int fd = -1, err = 0;

#if defined(HAVE_DB2) || defined(HAVE_DB3) || defined(HAVE_DB4)
	    err = (db->fd)(db, &fd);
	    if (fstat(fd, &stbuf) < 0) {
		fprintf(stderr, "open_btree: cannot fstat(\"%s\"(%d))!  err=%d/%s (%s/%s)\n",
			sip->file, fd, err, errno,
			db_strerror(err), strerror(errno));

		SLEEPYCATDBCLOSE(db);
		if (*prvp)
		  zsleepyprivatefree(*prvp);

		return NULL;
	    }
#else
	    fd = (db->fd)(db);
	    if (fstat(fd, &stbuf) < 0) {
		fprintf(stderr, "open_btree: cannot fstat(\"%s\"/%d))!  err=%d (%s)\n",
			sip->file, fd, errno, strerror(errno));

		SLEEPYCATDBCLOSE(db);
		if (*prvp)
		  zsleepyprivatefree(*prvp);

		return NULL;
	    }
#endif

	    (*prvp)->mtime = stbuf.st_mtime;

	}

	return *prvp;
}


/*
 * Search a B-TREE format database for a key pair.
 */

conscell *
search_btree(sip)
	search_info *sip;
{
	ZSleepyPrivate *prv;
	DB *db;
	DBT val, key;
	int retry, rc;

	retry = 0;
#if 0
reopen:
#endif
	prv = open_btree(sip, O_RDONLY, "search_btree");
	if (prv == NULL)
	  return NULL; /* Huh! */

	db = prv->db;

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
			close_btree(sip,"search_btree");
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
add_btree(sip, value)
	search_info *sip;
	const char *value;
{
	DB *db;
	DBT val, key;
	int rc;
	ZSleepyPrivate *prv;

	prv = open_btree(sip, O_RDWR, "add_btree");
	if (prv == NULL)
		return EOF;
	db = prv->db;

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
		fprintf(stderr, "add_btree: cannot store (\"%s\",\"%s\")\n",
				sip->key, value);
		return EOF;
	}
	return 0;
}

/*
 * Remove the indicated key from the database.
 */

int
remove_btree(sip)
	search_info *sip;
{
	DB *db;
	DBT key;
	int rc;
	ZSleepyPrivate *prv;

	prv = open_btree(sip, O_RDWR, "remove_btree");
	if (prv == NULL)
		return EOF;
	db = prv->db;

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
		fprintf(stderr, "remove_btree: cannot remove \"%s\"\n",
				sip->key);
		return EOF;
	}
	return 0;
}

/*
 * Print the database.
 */

void
print_btree(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	DB *db;
	DBT key, val;
	int rc;
	ZSleepyPrivate *prv;
#if defined(HAVE_DB2) || defined(HAVE_DB3) || defined(HAVE_DB4)
	DBC *curs = NULL;

	prv = open_btree(sip, O_RDONLY, "print_btree");
	if (prv == NULL)
		return;
	db = prv->db;

#ifdef HAVE_DB_CURSOR4
	rc = (db->cursor)(db, NULL, &curs, 0);
#else
	rc = (db->cursor)(db, NULL, &curs);
#endif
	prv->cursor = curs;

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
	prv->cursor = NULL;
#else

	prv = open_btree(sip, O_RDONLY, "print_btree");
	if (prv == NULL)
		return;
	db = prv->db;

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
count_btree(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	DB *db;
	DBT key, val;
	int cnt = 0;
	int rc;
	ZSleepyPrivate * prv;
#if defined(HAVE_DB2) || defined(HAVE_DB3) || defined(HAVE_DB4)
	DBC *curs;

	prv = open_btree(sip, O_RDONLY, "count_btree");

	if (prv && prv->db) {
	  db = prv->db;

	  curs = NULL;
#ifdef HAVE_DB_CURSOR4
	  rc = (db->cursor)(db, NULL, &curs, 0);
#else
	  rc = (db->cursor)(db, NULL, &curs);
#endif
	  prv->cursor = curs;

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
	prv->cursor = NULL;
#else
	prv = open_btree(sip, O_RDONLY, "count_btree");
	if (prv != NULL) {
	  db = prv->db;

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
owner_btree(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	DB *db;
	struct stat stbuf;
	int fd = -1;

	ZSleepyPrivate *prv = open_btree(sip, O_RDONLY, "owner_btree");
	if (!prv || !prv->db)
		return;
	db = prv->db;

	/* There are timing hazards, when the internal fd is not
	   available for probing.. */
#if defined(HAVE_DB2) || defined(HAVE_DB3) || defined(HAVE_DB4)
	(db->fd)(db, &fd);
#else
	fd = (db->fd)(db);
#endif
	if (fd < 0 || fstat(fd, &stbuf) < 0) {
		fprintf(stderr, "owner_btree: cannot fstat(\"%s\")!\n",
				sip->file);
		return;
	}
	fprintf(outfp, "%d\n", stbuf.st_uid);
	fflush(outfp);
}

int
modp_btree(sip)
	search_info *sip;
{
	DB *db;
	struct stat stbuf;
	int rval, fd = -1, err = 0;
	int roflag = O_RDONLY;

	ZSleepyPrivate *prv;

	prv = open_btree(sip, roflag, "owner_btree"); /* if it isn't open.. */
	if (!prv || !prv->db) return 0;
	
	roflag = prv->roflag;
	db     = prv->db;

#if defined(HAVE_DB2) || defined(HAVE_DB3) || defined(HAVE_DB4)
	err = (db->fd)(db, &fd);
#else
	fd = (db->fd)(db);
#endif
	if (fstat(fd, &stbuf) < 0) {
		fprintf(stderr, "modp_btree: cannot fstat(\"%s\"(%d))! err=%d\n",
				sip->file, fd, err);
		return 0;
	}
	if (stbuf.st_nlink == 0)
		return 1;	/* Unlinked underneath of us! */

	if (roflag != O_RDONLY) return 0; /* We are a WRITER ??
					     Of course it changes.. */

	rval = (stbuf.st_mtime != prv->mtime || stbuf.st_nlink != 1);

	prv->mtime = stbuf.st_mtime;


	return rval;
}
#endif	/* HAVE_DB */
