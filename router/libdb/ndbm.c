/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */
/*
 *	Lots of modifications (new guts, more or less..) by
 *	Matti Aarnio <mea@nic.funet.fi>  (copyright) 1992-2004
 */

/* LINTLIBRARY */

#include "mailer.h"
#ifdef	HAVE_NDBM
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#include <errno.h>
#include <ndbm.h>
#include <sys/file.h>
#include "search.h"
#include "io.h"
#include "libz.h"
#include "libc.h"
#include "libsh.h"

typedef struct ZNdbmPrivate {
  DBM	*db;
  int    roflag;
  time_t stmtime;
  long   stino;
  int    stnlink;
} ZNdbmPrivate;

static ZNdbmPrivate * open_ndbm __((search_info *, int, const char *));
static ZNdbmPrivate *
open_ndbm(sip, roflag, comment)
	search_info *sip;
	int roflag;
	const char *comment;
{
	ZNdbmPrivate *prv;
	int i, flag;

	if (sip->file == NULL)
		return NULL;

	prv = (ZNdbmPrivate*) sip->dbprivate;

	if (prv && roflag == O_RDWR && roflag != prv->roflag)
	  close_ndbm(sip,"open_ndbm");

	if (roflag == O_RDWR)	flag = O_RDWR;
	else			flag = O_RDONLY;

	prv = (ZNdbmPrivate*) sip->dbprivate;

	if (!prv || !prv->db) {

		DBM *db = NULL;

		if (!prv) {
		  prv = malloc(sizeof(*prv));
		  if (!prv) return NULL;
		  memset(prv, 0, sizeof(*prv));
		  sip->dbprivate = (void*)prv;
		}

		for (i = 0; i < 3; ++i) {
		  db = dbm_open(sip->file, 0, flag);
		  if (db != NULL)
		    break;
		  sleep(1);
		}

		if (db) {
		  prv->db     = db;
		  prv->roflag = roflag;
		}

		if (db == NULL) {
		  ++deferit;
		  v_set(DEFER, DEFER_IO_ERROR);
		  fprintf(stderr, "%s: cannot open %s!\n",
			  comment, sip->file);
		  return NULL;
		}
	}
	return prv;
}

/*
 * Flush buffered information from this database,
 * close any file descriptors, free private data.
 */

void
close_ndbm(sip,comment)
	search_info *sip;
	const char *comment;
{
	ZNdbmPrivate *prv;

	prv = (ZNdbmPrivate*) sip->dbprivate;

	if (prv == NULL) return;

	if (prv->db)
	  dbm_close(prv->db);

	prv->db = NULL;
}

/*
 * Search an NDBM format database for a key pair.
 */

conscell *
search_ndbm(sip)
	search_info *sip;
{
	DBM *db;
	ZNdbmPrivate *prv;
	datum val, key;
	int retry;

	retry = 0;

reopen:

	prv = open_ndbm(sip, O_RDONLY, "search_ndbm");
	if (prv == NULL || prv->db == NULL)
	  return NULL; /* Failed :-( */
	db = prv->db;

	key.dptr  = (void*) sip->key; /* Sigh.. the cast.. */
	key.dsize = strlen(sip->key) + 1;
	val = dbm_fetch(db, key);
	if (val.dptr == NULL) {
#ifdef HAVE_DBM_ERROR
	  if (!retry && dbm_error(db)) {
	    close_ndbm(sip,"search_ndbm");
	    ++retry;
	    goto reopen;
	  }
#else
	  if (!retry && errno != 0) {
	    close_ndbm(sip,"search_ndbm");
	    ++retry;
	    goto reopen;
	  }
#endif
	  return NULL;
	}
	return newstring(dupnstr(val.dptr, val.dsize), val.dsize);
}

/*
 * Add the indicated key/value pair to the database.
 */

int
add_ndbm(sip, value)
	search_info *sip;
	const char *value;
{
	ZNdbmPrivate *prv;
	DBM *db;
	datum val, key;

	prv = open_ndbm(sip, O_RDWR, "add_ndbm");
	if (prv == NULL || prv->db == NULL)
		return EOF;

	db = prv->db;

	key.dptr  = (void*) sip->key;	/* Sigh.. the cast.. */
	key.dsize = strlen(sip->key) + 1;
	val.dptr  = (void*) value;	/* Sigh.. the cast.. */
	val.dsize = strlen(value) + 1;
	if (dbm_store(db, key, val, DBM_REPLACE) < 0) {
		++deferit;
		v_set(DEFER, DEFER_IO_ERROR);
		fprintf(stderr, "add_ndbm: cannot store (\"%s\",\"%s\")\n",
				sip->key, value);
		return EOF;
	}
	return 0;
}

/*
 * Remove the indicated key from the database.
 */

int
remove_ndbm(sip)
	search_info *sip;
{
	ZNdbmPrivate *prv;
	DBM *db;
	datum key;

	prv = open_ndbm(sip, O_RDWR, "remove_ndbm");
	if (prv == NULL || prv->db == NULL)
		return EOF;

	db = prv->db;

	key.dptr  = (void*) sip->key;	/* Sigh.. the cast.. */
	key.dsize = strlen(sip->key) + 1;
	if (dbm_delete(db, key) < 0) {
		++deferit;
		v_set(DEFER, DEFER_IO_ERROR);
		fprintf(stderr, "remove_ndbm: cannot remove \"%s\"\n",
				sip->key);
		return EOF;
	}
	return 0;
}

/*
 * Print the database.
 */

void
print_ndbm(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	ZNdbmPrivate *prv;
	DBM *db;
	datum key, val;

	prv = open_ndbm(sip, O_RDONLY, "print_ndbm");
	if (prv == NULL || prv->db == NULL)
		return;

	db = prv->db;

	for (key = dbm_firstkey(db); key.dptr != NULL; key = dbm_nextkey(db)) {

		val = dbm_fetch(db, key);
		if (val.dptr == NULL)
			continue;
#ifdef HAVE_DBM_ERROR
		if (dbm_error(db))
			break;
#else
		if (errno != 0)
			break;
#endif
		if (*(char*)val.dptr == '\0')
			fprintf(outfp, "%s\n", key.dptr);
		else
			fprintf(outfp, "%s\t%s\n", key.dptr, val.dptr);
	}
	fflush(outfp);
}

/*
 * Count the database.
 */

void
count_ndbm(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	ZNdbmPrivate *prv;

	prv = open_ndbm(sip, O_RDONLY, "count_ndbm");
	if (prv != NULL && prv->db != NULL) {

	  DBM *db = prv->db;
	  datum key;
	  int cnt = 0;

	  for (key = dbm_firstkey(db);
	       key.dptr != NULL;
	       key = dbm_nextkey(db)) {
#ifdef HAVE_DBM_ERROR
	    if (dbm_error(db))
	      break;
#else
	    if (errno != 0)
	      break;
#endif
	    ++cnt;
	  }
	}

	fprintf(outfp,"%d\n",cnt);
	fflush(outfp);
}

/*
 * Print the uid of the owner of the database.  Note that for ndbm-style
 * databases there are several files involved so picking one of them for
 * security purposes is very dubious.
 */

void
owner_ndbm(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	ZNdbmPrivate *prv;
	struct stat stbuf;

	prv = open_ndbm(sip, O_RDONLY, "owner_ndbm");
	if (prv == NULL || prv->db == NULL)
		return;
	/* There are more timing hazards, when the internal fd is not
	   available for probing.. */
	if (fstat(dbm_pagfno(prv->db), &stbuf) < 0) {
		fprintf(stderr, "owner_ndbm: cannot fstat(\"%s\")!\n",
				sip->file);
		return;
	}
	fprintf(outfp, "%d\n", stbuf.st_uid);
	fflush(outfp);
}

int
modp_ndbm(sip)
	search_info *sip;
{
	ZNdbmPrivate *prv;
	struct stat stbuf;
	struct spblk *spl;
	spkey_t symid;
	int rval;

	prv = open_ndbm(sip, O_RDONLY, "owner_ndbm");
	if (prv == NULL || prv->db == NULL)
		return 0;

	if (fstat(dbm_pagfno(prv->db), &stbuf) < 0) {
		fprintf(stderr, "modp_ndbm: cannot fstat(\"%s\")!\n",
			sip->file);
		return 0;
	}
	if (stbuf.st_nlink == 0)
		return 1;	/* Unlinked underneath of us! */


	rval = ( (stbuf.st_mtime != prv->stmtime) ||
		 (stbuf.st_nlink != prv->stnlink) ||
		 (stbuf.st_ino   != prv->stino) );

	prv->stmtime = stbuf.st_mtime;
	prv->stnlink = stbuf.st_nlink;
	prv->stino   = stbuf.st_ino;

	return rval;
}
#endif	/* HAVE_NDBM */
