/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *
 *	Port of NDBM version to GDBM by Matti Aarnio 1989-1997
 *
 *	Currently uses GDBM version 1.7.3 !
 *	Supports also GDBM version 1.8.0!
 */
/*
 *	Lots of modifications (new guts, more or less..) by
 *	Matti Aarnio <mea@nic.funet.fi>  (copyright) 1992-2003
 */

/* LINTLIBRARY */

#include "mailer.h"
#ifdef	HAVE_GDBM
#include <gdbm.h>
#ifndef	HAVE_GDBM_FDESC
	/* Because GDBM 1.7.3 does not have gdbm_fdesc() or some such,
	   we must do "Horrible Kludges"(TM) to find the fileno..	*/
	/* THIS MUST TRACK THE GDBM INTERNAL DATA STRUCTURE ! Auurgh...! */
struct __gdbmfoo {
	char *name;     /* Space alloc for things that are there */
	int read_write;
#ifdef GDBM_FASTMODE	/* This appeared somewhen in between 0.9 and 1.7.3 */
        int fast_write;
#endif
	void (*fatal_err) __((void));
	int desc;       /* this is what we do need! */
	/* the rest is irrelevant for us.. */
};
#define gdbm_fdesc(db) (((struct __gdbmfoo *) (db))->desc)
#endif

#include <fcntl.h>
#include <sys/file.h>

#include "libsh.h"
#include "search.h"
#include "io.h"
#include "libz.h"
#include "libc.h"
#include "libsh.h"

/* extern int gdbm_errno; */
extern int deferit;
extern int nobody;	/* UID of NOBODY */

typedef struct ZGdbmPrivate {
  GDBM_FILE db;
  int roflag;
} ZGdbmPrivate;


static ZGdbmPrivate * open_gdbm __((search_info *, int, const char *));

static ZGdbmPrivate *
open_gdbm(sip, roflag, comment)
	search_info *sip;
	int roflag;
	const char *comment;
{
	int i, flag;
	ZGdbmPrivate *prv;

	if (sip->file == NULL)
		return NULL;

	prv = (ZGdbmPrivate*) sip->dbprivate;

	if (prv && roflag == O_RDWR && roflag != prv->roflag)
	  close_gdbm(sip,"open_gdbm");

	if (roflag == O_RDWR)	flag = GDBM_WRITER;
	else			flag = GDBM_READER;

	if (!prv || !prv->db) {

		GDBM_FILE db = NULL;

		prv = malloc(sizeof(*prv));
		if (!prv) return NULL;
		memset(prv, 0, sizeof(*prv));

		for (i = 0; i < 3; ++i) {
		  db = gdbm_open((void*)sip->file, 0, flag, 0, NULL);
		  if (db != NULL)
		    break;
		  free(prv);
		  prv = NULL;
		  sleep(1);
		}

		if (prv) {
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

		sip->dbprivate = (void*)prv;
	}
	return prv;
}


/*
 * Search an GDBM format database for a key pair.
 */

conscell *
search_gdbm(sip)
	search_info *sip;
{
	GDBM_FILE db;
	datum val, key;
	conscell *tmp;
	int retry;
	ZGdbmPrivate *prv;

	retry = 0;

reopen:
	prv = open_gdbm(sip, O_RDONLY, "search_gdbm");

	if (!prv || !prv->db)
	  return NULL;
	db = prv->db;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	key.dptr  = (void*)sip->key;
	key.dsize = strlen(sip->key) + 1;

	val = gdbm_fetch(db, key);

	if (val.dptr == NULL) {
	  if (!retry && gdbm_errno != GDBM_NO_ERROR &&
	      gdbm_errno != GDBM_EMPTY_DATABASE) {
	    close_gdbm(sip,"search_gdbm");
	    ++retry;
	    goto reopen;
	  }
	  return NULL;
	}
	tmp = newstring(dupnstr(val.dptr, val.dsize), val.dsize);
	free(val.dptr);
	return tmp;
}

/*
 * Flush buffered information from this database, close any file descriptors.
 */

void
close_gdbm(sip,comment)
	search_info *sip;
	const char *comment;
{
	GDBM_FILE db;
	struct spblk *spl;
	spkey_t symid;

	if (sip->file == NULL)
		return;
	symid = symbol_db(sip->file, spt_files->symbols);
	if ((spkey_t)0 == symid)
		return;
	spl = sp_lookup(symid, spt_modcheck);
	if (spl != NULL)
		sp_delete(spl, spt_modcheck);
	spl = sp_lookup(symid, spt_files);
	if (spl == NULL || (db = (GDBM_FILE)spl->data) == NULL)
		return;
	gdbm_close(db);
	sp_delete(spl, spt_files);
}


/*
 * Add the indicated key/value pair to the database.
 */

int
add_gdbm(sip, value)
	search_info *sip;
	const char *value;
{
	GDBM_FILE db;
	datum val, key;
	ZGdbmPrivate *prv;

	prv = open_gdbm(sip, O_RDWR, "add_gdbm");
	if (!prv || !prv->db)
		return EOF;
	db = prv->db;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	key.dptr  = (void*)sip->key;
	key.dsize = strlen(sip->key) + 1;

	val.dptr  = (void*)value;
	val.dsize = strlen(value) + 1;

	if (gdbm_store(db, key, val, GDBM_REPLACE) < 0) {
		++deferit;
		v_set(DEFER, DEFER_IO_ERROR);
		fprintf(stderr, "add_gdbm: cannot store (\"%s\",\"%s\")\n",
				sip->key, value);
		return EOF;
	}
	return 0;
}

/*
 * Remove the indicated key from the database.
 */

int
remove_gdbm(sip)
	search_info *sip;
{
	GDBM_FILE db;
	datum key;
	ZGdbmPrivate *prv;

	prv = open_gdbm(sip, O_RDWR, "remove_gdbm");
	if (!prv || !prv->db)
		return EOF;
	db = prv->db;

	memset(&key, 0, sizeof(key));

	key.dptr  = (void*)sip->key;
	key.dsize = strlen(sip->key) + 1;

	if (gdbm_delete(db, key) < 0) {
		++deferit;
		v_set(DEFER, DEFER_IO_ERROR);
		fprintf(stderr,
			"remove_gdbm: cannot remove \"%s\" from \"%s\"\n",
			sip->key, sip->file);
		return EOF;
	}
	return 0;
}

/*
 * Print the database.
 */

void
print_gdbm(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	GDBM_FILE db;
	datum key, nextkey, val;
	ZGdbmPrivate *prv;

	prv = open_gdbm(sip, O_RDONLY, "print_gdbm");
	if (!prv || !prv->db)
		return;
	db = prv->db;

	memset(&key, 0, sizeof(key));
	memset(&nextkey, 0, sizeof(nextkey));
	memset(&val, 0, sizeof(val));

	key = gdbm_firstkey(db);
	while (key.dptr) {
		val = gdbm_fetch(db, key);
		if (gdbm_errno)
			break;
		if (val.dptr == NULL || *val.dptr == '\0')
			fprintf(outfp, "%s\n", key.dptr);
		else
			fprintf(outfp, "%s\t%s\n", key.dptr, val.dptr);
		if (val.dptr)
			free(val.dptr);
		nextkey = gdbm_nextkey(db, key);
		free(key.dptr);
		key = nextkey;
	}
	fflush(outfp);
}

/*
 * Count the database.
 */

void
count_gdbm(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	ZGdbmPrivate *prv;
	int count = 0;

	prv = open_gdbm(sip, O_RDONLY, "count_gdbm");
	if (prv && prv->db) {

	  GDBM_FILE db = prv->db;
	  datum key, nextkey;
	  
	  key = gdbm_firstkey(db);
	  while (key.dptr) {
	    ++count;
	    nextkey = gdbm_nextkey(db, key);
	    if (key.dptr) free(key.dptr);
	    if (gdbm_errno) break;
	    key = nextkey;
	  }
	}
	fprintf(outfp,"%d\n",count);
	fflush(outfp);
}

/*
 * Print the uid of the owner of the database file.
 * (For the security purposes.)  Unlike  DBM and NDBM,
 * for GDBM there is only one file, and this makes
 * more sense..
 */

void
owner_gdbm(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	GDBM_FILE db;
	int	fno;
	struct stat stbuf;
	ZGdbmPrivate *prv;

	prv = open_gdbm(sip, O_RDONLY, "owner_gdbm");
	if (!prv || !prv->db) {
	  fprintf(outfp, "%d\n", nobody);
	  return;
	}
	db = prv->db;

	fno = gdbm_fdesc(db);
	if (fstat(fno, &stbuf) < 0) {
		fprintf(stderr, "owner_gdbm: cannot fstat(\"%s\")!\n",
				sip->file);
		fprintf(outfp, "%d\n", nobody);
		return;
	}
	fprintf(outfp, "%d\n", stbuf.st_uid);
	fflush(outfp);
}

int
modp_gdbm(sip)
	search_info *sip;
{
	GDBM_FILE db;
	int	fno;
	struct stat stbuf;
	struct spblk *spl;
	spkey_t symid;
	int rval;
	ZGdbmPrivate *prv;

	prv = open_gdbm(sip, O_RDONLY, "modp_gdbm");
	if (!prv || !prv->db)
		return 0;
	db = prv->db;

	fno = gdbm_fdesc(db);
	if (fstat(fno, &stbuf) < 0) {
		fprintf(stderr, "modp_gdbm: cannot fstat(\"%s\")!\n",
				sip->file);
		return 0;
	}
	if (stbuf.st_nlink == 0)
		return 1;	/* Unlinked underneath of us! */

	symid = symbol_db(sip->file, spt_files->symbols);
	spl   = sp_lookup(symid, spt_modcheck);
	if (spl != NULL) {
		rval = stbuf.st_mtime != (time_t)spl->data
			|| (long)stbuf.st_nlink != (long)spl->mark
			|| stbuf.st_nlink == 0;
	} else
		rval = 0;
	sp_install(symid, (u_char *)stbuf.st_mtime,
			  stbuf.st_nlink, spt_modcheck);
	return rval;
}
#endif	/* HAVE_GDBM */
