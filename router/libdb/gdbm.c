/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *
 *	Port of NDBM version to GDBM by Matti Aarnio 1989-1997
 *
 *	Currently uses GDBM version 1.7.3 !
 */

/* LINTLIBRARY */

#include "mailer.h"
#ifdef	HAVE_GDBM_H
#include <gdbm.h>
#ifndef	GDBM_VERSION /* In a hope of GDBM 1.7.4 having this #define, and
			the   gdbm_filefno() function.. */
	/* Because GDBM 1.7.3 does not have gdbm_filefno() or some such,
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
#define gdbm_filefno(db) (((struct __gdbmfoo *) (db))->desc)
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

static GDBM_FILE open_gdbm __((search_info *, int, const char *));

static GDBM_FILE
open_gdbm(sip, flag, comment)
	search_info *sip;
	int flag;
	const char *comment;
{
	GDBM_FILE db = NULL;
	struct spblk *spl;
	spkey_t symid;
	int i;

	if (sip->file == NULL)
		return NULL;

	symid = symbol_db(sip->file, spt_files->symbols);
	spl = sp_lookup(symid, spt_files);

	if (spl != NULL && flag == O_RDWR && spl->mark != O_RDWR)
		close_gdbm(sip,"open_gdbm");
	if (flag == O_RDWR)	flag = GDBM_WRITER;
	else			flag = GDBM_READER;
	if (spl == NULL || (db = (GDBM_FILE)spl->data) == NULL) {
		for (i = 0; i < 3; ++i) {
		  db = gdbm_open((void*)sip->file, 0, flag, 0, NULL);
		  if (db != NULL)
		    break;
		  sleep(1);
		}
		
		if (db == NULL) {
			++deferit;
			v_set(DEFER, DEFER_IO_ERROR);
			fprintf(stderr, "%s: cannot open %s!\n",
					comment, sip->file);
			return NULL;
		}
		if (spl == NULL)
			sp_install(symid, (void *)db, flag, spt_files);
		else
			spl->data = (void *)db;
	}
	return db;
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

	retry = 0;

reopen:
	db = open_gdbm(sip, O_RDONLY, "search_gdbm");

	if (db == NULL)
	  return NULL;

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

	db = open_gdbm(sip, O_RDWR, "add_gdbm");
	if (db == NULL)
		return EOF;

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

	db = open_gdbm(sip, O_RDWR, "remove_gdbm");
	if (db == NULL)
		return EOF;

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

	db = open_gdbm(sip, O_RDONLY, "print_gdbm");
	if (db == NULL)
		return;

	for (key = gdbm_firstkey(db); key.dptr != NULL; nextkey = gdbm_nextkey(db, key)) {
		val = gdbm_fetch(db, key);
		if (val.dptr == NULL)
			continue;
		if (gdbm_errno)
			break;
		if (val.dptr == NULL || *val.dptr == '\0')
			fprintf(outfp, "%s\n", key.dptr);
		else
			fprintf(outfp, "%s\t%s\n", key.dptr, val.dptr);
		if (val.dptr != NULL)
			free(val.dptr);
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
	GDBM_FILE db;
	datum key, nextkey;
	int count = 0;

	db = open_gdbm(sip, O_RDONLY, "count_gdbm");
	if (db != NULL)
	  for (key = gdbm_firstkey(db); key.dptr != NULL; nextkey = gdbm_nextkey(db, key)) {
	    if (gdbm_errno != 0)
	      break;
	    ++count;
	    key = nextkey;
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

	db = open_gdbm(sip, O_RDONLY, "owner_gdbm");
	if (db == NULL) {
	  fprintf(outfp, "%d\n", nobody);
	  return;
	}

	fno = gdbm_filefno(db);
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

	db = open_gdbm(sip, O_RDONLY, "modp_gdbm");
	if (db == NULL)
		return 0;

	fno = gdbm_filefno(db);
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
