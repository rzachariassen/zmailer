/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */
/*
 *	Lots of modifications (new guts, more or less..) by
 *	Matti Aarnio <mea@nic.funet.fi>  (copyright) 1992-2002
 */

/* NOTE: This can't co-exist with ndbm! */

/* We close the db after EVERY operation -- every search, every
   add, NOW we can co-exist with anything -- expect perhaps NDBM...  */

/* LINTLIBRARY */

#include "mailer.h"
#ifdef	HAVE_DBM_H

#warning "This really is not recommened anymore, and probably won't work"
#warning "if you can, try to pick something else, like gdbm ..."

#ifdef	NeXT
#define	__STRICT_BSD__
#endif	/* NeXT */
#include <dbm.h>
#ifdef	NeXT
#undef	__STRICT_BSD__
#endif	/* NeXT */
#include "search.h"
#include "io.h"


static int inited = 0;

extern int dbminit();
extern int deferit;
extern int delete();
extern int store();
#ifndef dbmclose
 extern void dbmclose();
#endif


int
open_dbm(sip, comment)
	search_info *sip;
	char *comment;
{
	int i;

	if (sip->file == NULL)
		return -1;
	if (inited == 0) {
		/* Retry it a few times */
		for (i = 0; i < 3; ++i) {
			if (dbminit(sip->file) < 0) {
				sleep(1);
				continue;
			}
			inited = 1;
			return 0;
		}
	}

	/* Didn't succeed to init the DBM database, we signal defer-IO.. */

	++deferit;
	v_set(DEFER, DEFER_IO_ERROR);
	fprintf(stderr, "%s: cannot open %s!\n", comment, sip->file);
	return -1;
}

/*
 * Search a DBM format database for a key pair.
 */

conscell *
search_dbm(sip)
	search_info *sip;
{
	conscell *tmp;
	datum val, key;

	if (open_dbm(sip, "search_dbm") < 0)
		return NULL;
	key.dptr  = sip->key;
	key.dsize = strlen(sip->key) + 1;
	val = fetch(key);
	if (val.dptr == NULL) {
		close_dbm(sip,"search_dbm");
		return NULL;
	}
	tmp = newstring(dupnstr(val.dptr, val.dsize), val.dsize);
	close_dbm(sip,"search_dbm");
	return tmp;
}

/*
 * Flush buffered information from this database, close any file descriptors.
 */

void
close_dbm(sip, comment)
	search_info *sip;
	const char *comment;
{
	if (sip->file == NULL)
		return;
	if (inited == 0)
		return;
#ifdef	HAVE_DBMCLOSE
	dbmclose();
#endif	/* HAVE_DBMCLOSE */
	inited = 0;
}

/*
 * Add the indicated key/value pair to the database.
 */

int
add_dbm(sip, value)
	search_info *sip;
	char *value;
{
	datum val, key;

	if (open_dbm(sip, "add_dbm") < 0)
		return EOF;
	key.dptr  = sip->key;
	key.dsize = strlen(sip->key) + 1;
	val.dptr  = value;
	val.dsize = strlen(value)+1;
	if (store(key, val) < 0) {
		++deferit;
		v_set(DEFER, DEFER_IO_ERROR);
		fprintf(stderr, "add_dbm: cannot store (\"%s\",\"%s\")\n",
				sip->key, value);
		close_dbm(sip, "add_dbm");
		return EOF;
	}
	close_dbm(sip, "add_dbm");
	return 0;
}

/*
 * Remove the indicated key from the database.
 */

int
remove_dbm(sip)
	search_info *sip;
{
	datum key;

	if (open_dbm(sip, "remove_dbm") < 0)
		return EOF;
	key.dptr  = sip->key;
	key.dsize = strlen(sip->key) + 1;
	if (delete(key) < 0) {
		++deferit;
		v_set(DEFER, DEFER_IO_ERROR);
		fprintf(stderr, "remove_dbm: cannot remove \"%s\"\n", sip->key);
		close_dbm(sip, "remove_dbm");
		return EOF;
	}
	close_dbm(sip, "remove_dbm");
	return 0;
}

/*
 * Print the database.
 */

void
print_dbm(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	datum key, val;

	if (open_dbm(sip, "print_dbm") < 0)
		return;
	for (key = firstkey(); key.dptr != NULL; key = nextkey(key)) {
		val = fetch(key);
		if (val.dptr == NULL)
			continue;
		if (*(char*)val.dptr == '\0')
			fprintf(outfp, "%s\n", key.dptr);
		else
			fprintf(outfp, "%s\t%s\n", key.dptr, val.dptr);
	}
	fflush(outfp);
	close_dbm(sip, "print_dbm");
}

/*
 * Count the database.
 */

void
count_dbm(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	datum key, val;
	int count = 0;

	if (open_dbm(sip, "count_dbm") >= 0)
	  for (key = firstkey(); key.dptr != NULL; key = nextkey(key)) {
#if 0
	    val = fetch(key); /* This doesn't make sense.. */
	    if (val.dptr == NULL)
	      continue;
#endif
	    ++count;
	  }
	fprintf(outfp,"%d\n",count);
	fflush(outfp);
	close_dbm(sip, "count_dbm");
}

/*
 * Print the uid of the owner of the database.  Note that for dbm-style
 * databases there are several files involved so picking one of them for
 * security purposes is very dubious.
 */

void
owner_dbm(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	struct stat stbuf;

	if (sip->file == NULL) {
		fprintf(stderr, "owner_dbm: no file specified!\n");
		return;
	}
	if (stat(sip->file, &stbuf) < 0) {
		fprintf(stderr, "owner_dbm: cannot stat \"%s\"!\n", sip->file);
		return;
	}
	fprintf(outfp, "%d\n", stbuf.st_uid);
	fflush(outfp);
}
#endif	/* HAVE_DBM_H */
