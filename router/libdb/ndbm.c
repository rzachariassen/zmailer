/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/* LINTLIBRARY */

#include "mailer.h"
#ifdef	HAVE_NDBM_H
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#include <ndbm.h>
#include <sys/file.h>
#include "search.h"
#include "io.h"
#include "libz.h"
#include "libc.h"
#include "libsh.h"

static DBM * open_ndbm __((search_info *, int, const char *));
static DBM *
open_ndbm(sip, flag, comment)
	search_info *sip;
	int flag;
	const char *comment;
{
	DBM *db;
	struct spblk *spl;
	spkey_t symid;
	int i;

	if (sip->file == NULL)		return NULL;

	symid = symbol_db(sip->file, spt_files->symbols);
	spl = sp_lookup(symid, spt_files);
	if (spl != NULL && flag == O_RDWR && spl->mark != O_RDWR)
		close_ndbm(sip,"open_ndbm");
	if (spl == NULL || (db = (DBM *)spl->data) == NULL) {
		for (i = 0; i < 3; ++i) {
		  db = dbm_open(sip->file, flag, 0);
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
 * Search an NDBM format database for a key pair.
 */

conscell *
search_ndbm(sip)
	search_info *sip;
{
	DBM *db;
	datum val, key;
	conscell *tmp;
	int retry;

	retry = 0;

reopen:

	db = open_ndbm(sip, O_RDONLY, "search_ndbm");
	if (db == NULL)
	  return NULL; /* Failed :-( */

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
 * Flush buffered information from this database, close any file descriptors.
 */

void
close_ndbm(sip,comment)
	search_info *sip;
	const char *comment;
{
	DBM *db;
	struct spblk *spl;
	spkey_t symid;

	if (sip->file == NULL)
		return;
	symid = symbol_db(sip->file, spt_files->symbols);
	spl = sp_lookup(symid, spt_modcheck);
	if (spl != NULL)
		sp_delete(spl, spt_modcheck);
	spl = sp_lookup(symid, spt_files);
	if (spl == NULL || (db = (DBM *)spl->data) == NULL)
		return;
	dbm_close(db);
	sp_delete(spl, spt_files);
	symbol_free_db(sip->file, spt_files->symbols);
}

/*
 * Add the indicated key/value pair to the database.
 */

int
add_ndbm(sip, value)
	search_info *sip;
	const char *value;
{
	DBM *db;
	datum val, key;

	db = open_ndbm(sip, O_RDWR, "add_ndbm");
	if (db == NULL)
		return EOF;

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
	DBM *db;
	datum key;

	db = open_ndbm(sip, O_RDWR, "remove_ndbm");
	if (db == NULL)
		return EOF;

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
	DBM *db;
	datum key, val;

	db = open_ndbm(sip, O_RDONLY, "print_ndbm");
	if (db == NULL)
		return;

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
	DBM *db;
	datum key;
	int cnt = 0;

	db = open_ndbm(sip, O_RDONLY, "count_ndbm");
	if (db != NULL)
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
	DBM *db;
	struct stat stbuf;

	db = open_ndbm(sip, O_RDONLY, "owner_ndbm");
	if (db == NULL)
		return;
	/* There are more timing hazards, when the internal fd is not
	   available for probing.. */
	if (fstat(dbm_dirfno(db), &stbuf) < 0) {
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
	DBM *db;
	struct stat stbuf;
	struct spblk *spl;
	spkey_t symid;
	int rval;

	db = open_ndbm(sip, O_RDONLY, "owner_ndbm");
	if (db == NULL)
		return 0;

	if (fstat(dbm_dirfno(db), &stbuf) < 0) {
		fprintf(stderr, "modp_ndbm: cannot fstat(\"%s\")!\n",
			sip->file);
		return 0;
	}
	if (stbuf.st_nlink == 0)
		return 1;	/* Unlinked underneath of us! */

	symid = symbol_db(sip->file, spt_files->symbols);
	spl = sp_lookup(symid, spt_modcheck);
	if (spl != NULL) {
		rval = ((long)stbuf.st_mtime != (long)spl->data ||
			(long)stbuf.st_nlink != (long)spl->mark);
	} else
		rval = 0;
	sp_install(symid, (u_char *)((long)stbuf.st_mtime),
		   stbuf.st_nlink, spt_modcheck);
	return rval;
}
#endif	/* HAVE_NDBM */
