/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *
 *	Copyright 1996-1998 Matti Aarnio
 */

/* LINTLIBRARY */

#include "mailer.h"
#ifdef	HAVE_DB_H
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#ifdef HAVE_DB_185_H
# include <db_185.h>	/* This code is in fact for BSD DB 1.85, ... */
#else
# include <db.h>	/* ... NOT for BSD DB 2.* if that is in the system! */
#endif
#include <sys/file.h>
#include "search.h"
#include "io.h"
#include "libz.h"
#include "libc.h"
#include "libsh.h"

extern int errno;
extern int deferit;

static BTREEINFO BINFO = { 0, 2560, 0, 0, 0, NULL,  NULL, 0 };

/*
 * Flush buffered information from this database, close any file descriptors.
 */

void
close_btree(sip)
	search_info *sip;
{
	DB *db;
	struct spblk *spl = NULL;
	spkey_t symid;

	if (sip->file == NULL)
		return;
	symid = symbol_lookup_db(sip->file, spt_files->symbols);
	if ((spkey_t)0 != symid)
	  spl = sp_lookup(symid, spt_modcheck);
	if (spl != NULL)
	  sp_delete(spl, spt_modcheck);
	spl = sp_lookup(symid, spt_files);
	if (spl == NULL || (db = (DB *)spl->data) == NULL)
		return;
	(db->close)(db);
	symbol_free_db(sip->file, spt_files->symbols);
	sp_delete(spl, spt_files);
}


static DB * open_btree __((search_info *, int, const char *));
static DB *
open_btree(sip, flag, comment)
	search_info *sip;
	int flag;
	const char *comment;
{
	DB *db = NULL;
	struct spblk *spl;
	spkey_t symid;
	int i;

	if (sip->file == NULL)
		return NULL;

	symid = symbol_db(sip->file, spt_files->symbols);
	spl = sp_lookup(symid, spt_files);
	if (spl != NULL && flag == O_RDWR && spl->mark != O_RDWR)
		close_btree(sip);
	if (spl == NULL || (db = (DB *)spl->data) == NULL) {
		for (i = 0; i < 3; ++i) {
		  db = dbopen(sip->file, flag, 0, DB_BTREE, &BINFO);
		  if (db != NULL)
		    break;
		  sleep(1); /* Open failed, retry after a moment */
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
 * Search a B-TREE format database for a key pair.
 */

conscell *
search_btree(sip)
	search_info *sip;
{
	DB *db;
	DBT val, key;
	conscell *tmp;
	int retry, rc;
	char *us;

	retry = 0;
reopen:
	db = open_btree(sip, O_RDONLY, "search_btree");
	if (db == NULL)
	  return NULL; /* Huh! */

	key.data = (void*)sip->key;
	key.size = strlen(sip->key) + 1;
	rc = (db->get)(db, &key, &val, 0);
	if (rc != 0) {
		if (!retry && rc < 0) {
			close_btree(sip);
			++retry;
			goto reopen;
		}
		return NULL;
	}
	us = strnsave(val.data, val.size);
	return newstring(us);
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

	db = open_btree(sip, O_RDWR, "add_btree");
	if (db == NULL)
		return EOF;

	key.data = (void*)sip->key;
	key.size = strlen(sip->key) + 1;
	val.data = (void*)value;
	val.size = strlen(value)+1;
	rc = (db->put)(db, &key, &val, 0);
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

	db = open_btree(sip, O_RDWR, "remove_btree");
	if (db == NULL)
		return EOF;

	key.data = (void*)sip->key;
	key.size = strlen(sip->key) + 1;
	rc = (db->del)(db, &key, 0);
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

	db = open_btree(sip, O_RDONLY, "print_btree");
	if (db == NULL)
		return;

	rc = (db->seq)(db, &key, &val, R_FIRST);
	for ( ; rc == 0 ; ) {
		if (val.data == NULL)
			continue;
		if (*(char*)val.data == '\0')
			fprintf(outfp, "%s\n", key.data);
		else
			fprintf(outfp, "%s\t%s\n", key.data, val.data);
		rc = (db->seq)(db, &key, &val, R_NEXT);
	}
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

	db = open_btree(sip, O_RDONLY, "count_btree");
	if (db != NULL) {
	  rc = (db->seq)(db, &key, &val, R_FIRST);
	  while (rc == 0) {
	    if (val.data == NULL) /* ???? When this would happen ? */
	      continue;
	    ++cnt;
	    rc = (db->seq)(db, &key, &val, R_NEXT);
	  }
	}
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

	db = open_btree(sip, O_RDONLY, "owner_btree");
	if (db == NULL)
		return;

	/* There are timing hazards, when the internal fd is not
	   available for probing.. */
	if (fstat((db->fd)(db), &stbuf) < 0) {
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
	struct spblk *spl;
	spkey_t symid;
	int rval;

	db = open_btree(sip, O_RDONLY, "owner_btree");
	if (db == NULL)
		return 0;

	if (fstat((db->fd)(db), &stbuf) < 0) {
		fprintf(stderr, "modp_btree: cannot fstat(\"%s\")!\n",
				sip->file);
		return 0;
	}
	if (stbuf.st_nlink == 0)
		return 1;	/* Unlinked underneath of us! */
	
	symid = symbol_lookup_db(sip->file, spt_files->symbols);
	spl = sp_lookup(symid, spt_modcheck);
	if (spl != NULL) {
		rval = ((long)stbuf.st_mtime != (long)spl->data ||
			(long)stbuf.st_nlink != (long)spl->mark);
	} else
		rval = 0;
	sp_install(symid, (void *)((long)stbuf.st_mtime),
		   stbuf.st_nlink, spt_modcheck);
	return rval;
}
#endif	/* HAVE_DB */
