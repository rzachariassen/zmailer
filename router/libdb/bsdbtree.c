/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *
 *	Copyright 1996-1999 Matti Aarnio
 */

/* LINTLIBRARY */

#include "mailer.h"
#ifdef	HAVE_DB_H
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#if defined(HAVE_DB_185_H) && !defined(HAVE_DB_OPEN2)
# include <db_185.h>
#else
# include <db.h>
#endif
#include <sys/file.h>
#include "search.h"
#include "io.h"
#include "libz.h"
#include "libc.h"
#include "libsh.h"

extern int errno;
extern int deferit;

#ifndef HAVE_DB_OPEN2
static BTREEINFO BINFO = { 0, 2560, 0, 0, 0, NULL,  NULL, 0 };
#endif

/*
 * Flush buffered information from this database, close any file descriptors.
 */

void
close_btree(sip,comment)
	search_info *sip;
	const char *comment;
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
#if 0
{
  char bb[2000];
  sprintf(bb,"/tmp/-mark2- file='%s' symid=%lx spl=%p db=%p cmt=%s",sip->file,symid,spl, (spl) ? spl->data : NULL, comment );
  unlink(bb);
}
#endif
	if (spl == NULL || (db = (DB *)spl->data) == NULL)
		return;
#ifdef HAVE_DB_OPEN2
	(db->close)(db,0);
#else
	(db->close)(db);
#endif
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
#if 0
{
  char bb[2000];
  sprintf(bb,"/tmp/-mark1- file='%s' symid=%lx spl=%p cmt=%s spl->mark=%lx flag=%x",sip->file,symid,spl,comment,spl?spl->mark:0,flag);
  unlink(bb);
}
#endif
	if (spl != NULL && flag != spl->mark)
		close_btree(sip,"open_btree");
	if (spl == NULL || (db = (DB *)spl->data) == NULL) {
		for (i = 0; i < 3; ++i) {
#ifdef HAVE_DB_OPEN2
		  int err;
		  db = NULL;
		  /*unlink("/tmp/ -mark1- ");*/
		  err = db_open(sip->file, DB_BTREE,
				DB_NOMMAP|((flag == O_RDONLY) ? DB_RDONLY:DB_CREATE),
				0644, NULL, NULL, &db);
		  /*unlink("/tmp/ -mark2- ");*/
#else
		  db = dbopen(sip->file, flag, 0, DB_BTREE, &BINFO);
#endif
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
			spl = sp_install(symid, (void *)db, flag, spt_files);
		spl->data = (void *)db;
		spl->mark = flag;
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
	int retry, rc;

	retry = 0;
#if 0
reopen:
#endif
	db = open_btree(sip, O_RDONLY, "search_btree");
	if (db == NULL)
	  return NULL; /* Huh! */

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	key.data = (void*)sip->key;
	key.size = strlen(sip->key) + 1;

#ifdef HAVE_DB_OPEN2
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

	db = open_btree(sip, O_RDWR, "add_btree");
	if (db == NULL)
		return EOF;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	key.data = (void*)sip->key;
	key.size = strlen(sip->key) + 1;

	val.data = (void*)value;
	val.size = strlen(value)+1;
#ifdef HAVE_DB_OPEN2
	rc = (db->put)(db, NULL, &key, &val, 0);
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

	db = open_btree(sip, O_RDWR, "remove_btree");
	if (db == NULL)
		return EOF;

	memset(&key, 0, sizeof(key));

	key.data = (void*)sip->key;
	key.size = strlen(sip->key) + 1;
#ifdef HAVE_DB_OPEN2
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
#ifdef HAVE_DB_OPEN2
	DBC *curs;

	db = open_btree(sip, O_RDONLY, "print_btree");
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

	db = open_btree(sip, O_RDONLY, "print_btree");
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
count_btree(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	DB *db;
	DBT key, val;
	int cnt = 0;
	int rc;
#ifdef HAVE_DB_OPEN2
	DBC *curs;

	db = open_btree(sip, O_RDONLY, "count_btree");

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
	int fd;

	db = open_btree(sip, O_RDONLY, "owner_btree");
	if (db == NULL)
		return;

	/* There are timing hazards, when the internal fd is not
	   available for probing.. */
#ifdef HAVE_DB_OPEN2
	(db->fd)(db, &fd);
#else
	fd = (db->fd)(db);
#endif
	if (fstat(fd, &stbuf) < 0) {
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
	int rval, fd;

	db = open_btree(sip, O_RDONLY, "owner_btree");
	if (db == NULL)
		return 0;

#ifdef HAVE_DB_OPEN2
	(db->fd)(db, &fd);
#else
	fd = (db->fd)(db);
#endif
	if (fstat(fd, &stbuf) < 0) {
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
			(long)stbuf.st_nlink != 1);
	} else
		rval = 0;
	sp_install(symid, (void *)((long)stbuf.st_mtime),
		   stbuf.st_nlink, spt_modcheck);

	return rval;
}
#endif	/* HAVE_DB */
