/* Copyright 1993 - Matti Aarnio, Turku University, Turku, Finland
   This will be free software, but only when it is finished.

   The way the Zmailer uses DBM entries is by using strings with
   their terminating NULL as keys, and as data..  Thus the length
   is strlen(string)+1, not strlen(string) !
*/

#include "hostenv.h"
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <fcntl.h>
#ifdef HAVE_NDBM_H
#define datum Ndatum
#include <ndbm.h>
#undef datum
#endif
#ifdef HAVE_GDBM_H
#define datum Gdatum
#include <gdbm.h>
#undef datum
#endif
#ifdef HAVE_DB_H
#include <db.h>
#endif

#include <errno.h>
extern int errno;

extern void usage __((const char *, const char *, int));
void
usage(av0,err,errn)
const char *av0, *err;
int errn;
{
  fprintf(stderr,"Usage: %s [-dump] dbtype database.name [key]\n",av0);
  fprintf(stderr,"  Dbtypes are:");
#ifdef HAVE_NDBM_H
  fprintf(stderr," ndbm");
#endif
#ifdef HAVE_GDBM_H
  fprintf(stderr," gdbm");
#endif
#ifdef HAVE_DB_H
  fprintf(stderr," btree bhash");
#endif
  fprintf(stderr,"\n");
#ifdef HAVE_NDBM_H
  fprintf(stderr,"  (NDBM appends  .pag, and .dir  into the actual db file names..)\n");
#endif
#ifdef HAVE_GDBM_H
  fprintf(stderr,"  (GDBM  DOES NOT append .gdbm  into the actual db file name..)\n");
#endif
#ifdef HAVE_DB_H
  fprintf(stderr,"  (BTREE DOES NOT append  .db   into the actual db file name..)\n");
  fprintf(stderr,"  (BHASH appends .pag, and .dir into actual db file names..)\n");
#endif
  fprintf(stderr," Error now: %s", err);
  fprintf(stderr,", errno=%d (%s)", errn, strerror(errn));
  fprintf(stderr,"\n");
  exit (1);
}

static int imax(a,b)
     int a, b;
{
  if (a > b)
    return a;
  return b;
}


void dumpit(fp, keyptr, keylen, datptr, datlen)
     FILE *fp;
     void *keyptr, *datptr;
     int keylen, datlen;
{
  if (((char*)keyptr)[imax(0, keylen - 1)] == 0)
    fwrite(keyptr, 1, imax(0, keylen - 1), fp);
  else
    fwrite(keyptr, 1, keylen, fp);
  if (datptr != NULL) {
    putc('\t',fp);
    if (((char*)datptr)[imax(0, datlen - 1)] == 0)
      fwrite(datptr, 1, imax(0, datlen - 1), fp);
    else
      fwrite(datptr, 1, datlen, fp);
  }
  putc('\n',fp);
}

int
main(argc,argv)
int argc;
char *argv[];
{
  char *dbasename = NULL;
  char *argv0 = argv[0];
  int dumpflag = 0;

  if (argc != 4) usage(argv0,"wrong number of arguments",0);

  if (strcmp(argv[1],"-dump") == 0) {
    dumpflag = 1;
    ++argv;
  }

  dbasename = argv[2];
#ifdef HAVE_NDBM_H
  if (strcmp(argv[1],"ndbm")==0) {
    DBM *Ndbmfile;
    Ndatum key;
    Ndatum result;
    Ndbmfile = dbm_open(dbasename, O_RDONLY, 0644);

    if (!Ndbmfile) {
      fprintf(stderr,"Failed to open '%s' NDBM-dbase\n",dbasename);
      return 1;
    }

    if (dumpflag) {
      key = dbm_firstkey(Ndbmfile);
      while (key.dptr != NULL) {
	result = dbm_fetch(Ndbmfile, key);
	dumpit(stdout, key.dptr, key.dsize, result.dptr, result.dsize);
	key = dbm_nextkey(Ndbmfile);
      }
    } else {
      key.dptr = argv[3];
      key.dsize = strlen(argv[3]) +1;

      result = dbm_fetch(Ndbmfile,key);

      if (result.dptr == NULL) {
	fprintf(stderr,"Key %s not found\n",argv[3]);
	return 2;
      }
      printf("siz:%d, dat: %s\n", result.dsize, result.dptr);
    }

    dbm_close(Ndbmfile);

    return 0;
  }
#endif /* NDBM */
#ifdef HAVE_GDBM_H
  if (strcmp(argv[1],"gdbm")==0) {
    GDBM_FILE gdbmfile;
    Gdatum key;
    Gdatum result;
    gdbmfile = gdbm_open(dbasename, 0, GDBM_READER, 0644, NULL);

    if (!gdbmfile) {
      fprintf(stderr,"Failed to open '%s' GDBM-dbase\n",dbasename);
      return 1;
    }

    if (dumpflag) {
      key = gdbm_firstkey(gdbmfile);
      while (key.dptr != NULL) {
	result = gdbm_fetch(gdbmfile, key);
	dumpit(stdout, key.dptr, key.dsize, result.dptr, result.dsize);
	key = gdbm_nextkey(gdbmfile, key);
      }
    } else {
      key.dptr = argv[3];
      key.dsize = strlen(argv[3]) +1;

      result = gdbm_fetch(gdbmfile,key);

      if (result.dptr == NULL) {
	fprintf(stderr,"Key %s not found\n",argv[3]);
	return 2;
      }
      printf("siz:%d, dat: %s\n",result.dsize,result.dptr);
    }

    gdbm_close(gdbmfile);

    return 0;
  }
#endif /* GDBM */
#ifdef HAVE_DB_H
  if (strcmp(argv[1],"btree")==0) {
    DB *dbfile;
    DBT key;
    DBT result;
    int rc;

    dbfile = dbopen(dbasename, O_RDONLY, 0644, DB_BTREE, NULL);

    if (!dbfile) {
      fprintf(stderr,"Failed to open '%s' BTREE-dbase\n",dbasename);
      return 1;
    }

    if (dumpflag) {
      rc = (dbfile->seq)(dbfile, &key, &result, R_FIRST);
      while ( rc == 0 ) {
	dumpit(stdout, key.data, key.size, result.data, result.size);
	rc = (dbfile->seq)(dbfile, &key, &result, R_NEXT);
      }
    } else {
      key.data = argv[3];
      key.size = strlen(argv[3]) +1;

      rc = (dbfile->get)(dbfile,&key,&result,0);

      if (rc != 0) {
	fprintf(stderr,"Key %s not found\n",argv[3]);
	return 2;
      }
      printf("siz:%d, dat: %s\n",result.size,(char*)result.data);
    }

    (dbfile->close)(dbfile);

    return 0;
  }

  if (strcmp(argv[1],"bhash")==0) {
    DB *dbfile;
    DBT key;
    DBT result;
    int rc;

    dbfile = dbopen(dbasename, O_RDONLY, 0644, DB_HASH, NULL);

    if (!dbfile) {
      fprintf(stderr,"Failed to open '%s' BHASH-dbase\n",dbasename);
      return 1;
    }

    if (dumpflag) {
      rc = (dbfile->seq)(dbfile, &key, &result, R_FIRST);
      while ( rc == 0 ) {
	dumpit(stdout, key.data, key.size, result.data, result.size);
	rc = (dbfile->seq)(dbfile, &key, &result, R_NEXT);
      }
    } else {
      key.data = argv[3];
      key.size = strlen(argv[3]) +1;

      rc = (dbfile->get)(dbfile,&key,&result,0);

      if (rc != 0) {
	fprintf(stderr,"Key %s not found\n",argv[3]);
	return 2;
      }
      printf("siz:%d, dat: %s\n",result.size,(char*)result.data);
    }

    (dbfile->close)(dbfile);

    return 0;
  }
#endif

  usage(argv0, "Unrecognized dbformat", 0);

  return 0;
}

