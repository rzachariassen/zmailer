/* Copyright 1993-1997 - Matti Aarnio

   The way the Zmailer uses DBM entries is by using strings with
   their terminating NULL as keys, and as data..  Thus the length
   is strlen(string)+1, not strlen(string) !
 */

/*
 * WARNING: Policy data parsing does use unchecked buffers!
 */

#define NO_Z_IO_H
#include "../lib/linebuffer.c"
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
#if defined(HAVE_DB_185_H) && !defined(HAVE_DB_OPEN2)
# include <db_185.h>
#else
# include <db.h>
#endif
#endif

#define PROG "makedb"

#include <errno.h>
extern int errno;	/* Not all systems declare it in <errno.h>, sigh ... */

extern int optind;
int  store_errors = 0;
char *progname    = NULL;
int   D_alloc     = 0;
int   verbose     = 0;
int   append_mode = 0;
int   lc_key	  = 0;
int   uc_key      = 0;
int   silent      = 0;

/* extern char *strchr(); */

extern void  create_dbase   __((FILE *, void *, int));
extern char *skip821address __((char *));
extern void  usage          __((const char *, const char *, int));

void usage(prog, errs, err)
const char *prog, *errs;
int err;
{
	fprintf(stderr, "Usage: %s [-l|-u]] [-A][-a|-p][-s] dbtype database.name [infilename|-]\n", prog);
	fprintf(stderr, "  where supported dbtypes are:");
#ifdef HAVE_NDBM_H
	fprintf(stderr, " ndbm");
#endif
#ifdef HAVE_GDBM_H
	fprintf(stderr, " gdbm");
#endif
#ifdef HAVE_DB_H
	fprintf(stderr, " btree bhash");
#endif
	fprintf(stderr, "\n");
	fprintf(stderr, " Error now: %s", errs);
	if (err != 0) {
	  fprintf(stderr, ", errno=%d (%s)", err, strerror(err));
	  fprintf(stderr, "\n");
	  exit(1);
	}
	fprintf(stderr, "\n\n  If no infilename is defined, database.name is assumed.\n");
#ifdef HAVE_NDBM_H
	fprintf(stderr, "  (NDBM appends  .pag, and .dir  into actual db file names..)\n");
#endif
#ifdef HAVE_GDBM_H
	fprintf(stderr, "  (GDBM appends .gdbm, to the actual db file name..)\n");
#endif
#ifdef HAVE_DB_H
	fprintf(stderr, "  (BTREE appends .db, to the actual db file name..)\n");
	fprintf(stderr, "  (BHASH appends .pag, and .dir into actual db file names..)\n");
#endif
	fprintf(stderr, "\n");

	fprintf(stderr,
"  The '-a' option is for parsing input that comes in\n\
  'aliases' format:  'key: data,in,long,line,'\n\
                     '  with,indented,extended,lines'\n\
  The '-p' option is for parsing smtpserver policy database.\n\
  The '-A' option APPENDS new data to existing keyed data.\n\
  The '-l' and '-u' will lower-/uppercasify key string before\n\
    storing it into the database.  This does not apply to '-p'.\n\
  The '-s' option orders 'silent running' -- report only errors.\n");

	exit(64);
}


static int store_db __((void *, const int, const int, const int, const void *, const int, const void *, const int));

static int store_db(dbf, typ, overwritemode, linenum, t, tlen, s, slen)
     void *dbf;
     const int typ, linenum;
     const void *s, *t;
     const int slen, tlen;
{
#ifdef HAVE_NDBM_H
	DBM *ndbmfile = dbf;
#endif
#ifdef HAVE_GDBM_H
	GDBM_FILE gdbmfile = dbf;
#endif
#ifdef HAVE_DB_H
	DB *dbfile = dbf;
#endif
	int rc = -2;

	if (verbose)
	  fprintf(stderr, "Storing key='%s' data='%s'\n",
		  (const char*)t, (const char *)s);

#ifdef HAVE_NDBM_H
	if (typ == 1) {
		Ndatum Ndat, Nkey;
		Nkey.dptr = (void*)t;
		Nkey.dsize = tlen;
		Ndat.dptr = (void*)s;
		Ndat.dsize = slen;
		rc = dbm_store(ndbmfile, Nkey, Ndat,
			       overwritemode ? DBM_REPLACE : DBM_INSERT);
	}
#endif
#ifdef HAVE_GDBM_H
	if (typ == 2) {
		Gdatum Gdat, Gkey;
		Gkey.dptr = (void*)t;
		Gkey.dsize = tlen;
		Gdat.dptr = (void*)s;
		Gdat.dsize = slen;
		rc = gdbm_store(gdbmfile, Gkey, Gdat,
				overwritemode ? GDBM_REPLACE : GDBM_INSERT);
	}
#endif
#ifdef HAVE_DB_H
	if (typ == 3 || typ == 4) {
		DBT Bkey, Bdat;
		Bkey.data = (void*)t;
		Bkey.size = tlen;
		Bdat.data = (void*)s;
		Bdat.size = slen;
#ifdef HAVE_DB_OPEN2
		rc = (dbfile->put) (dbfile, NULL, &Bkey, &Bdat,
				    overwritemode ? 0: DB_NOOVERWRITE);
#else
		rc = (dbfile->put) (dbfile, &Bkey, &Bdat,
				    overwritemode ? 0: R_NOOVERWRITE);
#endif
	}
#endif

	if (rc > 0 && append_mode == 0)
	  return rc; /* Duh! Duplicate, and no append_mode :-( */

	if (rc > 0 && overwritemode == 0) {
	  /* we shall try append, at first we have to get the old
	     data, and then append to it... */

	  void *dataptr = NULL;
	  int   datalen = 0;
	  char *newptr = NULL;
	  int   newlen = 0;

#ifdef HAVE_NDBM_H
	  if (typ == 1) {
	    Ndatum Ndat, Nkey;
	    Nkey.dptr = (void*)t;
	    Nkey.dsize = tlen;
	    Ndat = dbm_fetch(ndbmfile, Nkey);
	    dataptr = Ndat.dptr;
	    datalen = Ndat.dsize;
	  }
#endif
#ifdef HAVE_GDBM_H
	  if (typ == 2) {
	    Gdatum Gdat, Gkey;
	    Gkey.dptr = (void*)t;
	    Gkey.dsize = tlen;
	    Gdat = gdbm_fetch(gdbmfile, Gkey);
	    dataptr = Gdat.dptr; /* Must free() this */
	    datalen = Gdat.dsize;
	  }
#endif
#ifdef HAVE_DB_H
	  if (typ == 3 || typ == 4) {
	    DBT Bkey, Bdat;
	    Bkey.data = (void*)t;
	    Bkey.size = tlen;
#ifdef HAVE_DB_OPEN2
	    rc = (dbfile->get) (dbfile, NULL, &Bkey, &Bdat, 0);
#else
	    rc = (dbfile->get) (dbfile, &Bkey, &Bdat, 0);
#endif
	    if (rc != 0)
	      memset(&Bdat, 0, sizeof(Bdat));
	    dataptr = Bdat.data;
	    datalen = Bdat.size;
	  }
#endif

	  /* Ok, now we have  dataptr  and  datalen -- we should have
	     non-NULL dataptr.  We need to build a new block with
	     combined data */

	  if (dataptr == NULL)
	    return -1; /* Duh !? */

	  newlen = datalen + slen;
	  newptr = emalloc(newlen + 4);

	  if (append_mode > 0) { /* Ordinary alias append */
	    --datalen;
	    memcpy(newptr, dataptr, datalen);
	    memcpy(newptr + datalen, ",\n\t", 3);
	    memcpy(newptr + datalen + 3, s, slen);
	    newlen = datalen + slen + 3;
	  } else { /* append_mode < 0; PolicyDataset append; binary stuff */
	    memcpy(newptr, dataptr, datalen);
	    memcpy(newptr + datalen, s, slen);
	  }
	  if (typ == 2)
	    free(dataptr); /* GDBM fetched datablock must be freed */

	  rc = store_db(dbf, typ, 1, linenum, t, tlen, newptr, newlen);

	  free(newptr);    /* Our temporary datablock must be freed */
	  return rc;
	}

	if (rc < 0)
		store_errors = 1;
	return rc;
}

extern int parsepolicykey __((void *, char *));
extern int parseattributepair __((void *, char *, char *));


/* Scan over quoted string with embedded white spaces, or
   in case the object does not start with a double quote,
   just all non-white-space chars.   */


static char *tokskip __((char *, char **));
static char *
tokskip(s, sout)
char *s;
char **sout;
{
	char *start;

	while (*s == ' ' || *s == '\t')
	  ++s;
	*sout = s;

	if (*s == '\0')
	  return NULL;

	if (*s == '"') {
	  ++s;
	  start = s;
	  /* Scan thru the quoted string:
	      "message text right here"  */
	  while (*s != '\0') {
	    if (*s == '"') {
	      /* Ending double-quote */
	      *s = '\0';
	      ++s;
	      break;
	    }
	    ++s;
	  }
	} else {
	  start = s;
	  /* Scan over non-white-space chars */
	  while (*s != '\0' && *s != ' ' && *s != '\t')
	    ++s;
	  if (*s != '\0')
	    *(s++) = '\0';
	}
	*sout = s;
	return start;
}

int create_policy_dbase(infile, dbf, typ)
FILE *infile;
void *dbf;
const int typ;
{
	char policykeybuf[256];	/* Plenty enough ? */
	char policydata[16*1024];
	char *s, *t, *str1, *str2;
	int rc, tlen, slen, llen;
	int errflag = 0;

	int policydatalen = 0;
	int linenum = 0;

	/* Turn the append_mode into negative value -- this tells
	   store_db() to work differently from alias append */
	append_mode = -append_mode;

	while ((llen = getline(infile)) != 0) {
		++linenum;
		policydatalen = 0;
		if (linebuf[llen-1] != '\n') {
			/* Eh ? No line ending newline ?
			   Ah well, there is always at least one byte
			   of space after the read block. */
			++llen;
			fprintf(stderr, "input line of len %d lacking trailing newline, corrupted file ?\n", llen-1);
			errflag = 1;
		}
		linebuf[llen-1] = '\0';

		if (*linebuf == '#')
			continue;	/* Comment! */

		if (*linebuf == ' ' || *linebuf == '\t')
			continue;	/* Starts with a white-space! */

		/* Scan first white-space separated token,
		   point its start with t! */

		t = linebuf;
		while (*t == '\t' || *t == ' ')
			++t;

		if (*t == 0)
			continue;		/* Blank line! */
		if (*t == '#')
			continue;		/* Comment.. */
	
		s = t;
		/* scan over first word */
		while (*s && *s != '\t' && *s != ' ')
			++s;
		/* Stopped without line-end NIL ?  Trunc, and advance! */
		if (*s)
			*s++ = 0;

		strlower(t); /* Lowercasify the key */

		rc = parsepolicykey((void *) policykeybuf, t);
		if (rc != 0) {
			/* XX: rc != 0  ==> error */
			fprintf(stderr,
				"Error: line %d: bad policykey, rc = %d\n",
				linenum, rc);
			errflag = 1;
			continue;
		}
		/* Skip LWSP */
		/*      while (*s == ' ' || *s == '\t') ++s;
		 */


		/* Collect attribute pairs */
		str1 = tokskip(s, &s);
		if (str1 == NULL) {
			fprintf(stderr,
				"Error: No attribute pair on line %d.\n",
				linenum);
			errflag = 1;
			continue;
		} else {
			int err = 0;
			while (1) {
				str2 = tokskip(s, &s);
				if (str2 == NULL) {
					fprintf(stderr,
						"Error: Invalid attribute pair on line %d; aname='%s', value missing.\n",
						linenum, str1);
					errflag = 1;
					err = 1;
					break;
				}
				rc = parseattributepair((void *) &policydata[policydatalen],
							str1, str2);
				if (rc != 0) {
					fprintf(stderr,
						"Error: Invalid attribute pair (\"%s %s\")  on line %d.\n",
						str1, str2, linenum);
					errflag = 1;
					err = 1;
					break;
				}
				policydatalen += policydata[policydatalen] & 0xFF;

				str1 = tokskip(s, &s);
				if (str1 == NULL)
					break;
			}
			if (err)
				continue;
		}

		t = (void *) &policykeybuf[0];
		tlen = (policykeybuf[0] & 0xFF);

		s = (void *) &policydata[0];
		slen = policydatalen;

		rc = store_db(dbf, typ, 0, linenum,
			      t, tlen, s, slen);
		if (rc > 0) {
			int tl = tlen;
			fprintf(stderr, "WARNING: Duplicate key at line %d: \"",
				linenum);
			for (;tl > 0; --tl,++t) {
				unsigned char c = *t;
				if (c < ' ' || c > 126 || c == '\\')
					fprintf(stderr, "\\%03o", c);
				else
					fprintf(stderr, "%c", c);
			}
			fprintf(stderr, "\"\n");
		}
	}
	return errflag;
}
    

char *
skipaliastoken(s)
  char *s;
{
  char quote = 0;
  char c;
  while ((c = *s)) {
    if (c == '\\') {
      ++s;
      if (*s == 0)
	break;
    }
    if (c == quote) /* 'c' is non-zero here */
      quote = 0;
    else if (c == '"')
      quote = '"';
    else if (!quote && (c == ' ' || c == '\t' || c == ':'))
      break;
    ++s;
  }

  /* Scan possible white space in between alias token,
     and the colon after it; Zero it while doing this */
  while (*s == '\t' || *s == ' ') {
    *s++ = '\0';
  }

  /* Must have colon, if we have it, we zero it, and return
     pointer to after it. */
  if (*s == ':') {
    *s++ = '\0';
    return s;
  }

  /* Didn't have colon, error! */
  return NULL;
}


int create_aliases_dbase(infile, dbf, typ)
FILE *infile;
void *dbf;
const int typ;
{
	int tlen, slen, llen;
	char *s, *t;
	char *t0 = NULL, *s0 = NULL;
	int  linenum = 0;
	int  errflag = 0;
	int  longest = 0;
	int  count   = 0;
	long totsize = 0;

	while ((llen = getline(infile)) != 0) {
		++linenum;
		if (linebuf[llen-1] != '\n') {
			/* Eh ? No line ending newline ?
			   Ah well, there is always at least one byte
			   of space after the read block. */
			++llen;
			fprintf(stderr, "input line lacking trailing newline, corrupted file ?\n");
			fprintf(stderr, " len=%d, linebuf='%s'\n", llen, linebuf);
		}
		linebuf[llen-1] = '\0';

		if (verbose)
		  fprintf(stderr,"aliases parser: getline() llen=%d, str='%.*s'\n",
			  llen, llen, linebuf);

		if (*linebuf == '#') {
			/* Comment! */
		store_and_continue:
			if (t0 != NULL) {
				tlen = strlen(t0) + 1;
				slen = strlen(s0) + 1;

				++count;
				totsize += slen;
				if (longest < slen)
				  longest = slen;

				if (uc_key)
				  strupper(t0); /* Uppercasify the key */
				if (lc_key)
				  strlower(t0); /* Lowercasify the key */

				if (store_db(dbf, typ, 0, linenum,
					     t0, tlen, s0, slen) < 0)
					break;
				if (t0) free(t0);  t0 = NULL;
				if (s0) free(s0);  s0 = NULL;
			}
			continue;
		}

		t = linebuf;
		/* Key starts at line start, continuation lines start
		   with white-space */

		if (*t == 0)
			goto store_and_continue;	/* Blank line! */

		if (t0 != NULL && (*t == '\t' || *t == ' ')) {
			/* Continuation line */
			while (*t == '\t' || *t == ' ') ++t;
			slen = strlen(s0);
			tlen = strlen(t);
			for (llen = slen; llen > 0; --llen) {
			  /* Chop trailing white-space, if any */
			  if (s0[llen-1] == ' ' || s0[llen-1] == '\t') {
			    s0[llen-1] = '\0';
			  } else
			    break;
			}
			slen = llen; /* Shortened, possibly.. */
			if (s0[llen-1] != ',') {
			  fprintf(stderr, "Line %d: Continuation line on alias without preceeding line ending with comma (',')\n", linenum);
			  errflag = 1;
			  continue;
			}
			s0   = erealloc(s0, slen + tlen + 1);
			memcpy(s0 + slen, t, tlen + 1); /* end NIL included */
			continue;
		}
		if (*t == '\t' || *t == ' ') {
			/* Continuation line without previous key line */
			fprintf(stderr,"Line %d: Continuation line without initial keying line\n", linenum);
			errflag = 1;
			continue;
		}

		/* Ok, we MAY have proper line here.
		   If we now have saved t0/s0, we store them here */
		if (t0 != NULL) {
			tlen = strlen(t0) + 1;
			slen = strlen(s0) + 1;

			++count;
			totsize += slen;
			if (longest < slen)
			  longest = slen;

			if (uc_key)
			  strupper(t0); /* Uppercasify the key */
			if (lc_key)
			  strlower(t0); /* Lowercasify the key */

			if (store_db(dbf, typ, 0, linenum,
				     t0, tlen, s0, slen) < 0)
				break;
			if (t0) free(t0);  t0 = NULL;
			if (s0) free(s0);  s0 = NULL;
		}

		s = skipaliastoken(t);

		/* We [s] are now at the white-space -- possibly the last
		   char of the line prefix is a double-colon (:) */

		if (s == NULL) {
			/* This alias-token is invalid */
			fprintf(stderr,"Line %d: Invalid alias key token; missing colon ?\n",
				linenum);
			errflag = 1;
			continue;
		}

		/* Scan forward for additional data start */

		while (*s && (*s == '\t' || *s == ' '))
			++s;
	    
		t0 = strdup(t);
		strlower(t0); /* Lowercasify the key */
		s0 = strdup(s);
		/* Now we continue reading more input lines ... */
	}
	/* Something left to be stored ? */
	if (t0 != NULL) {
		tlen = strlen(t0) + 1;
		slen = strlen(s0) + 1;

		++count;
		totsize += slen;
		if (longest < slen)
		  longest = slen;

		if (uc_key)
		  strupper(t0); /* Uppercasify the key */
		if (lc_key)
		  strlower(t0); /* Lowercasify the key */

		(void) store_db(dbf, typ, 0, linenum,
				t0, tlen, s0, slen);
		if (t0) free(t0);  t0 = NULL;
		if (s0) free(s0);  s0 = NULL;
	}
	if (!silent)
	  fprintf(stdout, "%d aliases, longest %d bytes, %ld bytes total\n",
		  count, longest, totsize);
	return errflag;
}

int create_keyed_dbase(infile, dbf, typ)
FILE *infile;
void *dbf;
const int typ;
{
	int tlen, slen, llen;
	char *s, *t;
	int linenum = 0;
	int errflag = 0;

	while ((llen = getline(infile)) != 0) {
		++linenum;
		if (linebuf[llen-1] != '\n') {
			/* Eh ? No line ending newline ?
			   Ah well, there is always at least one byte
			   of space after the read block. */
			++llen;
			fprintf(stderr, "input file lacking trailing newline, corrupted file ?\n");
		}
		linebuf[llen-1] = '\0';

		if (*linebuf == '#')
			continue;	/* Comment! */

		/* Scan first white-space separated token,
		   point its start with t! */

		t = linebuf;
		while (*t == '\t' || *t == ' ')
			++t;

		if (*t == 0)
			continue;		/* Blank line! */
		if (*t == '#')
			continue;		/* Comment.. */


		s = t;
		/* Scan over the non-LWSP text */
		while (*s && *s != '\t' && *s != ' ')
			++s;
		/* Stopped without line-end NIL ?  Trunc, and advance! */
		if (*s)
			*s++ = 0;

		/* Scan forward, if we have some LWSP here, and then more data ? */
		while (*s && (*s == '\t' || *s == ' '))
			++s;
	    
		if (uc_key)
		  strupper(t); /* Uppercasify the key */
		if (lc_key)
		  strlower(t); /* Lowercasify the key */
	    
		tlen = strlen(t) + 1;
		slen = strlen(s) + 1;
		if (store_db(dbf, typ, 0, linenum,
			     t, tlen, s, slen) < 0) {
		  errflag = 1; /* Duplicate ?? */
		  break;
		}
	}
	return errflag;
}


int main(argc, argv)
int argc;
char *argv[];
{
    char *dbasename = NULL;
    FILE *infile = NULL;
    int c, rc;
    int typ = 0;
#ifdef HAVE_NDBM_H
    DBM *ndbmfile = NULL;
#endif
#ifdef HAVE_GDBM_H
    GDBM_FILE gdbmfile = NULL;
#endif
#ifdef HAVE_DB_H
    DB *dbfile = NULL;
#endif
    char *dbtype = NULL;
    void *dbf = NULL;
    char *argv0 = argv[0];

    int aliasinput = 0;
    int policyinput = 0;

    progname = argv[0];

    while ((c = getopt(argc, argv, "Aalpsuv")) != EOF) {
	switch (c) {
	case 'l':
	    lc_key = 1;
	    break;
	case 'u':
	    uc_key = 1;
	    break;
	case 'A':
	    append_mode = 1;
	    break;
	case 'a':
	    aliasinput = 1;
	    break;
	case 'p':
	    policyinput = 1;
	    break;
	case 's':
	    silent = 1;
	    break;
	case 'v':
	    verbose = 1;
	    break;
	default:
	    break;
	}
    }

    /* Usage: */
    /*  makedb [-Aap] dbtype database.name [infilename|-] */
    /* argv[] 0    1      2           3          4           */

    /* printf("optind = %d, argc = %d\n", optind, argc); */

    if ((argc - optind) < 2)
	usage(argv0, "too few arguments", 0);
    if ((argc - optind) > 3)
	usage(argv0, "too many arguments", 0);
    dbasename = argv[optind + 1];


    if ((argc - optind) == 3) {
	if (strcmp(argv[optind + 2], "-") == 0)
	    infile = stdin;
	else
	    infile = (FILE *) fopen(argv[optind + 2], "r");
    } else
	infile = stdin;
    dbtype = argv[optind];

    if (infile == NULL)
	usage(argv0, "bad infile", errno);

    typ = 0;
#ifdef HAVE_NDBM_H
    if (cistrcmp(dbtype, "ndbm") == 0)
	typ = 1;
    else
#endif
#ifdef HAVE_GDBM_H
    if (cistrcmp(dbtype, "gdbm") == 0)
	typ = 2;
    else
#endif
#ifdef HAVE_DB_H
    if (cistrcmp(dbtype, "btree") == 0)
	typ = 3;
    if (cistrcmp(dbtype, "bhash") == 0)
	typ = 4;
#endif
    if (typ == 0)
	usage(argv0, "unknown dbtype", 0);

#ifdef HAVE_NDBM_H
    if (typ == 1) {
	ndbmfile = dbm_open(dbasename, O_RDWR | O_CREAT | O_TRUNC, 0644);
	dbf = ndbmfile;
    }
#endif
#ifdef HAVE_GDBM_H
    if (typ == 2) {
	/* Play loose .. don't do syncs while writing */
	dbasename = strcpy(malloc(strlen(dbasename) + 8), dbasename);
	strcat(dbasename, ".gdbm");	/* ALWAYS append this */
	gdbmfile = gdbm_open(dbasename, 0, GDBM_NEWDB | GDBM_FAST, 0644, NULL);
	dbf = gdbmfile;
    }
#endif
#ifdef HAVE_DB_H
#ifdef HAVE_DB_OPEN2
    if (typ == 3) {
	dbasename = strcpy(malloc(strlen(dbasename) + 8), dbasename);
	strcat(dbasename, ".db");	/* ALWAYS append this */
	dbfile = NULL;
	db_open(dbasename, DB_BTREE,  DB_CREATE|DB_TRUNCATE,
		0644, NULL, NULL, &dbfile);
	dbf = dbfile;
    }
    if (typ == 4) {
	dbfile = NULL;
	db_open(dbasename, DB_HASH,  DB_CREATE|DB_TRUNCATE,
		0644, NULL, NULL, &dbfile);
	dbf = dbfile;
    }
#else
    if (typ == 3) {
	dbasename = strcpy(malloc(strlen(dbasename) + 8), dbasename);
	strcat(dbasename, ".db");	/* ALWAYS append this */
	dbfile = dbopen(dbasename, O_RDWR | O_CREAT | O_TRUNC, 0644,
			DB_BTREE, NULL);
	dbf = dbfile;
    }
    if (typ == 4) {
	dbfile = dbopen(dbasename, O_RDWR | O_CREAT | O_TRUNC, 0644,
			DB_HASH, NULL);
	dbf = dbfile;
    }
#endif
#endif
    if (dbf == NULL)
	usage(argv0, "Can't open dbase file", errno);

    initline(BUFSIZ);

    if (policyinput)
	    rc = create_policy_dbase(infile, dbf, typ);
    else if (aliasinput)
	    rc = create_aliases_dbase(infile, dbf, typ);
    else
	    rc = create_keyed_dbase(infile, dbf, typ);

#ifdef HAVE_NDBM_H
    if (typ == 1)
	dbm_close(ndbmfile);
#endif
#ifdef HAVE_GDBM_H
    if (typ == 2)
	gdbm_close(gdbmfile);
#endif
#ifdef HAVE_DB_H
    if (typ == 3 || typ == 4) {
	(dbfile->sync) (dbfile, 0);
#ifdef HAVE_DB_OPEN2
	(dbfile->close) (dbfile, 0);
#else
	(dbfile->close) (dbfile);
#endif
    }
#endif

    return (rc ? 1 : 0);
}
