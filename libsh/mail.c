/*
 *	Copyright 1989 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * Care and Maintenance of your mail reading habits: implements
 * MAIL, MAILCHECK, and MAILPATH shell variable semantics.
 */

#include <stdio.h>
#include "hostenv.h"
#include <sys/stat.h>
#include "listutils.h"
#include "io.h"		/* redefines stdio routines */
#include "shconfig.h"

#include "libsh.h"

STATIC char   *mailpath   = NULL;	/* cache of MAILPATH variable value */
STATIC time_t *mailmtimes = NULL;
STATIC int     mailintvl  = MAILCHECK_INTERVAL;

/* Given a file name, return time of last modification */

STATIC time_t mail_mtime __((const char *));
STATIC time_t
mail_mtime(file)
	const char *file;
{
	struct stat stbuf;

	if (stat(file, &stbuf) < 0)
		return 0;
	return stbuf.st_mtime;
}

/*
 * Check for mail in any of the files we're supposed to check for mail in.
 * This is typically called before printing out PS1 if we are interactive.
 */

void
mail_check()
{
	const char *msg;
	char *file, *cp, *path;
	int count;
	time_t now, mtime;
	static time_t lastcheck = 0;
	u_int pathlen;

	if (mailpath == NULL)
		return;
	time(&now);
	if (!(mailintvl == 0 || (mailintvl > 0 && lastcheck+mailintvl <= now)))
		return;
	lastcheck = now;
	msg = YOU_HAVE_MAIL;
	count = 0;
	file = mailpath;
	pathlen = strlen(file)+1+1;
#ifdef	USE_ALLOCA
	path = alloca(pathlen);
#else
	path = emalloc(pathlen);
#endif
	while (file != NULL) {
		file = prepath(file, (char *)NULL, path, pathlen);
		cp = strchr(path, MAILPATH_MSG_SEPARATOR);
		if (cp != NULL) {
		  *cp++ = '\0';
		  msg = cp;
		}
		mtime = mail_mtime(path);
		if (mailmtimes[count] < mtime) {
		  mailmtimes[count] = mtime;
		  printf("%s\n", msg);
		}
		++count;
	}
#ifndef	USE_ALLOCA
	free(path);
#endif
}

/*
 * Either the MAIL or MAILPATH variables were just changed, synchronize caches.
 */

void
mail_flush()
{
	register char *file, *cp;
	register conscell *d;
	int count;
	char *path;
	u_int pathlen;

	if (mailmtimes != NULL) {
	  free((char *)mailmtimes);
	  mailmtimes = NULL;
	  mailpath = NULL;
	}
	d = v_find(MAILPATH);
	if (d == NULL || cdr(d) == NULL || LIST(cdr(d))) {
	  d = v_find(MAIL);
	  if (d == NULL || cdr(d) == NULL || LIST(cdr(d)))
	    return;
	}
	mailpath = (char *)cdr(d)->string;
	count = 0;
	file = mailpath;
	pathlen = strlen(file)+1+1;
#ifdef	USE_ALLOCA
	path = alloca(pathlen);
#else
	path = emalloc(pathlen);
#endif
	while (file != NULL) {
	  file = prepath(file, (char *)NULL, path, pathlen);
	  ++count;
	}
	if (count > 0) {
	  mailmtimes = (time_t *)emalloc(count * sizeof (time_t));
	  count = 0;
	  file = mailpath;
	  while (file != NULL) {
	    file = prepath(file, (char *)NULL, path, pathlen);
	    if ((cp = strchr(path, MAILPATH_MSG_SEPARATOR)) != NULL)
	      *cp++ = '\0';
	    mailmtimes[count++] = mail_mtime(path);
	  }
	}
#ifndef	USE_ALLOCA
	free(path);
#endif
}

/*
 * The MAILCHECK variable was just changed, synchronize.
 */

void
mail_intvl()
{
	register char *cp;
	register conscell *d;

	d = v_find(MAILCHECK);
	if (d == NULL || cdr(d) == NULL || LIST(cdr(d))) {
		mailintvl = MAILCHECK_INTERVAL;
		return;
	}
	cp = (char *)cdr(d)->string;
	if ((mailintvl = atoi(cp)) <= 0 && !(*cp == '0' && *(cp+1) == '\0')) {
		fprintf(stderr, "%s: %s: %s\n",
				progname, ILLEGAL_MAILCHECK_VALUE, cp);
		mailintvl = MAILCHECK_INTERVAL;
	}
}
