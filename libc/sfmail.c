/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *
 *	SFIO version by Matti Aarnio, copyright 1999
 */

/*LINTLIBRARY*/

#include "hostenv.h"

#include <stdio.h>
#ifndef FILE /* Some systems don't have this as a MACRO.. */
# define FILE FILE
#endif
#include <sfio.h>

#include <errno.h>
#include <sys/param.h>
#include <sys/stat.h>
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#include <sys/file.h>
#include <sys/socket.h>

#include "mail.h"

#include "listutils.h"
#include "libc.h"
#include "libsh.h"

/*
 * Standard routines that may be used by any program to submit mail.
 *
 * This file should be part of the standard C library on your system.
 * 
 * The proper use of these routines is as follows:
 *
 *	...
 *      mail_priority = 0;
 *	Sfio_t *msp = sfmail_open(type);
 *	if (msp != NULL) {
 *	... output the mail message to msp ...
 *	} else
 *		... error handling for not even being able to open the file ...
 *	if (oops)
 *		(void) sfmail_abort(msp);
 *	else if (sfmail_close(msp) == EOF)
 *		... error handling if something went wrong ...
 *	...
 *
 * Note that the return value from these routines corresponds to the
 * return values of sfopen() and sfclose() respectively. The routines
 * are single-threaded due to the need to remember a filename.
 *
 * Note also that the mail_alloc() routine is called instead of malloc()
 * directly, allowing applications that make many calls to these routines
 * during the process lifetime to provide an alternate byte allocator
 * that will not cause them to run out of data space.  Similarly, the
 * mail_host() routine is expected to return a unique host identification.
 *
 * Some simple signal handling is advisable too.
 */


/* array of message file name associated with a file descriptor */
static char **mail_file = NULL;
static int mail_nfiles  = 0;
const char *postoffice;	/* may be extern or local */

/*
  Define sending mail priority.
*/

int mail_priority;

/*
 * Makes a temporary file under the postoffice, based on a file name template.
 * The last '%' character of the file name passed will be overwritten with
 * different suffix characters until the open() succeeds or we have exhausted
 * the search space.  Note: a single process cannot hold more than number-of-
 * suffix-characters message files at once.
 */

Sfio_t *
_sfmail_fopen(filenamep)
	char **filenamep;
{
	const char *suffix, *post;
	char *path, *cp;
	Sfio_t *fp;
	int fd, eno;

	if (postoffice == NULL && (postoffice = getzenv("POSTOFFICE")) == NULL)
	  postoffice = POSTOFFICE;
	path = mail_alloc(strlen(postoffice)+strlen(*filenamep)+2);
	sprintf(path, "%s/%s", postoffice, *filenamep);
	for (cp = *filenamep; *cp != '\0' && *cp != '%'; ++cp)
		continue;
	if (*cp == '%') {
		post = cp + 1;
		cp = (cp - *filenamep) + strlen(postoffice) + 1 + path;
	} else
		post = cp = NULL;
	fp = NULL;
	eno = 0;
	for (suffix = SUFFIXCHARS; *suffix != 0; ++suffix) {
		if (cp == NULL)
			sleep(2);	/* hope something happens meanwhile */
		else if (*suffix != ' ') {
			*cp = *suffix;
			strcpy(cp+1, post);
		} else
			strcpy(cp, post);
		if ((fd = open(path, O_CREAT|O_EXCL|O_RDWR, 0600)) >= 0) {
			fp = sfnew(NULL, NULL, 8192, fd,
				   SF_READ|SF_WRITE|SF_WHOLE);
			if (fp) {
			  mail_free(*filenamep);
			  *filenamep = path;
			}
			return fp;
		}
		eno = errno;
	}
	mail_free(path);
	errno = eno;
	return fp;
}

/*
 * Link from-file to a file given by the to-file template.
 * The last '%' character of the to-file name passed will be overwritten with
 * different suffix characters until the link() succeeds or we have exhausted
 * the search space.
 */

int
sfmail_link(from, tonamep)
	const char *from;
	char **tonamep;
{
	char *path, *cp;
	const char *suffix, *post;
	int eno;

	if (postoffice == NULL && (postoffice = getzenv("POSTOFFICE")) == NULL)
		postoffice = POSTOFFICE;
	path = mail_alloc(strlen(postoffice)+strlen(*tonamep)+2);
	sprintf(path, "%s/%s", postoffice, *tonamep);
	for (cp = *tonamep; *cp != '\0' && *cp != '%'; ++cp)
		continue;
	if (*cp == '%') {
		post = cp + 1;
		cp = (cp - *tonamep) + strlen(postoffice) + 1 + path;
	} else
		post = cp = NULL;
	eno = 0;
	for (suffix = SUFFIXCHARS; *suffix != 0; ++suffix) {
		if (cp == NULL)
			sleep(2); /* hope something happens meanwhile */
		else if (*suffix != ' ') {
			*cp = *suffix;
			strcpy(cp+1, post);
		} else
			strcpy(cp, post);
		if (link(from, path) >= 0) {
			mail_free(*tonamep);
			*tonamep = path;
			return 0;
		}
		eno = errno;
	}
	mail_free(path);
	errno = eno;
	return -1;
}

/*
 * Open a message file of the specified type and initialize generic envelope
 * information (i.e. the file position on return may not be 0).
 */

Sfio_t *
sfmail_open(type)
	const char *type;
{
	char *scratch, *message;
	const char *cp;
	Sfio_t *fp;
	int eno;
	struct stat stbuf;
	char namebuf[BUFSIZ];
	static const char *host = NULL;
	
	/* Create a file, any file, in the PUBLIC directory */

	if (host == NULL)
		host = mail_host();
	cp = (host == NULL) ? "I" : host ;
	scratch = mail_alloc(strlen(PUBLICDIR)+strlen(cp)+3+1+10);

	sprintf(scratch, "%s/%7s:%d%%", PUBLICDIR, cp, (int)getpid());

	fp = _sfmail_fopen(&scratch);
	if (fp == NULL) {
		eno = errno;
		fprintf(stderr, "sfmail_fopen(\"%s\", \"w+\"): errno %d\n",
			scratch, errno);
		mail_free(scratch);
		errno = eno;
		return NULL;
	}

	/* Determine a unique id associated with the file (inode number) */

	if (fstat(sffileno(fp), &stbuf) < 0) {
		eno = errno;
		fprintf(stderr, "fstat(\"%s\"): errno %d\n", scratch, errno);
		mail_free(scratch);
		errno = eno;
		return NULL;
	}

	/* Rename the scratch file to the message file name based on the id */

#ifdef	notype
	message = mail_alloc(strlen(PUBLICDIR)+1+1+10);
	sprintf(message, "%s/%d%%", PUBLICDIR, stbuf.st_ino);
#else
	if (type == NULL)
		type = MSG_RFC822;
	message = mail_alloc(strlen(PUBLICDIR)+strlen(type)+1+1+10);
	sprintf(message, "%s/%d%%%s", PUBLICDIR, (int)stbuf.st_ino, type);
#endif
	if (sfmail_link(scratch, &message) < 0) {
		eno = errno;
		fprintf(stderr, "sfmail_link(\"%s\", \"%s\"): errno %d\n",
				scratch, message, errno);
		mail_free(scratch);
		mail_free(message);
		errno = eno;
		return NULL;
	}
	unlink(scratch);
	mail_free(scratch);

	/* Extend when need! */

	if (sffileno(fp) >= mail_nfiles) {
	  int nfile = sffileno(fp)+1;
	  if (mail_file == NULL) {
	    mail_file = (char**)mail_alloc((u_int)(sizeof(char*) * nfile));
	  } else {
	    mail_file = (char**)mail_realloc((char*)mail_file,
					     (sizeof(char*) * nfile));
	  }
	  while (mail_nfiles < nfile) {
	    mail_file[mail_nfiles] = NULL;
	    ++mail_nfiles;
	  }
	}
	mail_file[sffileno(fp)] = message;

	/* Grab preferences from the environment to initialize the envelope */

#ifndef	notype
	if (type != NULL && *type != '\0')
		sfprintf(fp, "type %s\n", type);
#endif
	cp = getenv("FULLNAME");
	if (cp != NULL)
		sfprintf(fp, "fullname %s\n",
			fullname(cp, namebuf, sizeof namebuf, (char *)NULL));
	cp = getenv("PRETTYLOGIN");
	if (cp != NULL)
		sfprintf(fp, "loginname %s\n", cp);
	/*
	 * If the postoffice lives elsewhere, put our hostname
	 * in the Received-from header, to aid in message tracing.
	 */
	host = whathost(message);
	if (getzenv("MAILSERVER") != NULL ||
	    (host != NULL && strcmp(host,"localhost") != 0))
	  if (getmyhostname(namebuf, sizeof namebuf) == 0) {
	    cp = getenv("LOGNAME");
	    if (cp == NULL)
	      cp = getenv("USERNAME");
	    if (cp == NULL)
	      cp = getenv("USER");
	    if (cp == NULL)
	      cp = "\"??\"";
	    sfprintf(fp, "rcvdfrom STDIN (%s@%s)\n", cp, namebuf);
	  }
	return fp;
}


/*
 * Return currently open spool file name
 */

char *
sfmail_fname(fp)
	Sfio_t *fp;
{
	int fd = sffileno(fp);

	if (fd < 0 || fd >= mail_nfiles)
	  return NULL;

	return mail_file[fd];
}


/*
 * Abort the message file composition on the indicated stream.
 */

int
sfmail_abort(fp)
	Sfio_t *fp;
{
	register char **messagep, *message;
	int r;

	if (fp == NULL) {
		errno = EBADF;
		return -1;
	}
	if (sffileno(fp) >= mail_nfiles)
		abort(); /* Usage error -- no such fileno in our use! */
	messagep = &mail_file[sffileno(fp)];
	if (*messagep == NULL) {
		errno = ENOENT;
		return -1;
	}
	sfclose(fp);
	message = *messagep;
	*messagep = NULL;
	r = unlink(message);
	mail_free(message);
	return r;
}

/*
 * Close the message file on the indicated stream and submit it to the mailer.
 */

int
_sfmail_close_(fp,inop, mtimep)
	Sfio_t *fp;
	int *inop;
	time_t *mtimep;
{
	char **messagep, *message, *nmessage, *msgbase;
	const char *routerdir;
	char *s = NULL;
	struct stat stb;

	if (postoffice == NULL) {
		fprintf(stderr, "sfmail_close: called out of order!\n");
		errno = EINVAL;
		return -1;
	}
	if (fp == NULL) {
		errno = EBADF;
		return -1;
	}
	if (sffileno(fp) >= mail_nfiles)
		abort(); /* Usage error -- no such fileno in our use! */
	messagep = &mail_file[sffileno(fp)];
	if (*messagep == NULL) {
		errno = ENOENT;
		return -1;
	}

	message = *messagep;
	*messagep = NULL;

	/*
	 * *** NFS users beware ***
	 * the fsync() between sfsync() and sfclose() may be mandatory
	 * on NFS mounted postoffices if you want to guarantee not losing
	 * data without being told about it.
	 */

	if (sfsync(fp) != 0
#ifdef HAVE_FSYNC
	    || fsync(sffileno(fp)) < 0
#endif
	    || sfclose(fp) != 0) {
		mail_free(message);
		errno = EIO;
		return -1;
	}


	/* Find the base name (we know format is PUBLICDIR/basename) */
	if ((msgbase = strrchr(message, '/')) == NULL)
		msgbase = message;
	else
		++msgbase;

	routerdir = ROUTERDIR;
	nmessage  = NULL;
	s         = NULL;
	if (mail_priority) {
	  /* We are asked to place the mail somewhere else */
	  char *routerdirs = getzenv("ROUTERDIRS");
	  if (routerdirs) {
	    int i = mail_priority;
	    char *rd = routerdirs;
	    const char *ord = routerdir;
#ifdef HAVE_ALLOCA
	    nmessage = alloca(strlen(postoffice)+
			      strlen(routerdirs)+3+strlen(msgbase));
#else
	    nmessage = mail_alloc(strlen(postoffice)+
				  strlen(routerdirs)+3+strlen(msgbase));
#endif
	    /* There are some defined!   A ":" separated list of strings */

	    /* mail_priority == 1 pics first, 2 pics second, ..
	       if segments run out, last one is kept at  rd     */

	    while (i-- && (s = strchr(rd,':'))) {
	      *s = 0;
	      sprintf(nmessage, "%s/%s", postoffice, rd);
	      *s = ':';
	      if ((stat(nmessage,&stb) < 0) || !S_ISDIR(stb.st_mode)) {
		rd = s+1;
		continue;	/* Not ok -- not a dir, for example */
	      }
	      ord = rd;
	      rd = s+1;
	    }

	    /* Here we are when there is only one entry in the routerdirs: */
	    if (s == NULL && i > 0 && *rd != 0) {
	      if (s) *s = 0;
	      sprintf(nmessage, "%s/%s", postoffice, rd);
	      if (s) *s = ':';
	      /* Is it a valid directory ? */
	      if ((stat(nmessage,&stb) == 0) && S_ISDIR(stb.st_mode))
		ord = rd; /* IT IS ! */
	    }
	    routerdir = ord;
	  }
	}
	/* Assert postoffice != NULL */
	if (nmessage == NULL) {
#ifdef HAVE_ALLOCA
	  nmessage = alloca(strlen(postoffice)+
			    strlen(routerdir)+strlen(msgbase)+2+1);
#else
	  nmessage = mail_alloc(strlen(postoffice)+
				strlen(routerdir)+strlen(msgbase)+2+1);
#endif
	  sprintf(nmessage, "%s/%s/%s", postoffice, routerdir, msgbase);
	} else {
	  s = strchr(routerdir,':');
	  if (s) *s = 0;
	  sprintf(nmessage, "%s/%s/%s", postoffice, routerdir, msgbase);
	  if (s) *s = ':';
	}

	/*
	 * Unfortunately, rename() doesn't guarantee the same inode will
	 * be used if the two paths are on the same filesystem, so we do
	 * it the hard way.
	 */

	if (link(message, nmessage) != 0) {
	  int eno = errno;
	  fprintf(stderr, "link(\"%s\", \"%s\"): errno %d\n",
		  message, nmessage, errno);
	  mail_free(message);
	  mail_free(nmessage);
	  errno = eno;
	  return -1;
	}
#ifndef HAVE_ALLOCA
	mail_free(nmessage);
#endif
	stat(message, &stb);
	unlink(message);
	mail_free(message);

	if (inop != NULL)
	  *inop   = (int)    stb.st_ino;
	if (mtimep != NULL)
	  *mtimep = (time_t) stb.st_mtime;

	return 0;
}

/*
 * Close the message file on the indicated stream, and submit
 * it to alternate directory. (For smtpserver->scheduler messages,
 * for example.)
 */

int
sfmail_close_alternate(fp,where,suffix)
	Sfio_t *fp;
	const char *where, *suffix;
{
	char **messagep, *message, *nmessage, *msgbase;
	int eno;

	if (postoffice == NULL) {
		fprintf(stderr, "sfmail_close_alternate: called out of order!\n");
		errno = EINVAL;
		return -1;
	}
	if (fp == NULL) {
		errno = EBADF;
		return -1;
	}
	if (sffileno(fp) >= mail_nfiles)
		abort(); /* Usage error -- no such fileno in our use! */
	messagep = &mail_file[sffileno(fp)];
	if (*messagep == NULL) {
		errno = ENOENT;
		return -1;
	}

	message = *messagep;
	*messagep = NULL;

	/*
	 * *** NFS users beware ***
	 * the fsync() between sfsync() and sfclose() may be mandatory
	 * on NFS mounted postoffices if you want to guarantee not losing
	 * data without being told about it.
	 */
	if (sfsync(fp) == EOF
#ifdef HAVE_FSYNC
	    || fsync(sffileno(fp)) < 0
#endif
	    || sfclose(fp) == EOF) {
		mail_free(message);
		errno = EIO;
		return -1;
	}


	/* Find the base name (we know format is PUBLICDIR/basename) */
	if ((msgbase = strrchr(message, '/')) == NULL)
		msgbase = message;
	else
		++msgbase;

	nmessage  = NULL;
	/* Assert postoffice != NULL */
	nmessage = mail_alloc(strlen(postoffice)+1+strlen(where)+1+
			      strlen(msgbase)+strlen(suffix)+1);
	sprintf(nmessage, "%s/%s/%s%s", postoffice, where, msgbase, suffix);

	/*
	 * Unfortunately, rename() doesn't guarantee the same inode will
	 * be used if the two paths are on the same filesystem, so we do
	 * it the hard way.
	 */

	if (link(message, nmessage) != 0) {
		eno = errno;
		fprintf(stderr, "link(\"%s\", \"%s\"): errno %d\n",
				message, nmessage, errno);
		mail_free(nmessage);
		unlink(message); /* Throw the file away */
		mail_free(message);
		errno = eno;
		return -2;
	}
	mail_free(nmessage);
	unlink(message);
	mail_free(message);
	return 0;
}


int sfmail_close(fp)
	Sfio_t *fp;
{
	int ino;
	time_t mtime;

	return _sfmail_close_(fp, &ino, &mtime);
}
