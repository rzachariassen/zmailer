/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */
/*
 *	Some modifications  by
 *	Matti Aarnio <mea@nic.funet.fi>  (copyright) 1992-2000
 */

/*LINTLIBRARY*/

#include "hostenv.h"
#include <stdio.h>
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
 *	FILE *mfp = mail_open(type);
 *	if (mfp != NULL) {
 *	... output the mail message to mfp ...
 *	} else
 *		... error handling for not even being able to open the file ...
 *	if (oops)
 *		(void) mail_abort(mfp);
 *	else if (mail_close(mfp) == EOF)
 *		... error handling if something went wrong ...
 *	...
 *
 * Note that the return value from these routines corresponds to the
 * return values of fopen() and fclose() respectively. The routines
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
static char **mail_type = NULL;
static int mail_nfiles  = 0;
const char *postoffice;	/* may be extern or local */

#define USE_RENAME
#define USE_RENAME1

static int eqrename __((const char *, const char *));
static int
eqrename(from, to)
	const char *from, *to;
{
#ifdef	HAVE_RENAME
	while (rename(from, to) < 0) {
	  int serrno = errno;
	  if (errno == EBUSY || errno == EINTR) {
	    /* Solaris says EBUSY, we clean up.. */
	    while (unlink(to) < 0) {
	      if (errno == EBUSY || errno == EINTR)
		continue; /* Crazy Solaris 2.x (including 2.6!) */
	      /* Actually Solaris reports only EBUSY, but .. */
	      break;
	    }
	    /* Solaris says EBUSY, we retry.. */
	    continue;
	  }
	  errno = serrno;
	  return -1;
	}

#else	/* !HAVE_RENAME */
	
	if ((unlink(to) < 0 && errno != ENOENT) || (link(from, to) < 0)) {
	  return -1;
	}

	if (unlink(from) < 0) {
	  int serrno = errno;
	  unlink(to);
	  errno = serrno;
	  return -1;
	}
#endif	/* !HAVE_RENAME */

	return 0;
}



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

FILE *
_mail_fopen(filenamep)
	char **filenamep;
{
	const char *suffix, *post;
	char *path, *cp;
	FILE *fp;
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
			fcntl(fd, F_SETFD,
			      fcntl(fd, F_GETFD, 0) | FD_CLOEXEC);
			fp = fdopen(fd, "w+");
			if (fp) {
			  setvbuf(fp, NULL, _IOFBF, 8192);
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
mail_link(from, tonamep)
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
		if (eqrename(from, path) >= 0) {
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

FILE *
mail_open(type)
	const char *type;
{
	char *scratch;
#ifndef USE_RENAME
	char *message;
#endif
	const char *cp;
	FILE *fp;
	int eno, fn;
	struct stat stbuf;
	char namebuf[BUFSIZ];
	static const char *host = NULL;
	
	/* Create a file, any file, in the PUBLIC directory */

	if (host == NULL)
		host = mail_host();
	cp = (host == NULL) ? "I" : host ;
	scratch = mail_alloc(strlen(PUBLICDIR)+strlen(cp)+3+1+10);

	sprintf(scratch, "%s/%7s:%d%%", PUBLICDIR, cp, (int)getpid());

	fp = _mail_fopen(&scratch);
	if (fp == NULL) {
		eno = errno;
		fprintf(stderr, "mail_fopen(\"%s\", \"w+\"): errno %d\n",
			scratch, errno);
		mail_free(scratch);
		errno = eno;
		return NULL;
	}

	/* Determine a unique id associated with the file (inode number) */

	fn = FILENO(fp);
	if (fstat(fn, &stbuf) < 0) {
		eno = errno;
		fprintf(stderr, "fstat(\"%s\"): errno %d\n", scratch, errno);
		mail_free(scratch);
		errno = eno;
		return NULL;
	}

	/* Rename the scratch file to the message file name based on the id */

	if (type == NULL)
		type = MSG_RFC822;

#ifdef notype
	type = "";
#endif

#ifndef USE_RENAME1
	/* Yes, do multi-phase linking around and file name changes.
	   Alternate is to do single rename at the closing.. */

	message = mail_alloc(strlen(PUBLICDIR)+strlen(type)+1+1+10);
	sprintf(message, "%s/%d%%%s", PUBLICDIR, (int)stbuf.st_ino, type);

	if (mail_link(scratch, &message) < 0) {
		eno = errno;
		fprintf(stderr, "mail_link(\"%s\", \"%s\"): errno %d\n",
				scratch, message, errno);
		unlink(scratch);
		mail_free(scratch);
		mail_free(message);
		errno = eno;
		return NULL;
	}
#ifndef USE_RENAME
	unlink(scratch);
#endif
	mail_free(scratch);
#endif /* !USE_RENAME1 */

	/* Extend when need! */

	if (fn >= mail_nfiles) {
	  int nfile = fn+1;
	  if (mail_file == NULL) {
	    mail_file = (char**)mail_alloc((u_int)(sizeof(char*) * nfile));
	    mail_type = (char**)mail_alloc((u_int)(sizeof(char*) * nfile));
	  } else {
	    mail_file = (char**)mail_realloc((char*)mail_file,
					     (sizeof(char*) * nfile));
	    mail_type = (char**)mail_realloc((char*)mail_type,
					     (sizeof(char*) * nfile));
	  }
	  while (mail_nfiles < nfile) {
	    mail_file[mail_nfiles] = NULL;
	    mail_type[mail_nfiles] = NULL;
	    ++mail_nfiles;
	  }
	}
#ifdef USE_RENAME1
	mail_file[fn] = scratch;
	mail_type[fn] = strdup(type);
#else
	mail_file[fn] = message;
#endif

	/* Grab preferences from the environment to initialize the envelope */

#ifndef	notype
	if (type != NULL && *type != '\0')
		fprintf(fp, "type %s\n", type);
#endif
	cp = getenv("FULLNAME");
	if (cp != NULL)
		fprintf(fp, "fullname %s\n",
			fullname(cp, namebuf, sizeof namebuf, (char *)NULL));
	cp = getenv("PRETTYLOGIN");
	if (cp != NULL)
		fprintf(fp, "loginname %s\n", cp);
	/*
	 * If the postoffice lives elsewhere, put our hostname
	 * in the Received-from header, to aid in message tracing.
	 */
#if 0
	host = whathost(message);
	if (getzenv("MAILSERVER") != NULL ||
	    (host != NULL && strcmp(host,"localhost") != 0))
#endif
	  if (getmyhostname(namebuf, sizeof namebuf) == 0) {
	    cp = getenv("LOGNAME");
	    if (cp == NULL)
	      cp = getenv("USERNAME");
	    if (cp == NULL)
	      cp = getenv("USER");
	    if (cp == NULL)
	      cp = "\"??\"";
	    fprintf(fp, "rcvdfrom STDIN (%s@%s)\n", cp, namebuf);
	  }
	return fp;
}


/*
 * Return currently open spool file name
 */

char *
mail_fname(fp)
	FILE *fp;
{
	int fd = FILENO(fp);

	if (fd < 0 || fd >= mail_nfiles)
	  return NULL;

	return mail_file[fd];
}


/*
 * Abort the message file composition on the indicated stream.
 */

int
mail_abort(fp)
	FILE *fp;
{
	register char *message;
	int r, fn;

	if (fp == NULL) {
		errno = EBADF;
		return -1;
	}
	fn = FILENO(fp);
	if (fn >= mail_nfiles)
		abort(); /* Usage error -- no such fileno in our use! */
	if (mail_type[ fn ]) mail_free(mail_type[fn]);
	mail_type[ fn ] = NULL;
	message = mail_file[ fn ];
	if (message == NULL) {
		errno = ENOENT;
		return -1;
	}
	fclose(fp);
	mail_file[ fn ] = NULL;
	r = unlink(message);
	mail_free(message);
	return r;
}

/*
 * Close the message file on the indicated stream and submit it to the mailer.
 */

int mail_close(fp)
	FILE *fp;
{
	int ino;
	time_t mtime;

	return _mail_close_(fp, &ino, &mtime);
}


static int routersubdirhash = -1;

int
_mail_close_(fp,inop, mtimep)
	FILE *fp;
	int *inop;
	time_t *mtimep;
{
	char *message, *nmessage, *type, *ftype;
	const char *routerdir;
	char *s = NULL;
	struct stat stb;
	int fn;
	long ino;
	char subdirhash[6];

	if (routersubdirhash < 0) {
	  char *ss = getzenv("ROUTERDIRHASH");
	  if (ss && *ss == '1')
	    routersubdirhash = 1;
	  else
	    routersubdirhash = 0;
	}

	if (postoffice == NULL) {
		fprintf(stderr, "mail_close: called out of order!\n");
		errno = EINVAL;
		return -1;
	}
	if (fp == NULL) {
		errno = EBADF;
		return -1;
	}
	fn = FILENO(fp);
	if (fn >= mail_nfiles)
		abort(); /* Usage error -- no such fileno in our use! */
	message = mail_file[fn];
	if (message == NULL) {
		errno = ENOENT;
		return -1;
	}
	ftype = type = mail_type[fn];
	if (type == NULL) {
		type = "";
	}

	mail_type[fn] = NULL;
	mail_file[fn] = NULL;

	if (fstat(fn, &stb)) {
	  /* XXX: error processing */
	}
	ino = stb.st_ino;

	if (routersubdirhash > 0) {
	  sprintf(subdirhash, "%c/", 'A' + (ino % 26));
	} else
	  *subdirhash = 0;

	/*
	 * *** NFS users beware ***
	 * the fsync() between fflush() and fclose() may be mandatory
	 * on NFS mounted postoffices if you want to guarantee not losing
	 * data without being told about it.
	 */

	if (fflush(fp) != 0
#ifdef HAVE_FSYNC
	    || fsync(fn) < 0
#endif
	    || fclose(fp) != 0) {
		if (ftype) mail_free(ftype);
		mail_free(message);
		errno = EIO;
		return -1;
	}


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
	    nmessage = alloca(strlen(postoffice)+strlen(routerdirs)+3+
			      9+4+strlen(type));
#else
	    nmessage = mail_alloc(strlen(postoffice)+strlen(routerdirs)+3+
				  9+4+strlen(type));
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
	  nmessage = alloca(strlen(postoffice)+strlen(routerdir)+
			    9+4+2+1+strlen(type));
#else
	  nmessage = mail_alloc(strlen(postoffice)+strlen(routerdir)+
				9+4+2+1+strlen(type));
#endif
	  sprintf(nmessage, "%s/%s/%s%ld%s", postoffice, routerdir,
		  subdirhash, ino ,type);
	} else {
	  s = strchr(routerdir,':');
	  if (s) *s = 0;
	  sprintf(nmessage, "%s/%s/%s%ld%s", postoffice, routerdir,
		  subdirhash, ino, type);
	  if (s) *s = ':';
	}

#ifndef USE_RENAME
	/*
	 * Unfortunately, rename() doesn't guarantee the same inode will
	 * be used if the two paths are on the same filesystem, so we do
	 * it the hard way.
	 */

	if (link(message, nmessage) != 0) {
	  int eno = errno;
	  fprintf(stderr, "link(\"%s\", \"%s\"): errno %d\n",
		  message, nmessage, errno);
	  if (ftype) mail_free(ftype);
	  mail_free(message);
	  mail_free(nmessage);
	  errno = eno;
	  return -1;
	}
	unlink(message);
#else
	/* For performance reasons we optimize heavily.. */
	/* Even if that comment above about rename is true,
	   we won't trust it.. */

	if (eqrename(message,nmessage) != 0) {
	  int eno = errno;
	  fprintf(stderr, "link(\"%s\", \"%s\"): errno %d\n",
		  message, nmessage, errno);
	  if (ftype) mail_free(ftype);
	  mail_free(message);
	  mail_free(nmessage);
	  errno = eno;
	  return -1;
	}
#endif

	stat(nmessage, &stb);

#ifndef HAVE_ALLOCA
	mail_free(nmessage);
#endif
	mail_free(message);
	if (ftype) mail_free(ftype);

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
mail_close_alternate(fp,where,suffix)
	FILE *fp;
	const char *where, *suffix;
{
	char *message, *nmessage, *msgbase;
	char *type, *ftype;
	int fn;

	if (postoffice == NULL) {
		fprintf(stderr, "mail_close: called out of order!\n");
		errno = EINVAL;
		return -1;
	}
	if (fp == NULL) {
		errno = EBADF;
		return -1;
	}
	fn = FILENO(fp);
	if (fn >= mail_nfiles)
		abort(); /* Usage error -- no such fileno in our use! */
	message = mail_file[fn];
	if (message == NULL) {
		errno = ENOENT;
		return -1;
	}
	type = ftype = mail_type[fn];
	if (type == NULL)
	  type = "";

	mail_file[fn] = NULL;
	mail_type[fn] = NULL;

	/*
	 * *** NFS users beware ***
	 * the fsync() between fflush() and fclose() may be mandatory
	 * on NFS mounted postoffices if you want to guarantee not losing
	 * data without being told about it.
	 */
	if (fflush(fp) == EOF
#ifdef HAVE_FSYNC
	    || fsync(fn) < 0
#endif
	    || fclose(fp) == EOF) {
		mail_free(message);
		if (ftype) mail_free(ftype);
		errno = EIO;
		return -1;
	}


	/* Find the base name (we know format is PUBLICDIR/basename) */
	msgbase = strrchr(message, '/');
	if (msgbase == NULL)
		msgbase = message;
	else
		++msgbase;

	nmessage  = NULL;
	/* Assert postoffice != NULL */
	nmessage = mail_alloc(strlen(postoffice)+1+strlen(where)+1+
			      strlen(msgbase)+strlen(suffix)+1+strlen(type));
	sprintf(nmessage, "%s/%s/%s%s%s",
		postoffice, where, msgbase, suffix, type);

#ifndef USE_RENAME
	/*
	 * Unfortunately, rename() doesn't guarantee the same inode will
	 * be used if the two paths are on the same filesystem, so we do
	 * it the hard way.
	 */

	if (link(message, nmessage) != 0) {
		int eno = errno;
		fprintf(stderr, "link(\"%s\", \"%s\"): errno %d\n",
				message, nmessage, errno);
		mail_free(nmessage);
		unlink(message); /* Throw the file away */
		mail_free(message);
		if (ftype) mail_free(ftype);
		errno = eno;
		return -2;
	}
	unlink(message);
#else
	/* For performance reasons we optimize heavily.. */
	/* Even if that comment above about rename is true,
	   we won't trust it.. */

	if (eqrename(message,nmessage) != 0) {
	  int eno = errno;
	  fprintf(stderr, "eqrename(\"%s\", \"%s\"): errno %d\n",
		  message, nmessage, errno);
	  mail_free(message);
	  mail_free(nmessage);
	  if (ftype) mail_free(ftype);
	  errno = eno;
	  return -1;
	}
#endif
	mail_free(message);
	mail_free(nmessage);
	if (ftype) mail_free(ftype);
	return 0;
}
