/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * System call interface routines that record syscall failures.
 */

#ifdef	MALLOC_TRACE
#undef	MALLOC_TRACE
#endif
#include "hostenv.h"
#include <errno.h>
#include <fcntl.h>
#include "mailer.h"
#include "libz.h"

extern char	*progname;
extern int	errno;
extern char	*strerror __((int));

int
eopen(s, f, m)
	const char *s;
	int	f, m;
{
	int	r;

	r = open(s, f, m);
	if (r < 0) {
	  int serrno = errno;
	  fprintf(stderr, "%s: open: %s: %s\n", progname, s, strerror(errno));
	  errno = serrno;
	}
	return r;
}

int
eread(fd, buf, len)
	int	fd, len;
	char	*buf;
{
	int	r;

	r = read(fd, buf, len);
	if (r < 0) {
	  int serrno = errno;
	  fprintf(stderr, "%s: read: %s\n", progname, strerror(errno));
	  errno = serrno;
	}
	return r;
}

int
epipe(fdarr)
	int	fdarr[2];
{
	int	r;

	r = pipe(fdarr);
	if (r < 0) {
	  int serrno = errno;
	  fprintf(stderr, "%s: pipe: %s\n", progname, strerror(errno));
	  errno = serrno;
	}
	return r;
}

int
efstat(fd, stbuf)
	int	fd;
	struct stat	*stbuf;
{
	int	r;

	r = fstat(fd, stbuf);
	if (r < 0) {
	  int serrno = errno;
	  fprintf(stderr, "%s: fstat(%d): %s\n", progname, fd,strerror(errno));
	  errno = serrno;
	}
	return r;
}

int
estat(path, stbuf)
	const char	*path;
	struct stat	*stbuf;
{
	int	r;

	r = stat(path, stbuf);
	if (r < 0) {
	  int serrno = errno;
	  fprintf(stderr, "%s: stat(%s): %s\n",progname,path,strerror(errno));
	  errno = serrno;
	}
	return r;
}

off_t
elseek(fd, pos, action)
	int	fd, action;
	off_t	pos;
{
	off_t	r;

	r = lseek(fd, pos, action);
	if (r < 0) {
	  int serrno = errno;
	  fprintf(stderr, "%s: lseek(%d, %ld, %d): %s\n", progname,
		  fd, (long)pos, action, strerror(errno));
	  errno = serrno;
	}
	return r;
}

int
elink(file1, file2)
	const char *file1, *file2;
{
	int	r;

	r = link(file1, file2);
	if (r < 0) {
	  int serrno = errno;
	  fprintf(stderr, "%s: link(%s, %s): %s\n", progname,
		  file1, file2, strerror(errno));
	  errno = serrno;
	}
	return r;
}

int
eunlink(file,tag)
	const char *file, *tag;
{
	int	r;

	while ((r = unlink(file)) < 0 && (errno == EBUSY || errno == EINTR))
	  ;
	if (r < 0) {
	  int serrno = errno;
	  fprintf(stderr, "%s: unlink(%s)[%s]: %s\n", progname,
		  file, tag, strerror(errno));
	  errno = serrno;
	}
	return r;
}

int
eclose(fd)
	int fd;
{
	int	r;

	r = close(fd);
	if (r < 0) {
	  int serrno = errno;
	  fprintf(stderr, "%s: close(%d): %s\n", progname,
		  fd, strerror(errno));
	  errno = serrno;
	}
	return r;
}

int
echdir(file)
	const char *file;
{
	int	r;

	r = chdir(file);
	if (r < 0) {
	  int serrno = errno;
	  fprintf(stderr, "%s: chdir(%s): %s\n", progname,
		  file, strerror(errno));
	  errno = serrno;
	}
	return r;
}

int
emkdir(file, mode)
	const char *file;
	int mode;
{
	int	r;
#ifdef	USE_BINMKDIR
	char	cmdbuf[BUFSIZ];

	sprintf(cmdbuf, "exec /bin/mkdir '%s' 1>&2", file);
	r = system(cmdbuf);
	if (r > 0) {
		errno = EINVAL;
		r = -1;
	}
#else	/* !USE_BINMKDIR */

	r = mkdir(file, mode);
	if (r < 0) {
	  int serrno = errno;
	  fprintf(stderr, "%s: mkdir(%s, 0%o): %s\n", progname,
		  file, mode, strerror(errno));
	  errno = serrno;
	}
#endif	/* USE_BINMKDIR */
	return r;
}

int
ermdir(file)
	const char *file;
{
	int	r;
#ifdef	USE_BINRMDIR
	char	cmdbuf[BUFSIZ];

	sprintf(cmdbuf, "exec /bin/rmdir '%s' 1>&2", file);
	r = system(cmdbuf);
	if (r > 0) {
		errno = EINVAL;
		r = -1;
	}
#else	/* !USE_BINRMDIR */

	r = rmdir(file);
	if (r < 0) {
	  int serrno = errno;
	  fprintf(stderr, "%s: rmdir(%s): %s\n", progname,
		  file, strerror(errno));
	  errno = serrno;
	}
#endif	/* USE_BINRMDIR */
	return r;
}

int
erename(from, to)
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
	      /* Anything else is considered ok for the unlink(),
		 things like  ENOENT, etc.. */
	      break;
	    }
	    /* Solaris says EBUSY, we retry.. */
	    continue;
	  }
	  fprintf(stderr, "%s: rename(%s,%s): %s\n", progname,
		  from, to, strerror(serrno));
	  errno = serrno;
	  return -1;
	}

#else	/* !HAVE_RENAME */
	
	while (unlink(to) < 0) {
	  int serrno = errno;
	  if (errno == EINTR || errno == EBUSY)
	    continue; /* Solaris 2.x previous to 2.7 may yield EBUSY.. */
	  if (errno == ENOENT) break; /* Ok! */
	  fprintf(stderr, "%s: rename(%s,%s): %s\n", progname,
		  from, to, strerror(serrno));
	  errno = serrno;
	  return -1;
	}
	while (link(from, to) < 0) {
	  int serrno = errno;
	  if (errno == EINTR || errno == EBUSY)
	    continue; /* Solaris may yield this */
	  fprintf(stderr, "%s: rename(%s,%s): %s\n", progname,
		  from, to, strerror(errno));
	  errno = serrno;
	  return -1;
	}

	while (unlink(from) < 0) {
	  int serrno = errno;
	  if (errno == EINTR || errno == EBUSY)
	    continue; /* Solaris ... */
	  if (errno != ENOENT)
	    fprintf(stderr, "%s: rename(%s,%s): %s\n", progname,
		    from, to, strerror(errno));
	  unlink(to);
	  errno = serrno;
	  return -1;
	}
#endif	/* !HAVE_RENAME */

	return 0;
}

int
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
