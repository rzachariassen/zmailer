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
#include "mailer.h"
#include <errno.h>

extern char	*progname;
extern int	errno;
extern char	*strerror();

int
eopen(s, f, m)
	char	*s;
	int	f, m;
{
	int	r;

	if ((r = open(s, f, m)) < 0) {
		(void) fprintf(stderr, "%s: open: %s: %s\n",
				progname, s, strerror(errno));
	}
	return r;
}

int
eread(fd, buf, len)
	int	fd, len;
	char	*buf;
{
	int	r;

	if ((r = read(fd, buf, len)) < 0) {
		(void) fprintf(stderr, "%s: read: %s\n",
				progname, strerror(errno));
	}
	return r;
}

int
epipe(fdarr)
	int	fdarr[2];
{
	int	r;

	if ((r = pipe(fdarr)) < 0) {
		(void) fprintf(stderr, "%s: pipe: %s\n",
				progname, strerror(errno));
	}
	return r;
}

/* for statistics in router/allocate.c */
int embytes = 0;
int emcalls = 0;
unsigned emsleeptime = 60;

univptr_t
emalloc(len)
	size_t	len;
{
	univptr_t	r;

	while ((r = malloc(len)) == NULL) {
		(void) fprintf(stderr,
			"%s: malloc(%u): virtual memory exceeded, sleeping\n",
			progname, len);
		(void) sleep(emsleeptime);
	}
	embytes += len;
	++emcalls;
	return r;
}

univptr_t
erealloc(buf, len)
	univptr_t buf;
	size_t	len;
{
	univptr_t	r;

	while ((r = realloc(buf, len)) == NULL) {
		(void) fprintf(stderr,
			"%s: realloc(%u): virtual memory exceeded, sleeping\n",
			progname, len);
		(void) sleep(emsleeptime);
	}
	return r;
}

int
efstat(fd, stbuf)
	int	fd;
	struct stat	*stbuf;
{
	int	r;

	if ((r = fstat(fd, stbuf)) < 0) {
		(void) fprintf(stderr, "%s: fstat(%d): %s\n", progname,
			fd, strerror(errno));
	}
	return r;
}

int
estat(path, stbuf)
	char	*path;
	struct stat	*stbuf;
{
	int	r;

	if ((r = stat(path, stbuf)) < 0) {
		(void) fprintf(stderr, "%s: stat(%s): %s\n", progname,
			path, strerror(errno));
	}
	return r;
}

long
elseek(fd, pos, action)
	int	fd, action;
	long	pos;
{
	long	r;

	if ((r = lseek(fd, pos, action)) == -1) {
		(void) fprintf(stderr, "%s: lseek(%d, %d, %ld): %s\n", progname,
			fd, pos, action, strerror(errno));
	}
	return r;
}

int
elink(file1, file2)
	char *file1, *file2;
{
	int	r;

	if ((r = link(file1, file2)) < 0) {
		(void) fprintf(stderr, "%s: link(%s, %s): %s\n", progname,
			file1, file2, strerror(errno));
	}
	return r;
}

int
eunlink(file)
	char *file;
{
	int	r;

	if ((r = unlink(file)) < 0) {
		(void) fprintf(stderr, "%s: unlink(%s): %s\n", progname,
			file, strerror(errno));
	}
	return r;
}

int
eclose(fd)
	int fd;
{
	int	r;

	if ((r = close(fd)) < 0) {
		(void) fprintf(stderr, "%s: close(%d): %s\n", progname,
			fd, strerror(errno));
	}
	return r;
}

int
echdir(file)
	char *file;
{
	int	r;

	if ((r = chdir(file)) < 0) {
		(void) fprintf(stderr, "%s: chdir(%s): %s\n", progname,
			file, strerror(errno));
	}
	return r;
}

int
emkdir(file, mode)
	char *file;
	int mode;
{
	int	r;
#ifdef	USE_BINMKDIR
	char	cmdbuf[BUFSIZ];

	(void) sprintf(cmdbuf, "exec /bin/mkdir '%s' 1>&2", file);
	r = system(cmdbuf);
	if (r > 0) {
		errno = EINVAL;
		r = -1;
	}
#else	/* !USE_BINMKDIR */

	if ((r = mkdir(file, mode)) < 0) {
		(void) fprintf(stderr, "%s: mkdir(%s, 0%o): %s\n", progname,
			file, mode, strerror(errno));
	}
#endif	/* USE_BINMKDIR */
	return r;
}

int
ermdir(file)
	char *file;
{
	int	r;
#ifdef	USE_BINRMDIR
	char	cmdbuf[BUFSIZ];

	(void) sprintf(cmdbuf, "exec /bin/rmdir '%s' 1>&2", file);
	r = system(cmdbuf);
	if (r > 0) {
		errno = EINVAL;
		r = -1;
	}
#else	/* !USE_BINRMDIR */

	if ((r = rmdir(file)) < 0) {
		(void) fprintf(stderr, "%s: rmdir(%s): %s\n", progname,
			file, strerror(errno));
	}
#endif	/* USE_BINRMDIR */
	return r;
}

int
erename(from, to)
	char *from, *to;
{
	int	r;

#ifdef	HAVE_RENAME
	
	if ((r = rename(from, to)) < 0) {
#else	/* !HAVE_RENAME */
	
	if (((r = unlink(to)) < 0 && errno != ENOENT)
	    || (r = link(from, to)) < 0) {
#endif	/* !HAVE_RENAME */
		(void) fprintf(stderr, "%s: rename(%s,%s): %s\n", progname,
			from, to, strerror(errno));
	}
#ifndef	HAVE_RENAME
	else
		(void) unlink(from);
#endif	/* !HAVE_RENAME */
	return r;
}
