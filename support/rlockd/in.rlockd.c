/*
 * in.rlockd - remote locking server
 *
 * Copyright 1986 by Dennis Ferguson and Rayan Zachariassen
 */


#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <sgtty.h>
#include <netdb.h>
#include <sys/param.h>
#include <sys/file.h>

/*
 * Configuration defaults (s=0, reset; s=1, set):
 *
 * -DSTRICT=s	- if set we check pathname permissions
 * -DTIMEOUT=n	- time we spend waiting for input from remote host, in seconds
 * -DLOCKTIME=n	- maximum amount of time we spend waiting for a lock
 * -DINETD=s 	- if set we are run by inetd.
 *
 * -DCLIENTFILE=\"file\"	- name of client file, with STRICT only
 */

#ifndef STRICT
#define	STRICT		0	/* insecure by default */
#endif

#ifndef TIMEOUT
#define TIMEOUT		(600)	/* idle time out in seconds */
#endif

#ifndef LOCKTIME
#define	LOCKTIME	(120)	/* lock time out in seconds */
#endif

#ifndef	INETD
#define	INETD		1	/* run with inetd */
#endif

/*
 * remote lock server:
 *	him:			us:
 *
 *	filename\n				path to file to lock
 *	lock_type\n				2nd argument to flock()
 *	uid\n					uid of user
 *	gid\n					gid of user
 *	\0
 *				\0		if locked
 *				(char)errno	if lock failed
 */

extern	errno;
char	*progname;
struct	sockaddr_in sin = { AF_INET };
#if !INETD
int	reapchild();
int	gethostaccess();
#endif !INETD

/*
 * Compile in all space that could conceivably be required
 * for storage of file names and descriptors.  Thank god
 * for demand paging.  Fix this if malloc seems like a
 * better idea.
 */
struct locked {
	int	fd;			/* file descriptor we locked on */
	int	uid;			/* uid of locker */
	int	gid;			/* gid of locker */
	char	fname[MAXPATHLEN+1];	/* file name */
} *locked;


int
main(argc, argv)
	int argc;
	char **argv;
{
	int f, options = 0;
	struct sockaddr_in from;
	struct servent *sp;
	extern char *dottedquad();
	int on = 1;

	progname = argv[0];
	if (getuid() != 0) {
		(void) fprintf(stderr, "%s: permission denied\n", progname);
		exit(1);
	}
#if INETD
	f = sizeof from;
	if (getpeername(0, &from, &f) < 0) {
		(void) fprintf(stderr, "%s: permission denied\n", progname);
		exit(1);
	}
	trace("serving host %s", dottedquad(&from.sin_addr));
	doit(dup(0), &from);
	exit(0);
#else /* ! INETD */
	sp = getservbyname("flock", "tcp");
	if (sp == 0) {
		(void) fprintf(stderr, "%s: tcp/flock: unknown service\n", progname);
		exit(1);
	}
	sin.sin_port = sp->s_port;
	argc--, argv++;

#ifndef DEBUG
	if (fork())
		exit(0);
	for (f = 0; f < 10; f++)
		(void) close(f);
	(void) open("/", 0);
	(void) dup2(0, 1);
	(void) dup2(0, 2);
	{ int tt = open("/dev/tty", 2);
	  if (tt > 0) {
		(void) ioctl(tt, TIOCNOTTY, (char *)0);
		(void) close(tt);
	  }
	}
#endif DEBUG
	if (argc > 0 && !strcmp(argv[0], "-d")) {
		options |= SO_DEBUG;
		argc--, argv++;
	}
	if (argc > 0) {
		int port = atoi(argv[0]);

		if (port <= 0) {  /* 0 returned if non numeric argument */
			(void) fprintf(stderr, "%s: %s: bad port #\n", progname, argv[0]);
			exit(1);
		}
		sin.sin_port = htons((u_short)port);
		argv++, argc--;
	}

#if STRICT
	/* Compile client-pathname list */
	gethostaccess();
	(void) signal(SIGHUP, gethostaccess);
#endif

	f = socket(AF_INET, SOCK_STREAM, 0);
	if (f < 0) {
		(void) fprintf(stderr, "%s: ", progname);
		perror("socket");
		exit(1);
	}
	if (options & SO_DEBUG)
#ifdef NEWKERNEL
		if (setsockopt(f, SOL_SOCKET, SO_DEBUG, &on, sizeof(on)) < 0) {
#else NEWKERNEL
		if (setsockopt(f, SOL_SOCKET, SO_DEBUG, (char *)0, 0) < 0) {
#endif NEWKERNEL
			(void) fprintf(stderr, "%s: ", progname);
			perror("setsockopt (SO_DEBUG)");
		}
	if (bind(f, (struct sockaddr *)&sin, sizeof (sin)) < 0) {
		(void) fprintf(stderr, "%s: ", progname);
		perror("bind");
		exit(1);
	}
	(void) signal(SIGCHLD, reapchild);
	(void) listen(f, 10);
	for (;;) {
		int s, len = sizeof (from);

		s = accept(f, (struct sockaddr *)&from, &len);
		if (s < 0) {
			if (errno == EINTR)
				continue;
			(void) fprintf(stderr, "%s: ", progname);
			perror("accept");
			continue;
		}
		if (fork() == 0) {
			(void) signal(SIGHUP, SIG_IGN);
			(void) signal(SIGCHLD, SIG_IGN);
			(void) close(f);
			doit(s, &from);
		}
		(void) close(s);
	}
#endif /* INETD */
	exit(0);
}

reapchild()
{
	union wait status;

	while (wait3(&status, WNOHANG, (struct rusage *)0) > 0)
		;
}

static int netf;

/* ARGSUSED */
doit(f, fromp)
	int f;
	struct sockaddr_in *fromp;
{
	int cleanup();
	register struct locked *lk, *lktmp;
	register struct locked *maxlk;
	int lock_type, res;
	char *calloc();

	netf = f;			/* hack for cleanup */
	(void) signal(SIGALRM, cleanup);
#if STRICT && INETD
	gethostaccess();		/* compile file access info */
#endif
	/*
	 * Note: It is assumed that we will never run
	 * out of slots in locked[].
	 */
	 locked = (struct locked *)
			 calloc(getdtablesize(), sizeof(struct locked));
	 if (locked == 0)
		abort();
	 maxlk = &locked[0];

#ifdef DEBUG
fprintf(stderr, "lockd: starting\n");
#endif

	for (;;) {
		/*
		 * Find free descriptor
		 */
		for (lk = &locked[0]; lk < maxlk; lk++)
			if (lk->fd == -1)
				break;
		if (lk == maxlk) {
			lk->fd = -1;
			maxlk++;
		}
		trace("reading request");
		if (!getinfo(f, lk->fname, sizeof(lk->fname),
		    &lock_type, &lk->uid, &lk->gid)) {
#ifdef DEBUG
fprintf(stderr, "lockd: terminating\n");
#endif
			trace("getinfo failed, exiting");
			exit(0);
		}
		trace("request: file=%s uid=%d gid=%d locktype=%x",
			lk->fname, lk->uid, lk->gid, lock_type);
		/*
		 * Did we do this file before?
		 */
		for (lktmp = &locked[0]; lktmp < maxlk; lktmp++) {
			if (lktmp == lk || lktmp->fd == -1)
				continue;
			if (strcmp(lk->fname, lktmp->fname) == 0) {
				lk = lktmp;
				break;
			}
		}

		if (lk->fd == -1) {	/* first time? */
#if STRICT
			/*
			 * Accessable to this guy?
			 */
			if (!checkhostaccess(fromp, lk->fname)) {
				putstatus(f, EACCES);
				continue;
			}
#endif STRICT
			trace("opening file %s", lk->fname);
			if ((lk->fd = open(lk->fname, O_RDONLY)) < 0) {
				trace("open failed (%d)", errno);
				putstatus(f, errno);	/* non-local? */
				continue;
			}
		}
		/*
		 * Mask lock type for sanity.
	 	 */
		trace("flocking %x", lock_type);
#if LOCKTIME
		(void) alarm(LOCKTIME);
#endif
		res = flock(lk->fd,lock_type&(LOCK_SH|LOCK_EX|LOCK_NB|LOCK_UN));
#if LOCKTIME
		(void) alarm(0);
#endif
		trace("flock=%d (%d)", res, errno);
		if (res < 0) {
			putstatus(f, errno);
			continue;
		}
#ifdef DEBUG
fprintf(stderr, "lockd: \"%s\" locked %o\n", lk->fname, lock_type);
#endif
		if (lock_type == LOCK_UN) {
			(void) close(lk->fd);
			lk->fd = -1;
		}
		putstatus(f, 0);
	}
	/*NOTREACHED*/
}


/*
 * getinfo - get info about file to lock
 *	   - returns 1 if we got it, 0 if the
 *	     other guy quit.
 *	   - all errors in here are abnormal and
 *	     fatal.
 */

int
getinfo(f, filename, maxlen, lock_type, uid, gid)
int f;
char *filename;
int *lock_type;
int *uid;
int *gid;
{

#if TIMEOUT
	(void) alarm(TIMEOUT);
#endif
#ifdef DEBUG
fprintf(stderr, "lockd: waiting for file name\n");
#endif
	/*
	 * If there is a normal shutdown on the other end
	 * we will get -1 return from getfile but have a
	 * zero errno.
	 */
	if (getfile(f, filename, maxlen) < 0) {
		trace("getfile failed (%d)", errno);
		if (errno == 0) {
			(void) alarm(0);
			return (0);
		}
		else
			fatal(f, EINVAL);
	}
#ifdef DEBUG
fprintf(stderr, "lockd: got filename \"%s\"\n", filename);
#endif
	if ((*lock_type = getint(f)) < 0) {
		trace("getint locktype failed");
		fatal(f, EINVAL);
	}
#ifdef DEBUG
fprintf(stderr, "lockd: got lock_type 0x%x\n", *lock_type);
#endif
	if ((*uid = getint(f)) < 0) {
		trace("getint uid failed");
		fatal(f, EINVAL);
	}
#ifdef DEBUG
fprintf(stderr, "lockd: got uid %d\n", *uid);
#endif
	if ((*gid = getint(f)) < 0) {
		trace("getint gid failed");
		fatal(f, EINVAL);
	}
#ifdef DEBUG
fprintf(stderr, "lockd: got gid %d\n", *gid);
#endif
	if (geteos(f) < 0) {
		trace("geteos failed");
		fatal(f, EIO);	/* must be I/O error */
	}

#if TIMEOUT
	(void) alarm(0);
#endif
	return (1);
}


/*
 * cleanup - shut down socket and exit with error.
 */

cleanup()
{
#ifdef DEBUG
	fprintf(stderr, "lockd: in cleanup\n");
#endif
	(void) shutdown(netf, 2);
	exit(1);
}


/*
 * fatal - write error status back to client and clean up
 */

fatal(f, stat)
	int f;
	int stat;
{
#ifdef DEBUG
fprintf(stderr, "lockd: fatal error, errno = %d, stat = %d\n", errno, stat);
#endif
	(void) alarm(0);
	/* Woe be to yee if errno's get bigger than 127 */
	putstatus(f, stat);
	cleanup();
}


/*
 * putstatus - write a byte of status back to the client
 *	       exits at first sign of trouble
 */

putstatus(f, value)
	int f;
	int value;
{
	unsigned char byte;

	byte = (unsigned char)value;
	if (write(f, (char *)&byte, 1) != 1) {
		trace("putstatus: write (%d)", errno);
		(void) shutdown(f, 2);
		exit(1);
	}
	/*NOTREACHED*/
}


/*
 * getfile - receive file name from client
 */

int
getfile(f, buf, maxlen)
	int f;
	char *buf;
	int maxlen;
{
	/*
	 * Return the full file name that we recieve as long as
	 * we get an absolute path.
	 */
	if (getfield(f, buf, maxlen) < 0)
		return (-1);
	if (buf[0] != '/') {
		errno = EINVAL;
		return (-1);
	}
	return (0);
}


/*
 * getint - get a positive integer from the client
 *	    return -1 for errors, be fairly strict
 */

int
getint(f)
	int f;
{
	char buf[20];
	register char *bp;

	if (getfield(f, buf, sizeof(buf)) < 0)
		return (-1);
	for (bp = buf; *bp != '\0'; bp++) {
		if (!isdigit(*bp))
			return (-1);
	}
	if (bp == buf)
		return (-1);
	return atoi(buf);

}


/*
 * getfield - read data from socket up to '\n'
 *	      return error if field longer than len
 *              or if anything screws up
 *	      It pains me to do single character reads,
 *		check for alternative method
 */

int seeneos = 0;

int
getfield(f, buf, len)
int f;
char *buf;
int len;
{
	register int i;
	register char *bp;
	int res;

	if (seeneos)
		return (-1);
	for (i = 0; i < len; i++) {
		if ((res = read(f, (bp = &buf[i]), 1)) != 1) {
			trace("getfield: read (%d)",errno);
			if (res == 0)
				errno = 0;	/* I am ashamed*/
			return (-1);
		}
		if (!isascii(*bp))
			return (-1);
		switch (*bp) {
		case '\n':
			*bp = '\0';
			return (i);
		case '\0':
			seeneos = 1;
			return (i);
		default:
			if (!isascii(*bp))
				return (-1);
			break;
		}
	}
	return (-1);
}


/*
 * geteos - If we haven't seen eos, read until we find it
 */

int
geteos(f)
int f;
{
	char c;

	if (!seeneos) {
		do {
		if (read(f, &c, 1) != 1) {
			trace("geteos: read %d",errno);
			return (-1);
		}
		} while (c != '\0');
	}
	else {
		seeneos = 0;
	}
	return (0);
}


/*
 * gethostaccess, checkhostaccess (to come)
 */

#if STRICT
gethostaccess()
{
}

int
checkhostaccess(fromp, file)
	struct sockaddr_in *fromp;
	char *file;
{
#ifdef lint
	char *dum;
	struct sockaddr_in *from;

	dum = file;
	from = fromp;
	file = dum;
	fromp = from;
#endif
	return (1);
}
#endif

#include <varargs.h>
trace(va_alist)
	va_dcl
{
#ifdef TRACE
	va_list ap;
	char *fmt;
	static FILE *fp;

	va_start(ap);
	if (fp == 0) {
		fp = fopen("/tmp/rlockd.trace", "a");
		if (fp==0) return;
		fprintf(fp, "\n");
	}
	fmt = va_arg(ap, char *);
	vfprintf(fp, fmt, ap);
	fprintf(fp, "\n");
	fflush(fp);
	va_end(ap);
#endif /* TRACE */
}
