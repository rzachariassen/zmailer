#ifndef lint
static	char *RCSid = "$Header$";
#endif

/*
 * lock routine that works across rmounted filesystems.
 *
 * Copyright 1986 by Rayan Zachariassen and Dennis Ferguson
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/time.h>
#include <netinet/in.h>

#include <stdio.h>
#include <mntent.h>
#include <netdb.h>
#include <errno.h>

#define DAEMON_TIMEOUT		(10)	/* max time to wait for response */

#ifdef DEBUG
# define dperror(x) perror(x)
# define dpr printf
#else
# define dperror(x) /* nothing */
# define dpr if (0) printf
#endif

char *getmntpt();

#undef	MAIN
#ifdef	MAIN
int
main(argc, argv)
int argc;
char **argv;
{
	printf("locking %s, result is %d\n", argv[1], lock(argv[1]));
	sleep(2);
	printf("locking %s, result is %d\n", argv[2], lock(argv[2]));
	sleep(10);
	printf("unlocking %s, result is %d\n", argv[1], unlock(argv[1]));
	sleep(7);
	printf("unlocking %s, result is %d\n", argv[2], unlock(argv[2]));
	exit(0);
}
#endif	MAIN

int
nfslock(file, opt)
char	*file;
int	opt;
{
	struct stat	statb;
	char		*mnt, *cp, *dir;
	extern int	errno;
	extern char	*index();

	if (stat(file, &statb) < 0) {
#ifdef DEBUG
		fprintf(stderr, "rlock: can't stat file %s\n", file);
#endif
		return -1;
	} else if ((statb.st_mode & S_IFMT) == S_IFREG
		   && (mnt = getmntpt(file, &dir)) != NULL) {
		if ((cp = index(mnt, ':')) == 0) {
			dpr("file is local\n");
			/* file is local! */
			return llock(file, opt);
		} else {
			/* file is remote - use locking daemon! */
			char	crfile[MAXPATHLEN], rfile[MAXPATHLEN];
			char	hostname[32];

			dpr("file is remote\n");
			/* This obviates need for passing id info to lockd */
			if (access(file, W_OK) < 0) {
#ifdef DEBUG
				int saverr = errno;
				fprintf(stderr,
					"rlock: can't write on %s\n", file);
				errno = saverr;
#endif
				return -1;
			}

			*cp++ = '\0';
			strcpy(crfile, cp);
			strcpy(hostname, mnt);
			*--cp = ':';
			if (strncmp(dir, file, strlen(dir)) == 0) {
				strcat(crfile, file+strlen(dir));
			} else {
				/* file was probably symlink to another fs */
				if (getpwf(file, rfile)
				    && !strncmp(dir, rfile, strlen(dir))) {
					strcat(crfile, rfile+strlen(dir));
				} else {
#if 0
					errno = EINVAL;
					return -1;
#else
					strcpy(crfile, file);	/* punt */
#endif
				}
			}
			fcanon(crfile, rfile);
			return rlock(hostname, rfile, opt);
		}
	} else {
#ifdef DEBUG
		fprintf(stderr, "rlock: not a regular file %s\n", file);
#endif
		errno = EINVAL;
		return -1;
	}
	/* NOTREACHED */
}

static int
llock(file, opt)
char	*file;
int	opt;
{
	int	fd;

	/* If we are unlocking, do we have an open fd already for this file? */
	if (opt == LOCK_UN && (fd = haveentry(file)) >= 0) {
		int	retval = flock(fd, opt);	/* unlock file */
		/* Remove local fd entry and close it */
		dpr("unlocking: removing entry\n");
		rementry(fd);
		return retval;
	} else if ((fd = haveentry(file)) >= 0) {
		/* when would this happen? */
		dpr("already have entry!!!\n");
	} else if ((fd = addentry(file)) < 0)
		return -1;
	dpr("flock %d %x\n", fd, opt);
	return flock(fd, opt);
}

static char	**fdtable = NULL;
static int	fdmax = -1;
static unsigned dtablesize = 0;

static int
haveentry(file)
char	*file;
{
	register int	i;

	for (i = 0; i <= fdmax; i++)
		if (fdtable[i] != NULL && *(fdtable[i]) == *file
		    && strcmp(fdtable[i], file) == 0)
			return i;
	return -1;
}

static int
rementry(fd)
int	fd;
{
	if (fdtable == NULL || fd >= dtablesize || fdtable[fd] == NULL)
		return -1;	/* panic */
	dpr("rm entry %s %d\n", fdtable[fd], fd);
	free(fdtable[fd]);
	fdtable[fd] = NULL;
	return close(fd);
}

static int
addentry(file)
char	*file;
{
	int	fd;
	char	*malloc(), *calloc();

	if (dtablesize == 0) {
		dtablesize = getdtablesize();
		fdtable = (char **)calloc(dtablesize, sizeof(char *));
	}
	/*
	 * We must open the file for both read and write,
	 * because some SysV's (e.g. IRIX) emulate flock using
	 * fcntl, which requires read mode for shared locks
	 * and write mode for exclusive ones.
	 */
	if ((fd = open(file, 2)) < 0 || fdtable[fd] != NULL)
		return -1;
	dpr("add entry %s %d\n", file, fd);
	if (fd > fdmax) fdmax = fd;
	fdtable[fd] = malloc(strlen(file) + 1);
	strcpy(fdtable[fd], file);
	return fd;
}

/*
 * Perform a remote flock through the lock daemon.
 */

static int
rlock(rhost, rfile, opt)
char	*rhost, *rfile;
int	opt;
{
	static int hasbeendone = 0;
	static char lasthostname[64];
	static struct in_addr lastaddr;
	static struct sockaddr_in server;
	static struct hostent *hp;
	static int slock = -1;
	struct servent *sp;
	struct timeval tv;
	char	c;
	int	msglen, i, n;
	char	msg[BUFSIZ];
	extern void hp_init();
	extern char **hp_getaddr();

	dpr("rlock host %s file %s\n", rhost, rfile);
	if (!hasbeendone) {
		if ((sp = getservbyname("flock", "tcp")) == NULL) {
			fprintf(stderr,
			    "rlock: flock service not in services database\n");
			errno = EINVAL;
			return -1;
		}
		/* should check if host changes */
		bzero((char *)&server, sizeof (server));
		server.sin_port = sp->s_port;
		lasthostname[0] = '\0';
		hasbeendone = 1;
	}
	if (strcmp(rhost, lasthostname) != 0
	    && (hp = gethostbyname(rhost)) == NULL) {
		fprintf(stderr, "rlock: gethostbyname cannot find %s\n", rhost);
		return -1;
	}
	hp_init(hp);
	if (bcmp((char *)&lastaddr, hp_getaddr(), hp->h_length)) {
		/* new remote host */
		memcpy((char *)&server.sin_addr, hp_getaddr(), hp->h_length);
		lastaddr = server.sin_addr;
		server.sin_family = hp->h_addrtype;
		strcpy(lasthostname, rhost);
		if (slock >= 0) {
			close(slock);
			slock = -1;
		}
	}

	if (slock < 0) {
		dpr("connecting...\n");
		if ((slock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			dperror("rlock: socket");
			return -1;
		}
		if (connect(slock, &server, sizeof (server)) < 0) {
			dperror("rlock: connect");
			close(slock);
			slock = -1;
			return -1;
		}
	}

	sprintf(msg, "%s\n%d\n%d\n%d\n", rfile, opt, geteuid(), getegid());
	msglen = strlen(msg)+1;
	if (write(slock, msg, msglen) != msglen) {
		dperror("rlock: write");
		close(slock);
		slock = -1;
		return -1;
	}
	/*
	 * If the request is non-blocking, timeout the
	 * select after a short wait.  Otherwise just block
	 * until it's done.
	 */
	i = 1<<slock;
	tv.tv_sec = DAEMON_TIMEOUT;
	tv.tv_usec = 0;
	while ((n = select(slock+1, &i, NULL, NULL,
			   (opt & LOCK_NB) ? &tv : NULL)) < 0)
		if (errno != EINTR) {
			dperror("rlock: select");
			close(slock);
			slock = -1;
			return -1;
		}
	if (n == 0) {
		/* select timeout */
		dpr("select timeout\n");
		close(slock);
		slock = -1;
		errno = ETIMEDOUT;
		return -1;
	}
	if (read(slock, &c, 1) < 1) {
		dperror("rlock: read");
		close(slock);
		slock = -1;
		return -1;
	}
#ifdef notdef
	if (opt & LOCK_UN) {		/* Cleanup for normal case */
		close(slock);
		slock = -1;
	}
#endif
	if (c != '\0') {
		dpr("error %d\n", c);
		errno = (int) c;
		return -1;
	}
	return 0;
}

/*
 * Given a name like /usr/src/etc/foo.c returns the mount point
 * for the file system it lives in, or NULL in case of any error.
 */
static char *
getmntpt(file, dir)
char	*file, **dir;
{
	FILE	*mntp;
	struct mntent	*mnt;
	struct stat	filestat, dirstat;
	static char	lastfile[MAXPATHLEN];
	static char	lastmntpt[MAXPATHLEN], lastmntdir[MAXPATHLEN];

	if (stat(file, &filestat) < 0) {
		dperror(file);
		return(NULL);
	}

	/* mount point cashing */
	if (lastfile[0] == file[0] && strcmp(lastfile, file) == 0) {
		*dir = lastmntdir;
		return lastmntpt;
	}

	if ((mntp = setmntent(MOUNTED, "r")) == 0) {
		dperror(MOUNTED);
		return(NULL);
	}

	while ((mnt = getmntent(mntp)) != 0) {
		if (strcmp(mnt->mnt_type, MNTTYPE_IGNORE) == 0 ||
		    strcmp(mnt->mnt_type, MNTTYPE_SWAP) == 0)
			continue;
		if ((stat(mnt->mnt_dir, &dirstat) >= 0) &&
		   (filestat.st_dev == dirstat.st_dev)) {
			/* mount point cashing */
			strcpy(lastfile, file);
			strcpy(lastmntpt, mnt->mnt_fsname);
			strcpy(lastmntdir, mnt->mnt_dir);
			endmntent(mntp);
			*dir = lastmntdir;
			return lastmntpt;
		}
	}
	endmntent(mntp);
	return(NULL);
}

static char *
dbackup(base, offset, c)
register char	*base,
		*offset,
		c;
{
	while (offset > base && *--offset != c)
		;
	return offset;
}

static
fcanon(file, into)
char	*file, *into;
{
	char	*dp, *sp;

	dp = into;
	dp[0] = '\0';
	sp = file;
	do {
		if (*file == 0)
			break;
		if (sp = index(file, '/'))
			*sp = 0;
		if (strcmp(file, ".") == 0)
			;	/* So it will get to the end of the loop */
		else if (strcmp(file, "..") == 0) {
			*(dp = dbackup(into, dp, '/')) = 0;
			if (dp == into)
				strcpy(into, "/"), dp = into + 1;
		} else {
			if (into[strlen(into) - 1] != '/')
				strcat(into, "/");
			strcat(into, file);
		}
		file = sp + 1;
	} while (sp != 0);
}

static
getpwf(file, realpath)
char *file, *realpath;
{
	char buf[MAXPATHLEN], rpbuf[MAXPATHLEN];
	struct stat	stbuf;
	register char *rcp, *lname;

	rpbuf[0] = '\0';
	/* This may fail if getwd doesn't use lstat */
	if (*file != '/') {
		if (getwd(rpbuf) == NULL)
			return 0;
		strcat(rpbuf, "/");
	}
	rcp = rpbuf + strlen(rpbuf);
	while (1) {
		while (*file == '/') *rcp++ = *file++;
		*rcp = '\0';
		lname = buf;
		while (*file && *file != '/') *lname++ = *file++;
		*lname = '\0';
		if (lname == buf)
			break;
		strcpy(rcp, buf);
		if (lstat(rpbuf, &stbuf) < 0)
			return 0;
		if ((stbuf.st_mode & S_IFMT) == S_IFLNK) {
			int n = readlink(rpbuf, buf, sizeof buf);
			if (n <= 0) return 0;
			if (buf[0] == '/')
				rcp = rpbuf;
			lname = buf;
			while (n--) *rcp++ = *lname++;
			*rcp = '\0';
		} else
			while (*rcp) rcp++;
	}
	fcanon(rpbuf, realpath);
	return 1;
}

#ifdef sgi
/*
 * SGI's index() causes seg. faults for unknown reasons.
 */
char *
index(s, c)
	char *s;
{
	for ( ; *s; s++)
		if (*s == c)
			return s;
	return 0;
}
#endif
