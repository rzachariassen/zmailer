/* Merged into Zmailer by Edwin Allum -- and a bit later with some
   modifications -- to make the compile optional -- by Matti Aarnio */

/*
 * V7-style file locking: try to link a temp file to "file.lock".
 *
 *	dotlock(char *file): returns 0 on success, -1/errno otherwise.
 *	dotunlock(char *file): same
 *
 * By Ken Lalonde, based loosely on code from mush and pine.
 */


/*
   #include <sys/types.h>
   #include <sys/param.h>
   #include <sys/stat.h>
   #include <sys/time.h>
   #include <fcntl.h>
   #include <errno.h>
 */

#define MAXLOCKAGE	(5*60)	/* locks older than this are broken (secs) */
#define SLEEP		1	/* interval between busy lock checks (secs) */
#define MAXFAIL		5	/* max # checks before we give up */


#ifndef HAVE_GETHOSTID
/*
 * Solaris 2.x equivalent of gethostid().
 * This should be configured in differently, but for
 * now this #if will do. 
 */
#if defined(sun) && defined(__svr4__)
#include <sys/systeminfo.h>

static int gethostid __((void));
static int gethostid()
{
	char buf[1024];

	sysinfo(SI_HW_SERIAL, buf, sizeof buf);
	return atoi(buf);
}
#endif
#endif

#if defined(HAVE_DOTLOCK) /* Well, we DO use DOTLOCK scheme! */

#ifndef HAVE_GETHOSTID
#ifdef __hpux
/*
 * From: dd@mv.us.adobe.com (David DiGiacomo)
 */

#define _INCLUDE_HPUX_SOURCE
#include <sys/utsname.h>

static long gethostid __((void));
static long gethostid()
{
        struct utsname uts;

        if (uname(&uts) < 0)
                return 0;

        return atoi(uts.idnumber);
}
#endif /* __hpux */
#endif

int dotlock __((const char *file));
int
dotlock(file)
	const char *file;
{
	char lockname[MAXPATHLEN];
	char temp[MAXPATHLEN];
	struct stat st;
	time_t now;
	int fd, i, fail = 0;

	sprintf(lockname, "%s.lock", file);
	sprintf(temp, "%s.L%x.%lx.%x",
		file, (int)getpid(), (long)time(NULL), (int)gethostid());
	unlink(temp);
	for (;;) {
		if ((fd = open(temp, O_WRONLY|O_CREAT|O_EXCL, 0666)) < 0)
			return -1;
		fchmod(fd, 0666);
		fstat(fd, &st);
		now = st.st_ctime;	/* fileserver's idea of current time */
		close(fd);
		/* Ignore return value of link, to work around NFS pain */
		link(temp, lockname);
		i = stat(temp, &st);
		unlink(temp);
		if (i == 0 && st.st_nlink == 2)
			return 0;
		/* If the lock is too old, remove it. */
		if (stat(lockname, &st) == 0 && st.st_ctime < now-MAXLOCKAGE &&
		    unlink(lockname) == 0)
			continue;
		if (++fail == MAXFAIL) {
			errno = EBUSY;		/* yuk */
			return -2;
		}
		sleep(SLEEP);
	}
}

int dotunlock __((const char *));
int
dotunlock(file)
	const char *file;
{
	char lockname[MAXPATHLEN];

	sprintf(lockname, "%s.lock", file);
	return unlink(lockname);
}


#else	/* we don't compile this piece.. */
static int foo = 0;
#endif
