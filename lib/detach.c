#include "hostenv.h"
#include "mailer.h"
#include "libz.h"
#include "libc.h"
#include "zmsignal.h"
#include <fcntl.h>
#include <sys/ioctl.h>
#ifdef	HAVE_SETRLIMIT
#include <sys/resource.h>
#endif	/* HAVE_SETRLIMIT */
#ifdef __linux__
#include <linux/limits.h>
#endif
#ifdef	USE_NOFILE
#include <sys/param.h>
#endif	/* USE_NOFILE */

/*
 * Detach a daemon process from whoever/whatever started it.
 * Mostly lifted from an article in the July/August 1987 ;login:,
 * by Dave Lennert (hplabs!hpda!davel). Blame bugs on me. - rayan
 */

extern void cleanenv __((void));

void
detach()
{
	/*
	 * If launched by init (process 1), there's no need to detach.
	 *
	 * Note: this test is unreliable due to an unavoidable race
	 * condition if the process is orphaned.
	 */
	if (getppid() == 1)
		goto out;
	/* Ignore terminal stop signals */
#ifdef	SIGTTOU
	SIGNAL_IGNORE(SIGTTOU);
#endif	/* SIGTTOU */
#ifdef	SIGTTIN
	SIGNAL_IGNORE(SIGTTIN);
#endif	/* SIGTTIN */
#ifdef	SIGTSTP
	SIGNAL_IGNORE(SIGTSTP);
#endif	/* SIGTSTP */
	/*
	 * Allow parent shell to continue.
	 * Ensure the process is not a process group leader.
	 */
	if (fork() != 0)
		exit(0);	/* parent */
	/* child */
	/*
	 * Disassociate from controlling terminal and process group.
	 *
	 * Ensure the process can't reacquire a new controlling terminal.
	 * This is done differently on BSD vs. AT&T:
	 *
	 *	BSD won't assign a new controlling terminal
	 *	because process group is non-zero.
	 *
	 *	AT&T won't assign a new controlling terminal
	 *	because process is not a process group leader.
	 *	(Must not do a subsequent setpgrp()!)
	 */
#ifdef	HAVE_SETSID
	if (fork() != 0)
		exit(0);	/* setsid() can be called only once per proc. */
	setsid();
#else	/* !HAVE_SETSID */
#ifdef HAVE_GETPGRP
#ifdef GETPGRP_VOID /* POSIX.1 style */
	/* lose controlling terminal and change process group */
	setpgrp();
	SIGNAL_IGNORE(SIGHUP);	/* immune from pgrp leader death */
	if (fork() != 0)	/* become non-pgrp-leader */
	  exit(0);	/* first child */
	/* second child */
#else /* BSD style */
	{
	  int fd = open("/dev/tty", O_RDWR, 0);
	  if (fd >= 0) {
	    ioctl(fd, TIOCNOTTY, 0);	/* lose controlling terminal */
	    close(fd);
	  }
	}
	setpgrp(0, getpid());	/* change process group */
#endif	/* GETPGRP_VOID */
#endif	/* HAVE_GETPGRP */
#endif	/* !HAVE_SETSID */

out:
#if	0
	close(0);
	{
	  int fd;
	  for (fd = 3; fd < getdtablesize(); ++fd)
	    close(fd);	/* close almost all file descriptors */
	}
#endif	/* notdef */
	umask(022); /* clear any inherited file mode creation mask */

	/* Clean out our environment from personal contamination */
	cleanenv();

#if defined(HAVE_SETRLIMIT) && defined(RLIMIT_CPU)
	/* In case this place runs with cpu limits, remove them */
	{	struct rlimit rl;
		rl.rlim_cur = RLIM_INFINITY;
		rl.rlim_max = RLIM_INFINITY;
		setrlimit(RLIMIT_CPU, &rl);
	}
#endif	/* HAVE_SETRLIMIT */
	return;
}

/* Debugging stuff.. */
extern int countfds __((void));
int countfds()
{
  int fds = getdtablesize();
  int i;
  int cnt = 0;

  for (i=0; i<fds; ++i)
    if (fcntl(i,F_GETFL) >= 0)
      ++cnt;

  return cnt;
}
