/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include "hostenv.h"
#include "mailer.h"
#include <fcntl.h>
#include "zmsignal.h"
#include "libz.h"

/*
 * Reopen the log files, done at daemon startup, and when you want to roll over
 * the log files by doing a kill -HUP `cat .pid.router`.  The result of calling
 * this routine should be that stdout and stderr are attached to the same output
 * stream (for now anyway).
 * XX: possibly too much done inside a signal handler?
 */

extern char *progname;
extern char *logfn;

/* RETSIGTYPE */ int
loginit(sig)
     int sig;
{
	int flags;

	if (logfn == NULL)
		return -1;
	fflush(stdout);
	rewind(stdout);
	fflush(stderr);
	rewind(stderr);
	if (freopen(logfn, "a+", stdout) != stdout
	    || dup2(FILENO(stdout), FILENO(stderr)) < 0) {	/* sigh */
		/* XX: stderr might be closed at this point... */
		fprintf(stderr, "%s: cannot open log: %s\n", progname, logfn);
		return -1;
	}
#if	defined(F_SETFL) && defined(O_APPEND)
	flags = fcntl(FILENO(stdout), F_GETFL, 0);
	flags |= O_APPEND;
	fcntl(FILENO(stdout), F_SETFL, flags);
#endif	/* F_SETFL */
	setvbuf(stdout, (char *)NULL, _IOLBF, 0);
	freopen(logfn, "a", stderr);
	setvbuf(stderr, (char *)NULL, _IOLBF, 0);
	SIGNAL_HANDLE(sig, (RETSIGTYPE(*)())loginit);
	return 0;
}
