/*
 *	Copyright 1994-1998 Matti Aarnio, all rights reserved.
 *	This module is a part of Zmailer, and subject to its
 *	distribution rules.
 */


#include "hostenv.h"
#include "libz.h"

#include <sfio.h>
#include <sys/types.h>

#if defined(HAVE_SETRLIMIT) && !defined(_AIX)
/* AIX 4.2.1 has "funny" RLIMIT_NOFILE return value: RLIM_INFINITY ..
   Earlier AIXes don't have RLIMIT_NOFILE resource, thus lets not let
   AIX to use  setrlimit()  even when it exists.. */

/* ================================================================== */

#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>

/* #include "prototypes.h" */ /* Scheduler's prototypes */

int resources_query_nofiles()
{
#ifdef	RLIMIT_NOFILE
	struct rlimit rl;
	int rc;

	rc = getrlimit(RLIMIT_NOFILE,&rl);
	if (rc == 0 && rl.rlim_cur > 10)
	    return rl.rlim_cur;
	else
	  return getdtablesize();
#else
	return sysconf(_SC_OPEN_MAX);
#endif
}

void
resources_maximize_nofiles()
{
#ifdef	RLIMIT_NOFILE		/* Linuxes pre 1.2 (1.3?) don't have this..*/
	struct rlimit rl;
	int rc;

	rc = getrlimit(RLIMIT_NOFILE,&rl);
	if (rc != 0) return;
	rl.rlim_cur = rl.rlim_max;
	setrlimit(RLIMIT_NOFILE,&rl);
#endif
}

void
resources_limit_nofiles(nfiles)
int nfiles;
{
#ifdef	RLIMIT_NOFILE
	struct rlimit rl;
	int rc;

	rc = getrlimit(RLIMIT_NOFILE,&rl);
	if (rc != 0) return;
	rl.rlim_cur = nfiles;
	setrlimit(RLIMIT_NOFILE,&rl);
#endif
}

#else
#ifdef HAVE_SYSCONF
/* ================================================================ */

#include <unistd.h>
int
resources_query_nofiles()
{
	return sysconf(_SC_OPEN_MAX);
}

void
resources_maximize_nofiles()
{
}

void
resources_limit_nofiles(nfiles)
int nfiles;
{
}

#else
/* ================================================================ */

int
resources_query_nofiles()
{
	return getdtablesize();
}

void
resources_maximize_nofiles()
{
}

void
resources_limit_nofiles(nfiles)
int nfiles;
{
}

#endif
#endif

#ifdef HAVE_FPATHCONF
int
resources_query_pipesize(fildes)
int fildes;
{
	return (int) fpathconf(fildes, _PC_PIPE_BUF);
}
#else
int
resources_query_pipesize(fildes)
int fildes;
{
	return 4096;	/* pipe buffer size (max contents before blocking) */
}
#endif
