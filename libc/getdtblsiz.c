/*
 * getdtablesize -- call getrlimit, or ...
 */

#include "hostenv.h"
#include "libc.h"

#if !defined(HAVE_GETDTABLESIZE)
#if defined(HAVE_SYS_RESOURCE_H)

#include <sys/resource.h>
getdtablesize()
{
        struct rlimit res;
        int stat;
#ifdef	RLIMIT_NFILE /* Usually _POSIX_SOURCE, but also some others.. */
        stat = getrlimit(RLIMIT_NFILE, &res);
#else	/* Of BSD fame.. */
        stat = getrlimit(RLIMIT_NOFILE, &res);
#endif
        if (stat < 0) return(-1);
        return(res.rlim_cur);
}

#else
#ifdef HAVE_SYSCONF

#include <unistd.h>

int
getdtablesize()
{
	return sysconf(_SC_OPEN_MAX);
}

#else /* Brr... what ever... */
int
getdtablesize()
{
	return 256; 
}
#endif
#endif
#endif
