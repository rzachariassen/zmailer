/* emalloc.c: a couple localized routines */

#ifndef	MALLOC_TRACE

#include "hostenv.h"
#include "mailer.h"
#include "libz.h"
#include "libc.h"

/* for statistics in router/allocate.c */
extern int embytes;
extern int emcalls;
int emsleeptime = 60;

univptr_t
emalloc(len)
	size_t	len;
{
	univptr_t	r;

	while ((r = malloc(len)) == NULL) {
		fprintf(stderr,
			"%s[%d]: malloc(%u): virtual memory exceeded, sleeping\n",
			progname, (int)getpid(), (u_int)len);
		sleep(emsleeptime);
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
		fprintf(stderr,
			"%s[%d] realloc(%u): virtual memory exceeded, sleeping\n",
			progname, (int)getpid(), (u_int)len);
		sleep(emsleeptime);
	}
	return r;
}

#else
static void foo() {}
#endif /* MALLOC_TRACE */
