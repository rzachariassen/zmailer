/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */
/*
 *	A lot of changes all around over the years by Matti Aarnio
 *	<mea@nic.funet.fi>, copyright 1992-1997
 */

#include "hostenv.h"
#include <stdio.h>
#include <sys/param.h>
#include "zsyslog.h"

extern int errno;
extern const char *progname;

#ifdef HAVE_VPRINTF

#ifdef HAVE_STDARG_H
# include <stdarg.h>
#else
# include <varargs.h>
#endif

#include "ta.h"

#ifdef HAVE_STDARG_H
#ifdef __STDC__
void
warning(const char *fmt, ...)
#else /* Not ANSI-C */
void
warning(fmt)
	const char *fmt;
#endif
#else
/*VARARGS*/
void
warning(fmt, va_alist) /* ("fmtstr", remotemsg) */
	const char *fmt;
	va_dcl
#endif
{
	va_list	ap;
#ifdef HAVE_STDARG_H
	va_start(ap,fmt);
#else
	va_start(ap);
#endif
	
	if (progname != NULL)
	  fprintf(stderr, "# %s:%d: ", progname, (int)getpid());
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

#else /* No vfprintf() */
/*VARARGS*/
void
warning(fmt, arg, arg2, arg3, arg4)
	char *fmt, *arg, *arg2, *arg3, *arg4;
{
	static int isopen = 0;
	int e = errno; /* Save it over the openlog() .. */

	if (progname != NULL)
		(void) fprintf(stderr, "# %s:%d: ", progname, getpid());
	fprintf(stderr, fmt, arg, arg2, arg3, arg4);
	fprintf(stderr, "\n");
#if 0 /* Actually DON'T syslog this stuff! */
	if (!isopen) {
	  zopenlog(progname, 0, LOG_MAIL);
	}
	errno = e;
	zsyslog((LOG_ERR, fmt, arg, arg2, arg3, arg4));
#endif
}
#endif
