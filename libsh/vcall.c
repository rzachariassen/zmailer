/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/* 940626/mea: Nobody uses this ? */

#include "hostenv.h"
#ifdef HAVE_STDARG_H
# include <stdarg.h>
#else
# include <varargs.h>
#endif

/* called as vcall(builtin, argc, argv[0], argv[1], ...) */

int
#ifdef HAVE_STDARG_H
#ifdef __STDC__
vcall(int (*func)(), int argc, ...)
#else /* Non ANSI-C */
vcall(func, argc)
	int (*func)();
	int argc;
#endif
#else
vcall(func, argc, va_alist)	
	int (*func)();
	int argc;
	va_dcl
#endif
{
	int argc, i;
	va_list ap;
#ifdef	USE_ALLOCA
	char **argv = (char **)alloca(sizeof(char *) * (argc+2));
#else
	char *argv[100];		/* XXX */
#endif

#ifdef HAVE_STDARG_H
	va_start(ap, argc);
#else
	va_start(ap);
#endif
	for (i = 0; i < argc; ++i)
		argv[i++] = va_arg(ap, char *);
	va_end(ap);
	argv[i] = NULL;
	return (*func)(argc, argv);
}
