/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include "hostenv.h"
#ifdef	HAVE_INDEX
char *strchr(s,c)
	register char *s;
	register char c;
{
	return index(s,c);
}
#else /* No BSD index() available */

char *
strchr(s, c)
	register char *s;
	register char c;
{
	while (*s && *s != c)
		++s;
	return (*s == '\0' ? 0 : s);
}
#endif
