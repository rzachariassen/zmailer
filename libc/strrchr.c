/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include "hostenv.h"
#ifdef	HAVE_RINDEX
char *strchr(s,c)
	register char *s;
	register char c;
{
	return rindex(s,c);
}
#else /* No BSD rindex() available */

char *
strrchr(s, c)
	register char *s;
	register char c;
{
	register char *ss;

	ss = 0;
	while (*s) {
		if (*s == c)
			ss = s;
		++s;
	}
	return ss;
}
#endif
