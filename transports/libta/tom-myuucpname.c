/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include <stdio.h>
#include "hostenv.h"

int
getmyuucpname(namebuf, len)
	char *namebuf;
	int len;
{
	char	*c;
	int	r;

	/*
	 * Check environment for UUCP name first
	 */
	if ((c = getenv("UUNAME"))) {
		strncpy(namebuf, c, --len);
		namebuf[len] = '\0';
		return 0;
	}

	/*
	 * Try gethostbyname() and lop off everthing after the first '.'
	 */
	if ( (r = gethostname(namebuf, len)) == 0) {
		namebuf[--len] = '\0';
		if ((c = strchr(namebuf, '.'))) {
			*c = '\0';
		}
	}
	return r;

}
