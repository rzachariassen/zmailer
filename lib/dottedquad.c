/*
 *	Copyright 1991 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include "hostenv.h"
#ifdef	HAVE_NETINET_IN_H
#include <netinet/in.h>

/*
 * This does the same thing inet_ntoa() does, except it takes a pointer
 * argument.  This avoids problems with structure passing conventions being
 * different between different compilers.  The function is small enough that
 * it was easiest to just ignore the C library inet_ntoa() entirely.
 */

char *
dottedquad(inp)
	struct in_addr *inp;
{
	static char buf[44];
	unsigned char *cp = (unsigned char *)inp;

	sprintf(buf, "%d.%d.%d.%d", *(cp), *(cp+1), *(cp+2), *(cp+3));
	return buf;
}
#endif	/* USE_INET */
