/*
 *	Copyright 1991 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include "hostenv.h"
#ifdef	USE_INET
#include <netdb.h>

/*
 * There is much confusion about how to refer to the addresses of a host
 * as described by a (struct hostent).  These routines encapsulate that
 * knowledge so that changes can be made in one place (here) for the
 * entire distribution.
 */

/* initialize state */

static char **alist;

void
hp_init(hp)
	struct hostent *hp;
{
#ifdef	h_addr
	alist = hp->h_addr_list;
#else	/* !h_addr  - presumably 4.2BSD or earlier */
	static char *fakealist[2];

	fakealist[0] = hp->h_addr;
	fakealist[1] = 0;
	alist = fakealist;
#endif	/* h_addr */
}

void
hp_setalist(hp, newalist)
	struct hostent *hp;
	char **newalist;
{
#ifdef	h_addr
	hp->h_addr_list = newalist;
#else	/* !h_addr  - presumable 4.2BSD or earlier */
	hp->h_addr = newalist[0];
#endif	/* h_addr */
}

char *
hp_getaddr()
{
	return *alist;
}

char *
hp_nextaddr()
{
	if (*alist == 0)
		return 0;
	return *++alist;
}
#endif	/* USE_INET */
