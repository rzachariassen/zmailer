/*
 *	Copyright 1991 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/* With  getaddrinfo() these routines are going to be junked... */

#include "mailer.h"
#ifdef	HAVE_NETDB_H
#include <netdb.h>
#include "libz.h"

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
	void **newalist;
{
#ifdef	h_addr
	hp->h_addr_list = (char **) newalist;
#else	/* !h_addr  - presumable 4.2BSD or earlier */
	hp->h_addr      = (char *) newalist[0];
#endif	/* h_addr */
}

char **
hp_getaddr()
{
	return alist;
}

char **
hp_nextaddr()
{
	if (*alist == NULL)
		return NULL;
	return ++alist;
}

void
hp_addr_randomize(hp)
	struct hostent *hp;
{
	char **oalist = alist;
	int cnt = 0, i, j;
	hp_init(hp);
	while (*alist++ != 0) ++cnt;
	alist = oalist;
	if (cnt < 2) return;
	hp_init(hp);
	for (i = 0; i < cnt; ++i) {
	  char *tmpp;
	  j = ranny(cnt-1);
	  tmpp = alist[i];
	  alist[i] = alist[j];
	  alist[j] = tmpp;
	}
	alist = oalist;
}

#endif	/* HAVE_NETDB_H */
