/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/* LINTLIBRARY */

#include "mailer.h"
#ifdef	HAVE_RESOLVER
#include <netdb.h>
#include "search.h"
#include "libz.h"
#include "libc.h"
#include "libsh.h"

/*
 * Search the hosts database file for a hostname alias.
 */

conscell *
search_hosts(sip)
	search_info *sip;
{
	struct hostent *hp;

	/* sethostent(1); */
	hp = gethostbyname(sip->key);
	if (hp == NULL)
		return NULL;
	return newstring(dupstr(hp->h_name));
}

/*
 * Print the database.
 */

void
print_hosts(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
#ifdef HAVE_GETHOSTENT
	char **cpp;
	struct hostent *hp;

	sethostent(1);
	while ((hp = gethostent()) != NULL) {
		hp_init(hp);
		fprintf(outfp, "%s\t%s", dottedquad(*hp_getaddr()), hp->h_name);
		for (cpp = hp->h_aliases; *cpp != NULL; ++cpp)
			fprintf(outfp, " %s", *cpp);
		putc('\n', outfp);
	}
	endhostent();
#else
	fprintf(outfp,
		"# router: the gethostent() routine is not available\n");
	fprintf(outfp, "127.0.0.1\tlocalhost\n");
#endif
	fflush(outfp);
}
#endif	/* HAVE_RESOLVER */
