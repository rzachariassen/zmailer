/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include <stdio.h>
#include "hostenv.h"
#include "mailer.h"
#include "libz.h"

/*
 * Abnormal death: blabber about why we are croaking, then die.
 */

extern char *progname;

void
die(status, message)
	int status;
	const char *message;
{
#ifdef	MALLOC_TRACE
	int i;

	for (i = 0; i < 10; ++i)
		memstats(i);
	mal_dumpleaktrace(stderr);
	/* mal_heapdump(stderr); */
	prsymtable();
#endif	/* MALLOC_TRACE */

	if (message != NULL) {
		fprintf(stderr, "%s: exit(%d): %s\n",
				progname, status, message);
	} else
		fprintf(stderr, "%s: exit(%d)\n", progname, status);
	exit(status);
}

