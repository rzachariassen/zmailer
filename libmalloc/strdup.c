/*  Author: Mark Moraes <moraes@csri.toronto.edu> */

/*LINTLIBRARY*/

#include "defs.h"

RCSID("$Id: strdup.c,v 1.2 1999/12/29 19:37:35 mea Exp $")

/* 
 *  makes a copy of a null terminated string in malloc'ed storage.
 *  returns null if it fails.
 */
#ifdef strdup
#undef strdup
#endif

char *
strdup(s)
const char *s;
{
	char *cp;

	if (s) {
		cp = (char *) malloc((unsigned) (strlen(s)+1));
		if (cp)
			(void) strcpy(cp, s);
	} else
		cp = (char *) NULL;
	return(cp);
}
