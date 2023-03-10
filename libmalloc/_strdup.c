/*  Author: Mark Moraes <moraes@csri.toronto.edu> */

/*LINTLIBRARY*/

#include "defs.h"
#include "globals.h"
#include "trace.h"

RCSID("$Id: _strdup.c,v 1.2 1999/12/29 19:37:35 mea Exp $")

#ifdef __strdup
#undef __strdup
#endif

char *
___strdup(s, fname, linenum)
char *s;
const char *fname;
int linenum;
{
	char *cp;
	
	PRTRACE(sprintf(_malloc_statsbuf, "%s:%d:", fname, linenum));
	cp = strdup(s);
	RECORD_FILE_AND_LINE((univptr_t) cp, fname, linenum);
	return(cp);
}
