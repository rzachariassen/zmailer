#include "hostenv.h"
#ifndef HAVE_STRCSPN
/*
 * The following is provided for those people who do not have strcspn() in
 * their C libraries.  They should get off their butts and do something
 * about it; at least one public-domain implementation of those (highly
 * useful) string routines has been published on Usenet.
 */

/*
 * strcspn - find length of initial segment of s1 consisting entirely
 * of characters not from s2
 */

int
strcspn(s1, s2)
char *s1;
char *s2;
{
	register char *scan1;
	register char *scan2;
	register int count;

	count = 0;
	for (scan1 = s1; *scan1 != '\0'; scan1++) {
		for (scan2 = s2; *scan2 != '\0';)	/* ++ moved down. */
			if (*scan1 == *scan2++)
				return(count);
		count++;
	}
	return(count);
}
#else
static int dummy = 0;
#endif
