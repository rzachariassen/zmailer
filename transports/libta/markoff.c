/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include "hostenv.h"
#include <stdio.h>
#include <sysexits.h>
#include "mail.h"

#include "ta.h"

int
markoff(filecontents, bytesleft, offsets, filename)
	char	*filecontents;
	int	bytesleft;
	long	offsets[];
	const char * filename;
{
	register char *s, *eoc;
	int	n;

	eoc = filecontents + bytesleft;	/* 1 beyond last valid character */
	/* go through the file and mark it off */
	offsets[0] = 0L;
	for (n = 0, s = filecontents; s < eoc ; ++s) {
	    if (*s == '\n') {
	        *s++ = '\0';
		if (s < eoc) {
		    offsets[++n] = s - filecontents;
		    if (*s == _CF_MSGHEADERS) {
			/* terminate at a \n\n combination */
			while (s+1 < eoc) {
			    if (*s == '\n' && *(s+1) == '\n')
				break;
			    else
				++s;
			}
			if (s+1 >= eoc) {
			    /* header ran off file */
			    warning("bytesleft: %d",
				    eoc - s);
			    warning("Premature EOF in %s!",
				    filename);
			    return -1;
			}
		    }
		}
	    }
	}
	return ++n;
}
