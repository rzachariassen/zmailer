/*
 *  cfgets() -- A routine for Zmailer  libz.a -library.
 *
 *  Count how many chars are stored into the buffer, EOF if
 *  failed...
 *
 *  By Matti Aarnio <mea@utu.fi> on 26-Sep-94, 2001
 */

#include "mailer.h"

#include <stdio.h>
#ifndef FILE /* Some systems don't have this as a MACRO.. */
# define FILE FILE
#endif
#include <sfio.h>


#include "libz.h"


int csfgets(s, n, stream)
	char *s;
	int n;
	Sfio_t *stream;
{
	register int cnt = 0;
	char *eob = s + n-1;
	register int c = EOF;

	--n; /* Pre-shrink by one, thus will always have space
		for zero-termination at the EOB */
	while (n > 0) {
	  c = sfgetc(stream);
	  if (c != EOF) {
	    if (s < eob)
	      *s = c;
	    ++s;
	    ++cnt;
	    --n;
	    if (c == '\n')
	      break;
	  } else {
	    if (cnt == 0) {
	      *s = 0;
	      return EOF;
	    }
	    break;
	  }
	}

	/* If EOF/'\n' not reached, but buffer is full,
	   should we collect input until either if reached ? */

	if (s > eob)
	  *eob = 0;
	else
	  *s = 0;

	return cnt;
}
