/*
 *  cfgets() -- A routine for Zmailer  libz.a -library.
 *
 *  Count how many chars are stored into the buffer, EOF if
 *  failed...
 *
 *  By Matti Aarnio <mea@utu.fi> on 26-Sep-94
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

	while (n > 0) {
	  register int c = sfgetc(stream);
	  if (c != EOF) {
	    *s++ = c;
	    ++cnt;
	    --n;
	    if (c == '\n') {
	      if (n > 0) *s = 0;
	      break;
	    }
	  } else {
	    if (cnt == 0)
	      return EOF;
	    if (n > 0) *s = 0; /* Zero terminate it! */
	    break;
	  }
	}
	return cnt;
}
