/*
 *  cfgets() -- A routine for Zmailer  libz.a -library.
 *
 *  Count how many chars are stored into the buffer, EOF if
 *  failed...
 *
 *  By Matti Aarnio <mea@utu.fi> on 26-Sep-94
 */

#include "mailer.h"
#include "libz.h"

int cfgets(s, n, stream)
	char *s;
	int n;
	FILE *stream;
{
	register int cnt = 0;

	while (n > 0) {
	  register int c = getc(stream);
	  if (c != EOF) {
	    *s++ = c;
	    ++cnt;
	    --n;
	    if (c == '\n')
	      break;
	  } else {
	    if (cnt == 0)
	      return EOF;
	    break;
	  }
	}
	return cnt;
}
