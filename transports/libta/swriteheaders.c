/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */
/*
 *	Matti E Aarnio 1994,1999 -- write (new) multiline headers to the file
 *      This is part of the Zmailer
 *
 *	TODO: auto-wrapping/widening of (continued) headers to given
 *	      width! That is, to enable to limit header width to 80
 *	      chars is such is needed somewhere (like BITNET)..
 *	(will do it with MIME-2 code -- always in 80 chars..)
 */

/* This has a CLOSE cousin:  fwriteheaders()
   with difference of only the fp argument!  */

#include "hostenv.h"
#include <sys/types.h>
#include <sys/stat.h>
#include "zmalloc.h"
#include "ta.h"

static char *WriteTabs = NULL;
extern char *getzenv();

int
swriteheaders(rp, fp, newline, convertmode, maxwidth, chunkbufp)
	struct rcpt *rp;
	Sfio_t *fp;
	const char *newline;
	CONVERTMODE convertmode;
	int maxwidth;
	char ** chunkbufp;
{
	char **msgheaders = *(rp->newmsgheader);
	int newlinelen = strlen(newline);
	int hsize = 0;

	if (! WriteTabs) {
	  WriteTabs = getzenv("RFC822TABS");
	  if (! WriteTabs)
	    WriteTabs = "0";
	}

	if (*(rp->newmsgheadercvt) != NULL)
	  msgheaders = *(rp->newmsgheadercvt);

	if (!msgheaders) return -1;

	if (chunkbufp) {
	  for ( ; *msgheaders; ++msgheaders ) {
	    char *s = *msgheaders;
	    char *p;
	    int linelen = strlen(s);

	    if (*WriteTabs == '0') {
	      /* Expand line TABs */
	      int col = 0;
	      for (; linelen > 0; --linelen, ++s) {
		if (*s == '\t')
		  col += 8 - (col & 7);
		else
		  ++col;
	      }
	      linelen = col;
	    }

	    if (*chunkbufp == NULL)
	      /* Actually the SMTP has already malloced a block,
		 thus this branch should not be needed ... */
	      *chunkbufp = malloc( hsize + linelen + newlinelen );
	    else
	      *chunkbufp = realloc(*chunkbufp, hsize + linelen + newlinelen );
	    if (*chunkbufp == NULL) return -1;

	    p = hsize + (*chunkbufp);

	    if (*WriteTabs == '0') {
	      /* Expand line TABs */
	      int col = 0;
	      for (; linelen > 0; --linelen, ++s) {
		if (*s == '\t') {
		  int c2 = col + 8 - (col & 7);
		  while (col < c2) {
		    *p++ = ' ';
		    ++col;
		  }
		} else {
		  ++col;
		  *p++ = *s;
		}
	      }
	    }

	    if (linelen > 0)
	      memcpy( p, s, linelen);
	    hsize += linelen;
	    p     += linelen;
	    memcpy( p, newline, newlinelen );
	    hsize += newlinelen;
	  }
	} else {
	  while (*msgheaders && !sferror(fp)) {
	    char *s = *msgheaders;
	    int linelen = strlen(s);
	    if (**msgheaders == '.')
	      /* sferror() not needed to check here.. */
	      sfputc(fp,'.'); /* ALWAYS double-quote the begining
				 dot -- though it should NEVER occur
				 in the headers, but better safe than
				 sorry.. */
	    if (*WriteTabs == '0') {
	      /* Expand line TABs */
	      int col = 0;
	      for (; linelen > 0 && !sferror(fp); --linelen, ++s) {
		if (*s == '\t') {
		  int c2 = col + 8 - (col & 7);
		  while (col < c2) {
		    sfputc(fp, ' ');
		    ++col;
		  }
		} else {
		  sfputc(fp, *s);
		  ++col;
		}
	      }
	    }

	    if (linelen > 0)
	      if (sferror(fp) || sfwrite(fp, s, linelen) != linelen)
		return -1;

	    hsize += linelen;
	    if (sferror(fp) || sfwrite(fp, newline, newlinelen) != newlinelen)
	      return -1;

	    ++msgheaders;
	  }
	}
#if 0 /* CHANGE: All transport agents must now write the blank line
	         separating headers, and the messagebody! */
	if (sfwrite(fp, newline, newlinelen) != newlinelen)
		return -1;
	hsize += newlinelen;
#endif
	return hsize;
}
