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

/* This has a CLOSE cousin:  swriteheaders()
   with difference of only the fp argument!  */

#include "hostenv.h"
#include <sys/types.h>
#include <sys/stat.h>
#include "zmalloc.h"
#include "ta.h"

static char *WriteTabs = NULL;
extern char *getzenv();

int
fwriteheaders(rp, fp, newline, convertmode, maxwidth, chunkbufp)
	struct rcpt *rp;
	FILE *fp;
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
	      /* Actually the SMTP has already malloced a block */
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
	  while (*msgheaders && !ferror(fp)) {
	    char *s = *msgheaders;
	    int linelen = strlen(s);
	    if (*s == '.')
	      fputc('.', fp); /* ALWAYS double-quote the beginning
				 dot -- though it should NEVER occur
				 in the headers, but better safe than
				 sorry.. */
	    if (*WriteTabs == '0') {
	      /* Expand line TABs */
	      int col = 0;
	      for (; linelen > 0 && !ferror(fp); --linelen, ++s) {
		if (*s == '\t') {
		  int c2 = col + 8 - (col & 7);
		  while (col < c2) {
		    putc(' ', fp);
		    ++col;
		  }
		} else {
		  putc(*s, fp);
		  ++col;
		}
	      }
	    }

	    /* Write the rest (or all) */
	    if (linelen > 0)
	      if (fwrite(s, 1, linelen, fp) != linelen)
		return -1;

	    hsize += linelen;
	    if (ferror(fp) ||
		fwrite(newline, 1, newlinelen, fp) != newlinelen) {
	      return -1;
	    }
	    ++msgheaders;
	  }
	}
#if 0 /* CHANGE: All transport agents must now write the blank line
	         separating headers, and the messagebody! */
	if (fwrite(newline, 1, newlinelen, fp) != newlinelen)
		return -1;
	hsize += newlinelen;
#endif
	return hsize;
}
