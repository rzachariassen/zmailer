/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */
/*
 *	Matti E Aarnio 1994,1999-2001 -- write (new) multiline headers
 *	to the file.  This is part of the Zmailer
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

	  int allocsize = -1;
	  int chunkspace = 20;
	  if (*chunkbufp == NULL)
	    *chunkbufp = malloc( chunkspace );

	  for ( ; *msgheaders; ++msgheaders ) {
	    char *s = *msgheaders;
	    while (*s) {
	      char *p = strchr(s, '\n');
	      int linelen = p ? (p - s) : strlen(s);

	      p = hsize + (*chunkbufp);

	      if (*WriteTabs == '0') {
		/* Expand line TABs */
		int col = 0;

		for (; linelen > 0; --linelen, ++s) {
		  char c1 = *s;

		  allocsize = hsize + linelen + newlinelen + 8;
		  if (allocsize >= chunkspace) {
		    chunkspace = allocsize + 9;
		    *chunkbufp = realloc(*chunkbufp, chunkspace );
		    if (*chunkbufp == NULL) return -1;
		    p = hsize + (*chunkbufp);
		  }

		  if (c1 == '\t') {
		    int c2 = col + 8 - (col & 7);
		    while (col < c2) { /* 1 thru 8 loops */
		      *p = ' ';
		      ++p;
		      ++col;
		      ++hsize;
		    }
		  } else {
		    *p = c1;
		    ++p;
		    ++col;
		    ++hsize;
		  }
		}
	      }

	      allocsize = hsize + linelen + newlinelen + 8;
	      if (allocsize >= chunkspace) {
		chunkspace = allocsize + 9;
		*chunkbufp = realloc(*chunkbufp, chunkspace );
		if (*chunkbufp == NULL) return -1;
		p = hsize + (*chunkbufp);
	      }

	      if (linelen > 0)
		memcpy( p, s, linelen);
	      hsize += linelen;
	      p     += linelen;
	      s     += linelen;

	      memcpy( p, newline, newlinelen );
	      hsize += newlinelen;
	      p     += newlinelen;

	      /* New sub-line of the header ? */
	      if (*s == '\n') ++s;

	    } /* while in some header */
	  } /* for all headers */

	} else {

	  for (;*msgheaders && !sferror(fp); ++msgheaders) {
	    char *s = *msgheaders;
	    while (*s) {
	      char *p = strchr(s, '\n');
	      int linelen = p ? (p - s) : strlen(s);

	      if (*s == '.') {
		/* ALWAYS double-quote the beginning
		   dot -- though it should NEVER occur
		   in the headers, but better safe than
		   sorry.. */
		if (sfputc(fp,'.') < 0) {
		  return -1;
		}
	      }
	      if (*WriteTabs == '0') {
		/* Expand line TABs */
		int col = 0;
		for (; linelen > 0 && !sferror(fp); --linelen, ++s) {
		  if (*s == '\t') {
		    int c2 = col + 8 - (col & 7);
		    while (col < c2) {
		      if (sfputc(fp, ' ') < 0) return -1;
		      ++col;
		    }
		  } else {
		    if (sfputc(fp, *s) < 0) return -1;
		    ++col;
		  }
		}
	      }

	      /* Write the rest (or all) */
	      if (linelen > 0)
		if (sfwrite(fp, s, linelen) != linelen)
		  return -1;

	      hsize += linelen;
	      s     += linelen;

	      if (sfwrite(fp, newline, newlinelen) != newlinelen ||
		  sferror(fp))
		return -1;

	      hsize += newlinelen;

	      /* New sub-line of the header ? */
	      if (*s == '\n') ++s;
	    }
	  }
	}
	return hsize;
}
