/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */
/*
 *	Matti E Aarnio 1994 -- write (new) multiline headers to the file
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

int
fwriteheaders(rp, fp, newline, convertmode, maxwidth, chunkbufp)
	struct rcpt *rp;
	FILE *fp;
	const char *newline;
	int convertmode, maxwidth;
	char ** chunkbufp;
{
	char **msgheaders = *(rp->newmsgheader);
	int newlinelen = strlen(newline);
	int hsize = 0;

	if (*(rp->newmsgheadercvt) != NULL)
	  msgheaders = *(rp->newmsgheadercvt);

	if (!msgheaders) return -1;

	if (chunkbufp) {
	  for ( ; *msgheaders; ++msgheaders ) {
	    int linelen = strlen(*msgheaders);
	    if (*chunkbufp == NULL) {
	      /* Actually the SMTP has already malloced a block */
	      *chunkbufp = emalloc(hsize+linelen+newlinelen);
	    } else {
	      *chunkbufp = erealloc(*chunkbufp, hsize+linelen+newlinelen);
	    }
	    if (*chunkbufp == NULL) {
	      return -1;
	    }
	    memcpy( hsize + (*chunkbufp), *msgheaders, linelen );
	    hsize += linelen;
	    memcpy( hsize + (*chunkbufp), newline, newlinelen );
	    hsize += newlinelen;
	  }
	} else {
	  while (*msgheaders && !ferror(fp)) {
	    int linelen = strlen(*msgheaders);
	    if (**msgheaders == '.')
	      fputc('.', fp); /* ALWAYS double-quote the begining
				 dot -- though it should NEVER occur
				 in the headers, but better safe than
				 sorry.. */
	    if (fwrite(*msgheaders, 1, linelen, fp) != linelen) {
	      return -1;
	    }
	    hsize += linelen;
	    if (fwrite(newline, 1, newlinelen, fp) != newlinelen) {
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
