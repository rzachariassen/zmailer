/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/* customized routines to read in lines of potentially infinite length */

#include "hostenv.h"
#include "mailer.h"
#include <sys/file.h>
#ifndef NO_Z_IO_H
#include "../libsh/io.h"
#endif
#include "libz.h"

#ifndef	L_INCR
#define	L_INCR	1
#endif	/* L_INCR */

/*
 *  Returns the number of characters of the next line to be read. The line
 *  is pointed at by (char *)linebuf. This storage is part of a dynamically
 *  allocated buffer known only within this module. Code external to here
 *  should treat linebuf as a read-only (constant) buffer.
 */
static char	*getline_block = NULL;  /* malloc()'ed input buffer */
static char	*getline_bend;		/* end of line pointer */
static u_int	getline_blen;		/* bytes available to consume */
static u_int	getline_bsize;		/* size of malloc()'ed buffer */

char	*linebuf = NULL;	/* where to start consuming */

/*
 * This routine should be called between opening a file
 * and calling getline() for the first time on that file.
 */

void
initline(blksize)
	long blksize;
{
	if (getline_block == NULL) {
		getline_bsize = blksize;
		if (getline_bsize < BUFSIZ)
			getline_bsize = BUFSIZ;
		getline_block = (char *)emalloc(getline_bsize);
	}
	getline_blen = 0;
}

void
repos_getline(fp,newpos)
	FILE *fp;
	off_t newpos;
{
	getline_blen = 0;
	fseek(fp, newpos, 0);
}

/*
 * Return the number of bytes starting from linebuf, which make up a line.
 */

int
getline(fp)
	FILE *fp;
{
	register char	*cp;
	register u_int	n;

	/* assert getline_block != NULL */
	if (getline_blen == 0 ||
	    getline_bend >= (getline_block + getline_bsize)) {
	  getline_blen = fread(getline_block, 1, getline_bsize-1, fp);
	  if (getline_blen == 0) /* Error or EOF, never mind which */
	    return 0;
	  getline_bend = getline_block;
	}
	while (1) {
	  /* look for end of line in what remains of the input buffer */
	  for (cp = getline_bend, n = 0; n < getline_blen; ++n, ++cp)
	    if (*cp == '\n') {
	      linebuf = getline_bend;
	      getline_bend = ++cp;
	      getline_blen -= ++n;
	      return n;
	    }
	  /* copy the partial line to the beginning of the input buffer */
	  if (getline_bend > getline_block)
	    memcpy(getline_block, getline_bend, getline_blen);
	  /* get some more bytes which will hopefully contain a newline */
	  n = getline_bsize - getline_blen;
	  if (n <= 0) {		/* grow the buffer */
	    n = getline_bsize;
	    getline_bsize *= 2;
	    getline_block = (char *)erealloc(getline_block,
					     getline_bsize);
	  }
	  n = fread(getline_block + getline_blen, 1, n-1, fp);
	  if (n == 0) {
	    /* the file doesn't terminate in a newline */
	    n = getline_blen;
	    getline_blen = 0;
	    linebuf = getline_block;
	    return n;
	  }
	  getline_blen += n;
	  getline_bend = getline_block;
	}
	/* NOTREACHED */
}

/*
 * Return the number of bytes starting from linebuf, left in linebuf.
 * This is used to get the remaining bytes that have been read from the
 * file descriptor (and perhaps cannot be reread when the fp refers to
 * a pipe), to enable efficient copying of the rest of the data.
 */

int
linegetrest()
{
	/* assert getline_block != NULL */
	if (getline_blen <= 0 || getline_bend >= getline_block + getline_bsize)
		return 0;
	linebuf = getline_bend;
	return getline_blen;
}

/*
 *  Determine the position of linebuf in the open file described by fp.
 */

long
lineoffset(fp)
	FILE *fp;
{
	return ftell(fp) - getline_blen;
}
