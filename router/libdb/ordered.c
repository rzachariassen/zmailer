/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/* LINTLIBRARY */

#include "mailer.h"
#include <stdio.h>
#include <sys/file.h>
#include <ctype.h>
#include "search.h"
#ifdef	HAVE_MMAP
#include <sys/mman.h>
#endif
#include <errno.h>

#include "libz.h"
#include "libc.h"
#include "libsh.h"

extern int deferit;
extern char *skip821address __((char *));

#ifdef HAVE_MMAP
extern void seq_remap __((struct file_map *, long newsize));
extern char *mfgets __((char *, int, struct file_map *));
#endif

extern struct spblk * _open_seq __((search_info *, const char *));

/*
 * Binary search of a file for keyword-value pairs.
 */

conscell *
search_bin(sip)
	search_info *sip;
{
	FILE *fp;
	register char *s;
	off_t	top, bot;
	int	i, retry;
	conscell *tmp;
	struct spblk *spl;
	struct file_map *fm;
#ifdef	HAVE_MMAP
	/* This  fstat()  for possible seq_remap() trigger causes a bit
	   more syscalls, than is really necessary.   Therefore it is
	   likely best to have "-m" option on the relation definitions
	   and live with that -- relation information does not pass to
	   the low-level drivers, thus these drivers don't know about
	   possible upper-level "-m"..					*/
#define NO_SEQREMAP
#ifndef NO_SEQREMAP
	struct stat fst;
#endif
#endif
	char fixbuf[BUFSIZ];

	if (sip->file == NULL)
	  return NULL;

	retry = 0;

 reopen:
	spl = _open_seq(sip, "r");

	if (spl == NULL)
	  return NULL;

	fm = (struct file_map *)(spl->data);

	if (fm == NULL)
	  return NULL; /* Huh !? */

	fp = fm->fp;

#ifdef	HAVE_MMAP
	/* This  fstat()  for possible seq_remap() trigger causes a bit
	   more syscalls, than is really necessary.   Therefore it is
	   likely best to have "-m" option on the relation definitions
	   and live with that -- relation information does not pass to
	   the low-level drivers, thus these drivers don't know about
	   possible upper-level "-m"..					*/
#ifndef NO_SEQREMAP
	if (fstat(FILENO(fp),&fst) < 0) abort(); /* Will succeed, or crash.. */
	if (fst.st_mtime != fm->mtime ||
	    fst.st_size  != fm->size) {
		/* Changes at the original file, remap.. */
		seq_remap(fm,fst.st_size);
	}
#endif
	fm->pos = 0;	/* We have it mmap()ed incore, collect line
			   start offsets into an array for latter use
			   on searches..				*/
	if (fm->size > 0 && fm->lines == 0 && fm->offsets == NULL) {
	  int linecnt = 0;
	  const char *buf = fm->membuf;
	  const char *eof = fm->membuf + fm->size;

	  for (;buf < eof; ++buf)
	    if (*buf == '\n')
	      ++linecnt;
	  buf = fm->membuf;
	  fm->offsets = (off_t*)emalloc(sizeof(off_t)*(linecnt+1));
	  linecnt = 0;
	  while (buf < eof) {
	    fm->offsets[linecnt] = (buf - (const char*)fm->membuf);
	    while (buf < eof && *buf != '\n') ++buf;
	    ++buf; /* Skip over the newline */
	    ++linecnt;
	  }
	  fm->lines = linecnt;
	}

	top = fm->lines-1;
	bot = 0;
	while (bot <= top) {
	  off_t mid = (top + bot) / 2;
	  char *cp;

	  fm->pos = fm->offsets[mid];
	  if (mfgets(fixbuf, sizeof (fixbuf), fm) == NULL) return NULL;
		
	  cp = skip821address(fixbuf);

	  if (*cp == '\0')
	    *(cp+1) = '\0';
	  else
	    *cp = '\0';
	  i = cistrcmp(sip->key, fixbuf);
	  if (i == 0) {
	    for (++cp; *cp; ++cp) {
	      int c = (*cp) & 0xFF;
	      if (isascii(c) && !isspace(c))
		break;
	    }
	    for (s = cp; *s != '\0'; ++s) {
	      int c = (*s) & 0xFF;
	      if (!isascii(c) || isspace(c))
		break;
	    }
	    return newstring(strnsave(cp, (u_int)(s - cp)));
	  }
	  if (i < 0)
	    top = mid - 1;
	  else
	    bot = mid + 1;
	}
#endif

#ifndef	HAVE_MMAP
	bot = 0;
	fseek(fp, 0L, 2);	/* EOF */
	top = ftell(fp);
	for (;;) {
	  off_t mid = (top + bot)/2;
	  char *cp;
	  int c;

	  fseek(fp, mid, 0);
	  do {
	    c = getc(fp);
	    mid++;
	  } while (!ferror(fp) && c != EOF && c != '\n');

	  if (fgets(fixbuf, sizeof fixbuf, fp) == NULL) {
	    if (!retry && ferror(fp)) {
	      close_seq(sip);
	      ++retry;
	      goto reopen;
	    }
	    break;
	  }

	  cp = skip821address(fixbuf);

	  if (*cp == '\0')
	    *(cp+1) = '\0';
	  else
	    *cp = '\0';
	  i = cistrcmp(sip->key, fixbuf);
	  if (i < 0) {
	    if(top <= mid)
	      break;
	    top = mid;
	  } else if (i == 0) {
	    for (++cp; *cp; ++cp) {
	      int c = (*cp) & 0xFF;
	      if (isascii(c) && !isspace(c))
		break;
	    }
	    for (s = cp; *s != '\0'; ++s) {
	      int c = (*cp) & 0xFF;
	      if (!isascii(c) || isspace(c))
		break;
	    }
	    return newstring(strnsave(cp, s - cp));
	  } else
	    bot = mid;
	}
	fseek(fp, bot, 0);
	while (ftell(fp) < top) {
	  char *cp;

	  if (fgets(fixbuf, sizeof fixbuf, fp) == NULL)
	    return NULL;
	  for (cp = fixbuf; *cp; ++cp) {
	    int c = (*cp) & 0xFF;
	    if (!isascii(c) || isspace(c))
	      break;
	  }
	  if (*cp == '\0')
	    *(cp+1) = '\0';
	  else
	    *cp = '\0';
	  i = cistrcmp(sip->key, fixbuf);
	  if (i < 0)
	    return NULL;
	  else if (i == 0) {
	    for (++cp; *cp; ++cp) {
	      int c = (*cp) & 0xFF;
	      if (isascii(c) && !isspace(c))
		break;
	    }
	    for (s = cp; *s != '\0'; ++s) {
	      int c = (*s) & 0xFF;
	      if (!isascii(c) || isspace(c))
		break;
	    }
	    return newstring(strnsave(cp, s - cp));
	  }
	}
#endif
	return NULL;
}

