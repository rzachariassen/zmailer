/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/* LINTLIBRARY */

#include "mailer.h"
#include <stdio.h>
#include <sys/file.h>
#include <ctype.h>
#include <fcntl.h>
#include "search.h"
#include "io.h"
#include "libz.h"
#include "libc.h"
#include "libsh.h"

#ifdef	HAVE_MMAP
#include <sys/mman.h>
#endif
#include <errno.h>

extern int deferit;
extern char *skip821address __((char *));

#ifdef HAVE_MMAP
extern void seq_remap __((struct file_map *, long newsize));
extern char *mfgets __((char *, int, struct file_map *));
#endif

/*
 * Linear search of a file for keyword-value pairs.
 */

extern struct spblk * _open_seq __((search_info *, const char *));

conscell *
search_seq(sip)
	search_info *sip;
{
	FILE *fp;
	register char *cp, *s;
	conscell *tmp;
	struct spblk *spl;
	int retry;
	char buf[BUFSIZ];
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
#ifndef NO_SEQREMAP
	if (fstat(FILENO(fp),&fst) < 0) abort(); /* Will succeed, or crash.. */
	if (fst.st_mtime != fm->mtime ||
	    fst.st_size  != fm->size) {
		/* Changes at the original file, remap.. */
		seq_remap(fm,fst.st_size);
	}
#endif
	fm->pos = 0;
	while ((s = mfgets(buf, sizeof buf, fm)) != NULL)
#else
	fseek(fp, (off_t)0, 0);
	while ((s = fgets(buf, sizeof buf, fp)) != NULL)
#endif
	{
		buf[sizeof buf - 1] = '\0';

		cp = skip821address(buf);

		if (*cp == '\0')
			*(cp+1) = '\0';
		else
			*cp = '\0';
		if (cistrcmp(sip->key, buf) == 0) {
			for (++cp; *cp; ++cp)
			  if (isascii((*cp)&0xFF) && !isspace((*cp)&0xFF))
			    break;
			for (s = cp; *s != '\0'; ++s)
			  if (!isascii((*s)&0xFF) || isspace((*s)&0xFF))
			    break;
			return newstring(strnsave(cp, s - cp));
		}
	}
	if (!retry && ferror(fp)) {
		close_seq(sip);
		++retry;
		goto reopen;
	}

	return NULL;
}

/*
 * Flush buffered information from this database, close any file descriptors.
 */

void
close_seq(sip)
	search_info *sip;
{
	struct file_map *fm;
	struct spblk *spl;
	spkey_t symid;

	if (sip->file == NULL)
		return;

	symid = symbol_db(sip->file, spt_files->symbols);
	spl = sp_lookup(symid, spt_modcheck);
	if (spl != NULL)
		sp_delete(spl, spt_modcheck);
	spl = sp_lookup(symid, spt_files);

	if (spl == NULL || (fm = (struct file_map *)spl->data) == NULL)
		return;	/* nothing to flush */
	spl->data = NULL;	/* Delete the file-entry */
	fclose(fm->fp);
#ifdef	HAVE_MMAP
	/* We are throwing things away... */
	if (fm->membuf != NULL)
	  munmap((void*)fm->membuf,fm->size);
#endif
	if (fm->offsets != NULL)
	  free(fm->offsets);
	free(fm);
}


struct spblk *
_open_seq(sip, mode)
	search_info *sip;
	const char *mode;
{
	struct file_map *fm;
	struct spblk *spl;
	spkey_t symid;
	int imode;
#ifdef	HAVE_MMAP
	struct stat fst;
#endif

	if (sip->file == NULL)
		return NULL;

	symid = symbol_db(sip->file, spt_files->symbols);
	spl = sp_lookup(symid, spt_files);
	if (spl != NULL
	    && (*mode == 'w' || *mode == 'a'
		|| (*mode == 'r' && *(mode+1) == '+'))
	    && spl->mark != O_RDWR) {
		close_seq(sip);
		imode = O_RDWR;
	} else
		imode = O_RDONLY;
	if (spl == NULL || (fm = (struct file_map *)spl->data) == NULL) {
		FILE *fp;
		int i;
		for (i = 0; i < 3; ++i) {
		  fp = fopen(sip->file, mode);
		  if (fp != NULL)
		    break;
		  sleep(1); /* Retry a few times */
		}
		if (fp == NULL) {
			++deferit;
			v_set(DEFER, DEFER_IO_ERROR);
			fprintf(stderr,
				"add_seq: cannot open %s mode \"%s\"!\n",
				sip->file, mode);
			return NULL;
		}
		fm = (struct file_map *)emalloc(sizeof(struct file_map));
		fm->fp = fp;
#ifdef	HAVE_MMAP
		fstat(FILENO(fm->fp),&fst);
		fm->size = fst.st_size;
		fm->mtime = fst.st_mtime;
		fm->lines = 0;
		fm->offsets = NULL;
		if (fm->size)
		  fm->membuf = (void*)mmap(NULL, fst.st_size,
					   PROT_READ, MAP_SHARED,
					   FILENO(fm->fp), 0);
		else
		  fm->membuf = NULL;
#else
		fm->size   = 0;
		fm->mtime  = 0;
		fm->lines = 0;
		fm->offsets = NULL;
		fm->membuf = NULL;
#endif
		if (spl == NULL) {
			sp_install(symid, (void *)fm, imode, spt_files);
			spl = sp_lookup(symid, spt_files);
		} else
			spl->data = (void *)fm;
	}
	return spl;
}

static FILE *
open_seq(sip, mode)
	search_info *sip;
	const char *mode;
{
	struct file_map *fm;
	struct spblk *spl;

	spl = _open_seq(sip, mode);

	if (spl == NULL)
	  return NULL;

	fm = (struct file_map *)(spl->data);

	if (fm == NULL)
	  return NULL; /* Huh !? */

	return (fm->fp);
}


/*
 * Add the indicated key/value pair to the list.
 */

int
add_seq(sip, value)
	search_info *sip;
	const char *value;
{
	FILE *fp;
	int rc;

	fp = open_seq(sip, "r+");
	if (fp == NULL)
		return EOF;
	fseek(fp, (off_t)0, 2);
	if (value == NULL || *value == '\0')
		fprintf(fp, "%s\n", sip->key);
	else
		fprintf(fp, "%s\t%s\n", sip->key, value);
	rc = fflush(fp);
	close_seq(sip);
	return rc;
}

/*
 * Print the database.  This is equivalent to listing the file and so it
 * can be used by the other text-reading database types, e.g. search_bin().
 */

void
print_seq(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	FILE *fp;
	int n;
	char buf[BUFSIZ];

	fp = open_seq(sip, "r");
	if (fp == NULL)
		return;

	fseek(fp, (off_t)0, 0);
	while ((n = fread( buf, 1, sizeof buf, fp )) > 0)
	  fwrite(buf, 1, n, outfp );
	fflush(outfp);
}

/*
 * Count the database.  This is equivalent to listing the file and so it
 * can be used by the other text-reading database types, e.g. search_bin().
 */

void
count_seq(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	FILE *fp;
	int n;
	char buf[BUFSIZ];
	int cnt = 0;

	fp = open_seq(sip, "r");
	if (fp != NULL) {
#ifdef HAVE_MMAP_not
	  struct file_map *fm;
	  spkey_t symid     = symbol_db(sip->file, spt_files->symbols);
	  struct spblk *spl = sp_lookup(symid, spt_files);
	  int cnt;

	  if (spl == NULL) { /* XX: HOW ?? We have the file open! */
	    abort();
	  }
	  fm = (struct file_map *)spl->data;

	  if (fm->size > 0 && fm->lines == 0) /* not yet counted ? */ {
	    char *p   =     fm->membuf;
	    char *eop = p + fm->size;
	    for (;p < eop; ++p)
	      if (*p == '\n')
		++cnt;
	    fm->lines = cnt;
	  }
	  cnt = fm->lines;
#else
	  /* Essentially: 'wc -l' -- count newlines */

	  fseek(fp, (off_t)0, 0);
	  while ((n = fread(buf, 1, sizeof buf, fp)) > 0) {
	    while (n >= 0) {
	      if (buf[n] == '\n') ++cnt;
	      --n;
	    }
	  }
#endif
	}
	fprintf(outfp,"%d\n",cnt);
	fflush(outfp);
}

void
owner_seq(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	FILE *fp;
	struct stat stbuf;

	if (sip->file == NULL)
		return;
	fp = open_seq(sip, "r");
	if (fp == NULL)
		return;

	if (fstat(FILENO(fp), &stbuf) < 0) {
		fprintf(stderr, "owner_seq: cannot fstat(\"%s\")!\n",
			sip->file);
		return;
	}
	fprintf(outfp, "%d\n", stbuf.st_uid);
	fflush(outfp);
}

int
modp_seq(sip)
	search_info *sip;
{
	FILE *fp;
	struct stat stbuf, stbuf2;
	struct spblk *spl;
	spkey_t symid;
	int rval;

	if (sip->file == NULL)
		return 0;
	fp = open_seq(sip, "r");
	if (fp == NULL)
		return 0;

	if (stat(sip->file, &stbuf) < 0 ||
	    fstat(FILENO(fp), &stbuf2) < 0) {
		fprintf(stderr, "modp_seq: cannot fstat(\"%s\")!\n",
				sip->file);
		return 0;
	}

	if (stbuf.st_ino != stbuf2.st_ino)
		return 1; /* The name, and the FD point to different files! */
	if (stbuf2.st_nlink == 0) /* Changed underneath of us! */
		return 1;

	symid = symbol_db(sip->file, spt_files->symbols);
	spl = sp_lookup(symid, spt_modcheck);
	if (spl != NULL) {
		rval = ((long)stbuf.st_mtime != (long)spl->data ||
			(long)stbuf.st_nlink != (long)spl->mark);
	} else
		rval = 0;
	sp_install(symid, (void *)((long)stbuf.st_mtime),
		   stbuf.st_nlink, spt_modcheck);
	return rval;
}

#ifdef HAVE_MMAP
#ifndef NO_SEQREMAP
void
seq_remap(fm,newsize)
struct file_map *fm;
long newsize;
{
	if (fm->membuf != NULL)
	  munmap(fm->membuf, fm->size);
	if (newsize)
	  fm->membuf = (void*)mmap(NULL, newsize,
				   PROT_READ, MAP_SHARED, FILENO(fm->fp), 0);
	else
	  fm->membuf = NULL;
	fm->size = newsize;
	if (fm->offsets != NULL)
	  free(fm->offsets);
	fm->offsets = NULL;
	fm->lines = 0;
}
#endif

char *
mfgets(buf,bufsize,fm)
char *buf;
int bufsize;
struct file_map *fm;
{
	const char *eof = fm->membuf + (int) fm->size;
	const char *s   = fm->membuf + (int) fm->pos;
	char *b   = buf;
	int i;

	if (fm->size == 0) return NULL; /* no buffer mapped.. */
	if (s >= eof)      return NULL; /* EOF.. */

	for (i = 0; *s != '\n' && s < eof && i < bufsize; ++i)
		*b++ = *s++;
	if (*s == '\n' && s < eof && i < bufsize)
		*b++ = *s, ++i;
	if (b < eof)
		*b = 0; /* We may have space for this, if not.. */
	fm->pos += i;
	return buf;
}
#endif


/* Indirect mappings -- like  aliases -- use this */

conscell * readchunk __((const char *, long));
conscell *
readchunk(file, foffset)
	const char *file;
	long foffset;
{
	FILE *fp;
	register char *cp;
	char *as;
	conscell *tmp, *l;
	struct spblk *spl;
	int retry, flag, len;
	spkey_t symid;
	char buf[BUFSIZ];
	struct file_map *fm;
	int i;

	if (file == NULL || foffset < 0)
		return NULL;
	
	retry = 0;
	symid = symbol_db(file, spt_files->symbols);
	spl = sp_lookup(symid, spt_files);
	if (spl == NULL || (fm = (struct file_map *)spl->data) == NULL) {
reopen:
		for (i = 0; i < 3; ++i) {
		  fp = fopen(file, "r");
		  if (fp != NULL)
		    break;
		  sleep(1);
		}
		if (fp == NULL) {
			++deferit;
			v_set(DEFER, DEFER_IO_ERROR);
			fprintf(stderr, "search_seq: cannot open %s!\n", file);
			return NULL;
		}
		fm = (struct file_map*)emalloc(sizeof(struct file_map));
		/* No MMAP() of this data! */
		fm->fp = fp;
		fm->size   = 0;
		fm->mtime  = 0;
		fm->lines = 0;
		fm->offsets = NULL;
		fm->membuf = NULL;
		if (spl == NULL)
		  spl = sp_install(symid, (void *)fm,
				   O_RDONLY, spt_files);
		else
		  spl->data = (void *)fm;
	}
	fp = fm->fp;

	if (fseek(fp, (off_t)foffset, 0) != 0) {
		++deferit;
		v_set(DEFER, DEFER_IO_ERROR);
		fprintf(stderr,
			"indirect postprocessor: bad seek (%ld) on '%s'!\n",
			(long)foffset, file);
		return NULL;
	}

	len = 0;
	flag = 0;
	buf[sizeof(buf) - 1] = '\0';
	while (fgets(buf, sizeof(buf)-1, fp) != NULL) {
		/* tab and space are valid continuation characters */
		if (flag && buf[0] != '\t' && buf[0] != ' ')
			break;
		if (buf[sizeof buf - 1] == '\0')
			len += strlen(buf)-1;
		else if (buf[sizeof buf - 1] == '\n')
			len += sizeof buf - 1;
		else
			len += sizeof buf;
		flag = 1;
	}

	if (fseek(fp, (off_t)foffset, 0) != 0) {
		++deferit;
		v_set(DEFER, DEFER_IO_ERROR);
		fprintf(stderr,
			"indirect postprocessor: bad seek (%ld) on '%s'!\n",
			(long)foffset, file);
		return NULL;
	}

	cp = as = tmalloc(len+1);
	l = NULL;
	flag = 0;
	buf[sizeof buf - 1] = '\0';
	while (fgets(buf, sizeof buf, fp) != NULL) {
		/* printaliases (actually hdr_print()) prints lines < 80 char */

		if (buf[0] == '\t')
			buf[0] = ' ';
		else if (flag && buf[0] != ' ')
			break;

		if (buf[sizeof buf - 1] == '\0') {
			len = strlen(buf)-1;
			strncpy((char *)cp, buf, len);
			cp += len;
		} else if (buf[sizeof buf - 1] == '\n') {
			strncpy((char *)cp, buf, sizeof buf - 1);
			cp += sizeof buf - 1;
		} else {
			strncpy((char *)cp, buf, sizeof buf);
			cp += sizeof buf;
		}
		flag = 1;
	}
	if (cp > as) {
		*cp = 0;
		l = newstring(as);
	}
	if (!retry && ferror(fp)) {
		if (l != NULL) {
			if (stickymem == MEM_MALLOC)
				s_free_tree(l);
			l = NULL;
		}
		fclose(fp);
		free(fm);
		spl->data = NULL;
		++retry;
		goto reopen;
	}

	return l;
}
