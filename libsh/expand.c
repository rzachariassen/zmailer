/*
 *	Copyright 1989 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * Filename expansion (globbing) routines.  The expand() function is called
 * just before pushing an argv onto a command descriptor in the interpreter.
 * As a side-effect, multiple buffers are mashed into one, and word separation
 * using IFS characters is also done here.
 */

#include "hostenv.h"
#include <stdio.h>
#include <sys/file.h>
#include <sys/stat.h>

#ifdef HAVE_DIRENT_H
# include <dirent.h>
#else /* not HAVE_DIRENT_H */
# define dirent direct
# ifdef HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif /* HAVE_SYS_NDIR_H */
# ifdef HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif /* HAVE_SYS_DIR_H */
# ifdef HAVE_NDIR_H
#  include <ndir.h>
# endif /* HAVE_NDIR_H */
#endif /* HAVE_DIRENT_H */

#include "sh.h"
#include "flags.h"
#include "malloc.h"
#include "listutils.h"
#include "io.h"			/* redefines stdio routines */
#include "shconfig.h"

#include "libsh.h"

/*
 * For speed we look up magic characters (*, ?, and [) to check whether
 * a word requires filename globbing.  The globchars array contains such flags.
 */

char globchars[CHARSETSIZE];

/*
 * Initialize the array, called from main(), once.
 */

void
glob_init()
{
	int i;
	for (i = 0; i < CHARSETSIZE; ++i)
	  globchars[i] = 0;

	globchars['*'] = globchars['?'] = globchars['['] = 1;
	/* see also sJumpIfMatch in interpreter for globchars['|'] */
}

/*
 * Because the result of filename expansion must be presented in alphabetical
 * order, we have to keep the pathnames somewhere temporarily to do a qsort().
 * Since we don't know how many there will be, we maintain a linked list of
 * (struct sawpath), then turn that into an array that we can sort easily.
 */

struct sawpath {
	struct sawpath *next;
	char	array[1];	/* is really array[strlen(path)+1] */
};


STATIC int glut __((char *cwd, char *pwd, int *pb, int recur, struct sawpath **swp));

/*
 * Normally we don't want to descend into symlink'ed directories, but in
 * case you do, this is where you change it.  It is INADVISABLE to use
 * stat() since in that case a super-glob can lead to infinite recursion.
 */

#ifdef	HAVE_LSTAT
extern int lstat();
static int (*statfcn)() = lstat;	/* stat if following symlinks, o/w lstat */
#else	/* !HAVE_LSTAT */
extern int stat();
static int (*statfcn)() = stat;
#endif	/* HAVE_LSTAT */

/*
 * Qsort() comparison function to sort pathnames.
 */

int
pathcmp(ap, bp)
     const void *ap, *bp;
{
	register const void **a = (const void **)ap;
	register const void **b = (const void **)bp;

	return strcmp(*a, *b);
}

/* note that | is going to be used instead of / in some pathname examples */

/*
 * Super-glob.  This is exactly like glob except that the sequence: |**|
 * in a pathname will match any number of levels of directories.  Its an
 * old idea of mine so here's a wonderful opportunity to express myself within
 * the confines of sh!  The major thing to note is that quoted characters
 * do not qualify for globbing.  How does one know if a character is quoted?
 * Each character is stored in an int, the u_char value is obtained using
 * the BYTE() macro, and the quotedness is determined by the QUOTEBYTE bit
 * in the int.
 */

#define BYTE(X)		((X) & 0xFF)
#define	QUOTEBYTE	(0x8000)

STATIC conscell * sglob __((int *));

STATIC conscell *
sglob(ibuf)
	int *ibuf;	/* unglobbed pathname w/ each byte stored as int */
{
	register int i, n;
	conscell **pp, *cc;
	struct sawpath *spp;
	struct sawpath head;
	char	*pwd,		/* points to end of current directory in cwd */
		**base,		/* array of expanded filenames, for sorting */
		cwd[4096];	/* all pathnames are constructed in cwd */
	GCVARS1;

	if (BYTE(ibuf[0]) == '/') {
		cwd[0] = '/';
		pwd = cwd+1;
	} else if (BYTE(ibuf[0]) == '.' && BYTE(ibuf[1]) == '/') {
		cwd[0] = '.';
		cwd[1] = '/';
		pwd = cwd+2;
		ibuf += 2;
	} else
		pwd = cwd;

	*pwd = '\0';
	head.next = NULL;
	spp = &head;
	if (BYTE(ibuf[0]) != 0)
	  n = glut(cwd, pwd, ibuf, 0, &spp);	/* do expansion */
	else
	  goto leave;
	
	if (n <= 0)
	  goto leave;

#ifdef USE_ALLOCA
	base = (char **)alloca((sizeof (char *))*n);
#else
	base = (char **)malloc((sizeof (char *))*n);
#endif
	i = 0;
	for (spp = head.next; spp != NULL ; spp = spp->next)
		base[i++] = spp->array;
	qsort(base, n, sizeof base[0], pathcmp);
	/* construct a sorted linked list */
	cc = NULL;
	GCPRO1(cc);
	pp = &cc;
	for (i = 0; i < n; ++i) {
		int slen = strlen(base[i]);
		*pp = newstring(dupnstr(base[i],slen),slen);
		pp = &cdr(*pp);
		*pp = NULL;
		/* printf("saw %s\n", base[i]); */
	}
	UNGCPRO1;
#ifndef USE_ALLOCA
	free(base);
#endif
 leave:
	spp = head.next;
	while (spp != NULL) {
	  struct sawpath *spp2 = spp->next;
	  free(spp);
	  spp = spp2;
	}
	return cc;
}

/*
 * Utility function to append a pathname to a linked list for later sorting.
 */

STATIC struct sawpath * stash __((const void *, int, struct sawpath *));
STATIC struct sawpath *
stash(s, len, ps)
	const void *s;		/* the pathname we want to stash away */
	int len;		/* its length */
	struct sawpath *ps;	/* the previous list element */
{
	register struct sawpath *spp;
	
	spp = (struct sawpath *)malloc(sizeof (struct sawpath) + len);
	ps->next = spp;
	spp->next = NULL;
	memcpy(spp->array, s, len);
	spp->array[len] = 0;
	return spp;
}

STATIC int kleene[] = { '*', '/', 0 };	/* foo|**|  becomes foo|**|*| */

/*
 * This routine is the recursive workhorse of the filename globbing.
 */

static int
glut(cwd, pwd, bp, recur, swp)
	char	*cwd,		/* always the same buffer */
		*pwd;		/* pointer to end of directories/ inside cwd */
	int	*bp,		/* next character in the name to glob */
		recur;		/* flag: superglob mode, deep dir. descend */
	struct sawpath **swp;
{
	int	*start,		/* beginning of simple file name to expand */
		*eoname,	/* end of same */
		*ip,
		havepattern,	/* the simple file name contains glob chars */
		flag,		/* remember to put the trailing / on cwd back */
		count,		/* number of expansions */
		namlen,		/* filename length */
		i;
	struct stat stbuf;
	struct dirent *dp;
	DIR *dirp = NULL;
	
	if (interrupted)
		return 0;
	if (pwd > cwd+1) {
		*--pwd = '\0';
		flag = 1;
	} else
		flag = 0;
	/* printf("%s:\n", cwd); */
	/*
	 * must do stat since assuming opendir will
	 * fail on files might not be portable.
	 */
	if ((*cwd == '\0' && statfcn(".", &stbuf) < 0) ||
	    (*cwd != '\0' && statfcn(cwd, &stbuf) < 0) ||
	    (stbuf.st_mode & S_IFMT) != S_IFDIR)
		return -1;
again:
	while (*bp != '\0' && BYTE(*bp) == '/')
		++bp;
	if (*bp == '\0') {
		if (recur)	/* we're at the end of the road of a |**| */
			bp = kleene;
		else {
			*swp = stash(cwd, (pwd - cwd), *swp);
			return 1;
		}
	}
	if (*bp == '*' && *(bp+1) == '*' && BYTE(*(bp+2)) == '/') {
		recur = 1;	/* superglob mode */
		bp += 2;
		if (*(bp+1))
			goto again;
		else
			++bp;	/* start and eoname will point at 0 */
	}
	start = bp;
	while (*bp != '\0' && BYTE(*bp) != '/')
		++bp;
	eoname = bp;

	/*
	 * Now we have a local name between start and eoname, relative to
	 * the directory we have open. search through the directory for
	 * that name, then do the whole thing again, recursively.
	 */
	
	havepattern = count = 0;
	/* optimization... is it worth globbing in inner loop far below? */
	for (ip = start; ip < eoname; ++ip)
		if (*ip == '*' || *ip == '?' || *ip == '[') {
			havepattern = 1;
			break;
		}
	if ((*cwd == '\0' && (dirp = opendir(".")) == NULL) ||
	    (*cwd != '\0' && (dirp = opendir((char *)cwd)) == NULL)) {
		perror((char *)cwd);
		return 0;
	}
	if (flag) {
		*pwd++ = '/';
		*pwd = '\0';
	}

	/* major loop */

	for (dp = readdir(dirp); dp != NULL; dp = readdir(dirp)) {

		/* a * won't match .files */
		if (*start == '*' && start == eoname - 1
		    && dp->d_name[0] == '.')
			continue;

		/* if we can't match the simple name, forget it */
		if (!recur &&
		    glob_match(start, eoname, dp->d_name) == 0)
			continue;
		strcpy((char *)pwd, dp->d_name);
		namlen = strlen(dp->d_name);
		if (recur && !(dp->d_name[0] == '.' && (dp->d_name[1] == '\0'
			|| (dp->d_name[1] == '.' && dp->d_name[2] == '\0')))) {
			/* in superglob mode... glut returns -1 if is a file */
			i = glut(cwd, pwd+namlen+1, start, recur, swp);
			if (i >= 0) {
				count += i;
				strcpy((char *)pwd, dp->d_name);
				if (*start != 0 && start != kleene)
					continue;
				++count;
				*swp = stash(cwd, (int)((pwd+namlen)-cwd), *swp);
			}
		}
		if (*eoname == 0) {	/* end of the globbable name */
			/* we aren't interested in descending directories */
			if (!recur ||
			    glob_match(start, eoname, dp->d_name))
				++count,
				*swp = stash(cwd, (int)((pwd+namlen)-cwd), *swp);
		} else if (!recur) {
			/* we are only interested in directories */
			i = glut(cwd, pwd+namlen+1, eoname, recur, swp);
			count += (i > 0 ? i : 0);
		}
		if (recur || havepattern)
			continue;
		else
			break;
	}
#ifdef	BUGGY_CLOSEDIR
	/*
	 * Major serious bug time here;  some closedir()'s
	 * free dirp before referring to dirp->dd_fd. GRRR.
	 * XX: remove this when bug is eradicated from System V's.
	 */
	close(dirp->dd_fd);
#endif
	closedir(dirp);
	return count;
}

/*
 * This is a heavily recursive globbing function, it uses the string (which
 * is actually an int array as mentioned above) as a DFA that it interprets.
 * This routine should be kept in sync with the case-statement globbing
 * in the interpreter.  Unfortunately the requirements are different enough
 * that sharing code would be hard.
 */

int
glob_match(pattern, eopattern, s)
	register int	*pattern, *eopattern;
	register const char	*s;
{
	register int i, i2, sense;

	while (eopattern == NULL || pattern < eopattern) {
		switch (*pattern) {
		case '*':
			while (*pattern == '*')
				pattern++;
			do {
				if (glob_match(pattern, eopattern, s))
					return 1;
			} while (*s++ != '\0');
			return 0;
		case '[':
			if (*s == '\0')
				return 0;
			sense = (*(pattern+1) != '!');
			if (!sense)
			  ++pattern;
			while ((*++pattern != ']') && (*pattern != *s)) {
			  if (pattern == eopattern)
			    return !sense;
			  if (*(pattern+1) == '-'
			      && (i2 = BYTE(*(pattern+2))) != ']'
			      && i2 != 0) {
			    i2 = (i2 < 128) ? i2 : 127;
			    for (i = BYTE(*pattern)+1; i <= i2; i++)
			      if (i == *s) {
				if (sense)
				  goto ok;
				else
				  return 0;
			      }
			    pattern += 2;
			  }
			}
			if ((*pattern == ']') == sense)
				return 0;
ok:
			while (*pattern++ != ']')
				if (pattern == eopattern)
					return 0;
			s++;
			break;
		case '?':
			if (*s == '\0')
				return 0;
			s++;
			pattern++;
			break;
		case '\0':
			return (*s == '\0');
		default:
			if (BYTE(*pattern++) != *s++)
				return 0;
		}
	}
	return (*s == '\0');
}

/* 
 * Mash the linked list of buffers passed into a single buffer on return.
 */

int
squish(d, bufp, ibufp)
	conscell *d; /* input is protected */
	char **bufp;
	int **ibufp;
{
	register char *cp, *bp;
	register int *ip;
	register int sawglob, mask, len;
	register conscell *l;
	char *buf;
	int *ibuf;

	if ((LIST(d) || ISQUOTED(d)) && cdr(d) == NULL)
	  return -1;
	/* how much space will unexpanded concatenation of buffers take? */
	for (l = d, len = 0, sawglob = 0; l != NULL; l = cdr(l)) {
	  if (l->string == NULL)
	    continue;
	  cp = l->string;
	  if (!sawglob) {
	    while (*cp != '\0') {
	      if (globchars[BYTE(*cp)] != 0 &&
		  !(cp == d->string &&
		    *cp == '[' && *(d->string+1) == '\0')) {
		++sawglob;
		break;
	      }
	      ++cp;
	    }
	  }
	  while (*cp != '\0')
	    ++cp;
	  len += cp - l->string;
	}

	/* f option disables filename generation */
	sawglob = sawglob && !isset('f');
	if (!sawglob && cdr(d) == NULL) {
	  return -1;
	}

	/* allocate something large enough to hold integer per char */
	*bufp = buf = (char *)malloc((len+1)*(sawglob ? sizeof(int) : 1));
	*ibufp = ibuf = (int *)buf;

	for (l = d, bp = buf, ip = ibuf; l != NULL; l = cdr(l)) {
	  if (l->string) {
	    if (sawglob) {
	      /*
	       * Create int array with quoted characters
	       * marked by the QUOTEBYTE bit.
	       */
	      mask = ISQUOTED(l) ? QUOTEBYTE : 0;
	      for (cp = l->string; *cp != '\0'; ++cp) {
		if (*cp == '\\' && *(cp+1) != '\0')
		  *ip++ = BYTE(*++cp) | QUOTEBYTE;
		else
		  *ip++ = BYTE(*cp)   | mask;
	      }
	    } else if (ISQUOTED(l)) {
	      for (cp = l->string; *cp != '\0'; ++cp)
		*bp++ = *cp;
	    } else {
	      for (cp = l->string; *cp != '\0'; ++cp) {
		if (*cp == '\\' && *(cp+1) != '\0')
		  ++cp;
		*bp++ = *cp;
	      }
	    }
	  }
	}
	if (sawglob)
	  *ip = 0;
	else
	  *bp = '\0';
	return sawglob;
}

/*
 * Given a buffer list, check all non-quoted non-list portions for
 * file globbing characters and if relevant perform filename expansion.
 * The caller relies on the return value never being NULL.
 */

STATIC conscell * glob __((conscell *));
STATIC conscell *
glob(d)
	conscell *d;
{
	register char *bp;
	register int *ip;
	conscell *tmp;
	char *buf = NULL;
	int *ibuf;
	int s, slen;

	s = squish(d, &buf, &ibuf);
	switch (s) {
	case -1:
		/* if (buf) free(buf); -- no allocations; ever */
		return d;
	case 1:
		tmp = sglob(ibuf);
		if (tmp != NULL) {
		  free(buf);
		  return tmp;
		}
		for (bp = buf, ip = ibuf; *ip != '\0'; ++ip)
			*bp++ = BYTE(*ip);
		*bp = '\0';
		/* FALLTHROUGH */
		/* (re)filled the buffer, can throw away
		   the conscell chain in 'tmp'. */
	case 0:
		slen = strlen(buf);
		tmp = newstring(dupnstr(buf,slen),slen);
		free(buf);
		return tmp;
	}
	abort();
	/* NOTREACHED */
	return 0;
}


/*
 * This function is called with the unexpanded buffer contents (usually
 * a linked list of strings) just prior to it being added as a command
 * argument.  Expansion involves scanning unquoted strings for whitespace
 * (as defined by IFS) and breaking those apart into multiple argv's,
 * as well as filename globbing of the resulting unquoted strings.
 * The return value is a list of argv's.
 */

conscell *
expand(d)
	conscell *d; /* input protected */
{
	conscell *tmp, *head, *next, *orig;
	conscell *globbed = NULL, **pav;
	register char *cp;
	int slen, slen0;
	GCVARS6;

	tmp = head = next = orig = globbed = NULL;
	GCPRO6(tmp, head, next, orig, globbed, d);

	/* grindef("EXP = ", d); */

	d = s_copy_tree(d); /* this chain of data will be modified below! */
	orig = d;
	pav = &globbed;
	for (head = d; d != NULL; d = next) {
		if (head == NULL)
			head = d;
		next = cdr(d);
		if (LIST(d) || ISQUOTED(d)) {
			continue;
		} else if (ISELEMENT(d)) {
			if (head != d) {
				cdr(head) = NULL;
				*pav = glob(head);
				pav = &cdr(s_last(*pav));
			}
			head = NULL;
			d->flags &= ~ELEMENT;
			*pav = d;
			pav = &cdr(d);
			continue;
		}
		/* null strings should be retained */
		/* fprintf(stderr,"checking '%s'\n", d->string); */
		cp = d->string;
		slen = d->slen;
		if (head == d) {
			/* skip leading whitespace */
			char *p;
			while (slen > 0 && WHITESPACE(*cp)) ++cp, --slen;
			p    = dupnstr(cp,slen);
			/* UGLY replace-in-place code;
			   this 'freestr()' should not be
			   used outside  listmalloc.c! */
			if (ISNEW(d))
			  freestr(d->string,d->slen);
			d->string = p;
			d->slen   = slen;
			d->flags  = NEWSTRING;
			cp = p;
		}
		slen0 = slen;
		while (slen > 0) {
			if (WHITESPACE(*cp)) {
				/* can do this because stored data was copied */
				*cp++ = '\0';
				d->slen = (slen0 - slen);
				--slen;
				cdr(d) = NULL;
				/* wrap the stuff at head into its own argv */
				/* printf("wrapped '%s'\n", d->string); */
				*pav = glob(head);
				pav = &cdr(s_last(*pav));
				/* now find the continuation */
				while (slen > 0 && WHITESPACE(*cp))
					++cp, --slen;
				if (slen == 0) {
					head = NULL;
					break;
				} else {
					/* We have more non-white-space stuff
					   following */
					head = d = newstring(dupnstr(cp,slen),slen);
					cdr(head) = next;
					cp = d->string;
					slen0 = slen;
				}
			}
			++cp;
			--slen;
		}
	}

	if (head != NULL) {
		/* printf("trailing '%s'\n", head->string); */
		/* glob is guaranteed to not return NULL */
		*pav = glob(head);
		pav = &cdr(s_last(*pav));
	}
	*pav = NULL;

	UNGCPRO6;

	/* fprintf(stderr, "EXPLEN = %d ",globbed->slen);
	   grindef("EXPOUT = ", globbed); */

	return globbed;
}
