/*
 *	Copyright 1989 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *	Some subfunctions Copyright 1991-2001 Matti Aarnio.
 */

/*
 * This is the builtin "test" command.  It is implemented by a shunting
 * yard algorithm.  Pretty standard stuff, but hard to follow.
 */

#include "hostenv.h"
#include <stdio.h>
#include <ctype.h>
#include <sys/stat.h>
#include "io.h"
#include "shconfig.h"

#include "listutils.h"
#include "libsh.h"

int test_debug = 0;

static int testeval __((const char **avp[], const int ignoreferrs));
static int tellme   __((const char **avp[], int));

#define dprintf		if (test_debug) printf

STATIC const char *testprogname;

STATIC int testgv[20];		/* shunting-yard stack (operand values) */
STATIC int testgc = -1;		/* top of said stack */

STATIC short prec[CHARSETSIZE];

/*
 * Shunting yard galore.
 */

STATIC int testparse __((const char **avp[], int ignoreferrs));
STATIC int
testparse(avp,ignoreferrs)
	const char **avp[];
	int ignoreferrs;
{
	int	c;
	const char **av;

	dprintf("testparse:");
	for (av = *avp; *av != NULL; av++)
		dprintf(" %s", *av);
	dprintf("\n");

	if (**avp == NULL)
		return 0;
	c = (**avp)[0] & 0xFF;
	switch (c) {
	case '(':
		++*avp;
		testparse(avp,ignoreferrs);
		if (**avp != NULL && (**avp)[0] == ')') {
			++*avp;
		} else
			goto err;
		break;
	case ')':
		break;
	case '!':
		++*avp;
		if (**avp == NULL || prec[(**avp)[0] & 0xFF])
			goto err;
		testparse(avp,ignoreferrs);
		if (testgc < 0) goto err;
		testgv[testgc] = !testgv[testgc];
		dprintf("[%d] = ![%d] = %d\n", testgc, testgc, testgv[testgc]);
		testparse(avp,ignoreferrs);
		break;
	case '-':
		switch ((**avp)[1]) {
		case 'a':
			++*avp;
			dprintf("-a: **avp = %p (**avp)[0] = '%c'\n",
				**avp, **avp ? ((**avp)[0] & 0xFF) : '\277');
			if (**avp == NULL || prec[(**avp)[0] & 0xFF])
				goto err;
			ignoreferrs |= !testgv[testgc];
			testparse(avp,ignoreferrs);
			if (**avp != NULL &&
			    (testgc < 1 || !prec[(**avp)[0] & 0xFF]))
				goto err;

			while (**avp != NULL &&
			       prec[(**avp)[0] & 0xFF] > prec[c]) {
				ignoreferrs |= !testgv[testgc];
				testparse(avp,ignoreferrs);
			}
			testgv[testgc - 1] &= testgv[testgc];
			testgc--;
			dprintf("[%d] &= [%d] = %d\n",
				      testgc, testgc + 1, testgv[testgc]);
			break;
		case 'o':
			++*avp;
			dprintf("-o: **avp = %p (**avp)[0] = '%c'\n",
				**avp, **avp ? ((**avp)[0] & 0xFF) : '\277');
			if (**avp == NULL || prec[(**avp)[0] & 0xFF])
			  goto err;
			ignoreferrs |= testgv[testgc];
			testparse(avp,ignoreferrs);
			dprintf("-o2: **avp = %p (**avp)[0] = '%c'\n",
				**avp, **avp ? ((**avp)[0] & 0xFF) : '\277');
			if (**avp != NULL &&
			    (testgc < 1 || !prec[(**avp)[0] & 0xFF]))
				goto err;
			while (**avp != NULL &&
			       prec[(**avp)[0] & 0xFF] > prec[c]) {
				ignoreferrs |= testgv[testgc];
				testparse(avp,ignoreferrs);
			}
			testgv[testgc - 1] |= testgv[testgc];
			testgc--;
			dprintf("[%d] |= [%d] = %d\n",
				      testgc, testgc + 1, testgv[testgc]);
			break;
		default: /* push value onto stack */
			testgv[++testgc] = testeval(avp, ignoreferrs);
			if (testgv[testgc] < 0)
				goto err;
			dprintf("[%d] = %d\n", testgc, testgv[testgc]);
			break;
		}
		break;
	default: /* push value onto stack */
		testgv[++testgc] = testeval(avp, ignoreferrs);
		if (testgv[testgc] < 0)
			goto err;
		dprintf("[%d] = %d\n", testgc, testgv[testgc]);
		break;
	}
	return 0;
err:
	fprintf(stderr, "%s: %s:", testprogname, TEST_SYNTAX_ERROR);
	while (**avp) {
		fprintf(stderr, " %s", **avp);
		++*avp;
	}
	fprintf(stderr, "\n");
	testgv[testgc] = 0;
	return 1;
}

STATIC int fildes __((char **avp[]));
STATIC int
fildes(avp)
	char **avp[];
{
	int fd;

	if (**avp != NULL && isdigit((unsigned char)(***avp)))
		fd = atoi(**avp), ++*avp;
	else
		fd = 1;
	return isatty(fd);
}

STATIC int strng __((char **avp[], int));
STATIC int
strng(avp, i)
	char **avp[];
	int i;
{
	int len;
	
	if (**avp == NULL) abort(); /* calling convention error! */
	len = strlen(**avp);
	++*avp;
	return (i ? (!len) : len);
}

#ifdef HAVE_LSTAT
#if defined(sun) && !defined(__SVR4__)
extern int lstat(/*const char *, struct stat* */);
#endif
#endif

STATIC struct flags {
	char	flag;
	int	(*func)();
	int	i1,i2,i3;
} flarr[] = {
#ifdef	USG
{ 'f',	stat,	0,		S_IFMT,		S_IFREG			},
#else	/* BSD */
{ 'f',	stat,	0,		S_IFMT,		S_IFMT&~S_IFDIR		},
#endif	/* USG */
{ 'd',	stat,	0,		S_IFMT,		S_IFDIR			},
{ 's',	stat,	1,		~0,		~0			},
#ifdef	S_IRUSR
{ 'r',	stat,	0,		~S_IFMT,	S_IRUSR|S_IRGRP|S_IROTH	},
{ 'w',	stat,	0,		~S_IFMT,	S_IWUSR|S_IWGRP|S_IWOTH	},
{ 'x',	stat,	0,		~S_IFMT,	S_IXUSR|S_IXGRP|S_IXOTH	},
#else	/* !S_IRUSR */
{ 'r',	stat,	0,		~S_IFMT,	0x444			},
{ 'w',	stat,	0,		~S_IFMT,	0x222			},
{ 'x',	stat,	0,		~S_IFMT,	0x111			},
#endif	/* S_IRUSR */
#ifdef	HAVE_LSTAT
{ 'h',	lstat,	0,		S_IFMT,		S_IFLNK			},
#endif	/* HAVE_LSTAT */
{ 'b',	stat,	0,		S_IFMT,		S_IFBLK			},
{ 'c',	stat,	0,		S_IFMT,		S_IFCHR			},
#ifdef	S_IFIFO
{ 'p',	stat,	0,		S_IFMT,		S_IFIFO			},
#endif	/* S_IFIFO */
{ 'u',	stat,	0,		~S_IFMT,	S_ISUID			},
{ 'g',	stat,	0,		~S_IFMT,	S_ISGID			},
{ 'k',	stat,	0,		~S_IFMT,	S_ISVTX			},
{ 't',	fildes,	0,		0,		0			},
{ 'l',	strng,	0,		~0,		~0			},
{ 'n',	strng,	0,		~0,		~0			},
{ 'z',	strng,	1,		~0,		~0			},
};

#define	N1	(int)(value < 0 ? atoi(cp) : value)
#define N2	(int)(strcmp(*(*avp+1), "-l") == 0 && *(*avp+2) != NULL ? \
		       ++*avp, strlen(*(*avp+1)) : atoi(*(*avp+1)))

/*
 * Complicated operand evaluation.
 */

static int
testeval(avp, ignoreferrs)
	const char **avp[];
	const int ignoreferrs;
{
	register const char *cp;
	int	i, value = -1;
	const char *av1, *av2;

	cp = (*avp)[0];
	dprintf("testeval: %s (%d)\n", cp, value);
	++*avp;
	if (*cp == '-' && *(cp+1) != '\0') {
		++cp;
		for (i = 0; i < sizeof flarr / sizeof flarr[0]; ++i) {
			if (*cp == flarr[i].flag) {
				value = tellme(avp, i);
				if (*cp != 'l')
					goto gotvalue;
				break;
			}
		}
	}
	av1 = (*avp)[0];
	av2 = (*avp)[1];
	dprintf("    : %s (%d) av1=%p av2=%p\n", cp, value, av1, av2);
	if (value < 0 && av1 != NULL && av2 != NULL
		   && strcmp(av1, "=") == 0) {
		value = !strcmp(cp, av2);
		*avp += 2;
	} else if (value < 0 && av1 != NULL && av2 != NULL
		   && strcmp(av1, "!=") == 0) {
		value = strcmp(cp, av2);
		*avp += 2;
	} else if (av1 != NULL && av2 != NULL
		   && strcmp(av1, "-eq") == 0) {
		value = (N1 == N2);
		*avp += 2;
	} else if (av1 != NULL && av2 != NULL
		   && strcmp(av1, "-ne") == 0) {
		value = (N1 != N2);
		*avp += 2;
	} else if (av1 != NULL && av2 != NULL
		   && strcmp(av1, "-gt") == 0) {
		value = (N1 > N2);
		*avp += 2;
	} else if (av1 != NULL && av2 != NULL
		   && strcmp(av1, "-ge") == 0) {
		value = (N1 >= N2);
		*avp += 2;
	} else if (av1 != NULL && av2 != NULL
		   && strcmp(av1, "-lt") == 0) {
		value = (N1 < N2);
		*avp += 2;
	} else if (av1 != NULL && av2 != NULL
		   && strcmp(av1, "-le") == 0) {
		value = (N1 <= N2);
		*avp += 2;

	} else if (av1 != NULL && av2 != NULL
		   && strcmp(av1, "-nt") == 0) {

	  struct stat stb1, stb2;

	  if (stat(av2, &stb2) != 0) {
	    if (!ignoreferrs) {
	      fprintf(stderr,"%s:  '%s' stat failed on right of '-nt'\n",
		      testprogname, av2);
	      return -1;
	    } else
	      /* So what if it failed ! */
	      stb2.st_mtime = 0;
	  }
	  if (stat(cp,  &stb1) != 0) {
	    if (!ignoreferrs) {
	      fprintf(stderr,"%s:  '%s' stat failed on left of '-nt'\n",
		      testprogname, cp);
	      return -1;
	    } else
	      /* IgnoredFErrs means this is always true.. */
	      stb1.st_mtime = stb2.st_mtime + 1;
	  }
	  value = (stb1.st_mtime > stb2.st_mtime);
	  *avp += 2;

	} else if (av1 != NULL && av2 != NULL
		   && strcmp(av1, "-ot") == 0) {

	  struct stat stb1, stb2;
	  if (stat(cp,  &stb1) != 0) {
	    if (!ignoreferrs) {
	      fprintf(stderr,"%s: '%s' stat failed on left of '-ot'\n",
		      testprogname, cp);
	      return -1;
	    }
	    stb1.st_mtime = 0;
	  }
	  if (stat(av2,  &stb2) != 0) {
	    if (!ignoreferrs) {
	      fprintf(stderr,"%s: '%s' stat failed on right of '-ot'\n",
		      testprogname, av2);
	      return -1;
	    }
	    stb2.st_mtime = stb1.st_mtime + 1;
	  }
	  value = (stb1.st_mtime < stb2.st_mtime);
	  *avp += 2;

	} else if (av1 != NULL && av2 != NULL
		   && strcmp(av1, "-ef") == 0) {

	  struct stat stb1, stb2;
	  if (stat(cp,  &stb1) != 0 ||
	      stat(av2, &stb2) != 0) {
	    if (!ignoreferrs) {
	      fprintf(stderr,"%s: either '%s' or '%s' stat failed around '-ef'\n",
		      testprogname, cp, av2);
	      return -1;
	    }
	    value = 0;
	  } else
	    value = ((stb1.st_ino == stb2.st_ino) &&
		     (stb1.st_dev == stb2.st_dev));
	  *avp += 2;


	} else if (av1 == NULL) {
		fprintf(stderr, "%s: argument expected\n", testprogname);
		return -1;
	} else if (av2 == NULL) {
		fprintf(stderr, "%s: unknown operand '%s'\n", testprogname, cp);
		return -1;
	} else
		value = (*cp != '\0');
gotvalue:
#if 0
	if (av1 != NULL && av1[0] == ']' && av1[1] == '\0')
		++*avp;
#endif
	return value != 0;
}

static int
tellme(avp, i)
	const char **avp[];
	int i;
{
	struct stat stbuf;

	if (flarr[i].func == stat
#ifdef	HAVE_LSTAT
	    || flarr[i].func == lstat
#endif	/* HAVE_LSTAT */
	    ) {
		if ((flarr[i].func)(**avp, &stbuf) < 0) {
			++*avp;
			return 0;
		}
		++*avp;
		if (flarr[i].i1)
			return ((int)stbuf.st_size > 0);
		return stbuf.st_mode & flarr[i].i2 & flarr[i].i3;
	}
	return (flarr[i].func)(avp, flarr[i].i1, flarr[i].i2, flarr[i].i3);
}

/*
 * test(1).
 */

int
sh_test(argc, argv)
	int argc;
	const char *argv[];
{
	if (argc == 1)
		return 1;
	testprogname = argv[0];
	testgc = -1;
	++argv, --argc;
	prec[')'] = 1;	/* do everything before absorbing this */
	prec['|'] = 5;	/* OR has lower precedence than... */
	prec['&'] = 10;	/* AND, obviously. */
	if (strcmp(testprogname, "[") == 0) {
		if (strcmp(argv[argc-1], "]") != 0) {
			fprintf(stderr, "test: missing ]\n");
			return -1;
		}
		argv[--argc] = NULL;
		if (argc == 0)
			return 1;
	}
	if (argc == 1)
		return argv[0][0] == '\0';
	while (*argv)
		if (testparse(&argv,0))
			break;
	dprintf("ac = %d, av[%d] = %d\n", testgc, testgc, testgv[testgc]);
	return !testgv[testgc];
}

