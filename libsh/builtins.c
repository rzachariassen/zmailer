/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include "hostenv.h"
#ifdef	MAILER
#include "sift.h"
#endif	/* MAILER */
#include "mailer.h"
#include <ctype.h>
#include <fcntl.h>
#include <sys/times.h>
#include "interpret.h"
#include "io.h"		/* redefines stdio routines */
#include "shconfig.h"

#include "libz.h"
#include "libc.h"
#include "libsh.h"

#ifdef  HAVE_WAITPID
# include <sys/wait.h>
#else
# ifdef HAVE_WAIT3
#  include <sys/wait.h> /* Has BSD wait3() */
# else
#  ifdef HAVE_SYS_WAIT_H /* POSIX.1 compatible */
#   include <sys/wait.h>
#  else /* Not POSIX.1 compatible, lets fake it.. */
extern int wait();
#  endif
# endif
#endif

#ifndef WEXITSTATUS
# define WEXITSTATUS(s) (((s) >> 8) & 0377)
#endif
#ifndef WSIGNALSTATUS
# define WSIGNALSTATUS(s) ((s) & 0177)
#endif


#ifndef	HZ
#define	HZ	60
#endif	/* HZ */

extern int errno;

#define CSARGS2 __((conscell *, conscell *))

extern conscell *sh_car		CSARGS2;
static conscell *sh_cdr		CSARGS2;
static conscell *sh_list	CSARGS2;
static conscell *sh_grind	CSARGS2;
static conscell *sh_elements	CSARGS2;
static conscell *sh_get		CSARGS2;
static conscell *sh_length	CSARGS2;
static conscell *sh_last	CSARGS2;
static conscell *sh_lappend     CSARGS2;
static conscell *sh_lreplace    CSARGS2;

#define CSARGV2 __((int argc, const char *argv[]))

static int sh_read	CSARGV2;
static int sh_echo	CSARGV2;
static int sh_cd	CSARGV2;
static int sh_colon	CSARGV2;
static int sh_hash	CSARGV2;
static int sh_bce	CSARGV2;
static int sh_eval	CSARGV2;
static int sh_export	CSARGV2;
static int sh_getopts	CSARGV2;
static int sh_shift	CSARGV2;
static int sh_umask	CSARGV2;
static int sh_set	CSARGV2;
static int sh_unset	CSARGV2;
static int sh_wait	CSARGV2;
static int sh_times	CSARGV2;
static int sh_type	CSARGV2;
static int sh_sleep	CSARGV2;
static int sh_true	CSARGV2;
static int sh_false	CSARGV2;


struct shCmd builtins[] = {
{	"car",		NULL,	sh_car,		NULL,	SH_ARGV		},
{	"first",	NULL,	sh_car,/*sic*/	NULL,	SH_ARGV		},
{	"cdr",		NULL,	sh_cdr,		NULL,	SH_ARGV		},
{	"rest",		NULL,	sh_cdr,/*sic*/	NULL,	SH_ARGV		},
{	"last",		NULL,	sh_last,	NULL,	SH_ARGV		},
{	"list",		NULL,	sh_list,	NULL,	SH_ARGV		},
{	"grind",	NULL,	sh_grind,	NULL,	SH_ARGV		},
{	"elements",	NULL,	sh_elements,	NULL,	SH_ARGV		},
{	"get",		NULL,	sh_get,		NULL,	SH_ARGV		},
{	"length",	NULL,	sh_length,	NULL,	SH_ARGV		},
{	"[",		sh_test,	NULL,	NULL,	0		},
{	"test",		sh_test,	NULL,	NULL,	0		},
{	"echo",		sh_echo,	NULL,	NULL,	0		},
{	"cd",		sh_cd,		NULL,	NULL,	0		},
{	"hash",		sh_hash,	NULL,	NULL,	0		},
{	"read",		sh_read,	NULL,	NULL,	0		},
{	":",		sh_colon,	NULL,	NULL,	0		},
{	".",		sh_include,	NULL,	NULL,	0		},
{	"break",	sh_bce,		NULL,	NULL,	SH_INTERNAL	},
{	"continue",	sh_bce,		NULL,	NULL,	SH_INTERNAL	},
{	"return",	NULL,	NULL,	sh_return,	SH_ARGV		},
{	"returns",	NULL,	NULL,	sh_returns,	SH_ARGV		},
{	"exit",		sh_bce,		NULL,	NULL,	SH_INTERNAL	},
{	"eval",		sh_eval,	NULL,	NULL,	0		},
{	"export",	sh_export,	NULL,	NULL,	0		},
{	"getopts",	sh_getopts,	NULL,	NULL,	0		},
{	"shift",	sh_shift,	NULL,	NULL,	0		},
{	"umask",	sh_umask,	NULL,	NULL,	0		},
{	"set",		sh_set,		NULL,	NULL,	0		},
{	"unset",	sh_unset,	NULL,	NULL,	0		},
{	"wait",		sh_wait,	NULL,	NULL,	0		},
{	"times",	sh_times,	NULL,	NULL,	0		},
{	"trap",		sh_trap,	NULL,	NULL,	0		},
{	"type",		sh_type,	NULL,	NULL,	0		},
{	"builtin",	sh_builtin,	NULL,	NULL,	0		},
{	"sleep",	sh_sleep,	NULL,	NULL,	0		},
{	"true",		sh_true,	NULL,	NULL,	0		},
{	"false",	sh_false,	NULL,	NULL,	0		},
{	"lappend",	NULL,	sh_lappend,	NULL,	SH_ARGV		},
{	"lreplace",	NULL,	sh_lreplace,	NULL,	SH_ARGV		},
{	NULL,		NULL,		NULL,	NULL,	0		},
};

conscell *
sh_car(avl, il)
	conscell *avl, *il; /* Input conscells are gc-protected! */
{
	il = cdar(avl);
	if (il == NULL)
		return NULL;
	if (STRING(il)) {
		il = copycell(il);
		cdr(il) = NULL;
		return il;
	}
	if (car(il) == NULL) {
		return il;
	}
	car(il) = copycell(car(il));	/* don't modify malloc'ed memory! */
	cdar(il) = NULL;
	return car(il);
}

static conscell *
sh_cdr(avl, il)
	conscell *avl, *il; /* Input conscells are gc-protected! */
{
	il = cdar(avl);
	if (il == NULL || STRING(il) || car(il) == NULL)
		return NULL;
	car(il) = cdar(il);
	return il;
}

static conscell *
sh_last(avl, il)
	conscell *avl, *il; /* Input conscells are gc-protected! */
{
	il = cdar(avl);
	if (il == NULL || STRING(il) || car(il) == NULL)
		return NULL;
	while (cdar(il) != NULL)
		car(il) = cdar(il);
	return il;
}

static conscell *
sh_list(avl, il)
	conscell *avl, *il; /* Input conscells are gc-protected! */
{
	car(avl) = cdar(avl);
	return avl;
}

static conscell *
sh_grind(avl, il)
	conscell *avl, *il; /* Input conscells are gc-protected! */
{
	return cdar(avl);
}

static conscell *
sh_elements(avl, il)
	conscell *avl, *il; /* Input conscells are gc-protected! */
{
	conscell *p;

	if ((p = cdar(avl)) == NULL || !LIST(p))
		return p;
	il = cadar(avl);
#if 0
	/* This copy does not work :-O */
	p = il = s_copy_tree(il); /* creates new cells, but this is
				     also last call to the creator here */
#endif
	for (; p != NULL; p = cdr(p))
		p->flags |= ELEMENT;
	return il;
}


/*
 *  call: lappend varname $value
 *  The varname is looked up, and appended with supplied value;
 *  approach 
 *
 */

static conscell *
sh_lappend(avl, il)
	conscell *avl, *il; /* Input conscells are gc-protected! */
{
	conscell *key, *d, *tmp, *data;
	memtypes omem = stickymem;

	key = cdar(avl);
	if (key == NULL 
	    || !STRING(key)) {
		fprintf(stderr, "Usage: %s variable-name $moredata\n",
				car(avl)->string);
		return NULL;
	}
	d = v_find(key->string); /* no new objects allocated */
	if (!d) return NULL;

	d = cdr(d); /* This is variable content pointing object */

	stickymem = MEM_MALLOC;

	tmp = cdr(key); /* data is the next elt after the variable name */
	if (LIST(tmp))  /* If it is a LIST object, descend into it */
	  tmp = car(tmp);
	data = s_copy_tree(tmp); /* The only cell-allocator in here */

	if (car(d) != NULL) {
	  d = car(d);

	  while (cdr(d)) d = cdr(d); /* Scan to the end of the list */
	
	  cdr(d) = data;
	} else {
	  car(d) = data; /* the first entry into the list */
	}

	stickymem = omem;
	return NULL; /* Be quiet, don't force the caller
			to store the result into heap just
		        for latter discard... */
}

/*
 *  call: lreplace list_var_name fieldidx $new_value
 *  The varname is looked up, and indicated element of it
 *  is replaced with a new value.
 *
 *  This processes 1) linear lists where index is decimal value,
 *  and 2) key/value pair lists where 'index' is key name
 *
 *  If you are referring beyond end of the list (or to a key
 *  which does not exist), the value (or key + value) is (are)
 *  appended to the variable.
 */

static conscell *
sh_lreplace(avl, il)
	conscell *avl, *il;
{
	conscell *key, *d, *tmp, *data, **dp;
	memtypes omem = stickymem;
	int fieldidx, fieldnamelen;
	char *fieldname;

	GCVARS4;

	const char *lreplace_usage =
	  "Usage: %s variable-name fieldidx $new_value\n\
    where 'fieldidx' can be 1) numeric for index in a list (0..),\n\
    or 2) key/value list's key name\n";

	key = cdar(avl);
	if (key == NULL 
	    || !STRING(key)) {
		fprintf(stderr, lreplace_usage, car(avl)->string);
		return NULL;
	}
	d = v_find(key->string);
	if (!d) {
	  fprintf(stderr, lreplace_usage, car(avl)->string);
	  return NULL;
	}

	tmp = cdr(key);  /* Numeric value for field index */
	if (!tmp || !STRING(tmp)) {
		fprintf(stderr, lreplace_usage, car(avl)->string);
		return NULL;
	}
	if ('0' <= tmp->string[0] && tmp->string[0] <= '9') {
	  fieldidx = -1;
	  if (sscanf(tmp->string,"%i",&fieldidx) != 1 ||
	      fieldidx < 0 || fieldidx > 99) {
	    fprintf(stderr, lreplace_usage, car(avl)->string);
	    return NULL;
	  }
	  fieldname = NULL;
	  fieldnamelen = 0;
	} else {
	  fieldname    = tmp->string;
	  fieldnamelen = tmp->slen;
	}

	stickymem = MEM_MALLOC;

	tmp = cdr(tmp); /* data is the next elt after the field index */
#if 0
	if (LIST(tmp))  /* If it is a LIST object, descend into it */
	  tmp = car(tmp);
#endif

	data = NULL;
	GCPRO4(data, tmp, d, key);

	data = s_copy_tree(tmp);

	dp = &car(cdr(d)); /* This is variable pointing object */
	d = *dp;
	if (fieldname) {
	  while (d != NULL) {
	    /* Ok, this is key/value pairs in a linear list */
	    if (STRING(d) && fieldnamelen == d->slen &&
		memcmp(d->string,fieldname,fieldnamelen)==0) {
	      /* Move pointers to the value */
	      dp = &cdr(d);
	      d = *dp;
	      break;
	    }
	    dp = &cdr(d);
	    d = *dp;
	    if (d != NULL) { /* To be safe in case not key/value pairs */
	      dp = &cdr(d);
	      d = *dp;
	    }
	  }
	  if (d == NULL) {
	    /* Append the pair */
	    int slen = fieldnamelen;
	    d = newstring(dupnstr(fieldname,slen),slen);
	    *dp = d;
	    dp = &cdr(d);
	    d = NULL;
	  }
	} else {
	  while(fieldidx-- > 0 && d != NULL) {
	    dp = &cdr(d);
	    d = *dp;
	  }
	}

	*dp = data;		/* Replace the element */
	if (d) {
	  cdr(data) = cdr(d);
	  cdr(d) = NULL;	/* Disconnect and discard old data */
	  /* s_free_tree(d); -- GC cleans it out latter .. */
	}

	UNGCPRO4;

	stickymem = omem;
	return NULL; /* Be quiet, don't force the caller
			to store the result into heap just
		        for latter discard... */
}



static conscell *
sh_get(avl, il)
	conscell *avl, *il;
{
	conscell *plist, *key, *d = NULL;
	GCVARS3;

	if ((plist = cdar(avl)) == NULL
	    || (key = cddar(avl)) == NULL
	    || !STRING(key)) {
		fprintf(stderr, "Usage: %s variable-name key\n",
				car(avl)->string);
		return NULL;
	}
	if (STRING(plist)) {
		d = v_find((const char *)plist->string);
		if (d == NULL) {
			/* (setq plist '(key nil)) */
			GCPRO3(avl,plist,d);
			if (ISCONST(key))
			  d = conststring(key->string, key->slen);
			else
			  d = copycell(key);
			cdr(d) = NIL;
			d = ncons(d);
			assign(plist, d, (struct osCmd *)NULL);
			UNGCPRO3;
			return cdar(d);
		}
		plist = cdr(d);
		if (!LIST(plist))
			return NULL;
		plist = car(plist);
	}
	/* now we have a property list in plist, scan it */
	/* printf("plist = "); s_grind(plist, stdout); putchar('\n'); */
	for (d = plist; d != NULL; d = cdr(d)) {
		/* if (STRING(d))
			printf("comparing '%s' and '%s'\n",
				d->string, key->string);	*/
		if (STRING(d) && strcmp(d->string, key->string) == 0) {
			d = copycell(cdr(d)); /* This input is plist elt */
			cdr(d) = NULL;
			return d;
		}
		d = cdr(d);
		plist = d;
		if (d == NULL) {
			plist = NULL;
			break;
		}
	}
	if (plist) {
		memtypes oval = stickymem;

		/* plist is now s_last(cadr(v_find(key->string))) */
		cdr(plist) = copycell(key);
		d = NIL;
		cddr(plist) = d;

		stickymem = MEM_MALLOC;
		cdr(plist) = s_copy_tree(cdr(plist)); /* input gc-protected */
		stickymem = oval;
	}

	return d;
}

static conscell *
sh_length(avl, il)
	conscell *avl, *il;
{
	char buf[10];
	int len = 0;

	if ((il = cdar(avl)) && LIST(il)) {
		for (il = car(il); il != NULL; il = cdr(il))
			++len;
	}
	sprintf(buf, "%d", len);
	len = strlen(buf);

	avl = newstring(dupnstr(buf,len),len);
	return avl;
}

/* returns -- return ALWAYS a string [mea] */
conscell *
sh_returns(avl, il, statusp)
	conscell *avl, *il;
	int *statusp;
{
	int n;
	char *cp;

	if ((il = cdar(avl)) && LIST(il) && cdr(il) == NULL)
		return il;
	else if (il == NULL)
		return NULL;
	else if (STRING(il)) {
		for (cp = il->string; *cp != 0; ++cp) {
		  int c = (*cp) & 0xFF;
		  if (!isascii(c) || !isdigit(c))
		    break;
		}
		if (*cp)
			return il;
		n = atoi(il->string);
		if (n < 0) {
			fprintf(stderr, "%s: %s: %d\n", car(avl)->string,
					NEGATIVE_VALUE, n);
			n = 1;
		}
		*statusp = n;
		return NULL;
	}
	/* NOTREACHED */
	return NULL;
}

conscell *
sh_return(avl, il, statusp)
	conscell *avl, *il;
	int *statusp;
{
	int n;
	char *cp;

	if ((il = cdar(avl)) && LIST(il) && cdr(il) == NULL)
		return il;
	else if (il == NULL)
		return NULL;
	else if (STRING(il)) {
		for (cp = il->string; *cp != 0; ++cp) {
		  int c = (*cp) & 0xFF;
		  if (!isascii(c) || !isdigit(c))
		    break;
		}
		if (*cp != 0)
			return il;
		n = atoi(il->string);
		if (n < 0) {
			fprintf(stderr, "%s: %s: %d\n", car(avl)->string,
					NEGATIVE_VALUE, n);
			n = 1;
		}
		*statusp = n;
		return NULL;
	}
	/* NOTREACHED */
	return NULL;
}

/*-*/

static int
sh_colon(argc, argv)
	int argc;
	const char *argv[];
{
	return 0;
}

int
sh_builtin(argc, argv)
	int argc;
	const char *argv[];
{
	return 0;
}

static int
sh_echo(argc, argv)
	int argc;
	const char *argv[];
{
	int n;

	--argc, ++argv;
	/* '-n' ?? */
	if (argc > 0
	    && argv[0][0] == '-' && argv[0][1] == 'n' && argv[0][2] == '\0') {
		--argc, ++argv;
		n = 0;
	} else
		n = 1;
	/* '--' ?? */
	if (argc > 0
	    && argv[0][0] == '-' && argv[0][1] == '-' && argv[0][2] == '\0') {
		--argc, ++argv;
	}

	while (--argc >= 0) {
		fputs(*argv++, stdout);
		if (argc > 0)
			putchar(' ');
	}
	if (n)
		putchar('\n');
	fflush(stdout);
	return 0;
}

static int
sh_cd(argc, argv)
	int argc;
	const char *argv[];
{
	const char *dir;
	char *cddir, *path;
	conscell *d;
	u_int pathlen;

	if (argc == 1) {
		/* cd $HOME */
		d = v_find(HOME);
		if (d == NULL || cdr(d) == NULL || LIST(cdr(d))) {
			fprintf(stderr, "%s: %s\n", argv[0], NO_HOME_DIRECTORY);
			return 1;
		}
		dir = cdr(d)->string;
	} else if (argc == 2) {
		/* cd argv[1] */
		dir = argv[1];
	} else {
		fprintf(stderr, USAGE_CD, argv[0]);
		return 1;
	}
	if (!(dir[0] == '/' ||
	      (dir[0] == '.' &&
	       (dir[1] == '\0' || dir[1] == '/' ||
		(dir[1] == '.' && (dir[2] == '\0' || dir[2] == '/'))))) &&
	    (d = v_find(CDPATH)) != NULL &&
	    cdr(d) != NULL && STRING(cdr(d))) {
		cddir = cdr(d)->string;
		pathlen = strlen(cddir)+strlen(dir)+1+1;
		path = tmalloc(pathlen);
		while (cddir != NULL) {
			cddir = prepath(cddir, dir, path, pathlen);
			if (chdir(path) == 0) {
				if (!(path[0] == '.' && path[1] == '/'))
					printf("%s\n", path);
				return 0;
			}
		}
	} else if (chdir(dir) == 0)
		return 0;

	fprintf(stderr, "%s: %s: %s\n", argv[0], dir, strerror(errno));
	return 1;
}

static int
sh_hash(argc, argv)
	int argc;
	const char *argv[];
{
	if (argc == 1) {
		printf(NO_HASHING_INFORMATION);
		return 0;
	} else if (strcmp(argv[1], "-r") == 0) {
		path_flush();
		--argc, ++argv;
	}
	--argc, ++argv;
	while (argc-- > 0) {
		/* printf("hash '%s'\n", *argv); */
		path_hash(*argv++);
	}
	return 0;
}

static int
sh_read(argc, argv)
	int argc;
	const char *argv[];
{
	static char *buf = NULL;
	static u_int bufsize;
	char *cp, *value = NULL, *bp;
	int flag, offset;

	if (argc == 1) {
		fprintf(stderr, USAGE_READ, argv[0]);
		return 1;
	}
	if (ifs == NULL)
		ifs_flush();
	--argc, ++argv;
	if (buf == NULL) {
		bufsize = BUFSIZ - 24;
		buf = emalloc(bufsize);
	}
	flag = 0;
	bp = NULL;
	buf[0] = '\0';
	while (argc > 0 && fgets(buf, bufsize, stdin) != NULL) {
		for (cp = buf; argc > 0 && *cp != '\0'; ) {
			while (*cp != '\0' && WHITESPACE((unsigned)*cp))
				++cp;
			if (*cp == '\0') {
				if (cp > buf && *(cp-1) != '\n' &&
				    (offset = cp - buf)		&&
				    (bufsize = 2*bufsize)	&&
				    (buf = erealloc(buf, bufsize)) &&
				    fgets(cp, bufsize/2, stdin) != NULL) {
					cp = buf + offset;
					continue;
				} else
					goto eoinput;
			}
			if (!flag) {
				bp = cp;
				value = cp;
			}
			if (argc == 1)
				flag = 1;
			while (*cp == '\0' || !WHITESPACE((unsigned)*cp)) {
				if (*cp == '\0') {
					if (cp > buf && *(cp-1) != '\n' &&
					    (offset = cp - buf)		&&
					    (bufsize = 2*bufsize)	&&
					    (buf = erealloc(buf, bufsize)) &&
					    fgets(cp, bufsize/2, stdin)!=NULL) {
						cp = buf + offset;
						continue;
					} else
						break;
				}
				if (*cp == '\\' && *(cp+1) != '\0') { /* bug */
					if (*++cp == '\n') {
						*cp++ = '\0'; /* defeat above */
						continue;
					}
				}
				*bp++ = *cp++;
			}
			if (argc > 1) {
				--argc;
				if (*cp == '\0') {
					*bp = '\0';	/* bp might == cp */
					v_set(*argv++, value);
					bp = value;
					break;
				} else {
					*bp = '\0';
					v_set(*argv++, value);
					++cp;
				}
			} else if (*cp++ != '\0')
				*bp++ = ' ';
		}
		if (bp > value) {
			if (*(bp-1) == ' ')
				*--bp = '\0';
			else
				*bp = '\0';
			v_set(*argv++, value), --argc;
		}
	}
	if (buf[0] == '\0')
		return 1;
eoinput:
	while (argc-- > 0)
		v_set(*argv++, "");
	return 0;
}

int
sh_include(argc, argv)
	int argc;
	const char *argv[];
{
	int fd;
	int status;
	conscell *d;
	struct stat stbuf;
	u_int pathlen;
	char *dir, *buf, *path = NULL;
	const char *rpath = NULL;

	if (argc < 2 || argv[1][0] == '\0') {
		fprintf(stderr, USAGE_INCLUDE, argv[0]);
		return 1;
	}
	fd = -1;
	if (strchr(argv[1], '/') == NULL) {
		d = v_find(PATH);
		if (d != NULL && cdr(d) != NULL && STRING(cdr(d))) {
			dir = cdr(d)->string;
			pathlen = strlen(dir)+strlen(argv[1])+1+1;
			path = tmalloc(pathlen);
			rpath = path;
			while (dir != NULL) {
				dir = prepath(dir, argv[1], path, pathlen);
				rpath = path;
				fd = open(rpath, O_RDONLY, 0);
				if (fd >= 0)
					break;
			}
		}
	} else {
		rpath = argv[1];
		fd = open(rpath, O_RDONLY, 0);
	}
	if (fd < 0) {
		fprintf(stderr, "%s: %s\n", argv[1], NOT_FOUND);
		return 1;
	}
	if (fstat(fd, &stbuf) < 0) {
		perror("fstat");
		close(fd);
		return 1;
	}
	status = (int) loadeval(fd, rpath, &stbuf);
	if (status >= 0) {
		/* loadeval closes fd */
		return status;
	}
	buf = tmalloc((u_int)stbuf.st_size + 1);
	status = (int) read(fd, buf, (int)stbuf.st_size);
	if (status != (int) stbuf.st_size) {
		perror("read");
		close(fd);
		return 1;
	}
	close(fd);
	buf[(u_int)stbuf.st_size] = '\0';
	return eval(buf, argv[1], rpath, &stbuf);
}

static int
sh_bce(argc, argv)		/* handle break, continue, and exit */
	int argc;
	const char *argv[];
{
	int n;

	if (argc > 2 || (argc == 2 && !isdigit(argv[1][0])))
		fprintf(stderr, USAGE_BCE, argv[0]);
	else if (argc == 1)
		/* 0 for "return" and "exit", 1 o/w */
		return !(argv[0][0] == 'r' || argv[0][0] == 'e');
	if ((n = atoi(argv[1])) < 0) {
		fprintf(stderr, "%s: %s: %d\n", argv[0], NEGATIVE_VALUE, n);
		n = 1;
	} else if (n == 0) {
		switch (argv[0][0]) {
		case 'b': case 'c':	/* 0 for break and continue means 1 */
			n = 1;
			break;
		}
	}
	return n;
}

static int
sh_eval(argc, argv)
	int argc;
	const char *argv[];
{
	int len, i;
	int status;
	void *table, *eotable;
	char *cp, *buf;

	for (len = 0, i = 1; i < argc; ++i) {
		len += strlen(argv[i]);
		++len;
	}
	if (len < argc)
		return 0;
	buf = tmalloc(len+1+1/* trailing \n*/);
	for (cp = buf, i = 1; i < argc; ++i) {
		strcpy(cp, argv[i]);
		cp += strlen(argv[i]);
		*cp++ = ' ';
	}
	*cp++ = '\n';
	*cp = '\0';
	commandline = s_pushstack(commandline, buf);
	table = SslWalker("eval string", stdout, &eotable);
	status = 7;
	if (table != NULL) {
		if (isset('O')) {
			table = optimize(0, table, &eotable);
			if (isset('V'))
				table = optimize(1, table, &eotable);
		}
		interpret(table, eotable, NULL, globalcaller,
			  &status, (struct codedesc *)NULL);
	}
	return status;
}

static int
sh_export(argc, argv)
	int argc;
	const char *argv[];
{
	conscell *elist, *glist, *scope;

	if (argc > 1) {
		/* export the listed variables */
		--argc, ++argv;
		while (argc > 0) {
			v_export(argv[0]);
			--argc, ++argv;
		}
		return 0;
	}
	/* print which variables have been exported */
	for (scope = car(envarlist); cddr(scope) != NULL; scope = cdr(scope))
		continue;
	for (elist = cadr(scope); elist != NULL; elist = cddr(elist)) {
		if (LIST(elist) || elist->string == NULL)
			continue;
		for (glist = car(scope); glist != NULL; glist = cddr(glist)) {
			if (STRING(glist) && glist->slen == elist->slen &&
			    memcmp(glist->string, elist->string, elist->slen) == 0)
				break;
		}
		if (glist == NULL)
			printf("%s %s\n", EXPORT, elist->string);
	}
	return 0;
}

static int
sh_getopts(argc, argv)
	int argc;
	const char *argv[];
{
	char buf[20];
	const char *optstring, *name;
	const char **av;
	int c;
	conscell *d;

	if (argc < 3) {
		fprintf(stderr, USAGE_GETOPTS, argv[0]);
		return 1;
	}
	opterr = 0;
	--argc, ++argv;
	optstring = argv[0];
	--argc, ++argv;
	name = argv[0];
	if (argc == 1) {
		for (d = cdar(globalcaller->argv); d != NULL ; d = cdr(d))
			++argc;
		av = (const char **)tmalloc((argc+1)*sizeof (char *));
		argv = av;
		for (d = car(globalcaller->argv); d != NULL ; d = cdr(d))
			if (STRING(d)) {
				*av++ = d->string;
				++argc;
			}
		*av = NULL;
	}
	c = getopt(argc, (char*const*)argv,
		   optstring);	/* this MUST be our getopt() */
	sprintf(buf, "%d", optind);
	v_set(OPTIND, buf);
	if (c == EOF)
		return 1;
	if (optarg != NULL)	/* our getopt() makes this reliable */
		v_set(OPTARG, optarg);
	sprintf(buf, "%c", c);
	v_set(name, buf);
	return 0;
}

static int
sh_shift(argc, argv)
	int argc;
	const char *argv[];
{
	int n;
	conscell *d;

	if (argc > 2 || (argc == 2 && !isdigit(argv[1][0]))) {
		fprintf(stderr, USAGE_SHIFT, argv[0]);
		return 1;
	}
	if (argc == 2) {
		if ((n = atoi(argv[1])) < 1)
			return 0;
	} else
		n = 1;
	for (d = cdar(globalcaller->argv); d != NULL && n > 0; d = cdr(d))
		--n;
	cdar(globalcaller->argv) = d;		/* XX: possible malloc leak */
	return 0;
}

static int
sh_umask(argc, argv)
	int argc;
	const char *argv[];
{
	int mask;
	const char *cp;

	if (argc > 2 || (argc == 2 && !isdigit(argv[1][0]))) {
		fprintf(stderr, USAGE_UMASK, argv[0]);
		return 1;
	}
	if (argc == 1) {
		mask = umask(077);
		printf("%#o\n", mask);
		umask(mask);
		return 0;
	}
	mask = 0;
	for (cp = argv[1]; *cp != '\0'; ++cp)
		mask = mask * 8 + (*cp - '0');		/* XX: ebcdic?? */
	umask(mask);
	return 0;
}

static int
sh_set(argc, argv)
	int argc;
	const char *argv[];
{
	int n, i;
	memtypes oval;
	const char *cp;
	char **kk, *ep;
	conscell *d, *pd = NULL, *scope;
	char ebuf[32];

	if (argc == 1) {
		/* print variable values */
		/* first count how many there might be */
		n = 0;
		for (scope = car(envarlist); scope != NULL; scope = cdr(scope))
			for (d = car(scope); d != NULL; d = cddr(d))
				++n;
		/* allocate enough space to hold cache ptrs */
#ifdef	USE_ALLOCA
		kk = (char **)alloca((n+1) * sizeof (char *));
#else
		kk = (char **)emalloc((n+1) * sizeof (char *));
#endif
		kk[0] = NULL;
		/* iterate through all variables */
		for (scope = car(envarlist); scope != NULL; scope = cdr(scope))
			for (d = car(scope); d != NULL; d = cddr(d)) {
				if (!STRING(d) || cdr(d) == envarlist)
					continue;
				/* if we already saw it, skip this one O(N^2) */
				for (i = 0; kk[i] != NULL && i < n; ++i)
					if (strcmp(kk[i], (char *)d->string) == 0)
						break;
				if (kk[i] == NULL) {
					kk[i] = (char *)d->string;
					kk[i+1] = NULL;
					printf("%s=", (char*)d->string);
					s_grind(cdr(d), stdout);
					putchar('\n');
				}
			}
#ifndef USE_ALLOCA
		free(kk);
#endif
		return 0;
	}
	--argc, ++argv;
	if (argv[0][0] == '-' || argv[0][0] == '+') {
		i = (argv[0][0] == '-');
		ep = ebuf;
		for (cp = &argv[0][1]; *cp != '\0'; ++cp) {
			switch (*cp) {
			case 'a':/* automatically export changed variables */
			case 'e':/* exit on error exit status of any command */
			case 'f':/* disable filename generation (no globbing) */
			case 'h':/* hash program locations */
			case 'n':/* read commands but do not execute them */
			case 't':/* read and execute one command only */
			case 'u':/* unset variables are error on substitution */
			case 'v':/* print shell input lines as they are read */
			case 'x':/* print commands as they are executed */
			case 'L':/* Trace LEXER processing (sslWalker) */
			case 'C':
			case 'P':
			case 'S':
				setopt(*cp, i);
				break;
			case '-':	/* do nothing */
				break;
			case 'k':	/* we do not support the k option */
			default:	/* complain */
				if (ep < (ebuf + sizeof(ebuf)-2))
				  *ep++ = *cp;
				break;
			}
		}
		if (ep > ebuf) {
			*ep = '\0';
			fprintf(stderr, "%s: %s: %s\n",
					argv[-1], BAD_OPTIONS, ebuf);
		}
		--argc, ++argv;
	}
	if (argc == 0)
		return 0;
	/* the remaining arguments should replace $@ */
	oval = stickymem;
	stickymem = MEM_MALLOC;
	if (globalcaller != NULL && globalcaller->argv != NULL)
		pd = car(globalcaller->argv);
	while (argc-- > 0) {
		int slen = strlen(*argv);
		d = newstring(dupnstr(*argv,slen),slen);
		/* These go into  globalcaller->  protected storage */
		if (pd != NULL)
			cdr(pd) = d;
		++argv;
		pd = d;
	}
	stickymem = oval;
	return 0;
}

static const char *sacred[] = { PATH, PS1, PS2, IFS, MAILCHECK, 0 };

static int
sh_unset(argc, argv)
	int argc;
	const char *argv[];
{
	conscell *d, *pd = NULL, *scope, *next;
	const char **cpp, *av0;

	if (argc == 1) {
		fprintf(stderr, USAGE_UNSET, argv[0]);
		return 1;
	}
	av0 = argv[0];
	--argc, ++argv;
	while (argc-- > 0) {
		for (cpp = sacred; *cpp != NULL; ++cpp) {
			if (strcmp(*cpp, *argv) == 0) {
				fprintf(stderr, "%s: %s %s\n",
					av0, CANNOT_UNSET, *argv);
				break;
			}
		}
		if (*cpp != NULL) {	/* couldn't unset that one */
			++argv;
			continue;
		}
		for (scope = car(envarlist); scope != NULL; scope = cdr(scope))
			for (d = car(scope); d != NULL; pd = d, d = next) {
				next = cddr(d);
				if (LIST(d) || strcmp((char *)d->string, *argv) != 0)
					continue;
				/* now we've got it! unlink and free */
				if (d == car(scope))
					car(scope) = next;
				else
					cddr(pd) = next;
				cddr(d) = NULL;
				/* s_free_tree(d); -- GC does it.. */ 
				/* no point doing anything else in this scope */
				break;
			}
		++argv;
	}
	return 0;
}

static int
sh_wait(argc, argv)
	int argc;
	const char *argv[];
{
	int retcode, pid;
	int status = 0;

	if (argc > 2 || (argc == 2 && !isdigit(argv[1][0]))) {
		fprintf(stderr, USAGE_WAIT, argv[0]);
		return 1;
	}
	while ((pid = wait(&status)) > 0) {
		if (argc == 2 && pid == atoi(argv[1]))
			break;
	}
	if (pid < 0)		/* no more children */
		return 0;
	if (WSIGNALSTATUS(status) != 0) {
		fprintf(stderr, "%s", strsignal(WSIGNALSTATUS(status)));
		if (status&0200)
			fprintf(stderr, CORE_DUMPED);
		fprintf(stderr, "\n");
		retcode = 0200 + WSIGNALSTATUS(status);
	} else
		retcode = WEXITSTATUS(status);
	return retcode;
}

static int
sh_times(argc, argv)
	int argc;
	const char *argv[];
{
	struct tms foo;

	if (argc > 1) {
		fprintf(stderr, USAGE_TIMES, argv[0]);
		return 1;
	}
	if (times(&foo) < 0)
		return 1;
	printf("%dm%ds %dm%ds\n",
	       foo.tms_cutime / HZ / 60, (foo.tms_cutime / HZ) % 60,
	       foo.tms_cstime / HZ / 60, (foo.tms_cstime / HZ) % 60);
	return 0;
}

static int
sh_type(argc, argv)
	int argc;
	const char *argv[];
{
	char *dir, *path;
	struct shCmd *shcmdp;
	struct sslfuncdef *sfdp;
	u_int pathlen;

	for (--argc, ++argv; argc-- > 0 ; ++argv) {
		if (*argv == '\0') {
			printf(NULL_NAME);
			continue;
		}
		functype(*argv, &shcmdp, &sfdp);
		/* defined function ? */
		if (sfdp != NULL) {
			printf("%s %s\n", *argv, IS_A_SHELL_FUNCTION);
			continue;
		}
		/* builtin ? */
		if (shcmdp != NULL) {
			printf("%s %s\n", *argv, IS_A_SHELL_BUILTIN);
			continue;
		}
		/* unix command */
		dir = path_hash(*argv);
		if (dir != NULL) {
			pathlen = strlen(dir)+strlen(*argv)+1+1;
			path = tmalloc(pathlen);
			dir = prepath(dir, *argv, path, pathlen);
			printf("%s %s %s\n", *argv, IS, path);
			continue;
		}
		printf("%s %s\n", *argv, NOT_FOUND);
	}
	return 0;
}


static int
sh_sleep(argc, argv)
	int argc;
	const char *argv[];
{
	if (argc != 2 || atoi(argv[1]) <= 0) {
		fprintf(stderr, USAGE_SLEEP, argv[0]);
		return 1;
	}
	sleep(atoi(argv[1]));
	return 0;
}

static int
sh_true(argc, argv)
	int argc;
	const char *argv[];
{
	return 0;
}

static int
sh_false(argc, argv)
	int argc;
	const char *argv[];
{
	return 1;
}
