/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *	Some functions Copyright 1991-2001 Matti Aarnio.
 */

/*
 * The routines in this file implement various C-coded functions that
 * are callable from the configuration file.
 */

#include "router.h"

/* The builtin functions are declared and initialized here.  */

#define ARGCV __((int argc, const char *argv[]))
static int run_hostname    ARGCV;
static int run_whataddress ARGCV;
static int run_iserrormsg  ARGCV;
static int run_isinteractive ARGCV;
static int run_erraddrlog  ARGCV;

static conscell *run_dblookup __((conscell *avl, conscell *il));
static conscell *run_cadr     __((conscell *avl, conscell *il));
static conscell *run_caddr    __((conscell *avl, conscell *il));
static conscell *run_cadddr   __((conscell *avl, conscell *il));
static conscell *run_listexpand   __((conscell *avl, conscell *il));
#if 0
static conscell *run_newattribute __((conscell *avl, conscell *il));
#endif

static int run_grpmems   ARGCV;
#if 0 /* dead code */
static int run_praliases ARGCV;
#endif
static int zap_DSN_notify ARGCV;
static int post_zap_DSN_notify ARGCV;
static int run_homedir   ARGCV;
static int run_822date   ARGCV;
static int run_filepriv  ARGCV;
static int run_runas     ARGCV;
static int run_cat       ARGCV;
static int run_gensym    ARGCV;
static int run_uid2login ARGCV;
static int run_login2uid ARGCV;
static int run_basename  ARGCV;
static int run_recase    ARGCV;
static int run_squirrel  ARGCV;
static int run_822syntax ARGCV;
static int run_condquote ARGCV;
static int run_dequote   ARGCV;
static int run_syslog    ARGCV;

#if	defined(XMEM) && defined(CSRIMALLOC)
static int run_malcontents ARGCV;
#endif	/* CSRIMALLOC */

struct shCmd fnctns[] = {
{	"relation",	run_relation,	NULL,	NULL,	0	},
{	DBLOOKUPNAME,	NULL,	run_dblookup,	NULL,	SH_ARGV	},
/* The following are optional but are probably a good idea */
{	"db",		run_db,		NULL,	NULL,	0	},
{	"trace",	run_trace,	NULL,	NULL,	0	},
{	"untrace",	run_trace,	NULL,	NULL,	0	},
{	"hostname",	run_hostname,	NULL,	NULL,	0	},
{	"iserrormsg",	run_iserrormsg,	NULL,	NULL,	0	},
{	"isinteractive",	run_isinteractive,	NULL,	NULL,	0	},
{	"sender",	run_whataddress,NULL,	NULL,	0	},
{	"recipient",	run_whataddress,NULL,	NULL,	0	},
{	"erraddron",	run_erraddrlog,	NULL,	NULL,	0	},
{	"channel",	NULL,		sh_car,	NULL,	SH_ARGV	},
{	"host",		NULL,	run_cadr,	NULL,	SH_ARGV	},
{	"user",		NULL,	run_caddr,	NULL,	SH_ARGV	},
{	"attributes",	NULL,	run_cadddr,	NULL,	SH_ARGV	},
{	"stability",	run_stability,	NULL,	NULL,	0	},
{	"stableprocess", run_doit,	NULL,	NULL,	0	},
{	"daemon",	run_daemon,	NULL,	NULL,	0	},
{	"process",	run_process,	NULL,	NULL,	0	},
{	"rfc822",	run_rfc822,	NULL,	NULL,	0	},
{	"groupmembers",	run_grpmems,	NULL,	NULL,	0	},
#if 0
{	"printaliases",	run_praliases,	NULL,	NULL,	0	},
#endif
{	"zapDSNnotify", zap_DSN_notify,	NULL,	NULL,	SH_ARGV	},
{	"postzapDSNnotify", post_zap_DSN_notify, NULL, NULL, SH_ARGV },
{	"listexpand",	NULL,	run_listexpand,	NULL,	SH_ARGV	},
#if 0
{	"newattribute",	NULL,	run_newattribute, NULL,	SH_ARGV	},
#endif
{	"homedirectory",run_homedir,	NULL,	NULL,	0	},
{	"rfc822date",	run_822date,	NULL,	NULL,	0	},
{	"filepriv",	run_filepriv,	NULL,	NULL,	SH_ARGV	},
{	"runas",	run_runas,	NULL,	NULL,	SH_ARGV	},
{	"cat",		run_cat,	NULL,	NULL,	SH_ARGV	},
{	"gensym",	run_gensym,	NULL,	NULL,	0	},
{	"uid2login",	run_uid2login,	NULL,	NULL,	0	},
{	"login2uid",	run_login2uid,	NULL,	NULL,	0	},
{	"basename",	run_basename,	NULL,	NULL,	0	},
{	"recase",	run_recase,	NULL,	NULL,	0	},
{	"squirrel",	run_squirrel,	NULL,	NULL,	0	},
{	"rfc822syntax",	run_822syntax,	NULL,	NULL,	0	},
{	"dequote",	run_dequote,	NULL,	NULL,	0	},
{	"condquote",	run_condquote,	NULL,	NULL,	0	},
{	"syslog",	run_syslog,	NULL,	NULL,	0	},
{	"logger",	run_syslog,	NULL,	NULL,	0	},
#if	defined(XMEM) && defined(CSRIMALLOC)
{	"malcontents",	run_malcontents,NULL,	NULL,	0	},
#endif	/* CSRIMALLOC */
/* The rest have been added locally */
{ NULL, NULL, NULL, NULL, 0 }
};

int		funclevel = 0;

int		D_sequencer = 0;
int		D_hdr_rewrite = 0;
int		D_router = 0;
int		D_functions = 0;
int		D_compare = 0;
int		D_matched = 0;
int		D_assign = 0;
int		D_final = 0;
int		D_db = 0;
int		D_alias = 0;
int		D_bind = 0;
int		D_resolv = 0;
int		D_alloc = 0;
int		D_regnarrate = 0;
extern int	D_rfc822;

static struct debugind {
	const char	*name;
	int		*indicator;
} buggers[] = {
	{	"assign",		&D_assign	},
	{	"bind",			&D_bind		},
	{	"compare",		&D_compare	},
	{	"db",			&D_db		},
	{	"except",		0		},
	{	"final",		&D_final	},
	{	"functions",		&D_functions	},
	{	"matched",		&D_matched	},
	{	"memory",		&D_alloc	},
	{	"on",			&D_functions	},	/* dup */
	{	"regexp",		&D_regnarrate	},
	{	"resolv",		&D_resolv	},
	{	"rewrite",		&D_hdr_rewrite	},
	{	"rfc822",		&D_rfc822	},
	{	"router",		&D_router	},
	{	"sequencer",		&D_sequencer	},
	{	NULL,			0		}
};

/* add builtin router functions to list of builtin shell functions */
void router_functions_init()
{
	register struct shCmd *shcmdp;

	for (shcmdp = &fnctns[0]; shcmdp->name != NULL; ++shcmdp)
		sp_install(symbol(shcmdp->name),
			   (void*)shcmdp, 0, spt_builtins);
}


/* The builtin trace function. This is also used by command line debug specs */

int
run_trace(argc, argv)
	int argc;
	const char *argv[];
{
	struct debugind *dbi;
	int debug;
	const char *prog;
	int rc = 0;

	if (argc == 1) {
		fprintf(stderr, "Usage: %s all", argv[0]);
		for (dbi = &buggers[0]; dbi->name != NULL; ++dbi)
			fprintf(stderr, "|%s", dbi->name);
		putc('\n', stderr);
		return EX_USAGE;
	}
	prog = argv[0];
	debug = (strncmp(*argv, "un", 2) != 0);
	while (--argc > 0) {
		++argv;
		if (STREQ(*argv, "off")  ||  STREQ(*argv, "all")) {
			for (dbi = &buggers[0]; dbi->name != NULL; ++dbi)
			    if (dbi->indicator)
				*(dbi->indicator) = (**argv == (debug?'a':'o'));
			continue;
		} else {
			for (dbi = &buggers[0]; dbi->name != NULL; ++dbi) {
				if (STREQ(*argv, dbi->name)) {
					if (dbi->indicator == NULL)
					  debug = !debug; /* except */
					else
					  *(dbi->indicator) = debug;
					break;
				}
			}
		}
		if (dbi->name == NULL) {
			fprintf(stderr, "%s: unknown attribute: %s\n",
					prog, *argv);
			rc = EX_USAGE;
		}
	}
	return rc;
}


int gensym;
const char * const gs_name = "g%d";

static int
run_gensym(argc, argv)
	int argc;
	const char *argv[];
{
	printf(gs_name, gensym++);
	putchar('\n');
	return 0;
}

void
free_gensym()
{
	int i;
	char buf[30];

	for (i=0; i<gensym; ++i) {
		sprintf(buf, gs_name, i);
		v_purge(buf);
	}
}


/* hostname -- get system hostname or set my idea of the hostname */

static int
run_hostname(argc, argv)
	int argc;
	const char *argv[];
{
	static char hostname[128];

	if (argc > 1) {
		memtypes oval = stickymem;
		stickymem = MEM_MALLOC;
		myhostname = strdup(argv[1]);
		stickymem = oval;
	} else {
		/* can't fail... */
		getmyhostname(hostname, sizeof hostname);
		printf("%s\n", hostname);
	}
	return 0;
}

/*
 * senderaddress/recipientaddress -- find out whether the current header
 * address being rewritten is a sender or a recipient address
 */

static int
run_whataddress(argc, argv)
	int argc;
	const char *argv[];
{
	static int toggle = 0;

	if (isSenderAddr == isRecpntAddr /* == 0 */) {
		fprintf(stderr,
	"Should not call '%s' outside header address rewriting function!\n",
			argv[0]);
		toggle = !toggle;
		return toggle;	/* pseudorandom :-) */
	} else if (argc > 1)
		fprintf(stderr, "Usage: %s\n", argv[0]);
	if (argv[0][0] == 's')		/* called as 'senderaddress' */
		return isSenderAddr ? 0 : 1;
	return isRecpntAddr ? 0 : 1;
}

/*
 * $(iserrormsg dummyargs)  returns a flag 
 */

static int
run_iserrormsg(argc, argv)
	int argc;
	const char *argv[];
{
	return !isErrorMsg;
}

/*
 * $(isinteractive dummyargs)  returns a flag 
 */

static int
run_isinteractive(argc, argv)
	int argc;
	const char *argv[];
{
	return !isInteractive;
}

/*
 * this is like accton(), but for logging errors in addresses.
 */

char *erraddrlog;

static int
run_erraddrlog(argc, argv)
	int argc;
	const char *argv[];
{
	switch (argc) {
	case 1:
		if (erraddrlog)
			free(erraddrlog);
		erraddrlog = NULL;
		break;
	case 2:
		erraddrlog = smalloc(MEM_PERM, strlen(argv[1])+1);
		strcpy(erraddrlog, argv[1]);
		break;
	default:
		fprintf(stderr, "Usage: %s [ /path ]\n", argv[0]);
		return EX_USAGE;
	}
	return 0;
}


/*
 * Interface to databases; the relation function arranges to attach this
 * function to all database function definitions.  It is called as
 *	database key
 * and is expected to act like a normal function (i.e. print value on stdout).
 */

static conscell *
run_dblookup(avl, il)
	conscell *avl, *il; /* Inputs gc protected */
{
	conscell *l;
	const char *argv30[30];
	int i;

	memset(argv30, 0, sizeof(argv30));

	il = cdar(avl);
	if (il == NULL || !STRING(il)) {
		fprintf(stderr, "Usage: %s key [up_to_19_substitution_elements_or_options]\n", car(avl)->string);
		return NULL;
	}
	i = 0;
	for (; il && i < 30-1 && STRING(il); il = cdr(il))
	  argv30[i++] = il->string;

	l = dblookup(car(avl)->string, i, argv30);
	if (l == NULL)
		return NULL;
	return l;
}

static conscell *
run_cadr(avl, il)
	conscell *avl, *il; /* Inputs gc protected */
{
	il = cdar(avl);
	if (il == NULL || STRING(il) || car(il) == NULL)
		return NULL;
	/* cdr */
	car(il) = cdar(il);

	/* car */
	car(il) = copycell(car(il));	/* don't modify malloc'ed memory! */
	cdar(il) = NULL;
	return car(il);
}

static conscell *
run_caddr(avl, il)
	conscell *avl, *il; /* Inputs gc protected */
{
	il = cdar(avl);
	if (il == NULL || STRING(il) || car(il) == NULL)
		return NULL;
	/* cdr */
	car(il) = cdar(il);

	/* cdr */
	car(il) = cdar(il);

	/* car */
	/* setf preparation */
	if (car(il) == NULL) {
		return il;
	}
	car(il) = copycell(car(il));	/* don't modify malloc'ed memory! */
	cdar(il) = NULL;
	return car(il);
}

static conscell *
run_cadddr(avl, il)
	conscell *avl, *il; /* Inputs gc protected */
{
	il = cdar(avl);
	if (il == NULL || STRING(il) || car(il) == NULL)
		return NULL;
	/* cdr */
	car(il) = cdar(il);

	/* cdr */
	car(il) = cdar(il);

	/* cdr */
	car(il) = cdar(il);

	/* car */
	/* setf preparation */
	if (car(il) == NULL) {
		return il;
	}
	car(il) = copycell(car(il));	/* don't modify malloc'ed memory! */
	cdar(il) = NULL;
	return car(il);
}


/*
 * Print a list of the members of a group.
 */

static int
run_grpmems(argc, argv)
	int argc;
	const char *argv[];
{
	const char **cpp;
	struct Zgroup *grp;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s groupname\n", argv[0]);
		return EX_USAGE;
	}
	grp = zgetgrnam(argv[1]);
	if (grp == NULL) {
		fprintf(stderr, "%s: no group '%s'\n", argv[0], argv[1]);
		return 1;
	}
	for (cpp = grp->gr_mem; *cpp != NULL ; ++cpp)
		printf("%s\n", *cpp);
	endgrent();
	return 0;
}

static struct headerinfo aliashdr = {
	"aliases", AddressList, Recipient, normal
};

#if 0 /* dead code, 'zmailer newdb' does these differently... */
static int
run_praliases(argc, argv)
	int argc;
	const char *argv[];
{
	register struct header *h;
	struct envelope *e;
	const char *cp;
	int errflg, count, status;
	long offset, size, prevsize, maxsize;
	FILE *indexfp;
	int c, verbose;
	const char *indexfile;
	char buf[8192], ibuf[BUFSIZ];
	struct siobuf *osiop = NULL;
	int tabsep = 0;


	verbose = 0;
	indexfile = NULL;
	zoptind = 1;
	errflg = 0;
	while (1) {
		c = zgetopt(argc, (char*const*)argv, "vo:t");
		if (c == EOF)
			break;
		switch (c) {
		case 'v':
			++verbose;
			break;
		case 'o':
			indexfile = zoptarg;
			break;
		case 't':
			tabsep = 1;
			break;
		default:
			++errflg;
			break;
		}
	}
	if (errflg || zoptind != argc - 1) {
		fprintf(stderr,
			"Usage: %s [ -v ] [ -o indexoutputfile ] aliasfile\n",
			argv[0]);
		return EX_USAGE;
	}

	e = (struct envelope *)tmalloc(sizeof (struct envelope));
	if ((e->e_fp = fopen(argv[zoptind], "r")) == NULL) {
		c = errno;
		fprintf(stderr, "%s: open(\"%s\"): ", argv[0], argv[zoptind]);
		errno = c;
		perror("");
		status = PERR_BADOPEN;
	} else {
		setvbuf(e->e_fp, buf, _IOFBF, sizeof buf);
		osiop = siofds[FILENO(e->e_fp)];
		siofds[FILENO(e->e_fp)] = NULL;
		e->e_file = argv[zoptind];
		status = makeLetter(e, 1);	/* Parse the aliases database
						   as if all entries were of
						   same syntax as "To:" et.al.
						   on the normal email header*/
		siofds[FILENO(e->e_fp)] = osiop;
		fclose(e->e_fp);
		e->e_fp = NULL;
	}

	if (status != 0) {
		fprintf(stderr, "%s: format error!\n", argv[0]);
		return 2;
	}

	for (h = e->e_headers; h != NULL; h = h->h_next) {
		h->h_descriptor = &aliashdr;
		/* NOTE: (although this is dead code)
		   the '#' commenting in input file must be handled
		   in THIS code, not delayed into  hdr_scanparse() ! */
		h->h_contents = hdr_scanparse(e, h, 0);
		h->h_stamp = hdr_type(h);
		if (h->h_stamp == BadHeader) {
			hdr_errprint(e, h, stderr, "alias expansion");
			++errflg;
		} else if (h->h_contents.a == NULL) {
			fprintf(stderr, "%s: null alias '%s'\n", argv[0],
					h->h_pname);
			++errflg;
		}
	}

	if (errflg) {
		fprintf(stderr,
			"%s: aborted after detecting %d syntax error%s\n",
			argv[0], errflg, errflg == 1 ? "" : "s");
		return 3;
	}

	/* store all aliases in canonical lowercase */
	for (h = e->e_headers, count = 0; h != NULL; h = h->h_next, ++count) {
	  strlower((char*)h->h_pname);
	}

	if (count <= 0) {
		fprintf(stderr, "%s: no aliases found!\n", argv[0]);
		return 4;
	}

	if (indexfile != NULL) {
		if ((indexfp = fopen(indexfile, "w")) == NULL) {
			c = errno;
			fprintf(stderr, "%s: open(\"%s\"): ",
					argv[0], indexfile);
			errno = c;
			perror("");
			return 5;
		}
		setvbuf(indexfp, ibuf, _IOFBF, sizeof ibuf);
		osiop = siofds[FILENO(indexfp)];
		siofds[FILENO(indexfp)] = NULL;
	} else
		indexfp = NULL;
	maxsize = size = 0;
	cp = ":";	/* anything that can't be an alias */
	for (h = e->e_headers ; h != NULL ; h = h->h_next) {
		offset = 2 + strlen(h->h_pname);
		/* offset += offset >= 7 ? 1 : 8 - offset%8; */
		prevsize = size;
		size = ftell(stdout);
		if (size - prevsize > maxsize)
			maxsize = size - prevsize;
		if (*cp == *(h->h_pname) && STREQ(cp, h->h_pname)) {
			fprintf(stderr, "%s: multiple definitions of '%s'.\n",
					argv[0], h->h_pname);
			cp = ":";
		}
		prevsize = size + offset; /* prevsize is convenient scratch */
		if (indexfp != NULL) {
			if (fprintf(indexfp, "%s\t%ld\n",
					     h->h_pname, prevsize) == EOF)
				++errflg;
			if (errflg)
				break;
		}
		cp = h->h_pname;
		hdr_print(h, stdout);
	}
	if (verbose) {
		prevsize = size;
		size = ftell(stdout);
		if (size - prevsize > maxsize)
			maxsize = size - prevsize;
		fprintf(stderr,
			"%d aliases, longest %ld bytes, %ld bytes total\n",
			count, maxsize, size);
	}
	if (fflush(stdout) == EOF)
		++errflg;
	if (indexfp != NULL) {
		siofds[FILENO(indexfp)] = osiop;
		if (fclose(indexfp) == EOF)
			++errflg;
	}
	if (errflg)
		fprintf(stderr, "%s: I/O error while writing output!\n",
				argv[0]);
	return errflg;
}
#endif /* ... dead code */

#ifdef DEBUG_FOPEN
void
report_fds(fp)
FILE *fp;
{
	int fdnro;
	int lastfd = getdtablesize();
	fd_set fdset;
	struct timeval tv;
	extern int errno;

	fprintf(fp,"File handles: %d/",lastfd);

	for (fdnro = 0; fdnro < lastfd; ++fdnro) {
	  char ss[4];
	  char *s = ss;
	  *s = 0;
	  tv.tv_sec = 0;
	  tv.tv_usec = 0;
	  FD_ZERO(&fdset);
	  FD_SET(fdnro,&fdset);
	  errno = 0;
	  if (select(lastfd,&fdset,NULL,NULL,&tv) != -1)
	    *s++ = 'r';
	  tv.tv_sec = 0;
	  tv.tv_usec = 0;
	  FD_ZERO(&fdset);
	  FD_SET(fdnro,&fdset);
	  if (select(lastfd,NULL,&fdset,NULL,&tv) != -1)
	    *s++ = 'w';
	  *s = 0;
	  if (ss[0] != 0)
	    fprintf(fp," %d%s",fdnro,ss);
	}
	fprintf(fp,"\n");
	fflush(fp);
}
#endif


/*
 *  zap_DSN_notify()
 *
 *  To be called immediately after a new nattr value has been generated,
 *  and thus a new storage variable for it exists!
 *
 *  scrubbedset=$(zapDSNnotify attrlistvarname [diagname finalsuccessrcpt])
 *

 +
 +  Damn...  The issues here are rather complicated.
 +  These routines will be suspended for a while pending further
 +  analysis.  [mea/10-sept-2000]
 +

 */
static int zap_DSN_notify(argc, argv)
     int argc;
     const char *argv[];
{
#if 1
	return 0;
#else
	conscell *l, *lc, **pl;
	conscell *l1, *tmp;
	int notifysuccess = 0;
	int notifytrace   = 0;
	int len;
	char *s;
	const char *onam             = argv[1];
	const char *diagname         = argv[2];
	const char *finalsuccessrcpt = argv[3];
	const char *diagaddr         = argv[4];

	if (!diagname)         finalsuccessrcpt = NULL;
	if (!finalsuccessrcpt) diagaddr         = NULL;

	l1 = v_find(onam);
	if (!l1) return 0;
	l = cdr(l1);
	lc = l1 = NULL;

	pl = &car(l);
	l = *pl;
	for (lc = l; lc && cdr(lc); pl = &cddr(lc),lc = *pl) {
	  if (!STRING(lc))
	    return 0; /* ?? */
	  if (STREQ("DSN",lc->string)) {
	    lc = cdr(lc);
	    if (!lc || !STRING(lc))
	      return 0;
	    break;
	  }
	}
	if (!lc) return 0; /* No DSN data */

	s = lc->string;

	if (D_sequencer)
	  fprintf(stderr," zapDSNnotify('%s') DSN='%s'  -> ", onam, s);

	while (*s) {
	  if (CISTREQN(s,"NOTIFY=",7)) {
	    char *p = s+7;
	    /* While non-blank (parameter) string */
	    while (*p && *p != ' ' && *p != '\t') {
	      if (*p == ',') {
		++p;
		continue;
	      }
	      if (CISTREQN(p,"SUCCESS",7)) {
		notifysuccess=1;
		if (p[7] == ',')
		  strcpy(p,p+8); /* ZAP the "SUCCESS," status! */
		else
		  strcpy(p,p+7); /* ZAP the "SUCCESS" status! */
		continue;
	      }
	      if (CISTREQN(p,"TRACE",5)) {
		notifytrace = 1;
		if (p[5] == ',')
		  strcpy(p,p+6); /* ZAP the "TRACE," status! */
		else
		  strcpy(p,p+5); /* ZAP the "TRACE" status! */
		continue;
	      }
	      ++p;
	    }
	    /* Ok,  Now we may have e.g.:
	         i1: NOTIFY=NEVER
	         o1: NOTIFY=NEVER
		 i2: NOTIFY=SUCCESS,DELAY,FAILURE
		 o2: NOTIFY=DELAY,FAILURE
		 i3: NOTIFY=DELAY,SUCCESS,FAILURE
		 o3: NOTIFY=DELAY,FAILURE
		 i4: NOTIFY=DELAY,FAILURE,SUCCESS
		 o4: NOTIFY=DELAY,FAILURE,
		 i5: NOTIFY=SUCCESS
		 o5: NOTIFY=
	       of which the o4 needs trailing comma cleanup,
	       and o5 zapping of the entire NOTIFY parameter. */

	    if (p > s && p[-1] == ',') /* Case 4 */
	      p[-1] = ' '; /* An extra comma to zap */

	    if (p > s && p[-1] == '=') /* Case 5 */ {
	      while (*p == ' ' || *p == '\t') ++p;
	      strcpy(s, p); /* That the entire NOTIFY= parameter */
	      continue;
	    }

	    /* Skip over trailing whitespace */
	    while (*p == ' ' || *p == '\t') ++p;
	    s = p;
	    continue; /* This is done, restart */
	  } /* end of  if ("NOTIFY=") */

	  /* Nothing recognized, scan over the non-blank string */
	  while (*s && *s != ' ' && *s != '\t') ++s;
	  /* And possible trailing whitespace */
	  while (      *s == ' ' || *s == '\t') ++s;
	}

	if (D_sequencer)
	  fprintf(stderr,"'%s'  rc=%d\n", lc->string, notifysuccess);

	if (!notifysuccess && !notifytrace) return 0; /* We are DONE! */

	/* Now depending are we handling a mailing-list expansion, or
	   an alias expansion (RFC 1891, 6.2.7.*) we either report
	   "delivered" to the list input address, OR "expanded"
	   for aliases and .forwards (single recipient ones should
	   *not* report anything but rewrite the recipient address,
	   but we slip at that..) */

	s = lc->string;
	len = strlen(s);

	if (diagname)         len += strlen(diagname)+2;
	if (finalsuccessrcpt) len += strlen(finalsuccessrcpt)+2;
	if (diagaddr)         len += strlen(diagaddr)+2;

	s = (char *)realloc(s, len+23);
	if (!s) return -1; /* Hardly happens, but... */

	lc->string = s;

	s += len;

	if (notifysuccess && notifytrace)
	  strcpy(s, " NTRACE=SUCCESS,TRACE");
	else if (notifysuccess)
	  strcpy(s, " NTRACE=SUCCESS");
	else if (notifytrace)
	  strcpy(s, " NTRACE=TRACE");

	if (notifysuccess) {
	  s += strlen(s);
	  if (diagname)         sprintf(s,";%s", diagname);
	  s += strlen(s);
	  if (finalsuccessrcpt) sprintf(s,";%s", finalsuccessrcpt);
	  s += strlen(s);
	  if (diagaddr)         sprintf(s,";%s", diagaddr);
	}

	return notifysuccess;
#endif
}


/*
 *  post_zap_DSN_notify()
 *
 *  To be called immediately after a new nattr value has been generated,
 *  and thus a new storage variable for it exists!
 *
 *  $(postzapDSNnotify chainvarname)
 *
 *  If the variable called  chainvarname  has more than one address
 *  entry -- ( ((x x x x))  ((x x x x)) ) -- then we leave this NTRACE=
 *  data to be as is.  If the variable has only ONE address ( ((x x x x)) )
 *  AND the ...............

 +
 +  Damn...  The issues here are rather complicated.
 +  These routines will be suspended for a while pending further
 +  analysis.  [mea/10-sept-2000]
 +

 */
static int post_zap_DSN_notify(argc, argv)
     int argc;
     const char *argv[];
{
#if 1
	return 0;
#else
	conscell *l, *lc, **pl;
	conscell *l1, *tmp, *l0;
	int notifysuccess = 0;
	int notifytrace   = 0;
	int len;
	char *s;
	const char *onam = argv[1];

	l0 = v_find(onam);
	if (!l0) return 0;

	l = cdr(l1);
	lc = l1 = NULL;

	pl = &car(l);
	l = *pl;
	for (lc = l; lc && cdr(lc); pl = &cddr(lc),lc = *pl) {
	  if (!STRING(lc))
	    return 0; /* ?? */
	  if (STREQ("DSN",lc->string)) {
	    lc = cdr(lc);
	    if (!lc || !STRING(lc))
	      return 0;
	    break;
	  }
	}
	if (!lc) return 0; /* No DSN data */

	s = lc->string;

	if (D_sequencer)
	  fprintf(stderr," postzapDSNnotify('%s') DSN='%s'  -> ", onam, s);

	while (*s) {
	  if (CISTREQN(s,"NOTIFY=",7)) {
	    char *p = s+7;
	    /* While non-blank (parameter) string */
	    while (*p && *p != ' ' && *p != '\t') {
	      if (*p == ',') {
		++p;
		continue;
	      }
	      if (CISTREQN(p,"SUCCESS",7)) {
		notifysuccess=1;
		if (p[7] == ',')
		  strcpy(p,p+8); /* ZAP the "SUCCESS," status! */
		else
		  strcpy(p,p+7); /* ZAP the "SUCCESS" status! */
		continue;
	      }
	      if (CISTREQN(p,"TRACE",5)) {
		notifytrace = 1;
		if (p[5] == ',')
		  strcpy(p,p+6); /* ZAP the "TRACE," status! */
		else
		  strcpy(p,p+5); /* ZAP the "TRACE" status! */
		continue;
	      }
	      ++p;
	    }
	    /* Ok,  Now we may have e.g.:
	         i1: NOTIFY=NEVER
	         o1: NOTIFY=NEVER
		 i2: NOTIFY=SUCCESS,DELAY,FAILURE
		 o2: NOTIFY=DELAY,FAILURE
		 i3: NOTIFY=DELAY,SUCCESS,FAILURE
		 o3: NOTIFY=DELAY,FAILURE
		 i4: NOTIFY=DELAY,FAILURE,SUCCESS
		 o4: NOTIFY=DELAY,FAILURE,
		 i5: NOTIFY=SUCCESS
		 o5: NOTIFY=
	       of which the o4 needs trailing comma cleanup,
	       and o5 zapping of the entire NOTIFY parameter. */

	    if (p > s && p[-1] == ',') /* Case 4 */
	      p[-1] = ' '; /* An extra comma to zap */

	    if (p > s && p[-1] == '=') /* Case 5 */ {
	      while (*p == ' ' || *p == '\t') ++p;
	      strcpy(s, p); /* That the entire NOTIFY= parameter */
	      continue;
	    }

	    /* Skip over trailing whitespace */
	    while (*p == ' ' || *p == '\t') ++p;
	    s = p;
	    continue; /* This is done, restart */
	  } /* end of  if ("NOTIFY=") */

	  /* Nothing recognized, scan over the non-blank string */
	  while (*s && *s != ' ' && *s != '\t') ++s;
	  /* And possible trailing whitespace */
	  while (      *s == ' ' || *s == '\t') ++s;
	}

	if (D_sequencer)
	  fprintf(stderr,"'%s'  rc=%d\n", lc->string, notifysuccess);

	if (!notifysuccess && !notifytrace) return 0; /* We are DONE! */

	/* Now depending are we handling a mailing-list expansion, or
	   an alias expansion (RFC 1894, 6.2.7.*) we either report
	   "delivered" to the list input address, OR "expanded"
	   for aliases and .forwards (single recipient ones should
	   *not* report anything but rewrite the recipient address,
	   but we slip at that..) */

	s = lc->string;
	len = strlen(s);

	s = (char *)realloc(s, len+23);
	if (!s) return -1; /* Hardly happens, but... */

	lc->string = s;

	s += len;

	if (notifysuccess && notifytrace)
	  strcpy(s, " NTRACE=SUCCESS,TRACE");
	else if (notifysuccess)
	  strcpy(s, " NTRACE=SUCCESS");
	else if (notifytrace)
	  strcpy(s, " NTRACE=TRACE");

	return notifysuccess;
#endif
}


/* listexpand()  -- do a bunch of tasks usually done with a group of
   functions, starting with  "listaddresses" ... */

static conscell *
run_listexpand(avl, il)
	conscell *avl, *il;
{
	struct header hs;
	struct envelope *e;
	struct address *ap, *aroot = NULL, **atail = &aroot;
	token822 *t;
	conscell *al = NULL, *alp = NULL, *tmp = NULL;
	conscell *plustail = NULL, *domain = NULL;
	conscell *l, *lrc;
	char *localpart = NULL, *origaddr = NULL, *attributenam = NULL;
	int   c, n, errflag, stuff;
	volatile int cnt;
	const char *comment, *erroraddress;
	char *s, *s_end;
	int   privilege = -1;
	struct siobuf *osiop = NULL;
	FILE *mfp = NULL, *fp;
	char  buf[4096];
	char  DSNbuf[4096+200];
	int   fd2;
	char *olderrors = errors_to;
	char *notary = NULL;
	int   no_dsn = 0;
	int   okaddresses = 0;
	int   errcount = 0;
	int   linecnt = 0;
	int   euid = geteuid();
	GCVARS3;


	il = cdar(avl); /* The CDR (next) of the arg list.. */

	errflag = 0;
	erroraddress = NULL;
	comment = "list";
	zoptind = 1;

	while (il != NULL && STRING(il) && il->string[0] == '-' &&
	       cdr(il) != NULL && STRING(cdr(il))) {
	  switch( il->string[1] ) {
	    case 'c':
	      comment = (char*)cdr(il)->string;
	      if (strchr(comment,'\n') || strchr(comment,'\r'))
		errflag = 1;
	      break;
	    case 'p':
	      privilege = atoi((char*)cdr(il)->string);
	      break;
	    case 'e':
	      erroraddress = (char*)cdr(il)->string;
	      if (strchr(erroraddress,'\n') || strchr(erroraddress,'\r'))
		errflag = 1;
	      break;
	    case 'E':
	      if (errors_to != olderrors)
		free(errors_to);
	      errors_to = strdup((char*)cdr(il)->string);
	      if (strchr(errors_to,'\n') || strchr(errors_to,'\r'))
		errflag = 1;
	      break;
	    case 'N':
	      notary = (char *)cdr(il)->string;
	      if (strchr(notary,'\n') || strchr(notary,'\r'))
		errflag = 1;
	      if (STREQ(notary,"-")) no_dsn = 1;
	      break;
	    default:
	      errflag = 1;
	      break;
	  }
	  il = cddr(il); /* Skip TWO entries at the time! */
	}
	if (privilege < 0)
	  privilege = nobody;

	cnt = 0;
	tmp = il;
	for (; tmp != NULL; tmp = cdr(tmp)) ++cnt; /* Count arguments.. */

	if (errflag || cnt < 3 || cnt > 5 ||
	    !STRING(il) || !STRING(cdr(il)) || !STRING(cddr(il)) ) {
		fprintf(stderr,
			"Usage: %s [ -e error-address ] [ -E errors-to-address ] [-p privilege] [ -c comment ] [ -N notarystring ] $attribute $localpart $origaddr [$plustail [$domain]] [ [<] /file/path ]\n",
		car(avl)->string);
		if (errors_to != olderrors)
		  free(errors_to);
		errors_to = olderrors;
		return NULL;
	}

	attributenam = (char*)    (il)->string;
	localpart    = (char*) cdr(il)->string;
	origaddr     = (char*) cddr(il)->string;
	if (cdr(cddr(il))) {
	  plustail = cdr(cddr(il));
	  if (cddr(cddr(il)))
	    domain = cddr(cddr(il));
	}
	

	/* We (memory-)leak this stuff for a moment.. (but it is tmalloc()ed)*/
	e = (struct envelope *)tmalloc(sizeof (struct envelope));
	e->e_nowtime = now;
	e->e_file = (char*) car(avl)->string;
	/* we only need sensible `e' if its a time stamp header,
	   which it ain't, so "listaddress" is just fine for e_file .. */

	hs.h_descriptor = &aliashdr;
	hs.h_pname = (char*) car(avl)->string;

	initzline(4096);

	/*
	 * These hoops are so we can do this for both real stdin and
	 * the fake I/O stuff in ../libsh.
	 */
	if ((fp = fdopen(0, "r")) == NULL) {
		fprintf(stderr, "%s: fdopen failed\n", car(avl)->string);
#ifdef DEBUG_FOPEN
		report_fds(stderr);
#endif
		if (errors_to != olderrors)
		  free(errors_to);
		errors_to = olderrors;
		return NULL;
	}
	fd2 = dup(0);	/* Copy the file handle for later returning
			   AFTER an fclose() has closed the primary
			   copy.. */

	/* use a constant buffer to avoid memory leaks from stdio usage */
	setvbuf(fp, buf, _IOFBF, sizeof buf);
	c = 0;
	while ((n = zgetline(fp)) > 0) {
		++linecnt;
		/*
		 * For sendmail compatibility, addresses may not cross line
		 * boundaries, and line boundary is just as good an address
		 * separator as comma is, sigh.
		 * Also lines beginning with '#' are comments, and blank
		 * lines are (sortof) comments too.
		 */
		if (zlinebuf[n-1] == '\n')
			--n;
		if (zlinebuf[0] == '#')
			continue;

		stuff = 0;
		s_end = & zlinebuf[n];
		for (s = zlinebuf; s < s_end; ++s) {
			if (isascii(*s) && !isspace(*s))
				c = stuff = 1;
			if (*s == ',')
				c = 0;
		}
		if (!stuff)
			continue;
		if (c) {
			zlinebuf[n] = ',';
			++n;
		}

		/* NOTE:
		   the '#' commenting in input file must be handled
		   in THIS code, not delayed into  hdr_scanparse() ! */

		if (zlinebuf[0] == '#')
		  continue;

/* #ifdef SENDMAIL_COMPABILITY_KLUDGE */
		/**
		 * Additional sendmail compability kludge ++haa
		 * If address starts with \, zap the \ character.
		 * This is just to not to force people to edit their
		 * .forwards :-(  "\haa" works as expected  :-)
		 **/
		if (zlinebuf[0] == '\\') zlinebuf[0] = ' ';
		for (s = zlinebuf+1; s < s_end; ++s) {
		  if (s[-1] == ',' && s[0]=='\\') s[0] = ' ';
		}
		/* end of sendmail compatibility kluge */
/* #endif */

		/* create h->h_lines */
		/*
		 * It is best to maintain a line at a time as tokens,
		 * so errors will print out nicely.
		 */

		hs.h_lines = t = makeToken(zlinebuf, n);
		t->t_type = Line;

		/* fix up any trailing comma (more sendmail
		   compatibility kluges) */
		s = (char*)t->t_pname + TOKENLEN(t)-1;
		if (c && (*s == ',' || *s == '\n'))
		  *s = '\0';

		hs.h_contents = hdr_scanparse(e, &hs, 1);
		hs.h_stamp = hdr_type(&hs);

		if (hs.h_stamp == BadHeader || hs.h_contents.a == NULL) {
		  ++errcount;
		  if (hs.h_stamp == BadHeader) {
		    if (erroraddress != NULL) {
		      if (!isErrChannel && !isErrorMsg) {
			if (mfp == NULL) {
			  /* We are likely running under 'runas ..'
			     Do reset now to ROOT, then to TRUSTED, ... */
			  runasrootuser();
			  runastrusteduser();
			  mfp = mail_open(MSG_RFC822);
			  runasrootuser();
			  if (mfp != NULL) {
			    osiop = siofds[FILENO(mfp)];
			    siofds[FILENO(mfp)] = NULL;
			    fprintf(mfp, "channel error\n");
			    fprintf(mfp, "errormsg\n");
			    fprintf(mfp, "to <%s>\n", erroraddress);
			    fprintf(mfp, "to <postoffice>\n");
			    fprintf(mfp, "env-end\n");
			    fprintf(mfp, "From: Error Channel <MAILER-DAEMON>\n");
			    fprintf(mfp, "To: %s\n", erroraddress);
			    fprintf(mfp, "Subject: Error in %s\n", comment);
			    fprintf(mfp, "Precedence: junk\n\n");
			    /* Print the report: */
			    fprintf(mfp,"Input file line number %d:\n",linecnt);
			    hdr_errprint(e, &hs, mfp, comment);
			  }
			} else { /* mfp != NULL */
			  fprintf(mfp,"Input file line number %d:\n",linecnt);
			  hdr_errprint(e, &hs, mfp, comment);
			}
		      }
#if 0
		      if (errcount == 1) /* At the first time only! */
			printf("%s\n", erroraddress);
#endif
		    }
		    fprintf(stderr,"Input file line number %d:\n",linecnt);
		    hdr_errprint(e, &hs, stderr, comment);
		  } else {		/* if (hs.h_contents.a == NULL) */
#if 0 /* Hmmm... We CAN have empty input lines! */
		    if (errcount == 1) {
		      /* Print only for the first intance.. */
		      if (erroraddress != NULL)
			printf("%s\n", erroraddress);
		      fprintf(stderr, "listexpand: null input on line %d of STDIN\n", linecnt);
		    }
#endif
		  }
		  continue;
		}

		*atail = hs.h_contents.a;
		while (*atail != NULL)
		  atail = &((*atail)->a_next);

		++okaddresses;
		
	}


	fclose(fp);	/* Now we discard the stdio buffers, but not the
			   fd number 0!  Actually we use a copy of it..	*/
	dup2(fd2,0);	/* Return the fd to descriptor 0..		*/
	close(fd2);	/* .. and discard the backup copy..		*/

	if (okaddresses == 0 && !isErrChannel && !isErrorMsg) {
		/* If the file is empty, use error address ...
		   Except when this is already an error mesage, say nothing! */

		if (erroraddress == NULL)
			erroraddress = "postmaster";

		hs.h_lines = t = makeToken(erroraddress, strlen(erroraddress));
		t->t_type = Line;

		/* fix up any trailing comma (more sendmail
		   compatibility kluges) */
		s = (char*)t->t_pname + TOKENLEN(t)-1;
		if (c && (*s == ',' || *s == '\n'))
		  *s = '\0';

		hs.h_contents = hdr_scanparse(e, &hs, 1);
		hs.h_stamp = hdr_type(&hs);

		if (hs.h_stamp == BadHeader || hs.h_contents.a == NULL) {
		  /* OUTCH!  Even the "erroraddress" parameter is illegal! */
		  fprintf(stderr,"listexpand: input parameters bad, empty input, even 'erroraddress' bad!\n");
		} else {

		  *atail = hs.h_contents.a;
		  while (*atail != NULL)
		    atail = &((*atail)->a_next);
		}

		if (mfp == NULL) {
		  /* We are likely running under 'runas ..'
		     Do reset now to ROOT, then to TRUSTED, ... */
		  runasrootuser();
		  runastrusteduser();
		  mfp = mail_open(MSG_RFC822);
		  runasrootuser();
		  if (mfp != NULL) {
		    osiop = siofds[FILENO(mfp)];
		    siofds[FILENO(mfp)] = NULL;
		    fprintf(mfp, "channel error\n");
		    fprintf(mfp, "errormsg\n");
		    fprintf(mfp, "to <%s>\n", erroraddress);
		    fprintf(mfp, "to <postoffice>\n");
		    fprintf(mfp, "env-end\n");
		    fprintf(mfp, "From: Error Channel <MAILER-DAEMON>\n");
		    fprintf(mfp, "To: %s\n", erroraddress);
		    fprintf(mfp, "Subject: Error in %s\n", comment);
		    fprintf(mfp, "Precedence: junk\n\n");
		    /* Print the report: */
		    fprintf(mfp,"NO valid recipient addresses!\n");
		    fprintf(mfp,"Verify source file protection/ownership/access-path, and content.\n");
		    fprintf(mfp,"Current effective UID = %d\n", euid);
		  }
		} else { /* mfp != NULL */
		  fprintf(mfp,"\nNO valid recipient addresses!\n");
		  fprintf(mfp,"Verify source file protection/ownership/access-path, and content.\n");
		  fprintf(mfp,"Current effective UID = %d\n", euid);
		}
	}

	if (mfp != NULL) {
	  siofds[FILENO(mfp)] = osiop;
	  mail_close(mfp);
	}

	cnt = 0;

	al = l = lrc = NULL;
	GCPRO3(al, l, lrc);

	for (ap = aroot; ap != NULL; ap = ap->a_next) {
		int rc, slen;
		memtypes omem;
		char *s2, *se;
		struct addr *pp;

		for (pp = ap->a_tokens; pp != NULL; pp = pp->p_next)
			if (pp->p_type == anAddress)
				break;
		if (pp == NULL)
			continue;

		buf[0] = 0;
		pureAddressBuf(buf,sizeof(buf),pp);

		if (buf[0] == 0) continue; /* Burp ??? */

#define cdddr(x) cdr(cddr(x))

#define use_lapply 1
#ifdef use_lapply
		if (!no_dsn) {
		  *DSNbuf = 0;
		  if (notary != NULL)
		    strncpy(DSNbuf,notary,sizeof(DSNbuf)-30);
		  DSNbuf[sizeof(DSNbuf)-30] = 0; /* Be brutal, and chop
						    off the tail, if it is
						    too long.. */
		  s2 = strlen(DSNbuf)+DSNbuf;
		  if (s2 > DSNbuf)
		    strcpy(s2++," ");
		  strcpy(s2,"ORCPT=rfc822;");
		  s2 += strlen(s2);
		  se = DSNbuf + sizeof(DSNbuf)-1; /* BUF-end */
		  s = buf;
		  while (*s) {
		    c = *s;
		    if ('!' <= c && c <= '~' && c != '+' && c != '=') {
		      if (s2 < se)
			*s2++ = c;
		    } else if (s2 < se) {
		      sprintf(s2,"+%02X",c);
		      s2 += 3;
		    }
		    ++s;
		  }
		  *s2 = 0;
		  s = newattribute_2(attributenam,"DSN",DSNbuf);
		} else {
		  s = attributenam;
		}

		omem = stickymem;
		/* stickymem = MEM_MALLOC; */

		/* The set of parameters for the rrouter() script
		   function are:
		   - address
		   - origaddress
		   - Attribute variable name
		   - plustail
		   - domain
		   (The last two were added in June-1998)
		*/

		slen = strlen(buf);
		l         = newstring(dupnstr(buf, slen), slen);
		slen = strlen(origaddr);
		cdr(l)    = newstring(dupnstr(origaddr, slen), slen);
		slen = strlen(s);
		cddr(l)   = newstring(dupnstr(s, slen), slen);
		if (plustail != NULL) {
		  cdr(cddr(l))  = s_copy_chain(plustail);
		  if (domain != NULL)
		    cddr(cddr(l)) = s_copy_chain(domain);
		}
		l = ncons(l);

		stickymem = omem;

		deferit = 0;
		v_set(DEFER, "");

		rc = l_apply("rrouter", l);
		lrc = s_value;
		s_value = NULL;

		omem = stickymem;
		/* stickymem = MEM_MALLOC;
		   s_free_tree(l); */ /* We can clean up the input list */
		stickymem = omem;
#else
		lrc = router(ap, privilege, "recipient");
		rc = (lrc == NULL);
#endif
#if 0 /* XX: This HOLD handling didn't work ?? */
		if (deferit && (d = v_find(DEFER))) {
		  /* s_free_tree(lrc); */
		  lrc = NULL;
		  l = conststring("hold", 4);
		  cdr(l)   = copycell(cdr(d));
		  slen = strlen(buf);
		  cddr(l)  = newstring(dupnstr(buf, slen), slen);
		  cdddr(l) = car(attributes);
		  l = ncons(l);
		  l = ncons(l);
		} else
		  ;
#endif
		if (rc != 0 || lrc == NULL || !LIST(lrc)) {
		  /* $(rrouter xx xx xx)  returned something invalid.. */
#ifdef use_lapply
		  /* s_free_tree(lrc); */
#endif
		  lrc = NULL;
		  continue;
		} else {
		  /*
		   * We expect router to either return
		   * (local - user attributes) or (((local - user attributes)))
		   * or ( ((local - user attr)) ((local - another attr)) )
		   */
		  if (car(lrc) == NULL) {
		    /* duplicate removal trapped it. Empty list! */
		    continue;
		  }
		  if (LIST(car(lrc))) {
		    if (!LIST(caar(lrc)) || !STRING(caaar(lrc))) {
		      fprintf(stderr,
			      "%s: '%s' returned invalid 2-level list: ",
			      progname, ROUTER);
		      s_grind(lrc, stderr);
#ifdef use_lapply
		      /* s_free_tree(lrc); */
#endif
		      lrc = NULL;
		      if (errors_to != olderrors)
			free(errors_to);
		      errors_to = olderrors;
		      UNGCPRO3;
		      return NULL;
		    }
		    l = s_copy_chain(lrc);
		  } else {
		    l = s_copy_chain(lrc);
		    l = ncons(l);
		    l = ncons(l);
		  }

#ifdef use_lapply
		  /* s_free_tree(lrc); */
#endif
		  lrc = NULL;
		}

		/* Now the  "(conscell *) l" contains a route,
		   it is a time to put them together.. */
		/* l ->  ( ((chan param param2 attrs)) )  */
		if (al == NULL) {
		  al  = l;		/* The head anchor */
		  alp = car(al);	/* address list END node ptr */
		  while (cdr(alp) != NULL) {
		    alp = cdr(alp);
		    ++cnt;
		  }
		} else {
		  /*
		     (
		      ((chan param param2 attrs))
		      ((chan param param2 attrs))
		     )
		   */
		  cdr(alp) = car(l);	/* Attach the new list to the old */
		  while (cdr(alp) != NULL) {
		    alp = cdr(alp);	/* .. and traverse to its end ... */
		    ++cnt;
		  }
		}

		/* Debugging.. */
		/* buf[len] = '\n';
		   buf[len+1] = 0;
		   fwrite(buf,1,len+1,stdout); */
	}

#if 0
	if (al == NULL) { /* ERROR! NO ADDRESSES! */
	  int slen;
	  al = conststring("error", 5);
	  cdr(al)  = conststring("expansion", 9);
	  slen = strlen(localpart);
	  cddr(al) = newstring(dupnstr(localpart, slen), slen);
	  al = ncons(al);
	  al = ncons(al);
	}
#endif
	UNGCPRO3;

	if (errors_to != olderrors)
	  free(errors_to);
	errors_to = olderrors;
	return al;

} /* end-of: run_listexpand() */



static int
run_homedir(argc, argv)
	int argc;
	const char *argv[];
{
	struct Zpasswd *pw;
	char *b;
	int err;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s name\n", argv[0]);
		return EX_USAGE;
	}

	pw = zgetpwnam(argv[1]);
	err = errno;
	if (pw == NULL) {
		strlower((char*)argv[1]);
		pw = zgetpwnam(argv[1]);
		err = errno;
		if (pw == NULL) {
		  if (err == 0)      return 2;
		  ++deferit;

		  b = malloc(strlen(argv[1])+10);
		  sprintf(b, "HOME:%s", argv[1]);
		  v_set(DEFER, b);
		  free(b);

		  return 3;
		}
	}
	printf("%s\n", pw->pw_dir);
	return 0;
}

static int
run_822date(argc, argv)
	int argc;
	const char *argv[];
{
	time_t dnow;

	time(&dnow);
	if (argc == 2 && STREQ(argv[1], "-s"))
		printf("%ld\n", dnow);
	else
		printf("%s", rfc822date(&dnow));
	return 0;
}


static int
run_filepriv(argc, argv)
	int argc;
	const char *argv[];
{
	const char *argv0 = argv[0];
	int id;
	struct stat stbuf;
	long fmode = -1;
	long dmode = -1;
	const char *file, *cp;
	char *dir;
	int maxperm = 0666 ^ filepriv_mask_reg; /* XOR.. */
	int fd;

	if (argc > 2 && argv[1][0] == '-' && argv[1][1] == 'M') {
	  ++argv;
	  --argc;
	  maxperm = (int)strtol(argv[1],NULL,8); /* Octal! */
	  ++argv;
	  --argc;
	}
	if (argc == 1 || argc > 3 || (maxperm & (~0664)) != 0) {
		fprintf(stderr, "Usage: %s [-M maxperm] pathname [ uid ]\n", argv0);
		if (maxperm & (~0664))
		  fprintf(stderr, "       maxperm must be 664 or stricter!\n");
		return EX_USAGE;
	}
	file = argv[1];
	if (argc == 3 && isascii(argv[2][0]) && isdigit(argv[2][0])) {
		fmode = S_IFREG|0400;
		id = atoi(argv[2]);
	} else {
		fd = open(file, O_RDONLY, 0);
		if (fd < 0) {
			/* if we can't open it, don't trust it */
			perror(file);
			fprintf(stderr,
				"%s: cannot open(\"%s\")!\n", argv0, file);
			return 2;
		}
		if (fstat(fd, &stbuf) < 0) {
			fprintf(stderr, "%s: cannot fstat(\"%s\")!\n",
				argv0, file);
			close(fd);
			return 3;
		}
		fmode = stbuf.st_mode;
		close(fd);
		id = stbuf.st_uid;
	}
	cp = strrchr(file, '/');
	if (cp == NULL) {
		printf("%d\n", id);
		return 0;
	} else if (cp == file)	/* root path */
		++cp;
#ifdef	USE_ALLOCA
	dir = (char*)alloca(cp - file + 1);
#else
	dir = (char*)emalloc(cp - file + 1);
#endif
	memcpy(dir, file, cp - file);
	dir[cp - file] = '\0';

	/* Use stat(2), we fold symlinks to their final dirs(whatever) */
	if (stat(dir, &stbuf) < 0 || !S_ISDIR(stbuf.st_mode)) {
		fprintf(stderr, "%s: not a directory: \"%s\"!\n",
			argv0, dir);
#ifndef	USE_ALLOCA
		free(dir);
#endif
		return 4;
	}
#ifndef	USE_ALLOCA
	free(dir);
#endif

	dmode = stbuf.st_mode;

	if (!S_ISDIR(dmode)) {
	  /* Directory is not directory ?? */
	  id = nobody;
	}

	if (id != nobody) {
	  if (!S_ISREG(fmode))
	    /* File is not a regular file ?? */
	    id = nobody;
	}

	/*
	 * If it is a  special or directory or writable
	 * by non-owner (modulo permission), don't trust it!
	 * BUT ONLY if the directory where it is has X bits
	 * for group or others!
	 */

	/* Group and World accessibility of the residence directory
	   defines what bits to analyze.
	*/

	switch (dmode & 00011) {
	case 0000:	/* No Group access, no World access */
	  if ((fmode & 07700) & ~maxperm) /* Verify only User bits */
	    id = nobody;
	  break;
	case 0010:	/* Group access, no World access */
	  if ((fmode & 07770) & ~maxperm) /* Verify User and Group bits */
	    id = nobody;
	  break;
	case 0001:	/* No Group access, but yes World ?! */
	case 0011:	/* Group and World accesses */
	  if ((fmode & 07777) & ~maxperm) /* Verify all bits */
	    id = nobody;
	  break;
	}

	if ((dmode & filepriv_mask_dir) && /*If world/group writable*/
	    !(dmode & S_ISVTX))	/* and not sticky, OR */
	  id = nobody;				/* Don't trust */
	if (id != nobody &&
	    stbuf.st_uid != 0 && stbuf.st_uid != id)/*dir owned by root/user*/
	  id = nobody;				/* Don't trust */

	printf("%d\n", id);
	return 0;
}

static int
run_runas(argc, argv)
	int argc;
	const char *argv[];
{
	int uid, r;
	const char *cp;
	static int initeduid = 0;
	static short myuid = -1;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s user function [args...]\n", argv[0]);
		return EX_USAGE;
	}
	cp = argv[1];
	if (*cp == '-')
		uid = -1, ++cp;
	else
		uid = 1;
	if (isdigit(*cp))	/* what if user id is "3com" ? */
		uid *= atoi(cp);
	else			/* look up login name and get uid */
		uid = login_to_uid(cp);

	if (!initeduid)
		myuid = geteuid();
	if (myuid == 0 && uid != 0) {
		if (SETEUID(uid) < 0) {
			fprintf(stderr, "%s: seteuid(%d): %s\n",
				argv[0], uid, strerror(errno));
			return 1;
		}
	}
	/* must be builtin or defined function */
	r = s_apply(argc - 2, argv + 2); /* within:  run_runas() */
	if (myuid == 0 && uid != 0) {
		if (SETEUID(0) < 0)
			abort(); /* user-identity change failed! */
	}

	return r;
}

static int
run_cat(argc, argv)
	int argc;
	const char *argv[];
{
	FILE *fp;
	char buf[8192];
	int i;
	struct stat stbuf;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s [filenames ...]\n", argv[0]);
		return EX_USAGE;
	}

	for ( ;argv[1] != NULL; ++argv) {
	  /* Must be a regular file (via a symlink, though!), no
	     pipes, sockets, devices... */
	  if (stat(argv[1], &stbuf) == 0 && S_ISREG(stbuf.st_mode) &&
	      (fp = fopen(argv[1], "r"))) {
	    for (;!ferror(fp) && !feof(fp);) {
	      i = fread(buf, 1, sizeof(buf), fp);
	      if (i > 0) {
		int j = 0;
		while (j < i)
		  j += fwrite(buf + j, 1, i - j, stdout);
	      } else
		break;
	    }
	    fclose(fp);
	  }
	}
	return 0;
}


static int
run_uid2login(argc, argv)
	int argc;
	const char *argv[];
{
	if (argc != 2 || !isdigit(argv[1][0])) {
		fprintf(stderr, "Usage: %s uid\n", argv[0]);
		return EX_USAGE;
	}
	printf("%s\n", uidpwnam(atoi(argv[1])));
	return 0;
}

static int
run_login2uid(argc, argv)
	int argc;
	const char *argv[];
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s login\n", argv[0]);
		return EX_USAGE;
	}
	printf("%d\n", login_to_uid(argv[1]));
	return 0;
}

static int
run_basename(argc, argv)
	int argc;
	const char *argv[];
{
	const char *cp;
	int len;

	if (argc == 1) {
		fprintf(stderr, "Usage: %s pathname suffix-to-strip\n",
				argv[0]);
		return EX_USAGE;
	}
	cp = strrchr(argv[1], '/');
	if (cp == NULL)
		cp = argv[1];
	else
		++cp;
	if (argc > 2 && (len = strlen(cp) - strlen(argv[2])) > 0) {
		if (STREQ(cp + len, argv[2])) {
			while (len-- > 0)
				putchar(*cp++);
			putchar('\n');
			return 0;
		}
	}
	printf("%s\n", cp);
	return 0;
}

static int
run_syslog(argc, argv)
	int argc;
	const char *argv[];
{
	int c;
	int prio = LOG_INFO;
	int errflg = 0;
	zoptind = 1;

	while ((c = zgetopt(argc, (char*const*)argv, "p:")) != EOF) {
		switch (c) {
		case 'p':	/* priority */
			if(STREQ(zoptarg, "debug")) {
				prio = LOG_DEBUG;
			} else if(STREQ(zoptarg, "info")) {
				prio = LOG_INFO;
			} else if(STREQ(zoptarg, "notice")) {
				prio = LOG_NOTICE;
			} else if(STREQ(zoptarg, "warning")) {
				prio = LOG_WARNING;
			} else if(STREQ(zoptarg, "err")) {
				prio = LOG_ERR;
			} else if(STREQ(zoptarg, "crit")) {
				prio = LOG_CRIT;
			} else if(STREQ(zoptarg, "alert")) {
				prio = LOG_ALERT;
			} else if(STREQ(zoptarg, "emerg")) {
				prio = LOG_EMERG;
			} else {
				++errflg;
			}
			break;
		default:
			++errflg;
			break;
		}
	}

	if (errflg || zoptind != argc - 1) {
		fprintf(stderr, "Usage: %s [-p prio] string\n", argv[0]);
		return EX_USAGE;
	}
	zsyslog((prio, "%s", argv[zoptind]));
	return 0;
}

static int
run_recase(argc, argv)
	int argc;
	const char *argv[];
{
	char *cp;
	int c, flag, errflg, action = 0;

	zoptind = 1;
	errflg = 0;

	while (1) {
		c = zgetopt(argc, (char*const*)argv, "ulp");
		if (c == EOF)
			break;
		switch (c) {
		case 'u':	/* up-case */
		case 'l':	/* low-case */
		case 'p':	/* prettify */
			action = c;
			break;
		default:
			++errflg;
			break;
		}
	}
	if (errflg || zoptind != argc - 1) {
		fprintf(stderr, "Usage: %s [ -u | -l | -p ] -- string\n",
				argv[0]);
		return EX_USAGE;
	}

	switch (action) {
	case 'u':
		strupper((char*)argv[zoptind]);
		break;
	case 'l':
		strlower((char*)argv[zoptind]);
		break;
	case 'p':
		flag = 1;
		for (cp = (char*)argv[zoptind]; *cp != '\0'; ++cp) {
			if (isascii(*cp) && isalnum(*cp)) {
				if (flag && islower(*cp))
					*cp = toupper(*cp);
				else if (!flag && isupper(*cp))
					*cp = tolower(*cp);
				flag = 0;
			} else
				flag = 1;
		}
		break;
	}
	printf("%s\n", argv[zoptind]);
	return 0;
}

#if	defined(XMEM) && defined(CSRIMALLOC)
static int
run_malcontents(argc, argv)
	int argc;
	const char *argv[];
{
	mal_contents(stdout);
}
#endif	/* CSRIMALLOC */


static struct {
	short		 fyitype;
	short		 fyisave;
	const char	*fyiname;
	const char	*fyitext;
} fyitable[] = {
{ FYI_BREAKIN, 0, "breakin",	"external message claims local origin!"	},
{ FYI_BADHEADER, 0, "badheader","message header syntax error!"		},
{ FYI_ILLHEADER, 0, "illheader","null header field name!"		},
{ FYI_NOCHANNEL, 0, "nochannel","a null string input channel was specified" },
{ FYI_NOSENDER, 0, "nosender",	"no sender could be determined!"	},
};

void
optsave(type, e)
	int type;
	struct envelope *e;
{
	int i;

	for (i = 0; i < (sizeof fyitable / sizeof fyitable[0]); ++i) {
		if (type == fyitable[i].fyitype) {
			if (fyitable[i].fyisave) {
				char name[20];
				sprintf(name,"_%s", fyitable[i].fyiname);
				squirrel(e, name, fyitable[i].fyitext);
			}
			fprintf(stderr, "%s: *** %s\n",
				e->e_spoolid,
				fyitable[i].fyitext);
			return;
		}
	}
}

static int
run_squirrel(argc, argv)
	int argc;
	const char *argv[];
{
	int i, j, errflag, flag;

	errflag = 0;
	for (i = 1; i < argc; ++i) {
		if (argv[i][0] == '-') {
			argv[i] = argv[i]+1;
			flag = 0;
		} else
			flag = 1;
		for (j = 0; j < (sizeof fyitable / sizeof fyitable[0]); ++j) {
			if (CISTREQ(argv[i], fyitable[j].fyiname)) {
				fyitable[j].fyisave = flag;
				j = -1;
				break;
			}
		}
		if (j != -1)
			++errflag;
	}
	if (errflag || argc == 1) {
		fprintf(stderr, "Usage: %s [", argv[0]);
		for (j = 0; j < (sizeof fyitable / sizeof fyitable[0]); ++j) {
			if (j > 0)
				fprintf(stderr, " |");
			if (fyitable[j].fyisave)
				fprintf(stderr, " -%s", fyitable[j].fyiname);
			else
				fprintf(stderr, " %s", fyitable[j].fyiname);
		}
		fprintf(stderr, " ]\n");
		return EX_USAGE;
	}
	return 0;
}

static struct headerinfo addrhdr = {
	"route-addr", RouteAddress, Recipient, normal
};

static int
run_822syntax(argc, argv)
	int argc;
	const char *argv[];
{
	struct header hs;
	struct envelope es;
	/*char buf[4096];*/

	if (argc != 2)
		return EX_USAGE;
	es.e_nowtime = now;
	es.e_file = argv[0];
	hs.h_descriptor = &addrhdr;
	hs.h_pname = argv[1];
	hs.h_lines = makeToken(argv[1], strlen(argv[1]));
	hs.h_lines->t_type = Line;
	hs.h_lines->t_next = NULL;
	hs.h_contents = hdr_scanparse(&es, &hs, 0);
	hs.h_stamp = hdr_type(&hs);
	if (hs.h_stamp == BadHeader) {
	    if (z_isterminal(0))
		hdr_errprint(&es, &hs, stderr, "RFC822/976/2822");
	    return 1;
	} else if (hs.h_contents.a == NULL)
	    return 1;
	return 0;
}


static int
run_condquote_(argc, argv, condq)
	int argc, condq;
	const char *argv[];
{
	const char *s;
	int mustquote = 0;
	int c, quoted;
	int spc = 0;
	int errflg = 0;
	const char *appstr = NULL;

	extern int rfc822_mustquote __((const char *, const int));

	/* We remove quotes when they are not needed, and add them when
	   they really are needed! */

	zoptind = 1;
	while (1) {
	  c = zgetopt(argc, (char*const*)argv, "s:a:");
	    
	  if (c == EOF) break;
	  switch (c) {
	  case 's':
	    spc = *zoptarg; /* First char only */
	    break;
	  case 'a':
	    appstr = zoptarg;
	    break;
	  default:
	    ++errflg;
	    break;
	  }
	}
	if (errflg || zoptind != argc - 1) {
	  fprintf(stderr,
		  "Usage: %s [ -s SPCCHR ] [ -a APPENDSTR ] string\n",
		  argv[0]);
	  return EX_USAGE;
	}

	s = argv[zoptind];

	mustquote = rfc822_mustquote(s, spc);
	/* A bitset:
	   0001  Has Quotes
	   0002  Ended while inside a quote
	   0004  Has characters which must be quoted
	*/


	if (!condq || mustquote == 1) {
	  /* Well, we can actually DEQUOTE the thing just fine! */
	  quoted = 0;
	  for (; *s; ++s) {
	    c = *s;
	    if (c == ' ' && spc) {
	      putchar(spc);
	      quoted = 0;
	      continue;
	    }
	    if (quoted) {
	      putchar(c);
	      quoted = 0;
	      continue;
	    }
	    if (c == '\\') {
	      /* A quoted pair! */
	      quoted = 1;
	      putchar(c);
	      c = *++s;
	    } else if (c == '"') {
	      continue; /* Drop it! */
	    } else
	      putchar(c);
	  }
	} else if (mustquote > 1 && !(mustquote & 1) && condq) {
	  /* Has things needing quotes, but no quotes in place! */
	  putchar('"');
	  for (; *s; ++s) {
	    c = *s;
	    if (c == ' ' && spc)
	      putchar(spc);
	    else if (c == '"') {
	      putchar('\\');
	      putchar(c);
	    } else
	      putchar(c);
	  }
	  putchar('"');
	} else {
	  /* The original one.. */
	  for (; *s; ++s) {
	    c = *s;
	    if (c == ' ' && spc)
	      putchar(spc);
	    else if (c == '\\') {
	      putchar(c);
	    } else
	      putchar(c);
	  }
	}
	if (appstr)
	  puts(appstr);

	return 0;
}

static int
run_condquote(argc, argv)
	int argc;
	const char *argv[];
{
  return run_condquote_(argc,argv,1);
}

static int
run_dequote(argc, argv)
	int argc;
	const char *argv[];
{
  return run_condquote_(argc,argv,0);
}
