/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *	Some functions Copyright 1991-1998 Matti Aarnio.
 */

/*
 * The routines in this file implement various C-coded functions that
 * are callable from the configuration file.
 */

#include "mailer.h"
#include <stdio.h>
#include <sys/types.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <ctype.h>
#include <fcntl.h>
#include <sys/file.h>			/* O_RDONLY for run_praliases() */
#include <pwd.h>			/* for run_homedir() */
#include <grp.h>			/* for run_grpmems() */
#include <errno.h>

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

#include "zmsignal.h"
#include "zsyslog.h"
#include "mail.h"
#include "interpret.h"
#include "io.h"
#include "libz.h"
#include "libc.h"

#include "prototypes.h"

#ifndef	_IOFBF
#define	_IOFBF	0
#endif	/* !_IOFBF */

extern conscell *s_value;


/* The builtin functions are declared and initialized here.  */

#define ARGCV __((int argc, const char *argv[]))
static int run_hostname    ARGCV;
static int run_whataddress ARGCV;
static int run_erraddrlog  ARGCV;

static conscell *run_dblookup __((conscell *avl, conscell *il));
extern conscell *sh_car       __((conscell *avl, conscell *il));
static conscell *run_cadr     __((conscell *avl, conscell *il));
static conscell *run_caddr    __((conscell *avl, conscell *il));
static conscell *run_cadddr   __((conscell *avl, conscell *il));
static conscell *run_listexpand   __((conscell *avl, conscell *il));
#if 0
static conscell *run_newattribute __((conscell *avl, conscell *il));
#endif

static int run_stability ARGCV;
static int run_process   ARGCV;
static int run_grpmems   ARGCV;
static int run_praliases ARGCV;
static int run_listaddrs ARGCV;
static int run_homedir   ARGCV;
static int run_822date   ARGCV;
static int run_filepriv  ARGCV;
static int run_runas     ARGCV;
static int run_gensym    ARGCV;
static void free_gensym __((void));
static int run_uid2login ARGCV;
static int run_login2uid ARGCV;
static int run_basename  ARGCV;
static int run_recase    ARGCV;
static int run_squirrel  ARGCV;
static int run_822syntax ARGCV;
static int run_dequote   ARGCV;
static int run_condquote ARGCV;
static int run_syslog    ARGCV;

#if	defined(XMEM) && defined(CSRIMALLOC)
static int run_malcontents ARGCV;
#endif	/* CSRIMALLOC */

extern const char *traps[];
extern int nobody;
extern struct group  *getgrnam __((const char *));
extern struct passwd *getpwnam __((const char *));
extern time_t time __((time_t *));
extern int routerdirloops;

#ifndef strchr
extern char *strchr(), *strrchr();
#endif

struct shCmd fnctns[] = {
{	"relation",	run_relation,	NULL,	NULL,	0	},
{	DBLOOKUPNAME,	NULL,	run_dblookup,	NULL,	SH_ARGV	},
/* The following are optional but are probably a good idea */
{	"db",		run_db,		NULL,	NULL,	0	},
{	"trace",	run_trace,	NULL,	NULL,	0	},
{	"untrace",	run_trace,	NULL,	NULL,	0	},
{	"hostname",	run_hostname,	NULL,	NULL,	0	},
{	"sender",	run_whataddress,NULL,	NULL,	0	},
{	"recipient",	run_whataddress,NULL,	NULL,	0	},
{	"erraddron",	run_erraddrlog,	NULL,	NULL,	0	},
{	"channel",	NULL,		sh_car,	NULL,	SH_ARGV	},
{	"host",		NULL,	run_cadr,	NULL,	SH_ARGV	},
{	"user",		NULL,	run_caddr,	NULL,	SH_ARGV	},
{	"attributes",	NULL,	run_cadddr,	NULL,	SH_ARGV	},
{	"stability",	run_stability,	NULL,	NULL,	0	},
{	"daemon",	run_daemon,	NULL,	NULL,	0	},
{	"process",	run_process,	NULL,	NULL,	0	},
{	"rfc822",	run_rfc822,	NULL,	NULL,	0	},
{	"groupmembers",	run_grpmems,	NULL,	NULL,	0	},
{	"printaliases",	run_praliases,	NULL,	NULL,	0	},
{	"listaddresses",run_listaddrs,	NULL,	NULL,	SH_ARGV	},
{	"listexpand",	NULL,	run_listexpand,	NULL,	SH_ARGV	},
#if 0
{	"newattribute",	NULL,	run_newattribute, NULL,	SH_ARGV	},
#endif
{	"homedirectory",run_homedir,	NULL,	NULL,	0	},
{	"rfc822date",	run_822date,	NULL,	NULL,	0	},
{	"filepriv",	run_filepriv,	NULL,	NULL,	SH_ARGV	},
{	"runas",	run_runas,	NULL,	NULL,	SH_ARGV	},
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
	{	"rfc822",		&D_rfc822	},
	{	"sequencer",		&D_sequencer	},
	{	"rewrite",		&D_hdr_rewrite	},
	{	"router",		&D_router	},
	{	"functions",		&D_functions	},
	{	"on",			&D_functions	},	/* dup */
	{	"compare",		&D_compare	},
	{	"matched",		&D_matched	},
	{	"assign",		&D_assign	},
	{	"regexp",		&D_regnarrate	},
	{	"final",		&D_final	},
	{	"db",			&D_db		},
	{	"bind",			&D_bind		},
	{	"resolv",		&D_resolv	},
	{	"memory",		&D_alloc	},
	{	"except",		0		},
	{	NULL,			0		}
};

/* The builtin trace function. This is also used by command line debug specs */

int
run_trace(argc, argv)
	int argc;
	const char *argv[];
{
	struct debugind *dbi;
	int debug;
	const char *prog;

	if (argc == 1) {
		fprintf(stderr, "Usage: %s all", argv[0]);
		for (dbi = &buggers[0]; dbi->name != NULL; ++dbi)
			fprintf(stderr, "|%s", dbi->name);
		putc('\n', stderr);
		return 1;
	}
	prog = argv[0];
	debug = (strncmp(*argv, "un", 2) != 0);
	while (--argc > 0) {
		++argv;
		if (strcmp(*argv, "off") == 0 || strcmp(*argv, "all") == 0) {
			for (dbi = &buggers[0]; dbi->name != NULL; ++dbi)
			    if (dbi->indicator)
				*(dbi->indicator) = (**argv == (debug?'a':'o'));
			continue;
		} else {
			for (dbi = &buggers[0]; dbi->name != NULL; ++dbi) {
				if (strcmp(*argv, dbi->name) == 0) {
					if (dbi->indicator == NULL)
					  debug = !debug; /* except */
					else
					  *(dbi->indicator) = debug;
					break;
				}
			}
		}
		if (dbi->name == NULL)
			fprintf(stderr, "%s: unknown attribute: %s\n",
					prog, *argv);
	}
	return 0;
}


int gensym;
const char *gs_name = "g%d";

static int
run_gensym(argc, argv)
	int argc;
	const char *argv[];
{
	printf(gs_name, gensym++);
	putchar('\n');
	return 0;
}

static void
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
		return 1;
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

	il = cdar(avl);
	if (il == NULL || !STRING(il) || cdr(il) != NULL) {
		fprintf(stderr, "Usage: %s key\n", car(avl)->string);
		return NULL;
	}
	if ((l = db(car(avl)->string, il->string)) == NULL)
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

static RETSIGTYPE sig_exit __((int));
static RETSIGTYPE
sig_exit(sig)
int sig;
{
	if (canexit) {
#ifdef	MALLOC_TRACE
		dbfree(); zshfree();
#endif	/* MALLOC_TRACE */
		die(0, "signal");
	}
	mustexit = 1;
	/* no need to reenable signal in USG, once will be enough */
}

static int gothup = 0;

RETSIGTYPE
sig_hup(sigarg)
int sigarg;
{
	gothup = 1;
	/* fprintf(stderr,"HUP\n"); */
	SIGNAL_HANDLE(SIGHUP, sig_hup);
}

static void dohup __((int));
static void
dohup(sig)
int sig;
{
	gothup = 0;
	if (traps[SIGHUP] != NULL)
		eval(traps[SIGHUP], "trap", NULL, NULL);
}

/*
 * Run the Router in Daemon mode.
 */

/*
 * STABILITY option will make the router process incoming messages in
 * arrival (modtime) order, instead of randomly determined by position
 * in the router directory.  The scheme is to read in all the names,
 * and stat the files.  It would be possible to reuse the stat information
 * later, but I'm not convinced it is worthwhile since the later stat is
 * an fstat().  On the other hand, if we used splay tree insertion to
 * sort the entries, then the stat buffer could easily be reused in
 * makeLetter().
 *
 * SECURITY WARNING: iff makeLetter does not stat again, then there is
 * a window of opportunity for a Bad Guy to remove a file after it has
 * been stat'ed (with root privs), and before it has been processed.
 * This can be avoided partially by sticky-bitting the router directory,
 * and entirely by NOT saving the stat information we get here.
 */

struct de {
	int		f_name;
	time_t		mtime;
};

static int decmp __((const void *, const void *));
static int
decmp(a, b)
     const void *a, *b;
{
	register const struct de *aa = (const struct de *)a;
	register const struct de *bb = (const struct de *)b;

	return bb->mtime - aa->mtime;
}

static int desize, nbsize;
static struct de *dearray = NULL;
static char *nbarray = NULL;

static void rd_initstability __((void));
static void
rd_initstability()
{
	desize = 1;	/* max. number of directory entries */
	nbsize = 1;
	dearray = (struct de *)emalloc(desize * sizeof (struct de));
	nbarray = (char *)emalloc(nbsize * sizeof (char));
}

static void rd_endstability __((void));
static void
rd_endstability()
{
	if (dearray != NULL)
		free((char *)dearray);
	if (nbarray != NULL)
		free((char *)nbarray);
}

static int rd_doit __((const char *filename, const char *dirs));
static int
rd_doit(filename, dirs)
	const char *filename, *dirs;
{
	/* Do one file, return value is 0 or 1,
	   depending on actually doing something
	   on a file */

#ifdef	USE_ALLOCA
	char *buf;
#else
	static char *buf = NULL;
	static u_int blen = 0;
#endif
	const char *av[3];
	char *p;
	int len;
	char pathbuf[512];
	char *sh_memlevel = getlevel(MEM_SHCMD);
	int thatpid;
	struct stat stbuf;

	*pathbuf = 0;
	if (*dirs) {	/* If it is in alternate dir, move to primary one,
			   and process there! */
	  strcpy(pathbuf,dirs);
	  strcat(pathbuf,"/");
	}
	strcat(pathbuf,filename);

	len = strlen(filename);
	thatpid = 0;
	p = strchr(filename, '-');
	if (p != NULL) {
	  /* message file is "inode-pid" */
	  thatpid = atoi(p+1);

#if 0 /* very old thing, may harm at Solaris 2.6 ! */
	  if (thatpid < 10) {	/* old-style locking.. */
	    thatpid = 0;
	  }
#endif
	  /* Probe it!
	     Does the process exist ? */
	  if (thatpid && kill(thatpid,0)==0 && thatpid != router_id) {
	    /*
	     * an already locked message file,
	     * belonging to another process
	     */
	    if (*dirs) {
	      fprintf(stderr,
		      "** BUG **: %s%s not in primary router directory!\n",
		      dirs,filename);
	    }
	    return 0;
	    /*
	     * This should not happen anywhere but at
	     * primary router directory.  If  xxxx-nn
	     * format file exists anywhere else, it is
	     * a bug time!
	     */
	  }
	}
	if (strncmp(filename,"core",4) != 0 &&
	    (p == NULL || thatpid != router_id)) {
	  /* Not a core file, and ...
	     not already in format of 'inode-pid' */
	  /* If the pid did exist, we do not touch on that file,
	     on the other hand, we need to rename the file now.. */
#ifdef	USE_ALLOCA
	  buf = (char*)alloca(len+16);
#else
	  if (blen == 0) {
	    blen = len+16;
	    buf = (char *)malloc(len+16);
	  }
	  while (len + 12 > blen) {
	    blen = 2 * blen;
	    buf = (char *)realloc(buf, blen);
	  }
#endif
	  /* Figure out its inode number */
	  if (stat(pathbuf,&stbuf) != 0) return 0; /* Failed ?  Well, skip it */
	  if (!S_ISREG(stbuf.st_mode))   return 0; /* Not a regular file ??   */

	  sprintf(buf, "%ld-%d", (long)stbuf.st_ino, router_id);

	  if (eqrename(pathbuf, buf) < 0)
	    return 0;		/* something is wrong, erename() complains.
				   (some other process picked it ?) */
	  filename = buf;
	  /* message file is now "file-#" and belongs to this process */
	}

#ifdef	MALLOC_TRACE
	mal_contents(stdout);
#endif

	gensym = 1;
	av[0] = "process"; /* I think this needs to be here */
	av[1] = filename;
	av[2] = NULL;
	s_apply(2, av); /* "process" filename (within  rd_doit() ) */
	free_gensym();

	setlevel(MEM_SHCMD,sh_memlevel);

#ifdef MALLOC_TRACE
	mal_contents(stdout);
#endif

	return 1;
}

static int rd_stability __((DIR *dirp, const char *dirs));
static int
rd_stability(dirp,dirs)
	DIR *dirp;
	const char *dirs;
{
	int deindex, nbindex, did_cnt;
	int namelen;
	struct dirent *dp;
	struct stat statbuf;
	char pathbuf[512]; /* Enough ? */

	deindex = 0;
	nbindex = 0;
	/* collect the file names */
	while ((dp = readdir(dirp)) != NULL) {
		if (mustexit)
			break;
		if (dp->d_name[0] == '.')
			continue;
		/* Handle only files beginning with number -- plus "core"-
		   files.. */
		if (!(dp->d_name[0] >= '0' && dp->d_name[0] <= '9') &&
		    strncmp(dp->d_name,"core",4) != 0)
			continue;

		/* See that the file is a regular file! */
		sprintf(pathbuf,"%s%s%s", dirs, *dirs?"/":"", dp->d_name);
		if (lstat(pathbuf,&statbuf) != 0) continue; /* ??? */
		if (!S_ISREG(statbuf.st_mode)) continue; /* Hmm..  */

		if (deindex >= desize) {
			desize *= 2;
			dearray =
			  (struct de *)realloc((char *)dearray,
					       desize * sizeof (struct de));
		}

		namelen = strlen(dp->d_name); /* Not everybody has d_namlen.. */

		while (nbindex + namelen + 1 >= nbsize) {
			nbsize *= 2;
			nbarray =
			  (char *)realloc(nbarray,
					  nbsize * sizeof (char));
		}

		/*
		 * The explicit alloc is done because alloc/dealloc
		 * of such small chunks should not affect fragmentation
		 * too much, and allocating large chunks would require
		 * management code and might still do bad things with
		 * the malloc algorithm.
		 */
		dearray[deindex].mtime = statbuf.st_mtime;
		dearray[deindex].f_name = nbindex;
		memcpy(nbarray + nbindex, dp->d_name, namelen+1);
		nbindex += namelen + 1;

		++deindex;
	}
	if (mustexit) {
		return deindex;
	}

	qsort((void *)dearray, deindex, sizeof dearray[0], decmp);

	did_cnt = 0;
	while (deindex-- > 0) {
		if (mustexit)
			break;
		if (gothup) 
			dohup(0);
		did_cnt += rd_doit(nbarray + dearray[deindex].f_name, dirs);

		/* Maybe only process few files out of the low-priority
		   subdirs, so we can go back and see if any higher-priority
		   jobs have been created */
		if ((*dirs) &&
		    ((routerdirloops) && (routerdirloops == did_cnt)))
		  break;

	}
	return did_cnt;
}


static int rd_instability __((DIR *dirp, char *dirs));
static int
rd_instability(dirp, dirs)
	DIR *dirp;
	char *dirs;
{
	struct dirent *dp;
	int did_cnt = 0;
	struct stat statbuf;
	char pathbuf[512];

	while ((dp = readdir(dirp)) != NULL) {
		if (mustexit)
			break;
		if (gothup)
			dohup(0);

		/* Handle only files beginning with number -- plus "core"-
		   files.. */
		if (!(dp->d_name[0] >= '0' && dp->d_name[0] <= '9') &&
		    strncmp(dp->d_name,"core",4) != 0)
			continue;

		/* See that the file is a regular file! */
		sprintf(pathbuf,"%s%s%s", dirs, *dirs?"/":"", dp->d_name);
		if (stat(pathbuf,&statbuf) != 0) continue; /* ??? */
		if (!S_ISREG(statbuf.st_mode)) continue; /* Hmm..  */

		did_cnt += rd_doit(dp->d_name, dirs);

		/* Only process one file out of the low-priority subdirs,
		   so we can go back and see if any higher-priority
		   jobs have been created */
		if (*dirs)
			break;

	}
	return did_cnt;
}


static int
run_stability(argc, argv)
	int argc;
	const char *argv[];
{
	switch (argc) {
	case 1:
		printf("%s %s\n", argv[0], stability ? "on" : "off");
		break;
	case 2:
		if (strcmp(argv[1], "on") == 0) {
			real_stability = 1;
		} else if (strcmp(argv[1], "off") == 0) {
			real_stability = 0;
		} else {
	default:
			fprintf(stderr, "Usage: %s [ on | off ]\n", argv[0]);
			return 1;
		}
		break;
	}
	return 0;
}

int
run_daemon(argc, argv)
	int argc;
	const char *argv[];
{
#define ROUTERDIR_CNT 30
	DIR *dirp[ROUTERDIR_CNT];  /* Lets say we have max 30 router dirs.. */
	char *dirs[ROUTERDIR_CNT];
	int did_cnt, i;
	char *s, *rd, *routerdirs = getzenv("ROUTERDIRS");
	char pathbuf[256];
	memtypes oval = stickymem;
	struct stat stb;

	router_id = getpid();

	SIGNAL_HANDLE(SIGTERM, sig_exit);	/* mustexit = 1 */
	for (i=0; i<ROUTERDIR_CNT; ++i) {
		dirp[i] = NULL; dirs[i] = NULL;
	}
	/* dirp[0] = opendir("."); */	/* assert dirp != NULL ... */
#if 0
#ifdef BSD
	dirp[0]->dd_size = 0;	/* stupid Berkeley bug workaround */
#endif
#endif
	stickymem = MEM_MALLOC;
	dirs[0] = strnsave("",1);
	if (routerdirs) {
		/* Store up secondary router dirs! */
		rd = routerdirs;
		for (i = 1; i < ROUTERDIR_CNT && *rd; ) {
			s = strchr(rd,':');
			if (s)  *s = 0;
			sprintf(pathbuf,"../%s",rd);
			/* strcat(pathbuf,"/"); */

			if (stat(pathbuf,&stb) == 0  && S_ISDIR(stb.st_mode)) {
#if 0
#ifdef	BSD
			  dirp[i]->dd_size = 0;
#endif
#endif
			  dirs[i] = strdup(pathbuf);
			  ++i;
			}
			if (s)
			  *s = ':';
			if (s)
			  rd = s+1;
			else
			  break;
		}
	}
	setfreefd();
	if (stability)
		rd_initstability();
	stickymem = oval;
	did_cnt = 0;
	i = -1;
	for (; !mustexit ;) {
		++i;	/* Increment it */
		/* The last of the alternate dirs ?  Reset.. */
		if (i >= ROUTERDIR_CNT || dirs[i] == NULL) {
			i = 0;

			canexit = 1;
		/*
		 * If a shell signal interrupts us here, there is
		 * potential for problems knowing which file descriptors
		 * are free.  One could add a setfreefd() to the trap
		 * routine, in that case.
		 */
			sleep(sweepintvl);
			canexit = 0;
		}

		/*
		 * We would like to do a seekdir()/rewinddir()
		 * instead of opendir()/closedir()  inside this
		 * loop to avoid allocating and freeing a chunk
		 * of memory all the time.  This can lead to
		 * memory fragmentation and thus growing VM.
		 *
		 * However several systems do NOT guarantee that
		 * rewinddir() will find any new data from the
		 * system...
		 */
		/* rewinddir(dirp[i]); */	/* some system w/o this ? */

#if 0
#ifdef	BUGGY_CLOSEDIR
		/*
		 * Major serious bug time here;  some closedir()'s
		 * free dirp before referring to dirp->dd_fd. GRRR.
		 * XX: remove this when bug is eradicated from System V's.
		 */
		close(dirp[i]->dd_fd);
#endif
		closedir(dirp[i]);
#endif
		dirp[i] = opendir(dirs[i][0] == 0 ? "." : dirs[i]);
		did_cnt = 0;
		if (dirp[i] != NULL) {
		  if (stability)
		    did_cnt = rd_stability(dirp[i],dirs[i]);
		  else
		    did_cnt = rd_instability(dirp[i],dirs[i]);
		}

		if (stability != real_stability) {
			stability = real_stability;
			if (stability == 0)
				rd_endstability();
			else
				rd_initstability();
		}
#if 1
#ifdef	BUGGY_CLOSEDIR
		/*
		 * Major serious bug time here;  some closedir()'s
		 * free dirp before referring to dirp->dd_fd. GRRR.
		 * XX: remove this when bug is eradicated from System V's.
		 */
		close(dirp[i]->dd_fd);
#endif
		closedir(dirp[i]);
		dirp[i] = NULL;
#endif

		if (mustexit)
			break;

		/* Alter router directory.  If processed directory
		   had any job, reset the  index  to the begin.   */
		if (did_cnt > 0)
			i = -1;
	}
	for (i=0; dirp[i] != NULL && i < ROUTERDIR_CNT; ++i) {
#if 0
#ifdef	BUGGY_CLOSEDIR
		/*
		 * Major serious bug time here;  some closedir()'s
		 * free dirp before referring to dirp->dd_fd. GRRR.
		 * XX: remove this when bug is eradicated from System V's.
		 */
		close(dirp[i]->dd_fd);
#endif
		closedir(dirp[i]);
#endif
		free(dirs[i]);
	}
	return 0;
}

/*
 * Based on the name of a message file, figure out what to do with it.
 */

struct protosw {
	const char *pattern;
	const char *function;
} psw[] = {
/*{	"[0-9]*.x400",		"x400"		}, */
/*{	"[0-9]*.fax",		"fax"		}, */
/*{	"[0-9]*.uucp",		"uucp"		}, */
{	"[0-9]*",		"rfc822"	},
};


static int
run_process(argc, argv)
	int argc;
	const char *argv[];
{
	struct protosw *pswp;
	char *file;
	int r;
	char *sh_memlevel = getlevel(MEM_SHCMD);

	if (argc != 2 || argv[1][0] == '\0') {
		fprintf(stderr, "Usage: %s messagefile\n", argv[0]);
		return PERR_USAGE;
	}
#ifdef	USE_ALLOCA
	file = (char*)alloca(strlen(argv[1])+1);
#else
	file = (char*)emalloc(strlen(argv[1])+1);
#endif
	strcpy(file, argv[1]);

	r = 0;	/* by default, ignore it */
	for (pswp = &psw[0]; pswp < &psw[(sizeof psw / sizeof psw[0])]; ++pswp)
		if (strmatch(pswp->pattern, file)) {
			printf("process %s %s\n", pswp->function, file);
			argv[0] = pswp->function;
			r = s_apply(argc, argv); /* process-by-FUNC filename */
			printf("done with %s\n", file);
			if (r)
				printf("status %d\n", r);
			break;
		}

#ifndef	USE_ALLOCA
	free(file);
#endif
	setlevel(MEM_SHCMD,sh_memlevel);

	return r;
}


/*
 * Print a list of the members of a group.
 */

static int
run_grpmems(argc, argv)
	int argc;
	const char *argv[];
{
	char **cpp;
	struct group *grp;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s groupname\n", argv[0]);
		return 1;
	}
	grp = getgrnam(argv[1]);
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
	optind = 1;
	errflg = 0;
	while (1) {
		c = getopt(argc, (char*const*)argv, "vo:t");
		if (c == EOF)
			break;
		switch (c) {
		case 'v':
			++verbose;
			break;
		case 'o':
			indexfile = optarg;
			break;
		case 't':
			tabsep = 1;
			break;
		default:
			++errflg;
			break;
		}
	}
	if (errflg || optind != argc - 1) {
		fprintf(stderr,
			"Usage: %s [ -v ] [ -o indexoutputfile ] aliasfile\n",
			argv[0]);
		return 1;
	}

	e = (struct envelope *)tmalloc(sizeof (struct envelope));
	if ((e->e_fp = fopen(argv[optind], "r")) == NULL) {
		c = errno;
		fprintf(stderr, "%s: open(\"%s\"): ", argv[0], argv[optind]);
		errno = c;
		perror("");
		status = PERR_BADOPEN;
	} else {
		setvbuf(e->e_fp, buf, _IOFBF, sizeof buf);
		osiop = siofds[FILENO(e->e_fp)];
		siofds[FILENO(e->e_fp)] = NULL;
		e->e_file = argv[optind];
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
		h->h_contents = hdr_scanparse(e, h, 1, 0);
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
		if (*cp == *(h->h_pname) && strcmp(cp, h->h_pname) == 0) {
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
	char *localpart, *origaddr, *attributenam;
	int c, n, errflag, stuff;
	volatile int cnt;
	const char *comment, *erroraddress;
	char *s, *s_end;
	int privilege = -1;
	struct siobuf *osiop = NULL;
	FILE *mfp = NULL, *fp;
	char buf[4096];
	char DSNbuf[4096+200];
	int fd2;
	char *olderrors = errors_to;
	char *notary = NULL;
	int no_dsn = 0;
	int okaddresses = 0;
	int errcount = 0;
	int linecnt = 0;
	GCVARS3;

	il = cdar(avl); /* The CDR (next) of the arg list.. */

	errflag = 0;
	erroraddress = NULL;
	comment = "list";
	optind = 1;

	while (il != NULL && STRING(il) && il->string[0] == '-' &&
	       cdr(il) != NULL && STRING(cdr(il))) {
	  switch( il->string[1] ) {
	    case 'c':
	      comment = (char*)cdr(il)->string;
	      if (strchr(comment,'\n') != NULL ||
		  strchr(comment,'\r') != NULL)
		errflag = 1;
	      break;
	    case 'p':
	      privilege = atoi((char*)cdr(il)->string);
	      break;
	    case 'e':
	      erroraddress = (char*)cdr(il)->string;
	      if (strchr(erroraddress,'\n') != NULL ||
		  strchr(erroraddress,'\r') != NULL)
		errflag = 1;
	      break;
	    case 'E':
	      if (errors_to != olderrors)
		free(errors_to);
	      errors_to = strdup((char*)cdr(il)->string);
	      if (strchr(errors_to,'\n') != NULL ||
		  strchr(errors_to,'\r') != NULL)
		errflag = 1;
	      break;
	    case 'N':
	      notary = (char *)cdr(il)->string;
	      if (strchr(notary,'\n') != NULL ||
		  strchr(notary,'\r') != NULL)
		errflag = 1;
	      if (strcmp(notary,"-")==0)
		no_dsn = 1;
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
			"Usage: %s [ -e error-address ] [ -E errors-to-address ] [-p privilege] [ -c comment ] [ -N notarystring ] $attribute $localpart $origaddr [$plustail [$domain]]< /file/path \n",
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

	initline(4096);

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
	fd2 = dup(0);	/* Copy the file handle for latter returning
			   AFTER an fclose() has closed the primary
			   copy.. */

	/* use a constant buffer to avoid memory leaks from stdio usage */
	setvbuf(fp, buf, _IOFBF, sizeof buf);
	c = 0;
	while ((n = getline(fp)) > 0) {
		++linecnt;
		/*
		 * For sendmail compatibility, addresses may not cross line
		 * boundaries, and line boundary is just as good an address
		 * separator as comma is, sigh.
		 */
		if (linebuf[n-1] == '\n')
			--n;
		stuff = 0;
		s_end = &linebuf[n];
		for (s = linebuf; s < s_end; ++s) {
			if (isascii(*s) && !isspace(*s))
				c = stuff = 1;
			if (*s == ',')
				c = 0;
		}
		if (!stuff)
			continue;
		if (c) {
			linebuf[n] = ',';
			++n;
		}

/* #ifdef SENDMAIL_COMPABILITY_KLUDGE */
		/**
		 * Additional sendmail compability kludge ++haa
		 * If address starts with \, zap the \ character.
		 * This is just to not to force people to edit their
		 * .forwards :-(  "\haa" works as expected  :-)
		 **/
		if (linebuf[0] == '\\') linebuf[0] = ' ';
		for (s = linebuf+1; s < s_end; ++s) {
		  if (s[-1] == ',' && s[0]=='\\') s[0] = ' ';
		}
		/* end of sendmail compatibility kluge */
/* #endif */

		/* create h->h_lines */
		/*
		 * It is best to maintain a line at a time as tokens,
		 * so errors will print out nicely.
		 */

		hs.h_lines = t = makeToken(linebuf, n);
		t->t_type = Line;

		/* fix up any trailing comma (more sendmail
		   compatibility kluges) */
		s = (char*)t->t_pname + TOKENLEN(t)-1;
		if (c && (*s == ',' || *s == '\n'))
		  *s = '\0';

		hs.h_contents = hdr_scanparse(e, &hs, 1, 1);
		hs.h_stamp = hdr_type(&hs);

		if (hs.h_stamp == BadHeader || hs.h_contents.a == NULL) {
		  ++errcount;
		  if (hs.h_stamp == BadHeader) {
		    if (erroraddress != NULL) {
		      if (!iserrmessage()) {
			if (mfp == NULL) {
			  if ((mfp = mail_open(MSG_RFC822)) != NULL) {
			    osiop = siofds[FILENO(mfp)];
			    siofds[FILENO(mfp)] = NULL;
			    fprintf(mfp, "channel error\n");
			    fprintf(mfp, "to <%s>\n", erroraddress);
			    fprintf(mfp, "to <postmaster>\n");
			    fprintf(mfp, "env-end\n");
			    fprintf(mfp, "From: Error Channel <MAILER-DAEMON>\n");
			    fprintf(mfp, "To: %s\n", erroraddress);
			    fprintf(mfp, "Cc: The Post Office <postmaster>\n");
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
		      if (errcount == 1) /* At the first time only! */
			printf("%s\n", erroraddress);
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


	if (mfp != NULL) {
	  siofds[FILENO(mfp)] = osiop;
	  mail_close(mfp);
	}

	fclose(fp);	/* Now we discard the stdio buffers, but not the
			   fd number 0!  Actually we use a copy of it..	*/
	dup2(fd2,0);	/* Return the fd to descriptor 0..		*/
	close(fd2);	/* .. and discard the backup copy..		*/

	if (okaddresses == 0) {	/* if the file is empty, use error address */

		if (erroraddress == NULL)
			erroraddress = "postmaster";

		hs.h_lines = t = makeToken(erroraddress, strlen(erroraddress));
		t->t_type = Line;

		/* fix up any trailing comma (more sendmail
		   compatibility kluges) */
		s = (char*)t->t_pname + TOKENLEN(t)-1;
		if (c && (*s == ',' || *s == '\n'))
		  *s = '\0';

		hs.h_contents = hdr_scanparse(e, &hs, 1, 1);
		hs.h_stamp = hdr_type(&hs);

		if (hs.h_stamp == BadHeader || hs.h_contents.a == NULL) {
		  /* OUTCH!  Even the "erroraddress" parameter is illegal! */
		  fprintf(stderr,"listexpand: input parameters bad, empty input, even 'erroraddress' bad!\n");
		} else {

		  *atail = hs.h_contents.a;
		  while (*atail != NULL)
		    atail = &((*atail)->a_next);
		}
	}

	cnt = 0;

	al = l = lrc = NULL;
	GCPRO3(al, l, lrc);

	for (ap = aroot; ap != NULL; ap = ap->a_next) {
		int rc, slen;
		memtypes omem;
		char *s2, *se;

		buf[0] = 0;
		pureAddressBuf(buf,sizeof(buf),ap->a_tokens);

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
		  cdr(cddr(l))  = s_copy_tree(plustail);
		  if (domain != NULL)
		    cddr(cddr(l)) = s_copy_tree(domain);
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
		    l = s_copy_tree(lrc);
		  } else {
		    l = s_copy_tree(lrc);
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

	if (al == NULL) { /* ERROR! NO ADDRESSES! */
	  int slen;
	  al = conststring("error", 5);
	  cdr(al)  = conststring("expansion", 9);
	  slen = strlen(localpart);
	  cddr(al) = newstring(dupnstr(localpart, slen), slen);
	  al = ncons(al);
	  al = ncons(al);
	}
	UNGCPRO3;

	if (errors_to != olderrors)
	  free(errors_to);
	errors_to = olderrors;
	return al;

} /* end-of: run_listexpand() */


static int
run_listaddrs(argc, argv)
	int argc;
	const char *argv[];
{
	struct header hs;
	struct envelope *e;
	struct address *ap, *aroot = NULL, **atail = &aroot;
	token822 *t;
	struct addr *pp;
	int c, n, errflag, stuff;
	const char *comment, *erroraddress;
	char *s, *s_end;
	struct siobuf *osiop = NULL;
	FILE *mfp = NULL, *fp;
	char buf[4096];
	int fd2;
	int okaddresses = 0;
	int errcount = 0, linecnt = 0;
	char *old_errorsto = errors_to;

	errflag = 0;
	erroraddress = NULL;
	comment = "list";
	optind = 1;

	while (1) {
		c = getopt(argc, (char*const*)argv, "c:e:E:");
		if (c == EOF)
			break;
		switch (c) {
		case 'c':
			comment = optarg;
			break;
		case 'e':
			erroraddress = optarg;
			break;
		case 'E':
			if (errors_to != old_errorsto)
			  free(errors_to);
			errors_to = (void*)strdup(optarg);
			break;
		default:
			++errflag;
			break;
		}
	}
	if (errflag) {
	  fprintf(stderr,
		  "Usage: %s [ -e error-address ] [ -E errors-to-address ] [ -c comment ]\n",
		  argv[0]);
	  if (errors_to != old_errorsto)
	    free(errors_to);
	  errors_to = old_errorsto;
	  return 1;
	}
	e = (struct envelope *)tmalloc(sizeof (struct envelope));
	e->e_nowtime = now;
	e->e_file = argv[0];
	/* we only need sensible `e' if its a time stamp header,
	   which it ain't, so "listaddress" is just fine for e_file .. */

	hs.h_descriptor = &aliashdr;
	hs.h_pname = argv[0];

	initline(4096);

	/*
	 * These hoops are so we can do this for both real stdin and
	 * the fake I/O stuff in ../libsh.
	 */
	if ((fp = fdopen(0, "r")) == NULL) {
		fprintf(stderr, "%s: fdopen failed\n", argv[0]);
#ifdef DEBUG_FOPEN
		report_fds(stderr);
#endif
		if (errors_to != old_errorsto)
		  free(errors_to);
		errors_to = old_errorsto;
		return 1;
	}
	fd2 = dup(0);	/* Copy the file handle for latter returning
			   AFTER an fclose() has closed the primary
			   copy.. */

	/* use a constant buffer to avoid memory leaks from stdio usage */
	setvbuf(fp, buf, _IOFBF, sizeof buf);
	c = 0;
	while ((n = getline(fp)) > 0) {
		++linecnt;
		/*
		 * For sendmail compatibility, addresses may not cross line
		 * boundaries, and line boundary is just as good an address
		 * separator as comma is, sigh.
		 */
		if (linebuf[n-1] == '\n')
			--n;
		stuff = 0;
		s_end = &linebuf[n];
		for (s = linebuf; s < s_end; ++s) {
			if (isascii(*s) && !isspace(*s))
				c = stuff = 1;
			if (*s == ',')
				c = 0;
		}
		if (!stuff)
			continue;
		if (c) {
			linebuf[n] = ',';
			++n;
		}

/* #ifdef SENDMAIL_COMPABILITY_KLUDGE */
		/**
		 * Additional sendmail compability kludge ++haa
		 * If address starts with \, zap the \ character.
		 * This is just to not to force people to edit their
		 * .forwards :-(  "\haa" works as expected  :-)
		 **/
		if (linebuf[0] == '\\') linebuf[0] = ' ';
		for (s = linebuf+1; s < s_end; ++s) {
		  if (s[-1] == ',' && s[0]=='\\') s[0] = ' ';
		}
		/* end of sendmail compatibility kluge */
/* #endif */
		/* create h->h_lines */
		/*
		 * It is best to maintain a line at a time as tokens,
		 * so errors will print out nicely.
		 */

		hs.h_lines = t = makeToken(linebuf, n);
		t->t_type = Line;

		/* fix up any trailing comma (more sendmail
		   compatibility kluges) */
		s = (char*)t->t_pname + TOKENLEN(t)-1;
		if (c && (*s == ',' || *s == '\n'))
		  *s = '\0';

		hs.h_contents = hdr_scanparse(e, &hs, 1, 1);
		hs.h_stamp = hdr_type(&hs);

		if (hs.h_stamp == BadHeader || hs.h_contents.a == NULL) {
		  ++errcount;
		  if (hs.h_stamp == BadHeader) {
		    if (erroraddress != NULL) {
		      if (!iserrmessage()) {
			if (mfp == NULL) {
			  if ((mfp = mail_open(MSG_RFC822)) != NULL) {
			    osiop = siofds[FILENO(mfp)];
			    siofds[FILENO(mfp)] = NULL;
			    fprintf(mfp, "channel error\n");
			    fprintf(mfp, "to <%s>\n", erroraddress);
			    fprintf(mfp, "to <postmaster>\n");
			    fprintf(mfp, "env-end\n");
			    fprintf(mfp, "From: Error Channel <MAILER-DAEMON>\n");
			    fprintf(mfp, "To: %s\n", erroraddress);
			    fprintf(mfp, "Cc: The Post Office <postmaster>\n");
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
		      if (errcount == 1) /* At the first time only! */
			printf("%s\n", erroraddress);
		    }
		    fprintf(stderr,"Input file line number %d:\n",linecnt);
		    hdr_errprint(e, &hs, stderr, comment);
		  } else {		/* if (hs.h_contents.a == NULL) */
#if 0
		    if (errcount == 1) {
		      /* Print only for the first intance.. */
		      if (erroraddress != NULL)
			printf("%s\n", erroraddress);
		      fprintf(stderr, "%s: null input on line\n", argv[0]);
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

	if (mfp != NULL) {
	  siofds[FILENO(mfp)] = osiop;
	  mail_close(mfp);
	}


	fclose(fp);	/* Now we discard the stdio buffers, but not the
			   fd number 0!  Actually we use a copy of it..	*/
	dup2(fd2,0);	/* Return the fd to descriptor 0..		*/
	close(fd2);	/* .. and discard the backup copy..		*/

	if (okaddresses == 0) {	/* if the file is empty, use error address */

		if (erroraddress == NULL)
			erroraddress = "postmaster";

		hs.h_lines = t = makeToken(erroraddress, strlen(erroraddress));
		t->t_type = Line;

		/* fix up any trailing comma (more sendmail
		   compatibility kluges) */
		s = (char*)t->t_pname + TOKENLEN(t)-1;
		if (c && (*s == ',' || *s == '\n'))
		  *s = '\0';

		hs.h_contents = hdr_scanparse(e, &hs, 1, 1);
		hs.h_stamp = hdr_type(&hs);

		if (hs.h_stamp == BadHeader || hs.h_contents.a == NULL) {
		  /* OUTCH!  Even the "erroraddress" parameter is illegal! */
		  fprintf(stderr,"%s: input parameters bad, empty input, even 'erroraddress' bad!\n", argv[0]);
		} else {
		  *atail = hs.h_contents.a;
		  while (*atail != NULL)
		    atail = &((*atail)->a_next);
		}
	}

	for (ap = aroot; ap != NULL; ap = ap->a_next) {
		for (pp = ap->a_tokens; pp != NULL; pp = pp->p_next)
			if (pp->p_type == anAddress)
				break;
		if (pp == NULL)
			continue;
		pureAddress(stdout, ap->a_tokens);
		/* printAddress(stdout, ap->a_tokens, 0); */
		putc('\n', stdout);
	}
	/*
	 * XX: If the alias expansion was a mail group,
	 * we didn't print anything.
	 */
	if (errors_to != old_errorsto)
	  free(errors_to);
	errors_to = old_errorsto;
	return 0;
}

static int
run_homedir(argc, argv)
	int argc;
	const char *argv[];
{
	struct passwd *pw;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s name\n", argv[0]);
		return 1;
	}
	pw = getpwnam(argv[1]);
	if (pw == NULL) {
		strlower((char*)argv[1]);
		pw = getpwnam(argv[1]);
		if (pw == NULL)
			return 2;
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
	if (argc == 2 && strcmp(argv[1], "-s") == 0)
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
	const char *file, *cp;
	char *dir;
	int maxperm = 0666 ^ filepriv_mask_reg; /* XOR.. */
	FILE *fp;

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
		return 1;
	}
	file = argv[1];
	if (argc == 3 && isascii(argv[2][0]) && isdigit(argv[2][0]))
		id = atoi(argv[2]);
	else {
		fp = fopen(file, "r");
		if (fp == NULL) {
			/* if we can't open it, don't trust it */
			perror(file);
			fprintf(stderr,
				"%s: cannot fopen(\"%s\")!\n", argv0, file);
			return 2;
		}
		if (fstat(FILENO(fp), &stbuf) < 0) {
			fprintf(stderr, "%s: cannot fstat(\"%s\")!\n",
				argv0, file);
			fclose(fp);
			return 3;
		}
		fclose(fp);
		if (!S_ISREG(stbuf.st_mode)
		    || ((stbuf.st_mode & 07777) & ~maxperm) != 0) {
			/*
			 * If it is a  special or directory or writable
			 * by non-owner (modulo permission), don't trust it!
			 */
			printf("%d\n", nobody);
			return 0;
		}
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
	if (((stbuf.st_mode & filepriv_mask_dir) && /*If world/group writable*/
	     !(stbuf.st_mode & S_ISVTX))	/* and not sticky, OR */
	    || (stbuf.st_uid != 0 && stbuf.st_uid != id))/*owned by root/user*/
		id = nobody;				 /* Don't trust */
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
		return 1;
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
		if (setreuid(0, uid) < 0) {
			fprintf(stderr, "%s: setuid(%d): %s\n",
				argv[0], uid, strerror(errno));
			return 1;
		}
	}
	/* must be builtin or defined function */
	r = s_apply(argc - 2, argv + 2); /* within:  run_runas() */
	if (myuid == 0 && uid != 0) {
		if (setreuid(0, 0) < 0)
			abort(); /* user-identity change failed! */
	}

	return r;
}


static int
run_uid2login(argc, argv)
	int argc;
	const char *argv[];
{
	if (argc != 2 || !isdigit(argv[1][0])) {
		fprintf(stderr, "Usage: %s uid\n", argv[0]);
		return 1;
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
		return 1;
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
		return 1;
	}
	cp = strrchr(argv[1], '/');
	if (cp == NULL)
		cp = argv[1];
	else
		++cp;
	if (argc > 2 && (len = strlen(cp) - strlen(argv[2])) > 0) {
		if (strcmp(cp + len, argv[2]) == 0) {
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
	optind = 1;

	while ((c = getopt(argc, (char*const*)argv, "p:")) != EOF) {
		switch (c) {
		case 'p':	/* priority */
			if(!strcmp(optarg, "debug")) {
				prio = LOG_DEBUG;
			} else if(!strcmp(optarg, "info")) {
				prio = LOG_INFO;
			} else if(!strcmp(optarg, "notice")) {
				prio = LOG_NOTICE;
			} else if(!strcmp(optarg, "warning")) {
				prio = LOG_WARNING;
			} else if(!strcmp(optarg, "err")) {
				prio = LOG_ERR;
			} else if(!strcmp(optarg, "crit")) {
				prio = LOG_CRIT;
			} else if(!strcmp(optarg, "alert")) {
				prio = LOG_ALERT;
			} else if(!strcmp(optarg, "emerg")) {
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

	if (errflg || optind != argc - 1) {
		fprintf(stderr, "Usage: %s [-p prio] string\n", argv[0]);
		return 1;
	}
	zsyslog((prio, "%s", argv[optind]));
	return 0;
}

static int
run_recase(argc, argv)
	int argc;
	const char *argv[];
{
	char *cp;
	int c, flag, errflg, action = 0;

	optind = 1;
	errflg = 0;

	while (1) {
		c = getopt(argc, (char*const*)argv, "ulp");
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
	if (errflg || optind != argc - 1) {
		fprintf(stderr, "Usage: %s [ -u | -l | -p ] string\n",
				argv[0]);
		return 1;
	}

	switch (action) {
	case 'u':
		strupper((char*)argv[optind]);
		break;
	case 'l':
		strlower((char*)argv[optind]);
		break;
	case 'p':
		flag = 1;
		for (cp = (char*)argv[optind]; *cp != '\0'; ++cp) {
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
	printf("%s\n", argv[optind]);
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
			fprintf(stderr, "*** %s\n", fyitable[i].fyitext);
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
			if (cistrcmp(argv[i], fyitable[j].fyiname) == 0) {
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
		return 1;
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
		return 2;
	es.e_nowtime = now;
	es.e_file = argv[0];
	hs.h_descriptor = &addrhdr;
	hs.h_pname = argv[1];
	hs.h_lines = makeToken(argv[1], strlen(argv[1]));
	hs.h_lines->t_type = Line;
	hs.h_lines->t_next = NULL;
	hs.h_contents = hdr_scanparse(&es, &hs, 1, 0);
	hs.h_stamp = hdr_type(&hs);
	if (hs.h_stamp == BadHeader) {
		hdr_errprint(&es, &hs, stderr, "RFC822/976");
		return 1;
	} else if (hs.h_contents.a == NULL)
		return 1;
	return 0;
}


static int
run_dequote(argc, argv)
	int argc;
	const char *argv[];
{
	int len;
	const char *s = argv[1];

	if (argc != 2)
	  return 2; /* Bad bad! Missing/extra arg! */

	len = strlen(s);

	if (len > 1 &&
	    ((*s == '"'  && s[len-1] == '"' ) ||
	     (*s == '\'' && s[len-1] == '\''))) {
	  fwrite(s+1,1,len-2,stdout);
	} else
	  fwrite(s,1,len,stdout);
	putc('\n',stdout);
	return 0;
}


static int
run_condquote(argc, argv)
	int argc;
	const char *argv[];
{
	int len;
	const char *s = argv[1];
	int mustquote = 0;
	int candequote = 0;
	int c;

	/* We remove quotes when they are not needed, and add them when
	   they really are needed! */

	if (argc != 2)
	  return 2; /* Bad bad! Missing/extra arg! */

	c = *s;
	if (c == '"') {
	  ++s; /* Starting quote */
	  while (*s && *s != '"') {
	    /* While within quoted string */
	    if (*s == '\\')
	      ++s;
	    if (*s != 0)
	      ++s;
	  }
	  if (*s != '"')
	    mustquote = 1;
	  else if (*s == 0)
	    candequote = 1;
	}
	while (*s) {
	  if (c == '\\') {
	    ++s;
	    c = *s;
	  } else if (c == ' ' || c == '\t')
	    mustquote = 1; /* Unquoted spaces! */
	  if (c != 0)
	    ++s;
	}

	s = argv[1];
	len = strlen(s);

	/* Quoted, and without a need for quotes */
	if (candequote) {
	  /* XXX: THIS SHOULD REALLY USE SOME SYNTAX SCANNER -- LIKE THAT ONE
	          FOR SMTP: RFC821SCN()    */
	  fwrite(argv[1] + 1, 1, len -2, stdout); /* Dequoted! */
	  putc('\n', stdout);
	  return 0;
	}
	if (mustquote) {
	  /* We need to quote this */
	  s = argv[1];
	  putchar('"'); /* First quote */
	  while (*s) {
	    if (*s == '"' || *s == '\\')
	      putchar('\\');
	    putchar(*s);
	    ++s;
	  }
	  printf("\"\n"); /* The last quote */
	  return 0;
	}
	/* The original one.. */
	printf("%s\n",s);
	return 0;
}
