/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */
/*
 *	Lots of modifications (new guts, more or less..) by
 *	Matti Aarnio <mea@nic.funet.fi>  (copyright) 1992-1995
 */


/*
 * ZMailer router, main and miscellany routines.
 */

#include "mailer.h"
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/file.h>
#include "mail.h"
#include "zsyslog.h"
#include "interpret.h"
#include "splay.h"

#include "prototypes.h"

extern const char *postoffice; /* At libzmailer.a: mail.c */

#if 0
extern struct group *getgrnam __();
extern struct passwd *getpwnam __();
extern struct passwd *getpwuid __();
#endif

extern struct shCmd fnctns[];
extern time_t time __((time_t *));

static void initialize __((const char *configfile, int argc, const char *argv[]));
static void logit __((const char *file, const char *id, const char *from, const char *to));


extern const char *progname; /* At zmsh_init() et.friends */
const char * mailshare;
const char * myhostname = 0;
const char * pidfile = PID_ROUTER;
const char * logfn;
time_t	now;

extern memtypes stickymem;

int	mustexit = 0;
int	canexit = 0;
int	router_id = 0;
int	deferit;
int	deferuid;
int	origoptind;
int	savefile = 0;
const char * zshopts = "-O";
int	nosyslog = 1;

int
main(argc, argv)
	int	    argc;
	const char *argv[];
{
	int c, errflg, daemonflg, killflg, interactiveflg, tac, nrouters;
	int version;
	long offout, offerr;
	char *config, *cp;
	const char *tav[20], *av[3];
#ifdef	XMEM
	FILE *fp;
#endif	/* XMEM */

#ifdef HAVE_SETGROUPS
	/* We null supplementary groups list entirely */
	setgroups(0, NULL);
#endif

	progname = strrchr(argv[0], '/');
	if (progname == NULL)
		progname = argv[0];
	else
		++progname;
	origoptind = optind;	/* needed for reuse of getopt() */
	logfn = config = NULL;
	errflg = daemonflg = killflg = interactiveflg = version = 0;
	tac = 0;
	nrouters = 1;


	while (1) {
		c = getopt(argc, (char*const*)argv, "m:n:dikf:o:t:L:P:sSV");
		if (c == EOF)
			break;
	  
		switch (c) {
		case 'd':	/* become a daemon */
			daemonflg = 1;
			break;
		case 'm':
#ifdef	XMEM
			{ /* Rewritten to be portable...  Storing to
			     fileno()" is not guaranteed to success.. */
			  int fd = open(optarg, O_RDWR|O_CREAT|O_TRUNC,0644);
			  if (fd >= 0) {
			    dup2(fd,30); /* we ASSUME have far less fd's
					    in use.. */
			    close(fd);
			    fp = fdopen(30,"w+");
			    if (!fp) break;
			    mal_setstatsfile(fp);
			    mal_trace(1);
			    mal_debug(3);
			  }
			}
#endif	/* XMEM */
			break;
		case 'n':
			nrouters = atoi(optarg);
			if (nrouters < 1)
				nrouters = 1;
			break;
		case 'o':
			zshopts = optarg;
			break;
		case 't':
			if (tac < (sizeof tav)/(sizeof tav[0]))
				tav[++tac] = optarg;
			else {
				fprintf(stderr, "Too many trace options!\n");
				fprintf(stderr, "Ignoring '%s'\n", optarg);
			}
			break;
		case 'f':	/* override default config file */
			config = optarg;
			break;
		case 'i':	/* first read config file, then read from tty */
			interactiveflg = 1;
			break;
		case 'k':	/* kill the previous daemon upon startup */
			killflg = 1;
			break;
		case 's':
			stability = !stability;
			break;
		case 'S':	/* Logging also always to SYSLOG,
				   not only at serious stuff */
			nosyslog = 0;
			break;
		case 'L':	/* override default log file */
			logfn = optarg;
			break;
		case 'P':	/* override default postoffice */
			postoffice = optarg;
			break;
		case 'V':
			version = 1;
			break;
		case '?':
		default:
			errflg++;
			break;
		}
	}

	if (errflg || (interactiveflg && daemonflg)) {
		fprintf(stderr,
			"Usage: %s [ -dikV -n #routers -t traceflag -f configfile -L logfile -P postoffice]\n",
			progname);
		exit(128+errflg);
	}
	time(&now);
	mailshare = getzenv("MAILSHARE");
	if (mailshare == NULL)
		mailshare = MAILSHARE;
	if (config == NULL) {
		config = cf_suffix; /* XX: ???? delete this ? */
		/* we don't need to remember this for long */
		config = smalloc(MEM_TEMP, 3 + (u_int)(strlen(mailshare)
					     + strlen(progname)
					     + strlen(cf_suffix)));
		sprintf(config, "%s/%s.%s",
			       mailshare, progname, cf_suffix);
	}
	if (postoffice == NULL &&
	    (postoffice = getzenv("POSTOFFICE")) == NULL)
		postoffice = POSTOFFICE;

	if (killflg && !daemonflg) {
		killprevious(-SIGTERM, pidfile);
		exit(0);
	}

	getnobody();

	c = optind;	/* save optind since builtins can interfere with it */

	if (daemonflg && logfn == NULL) {
		if ((cp = getzenv("LOGDIR")) != NULL)
			logdir = cp;
		logfn = smalloc(MEM_PERM, 2 + (u_int)(strlen(logdir)
					  + strlen(progname)));
		sprintf((char*)logfn, "%s/%s", logdir, progname);
	}
	/* setvbuf(stdout, (char *)NULL, _IOLBF, 0);
	   setvbuf(stderr, (char *)NULL, _IOLBF, 0); */
	setvbuf(stdout, (char *)NULL, _IONBF, 0);
	setvbuf(stderr, (char *)NULL, _IONBF, 0);

	if (logfn != NULL) {
		/* loginit is a signal handler, so can't pass log */
		if (loginit(0) < 0)	/* do setlinebuf() there */
			die(1, "log initialization failure");
		signal(SIGHUP, sig_hup); /* close and reopen log files */
	} else
		signal(SIGHUP, SIG_IGN); /* no surprises please */

	if (version || interactiveflg || tac > 0) {
		prversion("router");
		if (version)
			exit(0);
		putc('\n', stderr);
	}
	if (tac > 0) {			/* turn on some trace/debug flags */
		tav[0] = "debug";
		/* lax, no NULL guard on end of tav */
		run_trace(++tac, tav);
	}
	stickymem = MEM_PERM;

	initialize(config, argc - c, &argv[c]);

	stickymem = MEM_TEMP;	/* this is the default allocation type */
	offout = ftell(stdout);
	offerr = ftell(stderr);

#ifdef	MALLOC_TRACE
	mal_leaktrace(1);
#endif	/* MALLOC_TRACE */

	if (daemonflg) {
		if (chdir(postoffice) < 0 || chdir(ROUTERDIR) < 0)
		  fprintf(stderr, "%s: cannot chdir.\n", progname);
		/* XX: check if another daemon is running already */
		if (offout < ftell(stdout) || offerr < ftell(stderr)) {
		  fprintf(stderr, "%d %d %d %d\n",
			  (int) offout, (int) ftell(stdout),
			  (int) offerr, (int) ftell(stderr));
		  fprintf(stderr, "%s: daemon not started.\n", progname);
		  die(1, "errors during startup");
		}
		if (tac == 0)		/* leave worldy matters behind */
		  detach();
		printf("%s: router daemon (%s)\n\tstarted at %s\n",
		       progname, Version, rfc822date(&now));
		if (killflg)
		  if (killprevious(-SIGTERM, pidfile) != 0) {
		    /* Indicates failure at pidfile creation! */
		    fprintf(stderr,"router can't create pidfile ?? Disk full ??\n");
		    exit(2);
		  }
		if (nrouters > 1) {
		  int pgrp, ppid = getpid();
#ifndef	GETPGRP_VOID		/* We assume getpgrp() and setpgrp() calling
				   conventions match in the machine.. */
		  pgrp = getpgrp(ppid);	/* BSD  -style */
#else
		  pgrp = getpgrp(); /* SysV/POSIX -style */
#endif
		  if (pgrp != ppid) {
		    fprintf(stderr, "process group %d != pid %d\n",
			    pgrp, ppid);
		    fprintf(stderr, "%s: daemon not started.\n", progname);
		    die(1, "capability error during startup");
		  }
		  for (router_id = 2; router_id <= nrouters; ++router_id){
		    if (fork() <= 0) /* child or error */
		      break;
		    /* parent */
		  }
		  printf("%s: number %d started as pid %d\n",
			 progname, router_id, getpid());
		  router_id = getpid();
		}
		else
		  router_id = getpid();
		zopenlog("router", LOG_PID, LOG_MAIL);
	}
	if (c < argc) {
	  savefile = 1;
	  /*
	   * we need to use a local variable (c) because optind is global
	   * and can (and will) be modified by the funcall()'s we do.
	   */
	  do {
	    av[0] = "process";
	    av[1] = argv[c];
	    av[2] = NULL;
#ifdef	XMEM
write(30, "\n", 1);
#endif	/* XMEM */
	    s_apply(2, &av[0]); /* "process" filename */
	  } while (++c < argc);
	} else if (daemonflg) {
	  av[0] = "daemon";
	  av[1] = NULL;
	  run_daemon(1, &av[0]);
	  /* NOTREACHED */
	} else if (interactiveflg) {
#ifdef	MALLOC_TRACE
	  zshtoplevel(NULL);
#else	/* !MALLOC_TRACE */
	  trapexit(zshtoplevel(NULL));
#endif	/* MALLOC_TRACE */
	  /* NOTREACHED */
	}
#ifdef	MALLOC_TRACE
	dbfree();
	zshfree();
#endif	/* MALLOC_TRACE */
	if (mustexit)
	  die(0, "signal");
#ifdef	MALLOC_TRACE
	die(0, "malloc trace");
#endif	/* MALLOC_TRACE */
	trapexit(0);
	/* NOTREACHED */
	return 0;
}

/* Run around and gather the necessary information for starting operation */

static void
initialize(configfile, argc, argv)
	const char *configfile;
	int argc;
	const char *argv[];
{
	struct group *grp;
	struct sptree_init *sptip;
	int ac;
	const char **cpp;
	const char **av;

	av = (const char **)emalloc((5+argc)*(sizeof (char *)));
	/* initialize shell */
	ac = 0;
	av[ac++] = progname;
	av[ac++] = "-s";
	av[ac++] = zshopts;
	while (argc-- > 0)
		av[ac++] = *argv++;
	av[ac] = NULL;
	zshinit(ac, av);

	/* add builtin router functions to list of builtin shell functions */
	{
		register struct shCmd *shcmdp;

		for (shcmdp = &fnctns[0]; shcmdp->name != NULL; ++shcmdp)
			sp_install(symbol(shcmdp->name),
				   (void*)shcmdp, 0, spt_builtins);
	}

	/* initialize splay trees in router */
	av[0] = "relation";
	av[1] = "-t";
	av[4] = NULL;

	for (sptip = &splaytrees[0]; sptip->spta != NULL; ++sptip) {
	  if (sptip->incore_name != NULL) {
	    if (sptip->spta == &spt_headers)
	      av[2] = "header";
	    else
	      av[2] = "incore";
	    av[3] = sptip->incore_name;
	    if (run_relation(4, av) == 0)
	      *(sptip->spta) = icdbspltree(sptip->incore_name);
	  } else
	    *(sptip->spta) = sp_init();
	}

	init_header();

	/* trusted users */
	for (cpp = default_trusted; cpp != NULL && *cpp != NULL; ++cpp)
		add_incoresp(*cpp, "", spt_goodguys);

	if (files_group != NULL) {
		if ((grp = getgrnam(files_group)) == NULL)
			files_gid = -1;
		else
			files_gid = grp->gr_gid;
	}

	/* source the router config file */
	ac = 0;
	av[ac++] = ".";
	if (strchr(configfile, '/') == NULL) {
		av[ac] = emalloc(strlen(configfile)+sizeof "./"+1);
		sprintf((char*)av[ac++], "./%s", configfile);
	} else
		av[ac++] = configfile;
	av[ac] = NULL;
	setfreefd();
	sh_include(ac, av);
	if (av[1] != configfile)
		free((void*)av[1]);
	free((char *)av);
}

int
login_to_uid(name)
	const char	*name;
{
	struct passwd *pw;
	uid_t uid;
	char buf[BUFSIZ];
	char *cp;
	struct spblk *spl;

	spl = lookup_incoresp(name, spt_loginmap);
	if (spl == NULL) {
		memtypes oval = stickymem;

		stickymem = MEM_MALLOC;
		pw = getpwnam(name);
		if (pw == NULL) {
			uid = nobody;
		} else {
			uid = pw->pw_uid;
			cp = strsave(pw->pw_name);
			sp_install(uid, cp, 0L, spt_uidmap);
			fullname(pw->pw_gecos,buf,sizeof buf,pw->pw_name);
			add_incoresp(cp, buf, spt_fullnamemap);
		}
		addd_incoresp(name, (void*)((long)uid), spt_loginmap);
		stickymem = oval;
	} else
		uid = (long)(spl->data);
	return uid;
}

const char *
uidpwnam(uid)
	int	uid;
{
	struct passwd *pw;
	register const char *cp;
	struct spblk *spl;
	char buf[BUFSIZ];

	spl = sp_lookup((u_long)uid, spt_uidmap);
	if (spl == NULL) {
		pw = getpwuid((uid_t)uid);
		if (pw == NULL) {
			/* memory shall be temporary in
			   its nature for this data! */
			sprintf(buf, "uid#%d", uid);
			cp = strsave(buf);
			deferuid = 1;
		} else {
			memtypes oval = stickymem;
			stickymem = MEM_MALLOC;
			cp = strsave(pw->pw_name);
			addd_incoresp(pw->pw_name, (void*)((long)(pw->pw_uid)), spt_loginmap);
			fullname(pw->pw_gecos,buf, sizeof buf, pw->pw_name);
			add_incoresp(pw->pw_name, buf, spt_fullnamemap);
			sp_install((u_int)uid, cp, 0L, spt_uidmap);
			stickymem = oval;
		}
	} else
		cp = spl->data;
	return cp;
}


/* Can we trust this person? */

int
isgoodguy(uid)
	int	uid;
{
	const char *name;
	spkey_t spk;
	struct spblk *spl;

	/*
	 * If you're wondering about this comparison... I had to store
	 * *something* in the splay tree; I'm really using it as a boolean.
	 */
	name = uidpwnam(uid);
	spk = symbol_lookup_db(name, spt_goodguys->symbols);
	spl = NULL;
	if (spk != (spkey_t)0)
	  spl = sp_lookup(spk, spt_goodguys);
	return spl != NULL;
}

#define	MAXSAFESIZE	700 /* syslog dumps core if we have much over this */

void
logmessage(e)
	struct envelope *e;
{
	int n, len;
	const char *from;
	char *to, *cp;
	char buf[MAXSAFESIZE];
	struct header *h;
	struct addr *p;
	struct address *ap;

	from = NULL;
	for (h = e->e_eHeaders; h != NULL; h = h->h_next) {
		if (h->h_descriptor->class == eFrom
		    && h->h_contents.a != NULL) {
			p = h->h_contents.a->a_tokens;
			if (p != NULL) {
				from = saveAddress(p);
				break;
			}
		}
	}
	if (from == NULL)
		from = "?from?";
	n = 0;
	to = buf;
	for (h = e->e_eHeaders; h != NULL; h = h->h_next) {
		if (h->h_descriptor->class == eTo && h->h_contents.a != NULL) {
			for (ap = h->h_contents.a; ap != NULL; ap=ap->a_next) {
				cp = saveAddress(ap->a_tokens);
				len = strlen(cp);
				if (to + len + 2 >= buf + sizeof buf) {
					/* print what we've got so far */
					if (to != buf) {
						*to = '\0';
						logit(e->e_file,
						      e->e_messageid,
						      from, buf);
						to = buf;
					}
					if (to + len + 2 >= buf + sizeof buf)
						continue;
				} else {
					if (n) *to++ = ',';
					*to++ = ' ';
				}
				strncpy(to, cp, len);
				to += len;
				++n;
			}
		}
	}
	if (to != buf) {
		*to = '\0';
		logit(e->e_file, e->e_messageid, from, buf);
	}
}

/*
 * All the strangeness in the logit() routine is because syslog() is
 * broken; it can only handle a certain size buffer before it'll dump core.
 * We do the same processing for stdout so that stdout can be fed into
 * logger without having to fix or customize a vendor program.  Sigh.
 */

static void
logit(file, id, from, to)
	const char *file, *id, *from, *to;
{
	int flen, baselen;
#if 0
	char c;

	if (id == NULL)
		id = file;
	baselen = strlen(file) + strlen(id) + 4;
	c = '\0';
	while (baselen + strlen(from) > MAXSAFESIZE) {
		/* Wonderful software we're dealing with here... */
		c = *(from+MAXSAFESIZE-baselen);
		*(from+MAXSAFESIZE-baselen) = '\0';
		printf("%s: file: %s %s...\n", id, file, from);
		if (!nosyslog)
		  zsyslog((LOG_INFO, "%s: file: %s %s...", id, file, from));
		from += MAXSAFESIZE-baselen;
		*from = c;
		*--from = '.';
		*--from = '.';
		*--from = '.';
	}
	flen = strlen(from);
	while (baselen + flen + strlen(to) > MAXSAFESIZE) {
		c = *(to+MAXSAFESIZE-baselen-flen);
		*(to+MAXSAFESIZE-baselen-flen) = '\0';
		if (flen > 0)
			printf("%s: file: %s %s =>%s\n", id, file, from, to);
		else
			printf("%s: file: %s %s\n", id, file, to);
		if (!nosyslog)
		  if (flen > 0)
		    zsyslog((LOG_INFO, "%s: file: %s %s =>%s",
			     id, file, from, to));
		  else
		    zsyslog((LOG_INFO, "%s: file: %s %s", id, file, to));
		to += MAXSAFESIZE-baselen-flen;
		*to = c;
		*--to = '.';
		*--to = '.';
		*--to = '.';
		flen = 0;
	}
	if (flen > 0) {
	  printf("%s: file: %s %s =>%s\n", id, file, from, to);
	  if (!nosyslog)
	    zsyslog((LOG_INFO, "%s: file: %s %s =>%s", id, file, from, to));
	}
#else
	if (id == NULL)
		id = file;
	baselen = strlen(file) + strlen(id) + 4;
	printf("%.200s: file: %.150s %.250s...\n", id, file, from);
	if (!nosyslog)
	  zsyslog((LOG_INFO, "%.200s: file: %.150s %.250s...",
		   id, file, from));
	flen = strlen(from);
	if (flen > 0)
	  printf("%.200s: file: %.150s %.200s => %.200s\n",
		 id, file, from, to);
	else
	  printf("%.200s: file: %.150s %.250s\n", id, file, to);
	if (!nosyslog) {
	  if (flen > 0)
	    zsyslog((LOG_INFO, "%.200s: file: %.150s %.200s => %.200s",
		     id, file, from, to));
	  else
	    zsyslog((LOG_INFO, "%.200s: file: %.150s %.200s", id, file, to));
	}
#endif
}

const char *
mail_host()
{
	return myhostname;
}

extern void printfds __((void));
void
printfds()
{
	int i, topfd = getdtablesize();
	struct stat fst;

	for (i=0; i < topfd; ++i) {
	  long flags = fcntl(i,F_GETFL,0);
	  if (flags >= 0) {
	    fstat(i,&fst);
	    if (S_ISREG(fst.st_mode))
	      fprintf(stderr," %d",i);
	    else if (S_ISDIR(fst.st_mode))
	      fprintf(stderr," %dd",i);
	    else if (S_ISCHR(fst.st_mode))
	      fprintf(stderr," %dC",i);
	    else if (S_ISBLK(fst.st_mode))
	      fprintf(stderr," %dB",i);
	    else
	      fprintf(stderr," %d(?)",i);
	  }
	}
	fprintf(stderr,"\n");
	fflush(stderr);
}
