/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */
/*
 *	Lots of modifications (new guts, more or less..) by
 *	Matti Aarnio <mea@nic.funet.fi>  (copyright) 1992-2004
 */


/*
 * ZMailer router, main and miscellany routines.
 */

#define NO_IO_H
#include "router.h"

static void initialize __((const char *configfile, int argc, const char *argv[]));
static void logit __((const char *id, const char *from, const char *to));
static void Imode_smtpserver __((void));


const char * mailshare;
const char * myhostname;
const char * pidfile = PID_ROUTER;
const char * logfn;
time_t	now;

int	mustexit;
int	canexit;
int	router_id;
int	deferit;
int	deferuid;
int	savefile;
const char * zshopts = "-O";
int	nosyslog = 1;
int	routerdirloops;
int	do_hdr_warning;
int	workermode;
int	nrouters = 1;
int	isInteractive;
int	no_logmessage;

#define IMODE_NONE 0
#define IMODE_SMTPSERVER 1

int	I_mode = IMODE_NONE;

int
main(argc, argv)
	int	    argc;
	const char *argv[];
{
	int c, errflg, daemonflg, killflg, interactiveflg, tac;
	int version;
	long offout, offerr;
	char *config;
	const char *tav[20], *av[3], *cp;
#ifdef	XMEM
	FILE *fp;
#endif	/* XMEM */

#ifdef HAVE_SETGROUPS
	/* We null supplementary groups list entirely */
	setgroups(0, NULL);
#endif

#if 1 /* LINE BUFFERED */

	setvbuf(stdout, (char *)NULL, _IOLBF, 0);
	setvbuf(stderr, (char *)NULL, _IOLBF, 0);

#else /* NOT BUFFERED AT ALL */

	setvbuf(stdout, (char *)NULL, _IONBF, 0);
	setvbuf(stderr, (char *)NULL, _IONBF, 0);

#endif

	progname = strrchr(argv[0], '/');
	if (progname == NULL)
		progname = argv[0];
	else
		++progname;

	logfn = config = NULL;
	errflg = daemonflg = killflg = interactiveflg = version = 0;
	tac = 0;
	nrouters = 1;


	while (1) {
		c = zgetopt(argc, (char*const*)argv, "m:n:diI:kf:o:t:lL:P:r:sSVwWZ:");
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
			  int fd = open(zoptarg, O_RDWR|O_CREAT|O_TRUNC,0644);
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
			nrouters = atoi(zoptarg);
			if (nrouters < 1)
				nrouters = 1;
			break;
		case 'o':
			zshopts = zoptarg;
			break;
		case 't':
			if (tac < (sizeof tav)/(sizeof tav[0]))
				tav[++tac] = zoptarg;
			else {
				fprintf(stderr, "Too many trace options!\n");
				fprintf(stderr, "Ignoring '%s'\n", zoptarg);
			}
			break;
		case 'f':	/* override default config file */
			config = (char*) zoptarg;
			break;
		case 'i':	/* first read config file, then read from tty */
			interactiveflg = 1;
			break;
		case 'I':
			if (strcmp(zoptarg,"smtpserver") == 0)
			  I_mode = IMODE_SMTPSERVER;
			else
			  ++errflg;
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
			logfn = zoptarg;
			break;
		case 'l':
			no_logmessage = 1;
			break;
		case 'P':	/* override default postoffice */
			postoffice = zoptarg;
			break;
		case 'V':
			version = 1;
			break;
		case 'w':
			workermode = 1;
			break;
		case 'W':
			do_hdr_warning = !do_hdr_warning;
			break;
		case 'r':
			routerdirloops = atoi(zoptarg);
			if (routerdirloops < 0)
				routerdirloops = 0;
			break;
		case 'Z':
			if (readzenv(zoptarg) == 0)
			  ++errflg;
			break;
		case '?':
		default:
			++errflg;
			break;
		}
	}

	if (errflg || (interactiveflg && daemonflg)) {
		fprintf(stderr,
			"Usage: %s [ -dikVl -n #routers -t traceflag -f configfile -L logfile -P postoffice -Z zenvfile]\n",
			progname);
		exit(128+errflg);
	}

	time(&now);
	mailshare = getzenv("MAILSHARE");
	if (mailshare == NULL)
		mailshare = MAILSHARE;
	if (config == NULL) {
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


	if (daemonflg || killflg) {

	  /* Daemon attaches the SHM block, and may complain, but will not
	     give up..  instead uses builtin fallback  */

	  int r = Z_SHM_MIB_Attach (1);  /* R/W mode */

	  if (r < 0) {
	    /* Error processing -- magic set of constants: */
	    switch (r) {
	    case -1:
	      /* fprintf(stderr, "No ZENV variable: SNMPSHAREDFILE\n"); */
	      break;
	    case -2:
	      perror("Failed to open for exclusively creating of the SHMSHAREDFILE");
	      break;
	    case -3:
	      perror("Failure during creation fill of SGMSHAREDFILE");
	      break;
	    case -4:
	      perror("Failed to open the SHMSHAREDFILE at all");
	      break;
	    case -5:
	      perror("The SHMSHAREDFILE isn't of proper size! ");
	      break;
	    case -6:
	      perror("Failed to mmap() of SHMSHAREDFILE into memory");
	      break;
	    case -7:
	      fprintf(stderr, "The SHMSHAREDFILE  has magic value mismatch!\n");
	      break;
	    default:
	      break;
	    }
	    /* return; NO giving up! */
	  }
	}


	if (killflg && !daemonflg) {
		killprevious(-SIGTERM, pidfile);
		exit(0);
	}

	getnobody();

	c = zoptind;	/* save optind since builtins can interfere with it */

	if (daemonflg && logfn == NULL) {
		if ((cp = (char *) getzenv("LOGDIR")) != NULL)
			logdir = cp;
		logfn = smalloc(MEM_PERM, 2 + (u_int)(strlen(logdir)
					  + strlen(progname)));
		sprintf((char*)logfn, "%s/%s", logdir, progname);
	}



	if (logfn != NULL) {
		/* loginit is a signal handler, so can't pass log */
		if (loginit(SIGHUP) < 0) /* do setlinebuf() there */
			die(1, "log initialization failure");
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

	/* We (and our children) run with SIGPIPE ignored.. */
	SIGNAL_HANDLE(SIGPIPE, SIG_IGN);


	initialize(config, argc - c, &argv[c]);

	stickymem = MEM_TEMP;	/* this is the default allocation type */
	offout = ftell(stdout);
	offerr = ftell(stderr);

#ifdef MALLOC_TRACE
	mal_leaktrace(1);
#endif /* MALLOC_TRACE */

	if (daemonflg) {
		if (chdir(postoffice) < 0 || chdir(ROUTERDIR) < 0)
		  fprintf(stderr, "%s: cannot chdir.\n", progname);
		/* XX: check if another daemon is running already */
		if (offout < ftell(stdout) || offerr < ftell(stderr)) {
		  fprintf(stderr, "%d %d %d %d\n",
			  (int) offout, (int) ftell(stdout),
			  (int) offerr, (int) ftell(stderr) );
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
		if (nrouters > 0) {
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
		}
		router_id = getpid();
	}

	/* Each (sub-)process does openlog() all by themselves */
	zopenlog("router", LOG_PID, LOG_MAIL);

	if (c < argc) {
	  savefile = 1;
	  /*
	   * we need to use a local variable (c) because zoptind is global
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

	  if (I_mode == IMODE_SMTPSERVER) {
	    Imode_smtpserver();
	  } else {
#ifdef	MALLOC_TRACE
	    zshtoplevel(NULL);
#else	/* !MALLOC_TRACE */
	    trapexit(zshtoplevel(NULL));
#endif	/* MALLOC_TRACE */
	    /* NOTREACHED */
	  }
	}
#ifdef	MALLOC_TRACE
	dbfree();
	zshfree();
#endif	/* MALLOC_TRACE */
	/* if (mustexit)
	   die(0, "signal"); */
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
	struct Zgroup *grp;
	struct sptree_init *sptip;
	int ac;
	const char **cpp;
	const char **av;
	const char *zconfig;

	av = (const char **)emalloc((5+argc)*(sizeof (char *)));
	/* initialize shell */
	ac = 0;
	av[ac++] = progname;
	av[ac++] = "-s";
	av[ac++] = zshopts;
	while (argc-- > 0)
		av[ac++] = *argv++;
	av[ac] = NULL;

	staticprot(&s_value);
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
		if ((grp = zgetgrnam(files_group)) == NULL)
			files_gid = -1;
		else
			files_gid = grp->gr_gid;
	}

	zconfig = getzenv("ZCONFIG");
	if (zconfig)
	  v_set("ZCONFIG", zconfig);

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
	struct Zpasswd *pw;
	uid_t uid;
	char buf[BUFSIZ];
	char *cp;
	struct spblk *spl;

	spl = lookup_incoresp(name, spt_loginmap);
	if (spl == NULL) {
		memtypes oval = stickymem;

		stickymem = MEM_MALLOC;

		pw = zgetpwnam(name);
		if (!pw)
			pw = zgetpwnam(name);

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
	struct Zpasswd *pw;
	register const char *cp;
	struct spblk *spl;
	char buf[BUFSIZ];

	spl = sp_lookup((u_long)uid, spt_uidmap);
	if (spl == NULL) {
		pw = zgetpwuid((uid_t)uid);
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
						logit(e->e_spoolid,
						      from, buf);
						to = buf;
					}
					if (to + len + 2 >= buf + sizeof buf)
					  /* Can't fit it in.. */
					  continue;
				} else {
					if (n) *to++ = ',';
					*to++ = ' ';
				}
				memcpy(to, cp, len);
				to += len;
				*to = 0;
				++n;
			}
		}
	}
	if (to != buf) {
		*to = '\0';
		logit(e->e_spoolid, from, buf);
	}
}

/*
 * All the strangeness in the logit() routine is because syslog() is
 * broken; it can only handle a certain size buffer before it'll dump core.
 * We do the same processing for stdout so that stdout can be fed into
 * logger without having to fix or customize a vendor program.  Sigh.
 */

static void
logit(id, from, to)
	const char *id, *from, *to;
{
	int flen, baselen;

	if (id == NULL)
		id = "<>";
	baselen = strlen(id) + 4;
	flen = strlen(from);
	if (flen > 0)
	  printf("%.30s: fromto: %s => %s\n", id, from, to);
	else
	  printf("%.30s: fromto: <> => %s\n",       id, to);
	if (!nosyslog) {
	  if (flen > 0)
	    zsyslog((LOG_INFO, "%.30s: fromto: %.200s => %.200s",
		     id, from, to));
	  else
	    zsyslog((LOG_INFO, "%.30s: fromto: <> => %.200s", id, to));
	}
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


void
Imode_smtpserver __((void))
{
	int n, c;
	const char *key;
	const char *data;
	memtypes oval;
	const char *av[4];
	char *linebuf = malloc(20000);
	int linespc = 19500;
	int cmdcount = 0;
	char *sh_memlevel = getlevel(MEM_SHCMD);

	oval = stickymem;
	stickymem = MEM_TEMP;	/* per-message space */

	setlinebuf(stdin);

	SIGNAL_HANDLE(SIGTERM, sig_exit);	/* mustexit = 1 */

	isInteractive = 1;

	av[0] = "server";
	av[1] = "init";
	av[2] = NULL;
	s_apply(2, &av[0]);

	while ( !mustexit ) {

	  ++cmdcount;
	  if (cmdcount > 1000) {
	    av[0] = "server";
	    av[1] = "purge";
	    av[2] = NULL;
	    s_apply(2, &av[0]);
	    cmdcount = 0;
	  }

	  fprintf(stdout, "#hungry\n");
	  fflush(stdout);

	  n = 0;
	  while (( c = fgetc(stdin) ) != EOF) {
	    if (n + 10  > linespc) {
	      linespc += 2000;
	      linebuf = realloc(linebuf, linespc);
	    }
	    linebuf[n++] = c;
	    if (c == '\n') break;
	  }
	  linebuf[n] = 0;

	  if (n <= 0) break;

	  /* process!   linebuf[]  has input data.. */

	  key  = strtok(linebuf, "\t");
	  data = strtok(NULL, "\n");

	  deferit = 0;
	  v_set(DEFER, "");

	  gensym = 1;

	  av[0] = "server";
	  av[1] = key;
	  av[2] = data;
	  av[3] = NULL;

	  s_apply(3, &av[0]); /* "server" key argument */

	  free_gensym();
	  setlevel(MEM_SHCMD,sh_memlevel);
	  
	  fflush(stdout);
	}
	stickymem = oval;
}
