/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *
 *	Feature maintenance by  Matti Aarnio <mea@nic.funet.fi> 1991-2000
 *
 */

/* Sendmail -- a sendmail compatible interface to ZMailer */

#include "hostenv.h"
#include <stdio.h>
#include <sysexits.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include "mail.h"
#include "zmsignal.h"
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#include <sys/file.h>
#include "zsyslog.h"

#include "zmalloc.h"
#include "libz.h"
#include "libc.h"


#define	SMTPSERVER	"smtpserver"
#define	ROUTER		"router"
#define	SCHEDULER	"scheduler"
#define MAILQ		"mailq"
#define	NEWALIASES	"newaliases"

const char *zmailer = "ZMailer";
char *verbfile = NULL;

extern FILE * deadletter __((int uid));
extern char *optarg;
#ifndef strchr
extern char *strchr();
extern char *strrchr();
#endif
extern char *strtok();
/* extern char *getenv();
   extern char *getlogin(); */
extern int  errno;
extern int  optind;
extern void doabort __((int));
extern int  mail_priority;
extern void check_and_print_to __((FILE *, const char*, const char*, const char *));
extern int  is_xtext_string __((const char *));

const char *progname;

int D_alloc = 0;	/* memory usage debugging */

#ifdef	lint
#undef	putc
#define	putc	fputc
#endif

FILE	*mfp = NULL;

#define RFC821_822QUOTE(newcp,cp) \
	if (cp && strchr(cp,'\\') != NULL && *cp != '"') {	\
	  const char *s1 = cp;					\
	  char *s2;						\
	  /* For this we can add at most 2 new quote chars */	\
	  s2 = emalloc(strlen(cp)+4);				\
	  newcp = s2;						\
	  *s2++ = '"';						\
	  while (*s1) {						\
	    if (*s1 == '@')					\
	      break; /* Unquoted AT --> move to plain copying! */ \
	    if (*s1 == '\\' && s1[1] != 0)			\
	      *s2++ = *s1++;					\
	    /* Normal copy */					\
	    *s2++ = *s1++;					\
	  }							\
	  *s2++ = '"';						\
	  while (*s1)						\
	    *s2++ = *s1++;					\
	  cp = newcp;						\
	}


void usage()
{
  
  fprintf(stderr, "Usage: %s [sendmail options] [recipient addresses]\n", progname);
  fprintf(stderr, "  ZMailer's sendmail recognizes and implements following options:\n\
     -B bodytype  -  Valid values: 8BITMIME, 7BIT\n\
     -C conffile  -  specifies config file (meaningfull for -bt)\n\
     -E           -  flag 'external' source\n\
     -F 'full name'  sender's full name string\n\
     -N notifyopt -  Notify option(s): NEVER or a set of: SUCCESS,DELAY,FAILURE\n\
     -P priority# -  numeric priority for ZMailer router queue pre-selection\n\
     -R returnopt -  Error report return option, either of: FULL, HDRS\n\
     -U           -  Flag as 'user submission'\n\
     -V envidstring - XTEXT encoded ENVID string\n\
     -b?          -  operational mode flags\n\
     -bd          -  starts smtpserver in daemon mode\n\
     -bi          -  runs 'newaliases' command\n\
     -bm          -  deliver mail; always :-)\n\
     -bp          -  runs 'mailq' command\n\
     -bs          -  speak smtp; runs smtpserver in interactive mode\n\
     -bt          -  starts router in interactive test mode\n\
     -e*             (ignored)\n\
     -f fromaddr  -  sets envelope from address for the message\n\
     -i           -  on inputs from tty this will ignore SMTP-like dot-EOF\n\
     -m           -  send a copy of the message to the sender too (ignored)\n\
     -o*          -  multiple options; those not listed cause error\n\
     -oQ queuedir -  defines POSTOFFICE directory for message submission\n\
     -ob*            (ignored)\n\
     -od*            (ignored)\n\
     -oe*            (ignored)\n\
     -oi          -  alias of '-i' option\n\
     -or*            (ignored)\n\
     -p submitprotocol - value for 'with' label at 'Received:' header\n\
     -q*          -  queue processing commands (ignored)\n\
     -r fromaddr  -  (alternate for -f)\n\
     -t           -  scan message rfc822 headers for recipient addresses\n\
     -v           -  verbose trace of processing\n\
");
}


extern int main __((int argc, const char *argv[]));
int
main(argc, argv)
	int argc;
	const char *argv[];
{
	int	c, errflg, n, pid, bpflag, uid, truid, external, verbose;
	int	speaksmtp, daemon_flg, interactive, aliases, printq, dotiseof;
	int	rfc822recipients, vfd;
	char	*ebp, *s, *cp, errbuf[BUFSIZ];
	const char *from, *mailbin, *mailshare, *fullname;
	const char *mav[10];
	const char *configfile, *mailpriority, *pooption;
	char * path;
	FILE	*vfp;
	struct passwd *pwd;
	char	*LC_ctype;
	char	buf[8192];
	char   *buf2 = NULL;
	char	*bodytype = NULL;
	int	usersubmission = 0;
	char	*submitprotocol = NULL;
	char	*notificationopt = NULL;
	char	*returnopt = NULL;
	char	*envidstr = NULL;
	const char * newcp = NULL;
	int	save_from = 0;
	int	outcount = 0;

	cp = strrchr(argv[0], '/');
	if (cp != NULL)
		progname = ++cp;
	else
		progname = argv[0];
	umask(022);

	mailpriority = getenv("MAILPRIORITY");

	/* Pick up the sender's idea about C-chartype.. */
	LC_ctype = getenv("LC_CTYPE");

	printq  = STREQ(progname, MAILQ);
	aliases = STREQ(progname, NEWALIASES);

	from = fullname = NULL;
	speaksmtp = daemon_flg = interactive = 0;
	bpflag = external = verbose = rfc822recipients = 0;
	dotiseof = 1;	/* tested below to see if changed */
	ebp = errbuf;
	*ebp = '\0';
	errflg = 0;
	configfile = pooption = NULL;
	if (printq || aliases)
		goto otherprog;
	while (1) {
		c = getopt(argc, (char*const*)argv,
			   "B:C:EF:JN:OP:R:UV:b:d:e:r:f:h:imno:p:q:stvx");
		if (c == EOF)
			break;
		switch (c) {
		case 'B':
			/* Sendmail 8.7 compability:
			   -B8BITMIME */
			bodytype = optarg;
			if (strcasecmp(bodytype,"8BITMIME") != 0 &&
			    strcasecmp(bodytype,"7BIT") != 0 &&
			    strcasecmp(bodytype,"BINARYMIME") != 0) {
			  fprintf(stderr,"sendmail: unrecognized -B option parameter value: '%s'\n",bodytype);
			  exit(EX_USAGE);
			}
			break;
		case 'J': break; /* Sony NEWS OS  JIS-conversion option,
				    ignore */
		case 'E':
			external = 1;
			break;
		case 'r':
		case 'f':	/* from address */
			from = optarg;
			break;
		case 'F':	/* full name of sender */
			fullname = optarg;
			break;
		case 't':	/* scan header for recipient addresses */
			rfc822recipients = 1;
			break;
		case 'b':
			switch (*optarg) {
			case 'm':	/* deliver mail */
				/* sure */
				break;
			case 's':	/* speak SMTP on input */
				speaksmtp = 1;
				break;
			case 'd':	/* run as daemon */
				daemon_flg = 1;
				break;
			case 't':	/* run in test mode */
				interactive = 1;
				break;
			case 'i':	/* initialize the alias database */
				aliases = 1;
				break;
			case 'p':	/* print the mail queue */
				printq = 1;
				bpflag = 1;
				break;
			case 'v':	/* just verify addresses */
			case 'a':	/* run in arpanet mode */
			case 'z':	/* freeze the configuration file */
				sprintf(ebp, " -%c%c", c, *optarg);
				ebp += strlen(ebp);
				break;
			}
			break;
		case 'h':	/* hop count */
		case 'n':	/* don't do aliasing or forwarding */
		case 'd':	/* debug level */
			sprintf(ebp, " -%c", c);
			ebp += strlen(ebp);
			break;
		case 'q':	/* process queue */
			/* sometimes with/without option in real sendmail */
			break;
		case 'C':	/* specify configuration file */
			configfile = emalloc((unsigned)(2+strlen(optarg)+1));
			sprintf((char*)configfile, "-f%s", optarg);
			break;
		case 'o':	/* options */
			switch (*optarg) {
			case 'Q':	/* queue directory */
				if (getuid() != geteuid() && getuid() != 0)
					break;
				pooption = emalloc((unsigned)(2+strlen(optarg+1)+1));
				sprintf((char*)pooption, "-P%s", optarg+1);
				postoffice = pooption + 2 /* "-P" */;
				break;
			case 'd':	/* -odb -- ignore quietly */
			case 'b':	/* -obd -- ignore quietly */
				break;
			case 'e':	/* -oem -- delivery mail, errors to sender.
					           Common from ELM MUA.
						   Ignored quietly [mea@utu.fi] */
				break;
				
			case 'i':	/* ignore dots */
				dotiseof = 0;
				break;
			case 'r':
				break;
			default:
#if 0
				sprintf(ebp, " -o%s", optarg);
				ebp += strlen(ebp);
#endif
				break;
			}
			break;
			/* option idioms */
		case 'e':
			/* too many applications use this, ignore silently */
			break;
		case 'i':	/* ignore dots */
			dotiseof = 0;
			break;
		case 'm':	/* me too */
		case 'O':	/* for NeXT mail */
			/* default behavior */
			break;
		case 'N':
			notificationopt = optarg;
			{
			  s = optarg;
			  while (*s) {
			    if (CISTREQN(s,"NEVER",5))
			      s += 5;
			    else if (CISTREQN(s,"SUCCESS",7))
			      s += 7;
			    else if (CISTREQN(s,"FAILURE",7))
			      s += 7;
			    else if (CISTREQN(s,"DELAY",5))
			      s += 5;
			    else if (CISTREQN(s,"TRACE",5))
			      s += 5; /* This is NOT even RFC 2852 derived
					 thing, although helps to debug it.. */
			    if (*s == ',') {
			      ++s;
			      continue;
			    }
			    if (*s != 0) {
			      fprintf(stderr,"sendmail: illegal -N -option parameter: '%s'\n",optarg);
			      exit(EX_USAGE);
			    }
			  }
			}
			break;
		case 'R':
			returnopt = optarg;
			if (!CISTREQ(returnopt,"FULL") &&
			    !CISTREQ(returnopt,"HDRS")) {
			  fprintf(stderr,"sendmail: illegal -R -option parameter: '%s'\n",optarg);
			  exit(EX_USAGE);
			}
			break;
		case 'U':
			usersubmission = 1;
			break;
		case 'v':	/* be verbose */
			verbose = 1;
			break;
		case 's':	/* save From_ lines */
			save_from = 1;
			break;
		case 'p':
			submitprotocol = optarg;
			for (;*optarg;++optarg) {
			  int c = (*optarg) & 0xFF;
			  if ('0' <= c && c <= '9') continue;
			  if ('A' <= c && c <= 'Z') continue;
			  if ('z' <= c && c <= 'z') continue;
			  fprintf(stderr,"sendmail: only alphanumeric characters accepted for -p option parameter: '%s'\n",submitprotocol);
			  exit(EX_USAGE);
			}
			break;
		case 'P':
			mailpriority = optarg;
			break;
		case 'V':
			envidstr = optarg;
			if (!is_xtext_string(envidstr)) {
			  fprintf(stderr,"sendmail: invalid format of -V (envid) parameter: '%s'\n",envidstr);
			  exit(EX_USAGE);
			}
			break;
		case 'x':	/* Ignore this AIXism */
			break;
		default:
			++errflg;
			break;
		}
	}

	mail_priority = _MAILPRIO_NORMAL;
	if (mailpriority) {
	  mail_priority = atoi(mailpriority);
	  if (mail_priority < 0) {
	    /* Some word ?? */
	    if (CISTREQ(mailpriority,"high"))
	      mail_priority = _MAILPRIO_HIGH;
	    else if (CISTREQ(mailpriority,"NORMAL"))
	      mail_priority = _MAILPRIO_NORMAL;
	    else if (CISTREQ(mailpriority,"BULK"))
	      mail_priority = _MAILPRIO_BULK;
	    else if (CISTREQ(mailpriority,"JUNK"))
	      mail_priority = _MAILPRIO_JUNK;
	    else
	      mail_priority = _MAILPRIO_NORMAL;
	  }
	}
	/* Make sure the submission priority is >= 0  */
	if (mail_priority < 0) mail_priority = 0;

	if (errbuf[0] != '\0')
		fprintf(stderr, "%s: ignored %s options:%s\n",
				zmailer, progname, errbuf);
otherprog:
	if (speaksmtp + interactive + aliases + printq + daemon_flg > 1) {
		fprintf(stderr, "%s: conflicting sendmail options\n",
				zmailer);
	}
	if (errflg) {
		usage();
		exit(EX_USAGE);
	}
	n = 0;
	mav[n++] = ROUTER;		/* has to be something... */
	mav[n++] = NULL;
	if (configfile != NULL)
		mav[n++] = configfile;
	if (pooption != NULL)
		mav[n++] = pooption;
	mav[n] = NULL;
	if ((mailbin = getzenv("MAILBIN")) == NULL)
		mailbin = MAILBIN;
	if ((mailshare = getzenv("MAILSHARE")) == NULL)
		mailshare = MAILSHARE;
	path = NULL;
	if (speaksmtp) {
		const char *av[30+1];
		path = emalloc((unsigned)(strlen(mailbin)+1+strlen(SMTPSERVER)+1));
		sprintf(path, "%s/%s", mailbin, SMTPSERVER);
		av[0] = "smtp-in";
		av[1] = "-i";
		n = 2;
		cp = getzenv("SMTPOPTIONS"); /* Normal smtp-server options */
		/* pass on suidness */
		s = strtok(cp, " \t\"'");
		do {
		  av[n++] = s;
		  s = strtok(NULL, " \t\"'");
		} while (s != NULL && n < 30);
		av[n] = NULL;
		execv(path, (char*const*)av);
		perror(path);
	} else if (daemon_flg) {
		setuid(getuid());
		if (chdir(mailbin) < 0) {
			perror(mailbin);
			exit(EX_UNAVAILABLE);
		}
		if ((pid = fork()) > 0) {
			exit(0);
		} else if (pid == 0) { /* Child */
			mav[0] = "zmailer";
			mav[1] = NULL;
			execv("zmailer", (char*const*)mav);
			perror(zmailer);
			exit(EX_UNAVAILABLE);
		}
		perror("fork");
		exit (EX_OSERR);
	} else if (interactive) {
		setuid(getuid());
		mav[1] = "-i";
		path = emalloc((unsigned)(strlen(mailbin)+1+strlen(ROUTER)+1));
		sprintf(path, "%s/%s", mailbin, ROUTER);
		execv(path, (char*const*)mav);
		perror(path);
		exit(EX_UNAVAILABLE);
	} else if (aliases) {
		setuid(getuid());
		mav[1] = emalloc((unsigned)(2+strlen(mailbin)+1
					     +strlen(NEWALIASES)+1));
		sprintf((char*)mav[1], "-f%s/%s", mailbin, NEWALIASES);
		path = emalloc((unsigned)(strlen(mailbin)+1+strlen(ROUTER)+1));
		sprintf(path, "%s/%s", mailbin, ROUTER);
		execv(path, (char*const*)mav);
		perror(path);
		exit(EX_UNAVAILABLE);
	} else if (printq) {
		setuid(getuid());
		path = emalloc((unsigned)(strlen(mailbin)+1+strlen(MAILQ)+1));
		sprintf(path, "%s/%s", mailbin, MAILQ);
		argv[0] = MAILQ;
		if (bpflag)
			argv[1] = NULL;
		execv(path, (char*const*)argv);
		perror(path);
		exit(EX_UNAVAILABLE);
	} else {	/* ahh, normal, at last! */
		RETSIGTYPE (*oldsig) __((int));
		SIGNAL_HANDLESAVE(SIGINT, SIG_IGN, oldsig);
		if (oldsig != SIG_IGN)
			SIGNAL_HANDLE(SIGINT, doabort);
		SIGNAL_HANDLESAVE(SIGTERM, SIG_IGN, oldsig);
		if (oldsig != SIG_IGN)
			SIGNAL_HANDLE(SIGTERM, doabort);
		SIGNAL_HANDLESAVE(SIGHUP, SIG_IGN, oldsig);
		if (oldsig != SIG_IGN)
			SIGNAL_HANDLE(SIGHUP, doabort);
		/*
		 * If running as root, run as the user who su'ed if applicable.
		 * If still running as root, run as the trusted user.  If from
		 * was specified, we're okay.  If from wasn't specified
		 * but the real uid is nonzero, use that name.  Else if
		 * getlogin() returns something, use that.  Else use root.
		 */
		uid = getuid();
		truid = runastrusteduser();
		if ((mfp = mail_open(MSG_RFC822)) == NULL) {
		  n = errno;
		  fprintf(stderr, "%s: cannot submit mail (err# %d)!\n",
			  zmailer, errno);

		  zopenlog("sendmail", LOG_PID, LOG_MAIL);

		  errno = n;
		  zsyslog((LOG_SALERT, "cannot submit mail for uid %d: %m",
			   uid));
		  mfp = deadletter(uid);
		}
		if (truid != uid) {
		  /* if we are setuid root, and not invoked by root,
		     hardwire in the definition of from so the mailer
		     will know */
#ifdef	HAVE_FCHOWN
		  runasrootuser();
		  if (uid != 0 && fchown(fileno(mfp), uid, -1) == 0)
		    ;
		  else
#endif /* HAVE_FCHOWN */
		    if (from == NULL) {
		      if (uid != 0 && (pwd = getpwuid(uid)) != NULL)
			from = pwd->pw_name;
		      else if ((cp = getlogin()) != NULL)
			from = cp;
		      else	/* could find with getpwnam */
			from = "root";
		    }
#ifdef	HAVE_FCHOWN
		  runastrusteduser();
#endif /* HAVE_FCHOWN */
		}

		vfd = -1;
		if (verbose) {
		  int old_umask;
		  if (postoffice == NULL) {
		    postoffice = getzenv("POSTOFFICE");
		    if (postoffice == NULL)
		      postoffice = POSTOFFICE;
		  }
		  verbfile = emalloc(strlen(postoffice)
				     +strlen(PUBLICDIR)+20);
		  sprintf(verbfile, "%s/%s/v_XXXXXX",
			  postoffice, PUBLICDIR);
		  old_umask = umask(0077);
#ifdef HAVE_MKSTEMP
		  vfd = mkstemp(verbfile);
		  if (*verbfile == '\0' || vfd < 0)
#else
		  mktemp(verbfile);
		  if (*verbfile == '\0' ||
		      (vfd = open(verbfile, O_CREAT|O_RDWR, 0600)) < 0)
#endif
		    {
		      fprintf(stderr,
			      "%s: cannot create verbose log file in %s/%s\n",
			      zmailer, postoffice, PUBLICDIR);
		      verbfile = NULL;
		    } else {
		      /*
		       * We need to make it a relative pathname
		       * in case the router/scheduler's idea of
		       * root directory is different than ours.
		       */
		      cp = strrchr(verbfile, '/');
		      while (--cp > verbfile)
			if (*cp == '/')
			  break;
		      fprintf(mfp, "verbose \"../%s\"\n", cp+1);
		    }
		  umask(old_umask);
		}
		if (external)
		  fprintf(mfp, "external\n");
		if (bodytype && *bodytype != 0)
		  fprintf(mfp, "bodytype %s\n", bodytype);
		if (fullname != NULL && *fullname != '\0')
		  /* maybe we should put it in the environment? */
		  fprintf(mfp, "fullname %s\n", fullname);

		RFC821_822QUOTE(newcp,from);

		if (from != NULL && STREQ(from,"<>"))
		  fprintf(mfp, "channel error\n");
		else if (from != NULL && *from != '\0')
		  fprintf(mfp, "from %s\n", from);

		if (newcp) free((void*)newcp); newcp = NULL;

		if (envidstr)
		  fprintf(mfp, "envid %s\n", envidstr);
		if (returnopt)
		  fprintf(mfp, "notaryret %s\n", returnopt);
		if (submitprotocol)
		  fprintf(mfp, "with %s\n", submitprotocol);

		if (!rfc822recipients)
		  for (; optind < argc; ++optind)
		    check_and_print_to(mfp,argv[optind],notificationopt,from);

		fprintf(mfp,"env-end\n");

		if (fflush(mfp) == EOF
/* #ifdef NFSFSYNC */  /* This is probably ALWAYS a good idea.. */
		    || fsync(fileno(mfp)) < 0
/* #endif */	/* NFSFSYNC */
		    || ferror(mfp)) {
		  mail_abort(mfp);
		  mfp = deadletter(uid);
		  errflg = 1;
		}

		/*
		 * The postoffice cannot be changed from outside mail_open(),
		 * which, though it may be unsatisfactory, is good for security.
		 */
		
		if (rfc822recipients) {
		  /* We don't mess with headers, nor the envelope at
		     this phase. */
		  while ((n = read(0, buf, sizeof buf)) > 0) {
		    if (fwrite(buf, sizeof buf[0], n, mfp) != n)
		      break;
		    outcount += n;
		  }
		} else {
		  /* cmd line can only set dotiseof to 0.. improvement? */
		  int crlf_strip = 0;
		  if (dotiseof)
		    dotiseof = isatty(fileno(stdin));
		  n = 0;
		  while (fgets(buf, sizeof buf, stdin)) {
		    /* In case the input contains CRLF instead of LF,
		       do convert them.. */
		    if (crlf_strip) {
		      s = strrchr(buf, '\r');
		      if (s && s[1] == '\n' && s[2] == 0) {
			s[0] = '\n';
			s[1] = 0;
		      }
		    }
		    if (++n == 1) {

		      /* The first line, see if we have junk in the begin..
			 But detect at first the input for CRLF line
			 termination in place of the UNIX-normal LF ... */

		      if ((s = strrchr(buf, '\r')) != NULL &&
			  s[1] == '\n' && s[2] == 0) {
			/* Brr... CRLF+NULL */
			crlf_strip = 1;
			s[0] = '\n';
			s[1] = 0;
		      }
		      if (!save_from && STREQN(buf,"From ",5)) {
			/* [mea@utu.fi] I vote for
			   removing this line if next
			   is a RFC-header */
			buf2 = emalloc(2+strlen(buf));
			if (!buf2) { errflg=1; break; }
			strcpy(buf2,buf);
			continue;
		      }
		      if (!save_from && STREQN(buf,">From ",6)) {
			/* [mea@utu.fi] I vote for
			   removing this line if next
			   is a RFC-header */
			buf2 = emalloc(2+strlen(buf));
			if (!buf2) { errflg=1; break; }
			strcpy(buf2,buf);
			continue;
		      }
		      for (s = buf;
			   isascii(*s) && !isspace(*s)
			   && *s != ':';
			   ++s)
			continue;
		      if (*s != ':')
			putc('\n', mfp);
		    }
		    if (n==2 && buf2) { /* Handle 2nd line if first begun
					   with a "From "  */
		      for (s = buf;
			   isascii(*s) && !isspace(*s) && *s != ':';
			   ++s)
			continue;
		      if (*s != ':') {
			putc('\n', mfp);
			fputs( buf2, mfp );
		      }
		    }
		    s = buf;
		    if (dotiseof && *s == '.' && *++s == '\n')
		      break;
		    fputs(buf, mfp);
		    ++outcount;
		  }
		}

		fflush(mfp);
		if (errflg || ferror(mfp)) {
		  fprintf(stderr,
			  "%s: message not submitted due to I/O error!\n",
			  zmailer);
		  if (!errflg)
		    mail_abort(mfp);
		  if (vfd >= 0)
		    unlink(verbfile);
		  exit(EX_IOERR);
		} else if (outcount == 0) {
		  /* No input ?? Ignore silently */
		  mail_abort(mfp);
		  if (vfd >= 0)
		    unlink(verbfile);
		  exit(EX_OK);
		} else if (mail_close(mfp) == EOF) {
		  fprintf(stderr, "%s: message not submitted!\n",
			  zmailer);
		  if (vfd >= 0)
		    unlink(verbfile);
		  exit(EX_UNAVAILABLE);
		}
		if (vfd >= 0) {
		  int sleeplimit = 260000; /* 260 000 seconds is circa 3d */

		  if (fork() > 0) exit(EX_OK); /* Let the child to do
						  the trace printout */
		  if (vfd != 0) close(0);
		  if (vfd != 1) close(1);
		  vfp = fdopen(vfd, "r");
		  while (vfp != NULL) {
		    while (fgets(buf, sizeof buf, vfp) != NULL) {
		      fprintf(stderr, "%s", buf);
		      if (STREQN(buf, "scheduler done", 14))
			sleeplimit = 20; /* 20 seconds to death */
		    }
		    clearerr(vfp);
		    sleep(1);
		    --sleeplimit;
		    if (sleeplimit < 0)
		      break;
		  }
		}
		if (verbfile)
		  unlink(verbfile);
		exit(EX_OK);
		/* NOTREACHED */
	}
	if (path != NULL)
	  free((void*)path);
	exit(EX_UNAVAILABLE);
	/* NOTREACHED */
	return 0;
}

FILE *
deadletter(uid)
	int uid;
{
	struct passwd *pwd;
	FILE *fp;
	char	buf[8192];

	if ((pwd = getpwuid(uid)) == NULL) {
		fprintf(stderr, "%s: can't save mail!\n", zmailer);
		exit(EX_NOUSER);
		/* NOTREACHED */
	}
	sprintf(buf, "%s/dead.letter", pwd->pw_dir);
	if ((fp = fopen(buf, "a")) == NULL) {
		fprintf(stderr, "%s: can't open \"%s\" to save mail!\n",
				zmailer, buf);
		exit(EX_CANTCREAT);
		/* NOTREACHED */
	}
	fprintf(stderr, "%s: mail saved in \"%s\"\n", zmailer, buf);
	return fp;
}

void
doabort(dummy)
int dummy;
{
	if (mfp != NULL)
		mail_abort(mfp);
	if (verbfile != NULL && *verbfile != '\0')
		unlink(verbfile);
	fprintf(stderr, "%s: interrupt! message submission aborted!\n",
		zmailer);
	exit(EX_TEMPFAIL);
}


/* haa@cs.hut.fi:  Sometimes address components contain pure junk.. */
void
check_and_print_to(mfp, addr, notify, from)
	FILE *mfp;
	const char *addr, *notify, *from;
{
	const char *copy = NULL, *printme = addr, *frm;
	const char *s, *newcp = NULL;
	char *to;

	if (addr == NULL) {
	  fprintf(stderr, "sendmail: Argument botch: NULL address\n");
	  return;
	}
	if (strchr(addr,'\n')) {
	  fprintf(stderr, "sendmail: LF in  to<SPC> address: %s\n",addr);
	  to = emalloc(strlen(addr)+1); /* +1 just to be sure */
	  if (to == NULL) return;	  /* should never happen... */

	  copy = to;
	  for (frm = addr; *frm; ++frm)
	    if (*frm != '\n') *to++ = *frm;
	  *to = 0;

	  printme = copy;
	}

	RFC821_822QUOTE(newcp,printme);

	/* FIRST 'todsn', THEN 'to' -header! */
	fprintf(mfp, "todsn ORCPT=rfc822;");
	s = printme;
	while (*s) {
	  u_char c = *s;
	  if ('!' <= c && c <= '~' && c != '+' && c != '=')
	    putc(c,mfp);
	  else
	    fprintf(mfp,"+%02X",c);
	  ++s;
	}

	fprintf(mfp, " INRCPT=rfc822;");
	s = printme;
	while (*s) {
	  u_char c = *s;
	  if ('!' <= c && c <= '~' && c != '+' && c != '=')
	    putc(c,mfp);
	  else
	    fprintf(mfp,"+%02X",c);
	  ++s;
	}

	if (from) {
	  fprintf(mfp, " INFROM=rfc822;");
	  s = from;
	  while (*s) {
	    u_char c = *s;
	    if ('!' <= c && c <= '~' && c != '+' && c != '=')
	      putc(c,mfp);
	    else
	      fprintf(mfp,"+%02X",c);
	    ++s;
	  }
	}

	if (notify)
	  fprintf(mfp," NOTIFY=%s", notify);
	putc('\n',mfp);
	fprintf(mfp, "to %s\n", printme);
	if (copy) free((void*)copy);
	if (newcp) free((void*)newcp);
}

#if 0
char *
tmalloc(n)
	unsigned int n;
{
	return emalloc(n);
}
#endif

int is_xtext_string(str)
const char *str;
{
	/* Verify that the input is valid RFC 1981 XTEXT string! */

	while (*str) {
		unsigned char c = *str;
		if ('!' <= c && c <= '~' && c != '+' && c != '=')
		  ; /* is ok! */
		else if (c == '+') {
		  c = *++str;
		  if (!(('0' <= c && c <= '9') || ('A' <= c && c <= 'F')))
		    return 0; /* Invalid! */
		  c = *++str;
		  if (!(('0' <= c && c <= '9') || ('A' <= c && c <= 'F')))
		    return 0; /* Invalid! */
		} else {
		  return 0; /* Is not valid XTEXT string */
		}
		++str;
	}
	return 1;
}
