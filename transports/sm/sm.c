/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *	Copyright 1994-2000 by Matti Aarnio -- MIME processings
 */

#define DefCharset "ISO-8859-1"

#include "hostenv.h"
#include <ctype.h>
#include <pwd.h>
#include "zmsignal.h"
#include <sysexits.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/stat.h>
#include "ta.h"
#include "mail.h"
#include "zmalloc.h"
#include "zsyslog.h"
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#include "libz.h"


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

#ifndef	SEEK_SET
#define	SEEK_SET 0
#endif	/* !SEEK_SET */

/* as in: SKIPWHILE(isascii,cp) */
#define SKIPSPACE(Y) while (*Y == ' ' || *Y == '\t' || *Y == '\n') ++Y
#define SKIPTEXT(Y)  while (*Y && *Y != ' ' && *Y != '\t' && *Y != '\n') ++Y

#define	FROM_	"From "

#ifndef	MAXHOSTNAMELEN
#define	MAXHOSTNAMELEN 64
#endif	/* MAXHOSTNAMELEN */

char uucpname[MAXHOSTNAMELEN+1];

char	*progname;
#if !(defined(HAVE_MMAP) && defined(TA_USE_MMAP))
int	readalready = 0;	/* does buffer contain valid message data? */
#endif
int	mimeqpnarrow = 0;	/* Can't send TAB thru without MIME-QP */
FILE	*verboselog = NULL;
FILE	*logfp   = NULL;
int	maxwidth = 0;
int	can_8bit = 0;		/* Can do 8-bit stuff! */
int	decode_qp = 0;
int	keep_header8 = 0;	/* Don't do "MIME-2" to the headers */

int	D_alloc = 0;		/* Memory debugging */
char    *defcharset;


extern RETSIGTYPE sigpipe();
int gotsigpipe = 0;

RETSIGTYPE
sigpipe(sig)
int sig;
{
	gotsigpipe = 1;
	SIGNAL_HANDLE(SIGPIPE, sigpipe);
}

extern RETSIGTYPE wantout();
#ifndef MALLOC_TRACE
extern univptr_t emalloc();
extern univptr_t erealloc();
#endif
extern char *optarg;
extern int optind;
extern int getmyuucpname();
extern struct maildesc *readsmcf __((char *file, char *mailer));
extern void prversion();
extern void process __((struct ctldesc *dp, struct maildesc *mp, FILE *verboselog));
extern void deliver __((struct ctldesc *dp, struct maildesc *mp, struct rcpt *startrp, struct rcpt *endrp, FILE *verboselog));
extern int appendlet __((struct ctldesc *dp, struct maildesc *mp, FILE *fp, FILE *verboselog, int convertmode));
extern int writebuf __((struct maildesc *mp, FILE *fp, const char *buf, int len));
extern time_t time();
#ifndef strchr
extern char *strchr(), *strrchr();
#endif

static int zsfsetfd(fp, fd)
     Sfio_t *fp;
     int fd;
{
  /* This is *NOT* the SFIO's sfsetfd() -- we do no sfsync() at any point.. */
  fp->file = fd;
  return fd;
}

extern int check_7bit_cleanness __((struct ctldesc *dp));

struct maildesc {
	char	*name;
	short	flags;
	char	*command;
#define MD_ARGVMAX 20
	char	*argv[MD_ARGVMAX];
};

extern int writemimeline __(( struct maildesc *mp, FILE *fp, const char *buf, int len, int convertmode));

#define	MO_FFROMFLAG		0x00001
#define	MO_RFROMFLAG		0x00002
#define	MO_NORESETUID		0x00004
#define	MO_STRIPQUOTES		0x00008
#define	MO_MANYUSERS		0x00010
#define	MO_RETURNPATH		0x00020
#define	MO_UNIXFROM		0x00040
#define	MO_HIDDENDOT		0x00080 /* SMTP dot-duplication */
#define	MO_ESCAPEFROM		0x00100
#define	MO_STRIPHIBIT		0x00200
#define	MO_REMOTEFROM		0x00400
#define	MO_CRLF			0x00800
#define MO_BSMTP		0x01000 /* BSMTP-wrapping -- with HIDDENDOT.. */
#define MO_BESMTP		0x02000 /* Extended BSMTP -- SIZE+8BITMIME    */
#define MO_BEDSMTP		0x04000 /* EBSMTP + DSN */
#define MO_BEBSMTP		0x04000 /* ESMTP + DELIVERBY */
#define MO_WANTSDATE		0x08000 /* Wants "Date:" -header */
#define MO_WANTSFROM		0x10000 /* Wants "From:" -header */
#define MO_BSMTPHELO		0x20000 /* Add HELO/EHLO to the BSMTP */

#define MO_XENVELOPES		0x40000 /* Write various X-Envelope-*: headers to mesage */

struct exmapinfo {
	int	origstatus;
	const char *statusmsg;
	int	newstatus;
	const char *dsnstatus;
	const char *dsndiags;
};
struct exmapinfo exmap[] = {
  { EX_USAGE,	"command line usage error",	EX_TEMPFAIL,	"5.3.0", "x-local; 500 (Command line usage error)"	},
  { EX_DATAERR,	"data format error",		EX_DATAERR,	"5.3.0", "x-local; 500 (Data format error)"	},
  { EX_NOINPUT,	"cannot open input",		EX_TEMPFAIL,	"5.3.0", "x-local; 530 (Cannot open input)"	},
  { EX_NOUSER,	"addressee unknown",		EX_NOUSER,	"5.1.1", "x-local; 521 (No such target user)"	},
  { EX_NOHOST,	"host name unknown",		EX_NOHOST,	"5.3.0", "x-local; 500 (Target host unknown)"	},
  { EX_UNAVAILABLE, "service unavailable",	EX_UNAVAILABLE,	"5.3.0", "x-local; 500 (Service unavailable)"	},
  { EX_SOFTWARE, "internal software error",	EX_TEMPFAIL,	"5.3.0", "x-local; 500 (Internal software error)"	},
  { EX_OSERR,	"system error",			EX_TEMPFAIL,	"5.3.0", "x-local; 500 (System error)"	},
  { EX_OSFILE,	"critical OS file missing",	EX_TEMPFAIL,	"5.3.0", "x-local; 500 (Critical OS file missing)"	},
  { EX_CANTCREAT, "can't create output file",	EX_TEMPFAIL,	"5.2.1", "x-local; 500 (Can't create output file)"	},
  { EX_IOERR,	"input/output error",		EX_TEMPFAIL,	"5.2.2", "x-local; 500 (Input/Output error)"	},
  { EX_TEMPFAIL, "temporary failure",		EX_TEMPFAIL,	"5.3.0", "x-local; 500 (Temporary failure)"	},
  { EX_PROTOCOL, "remote error in protocol",	EX_TEMPFAIL,	"5.3.0", "x-local; 500 (Remote error in protocol)"	},
  { EX_NOPERM,	"permission denied",		EX_NOPERM,	"5.2.0", "x-local; 520 (Permission denied)"	},
  { 0,		NULL,				EX_TEMPFAIL,	NULL,	NULL	}
};

char myhostname[MAXHOSTNAMELEN+1];

#ifdef	lint
#undef	putc
#define	putc	fputc
#endif	/* lint */

#ifndef	MAXPATHLEN
#define	MAXPATHLEN 1024
#endif	/* MAXPATHLEN */

int
main(argc, argv)
	int argc;
	char *argv[];
{
	char file[MAXPATHLEN+1];
	char *channel, *host = NULL, *mailer, *cf;
	struct ctldesc *dp;
	int errflg, c;
	struct maildesc *mp;
	RETSIGTYPE (*oldsig)();

	SIGNAL_HANDLESAVE(SIGINT, SIG_IGN, oldsig);
	if (oldsig != SIG_IGN)
	  SIGNAL_HANDLE(SIGINT, wantout);
	SIGNAL_HANDLESAVE(SIGTERM, SIG_IGN, oldsig);
	if (oldsig != SIG_IGN)
	  SIGNAL_HANDLE(SIGTERM, wantout);
	SIGNAL_HANDLESAVE(SIGQUIT, SIG_IGN, oldsig);
	if (oldsig != SIG_IGN)
	  SIGNAL_HANDLE(SIGQUIT, wantout);
	SIGNAL_HANDLESAVE(SIGHUP, SIG_IGN, oldsig);
	if (oldsig != SIG_IGN)
	  SIGNAL_HANDLE(SIGHUP, wantout);

	SIGNAL_HANDLE(SIGPIPE, sigpipe);

	if ((progname = strrchr(argv[0], '/')) == NULL)
	  progname = argv[0];
	else
	  ++progname;
	errflg = 0;
	host = channel = NULL;
	myhostname[0] = 0;
	cf = NULL;
	while (1) {
	  c = getopt(argc, argv, "f:c:h:HQvVw:8");
	  if (c == EOF)
	    break;

	  switch (c) {
	  case 'f':
	    cf = optarg;
	    break;
	  case 'c':		/* remote hostname */
	    channel = optarg;
	    break;
	  case 'h':		/* remote hostname */
	    host = strdup(optarg);
	    break;
	  case 'Q':
	    mimeqpnarrow = 1;
	    break;
	  case 'V':
	    prversion("sm");
	    exit(0);
	    break;
	  case 'v':
	    verboselog = stdout;
	    break;
	  case '8':
	    can_8bit = decode_qp = 1;
	    break;
	  case 'H':
	    keep_header8 = 1;
	    break;
	  case 'w':
	    maxwidth = atoi(optarg);
	    if (maxwidth < 0)
	      maxwidth = 0;
	  default:
	    ++errflg;
	    break;
	  }
	}
	if (errflg || optind != argc - 1 || host == channel) {
	  fprintf(stderr,
		  "Usage: %s [-V][-v][-H][-8 | -Q][-f cfgfile][-w maxwidth][-c channel | -h host] mailer\n", argv[0]);
	  exit(EX_USAGE);
	}
	mailer = argv[optind];

	/* We need this latter on .. */
	zopenlog("sm", LOG_PID, LOG_MAIL);

	defcharset = getzenv("DEFCHARSET");
	if (!defcharset)
	  defcharset = DefCharset;

	if ((mp = readsmcf(cf, mailer)) == NULL)
	  exit(EX_OSFILE);
	if (mp->flags & MO_REMOTEFROM)
	  getmyuucpname(uucpname, sizeof uucpname);	/*XX*/
	while (!getout) {
	  char *s;

	  /* Input:
	       spool/file/name [ \t host.info ] \n
	   */

	  printf("#hungry\n");
	  fflush(stdout);

	  if (fgets(file, sizeof file, stdin) == NULL)
	    break;
	  if (strchr(file, '\n') == NULL) break; /* No ending '\n' !  Must
						    have been partial input! */
	  if (strcmp(file, "#idle\n") == 0)
	    continue; /* Ah well, we can stay idle.. */
	  if (emptyline(file, sizeof file))
	    break;

	  s = strchr(file,'\t');
	  if (s != NULL) {
	    if (host) free(host);
	    host = strdup(s+1);
	    *s = 0;
	  }

	  ctlsticky(NULL, NULL, NULL); /* reset */
	  dp = ctlopen(file, channel, host, &getout, ctlsticky, NULL, NULL, NULL);
	  if (dp == NULL) {
	    printf("#resync %s\n",file);
	    fflush(stdout);
	    continue;
	  }
	  if (verboselog != stdout && verboselog != NULL) {
	    fclose(verboselog);
	    verboselog = NULL;
	  }
	  if (verboselog != stdout && dp->verbose) {
	    verboselog = fopen(dp->verbose,"a");
	    if (verboselog) setbuf(verboselog,NULL);
	  }
	  process(dp, mp, verboselog);
	  ctlclose(dp);
	}
	if (verboselog != NULL)
	  fclose(verboselog);
	if (logfp != NULL)
	  fclose(logfp);
	exit(EX_OK);
	/* NOTREACHED */
	return 0;
}

void
process(dp, mp, verboselog)
	struct ctldesc *dp;
	struct maildesc *mp;
	FILE *verboselog;
{
	struct rcpt *rp, *rphead;

#if !(defined(HAVE_MMAP) && defined(TA_USE_MMAP))
	readalready = 0; /* ignore any previous message data cache */
#endif

	if (mp->flags & MO_MANYUSERS) {
	  for (rp = rphead = dp->recipients; rp != NULL; rp = rp->next) {
	    if (rp->next == NULL
		|| rp->addr->link != rp->next->addr->link
		|| rp->newmsgheader != rp->next->newmsgheader) {
	      deliver(dp, mp, rphead, rp->next, verboselog);
	      rphead = rp->next;
	    }
	  }
	} else {
	  for (rp = dp->recipients; rp != NULL; rp = rp->next) {
	    deliver(dp, mp, rp, rp->next, verboselog);
	  }
	}
}

/*
 * deliver - deliver the letter in to user's mail box.  Return
 *	     errors and requests for further processing in the structure
 */

void
deliver(dp, mp, startrp, endrp, verboselog)
	struct ctldesc *dp;
	struct maildesc *mp;
	struct rcpt *startrp, *endrp;
	FILE *verboselog;
{
	struct rcpt *rp = NULL;
	struct exmapinfo *exp;
	const char *exs, *exd;
	int i, j, pid = 0, in[2], out[2], ii = 0;
	unsigned int avsize;
	FILE *tafp = NULL, *errfp = NULL;
	char *cp = NULL, buf[BUFSIZ], buf2[BUFSIZ];
	char *ws = NULL, *we = NULL;
	const char *ds, **av, *s;
	int status;
	int content_kind, conversion_prohibited, ascii_clean = 0;
	time_t now;
	char *timestring;
	CONVERTMODE convertmode = _CONVERT_NONE;

	now = time((time_t *)0);
	timestring = ctime(&now);
	*(timestring+strlen(timestring)-1) = '\0';

	if (lseek(dp->msgfd, (off_t)(dp->msgbodyoffset), SEEK_SET) < 0L)
		warning("Cannot seek to message body! (%m)", (char *)NULL);

	i = 0;
	avsize = 5;
	av = (const char **)emalloc(sizeof av[0] * avsize);
	av[i++] = mp->argv[0];
	if (mp->flags & MO_FFROMFLAG) {
	  av[i++] = "-f";
	  if (strcmp(startrp->addr->link->channel,"error")==0)
	    av[i++] = "<>";
	  else
	    av[i++] = startrp->addr->link->user;
	} else if (mp->flags & MO_RFROMFLAG) {
	  av[i++] = "-r";
	  if (strcmp(startrp->addr->link->channel,"error")==0)
	    av[i++] = "<>";
	  else
	    av[i++] = startrp->addr->link->user;
	}
	for (j = 0; mp->argv[j] != NULL; ++j) {
	  while (i+2 >= avsize) {
	    avsize *= 2;
	    av = (const char **)erealloc((char *)av,
					 sizeof av[0] * avsize);
	  }
	  if (strchr(mp->argv[j], '$') == NULL) {
	    if (j > 0)
	      av[i++] = mp->argv[j];
	    continue;
	  }
	  rp = startrp;
	  do {

	    /* Even argv[0] MAY have $-expansions.. */
	    ii = i; if (j == 0) ii = 0;

	    while (i+2 >= avsize) {
	      avsize <<= 1;
	      av = (const char **)erealloc((char *)av,
					   sizeof av[0] * avsize);
	    }
	    ws = buf;
	    we = buf + sizeof(buf);
	    for (cp = mp->argv[j]; *cp != '\0'; ++cp) {
	      if (*cp == '$') {
		switch (*++cp) {
		case 'g':
		  ds = rp->addr->link->user;
		  break;
		case 'h':
		  ds = rp->addr->host;
		  break;
		case 'u':
		  ds = rp->addr->user;
		  rp = rp->next;
		  break;
		case 'U':
		  strncpy(buf2, rp->addr->user, sizeof(buf2));
		  buf2[sizeof(buf2)-1] = 0;
		  strlower(buf2);
		  ds = buf2;
		  rp = rp->next;
		  break;
		case '{':
		  s = ++cp;
		  while (*cp != 0 && *cp != '}') ++cp;
		  if (*cp != 0) {
		    *cp = 0;
		    ds = getzenv(s);
		    *cp = '}';
		  } else {
		    ds = getzenv(s);
		  }
		  break;
		default:
		  ds = NULL;
		  break;
		}
		if (ds == NULL || *ds == '\0') {
		  char msg[BUFSIZ];

		  sprintf(msg,
			  "Null value for $%c (%%s) (msgfile: %s)!",
			  *cp, dp->msgfile);
		  warning(msg, mp->name);
		} else {
		  int len = strlen(ds);
		  if (ws + len >= we)
		    break; /* D'uh :-( */
		  memcpy(ws, ds, len+1);
		  ws += len;
		}
	      } else
		if (ws < we)
		  *ws++ = *cp;
	    }
	    if (ws < we)
	      *ws = '\0';
	    else
	      we[-1] = '\0'; /* Trunk in all cases */
	    /* not worth freeing this stuff */
	    av[ii] = strdup(buf);
	    if (j > 0)
	      ++i;
	  } while (rp != startrp && rp != endrp);
	  /* End of: "do {" */
	}
	/* End of: "for (j = ...) {" */
	av[i] = NULL;

	gotsigpipe = 0;

	/* now we can fork off and run the command... */
	if (pipe(out) < 0) {
	  for (rp = startrp; rp != endrp; rp = rp->next) {
	    notaryreport(rp->addr->user,"failed",
			 "5.3.0 (Out of system resources, pipe creation failed)",
			 "x-local; 500 (pipe creation error, out of system resources ?)");
	    diagnostic(rp, EX_OSERR, 0,
		       "cannot create pipe from \"%s\"",
		       mp->command);
	  }
	  return;
	}
	if (pipe(in) < 0) {
	  for (rp = startrp; rp != endrp; rp = rp->next) {
	    notaryreport(rp->addr->user,"failed",
			 "5.3.0 (Out of system resources, pipe creation failed)",
			 "x-local; 500 (pipe creation error, out of system resources ?)");
	    diagnostic(rp, EX_OSERR, 0,
		       "cannot create pipe to \"%s\"",
		       mp->command);
	  }
	  return;
	}
	if (verboselog) {
	  const char **p = av;
	  fprintf(verboselog,"To run UID=%d GID=%d ARGV[] =",
		  (int)getuid(), (int)getgid());
	  for ( ;*p != NULL; ++p) {
	    fprintf(verboselog," '%s'", *p);
	  }
	  fprintf(verboselog,"\n");
	  fflush(verboselog);
	}
	if ((pid = fork()) == 0) { /* child, run the command */
	  if (!(mp->flags & MO_NORESETUID)) {
	    /* struct passwd *pw = getpwuid(); */
	    setuid(getuid());
	  }
	  if (in[1] > 0) {
	    /* its stdout and stderr is the pipe, its stdin is our tafp */
	    if (out[0] > 0) dup2(out[0], 0);
	    if (in[1]  > 1) dup2(in[1], 1);
	    dup2(1, 2);
	    if (in[0] > 2) close(in[0]);
	    if (in[1] > 2) close(in[1]);
	    if (out[0] > 2) close(out[0]);
	    if (out[1] > 2) close(out[1]);
	  } else {
	    close(in[0]);
	    close(out[1]);
	    /* its stdout and stderr is the pipe, its stdin is our tafp */
	    close(0);
	    close(1);
	    close(2);
	    dup2(out[0], 0);
	    close(out[0]);
	    dup2(in[1], 1);
	    dup2(in[1], 2);
	    close(in[1]);
	  }
	  execv(mp->command, (char**) av);
	  _exit(254);
	} else if (pid < 0) {	/* couldn't fork, complain */
	  for (rp = startrp; rp != endrp; rp = rp->next) {
	    notaryreport(rp->addr->user,"failed",
			 "5.3.0 (Out of system resources, fork failed)",
			 "x-local; 500 (fork failure, out of system resources ?)");
	    diagnostic(rp, EX_OSERR, 0, "cannot fork");
	  }
	  return;
	}
	close(out[0]); /* child ends.. */
	close(in[1]);
	tafp = fdopen(out[1], "w"); /* parent ends .. */
	errfp = fdopen(in[0], "r");
	/* read any messages from its stdout/err on in[0] */

	if (verboselog) {
	  fprintf(verboselog,"%s\n\t", mp->command);
	  for (i = 0; av[i] != NULL; ++i)
	    fprintf(verboselog,"%s ", av[i]);
	  fprintf(verboselog,"\n");
	}

	free((char *)av);
	/* ... having forked and set up the pipe, we quickly continue */

	/* BSMTP et.al. envelope formation here! */

	if (mp->flags & MO_BSMTP) {

	  if (mp->flags & MO_BSMTPHELO) {
	    if (mp->flags & MO_BESMTP)
	      fprintf(tafp,"EHLO %s",myhostname);
	    else
	      fprintf(tafp,"HELO %s",myhostname);
	    if (mp->flags & MO_CRLF) putc('\r',tafp);
	    putc('\n',tafp);
	  }

	  if (strcmp(startrp->addr->link->channel,"error")==0)
	    fprintf(tafp,"MAIL From:<>");
	  else
	    fprintf(tafp,"MAIL From:<%s>", startrp->addr->link->user);
	  if (mp->flags & MO_BESMTP) {
	      fprintf(tafp," SIZE=%ld",startrp->desc->msgsizeestimate);
	    if (can_8bit)
	      fprintf(tafp," BODY=8BITMIME");
	  }
	  if (mp->flags & MO_BEDSMTP) {
	    if (startrp->desc->envid != NULL)
	      fprintf(tafp," ENVID=%s",startrp->desc->envid);
	    if (startrp->desc->dsnretmode != NULL)
	      fprintf(tafp, " RET=%s", startrp->desc->dsnretmode);
	  }
	  if (mp->flags & MO_CRLF) putc('\r',tafp);
	  putc('\n',tafp);
	  for (rp = startrp; rp != endrp; rp = rp->next) {
	    fprintf(tafp,"RCPT TO:<%s>",rp->addr->user);
	    /* if (mp->flags & MO_BESMTP) { } */
	    if (mp->flags & MO_BEDSMTP) {
	      if (rp->notifyflgs) {
		char *s = "";
		fprintf(tafp," NOTIFY=");
		if (rp->notifyflgs & _DSN_NOTIFY_NEVER) {
		  fprintf(tafp,"NEVER");
		}
		if (rp->notifyflgs & _DSN_NOTIFY_SUCCESS) {
		  fprintf(tafp,"SUCCESS");
		  s = ",";
		}
		if (rp->notifyflgs & _DSN_NOTIFY_FAILURE) {
		  fprintf(tafp,"%sFAILURE",s);
		  s = ",";
		}
		if (rp->notifyflgs & _DSN_NOTIFY_DELAY) {
		  fprintf(tafp,"%sDELAY",s);
		}
	      }
	      if (rp->orcpt)
		fprintf(tafp," ORCPT=%s",rp->orcpt);
	    }
	    if (mp->flags & MO_BEBSMTP) {
	      if (rp->deliverby) {
		fprintf(tafp," BY=%ld;", rp->deliverby - now);
		if (rp->deliverbyflgs & _DELIVERBY_R) fputc('R',tafp);
		if (rp->deliverbyflgs & _DELIVERBY_N) fputc('N',tafp);
		if (rp->deliverbyflgs & _DELIVERBY_T) fputc('T',tafp);
	      }
	    }
	    if (mp->flags & MO_CRLF) putc('\r',tafp);
	    putc('\n',tafp);
	  }

	  fprintf(tafp,"DATA");
	  if (mp->flags & MO_CRLF) putc('\r',tafp);
	  putc('\n',tafp);
	}

	/* Now continue with inside stuff -- well, normal UUCP stuff */

	if (mp->flags & (MO_UNIXFROM|MO_REMOTEFROM)) {
	  const char *uu = startrp->addr->link->user;

	  if (strcmp(startrp->addr->link->channel,"error")==0)
	    uu = "<>";
	  fprintf(tafp, "%s%s %s", FROM_, uu, timestring);
	  if (mp->flags & MO_REMOTEFROM)
	    fprintf(tafp, " remote from %s", uucpname);
	  if (verboselog) {
	    fprintf(verboselog, "%s%s %s", FROM_, uu, timestring);
	    if (mp->flags & MO_REMOTEFROM)
	      fprintf(verboselog, " remote from %s", uucpname);
	    putc('\n',verboselog);
	  }
	  putc('\n', tafp);
	}

	conversion_prohibited = check_conv_prohibit(startrp);

	/* Content-Transfer-Encoding: 8BIT ? */
	content_kind = cte_check(startrp);

	/* If the header says '8BIT' and ISO-8859-* something,
	   but body is plain 7-bit, turn it to '7BIT', and US-ASCII */
	ascii_clean = check_7bit_cleanness(dp);
	if (!conversion_prohibited && ascii_clean && content_kind == 8) {
	  if (downgrade_charset(startrp, verboselog))
	    content_kind = 7;
	}

	convertmode = _CONVERT_NONE;
	if (!conversion_prohibited) {
	  switch (content_kind) {
	  case 0:		/* No MIME headers defined */
	    if (!can_8bit && !ascii_clean) {
	      convertmode = _CONVERT_UNKNOWN;
	      downgrade_headers(startrp, convertmode, verboselog);
	    }
	    break;
	  case 2:		/* MIME, but no C-T-E: ? */
	  case 1:		/* MIME BASE64 ? some MIME anyway.. */
	  case 7:		/* 7BIT */
	    convertmode = _CONVERT_NONE;
	    break;
	  case 8:		/* 8BIT */
	    if (!can_8bit && !ascii_clean) {
	      convertmode = _CONVERT_QP;
	      if (!downgrade_headers(startrp, convertmode, verboselog))
		convertmode = _CONVERT_NONE;
	    }
	    break;
	  case 9:		/* QUOTED-PRINTABLE */
	    if (decode_qp) {
	      /* Force(d) to decode Q-P while transfer.. */
	      convertmode = _CONVERT_8BIT;
	      /*  UPGRADE TO 8BIT !  */
	      if (!qp_to_8bit(startrp))
		convertmode = _CONVERT_NONE;
	      content_kind = 10;
	      ascii_clean = 0;
	    }
	    break;
	  default:		/* ?? should not happen.. */
	    break;
	  }
	  
	  if (!keep_header8 && headers_need_mime2(startrp)) {
	    headers_to_mime2(startrp,defcharset,verboselog);
	  }
	}

 	/* Add the "Return-Path:" is it is desired, but does not yet
	   exist.. */
	if (mp->flags & MO_RETURNPATH) {
	  const char *uu = startrp->addr->link->user;
	  char **hdrs;
	  do {
	    hdrs = has_header(startrp,"Return-Path:");
	    if (hdrs) delete_header(startrp, hdrs);
	  } while (hdrs);
	  if (strcmp(startrp->addr->link->channel,"error")==0)
	    uu = "";
	  append_header(startrp,"Return-Path: <%.999s>", uu);
	}

	if (mp->flags & MO_XENVELOPES) {
	  const char *uu;
	  char **hdrs;
	  do {
	    hdrs = has_header(startrp,"X-Envelope-To:");
	    if (hdrs) delete_header(startrp, hdrs);
	  } while (hdrs);
	  for (rp = startrp; rp != endrp; rp = rp->next) {
	    uu = rp->addr->user;
	    if (strcmp(rp->addr->link->channel,"error")==0)
	      uu = "";
	    append_header(rp,"X-Envelope-To: <%.999s> (uid %s)",
			  uu, rp->addr->misc);
	  }
	}

	if (mp->flags & MO_CRLF) {
	  fwriteheaders(startrp, tafp, "\r\n", convertmode, maxwidth, NULL);
	  fprintf(tafp, "\r\n");
	} else {
	  fwriteheaders(startrp, tafp, "\n",   convertmode, maxwidth, NULL);
	  fprintf(tafp, "\n");
	}

	if (verboselog) {
	  fwriteheaders(startrp, verboselog, "\n", convertmode, maxwidth, NULL);
	  fprintf(verboselog, "\n");
	}

	/* append message body itself */
	i = appendlet(dp, mp, tafp, verboselog, convertmode);
	if (i != EX_OK && !gotsigpipe) {
	  for (rp = startrp; rp != endrp; rp = rp->next) {
	    notaryreport(rp->addr->user,"failed",
			 /* Could indicate: 4.3.1 - mail system full ?? */
			 "5.3.0 (Write to target failed for some reason)",
			 "x-local; 500 (Write to target failed for some reason)");
	    diagnostic(rp, i, 0, "write error");
	  }
	  /* just to make sure nothing will get delivered */
	  kill(pid, SIGTERM);
	  sleep(1);
	  kill(pid, SIGKILL);
	  wait(NULL);
	  fclose(tafp); /* FP/pipe cleanups */
	  fclose(errfp);
	  return;
	}

	if (mp->flags & MO_BSMTP) {
	  if (mp->flags & MO_CRLF)
	    fprintf(tafp,".\r\n");
	  else
	    fprintf(tafp,".\n");
	}
	
	fclose(tafp);
	close(out[1]);	/* paranoia */
	if (fgets(buf, sizeof buf, errfp) == NULL)
	  buf[0] = '\0';
	else if ((cp = strchr(buf, '\n')) != NULL)
	  *cp = '\0';
	fclose(errfp);
	close(in[0]);	/* more paranoia */
	cp = buf + strlen(buf);

	exd = exs = NULL;
	pid = wait(&status);
	if (WSIGNALSTATUS(status) != 0) {
	  if (cp != buf)
	    *cp++ = ' ';
	  sprintf(cp, "[signal %d", WSIGNALSTATUS(status));
	  if (status&0200)
	    strcat(cp, " (Core dumped)");
	  strcat(cp, "]");
	  i = EX_TEMPFAIL;
	  exd = "x-local; 500 (failed on signal)";
	  exs = "5.3.0";
	} else if (WEXITSTATUS(status) == 0
#if EX_OK != 0
		   || WEXITSTATUS(status) == EX_OK
#endif
		   ) {
	  i = EX_OK;
	} else {
	  i = WEXITSTATUS(status);
	  s = NULL;
	  for (exp = & exmap[0]; exp->origstatus != 0; ++exp)
	    if (exp->origstatus == i) {
	      s = exp->statusmsg;
	      i = exp->newstatus;
	      exs = exp->dsnstatus;
	      exd = exp->dsndiags;
	      break;
	    }
	  sprintf(cp, "[exit status %d/%d", WEXITSTATUS(status), i);
	  if (s)
	    sprintf(cp+strlen(cp), " (%s)", s);
	  /* sprintf(cp+strlen(cp), " of command: %s", mp->command); */
	  strcat(cp, "]");
	}
	if (verboselog)
	  fprintf(verboselog,"Diagnostic: %s\n",cp);
	for (rp = startrp; rp != endrp; rp = rp->next) {
	  if (i == EX_OK)
	    notaryreport(rp->addr->user, "relayed",
			 "2.5.0", "smtp;250 (Delivered)");
	  else
	    notaryreport(rp->addr->user, "failed", exs, exd);
	  diagnostic(rp, i, 0, "%s", buf);
	}
	/* XX: still need to deal with MO_STRIPQUOTES */
}

/*
 * appendlet - append letter to file pointed at by fd
 */

#if !(defined(HAVE_MMAP) && defined(TA_USE_MMAP))
static char let_buffer[BUFSIZ*8];
#endif

int
appendlet(dp, mp, fp, verboselog, convertmode)
	struct ctldesc *dp;
	struct maildesc *mp;
	FILE *fp;
	FILE *verboselog;
	int convertmode;
{
	/* `convertmode' controls the behaviour of the message conversion:
	     _CONVERT_NONE (0): send as is
	     _CONVERT_QP   (1): Convert 8-bit chars to QUOTED-PRINTABLE
	     _CONVERT_8BIT (2): Convert QP-encoded chars to 8-bit
	     _CONVERT_UNKNOWN (3): Turn message to charset=UNKNOWN-8BIT, Q-P..
	 */

	register int i;
	int lastch;
#if !(defined(HAVE_MMAP) && defined(TA_USE_MMAP))
	register int bufferfull;
	int mfd = dp->msgfd;
#endif

	writebuf(mp, fp, (char *)NULL, 0);  /* magic initialization */

#if !(defined(HAVE_MMAP) && defined(TA_USE_MMAP))
	/* can we use cache of message body data */
	if (convertmode == _CONVERT_NONE && readalready != 0) {
	  lastch = let_buffer[readalready-1];
	  if (writebuf(mp, fp, let_buffer, readalready) != readalready)
	    return EX_IOERR;
	  if (lastch != '\n')
	    if (writebuf(mp, fp, "\n", 1) != 1)
	      return EX_IOERR;
	  return EX_OK;
	}
#endif

	lastch = -1;
	if (convertmode == _CONVERT_NONE) {
#if !(defined(HAVE_MMAP) && defined(TA_USE_MMAP))
	  bufferfull = 0;
	  readalready = 0;
	  lseek(mfd, dp->msgbodyoffset, SEEK_SET);
	  while ((i = read(mfd, let_buffer, sizeof let_buffer)) != 0) {
#else
	    const char *let_buffer = dp->let_buffer + dp->msgbodyoffset;
	    i = dp->let_end - (dp->let_buffer + dp->msgbodyoffset);
#endif
	    if (i < 0)
	      return EX_IOERR;
	    lastch = let_buffer[i-1];
	    if (writebuf(mp, fp, let_buffer, i) != i)
	      return EX_IOERR;
#if !(defined(HAVE_MMAP) && defined(TA_USE_MMAP))
	    readalready = i;
	    bufferfull++;
	  }
	  if (bufferfull > 1)	/* not all in memory, need to reread */
	    readalready = 0;
#endif

	} else {
	  /* convertmode something else, than _CONVERT_NONE */
	  /* Various esoteric conversion modes..
	     We are better to feed writemimeline() with LINES
	     instead of blocks of data.. */
#if !(defined(HAVE_MMAP) && defined(TA_USE_MMAP))
	  Sfio_t *mfp = sfnew(NULL, NULL, 64*1024, mfd, SF_READ|SF_WHOLE);
	  sfseek(mfp, dp->msgbodyoffset, SEEK_SET);

#define MFPCLOSE zsfsetfd(mfp, -1); sfclose(mfp);

	  readalready = 0;
#else
#define MFPCLOSE
	  const char *s = dp->let_buffer + dp->msgbodyoffset;
#endif
	  writemimeline(mp, fp, (char *)NULL, 0, 0);

	  /*
	     if(verboselog) fprintf(verboselog,
	     "sm: Convert mode: %d, fd=%d, fdoffset=%d, bodyoffset=%d\n",
	     convertmode, mfd, (int)lseek(mfd, (off_t)0, SEEK_CUR),
	     dp->msgbodyoffset);
	   */

	  /* we are assuming to be positioned properly
	     at the start of the message body */
	  lastch = -1;
	  i = 0;

	  for (;;) {
#if !(defined(HAVE_MMAP) && defined(TA_USE_MMAP))
	    if ((i = csfgets(let_buffer, sizeof(let_buffer), mfp)) == EOF)
	      break;
#else
	    const char *let_buffer = s, *s2 = s;
	    i = 0;
	    if (s >= dp->let_end) break;	/* "EOF" */
	    while (s2 < dp->let_end && *s2 != '\n')
	      ++s2, ++i;
	    if ((lastch = *s2) == '\n')
	      ++s2, ++i;
	    s = s2;
#endif
	    /* It MAY be malformed -- if it has a BUFSIZ length
	       line in it, IT CAN'T BE MIME  :-/		*/
	    /* Ok, write the line */
	    if (writemimeline(mp, fp, let_buffer, i, convertmode) != i) {
	      return EX_IOERR;
	    }
	  }
#if !(defined(HAVE_MMAP) && defined(TA_USE_MMAP))
	  if (i == EOF && !sfeof(mfp) && !sferror(mfp)) {
	    MFPCLOSE
	    return EX_IOERR;
	  }
	  MFPCLOSE
#endif
	}

	/* we must make sure the last thing we transmit is a CRLF sequence */
	if (lastch != '\n')
	  writebuf(mp, fp, "\n", 1);

	return EX_OK;
}

/*
 * Writebuf() is like write(), except all '\n' are converted to "\r\n"
 * (CRLF), and the sequence "\n.\n" is converted to "\r\n..\r\n".
 */

int
writebuf(mp, fp, buf, len)
	struct maildesc *mp;
	FILE *fp;
	const char *buf;
	int len;
{
	register const char *cp;
	register int n;
	int tlen;
	register char expect;
	static char save = '\0';
	static char frombuf[8];
	static char *fromp;

	if (buf == NULL) {	/* magic initialization */
	  save = '.';
	  frombuf[0] = 0;
	  fromp = frombuf;
	  return 0;
	}
	expect = save;
	for (cp = buf, n = len, tlen = 0; n > 0; --n, ++cp) {
	  int c = (*cp) & 0xFF;
	  if (mp->flags & MO_STRIPHIBIT)
	    c &= 0x7F;
	  ++tlen;
	  if (c == '\n') {
	    frombuf[0] = 0;
	    fromp = frombuf;
	    if (expect == '\n' && (mp->flags & MO_HIDDENDOT))
	      /* "\n.\n" sequence */
	      if (putc('.', fp) == EOF) { tlen = -1; break; }
	    if (mp->flags & MO_CRLF)
	      if (putc('\r', fp) == EOF) { tlen = -1; break; }
	    if (putc(c,fp) == EOF) { tlen = -1; break; }
	    expect = '.';
	  } else if (expect != '\0') {
	    if (expect == '.') {
	      if ((mp->flags & MO_ESCAPEFROM) && c == 'F')
		expect = 'F';
	      else if (c == '.' && (mp->flags & MO_HIDDENDOT)) {
		if (putc('.', fp) == EOF || putc('.', fp) == EOF)
		  { tlen = -1; break; }
		expect = '\0';
		continue;
	      } else {
		if (putc(c, fp) == EOF)
		  { tlen = -1; break; }
		expect = '\0';
		continue;
	      }
	    }
	    if (c == expect) {
	      *fromp++ = c;
	      *fromp   = 0;
	      switch (expect) {
		case 'F':	expect = 'r'; break;
	        case 'r':	expect = 'o'; break;
		case 'o':	expect = 'm'; break;
		case 'm':	expect = ' '; break;
		case ' ':
		  /* Write the separator, and the word.. */
		  if (fwrite(">From ", 6, 1, fp) == 0)
		    { tlen = -1; break; }
		  /* anticipate future instances */
		  expect = '\0';
		  break;
	      }
	    } else {
	      expect = '\0';
	      fromp = frombuf;
	      while (*fromp) {
		if (putc(*fromp,fp) == EOF)
		  { tlen = -1; break; }
		++fromp;
	      }
	      frombuf[0] = 0;
	      if (putc(c,fp) == EOF)
		{ tlen = -1; break; }
	    }
	  } else {
	    /* expect == 0 */
	      if (putc(c,fp) == EOF)
		{ tlen = -1; break; }
	  }
	}
	save = expect;

	return tlen;
}

int
writemimeline(mp, fp, buf, len, convertmode)
	struct maildesc *mp;
	FILE *fp;
	const char *buf;
	int len, convertmode;
{
	/* `convertmode' controls the behaviour of the message conversion:
	     _CONVERT_NONE (0): send as is
	     _CONVERT_QP   (1): Convert 8-bit chars to QUOTED-PRINTABLE
	     _CONVERT_8BIT (2): Convert QP-encoded chars to 8-bit
	     _CONVERT_UNKNOWN (3): Turn message to charset=UNKNOWN-8BIT, Q-P..
	 */
	register const char *cp;
	register int n;
	static int  column;
	register int qp_conv;
	register int qp_chrs = 0;

	if (buf == NULL) {
	  column = -1;
	  return 0;
	}

	qp_conv = (convertmode == _CONVERT_QP ||
		   convertmode == _CONVERT_UNKNOWN);

	for (cp = buf, n = len; n > 0; --n, ++cp) {
	  int c = (*cp) & 0xFF;
	  ++column;

	  if (qp_conv) {
	    /* ENCODE to QUOTED-PRINTABLE ... */ 
	    if (column > 70 && c != '\n') {
	      putc('=',fp);
	      if (mp->flags & MO_CRLF)
		putc('\r', fp);
	      putc('\n',fp);
	      column = 0;
	    }

	    if (column == 0 && (mp->flags & MO_HIDDENDOT) && c == '.') {
	      /* Duplicate the line initial dot.. */
	      if (putc(c,fp)==EOF) return EOF;
	    } else if (column == 0  &&  (mp->flags & MO_ESCAPEFROM)  &&
		       c == 'F'  &&  n >= 4  &&  strncmp(cp,"From",4)==0) {
	      /* We Q-P encode the leading 'F'.. */
	      if (fputs("=46",fp) != 3) return EOF;
	      column += 2;
	    } else if ((n < 3 || mimeqpnarrow) && c != '\n' &&
		       (c <= 32 || c > 126 || c == '=')) {
	      /* Downgrade it by translating it to Quoted-Printable.. */
	      /* Translate also trailing spaces/TABs */
	      if (fprintf(fp,"=%02X",c) != 3) return EOF;
	      column += 2;
	    } else if (c != '\n' && c != '\t' &&
		       (c < 32 || c > 126 || c == '=')) {
	      /* Downgrade it by translating it to Quoted-Printable.. */
	      /* SPACE and TAB are left untranslated */
	      if (fprintf(fp,"=%02X",c) != 3) return EOF;
	      column += 2;
	      buf = cp;
	    } else if (c == '\n') { /* This is most likely the LAST char */
	      if (mp->flags & MO_CRLF)
		if (putc('\r', fp) == EOF) return EOF;
	      if (putc(c,fp) == EOF) return EOF;
	      column = -1;
	    } else {
	      if (putc(c, fp) == EOF) return EOF;
	    }
	  } else if (convertmode == _CONVERT_8BIT) {
	    /* DECODE from QUOTED-PRINTABLE text.. */
	    static int qp_val = 0;
	    if (!qp_chrs && c == '=') { /* Q-P -prefix */
	      qp_chrs = 2;
	      qp_val = 0;
	      continue;
	    } else if (qp_chrs) {
	      --column;
	      if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
		break; /* Done with it, it was soft end-of-line */
	      if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') ||
		  (c >= 'a' && c <= 'f')) {
		/* A HEX digit ? QP char coming up ? */
		if (c >= 'a') c -= ('a' - 'A');
		if (c >= 'A') c -= ('A' - '9' -1);
		qp_val <<= 4;
		qp_val |= (c & 0x0F);
		if (--qp_chrs)
		  continue;	/* Not yet last.. */
		else
		  c = qp_val;	/* The second (=last) hex digit */
	      } else
		qp_chrs = 0;	/* While in this mode, NOT QP-hex-digit! */
	    } /* Ok, decoded possible Q-P chars.  Now normal processing.. */

	    if (column == 0 && c == '.' && (mp->flags & MO_HIDDENDOT)) {
	      if (putc(c,fp)==EOF) return EOF;
	    } else if (column == 0 && (mp->flags & MO_ESCAPEFROM) &&
		       c == 'F' && strncmp(cp+1,"rom",3)==0) {
	      if (putc('>',fp)==EOF) return EOF;
	      ++column;
	    } else if (c == '\n') {
	      if (mp->flags & MO_CRLF)
		if (putc('\r',fp)==EOF) return EOF;
	      column = -1;
	    }
	    /* And output the char.. */
	    if (putc(c,fp)==EOF) return EOF;
	  } else
	    abort(); /* WOO! We should not be called for '_CONVERT_NONE'! */
	}

	if (feof(fp) || ferror(fp)) return EOF;
	return len;
}


struct maildesc *
readsmcf(file, mailer)
	char *file, *mailer;
{
	char *entry, buf[BUFSIZ];
	unsigned char *cp;
	FILE *fp;
	int i;
	static struct maildesc m;

	if (file == NULL) {
	  char *mailshare = getzenv("MAILSHARE");

	  if (mailshare == NULL)
	    mailshare = MAILSHARE;
	  sprintf(buf, "%s/%s.conf", mailshare, progname);
	  file = buf;
	}
	if ((fp = fopen(file, "r")) == NULL) {
	  fprintf(stderr, "%s: cannot open ", progname);
	  perror(file);
	  exit(EX_OSFILE);
	}
	entry = cp = NULL;
	while (fgets(buf, sizeof buf, fp) != NULL) {
	  if (buf[0] == '#' || buf[0] == '\n')
	    continue;
	  if ((cp = emalloc(strlen(buf)+1)) == NULL) {
	    fprintf(stderr, "%s: Out of Virtual Memory!\n",
		    progname);
	    exit(EX_OSERR);
	  }
	  entry = (char*)cp;
	  strcpy(entry, buf);
	  SKIPTEXT(cp);
	  if (isascii(*cp) && isspace(*cp)) {
	    if (*cp == '\n') {
	      fprintf(stderr, "%s: %s: bad entry: %s",
		      progname, file, entry);
	    } else
	      *cp = '\0';
	  } else {
	    fprintf(stderr, "%s: %s: bad entry: %s",
		    progname, file, entry);
	  }
	  if (strcmp(entry, mailer) == 0)
	    break;
	  free(entry);
	  entry = NULL;
	}
	fclose(fp);
	if (entry == NULL)
		return NULL;
	m.name = entry;
	m.flags = MO_UNIXFROM;
	++cp;
	SKIPSPACE(cp);
	/* process mailer option flags */
	for (;*cp && *cp != ' ' && *cp != '\t' && *cp != '\n'; ++cp) {
	  int no = 0;
	  switch (*cp) {
	  case '7':	m.flags |= MO_STRIPHIBIT;	break;
	  case '8':	can_8bit = 1;			break;
	  case '9':	decode_qp = 1;			break;
	  case 'A': no=*cp; break;	/* arpanet-compatibility */
	  case 'b':	m.flags |= (MO_BSMTP|MO_HIDDENDOT); break;
	  case 'B':	if (m.flags & MO_BESMTP) /* -BB */
			    m.flags |= MO_BEDSMTP;
			else
			    m.flags |= MO_BESMTP|MO_BSMTP|MO_HIDDENDOT;
			break;
	  case 'C': no=*cp; break; /* canonicalize remote hostnames */
	  case 'D':		/* this mailer wants a Date: line */
	    	m.flags |= MO_WANTSDATE;	break;
	  case 'e':	m.flags |= MO_XENVELOPES;	break;
	  case 'E':	m.flags |= MO_ESCAPEFROM;	break;
	  case 'f':	m.flags |= MO_FFROMFLAG;	break;
	  case 'F':		/* this mailer wants a From: line */
	    	m.flags |= MO_WANTSFROM;	break;
	  case 'h': no=*cp; break; /* preserve upper case in host names */
	  case 'H':     m.flags |= MO_BSMTPHELO;	break;
	  case 'I': no=*cp; break; /* talking to a clone of I */
	  case 'l': no=*cp; break; /* this is a local mailer */
	  case 'L': no=*cp; break; /* limit line length */
	  case 'm':	m.flags |= MO_MANYUSERS;	break;
	  case 'M': no=*cp; break; /* this mailer wants a Message-Id: line */
	  case 'n':	m.flags &= ~MO_UNIXFROM;	break;
	  case 'p': no=*cp; break; /* use SMTP return path */
	  case 'P':	m.flags |= MO_RETURNPATH;	break;
	  case 'r':	m.flags |= MO_RFROMFLAG;	break;
	  case 'R':	m.flags |= MO_CRLF;		break;
	  case 's':	m.flags |= MO_STRIPQUOTES;	break;
	  case 'S':	m.flags |= MO_NORESETUID;	break;
	  case 'u': no=*cp; break; /* preserve upper case in user names */
	  case 'U':	m.flags |= MO_REMOTEFROM;	break;
	  case 'x': no=*cp; break; /* this mailer wants a Full-Name: line */
	  case 'X':	m.flags |= MO_HIDDENDOT;	break;

	  case '-':	break;	/* ignore */
	  default:
	    fprintf(stderr,
		    "%s: unknown sendmail mailer option '%c'\n",
		    progname, *cp);
	    break;
	  }
	  if (no) {
	    fprintf(stderr,
		    "%s: the '%c' sendmail mailer option does not make sense in this environment\n",
		    progname,no);
	  }
	}
	SKIPSPACE(cp);
	m.command = (char*) cp;
	SKIPTEXT(cp);
	if ((char*)cp == m.command) {
		fprintf(stderr,"%s: bad entry for %s\n",progname, m.name);
		return NULL;
	}
	*cp++ = '\0';
	if (*m.command != '/') {
	  char *nmc, *mailbin = getzenv("MAILBIN");

	  if (mailbin == NULL)
	    mailbin = MAILBIN;
		
	  nmc = emalloc(strlen(mailbin)+1+strlen(m.command)+1);
	  sprintf(nmc, "%s/%s", mailbin, m.command);
	  m.command = nmc;
	}
	SKIPSPACE(cp);
	i = 0;
	while (isascii(*cp) && !isspace(*cp) && i < MD_ARGVMAX) {
	  if (*cp == '\0')
	    break;
	  m.argv[i++] = (char*) cp;
	  SKIPTEXT(cp);
	  if (*cp) {
	    *cp++ = '\0';
	    SKIPSPACE(cp);
	  }
	}
	if (i == 0) {
	  fprintf(stderr,
		  "%s: bad command for %s\n", progname, m.name);
	  return NULL;
	}
	m.argv[i] = NULL;
	return &m;
}

/* When data is clean 7-BIT, return 1.. (zero == non-clean) */
int
check_7bit_cleanness(dp)
struct ctldesc *dp;
{
#if (defined(HAVE_MMAP) && defined(TA_USE_MMAP))
	/* With MMAP()ed spool file it is sweet and simple.. */
	register const char *s = dp->let_buffer + dp->msgbodyoffset;
	while (s < dp->let_end)
	  if (128 & *s) {
    /*
       if (verboselog)
       fprintf(verboselog,
       "check_7bit_cleanness() non-clean byte on offset %d, str=\"%-8s\"\n",
       s-(dp->let_buffer + dp->msgbodyoffset), s);
     */
	    return 0; /* Not clean ! */
	  }
	  else ++s;
	return 1;
#else
	register int i;
	register int bufferfull;
	int lastwasnl;
	int mfd = dp->msgfd;

/* can we use cache of message body data */
	if (readalready != 0) {
	  for (i=0; i<readalready; ++i)
	    if (128 & (let_buffer[i]))
	      return 0;		/* Not clean ! */
	}

	/* we are assumed to be positioned properly at start of message body */
	bufferfull = 0;

	while ((i = read(mfd, let_buffer, sizeof let_buffer)) != 0) {
	  if (i < 0) {
	    /* ERROR ?!?!? */
	    if (errno == EINTR)
	      continue;
	    readalready = 0;
	    lseek(mfd, dp->msgbodyoffset, SEEK_SET);
	    return 0;
	  }
	  lastwasnl = (let_buffer[i-1] == '\n');
	  readalready = i;
	  bufferfull++;
	  for (i=0; i < readalready; ++i)
	    if (128 & (let_buffer[i])) {
	      lseek(mfd, dp->msgbodyoffset, SEEK_SET);
	      /* We probably have not read everything of the file! */
	      readalready = 0;
	      return 0;		/* Not clean ! */
	    }
	}
	/* Got to EOF, and still it is clean 7-BIT! */
	lseek(mfd, dp->msgbodyoffset, SEEK_SET);

	if (bufferfull > 1)	/* not all in memory, need to reread */
	  readalready = 0;

	return 1;
#endif
}
