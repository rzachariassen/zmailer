/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *	Copyright 1992-2003 Matti Aarnio -- MIME processing et.al.
 */

#include "mailer.h"

#ifdef linux
#define __USE_BSD 1
#endif
#include <ctype.h>
#include <pwd.h>
#include <sysexits.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <errno.h>

#include "zmsignal.h"
#include "zmalloc.h"
#include "zsyslog.h"

#include "ta.h"
#include "libz.h"
#include "libc.h"

#include "shmmib.h"

#ifdef	HAVE_RESOLVER
#include "netdb.h"
#include <sys/socket.h>
#include <netinet/in.h>
#endif
#include "dnsgetrr.h"

#if	defined(TRY_AGAIN) && defined(HAVE_RESOLVER)
#define	BIND		/* Want BIND (named) nameserver support enabled */
#endif	/* TRY_AGAIN */
#ifdef	BIND
#undef NOERROR /* Solaris  <sys/socket.h>  has  NOERROR too.. */
#include <arpa/nameser.h>
#include <resolv.h>

#ifndef	BIND_VER
#ifdef	GETLONG
/* 4.7.3 introduced the {GET,PUT}{LONG,SHORT} macros in nameser.h */
#define	BIND_VER	473
#else	/* !GETLONG */
#define	BIND_VER	472
#endif	/* GETLONG */
#endif	/* !BIND_VER */
#endif	/* BIND */

#if	defined(BIND_VER) && (BIND_VER >= 473)
typedef u_char msgdata;
#else	/* !defined(BIND_VER) || (BIND_VER < 473) */
typedef char msgdata;
#endif	/* defined(BIND_VER) && (BIND_VER >= 473) */


/* Define all those things which exist on newer BINDs, and which may
   get returned to us, when we make a query with  T_ANY ... */

#ifndef	T_TXT
# define T_TXT 16
#endif
#ifndef T_RP
# define T_RP 17
#endif
#ifndef T_AFSDB
# define T_AFSDB 18
#endif
#ifndef T_NSAP
# define T_NSAP 22
#endif
#ifndef T_AAAA
# define T_AAAA 28	/* IPv6 Address */
#endif
#ifndef T_NSAP_PTR
# define T_NSAP_PTR 23
#endif
#ifndef	T_UINFO
# define T_UINFO 100
#endif
#ifndef T_UID
# define T_UID 101
#endif
#ifndef T_GID
# define T_GID 102
#endif
#ifndef T_UNSPEC
# define T_UNSPEC 103
#endif
#ifndef T_SA
# define T_SA 200
#endif


#include "mail.h"
#include "splay.h"

#if HAVE_SYS_WAIT_H /* POSIX-thing ?  If not, declare it so.. */
# include <sys/wait.h>
#endif
#ifndef WEXITSTATUS
# define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
# define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif

#ifndef	SEEK_SET
#define	SEEK_SET 0
#endif	/* SEEK_SET */

#define	PROGNAME	"hold"	/* for logging */
#define	CHANNEL		"hold"	/* the default channel name we look at */

char errormsg[BUFSIZ];
const char *progname;
char *cmdline, *eocmdline;
int pid;

#ifdef MALLOC_TRACE
#define	MEM_MALLOC 1000
int	stickymem = MEM_MALLOC;	/* for strnsave() */
struct conshell *envarlist = NULL;
#endif
int	D_alloc = 0;

extern char *optarg;
extern int optind;
extern void process __((struct ctldesc *));
extern int  hold __((const char *, char **));
extern char **environ;

#ifndef strchr
extern char *strchr(), *strrchr();
#endif

#ifdef	lint
#undef	putc
#define	putc	fputc
#endif	/* lint */



static void MIBcountCleanup __((void))
{
	MIBMtaEntry->tahold.TaProcCountG -= 1;
	if (MIBMtaEntry->tahold.TaProcCountG > 99999U)
	  MIBMtaEntry->tahold.TaProcCountG = 0;
}

static void SHM_MIB_diag(rc)
     const int rc;
{
  switch (rc) {
  case EX_OK:
    /* OK */
    MIBMtaEntry->tahold.TaRcptsOk ++;
    break;
  case EX_TEMPFAIL:
  case EX_IOERR:
  case EX_OSERR:
  case EX_CANTCREAT:
  case EX_SOFTWARE:
  case EX_DEFERALL:
    /* DEFER */
    MIBMtaEntry->tahold.TaRcptsRetry ++;
    break;
  case EX_NOPERM:
  case EX_PROTOCOL:
  case EX_USAGE:
  case EX_NOUSER:
  case EX_NOHOST:
  case EX_UNAVAILABLE:
  default:
    /* FAIL */
    MIBMtaEntry->tahold.TaRcptsFail ++;
    break;
  }
}


FILE *verboselog = NULL;

static char filename[MAXPATHLEN+8000];

int
main(argc, argv)
	int argc;
	char *argv[];
{
	const char *channel, *host;
	int errflg, c, i;
	struct ctldesc *dp;
	RETSIGTYPE (*oldsig) __((int));

	pid = getpid();
	cmdline = &argv[0][0];
	eocmdline = cmdline;
	for (i = 0; i < argc; ++i)
	  eocmdline += strlen(argv[i]) + 1;

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

	if (getenv("ZCONFIG")) readzenv(getenv("ZCONFIG"));


	Z_SHM_MIB_Attach(1); /* we don't care if it succeeds or fails.. */

	MIBMtaEntry->tahold.TaProcessStarts += 1;
	MIBMtaEntry->tahold.TaProcCountG    += 1;

	atexit(MIBcountCleanup);


	if ((progname = strrchr(argv[0], '/')) == NULL)
	  progname = argv[0];
	else
	  ++progname;
	errflg = 0;
	channel = CHANNEL;
	while (1) {
	  c = getopt(argc, argv, "c:V");
	  if (c == EOF)
	    break;
	  switch (c) {
	  case 'c':		/* specify channel scanned for */
	    channel = optarg;
	    break;
	  case 'V':
	    prversion(PROGNAME);
	    exit(EX_OK);
	    break;
	  default:
	    ++errflg;
	    break;
	  }
	}
	if (errflg || optind != argc) {
	  fprintf(stderr, "Usage: %s [-V] [-c channel]\n",
		  argv[0]);
	  exit(EX_USAGE);
	}

	/* We need this later on .. */
	zopenlog("hold", LOG_PID, LOG_MAIL);

	while (!getout) {
	  char *s;
	  /* Input:
	       spool/file/name [ \t host.info ] \n
	   */

	  printf("#hungry\n");
	  fflush(stdout);
	  if (fgets(filename, sizeof(filename), stdin) == NULL)
	    break;
	  if (strchr(filename, '\n') == NULL) break; /* No ending '\n' !  Must
						    have been partial input! */
	  if (strcmp(filename, "#idle\n") == 0) {
	    MIBMtaEntry->tahold.TaIdleStates += 1;
	    continue; /* Ah well, we can stay idle.. */
	  }
	  if (emptyline(filename, sizeof(filename)))
	    break;

	  MIBMtaEntry->tahold.TaMessages += 1;


	  s = strchr(filename,'\t');
	  host = NULL;
	  if (s != NULL) {
	    /* Ignore the host part */
	    *s++ = 0;
	    host = s;
	  }

	  dp = ctlopen(filename, channel, host, &getout, NULL, NULL);
	  if (dp != NULL) {
	    process(dp);
	    ctlclose(dp);
	  } else {
	    printf("#resync %s\n",filename);
	    fflush(stdout);
	  }
	}
	exit(0);
	/* NOTREACHED */
	return 0;
}

/*
 * process - resubmit the message if the hold condition has disappeared.
 */

void
process(dp)
	struct ctldesc *dp;
{
	FILE *mfp;
	int n, sawok, code;
	struct rcpt *rp;
	const char *cp;
	char buf[BUFSIZ];

	MIBMtaEntry->tahold.TaDeliveryStarts += 1;

	sawok = 0;
	for (rp = dp->recipients; rp != NULL; rp = rp->next) {
	  cp = rp->addr->user;
	  rp->status = hold(rp->addr->host, (char**)&(rp->addr->user));
	  if (rp->status == EX_OK) {
	    rp->addr->user = cp;
	    sawok = 1;
	  } else {
	    const char *action = NULL;
	    const char *status = NULL;
	    const char *diagnostics = NULL;
	    switch (rp->status) {
	    case EX_PROTOCOL:
	    case EX_SOFTWARE:
	      action = "failed";
	      status = "5.0.0 (ZMailer internal protocol error)";
	      diagnostics = "x-local; 500 (Protocol failure inside ZMAILER! AARGH!)";
	      break;
	    case EX_TEMPFAIL:
	      action = "delayed";
	      status = "4.4.3 (Temporary routing lookup failure)";
	      diagnostics = "x-local; 466 (Temporary routing lookup failure)";
	      break;
	    default:
	      action = "failed";
	      status = "4.4.0 (Unknown ZMailer HOLD status ** CAN'T HAPPEN)";
	      diagnostics = "x-local; 500 (Unknown HOLD return code **CAN'T HAPPEN**)";
	      break;
	    }
	    notaryreport(rp->addr->user,action,status,diagnostics);
	    diagnostic(verboselog, rp, rp->status, 0, "%s", rp->addr->user);
	    SHM_MIB_diag(rp->status);
	  }
	}

	if (!sawok)
	  return;

	if (lseek(dp->msgfd, (off_t)(dp->msgbodyoffset), SEEK_SET) < 0L)
	  warning("Cannot seek to message body! (%m)", (char *)NULL);

	SETEUID(atoi(dp->senders->misc));

	mfp = mail_open(MSG_RFC822);
	if (mfp == NULL) {
	  for (rp = dp->recipients; rp != NULL; rp = rp->next)
	    if (rp->status == EX_OK) {
	      notaryreport(rp->addr->user,"delayed",
			   "4.3.1 (System spool full?)",
			   "x-local; 400 (Cannot resubmit anything, out of spool space?)");
	      diagnostic(verboselog, rp, EX_TEMPFAIL, 0,
			 "cannot resubmit anything!");
	      SHM_MIB_diag(EX_TEMPFAIL);
	    }
	  SETEUID(getuid());
	  return;
	}
	SETEUID(getuid());

	fprintf(mfp, "via suspension\n");
	if (STREQ(dp->senders->channel,"error"))
	  fprintf(mfp, "channel error\n");
	else
	  fprintf(mfp, "from <%s>\n", dp->senders->user);
	if (dp->envid != NULL)
	  fprintf(mfp, "envid %s\n", dp->envid);
	if (dp->dsnretmode)
	  fprintf(mfp, "notaryret %s\n", dp->dsnretmode);

	for (rp = dp->recipients; rp != NULL; rp = rp->next)
	  if (rp->status == EX_OK) {
	    if ( rp->notify || rp->orcpt  ||
		 rp->inrcpt || rp->infrom ||
		 rp->deliverby                 ) {
	      
	      fputs("todsn",mfp);
	      if (rp->orcpt != NULL)
		fprintf(mfp," ORCPT=%s",rp->orcpt);

	      if (rp->inrcpt != NULL)
		fprintf(mfp," INRCPT=%s",rp->inrcpt);

	      if (rp->infrom != NULL)
		fprintf(mfp," INFROM=%s",rp->infrom);

	      if (rp->ezmlm != NULL)
		fprintf(mfp," EZMLM=%s",rp->ezmlm);

	      if (rp->notify)
		fprintf(mfp," NOTIFY=%s", rp->notify);

	      if (rp->deliverby) {
		fprintf(mfp," BY=%ld;", (long)rp->deliverby);
		if (rp->deliverbyflgs & _DELIVERBY_R) fputc('R',mfp);
		if (rp->deliverbyflgs & _DELIVERBY_N) fputc('N',mfp);
		if (rp->deliverbyflgs & _DELIVERBY_T) fputc('T',mfp);
	      }

	      putc('\n',mfp);
	    }
	    fprintf(mfp, "to <%s>\n", rp->addr->user);
	  }
	fprintf(mfp,"env-end\n");

	fwriteheaders(dp->recipients,mfp,"\n",0,0,NULL);
	fprintf(mfp,"\n");

	/* append message body itself */
	while ((n = read(dp->msgfd, buf, sizeof buf)) > 0)
	  fwrite(buf, sizeof buf[0], n, mfp);

	if (ferror(mfp)) {
	  mail_abort(mfp);
	  code = EX_TEMPFAIL;
	  cp = "write error during resubmission";
	} else if (mail_close(mfp) == EOF) {
	  code = EX_TEMPFAIL;
	  cp = "message not resubmitted";
	} else {
	  code = EX_OK;
	  cp = NULL;
	}

	for (rp = dp->recipients; rp != NULL; rp = rp->next)
	  if (rp->status == EX_OK) {
	    notaryreport(rp->addr->user,"relayed",
			 "2.2.0 (Relayed via deferral channel)",
			 "x-local; 250 (Relayed via deferral channel)");
	    diagnostic(verboselog, rp, code, 0, cp);
	    SHM_MIB_diag(code);
	  }
}


/*
 * The hostname for the hold channel describes a wait condition that can
 * be tested (here) before the message can be resubmitted.  The condition
 * string is canonicalized and parsed hierarchically.
 */

extern int hold_ns	__(( const char* ));
extern int hold_timeout	__(( const char* ));
extern int hold_io	__(( const char* ));
extern int hold_script	__(( const char* ));
extern int hold_home	__(( const char* ));

struct holds_info {
	const char	*type;
	int	(*f) __(( const char * ));
} holds[] = {
	{	"ns",		hold_ns		},
	{	"timeout",	hold_timeout	},
	{	"io",		hold_io		},
	{	"script",	hold_script	},
	{	"home",		hold_home	},
	{	NULL,		NULL		},
};


int
hold(s, errmsgp)
	const char *s;
	char **errmsgp;
{
	char *cp, *colon;
	struct holds_info *hip;
	static struct sptree *spt_hash = NULL;
	struct spblk *spl;
	int v;
	spkey_t symid;

	colon = NULL;
	for (cp = (char*)s; *cp != '\0'; ++cp) {
	  unsigned char c = *cp;
	  if (isascii(c) && isupper(c))
	    *cp = tolower(c);
	  else if (c == ':')
	    colon = cp;
	}

	if (colon == NULL)
	  return EX_PROTOCOL;	/* invalid hold condition */

	symid = symbol((void*)s);
	if (spt_hash == NULL)
	  spt_hash = sp_init();
	if ((spl = sp_lookup(symid, spt_hash)) != NULL) {
	  *errmsgp = (char *)spl->data;
	  return spl->mark;
	}

	*colon++ = '\0';
	for (hip = &holds[0]; hip->type != NULL ; ++hip)
	  if (strcmp(s, hip->type) == 0)
	    break;
	if (hip->type == NULL)
	  return EX_SOFTWARE;	/* unsupported hold condition */

	errormsg[0] = '\0';

	if ((hip->f)(colon))
	  v = EX_OK;		/* resubmit the message address */
	else
	  v = EX_TEMPFAIL;	/* defer resubmission */

	if (errormsg[0] != '\0') {
	  cp = emalloc((u_int)strlen(errormsg)+1);
	  strcpy(cp, errormsg);
	} else
	  cp = "deferred";
	sp_install(symid, (const void *)cp, v, spt_hash);
	*errmsgp = cp;

	return v;
}

/* return true if the nameserver lookup of (name,type) succeeds */

#ifdef	BIND
extern int	h_errno;

struct qtypes {
	const char	*typename;
	int		 value;
} qt[] = {
	{	"cname",	T_CNAME		},
	{	"mx",		T_MX		},
	{	"a",		T_A		},
	{	"aaaa",		T_AAAA		},
#ifdef  T_ANY
	{	"any",		T_ANY		},
#endif
#ifdef	T_MP
	{	"mp",		T_MP		},
#endif	/* T_MP */
#ifdef	T_UNAME
	{	"uname",	T_UNAME		},
#endif	/* T_UNAME */
#ifdef	T_TXT
	{	"txt",		T_TXT		},
#endif	/* T_TXT */
	{	"wks",		T_WKS		},
	{	"ptr",		T_PTR		},
	{	NULL,		0		}
};

int
hold_ns(s)
	const char *s;
{
	struct qtypes *qtp;
	char *cp, host[1024]; /* 256 should be enough .. */
	int ttl;

	res_init();

	if ((cp = strrchr(s, '/')) == NULL)
	  return 1;	/* human error, lets be nice */
	if (cp > s && *(cp-1) == '.')
	  *(cp-1) = '\0';
	else
	  *cp = '\0';
	++cp;

	for (qtp = &qt[0]; qtp->typename != NULL ; ++qtp) {
	  if (strcmp(qtp->typename, cp) == 0)
	    break;
	}
	if (qtp->typename == NULL) {
	  fprintf(stderr, "%s: unknown nameserver type '%s'\n",
		  progname, cp);
	  return 1;		/* inconsistency with search_res.c, yell! */
	}
	strncpy(host, s, sizeof(host));
	host[sizeof(host)-1] = 0;
	switch (getrrtype(host, &ttl, sizeof host, qtp->value, 2, NULL)) {
	case 0:
		return 1;	/* negative reply */
	case 1:
		return 1;	/* positive reply */
	case -1:
	case -2:
	case -3:
		return 0;	/* no reply */
	}
	return 0;
}
#else	/* !BIND */

struct qtypes {
	char	*typename;
	u_short	value;
} qt[] = {
	{	"cname",	1		},
	{	"a",		1		},
	{	"aaaa",		1		},
	{	"ptr",		2		},
	{	NULL,		NULL		}
};

int
hold_ns(s)
	char *s;
{
	struct qtypes *qtp;
	char *cp, host[BUFSIZ];
	struct hostent *hp;
	struct in_addr ia;

	if ((cp = strrchr(s, '/')) == NULL)
	  return 1;	/* human error, lets be nice */
	if (cp > s && *(cp-1) == '.')
	  *(cp-1) = '\0';
	else
	  *cp = '\0';
	++cp;

	for (qtp = &qt[0]; qtp->typename != NULL ; ++qtp) {
	  if (strcmp(qtp->typename, cp) == 0)
	    break;
	}
	if (qtp->typename == NULL) {
	  fprintf(stderr, "%s: unknown hosts file lookup '%s'\n",
		  progname, cp);
	  return 1;		/* inconsistency with search_res.c, yell! */
	}
	strcpy(host, s);
	hp = NULL;
	switch (qtp->value) {
	case 1:
	  /* XXX: getaddrinfo() */
	  hp = gethostbyname(host);
	  break;
	case 2:
/* XXX: use  inet_pton() here ?! */
	  ia.s_addr = inet_addr(host);
	  hp = gethostbyaddr(&ia, sizeof ia.s_addr, AF_INET);
	  break;
	}
	return hp != NULL;
}
#endif	/* !BIND */

/* return true if the seconds-since-epoch in argument has passed */

int
hold_timeout(s)
	const char *s;
{
	time_t now, then;

	time(&now);
	then = (time_t)atol(s);
	return now >= then;
}

/* return true if we should retry the I/O operation causing the error */

int
hold_io(s)
	const char *s;
{
	return ranny(9) == 0;	/* 10% of the time */
}

/* based on tuple "hold" "script:command/$user" "$address"
   return exit status of "$MAILBIN/bin/command $user" command */

int
hold_script(command)
	const char *command;
{
	int i, in[2];
	const char *env[20], *s;
	char buf[8192], *cp, *arg;
	FILE *errfp;
	int status;

	arg = strchr(command, '/');
	if (arg != NULL)
	  *arg++ = '\0';
	else
	  arg = NULL;
	i = 0;
	env[i++] = "SHELL=/bin/sh";
	cp = buf;
	s = getzenv("PATH");
	if (s == NULL)
	  env[i++] = "PATH=/usr/ucb:/usr/bin:/bin";
	else {
	  sprintf(cp, "PATH=%s", s);
	  env[i++] = cp;
	  cp += strlen(cp) + 1;
	}
	env[i++] = "HOME=/tmp";
	env[i++] = "USER=anonymous";
	s = getzenv("ZCONFIG");
	if (s == NULL)
	  s = ZMAILER_ENV_FILE;
	sprintf(cp, "ZCONFIG=%s", s);
	env[i++] = cp;
	s = getzenv("MAILSHARE");
	if (s == NULL)
	  s = MAILBIN;
	cp += strlen(cp) + 1;
	sprintf(cp, "MAILSHARE=%s", s);
	env[i++] = cp;
	s = getzenv("MAILBIN");
	if (s == NULL)
	  s = MAILSHARE;
	cp += strlen(cp) + 1;
	sprintf(cp, "MAILBIN=%s", s);
	env[i++] = cp;
	env[i] = NULL;

	/* now we can fork off and run the command... */
	if (pipe(in) < 0) {
	  sprintf(errormsg,
		  "cannot create pipe from \"%s\"", command);
	  return 0;
	}
	cp += strlen(cp) + 1;
	sprintf(cp, "%s/bin/%s", s, command);

	if ((pid = fork()) == 0) { /* child */
	  environ = (char**) env;
	  dup2(in[1],1);
	  dup2(in[1],2);
	  close(0);
	  if (in[0] != 1 && in[0] != 2)
	    close(in[0]);
	  if (in[1] != 1 && in[1] != 2)
	    close(in[1]);
	  SIGNAL_IGNORE(SIGINT);
	  SIGNAL_IGNORE(SIGHUP);
	  SIGNAL_HANDLE(SIGTERM, SIG_DFL);
	  /*
	   * Note that argv[0] is set to the command we are running.
	   * That way, we should get some better error messages, at
	   * least more understandable in rejection messages.
	   * Some bourne shells may go into restricted mode if the
	   * stuff to run contains an 'r'. XX: investigate.
	   */
	  execl("/bin/sh", "sh", cp, arg, (char *)NULL);
	  execl("/sbin/sh", "sh", cp, arg, (char *)NULL);
	  write(2, "Cannot exec /bin/sh\n", 20);
	  _exit(128);
	} else if (pid < 0) {	/* fork failed */
	  sprintf(errormsg, "cannot fork");
	  return 0;
	} /* parent */
	close(in[1]);
	errfp = fdopen(in[0], "r");
	/* read any messages from its stdout/err on in[0] */
	cp = errormsg;
	if (fgets(errormsg, sizeof errormsg, errfp) == NULL)
		errormsg[0] = '\0';
	else if ((cp = strchr(errormsg, '\n')) != NULL)
		*cp = '\0';
	wait(&status);
	fclose(errfp);
	close(in[0]);

        if (status & 0177) { /* any signals ? */
	  if (cp != errormsg)
	    *cp++ = ' ';
	  sprintf(cp, "[signal %d", status & 0177);
	  if (status & 0200)
	    strcat(cp, " (Core dumped)");
	  strcat(cp, "]");
	  return 0;
        } else if (WEXITSTATUS(status) != 0) {
	  if (cp != errormsg)
	    *cp++ = ' ';
	  sprintf(cp, "[exit status %d]", WEXITSTATUS(status));
	  return 0;
        }
	return 1;
}


/* The transient condition is the user's home directory is not available.
   So if the user doesn't exist any more, or if his home directory is
   null, then we "succeed", to try to redeliver the mail. */

int
hold_home(user)
const char *user;
{
	struct Zpasswd *pw;
	struct stat st;

	pw = zgetpwnam(user);
	if (!pw)
	  pw = zgetpwnam(user);
	if (!pw) {
	  if (errno == 0)      return 1;
	  return ranny(2) == 0;	/* 30% of the time */
	}
	if (pw->pw_dir == NULL || pw->pw_dir[0] == '\0') return 1;
	if (stat(pw->pw_dir, &st) == 0 &&
	    S_ISDIR(st.st_mode)) return 1;
	return 0;
}
