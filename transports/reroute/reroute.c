/*
 *	"Reroute", copyright Matti Aarnio 2002.
 *
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *
 *	Copyright 1991-2003 by Matti Aarnio.
 */

/*
 * This program is based on 'hold', but the usage semantics are special
 * and hard-coded inside the scheduler system.
 *
 * This implements target recipient manually ordered resending to router.
 *
 * This has unusual parametrization convention, as each input line this
 * program receives can have up to 2 TAB separated fields:
 *  - spoolfilename
 *  - optional host selector
 *
 * The scheduler will supply '-c' option to drive the channel selection.
 *
 * THIS CAN'T REROUTE QUITE EVERYTHING!  Specifically there are
 * problems with e.g. messages already routed into some local pipes,
 * and similar things.   Rerouting smtp like destinations is this
 * facility's primary reason of existence.

 * (Rerouting arrived messages which have some INRCPT=  data
 *  might be doable, but as that data gets passed over the
 *  internal alias expansions, it might not be wise, either..)
 *
 */


#include "mailer.h"

#ifdef linux
#define __USE_BSD 1
#endif
#include <ctype.h>
#include <pwd.h>
#include <sysexits.h>
#include <sys/param.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#include "zmsignal.h"
#include "zmalloc.h"
#include "zsyslog.h"

#include "ta.h"
#include "mail.h"
#include "zmsignal.h"
#include "zsyslog.h"

#include "libz.h"
#include "libc.h"

#include "shmmib.h"


#define	PROGNAME	"reroute"	/* for logging */
#define	CHANNEL		"reroute"	/* the default channel name we look at */

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

FILE *verboselog = NULL;

extern char *optarg;
extern int optind;
extern void process __((struct ctldesc *));
extern int  reroute __((const char *, char **));
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
	MIBMtaEntry->tarert.TaProcCountG -= 1;
}

static void SHM_MIB_diag(rc)
     const int rc;
{
  switch (rc) {
  case EX_OK:
    /* OK */
    MIBMtaEntry->tarert.TaRcptsOk ++;
    break;
  case EX_TEMPFAIL:
  case EX_IOERR:
  case EX_OSERR:
  case EX_CANTCREAT:
  case EX_SOFTWARE:
  case EX_DEFERALL:
    /* DEFER */
    MIBMtaEntry->tarert.TaRcptsRetry ++;
    break;
  case EX_NOPERM:
  case EX_PROTOCOL:
  case EX_USAGE:
  case EX_NOUSER:
  case EX_NOHOST:
  case EX_UNAVAILABLE:
  default:
    /* FAIL */
    MIBMtaEntry->tarert.TaRcptsFail ++;
    break;
  }
}

static char filename[MAXPATHLEN+8000];

int
main(argc, argv)
	int argc;
	char *argv[];
{
	const char *channel, *host;
	int errflg, c, i;
	struct ctldesc *dp;
	int matchhost = 0;
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

	MIBMtaEntry->tarert.TaProcessStarts += 1;
	MIBMtaEntry->tarert.TaProcCountG    += 1;

	atexit(MIBcountCleanup);


	if ((progname = strrchr(argv[0], '/')) == NULL)
	  progname = argv[0];
	else
	  ++progname;
	errflg  = 0;
	channel = CHANNEL;
	host    = NULL;

	while (1) {
	  c = getopt(argc, argv, "c:h:V");
	  if (c == EOF)
	    break;
	  switch (c) {
	  case 'c':		/* specify channel scanned for */
	    channel = optarg;
	    break;
	  case 'h':
	    host = strdup(optarg);
	    matchhost = 1;
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
	  fprintf(stderr, "Usage: %s [-V] [-c channel] [-h host]\n",
		  argv[0]);
	  exit(EX_USAGE);
	}

	/* We need this later on .. */
	zopenlog("reroute", LOG_PID, LOG_MAIL);

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
	    MIBMtaEntry->tarert.TaIdleStates += 1;
	    continue; /* Ah well, we can stay idle.. */
	  }
	  if (emptyline(filename, sizeof(filename)))
	    break;

	  MIBMtaEntry->tarert.TaMessages += 1;

	  s = strchr(filename,'\t');

	  if (s != NULL) {
	    if (host) free((void*)host);
	    host = strdup(s+1);
	    *s = 0;
	  }


	  SETUID(0); /* We begin as roots..  process() may change us */
	  SETEUID(0); /* We begin as roots..  process() may change us */

	  notary_setxdelay(0); /* Our initial speed estimate is
				  overtly optimistic.. */

	  dp = ctlopen(filename, channel, host, &getout, NULL, NULL, NULL, NULL);
	  if (verboselog) {
	    fclose(verboselog);
	    verboselog = NULL;
	  }

	  if (dp != NULL) {

	    if (dp->verbose) {
	      verboselog = fopen(dp->verbose,"a");
	      if (verboselog) {
		/* Buffering, and Close-On-Exec bit! */
		setbuf(verboselog,NULL);
		fcntl(FILENO(verboselog), F_SETFD, 1);
	      }
	    }

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
 * process - resubmit the message
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
	long ino;
	time_t mtime;
	int rcpt_cnt = 0;

	MIBMtaEntry->tarert.TaDeliveryStarts += 1;

	sawok = 0;
	for (rp = dp->recipients; rp != NULL; rp = rp->next) {
	  cp = rp->addr->user;
	  rp->status = EX_OK;
	  rp->addr->user = cp;
	  sawok = 1;

	}

	if (!sawok)
	  return;

	if (lseek(dp->msgfd, (off_t)(dp->msgbodyoffset), SEEK_SET) < 0L)
	  warning("Cannot seek to message body! (%m)", (char *)NULL);

	mfp = mail_open(MSG_RFC822);
	if (mfp == NULL) {
	  for (rp = dp->recipients; rp != NULL; rp = rp->next) {
	    if (rp->status == EX_OK) {
	      notaryreport(rp->addr->user,"delayed",
			   "4.3.1 (System spool full?)",
			   "x-local; 400 (Cannot resubmit anything, out of spool space?)");
	      diagnostic(verboselog, rp, EX_TEMPFAIL, 0,
			 "cannot resubmit anything!");
	      SHM_MIB_diag(EX_TEMPFAIL);
	    }
	  }
	  return;
	}

	fprintf(mfp, "via reroute\n");

	if (STREQ(dp->senders->channel,"error"))
	  fprintf(mfp, "channel error\n");
	else
	  fprintf(mfp, "from <%s>\n", dp->senders->user);

	if (dp->envid != NULL)
	  fprintf(mfp, "envid %s\n", dp->envid);

	if (dp->dsnretmode)
	  fprintf(mfp, "notaryret %s\n", dp->dsnretmode);

	for (rp = dp->recipients; rp != NULL; rp = rp->next) {
	  if (rp->status == EX_OK) {
	    ++rcpt_cnt;
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
	}

	fprintf(mfp,"env-end\n");

	header_received_for_clause(dp->recipients, rcpt_cnt, verboselog);


	fwriteheaders(dp->recipients,mfp,"\n",0,0,NULL);
	fprintf(mfp,"\n");

	/* append message body itself */
	while ((n = read(dp->msgfd, buf, sizeof buf)) > 0)
	  fwrite(buf, sizeof buf[0], n, mfp);

	if (ferror(mfp)) {
	  mail_abort(mfp);
	  code = EX_TEMPFAIL;
	  cp = "write error during resubmission";
	} else if (_mail_close_(mfp, &ino, &mtime) == EOF) {
	  code = EX_TEMPFAIL;
	  cp = "message not resubmitted";
	} else {
	  code = EX_OK;
	  cp = NULL;
	}

	{
	  /* Construct diagnostic report,
	     tell the NEW spoolid for the message */

	  char taspid[30];
	  char msgbuf[100], msgbuf2[100];
	  char msgbuf3[100];
	  taspoolid(taspid, mtime, ino);

	  sprintf(msgbuf,"2.2.0 (Sent into reroute with spoolid: %s )",taspid);
	  sprintf(msgbuf2,"x-local; 250 (Sent into reroute with spoolid: %s )",taspid);
	  sprintf(msgbuf3,"Sent into reroute with spoolid: %s",taspid);
	  if (!cp) cp = msgbuf3;

	  for (rp = dp->recipients; rp != NULL; rp = rp->next) {
	    if (rp->status == EX_OK) {

	      /* Magic upon magic..  We have sent the message into
		 rerouting, thus we shut up about it completely! */
	      rp->notifyflgs = _DSN_NOTIFY_NEVER;

	      notaryreport(rp->addr->user, "relayed",  msgbuf, msgbuf2);
	      diagnostic(verboselog, rp, code, 0, cp);
	      SHM_MIB_diag(code);
	    }
	  }
	}
}
