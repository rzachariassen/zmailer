/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */
/*
 *	A lot of changes all around over the years by Matti Aarnio
 *	<mea@nic.funet.fi>, copyright 1992-2003
 */

/*
 * Common routine to produce a diagnostic message for the scheduler to read
 */

#include "hostenv.h"
#include <stdio.h>
#include <sysexits.h>
#ifdef HAVE_STDARG_H
# include <stdarg.h>
#else
# include <varargs.h>
#endif
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#include "ta.h"

#include "mail.h"
#include "zmalloc.h"
#include "libz.h"
#include "libc.h"

/*

   If WE log the diagnostic status information into the transport
   specification file, the protocol changes a bit...  We don't
   report quite THAT much to the scheduler then, just that things happen,
   and that we did log it...

   This way the errors reported by the TAs will get logged properly,
   and the scheduler has a bit less to do, and no need to fuss with
   all that logging...

   This integer controls wether we log things ourselves, or (when zero)
   we let the scheduler do it all -- like in original system.

 */

int ta_logs_diagnostics = 1;

/*

  If we encounter malloc failure, we diagnose everything grimly as
  EX_TEMPFAIL - always.. and hope the TA caller understands to exit..
  
*/
int zmalloc_failure; /* For 0/NULL values: let BSS handle it */

static char *notarybuf;
time_t retryat_time; /* Used at SMTP to avoid trying same host too soon.. */

const char *
notaryacct(rc,okstr)
int rc;
const char *okstr;
{
	static char msgbuf[20];
	switch (rc) {
	  case EX_OK:
	      return okstr; /* "delivered" or "relayed" ..  Depends.. */
	  case EX_TEMPFAIL:
	  case EX_IOERR:
	  case EX_OSERR:
	  case EX_CANTCREAT:
	  case EX_SOFTWARE:
	      return "delayed";
	  case EX_NOUSER:
	  case EX_NOHOST:
	  case EX_UNAVAILABLE:
	      return "failed";
	  case EX_NOPERM:
	  case EX_PROTOCOL:
	  case EX_USAGE:
	  default:
	      sprintf(msgbuf,"*SW-ERROR*not-act-rc=%d*",rc);
	      return msgbuf;
	}
}

static char *wtthost; /* NOTARY wtthost: 'While-Talking-To -host' */
static char *wttip;
static char *wtttaid;
       int   wtttaidpid = -1;
CONVERTMODE wttcvtmode = _CONVERT_UNKNOWN;

void notary_setwtt(host)
const char *host;
{
	if (wtthost) free(wtthost);
	if (host)
	  wtthost = strdup(host);
	else
	  wtthost = NULL;
}

void notary_settaid(progname,pid)
const char *progname;
int pid;
{
	if (wtttaid) free(wtttaid);
	if (progname)
	  wtttaid = strdup(progname);
	else
	  wtttaid = NULL;
	wtttaidpid = pid;
}

void notary_setcvtmode(mode)
CONVERTMODE mode;
{
	wttcvtmode = mode;
}

void notary_setwttip(ip)
const char *ip;
{
	if (wttip) free(wttip);
	if (ip)
	  wttip = strdup(ip);
	else
	  wttip = NULL;
}

static int xdelay;
void notary_setxdelay(xdly)
int xdly;
{
	xdelay = xdly;
}

void
notaryreport(arg1,arg2,arg3,arg4)
     const char *arg1, *arg2, *arg3, *arg4;
{
	int len;
	static char *A1, *A2, *A3, *A4;

	if (arg1) {
	  if (A1) free(A1);
	  A1 = strdup(arg1);
	}
	if (arg2) {
	  if (A2) free(A2);
	  A2 = strdup(arg2);
	}
	if (arg3) {
	  if (A3) free(A3);
	  A3 = strdup(arg3);
	}
	if (arg4) {
	  if (A4) free(A4);
	  A4 = strdup(arg4);
	}

	len = 5; /* "\001\001\001\001" */
	if (A1) len += strlen(A1);
	if (A2) len += strlen(A2);
	if (A3) len += strlen(A3);
	if (A4) len += strlen(A4);
	if (wtthost) len += strlen(wtthost);
	if (wttip)   len += strlen(wttip)+5;
	if (wtttaid) len += strlen(wtttaid)+9;

	notarybuf = (char*) realloc(notarybuf,len);

	if (! notarybuf) {
	  zmalloc_failure = 1;
	  return;
	}

	sprintf(notarybuf, "%s\001%s\001%s\001%s\001%s",
		A1?A1:"", A2?A2:"", A3?A3:"", A4?A4:"",
		wtthost?wtthost:"");
	if (wttip) {
	  sprintf(notarybuf + strlen(notarybuf), " (%s)", wttip);
	}
	if (wtttaid) {
	  sprintf(notarybuf + strlen(notarybuf), "\001%s[%d]",
		  wtttaid, wtttaidpid);
	}
}


#ifdef HAVE_STDARG_H
#ifdef __STDC__
void
diagnostic(FILE *verboselog, struct rcpt *rp, int rc, int timeout, const char *fmt, ...)
#else /* Not ANSI-C */
void
diagnostic(verboselog, rp, rc, timeout, fmt) /* (rp, rc, timeout, "fmtstr", remotemsg) */
	FILE *verboselog;
	struct rcpt *rp;
	int rc, timeout;
	const char *fmt;
#endif
#else
/*VARARGS*/
void
diagnostic(verboselog, rp, rc, timeout, fmt, va_alist) /* (verboselog, rp, rc, timeout, "fmtstr", remotemsg) */
	FILE *verboselog;
	struct rcpt *rp;
	int rc, timeout;
	const char *fmt;
	va_dcl
#endif
{
	char	message[8192];
	char	statmsgbuf[32+16];
	const char * statmsg;
	const char * syslogmsg = NULL;
	char	mark;
	register char *s, *es, *s2;
	va_list	ap;
	int report_notary = 1;
	int logreport = 0;
	int no_notary = 0;
	int lockoffset = rp->lockoffset;


	/* Nothing to do ?? */
	if (lockoffset == 0 && !verboselog) return;

	/* Ok, we either release the lock, and do diagnostics,
	   or we do verbose logging... or both. */

	rp->status = rc;

#ifdef HAVE_STDARG_H
	va_start(ap,fmt);
#else
	va_start(ap);
#endif
	es = &message[sizeof message - 30];
	*message = 0;
	for (s = message; fmt != NULL && *fmt != '\0'; ++fmt) {
		if (s >= es)
			break;
		if (*fmt != '%') {
			*s++ = *fmt;
			continue;
		}
		switch (*++fmt) {
		case 's':	/* string */
			s2 = va_arg(ap, char *);
			for ( ; *s2 != 0; ++s2) {
				*s++ = *s2;
				if (s >= es)
					break;
			}
			break;
		case 'd':	/* integer */
			if (s >= es - 10)
				break;
			sprintf(s, "%d", va_arg(ap, int));
			while (*s != '\0') ++s;
			break;
		case '%':	/* percent */
			*s++ = '%';
			break;
		case '\0':
			--fmt;	/* exit asap! */
			break;
		}
	}
	*s = '\0';
	va_end(ap);

	/* If we had ZMALLOC_FAILURE -> ABORT!  */
	if (zmalloc_failure && !(rp->notifyflgs & _DSN__DIAGDELAYMODE)) {

	  if (!rp->lockoffset) return; /* Don't re-report... */

	  fprintf(stdout,"%d/%d\t%s\t%s %s\n",
		  rp->desc->ctlid, rp->id,
		  (notarybuf && report_notary) ? notarybuf : "",
		  
		  "deferred", "MALLOC FAILURE!");
	  fflush(stdout);

	  if (!lockaddr(rp->desc->ctlfd, rp->desc->ctlmap,
			rp->lockoffset, _CFTAG_LOCK, _CFTAG_DEFER,
			(char*)rp->desc->msgfile, rp->addr->host, getpid())) {
	    /* something went wrong in unlocking it, concurrency problem? */
	  }
	  rp->lockoffset = 0;	/* mark this recipient unlocked */

	  tasyslog(rp, xdelay, wtthost, wttip, "deferred", "MALLOC FAILURE!");

	  return;
	}


	retryat_time = 0;

	/* Optimize the common case -- less stuff into back-report
	   pipe per message.. */
	if (rp->status == EX_OK &&
	    !(rp->notifyflgs & _DSN_NOTIFY_SUCCESS))
	   report_notary = 0;

	switch (rp->status) {
	case EX_OK:
		if (ta_logs_diagnostics) {
		  if (!(rp->notifyflgs & _DSN_NOTIFY_SUCCESS))
		    statmsg = "ok3";
		  else
		    statmsg = "ok2";
		} else
		  statmsg = "ok";
		mark = _CFTAG_OK;
		logreport = ta_logs_diagnostics && report_notary;
		break;
	case EX_TEMPFAIL:
	case EX_IOERR:
	case EX_OSERR:
	case EX_CANTCREAT:
	case EX_SOFTWARE:
		if (timeout > 0) {
		  sprintf(statmsgbuf,"retryat +%d",timeout);
		  statmsg = statmsgbuf;
		  time(&retryat_time);
		  retryat_time += timeout;
		}
		else
		  statmsg = "deferred";
		mark = _CFTAG_DEFER;
		break;
	case EX_DEFERALL:
		statmsg = "deferall";
		mark = _CFTAG_DEFER;
		break;
	case EX_NOPERM:
	case EX_PROTOCOL:
	case EX_USAGE:
		strcat(message,
		       " (this is abnormal, investigate!)");
		s += strlen(s);
		/* fall through */
	case EX_NOUSER:
	case EX_NOHOST:
	case EX_UNAVAILABLE:
		if (ta_logs_diagnostics)
		  statmsg = "error2";
		else
		  statmsg = "error";
		mark = _CFTAG_NOTOK;
		logreport = ta_logs_diagnostics;
		break;
	default:
		sprintf(statmsgbuf,"error Unknown sysexits error code %d!",
			rp->status);
		statmsg = statmsgbuf;
		mark = _CFTAG_NOTOK;
		break;
	}

	/* If there are newlines in them for some weird reason... */
	s = notarybuf; while (s && (s = strchr(s,'\n'))) *s = '\r';
	s = message;   while (s && (s = strchr(s,'\n'))) *s = '\r';

	if (logreport && rp->lockoffset) {
	  /* Right, we have a honour to append our diagnostics to the
	     transport specification file ourselves */
	  int oldfl = fcntl(rp->desc->ctlfd, F_GETFL);
	  int newfl;
	  int len = 80 + strlen(notarybuf ? notarybuf : "") + strlen(message);
	  int rc2;
	  off_t ctlsize;
	  long oldalarm;
	  char *sbuf;

	  /* Set the APPEND-mode on.. We need it now !
	     (and make sure the non-blocking mode is NOT on!) */
	  newfl = (oldfl & ~O_NONBLOCK) | O_APPEND;
	  if (oldfl != newfl)
	    fcntl(rp->desc->ctlfd, F_SETFL, newfl);

#ifdef HAVE_ALLOCA
	  sbuf = alloca(len);
#else
	  sbuf = malloc(len);
	  if (!sbuf)
	    zmalloc_failure = 1;
#endif

	  if (sbuf) {
	    /* Log the diagnostic string to the file */
	    int oldflg;
#ifndef SPRINTF_CHAR
	    len = 
#endif
	      sprintf(sbuf, "%c%c%d:%d:%d::%ld\t%s\t%s\n",
		      _CF_DIAGNOSTIC, _CFTAG_NORMAL,
		      rp->id, rp->headeroffset, rp->drptoffset,
		      (long)time(NULL), notarybuf ? notarybuf : "", message);
#ifdef SPRINTF_CHAR
	    len = strlen(sbuf);
#endif

	    oldalarm = alarm(0);	/* We do NOT want to be alarmed while
					   writing to the log! */

	    ctlsize = lseek(rp->desc->ctlfd, 0, SEEK_END);
	    oldflg = fcntl(rp->desc->ctlfd, F_GETFL, 0);
	    fcntl(rp->desc->ctlfd, F_SETFL, oldflg | O_APPEND);

	    rc2 = write(rp->desc->ctlfd, sbuf, len);

	    fcntl(rp->desc->ctlfd, F_SETFL, oldflg);


	    if (rc2 != len || rc2 < 0 || len < 0) {
	      /* UAARGH! -- write failed, must have disk full! */
#ifdef HAVE_FTRUNCATE
	      while (ftruncate(rp->desc->ctlfd, ctlsize) < 0) /* Sigh.. */
		if (errno != EINTR && errno != EAGAIN)
		  break;
#endif /* HAVE_FTRUNCATE */
	      fprintf(stdout,"#HELP! diagnostic writeout with bad results!: len=%d, rc=%d\n", len, rc2);
	      fflush(stdout);
	      exit(EX_DATAERR);
	    }
#ifdef HAVE_FSYNC
	    while (fsync(rp->desc->ctlfd) < 0) {
	      if (errno == EINTR || errno == EAGAIN)
		continue;
	      break;
	    }
#endif
	    if (oldalarm)		/* Restore it, if it was ticking. */
	      alarm(oldalarm);

#ifndef HAVE_ALLOCA
	    free(sbuf);
#endif
	  }

	  /* If we had to set the APPEND mode previously, clear it now! */
	  if (oldfl != newfl)
	    fcntl(rp->desc->ctlfd, F_SETFL, oldfl);

	  /* Now we have no reason to send also the NOTARY report up.. */
	  no_notary = 1;
	}


	/* Do the verbose logging BEFORE actual diagnostics output.
	   That way the "scheduler done processing" will always be
	   the last -- presuming the verboselog does not throw in
	   things AFTER the final diagnostic() call... */

	if (verboselog) {
	  fprintf(verboselog,
		  "DIAG: C='%s' H='%s' U='%s' P='%s' ID=%d/%d L=%d -- stat='%s' notary='%s' ",
		  rp->addr->channel, rp->addr->host, rp->addr->user,
		  rp->addr->misc,
		  rp->desc->ctlid, rp->id, lockoffset,
		  statmsg, (notarybuf ? notarybuf : ""));
	  if (wtthost)
	    fprintf(verboselog, "WTT='%s' ", wtthost);
	  fprintf(verboselog, " MSG='%s'\n", message);
	  fflush(verboselog);
	}


	/* "Delay" the diagnostics from mailbox sieve subprocessing.
	   Actually DON'T do then at all! */
	if (rp->lockoffset && (!(rp->notifyflgs & _DSN__DIAGDELAYMODE))) {

	  fprintf(stdout,"%d/%d\t%s\t%s %s\n",
		  rp->desc->ctlid, rp->id,
		  (!no_notary && notarybuf && report_notary) ? notarybuf : "",
		  statmsg, message);
	  fflush(stdout);

	  switch(rp->status) {
	  case EX_IOERR:
	  case EX_TEMPFAIL:
	    if (rp->notifyflgs & _DSN__TEMPFAIL_NO_UNLOCK)
	      break;
	  default:
	    if (!lockaddr(rp->desc->ctlfd, rp->desc->ctlmap,
			  rp->lockoffset, _CFTAG_LOCK, mark,
			  (char*)rp->desc->msgfile, rp->addr->host,
			  getpid())) {
	      /* FIXME: something went wrong in unlocking it,
		 FIXME: concurrency problem? */
	    }
	    rp->lockoffset = 0;	/* mark this recipient unlocked */
	  }

	  syslogmsg = strrchr(message, '\r');
	  if (!syslogmsg) syslogmsg = message;
	  else syslogmsg++; /* Skip the last \r ... */

	  tasyslog(rp, xdelay, wtthost, wttip, statmsg, syslogmsg);
	}
}
