/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */
/*
 *	A lot of changes all around over the years by Matti Aarnio
 *	<mea@nic.funet.fi>, copyright 1992-1997
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

char *notarybuf = NULL;
time_t retryat_time = 0; /* Used at SMTP to avoid trying same host too soon.. */


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

static char *wtthost = NULL; /* NOTARY wtthost: 'While-Talking-To -host' */
static char *wttip   = NULL;

void notary_setwtt(host)
const char *host;
{
	if (wtthost) free(wtthost);
	if (host)
	  wtthost = strdup(host);
	else
	  wtthost = NULL;
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

static int xdelay = 0;
void notary_setxdelay(xdly)
int xdly;
{
	xdelay = xdly;
}

static char *A1 = NULL, *A2 = NULL, *A3 = NULL, *A4 = NULL;

void
notaryreport(arg1,arg2,arg3,arg4)
     const char *arg1, *arg2, *arg3, *arg4;
{
	const char *fmt = "%s\001%s\001%s\001%s\001%s";
	int len;

	if (arg1) { if (A1) free(A1); A1 = strdup(arg1); }
	if (arg2) { if (A2) free(A2); A2 = strdup(arg2); }
	if (arg3) { if (A3) free(A3); A3 = strdup(arg3); }
	if (arg4) { if (A4) free(A4); A4 = strdup(arg4); }

	len = 5; /* "\001\001\001\001" */
	if (A1) len += strlen(A1);
	if (A2) len += strlen(A2);
	if (A3) len += strlen(A3);
	if (A4) len += strlen(A4);
	if (wtthost) len += strlen(wtthost);
	if (wttip) len += strlen(wttip)+5;

	if (!notarybuf)
	  notarybuf = (char*) emalloc(len);
	else
	  notarybuf = (char*) erealloc(notarybuf,len);
	sprintf(notarybuf,fmt,
		A1?A1:"",A2?A2:"",A3?A3:"",A4?A4:"",
		wtthost?wtthost:"");
	if (wttip) {
	  sprintf(notarybuf + strlen(notarybuf), " (%s)", wttip);
	}
}


#ifdef HAVE_STDARG_H
#ifdef __STDC__
void
diagnostic(struct rcpt *rp, int rc, int timeout, const char *fmt, ...)
#else /* Not ANSI-C */
void
diagnostic(rp, rc, timeout, fmt) /* (rp, rc, timeout, "fmtstr", remotemsg) */
	struct rcpt *rp;
	int rc, timeout;
	const char *fmt;
#endif
#else
/*VARARGS*/
void
diagnostic(rp, rc, timeout, fmt, va_alist) /* (rp, rc, timeout, "fmtstr", remotemsg) */
	struct rcpt *rp;
	int rc, timeout;
	const char *fmt;
	va_dcl
#endif
{
	char	message[8192];
	char	statmsgbuf[32+16];
	const char * statmsg;
	char	mark;
	register char *s, *es, *s2;
	va_list	ap;
	int report_notary = 1;
	int logreport = 0;

	if (!rp->lockoffset) return; /* Don't re-report... */

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

	if (logreport) {
	  /* Right, we have a honour to append our diagnostics to the
	     transport specification file ourselves */
	  int oldfl = fcntl(rp->desc->ctlfd, F_GETFL);
	  int len = 80 + strlen(notarybuf ? notarybuf : "") + strlen(message);
	  int rc2;
	  off_t ctlsize;
	  long oldalarm;
	  char *sbuf;

	  /* Set the APPEND-mode on.. We need it now !
	     (and make sure the non-blocking mode is NOT on!) */
	  if ((oldfl & O_APPEND) == 0 || (oldfl & O_NONBLOCK) != 0)
	    fcntl(rp->desc->ctlfd, F_SETFL, (oldfl & ~O_NONBLOCK) | O_APPEND);

#ifdef HAVE_ALLOCA
	  sbuf = alloca(len);
#else
	  sbuf = emalloc(len);
#endif

	  /* Log the diagnostic string to the file */
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

	  rc2 = write(rp->desc->ctlfd, sbuf, len);
	  if (rc2 != len || rc2 < 0 || len < 0) {
	    /* UAARGH! -- write failed, must have disk full! */
#ifdef HAVE_FTRUNCATE
	    ftruncate(rp->desc->ctlfd, ctlsize); /* Sigh.. */
#endif
	    fprintf(stdout,"#HELP! diagnostic writeout with bad results!: len=%d, rc=%d\n", len, rc2);
	    exit(EX_DATAERR);
	  }
#ifdef HAVE_FSYNC
	  fsync(rp->desc->ctlfd);
#endif
	  if (oldalarm)		/* Restore it, if it was ticking. */
	    alarm(oldalarm);

#ifndef HAVE_ALLOCA
	  free(sbuf);
#endif

	  /* If we had to set the APPEND mode previously, clear it now! */
	  if ((oldfl & O_APPEND) == 0 || (oldfl & O_NONBLOCK) != 0)
	    fcntl(rp->desc->ctlfd, F_SETFL, oldfl);

	  /* Now we have no reason to send also the NOTARY report up.. */
	  if (notarybuf != NULL)
	    *notarybuf = 0;
	}

	/* "Delay" the diagnostics from mailbox sieve subprocessing.
	   Actually DON'T do then at all! */
	if (!(rp->notifyflgs & _DSN__DIAGDELAYMODE)) {

	  int fd = FILENO(stdout);

	  /* This should always be in blocking mode, but... */
	  fd_blockingmode(fd);
#if 0
	  int len;
	  char *buf;
	  len = (9+9+4+strlen(notarybuf ? notarybuf : "") +
		 strlen(statmsg) + strlen(message));
#endif
	  fprintf(stdout,"%d/%d\t%s\t%s %s\n",
		  rp->desc->ctlid, rp->id,
		  (notarybuf && report_notary) ? notarybuf : "",
		  statmsg, message);
	  fflush(stdout);

	  if (!lockaddr(rp->desc->ctlfd, rp->desc->ctlmap,
			rp->lockoffset, _CFTAG_LOCK, mark,
			(char*)rp->desc->msgfile, rp->addr->host, getpid())) {
	    /* something went wrong in unlocking it, concurrency problem? */
	  }
	  rp->lockoffset = 0;	/* mark this recipient unlocked */

	  tasyslog(rp, xdelay, wtthost, wttip, statmsg, message);
	}
	fflush(stdout);
}
