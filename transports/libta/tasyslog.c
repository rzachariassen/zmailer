/*
 * tasyslog() -- support routine for ZMailer transport agents.
 * Copyright 1997-1999, Matti Aarnio <mea@nic.funet.fi>
 *
 * The purpose of this routine is to produce similar syslog entries
 * to those that sendmail(8) does for its message processing.
 *
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
#include "zmalloc.h"
#include "zsyslog.h"
#include "mail.h"
#include "ta.h"
#include "libz.h"

extern        int   wtttaidpid;
extern CONVERTMODE  wttcvtmode;

void
tasyslog(rp,xdelay,wtthost,wttip,statstr,msg)
struct rcpt *rp;
int xdelay;
const char *wtthost, *wttip;
const char *statstr;
const char *msg;
{
  char linebuf[8000];		/* Should be aplenty..		*/
  char spoolid[30];		/* Min. space: 6+8+1 chars	*/
  char delays[16], xdelays[16]; /* Min. space: 8+1 chars	*/
  time_t now;
  static const char *syslogflg = NULL;
  const char *t;

  /* Syslogflag 'T' for classical format, and 't' for TAB-separated format */

  static const char *fmt1c = "%s: to=<%.200s>, delay=%s, xdelay=%s, mailer=%.80s, stat=%.80s %.200s";
  static const char *fmt1t = "%s:\tto=<%.200s>\tdelay=%s\txdelay=%s\tmailer=%.80s\tstat=%.80s\t%.200s";

  static const char *fmt2c = "%s: to=<%.200s>, delay=%s, xdelay=%s, mailer=%.80s, relay=%.200s ([%.80s]), stat=%.80s %.400s";
  static const char *fmt2t = "%s:\tto=<%.200s>\tdelay=%s\txdelay=%s\tmailer=%.80s\trelay=%.200s ([%.80s])\tstat=%.80s\t%.400s";

  static const char *fmt3c = "%s: to=<%.200s>, delay=%s, xdelay=%s, mailer=%.80s, relay=%.200s, stat=%.80s %.400s";
  static const char *fmt3t = "%s:\tto=<%.200s>\tdelay=%s\txdelay=%s\tmailer=%.80s\trelay=%.200s\tstat=%.80s\t%.400s";

  if (syslogflg == NULL) {
    syslogflg = getzenv("SYSLOGFLG");
    if (syslogflg == NULL)
      syslogflg = "T";
  }
  t = syslogflg;
  for ( ; *t ; ++t ) {
    if (*t == 't' || *t == 'T')
      break;
  }
  if (*t == '\0')
    return;  /* If no 'T' flag in SYSLOGFLG, no transport agent sysloging! */
  

  taspoolid(spoolid, rp->desc->msgmtime, rp->desc->msginonumber);

  time(&now);

  tatimestr(delays,(int)(now - rp->desc->msgmtime));
  tatimestr(xdelays,xdelay);

  /* to='rp->addr->user'
     ctladdr=`getpwuid(rp->addr->misc)`
     mailer='rp->addr->channel' */

  if (wtthost != NULL) {
    char *s = strchr(wtthost,';');
    if (s) ++s;
    while (s && (*s == ' ')) ++s;
    if (s)
      wtthost = s;
  }
#if 0
  if (strcmp(statstr,"ok")==0) {
    msg = ""; /* Shut up ... */
  } else if (strcmp(statstr,"ok2")==0) {
    msg = ""; /* Shut up ... */
  }
#endif
  if (wtthost == NULL)
    sprintf(linebuf, ((*t == 't') ? fmt1t : fmt1c),
	    spoolid, rp->addr->user, delays, xdelays, rp->addr->channel, statstr, msg);
  else {
    if (wttip != NULL)
      sprintf(linebuf, ((*t == 't') ? fmt2t : fmt2c),
	    spoolid, rp->addr->user, delays, xdelays, rp->addr->channel,
	      wtthost, wttip, statstr, msg);
    else
      sprintf(linebuf, ((*t == 't') ? fmt3t : fmt3c),
	      spoolid, rp->addr->user, delays, xdelays, rp->addr->channel,
	      wtthost, statstr, msg);
  }

  if (wtttaidpid > 0) {
    char *s = "UNKNOWN";
    switch (wttcvtmode) {
    case _CONVERT_NONE:
      s = "NONE";
      break;
    case _CONVERT_MULTIPARTQP:
      s = "MPQP";
      break;
    case _CONVERT_QP:
      s = "QP";
      break;
    case _CONVERT_8BIT:
      s = "8BIT";
      break;
    case _CONVERT_UNKNOWN:
      break;
    }
    sprintf(linebuf + strlen(linebuf), " cvt=%s", s);
  }

  zsyslog((LOG_INFO, "%s", linebuf));
}
