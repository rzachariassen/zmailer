/*
 * tasyslog() -- support routine for ZMailer transport agents.
 * Copyright 1997, Matti Aarnio <mea@nic.funet.fi>
 *
 * The purpose of this routine is to produce similar syslog entries
 * to those that sendmail(8) does for its message processing.
 *
 */

#include "mailer.h"
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
#include "zsyslog.h"
#include "mail.h"
#include "ta.h"
#include "libz.h"

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
  static char *syslogflg = NULL;
  char *t;

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
  

  taspoolid(spoolid, sizeof(spoolid), rp->desc->msgmtime, rp->desc->msgfile);

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
    sprintf(linebuf, "%s: to=<%.200s>, delay=%s, xdelay=%s, mailer=%.80s, stat=%.80s %.200s",
	    spoolid, rp->addr->user, delays, xdelays, rp->addr->channel, statstr, msg);
  else {
    if (wttip != NULL)
      sprintf(linebuf, "%s: to=<%.200s>, delay=%s, xdelay=%s, mailer=%.80s, relay=%.200s ([%.80s]), stat=%.80s %.200s",
	    spoolid, rp->addr->user, delays, xdelays, rp->addr->channel,
	      wtthost, wttip, statstr, msg);
    else
      sprintf(linebuf, "%s: to=<%.200s>, delay=%s, xdelay=%s, mailer=%.80s, relay=%.200s, stat=%.80s %.200s",
	      spoolid, rp->addr->user, delays, xdelays, rp->addr->channel,
	      wtthost, statstr, msg);
  }

  zsyslog((LOG_INFO, "%s", linebuf));
}
