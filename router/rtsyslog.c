/*
 * rtsyslog() -- support routine for ZMailer transport agents.
 * Copyright 1997-1999, Matti Aarnio <mea@nic.funet.fi>
 *
 * The purpose of this routine is to produce similar syslog entries
 * to those that sendmail(8) does for its message processing.
 *
 */

#include "router.h"
#include "ta.h"  /* for  tatimestr() */

static char lbuf[8000];	/* Should be aplenty..		*/

void
rtsyslog(spoolid,msgmtime,from,smtprelay,size,nrcpts,msgid,starttime)
const time_t starttime, msgmtime;
const char *spoolid, *from, *smtprelay, *msgid;
const int size, nrcpts;
{
  char delays[16], xdelays[16]; /* Min. space: 8+1 chars	*/
  time_t now;
  static const char *syslogflg = NULL;
  const char *t;

  /* Syslogflag 'R' for classical format, and 'r' for TAB-separated format */

  if (syslogflg == NULL) {
    syslogflg = getzenv("SYSLOGFLG");
    if (syslogflg == NULL)
      syslogflg = "R";
  }
  t = syslogflg;
  for ( ; *t ; ++t ) {
    if (*t == 'r' || *t == 'R')
      break;
  }
  if (*t == '\0')
    return;  /* If no 'R' flag in SYSLOGFLG, no router sysloging! */

  time(&now);

  /* to='rp->addr->user'
     ctladdr=`getpwuid(rp->addr->misc)`
     mailer='rp->addr->channel' */

  tatimestr(delays,  now - msgmtime);
  tatimestr(xdelays, now - starttime);

  if (*t == 'R')
    sprintf(lbuf,
	    "%s: from=<%.200s>, rrelay=%.200s, size=%d, nrcpts=%d, msgid=%.200s, delay=%s, xdelay=%s",
	    spoolid, from, smtprelay, size, nrcpts, msgid, delays, xdelays);
  else
    sprintf(lbuf,
	    "%s:\tfrom=<%.200s>\trrelay=%.200s\tsize=%d\tnrcpts=%d\tmsgid=%.200s\tdelay=%s\txdelay=%s",
	    spoolid, from, smtprelay, size, nrcpts, msgid, delays, xdelays);

  zsyslog((LOG_INFO, "%s", lbuf));
}
