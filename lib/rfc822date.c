/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *
 *	Rewrite for GNU autoconf by  Matti Aarnio <mea@nic.funet.fi> 1996
 */

#include "hostenv.h"
#include "mailer.h"
#include "libz.h"

static const char *weekday[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

const char *monthname[] = {	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
				"Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

char *
rfc822tz(timep, ts, prettyname)
	time_t *timep;
	struct tm **ts;
	int prettyname;
{
	char *cp;
	int sign, offset;
	static char zone[64];

	*ts    = localtime(timep);
#ifdef HAVE_TM_GMTOFF
	offset = ((*ts)->tm_gmtoff) / 60;	/* Offset in minutes */
#else
#ifdef HAVE_ALTZONE
	if ((*ts)->tm_isdst)
	  offset = -altzone;
	else
	  offset = -timezone;
	offset /= 60;				/* Offset in minutes */
#else
#ifdef HAVE_TIMEZONE /* Has ``timezone'', but no ``altzone'' ?? */
	offset = -timezone;
	if ((*ts)->tm_isdst)
	  offset += 3600; /* One hour! */
	offset /= 60;				/* Offset in minutes */
#else
	{		/* This is fallback stuff, beware! */
	  time_t tm;
	  struct tm ts2;

	  ts2    = *(*ts);
	  tm     = mktime(&ts2);
	  offset = (tm - *timep) / 60; /* Offset in minutes */
	}
#endif
#endif
#endif
	sign   = offset >= 0;
	if (offset < 0)
	  offset = -offset;

	sprintf(zone, "%c%02d%02d",
		sign ? '+' : '-', offset / 60, offset % 60);
	cp = zone + strlen(zone);

#ifdef	HAVE_TM_ZONE
	if (prettyname)
	  sprintf(cp," (%.19s)",(*ts)->tm_zone);
#else	/* !HAVE_TM_ZONE */
#ifdef HAVE_TZNAME
	if (prettyname)
	  sprintf(cp, " (%.19s)", tzname[(*ts)->tm_isdst]);
#else
	if (prettyname)
	  strcat(cp, " (Zone Name?)");
#endif
#endif	/* USE_BSDTIMEZONE */
	return zone;
}

/* Like ctime(), except returns RFC822 format (variable length!) date string */

char *
rfc822date(unixtimep)
	time_t *unixtimep;
{
	static char buf[40];
	struct tm *ts;
	char *tzp = rfc822tz(unixtimep, &ts, 0);

	sprintf(buf, "%s, %d %s %d %02d:%02d:%02d %s\n",
		weekday[ts->tm_wday], ts->tm_mday,
		monthname[ts->tm_mon], 1900 + ts->tm_year,
		ts->tm_hour, ts->tm_min, ts->tm_sec, tzp);
	return buf;
}
