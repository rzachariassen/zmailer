/*  $Revision: 1.1.1.1 $
**  Modified by Rich $alz <rsalz@osf.org> to be more portable to older
**  systems.
*/
/*
 * Copyright (c) 1983, 1988 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted provided
 * that: (1) source distributions retain this entire copyright notice and
 * comment, and (2) distributions including binaries display the following
 * acknowledgement:  ``This product includes software developed by the
 * University of California, Berkeley and its contributors'' in the
 * documentation or other materials provided with the distribution and in
 * all advertising materials mentioning features or use of this software.
 * Neither the name of the University nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)syslog.c	5.28 (Berkeley) 6/27/90";
#endif /* LIBC_SCCS and not lint */

/*
 * SYSLOG -- print message on log file
 *
 * This routine looks a lot like printf, except that it outputs to the
 * log file instead of the standard output.  Also:
 *	adds a timestamp,
 *	prints the module name in front of the message,
 *	has some other formatting types (or will sometime),
 *	adds a newline on the end of the message.
 *
 * The output of this routine is intended to be read by syslogd(8).
 *
 * Author: Eric Allman
 * Modified to use UNIX domain IPC by Ralph Campbell
 */

#include <stdio.h>
#include "hostenv.h"
#ifndef HAVE_SYSLOG /* If not have system defined syslog, use this! */
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/file.h>
#include "syslog.h"
#ifdef HAVE_WRITEV
# include <sys/uio.h>
#endif
#ifdef HAVE_STDARG_H
# include <stdarg.h>
#else
# include <varargs.h>
#endif

#ifndef	_PATH_LOGNAME
    /* if you are running an old syslog, change /dev/log to the same as it
     * is in syslogd.c */
#define	_PATH_LOGNAME	"/dev/log"
#endif

#define	_PATH_CONSOLE	"/dev/console"

static int	LogFile = -1;		/* fd for log */
static int	connected = 0;		/* have done connect */
static int	LogStat = 0;		/* status bits, set by openlog() */
static char	*LogTag = "syslog";	/* string to tag the entry with */
static int	LogFacility = LOG_USER;	/* default facility code */

/* extern char *strchr(), *strcpy(), *strncpy(), *strcat(); */
/* =()<extern @<SIZE_T>@	strlen();>()= */
/* extern int	strlen(); */

extern char *strerror();

void vsyslog(pri, fmt, ap)
	int pri;
	register char *fmt;
	va_list ap;
{
	extern int errno;
	register int cnt;
	register char *p;
	time_t now, time();
	int fd, saved_errno, len;
	char tbuf[2048], fmt_cpy[1024], *stdp, *ctime();

	saved_errno = errno;

	/* see if we should just throw out this message */
	if (!LOG_MASK(LOG_PRI(pri)) || (pri &~ (LOG_PRIMASK|LOG_FACMASK)))
		return;
	if (LogFile < 0 || !connected)
		openlog(LogTag, LogStat | LOG_NDELAY, 0);

	/* set default facility if none specified */
	if ((pri & LOG_FACMASK) == 0)
		pri |= LogFacility;

	/* build the message */
	(void)time(&now);
	(void)sprintf(tbuf, "<%d>%.15s ", pri, ctime(&now) + 4);
	for (p = tbuf; *p; ++p);
	if (LogStat & LOG_PERROR)
		stdp = p;
	if (LogTag) {
		(void)strcpy(p, LogTag);
		for (; *p; ++p);
	}
	if (LogStat & LOG_PID) {
		(void)sprintf(p, "[%d]", getpid());
		for (; *p; ++p);
	}
	if (LogTag) {
		*p++ = ':';
		*p++ = ' ';
	}

	/* substitute error message for %m */
	{
		register char ch, *t1, *t2;

		for (t1 = fmt_cpy; ch = *fmt; ++fmt)
			if (ch == '%' && fmt[1] == 'm') {
				++fmt;
				for (t2 = strerror(saved_errno);
				    *t1 = *t2++; ++t1);
			}
			else
				*t1++ = ch;
		*t1 = '\0';
	}
#ifdef HAVE_VSNPRINTF
	len = sizeof(tbuf) - 1 - (p - tbuf);
	(void)vsnprintf(p, len, fmt_cpy, ap);
#else
#ifdef HAVE_VSPRINTF
	(void)vsprintf(p, fmt_cpy, ap);
#else
error:error:error!  No vsprintf() NOR vsnprintf() !
#endif
#endif
	cnt = strlen(tbuf);

	/* output to stderr if requested */
#ifdef HAVE_WRITEV
	if (LogStat & LOG_PERROR) {
		struct iovec iov[2];
		register struct iovec *v = iov;

		v->iov_base = stdp;
		v->iov_len = cnt - (stdp - tbuf);
		++v;
		v->iov_base = "\n";
		v->iov_len = 1;
		(void)writev(2, iov, 2);
	}
#endif
	/* output the message to the local logger */
	if (send(LogFile, tbuf, cnt, 0) >= 0 || !(LogStat&LOG_CONS))
		return;

	/*
	 * output the message to the console; don't worry about
	 * blocking, if console blocks everything will.
	 */
	if ((fd = open(_PATH_CONSOLE, O_WRONLY, 0)) < 0)
		return;
	(void)strcat(tbuf, "\r\n");
	cnt += 2;
	p = strchr(tbuf, '>') + 1;
	(void)write(fd, p, cnt - (p - tbuf));
	(void)close(fd);
}


#ifdef HAVE_STDARG_H
#ifdef __STDC__
void syslog(int pri, char *fmt, ... )
#else
void syslog(pri, fmt)
	int pri;
	char *fmt;
#endif
#else
/* VARARGS0 */
void syslog(va_alist)
    va_dcl
#endif
{
	va_list ap;
#ifdef HAVE_STDARG_H
	va_start(ap,fmt);
#else
	int pri;
	char *fmt;

	va_start(ap);
	pri = va_arg(ap, int);
	fmt = va_arg(ap, char*);
#endif
	vsyslog(pri, fmt, ap);
	va_end(ap);
}


static struct sockaddr SyslogAddr;	/* AF_UNIX address of local logger */
/*
 * OPENLOG -- open system log
 */
void
openlog(ident, logstat, logfac)
	char *ident;
	int logstat, logfac;
{
	if (ident != NULL)
		LogTag = ident;
	LogStat = logstat;
	if (logfac != 0 && (logfac &~ LOG_FACMASK) == 0)
		LogFacility = logfac;
	if (LogFile == -1) {
		SyslogAddr.sa_family = AF_UNIX;
		strncpy(SyslogAddr.sa_data, _PATH_LOGNAME,
			sizeof(SyslogAddr.sa_data));
		if (LogStat & LOG_NDELAY) {
			LogFile = socket(AF_UNIX, SOCK_DGRAM, 0);
			fcntl(LogFile, F_SETFD, 1);
		}
	}
	if (LogFile != -1 && !connected &&
	    connect(LogFile, &SyslogAddr, sizeof(SyslogAddr)) != -1)
		connected = 1;
}

/*
 * CLOSELOG -- close the system log
 */
void closelog()
{
	(void) close(LogFile);
	LogFile = -1;
	connected = 0;
}

static int	LogMask = 0xff;		/* mask of priorities to be logged */
/*
 * SETLOGMASK -- set the log mask level
 */
int setlogmask(pmask)
	int pmask;
{
	int omask;

	omask = LogMask;
	if (pmask != 0)
		LogMask = pmask;
	return (omask);
}

#endif
