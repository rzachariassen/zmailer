/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include "hostenv.h"
#include "zmsignal.h"

#ifndef HAVE_STRSIGNAL

#if !HAVE_DECL_SYS_SIGLIST
#ifndef	HAVE_SYS_SIGLIST /* No  sys_siglist[]  at the libc ? */
const char *sys_siglist[] = {
	"Signal 0",
	"Signal 1",
	"Signal 2",
	"Signal 3",
	"Signal 4",
	"Signal 5",
	"Signal 6",
	"Signal 7",
	"Signal 8",
	"Signal 9",
	"Signal 10",
	"Signal 11",
	"Signal 12",
	"Signal 13",
	"Signal 14",
	"Signal 15",
	"Signal 16",
	"Signal 17",
	"Signal 18",
	"Signal 19",
	"Signal 20",
	"Signal 21",
	"Signal 22",
	"Signal 23",
	"Signal 24",
	"Signal 25",
	"Signal 26",
	"Signal 27",
	"Signal 28",
	"Signal 29",
	"Signal 30",
	"Signal 31"
};
#endif	/* HAVE_SYS_SIGLIST */
#endif

#if !HAVE_DECL_SYS_SIGLIST /* Not declared anywhere ? */
extern const char *sys_siglist[];
#endif

const char *strsignal(sig)
     int sig;
{
	if (sig < 1 || sig > 31)
	  return "Bad signal number";
	return sys_siglist[sig];
}
#endif
