/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */
/*
 *	Lots of modifications (new guts, more or less..) by
 *	Matti Aarnio <mea@nic.funet.fi>  (copyright) 1992-2000
 *
 *	This has been taken from scheduler and after some modifications,
 *	moved to general ZMailer library level.
 */

#include "hostenv.h"
#include <sfio.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include "zmalloc.h"

#include "libz.h"


u_long
parse_interval(string, restp)
	const char *string;
	const char **restp;
{
	u_long	intvl = 0;
	long	val;

	for (; *string; ++string) {

	  val = 0;
	  while (isascii((255 & *string)) && isdigit((255 & *string))) {
	    val = val * 10 + (*string - '0');
	    ++string;
	  }

	  switch (*string) {
	  case 'd':		/* days */
	    val *= 24;
	  case 'h':		/* hours */
	    val *= 60;
	  case 'm':		/* minutes */
	    val *= 60;
	  case 's':		/* seconds */
	    /* val *= 1; */
	    ++string;
	    break;
	  default: /* Not of: "dhms" - maybe string end, maybe junk ? */
	    if (restp) *restp = string;
	    return intvl + val;
	  }
	  intvl += val;
	}

	if (restp) *restp = string;
	return intvl;
}
