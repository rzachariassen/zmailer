/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *
 *	This module by Matti Aarnio <mea@utu.fi> 1992
 */

#include "hostenv.h"
#include <stdio.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sysexits.h>

#include "mail.h"
#include "zmalloc.h"
#include "ta.h"


/*
 *  char *routermxes(char *cp, struct taddress *ap);
 *
 *	Parses input string for   ((mxer)(mxer mxer)(mxer))
 *	formatted multi-homing router target info (like MX records)
 *	storing them into argv-style array (actually one string)
 *
 *	The first character of each entry is value of increasing
 *	PRIORITY value -- above example shows how to present multiple
 *	entries on same priority (two intermediate ones)
 *
 *	There shall be no other white spaces than those between same
 *	priority level entries.
 */

char *
routermxes(cp,ap)
	char *cp;
	struct taddress *ap;
{
	/* We receive information from router about its ideas of MXes
	   (for SMTP mainly) */
	char *s, **ss;
	int mxes     = 0;
	int priority = 0;
	int len      = 0;

	/* All right, "((mxer)(mxer mxer)(mxer mxer))", count them to
	   know how much space is needed to be allocated for this    */
	s = cp + 1;
	while (*s == '(') {
	  ++s;
	  while (*s && *s != ')') {
	    while(*s && *s != ' ' && *s != '\t' && *s != ')')
	      ++s;
	    ++mxes;
	    while (*s == ' ' || *s == '\t')
	      ++s;
	  }
	  if (*s == ')')
	      ++s;
	}
	/* Well, length overshoots by some characters, but never mind... */
	len = s - cp + mxes + mxes;
	ss = (char**)emalloc((u_int)(len + sizeof(char *)*(mxes+1)));
	ap->routermxes = (const char **)ss;
	*ss = NULL;
	s = (char*)ss + sizeof(char *)*(mxes+1);
	++cp; /* Skip the first '(' */
	while (*cp == '(') { /* Inner sequences */
	  ++cp;
	  ++priority;
	  while (*cp && *cp != ')') { /* Parallel level cases */
	    *ss++ = s;		/* Fill in the routermxes array */
	    *ss = NULL;
	    *s++  = priority;
	    while (*cp && *cp != ' ' && *cp != '\t' && *cp != ')')
	      *s++ = *cp++;
	    *s++ = 0;
	    while (*cp == ' ' || *cp == '\t') /* Skip white space */
	      ++cp;
	  }
	  if (*cp == ')')
	    ++cp; /* trailing ')' */
	}
	/* Now there should be outer ')' */
	if (*cp == ')')
	  ++cp;
	/* Set 'host' to be the first list entry */
	ap->host = ap->routermxes[0] + 1;
	/* ...and finally, we did scan past them all.. */
	return cp;
}
