/*
 * XX: Build unique boundary for MIME applications needing such
 *
 * Copyright Matti Aarnio <mea@nic.funet.fi> 1994,1995
 */

#include "hostenv.h"
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <time.h>

extern int getmyhostname();
extern char *getzenv();
#ifndef strdup
extern char *strdup();
#endif

char *
mydomain()
{
	static char *mydomainname = NULL;

	if (!mydomainname)
	  mydomainname = getzenv("ORGDOMAIN");
	if (!mydomainname) {
	  char buf[200];
	  *buf = 0; buf[sizeof(buf)-1] = 0;
	  getmyhostname(buf,sizeof(buf)-1);
	  if (*buf == 0)
	    return NULL;
	  mydomainname = strdup(buf);
	}
	return mydomainname;
}

/*
 * This route is probabilistic, rather than algorithmic;
 * that is, there exists a possibility that it will fail
 * because it will produce a MIME boundary line that also exists
 * in the source message. It would be safer, but more expensive,
 * to scan the message before committing this boundary candidate.
 *
 * The better a rand() function you have (i.e. the more random it is),
 * the less probable this bad outcome is. XXX
 */


char *
buildboundary()
{
	static char buf[400];
	static int  boundaryserial = 0;
	char *dom = mydomain();

	if (dom == NULL) dom = "unknown.domain";

	if (boundaryserial == 0)
	  boundaryserial = rand();

	sprintf(buf,"A%X.%ld=_/%s",boundaryserial++,(long)time(NULL),dom);
	return buf;
}
