/*
 *	Copyright 1991 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include "hostenv.h"
#ifndef	HAVE_STRERROR

extern char *sys_errlist[];
extern int sys_nerr;

char *
strerror(num)
	int num;
{
	if (num < 0 || num > sys_nerr)
		return "Bad errno??";

	return sys_errlist[num];
}
#endif	/* HAVE_STRERROR */
