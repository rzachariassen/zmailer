/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include "hostenv.h"
#include <stdio.h>
#ifndef	HAVE_SETVBUF

#define _IOFBF	0
#define	_IONBF	04
#define	_IOLBF	0200

int
setvbuf(fp, buf, type, size)
	FILE *fp;
	char *buf;
	int type, size;
{
	if (type == _IONBF)
		setbuffer(fp, (char *)NULL, 0);
	else if (buf != NULL) {
		if (size <= 0)
			return 1;
		setbuffer(fp, buf, size);
	}
	if (type == _IOLBF)
		setlinebuf(fp);
	return (type != _IOLBF && type != _IONBF && type != _IOFBF);
}
#endif	/* !HAVE_SETVBUF */
