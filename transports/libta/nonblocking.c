/*
 *	A component for ZMailer by Matti Aarnio <mea@nic.funet.fi>
 *	Copyright 1996 Matti Aarnio
 *
 */

#include "hostenv.h"
#include <stdio.h>
#include <sys/param.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/file.h>
#include <stdlib.h>
#include <unistd.h>


int
fd_nonblockingmode(fd)
	int fd;
{
	int i, i2;
	i2 = i = fcntl(fd, F_GETFL, 0);
	if (i >= 0) {
#ifdef O_NONBLOCK /* POSIXy thing */
	  /* set up non-blocking I/O */
	  i |= O_NONBLOCK;
#else
#ifdef	FNONBLOCK
	  i |= FNONBLOCK;
#else
	  i |= FNDELAY;
#endif
#endif
	  i = fcntl(fd, F_SETFL, i);
	}
	return i2;
}

int
fd_blockingmode(fd)
	int fd;
{
	int i, i2;
	i2 = i = fcntl(fd, F_GETFL, 0);
	if (i >= 0) {
#ifdef O_NONBLOCK /* POSIXy thing */
	  /* set up blocking I/O */
	  i &= ~O_NONBLOCK;
#else
#ifdef	FNONBLOCK
	  i &= ~FNONBLOCK;
#else
	  i &= ~FNDELAY;
#endif
#endif
	  i = fcntl(fd, F_SETFL, i);
	}
	return i2;
}


void
fd_restoremode(fd,mode)
int fd, mode;
{
	fcntl(fd, F_SETFL, mode);
}
