/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *
 *  mmap() using region mapping -- gives efficiency at message
 *  lock accesses
 *
 *  FCNTL-style locking by Matti Aarnio <mea@nic.funet.fi>
 *  Theory:  On system where it works, it makes LESS IO
 */

/*
 * Common routine to fiddle control file tag characters.
 */

#include "hostenv.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include "mail.h"
#include "ta.h"

#ifndef	SEEK_SET
#define	SEEK_SET  0
#endif	/* SEEK_SET */

int
lockaddr(fd, map, offset, was, new, file, host, mypid)
	int	fd;
	char	*map;
	int	offset;
	int	was;
	int	new;
	const char *file, *host;
	const int mypid;
{
	char	lockbuf[16];
	int	newlock = 0;

#ifdef USE_FCNTLLOCK
	struct flock fl;
	int rc = 0;

	fl.l_type   = F_WRLCK;
	fl.l_start  = offset;
	fl.l_whence = SEEK_SET;
	fl.l_len    = 10; /* fixed.. */

	if (new == _CFTAG_LOCK || new == _CFTAG_DEFER) {
	  rc = fcntl(fd,F_GETLK,&fl);
	  if (rc == -1) {
	    warning("lockaddr: fcntl() lock error");
	    return 0;
	  }
	}
	lockbuf[1] = ' ';
	if (was == _CFTAG_NORMAL) {
	  if (fl.l_type == F_UNLCK)
	    lockbuf[0] = was;
	  else
	    lockbuf[0] = _CFTAG_LOCK;
	} else if (was == _CFTAG_LOCK) {
	  if (fl.l_type == F_UNLCK)
	}
#endif
	if (map) {
	  /* MMAP()ed block helps.. */
	  memcpy(lockbuf,map+offset,sizeof(lockbuf));
	} else {
	  if (lseek(fd, offset, SEEK_SET) < 0L) {
	    warning("lockaddr: lseek() failure");
	    return 0;
	  }
	  if (read(fd, lockbuf, sizeof(lockbuf)) != sizeof(lockbuf)) {
	    warning("lockaddr: read() failure");
	    return 0;
	  }
	}
	newlock = ((lockbuf[1] == ' ') ||
		   (lockbuf[1] >= '0' && lockbuf[1] <= '9'));
	if (lockbuf[0] == was) {
	  if (!map && lseek(fd, offset, SEEK_SET) < 0L) {
	    warning("lockaddr: lseek() failure 2");
	    return 0;
	  }
	  lockbuf[0] = new;
	  if (newlock) {
	    if (new == _CFTAG_LOCK) {
#ifdef USE_FCNTLLOCK
	      /* Using FCNTL region locking */
#else
	      /* Mark the lock with client process-id */
	      sprintf(lockbuf+1, "%*d", _CFTAG_RCPTPIDSIZE, mypid);
	      if (map)
		memcpy(map+offset, lockbuf, _CFTAG_RCPTPIDSIZE+1);
	      else if (write(fd,lockbuf,
			     _CFTAG_RCPTPIDSIZE+1) != _CFTAG_RCPTPIDSIZE+1)
		return 0;
#endif
	    } else if (new == _CFTAG_DEFER) {
#ifdef USE_FCNTLLOCK
	      /* Using FCNTL region locking */
#else
	      /* Clear the lock location */
	      sprintf(lockbuf+1,"%*s", _CFTAG_RCPTPIDSIZE, "");
	      if (map)
		memcpy(map+offset, lockbuf, _CFTAG_RCPTPIDSIZE+1);
	      else if (write(fd,lockbuf,
			     _CFTAG_RCPTPIDSIZE+1) != _CFTAG_RCPTPIDSIZE+1)
		return 0;
#endif
	    } else {
	      /* Clear the lock location */
	      sprintf(lockbuf+1, "%*s", _CFTAG_RCPTPIDSIZE, "");
	      if (map)
		memcpy(map+offset, lockbuf, _CFTAG_RCPTPIDSIZE+1);
	      else if (write(fd,lockbuf,
			     _CFTAG_RCPTPIDSIZE+1) != _CFTAG_RCPTPIDSIZE+1)
		return 0;
	    }
	  }
	  return 1;
	}
	if (host == NULL) host = "-";
	warning("lockaddr: file '%s' host '%s' expected '%c' found '%c'\n", file, host, was, new);
	return 0;
}
