/*
 *    Copyright 1994-1999, 2003,2004 Matti Aarnio
 *      This is part of the ZMailer (2.99+), and available with
 *      the rules of the main program itself
 *
 *	This yields available/used disk-space in KILOBYTES!
 *	This function maxes out at LONG_MAX for both the free,
 *	and the used space. (E.g. around 2 TB for 32 bit machines.)
 */

#include "hostenv.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/param.h>
#include <errno.h>

#ifdef HAVE_LIMIT_H
#include <limit.h>
#endif
#ifndef LONG_MAX
# define LONG_MAX 2147483647L /* For 32 bit machine! */
#endif

#ifdef	HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif				/* !HAVE_STATVFS */
#ifdef HAVE_SYS_STATFS_H
#include <sys/statfs.h>
#endif
#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
#ifdef HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif

#include "libz.h"

int fd_statfs(fd, bavailp, busedp, iavailp, iusedp)
     int fd;
     long *bavailp, *busedp, *iavailp, *iusedp;
{
    long bavail = 0;
    long bsize  = 0;
    long bused  = 0;
    long iavail = 0;
    long iused  = 0;
    int rc;

    /* Query the available space on the filesystem where the
       currently open (int fd) file is located.  This call
       should be available on all systems, and given valid
       parametrization, never fail... */

    for (;;) {

#ifdef HAVE_STATVFS
      struct statvfs statbuf;	/* SysV and BSD definitions differ..    */
      rc = fstatvfs(fd, &statbuf); /* Solaris, autoconfigures into use in
				      Linux glibc 2.3+ as well... */
      if (rc == 0) {
	/* Availability by 'non-super-user', usage per last drop.. */

	bavail = statbuf.f_bavail;  /* available to non-super-user */
	bused  = statbuf.f_blocks - statbuf.f_bfree; /* real usage */

	if (statbuf.f_frsize != 0)
	  bsize = statbuf.f_frsize;
	else
	  bsize = statbuf.f_bsize;

	if (statbuf.f_favail >= LONG_MAX)
	  iavail = LONG_MAX;
	else
	  iavail = statbuf.f_favail;

	if ((statbuf.f_files - statbuf.f_ffree) >= LONG_MAX)
	  iused = LONG_MAX;
	else
	  iused = (statbuf.f_files - statbuf.f_ffree);
      }
#else
#ifdef STAT_STATFS3_OSF1
      struct statfs statbuf;
      rc = fstatfs(fd, &statbuf, sizeof(statbuf));
      if (rc == 0) {
	bavail = statbuf.f_bavail;
	bsize  = statbuf.f_fsize;
	/* UNSURE OF THIS WITHOUT MACHINE WHERE TO CHECK! */
	bused = statbuf.f_blocks - statbuf.f_bavail;
	bsize = statbuf.f_fsize;
	if (statbuf.f_ffree >= LONG_MAX)
	  iavail = LONG_MAX;
	else
	  iavail = statbuf.f_ffree;
	if ((statbuf.f_files - statbuf.f_ffree) >= LONG_MAX)
	  iused = LONG_MAX;
	else
	  iused = (statbuf.f_files - statbuf.f_ffree);
      }
#else
#ifdef STAT_STATFS2_BSIZE /* 2 param fstatfs(), with f_bsize field */
      struct statfs statbuf;	  /* Linux, FreeBSD 4.x */
      rc = fstatfs(fd, &statbuf);
      if (rc == 0) {
	/* Availability by 'non-super-user', usage per last drop.. */

	bavail = statbuf.f_bavail;		/* avail to non-root */
	bsize  = statbuf.f_bsize;
	bused  = statbuf.f_blocks - statbuf.f_bfree; /* real used */

	if (statbuf.f_ffree >= LONG_MAX)
	  iavail = LONG_MAX;
	else
	  iavail = statbuf.f_ffree;

	if ((statbuf.f_files - statbuf.f_ffree) >= LONG_MAX)
	  iused = LONG_MAX;
	else
	  iused = (statbuf.f_files - statbuf.f_ffree);
      }
#else
#ifdef STAT_STATFS2_FSIZE /* 2 param fstatfs(), with f_fsize field */
      struct statfs statbuf;
      rc = fstatfs(fd, &statbuf);
      if (rc == 0) {
	bavail = statbuf.f_bavail;
	bsize  = statbuf.f_fsize;
	/* UNSURE OF THIS WITHOUT MACHINE WHERE TO CHECK! */
	bused = statbuf.f_blocks - statbuf.f_bavail;
	bsize = statbuf.f_fsize;
	if (statbuf.f_ffree >= LONG_MAX)
	  iavail = LONG_MAX;
	else
	  iavail = statbuf.f_ffree;
	if ((statbuf.f_files - statbuf.f_ffree) >= LONG_MAX)
	  iused = LONG_MAX;
	else
	  iused = (statbuf.f_files - statbuf.f_ffree);
      }
#else
#ifdef STAT_STATFS2_FS_DATA	/* Ultrix ? */
  XX: XXX: XX: XXX:
#else				/* none of the previous  -- SVR3 stuff... */
      struct statfs statbuf;
      rc = fstatfs(fd, &statbuf, sizeof statbuf, 0);
      if (rc == 0) {
	bavail = statbuf.f_bfree;
	bsize  = statbuf.f_bsize;
	/* UNSURE OF THIS WITHOUT MACHINE WHERE TO CHECK! */
	bused = statbuf.f_blocks - statbuf.f_bfree;
	bsize = statbuf.f_bsize;
	if (statbuf.f_ffree >= LONG_MAX)
	  iavail = LONG_MAX;
	else
	  iavail = statbuf.f_ffree;
	if ((statbuf.f_files - statbuf.f_ffree) >= LONG_MAX)
	  iused = LONG_MAX;
	else
	  iused = (statbuf.f_files - statbuf.f_ffree);
      }
#endif
#endif
#endif
#endif
#endif
      else {
	if (errno == EINTR || errno == EAGAIN)
	  continue; /* restart the syscall! */
	return -1; /* Don't know what! */
      }
      break; /* Out of  for(;;) loop .. */
    }


    /* Convert the free space size to kilobytes ...
       .. so that even 32 bit machines can handle
       spools with more than 2 GB of free space
       without using any sort of 64-bit gimmic codes... */

    if (bsize < 1024) {
      if (!bsize) bsize = 1024; /* Just code safety... */

      bavail /= (1024 / bsize);
      bused  /= (1024 / bsize);
    }

    if (bsize > 1024) {
      if (bavail <= (LONG_MAX / (long)(bsize / 1024)))
	bavail *= (bsize / 1024);
      else
	bavail = LONG_MAX;

      if (bused <= (LONG_MAX / (long)(bsize / 1024)))
	bused *= (bsize / 1024);
      else
	bused = LONG_MAX;
    }

    *bavailp = bavail;
    *busedp  = bused;
    *iavailp = iavail;
    *iusedp  = iused;

    return rc;
}
