/*
 *    Copyright 1994-1999, 2003 Matti Aarnio
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

long free_fd_statfs(fd)
int fd;
{
    long bavail = 0;
    long bsize  = 0;
    int rc;

    /* Query the available space on the filesystem where the
       currently open (int fd) file is located.  This call
       should be available on all systems, and given valid
       parametrization, never fail... */

    for (;;) {

#ifdef HAVE_STATVFS
      struct statvfs statbuf;	/* SysV and BSD definitions differ..    */
      if ((rc = fstatvfs(fd, &statbuf)) == 0) {
	/* Sidestep a problem at glibc 2.1.1 when running at Linux/i386 */
	bavail = statbuf.f_bavail;
	if (statbuf.f_frsize != 0)
	  bsize = statbuf.f_frsize;
	else
	  bsize = statbuf.f_bsize;
      }
#else
#ifdef STAT_STATFS3_OSF1
      struct statfs statbuf;
      if ((rc = fstatfs(fd, &statbuf, sizeof(statbuf))) == 0) {
	bavail = statbuf.f_bavail;
	bsize  = statbuf.f_fsize;
      }
#else
#ifdef STAT_STATFS2_BSIZE
      struct statfs statbuf;
      if ((rc = fstatfs(fd, &statbuf)) == 0) {
	bavail = statbuf.f_bavail;
	bsize  = statbuf.f_bsize;
      }
#else
#ifdef STAT_STATFS2_FSIZE
      struct statfs statbuf;
      if ((rc = fstatfs(fd, &statbuf)) == 0) {
	bavail = statbuf.f_bavail;
	bsize  = statbuf.f_fsize;
      }
#else
#ifdef STAT_STATFS2_FS_DATA	/* Ultrix ? */
  XX: XXX: XX: XXX:
#else				/* none of the previous  -- SVR3 stuff... */
      struct statfs statbuf;
      if ((rc = fstatfs(fd, &statbuf, sizeof statbuf, 0)) == 0) {
	bavail = statbuf.f_bfree;
	bsize  = statbuf.f_bsize;
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
    }
    if (bsize > 1024) {
      if (bavail <= (LONG_MAX / (long)(bsize / 1024)))
	bavail *= (bsize / 1024);
      else
	bavail = LONG_MAX;
    }

    return bavail;
}


long used_fd_statfs(fd)
int fd;
{
    long bused = 0;
    long bsize  = 0;
    int rc;

    /* Query the available space on the filesystem where the
       currently open (int fd) file is located.  This call
       should be available on all systems, and given valid
       parametrization, never fail... */

    for (;;) {

#ifdef HAVE_STATVFS
      struct statvfs statbuf;	/* SysV and BSD definitions differ..    */
      if ((rc = fstatvfs(fd, &statbuf)) == 0) {
	/* Sidestep a problem at glibc 2.1.1 when running at Linux/i386 */
	bused = statbuf.f_blocks - statbuf.f_bavail;
	if (statbuf.f_frsize != 0)
	  bsize = statbuf.f_frsize;
	else
	  bsize = statbuf.f_bsize;
      }
#else
#ifdef STAT_STATFS3_OSF1
      struct statfs statbuf;
      if ((rc = fstatfs(fd, &statbuf, sizeof(statbuf))) == 0) {
	/* UNSURE OF THIS WITHOUT MACHINE WHERE TO CHECK! */
	bused = statbuf.f_blocks - statbuf.f_bavail;
	bsize = statbuf.f_fsize;
      }
#else
#ifdef STAT_STATFS2_BSIZE
      struct statfs statbuf;
      if ((rc = fstatfs(fd, &statbuf)) == 0) {
	/* UNSURE OF THIS WITHOUT MACHINE WHERE TO CHECK! */
	bused = statbuf.f_blocks - statbuf.f_bavail;
	bsize = statbuf.f_bsize;
      }
#else
#ifdef STAT_STATFS2_FSIZE
      struct statfs statbuf;
      if ((rc = fstatfs(fd, &statbuf)) == 0) {
	/* UNSURE OF THIS WITHOUT MACHINE WHERE TO CHECK! */
	bused = statbuf.f_blocks - statbuf.f_bavail;
	bsize = statbuf.f_fsize;
      }
#else
#ifdef STAT_STATFS2_FS_DATA	/* Ultrix ? */
  XX: XXX: XX: XXX:
#else				/* none of the previous  -- SVR3 stuff... */
      struct statfs statbuf;
      if ((rc = fstatfs(fd, &statbuf, sizeof statbuf, 0)) == 0) {
	/* UNSURE OF THIS WITHOUT MACHINE WHERE TO CHECK! */
	bused = statbuf.f_blocks - statbuf.f_bfree;
	bsize = statbuf.f_bsize;
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
       spools with more than 2 GB of used space
       without using any sort of 64-bit gimmic codes... */

    if (bsize < 1024) {
      if (!bsize) bsize = 1024; /* Just code safety... */
      bused /= (1024 / bsize);
    }
    if (bsize > 1024) {
      if (bused <= (LONG_MAX / (long)(bsize / 1024)))
	bused *= (bsize / 1024);
      else
	bused = LONG_MAX;
    }

    return bused;
}
