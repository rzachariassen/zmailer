/*
 *    Copyright 1994-1996 Matti Aarnio
 *      This is part of the ZMailer (2.99+), and available with
 *      the rules of the main program itself
 */

#include "hostenv.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/param.h>


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

long fd_statfs(fd)
int fd;
{
    long availspace = 0;
    int rc;

    /* Query the available space on the filesystem where the
       currently open (int fd) file is located.  This call
       should be available on all systems, and given valid
       parametrization, never fail... */

#ifdef HAVE_STATVFS
    struct statvfs statbuf;	/* SysV and BSD definitions differ..    */
    if ((rc = fstatvfs(fd, &statbuf)) == 0) {
      /* Sidestep a problem at glibc 2.1.1 when running at Linux/i386 */
      if (statbuf.f_frsize != 0)
	availspace = statbuf.f_bavail * statbuf.f_frsize;
      else
	availspace = statbuf.f_bavail * statbuf.f_bsize;
    }
#else
#ifdef STAT_STATFS3_OSF1
    struct statfs statbuf;
    if ((rc = fstatfs(fd, &statbuf, sizeof(statbuf))) == 0) {
	availspace = statbuf.f_bavail * statbuf.f_fsize;
    }
#else
#ifdef STAT_STATFS2_BSIZE
    struct statfs statbuf;
    if ((rc = fstatfs(fd, &statbuf)) == 0) {
	availspace = statbuf.f_bavail * statbuf.f_bsize;
    }
#else
#ifdef STAT_STATFS2_FSIZE
    struct statfs statbuf;
    if ((rc = fstatfs(fd, &statbuf)) == 0) {
	availspace = statbuf.f_bavail * statbuf.f_fsize;
    }
#else
#ifdef STAT_STATFS2_FS_DATA	/* Ultrix ? */
  XX: XXX: XX: XXX:
#else				/* none of the previous  -- SVR3 stuff... */
    struct statfs statbuf;
    if ((rc = fstatfs(fd, &statbuf, sizeof statbuf, 0)) == 0) {
	availspace = statbuf.f_bfree * statbuf.f_bsize;
    }
#endif
#endif
#endif
#endif
#endif
    return availspace;
}
