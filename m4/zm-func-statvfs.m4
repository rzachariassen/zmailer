#
#  Local hacks for ZMailer with  GNU autoconfig 2.12
#

# AC_DEFUN(AC_STRUCT_ST_BLKSIZE,
# [dnl
# #
# # Do we have "st_blksize" in the "struct stat" ?
# # Defines  HAVE_ST_BLKSIZE  if we do
# #
# AC_CACHE_CHECK(for st_blksize in struct stat, ac_cv_struct_stat_st_blksize, [
# AC_TRY_LINK([#include <sys/types.h>
# #include <sys/stat.h>], [struct stat st; st.st_blksize; ],
# 		AC_DEFINE(HAVE_ST_BLKSIZE) ac_cv_struct_stat_st_blksize=yes)
# ])
# ])


AC_DEFUN(AC_FUNC_STATVFS,
[dnl
#
# AC_FUNC_STATVFS -- test how to find out the filesystem space usage
#
# Defines one of:	STAT_STATVFS, STAT_STATFS3_OSF1, STAT_STATFS2_BSIZE,
#			STAT_STATFS4, STAT_STATFS2_FSIZE, STAT_STATFS2_FS_DATA,
#			STAT_READ_FILSYS
#

AC_CHECKING(how to get filesystem space usage:)
space=no

# Here we'll compromise a little (and perform only the link test)
# since it seems there are no variants of the statvfs function.
if test $space = no; then
  # SVR4
  AC_CHECK_FUNCS(statvfs)
  if test $ac_cv_func_statvfs = yes; then
    space=yes
    AC_DEFINE(STAT_STATVFS,1,[Define if there is a function named statvfs.  [SVR4]])
  fi
fi

if test $space = no; then
  # DEC Alpha running OSF/1
  AC_MSG_CHECKING([for 3-argument statfs function (DEC OSF/1)])
  AC_CACHE_VAL(fu_cv_sys_stat_statfs3_osf1,
  [AC_TRY_RUN([
#include <sys/param.h>
#include <sys/types.h>
#include <sys/mount.h>
  main ()
  {
    struct statfs fsd;
    fsd.f_fsize = 0;
    exit (statfs (".", &fsd, sizeof (struct statfs)));
  }],
  fu_cv_sys_stat_statfs3_osf1=yes,
  fu_cv_sys_stat_statfs3_osf1=no,
  fu_cv_sys_stat_statfs3_osf1=no)])
  AC_MSG_RESULT($fu_cv_sys_stat_statfs3_osf1)
  if test $fu_cv_sys_stat_statfs3_osf1 = yes; then
    space=yes
    AC_DEFINE(STAT_STATFS3_OSF1,1,[Define if  statfs takes 3 args.  [DEC Alpha running OSF/1]])
  fi
fi

if test $space = no; then
# AIX
  AC_MSG_CHECKING([for two-argument statfs with statfs.bsize dnl
member (AIX, 4.3BSD)])
  AC_CACHE_VAL(fu_cv_sys_stat_statfs2_bsize,
  [AC_TRY_RUN([
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
#ifdef HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif
  main ()
  {
  struct statfs fsd;
  fsd.f_bsize = 0;
  exit (statfs (".", &fsd));
  }],
  fu_cv_sys_stat_statfs2_bsize=yes,
  fu_cv_sys_stat_statfs2_bsize=no,
  fu_cv_sys_stat_statfs2_bsize=no)])
  AC_MSG_RESULT($fu_cv_sys_stat_statfs2_bsize)
  if test $fu_cv_sys_stat_statfs2_bsize = yes; then
    space=yes
    AC_DEFINE(STAT_STATFS2_BSIZE,1,[Define if statfs takes 2 args and struct statfs has a field named f_bsize.
   [4.3BSD, SunOS 4, HP-UX, AIX PS/2]])
  fi
fi

if test $space = no; then
# SVR3
  AC_MSG_CHECKING([for four-argument statfs (AIX-3.2.5, SVR3)])
  AC_CACHE_VAL(fu_cv_sys_stat_statfs4,
  [AC_TRY_RUN([#include <sys/types.h>
#include <sys/statfs.h>
  main ()
  {
  struct statfs fsd;
  exit (statfs (".", &fsd, sizeof fsd, 0));
  }],
    fu_cv_sys_stat_statfs4=yes,
    fu_cv_sys_stat_statfs4=no,
    fu_cv_sys_stat_statfs4=no)])
  AC_MSG_RESULT($fu_cv_sys_stat_statfs4)
  if test $fu_cv_sys_stat_statfs4 = yes; then
    space=yes
    AC_DEFINE(STAT_STATFS4,1,[Define if statfs takes 4 args.  [SVR3, Dynix, Irix, Dolphin]])
  fi
fi

if test $space = no; then
# 4.4BSD and NetBSD
  AC_MSG_CHECKING([for two-argument statfs with statfs.fsize dnl
member (4.4BSD and NetBSD)])
  AC_CACHE_VAL(fu_cv_sys_stat_statfs2_fsize,
  [AC_TRY_RUN([#include <sys/types.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
  main ()
  {
  struct statfs fsd;
  fsd.f_fsize = 0;
  exit (statfs (".", &fsd));
  }],
  fu_cv_sys_stat_statfs2_fsize=yes,
  fu_cv_sys_stat_statfs2_fsize=no,
  fu_cv_sys_stat_statfs2_fsize=no)])
  AC_MSG_RESULT($fu_cv_sys_stat_statfs2_fsize)
  if test $fu_cv_sys_stat_statfs2_fsize = yes; then
    space=yes
    AC_DEFINE(STAT_STATFS2_FSIZE,1,[Define if statfs takes 2 args and struct statfs has a field named f_fsize.
   [4.4BSD, NetBSD]])
  fi
fi

if test $space = no; then
  # Ultrix
  AC_MSG_CHECKING([for two-argument statfs with struct fs_data (Ultrix)])
  AC_CACHE_VAL(fu_cv_sys_stat_fs_data,
  [AC_TRY_RUN([#include <sys/types.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
#ifdef HAVE_SYS_FS_TYPES_H
#include <sys/fs_types.h>
#endif
  main ()
  {
  struct fs_data fsd;
  /* Ultrix's statfs returns 1 for success,
     0 for not mounted, -1 for failure.  */
  exit (statfs (".", &fsd) != 1);
  }],
  fu_cv_sys_stat_fs_data=yes,
  fu_cv_sys_stat_fs_data=no,
  fu_cv_sys_stat_fs_data=no)])
  AC_MSG_RESULT($fu_cv_sys_stat_fs_data)
  if test $fu_cv_sys_stat_fs_data = yes; then
    space=yes
    AC_DEFINE(STAT_STATFS2_FS_DATA,1,[Define if statfs takes 2 args and the second argument has
   type struct fs_data.  [Ultrix]])
  fi
fi

if test $space = no; then
# SVR2
AC_TRY_CPP([#include <sys/filsys.h>],
  AC_DEFINE(STAT_READ_FILSYS,1,[Define if there is no specific function for reading filesystems usage
   information and you have the <sys/filsys.h> header file.  [SVR2]])
  space=yes)
fi
])
