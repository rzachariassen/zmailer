#
#  Local hacks for ZMailer with  GNU autoconfig 2.12
#

AC_DEFUN(AC_STRUCT_TM_GMTOFF,
[dnl
#
# Timezones are always a pain in... everybody has their own ways :-(
#
AC_REQUIRE([AC_STRUCT_TM])dnl
AC_CACHE_CHECK([for tm_gmtoff in struct tm], ac_cv_struct_tm_gmtoff,
[AC_TRY_COMPILE([#include <sys/types.h>
#include <$ac_cv_struct_tm>], [struct tm tm; tm.tm_gmtoff;],
  ac_cv_struct_tm_gmtoff=yes, ac_cv_struct_tm_gmtoff=no)])
if test "$ac_cv_struct_tm_gmtoff" = yes; then
  AC_DEFINE(HAVE_TM_GMTOFF)
else
  AC_CACHE_CHECK(for altzone, ac_cv_var_altzone,
[AC_TRY_LINK([#include <time.h>
static int tt;],
[tt = (int)altzone;], ac_cv_var_altzone=yes, ac_cv_var_altzone=no)])
  AC_CACHE_CHECK(for timezone, ac_cv_var_timezone,
[AC_TRY_LINK([#include <time.h>
static int tt;],
[tt = (int)timezone;], ac_cv_var_timezone=yes, ac_cv_var_timezone=no)])
  if test "$ac_cv_var_altzone" = yes; then
    AC_DEFINE(HAVE_ALTZONE)
  fi
  if test "$ac_cv_var_timezone" = yes; then
    AC_DEFINE(HAVE_TIMEZONE)
  fi
fi
if test "x$ac_cv_var_altzone" = xno -a x$ac_cv_struct_tm_gmtoff = xno -a \
        "x$ac_cv_var_timezone" = xno ; then
  AC_MSG_RESULT([Aiee, autoconfig did not recognize timezone mechanism!  Time-zone offset calculation may give wrong results])
fi
])

AC_DEFUN(AC_STRUCT_SA_LEN,
[dnl
#
# Test to see, if we have BSD4.4  sa_len -field in the "struct sockaddr*"
#
AC_CACHE_CHECK([for 'sa_len' in 'struct sockaddr'], ac_cv_struct_sa_len,
[AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/socket.h>], [struct sockaddr sa; sa.sa_len = 0; ],
        ac_cv_struct_sa_len=yes, ac_cv_struct_sa_len=no)])
if test "$ac_cv_struct_sa_len" = yes; then
  AC_DEFINE(HAVE_SA_LEN)
fi
])

AC_DEFUN(AC_FUNC_SPRINTF,
[dnl
#
#  How the  sprintf()  really behaves ?
#  Does it return  char *, or integer counting stored chars ?
#
# Substitutes @DSPRINTF_TYPE@ definitions into Makefiles (-DSPRINTF_CHAR)
# Defines  SPRINTF_CHAR  for  config.h  in case the test yields "char *"..
#
AC_MSG_CHECKING([for the return type of sprintf() being char*])
AC_CACHE_VAL(ac_cv_func_char_sprintf,
 [AC_TRY_RUN([
    extern char *sprintf();
    int main()
    {
	char buf[20];
	char *ss = sprintf(buf,"xx");
	return (ss == buf); /* returns the char pointer */
    }],
    ac_cv_func_char_sprintf=no,
    ac_cv_func_char_sprintf=yes,
    ac_cv_func_char_sprintf=no)])
AC_MSG_RESULT([$ac_cv_func_char_sprintf])
AC_SUBST(DSPRINTF_TYPE)
if test $ac_cv_func_char_sprintf = yes; then
  AC_DEFINE(SPRINTF_CHAR)
  DSPRINTF_TYPE="-DSPRINTF_CHAR"
else
  DSPRINTF_TYPE=""
fi
])

AC_DEFUN(AC_STRUCT_DIRENT_D_INO,
[dnl
#
#  Is there  "d_ino"  within the  dirent structure ?
#  Defines  D_INO_IN_DIRENT  if it is.
#
AC_MSG_CHECKING([for d_ino member in directory struct])
AC_CACHE_VAL(fu_cv_sys_d_ino_in_dirent,
[AC_TRY_LINK([
#include <sys/types.h>
#ifdef HAVE_DIRENT_H
# include <dirent.h>
#else /* not HAVE_DIRENT_H */
# define dirent direct
# ifdef HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif /* HAVE_SYS_NDIR_H */
# ifdef HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif /* HAVE_SYS_DIR_H */
# ifdef HAVE_NDIR_H
#  include <ndir.h>
# endif /* HAVE_NDIR_H */
#endif /* HAVE_DIRENT_H */
],
  [struct dirent dp; dp.d_ino = 0;],
    fu_cv_sys_d_ino_in_dirent=yes,
    fu_cv_sys_d_ino_in_dirent=no)])
AC_MSG_RESULT($fu_cv_sys_d_ino_in_dirent)
if test $fu_cv_sys_d_ino_in_dirent = yes; then
  AC_DEFINE(D_INO_IN_DIRENT)
fi])

AC_DEFUN(AC_FUNC_SVR4_MAILLOCK,
[dnl
#
#  Test for SVR4  maillock()/mailunlock() mechanism (Solaris et.al.)
#  Substitutes  @LIBMAIL@
#  Defines HAVE_MAILLOCK or HAVE_DOTLOCK depending upon the result
#
AC_SUBST(LIBMAIL)
if test "x$ac_cv_func_maillock_lmail" = "x"; then
  if test "$ac_cv_header_maillock_h" = "yes" ; then
    t_oldLibs="$LIBS"
    LIBS="$LIBS -lmail"
    AC_TRY_LINK([#include <maillock.h>],[mailunlock();],[
	ac_cv_func_maillock_lmail=yes])
    LIBS="$t_oldLibs"
    if test "x$ac_cv_func_maillock_lmail" = "x"; then
      # On some Debian systems this exists as  -llockfile  :-/
      LIBS="$LIBS -llockfile"
      AC_TRY_LINK([#include <maillock.h>],[mailunlock();],[
		ac_cv_func_maillock_llockfile=yes])
      LIBS="$t_oldLibs"
    fi
  else
    ac_cv_func_maillock_lmail=no
    ac_cv_func_maillock_llockfile=no
  fi
fi
if test "$ac_cv_func_maillock_lmail" = "yes"; then
	AC_DEFINE(HAVE_MAILLOCK)
	LIBMAIL="-lmail"
	AC_MSG_RESULT([System has  maillock()  with -lmail])
else
  if test "$ac_cv_func_maillock_llockfile" = "yes"; then
	AC_DEFINE(HAVE_MAILLOCK)
	LIBMAIL="-llockfile"
	AC_MSG_RESULT([System has  maillock()  with -llockfile])
  else
	AC_DEFINE(HAVE_DOTLOCK)
	AC_MSG_RESULT([Using traditional UNIX 'dot-lock' mailbox locks])
  fi
fi])

AC_DEFUN(AC_STRUCT_ST_BLKSIZE,
[dnl
#
# Do we have "st_blksize" in the "struct stat" ?
# Defines  HAVE_ST_BLKSIZE  if we do
#
AC_CACHE_CHECK(for st_blksize in struct stat, ac_cv_struct_stat_st_blksize, [
AC_TRY_LINK([#include <sys/types.h>
#include <sys/stat.h>], [struct stat st; st.st_blksize; ],
		AC_DEFINE(HAVE_ST_BLKSIZE) ac_cv_struct_stat_st_blksize=yes)
])
])

AC_DEFUN(AC_FUNC_GETMNTENT_MORE,
[dnl
#
# Determine how to get the list of mounted filesystems.
#
# Defines one of:  MOUNTED_GETMNTENT1, MOUNTED_GETMNTENT2 MOUNTED_GETFSSTAT,
#		   MOUNTED_VMOUNT, MOUNTED_FREAD_FSTYP, MOUNTED_GETMNTINFO,
#		   MOUNTED_GETMNT, MOUNTED_FREAD
#

list_mounted_fs=

# If the getmntent function is available but not in the standard library,
# make sure LIBS contains -lsun (on Irix4) or -lseq (on PTX).
if test $ac_cv_func_getmntent = yes; then

  # This system has the getmntent function.
  # Determine whether it's the one-argument variant or the two-argument one.

  if test -z "$list_mounted_fs"; then
    # 4.3BSD, SunOS, HP-UX, Dynix, Irix
    AC_MSG_CHECKING([for one-argument getmntent function])
    AC_CACHE_VAL(fu_cv_sys_mounted_getmntent1,
		 [test $ac_cv_header_mntent_h = yes \
		   && fu_cv_sys_mounted_getmntent1=yes \
		   || fu_cv_sys_mounted_getmntent1=no])
    AC_MSG_RESULT($fu_cv_sys_mounted_getmntent1)
    if test $fu_cv_sys_mounted_getmntent1 = yes; then
      list_mounted_fs=found
      AC_DEFINE(MOUNTED_GETMNTENT1)
    fi
  fi

  if test -z "$list_mounted_fs"; then
    # SVR4
    AC_MSG_CHECKING([for two-argument getmntent function])
    AC_CACHE_VAL(fu_cv_sys_mounted_getmntent2,
    [AC_EGREP_HEADER(getmntent, sys/mnttab.h,
      fu_cv_sys_mounted_getmntent2=yes,
      fu_cv_sys_mounted_getmntent2=no)])
    AC_MSG_RESULT($fu_cv_sys_mounted_getmntent2)
    if test $fu_cv_sys_mounted_getmntent2 = yes; then
      list_mounted_fs=found
      AC_DEFINE(MOUNTED_GETMNTENT2)
    fi
  fi

  if test -z "$list_mounted_fs"; then
    AC_MSG_ERROR([could not determine how to read list of mounted filesystems])
  fi

fi

if test -z "$list_mounted_fs"; then
  # DEC Alpha running OSF/1.
  AC_MSG_CHECKING([for getfsstat function])
  AC_CACHE_VAL(fu_cv_sys_mounted_getsstat,
  [AC_TRY_LINK([
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/fs_types.h>],
  [struct statfs *stats;
  numsys = getfsstat ((struct statfs *)0, 0L, MNT_WAIT); ],
    fu_cv_sys_mounted_getsstat=yes,
    fu_cv_sys_mounted_getsstat=no)])
  AC_MSG_RESULT($fu_cv_sys_mounted_getsstat)
  if test $fu_cv_sys_mounted_getsstat = yes; then
    list_mounted_fs=found
    AC_DEFINE(MOUNTED_GETFSSTAT)
  fi
fi

if test -z "$list_mounted_fs"; then
  # AIX.
  AC_MSG_CHECKING([for mntctl function and struct vmount])
  AC_CACHE_VAL(fu_cv_sys_mounted_vmount,
  [AC_TRY_CPP([#include <fshelp.h>],
    fu_cv_sys_mounted_vmount=yes,
    fu_cv_sys_mounted_vmount=no)])
  AC_MSG_RESULT($fu_cv_sys_mounted_vmount)
  if test $fu_cv_sys_mounted_vmount = yes; then
    list_mounted_fs=found
    AC_DEFINE(MOUNTED_VMOUNT)
  fi
fi

if test -z "$list_mounted_fs"; then
  # SVR3
  AC_MSG_CHECKING([for FIXME existence of three headers])
  AC_CACHE_VAL(fu_cv_sys_mounted_fread_fstyp,
    [AC_TRY_CPP([
#include <sys/statfs.h>
#include <sys/fstyp.h>
#include <mnttab.h>],
		fu_cv_sys_mounted_fread_fstyp=yes,
		fu_cv_sys_mounted_fread_fstyp=no)])
  AC_MSG_RESULT($fu_cv_sys_mounted_fread_fstyp)
  if test $fu_cv_sys_mounted_fread_fstyp = yes; then
    list_mounted_fs=found
    AC_DEFINE(MOUNTED_FREAD_FSTYP)
  fi
fi

if test -z "$list_mounted_fs"; then
  # 4.4BSD and DEC OSF/1.
  AC_MSG_CHECKING([for getmntinfo function])
  AC_CACHE_VAL(fu_cv_sys_mounted_getmntinfo,
    [
      ok=
      if test $ac_cv_func_getmntinfo = yes; then
	AC_EGREP_HEADER(f_type;, sys/mount.h,
			ok=yes)
      fi
      test -n "$ok" \
	  && fu_cv_sys_mounted_getmntinfo=yes \
	  || fu_cv_sys_mounted_getmntinfo=no
    ])
  AC_MSG_RESULT($fu_cv_sys_mounted_getmntinfo)
  if test $fu_cv_sys_mounted_getmntinfo = yes; then
    list_mounted_fs=found
    AC_DEFINE(MOUNTED_GETMNTINFO)
  fi
fi

# FIXME: add a test for netbsd-1.1 here

if test -z "$list_mounted_fs"; then
  # Ultrix
  AC_MSG_CHECKING([for getmnt function])
  AC_CACHE_VAL(fu_cv_sys_mounted_getmnt,
    [AC_TRY_CPP([
#include <sys/fs_types.h>
#include <sys/mount.h>],
		fu_cv_sys_mounted_getmnt=yes,
		fu_cv_sys_mounted_getmnt=no)])
  AC_MSG_RESULT($fu_cv_sys_mounted_getmnt)
  if test $fu_cv_sys_mounted_getmnt = yes; then
    list_mounted_fs=found
    AC_DEFINE(MOUNTED_GETMNT)
  fi
fi

if test -z "$list_mounted_fs"; then
  # SVR2
  AC_MSG_CHECKING([whether it is possible to resort to fread on /etc/mnttab])
  AC_CACHE_VAL(fu_cv_sys_mounted_fread,
    [AC_TRY_CPP([#include <mnttab.h>],
		fu_cv_sys_mounted_fread=yes,
		fu_cv_sys_mounted_fread=no)])
  AC_MSG_RESULT($fu_cv_sys_mounted_fread)
  if test $fu_cv_sys_mounted_fread = yes; then
    list_mounted_fs=found
    AC_DEFINE(MOUNTED_FREAD)
  fi
fi

if test -z "$list_mounted_fs"; then
  AC_MSG_ERROR([could not determine how to read list of mounted filesystems])
  # FIXME -- no need to abort building the whole package
  # Can't build mountlist.c or anything that needs its functions
fi
])

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
    AC_DEFINE(STAT_STATVFS)
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
    AC_DEFINE(STAT_STATFS3_OSF1)
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
    AC_DEFINE(STAT_STATFS2_BSIZE)
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
    AC_DEFINE(STAT_STATFS4)
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
    AC_DEFINE(STAT_STATFS2_FSIZE)
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
    AC_DEFINE(STAT_STATFS2_FS_DATA)
  fi
fi

if test $space = no; then
# SVR2
AC_TRY_CPP([#include <sys/filsys.h>],
  AC_DEFINE(STAT_READ_FILSYS) space=yes)
fi
])
