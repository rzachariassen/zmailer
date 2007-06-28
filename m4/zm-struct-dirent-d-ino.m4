dnl #
dnl #  Local hacks for ZMailer with  GNU autoconfig 2.12
dnl #
dnl 
dnl AC_DEFUN(AC_STRUCT_DIRENT_D_INO,
dnl [dnl
dnl #
dnl #  Is there  "d_ino"  within the  dirent structure ?
dnl #  Defines  D_INO_IN_DIRENT  if it is.
dnl #
dnl AC_MSG_CHECKING([for d_ino member in directory struct])
dnl AC_CACHE_VAL(fu_cv_sys_d_ino_in_dirent,
dnl [AC_TRY_LINK([
dnl #include <sys/types.h>
dnl #ifdef HAVE_DIRENT_H
dnl # include <dirent.h>
dnl #else /* not HAVE_DIRENT_H */
dnl # define dirent direct
dnl # ifdef HAVE_SYS_NDIR_H
dnl #  include <sys/ndir.h>
dnl # endif /* HAVE_SYS_NDIR_H */
dnl # ifdef HAVE_SYS_DIR_H
dnl #  include <sys/dir.h>
dnl # endif /* HAVE_SYS_DIR_H */
dnl # ifdef HAVE_NDIR_H
dnl #  include <ndir.h>
dnl # endif /* HAVE_NDIR_H */
dnl #endif /* HAVE_DIRENT_H */
dnl ],
dnl   [struct dirent dp; dp.d_ino = 0;],
dnl     fu_cv_sys_d_ino_in_dirent=yes,
dnl     fu_cv_sys_d_ino_in_dirent=no)])
dnl AC_MSG_RESULT($fu_cv_sys_d_ino_in_dirent)
dnl if test $fu_cv_sys_d_ino_in_dirent = yes; then
dnl   AC_DEFINE(D_INO_IN_DIRENT,1,[The dirent structure has d_ino field.])
dnl fi])
dnl 
