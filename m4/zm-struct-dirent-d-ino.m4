#
#  Local hacks for ZMailer with  GNU autoconfig 2.12
#

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
  AC_DEFINE(D_INO_IN_DIRENT,1,[The dirent structure has d_ino field.])
fi])

