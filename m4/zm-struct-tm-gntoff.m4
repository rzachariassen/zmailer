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
  AC_DEFINE(HAVE_TM_GMTOFF,1,[The  struct tm  has field  tm_gmtoff])
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
    AC_DEFINE(HAVE_ALTZONE,1,[Timezone offset variable 'altzone' exists])
  fi
  if test "$ac_cv_var_timezone" = yes; then
    AC_DEFINE(HAVE_TIMEZONE,1,[Timezone offset variable 'timezone' exists])
  fi
fi
if test "x$ac_cv_var_altzone" = xno -a x$ac_cv_struct_tm_gmtoff = xno -a \
        "x$ac_cv_var_timezone" = xno ; then
  AC_MSG_RESULT([Aiee, autoconfig did not recognize timezone mechanism!  Time-zone offset calculation may give wrong results])
fi
])
