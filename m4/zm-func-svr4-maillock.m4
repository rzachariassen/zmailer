#
#  Local hacks for ZMailer with  GNU autoconfig 2.12
#

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
	AC_DEFINE(HAVE_MAILLOCK,1,[Have maillock() in -lmail])
	LIBMAIL="-lmail"
	AC_MSG_RESULT([System has  maillock()  with -lmail])
else
  if test "$ac_cv_func_maillock_llockfile" = "yes"; then
	AC_DEFINE(HAVE_MAILLOCK,1,[Have maillock() in -llockfile])
	LIBMAIL="-llockfile"
	AC_MSG_RESULT([System has  maillock()  with -llockfile])
  else
	AC_DEFINE(HAVE_DOTLOCK,1,[Using traditional UNIX 'dot-lock' mailbox locks])
	AC_MSG_RESULT([Using traditional UNIX 'dot-lock' mailbox locks])
  fi
fi])

