#
#  Local hacks for ZMailer with  GNU autoconfig 2.12
#

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
  AC_DEFINE(SPRINTF_CHAR,1,[The sprinf() function returns a char*])
  DSPRINTF_TYPE="-DSPRINTF_CHAR"
else
  DSPRINTF_TYPE=""
fi
])

