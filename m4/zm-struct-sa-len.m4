#
#  Local hacks for ZMailer with  GNU autoconfig 2.12
#

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
  AC_DEFINE(HAVE_SA_LEN,1,[The  struct sockaddr  has field  sa_len])
fi
])
