#ifndef	__HOSTENV__
#define	__HOSTENV__

/* #ifdef HAVE_CONFIG_H */
#include "config.h" /* We have this always.. */
/* #endif */

#ifdef HAVE_FCNTL_H
# define FCNTL_H <fcntl.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef __GNUC__
# define alloca __builtin_alloca
# define HAVE_ALLOCA 1
#else
# if HAVE_ALLOCA_H
#  include <alloca.h>
#  define HAVE_ALLOCA 1
# else
#  ifdef _AIX
 #pragma alloca
#   define HAVE_ALLOCA 1
#  else
	/* no alloca() .. */
#  endif
# endif
#endif

#ifdef HAVE_ALLOCA
# define USE_ALLOCA HAVE_ALLOCA
#endif

#include <sys/types.h>
#ifdef __linux__ /* Linux libc-4 needs this, libc-5 doesn't.. */
# include <linux/limits.h>
#endif
#include <sys/param.h> /* Troublepotential: If somebody does not have it ? */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

/* There are systems which store the stdio fp contained fileno into
   a SIGNED CHARACTER, and simple-minded  fileno() will therefore
   pick an FD of over 127 as negative number..  We provide a wrapper
   for such in case by case basis.. */

#ifndef FILENO
# if defined(sun) && !defined(__svr4__)
#  define FILENO(x) (((unsigned)fileno(x)) & 0xFF)
# else
#  define FILENO(x) fileno(x)
# endif
#endif

#ifndef	__
# ifndef __STDC__
#  define __(x) ()
#  ifdef __GNUC__
#   ifndef const
#    define const    __const
#   endif
#   define volatile __volatile
#  else
#   define const
#   define volatile
#  endif
# else
#  define __(x) x
# endif
#endif

#include "sysprotos.h"

#endif	/* !__HOSTENV__ */
