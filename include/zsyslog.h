#ifdef HAVE_SYSLOG_H

#include <syslog.h>

#ifndef	LOG_ALERT
#endif	/* LOG_ALERT */
#ifndef	LOG_ERR
#endif	/* LOG_ERR */
#ifndef	LOG_NOTICE
#endif	/* LOG_NOTICE */
#ifndef	LOG_INFO
#endif	/* LOG_INFO */

#ifndef LOG_SALERT
# define LOG_SALERT LOG_ALERT
#endif

# define zopenlog(ident,stat,fac)  openlog(ident,stat,fac)
# define zcloselog                 closelog
# define zsyslog(params)           syslog params

#else

/* DAMN!  Some (ancient) compilers would barf even with  #error
   here on this part... */

#endif
