#ifndef	__
# ifdef __STDC__
#  define __(x) x
# else
#  define __(x) ()
#  define const
#  define volatile
# endif
#endif

#define MAILER 1

#include "mailer.h"
#include "interpret.h"

#include <stdio.h>
#include "io.h"		/* include after <stdio.h>  */

#include <sys/file.h>			/* O_RDONLY for run_praliases() */
#include <pwd.h>			/* for run_homedir() */
#include <grp.h>			/* for run_grpmems() */
#include <ctype.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>

#include "sysexits.h"
#include "mail.h"
#include "zsyslog.h"
#include "zmsignal.h"
#include "splay.h"
#include "prototypes.h"
#include "shmmib.h"

#include "libz.h"
#include "libsh.h"
#include "libc.h"

#ifdef  USE_SETUIDX	/* IBM AIXism */
# include <sys/id.h>
# ifdef USE_SETREUID
#  define  setreuid(x,y) setuidx(ID_REAL|ID_EFFECTIVE, y)
# else /* !USE_SETREUID */
#  define  setuid(y)     setuidx(ID_REAL|ID_EFFECTIVE, y)
# endif
#endif


#ifndef _IOFBF
#define _IOFBF  0
#endif  /* !_IOFBF */

#ifndef _IOLBF
#define _IOLBF  0200
#endif  /* !_IOFBF */

#ifdef	HAVE_LOCKF
#ifdef	F_OK
#undef	F_OK
#endif	/* F_OK */
#ifdef	X_OK
#undef	X_OK
#endif	/* X_OK */
#ifdef	W_OK
#undef	W_OK
#endif	/* W_OK */
#ifdef	R_OK
#undef	R_OK
#endif	/* R_OK */

#endif	/* HAVE_LOCKF */
