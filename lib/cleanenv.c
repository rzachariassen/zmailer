/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * A routine to clean out the environment from strings that the mail_*()
 * library pays attention to.  This is usually only called from detach()
 * since all the daemons call that at an appropriate time.  Transport
 * agents usually don't need to call this since the scheduler already has.
 */

#include "mailer.h"
#include "libz.h"

extern char **environ;

const char *nukelist[] = { "LOGNAME", "USER", "FULLNAME", "PRETTYLOGIN",
			   "IFS", (char *)0 };

void
cleanenv()
{
	const char **np;
	const char **ep;

	for (ep = (const char **)environ; *ep != NULL; ++ep) {
		for (np = nukelist; *np != NULL; ++np) {
			int len = strlen(*np);
			if (strncmp(*np, *ep, len) == 0 && (*ep)[len] == '=')
				*ep = "SHELL=/bin/sh";
		}
	}
}
