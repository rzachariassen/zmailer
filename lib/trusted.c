/*
 *	Copyright 1988 by Rayan Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *	This file is mostly the work of Dennis Ferguson.  Thanks Dennis.
 */

/*
 * settrusteduser, runastrusteduser - if running as root, setuid to
 *	a nonroot but trusted (by mail) user, if not running as root
 *	ignore any effect of a setuid bit.
 */

#include "hostenv.h"
#include "mailer.h"
#include <ctype.h>
#include <pwd.h>
#include <errno.h>
#include "libz.h"
#include "libc.h"

#define	DEFTRUSTEDUSER	"daemon"	/* default trusted user if no other */

static int trusteduid = -1;	/* set to trusted uid if we find it */

/*
 * As far as I know, BSD systems are the only ones which allow you
 * to undo the effects of a setuid to a nonroot user.  This stores
 * the original real uid mostly for this purpose.
 */
static int origruid;

/*
 * settrusteduser - find the trusted uid if we can
 */
void
settrusteduser()
{
	const char *trusteduser;
	struct Zpasswd *pw;

	if ((trusteduser = getzenv("TRUSTEDUSER")) == NULL)
		trusteduser = DEFTRUSTEDUSER;
	if (isascii(*trusteduser) && isdigit(*trusteduser)) {
		int n = atoi(trusteduser);
		if (n > 0) {
			trusteduid = n;
			return;
		}
	}
	errno = 0;
	pw = zgetpwnam(trusteduser);
	if (pw == NULL) {
		trusteduid = 0;		/* can't do anything, run as root */
		return;
	}
	trusteduid = pw->pw_uid;
}

/*
 * runastrusteduser - setuid us to the user ID with minimal loss of security
 *	(i.e. invoking user if not root, trusted user if root).  This should
 *	be done reversibly if possible.  This routine should never be called
 *	twice without an intervening call to runasrootuser().
 */
int
runastrusteduser()
{
	int uid;

	uid = geteuid();
	origruid = getuid();	/* this may be wrong if called 2nd time */
	if (origruid != 0 && origruid != uid)
		trusteduid = origruid;
	else if (uid != 0)
		return uid;		/* forget it.  No need, no way */
	if (trusteduid == -1)
		settrusteduser();
	if (trusteduid == 0)
		return 0;		/* trusted uid not found */
	setuid(0);			/* set real uid to root */
	setreuid(-1, trusteduid);	/* set euid to trusted */

	return trusteduid;
}

/*
 * runasrootuser - undo what was done by runastrusteduser()
 */
void
runasrootuser()
{
	if (trusteduid <= 0)
		return;			/* nothing done before */

	setreuid(-1, 0);		/* make us effectively root */
	setuid(origruid);		/* reset to old real uid */
}
