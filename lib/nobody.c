/*
 *	Copyright 1988 by Rayan Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include "hostenv.h"
#include "mailer.h"
#include <stdio.h>
#include <errno.h>
#include "libz.h"
#include "libc.h"
#include <ctype.h>
#include <pwd.h>
#ifdef	__svr4__
#include <sys/param.h>
#endif

/*
 * Routine to initialize the 'nobody' variable to contain a nonprivileged uid.
 *
 * There are three choices:
 * 1. Whatever is specified by the NOBODY key in the /etc/zmailer.conf file
 * 2. The uid of the 'nobody' user if any
 * 3. -2 if that works
 * 4. MAX_SIGNED_SHORT otherwise
 */


const char *nouser = "nobody";
#ifdef	UID_NOBODY
int nobody = UID_NOBODY;
#else
int nobody = -2;
#endif

static int nobodies[] = {
	0,
#ifdef	UID_NOBODY
	UID_NOBODY,
#else
	-2,
#endif
	29999,
	0
};

static int didnobody = 0;

extern int getnobody __((void));

int
getnobody()
{
	int i, factor = 1;
	struct Zpasswd *pw;
	const char *s;

	if (didnobody)
		return nobody;

	if ((s = getzenv("NOBODY")) != NULL) {
		while (*s == '-')
			factor = -1, ++s;
		errno = 0;
		if (isdigit(*s) && atoi(s) != 0) {
			nobody = atoi(s) * factor;
			goto done;
		}
		errno = 0;
		if (isalpha(*s) && (pw = zgetpwnam(s)) != NULL) {
			nobody = pw->pw_uid;
			goto done;
		}
	}

	errno = 0;
	pw = zgetpwnam(nouser);
	if (pw != NULL) {
		nobody = pw->pw_uid;
		goto done;
	}

	if (getuid() != 0)	/* it doesn't matter anyway */
		goto done;

	/* check that we can seteuid(nobody) */
	i = -1;
	while (nobodies[++i] != 0) {
		if (SETEUID(nobodies[i]) == 0)
			break;
	}

	if (nobodies[i] == 0) {
		perror("setuid");
		fprintf(stderr, "Cannot determine 'nobody' uid\n");
		exit(2);
	}
	if (SETEUID(0) < 0 || getuid() != 0) {
		perror("setuid");
		fprintf(stderr, "Cannot reset root uid\n");
		exit(3);
	}

	nobody = nobodies[i];
done:
	didnobody = 1;
	return nobody;
	
}

