/*
 *	Copyright 1992 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include <stdio.h>
#include "hostenv.h"

static char *Copyright = "Copyright 1992 Rayan S. Zachariassen";

void
prversion(progname)
	char *progname;
{
	extern char *Version, *CC_user, *CC_pwd;

	(void) fprintf(stderr, "ZMailer %s (%s)\n  %s:%s\n%s\n", progname,
			Version, CC_user, CC_pwd, Copyright);
}
