/*
 *	Copyright 1992 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */
/*
 *	A lot of changes all around over the years by Matti Aarnio
 *	<mea@nic.funet.fi> (and elsewere), copyright 1992-2000
 */

#include "mailer.h"
#include "libz.h"
#include "libsh.h"

static const char *Copyright = "Copyright 1992 Rayan S. Zachariassen\n\
Copyright 1992-2000 Matti Aarnio";

void
prversion(prgname)
	const char *prgname;
{
	fprintf(stderr, "ZMailer %s (%s)\n  %s:%s\n%s\n", prgname,
		Version, CC_user, CC_pwd, Copyright);
	fprintf(stderr, "Configured with command: '%s'\n",
		CONFIGURE_CMD);
}
