/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include <stdio.h>
#include "hostenv.h"
#ifdef	HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif	/* UTSNAME_H */

#include "ta.h"

int
getmyuucpname(namebuf, len)
	char *namebuf;
	int len;
{
#ifdef	HAVE_SYS_UTSNAME_H
	struct utsname id;

	if (uname(&id) < 0)
		return -1;
	if (strlen(id.nodename) < len)
		(void) strcpy(namebuf, id.nodename);
#else	/* !UTSNAME_H */

	FILE *fp;

	namebuf[len-1] = '\0';
	if (((fp = fopen("/etc/name.uucp", "r")) == NULL
	     && (fp = fopen("/etc/uucpname", "r")) == NULL)
	    || fgets(namebuf, len, fp) == NULL
	    || namebuf[len-1] != '\0') {
		return gethostname(namebuf, len);
	}
	(void) fclose(fp);
	if (namebuf[strlen(namebuf)-1] == '\n')
		namebuf[strlen(namebuf)-1] = '\0';
#endif	/* UTSNAME_H */
	return 0;
}
