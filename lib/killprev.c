/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include "hostenv.h"
#include "mailer.h"
#include "zmsignal.h" /* used for kill(2) */
#include "libz.h"
#include "libc.h"

#ifndef	_IOFBF
#define	_IOFBF	0
#endif	/* !_IOFBF */

/* send a signal to an already-running daemon process or process group */

int
killprevious(sig, pidfile)
	int sig;
	const char *pidfile;
{
	int c, rc;
	FILE *fp;
	char *path, buf[128];

	path = emalloc((unsigned)(strlen(postoffice) + strlen(pidfile) + 2));
	sprintf(path, "%s/%s", postoffice, pidfile);
	if (sig != 0 && (fp = fopen(path, "r")) != NULL) {
		setvbuf(fp, buf, _IOFBF, sizeof buf);
		if (fscanf(fp, "%d", &c) != 1)
			fprintf(stderr,
				"couln't make sense of contents of %s!\n",
				path);
		else if (c == getpid())
			printf("was about to commit suicide\n");
		else if ((sig < 0 && kill(-c, -sig) == 0 && sig == -SIGTERM)
			 || (sig > 0 && kill(c, sig) == 0 && sig == SIGTERM)) {
			printf("killed previous daemon%s = %d\n",
			       (sig > 0) ? ", pid" : "s, pgrp", c);
			sleep(5); /* Give process time to die */
		}
		fclose(fp);
	}
	rc = 0;
	if ((sig == 0 || sig == SIGTERM || -sig == SIGTERM)
	    && (fp = fopen(path, "w+")) != NULL) {
		setvbuf(fp, buf, _IOFBF, sizeof buf);
		fprintf(fp, "%d\n", getpid());
		rc = fflush(fp);
		if (fclose(fp) != 0)
		  rc |= 1; /* indicate error */
		if (rc != 0)
		  unlink(path);
	}
	free(path);
	return rc;
}
