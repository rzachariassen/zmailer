/*
 *	Copyright 1989 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * Job control control.
 */

#include "hostenv.h"
#include <stdio.h>
#include <sys/stat.h>
#include "listutils.h"
#include "io.h"
#include "shconfig.h"

#include "libsh.h"

int lastbgpid = 0;

/*
 * We're finished forking things, now report to the user.
 */

void
jc_report(pgrp)
	int pgrp;
{
	/*
	 * Note the number reported will be the id of the first process in
	 * a pipeline, not the last one like the standard sh will report.
	 */
	printf("%d\n", pgrp);
}


/*
 * A new process just started associated with the indicated process group.
 */

void
jc_newproc(pgrpp, pid, argc, argv)
	int *pgrpp, pid, argc;
	const char *argv[];
{
	if (*pgrpp == 0)
		*pgrpp = pid;
	lastbgpid = pid;
#ifdef	JOBCONTROL
	setpgrp(pid, *pgrpp);
#endif	/* JOBCONTROL */
}
