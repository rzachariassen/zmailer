/*
 *	Copyright 1989 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * Caching and printing of the PS1/PS2 prompt strings.
 */

#include "hostenv.h"
#include <stdio.h>
#include <sys/stat.h>
#include "listutils.h"
#include "shconfig.h"

#include "libsh.h"

STATIC char *ps1 = NULL;
STATIC char *ps2 = NULL;

void
prompt_print()
{
	if (funcall(PS1) < 0 && ps1 != NULL)
		printf("%s", ps1);
}

void
prompt_flush()
{
	conscell *d = v_find(PS1);

	if (d == NULL || cdr(d) == NULL || LIST(cdr(d))
	    || *(ps1 = (char *)cdr(d)->string) == '\0')
		ps1 = NULL;
}

void
prompt2_print()
{
	if (funcall(PS2) < 0 && ps2 != NULL)
		printf("%s", ps2);
}

void
prompt2_flush()
{
	conscell *d = v_find(PS2);

	if (d == NULL || cdr(d) == NULL || LIST(cdr(d))
	    || *(ps2 = (char *)cdr(d)->string) == '\0')
		ps2 = NULL;
}

