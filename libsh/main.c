/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include "hostenv.h"
#include <stdio.h>
#include <sys/stat.h>

int D_alloc = 0;

#ifdef	MAILER
int D_regnarrate = 0, D_compare = 0, D_matched = 0, D_functions = 0;
int D_assign = 0;
int funclevel = 0;

#include "listutils.h"
conscell **return_valuep = 0;
#endif	/* MAILER */

#include "libsh.h"

extern int optind;

int
main(argc, argv)
	int argc;
	char *argv[];
{
	/* mal_debug(3); */
	zshinit(argc, argv);
	/* mal_leaktrace(1); */
	trapexit(zshtoplevel(optind < argc ? argv[optind] : (char *)NULL));
	/* NOTREACHED */
	return 0;
}

