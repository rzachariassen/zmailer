/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * Support routine for the mail submission interface.  This file gets linked
 * in if the application doesn't define its own mail_alloc() routine.
 */
#include <stdio.h>
#include <sys/types.h>

#include "hostenv.h"
#include "zmalloc.h"
#include "libc.h"

void *
mail_alloc(nbytes)
	unsigned int nbytes;
{
	return (void*)malloc(nbytes);
}

void *
mail_realloc(oldptr,nbytes)
	unsigned int nbytes;
	void *oldptr;
{
	return (void*)realloc(oldptr,nbytes);
}

void
mail_free(s)
	void *s;
{
	free(s);
}
