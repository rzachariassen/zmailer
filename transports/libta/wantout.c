/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include "hostenv.h"

int getout = 0;

RETSIGTYPE
wantout(sig)
int sig;
{
	getout = 1;
}

