/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include "hostenv.h"
#include <stdio.h>

#ifndef strchr
extern char *strchr();
#endif

#include "ta.h"

int
emptyline(line, size)
	char *line;
	int size;
{
	char *s;

	if (line[0] == '\0' || line[0] == '\n')
		return 1;
	line[size - 1] = '\0';
	if ((s = strchr(line, '\n')) == NULL)
		return 1;
	*s = '\0';
	return 0;
}

