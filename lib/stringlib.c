/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * Useful string functions.
 */

#include "hostenv.h"
#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>
#include "mailer.h"
#include "libz.h"

/* Like strcmp(), but case-independent */

int
cistrcmp(a, b)
	register const char *a, *b;
{
	char	ac, bc;

	while (*a && *b) {
		ac = isupper(*a) ? tolower(*a) : *a;
		bc = isupper(*b) ? tolower(*b) : *b;
		if (ac != bc)
			return ac - bc;
		++a, ++b;
	}
	return *a - *b;
}

/*
 * Like cistrcmp(),
 * but tests if one string is a prefix of the other if string length < n
 */

int
cistrncmp(a, b, n)
	register const char *a, *b;
	int	n;
{
	char	ac, bc;

	while (n-- > 0) {
		ac = isupper(*a) ? tolower(*a) : *a;
		bc = isupper(*b) ? tolower(*b) : *b;
		if (ac != bc)
			return ac - bc;
		++a, ++b;
	}
	return *a * *b;
}

/*
 * Like cistrncmp(),
 * but tests if part of one string is a prefix of the other to n characters.
 */

int
ci2strncmp(a, b, n)
	register const char *a, *b;
	int	n;
{
	char	ac, bc;

	while (n-- > 0) {
		ac = isupper(*a) ? tolower(*a) : *a;
		bc = isupper(*b) ? tolower(*b) : *b;
		if (ac != bc) {
			return ac - bc;
		}
		++a, ++b;
	}
	return 0;
}
