/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * Sh-style globbing is done by this function.
 *
 * Notice that the shell uses a very similar function glob_match()
 * (they should be kept synchronized) that uses integer arrays to hold
 * the characters.
 */

#include <sys/types.h>

#ifndef __STDC__
#define const /* no const withot ANSI-C ?? */
#endif

int
strmatch(pattern, term)
	register const char	*pattern, *term;
{
	register int sense;
	register u_char c, c2;

	while (1)
		switch (*pattern) {
		case '*':
			pattern++;
			do {
			  if (strmatch(pattern, term))
			    return 1;
			} while (*term++ != '\0');
			return 0;

		case '\\':
			if (*term == 0) return 0;
			++pattern;
			if (*pattern == 0) return 0;
			if (*pattern != *term) return 0;
			++pattern; ++term;
			break;

		case '[':
			if (*term == '\0')
			  return 0;
			sense = (*(pattern+1) != '!');
			if (!sense)
			  ++pattern;
			while ((*++pattern != ']') && (*pattern != *term)) {
			  if (*pattern == '\0')
			    return !sense;
			  if (*(pattern+1) == '-') {
			    c2 = (*(pattern+2)) & 0xFF;
			    if (c2 != ']' && c2!='\0') {
			      c2 = (c2 < 128) ? c2 : 127;
			      c = ((*pattern) +1) & 0xFF;
			      for (; c <= c2; ++c)
				if (c == *term) {
				  if (sense)
				    goto ok;
				  else
				    return 0;
				}
			      pattern += 2;
			    }
			  }
			}
			if ((*pattern == ']') == sense)
			  return 0;
ok:
			while (*pattern++ != ']')
			  if (*pattern == '\0')
			    return 0;
			term++;
			break;

		case '?':
			pattern++;
			if (*term++ == '\0')
			  return 0;
			break;

		case '\0':
			return (*term == '\0');

		default:
			if (*pattern++ != *term++)
			  return 0;
			break;
		}
}
