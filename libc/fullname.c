/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*LINTLIBRARY*/

#include <stdio.h>
#include <ctype.h>

#ifndef __STDC__
#define const
#endif


extern char *getenv();


/*
 * Return a pretty, and properly quoted, Full Name as listed in the passwd file.
 * Berkeley conventions are obeyed.
 */

char *
fullname(s, buf, buflen, up)
	const char *s;		/* the name we wish to quotify */
	char buf[];		/* place to put the result */
	int buflen;		/* how much space we have */
	const char *up;		/* what to use for a login name */
{
	register char *cp, *eob;
	int mustquote;

	mustquote = 0;
	eob = buf + buflen - 1;
	for (cp = buf; cp < eob && *s != '\0' && *s != ','; ++s) {
		switch (*s) {
		case '&':
			if (up == NULL && (up = getenv("USER")) == NULL)
				up = getenv("LOGNAME");
			if (up != NULL) {
				if (isascii(*up) && islower(*up))
					*cp = toupper(*up);
				else
					*cp = *up;
				/* we assume login names are alphanumerical */
				for (++up, ++cp; *up != '\0' && cp < eob; ++up)
					*cp++ = *up;
			}
			break;
		case '"':
			if (!mustquote) {
				mustquote = 1;
				eob -= 2;
			}
			/*
			 * We don't want to end up with just a \ at
			 * the end of the name, so make sure there is
			 * room for both characters.
			 */
			if (cp < eob-1) {
				*cp++ = '\\';
				*cp++ = *s;
			}
			break;
		case '.':
		case '(': case ')':
		case '<': case '>':
		case '[': case ']':
		case '@':
		case ';':
		case ':':
		case '\\':
			if (!mustquote) {
				mustquote = 1;
				eob -= 2;
			}
			/* fall through */
		default:
			*cp++ = *s;
			break;
		}
	}
	if (mustquote) {
		cp = (cp > eob) ? eob : cp;
		*(cp+1) = '"';
		*(cp+2) = '\0';
		for (s = cp-1; s >= &buf[0]; --s, --cp)
			*cp = *s;
		buf[0] = '"';
	} else {
		*cp = '\0';
	}
	return buf;
}

