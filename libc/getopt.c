/*
 * getopt - get option letter from argv
 *
 * This is a version of the public domain getopt() implementation by
 * Henry Spencer, changed for 4.3BSD compatibility (in addition to System V).
 * It allows rescanning of an option list by setting optind to 1 before
 * calling.  Thanks to Dennis Ferguson for the appropriate modifications.
 *
 * This file is in the Public Domain.
 */

/*LINTLIBRARY*/

#include "hostenv.h"
#include <stdio.h>

#ifdef	lint
#undef	putc
#define	putc	fputc
#endif	/* lint */

char	*zoptarg;	/* Global argument pointer. */
int	zoptind = 1;	/* Global argv index. */

/*
 * N.B. use following at own risk
 */
int	zopterr = 1;	/* for compatibility, should error be printed? */
int	zoptopt;	/* for compatibility, option character checked */

static char	*scan = NULL;	/* Private scan pointer. */

/*
 * Print message about a bad option.  Watch this definition, it's
 * not a single statement.
 */
#define	BADOPT(mess, ch)	if (zopterr) { \
					extern int fputs(), fputc(); \
					(void) fputs(argv[0], stderr); \
					(void) fputs(mess, stderr); \
					(void) fputc(ch, stderr); \
					(void) fputc('\n', stderr); \
				} \
				return('?')

int
zgetopt(argc, argv, optstring)
	int argc;
	char *const argv[];
	const char *optstring;
{
	register char c;
	register const char *place;

	zoptarg = NULL;

	if (zoptind == 1)
		scan = NULL;
	
	if (scan == NULL || *scan == '\0') {

		if (zoptind >= argc || argv[zoptind][0] != '-' || argv[zoptind][1] == '\0')
			return EOF;

		if (argv[zoptind][1] == '-' && argv[zoptind][2] == '\0') {
			zoptind++;
			return EOF;
		}
	
		scan = argv[zoptind]+1;
		zoptind++;
	}

	c = *scan++;
	zoptopt = c & 0377;

	for (place = optstring; place != NULL && *place != '\0'; ++place) {
		if (*place == c)
			break;
		if (place[1] == ':')
			++place;
	}

	if (place == NULL || *place == '\0' || c == '?') {
		BADOPT(": unknown option -", c);
	}

	place++;
	if (*place == ':') {
		if (*scan != '\0') {
			zoptarg = scan;
			scan = NULL;
		} else if (zoptind >= argc) {
			BADOPT(": option requires argument -", c);
		} else {
			zoptarg = argv[zoptind];
			zoptind++;
		}
	}

	return c&0377;
}
