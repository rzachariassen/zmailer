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

char	*optarg;	/* Global argument pointer. */
int	optind = 1;	/* Global argv index. */

/*
 * N.B. use following at own risk
 */
int	opterr = 1;	/* for compatibility, should error be printed? */
int	optopt;		/* for compatibility, option character checked */

static char	*scan = NULL;	/* Private scan pointer. */

/*
 * Print message about a bad option.  Watch this definition, it's
 * not a single statement.
 */
#define	BADOPT(mess, ch)	if (opterr) { \
					extern int fputs(), fputc(); \
					(void) fputs(argv[0], stderr); \
					(void) fputs(mess, stderr); \
					(void) fputc(ch, stderr); \
					(void) fputc('\n', stderr); \
				} \
				return('?')

int
getopt(argc, argv, optstring)
	int argc;
	char *const argv[];
	const char *optstring;
{
	register char c;
	register const char *place;

	optarg = NULL;

	if (optind == 1)
		scan = NULL;
	
	if (scan == NULL || *scan == '\0') {
		if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == '\0')
			return EOF;
		if (argv[optind][1] == '-' && argv[optind][2] == '\0') {
			optind++;
			return EOF;
		}
	
		scan = argv[optind]+1;
		optind++;
	}

	c = *scan++;
	optopt = c & 0377;
	for (place = optstring; place != NULL && *place != '\0'; ++place)
		if (*place == c)
			break;

	if (place == NULL || *place == '\0' || c == ':' || c == '?') {
		BADOPT(": unknown option -", c);
	}

	place++;
	if (*place == ':') {
		if (*scan != '\0') {
			optarg = scan;
			scan = NULL;
		} else if (optind >= argc) {
			BADOPT(": option requires argument -", c);
		} else {
			optarg = argv[optind];
			optind++;
		}
	}

	return c&0377;
}
