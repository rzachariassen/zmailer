/*
 *  Copyright (c) 1986 by The Governing Council of the University of Toronto.
 *  Authored by Rayan Zachariassen for University of Toronto Computing Services.
 */

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>

#ifndef TRUE
#define TRUE 1
#endif

/*
 * Copy the message on stdin to the fp output.
 *
 * This routine should:
 *	- fold message header lines according to rfc822, by prepending a tab
 *	  to each continuation line and breaking it at the right place.
 *	- fold message body lines, prepending a '+ ' to each continuation line.
 *	- ensure message terminates with a newline.
 *	- escape '.'s in the first column of body lines by prepending a '.'
 */

copydata(fp)
FILE *fp;
{
	register char *cp, *s;
	register int	n;
	char	buf[BUFSIZ], linebuf[BUFSIZ];

	s = linebuf;
	while ((n = fread(buf, 1, sizeof buf, stdin)) > 0) {
		for (cp = buf; n-- > 0; ++cp) {
			if (*cp == '\n' || s - linebuf >= BUFSIZ - 5) {
				*s = '\0';
				doline(linebuf, fp);
				s = linebuf;
				continue;
			} else if (*cp != '\t' && (*cp < ' ' || *cp > '\176')) {
				if (*cp & 0200) {
					*s++ = 'M';
					*s++ = '-';
					*cp &= ~0200;
				}
				if (*cp != '\t' && (*cp < ' ' || *cp > '\176')){
					*s++ = '~';
					*cp = (*cp + 0100)&~0200;
				}
			}
			*s++ = *cp;
		}
	}
	if (s > linebuf) {
		*s = '\0';
		doline(linebuf, fp);
	}
}

doline(buf, fp)
char	buf[];
FILE	*fp;
{
	register char *cp, *s;
	register int col;
	int maxwidth;
	char *ocp, *cutoff, *semicolon, *nonalnum;
	static int inheader = 1;

	/* find end of line, not including trailing blanks */
	for (cp = buf; *cp != NULL; cp++)
		continue;
	while (*--cp == ' ')
		continue;
	*++cp = '\0';

	/* a blank line separates header from body */
	if (inheader && cp == buf)
		inheader = 0;

	maxwidth = 80;
	ocp = buf;
	if (inheader) {
		do {
			col = 1;
			semicolon = nonalnum = NULL;
			for (s = ocp; s < cp && col <= maxwidth; s++) {
				if (*s == ';')
					semicolon = s;
				else if (isascii(*s) && !isalnum(*s))
					nonalnum = s;
				if (*s == '\t')
					col = ((col + 7)>>3)<<3;
				col++;
			}
			if (s >= cp) {
				fputs(ocp, fp);
				fputs("\n", fp);
				return;
			}
			if (semicolon > ocp)
				cutoff = ++semicolon;
			else if (nonalnum)
				cutoff = ++nonalnum;
			else
				cutoff = (ocp + maxwidth > cp) ? cp :
						ocp + maxwidth;
			fwrite(ocp, 1, cutoff - ocp, fp);
			ocp = cutoff;
			while (*ocp == ' ')
				ocp++;
			fputs("\n\t", fp);
			maxwidth = 72;	/* 80 - tab */
		} while (TRUE);
	} else {
		/* escape dot in first column by adding another one */
		if (*ocp == '.') {
			fputs(".", fp);
			--maxwidth;
		}

		/* handle line continuation for lines >80 columns */
		do {
			cutoff = NULL;
			col = 1;
			for (s = ocp; s<cp && col <= maxwidth; s++) {
				if (isascii(*s) && !isalnum(*s))
					cutoff = s;
				if (*s == '\t')
					col = ((col + 7)>>3)<<3;
				col++;
			}
			/* line done? */
			if (s == cp) {
				fputs(ocp, fp);
				fputs("\n", fp);
				return;
			}
			if (cutoff < ocp)
				cutoff = (ocp + maxwidth > cp) ? cp :
						ocp + maxwidth;
			else
				cutoff++;
			fwrite(ocp, 1, cutoff - ocp, fp);
			ocp = cutoff;

			/* '+ ' indicates line continuation */
			fputs("\n+ ", fp);
			maxwidth = 78;	/* 80 - '+ ' */
		} while (TRUE);
	}
}
