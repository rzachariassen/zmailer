/*
 * mhsend - quick replacement for mhsend for zmailer
 * ignore .mh_profile for now, just copy file to zmailer
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "mail.h"

#define STREQ(s,t) (*(s)==*(t) && strcmp(s, t)==0)

char *progname;
int debug = 0, verbose = 0;
FILE *efopen();
struct stat statbuf;
void exit();

/*
 * main - parse arguments and handle options
 */
main(argc, argv)
int argc;
char *argv[];
{
	int c, errflg = 0;
	FILE *in;
	extern int optind;
	extern char *optarg;

	progname = argv[0];

	/* use getopt, means you can only use single-letter arguments...
	 * probably a feature...
	 */
	while ((c = getopt(argc, argv, "dv")) != EOF)
		switch (c) {
		case 'v':
			++verbose;
			break;
		case 'd':
			++debug;
			break;
		case '?':
		default:
			errflg++;
			break;
		}
	if (errflg) 
#define USAGE "usage: %s file ...\n"
		error(USAGE, progname);

	if (optind >= argc)
		error(USAGE, progname);
	else
		for (; optind < argc; optind++)
			if (strcmp(argv[optind], "-") == 0)
				process(stdin, "-");
			else {
				in = efopen(argv[optind], "r");
				if (fstat(fileno(in), &statbuf) != 0)
					error("can't fstat %s", argv[optind]);
				if ((statbuf.st_mode & S_IFMT)==S_IFDIR)
					error("%s is a directory!",
								argv[optind]);
				process(in, argv[optind]);
				(void) fclose(in);
			}
	exit(0);
}

/*
 * process - process input file
 */
process(in, inname)
FILE *in;
char *inname;
{
#define MAXSTR	512
	char buf[MAXSTR+1];
	FILE *mfp;

	if (verbose)
		(void) fprintf(stderr, "%s: %s... connecting to zmailer\n",
			progname, inname);

	if ((mfp = mail_open()) == NULL)
		error("can't open output mailbox for file %s", inname);

	while (fgets(buf, MAXSTR, in) != NULL)
		fputs(buf, mfp);
	if (ferror(mfp))
		error("error writing \"%s\" to zmailer", inname);

	if (mail_close(mfp) == EOF)
		error("failure closing output mailbox for %s", inname);

	if (verbose)
		(void) fprintf(stderr, "%s: %s... sent to zmailer\n",
                        progname, inname);

	if (in != stdin)
		mh_style_rename(inname);
}

/*
 * rename file by prepending "#" in its last component.
 * "foo" -> "#foo"
 * "/tmp/foo" -> "/tmp/#foo"
 */
mh_style_rename(s)
char *s;
{
	extern char *malloc(), *strrchr();
	register char *p, *ns = malloc(strlen(s)+2);

	if (ns == NULL) {
		(void) fprintf(stderr, 
			"%s: out of memory!! (input file \"%s\")", s);
		return;
	}

	if ((p=strrchr(s, '/')) == NULL) {	/* simple path */
		*ns = '#';
		*(ns+1) = '\0';
		strcat(ns, s);
	} else {				/* multi-dir path */
		strncpy(ns, s, p-s+1);		/* +1 to include the "/" */
		strcat(ns, "#");
		strcat(ns, p+1);
	}

	if (debug)
		(void) fprintf(stderr,
			"%s: rename %s to %s\n", progname, s, ns);

	(void) unlink(ns);			/* must not exist */

	if (link(s, ns) <0) {
		error("cannot link input file to \"%s\"", ns);
		return;				/* heh heh */
	}
	if (unlink(s) <0)
		error("cannot unlink \"%s\"", s);
}
