/* note-send.c  -  linefolding and transmission of a message via UREP */

/*
 *  Based on software which is
 *  Copyright (c) 1986 by The Governing Council of the University of Toronto.
 *  Authored by Rayan Zachariassen for University of Toronto Computing Services.
 */

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <time.h>
#include <sysexits.h>

char Usage[] = "touser@tohost fromuser";

#ifndef	NETCOPY
#define	NETCOPY	"/usr/local/lib/urep/bin/netcopy"
#endif

char *netcopy = NETCOPY;

main(argc, argv)
int argc;
char *argv[];
{
	char *cp, *progname;
	FILE *note;
	char fromname[BUFSIZ], priority[BUFSIZ], *tmp_file;
	extern char *mktemp(), *index(), *rindex();

	progname = argv[0];
	umask(~(S_IREAD|S_IWRITE));

#ifdef SENDBITNETLOG
	{
		FILE *trace;
		int argn;
		int clock;

		if (access(SENDBITNETLOG,F_OK) != -1) {
			if ((trace = fopen(SENDBITNETLOG,"a")) != NULL) {
				clock = time(0L);
				fprintf(trace,"%.19s",ctime(&clock));
				for (argn = 0; argn < argc; argn++)
					fprintf(trace," %s", argv[argn]);
				fprintf(trace, "\n");
				fclose(trace);
			}
		}
	}
#endif
	if (argc < 3) {
		fprintf(stderr, "Usage: %s %s\n", progname, Usage);
		exit(EX_USAGE);
	}
	tmp_file = mktemp("/tmp/noteSXXXXXX");
	if ((cp = index(argv[2], '@')) != NULL)
		*cp = '\0';
#ifdef NODOTNAME
	if (cp != NULL && (cp = rindex(cp+1, '.')) != NULL)
		*cp = '\0';
	if ((cp = index(argv[1], '.')) != NULL)
		*cp = '\0';
#endif
	if (strncmp(argv[1], "devnull", 7) == 0)
		exit(0);
	sprintf(fromname, "fname=%s", argv[2]);
	if ((note = fopen(tmp_file, "w")) == NULL)
		exit(EX_OSERR);
	copydata(note);
	/* Emulate normal RSCS/MAILER priorities (really "card"-based, but..) */
	sprintf(priority, "priority=%d", ftell(note) <= 8000 ? 0 : 50);
	fclose(note);
	if (freopen(tmp_file, "r", stdin) == NULL) {
		printf("%s: cannot open %s on stdin!\n", progname, tmp_file);
		exit(EX_TEMPFAIL);
	}
	(void) unlink(tmp_file);
	execl(netcopy, "urep-note", "-W", argv[1], fromname,
		       "ftype=MAIL", "class=M", "width=80", "device=PUNCH",
		       "user=MAILER", priority, (char *)0);
	printf("%s: cannot exec %s!\n", progname, netcopy);
	exit(EX_TEMPFAIL);
}
