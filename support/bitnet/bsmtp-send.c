/* bsmtp-send.c  -  wrap up a message in a BSMTP envelope and send via UREP */

/*
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

char Usage[] = "mailer-id@bitnet-node fromuser[@mydomain] fromaddr toaddr [ toaddr ... ]";

#ifndef	NETCOPY
#define	NETCOPY "/usr/local/lib/urep/bin/netcopy"
#endif

char *myname;
char *netcopy = NETCOPY;

main(argc, argv)
int argc;
char *argv[];
{
	char *cp, *progname;
	FILE *bsmtp;
	char fromname[BUFSIZ], priority[BUFSIZ], *tmp_file;
	int n;
	long count;
	extern char *mktemp(), *index();

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

	if (argc < 5) {
		fprintf(stderr, "Usage: %s %s\n", progname, Usage);
		exit(EX_USAGE);
	}
	tmp_file = mktemp("/tmp/bsmtpSXXXXXX");
	if ((cp = index(argv[2], '@')) != NULL) {
		*cp = '\0';
		myname = cp + 1;
	} else {
		char myhost[10];

		bitnetname(myhost);
		(void) strcpy(myname, myhost);
	}
	sprintf(fromname, "fname=%s", argv[2]);
	if ((bsmtp = fopen(tmp_file, "w")) == NULL)
		exit(EX_OSERR);
	fprintf(bsmtp, "HELO %s\n", myname);
	fprintf(bsmtp, "TICK %d\n", getpid());
#ifdef VERBOSE
	fprintf(bsmtp, "VERB ON\n");
#endif
	fprintf(bsmtp, "MAIL FROM:<%s>\n", argv[3]);
	for (n=4; n < argc; n++)
		fprintf(bsmtp, "RCPT TO:<%s>\n", argv[n]);
	fprintf(bsmtp, "DATA\n");
	count = ftell(bsmtp);
	copydata(bsmtp);
	count = ftell(bsmtp) - count;
	/* Emulate normal RSCS/MAILER priorities (really "card"-based, but..) */
	sprintf(priority, "priority=%d", count <= 8000 ? 0 : 50);
	fprintf(bsmtp, ".\n");		/* copydata will newline-terminate */
	fprintf(bsmtp, "QUIT\n");
	fclose(bsmtp);
	if (freopen(tmp_file, "r", stdin) == NULL) {
		printf("%s: cannot open %s on stdin!\n", progname, tmp_file);
		exit(EX_TEMPFAIL);
	}
	(void) unlink(tmp_file);
	execl(netcopy, "urep-bsmtp", "-W", argv[1], fromname,
		       "ftype=MAIL", "class=M", "width=80", "device=PUNCH",
		       "user=MAILER", priority, (char *)0);
	printf("%s: cannot exec %s!\n", progname, netcopy);
	exit(EX_TEMPFAIL);
}
