/*
 * mprobe -- ZMailer's SMTP-server operability test
 *
 *  rc  = 0: Works
 *  rc != 0: fault
 *
 * Written at, and used at DEC OSF/1 v3.2 only...
 * ... that is, your mileage may vary..
 *
 * By Matti Aarnio <mea@nic.funet.fi> 1995
 */

#include "hostenv.h"
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include "zmsignal.h"
#include <sysexits.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>

void got_alarm(n)
     int n;
{
	_exit(20);
}


void read_220(fp)
FILE *fp;
{
	char line[2048];
	int lines = 0;

	while(!feof(fp) && !ferror(fp)) {
	  *line = 0;
	  if (fgets(line, sizeof(line), fp) == NULL) exit(19);
	  ++lines;
	  if (line[0] != '2' ||
	      line[1] != '2' ||
	      line[2] != '0') exit(18);
	  if (line[3] == ' ') break;
	}
	if (lines == 0) exit(17);
}

int main(argc, argv)
int argc;
char *argv[];
{
	int sock;
	FILE *fp;
	struct hostent *hp;
	struct sockaddr_in sad;
	int rem_port = 25; /* SMTP's well-known port */

	SIGNAL_HANDLE(SIGALRM, got_alarm);

	alarm(60); /* --> hits, _exit(20) */

	if (argc <= 1) exit(99);

	hp = gethostbyname(argv[argc-1]);
	if ( !hp ) exit(2);
	sad.sin_family = AF_INET;
	sad.sin_port = htons(rem_port);
	memcpy(&sad.sin_addr.s_addr,hp->h_addr,4); /* TCP/IP */

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) exit(3);

	if (connect(sock, (struct sockaddr *)&sad, sizeof(sad)) < 0)
	  exit(4);

	fp = fdopen(sock,"r");
	if (!fp /* why?? */) _exit(5);

	read_220(fp);
	write(sock,"QUIT\r\n",6);
	fclose(fp); /* Implied  'close(sock)' */
	return 0;
}
