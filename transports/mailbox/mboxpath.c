/*
 *  mboxpath -- give a couple options, and two arguments, and this
 *              program produces full file path with possible hash
 *		directories for the user.
 *
 *  Calling methods:
 *    mboxpath [-d mailboxdir]     user
 *    mboxpath [-d mailboxdir] -P  user
 *    mboxpath [-d mailboxdir] -PP user
 *    mboxpath [-d mailboxdir] -D  user
 *    mboxpath [-d mailboxdir] -DD user
 *    mboxpath [-d mailboxdir] -X  user
 *    mboxpath [-d mailboxdir] -XX user
 *
 */


#include "hostenv.h"
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <sysexits.h>
#include <sys/param.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h> /* F_LOCK is there at some systems.. */
#endif
#include <string.h>
#include "mail.h"
#include "zsyslog.h"
#include "zmsignal.h"

#include "ta.h"
#include "zmalloc.h"
#include "libz.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif


int dirhashes = 0;
int pjwhashes = 0;
int crchashes = 0;
const char *progname = "mboxpath";
int D_alloc = 0;

extern int optind;
extern char *optarg;


/*
 * The following is stuck in for reference only.  You could add
 * alternate spool directories to the list (they are checked in
 * order, first to last) but if the MAILBOX zenvariable exists it will
 * override the entire list.  ( This list is from  mailbox.c ! )
 */
const char *maildirs[] = {
	"/var/mail",
	"/usr/mail",
	"/var/spool/mail",
	"/usr/spool/mail",
	NULL
};


void usage()
{
  fprintf(stderr,"%s: Usage: [-P[P]|-D[D]] [-d maildir] username\n", progname);
  exit(EX_USAGE);
}


static void mkhashpath __((char *, const char *));
static void mkhashpath(s, uname)
     char *s;
     const char *uname;
{
	extern long pjwhash32 __((const char *));
	extern long crc32     __((const char *));

	if (crchashes) {
	  int h = crc32(uname);
	  switch (crchashes) {
	  case 1:
	    h %= 26;
	    sprintf(s,"%c/", ('A' + h));
	    break;
	  default:
	    h %= (26*26);
	    sprintf(s,"%c/%c/", ('A' + (h / 26)), ('A' + (h % 26)));
	    break;
	  }
	}
	if (pjwhashes) {
	  int h = pjwhash32(uname);
	  switch (pjwhashes) {
	  case 1:
	    h %= 26;
	    sprintf(s,"%c/", ('A' + h));
	    break;
	  default:
	    h %= (26*26);
	    sprintf(s,"%c/%c/", ('A' + (h / 26)), ('A' + (h % 26)));
	    break;
	  }
	}
	if (dirhashes) {
	  switch (dirhashes) {
	  case 1:
	    sprintf(s,"%c/",uname[0]);
	    s += 2;
	    break;
	  case 2:
	    if (uname[1])
	      sprintf(s,"%c/%c/",uname[0],uname[1]);
	    else /* Err.... One char userid ?? TROUBLE TIME! */
	      sprintf(s,"%c/%c/",uname[0],uname[0]);
	    s += 4;
	    break;
	  default:
	    break;
	  }
	}
	strcat(s, uname);
}



int main(argc,argv)
     int argc;
     char *argv[];
{
	char *uname;
	int c;
	char *s;
	struct stat st;
	const char **maild;
	char pathbuf[2000]; /* more than enough, he said.. */

	s = getzenv("MAILBOX");
	if (s != NULL) {
	  maildirs[0] = s;
	  maildirs[1] = NULL;
	}


	while ((c = getopt(argc,argv,"d:DPX")) != EOF) {
	  switch (c) {
	  case 'D':
	    ++dirhashes;
	    break;
	  case 'P':
	    ++pjwhashes;
	    break;
	  case 'X':
	    ++crchashes;
	    break;
	  case 'd':
	    maildirs[0] = optarg;
	    maildirs[1] = NULL;
	    break;
	  default:
	    usage();
	    break;
	  }
	}

	if (argc != optind+1)
	  usage();
	uname = argv[optind];

	st.st_mode = 0;
	for (maild = maildirs; *maild != NULL; ++maild) {
	  if (stat(*maild,&st) == 0 &&
	      S_ISDIR(st.st_mode))
	    break;
	}

	if (!S_ISDIR(st.st_mode)) {
	  fprintf(stderr,"mboxpath: Did not find any mbox directory\n");
	  exit(8);
	}

	sprintf(pathbuf, "%s/", *maild);
	s = pathbuf + strlen(pathbuf);
	mkhashpath(s, uname);
	printf( "%s\n", pathbuf);
	return (0);
}
