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
#include "libc.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

extern int fmtmbox __((char *, int, const char *, const char *, \
			const struct Zpasswd *));
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
  fprintf(stderr,"%s: Usage: [-P[P]|-D[D]|-X[X]] [-d maildir] [-|username]\n", progname);
  exit(EX_USAGE);
}


static void mkhashpath __((char *, const char *));
static void mkhashpath(s, uname)
     char *s;
     const char *uname;
{
	if (pjwhashes || crchashes) {
	  int i, h = 0, hlim = 0;
	  int hashes[10]; /* Hard-coded max of 10 levels */

	  if (pjwhashes) {
	    h = pjwhash32(uname);
	    hlim = pjwhashes;
	  }
	  if (crchashes) {
	    h = crc32(uname);
	    hlim = crchashes;
	  }
	  for (i = 0; i < hlim; ++i) {
	    hashes[i] = h % 26;
	    h = h / 26;
	  }
	
	  for (i = hlim-1; i >= 0; --i) {
	    sprintf(s, "%c/", 'A' + hashes[i]);
	    s += 2;
	  }
	}

	if (dirhashes) {
	  const char *p = uname;
	  int i;
	  for (i = 0; i < dirhashes; ++i) {
	    if (!*p) break;
	    *s++ = *p++;
	    *s++ = '/';
	  }
	  *s = 0;
	}
	strcat(s, uname);
}


int main(argc,argv)
     int argc;
     char *argv[];
{
	int c;
	char *s;
	const char *cs;
	struct stat st;
	const char **maild;
	struct Zpasswd *pw;
	char pathbuf[2000]; /* more than enough, he said.. */
	char uname[1000]; /* .. and repeated himself... */
	int stdinmode = 0;
	int once = 1;

	cs = getzenv("MAILBOX");
	if (cs != NULL) {
	  maildirs[0] = cs;
	  maildirs[1] = NULL;
	}


	while ((c = getopt(argc,argv,"d:DPX")) != EOF) {
	  switch (c) {
	  case 'D':
	    ++dirhashes;
	    if (dirhashes > 10) dirhashes = 10;
	    break;
	  case 'P':
	    ++pjwhashes;
	    if (pjwhashes > 10) pjwhashes = 10;
	    break;
	  case 'X':
	    ++crchashes;
	    if (crchashes > 10) crchashes = 10;
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
	strncpy(uname, argv[optind], sizeof(uname)-1);
	uname[sizeof(uname)-1] = 0;

	if (strcmp(uname, "-") == 0)
	  stdinmode = 1;

	for (once = 1; stdinmode || once; once = 0) {
	  if (stdinmode) {
	    uname[0] = 0;
	    s = fgets(uname, sizeof(uname)-1, stdin);
	    if (!s || uname[0] == 0) break;
	    s = strchr(uname, '\n');
	    if (s) *s = 0;
	  }

	  st.st_mode = 0;
	  for (maild = maildirs; *maild != NULL; ++maild) {
	    if (strchr(*maild,'%') || (stat(*maild,&st) == 0 &&
				       S_ISDIR(st.st_mode)))
	      break;
	  }
	  if (!*maild) {
	    fprintf(stderr,"mboxpath: Did not find any mbox directory\n");
	    exit(8);
	  }

	  if (strchr(*maild,'%')) {
	    pw = zgetpwnam(uname);
	    if (pw == NULL) {
	      if (errno) perror("zgetpwnam");
	      else fprintf(stderr,"%s: no such user\n",uname);
	      exit(8);
	    }
	    if (fmtmbox(pathbuf,sizeof(pathbuf),*maild,uname,pw)) {
	      pathbuf[70]='\0';
	      strcat(pathbuf,"...");
	      fprintf(stderr,"mboxpath: path does not fit in buffer: \"%s\"\n",
		      pathbuf);
	      exit(8);
	    } else {
	      printf( "%s\n", pathbuf);
	    }
	  } else {
	    sprintf(pathbuf, "%s/", *maild);
	    s = pathbuf + strlen(pathbuf);
	    mkhashpath(s, uname);
	    printf( "%s\n", pathbuf);
	  }
	}

	return (0);
}
