/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *	Copyright 1992-2001 Matti Aarnio -- MIME processing et.al.
 */

/* History:
 *
 * Based on code by Geoff Collyer.
 * Rewritten for Sun environment by Dennis Ferguson and Rayan Zachariassen.
 * RBIFF code originally added by Jean-Francois Lamy.
 * Heavily modified for ZMailer by Rayan Zachariassen.
 * Still more modifications by Matti Aarnio <mea@nic.funet.fi>
 */

/* ZENV variables used by this program:
 *
 *	ZCONFIG		-- passed to programs run at pipes
 *	MAILBOX		-- same
 *	MAILBIN		-- same
 *	MAILSHARE	-- same
 *	PATH		-- used to find programs, passed to programs
 *	MBOXLOCKS	-- defines file/mbox lock mechanisms; a string with:
 *		'.' -- "dotlock" mechanism for mail spool files
 *		':' -- separates mailbox, and file lock schemes
 *		'L' -- lockf() lock
 *		'F' -- flock() lock
 *		'N' -- NFSMBOX (uses special locking daemon at remote system)
 */

#define DefCharset "ISO-8859-1"

#include "mailer.h"
#include <ctype.h>
#include <errno.h>
#include <sysexits.h>
#include <sys/param.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h> /* F_LOCK is there at some systems.. */
#endif
#include <string.h>

#include "ta.h"

#include "mail.h"
#include "zsyslog.h"
#include "zmsignal.h"

#include "zmalloc.h"
#include "libz.h"
#include "splay.h"
#include "sieve.h"

#ifdef  HAVE_WAITPID
# include <sys/wait.h>
#else
# ifdef HAVE_WAIT3
#  include <sys/wait.h> /* Has BSD wait3() */
# else
#  ifdef HAVE_SYS_WAIT_H /* POSIX.1 compatible */
#   include <sys/wait.h>
#  else /* Not POSIX.1 compatible, lets fake it.. */
extern int wait();
#  endif
# endif
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef	HAVE_LOCKF
#ifdef	F_OK
#undef	F_OK
#endif	/* F_OK */
#ifdef	X_OK
#undef	X_OK
#endif	/* X_OK */
#ifdef	W_OK
#undef	W_OK
#endif	/* W_OK */
#ifdef	R_OK
#undef	R_OK
#endif	/* R_OK */
#endif	/* HAVE_LOCKF */

#ifndef	HAVE_LSTAT
#define	lstat stat
#endif	/* !HAVE_LSTAT */

#ifdef	HAVE_MAILLOCK_H
# include <maillock.h>
#endif

extern time_t time __((time_t *));

#ifdef HAVE_DOTLOCK
#include "dotlock.c"
#endif

#ifdef  HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#ifdef HAVE_UTIME_H
# include <utime.h>
#else
/* XXX: some systems have utimbuf defined in unistd.h, some don't... */
struct utimbuf {
	time_t  actime;
	time_t  modtime;
};
#endif

#ifndef	SEEK_SET
#define	SEEK_SET 0
#endif	/* !SEEK_SET */
#ifndef	SEEK_END
#define	SEEK_END	2
#endif	/* !SEEK_END */
#ifndef	F_OK
#define	F_OK	0
#endif	/* !F_OK */

#ifdef HAVE_LOCKF
const char *MBOXLOCKS_default = ".L:L";
#else
#ifdef HAVE_FLOCK
const char *MBOXLOCKS_default = ".F:F";
#else
const char *MBOXLOCKS_default = ".:"; /* Huh ?? No lockf() nor flock() ??? */
#endif
#endif

#ifdef HAVE_DIRENT_H
# include <dirent.h>
#else /* not HAVE_DIRENT_H */
# define dirent direct
# ifdef HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif /* HAVE_SYS_NDIR_H */
# ifdef HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif /* HAVE_SYS_DIR_H */
# ifdef HAVE_NDIR_H
#  include <ndir.h>
# endif /* HAVE_NDIR_H */
#endif /* HAVE_DIRENT_H */

#ifdef	HAVE_SOCKET
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif	/* HAVE_SOCKET */

#ifdef HAVE_PROTOCOLS_RWHOD_H
#include <utmp.h>
#include <protocols/rwhod.h>
#define RWHODIR		"/var/spool/rwho"
#define	WHDRSIZE	(sizeof (wd) - sizeof (wd.wd_we))
#define RBIFFRC		".rbiff"
#endif	/* HAVE_PROTOCOLS_RWHOD_H */

#define	PROGNAME	"mailbox"	/* for logging */
#define	CHANNEL		"local"	/* the default channel name we deliver for */
#define TO_FILE		'/'	/* first character of file username */
#define TO_PIPE		'|'	/* first character of program username */
#define TO_USER		'\\'	/* first character of escaped username */
#define	QUOTE		'"'	/* some usernames have these around them */
#define	FROM_		"From "	/* mailbox separator string (q.v. writebuf) */

#define MAILMODE        0600    /* prevent snoopers from looking at mail */
#define	NONUIDSTR	"6963"	/* X:magic nonsense uid if nobody uid is bad */

/* [Thomas Knott] [mea]
 * The form for "-S" (sendmail-style-behaviour) enabled
 * "Return-Receipt-To:" -header processing.
 * This is a file in $MAILSHARE/FORMSDIR/ -directory
 */
#define RETURN_RECEIPT_FORM "return-receipt"

/*
 * The following is stuck in for reference only.  You could add
 * alternate spool directories to the list (they are checked in
 * order, first to last) but if the MAILBOX zenvariable exists it will
 * override the entire list.
 */
const char *maildirs[] = {
	"/var/mail",
	"/usr/mail",
	"/var/spool/mail",
	"/usr/spool/mail",
	0 
};

/*
 * Macro to determine from the given error number whether this
 * should be considered a temporary failure or not.
 */
#ifdef	USE_NFSMBOX
#define	TEMPFAIL(err)	(err == EIO || err == ENETRESET || \
			 err == ECONNRESET || err == ENOBUFS || \
			 err == ETIMEDOUT || err == ECONNREFUSED || \
			 err == EHOSTDOWN || err == ENOTCONN)
#else	/* !USE_NFSMBOX */
#define TEMPFAIL(err)	(err == EIO)
#endif	/* USE_NFSMBOX */


#define	DIAGNOSTIC(R,U,E,A1,A2)	diagnostic((R), \
					(*(U) == TO_PIPE \
					 && (R)->status != EX_OK \
					 && (R)->status != EX_TEMPFAIL) ? \
					      EX_UNAVAILABLE : (E), 0, (A1), (A2))
#define	DIAGNOSTIC3(R,U,E,A1,A2,A3)   diagnostic((R), \
					(*(U) == TO_PIPE \
					 && (R)->status != EX_OK \
					 && (R)->status != EX_TEMPFAIL) ? \
					      EX_UNAVAILABLE : (E), 0, \
						(A1), (A2), (A3))
#define	DIAGNOSTIC4(R,U,E,A1,A2,A3,A4) diagnostic((R), \
					(*(U) == TO_PIPE \
					 && (R)->status != EX_OK \
					 && (R)->status != EX_TEMPFAIL) ? \
					      EX_UNAVAILABLE : (E), 0, \
						(A1), (A2), (A3), (A4))

#ifdef CHECK_MB_SIZE
extern int checkmbsize(const char *uname, const char *host, const char *user,
		       size_t cursize, struct Zpasswd *pw);
#endif

#if	defined(HAVE_SOCKET)
/*
 * Biff strategy:
 *
 * If any biff is desired, add user to list with empty structure.
 * For all users in list, if remote biff is desired, read rwho files
 * to determine the hosts user is on.  Add user to list for each host.
 * The "user" is really a struct containing username and offset into
 * their mailbox.
 */

struct biffer {
	struct biffer	*next;
	char		*user;
	long		offset;
	int		wantrbiff;
};

struct biffer *biffs = NULL;
struct biffer *eobiffs = NULL;

struct userhost {
	struct userhost *next;
	char		*hostname;
};

struct wsdisc {
  Sfdisc_t D;		/* Sfio Discipline structure		*/
  void *WS;		/* Ptr to SS context			*/
};

struct writestate {
	Sfio_t *fp;
	int  lastch;
	char expect;
	char frombuf[8];
	char *fromp;
	char *buf2; /* writemimeline() processing aux buffer */
	int buf2len;
	int epipe_seen;
	struct wsdisc WSdisc;
};


struct sptree *spt_users = NULL;
#endif /* HAVE_SOCKET -- no use to biff, if no socket available .. */

const char *defcharset;
const char *progname;
const char *channel;
const char *logfile;
FILE *logfp = NULL;
FILE *verboselog = NULL;
#if !(defined(HAVE_MMAP) && defined(TA_USE_MMAP))
int   readalready = 0;		/* does buffer contain valid message data? */
char  let_buffer[8*BUFSIZ];
#endif
uid_t currenteuid;		/* the current euid */
extern int nobody;		/* safe uid for file/program delivery */
int  dobiff = 1;		/* enable biff notification */
int  dorbiff = 0;		/*    "   rbiff   " */
int  dorbiff_always = 0;
int  keepatime = 1;		/* preserve mbox st_atime, for login etc. */
int  creatflag = 1;		/* attempt to create files that don't exist */
int  mime8bit = 0;		/* Has code which translates  MIME text/plain
				   Quoted-Printable  to 8BIT.. */
int keep_header8 = 0;		/* Headers can have 8-bit stuff ? */
int convert_qp = 0;		/* Flag: We have a job.. */
int conversion_prohibited = 0;	/* Flag: Under no circumstances touch on it.. */
int is_mime    = 0;		/* Flag: Msg is MIME msg .. */
char *mime_boundary = NULL;
int   mime_boundary_len = 0;
int mmdf_mode = 0;		/* Write out MMDF-style mail folder
				   ("\001\001\001\001" as the separator..)  */
long eofindex  = -1;		/* When negative, putmail() can't truncate() */
int  dirhashes = 0;
int  pjwhashes = 0;
int  crchashes = 0;
int  canonify_user = 0;
int  do_xuidl = 0;		/* Store our own  X-UIDL: header to allow
				   POP3 server to have some unique id for
				   the messages..  IMAP4 does require
				   something different -- 32-bit unique
				   counter..  See RFC 2060 for IMAP4. */

extern int fmtmbox __((char *, int, const char *, const char *, \
			const struct Zpasswd *));

extern RETSIGTYPE wantout __((int));
extern int optind;
extern char *optarg;
extern void biff __((const char *, const char *, long));
extern void rbiff __((struct biffer *));
extern void prversion __((const char *));

extern int setupuidgid __((struct rcpt *, int, int));
extern int createfile __((struct rcpt *, const char *, int, int));
extern int exstat __((struct rcpt *, const char *, struct stat *, int (*)(const char*, struct stat*) ));
extern int creatembox __((struct rcpt *, const char *, char **, uid_t*, gid_t*, struct Zpasswd *));
extern char *exists __((const char *, const char *, struct Zpasswd *, struct rcpt *));
extern void setrootuid __((struct rcpt *));
extern void process __((struct ctldesc *dp));
extern void deliver __((struct ctldesc *dp, struct rcpt *rp, const char *userbuf, const char *timestring));
extern Sfio_t *putmail __((struct ctldesc *dp, struct rcpt *rp, int fdmail, const char *fdopmode, const char *timestring, const char *file, uid_t));
extern int appendlet __((struct ctldesc *dp, struct rcpt *rp, struct writestate *WS, const char *file, int ismime));
extern char **environ;
extern int writebuf __((struct writestate *, const char *buf, int len));
extern int writemimeline __((struct writestate *, const char *buf, int len));


extern int program __((struct ctldesc *dp, struct rcpt *rp, const char *cmdbuf, const char *usernam, const char *timestring, int pipeuid));

static int do_return_receipt_to = 0;
static void  return_receipt __((struct ctldesc *dp, const char *retrecpaddr, const char *uidstr));
static const char *find_return_receipt_hdr __((struct rcpt *rp));

extern int  qp_to_8bit   __((struct rcpt *rp));
extern int  qptext_check __((struct rcpt *rp));

extern void hp_init();
extern char **hp_getaddr();
extern int errno;
#ifndef strchr
extern char *strchr(), *strrchr();
#endif
extern int  lstat __((const char *, struct stat *)); /* remaps to  stat() if USE_LSTAT is not defined.. */
extern FILE *fdopen();
#ifndef MALLOC_TRACE
extern void * emalloc __((size_t));
#else
struct conshell *envarlist = NULL;
#endif
int	D_alloc = 0;

static int zsfsetfd(fp, fd)
     Sfio_t *fp;
     int fd;
{
  /* This is *NOT* the SFIO's sfsetfd() -- we do no sfsync() at any point.. */
  fp->file = fd;
  return fd;
}

static void zsfclose(fp)
     Sfio_t *fp;
{
  /* This is *NOT* the SFIO's sfclose() -- in case of an error,
     we junk the buffers ourselves! */

  if (sferror(fp)) {
    close(fp->file);
    fp->file = -1;
  }
  sfclose(fp);
}


static void decodeXtext __((Sfio_t *, const char *));

#if defined(HAVE_SOCKET) && defined(HAVE_PROTOCOLS_RWHOD_H)
static int readrwho __((void));
#endif

static void sig_alrm __((int));
static void sig_alrm(sig)
int sig;
{
	/* Sigh, actually dummy routine.. */
}

static int free_spu __((void *));
static int
free_spu(p)
     void *p;
{
	free(p);
	return 0;
}


#ifndef	MAXPATHLEN
#define	MAXPATHLEN 1024
#endif

char filename[MAXPATHLEN+8000];

int
main(argc, argv)
	int argc;
	const char *argv[];
{
	char *s;
	const char *cs;
	int c, errflg, fd;
	char *host = NULL;	/* .. and what is my host ? */
	int matchhost = 0;
#if	defined(HAVE_SOCKET)
	struct biffer *nbp;
#endif
	struct ctldesc *dp;

	RETSIGTYPE (*oldsig) __((int));

	SIGNAL_HANDLESAVE(SIGINT, SIG_IGN, oldsig);
	if (oldsig != SIG_IGN)
	  SIGNAL_HANDLE(SIGINT, wantout);
	SIGNAL_HANDLESAVE(SIGTERM, SIG_IGN, oldsig);
	if (oldsig != SIG_IGN)
	  SIGNAL_HANDLE(SIGTERM, wantout);
	SIGNAL_HANDLESAVE(SIGQUIT, SIG_IGN, oldsig);
	if (oldsig != SIG_IGN)
	  SIGNAL_HANDLE(SIGQUIT, wantout);
	SIGNAL_HANDLESAVE(SIGHUP, SIG_IGN, oldsig);
	if (oldsig != SIG_IGN)
	  SIGNAL_HANDLE(SIGHUP, wantout);
	SIGNAL_HANDLE(SIGALRM, sig_alrm); /* Actually ignored, but
					     fcntl() will break ? */

	SIGNAL_IGNORE(SIGPIPE);

	progname = strrchr(argv[0], '/');
	if (progname == NULL)
	  progname = argv[0];
	else
	  ++progname;

	cs = getzenv("MAILBOX");
	if (cs != NULL) {
	  maildirs[0] = cs;
	  maildirs[1] = NULL;
	}

	umask(002);

	errflg = 0;
	logfile = NULL;
	channel = CHANNEL;
	while (1) {
	  c = getopt(argc, (char*const*)argv, "abc:Cd:Dgh:Hl:MPrRSVUX8");
	  if (c == EOF)
	    break;
	  switch (c) {
	  case 'c':		/* specify channel scanned for */
	    channel = optarg;
	    break;
	  case 'C':
	    canonify_user = 1;
	    break;
	  case 'd':             /* mail directory */
	    maildirs[0] = strdup(optarg);
	    maildirs[1] = NULL;
	    break;
	  case 'D':
	    ++dirhashes;	/* For user "abcdefg" the mailbox path is:
				   MAILBOX/a/b/abcdefg -- supported by
				   qpopper, for example... */
	    break;
	  case 'P':		/* pjwhash32() from the last component of the
				   mailbox file path (filename) is used to
				   create hashes by calculating N levels
				   (one or two) of modulo 26 ('A'..'Z') alike
				   the scheduler does its directory hashes. */
	    ++pjwhashes;
	    break;
	  case 'X':		/* Like pjwhash32() above, but with crc32() */
	    ++crchashes;
	    break;
	  case 'U':
	    do_xuidl = 1;
	    break;
	  case 'M':
	    mmdf_mode = 1;
	    break;
	  case 'V':
	    prversion(PROGNAME);
	    exit(EX_OK);
	    break;
	  case 'b':		/* toggle biffing */
	    dobiff = !dobiff;
	    break;
	  case 'r':		/* toggle rbiffing */
	    dorbiff = !dorbiff;
	    break;
	  case 'R':
	    dorbiff_always = !dorbiff_always;
	    break;
	  case 'S':
	    do_return_receipt_to = 1;
	    break;
	  case 'a':		/* toggle mbox st_atime preservation */
	    keepatime = !keepatime;
	    break;
	  case 'g':		/* toggle file creation */
	    creatflag = !creatflag;
	    break;
	  case 'h':
	    host = strdup(optarg);
	    matchhost = 1;
	    break;
	  case 'l':		/* log file */
	    logfile = strdup(optarg);
	    break;
	  case 'H':
	    keep_header8 = 1;
	    break;
	  case '8':
	    mime8bit = 1;
	    break;
	  default:
	    ++errflg;
	    break;
	  }
	}
	if (errflg || optind != argc) {
	  fprintf(stderr, "Usage: %s [-8abDPXgHMrSV] [-l logfile] [-c channel] [-h host] [-d mailboxdir]\n",
		  argv[0]);
	  exit(EX_USAGE);
	}

	if (geteuid() != 0 || getuid() != 0) {
	  fprintf(stderr, "%s: not running as root!\n", progname);
	  exit(EX_NOPERM);
	}

#if 0 /* hmm.. weird obsolete code ? */
	SETEUID(0);		/* make us root all over */
	currenteuid = 0;
#endif

	logfp = NULL;
	if (logfile != NULL) {
	  if ((fd = open(logfile, O_CREAT|O_APPEND|O_WRONLY, 0644)) < 0)
	    fprintf(stderr,
		    "%s: open(\"%s\") failed: %s\n",
		    progname, logfile, strerror(errno));
	  else {
	    logfp = fdopen(fd, "a");
	    fcntl(fd, F_SETFD, 1);
	  }
	}

	/* We need this latter on .. */
	zopenlog("mailbox", LOG_PID, LOG_MAIL);

	getnobody();

	defcharset = getzenv("DEFCHARSET");
	if (!defcharset)
	  defcharset = DefCharset;

	while (!getout) {

	  /* Input:
	       spool/file/name [ \t host.info ] \n
	   */

	  printf("#hungry\n");
	  fflush(stdout);

	  if (fgets(filename, sizeof(filename), stdin) == NULL)
	    break;
	  if (strchr(filename, '\n') == NULL) break; /* No ending '\n' !  Must
						    have been partial input! */
	  if (strcmp(filename, "#idle\n") == 0)
	    continue; /* Ah well, we can stay idle.. */
	  if (emptyline(filename, sizeof filename))
	    break;

	  s = strchr(filename,'\t');
	  if (s != NULL) {
	    if (host) free(host);
	    host = strdup(s+1);
	    *s = 0;
	  }

	  SETUID(0); /* We begin as roots..  process() may change us */
	  SETEUID(0);
	  currenteuid = 0;

	  notary_setxdelay(0); /* Our initial speed estimate is
				  overtly optimistic.. */

	  dp = ctlopen(filename, channel, host, &getout, NULL, NULL, NULL, NULL);
	  if (dp == NULL) {
	    printf("#resync %s\n",filename);
	    fflush(stdout);
	    continue;
	  }
	  if (verboselog) {
	    fclose(verboselog);
	    verboselog = NULL;
	  }
	  if (dp->verbose) {
	    verboselog = fopen(dp->verbose,"a");
	    if (verboselog) {
	      /* Buffering, and Close-On-Exec bit! */
	      setbuf(verboselog,NULL);
	      fcntl(FILENO(verboselog), F_SETFD, 1);
	    }
	  }
	  process(dp);
	  ctlclose(dp);

#if	defined(HAVE_SOCKET)
	  /* now that the delivery phase is over, hoot'n wave */
	  for (nbp = biffs ; nbp != NULL; nbp = nbp->next) {
	    if (dobiff && nbp->offset >= 0)
	      biff("localhost", nbp->user, nbp->offset);
#ifdef	HAVE_PROTOCOLS_RWHOD_H /* RBIFF */
	    if (nbp->wantrbiff != 0) {
	      if (spt_users == NULL)
		spt_users = sp_init();
	      sp_install(symbol((void*)nbp->user), NULL, 0, spt_users);
	    }
#endif /* RBIFF */
	  }
#ifdef	HAVE_PROTOCOLS_RWHOD_H /* RBIFF */
	  if (spt_users != NULL) {
	    if (readrwho())
	      for (nbp = biffs ; nbp != NULL; nbp = nbp->next) {
		if (nbp->offset >= 0 && nbp->wantrbiff)
		  rbiff(nbp);
	      }
	  }
#endif	/* RBIFF */
	  while ((nbp = biffs) != NULL) {
	    biffs = nbp->next;
	    free(nbp->user);
	    free(nbp);
	  }
	  sp_scan( (int(*)__((struct spblk*))) free_spu, NULL, spt_users);
	  free((void*)spt_users);
	  spt_users = NULL;
#endif	/* HAVE_SOCKET */
	}
	exit(EX_OK);
	/* NOTREACHED */
	return 0;
}

static void rfc822localize __((char *));
static void
rfc822localize(user)
	char *user;
{
	char *s = user;

	if (*s == '"') {
	  /* Quoted local part */
	  ++user;
	  while (*user && *user != '"') {
	    if (*user == '\\' && user[1] != 0)
	      ++user;
	    *s = *user;
	    ++s; ++user;
	  }
	  *s = 0;
	  if (*user == '"')
	    ++user;
	  /* End of local part, now it MUST be '@' */
	} else {
	  /* Non-quoted local part */
	  while (*user && *user != '@') {
	    if (*user == '\\' && user[1] != 0)
	      ++user;
	    *s = *user;
	    ++s; ++user;
	  }
	  *s = 0;
	}
	/* Now the '*user' points to a NIL, or '@' */
}

void
process(dp)
	struct ctldesc *dp;
{
	char *ts;
	struct rcpt *rp;
	time_t curtime;
	int is_mime_qptext = 0;
	char *userbuf = NULL;
	char *user;
	int userlen;
	int userspace = 0;
	struct ct_data  *CT  = NULL;
	struct cte_data *CTE = NULL;
	char **hdr;

	rp = dp->recipients;

	conversion_prohibited = check_conv_prohibit(rp);

	hdr = has_header(rp,"Content-Type:");
	if (hdr)
	  CT = parse_content_type(*hdr);
	hdr = has_header(rp,"Content-Transfer-Encoding:");
	if (hdr)
	  CTE = parse_content_encoding(*hdr);
	if (CT) {
	  if (CT->basetype == NULL ||
	      CT->subtype  == NULL ||
	      cistrcmp(CT->basetype,"text") != 0 ||
	      cistrcmp(CT->subtype,"plain") != 0)

	    /* Not TEXT/PLAIN! */
	    conversion_prohibited = -1;
	  /* We don't know how to convert anything BUT  TEXT/PLAIN :-(  */
	}

	if (!conversion_prohibited)
	  is_mime_qptext = qptext_check(dp->recipients);

	if (!keep_header8 && headers_need_mime2(dp->recipients)) {
	  headers_to_mime2(dp->recipients,defcharset,verboselog);
	}

	/*
	 * Strip backslashes prefixed to the user name,
	 * and strip the quotes from around a name.
	 */

#if !(defined(HAVE_MMAP) && defined(TA_USE_MMAP))
	readalready = 0; /* ignore any previous message data cache */
#endif

	for (rp = dp->recipients; rp != NULL; rp = rp->next) {

	  userlen = strlen(rp->addr->user);
	  if (userlen >= userspace) {
	    userspace = userlen + 1;
	    if (userbuf == NULL)
	      userbuf = emalloc(userspace);
	    else
	      userbuf = realloc(userbuf, userspace);
	  }
	  memcpy(userbuf, rp->addr->user, userlen+1);
	  user = userbuf;

	  while (*user == TO_USER)
	    ++user;

	  rfc822localize(user);

	  time(&curtime);
	  ts = ctime(&curtime);

	  /* seek to message body start on each iteration */
	  if (lseek(dp->msgfd, (off_t)dp->msgbodyoffset, SEEK_SET) < 0L) {
	    warning("Cannot seek to message body in %s! (%m)",
		    dp->msgfile);
	    DIAGNOSTIC(rp, user, EX_TEMPFAIL,
		       "cannot seek to message body!", 0);
	  } else {

	    if (verboselog)
	      fprintf(verboselog,"mailbox: %s/%s %s %s\n",
		      rp->addr->channel, rp->addr->host,
		      rp->addr->user,    rp->addr->misc  );

	    if (dp->msgbodyoffset == 0)
	      warning("Null message offset in \"%s\"!",
		      dp->msgfile);
	    convert_qp = is_mime_qptext && mime8bit;
	    deliver(dp, rp, userbuf, ts);
	  }
#ifdef  HAVE_SOCKET
#ifdef	HAVE_PROTOCOLS_RWHOD_H /* RBIFF */
	  /*
	   * "contents" will be freed before rbiff done:
	   * must copy username somewhere.
	   */
	  rp->addr->user = strdup(userbuf);
#endif /* RBIFF */
#endif /* BIFF */
	}
	if (userbuf != NULL)
	  free(userbuf);
}

/*
 * probably_x400() -- some heuristics to see if this is likely
 *		      a mis-written X.400 address
 */
int probably_x400 __((const char *));
int
probably_x400(addr)
	const char *addr;
{
	int slashes = 0;
	int equs = 0;

	while (*addr) {
	  if (*addr == '/') {
	    ++slashes;
	  } else if (*addr == '=') {
	    ++equs;
	  } else {
	    ; /* Hmm...  No other testings */
	  }
	  ++addr;
	}

	/* Match things like:
		/X=yyy/Z=xxx/
		/G=fff/S=kkk/O=gggg/@foo.faa
		/=/
	   But not:
		/foo/faa/path
	 */

	if (equs > 0 && equs <= slashes)
		return 1;

	return 0;
}

/* Various lock acquisition routines */

int havedotlock = 0, havemaillock = 0;

int acquire_mboxlock __((struct rcpt *, const char *, int));
int
acquire_mboxlock(rp,file,iuid)
struct rcpt *rp;
const char *file;
int iuid;
{
#ifdef	HAVE_MAILLOCK
	const char *maillockuser;
	struct Zpasswd *pw;
	int i;
	char errbuf[30];
	const char *cp;
	uid_t uid = (uid_t) iuid;

	pw = zgetpwuid(uid);

	if (*(rp->addr->user) == TO_FILE) {
	  if (pw == NULL) {
	    notaryreport(file,"failed",
			 "5.2.1 (Target file has no known owner)",
			 "x-local; 510 (Target file has no known owner)");
	    DIAGNOSTIC(rp, file, EX_NOPERM,
		       "File \"%s\" has no owner", file);
	    return 1;
	  }
	  maillockuser = pw->pw_name;
	} else {
	  char *at, *plus;
	  maillockuser = rp->addr->user;
	  at = strchr(maillockuser, '@');
	  if (at) *at = 0;
	  plus = strchr(maillockuser, '+');
	  if (plus) *plus = 0;

	  pw = zgetpwnam(maillockuser);

	  if (plus) *plus = '+';
	  if (at) *at = '@';

	  if (pw)
	    maillockuser = pw->pw_name;
	}

	i = maillock((char*)maillockuser, 2); /* Sigh.. proto vs. man-page */
	switch (i) {
	case L_SUCCESS:
	  cp = NULL;
	  break;
	case L_MAXTRYS:
	  notaryreport(file,"failed",
		       "5.4.5 (Mailbox unlocking fails)",
		       "x-local; 550 (Mailbox unlocking fails)");
	  DIAGNOSTIC(rp, file, EX_TEMPFAIL,
		     "\"%s\" is locked", file);
	  return 1;
	case L_NAMELEN:
	  cp = "recipient name > 13 chars";
	  break;
	case L_TMPLOCK:
	  cp = "problem creating temp lockfile";
	  break;
	case L_TMPWRITE:
	  cp = "problem writing pid into temp lockfile";
	  break;
	case L_ERROR:
	  cp = "Something other than EEXIST happened";
	  break;
#ifdef L_MANLOCK /* Some Debian version has copied this mechanism,
		    but has done imperfect job on it..  I hope they
		    don't do ``enum'' on these error codes. [mea] */
	case L_MANLOCK:
	  cp = "cannot set mandatory lock on temp lockfile";
	  break;
#endif
	default:
	  sprintf(errbuf, "maillock() error %d", i);
	  cp = errbuf;
	  break;
	}
	if (cp != NULL) {
	  DIAGNOSTIC3(rp, file, EX_UNAVAILABLE,
		      "Error maillock()ing \"%s\": %s", file, cp);
	  return 1;
	}
	havemaillock = 1;
#endif	/* HAVE_MAILLOCK */
#ifdef  HAVE_DOTLOCK
	havedotlock = (dotlock(file) == 0);
	if (!havedotlock) {
	  char mbuf[256];
	  int rc, err = errno;
	  sprintf(mbuf, "\"%s\": %s", file, strerror(err));
	  notaryreport(file,"failed",
		       "5.4.5 (File locking with dotlock failed)",
		       "x-local; 550 (File locking with dotlock failed)");
	  rc = EX_UNAVAILABLE;
	  switch (err) {
	  case EBUSY:
	    rc = EX_TEMPFAIL;
	    break;
	  case EACCES:
	    rc = EX_NOPERM;
	    break;
	  default:
	    break;
	  }
	  DIAGNOSTIC(rp, file, rc, "can't dotlock %s", mbuf);
	  return 1;
	}
#endif  /* HAVE_DOTLOCK */
	return 0;
}

int acquire_nfsmboxlock __((struct rcpt *, const char *));
int
acquire_nfsmboxlock(rp,file)
struct rcpt *rp;
const char *file;
{
#ifdef	USE_NFSMBOX
	if (nfslock(file, LOCK_EX) != 0) {
	  alarm(0);
	  notaryreport(file,"failed",
		       "5.4.5 (File locking with NFS lock failed)",
		       "x-local; 550 (File locking with NFS lock failed)");
	  DIAGNOSTIC(rp, file, EX_TEMPFAIL,
		     "nfs lock() can't nfslock \"%s\"", file);
	  return 1;
	}
#endif	/* USE_NFSMBOX */
	return 0;
}


int acquire_lockflock __((int, struct rcpt *, const char *));
int
acquire_lockflock(fdmail,rp,file)
int fdmail;
struct rcpt *rp;
const char *file;
{
#if defined(HAVE_LOCKF) && defined(F_LOCK)
	/* Seek to begining for locking! [mea@utu.fi] */
	if (lseek(fdmail, (off_t)0, SEEK_SET) < 0 ||
	    lockf(fdmail, F_LOCK, 0) < 0) {
	  alarm(0);
	  notaryreport(file,"failed",
		       "5.4.5 (File locking with  lockf  failed)",
		       "x-local; 550 (File locking with  lockf  failed)");
	  DIAGNOSTIC(rp, file, EX_TEMPFAIL,
		     "can't lockf() \"%s\"", file);
	  return 1;
	}
	lseek(fdmail, (off_t)0, SEEK_END); /* To the end of the file */
#endif	/* HAVE_LOCKF */
	return 0;
}

int acquire_flocklock __((int, struct rcpt *, const char *));
int
acquire_flocklock(fdmail,rp,file)
int fdmail;
struct rcpt *rp;
const char *file;
{
#ifdef	HAVE_FLOCK
	if (flock(fdmail, LOCK_EX) < 0) {
	  alarm(0);
	  notaryreport(file,"failed",
		       "5.4.5 (File locking with  flock  failed)",
		       "x-local; 550 (File locking with  flock  failed)");
	  DIAGNOSTIC(rp, file, EX_TEMPFAIL,
		     "can't flock() \"%s\"", file);
	  return 1;
	}
#endif	/* HAVE_FLOCK */
	return 0;
}

/*
 * deliver - deliver the letter in to user's mail box.  Return
 *	     errors and requests for further processing in the structure
 */

#ifndef __STDC__
extern void store_to_file();
#else
extern void store_to_file(struct ctldesc *dp, struct rcpt *rp,
			  const char *file, int ismbox, const char *usernam,
			  struct stat *st, uid_t uid,
#if	defined(HAVE_SOCKET)
			  struct biffer *nbp,
#endif
			  time_t starttime,
			  const char *timestring
			  );
#endif

void
deliver(dp, rp, usernam, timestring)
	struct ctldesc *dp;
	struct rcpt *rp;
	const char *usernam;
	const char *timestring;
{
	register const char **maild;
	int fdmail;
	long uid;
	int hasdir;
	struct stat st, s2;
	const char *file = NULL;
	char *cp, *plus;
	const char *retrecptaddr;
	int ismbox = 0;
#if	defined(HAVE_SOCKET)
	struct biffer *nbp = NULL;
#ifdef	HAVE_PROTOCOLS_RWHOD_H
	char *path;
#endif
#endif
	const char *unam = usernam;
	struct Zpasswd *pw = NULL;
	time_t starttime;

	time(&starttime);
	notary_setxdelay(0); /* Our initial speed estimate is
				overtly optimistic.. */

	if (sscanf(rp->addr->misc,"%ld",&uid) != 1) {
	  char buf[1000];
	  if (verboselog) {
	    fprintf(verboselog,"mailbox: User recipient address privilege code invalid (non-numeric!): '%s'\n",rp->addr->misc);
	  }
	  sprintf(buf,"x-local; 500 (User recipient address privilege code invalid [non-numeric!]: '%.200s')", rp->addr->misc);
	  notaryreport(NULL,"failed",
		       "5.3.0 (User address recipient privilege code invalid)",
		       buf);
	  DIAGNOSTIC(rp, usernam, EX_SOFTWARE,
		     "Non-numeric recipient privilege code: \"%s\"", rp->addr->misc);
	  return;
	}

	plus = strchr(usernam,'+');
	switch (*usernam) {
	case TO_PIPE:		/* pipe to program */
	  /* one should disallow this if uid == nobody? */
	  if (uid == nobody) {

	    if (verboselog)
	      fprintf(verboselog,
		      "   the recipient address privilege == NOBODY!\n");

	    notaryreport("?program?", "failed",
			 "5.2.1 (Mail to program disallowed w/o proper privileges)",
			 "x-local; 550 (Mail to program disallowed w/o proper privileges)");
	    DIAGNOSTIC(rp, usernam, EX_UNAVAILABLE,
		       "mail to program disallowed", 0);
	    return;
	  }
	  program(dp, rp, usernam, "", timestring, uid);
	  /* DIAGNOSTIC(rp, usernam, EX_UNAVAILABLE,
	     "mailing to programs (%s) is not supported",
	     rp->addr->user); */
	  return;

	case TO_FILE:		/* append to file */

	  /* Solaris has "interesting" /dev/null -- it is a symlink
	     to the actual device.. So lets just use that magic
	     name and create a FAST "write" to  /dev/null..  */
	  if (strcmp(usernam,"/dev/null") == 0) {
	    notaryreport(rp->addr->user,"delivered",
			 "2.2.0 (delivered successfully)",
			 "x-local; 250 (Delivered successfully)");
	    DIAGNOSTIC(rp, usernam, EX_OK, "Ok", 0);
	    return;
	  }

	  if (uid == nobody) {
	    if (probably_x400(usernam)) {

	      if (verboselog)
		fprintf(verboselog,
			"   This smells of misdirected X.400 message? Rejected due to priviledge == NOBODY\n");

	      notaryreport(rp->addr->user,"failed",
			   "5.1.4 (this feels like a misplaced X.400 address -- no support for them)",
			   "x-local; 550 (this feels like a misplaced X.400 address -- no support for them)");
	      DIAGNOSTIC(rp, usernam, EX_UNAVAILABLE,
			 "This appears to be a misplaced X.400 address, no support for them", 0);
	    } else {

	      if (verboselog)
		fprintf(verboselog,
			"   Mail to file rejected due to priviledge == NOBODY\n");

	      notaryreport(rp->addr->user,"failed",
			   "5.2.1 (Mail to file disallowed w/o proper privileges)",
			   "x-local; 550 (mail to file disallowed w/o proper privileges)");
	      DIAGNOSTIC(rp, usernam, EX_UNAVAILABLE,
			 "mail to file disallowed", 0);
	    }
	    return;
	  }
	  if (!setupuidgid(rp, uid, -3 /* GID of user with UID=='uid' */)) {
	    setrootuid(rp);
	    return;
	  }
	  file = usernam;
	  
	  if (access(file, F_OK) < 0) {
	    fdmail = createfile(rp, file, uid, 0);
	    /* Did the create fail for some other reason, than
	       that the file exists already ? (Due to a race in
	       between two processes creating the files.) */
	    if (fdmail < 0 && errno != EEXIST) {
	      setrootuid(rp);
	      return;
	    }
#ifdef HAVE_FSYNC
	    while (fsync(fdmail) < 0)
	      if (errno != EINTR && errno != EAGAIN)
		break;
#endif
	    close(fdmail);
	  }
	  setrootuid(rp);
	  break;
	default:		/* local user */
	  /* Zap the possible '@' for a moment -- and restore later
	     [mea@utu.fi] -- same with '+' --  user+localspecs */
	  ismbox = 1;
	  if (plus) *plus = 0;
#if 0
	  setpwent(); /* Effectively rewind the database,
			 needed for multi-recipient processing ? */
#endif
	  unam = usernam;

	  pw = zgetpwnam(usernam);
	  if (pw == NULL) {

	    /* No match as is ?  Lowercasify, and try again! */
	    strlower((char*)usernam);

	    pw = zgetpwnam(usernam);
	    if (pw == NULL) {
	      if (plus) *plus = '+';

	      /* Linux, very least, seems to sometimes yield
		 NULL and errno=ENOENT, when Single Unix Spec
		 tells it to yield NULL and errno==0 :-|

		 The problem seems to be quite broad, as most
		 systems don't do sensible things, when two
		 conditions hold: All database lookups were
		 without errors (although did yield notning),
		 and nothing was found!  The sensible thing
		 would be to yield NULL along with   errno==0 ! */

	      /* Now given the above, how the hell are we going
		 to detect when any of the databases used for
		 the username resolution has a hickup, and the
		 lack of found username is simply due to the db
		 problem, which time will solve (as with system
		 operator taking some action) ?  */

	      if (errno != 0) { /* zgetpwnam() failed for some other
				   reason than simply not finding the
				   given user... */
		int err = errno;

		if (verboselog)
		  fprintf(verboselog,
			"   zgetpwnam(\"%s\") failed (%d)\n", usernam, errno);

		notaryreport(rp->addr->user,"failed",
			     "5.3.0 (Error getting user identity)",
			     "x-local; 550 (Error getting user identity)");
		DIAGNOSTIC3(rp, usernam, EX_TEMPFAIL,
			   "zgetpwnam for user \"%s\" failed; errno=%d",
			   usernam, err);

	      } else if (probably_x400(usernam)) {

		if (verboselog)
		  fprintf(verboselog,
			  "   User '%s' unknown, feels like misplaced X.400 address?\n",
			  usernam);

		notaryreport(rp->addr->user,"failed",
			     "5.1.4 (this feels like a misplaced X.400 address -- no support for them)",
			     "x-local; 550 (this feels like a misplaced X.400 address -- no support for them)");
		DIAGNOSTIC(rp, usernam, EX_UNAVAILABLE,
			   "This appears to be a misplaced X.400 address, no support for them", 0);
	      } else {

		if (verboselog)
		  fprintf(verboselog, "   User '%s' unknown\n", usernam);

		notaryreport(rp->addr->user,"failed",
			     "5.1.1 (User does not exist)",
			     "x-local; 550 (User does not exist)");
		DIAGNOSTIC(rp, usernam, EX_NOUSER,
			   "user \"%s\" doesn't exist", usernam);

	      }
	      return;
	    }
	  }

	  if (canonify_user)
	    unam = pw->pw_name;

	  hasdir = 0;
	  for (maild = maildirs; *maild != 0; maild++) {
	    if ((strchr(*maild,'%') == NULL) &&
	        (stat(*maild,&st) < 0 ||
		!S_ISDIR(st.st_mode)))
	      /* Does not exist, or is not a directory */
	      continue;
	    hasdir = 1;
	    file = exists(*maild, unam, pw, rp);
	    if (file != NULL)
	      break;		/* found it */
	    if (rp->status != EX_OK)
	      return;
	  }

	  if (hasdir && *maild == 0 &&
	      !creatembox(rp, unam, (char**)&file,
			  &st.st_uid, &st.st_gid, pw))
	    return; /* creatembox() sets status */
	  
	  if (!hasdir) {	/* No directory ?? */

	    const char *mailbox = getzenv("MAILBOX");
	    notaryreport(rp->addr->user,"failed",
			 "5.3.5 (System mailbox configuration is wrong, we are in deep trouble..)",
			 "x-local; 566 (System mailbox configuration is wrong!  No such directory!  Aargh!)");
	    DIAGNOSTIC(rp, usernam, EX_TEMPFAIL,
		       "System mailbox configuration is wrong!  No such directory (%s)!  Aargh!",maildirs[0]);

	    if (!mailbox) 
	      zsyslog((LOG_ALERT, "ZMailer mailbox can't open local mail folder directory! (Using BUILTIN list of choices)\n"));
	    else
	      zsyslog((LOG_ALERT, "ZMailer mailbox can't open local mail folder directory!  $MAILBOX='%s'\n", mailbox));
	    zcloselog();
	    return;
	  }
#if	defined(HAVE_SOCKET)
	  if (!dobiff && !dorbiff && !dorbiff_always)
	    break;
	  nbp = (struct biffer *)emalloc(sizeof (struct biffer));
	  nbp->next = NULL;
	  nbp->user = strdup(rp->addr->user);
	  nbp->offset = -1;
	  nbp->wantrbiff = 0;
#ifdef	HAVE_PROTOCOLS_RWHOD_H
	  if (dorbiff) {
	    if (dorbiff_always)
	      nbp->wantrbiff = 1;
	    else {
	      path = emalloc(2+strlen(pw->pw_dir)+strlen(RBIFFRC));
	      sprintf(path, "%s/%s", pw->pw_dir, RBIFFRC);
	      nbp->wantrbiff = (access(path, F_OK) == 0);
	    }
	  }
#endif /* RBIFF */
	  if (biffs == NULL)
	    biffs = eobiffs = nbp;
	  else {
	    eobiffs->next = nbp;
	    eobiffs = nbp;
	  }
#endif /* BIFF || RBIFF */
	  if (plus) *plus = '+';
	  break;

	} /* end of  switch (*username)  */

	
	/* Solaris has "interesting" /dev/null -- it is a symlink
	   to the actual device.. So lets just use that magic
	   name and create a FAST "write" to  /dev/null..  */
	if (strcmp(file,"/dev/null") == 0) {
	  notaryreport(rp->addr->user,"delivered",
		       "2.2.0 (delivered successfully)",
		       "x-local; 250 (Delivered successfully)");
	  DIAGNOSTIC(rp, usernam, EX_OK, "Ok", 0);
	  return;
	}

	/* we only deliver to singly-linked, regular file */

	if (exstat(rp, file, &st, lstat) < 0) {
	  notaryreport(rp->addr->user,"failed",
		       "5.2.0 (User's mailbox disappeared, will retry)",
		       "x-local; 566 (User's mailbox disappeared, will retry)");
	  DIAGNOSTIC(rp, usernam, EX_TEMPFAIL,
		     "mailbox file \"%s\" disappeared", file);
	  return;
	}

	if (!S_ISREG(st.st_mode)) {
	  /* XX: may want to deliver to named pipes */
	  notaryreport(rp->addr->user,"failed",
		       "5.2.1 (Attempting to deliver into non-regular file)",
		       "x-local; 500 (Attempting to deliver into non-regular file)");
	  DIAGNOSTIC(rp, usernam, EX_UNAVAILABLE,
		     "attempted delivery to special file \"%s\"",
		     file);
	  return;
	}

#ifdef CHECK_MB_SIZE
	if (1) {
	  extern  int checkmbsize __((const char *uname,
				      const char *host, const char *user,
				      size_t cursize, struct Zpasswd *pw));

	  /* external procedure checkmbsize() accepts user name, "host"
	     name as on routing result, "user" part of routed data,
	     and current mailbox size.  It should return 0 if it is OK
	     to write to the mailbox, or non-zero if `mailbox full'
	     condition encountered.  The procedure itself is not included
	     in ZMailer distribution; you need to write it yourself and
	     modify the Makefile to pass -DCHECK_MB_SIZE to the compiler
	     and to link with the object containing your custom
	     checkmbsize() procedure. == <crosser@average.org> */

	  if (checkmbsize(usernam, rp->addr->host, rp->addr->user,
			  st.st_size, pw)) {
	    notaryreport(usernam, "failed",
			 "4.2.2 (Destination mailbox full)",
			 "x-local; 500 (Attempting to deliver to full mailbox)");
	    DIAGNOSTIC(rp, usernam, EX_UNAVAILABLE,
		       "size of mailbox \"%s\" exceeds quota for the user",
		       file);
	    return;
	  }
	}
#endif
	
	if (st.st_nlink > 1) {
	  notaryreport(rp->addr->user,"failed",
		       "5.2.1 (Destination file ambiguous)",
		       "x-local; 500 (Destination file has more than one name..)");
	  DIAGNOSTIC(rp, usernam, EX_UNAVAILABLE,
		     "too many links to file \"%s\"", file);
	  return;
	}
	/* [Edwin Allum]
	 * If we're delivering to a mailbox, and the mail spool directory
	 * is group writable, set our gid to that of the directory.
	 * This allows us to create lock files if need be, without
	 * making the spool dir world-writable.
	 */
	if (ismbox && (cp = strrchr(file, '/')) != NULL) {
	  *cp = '\0';
	  if (stat(file, &s2) == 0 && (s2.st_mode&020))
	    st.st_gid = s2.st_gid;
	  *cp = '/';
	}
	if (!setupuidgid(rp, st.st_uid, st.st_gid)) {
	  setrootuid(rp);
	  return;			/* setupuidgid sets status */
	}

	if (verboselog)
	  fprintf(verboselog, " ismbox=%d file='%s' usernam='%s'\n",
		  ismbox, file, usernam);

	if (ismbox) {

	  struct sieve sv;
	  memset(&sv,0,sizeof(sv));
	  sv.pw       = pw;
	  sv.uid      = uid;
	  sv.pipeuid  = uid;
	  sv.username = usernam;
	  sv.spoolfile = file;

	  rp->notifyflgs |= _DSN__DIAGDELAYMODE;

	  if (sieve_start(&sv) == 0) {
	    for (;
		 sv.state != 0;
		 sieve_iterate(&sv)) {

	      /* XX: SIEVE PROCESSOR/ITERATOR */
	      int cmd = sieve_command(&sv);

	      switch(cmd) {
	      case SIEVE_NOOP:
		/* Absolutely NOTHING done with this label; end of iterator */
		break;
	      case SIEVE_RUNPIPE:
		if (program(dp, rp, sv.pipecmdbuf, usernam, timestring, sv.pipeuid) != EX_OK) {
		  /*  Possible FALSE negative ?? */
		  /*  Tell also about SUCCESSES! */
		  rp->notifyflgs |= _DSN_NOTIFY_SUCCESS;
		}
		break;
	      case SIEVE_USERSTORE:
		store_to_file(dp, rp, file, ismbox, usernam, &st, uid,
#ifdef HAVE_SOCKET
			      nbp,
#endif
			      starttime, timestring );
		break;
	      case SIEVE_DISCARD:
		break;
	      }
	    }
	    /* Cleanup of sieve processor */
	    sieve_end(&sv);
	  }

	  /* Sieve-filter sets state mode -- keep_or_discard (<=>0) to
	     tell what we should do to the message regarding its storage
	     to the local message store. */

	  rp->notifyflgs &= ~ _DSN__DIAGDELAYMODE;

	  if (sv.keep_or_discard >= 0) {
	    store_to_file(dp, rp, file, ismbox, usernam, &st, uid,
#ifdef HAVE_SOCKET
			  nbp,
#endif
			  starttime, timestring );
	  } else {
	    /* This happens only ONCE per recipient, if ever */
	    notaryreport(rp->addr->user,"delivered",
			 "2.2.0 (Discarded successfully)",
			 "x-local; 250 (Discarded successfully)");
	    DIAGNOSTIC(rp, usernam, EX_OK, "Ok", 0);
	  }

	} else {

	  store_to_file(dp, rp, file, ismbox, usernam, &st, uid,
#ifdef HAVE_SOCKET
			nbp,
#endif
			starttime, timestring );
	}

	/* [Thomas Knott]  "Return-Receipt-To:" */
	if (do_return_receipt_to) {
	  retrecptaddr = find_return_receipt_hdr(rp);
	  if (retrecptaddr != NULL)
	    return_receipt(dp,retrecptaddr,rp->addr->misc);
	}
}

void store_to_file(dp,rp,file,ismbox,usernam,st,uid,
#ifdef HAVE_SOCKET
		   nbp,
#endif
		   starttime,
		   timestring
		   )
     struct ctldesc *dp;
     struct rcpt *rp;
     const char *file, *usernam;
     int ismbox;
     struct stat *st;
     uid_t uid;
#ifdef HAVE_SOCKET
     struct biffer *nbp;
#endif
     time_t starttime;
     const char *timestring;
{
	int fdmail;
	struct stat s2;
	Sfio_t *fp = NULL;
	const char *mboxlocks = getzenv("MBOXLOCKS");
	const char *filelocks = NULL;
	const char *locks     = NULL;
	time_t endtime;

	if (mboxlocks == NULL || *mboxlocks == 0 )
	  mboxlocks = MBOXLOCKS_default;

	if ((filelocks = strchr(mboxlocks,':')))
	  ++filelocks;
	else
	  filelocks = "";


	if (verboselog)
	  fprintf(verboselog,
		  "To open a file with euid=%d egid=%d ismbox=%d file='%s'\n",
		  (int)geteuid(), (int)getegid(), ismbox, file);

	fdmail = open(file, O_RDWR|O_APPEND);
	if (fdmail < 0) {
	  char fmtbuf[512];
	  int saverrno = errno;

	  sprintf(fmtbuf, "open(\"%%s\") failed: %s",
		  strerror(saverrno));

	  if (verboselog)
	    fprintf(verboselog,
		    " ... failed, errno = %d (%s)\n",
		    saverrno, strerror(saverrno));

	  if (TEMPFAIL(saverrno))
	    rp->status = EX_TEMPFAIL;
	  else if (errno == EACCES)
	    rp->status = EX_NOPERM;
	  else
	    rp->status = EX_UNAVAILABLE;
	  notaryreport(file,"failed",
		       "5.2.1 (File open for append failed)",
		       "x-local; 500 (File open for append failed)");
	  DIAGNOSTIC(rp, usernam, rp->status, fmtbuf, file);
	  setrootuid(rp);
	  return;
	}
	/*
	 * The mbox may have been removed and symlinked
	 * after the exstat() above, but before the open(),
	 * so verify that we have the same inode.
	 */
	if (fstat(fdmail, &s2) < 0) {
	    /* This simply CAN'T HAPPEN! Somebody has broken our
	       fdmail -channel... */
	    DIAGNOSTIC(rp, usernam, EX_TEMPFAIL,
		       "can't fstat mailbox \"%s\"", file);
	    close(fdmail);
	    setrootuid(rp);
	    return;
	}
	if (st->st_ino != s2.st_ino || st->st_dev != s2.st_dev ||
	    s2.st_nlink != 1) {
	    notaryreport(file,"failed",
			 "5.4.5 (Lost race for mailbox file)",
			 "x-local; 550 (Lost race for mailbox file)");
	    DIAGNOSTIC(rp, usernam, EX_TEMPFAIL,
		       "lost race for mailbox \"%s\"", file);
	    close(fdmail);
	    setrootuid(rp);
	    return;
	}

	alarm(180); /* Set an timed interrupt coming to us to break
		       overlengthy file lock acquisition.. */

	if (!S_ISREG(st->st_mode))
	  /* don't lock non-files */;
	else {

	  int err;


	  if (!ismbox)	/* Not mailbox, use file-locks */
	    mboxlocks = filelocks;

	  locks = mboxlocks;

	  if (verboselog)
	    fprintf(verboselog,"Locking sequence: '%s'\n",locks);

	  err = 0;
	  while (*locks != 0) {
	    switch(*locks) {
	      case '"': /* ZENV variable may have quotes with it.. */
		break;
	      case ':':
		err = -1; /* negative error is no REAL error */
		break;
	      case '.':
		if (ismbox)
		  err = acquire_mboxlock(rp,file,uid);
		break;
	      case 'N':
	      case 'n':
		err = acquire_nfsmboxlock(rp,file);
		break;
	      case 'L':
	      case 'l':
		err = acquire_lockflock(fdmail,rp,file);
		break;
	      case 'F':
	      case 'f':
		err = acquire_flocklock(fdmail,rp,file);
		break;
	      default:
		err = 1;
		break;
	    }
	    if (err) break;
	    ++locks; /* Advance on success only! */
	  }

	  if (err > 0) {
	    --locks; /* Don't try to revert the failed (= last) lock! */
	    while (locks >= mboxlocks) {
	      switch (*locks) {
		case '"':
		  break;
		case '.':
#ifdef	HAVE_MAILLOCK
		  if (havemaillock && ismbox)
		    mailunlock();
		  havemaillock = 0;
#endif	/* HAVE_MAILLOCK */
#ifdef	HAVE_DOTLOCK
		  if (ismbox)
		    dotunlock(file);
		  havedotlock = 0;
#endif /*HAVE_DOTLOCK*/
		  break;
	        case 'N':
		case 'n':
#ifdef	USE_NFSMBOX
		  unlock(file);
#endif	/* USE_NFSMBOX */
		  break;
	        case 'L':
		case 'l':
#if defined(HAVE_LOCKF) && defined(F_LOCK) /* If one, also the other */
		  lseek(fdmail,(off_t)0,SEEK_SET);
		  lockf(fdmail, F_ULOCK, 0);
#endif	/* HAVE_LOCKF */
		  break;
	        case 'F':
		case 'f':
#ifdef HAVE_FLOCK
		  flock(fdmail, LOCK_UN);
#endif
		  break;
		default:
		  break;
	      }
	      --locks;
	    }
	    close(fdmail);
	    setrootuid(rp);
	    return;
	  }
	}

	/* Turn off the alarm */
	alarm(0);


	/* Where is the end of file -- before we write anything */
	eofindex = lseek(fdmail, (off_t)0, SEEK_END);
#if	defined(HAVE_SOCKET)
	if (nbp != NULL)
	  nbp->offset = eofindex;
#endif	/* BIFF || RBIFF */

	fp = putmail(dp, rp, fdmail, "a+", timestring, file, uid);
	
	if (S_ISREG(st->st_mode)) {

	  /* Previously acquired locks need to be released,
	     preferrably in reverse order */

	  --locks;

	  while (locks >= mboxlocks) {
	    /* if (verboselog)
	       fprintf(verboselog, "Unlock char: '%c'\n",*locks); */
	    switch (*locks) {
	    case '"':
	      break;
	    case '.':
#ifdef	HAVE_MAILLOCK
	      if (ismbox && havemaillock)
		mailunlock();
	      havemaillock = 0;
#endif	/* HAVE_MAILLOCK */
#ifdef	HAVE_DOTLOCK
	      if (ismbox)
		dotunlock(file);
	      havedotlock = 0;
#endif /*HAVE_DOTLOCK*/
	      break;
	    case 'N':
	    case 'n':
#ifdef	USE_NFSMBOX
	      unlock(file);
#endif	/* USE_NFSMBOX */
	      break;
	    case 'L':
	    case 'l':
#if defined(HAVE_LOCKF) && defined(F_LOCK)
	      lseek(fdmail,(off_t)0,SEEK_SET);
	      lockf(fdmail, F_ULOCK, 0);
#endif	/* HAVE_LOCKF */

	      break;
	    case 'F':
	    case 'f':
#ifdef HAVE_FLOCK
	      flock(fdmail, LOCK_UN);
#endif
	      break;
	    default:
	      break;
	    }
	    --locks;
	  }
	}

	setrootuid(rp);
	time(&endtime);

	close(fdmail);
	if (fp != NULL) { /* Dummy marker! */
	  notary_setxdelay((int)(endtime-starttime));
	  notaryreport(rp->addr->user,"delivered",
		       "2.2.0 (Delivered successfully)",
		       "x-local; 250 (Delivered successfully)");
	  DIAGNOSTIC(rp, usernam, EX_OK, "Ok", 0);
	} else {
#if 0 /* garbage.. */
#if	defined(HAVE_SOCKET)
	  if (fp) {
	    if (nbp != NULL) /* putmail() has produced a DIAGNOSTIC */
	      nbp->offset = -1;
	}
#endif	/* BIFF || RBIFF */
#endif
	}
	
	return;
}


/*
 * SFIO write discipline which ignores PIPE write errors (EPIPE)
 * and just claims success at them.  Otherwise quite normal
 * error processing.
 *
 */

ssize_t
mbox_sfwrite(sfp, vp, len, discp)
     Sfio_t *sfp;
     const void * vp;
     size_t len;
     Sfdisc_t *discp;
{
    struct wsdisc *wd = (struct wsdisc *)discp;
    struct writestate *WS = wd->WS;
    const char * p = (const char *)vp;
    int outlen = 0;

    /* If knowingly write to a pipe, and failing with EPIPE,
       *then* silently ignore it.. */

    if (WS->epipe_seen > 0) return len; /* We ignore - fast - the EPIPE */

    while (len > 0) {
      int rc = write(sffileno(sfp), p, len);
      int e  = errno;

if (verboselog)
  fprintf(verboselog, " mbox_sfwrite(ptr, len=%d) rc=%d errno=%d\n",
	  (int)len, rc, e);

      if (rc < 0) {
	if (e == EPIPE && WS->epipe_seen >= 0) {
	  WS->epipe_seen = 1;
	  return len + outlen; /* CLAIM success */
	}
	/* Retry on interrupts */
	if (e == EINTR)
	  continue;
	errno = e;
	/* All other errors, return written amount, or if none, then error! */
	if (outlen == 0)
	  return rc;
	return outlen;
      }
      outlen += rc;
      len    -= rc;
      p      += rc;
    }
    return outlen;
}


Sfio_t *
putmail(dp, rp, fdmail, fdopmode, timestring, file, uid)
     struct ctldesc *dp;
     struct rcpt *rp;
     int fdmail;
     const char *fdopmode, *timestring, *file;
     uid_t uid;
{
	int len, rc, mw=0, err;
	Sfio_t *fp;
	char buf[2];
	struct stat st;
	const char *fromuser;
	int lastch = 0xFFF;
	int topipe = (*(file) == TO_PIPE);
	int failed = 0;

	struct writestate WS;
	char **hdrs;

	fstat(fdmail, &st);

	fp = sfnew(NULL, NULL, 64*1024, fdmail, SF_READ|SF_WRITE|SF_APPENDWR);
	if (fp == NULL) {
	  notaryreport(NULL,NULL,NULL,NULL);
	  DIAGNOSTIC3(rp, file, EX_TEMPFAIL, "cannot fdopen(%d,\"%s\")",
		      fdmail,fdopmode);
	  return NULL;
	}


	WS.fp     = fp;
	WS.expect = mmdf_mode ? 0 : 'F';
	WS.lastch = 256;	/* Something no character can be,
				   and not "-1" either.. */
	WS.frombuf[0] = 0;
	WS.fromp = WS.frombuf;
	WS.epipe_seen = topipe ? 0 : -1;

	memset(&WS.WSdisc, 0, sizeof(WS.WSdisc));
	WS.WSdisc.D.readf   = NULL;
	WS.WSdisc.D.writef  = mbox_sfwrite;
	WS.WSdisc.D.seekf   = NULL;
	WS.WSdisc.D.exceptf = NULL;
	WS.WSdisc.WS        = &WS;

	sfdisc(WS.fp, &WS.WSdisc.D);


	if (!topipe && eofindex > 0L) {

	  if (keepatime) {
#ifdef	HAVE_UTIME
	    struct utimbuf tv;
	    tv.actime  = st.st_atime;
	    tv.modtime = st.st_mtime;
	    rc = utime(file, &tv);
#else  /* HAVE_UTIMES */
	    struct timeval tv[2];
	    tv[0].tv_sec = st.st_atime;
	    tv[1].tv_sec = st.st_mtime;
	    tv[0].tv_usec = tv[1].tv_usec = 0;
	    rc = utimes(file, tv);
#endif /* HAVE_UTIMES */
	  }
	} else if (eofindex > 0L && eofindex < (sizeof "From x\n")) {
	  /* A mail message *cannot* be this small.  It must be
	     a corrupted mailbox file.  Ignore the trash bytes. */
	  sfseek(fp, (off_t)0, SEEK_SET);
	  eofindex = 0;
	}

	if (!(convert_qp && qp_to_8bit(rp)))
	  convert_qp = 0; /* If malloc failed, clear this too,
			     if it was not set, it doesn't change.. */

	/* Begin of the file, and MMDF-style ? */
	if (mmdf_mode == 1 /* Values 2 and 3 exist on PIPEs only.. */   )
	  sfprintf(fp,"\001\001\001\001\n");

	fromuser = rp->addr->link->user;
	if (*fromuser == 0 ||
	    STREQ(rp->addr->link->channel, "error"))
	  fromuser = "";

	do {
	  hdrs = has_header(rp,"Return-Path:");
	  if (hdrs) delete_header(rp,hdrs);
	} while (hdrs);

	append_header(rp,"Return-Path: <%.999s>", fromuser);


	if (*fromuser == 0)
	  fromuser = "MAILER-DAEMON";

	hdrs = has_header(rp,"To:");
	if (!hdrs) {
	  /* No "To:" -header ?  Rewrite possible "Apparently-To:" header! */

	  /* Sendmailism... */
	  do {
	    hdrs = has_header(rp,"Apparently-To:");
	    if (hdrs) delete_header(rp,hdrs);
	  } while (hdrs);

	  append_header(rp,"Apparently-To: <%.999s>", rp->addr->link->user);
	}

	do {
	  hdrs = has_header(rp,"X-Envelope-To:");
	  if (hdrs) delete_header(rp,hdrs);
	} while (hdrs);

	do {
	  hdrs = has_header(rp,"X-Orcpt:");
	  if (hdrs) delete_header(rp,hdrs);
	} while (hdrs);
	do { /* RFC 2298 section  2.3 */
	  hdrs = has_header(rp,"Original-Recipient:");
	  if (hdrs) delete_header(rp,hdrs);
	} while (hdrs);

	do {
	  hdrs = has_header(rp,"X-Envid:");
	  if (hdrs) delete_header(rp,hdrs);
	} while (hdrs);
	do {
	  hdrs = has_header(rp,"Envelope-Id:");
	  if (hdrs) delete_header(rp,hdrs);
	} while (hdrs);

	if (do_xuidl)
	  do {
	    hdrs = has_header(rp,"X-UIDL:");
	    if (hdrs) delete_header(rp,hdrs);
	  } while (hdrs);

	/* Add the From_ line and print out the header */

	if ((sfprintf(fp, "%s%s %s", FROM_, fromuser, timestring) < 0) ||
	    (swriteheaders(rp, fp, "\n", convert_qp, 0, NULL) < 0))
	  failed = 1;

	if (!failed && sferror(fp)) failed = 1;

	if (!failed)
	  sfprintf(fp, "X-Envelope-To: <%s> (uid %d)\n", rp->addr->user, uid);

	if (!failed && sferror(fp)) failed = 1;

	if (!failed && rp->orcpt) {
	  sfprintf(fp, "X-Orcpt: ");
	  decodeXtext(fp, rp->orcpt);
	  sfprintf(fp, "\n");

	  /* RFC 2298: section 2.3 */
	  sfprintf(fp, "Original-Recipient: ");
	  decodeXtext(fp, rp->orcpt);
	  sfprintf(fp, "\n");
	}
	if (!failed && sferror(fp)) failed = 1;

	if (!failed && dp->envid) {
	  sfprintf(fp, "X-Envid: ");
	  decodeXtext(fp, dp->envid);
	  sfprintf(fp, "\n");

	  sfprintf(fp, "Envelope-Id: ");
	  decodeXtext(fp, dp->envid);
	  sfprintf(fp, "\n");
	}
	if (!failed && sferror(fp)) failed = 1;

	if (!failed && do_xuidl && !topipe) {
	  struct timeval tv;
	  gettimeofday(&tv, NULL);

	  sfprintf(fp, "X-UIDL: %ld.%ld.%d\n",
		  (long)tv.tv_sec, (long)tv.tv_usec, (int)getpid());
	}
	if (!failed && sferror(fp)) failed = 1;

	if (!failed)
	  sfprintf(fp, "\n");
	if (!failed && sferror(fp)) failed = 1;

	if (!failed)
	  sfsync(fp); /* Headers written, sync possible errors here! */

	if (!failed && sferror(fp)) failed = 1;

	if (failed) goto write_failure;

	/* From now on, write errors to PIPE will not cause errors */

	if (!failed)
	  lastch = appendlet(dp, rp, &WS, file, is_mime);

	if (!failed && sferror(fp)) failed = 1;

	if (!failed) sfsync(fp);

	if (!failed && sferror(fp)) failed = 1;

	mw = 1;
	if (!topipe)

	  if (lastch < -128 || failed) {

	  write_failure:

	    /* Does the 'errno' really have correct data in all paths ? */
	    err = errno;

	    notaryreport(NULL,NULL,NULL,NULL);
	    DIAGNOSTIC4(rp, file, EX_IOERR,
			"message write[%d] to \"%s\" failed: %s",
			mw, file, strerror(err));
#ifdef HAVE_FTRUNCATE
	    if (eofindex >= 0)
	      while (ftruncate(sffileno(fp), (off_t)eofindex) < 0)
		if (errno != EINTR && errno != EAGAIN)
		  break;

	    /* Some syscall traces seem to tell that Solaris 7/8
	       implements  ftruncate()  as:

> 9497:   fcntl(7, F_FREESP, 0xFFBEE5BC)                  = 0
> 9497:     typ=F_WRLCK whence=SEEK_SET start=0 len=0
> 9497:     sys=428042295   pid=-4266544  

	       Also notable details being that this moves
	       the read/write cursor into SEEK_SET/start=0
	       location, which did latter cause some trouble..

	     */
#endif /* HAVE_FTRUNCATE */

#ifdef HAVE_FSYNC
	    while (fsync(sffileno(fp)) < 0)
	      if (errno != EINTR && errno != EAGAIN)
		break;
#endif
	    /* Discard and close! */
	    zsfclose(fp);
	    eofindex = -1;
	    fp = NULL;
	    goto time_reset;
	  }

	if (verboselog)
	  fprintf(verboselog," end of putmail(file='%s'), topipe=%d\n",
		  file,topipe);

	if (!topipe) {
	  /*
	   * Ok, we are NOT writing to a pipe, and thus we can do
	   * fseek(), and play with things...
	   */
	  /*
	   * Determine how many newlines to append to the previous text.
	   *
	   * If the last characters are:	\n\n, append 0 newlines,
	   *				[^\n]\n or \n append 1 newline,
	   *				else append 2 newlines.
	   *
	   * Optionally preserve the mbox's atime, so
	   * login etc. can distinguish new mail from old.
	   * The mtime will be set to now by the following write() calls.
	   */
	  err = errno;
	  sfseek(fp, (Sfoff_t)-2LL, SEEK_END);
	  len = sfread(fp, buf, 2);
	  sfseek(fp, (Sfoff_t)0,    SEEK_END);
	  /* to end of file, again */
	  errno = err;

	  if (verboselog)
	    fprintf(verboselog," .. EOF read did yield %d bytes\n", len);

	  if (len == 1 || len == 2) {
	    --len;
	    len = (buf[len]!='\n') + (len == 1 ? buf[0]!='\n' : 1);

	    if (len > 0 && sfwrite(fp, "\n\n", len) != len)
	      failed = 1;

	    if (!failed) sfsync(fp);
	    if (!failed && sferror(fp)) failed = 1;

	    if (verboselog)
	      fprintf(verboselog," .. wrote %d newlines to the end%s\n",
		      len, failed ? " FAILED!":"");

	    mw=2;

	    if (failed)
	      goto write_failure;

	  }

	  /* End of the file, and MMDF-style ? */
	  if (mmdf_mode == 1 /* Values 2 and 3 exist on PIPEs only.. */ ) {
	    if (sfprintf(fp,"\001\001\001\001\n") == EOF) {
	      mw=3;
	      goto write_failure;
	    }
	  }

	} /* !topipe */

	/* Flush everything out */
	sfsync(fp);
	/* Raise an error only if it is non-pipe target */
	if (!topipe && sferror(fp)) {
	  mw=4;
	  goto write_failure;
	}

#ifdef HAVE_FSYNC
	if (!topipe) {
	  while (fsync(fdmail) < 0) {
	    if (errno == EINTR || errno == EAGAIN)
	      continue;

#if 0	/* No, don't err if fsync() fails. */
	    mw=5;
	    goto write_failure;
#else
	    break;
#endif
	  }
	}
#endif


      time_reset:

	/* This is actually Linux-thing, we reset the last access time
	   to be that of before we did read the file, last modification
	   into current moment -- At Linux 1.3.8x the system is a bit
	   over-eager to update atime information at  O_RDWR -file.. */
	time(&st.st_mtime); /* Set the modification time to be now.. */

	if (logfp != NULL) {
	  /* [haa@cs.hut.fi] added more info here to catch errors
	     in delivery  */
	  fprintf(logfp,
		  "%s: %d + %d : %s (pid %d user %s)\n",
		  dp->logident, (int)eofindex,
		  (int)((fp ? sftell(fp): 0) - eofindex), file,
		  (int)getpid(), rp->addr->user);
	  fflush(logfp);
	}

	if (!topipe && keepatime) {
#ifdef	HAVE_UTIME
	  struct utimbuf tv;
	  tv.actime  = st.st_atime;
	  tv.modtime = st.st_mtime;
	  rc = utime(file, &tv);
#else  /* !HAVE_UTIMES */
	  struct timeval tv[2];
	  tv[0].tv_sec = st.st_atime;
	  tv[1].tv_sec = st.st_mtime;
	  tv[0].tv_usec = tv[1].tv_usec = 0;
	  rc = utimes(file, tv);
#endif /* !HAVE_UTIMES */
	}


	if (fp) {
	  /* Discard and close */
	  zsfclose(fp);
	  /* The pointer is needed latter! */
	}

	return fp; /* Dummy marker! */
}

int
program(dp, rp, cmdbuf, user, timestring, uid)
	struct ctldesc *dp;
	struct rcpt *rp;
	const char *cmdbuf;
	const char *user;
	const char *timestring;
	int uid;
{
	int envi, rc, pid, in[2], out[2];
	int gid = -1;
	char *env[40];
	const char *s;
	char *cp, *cpe;
	int status;
	struct Zpasswd *pw;
	Sfio_t *errfp;
	Sfio_t *fp;
	time_t starttime, endtime;
	char safe1[1100]; /* Stack safety buffer zones.. */
	char buf[8192];
	char safe2[1100]; /* second stack safety buffer */
	char errbuf[4*1024];

	time(&starttime);
	cp = safe1; cp = safe2; /* Silence compiler... */

	notaryreport(rp->addr->user, NULL, NULL, NULL);

	envi = 0;
	env[envi++] = "SHELL=/bin/sh";
	env[envi++] = "IFS= \t\n";

	while (1) {
	  /* Zone in which:
	       if (cp > cpe) break;
	     statement can be used as buffer overflow safety.. */


	  cp = buf;
	  *cp = 0; /* Trunc the buf string... */
	  cpe = buf + sizeof(buf) -2;
	  if ((s = getzenv("PATH")) == NULL)
	    env[envi++] = "PATH=/usr/bin:/bin:/usr/ucb";
	  else {
	    sprintf(cp, "PATH=%.999s", s);
	    env[envi++] = cp;
	    cp += strlen(cp) + 1;
	  }
	  s = getenv("TZ");
	  if (s != NULL) {
	    sprintf(cp,"TZ=%.99s", s);
	    env[envi++] = cp;
	    cp += strlen(cp) + 1;
	  }

	  pw = zgetpwuid(uid);
	  if (pw == NULL) {

	    if (verboselog) {
	      fprintf(verboselog,"mailbox: User recipient address privilege code invalid (no user with this uid?): '%s'\n", rp->addr->misc);
	    }
	    sprintf(buf,"x-local; 500 (User recipient address privilege code invalid [no user with this uid?]: '%.200s')", rp->addr->misc);
	    notaryreport(NULL,"failed",
			 "5.3.0 (User address recipient privilege code invalid)",
			 buf);
	    DIAGNOSTIC(rp, cmdbuf, EX_SOFTWARE,
		       "Bad privilege for a pipe \"%s\"", rp->addr->misc);
	    return EX_SOFTWARE;
	  } else {
	    gid = pw->pw_gid;
	    sprintf(cp, "HOME=%.500s", pw->pw_dir);
	    env[envi++] = cp;
	    cp += strlen(cp) + 1;

	    if (user[0] == 0)
	      sprintf(cp, "USER=%.100s", pw->pw_name);
	    else
	      sprintf(cp, "USER=%.100s", user);
	    env[envi++] = cp;
	    cp += strlen(cp) + 1;
	  }
	  if (STREQ(rp->addr->link->channel,"error"))
	    sprintf(cp, "SENDER=<>");
	  else
	    sprintf(cp, "SENDER=%.999s", rp->addr->link->user);
	  env[envi++] = cp;
	  cp += strlen(cp) + 1;

	  sprintf(cp, "UID=%d", (int)uid);
	  env[envi++] = cp;
	  cp += strlen(cp) + 1;
	  if (cp > cpe) break;

	  if ((s = getzenv("ZCONFIG")) == NULL)
	    s = ZMAILER_ENV_FILE;

	  sprintf(cp, "ZCONFIG=%.200s", s);
	  env[envi++] = cp;
	  cp += strlen(cp) + 1;
	  if (cp > cpe) break;

	  if ((s = getzenv("MAILBIN")) == NULL)
	    s = MAILBIN;
	  sprintf(cp, "MAILBIN=%.200s", s);
	  env[envi++] = cp;
	  cp += strlen(cp) + 1;
	  if (cp > cpe) break;

	  if ((s = getzenv("MAILSHARE")) == NULL)
	    s = MAILSHARE;
	  env[envi++] = cp;
	  sprintf(cp, "MAILSHARE=%.200s", s);
	  cp += strlen(cp) + 1;
	  if (cp > cpe) break;

	  if (rp->notifyflgs) {
	    char *p = "", *p2 = ",";
	    env[envi++] = cp;
	    sprintf(cp,"NOTIFY="); cp += strlen(cp);
	    if (rp->notifyflgs & _DSN_NOTIFY_NEVER) {
	      strcpy(cp, "NEVER"); p = p2; cp += strlen(cp); }
	    if (rp->notifyflgs & _DSN_NOTIFY_DELAY) {
	      sprintf(cp, "%sDELAY", p); p = p2; cp += strlen(cp); }
	    if (rp->notifyflgs & _DSN_NOTIFY_FAILURE) {
	      sprintf(cp, "%sFAILURE", p); p = p2; cp += strlen(cp); }
	    if (rp->notifyflgs & _DSN_NOTIFY_SUCCESS) {
	      sprintf(cp, "%sSUCCESS", p); p = p2; cp += strlen(cp); }
	    if (rp->notifyflgs & _DSN_NOTIFY_TRACE) {
	      sprintf(cp, "%sTRACE", p); p = p2; cp += strlen(cp); }
	    ++cp;
	  }
	  if (rp->deliverby || rp->deliverbyflgs) {
	    env[envi++] = cp;
	    sprintf(cp,"BY=%ld;",rp->deliverby); cp += strlen(cp);
	    if (rp->deliverbyflgs & _DELIVERBY_R) *cp++ = 'R';
	    if (rp->deliverbyflgs & _DELIVERBY_N) *cp++ = 'N';
	    if (rp->deliverbyflgs & _DELIVERBY_T) *cp++ = 'T';
	    *cp++ = 0;
	  }
	  if (rp->orcpt) {
	    sprintf(cp, "ORCPT=%.999s", rp->orcpt);
	    env[envi++] = cp;
	    cp += strlen(cp) + 1;
	    if (cp > cpe) break;
	  }
	  if (rp->inrcpt) {
	    sprintf(cp, "INRCPT=%.999s", rp->inrcpt);
	    env[envi++] = cp;
	    cp += strlen(cp) + 1;
	    if (cp > cpe) break;
	  }
	  if (rp->infrom) {
	    sprintf(cp, "INFROM=%.999s", rp->infrom);
	    env[envi++] = cp;
	    cp += strlen(cp) + 1;
	    if (cp > cpe) break;
	  }
	  if (rp->ezmlm) {
	    sprintf(cp, "EZMLM=%.999s", rp->ezmlm);
	    env[envi++] = cp;
	    cp += strlen(cp) + 1;
	    if (cp > cpe) break;
	  }
	  if (dp->envid) {
	    sprintf(cp, "ENVID=%.999s", dp->envid);
	    env[envi++] = cp;
	    cp += strlen(cp) + 1;
	    if (cp > cpe) break;
	  }
	
	  env[envi++] = cp;
	  strcpy(cp, "MSGSPOOLID="); cp += 11;
	  taspoolid(cp, rp->desc->msgmtime, rp->desc->msginonumber);
	  cp += strlen(cp) + 1;
	  if (cp > cpe) break;

	  if (rp->desc->msgfile) {
	    /* Put also the message-id of the message into variables. */
	    env[envi++] = cp;
	    sprintf(cp, "MESSAGEID=%.199s", rp->desc->msgfile);
	    cp += strlen(cp) + 1;
	    if (cp > cpe) break;
	  }

	  if (verboselog)
	    fprintf(verboselog,"To run a pipe with uid=%d gid=%d cmd='%s'\n",
		    uid, gid, cmdbuf);

	  /* Here the CP should be less than about 5000 bytes
	     into the 8k buffer .. */

	  break;
	}

	env[envi] = NULL;

	if (cp >= cpe)
	  /* OVERFLOWED THE 8kB BUFFER FOR THE NEW ENVIRONMENT VARIABLES! */
	  exit(EX_SOFTWARE);

	/* now we can fork off and run the command... */
	if (pipe(in) < 0) {
	  notaryreport(NULL,"failed",
		       "5.3.0 (out of pipe resources)",
		       "x-local; 500 (out of pipe resources)");
	  DIAGNOSTIC(rp, cmdbuf, EX_OSERR,
		     "cannot create pipe from \"%s\"", cmdbuf);
	  return EX_OSERR;
	}
	if (pipe(out) < 0) {
	  notaryreport(NULL,"failed",
		       "5.3.0 (out of pipe resources)",
		       "x-local; 500 (out of pipe resources)");
	  DIAGNOSTIC(rp, cmdbuf, EX_OSERR,
		     "cannot create pipe to \"%s\"", cmdbuf);
	  close(in[0]);
	  close(in[1]);
	  return EX_OSERR;
	}

	pid = fork();
	if (pid == 0) { /* child */
	  char * argv[100];
	  int i;

	  SETGID(gid);
	  SETEGID(gid);
	  SETUID(uid);
	  SETEUID(uid);

	  close(in[0]);
	  close(out[1]);
	  /* its stdout and stderr is the pipe, its stdin is our fdmail */
	  close(0);
	  dup(out[0]);		/* in fd 0 */
	  close(1);
	  dup(in[1]);		/* in fd 1 */
	  close(2);
	  dup(in[1]);		/* in fd 2 */
	  close(out[0]);
	  close(in[1]);
	  SIGNAL_IGNORE(SIGINT);
	  SIGNAL_IGNORE(SIGHUP);
	  SIGNAL_HANDLE(SIGTERM, SIG_DFL);

	  /* hmm.. must split the command line to inputs for  execve();
	     I have uses for a strict environment without  /bin/sh ... [mea] */

	  cp = (char*)cmdbuf+1;
	  s = strchr(cp,'$');
	  if (!s)
	    s = strchr(cp,'>');

	  if (*cp == '/' && s == NULL) {
	    /* Starts with an ABSOLUTE PATH -- at least "/" */
	    /* ... and does *NOT* contain '$', nor '>' */
	    i = 0;
	    while (*cp != 0) {
	      while (*cp == ' ') ++cp;
	      if (*cp == '\'') {
		argv[i] = ++cp;
		while (*cp != 0 && *cp != '\'') ++cp;
		if (*cp == '\'') *cp++ = 0;
	      } else if (*cp != 0)
		argv[i] = cp;
	      ++i;
	      while (*cp != 0 && *cp != ' ') ++cp;
	      if (*cp == ' ') *cp++ = 0;
	    }
	    argv[i] = NULL;
	    if (verboselog) {
	      fprintf(verboselog," argv:");
	      for (i = 0; argv[i] != NULL; ++i)
		fprintf(verboselog," [%d]<%s>", i, argv[i]);
	      fprintf(verboselog,"\n");
	    }
	    execve(argv[0], argv, env);

	  } else {

	    /* Duh, probably something like:
	       "|IFS=' '&&.... "
	    */

	    /*
	     * Note that argv[0] is set to the command we are running.
	     * That way, we should get some better error messages, at
	     * least more understandable in rejection messages.
	     * Some bourne shells may go into restricted mode if the
	     * stuff to run contains an 'r'. XX: investigate.
	     */

	    argv[0] = (char*)cmdbuf+1;
	    argv[1] = "-c";
	    argv[2] = (char*)cmdbuf+1;
	    argv[3] = NULL;

	    execve("/bin/sh", argv, env);
	    /* execle(argv[0], cmdbuf+1,"-c",cmdbuf+1,(char*)NULL,env);*/
	    execve("/sbin/sh", argv, env);
	    /* execle(argv[0], cmdbuf+1, "-c", cmdbuf+1, (char *)NULL, env); */
	  }

	  write(2, "Cannot exec '", 13);
	  write(2, argv[0], strlen(argv[0]));
	  write(2, "'\n", 2);
	  _exit(128);

	} else if (pid < 0) {	/* fork failed */

	  notaryreport(NULL,"failed",
		       "5.3.0 (fork failure)",
		       "x-local; 500 (fork failure)");
	  DIAGNOSTIC(rp, cmdbuf, EX_OSERR, "cannot fork", 0);
	  return EX_OSERR;

	} /* parent */

	close(out[0]);
	close(in[1]);

	errfp = sfnew(NULL, errbuf, sizeof(errbuf), in[0], SF_READ);
	/* write the message */
	mmdf_mode += 2;
	eofindex = -1; /* NOT truncatable! */
	fp = putmail(dp, rp, out[1], "a", timestring, cmdbuf, uid);
	/* ``fp'' is dummy marker */
	mmdf_mode -= 2;
	if (fp == NULL) {
	  pid = wait(&status);
	  close(out[1]);
	  zsfclose(errfp);
	  return status;
	}
	close(out[1]);
	/* read any messages from its stdout/err on in[0] */
	/* ... having forked and set up the pipe, we quickly continue */
	buf[sizeof(buf)-100] = 0; /* Chop it just to make sure */
	if (csfgets(buf, (sizeof buf) - 100, errfp) < 0)
		buf[0] = '\0';
	else if ((cp = strchr(buf, '\n')) != NULL)
		*cp = '\0';
	pid = wait(&status);
	zsfclose(errfp);
	cp = buf + strlen(buf);

	/* Union or not, we treat it as if it were an integer.. */

	if (status == 0) {
	  rc = EX_OK;
	  if (cp != buf)
	    *cp++ = ' ';
	  strcpy(cp, "[Exit Status 0]");
	} else if ((status & 0177) > 0) {
	  if (cp != buf)
	    *cp++ = ' ';
	  sprintf(cp, "[signal %d", status & 0177);
	  if (status & 0200)
	    strcat(cp, " (Core dumped)");
	  strcat(cp, "]");
	  rc = EX_TEMPFAIL;
	} else if ((rc = (status >> 8) & 0377) > 0) {
	  if (cp != buf)
	    *cp++ = ' ';
	  sprintf(cp, "[exit status %d]", rc);
	  /* We report following status codes to the system as is,
	     all the rest are treated as EX_TEMPFAIL, and retried.. */
	  if (rc != EX_NOPERM && rc != EX_UNAVAILABLE && rc != EX_NOHOST &&
	      rc != EX_NOUSER && rc != EX_DATAERR     && rc != EX_OK )
	    rc = EX_TEMPFAIL;
	}

	if (verboselog)
	  fprintf(verboselog,"Run result: '%s'\n", buf);

	time(&endtime);
	notary_setxdelay((int)(endtime-starttime));
	if (rc == EX_OK) {
	  notaryreport(NULL,"delivered",
		       "2.2.0 (Delivered successfully)",
		       "x-local; 250 (Delivered successfully)");
	} else {
	  char buf2[sizeof(buf)+10];
	  sprintf(buf2,"x-local; 500 (%s)", buf);
	  notaryreport(NULL,"failed",
		       "5.3.0 (subprogram non-zero termination code)",
		       buf2);
	}
	
	DIAGNOSTIC(rp, cmdbuf, rc, "%s", buf);
	return rc;
}

static void mkhashpath __((char *, const char *));
static void mkhashpath(s, uname)
     char *s;
     const char *uname;
{
	extern long pjwhash32 __((const char *));
	extern long crc32     __((const char *));

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


/*
 * creatembox - see if we can create the mailbox
 */
int
creatembox(rp, uname, filep, uid, gid, pw)
	struct rcpt *rp;
	const char *uname;
	char **filep;
	uid_t *uid;
	gid_t *gid;
	struct Zpasswd *pw;
{
	const char **maild;
	int fd = -1;
	char *s;

	*uid = pw->pw_uid;
	*gid = pw->pw_gid;

	for (maild = &maildirs[0]; *maild != 0; maild++) {
	  if (*filep != NULL)
	    free(*filep);
	  if (strchr(*maild,'%')) {
	    *filep = emalloc(2048);
	    if (fmtmbox(*filep,2048,*maild,uname,pw)) {
	      (*filep)[70]='\0';
	      strcat(*filep,"...");
	      notaryreport(rp->addr->user, "failed",
		       "5.3.1 (too long path for user spool mailbox file)",
		       "x-local; 566 (too long path for user spool mailbox file)");
	      DIAGNOSTIC(rp, *filep, EX_CANTCREAT, "Too long path \"%s\"", *filep);
	      free(*filep);
	      *filep=NULL;
	      return 0;
	    }
/*
  FIXME! Need to create intermediate directories here
*/
	  } else {
	    *filep = emalloc(8+2+strlen(*maild)+strlen(uname));
	    sprintf(*filep, "%s/", *maild);
	    s = *filep + strlen(*filep);

	    mkhashpath(s, uname);
	  }

	  fd = createfile(rp, *filep, *uid, 1);
	  if (fd >= 0) {
#ifdef	HAVE_FCHOWN
	    fchown(fd, *uid, *gid);
#else  /* !HAVE_FCHOWN */
	    chown(*filep, *uid, *gid);
#endif /* HAVE_FCHOWN */
	    close(fd);
	    {
	      struct stat st;
#ifdef	HAVE_UTIME
	      struct utimbuf tv;
	      stat(*filep,&st); /* This by all probability will not fail.. */
	      tv.actime  = 0;	/* never read */
	      tv.modtime = st.st_mtime;
	      utime(*filep, &tv);
#else
	      struct timeval tv[2];
	      stat(*filep,&st); /* This by all probability will not fail.. */
	      tv[0].tv_sec = 0; /* never read */
	      tv[1].tv_sec = st.st_mtime;
	      tv[0].tv_usec = tv[1].tv_usec = 0;
	      utimes(*filep, tv);
#endif
	    }
	    return 1;
	  }
	  if (errno == EEXIST) { /* It exists -- probably a race between
				    two file creators caused this */
	    
	    return 1;
	  }
	}

	/* assert *filep != NULL */
	if (fd == -1) {
	  notaryreport(rp->addr->user, "failed",
		       "5.3.1 (can't create user spool mailbox file)",
		       "x-local; 566 (can't create user spool mailbox file)");
	  DIAGNOSTIC(rp, *filep, EX_CANTCREAT, "can't create \"%s\"", *filep);
	}
	/* otherwise the message was printed by createfile() */
	free(*filep);
	return 0;
}

int
createfile(rp, file, iuid, ismbox)
	struct rcpt *rp;
	const char *file;
	int iuid, ismbox;
{
	int fd, i = 0, saverrno;
	struct stat st;
	char *cp, msg[BUFSIZ];
	uid_t uid = iuid;
	int mailmode = MAILMODE;

	if (verboselog)
	  fprintf(verboselog,
		  "To create a file with euid=%d egid=%d file='%s', mode=%o\n",
		  (int)geteuid(), (int)getegid(), file, mailmode);

	fd = open(file, O_RDWR|O_CREAT|O_EXCL, mailmode);
	if (fd < 0) {
	  saverrno = errno;
	  if (verboselog)
	    fprintf(verboselog,
		    " ... failed, errno = %d (%s)\n",
		    saverrno, strerror(saverrno));
	  
	  if (errno == EEXIST)
	    return -3;
	  cp = strrchr(file, '/');
	  if (cp != NULL) {
	    *cp = '\0';
	    if (exstat(rp, file, &st, stat) < 0) {
	      *cp = '/';
	      sprintf(msg,"x-local; 566 (*INVOCATION BUG* Can't create user spool mailbox file: \"%s\", Directory stat() error: %s)",
		      file,strerror(errno));
	      *cp = 0;
	      notaryreport(rp->addr->user, "failed",
			   "5.3.5 (Something wrong, bad config ?)", msg);
	      DIAGNOSTIC(rp, file, i, "stat failed on %s", file);
	      return -2;
	    }
	    *cp = '/';
	    if (ismbox && st.st_mode & 020) { /* group writable? */
	      if (!setupuidgid(rp, uid, st.st_gid)) {
		notaryreport(rp->addr->user, "failed",
			     "5.3.5 (The mailbox configuration is faulty)",
			     "x-local; 566 (*INVOCATION BUG* The mailbox directory is group writable, but can't change my gid to it)");
		DIAGNOSTIC(rp, file, i,
			   "failed changing group id to create file in \"%s\"",
			   file);
		return -2;
	      }
	      mailmode += 0060;
	    }
	  }

	  if (verboselog)
	    fprintf(verboselog,
		    "To create a file with euid=%d egid=%d file='%s' mode=%o\n",
		    (int)geteuid(), (int)getegid(), file, mailmode);

	  fd = open(file, O_RDWR|O_CREAT|O_EXCL, mailmode);
	  if (fd < 0) {
	    saverrno = errno;
	    if (verboselog)
	      fprintf(verboselog,
		      " ... failed, errno = %d (%s)\n",
		      saverrno, strerror(saverrno));
	    setrootuid(rp);
	    errno = saverrno;
	    if (errno == EEXIST)
	      return -3;
	  } else {
	    setrootuid(rp);
	    return fd;
	  }
	} else
	  return fd;

	/* No system calls in this spot -- must preserve errno */
	if (TEMPFAIL(saverrno))	/* temporary error? */
	  i = EX_TEMPFAIL;
	else if (saverrno != EACCES && saverrno != ENOENT)
	  i = EX_UNAVAILABLE;
	else if (saverrno == EACCES)
	  i = EX_NOPERM;
	else /* if (saverrno == ENOENT) */
	  i = EX_CANTCREAT;
	/* convoluted to maintain 4 arguments to DIAGNOSTIC */
	sprintf(msg, "x-local; 566 (error [%s] creating \"%%s\")", strerror(saverrno));
	notaryreport(rp->addr->user, "failed",
		     "5.3.0 (Other mailsystem error)",
		     msg);
	sprintf(msg, "error (%s) creating \"%%s\"", strerror(saverrno));
	DIAGNOSTIC(rp, file, i, msg, file);
	errno = saverrno;
	return -2;
}

/*
 * setupuidgid - set the euid and gid of the process
 */
int
setupuidgid(rp, uid, gid)
	struct rcpt *rp;
	int uid;
	int gid;
{
	setrootuid(rp);

	if (gid == -3) {
	  /* MAGIC! Ask GID of the UID of 'uid' */
	  struct Zpasswd *pw = zgetpwuid(uid);
	  if (pw != NULL)
	    gid = pw->pw_gid;
	}
	
	if (gid >= 0)
	  if (SETGID(gid) < 0) {
	    DIAGNOSTIC(rp, "", EX_OSERR, "can't setgid to %d", (int)gid);
	    return 0;
	  }
	if (*(rp->addr->user) == TO_FILE || *(rp->addr->user) == TO_PIPE)
	  uid = atol(rp->addr->misc);
	if (SETEUID(uid) < 0) {
	  if (uid < 0 && atol(rp->addr->misc) < 0) {
	    /* use magic non-sense +ve uid < MAXSHORT */
	    rp->addr->misc = NONUIDSTR;
	    return setupuidgid(rp, (uid_t)atoi(NONUIDSTR), gid);
	  }
	  DIAGNOSTIC(rp, "", EX_OSERR, "can't seteuid to %d", (int)uid);
	  return 0;
	}
	currenteuid = uid;
	return 1;
}


/*
 * exists - see if a mail box exists.  Looks at the exit status
 *	    to guess whether failure is due to nfs server being
 *	    down.
 */

char *
exists(maildir, uname, pw, rp)
	const char *maildir;
	const char *uname;
	struct Zpasswd *pw;
	struct rcpt *rp;
{
	char *file, *s;

	if (strchr(maildir, '%') != NULL) {
	  file = emalloc(2048);
	  if (fmtmbox(file, 2048, maildir, uname, pw)) {
	    file[70]='\0';
	    strcat(file,"...");
	    DIAGNOSTIC(rp, file, EX_SOFTWARE,
		     "mailbox path does not fit in buffer \"%s\"", file);
	    free(file);
	    return NULL;
	  }
	} else {
	  file = emalloc(8+strlen(maildir)+strlen(uname));
	  sprintf(file, "%s/", maildir);

	  s = file + strlen(file);
	  mkhashpath(s, uname);
	}

	if (access(file, F_OK) == 0) { /* file exists */
	  rp->status = EX_OK;
	  return file;
	}

	if (TEMPFAIL(errno)) {	/* temporary error? */
	  DIAGNOSTIC(rp, file, EX_TEMPFAIL, "error accessing \"%s\"", file);
	} else if (errno == ENOENT || errno == EACCES) /* really not there? */
	  rp->status = EX_OK;
	else {					/* who knows? */
	  DIAGNOSTIC(rp, file, EX_SOFTWARE,
		     "unexpected error accessing \"%s\"", file);
	}
	free(file);
	return NULL;
}


/*
 * setrootuid - set us back to root uid
 */

void
setrootuid(rp)
	struct rcpt *rp;
{
	if (currenteuid != 0) {
	  if (SETEUID(0) < 0)
	    DIAGNOSTIC(rp, "", EX_OSERR, "can't reset uid to root", 0);
	}
	currenteuid = 0;
}


/*
 * appendlet - append letter to file pointed at by fd
 *
 *	Return the last character written..
 *
 */
int
appendlet(dp, rp, WS, file, ismime)
     struct ctldesc *dp;
     struct rcpt *rp;
     struct writestate *WS;
     int ismime;
     const char *file;
{
#if !(defined(HAVE_MMAP) && defined(TA_USE_MMAP))
	register int i;
	register int bufferfull;
	Sfio_t *mfp;
	int mfd = dp->msgfd;
#else
	char *s;
#endif


#if !(defined(HAVE_MMAP) && defined(TA_USE_MMAP))

	if (ismime) {
	  /* can we use cache of message body data ? */
	  /* Split it to lines.. */
	  if (readalready > 0) {
	    int linelen, readidx = 0;
	    const char *s0 = let_buffer, *s;
	    while (readidx < readalready) {
	      s = s0;
	      linelen = 0;
	      while (*s != 0 && *s != '\n' && readidx < readalready) {
		++s; ++linelen; ++readidx;
	      }
	      if (*s == '\n' && readidx < readalready) {
		++s; ++linelen; ++readidx;
	      }
	      if (writemimeline(WS, s0, linelen) != linelen) {
		DIAGNOSTIC(rp, file, EX_IOERR,
			   "write to \"%s\" failed(1)", file);
		return -256;
	      }
	      s0 = s;
	    }
	    rp->status = EX_OK;
	    return WS->lastch;
	  }

	  lseek(mfd, (off_t)dp->msgbodyoffset, SEEK_SET);
	  mfp = sfnew(NULL, NULL, 16*1024, mfd, SF_READ|SF_WHOLE);

#define MFPCLOSE zsfsetfd(mfp,-1); zsfclose(mfp);

	  /* we are assuming to be positioned properly
	     at the start of the message body */
	  bufferfull = 0;
	  /* We really can't use the 'let_buffer' cache here */
	  readalready = 0;
	  i = 0;
	  while ((i = csfgets(let_buffer, sizeof(let_buffer), mfp)) != EOF) {
	    /* It MAY be malformed -- if it has a BUFSIZ length
	       line in it, IT CAN'T BE MIME  :-/		*/
	    if (i == sizeof(let_buffer) &&
		let_buffer[sizeof(let_buffer)-1] != '\n')
	      ismime = 0;
	    /* Ok, write the line */
	    if (writemimeline(WS, let_buffer, i) != i) {
	      DIAGNOSTIC(rp, file, EX_IOERR, "write to \"%s\" failed(2)", file);
 	      MFPCLOSE;
	      return -256;
	    }
	  }
	  if (i == EOF && !sfeof(mfp) && !sferror(mfp)) {
	    DIAGNOSTIC(rp, file, EX_IOERR, "read error from message file", 0);
	    MFPCLOSE;
	    return -256;
	  }

	  MFPCLOSE;

	} else {		/* is NOT MIME message.. */

	  /* can we use cache of message body data ? */
	  if (readalready != 0) {
	    if (writebuf(WS, let_buffer, readalready) != readalready) {
	      DIAGNOSTIC(rp, file, EX_IOERR,
			 "write to \"%s\" failed(3)", file);
	      return -256;
	    }
	    rp->status = EX_OK;
	    return WS->lastch;
	  }

	  /* Make sure we are properly positioned at the start
	     of the message body */
	  lseek(mfd, dp->msgbodyoffset, SEEK_SET);
	  bufferfull = 0;
	  while (1) {
	    i = read(mfd, let_buffer, sizeof(let_buffer));
	    if (i == 0)
	      break;
	    if (i < 0) {
	      DIAGNOSTIC(rp, file, EX_IOERR,
			 "read error from message file", 0);
	      readalready = 0;
	      return -256;
	    }
	    if (writebuf(WS, let_buffer, i) != i) {
	      DIAGNOSTIC(rp, file, EX_IOERR, "write to \"%s\" failed(4)", file);
	      readalready = 0;
	      return -256;
	    }
	    readalready = i;
	    bufferfull++;
	  }

	  if (bufferfull > 1)	/* not all in memory, need to reread */
	    readalready = 0;
	}
#else /* HAVE_MMAP  --  get the input from  mmap():ed memory area.. */
	s = dp->let_buffer + dp->msgbodyoffset;
	if (ismime) {
	  int i;

	  while (s < dp->let_end) {
	    const char *s2 = s;
	    i = 0;
	    while (s2 < dp->let_end && *s2 != '\n') ++s2, ++i;
	    if (s2 < dp->let_end && *s2 == '\n') ++s2, ++i;
	    if (writemimeline(WS, s, i) != i) {
	      DIAGNOSTIC(rp, file, EX_IOERR,
			 "write to \"%s\" failed(5)", file);
	      return -256;
	    }
	    s = s2;
	  }
	} else {
	  if (writebuf(WS, s, dp->let_end - s) != (dp->let_end - s)) {
	      DIAGNOSTIC(rp, file, EX_IOERR,
			 "write to \"%s\" failed(6)", file);
	      return -256;
	  }
	}
#endif
	return WS->lastch;
}


/*
 * estat - stat with error checking
 */
int
exstat(rp, file, stbufp, statfcn)
	struct rcpt *rp;
	const char *file;
	struct stat *stbufp;
	int (*statfcn) __((const char *, struct stat *));
{
	if (statfcn(file, stbufp) < 0) {
	  if (TEMPFAIL(errno))
	    rp->status = EX_TEMPFAIL;
	  else
	    rp->status = EX_SOFTWARE;
	  DIAGNOSTIC(rp, file, rp->status, "can't stat \"%s\"", file);
	  return -1;
	}
	return 0;
}

#if	defined(HAVE_SOCKET)
void
biff(hostname, username, offset)
	const char *hostname, *username;
	long offset;
{
	int f;
	spkey_t symid;
	struct hostent *hp;
	struct sockaddr_in biffaddr, *bap;
	struct spblk *spl;
	static struct sptree *spt_hosts = NULL;
	char *buf;

#define BIFF_PORT 512 /* A well-known UDP port.. */
	/* Could do this with  getservbyname() - but sometimes (with NIS
	   on loaded Suns) it takes AGES...  Hardwiring works as well.   */

	symid = symbol((const void*)hostname);
	if (spt_hosts == NULL)
	  spt_hosts = sp_init();
	spl = sp_lookup(symid, spt_hosts);
	if (spl == NULL) {
	  if ((hp = gethostbyname(hostname)) == NULL)
	    return;
	  memset((char *)&biffaddr, 0, sizeof biffaddr);
	  biffaddr.sin_family = hp->h_addrtype;
	  hp_init(hp);
	  if (hp_getaddr() && *hp_getaddr())
	    memcpy((char *)&biffaddr.sin_addr, *hp_getaddr(),  hp->h_length);
	  biffaddr.sin_port = htons(BIFF_PORT);
	  bap = (struct sockaddr_in *)emalloc(sizeof(struct sockaddr_in));
	  *bap = biffaddr;
	  sp_install(symid, (void*) bap, 0, spt_hosts);
	} else
	  biffaddr = *(struct sockaddr_in *)spl->data;
	buf = emalloc(3+strlen(username)+20);
	sprintf(buf, "%s@%ld\n", username, offset);
	f = socket(PF_INET, SOCK_DGRAM, 0);
	sendto(f, buf, strlen(buf)+1, 0,
	       (struct sockaddr *)&biffaddr, sizeof biffaddr);
	close(f);
	free(buf);
}
#endif	/* BIFF || RBIFF */


#if defined(HAVE_SOCKET) && defined(HAVE_PROTOCOLS_RWHOD_H)
static int
readrwho()
{
	struct whod wd;
	struct outmp outmp;
#define NMAX sizeof(outmp.out_name)
#define LMAX sizeof(outmp.out_line)

	int cc, f, n;
	spkey_t symid;
	register struct whod *w = &wd;
	register struct whoent *we;
	long now;
	char username[NMAX+1];
	DIR *dirp;
	struct dirent *dp;
	struct userhost *uhp;
	struct spblk *spl;
	
	if (spt_users == NULL)
	  return 0;
	now = time(NULL);
	if (chdir(RWHODIR) || (dirp = opendir(".")) == NULL ) {
	  /* BE SILENT -- failing RBIFF is no fault! */
	  return 0;
	  /*
	     perror(RWHODIR);
	     exit(EX_OSFILE);
	   */
	}
	while ((dp = readdir(dirp))) {
	  if (dp->d_ino == 0
	      || strncmp(dp->d_name, "whod.", 5)
	      || (f = open(dp->d_name, 0)) < 0 )
	    continue;
	  cc = read(f, (char *)&wd, sizeof (struct whod));
	  if (cc < WHDRSIZE) {
	    close(f);
	    continue;
	  }
	  if (now - w->wd_recvtime > 5 * 60) {
	    close(f);
	    continue;
	  }
	  cc -= WHDRSIZE;
	  we = w->wd_we;
	  for (n = cc / sizeof (struct whoent); n > 0; n--,we++){
	    /* make sure name null terminated */
	    strncpy(username, we->we_utmp.out_name, NMAX);
	    username[NMAX] = 0;
	    /* add to data structure */

	    symid = symbol((void*)username);
	    spl = sp_lookup(symid, spt_users);
	    if (spl == NULL)
	      continue;
	    uhp = (struct userhost *)spl->data;
	    if (uhp != NULL
		&& strcmp(uhp->hostname, w->wd_hostname) == 0)
	      continue;

	    uhp = (struct userhost *)emalloc(sizeof (struct userhost));
	    uhp->next     = (struct userhost *)spl->data;
	    uhp->hostname = strdup(w->wd_hostname);
	    spl->data     = (void *)uhp;
	  }
	  close(f);
	}
	closedir(dirp);
	return 1;
}

void
rbiff(nbp)
	struct biffer *nbp;
{
	struct spblk *spl;
	struct userhost *uhp;
	spkey_t symid;

	symid = symbol((void*)(nbp->user));
	if ((spl = sp_lookup(symid, spt_users)) == NULL)
	  return;
	for (uhp = (struct userhost *)spl->data; uhp != NULL; uhp = uhp->next)
	  biff(uhp->hostname, nbp->user, nbp->offset);
}
#endif	/* RBIFF */

/*
 * Writebuf() is like write(), except any instances of "From " at the
 * beginning of a line cause insertion of '>' at that point.
 * (Except with MMDF_MODE!)
 */

int
writebuf(WS, buf, len)
	struct writestate *WS;
	const char *buf;
	int len;
{
	register const char *cp;
	register int n;
	int   tlen;
	register char expect;
	char *fromp;

	/* -------------------------------------------- */
	/* Non-MIME processing				*/

	expect = WS->expect;
	fromp  = WS->fromp;

	WS->lastch = buf[len-1];

	for (cp = buf, n = len, tlen = 0; n > 0; --n, ++cp) {
	  register int c = *cp;
	  ++tlen;

	  if (c == '\n') {
	    expect = mmdf_mode ? 0 : 'F';
	    fromp = WS->frombuf;
	    *fromp = 0;
	    if (sfputc(WS->fp,c) == EOF)
	      { tlen = -1; break; }
	  } else if (expect != '\0') {
	    if (c == expect) {
	      *fromp++ = c;
	      *fromp   = 0;
	      switch (expect) {
	        case 'F':	expect = 'r'; break;
		case 'r':	expect = 'o'; break;
		case 'o':	expect = 'm'; break;
		case 'm':	expect = ' '; break;
		case ' ':
		  /* Write the separator, and the word.. */
		  if (sfwrite(WS->fp, ">From ", 6) == 0 || sferror(WS->fp))
		    { tlen = -1; break; }
		  /* anticipate future instances */
		  expect = '\0';
		  break;
		}
	    } else {
	      expect = '\0';
	      if (WS->frombuf[0] != 0 &&
		  sfprintf(WS->fp, "%s", WS->frombuf) < 0)
		{ tlen = -1; break; }
	      WS->frombuf[0] = 0;
	      fromp = WS->frombuf;
	      if (sfputc(WS->fp, c) < 0)
		{ tlen = -1; break; }
	    }
	  } else { /* expect == '\0'; */
	    if (sfputc(WS->fp, c) == EOF)
	      { tlen = -1; break; }
	  }
	}
	WS->expect = expect;
	WS->fromp  = fromp;
	if (tlen >= 0) return len; /* It worked ok */
	return -1;	/* errno is correct if tlen == -1 ! */
}

int
writemimeline(WS, buf, len)
	struct writestate *WS;
	const char *buf;
	int len;
{
	register char *s;
	register const char *cp;
	register int n;
	int   tlen = 0, i = 0;
	char *buf2;

#ifdef	USE_ALLOCA
	WS->buf2 = (char*)alloca(len+1);
#else
	if (WS->buf2 == NULL) {
	  WS->buf2 = (char*)emalloc(len+1);
	  WS->buf2len = len;
	}
	if (WS->buf2len < len) {
	  WS->buf2 = (char*)realloc(WS->buf2, len+1);
	  WS->buf2len = len;
	}
#endif
	buf2 = WS->buf2;

#if 0 /* Not yet */
	/* ------------------------------------------------------------ */
	/* MIME format processing, the input is LINE BY LINE */
	if (mime_boundary != NULL && len > mime_boundary_len+2 &&
	    buf[0] == '-' && buf[1] == '-' &&
	    strncmp(buf+2, mime_boundary, mime_boundary_len) == 0) {
	  /* ------------------------------------------------------------ */
	  /* XX: process MIME boundary! */
	  WS->lastch = buf[len-1];
	  return fwrite(buf, len, WS->fp);

	} else
#endif
	  if (convert_qp) {
	    /* ------------------------------------------------------------ */
	    /* Process Q-P chars of this line */
	    int qp_hex = 0;
	    int qp_chrs = 0;

	    for (cp = buf, s = buf2, n = len; n > 0; --n, ++cp) {
	      register int c = *cp;
	      /* At first, convert the possible QP character.. */
	      if (!qp_chrs && c == '=') {
		qp_chrs = 2;
		qp_hex  = 0;
		continue;		/* '=' starts something */
	      }
	      if (qp_chrs && c == '\n') {
		qp_chrs = 0;	/* It was "=[ \t]*\n", which was thrown away.*/
		continue;
	      }
	      if (qp_chrs == 2 && (c == ' ' || c == '\t'))
		continue;		/* It is "=[ \t]*\n", throw it away */
	      /* Ok, this may be of  =HexHex ? */
	      if (qp_chrs && ((c >= '0' && c <= '9') ||
			      (c >= 'A' && c <= 'F') ||
			      (c >= 'a' && c <= 'f'))) {
		qp_hex <<= 4;
		if (c >= '0' && c <= '9') qp_hex += (c - '0');
		if (c >= 'A' && c <= 'F') qp_hex += (c - 'A' + 10);
		if (c >= 'a' && c <= 'f') qp_hex += (c - 'a' + 10);
		--qp_chrs;
		if (!qp_chrs) c = qp_hex;
		else continue;	/* Go collect another digit */
	      } else if (qp_chrs)
		qp_chrs = 0;	/* Failed a HEX check.. */
	      /* Now we have a converted character at `c', save it! */
	      *s++ = c;
	      ++tlen;
	    }
	    /* Uhh... Stored the conversion result into buf2[], length  tlen */
	    if (!mmdf_mode && tlen >= 5 &&
		buf2[0] == 'F' && memcmp(buf2,"From ",5)==0)
	      if (WS->lastch >= 256 || WS->lastch == '\n')
		if (sfputc(WS->fp, '>') == EOF)
		  return -1;
	    if (tlen > 0) {
	      i = sfwrite(WS->fp, buf2, tlen);
	      WS->lastch = buf2[tlen-1];
	    } else
	      i = 0;
	    if (i != tlen) return -1;
	    return len;		/* Return the incoming length,
				   NOT the true length! */
	  }
	/* ------------------------------------------------------------ */
	/* Well, no other processings known.. */
	if (!mmdf_mode && buf[0] == 'F' && strncmp(buf,"From ",5)==0)
	  if (WS->lastch >= 256 || WS->lastch == '\n')
	    if (sfputc(WS->fp,'>') == EOF)
	      return -1;
	WS->lastch = buf[len-1];
	return sfwrite(WS->fp, buf, len);
}


/* [mea] See if we have a MIME  TEXT/PLAIN message encoded with
         QUOTED-PRINTABLE... */

int
qptext_check(rp)
	struct rcpt *rp;
{
	/* "Content-Transfer-Encoding: 8BIT" */

	const char **hdrs = *((const char ***)rp->newmsgheader);
	const char *hdr;
	int cte = 0;

	is_mime = 0;

	if (hdrs == NULL) return 0; /* Oh ?? */

	while (hdrs && *hdrs && (!is_mime || !cte)) {
	  hdr = *hdrs;
	  if (!cte && cistrncmp(hdr,"Content-Transfer-Encoding:",26)==0) {
	    hdr += 26;
	    while (*hdr == ' ' || *hdr == '\t') ++hdr;
	    if (cistrncmp(hdr,"QUOTED-PRINTABLE",16)==0)
	      cte = 1;
	  } else if (!is_mime && cistrncmp(hdr,"MIME-Version:",13)==0)
	    is_mime = 1;

	  ++hdrs;
	}
	if (!is_mime) cte = 0;
	return cte;
}

static const char *
find_return_receipt_hdr (rp)
    struct rcpt *rp;
{
    const char **ptr, *hdr;

    for (ptr = *((const char ***)rp->newmsgheader); *ptr != NULL; ptr++) {
        if (CISTREQN(*ptr, "Return-Receipt-To:", 18))
            break;
    }

    if (*ptr == NULL)
        return (NULL);

    hdr = *ptr + 18;
    while (*hdr != '\0' && isspace(*(unsigned char *)hdr))
        hdr++;

    return(hdr);
}

static void encodeXtext __((Sfio_t *, const char *));
static void encodeXtext(fp,str)
     Sfio_t *fp;
     const char *str;
{
	while (*str) {
	  u_char c = *str;
	  if ('!' <= c && c <= '~' && c != '+' && c != '=')
	    sfputc(fp,c);
	  else
	    sfprintf(fp,"+%02X",c);
	  ++str;
	}
}

static void
decodeXtext(mfp,xtext)
	Sfio_t *mfp;
	const char *xtext;
{
	for (;*xtext;++xtext) {
	  if (*xtext == '+') {
	    int c = '?';
	    sscanf(xtext+1,"%02X",&c);
	    sfputc(mfp,c);
	    if (*xtext) ++xtext;
	    if (*xtext) ++xtext;
	  } else
	    sfputc(mfp,*xtext);
	}
}

static const char *dfltform[7] = {
	"Subject: Returned mail: Return receipt",
	"MIME-Version: 1.0",
	"Priority: junk",
	"Content-Type: multipart/report; report-type=delivery-status;",
	"",
	"Your mail message has been delivered properly to the following recipients:",
	NULL
};

static void
return_receipt (dp, retrecptaddr, uidstr)
	struct ctldesc *dp;
	const char *retrecptaddr;
	const char *uidstr;
{
	char buf[BUFSIZ];
	const char **cpp, *mailshare, *mfpath;
	Sfio_t *mfp, *efp;
	struct rcpt *rp;
	int n;
	char boundarystr[400];
	struct Zpasswd *pw;
	int uid;
	struct stat stb;
	const char *username = "unknown";
	char *retaddr = strsave(retrecptaddr);
	char *s;

	while ((s = strchr(retaddr, '\n'))) *s = ' ';
	while ((s = strchr(retaddr, '\r'))) *s = ' ';
	while ((s = strchr(retaddr, '\t'))) *s = ' ';

	uid = atoi(uidstr);
	pw = zgetpwuid(uid);
	if (pw)
	  username = pw->pw_name;

	mfp = sfmail_open(MSG_RFC822);
	if (mfp == NULL) {
	  for (rp = dp->recipients; rp != NULL; rp = rp->next)
	    DIAGNOSTIC(rp, "", EX_TEMPFAIL, "sfmail_open failure", 0);
	  warning("Cannot open mail file!");
	  return;
	}
	sfprintf(mfp, "channel error\n");

	rp = dp->recipients;

	/* copy To: from return-receipt address */
	sfprintf(mfp, "todsn NOTIFY=NEVER ORCPT=rfc822;");
	encodeXtext(mfp, retaddr);
	sfprintf(mfp, "\nto %s\n",retaddr);
	sfprintf(mfp, "env-end\n");
	sfprintf(mfp, "To: %s\n", retaddr);
	sfprintf(mfp, "From: Automatically on behalf of the user <%s>\n",
		 username);

	free(retaddr);

	/* copy error message file itself */
	mailshare = getzenv("MAILSHARE");
	if (mailshare == NULL)
	  mailshare = MAILSHARE;

	mfpath = emalloc(3+strlen(mailshare)+strlen(FORMSDIR)
			 +strlen(RETURN_RECEIPT_FORM));
	sprintf((char*)mfpath, "%s/%s/%s",
		mailshare, FORMSDIR, RETURN_RECEIPT_FORM);


	efp = sfopen(NULL, mfpath, "r");

	{
	  char *dom = mydomain(); /* transports/libta/buildbndry.c */
	  struct stat stbuf;

	  fstat(sffileno(mfp),&stbuf);
	  taspoolid(boundarystr, stbuf.st_ctime, (long)stbuf.st_ino);
	  strcat(boundarystr, "=_/return-receipt/");
	  strcat(boundarystr, dom);
	}

	if (efp != NULL) {
	  int inhdr = 1;
	  buf[sizeof(buf)-1] = 0;
	  while (csfgets(buf,sizeof(buf)-1,efp) >= 0) {
	    if (strncmp(buf,"HDR",3)==0) {
	      sfprintf(mfp, "%s", buf+4);
	    } else if (strncmp(buf,"SUB",3)==0) {
	      sfprintf(mfp, "%s", buf+4);
	    } else {
	      if (inhdr) {
		inhdr = 0;
		sfprintf(mfp,"MIME-Version: 1.0\n");
		sfprintf(mfp,"Content-Type: multipart/report; report-type=delivery-status;\n");
		sfprintf(mfp,"\tboundary=\"%s\"\n\n\n",boundarystr);
		sfprintf(mfp, "--%s\n", boundarystr);
		sfprintf(mfp, "Content-Type: text/plain\n");
	      }
	      sfprintf(mfp, "%s", buf);
	    }
	  } /* ... while() ends.. */
	  zsfclose(efp);
	} else {
	  for (cpp = dfltform; *cpp != NULL; ++cpp)
	    if (*cpp[0] == 0) {
	      sfprintf(mfp, "\tboundary=\"%s\"\n\n", boundarystr);
	      sfprintf(mfp, "--%s\n", boundarystr);
	      sfprintf(mfp, "Content-Type: text/plain\n\n");
	    } else
	      sfprintf(mfp, "%s\n", *cpp);
	}
	/* print out errors in standard format */
	for (rp = dp->recipients; rp != NULL; rp = rp->next) {
	  sfprintf(mfp, "\t%s\n", rp->addr->user);
	}
	sfprintf(mfp, "\n--%s\n", boundarystr);
	sfprintf(mfp, "Content-Type: message/delivery-status\n\n");

	if (mydomain() != NULL) {
	  sfprintf(mfp, "Reporting-MTA: dns;%s\n", mydomain() );
	} else {
	  sfprintf(mfp, "Reporting-MTA: x-local-hostname; -unknown-\n");
	}
	if (dp->envid != NULL) {
	  sfprintf(mfp, "Original-Envelope-Id: ");
	  decodeXtext(mfp,dp->envid);
	  sfputc(mfp, '\n');
	}
	/* rfc822date() returns a string with trailing newline! */
	fstat(dp->msgfd,&stb);
	sfprintf(mfp, "Arrival-Date: %s", rfc822date(&stb.st_mtime));
	sfprintf(mfp, "\n");

	for (rp = dp->recipients; rp != NULL; rp = rp->next) {
	  if (rp->orcpt != NULL) {
	    sfprintf(mfp, "Original-Recipient: ");
	    decodeXtext(mfp,rp->orcpt);
	    sfprintf(mfp, "\n");
	  }
	  sfprintf(mfp, "Final-Recipient: X-LOCAL;%s\n", rp->addr->user);
	  sfprintf(mfp, "Action: delivered\n");
	  sfprintf(mfp, "Status: 2.2.0 (delivered successfully)\n");
	  sfprintf(mfp, "Diagnostic-Code: smtp; 250 ('%s' delivered)\n", rp->addr->user );
	  sfprintf(mfp, "\n");
	}

	sfprintf(mfp, "--%s\n", boundarystr);
	sfprintf(mfp, "Content-Type: message/rfc822\n\n");

	rp = dp->recipients;
	/* write the (new) headers with local "Received:"-line.. */
	swriteheaders(rp, mfp, "\n", 0, 0, NULL);
	sfprintf(mfp, "\n");

	sfprintf(mfp, "--%s--\n", boundarystr);
	if (sferror(mfp)) {
	  sfmail_abort(mfp);
	  n = EX_IOERR;
	} else if (sfmail_close(mfp) == EOF)
	  n = EX_IOERR;
	else
	  n = EX_OK;
	for (rp = dp->recipients; rp != NULL; rp = rp->next)
	  DIAGNOSTIC(rp, "", n, (char *)NULL, 0);
}
