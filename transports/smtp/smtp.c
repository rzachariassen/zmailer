/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *	Copyright 1991-2000 by Matti Aarnio -- modifications, including MIME
 */

#include "smtp.h"

/* About timeouts the RFC 1123 recommends:
     - Initial 220: 5 minutes
     - MAIL, RCPT : 5 minutes
     - DATA initialization (until "354.."): 2 minutes
     - While writing data, a block
       at the time: 3 minutes  (How large a block ?)
       (We increased this to 5 minutes)
     - From "." to "250 OK": 10 minutes
       (We use 20 minutes here - sendmail uses 60 minutes..)
 */
int timeout = 0;		/* how long do we wait for response? (sec.) */
int timeout_cmd  =  5*60;
int timeout_data =  2*60;
int timeout_tcpw =  5*60;	/* All tcp writes ?? */
int timeout_dot  = 20*60;
int timeout_conn =  3*60;	/* connect() timeout */

char *defcharset;
char myhostname[MAXHOSTNAMELEN+1];
int myhostnameopt;
char errormsg[ZBUFSIZ]; /* Global for the use of  dnsgetrr.c */
const char *progname;
const char *cmdline, *eocmdline, *logfile, *msgfile;
int pid;
int debug = 0;
int verbosity = 0;
int conndebug = 0;
int dotmode = 0;		/* At the SMTP '.' phase, DON'T LEAVE IMMEDIATELY!. */
int getout  = 0;		/* signal handler turns this on when we are wanted to abort! */
int gotalarm = 0;		/* indicate that alarm happened! */
jmp_buf procabortjmp;
int procabortset = 0;
#if !(defined(HAVE_MMAP) && defined(TA_USE_MMAP))
int readalready = 0;		/* does buffer contain valid message data? */
#endif
int wantreserved = 0;		/* open connection on secure (reserved) port */
int statusreport = 0;		/* put status reports on the command line */
int force_8bit = 0;		/* Claim to the remote to be 8-bit system, even
				   when it doesn't report itself as such..*/
int force_7bit = 0;		/* and reverse the previous.. */
int keep_header8 = 0;		/* Don't do "MIME-2" to the headers */
int checkwks = 0;
FILE *logfp = NULL;
extern int nobody;
char *localidentity = NULL;	/* If we are wanted to bind some altenate
				   interface than what the default is thru
				   normal kernel mechanisms.. */
int daemon_uid = -1;
int first_uid = 0;		/* Make the opening connect with the UID of the
				   sender (atoi(rp->addr->misc)), unless it is
				   "nobody", in which case use "daemon"      */

int D_alloc = 0;		/* Memory usage debug */
int no_pipelining = 0;		/* In case the system just doesn't cope with it */
int prefer_ip6 = 1;
int close_after_data = 0;


#ifdef HAVE_OPENSSL
int demand_TLS_mode = 0;	/* Demand TLS */
int tls_available = 0;		/* local client code running ok */
char *tls_conf_file = NULL;
#endif /* - HAVE_OPENSSL */

const char *FAILED = "failed";
time_t now;

extern time_t retryat_time;	/* diagnostic() thing */


time_t starttime, endtime;

char *logtag()
{
	static char buf[30];
	static int logcnt = 0;
	static char id = 0;

	/* The `id' is pseudo-random character inteded to lessen
	   the propablility of reused PID matching same prefix-
	   string between two SMTP sessions, and thus making the
	   resulting output  sort(1)able in flat ascii mode.
	   Timeorder would not be valid, perhaps, but 
	   For debugging uses, of course  */

	if (id == 0) {
	  id = '0' + (time(NULL) % 58);
	  if (id > '9') id += ('A'-'9'+1);
	  if (id > 'Z') id += ('a'-'Z'+1);
	}

	time(&now);

	sprintf(buf,"%05d%c%05d%05d", pid, id, logcnt, (int)(now % 100000));
	++logcnt;
	return buf;
}

/*
 *  ssfgets(bufpp, bufsizep, infilep, SS)
 *
 *  ALMOST like  fgets(),  but will do the smtp connection close
 *  after 3 minutes delay of sitting here..
 *
 */

static char * ssfgets __((char **, int*, int, SmtpState *));
static char *
ssfgets(bufp, bufsizp, infd, SS)
char **bufp;
int *bufsizp;
int infd;
SmtpState *SS;
{
	struct timeval tv;
	fd_set rdset;
	int rc, i, buflen, bufsiz;
	time_t tmout;
	char *s;

	time(&now);

	
	tmout = now + 3*60;


	s = *bufp;
	buflen = 0;
	bufsiz = *bufsizp -1;

outbuf_fillup:
	while (SS->stdinsize > SS->stdincurs) {
	  if (SS->stdinbuf[SS->stdincurs] == '\n') {
	    *s++ = '\n';
	    ++buflen;
	    *s = 0;
	    SS->stdincurs += 1;
	    /* Move down the buffer contents (if any) */
	    if (SS->stdinsize > SS->stdincurs)
	      memcpy(SS->stdinbuf, SS->stdinbuf+SS->stdincurs,
		     (SS->stdinsize - SS->stdincurs));
	    SS->stdinsize -= SS->stdincurs;
	    SS->stdincurs  = 0;
	    return *bufp;
	  }
	  *s = SS->stdinbuf[SS->stdincurs];
	  SS->stdincurs += 1;
	  ++buflen, ++s;
	  if (buflen >= bufsiz) {
	    /* Grow space */
	    *bufsizp <<= 1;
	    bufsiz = *bufsizp;
	    *bufp = realloc(*bufp, bufsiz);
	    --bufsiz;
	    if (!*bufp) return NULL; /* OUT OF MEMORY! */
	    s = *bufp + buflen;
	  }
	}
	/* Still here, and nothing to chew on ?  Buffer drained.. */
	SS->stdincurs = 0;
	SS->stdinsize = 0;


	while (!getout) {

	  time(&now);
	  if (tmout >= now)
	    tv.tv_sec = tmout - now;
	  else
	    tv.tv_sec = 0;
	  tv.tv_usec = 0;
	  _Z_FD_ZERO(rdset);
	  if (infd >= 0)
	    _Z_FD_SET(infd,rdset);

	  rc = select(infd+1, &rdset, NULL, NULL, &tv);
	  time(&now);

	  if (now > tmout && SS->smtpfp && sffileno(SS->smtpfp) >= 0) {
	    /* Timed out, and have a writable SMTP connection active.. */
	    /* Lets write a NOOP there. */
	    i = smtpwrite(SS, 0, "NOOP", 0, NULL);
	    if (i != EX_OK && SS->smtpfp != NULL) {
	      /* No success ?  QUIT + close! (if haven't closed yet..) */
	      if (!getout)
		smtpwrite(SS, 0, "QUIT", -1, NULL);
	      smtpclose(SS, 0);
	    }
	  }
	  if (now > tmout)
	    tmout = now + 3*60; /* Another 'keepalive' in 3 minutes */

	  if (rc == 1) { /* We have only ONE descriptor readable.. */
	    /* Got something to read on 'infd' (or EOF)
	       .. and we are non-blocking! */
	    int rdspace = sizeof(SS->stdinbuf) - SS->stdinsize;
	    fd_nonblockingmode(infd);
	    rc = read(infd, SS->stdinbuf + SS->stdinsize, rdspace);
	    fd_blockingmode(infd);

	    if (rc == 0) /* EOF! */
	      break;

	    if (rc > 0) { /* We have data! */
	      SS->stdinsize += rc;
	      goto outbuf_fillup;
	    }
#if 0
	    if (rc < 0) /* EINTR, et.al. */
	      continue;
#endif
	  }
	}

	if (s == *bufp)
	  return NULL; /* NOTHING received, gotten EOF! */
	return *bufp; /* Not EOF, got SOMETHING */
			  
}

void wantout(sig)
int sig;
{
  getout = 1;
  SIGNAL_HANDLE(sig,wantout);
  SIGNAL_RELEASE(sig);
  if (!dotmode && procabortset) /* Not within protected phase ? */
    longjmp(procabortjmp,1);
}


/* #define GLIBC_MALLOC_DEBUG__ */
#ifdef GLIBC_MALLOC_DEBUG__ /* memory allocation debugging with GLIBC */

#include <malloc.h> /* GLIBC malloc.h ! */

/* Global variables used to hold underlaying hook values.  */
static void *(*old_malloc_hook) (size_t, const void * );
static void *(*old_realloc_hook) (void *, size_t, const void *);
static void (*old_free_hook) (void*, const void *);
static void *(*old_memalign_hook) (size_t, size_t, const void *);

/* Prototypes for our hooks.  */
static void *my_malloc_hook  (size_t, const void*);
static void *my_realloc_hook (void *,size_t, const void*);
static void  my_free_hook    (void*, const void*);
static void *my_memalign_hook  (size_t, size_t, const void*);
     
static void *
my_malloc_hook (size_t size, const void *CALLER)
{
  void *result;
  /* Restore all old hooks */
  __malloc_hook = old_malloc_hook;
  __free_hook   = old_free_hook;
  /* Call recursively */
  result = malloc (size);
  /* Save underlaying hooks */
  old_malloc_hook = __malloc_hook;
  old_free_hook   = __free_hook;
  /* `printf' might call `malloc', so protect it too. */
  fprintf(stderr,"# malloc (%u) returns %p @%p\n",
	  (unsigned int) size, result, CALLER);
  /* Restore our own hooks */
  __malloc_hook = my_malloc_hook;
  __free_hook = my_free_hook;
  return result;
}

static void *
my_realloc_hook (void *ptr, size_t size, const void *CALLER)
{
  void *result;
  /* Restore all old hooks */
  __realloc_hook = old_realloc_hook;
  __malloc_hook = old_malloc_hook;
  __free_hook = old_free_hook;
  /* Call recursively */
  result = realloc (ptr, size);
  /* Save underlaying hooks */
  old_realloc_hook = __realloc_hook;
  old_malloc_hook  = __malloc_hook;
  old_free_hook    = __free_hook;
  /* `printf' might call `malloc', so protect it too. */
  fprintf(stderr,"# realloc (%p,%u) returns %p @%p\n", ptr, (unsigned int) size, result, CALLER);
  /* Restore our own hooks */
  __realloc_hook = my_realloc_hook;
  __malloc_hook  = my_malloc_hook;
  __free_hook    = my_free_hook;
  return result;
}

static void *
my_memalign_hook (size_t align, size_t size, const void *CALLER)
{
  void *result;
  /* Restore all old hooks */
  __memalign_hook = old_memalign_hook;
  __malloc_hook = old_malloc_hook;
  __free_hook = old_free_hook;
  /* Call recursively */
  result = memalign (align, size);
  /* Save underlaying hooks */
  old_memalign_hook = __memalign_hook;
  old_malloc_hook  = __malloc_hook;
  old_free_hook    = __free_hook;
  /* `printf' might call `malloc', so protect it too. */
  fprintf(stderr,"# memalign (%u,%u) returns %p @%p\n",
	  (unsigned)align, (unsigned)size, result, CALLER);
  /* Restore our own hooks */
  __memalign_hook = my_memalign_hook;
  __malloc_hook  = my_malloc_hook;
  __free_hook    = my_free_hook;
  return result;
}
     
static void
my_free_hook (void *ptr, const void *CALLER)
{
  /* Restore all old hooks */
  __malloc_hook = old_malloc_hook;
  __free_hook = old_free_hook;
  /* Call recursively */
  free (ptr);
  /* Save underlaying hooks */
  old_malloc_hook = __malloc_hook;
  old_free_hook = __free_hook;
  /* `printf' might call `free', so protect it too. */
  fprintf(stderr,"# freed pointer %p @%p\n", ptr, CALLER);
  /* Restore our own hooks */
  __malloc_hook = my_malloc_hook;
  __free_hook = my_free_hook;
}
#endif

static char *filename;
static int   filenamesize;

int
main(argc, argv)
	int argc;
	char *argv[];
{
	volatile char *channel = NULL, *host = NULL;
	int i, fd, errflg, c;
	volatile int smtpstatus;
	volatile int need_host = 0;
	int skip_host = 0;
	volatile int idle;
	volatile int noMX = 0;
	SmtpState SS;
	volatile struct ctldesc *dp;
#ifdef	BIND
	volatile int checkmx = 0; /* check all destination hosts for MXness */
#endif	/* BIND */
	RETSIGTYPE (*oldsig)__((int));
	volatile const char *smtphost, *punthost = NULL;

#ifdef GLIBC_MALLOC_DEBUG__ /* memory allocation debugging with GLIBC */
	old_malloc_hook = __malloc_hook;
	__malloc_hook = my_malloc_hook;
	old_memalign_hook = __memalign_hook;
	__memalign_hook = my_memalign_hook;
	old_realloc_hook = __realloc_hook;
	__realloc_hook = my_realloc_hook;
	old_free_hook = __free_hook;
	__free_hook = my_free_hook;
#endif

	setvbuf(stdout, NULL, _IOFBF, 8096*4 /* 32k */);
	fd_blockingmode(FILENO(stdout)); /* Just to make sure.. */

	pid = getpid();
	msgfile = "?";
	getout = 0;
	cmdline = &argv[0][0];
	eocmdline = cmdline;

	memset(&SS,0,sizeof(SS));
	SS.main_esmtp_on_banner = -1;
	SS.servport      = -1;
	SS.smtp_bufsize  = 64*1024;
	SS.ehlo_sizeval  = -1;

	for (i = 0; argv[i] != NULL; ++i)
	  eocmdline = strlen(argv[i])+ argv[i] + 1;
	/* Can overwrite also the environment strings.. */
	for (i = 0; environ[i] != NULL; ++i)
	  eocmdline = strlen(environ[i]) + environ[i] + 1;

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
	SIGNAL_IGNORE(SIGPIPE);
	timeout = timeout_cmd;

	progname = PROGNAME;
	errflg = 0;
	channel = CHANNEL;
	wantreserved = debug = statusreport = 0;
	logfile = NULL;
	myhostname[0] = '\0';
	myhostnameopt = 0;
	SS.remotemsg[0] = '\0';
	SS.remotehost[0] = '\0';
	while (1) {
	  c = getopt(argc, argv, "c:deh:l:p:rsvxDEF:L:HPS:T:VWZ:678");
	  if (c == EOF)
	    break;
	  switch (c) {
	  case 'c':		/* specify channel scanned for */
	    channel = strdup(optarg);
	    break;
	  case 'd':		/* turn on debugging output */
	    ++debug;
	    break;
	  case 'e':		/* expensive MX checking for *all* addresses */
#ifdef	BIND
	    checkmx = 1;
#else  /* !BIND */
	    ++errflg;
	    fprintf(stderr, "%s: -e unavailable, no nameserver support!\n",
		    progname);
#endif /* BIND */
	    break;
	  case 'h':		/* my hostname */
	    strncpy(myhostname,optarg,sizeof(myhostname)-1);
	    myhostname[sizeof(myhostname)-1] = 0;
	    myhostnameopt = 1;
	    break;
	  case 'l':		/* log file */
	    logfile = strdup(optarg);
	    break;
	  case 'p':		/* server port */
	    SS.servport = atoi(optarg);
	    break;
	  case 'P':
	    no_pipelining = 1;	/* It doesn't handle it.. */
	    break;
	  case 'r':		/* use reserved port for SMTP connection */
	    wantreserved = 1;
	    break;
	  case 's':		/* report status to command line */
	    statusreport = 1;
	    break;
	  case 'x':		/* don't use MX records lookups */
	    noMX = 1;
	    break;
	  case 'D':		/* only try connecting to remote host */
	    conndebug = 1;
	    break;
	  case 'E':		/* don't do EHLO, unless target system
				   has "ESMTP" on its banner */
	    SS.main_esmtp_on_banner = 0;
	    break;
	  case 'F':		/* Send all SMTP sessions to that host,
				   possibly set also '-x' to avoid MXes! */
	    punthost = strdup(optarg);
	    break;
	  case 'L':		/* Specify which local identity to use */
	    localidentity = strdup(optarg);
	    break;
	  case 'T':		/* specify Timeout in seconds */
	    if (strncasecmp(optarg,"conn=",5)==0) {
	      timeout_conn = parse_interval(optarg+5,NULL);
	      if (timeout_conn < 10) {
		fprintf(stderr, "%s: bad tcp connection timeout: %s\n",
			argv[0], optarg+5);
		++errflg;
	      }
	      break;
	    } else if (strncasecmp(optarg,"data=",5)==0) {
	      timeout_data = parse_interval(optarg+5,NULL);
	      if (timeout_data < 10) {
		fprintf(stderr, "%s: bad data timeout: %s\n",
			argv[0], optarg+5);
		++errflg;
	      }
	      break;
	    } else if (strncasecmp(optarg,"dot=",4)==0) {
	      timeout_dot = parse_interval(optarg+4,NULL);
	      if (timeout_dot < 10) {
		fprintf(stderr, "%s: bad data-dot-reply timeout: %s\n",
			argv[0], optarg+4);
		++errflg;
	      }
	      break;
	    } else if (strncasecmp(optarg,"tcpw=",5)==0) {
	      timeout_tcpw = parse_interval(optarg+5,NULL);
	      if (timeout_tcpw < 10) {
		fprintf(stderr, "%s: bad tcp-write timeout: %s\n",
			argv[0], optarg+5);
		++errflg;
	      }
	      break;
	    } else if (strncasecmp(optarg,"cmd=",4)==0) {
	      timeout_cmd = parse_interval(optarg+4,NULL);
	      optarg += 4;
	    } else
	      timeout_cmd = parse_interval(optarg,NULL);
	    if (timeout_cmd < 5) {
	      fprintf(stderr, "%s: bad general cmd timeout: %s\n",
		      argv[0], optarg);
	      ++errflg;
	    }
	    break;
	  case 'v':
	    ++verbosity;
	    break;
	  case 'V':
	    prversion("smtp");
	    exit(0);
	    break;
	  case 'W':		/* Enable RFC974 WKS checks */
	    checkwks = 1;
	    break;
	  case 'H':
	    keep_header8 = 1;
	    break;
	  case '8':
	    force_8bit = 1;
	    force_7bit = 0;
	    break;
	  case '7':
	    force_7bit = 1;
	    force_8bit = 0;
	    break;
	  case 'Z':  /* Dummy option to carry HUGE parameter string for
			the report system to make sense.. at OSF/1, at least */
	    break;
	  case '6':
	    prefer_ip6 = !prefer_ip6;
	    break;
	  case 'S':
	    /* -S /path/to/SmtpSSL.conf */
#ifdef HAVE_OPENSSL
	    tls_conf_file = strdup(optarg);
#endif /* - HAVE_OPENSSL */
	    break;
	  default:
	    ++errflg;
	    break;
	  }
	}

	if (errflg || optind > argc) {
	  fprintf(stderr,
		  "Usage: %s [-8|-8H|-7][-e][-r][-x][-E][-P][-W][-T timeout][-h myhostname][-l logfile][-p portnum][-c channel][-F forcedest][-L localidentity][-S /path/to/SmtpSSL.conf] [host]\n", argv[0]);
	  exit(EX_USAGE);
	}

	if (SS.servport < 0)
	  SS.servport = IPPORT_SMTP;

	if (optind < argc) {
	  host = strdup(argv[optind]);
	  strncpy(SS.remotehost, (char*)host, sizeof(SS.remotehost));
	  SS.remotehost[sizeof(SS.remotehost)-1] = 0;
	} else
	  need_host = 1;

	if (myhostnameopt == 0) {
	  /* Default it only when not having an explicite value
	     in it..   James S MacKinnon <jmack@Phys.UAlberta.Ca> */
	  getmyhostname(myhostname, sizeof myhostname);
	}

	if (conndebug && !debug && host) {
	  SS.firstmx = 0;
	  smtpconn(&SS, (char*)host, noMX);
	  exit(0);
	}

	logfp = NULL;
	if (logfile != NULL) {
	  if ((fd = open(logfile, O_CREAT|O_APPEND|O_WRONLY, 0644)) < 0)
	    fprintf(stdout, "# %s: cannot open logfile \"%s\"!\n",
		    argv[0], logfile);
	  else
	    logfp = (FILE *)fdopen(fd, "a");
	}

	if (logfp)
	  setvbuf(logfp, NULL, _IOLBF, 0);

	getnobody();
	getdaemon();

	defcharset = getzenv("DEFCHARSET");
	if (!defcharset)
	  defcharset = DefCharset;

	/* We need this latter on .. */
	zopenlog("smtp", LOG_PID, LOG_MAIL);
	notary_settaid("smtp",getpid());

	/* We defer opening a connection until we know there is work */

	smtpstatus = EX_OK;
	idle = 0;
	SS.stdinsize = 0;
	SS.stdincurs = 0;

	filenamesize = 80;
	filename = malloc(filenamesize);

	while (!getout && !zmalloc_failure) {
	  /* Input:
	       spool/file/name [ \t host.info ] \n
	   */
	  char *s;

	  fd_blockingmode(FILENO(stdout));

	  fprintf(stdout, "#hungry\n");
	  fflush(stdout);

	  if (statusreport) {
	    if (idle)
	      report(&SS,"#idle");
	    else
	      report(&SS,"#hungry");
	  }

	  /* if (fgets(filename, sizeof(filename), stdin) == NULL) break; */
	  if (ssfgets(&filename, &filenamesize, FILENO(stdin), &SS) == NULL)
	    break;

#if !(defined(HAVE_MMAP) && defined(TA_USE_MMAP))
	  readalready = 0; /* internal body read buffer 'flush' */
#endif
	  idle = 0; skip_host = 0;
	  if (strchr(filename, '\n') == NULL) break; /* No ending '\n' !  Must
						    have been partial input! */
	  if (logfp)
	    fprintf(logfp,"%s#\tjobspec: %s",logtag(),filename);

	  if (strcmp(filename, "#idle\n") == 0) {
	    idle = 1;
	    continue; /* XX: We can't stay idle for very long, but.. */
	  }
	  if (emptyline(filename, filenamesize))
	    break;

	  time(&now);

	  s = strchr(filename,'\t');
	  if (s != NULL) {
	    *s++ = 0;

	    if (host && strcasecmp((char*)host,s)==0) {

	      /* XXX: Behaviour with 'close_after_data' ??? */

	      if (now < retryat_time) {
		/* Same host, we don't touch on it for a while.. */
		/* sleep(2); */
		if (logfp && verbosity > 1) {
		  fprintf(logfp,"%s#\t(too soon trying to touch on host with 'retryat' diagnostic -- flushing job queue..host='%s')\n",logtag(),host);
		}
		++skip_host;
	      }
	    }

	    /* If different target host, close the old connection.
	       In theory we could use same host via MX, but...     */
	    if (host && strcmp(s,(char*)host) != 0) {
	      if (SS.smtpfp) {
		if (!getout && !zmalloc_failure)
		  smtpstatus = smtpwrite(&SS, 0, "QUIT", -1, NULL);
		else
		  smtpstatus = EX_OK;
		smtpclose(&SS, 0);
		notary_setwtt(NULL);
		notary_setwttip(NULL);
		if (logfp)
		  fprintf(logfp, "%s#\t(closed SMTP channel - new host)\n",
			  logtag());
		strncpy(SS.remotehost, (char*)host, sizeof(SS.remotehost));
		SS.remotehost[sizeof(SS.remotehost)-1] = 0;
		if (statusreport)
		  report(&SS, "NewDomain: %s", host);
	      }
	      close_after_data = 0;
	    }
	    if (host) free((void*)host);
	    host = strdup(s);
	  } else
	    if (need_host) {
	      fprintf(stdout,"# smtp needs defined host!\n");
	      fflush(stdout);
	      continue;
	    }

	  if (debug > 1) { /* "DBGdiag:"-output */
	    fprintf(stdout,"# (fdcnt=%d, file:%.200s, host:%.200s)\n", countfds(), filename, host);
	    fflush(stdout);
	  }

#ifdef	BIND
	  res_init();

	  if (checkmx)
	    dp = ctlopen(filename, (char*)channel, (char*)host, &getout, rightmx, &SS, matchroutermxes, &SS);
	  else
#endif /* BIND */
	    dp = ctlopen(filename, (char*)channel, (char*)host, &getout, NULL, NULL, matchroutermxes, &SS);
	  if (dp == NULL) {
	    fprintf(stdout,"#resync %.200s\n", filename);
	    fflush(stdout);
	    if (logfp)
	      fprintf(logfp, "%s#\tc='%s' h='%s' #resync %s\n", logtag(), channel, host, filename);
	    continue;
	  }

	  time(&starttime);
	  notary_setxdelay(0);
	
	  if (punthost)
	    smtphost = punthost;
	  else
	    smtphost = host;

	  if (dp->verbose) {
	    if (SS.verboselog)
	      fclose(SS.verboselog);
	    SS.verboselog = (FILE *)fopen(dp->verbose,"a");
	    if (SS.verboselog)
	      setvbuf(SS.verboselog, NULL, _IONBF, 0);
	  }


#ifdef HAVE_OPENSSL
	  if (SS.verboselog && tls_conf_file)
	    fprintf(SS.verboselog, "# tls_conf_file='%s'\n", tls_conf_file);

	  if (tls_conf_file && !tls_available) {
	    /* -S /path/to/SmtpSSL.conf */

	    tls_available = (tls_init_clientengine(&SS, tls_conf_file) == 0);

	    if (SS.verboselog)
	      fprintf(SS.verboselog,
		      "# -S '%s' tls_init_client_engine() -> tls_available=%d\n",
		      tls_conf_file, tls_available);
#if 0
	    else
	      fprintf(stderr,
		      "# -S '%s' tls_init_client_engine() -> tls_available=%d\n",
		      tls_conf_file, tls_available);
#endif
	  }
#endif /* - HAVE_OPENSSL */


	  smtpstatus = process(&SS, (struct ctldesc *)dp, smtpstatus,
			       (char*)smtphost, noMX);

	  if (SS.verboselog)
	    fclose(SS.verboselog);
	  SS.verboselog = NULL;

	  ctlclose((struct ctldesc *)dp);
	} /* while (!getout) ... */

	if (SS.smtpfp && !getout)
	  smtpstatus = smtpwrite(&SS, 0, "QUIT", -1, NULL);

	/* Close the channel -- if it is open anymore .. */
	if (SS.smtpfp) {
	  smtpclose(&SS, 0);
	  if (logfp)
	    fprintf(logfp, "%s#\t(closed SMTP channel - final close)\n", logtag());
	}

	if (SS.verboselog != NULL)
	  fclose(SS.verboselog);
	if (logfp != NULL)
	  fclose(logfp);

	return 0;
}

int
process(SS, dp, smtpstatus, host, noMX)
	SmtpState *SS;
	struct ctldesc *dp;
	volatile int smtpstatus;
	const char *host;
	int noMX;
{
	if (setjmp(procabortjmp) == 0) {

	  struct rcpt *rp, *rphead;
	  int loggedid;
	  int openstatus = EX_OK;

	  procabortset = 1;

	  smtpstatus = EX_OK; /* Hmm... */
	  loggedid = 0;

	  SS->firstmx = 0; /* If need be to connect to a new host,
			      because the socket is not on, we start
			      from the begin of the MX list */

	  *SS->remotemsg = 0;

	  for (rp = rphead = dp->recipients; rp != NULL; rp = rp->next) {

	    /* Set this special flag so that we can retry EX_IOERR and
	       EX_TEMPFAIL status cases more easily.. */
	    rp->notifyflgs |= _DSN__TEMPFAIL_NO_UNLOCK;

	    if (rp->next == NULL
		|| rp->addr->link   != rp->next->addr->link
		|| rp->newmsgheader != rp->next->newmsgheader) {

	      if (smtpstatus == EX_OK && openstatus == EX_OK) {
		if (logfp != NULL && !loggedid) {
		  loggedid = 1;
		  fprintf(logfp, "%s#\t%s: %s\n", logtag(), dp->msgfile, dp->logident);
		}

		do {

		  if (!SS->smtpfp) {
	
		    /* Make the opening connect with the UID of the
		       sender (atoi(rp->addr->misc)), unless it is
		       "nobody", in which case use "daemon"      */
		    if ((first_uid = atoi(dp->senders->misc)) < 0 ||
			first_uid == nobody)
		      first_uid = daemon_uid;

		    openstatus = smtpopen(SS, host, noMX);
		    if (openstatus != EX_OK && openstatus != EX_TEMPFAIL) {
		      for ( ; rphead != rp->next; rphead = rphead->next) {
			if (rphead->lockoffset) {
			  notaryreport(rphead->addr->user, FAILED, NULL, NULL);
			  diagnostic(rphead, openstatus, 60, "%s", SS->remotemsg);
			}
		      }
		      break;
		    }
		  }

		  if (openstatus == EX_OK)
		    smtpstatus = deliver(SS, dp, rphead, rp->next);

		  /* Only for EX_TEMPFAIL, or for any non EX_OK ? */
		  if (smtpstatus == EX_TEMPFAIL) {
		    smtpclose(SS, 1);
		    notary_setwtt(NULL);
		    notary_setwttip(NULL);
		    if (logfp)
		      fprintf(logfp, "%s#\t(closed SMTP channel - after delivery failure)\n", logtag());
		    if (SS->verboselog)
		      fprintf(SS->verboselog, "(closed SMTP channel - after delivery failure; firstmx = %d, mxcount=%d)\n",SS->firstmx,SS->mxcount);
		  }

		  /* If delivery fails, try other MX hosts */
		} while (((smtpstatus == EX_TEMPFAIL) ||
			  (smtpstatus == EX_IOERR)) &&
			 (SS->firstmx < SS->mxcount));

		/* Report (and unlock) all those recipients which aren't
		   otherwise diagnosed.. */

		for (;rphead && rphead != rp->next; rphead = rphead->next) {
		  if (rphead->lockoffset) {
		    /* Clear this special flag so that we can now diagnose
		       them.. */
		    rphead->notifyflgs &= ~ _DSN__TEMPFAIL_NO_UNLOCK;

		    notaryreport(rphead->addr->user, FAILED, NULL, NULL);
		    diagnostic(rphead, EX_TEMPFAIL,
			       openstatus == EX_TEMPFAIL ? 60 : 0,
			       "%s", SS->remotemsg);
		  }
		}

		rphead = rp->next;
	      } else {
		time(&endtime);
		notary_setxdelay((int)(endtime-starttime));
		while (rphead != rp->next) {
		  /* SMTP open -- meaning (propably) that we got reject
		     from the remote server */
		  /* NOTARY: address / action / status / diagnostic */
		  if (rphead->lockoffset) {
		    /* Clear this special flag so that we can now diagnose
		       them.. */
		    rphead->notifyflgs &= ~ _DSN__TEMPFAIL_NO_UNLOCK;

		    notaryreport(rp->addr->user,FAILED,
				 "5.0.0 (Target status indeterminable)",
				 NULL);
		    diagnostic(rphead, EX_TEMPFAIL,
			       openstatus == EX_TEMPFAIL ? 60 : 0,
			       "%s", SS->remotemsg);
		  }

		  rphead = rphead->next;
		}
	      }
	    }
	  }

	} else {
	  /* processing fails entirely if PROCABORT is received */
	  smtpstatus = EX_UNAVAILABLE;
	  smtpclose(SS, 1);
	  if (logfp)
	    fprintf(logfp, "%s#\t(procabort executed)\n", logtag());
	}

	procabortset = 0;

	return smtpstatus;
}
/*
 * deliver - deliver the letter in to user's mail box.  Return
 *	     errors and requests for further processing in the structure
 */

int
deliver(SS, dp, startrp, endrp)
	SmtpState *SS;
	struct ctldesc *dp;
	struct rcpt *startrp, *endrp;
{
	struct rcpt *rp = NULL;
	int r = EX_TEMPFAIL;
	int nrcpt, rcpt_cnt, size, tout, hdrsize;
	int content_kind = 0;
	int mail_from_failed;
	CONVERTMODE convertmode;
	int ascii_clean = 0;
	struct stat stbuf;
	char SMTPbuf[2000];
	char *s;
	int conv_prohibit = check_conv_prohibit(startrp);
	int hdr_mime2 = 0;
	int pipelining = ( SS->ehlo_capabilities & ESMTP_PIPELINING );
	time_t env_start, body_start, body_end;
	struct rcpt *more_rp = NULL;
	char **chunkptr = NULL;
	char *chunkblk = NULL;
	int early_bdat_sync = 0;
	struct ct_data  *CT  = NULL;
	struct cte_data *CTE = NULL;
	char **hdr;

	hdr = has_header(startrp,"Content-Type:");
	if (hdr)
	  CT = parse_content_type(hdr);
	hdr = has_header(startrp,"Content-Transfer-Encoding:");
	if (hdr)
	  CTE = parse_content_encoding(hdr);
	if (CT) {
	  if (CT->basetype == NULL ||
	      CT->subtype  == NULL ||
	      cistrcmp(CT->basetype,"text") != 0 ||
	      cistrcmp(CT->subtype,"plain") != 0)

	    /* Not TEXT/PLAIN! */
	    conv_prohibit = -1;
	  /* We don't know how to convert anything BUT  TEXT/PLAIN :-(  */
	}


	if (no_pipelining) pipelining = 0;
	SS->pipelining = pipelining;

	SS->chunking   = ( SS->ehlo_capabilities & ESMTP_CHUNKING );

	convertmode = _CONVERT_NONE;
	if (conv_prohibit >= 0) {

	  /* Content-Transfer-Encoding: 8BIT ? */
	  content_kind = cte_check(startrp);

	  /* If the header says '8BIT' and ISO-8859-* something,
	     but body is plain 7-bit, turn it to '7BIT', and US-ASCII */
	  ascii_clean = check_7bit_cleanness(dp);

	  if (ascii_clean && content_kind == 8) {
	    if (downgrade_charset(startrp, SS->verboselog))
	      content_kind = 7;
	  }

	  if (conv_prohibit == 7)
	    force_7bit = 1;

	  if (force_7bit)	/* Mark off the 8BIT MIME capability.. */
	    SS->ehlo_capabilities &= ~ESMTP_8BITMIME;

	  switch (content_kind) {
	  case 0:		/* Not MIME */
	    if ((SS->ehlo_capabilities & ESMTP_8BITMIME) == 0 &&
		!ascii_clean && !force_8bit) {
	      convertmode = _CONVERT_UNKNOWN;
	      /* It is ASCII clean */
	      downgrade_headers(startrp, convertmode, SS->verboselog);
	    }
	    break;
	  case 2:		/* MIME, but no C-T-E: -> defaults to 7BIT */
	  case 1:		/* C-T-E: BASE64  ?? */
	  case 7:		/* C-T-E: 7BIT */
	    convertmode = _CONVERT_NONE;
	    break;
	  case 8:		/* C-T-E: 8BIT */
	    if ((force_7bit || (SS->ehlo_capabilities & ESMTP_8BITMIME)== 0) &&
		!ascii_clean && !force_8bit) {
	      convertmode = _CONVERT_QP;
	      if (!downgrade_headers(startrp, convertmode, SS->verboselog))
		convertmode = _CONVERT_NONE; /* Failed! */
	    }
	    break;
	  case 9:		/* C-T-E: Quoted-Printable */
	    if (force_8bit || (SS->ehlo_capabilities & ESMTP_8BITMIME)) {
	      /* Force(d) to decode Q-P while transfer.. */
	      convertmode = _CONVERT_8BIT;
	      /*  UPGRADE TO 8BIT !  */
	      if (!qp_to_8bit(startrp))
		convertmode = _CONVERT_NONE;
	      content_kind = 10;
	      ascii_clean = 0;
	    }
	    break;
	  default:
	    /* ???? This should NOT happen! */
	    break;
	  } /* switch().. */

	  hdr_mime2 = headers_need_mime2(startrp);
	  if (hdr_mime2 && !keep_header8) {
	    headers_to_mime2(startrp,defcharset,SS->verboselog);
	  }

	}

	notary_setcvtmode(convertmode);

	if (SS->ehlo_capabilities & ESMTP_SIZEOPT) {

	  /* We can do this SIZE option analysis without trying to
	     feed this in the MAIL command */

	  if (SS->ehlo_sizeval > 0 &&
	      startrp->desc->msgsizeestimate > SS->ehlo_sizeval) {

	    /* Reuse SMTPbuf for writing an error report
	       explaining things a bit.. */

	    sprintf(SMTPbuf, "smtp; 552 (Current message size %d exceeds limit given by the remote system: %d)",
		    (int)startrp->desc->msgsizeestimate,
		    (int)SS->ehlo_sizeval);

	    if (SS->verboselog)
	      fprintf(SS->verboselog, "%s\n", SMTPbuf+6);
	    
	    time(&endtime);
	    notary_setxdelay((int)(endtime-starttime));
	    for (rp = startrp; rp && rp != endrp; rp = rp->next)
	      if (rp->lockoffset) {
		/* NOTARY: address / action / status / diagnostic / wtt */
		notaryreport(rp->addr->user, FAILED,
			     "5.3.4 (Message size exceeds limit given by remote system)", SMTPbuf);
		diagnostic(rp, EX_UNAVAILABLE, 0, "\r\r%s", SMTPbuf+6);
	      }

	    return EX_UNAVAILABLE;
	  }
	}


	SS->rcptstates = 0;
	mail_from_failed = 0;

    more_recipients:
	if (more_rp != NULL) {
	  startrp = more_rp;
	  more_rp = NULL;
	}

	/* We are starting a new pipelined phase */
	smtp_flush(SS); /* Flush in every case */

	/* Store estimate on how large a file it is */
	if (fstat(dp->msgfd, &stbuf) >= 0)
	  size = stbuf.st_size - dp->msgbodyoffset;
	else
	  size = -1;
	SS->msize = size;

	SS->prevcmdstate = 99;
	SS->cmdstate     = SMTPSTATE_MAILFROM;

	if (strcmp(startrp->addr->link->channel,"error")==0)
	  sprintf(SMTPbuf, "MAIL From:<>");
	else
	  sprintf(SMTPbuf, "MAIL From:<%.1000s>", startrp->addr->link->user);
	if (SS->ehlo_capabilities & ESMTP_8BITMIME)
	  strcat(SMTPbuf, " BODY=8BITMIME");
	s = SMTPbuf + strlen(SMTPbuf);

	/* Size estimate is calculated in the  ctlopen()  by
	   adding msg-body size to the largest known header size,
	   though excluding possible header and body rewrites.. */
	if (SS->ehlo_capabilities & ESMTP_SIZEOPT) {
	  sprintf(s, " SIZE=%ld", startrp->desc->msgsizeestimate);
	  s += strlen(s);
	}
	/* DSN parameters ... */
	if (SS->ehlo_capabilities & ESMTP_DSN) {
	  if (startrp->desc->envid != NULL) {
	    sprintf(s," ENVID=%.800s",startrp->desc->envid);
	    s += strlen(s);
	  }
	  if (startrp->desc->dsnretmode != NULL)
	    sprintf(s, " RET=%.20s", startrp->desc->dsnretmode);
	}

	time(&env_start); /* Mark the timestamp */

	/* MAIL FROM:<...> -- pipelineable.. */
	r = smtpwrite(SS, 1, SMTPbuf, pipelining, NULL);
	if (!SS->smtpfp || sffileno(SS->smtpfp) < 0) r = EX_TEMPFAIL; /* ALWAYS! */
	if (r != EX_OK) {
	  /* If we err here, we propably are in SYNC mode... */
	  /* Uh ??  Many new sendmail's have a pathological error mode:
	        MAIL FROM...
		451 cannot preopen /etc/aliases.db
		  (wait a bit)
		250 ... Sender ok.
	     We try to accomodate that behaviour, and resync,
	     although treat it as temporary error -- 4xx series.  */
	  if (SS->smtpfp) {
	    sleep(10); /* After a sleep of 10 seconds, if we find that
			  we have some new input, do close the connection */
	    if (has_readable(SS->smtpfd)) {
	      /* Drain the input, and then close the channel */
	      (void) smtpwrite(SS, 1, NULL, 0, NULL);
	      smtpclose(SS, 1);
	      if (logfp)
		fprintf(logfp, "%s#\t(closed SMTP channel - MAIL FROM:<> got two responses!)\n", logtag());
	    }
	  }
	  time(&endtime);
	  notary_setxdelay((int)(endtime-starttime));
	  if (SS->smtpfp) {
	    if (pipelining)
	      r = smtp_sync(SS, r, 0); /* Collect reports in blocking mode */
	  } else {
	    r = EX_TEMPFAIL; /* XXX: ??? */
	  }

	  /* Sync system which rejects subsequent MAIL FROM if not
	     getting an RSET ??   *dont* yield diagnostic()s here! */

	  SS->cmdstate     = SMTPSTATE_RCPTTO; /* 1 + MAILFROM.. */

	  if (SS->smtpfp)
	    if (smtpwrite(SS, 0, "RSET", 0, NULL) == EX_OK)
	      if ( ! mail_from_failed ) {
		mail_from_failed = 1;
		goto more_recipients;
	      }

	  for (rp = startrp; rp && rp != endrp; rp = rp->next) {
	    /* NOTARY: address / action / status / diagnostic */
	    if (rp->lockoffset) {
		notaryreport(rp->addr->user, FAILED,
			   "5.5.0 (Undetermined protocol error)",NULL);
	      diagnostic(rp, r, 0, "%s", SS->remotemsg);
	    }
	  }
	  return r;
	}
	mail_from_failed = 0;
	nrcpt = 0;
	rcpt_cnt = 0;
	SS->rcptstates = 0;
	for (rp = startrp; rp && rp != endrp; rp = rp->next) {

	  /* Set this special flag so that we can retry EX_IOERR and
	     EX_TEMPFAIL status cases more easily.. */
	  rp->notifyflgs |= _DSN__TEMPFAIL_NO_UNLOCK;

	  if (++rcpt_cnt >= SS->rcpt_limit) {
	    more_rp = rp->next;
	    rp->next = NULL;
	  }

	  SS->cmdstate = SMTPSTATE_RCPTTO;

	  sprintf(SMTPbuf, "RCPT To:<%.800s>", rp->addr->user);
	  s = SMTPbuf + strlen(SMTPbuf);

	  if (SS->ehlo_capabilities & ESMTP_DSN) {
	    if (rp->notify) {
	      strcat(s, " NOTIFY=");
	      strcat(s,rp->notify);
	      s += strlen(s);
	    }
	    if (rp->orcpt != NULL) {
	      sprintf(s, " ORCPT=%.800s", rp->orcpt);
	    }
	  }
	  
	  /* NOTARY: address / action / status / diagnostic */
	  notaryreport(rp->addr->user, NULL, NULL, NULL);
	  /* RCPT To:<...> -- pipelineable */
 	  r = smtpwrite(SS, 1, SMTPbuf, pipelining, rp);
	  if (r != EX_OK) {
	    if (!SS->smtpfp || sffileno(SS->smtpfp) < 0) r = EX_TEMPFAIL; /* ALWAYS! */
	    if (!pipelining) {
	      if (r == EX_TEMPFAIL)
		SS->rcptstates |= RCPTSTATE_400;
	      else
		SS->rcptstates |= RCPTSTATE_500;
	      rp->status = r;
	    }
	    time(&endtime);
	    notary_setxdelay((int)(endtime-starttime));
	    if (SS->smtpfp) {
	      if (pipelining)
		r = smtp_sync(SS, r, 0); /* Collect reports -- by blocking */
	    } else
	      r = EX_TEMPFAIL;

	    /* NOTARY: address / action / status / diagnostic / wtt */
	    notaryreport(NULL, FAILED, NULL, NULL);
	    diagnostic(rp, r, 0, "%s", SS->remotemsg);
	    if (!SS->smtpfp)
	      break;
	  } else {
	    if (!pipelining)
	      SS->rcptstates |= RCPTSTATE_OK;
	    nrcpt += 1;
	    SS->rcptcnt += 1;
	    /* Actually we DO NOT KNOW, we need to sync this latter on.. */
	    rp->status = EX_OK;
	  }
	}

	if (nrcpt == 0) {
	  /* all the RCPT To addresses were rejected, so reset server */

	  SS->cmdstate     = SMTPSTATE_DATA; /* 1 + RCPTTO.. */

	  if (SS->smtpfp)
	    if (smtpwrite(SS, 0, "RSET", 0, NULL) == EX_OK)
	      r = EX_TEMPFAIL;

	  if (r == EX_OK && more_rp)
	    /* we have more recipients,
	       and things have worked ok so far.. */
	    goto more_recipients;

	  if (SS->rcptstates & RCPTSTATE_400)
	    return EX_TEMPFAIL; /* Even ONE temp failure -> total result
				   is then TEMPFAIL */
	  return EX_UNAVAILABLE;
	}

	if (!SS->smtpfp)
	  return EX_TEMPFAIL;

	chunkptr = NULL;
	SS->chunksize = 0;
	SS->chunkbuf  = NULL;

#ifndef DO_CHUNKING
	SS->chunking = 0;
#endif

	SS->cmdstate = SMTPSTATE_DATA;

	if (SS->chunking) {

	  chunkblk = NULL;
	  chunkptr = & chunkblk;

	  /* We do surprising things here, we construct
	     at first the headers (and perhaps some of
	     the body) into a buffer, then write it out
	     in BDAT transaction. */

	  time(&endtime);
	  notary_setxdelay((int)(endtime-starttime));

	  /* Sometimes it MIGHT make sense to sync incoming
	     status data.    When and how ? */

	  if (!pipelining ||
	      (startrp->desc->msgsizeestimate >= CHUNK_MAX_SIZE))
	    early_bdat_sync = 1;

	  if (SS->smtpfp && early_bdat_sync) {
	    /* Now is time to do synchronization .. */
	    r = smtp_sync(SS, EX_OK, 0); /* Up & until "DATA".. */
	  }

	  if (r != EX_OK) {
	    /* XX:
	       #error  Uncertain of what to do ...
	       ... reports were given at each recipient, and if all failed,
	       we failed too.. (there should not be any positive diagnostics
	       to report...)
	     */
	    for (rp = startrp; rp && rp != endrp; rp = rp->next)
	      if (rp->lockoffset) {
		/* NOTARY: address / action / status / diagnostic / wtt */
		notaryreport(rp->addr->user,FAILED,NULL,NULL);
		diagnostic(rp, r, 0, "%s", SS->remotemsg);
	      }
	    if (SS->smtpfp)
	      if (smtpwrite(SS, 0, "RSET", 0, NULL) == EX_OK)
		r = EX_TEMPFAIL;
	    return r;
	  }

	  /* OK, we synced, lets continue with BDAT ...
	     The RFC 1830 speaks of more elaborate
	     pipelining with BDAT, but lets do this
	     with checkpoints at first */

	} else if (pipelining) {

	  /* No CHUNKING here... do normal DATA-dot exchange */

	  /* In PIPELINING mode ... send "DATA" */
	  r = smtpwrite(SS, 1, "DATA", pipelining, NULL);
	  if (r != EX_OK) { /* failure on pipes ? */
	    time(&endtime);
	    notary_setxdelay((int)(endtime-starttime));
	    if (SS->smtpfp)
	      r = smtp_sync(SS, r, 0); /* Sync it.. */
	    for (rp = startrp; rp && rp != endrp; rp = rp->next)
	      if (rp->lockoffset) {
		/* NOTARY: address / action / status / diagnostic / wtt */
		notaryreport(rp->addr->user,FAILED,NULL,NULL);
		diagnostic(rp, r, 0, "%s", SS->remotemsg);
	      }
	    if (SS->smtpfp)
	      if (smtpwrite(SS, 0, "RSET", 0, NULL) == EX_OK)
		r = EX_TEMPFAIL;
	    return r;
	  }
	  time(&endtime);
	  notary_setxdelay((int)(endtime-starttime));
	  /* Now it is time to do synchronization .. */
	  if (SS->smtpfp)
	    r = smtp_sync(SS, EX_OK, 0); /* Up & until "DATA".. */
	  if (r != EX_OK) {
	    /* XX:
	       #error  Uncertain of what to do ...
	       ... reports were given at each recipient, and if all failed,
	       we failed too.. (there should not be any positive diagnostics
	       to report...)
	     */
	    for (rp = startrp; rp && rp != endrp; rp = rp->next)
	      if (rp->lockoffset) {
		/* NOTARY: address / action / status / diagnostic / wtt */
		notaryreport(rp->addr->user,FAILED,NULL,NULL);
		diagnostic(rp, r, 0, "%s", SS->remotemsg);
	      }
	    if (SS->smtpfp &&
		(SS->rcptstates & DATASTATE_OK)) {
	      /* HUH!!!
		 MAIL FROM/RCPT TO ones have failed, but DATA has succeeded !!
		 This is SERIOUSLY weird, but some may work even that way.. */
	      smtpclose(SS,1);
	      fprintf(logfp, "%s#\t(closed SMTP channel - DATA ok, but MAIL FROM/RCPT TO failed!  rc=%d)\n", logtag(), rp ? rp->status : -999);
	      r = EX_TEMPFAIL;
	    }
	    if (SS->smtpfp &&
		(SS->rcptstates & RCPTSTATE_400) &&
		(SS->rcptstates & FROMSTATE_OK)) {
	      smtpwrite(SS, 0, "QUIT", -1, NULL);
	      smtpclose(SS,1);
	      fprintf(logfp, "%s#\t(closed SMTP channel - tempfails for RCPTs; 'too many recipients per session' ??  rc=%d)\n", logtag(), rp ? rp->status : -999);
	      if (SS->rcptstates & RCPTSTATE_OK)
		retryat_time = 0;

	      close_after_data = 1;
	      r = EX_TEMPFAIL;
	    }
	    if (SS->smtpfp) {
	      if (smtpwrite(SS, 0, "RSET", 0, NULL) == EX_OK)
		r = EX_TEMPFAIL;
	    }
	    if (SS->verboselog)
	      fprintf(SS->verboselog," .. timeout ? smtp_sync() rc = %d\n",r);
	    return r;
	  }
	  /* Successes are reported AFTER the DATA-transfer is ok */
	} else {
	  /* Non-PIPELINING sync mode */
	  timeout = timeout_data;
	  r = smtpwrite(SS, 1, "DATA", 0, NULL);
	  if (r != EX_OK) {
	    time(&endtime);
	    notary_setxdelay((int)(endtime-starttime));
	    for (rp = startrp; rp && rp != endrp; rp = rp->next)
	      if (rp->lockoffset) {
		/* NOTARY: address / action / status / diagnostic / wtt */
		notaryreport(rp->addr->user,FAILED,NULL,NULL);
		diagnostic(rp, r, 0, "%s", SS->remotemsg);
	      }
	    if (SS->smtpfp)
	      if (smtpwrite(SS, 0, "RSET", 0, NULL) == EX_OK)
		r = EX_TEMPFAIL;
	    return r;
	  }
	  timeout = timeout_dot;
	}
	/* Headers are 7-bit stuff -- says MIME specs */

	time(&body_start); /* "DATA" issued, and synced */

	if (SS->verboselog) {
	  char **hdrs = *(startrp->newmsgheader);
	  if (*(startrp->newmsgheadercvt) != NULL &&
	      convertmode != _CONVERT_NONE)
	    hdrs = *(startrp->newmsgheadercvt);
	  fprintf(SS->verboselog,
		  "Processed headers:  ContentKind=%d, CvtMode=%d\n------\n",
		  content_kind,(int)convertmode);
	  while (hdrs && *hdrs)
	    fprintf(SS->verboselog,"%s\n",*hdrs++);
	}

	SS->hsize = swriteheaders(startrp, SS->smtpfp, "\r\n",
				  convertmode, 0, chunkptr);

	if (SS->hsize >= 0 && chunkblk) {

	  chunkblk = realloc(chunkblk, SS->hsize+2);
	  if (chunkblk) {
	    memcpy(chunkblk + SS->hsize, "\r\n", 2);
	    SS->hsize += 2;
	  } else {
	    SS->hsize = -1;
	  }

	} else if (SS->hsize >= 0) {

	  if (!sferror(SS->smtpfp))
	    sfprintf(SS->smtpfp, "\r\n");

	  if (sferror(SS->smtpfp))
	    SS->hsize = -1;

	}

	if (chunkblk) {
	  SS->chunksize  = SS->hsize;
	  SS->chunkspace = SS->hsize;
	  SS->chunkbuf   = chunkblk;
	}

	if (SS->hsize < 0) {
	  int r = EX_TEMPFAIL;
	  for (rp = startrp; rp != endrp; rp = rp->next)
	    if (rp->lockoffset) {
	      time(&endtime);
	      notary_setxdelay((int)(endtime-starttime));
	      /* NOTARY: address / action / status / diagnostic / wtt */
	      notaryreport(rp->addr->user,FAILED,
			   "5.4.2 (Message header write failure)",
			   /* XX: FIX THE STATUS? */
			   "smtp; 566 (Message header write failure)");
	      diagnostic(rp, r, 0, "%s", "header write error");
	    }
	  if (SS->verboselog)
	    fprintf(SS->verboselog,"Writing headers after DATA failed\n");
	  if (SS->smtpfp)
	    if (smtpwrite(SS, 0, "RSET", 0, NULL) == EX_OK)
	      r = EX_TEMPFAIL;

	  if (SS->chunkbuf) free(SS->chunkbuf);

	  return r;
	}

	/* Add the header size to the initial body size */
	if (SS->msize >= 0)
	  SS->msize += SS->hsize;
	else
	  SS->msize -= SS->hsize-1;

	hdrsize = SS->hsize;

	/* Append the message body itself */

	r = appendlet(SS, dp, convertmode);

	if (r != EX_OK) {
	  time(&endtime);
	  notary_setxdelay((int)(endtime-starttime));
	  for (rp = startrp; rp && rp != endrp; rp = rp->next)
	    if (rp->lockoffset) {
	      notaryreport(rp->addr->user, FAILED,
			   "5.4.2 (Message write timed out;2)",
			   "smtp; 566 (Message write timed out;2)"); /* XX: FIX THE STATUS? */
	      diagnostic(rp, r, 0, "%s", SS->remotemsg);
	    }
	  /* Diagnostics are done, protected (failure-)section ends! */
	  dotmode = 0;
	  /* The failure occurred during processing and was due to an I/O
	   * error.  The safe thing to do is to just abort processing.
	   * Don't send the dot! 2/June/94 edwin@cs.toronto.edu
	   */
	  if (SS->smtpfp) {
	    smtpclose(SS, 1);
	    if (logfp)
	      fprintf(logfp, "%s#\t(closed SMTP channel - appendlet() failure, status=%d)\n", logtag(), rp ? rp->status : -999);
	  }

	  if (SS->chunkbuf) free(SS->chunkbuf);

	  return EX_TEMPFAIL;
	}
	/*
	 * This is the one place where we *have* to wait forever because
	 * there is no reliable way of aborting the transaction.
	 * Note that a good and useful approximation to "forever" is one day.
	 * Murphy's Law you know: Connections will hang even when they can't.
	 */
	/* RFC-1123 says: 10 minutes! */
	tout = timeout;
	timeout = timeout_dot;

	dotmode = 1;

	gotalarm = 0;

	SS->cmdstate = SMTPSTATE_DATADOT;

	if (SS->chunking) {
	  r = bdat_flush(SS, 1);
	} else {
	  r = smtpwrite(SS, 1, ".", 0, NULL);
	}

	timeout = tout;
	if (r != EX_OK) {
	  time(&endtime);
	  notary_setxdelay((int)(endtime-starttime));
	  for (rp = startrp; rp && rp != endrp; rp = rp->next)
	    if (rp->lockoffset) {
	      notaryreport(rp->addr->user, FAILED,
#if 1
			   NULL, NULL
#else
			   "5.4.2 (Message write failed; possibly remote rejected the message)",
			   "smtp; 566 (Message write failed; possibly remote rejected the message)"
#endif
			   );
	      /* If remote closed socket, don't diagnose here, diagnose
		 latter.. (might also retry via other server!) */
	      if (r != EX_TEMPFAIL)
		diagnostic(rp, r, 0, "%s", SS->remotemsg);
	    }

	  /* Diagnostics are done, protected (failure-)section ends! */
	  dotmode = 0;

	  if (SS->smtpfp && gotalarm) {
	    smtpclose(SS, 1);
	    if (logfp)
	      fprintf(logfp, "%s#\t(closed SMTP channel - smtpwrite('.') failure)\n", logtag());
	  }

	  if (SS->chunkbuf) free(SS->chunkbuf);

	  return r;
	}

	time(&body_end); /* body endtime */

	if (logfp != NULL) {
	  if (r != EX_OK)
	    fprintf(logfp, "%s#\t%s\n", logtag(), SS->remotemsg);
	  else
	    fprintf(logfp, "%s#\t%d bytes, %d in header, %d recipients, %d secs for envelope, %d secs for body xfer\n",
		    logtag(), SS->hsize, hdrsize, nrcpt,
		    (int)(body_start - env_start),
		    (int)(body_end   - body_start));
	}
	time(&endtime);
	notary_setxdelay((int)(endtime-starttime));

	for (rp = startrp; rp && rp != endrp; rp = rp->next) {
	  if (rp->lockoffset) {
	    char *reldel = "-";
	    /* Turn off the flag of NOTIFY=SUCCESS, we have handled
	       the burden to the next server ... */
	    if (SS->ehlo_capabilities & ESMTP_DSN)
	      rp->notifyflgs &= ~ _DSN_NOTIFY_SUCCESS;
	    /* Remote wasn't DSN speaker, and we have NOTIFY=SUCCESS,
	       then we say, we "relayed" the message */
	    if (!(SS->ehlo_capabilities & ESMTP_DSN) &&
		(rp->notifyflgs & _DSN_NOTIFY_SUCCESS))
	      reldel = "relayed";
	    notaryreport(rp->addr->user, reldel, NULL, NULL);
	    diagnostic(rp, r, 0, "%s", SS->remotemsg);
	  }
	}

	/* Diagnostics are done, protected section ends! */
	dotmode = 0;

	if (SS->smtpfp &&
	    (SS->rcptstates & RCPTSTATE_400) &&
	    (SS->rcptstates & FROMSTATE_OK)) {
	  smtpwrite(SS, 0, "QUIT", -1, NULL);
	  smtpclose(SS,1);
	  fprintf(logfp, "%s#\t(closed SMTP channel - tempfails for RCPTs; 'too many recipients per session' ??  rc=%d)\n", logtag(), rp ? rp->status : -999);
	  if (SS->rcptstates & RCPTSTATE_OK)
	    retryat_time = 0;
	  close_after_data = 1;
	}
	if (SS->smtpfp && close_after_data) {
	  smtpwrite(SS, 0, "QUIT", -1, NULL);
	  smtpclose(SS,1);
	  fprintf(logfp, "%s#\t(closed SMTP channel - ``close_after_data'' mode.", logtag());
	  retryat_time = 0;
	}


	/* More recipients to send ? */
	if (r == EX_OK && more_rp != NULL && !getout)
	  goto more_recipients;

	SS->cmdstate = SMTPSTATE_DATADOTRSET;

	if (r != EX_OK && SS->smtpfp && !getout)
	  if (smtpwrite(SS, 0, "RSET", 0, NULL) == EX_OK)
	    r = EX_TEMPFAIL;

	if (SS->chunkbuf) free(SS->chunkbuf);

	return r;
}


int
ehlo_check(SS,buf)
SmtpState *SS;
const char *buf;
{
	char *r = strchr(buf,'\r');
	if (r != NULL) *r = 0;
	if (strcmp(buf,"8BITMIME")==0) {
	  SS->ehlo_capabilities |= ESMTP_8BITMIME;
	} else if (strcmp(buf,"DSN")==0) {
	  SS->ehlo_capabilities |= ESMTP_DSN;
	} else if (strcmp(buf,"ENHANCEDSTATUSCODES")==0) {
	  SS->ehlo_capabilities |= ESMTP_ENHSTATUS;
	} else if (strcmp(buf,"CHUNKING")==0) {
	  SS->ehlo_capabilities |= ESMTP_CHUNKING;
	} else if (strcmp(buf,"PIPELINING")==0) {
	  SS->ehlo_capabilities |= ESMTP_PIPELINING;
#ifdef HAVE_OPENSSL
	} else if (strcmp(buf,"STARTTLS")==0) {
	  SS->ehlo_capabilities |= ESMTP_STARTTLS;
#endif /* - HAVE_OPENSSL */
	} else if (strncmp(buf,"SIZE ",5)==0 ||
		   strcmp(buf,"SIZE") == 0) {
	  SS->ehlo_capabilities |= ESMTP_SIZEOPT;
	  SS->ehlo_sizeval = -1;
	  if (buf[4] == ' ')
	    sscanf(buf+5,"%ld",&SS->ehlo_sizeval);
	} else if (strncmp(buf,"X-RCPTLIMIT ",12)==0) {
	  int nn = atoi(buf+12);
	  if (nn < 10)
	    nn = 10;
	  if (nn > 100000)
	    nn = 100000;
	  SS->rcpt_limit = nn;
	}
	return 0;
}

/* Flag that banner contained "ESMTP" (case insensitive) */
void
esmtp_banner_check(SS,str)
SmtpState *SS;
char *str;
{
	char *s = str;
	while (*s) {
	  while (*s && *s != 'e' && *s != 'E') ++s;
	  if (!s) return;
	  if (cistrncmp(s,"ESMTP",5)==0) {
	    SS->esmtp_on_banner = 1;
	    return;
	  }
	  ++s;
	}
}


int
smtpopen(SS, host, noMX)
	const char *host;
	SmtpState *SS;
	int noMX;
{
	int i;
	int retries = 0;
	char SMTPbuf[1000];

	if (debug && logfp)
	  fprintf(logfp, "%s#\tsmtpopen: connecting to %.200s\n", logtag(), host);

	do {

	  SS->esmtp_on_banner = SS->main_esmtp_on_banner;
	  SS->ehlo_capabilities = 0;
	  SS->ehlo_sizeval = 0;
	  SS->rcpt_limit = 100; /* Max number of recipients per message */

	  i = smtpconn(SS, host, noMX);
	  if (i != EX_OK)
	    continue;

	  SS->prevcmdstate = 99;
	  SS->cmdstate     = SMTPSTATE_MAILFROM; /* well, reusing this key */

	  if (SS->esmtp_on_banner) {
	    /* Either it is not tested, or it is explicitely
	       desired to be tested, and was found! */
	    if (SS->myhostname)
	      sprintf(SMTPbuf, "EHLO %.200s", SS->myhostname);
	    else
	      sprintf(SMTPbuf, "EHLO %.200s", myhostname);
	    i = smtp_ehlo(SS, SMTPbuf);

#ifdef HAVE_OPENSSL

	    if (logfp)
	      fprintf(logfp, "%s#\tEHLO rc=%d demand_TLS_mode=%d tls_available=%d%s\n", logtag(), i, demand_TLS_mode, tls_available, (SS->ehlo_capabilities & ESMTP_STARTTLS) ? " STARTTLS":"");
	    if (SS->verboselog)
	      fprintf(SS->verboselog, "%s#\tEHLO rc=%d demand_TLS_mode=%d tls_available=%d%s\n", logtag(), i, demand_TLS_mode, tls_available, (SS->ehlo_capabilities & ESMTP_STARTTLS) ? " STARTTLS":"");

	    if ((i == EX_OK) && demand_TLS_mode && tls_available &&
		!(SS->ehlo_capabilities & ESMTP_STARTTLS)) {

	      /* Whoops! No TLS at the server, while we are configured
		 to demand it! */

	      i = EX_UNAVAILABLE;
	      notaryreport(NULL,NULL,"5.7.3 (Mandated TLS security mode not available)",
			   "local; 500 (Remote system doesn't support mandated TLS mode)");
	      strcpy(SS->remotemsg,"500 (Remote system doesn't support mandated TLS mode)");

	      continue;
	    }

	    if ((i == EX_OK) && tls_available &&
		(SS->ehlo_capabilities & ESMTP_STARTTLS)) {

	      i = smtpwrite(SS, 0, "STARTTLS", 0, NULL);
	      if (i == EX_OK) {
		/* Wow, "STARTTLS" command started successfully! */
		i = tls_start_clienttls(SS, host);
		if (i != 0) {
		  /* TLS startup failed :-( */
		  smtpclose(SS, 1);

		  /* Only if we are configured to *demand* the TLS mode,
		     then this situation is an error! */

		  if (demand_TLS_mode) {
		    i = EX_UNAVAILABLE;
		    notaryreport(NULL,NULL,"5.7.3 (Mandated TLS security mode not available)",
				 "local; 500 (Remote system doesn't support mandated TLS mode)");
		    strcpy(SS->remotemsg,"500 (Remote system doesn't support mandated TLS mode)");
		    
		    continue;
		  }
		  /* Well, TLS startup failed, then just reopen same
		     server, and don't redo  STARTTLS. */
		}
		if (SS->verboselog) {
		  if (i == EX_OK) {
		    extern const char *tls_cipher_name;
		    extern char       *tls_protocol;
		    extern int tls_cipher_usebits, tls_cipher_algbits;
		    extern char tls_peer_cert_name [];
		    extern char tls_peer_cert_issuer_name [];
		    fprintf(SS->verboselog,
			    " TLS mode running successfully!\n");
		    if (tls_cipher_name)
		      fprintf(SS->verboselog,
			      " TLS cipher: %s\n", tls_cipher_name);
		    if (tls_protocol)
		      fprintf(SS->verboselog,
			      " TLS protocol: %s\n", tls_protocol);
		    fprintf(SS->verboselog,
			    " TLS cipher bits: %d in use: %d\n",
			    tls_cipher_algbits, tls_cipher_usebits);
		    fprintf(SS->verboselog,
			    " TLS peer cert name:        %s\n",
			    tls_peer_cert_name);
		    fprintf(SS->verboselog,
			    " TLS peer cert issuer name: %s\n",
			    tls_peer_cert_issuer_name);
		  } else
		    fprintf(SS->verboselog, " Failed the TLS startup!\n");
		}

		/* Now re-negotiate the modes, possibly after
		   reopening the connection.  */

		SS->ehlo_capabilities = 0;
		SS->ehlo_sizeval = 0;
		SS->rcpt_limit = 100; /* Max number of recipients per msg */

		if (i != EX_OK) {
		  SS->esmtp_on_banner = SS->main_esmtp_on_banner;
		  i = makereconn(SS);
		} else
		  i = EX_OK; /* Even if 'EX_OK' is zero.. */

		if (i != EX_OK)
		  continue;

	      } else {
		smtpclose(SS, 1); /* D'uh.. STARTTLS verb failed! */

		SS->esmtp_on_banner = SS->main_esmtp_on_banner;
		SS->ehlo_capabilities = 0;
		SS->ehlo_sizeval = 0;
		SS->rcpt_limit = 100; /* Max number of recipients per msg */

		i = makereconn(SS);
		if (i != EX_OK)
		  continue;
	      }
	      /* The system *did* successfully respond to EHLO previously,
		 why would it not do so now ??? */
	      i = smtp_ehlo(SS, SMTPbuf);
	    }
#endif /* - HAVE_OPENSSL */
	    if (i == EX_TEMPFAIL) {
	      /* There are systems, which hang up on us, when we
		 greet them with an "EHLO".. Do here a normal "HELO".. */
	      i = makereconn(SS);
	      if (i != EX_OK)
		continue;
	      i = EX_TEMPFAIL;
	    }
	  }

	  if (SS->esmtp_on_banner && i == EX_OK ) {
	    if (SS->verboselog)
	      fprintf(SS->verboselog,
		      "  EHLO response flags = 0x%02x, rcptlimit=%d, sizeopt=%ld\n",
		      (int)SS->ehlo_capabilities, (int)SS->rcpt_limit,
		      (long)SS->ehlo_sizeval);
	  } else {
	    if (SS->myhostname)
	      sprintf(SMTPbuf, "HELO %.200s", SS->myhostname);
	    else
	      sprintf(SMTPbuf, "HELO %.200s", myhostname);
	    i = smtpwrite(SS, 1, SMTPbuf, 0, NULL);
	    if (i != EX_OK && SS->smtpfp) {
	      smtpclose(SS, 1);
	      if (logfp)
		fprintf(logfp, "%s#\t(closed SMTP channel - HELO failed ?)\n", logtag());
	    }
	    if (i == EX_TEMPFAIL || !SS->smtpfp || sffileno(SS->smtpfp) < 0) {
	      /* Ok, sometimes EHLO+HELO cause crash, open and do HELO only */
	      if (SS->smtpfp) smtpclose(SS, 1);
	      i = makereconn(SS);
	      if (i != EX_OK)
		continue;;
	      i = smtpwrite(SS, 1, SMTPbuf, 0, NULL);
	      if (i != EX_OK && SS->smtpfp) {
		smtpclose(SS, 1);
		if (logfp)
		  fprintf(logfp,
			  "%s#\t(closed SMTP channel - HELO failed(2))\n",
			  logtag());
	      }
	    }
	  }

	  ++retries;

	  if (SS->verboselog)
	    fprintf(SS->verboselog," retries=%d firstmx=%d mxcount=%d\n",
		    retries, SS->firstmx, SS->mxcount);

	} while ((i == EX_TEMPFAIL) && (SS->firstmx < SS->mxcount));

	if (logfp)
	  fprintf(logfp, "%s#\tsmtpopen: status = %d\n", logtag(), i);

	return i;
}

int
smtpconn(SS, host, noMX)
	SmtpState *SS;
	const char *host;
	int noMX;
{
	int	i, r, retval;
	char	hbuf[MAXHOSTNAMELEN+1];
	struct addrinfo req, *ai;
	volatile int	rc;

	memset(&req, 0, sizeof(req));
	req.ai_socktype = SOCK_STREAM;
	req.ai_protocol = IPPROTO_TCP;
	req.ai_flags    = AI_CANONNAME;
	req.ai_family   = 0; /* Either IPv4 or IPv6 ok */
	ai = NULL;

	SS->literalport = -1;

	if (SS->firstmx == 0) {
	  SS->mxcount = 0;
	  /* Cleanup of the MXH array */
	  for (i = 0; i < MAXFORWARDERS; ++i) {
	    if (SS->mxh[i].host != NULL)
	      free(SS->mxh[i].host);
	    if (SS->mxh[i].ai != NULL)
	      freeaddrinfo(SS->mxh[i].ai);
	  }
	  memset(SS->mxh, 0, sizeof(SS->mxh));
	}

#ifdef	BIND
	h_errno = 0;
#endif	/* BIND */

	stashmyaddresses(myhostname);

	if (debug && logfp)
	  fprintf(logfp, "%s#\tsmtpconn: host = %.200s\n", logtag(), host);

	if (host[0] == '"' && host[1] == '[')
	  ++host;

	if (*host == '[') {	/* hostname is IP address domain literal */
	  char *cp, buf[500];
	  const char *hcp;

	  if (SS->verboselog)
	    fprintf(SS->verboselog,"SMTP: Connecting to host: %.200s (IP literal)\n",host);

	  for (cp = buf, hcp = host+1 ;
	       *hcp != 0 && *hcp != ']' && cp < (buf+500-1) ;
	       ++cp, ++hcp)
	    *cp = *hcp;
	  *cp = '\0';

	  if (*hcp == ']' &&
	      *++hcp == ':') {
	    ++hcp;
	    sscanf(hcp,"%d",&SS->literalport);
	  }

#if defined(AF_INET6) && defined(INET6)
	  if (cistrncmp(buf,"IPv6 ",5) == 0 ||
	      cistrncmp(buf,"IPv6.",5) == 0 || 
	      cistrncmp(buf,"IPv6:",5) == 0  ) {
	    /* We parse ONLY IPv6 form of address .. well, also
	       the potential IPv4 compability addresses ... */
	    req.ai_family = PF_INET6;
#if !GETADDRINFODEBUG
	    rc = getaddrinfo(buf+5, "smtp", &req, &ai);
#else
	    rc = _getaddrinfo_(buf+5, "smtp", &req, &ai, SS->verboselog);
	    if (SS->verboselog)
	      fprintf(SS->verboselog,
		      "getaddrinfo('%s','smtp') -> r=%d, ai=%p\n",buf+5,rc,ai);
#endif
	  } else
#endif
	    {
	      /* Definitely only IPv4 address ... */
	      req.ai_family = PF_INET;
#if !GETADDRINFODEBUG
	      rc = getaddrinfo(buf, "smtp", &req, &ai);
#else
	      rc = _getaddrinfo_(buf, "smtp", &req, &ai, SS->verboselog);
	      if (SS->verboselog)
		fprintf(SS->verboselog,
			"getaddrinfo('%s','smtp') -> r=%d, ai=%p\n",buf,rc,ai);
#endif
	    }
	  {
	    char nbuf[100];
	    sprintf(nbuf,"X-IP-addr; [%.80s]", buf);
	    notary_setwtt(nbuf);
	  }


	  if (rc != 0) {
	    sprintf(SS->remotemsg, "smtp; 500 (bad IP address: %.500s)", host);
	    time(&endtime);
	    notary_setxdelay((int)(endtime-starttime));
	    notaryreport(NULL,FAILED,"5.1.2 (bad literal IP address)",
			 SS->remotemsg);
	    if (SS->verboselog)
	      fprintf(SS->verboselog,"%s\n", SS->remotemsg+6);
	    if (ai != NULL)
	      freeaddrinfo(ai);
	    return EX_NOHOST;
	  }

	  SS->mxcount = 0;
	  retval = makeconn(SS, ai, -2);

	} else {

	  /* HOSTNAME; (non-literal) */

	  if (SS->verboselog)
	    fprintf(SS->verboselog,"SMTP: Connecting to host: %.200s firstmx=%d mxcount=?\n",host,SS->firstmx);
	  hbuf[0] = '\0';
	  errno = 0;

	  /* use the hostent we got */
#ifdef	BIND
	  /*
	   * Look for MX RR's. If none found, use the hostentry in hp.
	   * Otherwise loop through all the mxhosts doing gethostbyname's.
	   */
	  if (!noMX && SS->firstmx == 0) {
	    if (SS->verboselog)
	      fprintf(SS->verboselog," getmxrr(%.200s)",host);

	    /*	We pick (dynamically!) our current interfaces,
		and thus can (hopefully!) avoid sending mail to
		ourselves thru MX pointed identity we didn't
		realize being ours!				*/
	    stashmyaddresses(myhostname);

	    if (statusreport)
	      report(SS,"MX-lookup: %s", host);

	    SS->mxcount = 0;
	    rc = getmxrr(SS, host, SS->mxh, MAXFORWARDERS, 0);
	    if (SS->verboselog) {
	      if (SS->mxcount == 0)
		fprintf(SS->verboselog,
			" rc=%d, no MXes (host=%.200s)\n", rc, host);
	      else
		fprintf(SS->verboselog,
			" rc=%d, mxh[0].host=%.200s (host=%.200s) mxcnt=%d\n",
			rc, (SS->mxh[0].host) ? (char*)SS->mxh[0].host : "<NUL>",
			host, SS->mxcount);
	    }
	    switch (rc) {
	      /* remotemsg is generated within getmxrr */
	    case EX_TEMPFAIL:
	      /* This will look MAD.. We had a timeout on MX lookup,
		 but the same domain name MAY have an A record.
		 In this case the domain is likely to have an NS with
		 failing DNS server, and nobody notices it... */
	      if (ai != NULL)
		freeaddrinfo(ai);
	      break;
	    case EX_SOFTWARE:
	    case EX_UNAVAILABLE:
	      if (ai != NULL)
		freeaddrinfo(ai);
	      return EX_TEMPFAIL;
	    case EX_NOHOST:
	      if (ai != NULL)
		freeaddrinfo(ai);
	      return EX_NOHOST;
	    case EX_NOPERM:
	      if (ai != NULL)
		freeaddrinfo(ai);
	      return EX_NOPERM;
	    default:
	      break;
	    }
	  }
#endif /* BIND */

	  if (!checkwks && SS->mxcount > 0 && SS->mxh[0].host == NULL) {

	    /* Condition ( SS->mxcount > 0 && SS->mxh[0].host == NULL ) can
	       be considered as: Instant (Configuration?) Error;
	       No usable MXes, possibly we are at the lowest MX priority level,
	       and somebody has made some configuration errors... */

	    if (ai != NULL)
	      freeaddrinfo(ai);

	    strcpy(SS->remotemsg,
		   "smtp; 500 (configuration inconsistency, we are lowest MX, but this is not our local domain!)");
	    notaryreport(NULL, NULL,
			 "5.4.4 (unable to route)",
			 "smtp; 500 (configuration inconsistency, we are lowest MX but this is not our local domain)");

	    return EX_NOHOST;
	  }

	  if (SS->mxcount == 0 || SS->mxh[0].host == NULL) {

	    errno = 0;
	    /* Either forbidden MX usage, or does not have MX entries! */

	    ai = NULL;
	    req.ai_family   = PF_INET;
#if !GETADDRINFODEBUG
	    r = getaddrinfo(host, "smtp", &req, &ai);
#else
	    r = _getaddrinfo_(host, "smtp", &req, &ai, SS->verboselog);
if (SS->verboselog)
  fprintf(SS->verboselog,"getaddrinfo('%s','smtp') -> r=%d, ai=%p\n",host,r,ai);
#endif
#if defined(AF_INET6) && defined(INET6)
	    {
	      struct addrinfo *ai2 = NULL, *a;
	      int i2;
	      memset(&req, 0, sizeof(req));
	      req.ai_socktype = SOCK_STREAM;
	      req.ai_protocol = IPPROTO_TCP;
	      req.ai_flags    = AI_CANONNAME;
	      req.ai_family   = PF_INET6;

	      /* This resolves CNAME, it should not happen in case
		 of MX server, though..    */
#if !GETADDRINFODEBUG
	      i2 = getaddrinfo(host, "0", &req, &ai2);
#else
	      i2 = _getaddrinfo_(host, "0", &req, &ai2, SS->verboselog);
	      if (SS->verboselog)
		fprintf(SS->verboselog,
			"  getaddrinfo('%s','smtp') -> r=%d, ai=%p\n",
			host,i2,ai2);
#endif

	      if (r != 0 && i2 == 0) {
		/* IPv6 address, no IPv4 (or error..) */
		r = i2;
		ai = ai2; ai2 = NULL;
	      }
	      if (ai2 && ai) {
		/* BOTH ?!  Catenate them! */
		a = ai;
		while (a && a->ai_next) a = a->ai_next;
		if (a) a->ai_next = ai2;
	      }
	    }
#endif
	    if (r != 0) {

	      int gai_err = r;

	      /* getaddrinfo() yields no data, and getmxrr() yielded
		 EX_TEMPFAIL ?   Well, getmxrr() did set some reports,
		 lets use them! */
	      if ((r == EAI_NONAME || r == EAI_AGAIN) && rc == EX_TEMPFAIL)
		return rc;

	      if ( r == EAI_AGAIN ) {

		sprintf(SS->remotemsg,"smtp; 566 (getaddrinfo<%.200s>: try latter)",host);
		time(&endtime);
		notary_setxdelay((int)(endtime-starttime));
		notaryreport(NULL,FAILED,"5.4.3 (dns lookup 'try again')", SS->remotemsg);
		if (SS->verboselog)
		  fprintf(SS->verboselog,"%s\n",SS->remotemsg+6);
		if (ai != NULL)
		  freeaddrinfo(ai);
		return EX_TEMPFAIL;
	      }

	      if ( r == EAI_NODATA ) {
		sprintf(SS->remotemsg,"smtp; 500 (getaddrinfo<%.200s>: No data)",host);
		time(&endtime);
		notary_setxdelay((int)(endtime-starttime));
		notaryreport(NULL,FAILED,"5.4.3 (dns lookup 'no data')", SS->remotemsg);
		if (SS->verboselog)
		  fprintf(SS->verboselog,"%s\n",SS->remotemsg+6);
		if (ai != NULL)
		  freeaddrinfo(ai);
		if (rc == EX_TEMPFAIL)
		  return rc;
		return EX_UNAVAILABLE;
	      }

	      r = EX_UNAVAILABLE; /* This gives instant rejection */
	      if (rc == EX_TEMPFAIL)
		r = rc;

	      if (strchr(host,'_') != NULL) {
		sprintf(SS->remotemsg,
			"smtp; 500 (Hostname with illegal [to the DNS] underscore in it: '%.200s')", host);
	      } else if (noMX) {
		sprintf(SS->remotemsg,
			"smtp; 500 (configuration inconsistency. MX usage forbidden, no address in the DNS: '%.200s')", host);
	      } else {
		if (SS->mxcount > 0) {
		  sprintf(SS->remotemsg,
			  "smtp; 500 (nameserver data inconsistency. All MXes rejected [we are the best?], no address: '%.200s')", host);
#if 1
		  zsyslog((LOG_ERR, "%s", SS->remotemsg));
		  if (r != EX_TEMPFAIL)
		    r = EX_NOHOST;
#endif
		} else if (gai_err == EAI_NONAME || gai_err == EAI_NODATA) {
		  sprintf(SS->remotemsg,
			  "smtp; 500 (nameserver data inconsistency. No MX, no address: '%.200s' (%s))",
			  host, gai_err == EAI_NONAME ? "NONAME" : "NODATA");
		  zsyslog((LOG_ERR, "%s r=%d", SS->remotemsg, r));
#if 0
		  if (r != EX_TEMPFAIL)
		    r = EX_NOHOST; /* Can do instant reject */
#else
		  r = EX_TEMPFAIL;
#endif
		} else {
		  sprintf(SS->remotemsg,
			  "smtp; 500 (nameserver data inconsistency. No MX, no address: '%.200s', errno=%s, gai_errno='%s')",
			  host, strerror(errno), gai_strerror(gai_err));
#if 1
		  zsyslog((LOG_ERR, "%s", SS->remotemsg));
		  r = EX_TEMPFAIL; /* This gives delayed rejection (after a timeout) */
#endif
		}
	      }
	      time(&endtime);
	      notary_setxdelay((int)(endtime-starttime));
	      notaryreport(NULL,FAILED,"5.4.4 (nameserver data inconsistency)",
			   SS->remotemsg);
	      if (SS->verboselog)
		fprintf(SS->verboselog,"%s\n",SS->remotemsg+6);
	      /* it was: EX_UNAVAILABLE, but such blocks retrying, thus
		 current EX_TEMPFAIL, which will cause timeout latter on.. */
	      if (ai != NULL)
		freeaddrinfo(ai);
	      return r;
	    }
	    {
	      char buf[512];
	      sprintf(buf,"dns; %.200s", host);
	      notary_setwtt(buf);
	    }
	    retval = makeconn(SS, ai, -1);

	  } else {

	    /* Has valid MX records, they have been suitably randomized
	       at  getmxrr(), and are now ready for use.  */

	    retval = EX_UNAVAILABLE;

	    for (i = SS->firstmx; (i < SS->mxcount &&
				   SS->mxh[i].host != NULL); ++i) {

	      char buf[512];
	      sprintf(buf,"dns; %.200s", SS->mxh[i].host);
	      notary_setwtt(buf);

	      r = makeconn(SS, SS->mxh[i].ai, i);
	      SS->firstmx = i+1;
	      if (r == EX_OK) {
		retval = EX_OK;
		break;
	      } else if (r == EX_TEMPFAIL)
		retval = EX_TEMPFAIL;
	    }
	  }
	} /* end of HOSTNAME MX lookup processing */

	if (debug && logfp)
	  fprintf(logfp,
		  "%s#\tsmtpconn: retval = %d\n", logtag(), retval);

	if (ai != NULL)
	  freeaddrinfo(ai);

	return retval;
}

void
deducemyifname(SS)
	SmtpState *SS;
{
	union {
	  struct sockaddr_in  v4;
#if defined(AF_INET6) && defined(INET6)
	  struct sockaddr_in6 v6;
#endif
	} laddr;
	int laddrsize;
	struct hostent *hp;

	if (SS->myhostname != NULL)
	  free(SS->myhostname);
	SS->myhostname = NULL;

	laddrsize = sizeof(laddr);
	if (getsockname(sffileno(SS->smtpfp), (struct sockaddr*) &laddr,
			&laddrsize) != 0)
	  return; /* Failure .. */

	if (laddr.v4.sin_family == AF_INET)
	  hp = gethostbyaddr((char*)&laddr.v4.sin_addr,   4, AF_INET);
#if defined(AF_INET6) && defined(INET6)
	else if (laddr.v6.sin6_family == AF_INET6)
	  hp = gethostbyaddr((char*)&laddr.v6.sin6_addr, 16, AF_INET6);
#endif
	else
	  hp = NULL;

	if (hp == NULL)
	  return;

	/* Ok, NOW we have a hostent with our IP-address reversed to a name */
	SS->myhostname = strdup(hp->h_name);
}

int
makeconn(SS, ai, ismx)
	SmtpState *SS;
	struct addrinfo *ai;
	int ismx;
{
	int retval;
	int mfd;
	int isreconnect = (ai == &SS->ai);

#ifdef	BIND
#ifdef	RFC974
	char	hostbuf[MAXHOSTNAMELEN+1];
	int	ttl;

	if (ai->ai_canonname)
	  strncpy(hostbuf, ai->ai_canonname, sizeof(hostbuf));
	else
	  *hostbuf = 0;
	hostbuf[sizeof(hostbuf)-1] = 0;

	if (checkwks && SS->verboselog)
	  fprintf(SS->verboselog,"  makeconn(): checkwks of host %.200s\n",
		  hostbuf);

	if (checkwks &&
	    getrr(hostbuf, &ttl, sizeof hostbuf, (u_short)T_WKS, 2, SS->verboselog) != 1) {
	  sprintf(SS->remotemsg,"smtp; 550 (WKS checks: no SMTP reception capability registered for host %.200s)",
		  hostbuf);
	  time(&endtime);
	  notary_setwttip(NULL);
	  notary_setxdelay((int)(endtime-starttime));
	  notaryreport(NULL,FAILED,"5.4.4 (WKS Checks: no SMTP reception capability registered)", SS->remotemsg);
	  if (SS->verboselog)
	    fprintf(SS->verboselog,"%s\n",SS->remotemsg+6);
	  return EX_UNAVAILABLE;
	}
#endif	/* RFC974 */
#endif	/* BIND */


	retval = EX_TEMPFAIL;
#if 0
	if (SS->verboselog) {
	  fprintf(SS->verboselog,"makeconn('%.200s') to IP addresses:", hostbuf);
	  for ( ; ai ; ai = ai->ai_next ) {
	    /* XX: print the addresses... */
	    fprintf(SS->verboselog," %s",
		    dottedquad((struct in_addr*)*hp_getaddr()));
	  }
	  fprintf(SS->verboselog,"\n");
	}
#endif

	for ( ; ai && !getout ; ai = ai->ai_next ) {

	  int i = 0;
	  struct sockaddr_in *si;
#if defined(AF_INET6) && defined(INET6)
	  struct sockaddr_in6 *si6;
#endif

	  if (! isreconnect) {

	    /* For possible reconnect */
	    if (SS->ai.ai_canonname) free(SS->ai.ai_canonname);
	    memcpy(&SS->ai, ai, sizeof(*ai));
	    memset(&SS->ai_addr, 0, sizeof(SS->ai_addr));
	    if (ai->ai_family == AF_INET)
	      memcpy(&SS->ai_addr.v4, ai->ai_addr, sizeof(SS->ai_addr.v4));
#if defined(AF_INET6) && defined(INET6)
	    else
	      memcpy(&SS->ai_addr.v6, ai->ai_addr, sizeof(SS->ai_addr.v6));
#endif
	    SS->ai.ai_addr = (struct sockaddr *) & SS->ai_addr;
	    SS->ai.ai_canonname = NULL;
	    if (ai->ai_canonname)
	      SS->ai.ai_canonname = strdup(ai->ai_canonname);
	    SS->ai.ai_next = NULL;
	    SS->ismx = ismx;
	  }

	  if (ai->ai_family == AF_INET) {
	    si = (struct sockaddr_in *)ai->ai_addr;
	    i = matchmyaddress((struct sockaddr*)ai->ai_addr);
	    inet_ntop(AF_INET, &si->sin_addr, SS->ipaddress, sizeof(SS->ipaddress));
	    sprintf(SS->ipaddress + strlen(SS->ipaddress), "|%d",
		    SS->servport);
	  } else
#if defined(AF_INET6) && defined(INET6)
	  if (ai->ai_family == AF_INET6) {
	    si6 = (struct sockaddr_in6*)ai->ai_addr;
	    i = matchmyaddress((struct sockaddr*)ai->ai_addr);
	    strcpy(SS->ipaddress,"ipv6 ");
	    inet_ntop(AF_INET6, &si6->sin6_addr, SS->ipaddress+5, sizeof(SS->ipaddress)-5);
	    sprintf(SS->ipaddress + strlen(SS->ipaddress), "|%d",
		    SS->servport);
	  } else
#endif
	    sprintf(SS->ipaddress,"UNKNOWN-ADDR-FAMILY-%d", ai->ai_family);

	  notary_setwttip(SS->ipaddress);

	  if (i != 0 && ismx == -2)
	    i = 0; /* Allow routing back to [1.2.3.4] ! */

	  if (SS->verboselog)
	    fprintf(SS->verboselog,"Trying address: %s port %d\n",
		    SS->ipaddress, SS->servport);

	  /* XXX: Locally matched address is on some MX target, if  ismx >= 0.
	     In such a case, the error should be ???? What ? */

	  if (i != 0 && SS->servport == IPPORT_SMTP) {
	    time(&endtime);
	    notary_setxdelay((int)(endtime-starttime));
	    switch (i) {
	    case 3:
	      notaryreport(NULL,FAILED,"5.4.6 (trying to use invalid destination address)","smtp; 500 (Trying to talk to invalid destination network address!)");
	      break;
	    case 2:
	      notaryreport(NULL,FAILED,"5.4.6 (trying to talk to loopback (=myself)!)","smtp; 500 (Trying to talk to loopback (=myself)!)");
	      break;
	    default:
	      notaryreport(NULL,FAILED,"5.4.6 (trying to talk with myself!)","smtp; 500 (Trying to talk with myself!)");
	      break;
	    }
	    sprintf(SS->remotemsg,"Trying to talk with myself!");
	    retval = EX_UNAVAILABLE;
	    break;		/* TEMPFAIL or UNAVAILABLE.. */
	  }

	  if (SS->smtpfp) {
	    /* Clean (close) these fds -- they have been noted to leak.. */
	    smtpclose(SS, 1);
	    if (logfp)
	      fprintf(logfp,"%s#\t(closed SMTP channel at makeconn())\n",logtag());
	  }


	  i = vcsetup(SS, /* (struct sockaddr*) */ ai->ai_addr, &mfd, hostbuf);
	  retval = i;

	  switch (i) {
	  case EX_OK:

	      SS->smtpfd = mfd;
	      SS->smtpfp = sfnew(NULL, NULL, SS->smtp_bufsize, mfd, SF_WRITE);

	      memset(&SS->smtpdisc, 0, sizeof(SS->smtpdisc));
	      SS->smtpdisc.D.readf   = NULL;
	      SS->smtpdisc.D.writef  = smtp_sfwrite;
	      SS->smtpdisc.D.seekf   = NULL;
	      SS->smtpdisc.D.exceptf = NULL;
	      SS->smtpdisc.SS        = SS;
	      sfdisc(SS->smtpfp, &SS->smtpdisc.D);

	      if (SS->smtpfp == NULL) {
		int err;
		err = errno;
		fprintf(stdout,"# smtp: Failed to fdopen() a socket stream, errno=%d, err='%s' Hmm ??\n",err, strerror(err));
		fflush(stdout);
		abort(); /* sock-stream fdopen() failure! */
	      }

	      deducemyifname(SS);

	      SS->smtp_outcount = 0;
	      SS->block_written = 0;

	      if (SS->esmtp_on_banner > 0)
		SS->esmtp_on_banner = 0;

	      SS->prevcmdstate = 99;
	      SS->cmdstate     = SMTPSTATE_MAILFROM;

	      /* Wait for the initial "220-" greeting */
	      retval = smtpwrite(SS, 1, NULL, 0, NULL);
	      if (retval != EX_OK)
		/*
		 * If you want to continue with the next host,
		 * the below should be 'return EX_TEMPFAIL'.
		 */
		break;		/* try another host address */
	      return EX_OK;
	  case EX_TEMPFAIL:
	      retval = EX_TEMPFAIL;
	      break;
	  }
	} /* end of for-loop */

	if (getout)
	  retval = EX_TEMPFAIL;
	return retval;
}

int
makereconn(SS)
     SmtpState *SS;
{
  smtpclose(SS, 1);
  return makeconn(SS, & SS->ai, SS->ismx);
}

int
vcsetup(SS, sa, fdp, hostname)
	SmtpState *SS;
	struct sockaddr *sa;
	int *fdp;
	char *hostname;
{
	int af, port;
	volatile int addrsiz;
	int sk;
	struct sockaddr_in *sai = (struct sockaddr_in *)sa;
	struct sockaddr_in sad;
#if defined(AF_INET6) && defined(INET6)
	struct sockaddr_in6 *sai6 = (struct sockaddr_in6 *)sa;
	struct sockaddr_in6 sad6;
#endif
	union {
	  struct sockaddr_in sai;
#if defined(AF_INET6) && defined(INET6)
	  struct sockaddr_in6 sai6;
#endif
	} upeername;
	int upeernamelen = 0;

	u_short p;
	int errnosave, flg;
	char *se;

#if 0
	& addrsiz;
#endif
	time(&now);

	af = sa->sa_family;
#if defined(AF_INET6) && defined(INET6)
	if (sa->sa_family == AF_INET6) {
	  addrsiz = sizeof(*sai6);
	  memset(&sad6, 0, sizeof(sad6));
	}
	else
#endif
	  {
	    addrsiz = sizeof(*sai);
	    memset(&sad, 0, sizeof(sad));
	  }

	if (conndebug)
	  fprintf(stderr, "Trying %.200s [%.200s] ... ",
		  hostname, SS->ipaddress);
	if (logfp)
	  fprintf(logfp, "%s#\t(Connecting to `%.200s' [%.200s] %24.24s)\n",
		  logtag(), hostname, SS->ipaddress, ctime(&now));
	strncpy(SS->remotehost, hostname, sizeof(SS->remotehost));
	SS->remotehost[sizeof(SS->remotehost)-1] = 0;
	if (statusreport) {
	  report(SS,"connecting to [%s]",SS->ipaddress);
	}

	sk = socket(af, SOCK_STREAM, 0);
	if (sk < 0) {
	  se = strerror(errno);
	  sprintf(SS->remotemsg, "smtp; 500 (Internal error, socket(AF=%d): %s)", af, se);
	  time(&endtime);
	  notary_setxdelay((int)(endtime-starttime));
	  notaryreport(NULL,FAILED,"5.4.0 (internal error)",SS->remotemsg);
	  if (conndebug)
	    fprintf(stderr, "%s\n", SS->remotemsg+6);
	  if (SS->verboselog)
	    fprintf(SS->verboselog,"%s\n",SS->remotemsg+6);
	  if (logfp)
	    fprintf(logfp,"%s#\t(Internal error, socket: %s)\n",logtag(),se);
abort();
	  return EX_TEMPFAIL;
	}

	if (localidentity != NULL) {
	  /* Uh... Somebody wants us to do special hoops...
	     ... to bind some of our alternate IP addresses,
	     for example.. */
#if defined(AF_INET6) && defined(INET6)
	  if (cistrncmp(localidentity,"[ipv6 ",6) == 0 ||
	      cistrncmp(localidentity,"[ipv6:",6) == 0 ||
	      cistrncmp(localidentity,"[ipv6.",6) == 0) {
	    char *s = strchr(localidentity,']');
	    if (s) *s = 0;
	    if (inet_pton(AF_INET6, localidentity+6, &sad6.sin6_addr) < 1) {
	      /* False IPv6 number literal */
	      /* ... then we don't set the IP address... */
	    }
	  } else
#endif
	    if (*localidentity == '[') {
	      char *s = strchr(localidentity,']');
	      if (s) *s = 0;
	      if (inet_pton(AF_INET, localidentity+1, &sad.sin_addr) < 1) {
		/* False IP(v4) number literal */
		/* ... then we don't set the IP address... */
	      }
	    } else {
	      struct addrinfo req, *ai = NULL;
	      int r2;

	      memset(&req, 0, sizeof(req));
	      req.ai_socktype = SOCK_STREAM;
	      req.ai_protocol = IPPROTO_TCP;
	      req.ai_flags    = AI_CANONNAME;
	      req.ai_family   = sa->sa_family; /* Same family, as our
						  destination address is */
#if !GETADDRINFODEBUG
	      r2 = getaddrinfo(localidentity, "smtp", &req, &ai);
#else
	      r2 = _getaddrinfo_(localidentity, "smtp", &req, &ai, SS->verboselog);
if (SS->verboselog)
  fprintf(SS->verboselog,"getaddrinfo('%s','smtp') -> r=%d, ai=%p\n",localidentity,r2,ai);
#endif
	      if (r2 == 0 && ai != NULL) /* We try ONLY the first address. */ {
		if (ai->ai_family == AF_INET) {
		  memcpy((void*)&sad.sin_addr,
			 (void*)&((struct sockaddr_in*)ai->ai_addr)->sin_addr,
			 4);
		}
#if defined(AF_INET6) && defined(INET6)
		else {
		  memcpy((void*)&sad6.sin6_addr,
			 (void*)&((struct sockaddr_in6*)ai->ai_addr)->sin6_addr,
			 16);
		}
#endif
	      }
	      if (ai != NULL)
		freeaddrinfo(ai);
	      /* If it didn't resolv, */
	      /* ... then we don't set the IP address... */
	    }
	}

	if (wantreserved && getuid() == 0) {
	  /* try grabbing a port */
	  for (p = IPPORT_RESERVED-1; p >= (u_short)(IPPORT_RESERVED/2); --p) {
	    if (af == AF_INET) {
	      sad.sin_family = AF_INET;
	      sad.sin_port   = htons(p);
	      if (bind(sk, (struct sockaddr *)&sad, sizeof sad) >= 0)
		break;
	    }
#if defined(AF_INET6) && defined(INET6)
	    else if (af == AF_INET6) {
	      sad6.sin6_family = AF_INET6;
	      sad6.sin6_port   = htons(p);
	      if (bind(sk, (struct sockaddr *)&sad6, sizeof sad6) >= 0)
		break;
	    }
#endif
	    if (errno != EADDRINUSE && errno != EADDRNOTAVAIL) {
	      char *s = strerror(errno);
	      sprintf(SS->remotemsg, "smtp; 500 (Internal error, bind: %s)", s);
	      time(&endtime);
	      notary_setxdelay((int)(endtime-starttime));
	      notaryreport(NULL,FAILED,"5.4.0 (internal error, bind)",SS->remotemsg);
	      if (SS->verboselog)
		fprintf(SS->verboselog,"%s\n", SS->remotemsg+6);
	      if (conndebug)
		fprintf(stderr, "%s\n", SS->remotemsg+6);
	      if (logfp)
		fprintf(logfp, "%s#\t(Internal error, bind: %s)\n", logtag(), s);
	      return EX_UNAVAILABLE;
	    }
	  }

	  if (p < (u_short)(IPPORT_RESERVED/2)) {
	    sprintf(SS->remotemsg, "too many busy ports");
	    time(&endtime);
	    notary_setxdelay((int)(endtime-starttime));
	    notaryreport(NULL,FAILED,"5.4.0 (internal error, too many busy ports)","smtp; 500 (Internal error, too many busy ports)");
	    if (conndebug)
	      fprintf(stderr, "%s\n", SS->remotemsg+6);
	    if (SS->verboselog)
	      fprintf(SS->verboselog,"%s\n",SS->remotemsg+6);
	    if (logfp)
	      fprintf(logfp,"%s#\t(Internal error, too many busy ports)\n", logtag());
	    return EX_TEMPFAIL;
	  }
	} else if (localidentity != NULL) {
	  /* Ok, it wasn't a desire for any PRIVILEGED port, just
	     binding on the specific IP will be accepted. */
	  errno = 0;
	  if (af == AF_INET)
	    bind(sk, (struct sockaddr *)&sad, sizeof sad);
#if defined(AF_INET6) && defined(INET6)
	  if (af == AF_INET6)
	    bind(sk, (struct sockaddr *)&sad6, sizeof sad6);
#endif
	  if (logfp)
	    fprintf(logfp,"%s#\tlocalidentity=%s bind() errno = %d\n",
		    logtag(), localidentity, errno);
	  /* If it fails, what could we do ? */
	}

	port = SS->servport;
	if (SS->literalport > 0)
	  port = SS->literalport;
	if (af == AF_INET)
	  sai->sin_port   = htons(port);
#if defined(AF_INET6) && defined(INET6)
	if (af == AF_INET6)
	  sai6->sin6_port = htons(port);
#endif
	/* setreuid(0,first_uid);
	   if(SS->verboselog) fprintf(SS->verboselog,"setreuid: first_uid=%d, ruid=%d, euid=%d\n",first_uid,getuid(),geteuid()); */

	if (SS->verboselog)
	  fprintf(SS->verboselog, "Connecting to %.200s [%.200s] port %d\n",
		  hostname, SS->ipaddress, ntohs(sai->sin_port));


	gotalarm = 0;

	/* The socket will be non-blocking for its entire lifetime.. */
	fd_nonblockingmode(sk);

	errnosave = errno = 0;

	if (connect(sk, sa, addrsiz) < 0 &&
	    (errno == EWOULDBLOCK || errno == EINPROGRESS)) {

	  /* Wait for the connection -- or timeout.. */

	  struct timeval tv;
	  fd_set wrset;
	  int rc;

	  errno = 0;

	  /* Pick our local socket name */
	  /* NOTE: At Solaris 2.5.1 (STREAMS based) this may take
	     lots of time! */

	  memset(&upeername, 0, sizeof(upeername));
	  upeernamelen = sizeof(upeername);
	  getsockname(sk, (struct sockaddr*) &upeername, &upeernamelen);

	  errnosave = errno;

	  /* Select for the establishment, or for the timeout */

	  tv.tv_sec = timeout_conn;
	  tv.tv_usec = 0;
	  _Z_FD_ZERO(wrset);
	  _Z_FD_SET(sk, wrset);

	  rc = select(sk+1, NULL, &wrset, NULL, &tv);

	  errno = 0; /* All fine ? */
	  if (rc == 0) {
	    /* Timed out :-( */
	    gotalarm = 1; /* Well, sort of ... */
	    errno = ETIMEDOUT;
	  }
	}

	if (!errnosave)
	  errnosave = errno;

#ifdef SO_ERROR
	flg = 0;
	if (errnosave == 0) {
	  int flglen = sizeof(flg);
	  getsockopt(sk, SOL_SOCKET, SO_ERROR, (void*)&flg, &flglen);
	}
	if (flg != 0 && errnosave == 0)
	  errnosave = flg;
	/* "flg" contains socket specific error condition data */
#endif

	if (errnosave == 0) {
	  /* We have successfull connection,
	     lets record its peering data */
	  memset(&upeername, 0, sizeof(upeername));
	  upeernamelen = sizeof(upeername);
	  getsockname(sk, (struct sockaddr*) &upeername, &upeernamelen);
	}

	if (upeernamelen != 0) {
#if defined(AF_INET6) && defined(INET6)
	  if (upeername.sai6.sin6_family == AF_INET6) {
	    int len = strlen(SS->ipaddress);
	    char *s = SS->ipaddress + len;
	    strcat(s++, "|");
	    inet_ntop(AF_INET6, &upeername.sai6.sin6_addr,
		      s, sizeof(SS->ipaddress)-len-9);
	    s = s + strlen(s);
	    sprintf(s, "|%d", ntohs(upeername.sai6.sin6_port));
	  } else
#endif
	    if (upeername.sai.sin_family == AF_INET) {
	      int len = strlen(SS->ipaddress);
	      char *s = SS->ipaddress + len;
	      strcat(s++, "|");
	      inet_ntop(AF_INET, &upeername.sai.sin_addr,
			s, sizeof(SS->ipaddress)-len-9);
	      s = s + strlen(s);
	      sprintf(s, "|%d", ntohs(upeername.sai.sin_port));
	    } else {
	      strcat(SS->ipaddress, "|UNKNOWN-LOCAL-ADDRESS");
	    }

	  notary_setwttip(SS->ipaddress);
	}

	if (errnosave == 0 && !gotalarm) {
	  int on = 1;
	  /* setreuid(0,0); */
	  *fdp = sk;
#if 1
	  setsockopt(sk, SOL_SOCKET, SO_KEEPALIVE, (void*)&on, sizeof on);
#else
#if	defined(__svr4__) || defined(BSD) && (BSD-0) >= 43
	  setsockopt(sk, SOL_SOCKET, SO_KEEPALIVE, (void*)&on, sizeof on);
#else  /* BSD < 43 */
	  setsockopt(sk, SOL_SOCKET, SO_KEEPALIVE, 0, 0);
#endif /* BSD >= 43 */
#endif
	  if (conndebug)
	    fprintf(stderr, "connected!\n");

	  return EX_OK;
	}
	/* setreuid(0,0); */

	se = strerror(errnosave);

	sprintf(SS->remotemsg, "smtp; 500 (connect to %.200s [%.200s]: %s)",
		hostname, SS->ipaddress, se);
	if (statusreport)
	  report(SS,"%s",SS->remotemsg+4);
	time(&endtime);
	notary_setxdelay((int)(endtime-starttime));
	notaryreport(NULL,FAILED,"5.4.1 (TCP/IP-connection failure)", SS->remotemsg);

	if (conndebug)
		fprintf(stderr, "%s\n", SS->remotemsg);
	if (SS->verboselog)
		fprintf(SS->verboselog,"%s\n",SS->remotemsg);
	if (logfp)
	  fprintf(logfp,"%s#\t%s\n", logtag(), SS->remotemsg+4);
	switch (errnosave) {	/* from sendmail... */
	case EISCONN:
	case ETIMEDOUT:
	case EINPROGRESS:
	case EALREADY:
	case EADDRINUSE:
	case EHOSTDOWN:
	case ENETDOWN:
	case ENETRESET:
	case ENOBUFS:
	case ECONNREFUSED:
	case ECONNRESET:
	case EHOSTUNREACH:
	case ENETUNREACH:
	case EPERM:
	/* wonder how Sendmail missed this one... */
	case EINTR:
		close(sk);
		return EX_TEMPFAIL;
	}
	close(sk);
	return EX_UNAVAILABLE;
}


RETSIGTYPE
sig_pipe(sig)
int sig;
{
	if (logfp != NULL) {
	  fprintf(logfp, "%s#\t*** Received SIGPIPE!\n", logtag());
	  /* abort(); */
	}
	SIGNAL_HANDLE(sig, sig_pipe);
	SIGNAL_RELEASE(sig);
}

#ifdef HAVE_STDARG_H
#ifdef __STDC__
void
rmsgappend(SmtpState *SS, int append, char *fmt, ...)
#else /* Not ANSI-C */
void
rmsgappend(SS, append, fmt)
	SmtpState *SS;
	int append;
	char *fmt;
#endif
#else
void
rmsgappend(va_alist)
	va_dcl
#endif
{
	va_list ap;
	char *arg;
	char *cp, *cpend;
#ifdef HAVE_STDARG_H
	va_start(ap,fmt);
#else
	char *fmt;
	SmtpState *SS;
	int append;
	va_start(ap);
	SS     = va_arg(ap, SmtpState *);
	append = va_arg(ap, int);
	fmt    = va_arg(ap, char *);
#endif

	cp    = SS->remotemsg + strlen(SS->remotemsg);
	cpend = SS->remotemsg + sizeof(SS->remotemsg) -1;

	if (SS->prevcmdstate >= 99) /* magic limit.. */
	  SS->remotemsgs[SS->cmdstate] = SS->remotemsg;
	if (SS->cmdstate > SS->prevcmdstate)
	  SS->remotemsgs[SS->cmdstate] = cp;

	if (!append)
	  cp = SS->remotemsgs[SS->cmdstate];

	SS->prevcmdstate = SS->cmdstate;

	if (!fmt) fmt="(NULL)";
	for (; *fmt != 0; ++fmt) {
	  if (*fmt == '%' && *++fmt == 's') {
	    arg = va_arg(ap, char *);
	    while (*arg && cp < cpend)
	      *cp++ = *arg++;
	  } else
	    if (cp < cpend)
	      *cp++ = *fmt;
	}
	*cp = 0;
	va_end(ap);
}

/*
 *  SMTP PIPELINING (RFC 1854/2197) support uses model of:
 *       1st RCPT is for "MAIL From:<>".. -line
 *       2..n-1: are actual RCPT To:<> -lines
 *	 n:th is the "DATA"-line.
 */


void
smtpclose(SS, failure)
     SmtpState *SS;
     int failure;
{
	if (SS->smtpfp != NULL) {

	  /* First close the socket so that no FILE buffered stuff
	     can become flushed out anymore. */

	  if (SS->smtpfd >= 0)
	    close(SS->smtpfd);
	  SS->smtpfd = -1;
	  /* Absolutely NO SFIO SYNC AT THIS POINT! */
	  zsfsetfd(SS->smtpfp, -1);

	  /* Now do all normal SFIO close things -- including
	     buffer flushes... */

	  sfclose(SS->smtpfp);
	  SS->smtpfp = NULL;
	}

#ifdef HAVE_OPENSSL
	if (SS->sslmode)
	  tls_stop_clienttls(SS, failure);
	SS->sslmode = 0;
#endif /* - HAVE_OPENSSL */

	if (SS->smtphost != NULL)
	  free(SS->smtphost);
	SS->smtphost = NULL;
}

void
smtp_flush(SS)
	SmtpState *SS;
{
	SS->pipebufsize = 0;
	if (SS->pipebuf == NULL) {
	  SS->pipebufspace = 240;
	  SS->pipebuf = malloc(SS->pipebufspace);
	  if (! SS->pipebuf) zmalloc_failure = 1;
	}
	for (;SS->pipeindex > 0; --SS->pipeindex) {
	  if (SS->pipecmds[SS->pipeindex-1])
	    free(SS->pipecmds[SS->pipeindex-1]);
	  SS->pipecmds[SS->pipeindex-1] = NULL;
	}
	SS->pipeindex   = 0;
	SS->pipereplies = 0;
}


int bdat_flush(SS, lastflg)
	SmtpState *SS;
	int lastflg;
{
	int pos, i, wrlen;
	volatile int r;   /* longjmp() globber danger */
	char lbuf[80];

	if (lastflg)
	  sprintf(lbuf, "BDAT %d LAST", SS->chunksize);
	else
	  sprintf(lbuf, "BDAT %d", SS->chunksize);

	r = smtpwrite(SS, 1, lbuf, 1 /* ALWAYS "pipeline" */, NULL);
	if (r != EX_OK)
	  return r;

	for ( pos = 0; pos < SS->chunksize && !sferror(SS->smtpfp); ) {
	  wrlen = SS->chunksize - pos;
	  i = sfwrite(SS->smtpfp, SS->chunkbuf + pos, wrlen);
	  if (i >= 0)
	    pos += i;
	  else {
	    /* ERROR!!! */
	    SS->chunksize = 0;
	    notaryreport(NULL,NULL,
			 "5.4.2 (BDAT message write failed)",
			 "smtp; 566 (BDAT Message write failed)");
	    return EX_TEMPFAIL;
	  }
	}
	SS->chunksize = 0;

	if (SS->smtpfp && !sferror(SS->smtpfp)) {
	  if (lastflg || ! SS->pipelining)
	    r = smtp_sync(SS, r, 0);
	  else
	    r = smtp_sync(SS, r, 1); /* non-blocking */
	} else {
	  r = EX_TEMPFAIL;
	  notaryreport(NULL,NULL,
		       "5.4.2 (BDAT message write failed)",
		       "smtp; 566 (BDAT message write failed)");
	}

	return r;
}


#ifdef	HAVE_SELECT

int select_sleep(fd,tout)
int fd, tout;
{
	struct timeval tv;
	int rc;
	fd_set rdmask;
	fd_set wrmask;

	tv.tv_sec = tout;
	tv.tv_usec = 0;
	_Z_FD_ZERO(rdmask);
	_Z_FD_ZERO(wrmask);
	if (fd > 0)
	  _Z_FD_SET(fd,rdmask);
	else {
	  _Z_FD_SET(fd,wrmask);
	  fd = -fd;
	}

	rc = select(fd+1,&rdmask,&wrmask,NULL,&tv);
	if (rc == 0) /* Timeout w/o input */
	  return -1;
	if (rc == 1) /* There is something to read (or write)! */
	  return 0;
	return 1;    /* interrupt, or some such.. */
}

int has_readable(fd)
int fd;
{
	struct timeval tv;
	int rc;
	fd_set rdmask;

	tv.tv_sec = 0;
	tv.tv_usec = 0;
	_Z_FD_ZERO(rdmask);
	_Z_FD_SET(fd,rdmask);

	rc = select(fd+1,&rdmask,NULL,NULL,&tv);
	if (rc > 0) /* There is something to read! */
	  return 1;
	return 0;    /* interrupt or timeout, or some such.. */
}
#else /* not HAVE_SELECT */
int select_sleep(fd, tout)
int fd, tout;
{
	return -1;
}

int has_readable(fd)
int fd;
{
	return 1;
}
#endif

static int code_to_status(code,statusp)
int code;
char **statusp;
{
	int rc;
	char *status;

	switch (code) {
	case 211: /* System status, or system help reply */
	case 214: /* Help message */
	case 220: /* <domain> Service ready */
	case 221: /* <domain> Service closing transmission channel */
	case 250: /* Requested mail action okay, completed */
	case 251: /* User not local; will forward to <forward-path> */
        case 255: /* Something the PMDF 4.1 returns.. for EHLO */
	case 354: /* Start mail input; end with <CRLF>.<CRLF> */
		status = "2.0.0";
		rc = EX_OK;
		break;
	case 421: /* <domain> Service not available, closing transmission channel */
	case 450: /* Requested mail action not taken: mailbox unavailable */
	case 451: /* Requested action aborted: local error in processing */
	case 452: /* Requested action not taken: insufficient system storage */
		status = "4.0.0";
		rc = EX_TEMPFAIL;
		break;
	case 455: /* ESMTP parameter failure */
		status = "5.5.4";
		rc = EX_USAGE;
		break;
	case 501: /* Syntax error in parameters or arguments */
		status = "5.5.2";
		rc = EX_USAGE;
		break;
	case 500: /* Syntax error, command unrecognized */
	case 502: /* Command not implemented */
		status = "5.5.1";
		rc = EX_PROTOCOL;
		break;
	case 503: /* Bad sequence of commands */
		status = "5.5.0";
		rc = EX_TEMPFAIL;
		break;
	case 504: /* Command parameter not implemented */
		status = "5.5.4";
		rc = EX_PROTOCOL;
		break;
	case 550: /* Requested action not taken: mailbox unavailable */
		status = "5.1.1 (bad destination mailbox)";
		rc = EX_NOUSER;
		break;
	case 551: /* User not local; please try <forward-path> */
		status = "5.1.6 (mailbox has moved)";
		rc = EX_NOUSER;
		break;
	case 552: /* Requested mail action aborted: exceeded storage allocation */
		status = "5.2.3 (message length exceeds administrative limit)";
		rc = EX_UNAVAILABLE;
		break;
	case 553: /* Requested action not taken: mailbox name not allowed */
		status = "5.1.3 (bad destination mailbox address [syntax])";
		rc = EX_NOUSER;
		break;
	case 554:
		status = "5.1.1 (No acceptable recipients given)";
		rc = EX_NOUSER;
		break;
	case 555: /* Unknown MAIL From:<>/RCPT To:<> parameter */
		status = "5.5.4 (invalid parameters)";
		rc = EX_USAGE;
		break;
	case 571:
		status = "5.7.1 (Delivery not authorized, message refused)";
		rc = EX_NOUSER;
		break;
	default:
		switch (code/100) {
		case 2:
		case 3:
			status = "2.0.0 (generic ok)";
			rc = EX_OK;
			break;
		case 4:
			status = "4.0.0 (generic temporary failure)";
			rc = EX_TEMPFAIL;
			break;
		case 5:
			status = "5.0.0 (generic permanent failure)";
			rc = EX_UNAVAILABLE;
			break;
		default:
			status = "5.5.0 (generic protocol failure)";
			rc = EX_TEMPFAIL;
			break;
		}
		break;
	}
	*statusp = status;
	return rc;
}


int
smtp_sync(SS, r, nonblocking)
	SmtpState *SS;
	int r, nonblocking;
{
	char *s, *eof, *eol;
	volatile int idx  = 0, code = 0;
	volatile int rc   = EX_OK, len;
	volatile int err  = 0;
	int          infd;
	char buf[512];
	char *p;
	char *status = NULL;
	int statesave;

	SS->smtp_outcount = 0;
	SS->block_written = 0;

	eol = SS->pipebuf;

	if (SS->pipereplies == 0) {
	  SS->continuation_line = 0;
	  SS->first_line = 1;
	}

	for (idx = SS->pipereplies; idx < SS->pipeindex; ++idx) {
      rescan_line_0: /* processed some continuation line */
	  s = eol;
      rescan_line:   /* Got additional input */

	  if (!nonblocking && SS->smtpfp && sffileno(SS->smtpfp) >= 0)
	    sfsync(SS->smtpfp);			/* Flush output */

	  eof = SS->pipebuf + SS->pipebufsize;
	  for (eol = s; eol < eof; ++eol)
	    if (*eol == '\n') break;
	  if (eol < eof && *eol == '\n') {
	    ++eol; /* points to char AFTER the newline */
	    if (debug && logfp)
	      fprintf(logfp,"%s#\t(pipebufsize=%d, s=%d, eol=%d)\n",
		      logtag(), SS->pipebufsize,(int)(s-SS->pipebuf),
		      (int)(eol-SS->pipebuf));
	  } else { /* No newline.. Read more.. */
	    int en;
	    if (nonblocking) {
	      err = 0;
	    } else {
	      infd = SS->smtpfd;
#ifdef HAVE_OPENSSL
	      if (SS->sslmode) {
		err = 0;
		len = smtp_nbread(SS, buf, sizeof(buf));
		if (SS->wantreadwrite > 0)
		  infd = -infd;
		if (len < 0)
		  err = errno;
		else
		  goto have_some_data;
	      }
#endif /* - HAVE_OPENSSL */
	      err = select_sleep(infd, timeout);
	      en = errno;
	      if (debug && logfp)
		fprintf(logfp,"%s#\tselect_sleep(%d,%d); rc=%d\n",
			logtag(),infd,timeout,err);
	      if (err < 0) {
		if (logfp)
		  fprintf(logfp,"%s#\tTimeout (%d sec) while waiting responses from remote (errno=%d)\n",logtag(),timeout,en);
		if (SS->verboselog)
		  fprintf(SS->verboselog,"Timeout (%d sec) while waiting responses from remote\n",timeout);
		break;
	      }
	    }
	    
	  reread_line:

	    err = 0;
	    len = smtp_nbread(SS, buf, sizeof(buf));
	    if (len < 0)
	      err = errno;
	    
	  have_some_data:

	    if (len < 0) {
	      /* Some error ?? How come ?
		 We have select() confirmed input! */
	      if (nonblocking) {
		if (err == EINTR || err == EAGAIN
#ifdef EWOULDBLOCK
		    || err == EWOULDBLOCK
#endif
		    ) {
		  err = 0;
		  break; /* XX: return ?? */
		}
	      } else {
		if (err == EINTR || err == EAGAIN
#ifdef EWOULDBLOCK
		    || err == EWOULDBLOCK
#endif
		    ) {
		  err = 0;
		  goto reread_line;
		}
	      }
	      /* XX: what to do with the error ? */
	      if (logfp)
		fprintf(logfp,"%s#\tRemote gave error %d (%s) while %d responses missing\n",
			logtag(), err, strerror(err), SS->pipeindex - 1 - idx);
	      if (SS->verboselog)
		fprintf(SS->verboselog,"Remote gave error %d (%s) while %d responses missing\n",
			err, strerror(err), SS->pipeindex - 1 - idx);
	      break;
	    } else if (len == 0) {
	      /* The remote hung up! */
	      if (logfp)
		fprintf(logfp,"%s#\tRemote hung up on us while %d responses missing\n",
			logtag(), SS->pipeindex - idx);
	      if (SS->verboselog)
		fprintf(SS->verboselog,"Remote hung up on us while %d responses missing\n",
			SS->pipeindex - idx);
	      err = EX_TEMPFAIL;
	      break;
	    } else {
	      /* more data for processing.. munch munch.. */
	      if (s > SS->pipebuf) {
		/* Compress the buffer at first */
		memcpy(SS->pipebuf, s, SS->pipebufsize - (s - SS->pipebuf));
		SS->pipebufsize -= (s - SS->pipebuf);
		s   = SS->pipebuf;
		eol = SS->pipebuf;
	      }
	      eof = SS->pipebuf;
	      if ((SS->pipebufsize+len+1) > SS->pipebufspace) {
		while ((SS->pipebufsize+len+2) > SS->pipebufspace)
		  SS->pipebufspace <<= 1; /* Double the size */
		SS->pipebuf = (void*)realloc(SS->pipebuf,SS->pipebufspace);
		if (! SS->pipebuf) zmalloc_failure = 1;
	      }
	      if (SS->pipebuf != eof) {
		/* Block changed.. Reset those pointers */
		long offsetchange = SS->pipebuf - eof;
		eol += offsetchange;
		s   += offsetchange;
	      }
	      memcpy(SS->pipebuf + SS->pipebufsize, buf, len);
	      SS->pipebufsize += len;
	      goto rescan_line;
	    }
	  } /* -- endif -- ... globbing more input */

	  p = eol-1;		  /* The '\n' at the end of the line	*/
	  if (p > s && p[-1] == '\r') --p; /* "\r\n" ?			*/
	  *p = 0;

	  if (logfp != NULL) {
	    if (debug)
	      putc('\n',logfp);
	    fprintf(logfp, "%sr\t%s\n", logtag(), s);
	  }
	  if (SS->verboselog)
	    fprintf(SS->verboselog,"%s\n",s);

	  if (s[0] >= '0' && s[0] <= '9' &&
	      s[1] >= '0' && s[1] <= '9' &&
	      s[2] >= '0' && s[2] <= '9' &&
	      (s[3] == ' ' || s[3] == 0)) {
	    code = atoi(s);

	    /* We have a 'terminal' line */

	    SS->continuation_line = 0;
	  } else { /* it is 'continuation line', or some such, ignore */
	    SS->continuation_line = 1;
	  }

	  statesave = SS->cmdstate;

	  SS->cmdstate = SS->pipestates[idx];

	  if (SS->first_line)
	    rmsgappend(SS, 0, "\r<<- %s",
		       SS->pipecmds[idx] ? SS->pipecmds[idx] : "(null)");

	  /* first_line is not exactly complement of continuation_line,
	     it is rather a more complex entity. */

	  SS->first_line = !SS->continuation_line;

	  rmsgappend(SS, 1, "\r->> %s", s);

	  SS->cmdstate = statesave;


	  if (SS->continuation_line)
	    goto rescan_line_0;
	  else
	    SS->pipereplies = idx +1; /* Final line, mark this as processed! */
   

	  /* If write-fd has closed(shut down), we shall turn all
	     500-series hard errors into soft ones, as we must try
	     re-sending the message sometime. */

	  if ((SS->smtpfp == NULL || sffileno(SS->smtpfp) < 0) && code >= 500)
	    code -= 100; /* SOFTEN IT! */

	  rc = code_to_status(code, &status);
	  if (code >= 400) {
	    /* Errors */

	    /* MAIL From:<*>: ... */
	    /* DATA: 354/ 451/554/ 500/501/503/421 */
	    /* RCPT To:<*>: 250/251/ 550/551/552/553/450/451/452/455/ 500/501/503/421 */
	    if (SS->pipercpts[idx] != NULL) {
	      if (SS->rcptstates & (FROMSTATE_400|FROMSTATE_500)) {
		/* If "MAIL From:<..>" tells non-200 report, and
		   causes "RCPT To:<..>" commands to yield "400/500",
		   we IGNORE the "500" status. */
		SS->rcptstates |= RCPTSTATE_400;
		rc = EX_TEMPFAIL;
	      } else {
		if (code >= 500)
		  SS->rcptstates |= RCPTSTATE_500;
		else
		  SS->rcptstates |= RCPTSTATE_400;
		/* ``rc'' is correct. */
	      }

	      /* Diagnose the errors, we report successes AFTER the DATA phase.. */
	      time(&endtime);
	      notary_setxdelay((int)(endtime-starttime));
	      notarystatsave(SS,s,status);
	      notaryreport(SS->pipercpts[idx]->addr->user,FAILED,NULL,NULL);

	      diagnostic(SS->pipercpts[idx], rc, 0, "%s", SS->remotemsg);

	    } else {

	      /* No diagnostic()s for  MAIL FROM:<> nor for DATA/BDAT phases */

	      if (idx == 0 && SS->pipecmds[idx] != NULL &&
		  strncmp(SS->pipecmds[idx],"MAIL", 4) == 0) {
		/* We are working on MAIL From:<...> command here */
		if (code >= 500)
		  SS->rcptstates |= FROMSTATE_500;
		else if (code >= 400)
		  SS->rcptstates |= FROMSTATE_400;
		else
		  SS->rcptstates |= FROMSTATE_OK;
	      } else {
		/* "DATA" or "BDAT" phase */
		if (code >= 500) {
		  if (SS->rcptstates & (FROMSTATE_400|FROMSTATE_500)) {
		    /* The FROM failed already, make us 'soft' */
		    SS->rcptstates |= DATASTATE_400;
		  } else if (SS->rcptstates & RCPTSTATE_OK) {
		    /* At least one OK result for RCPTs,
		       It means we are REALLY hard error! */
		    SS->rcptstates |= DATASTATE_500;
		  } else if (SS->rcptstates & RCPTSTATE_400) {
		    /* TMPFAIL RCPTs, make us 'soft' error! */
		    SS->rcptstates |= DATASTATE_400;
		  } else {
		    /* All others are HARD errors! */
		    SS->rcptstates |= DATASTATE_500;
		  }
		} else if (code >= 400) {
		  SS->rcptstates |= DATASTATE_400;
		}
	      }
	    }
	  } else {
	    /* Ok results */
	    if (SS->pipercpts[idx] != NULL) {
	      if (SS->rcptstates & (FROMSTATE_400|FROMSTATE_500)) {
		/* MAIL FROM gave error, we won't believe OK on
		   recipients either. */
		SS->rcptstates |= RCPTSTATE_400;
		/* Actually we SHOULD NOT arrive here, but we never know,
		   what kind of smtp-servers are out there... */
	      } else {
		/* MAIL FROM was apparently ok. */
		SS->rcptstates |= RCPTSTATE_OK;
		SS->pipercpts[idx]->status = EX_OK;
if (SS->verboselog) fprintf(SS->verboselog,"[Some OK - code=%d, idx=%d, pipeindex=%d]\n",code,idx,SS->pipeindex-1);
	      }
	    } else {
	      if (idx > 0)
		SS->rcptstates |= DATASTATE_OK;
	      /* Should we do same as we do above ?  Don't believe in OK
		 in case MAIL FROM failed ? */
	    }
	  }
	  if (! nonblocking) {
	    if (SS->pipecmds[idx] != NULL)
	      free(SS->pipecmds[idx]);
	    else
	      if (logfp) fprintf(logfp,"%s#\t[Freeing free object at pipecmds[%d] ??]\n",logtag(),idx);
	    SS->pipecmds[idx] = NULL;
	  }

	  /* Now compress away that processed dataset */
	  if (eol > SS->pipebuf) {
	    int sz = eol - SS->pipebuf;
	    SS->pipebufsize -= sz;
	    if (SS->pipebufsize > 0)
	      memcpy(SS->pipebuf, eol, SS->pipebufsize);
	    s -= sz;
	    eol = SS->pipebuf;
	  }

	} /* for(..; idx < SS->pipeindex ; ..) */

	if (! nonblocking) {
	  for (idx = 0; idx < SS->pipeindex; ++idx) {
	    if (SS->pipecmds[idx] != NULL)
	      free(SS->pipecmds[idx]);
	    SS->pipecmds[idx] = NULL;
	  }
	}

	rc = EX_OK;
	if (err != 0)
	  rc = EX_TEMPFAIL; /* Some timeout happened at the response read */
	if (rc == EX_OK && (SS->rcptstates & FROMSTATE_400))
	  rc = EX_TEMPFAIL; /* MAIL FROM was a 4** code */
	if (rc == EX_OK && (SS->rcptstates & FROMSTATE_500))
	  rc = EX_UNAVAILABLE; /* MAIL FROM was a 5** code */
	if (rc == EX_OK) {
	  /* Study the RCPT STATES! */
	  if (SS->rcptstates & RCPTSTATE_OK) {
	    rc = EX_OK; /* SOME OK */
	  } else if (SS->rcptstates & RCPTSTATE_400) {
	    /* Some TEMPFAIL */
	    rc = EX_TEMPFAIL;
	  } else if (SS->rcptstates & RCPTSTATE_400) {
	    /* only full failures :-( */
	    rc = EX_UNAVAILABLE;
	  }
	}
	if (rc == EX_OK) {
	  /* Study the DATA STATES! */
	  if (SS->rcptstates & DATASTATE_400)
	    rc = EX_TEMPFAIL;
	  if (SS->rcptstates & DATASTATE_500)
	    rc = EX_UNAVAILABLE;
	}

	if (rc != EX_OK && logfp)
	    fprintf(logfp,"%s#\t smtp_sync() did yield code %d\n", logtag(), rc);
	if (SS->verboselog)
	  fprintf(SS->verboselog," smtp_sync() did yield code %d (rcptstates = 0x%x)\n", rc, SS->rcptstates);

	return rc;
}

/* */
void
pipeblockread(SS)
SmtpState *SS;
{
	int infd = SS->smtpfd;
	char buf[512];

	/* BLOCKALARM; */
	if (SS->block_written && has_readable(infd)) {
	  /* Read and buffer all so far accumulated responses.. */
	  for (;;) {
	    /* Do non-blocking */
	    int r = smtp_nbread(SS, buf, sizeof buf);
	    if (r <= 0) break; /* Nothing to read ? EOF ?! */
	    if (SS->pipebuf == NULL) {
	      SS->pipebufspace = 240;
	      SS->pipebufsize  = 0;
	    }
	    while (SS->pipebufspace < (SS->pipebufsize+r+2))
	      SS->pipebufspace <<= 1;

	    if (SS->pipebuf == NULL)
	      SS->pipebuf = malloc(SS->pipebufspace);
	    else
	      SS->pipebuf = realloc(SS->pipebuf,SS->pipebufspace);
	    if (! SS->pipebuf) zmalloc_failure = 1;

	    if (SS->pipebuf)
	      memcpy(SS->pipebuf+SS->pipebufsize,buf,r);
	    SS->pipebufsize += r;
	    SS->block_written = 0; /* We drain the accumulated input here,
				      and can thus mark this draining
				      unneeded for a while. */
	  }
	  /* Continue the processing... */
	}
	if (SS->pipebufsize != 0)
	  smtp_sync(SS, EX_OK, 1); /* NON-BLOCKING! */
	/* ENABLEALARM; */
}


int dflag = 0;

int
smtpwrite(SS, saverpt, strbuf, pipelining, syncrp)
	SmtpState *SS;
	int saverpt;
	const char *strbuf;
	int pipelining;
	struct rcpt *syncrp;
{
	register char *s;
	volatile char *cp;
	int response, infd, rc;
	volatile int r = 0, i;
	char *se;
	char *status = NULL;
	char buf[2*8192]; /* XX: static buffer - used in several places */
	char ch;

	gotalarm = 0; /* smtp_sfwrite() may set it.. */

	infd = SS->smtpfd;

	if (pipelining > 0) {
	  if (SS->pipespace <= SS->pipeindex) {
	    SS->pipespace += 8;
	    if (SS->pipecmds == NULL) {
	      SS->pipecmds  = (char**)malloc(SS->pipespace * sizeof(char*));
	      SS->pipercpts = (struct rcpt **)malloc(SS->pipespace *
						     sizeof(struct rcpt*));
	      SS->pipestates = (int*)malloc(SS->pipespace * sizeof(int));
	    } else {
	      SS->pipecmds  = (char**)realloc((void**)SS->pipecmds,
					      SS->pipespace * sizeof(char*));
	      SS->pipercpts = (struct rcpt **)realloc((void**)SS->pipercpts,
						      SS->pipespace *
						      sizeof(struct rcpt*));
	      SS->pipestates  = (int*)realloc((void*)SS->pipestates,
					      SS->pipespace * sizeof(int));
	    }
	  }
	  SS->pipecmds  [SS->pipeindex] = strdup(strbuf);
	  SS->pipercpts [SS->pipeindex] = syncrp; /* RCPT or NULL */
	  SS->pipestates[SS->pipeindex] = SS->cmdstate;
	  SS->pipeindex += 1;

	} /* ... end of if(pipelining) */

	if (strbuf != NULL) {
	  int len = strlen(strbuf) + 2;
	  volatile int err = 0;

	  if (pipelining > 0) {
	    /* We are asynchronous! */
	    SS->smtp_outcount += len; /* Where will we grow to ? */

	    /* Read possible responses into response buffer.. */
	    pipeblockread(SS);

	    memcpy(buf,strbuf,len-2);
	    memcpy(buf+len-2,"\r\n",2);

	    if (SS->verboselog)
	      fwrite(buf, 1, len, SS->verboselog);

	    if (!sferror(SS->smtpfp))
	      r = sfwrite(SS->smtpfp, buf, len);
	    else
	      r = -1;
	    err = (r != len) || sferror(SS->smtpfp);

	    if (SS->smtp_outcount > SS->smtp_bufsize) {
	      SS->smtp_outcount -= SS->smtp_bufsize;
	      SS->block_written = 1;
	    }

	  } else {

	    /* We act synchronously */

	    memcpy(buf,strbuf,len-2);
	    memcpy(buf+len-2,"\r\n",2);

	    if (SS->verboselog)
	      fwrite(buf, 1, len, SS->verboselog);

	    if (!sferror(SS->smtpfp))
	      r = sfwrite(SS->smtpfp, buf, len);
	    else
	      r = -1;
	    err = (r != len);
	    if (sferror(SS->smtpfp) || sfsync(SS->smtpfp))
	      err = 1;
	  }

	  if (err) {
	    if (gotalarm) {
	      strcpy(SS->remotemsg, "Timeout on cmd write");
	      time(&endtime);
	      notary_setxdelay((int)(endtime-starttime));
	      notaryreport(NULL,FAILED,"5.4.2 (timeout on cmd write)",
			   "smtp; 500 (timeout on cmd write)");
	    } else {
	      se = strerror(errno);
	      sprintf(SS->remotemsg, "smtp; 500 (write to server error: %s)", se);
	      time(&endtime);
	      notary_setxdelay((int)(endtime-starttime));
	      notaryreport(NULL,FAILED,"5.4.2 (write to server, err)",SS->remotemsg);
	    }
	    if (SS->verboselog)
	      fprintf(SS->verboselog,"%s\n",SS->remotemsg);
#if 0
	    smtpclose(SS, 1);
	    if (logfp)
	      fprintf(logfp, "%s#\t(closed SMTP channel - timeout on smtpwrite())\n", logtag());
	    /* Alarm OFF */
	    return EX_TEMPFAIL;
#endif
	  } else if (r != len) {
	    sprintf(SS->remotemsg, "smtp; 500 (SMTP cmd write failure: Only wrote %d of %d bytes!)", r, len);
	    time(&endtime);
	    notary_setxdelay((int)(endtime-starttime));
	    notaryreport(NULL,FAILED,"5.4.2 (SMTP cmd partial write failure)",SS->remotemsg);
	    if (SS->verboselog)
	      fprintf(SS->verboselog,"%s\n",SS->remotemsg);
#if 0
	    smtpclose(SS, 1);
	    if (logfp)
	      fprintf(logfp, "%s#\t(closed SMTP channel - second timeout on smtpwrite() )\n", logtag());
	    /* Alarm OFF */
	    return EX_TEMPFAIL;
#endif
	  }
	  if (logfp != NULL) {
	    if (dflag) abort();
	    fprintf(logfp, "%sw\t%s\n", logtag(), strbuf);
	    if (!pipelining)
	      dflag = 1;
	  }
	}

	if (SS->smtpfp && sffileno(SS->smtpfp) >= 0) {
	  if (strbuf) {
	    rmsgappend(SS, 0, "\r<<- %s", strbuf);
	  } else {
	    SS->remotemsg[0] = 0;
	    rmsgappend(SS, 0, "\r<<- (null)");
	  }
	} else {
	  /* socket closed outwards, commands not written! */
	  if (strbuf)
	    rmsgappend(SS, 0, "\rWrite Failure; shunted cmd: %s", strbuf);
	  else
	    strcpy(SS->remotemsg,
		   "\rWrite Failure; expecting initial greeting??");
	}

	if (debug) {
	  fprintf(logfp, "%s#\tAttempting to read reply\n",logtag());
	}

	if (statusreport && strbuf != NULL) {
	  report(SS,"%s", strbuf);
	}

	if (pipelining != 0) {
	  /* With "QUIT" this is negative value, and we are not
	     in reality interested of the return value... */

	  /* Read possible reponses into response buffer.. */
	  pipeblockread(SS);

	  return EX_OK;
	}

	i = 2;	/* state variable, beginning of new line */
	cp = buf;

	do {

	  fd_set rdset;
	  struct timeval tv;

	do_reread:

	  tv.tv_sec = timeout;
	  tv.tv_usec = 0;

	  if (sffileno(SS->smtpfp) < 0  &&  timeout > 300) {
	    /* Earlier write failure has bitten us, and we
	       arrived into DOT-WAIT, or some such.. */
	    /* Cut this wait down to 5 minutes */
	    tv.tv_sec = 300;
	  }

	  _Z_FD_ZERO(rdset);
	  _Z_FD_SET(infd,rdset);

	  gotalarm = 0;

	  r = select(infd+1, &rdset, NULL, NULL, &tv);
	  if (r < 0 && errno == EINTR) goto do_reread;
	  if (r > 0) {
	    r = smtp_nbread(SS, (char*)cp, sizeof(buf) - (cp - buf));
	    if (r < 0 && errno == EINTR) goto do_reread;
	  } else { /* == 0 */
	    if (r == 0)
	      gotalarm = 1;
	    r = -1;
	  }
	  if (r > 0) {
	    if (SS->verboselog)
	      fwrite((char*)cp,r,1,SS->verboselog);
	    s = (char*)cp;
	    cp += r;
	    for ( ; s < cp; ++s ) {
	      switch (i) {
	      	/* i == 0 means we're on last line */
	      case 1:		/* looking for \n */
		if (*s != '\n')
		  break;
		*s = '\0';

		rmsgappend(SS, 1, "\r->> %s", buf);

		if (SS->within_ehlo)
		  ehlo_check(SS,&buf[4]);
		if (!strbuf && !SS->esmtp_on_banner)
		  esmtp_banner_check(SS,&buf[4]);
		if (logfp != NULL) {
		  if (debug)
		    putc('\n',logfp);
		  fprintf(logfp, "%sr\t%s\n", logtag(), buf);
		}

		if (s + 1 < cp)	/* Compress the buffer */
		  memcpy(buf, s+1, cp-s-1);
		cp = buf + (cp-s-1);
		s = buf;
		--s;		/* incremented in for() stmt */
		/* fall through */
	      case 2:		/* saw \n, 1st char on line */
	      case 3:		/* 2nd char on line */
	      case 4:		/* 3rd char on line */
		if ((i == 1) || ('0' <= *s && *s <= '9'))
		  ++i;
		else
		  /* silently look for num. code lines */
		  i = 1;
		break;
	      case 5:		/* 4th char on line */
		i = (*s == '-');
		break;
	      }
	    }
	  } else if (r == -1) {
	    if (gotalarm) {
	      time(&endtime);
	      notary_setxdelay((int)(endtime-starttime));
	      if (SS->smtpfp && sffileno(SS->smtpfp) < 0) {
		sprintf(SS->remotemsg,
			"smtp; 466 (Timeout on SMTP write, and response read)");
		notaryreport(NULL,FAILED,
			     "5.4.2 (smtp transaction write+read timeout)",
			     SS->remotemsg);
	      } else {
		if (strbuf == NULL)
		  sprintf(SS->remotemsg,
			  "smtp; 466 (Timeout on initial SMTP response read)");
		else
		  sprintf(SS->remotemsg,
			  "smtp; 466 (Timeout on SMTP response read, Cmd: %s)",
			  strbuf);
		notaryreport(NULL,FAILED,
			     "5.4.2 (smtp transaction read timeout)",
			     SS->remotemsg);
	      }
	    } else {
	      se = strerror(errno);
	      if (strbuf == NULL)
		sprintf(SS->remotemsg,
			"smtp; 500 (Error on initial SMTP response read: %s)",se);

	      else
		sprintf(SS->remotemsg,
			"smtp; 500 (Error on SMTP response read: %s, Cmd: %s)",
			se, strbuf);
	      time(&endtime);
	      notary_setxdelay((int)(endtime-starttime));
	      notaryreport(NULL,FAILED,"5.4.2 (smtp transaction read timeout)",SS->remotemsg);
	    }

	    dflag = 0;
	    if (SS->verboselog)
	      fprintf(SS->verboselog,"%s\n",SS->remotemsg);
	    smtpclose(SS, 1);
	    if (logfp)
	      fprintf(logfp, "%s#\t(closed SMTP channel - bad response on smtpwrite() )\n", logtag());
	    return EX_TEMPFAIL;
	  } else {
	    /* read() returned 0 .. usually meaning EOF .. */
	    sprintf(SS->remotemsg, "smtp; 500 (Server hung up on us! Cmd: %s)",
		    strbuf == NULL ? "(null cmd)" : strbuf);
	    time(&endtime);
	    notary_setxdelay((int)(endtime-starttime));
	    notaryreport(NULL,FAILED,"5.4.2 (server hung-up on us)",SS->remotemsg);
	    dflag = 0;
	    if (SS->verboselog)
	      fprintf(SS->verboselog,"%s\n",SS->remotemsg);
	    smtpclose(SS, 1);
	    if (logfp)
	      fprintf(logfp, "%s#\t(closed SMTP channel - hangup on smtpwrite() )\n", logtag());
	    return EX_TEMPFAIL;
	  }
	  /* Exit if the last thing we read was a LF and we're on the
	     last line (in case of multiline response).  This
	     also takes care of the required CRLF termination */
	} while (cp < buf+sizeof buf && !(i == 0 && *(cp-1) == '\n'));

	if (cp >= (buf+sizeof buf)) {
	  strcpy(SS->remotemsg,"smtp; 500 (SMTP Response overran input buffer!)");
	  time(&endtime);
	  notary_setxdelay((int)(endtime-starttime));
	  notaryreport(NULL,"X-BUG","5.5.0 (SMTP-response overran input buffer!)",SS->remotemsg);
	  dflag = 0;
	  if (SS->verboselog)
	    fprintf(SS->verboselog,"%s\n",SS->remotemsg);
	  smtpclose(SS, 1);
	  if (logfp)
	    fprintf(logfp, "%s#\t(closed SMTP channel - response overrun on smtpwrite() )\n", logtag());
	  return EX_TEMPFAIL;
	}
	*--cp = '\0';	/* kill the LF */
	if ((cp - buf) < 3) {
	  /* A '354<CRLR>' could be treated as ok... */
	  sprintf(SS->remotemsg, "smtp; 500 (SMTP response '%s' unexpected!)", buf);
	  time(&endtime);
	  notary_setxdelay((int)(endtime-starttime));
	  notaryreport(NULL,"X-BUG","5.5.0 (SMTP response unexpected)",SS->remotemsg);
	  dflag = 0;
	  if (SS->verboselog)
	    fprintf(SS->verboselog,"%s\n",SS->remotemsg);
	  smtpclose(SS, 1);
	  if (logfp)
	    fprintf(logfp, "%s#\t(closed SMTP channel - unexpected response on smtpwrite() )\n", logtag());
	  return EX_TEMPFAIL;
	}
	--cp;
	/* trim trailing whitespace */
	while (isascii((*cp)&0xFF) && isspace((*cp)&0xFF))
	  --cp;
	*++cp = '\0';
	for (i = 0; i < 4; ++i)		/* can't happen, right? wrong... */
	  if (buf[i] == ' ' || buf[i] == '\r' || buf[i] == '\n')
	    break;
	if (i == 4) --i;
	ch = buf[i];
	buf[i] = '\0';
	response = atoi(buf);
	if (logfp != NULL)
	  fprintf(logfp, "%sr\t%s%c%s\n", logtag(), buf, ch, &buf[i+1]);
	buf[i] = ch;

	if (SS->within_ehlo)
	  ehlo_check(SS,&buf[4]);
	if (!strbuf && !SS->esmtp_on_banner)
	  esmtp_banner_check(SS,&buf[4]);

	rmsgappend(SS, 1, "\r->> %s", buf);

	dflag = 0;

	if (response >= 400)
	  notaryreport(NULL,FAILED,NULL,NULL);

	rc = code_to_status(response, &status);

	if (saverpt)
	  notarystatsave(SS,buf,status);
	return rc;
}


int
smtp_ehlo(SS, strbuf)
	SmtpState *SS;
	const char *strbuf;
{
	int rc;
	SS->within_ehlo = 1;
	SS->ehlo_capabilities = 0;
	rc = smtpwrite(SS, 1, strbuf, 0, NULL);
	SS->within_ehlo = 0;
	return rc;
}

/*
 * In theory, this should modify the command that ps shows for this process.
 * This is known not to be portable, hopefully it will break badly on systems
 * where it doesn't work.
 */

#ifdef HAVE_STDARG_H
#ifdef __STDC__
void report(SmtpState *SS, char *fmt, ...)
#else /* Not ANSI-C */
void report(SS, fmt)
	SmtpState *SS;
	char *fmt;
#endif
#else
/* VARARGS */
void
report(va_alist)
	va_dcl
#endif
{
	va_list	ap;
	char buf[8192];
	int cmdlen;

#ifdef HAVE_STDARG_H
	va_start(ap,fmt);
#else
	SmtpState *SS;
	char *fmt;
	va_start(ap);
	SS  = va_arg(ap, SmtpState *);
	fmt = va_arg(ap, char *);
#endif
	if (SS->smtpfp && sffileno(SS->smtpfp) >= 0)
	  sprintf(buf, ">%.200s ", SS->remotehost);
	else
	  sprintf(buf, ">[%.200s] ", SS->remotehost);
#ifdef	notdef
	if (logfp)
	  sprintf(buf+strlen(buf), ">>%s ", logfile);
	strcat(buf, "# ");
#endif
#ifdef	HAVE_VPRINTF
	vsprintf(buf+strlen(buf), fmt, ap);
#else	/* !HAVE_VPRINTF */
	sprintf(buf+strlen(buf), fmt, va_arg(ap, char *));
#endif	/* HAVE_VPRINTF */
	cmdlen = (eocmdline - cmdline);
	if (cmdlen >= sizeof(buf))
	  cmdlen = sizeof(buf) - 1;
	for (fmt = buf+strlen(buf); fmt < buf + cmdlen; ++fmt)
	  *fmt = '\0';
	buf[cmdlen] = '\0';
	memcpy((char*)cmdline, buf, cmdlen); /* Overwrite it! */
	va_end(ap);
}

#ifdef	BIND

typedef union {
	HEADER qb1;
	char qb2[PACKETSZ];
} querybuf;

int
getmxrr(SS, host, mx, maxmx, depth)
	SmtpState *SS;
	const char *host;
	struct mxdata mx[];
	int maxmx, depth;
{
	HEADER *hp;
	msgdata *eom, *cp;
	querybuf qbuf, answer;
	struct mxdata mxtemp;
	msgdata buf[8192], realname[8192];
	int qlen, n, i, j, nmx, ancount, qdcount, maxpref;
	u_short type;
	int saw_cname = 0;
	int ttl;
	int had_eai_again = 0;
	struct addrinfo req, *ai;

	h_errno = 0;

	notary_setwtt  (NULL);
	notary_setwttip(NULL);

	if (depth > 3) {
	  sprintf(SS->remotemsg,"smtp; 500 (DNS: Recursive CNAME on '%.200s')",host);
	  time(&endtime);
	  notary_setxdelay((int)(endtime-starttime));
	  notaryreport(NULL,FAILED,"5.4.3 (Recursive DNS CNAME)",SS->remotemsg);
	  fprintf(stderr, "%s\n", SS->remotemsg);
	  return EX_NOHOST;
	}


	qlen = res_mkquery(QUERY, host, C_IN, T_MX, NULL, 0, NULL,
			   (void*)&qbuf, sizeof qbuf);
	if (qlen < 0) {
	  fprintf(stderr, "res_mkquery failed\n");
	  sprintf(SS->remotemsg,
		  "smtp; 466 (Internal: res_mkquery failed on host: %.200s)",host);
	  if (SS->verboselog)
	    fprintf(SS->verboselog,"  %s\n", SS->remotemsg);

	  time(&endtime);
	  notary_setxdelay((int)(endtime-starttime));
	  notaryreport(NULL,FAILED,"5.4.3 (DNS-failure)",SS->remotemsg);
	  return EX_SOFTWARE;
	}
	n = res_send((void*)&qbuf, qlen, (void*)&answer, sizeof answer);
	if (n < 0) {
	  sprintf(SS->remotemsg,
		  "smtp; 466 (No DNS response for host: %.200s; h_errno=%d)",
		  host, h_errno);
	  if (SS->verboselog)
	    fprintf(SS->verboselog,"  %s\n", SS->remotemsg);

	  time(&endtime);
	  notary_setxdelay((int)(endtime-starttime));
	  notaryreport(NULL,FAILED,"5.4.3 (DNS-failure)",SS->remotemsg);
	  return EX_TEMPFAIL;
	}

	time(&now);

	eom = (msgdata *)&answer + n;
	/*
	 * find first satisfactory answer
	 */
	hp = (HEADER *) &answer;
	ancount = ntohs(hp->ancount);
	qdcount = ntohs(hp->qdcount);
	if (hp->rcode != NOERROR || ancount == 0) {
	  switch (hp->rcode) {
	  case NXDOMAIN:
	    /* Non-authoritative iff response from cache.
	     * Old BINDs used to return non-auth NXDOMAINs
	     * due to a bug; if that is the case by you,
	     * change to return EX_TEMPFAIL iff hp->aa == 0.
	     */
	    sprintf(SS->remotemsg, "smtp; 500 (DNS: no such domain: %.200s)", host);
	    endtime = now;
	    notary_setxdelay((int)(endtime-starttime));
	    notaryreport(NULL,FAILED,"5.4.4 (DNS lookup report)",SS->remotemsg);
	    return EX_NOHOST;
	  case SERVFAIL:
	    sprintf(SS->remotemsg, "smtp; 500 (DNS: server failure: %.200s)", host);
	    endtime = now;
	    notary_setxdelay((int)(endtime-starttime));
	    notaryreport(NULL,FAILED,"5.4.4 (DNS lookup report)",SS->remotemsg);
	    return EX_TEMPFAIL;
	  case NOERROR:
	    mx[0].host = NULL;
	    SS->mxcount = 0;
	    return EX_OK;
	  case FORMERR:
	  case NOTIMP:
	  case REFUSED:
	    sprintf(SS->remotemsg, "smtp; 500 (DNS: unsupported query: %.200s)", host);
	    endtime = now;
	    notary_setxdelay((int)(endtime-starttime));
	    notaryreport(NULL,FAILED,"5.4.4 (DNS lookup report)",SS->remotemsg);
	    return EX_NOPERM;
	  }
	  sprintf(SS->remotemsg, "smtp; 500 (DNS: unknown error, MX info unavailable: %.200s)", host);
	  endtime = now;
	  notary_setxdelay((int)(endtime-starttime));
	  notaryreport(NULL,FAILED,"5.4.4 (DNS lookup report)",SS->remotemsg);

	  if (had_eai_again)
	    return EX_TEMPFAIL;
	  return EX_UNAVAILABLE;
	}
	nmx = SS->mxcount;
	cp = (msgdata *)&answer + sizeof(HEADER);
	for (; qdcount > 0; --qdcount) {
#if	defined(BIND_VER) && (BIND_VER >= 473)
	  cp += dn_skipname(cp, eom) + QFIXEDSZ;
#else	/* !defined(BIND_VER) || (BIND_VER < 473) */
	  cp += dn_skip(cp) + QFIXEDSZ;
#endif	/* defined(BIND_VER) && (BIND_VER >= 473) */
	}
	realname[0] = '\0';
	maxpref = -1;
	while (--ancount >= 0 && cp < eom && nmx < maxmx-1) {
	  n = dn_expand((msgdata *)&answer, eom, cp, (void*)buf, sizeof buf);
	  if (n < 0)
	    break;
	  cp += n;
	  type = _getshort(cp);
	  cp += 2;
	  /*
	     class = _getshort(cp);
	     */
	  cp += 2;
	  mx[nmx].expiry = now + _getlong(cp); /* TTL */
	  cp += 4; /* "long" -- but keep in mind that some machines
		      have "funny" ideas about "long" -- those 64-bit
		      ones, I mean ... */
	  n = _getshort(cp); /* dlen */
	  cp += 2;
	  if (type == T_CNAME) {
	    cp += dn_expand((msgdata *)&answer, eom, cp,
			    (void*)realname, sizeof realname);
	    saw_cname = 1;
	    continue;
	  } else if (type != T_MX)  {
	    cp += n;
	    continue;
	  }
	  mx[nmx].pref = _getshort(cp);
	  cp += 2; /* MX preference value */
	  n = dn_expand((msgdata *)&answer, eom, cp, (void*)buf, sizeof buf);
	  if (n < 0)
	    break;
	  cp += n;

	  memset(&req, 0, sizeof(req));
	  req.ai_socktype = SOCK_STREAM;
	  req.ai_protocol = IPPROTO_TCP;
	  req.ai_flags    = AI_CANONNAME;
	  req.ai_family   = PF_INET;
	  ai = NULL;

	  /* This resolves CNAME, it should not happen in case
	     of MX server, though..    */
#if !GETADDRINFODEBUG
	  i = getaddrinfo((const char*)buf, "0", &req, &ai);
#else
	  i = _getaddrinfo_((const char*)buf, "0", &req, &ai, SS->verboselog);
	  if (SS->verboselog)
	    fprintf(SS->verboselog,"  getaddrinfo('%s','0') -> r=%d, ai=%p\n",
		    buf,i,ai);
#endif

#if defined(AF_INET6) && defined(INET6)
	  {
	    struct addrinfo *ai2 = NULL, *a;
	    int i2;
	    memset(&req, 0, sizeof(req));
	    req.ai_socktype = SOCK_STREAM;
	    req.ai_protocol = IPPROTO_TCP;
	    req.ai_flags    = AI_CANONNAME;
	    req.ai_family   = PF_INET6;

	  /* This resolves CNAME, it should not happen in case
	     of MX server, though..    */
#if !GETADDRINFODEBUG
	    i2 = getaddrinfo((const char*)buf, "0", &req, &ai2);
#else
	    i2 = _getaddrinfo_((const char*)buf, "0", &req, &ai2,
			       SS->verboselog);
	    if (SS->verboselog)
	      fprintf(SS->verboselog,"  getaddrinfo('%s','0') -> r=%d, ai=%p\n",
		      buf,i2,ai2);
#endif

	    if (i != 0 && i2 == 0) {
	      /* IPv6 address, no IPv4 (or error..) */
	      i = i2;
	      ai = ai2; ai2 = NULL;
	    }
	    if (ai2 && ai) {
	      /* BOTH ?!  Catenate them! */
	      a = ai;
	      while (a && a->ai_next) a = a->ai_next;
	      if (a) a->ai_next = ai2;
	    }
	  }
#endif


	  if (i != 0) {
	    if (i == EAI_AGAIN) {
	      sprintf(SS->remotemsg, "smtp; 500 (DNS: getaddrinfo<%.200s> got EAI_AGAIN)", buf);
	      endtime = now;
	      notary_setxdelay((int)(endtime-starttime));
	      notaryreport(NULL,FAILED,"5.4.4 (DNS lookup report)",SS->remotemsg);

	      had_eai_again = 1;
	    }
	    continue;		/* Well well.. spurious! */
	  }


	  if (cistrcmp(ai->ai_canonname, myhostname) == 0 ||
	      matchmyaddresses(ai) == 1) {

#if GETMXRRDEBUG
	    if (SS->verboselog)
	      fprintf(SS->verboselog,"  matchmyaddresses(): matched!  canon='%s', myname='%s'\n", ai->ai_canonname, myhostname);
#endif
	    if (maxpref < 0 || maxpref > (int)mx[nmx].pref)
	      maxpref = mx[nmx].pref;
	  }

	  /* Separate all addresses into their own MXes */
	  i = nmx;
	  while (ai && nmx < maxmx) {
	    mx[nmx].ai   = ai;
	    ai = ai->ai_next;
	    mx[nmx].ai->ai_next = NULL;
	    mx[nmx].host = (msgdata *)strdup((void*)buf);
	    if (mx[nmx].host == NULL) {
	      fprintf(stderr, "Out of virtual memory!\n");
	      exit(EX_OSERR);
	    }
	    if (nmx > i) {
	      mx[nmx].pref   = mx[i].pref;
	      mx[nmx].expiry = mx[i].expiry;
	    }
	    ++nmx;
	  }
	  /* [mea] Canonicalized this target & got A/AAAA records.. */
	  SS->mxcount = nmx;
	}

#if GETMXRRDEBUG
	if (SS->verboselog)
	  fprintf(SS->verboselog,"  getmxrr('%s') -> nmx=%d, maxpref=%d, realname='%s'\n", host, nmx, maxpref, realname);
#endif

	if (nmx == 0 && realname[0] != '\0' &&
	    cistrcmp(host,(char*)realname) != 0) {
	  /* do it recursively for the real name */
	  n = getmxrr(SS, (char *)realname, mx, maxmx, depth+1);
	  if (had_eai_again)
	    return EX_TEMPFAIL;
	  return n;
	} else if (nmx == 0) {
	  /* "give it the benefit of doubt" */
	  mx[0].host = NULL;
	  mx[0].ai   = NULL;
	  SS->mxcount = 0;
	  if (had_eai_again)
	    return EX_TEMPFAIL;
	  return EX_OK;
	}

	/* discard MX RRs with a value >= that of  myhost */
	if (maxpref >= 0) {
	  for (n = i = 0; n < nmx; ++n) {
	    if ((int)mx[n].pref >= maxpref) {
	      free(mx[n].host);
	      freeaddrinfo(mx[n].ai);
	      mx[n].host = NULL;
	      mx[n].ai   = NULL;
	      ++i;
	    }
	  }
	  if (i == nmx) {	/* we are the best MX, do it another way */
	    mx[0].host = NULL;
	    SS->mxcount = 0;
	    if (had_eai_again)
	      return EX_TEMPFAIL;
	    return EX_OK;
	  }
	}
#ifdef	RFC974
	/* discard MX's that do not support SMTP service */
	if (checkwks)
	  for (n = 0; n < nmx; ++n) {
	    if (mx[n].host == NULL)
	      continue;
	    strncpy((char*)buf, (char*)mx[n].host, sizeof(buf));
	    buf[sizeof(buf)-1] = 0;
	    /* It is an MX, it CAN'T have CNAME ! */
	    if (!getrrtype((void*)buf, &ttl, sizeof buf, T_WKS,
			   0, SS->verboselog)) {
	      free(mx[n].host);
	      mx[n].host = NULL;
	      freeaddrinfo(mx[n].ai);
	      mx[n].ai   = NULL;
	    }
	  }
#endif	/* RFC974 */
	/* determine how many are left */
	for (i = 0, n = 0; i < nmx; ++i) {
	  if (mx[i].host == NULL)
	    continue;
	  if (n < i) {
	    mx[n]      = mx[i];
	    mx[i].host = NULL;
	    mx[i].ai   = NULL;
	  }
	  ++n;			/* found one! */
	}
	if (n == 0) {/* MX's exist, but their WKS's show no TCP smtp service */
	  sprintf(SS->remotemsg,
		  "smtp; 500 (DNS: MX host does not support SMTP: %.200s)", host);
	  time(&endtime);
	  notary_setxdelay((int)(endtime-starttime));
	  notaryreport(NULL,FAILED,"5.4.4 (DNS lookup report)",SS->remotemsg);
	  if (had_eai_again)
	    return EX_TEMPFAIL;
	  return EX_UNAVAILABLE;
	}
	nmx = n;
	SS->mxcount = nmx;
	/* sort the records per preferrence value */
	for (i = 0; i < nmx; i++) {
	  for (j = i + 1; j < nmx; j++) {
	    if (mx[i].pref > mx[j].pref) {
	      mxtemp = mx[i];
	      mx[i] = mx[j];
	      mx[j] = mxtemp;
	    }
	  }
	}

	/* Randomize the order of those of same preferrence [mea]
	   This will do some sort of load-balancing on large sites
	   which have multiple mail-servers at the same priority.  */
	for (i = 0, maxpref = mx[0].pref; i < nmx; ++i) {
	  /* They are in numerical order, now we can
	     detect when a new preferrence group steps in */
	  j = i;
	  while (j < nmx && maxpref == mx[j].pref) ++j;
	  if ((j-i) > 1) {
	    /* At least two of the same preferrence */
	    int k, len = j-i;
	    for (k = 0; k < len; ++k) {
	      int l = ranny(len-1);
	      mxtemp = mx[i+k];
	      mx[i+k] = mx[i+l];
	      mx[i+l] = mxtemp;
	    }
#if defined(AF_INET6) && defined(INET6)
	    if (prefer_ip6) {
	      int l; /* Bring IPv6 addresses before IPv4 ones */
	      for (l = 0, k = 1; k < len; ++k) {
		if (mx[l].ai->ai_family == PF_INET &&
		    mx[k].ai->ai_family == PF_INET6) {
		  mxtemp = mx[k];
		  mx[k] = mx[l];
		  mx[l] = mxtemp;
		  ++l;
		}
	      }
	    }
#endif
	  }
	  /* Processed that preference, now next */
	  i = j-1;
	  if (j < nmx)		/* If within the array */
	    maxpref = mx[j].pref;
	}
#if GETMXRRDEBUG
	if (SS->verboselog) {
	  fprintf(SS->verboselog,"Target has following MXes (cnt=%d):\n",nmx);
	  for (i=0; i<nmx; ++i)
	    fprintf(SS->verboselog,"  MX %3d %.200s\n", mx[i].pref, mx[i].host);
	}
#endif
	mx[nmx].host = NULL;
	SS->mxcount = nmx;
	if (had_eai_again)
	  return EX_TEMPFAIL;
	return EX_OK;
}


/*
 * This is the callback function for ctlopen.  It should return 0 to reject
 * an address, and 1 to accept it.  This routine will only be used if we've
 * been asked to check MX RR's for all hosts for applicability. Therefore we
 * check whether the addr_host has an MX RR pointing at the host that we have
 * an SMTP connection open with.  Return 1 if it is so.
 * [mea] This also understands routermxes data.
 */

int
rightmx(spec_host, addr_host, cbparam)
	const char *spec_host, *addr_host;
	void	*cbparam;
{
	SmtpState *SS = cbparam;
	int	i, rc;

	if (cistrcmp(spec_host, addr_host) == 0)
	  return 1;
	if (SS->remotehost[0] == '\0')
	  return 0;

	SS->mxh[0].host = NULL;
	SS->mxcount = 0;
	SS->firstmx = 0;

	if (statusreport)
	  report(SS,"MX-lookup: %s", addr_host);

	switch (getmxrr(SS, addr_host, SS->mxh, MAXFORWARDERS, 0)) {
	case EX_OK:
	  if (SS->mxh[0].host == NULL)
	    return cistrcmp(addr_host, SS->remotehost) == 0;
	  break;
	default:
	  return 0;
	}
	rc = 0;
	for (i = 0; SS->mxh[i].host != NULL; ++i) {
	  if (cistrcmp((const void*)SS->mxh[i].host, SS->remotehost) == 0)
	    rc = 1;
	  freeaddrinfo(SS->mxh[i].ai);
	  SS->mxh[i].ai = NULL;
	  free(SS->mxh[i].host);
	  SS->mxh[i++].host = NULL;
	}
	return 0;
}
#endif	/* BIND */

/*
 * [mea] matchroutermxes()
 * like rightmx above, only a lot more light-weight...
 */
int
matchroutermxes(spec_host, ap, mrparam)
	const char *spec_host;
	struct taddress *ap;
	void *mrparam;
{
	SmtpState *SS = mrparam;
	const char **mxes = ap->routermxes;

	if (cistrcmp(spec_host, ap->host) == 0)
	  return 1;
	if (SS->remotehost[0] == 0)
	  return 0;

	while (*mxes) {
	  if (cistrcmp(spec_host,*mxes)==0) return 1; /* Found it */
	  ++mxes;
	}
	return 0;
}


void
notarystatsave(SS,smtpline,status)
SmtpState *SS;
char *smtpline, *status;
{
	char statbuf[10];
	int len = strlen(smtpline)+8+6;
#ifdef USE_ALLOCA
	char *str = alloca(len);
#else
	char *str = malloc(len);
#endif
	char *s = str;
#if 0
if (SS->verboselog)
  fprintf(SS->verboselog," notarystatsave1(len=%d status='%s', smtpline='%s')\n",len,status,smtpline);
#endif

	*statbuf = 0;
	strcpy(s,"smtp; ");
	s += 6;

	*s++ = *smtpline++;
	*s++ = *smtpline++;
	*s++ = *smtpline++;
	*s++ = ' ';
	if (*smtpline == ' ') ++smtpline;

	if (len >= 11) {
	  if (ESMTP_ENHSTATUS & SS->ehlo_capabilities) {
	    char *p = statbuf;
	    status = statbuf;
	    while ((p - statbuf) < sizeof(statbuf)-1) {
	      int c = (*smtpline) & 0xFF;
	      if (('0' <= c && c <= '9') || c == '.')
		*p++ = c;
	      else
		break;
	      ++smtpline;
	    }
	    *p = 0;
	    while (*smtpline == ' ' || *smtpline == '\t')
	      ++smtpline;
	  }
	}

	if (*smtpline) {
	  *s++ = '(';
	  while (*smtpline) {
	    switch (*smtpline) {
	    case '(':
	      *s++ = '[';
	      break;
	    case ')':
	      *s++ = ']';
	      break;
	    default:
	      *s++ = *smtpline;
	    }
	    ++smtpline;
	  }
	  *s++ = ')';
	}
	*s = 0;

	notaryreport(NULL,NULL,status,str);
#if 0
if (SS->verboselog)
  fprintf(SS->verboselog," notarystatsave2(status='%s', smtpline='%s')\n",status,str);
#endif
#ifndef USE_ALLOCA
	free(str);
#endif
}


void getdaemon()
{
	struct passwd *pw = getpwnam("daemon");
	if (!pw) pw = getpwnam("daemons"); /* Some SGI machines! */
	if (!pw) pw = getpwnam("uucp");

	if (!pw) daemon_uid = 0; /* Let it be root, if nothing else */
	else     daemon_uid = pw->pw_uid;
}
