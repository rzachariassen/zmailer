/*
 *    Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *      This will be free software, but only when it is finished.
 */
/*
 *    Several extensive changes by Matti Aarnio <mea@nic.funet.fi>
 *      Copyright 1991-1997.
 */

/*
 * ZMailer SMTP server.
 */

#include "smtpserver.h"

const char *VerbID = "ZMailer SMTP server %s";
const char *Copyright = "Copyright 1990 Rayan S. Zachariassen";
const char *Copyright2 = "Copyright 1991-1997 Matti Aarnio";

/* Timing parameters -- when expired, session is killed ... */


#include "identuser.h"
#ifdef USE_TRANSLATION
#include "libtrans.h"
#endif				/* USE_TRANSLATION */

#ifdef HAVE_WHOSON_H
#include <whoson.h>
#endif

/*
 * Early inetd's, which may be found on 4.2BSD based systems (e.g.
 * Sun OS 3.x), are incapable of passing a flag to indicate we are
 * being run by inetd rather than directly.  Some hackery to detect
 * when we are being run by the 4.2 inetd is included by defining
 * CHECK42INETD.  Should be deleted at the earliest possible opportunity.
 */

/* #define  CHECK42INETD */
/* heuristics to detect the 4.2 inetd */
/* [mea@utu.fi] - 4-Feb-95, I disabled this.. */

struct command command_list[] =
{
			/* 8-bit smtp extensions */
    {"EHLO", Hello2},
			/* Normal stuff.. */
    {"HELO", Hello},
    {"MAIL", Mail},
    {"RCPT", Recipient},
    {"DATA", Data},
    {"BDAT", BData,},
    {"RSET", Reset},
    {"VRFY", Verify},
    {"EXPN", Expand},
    {"HELP", Help},
    {"NOOP", NoOp},
    {"QUIT", Quit},
			/* ZMailer speciality, and an alias for it */
    {"ETRN", Turnme},
    {"TURNME", Turnme},
			/* sendmail extensions */
    {"VERB", Verbose},
    {"ONEX", NoOp},
			/* Depreciated */
    {"SEND", Send},
    {"SOML", SendOrMail},
    {"SAML", SendAndMail},
    {"TURN", Turn},
			/* bsmtp extensions */
    {"TICK", Tick},
			/* 8-bit smtp extensions -- depreciated */
    {"EMAL", Mail2},
    {"ESND", Send2},
    {"ESOM", Send2},
    {"ESAM", Send2},
    {"EVFY", Verify2},
			/* To fool loosers.. */
    {"IDENT", DebugIdent},
    {"DEBUG", DebugMode},
			/* End of the list */
    {0, Null}
};

struct policytest *policydb = NULL;
struct smtpconf *cfhead = NULL;
struct smtpconf *cfinfo = NULL;

const char *progname, *cmdline, *eocmdline, *logfile;
char *routerprog = NULL;
int logstyle = 0;		/* 0: no suffix, 1: 'myhostname', 2: 'rhostname' */
int debug = 0;
int skeptical = 1;
int checkhelo = 0;
int verbose = 0;
int daemon_flg = 1;
int netconnected_flg = 0;
int pid, routerpid = -1;
int router_status = 0;
FILE *logfp = NULL;
int D_alloc = 0;
int smtp_syslog = 0;
#ifdef USE_TRANSLATION
int X_translation = 0;
int X_8bit = 0;
int X_settrrc = 9;
#endif				/* USE_TRANSLATION */

jmp_buf jmpalarm;		/* Return-frame for breaking smtpserver
				   when timeout hits.. */


char *helplines[HELPMAX + 2] =
{NULL,};

const char *m200 = "2.0.0";
const char *m400 = "4.0.0";
const char *m430 = "4.3.0";
const char *m431 = "4.3.1";
const char *m443 = "4.4.3";
const char *m454 = "4.5.4";
const char *m471 = "4.7.1";
const char *m513 = "5.1.3";
const char *m517 = "5.1.7";
const char *m534 = "5.3.4";
const char *m540 = "5.4.0";
const char *m543 = "5.4.3";
const char *m550 = "5.5.0";
const char *m551 = "5.5.1";
const char *m552 = "5.5.2";
const char *m554 = "5.5.4";
const char *m571 = "5.7.1";

/*
 * The "style" variable controls when the router is interrogated about the
 * validity of something.  It is a string of letter-flags:
 * f:   check MAIL FROM addresses
 * t:   check RCPT TO addresses
 * v:   check VRFY command argument
 * e:   check EXPN command argument
 * R:   Demand strict conformance to RFC821/822 at address arguments
 */

const char *style = "ve";

long availspace = -1;		/* available diskspace/2 in bytes       */
long maxsize = 0;
int ListenQueueSize  = 20000;
int TcpRcvBufferSize = 0;
int TcpXmitBufferSize = 0;
int MaxSameIpSource = 100;	/* Max number of smtp connections in progress
				   from same IP address -- this to detect
				   systems sending lots of mail all in
				   parallel smtp sessions -- also to detect
				   some nutty Windows systems opening up
				   bunches of connections to the remote
				   system -- and to detect an attempt on
				   creating a denial-of-service attach by
				   opening lots and lots of connections to
				   the remote SMTP server... */
int MaxErrorRecipients = 10;	/* Max number of recipients for a message
				   that has a "box" ( "<>" ) as its source
				   address. */
int percent_accept = 0;
int maxloadavg = 999;		/* Maximum load-average that is tolerated
				   with smtp-server actively receiving..
				   Default value of 999 is high enough
				   so that it will never block -- use
				   "-L 10" to define lower limit (10) */

int allow_source_route = 0;	/* When zero, do ignore source route address
				   "@a,@b:c@d" by collapsing it into "c@d" */
int debugcmdok = 0;
int expncmdok = 0;
int vrfycmdok = 0;
int use_ipv6 = 0;
int ident_flag = 0;
#ifndef	IDENT_TIMEOUT
#define	IDENT_TIMEOUT	5
#endif				/* IDENT_TIMEOUT */

#if defined(AF_INET6) && defined(INET6)
static const struct in6_addr zin6addrany = 
{
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
const struct in6_addr zv4mapprefix = 
{
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0}};
#endif

static void setrfc1413ident __((SmtpState * SS));
static void setrhostname __((SmtpState *));
static RETSIGTYPE reaper __((int sig));
static RETSIGTYPE timedout __((int sig));
static void smtpserver __((SmtpState *, int insecure));


const char *msg_toohighload = "421 Sorry, the system is too loaded for email reception at the moment\r\n";	/* XX: ??? */

extern void openlogfp __((SmtpState * SS, int insecure));

void openlogfp(SS, insecure)
SmtpState *SS;
int insecure;
{
    /* opening the logfile should be done before we reset the uid */
    pid = getpid();
    if (logfp != NULL)
	fclose(logfp);
    logfp = NULL;
    if (logfile != NULL) {
	char *fname;
	int len1 = strlen(logfile);
	int len2, fd;
	const char *s = "";
	if (logstyle == 1)
	    s = SS->myhostname;
	if (logstyle == 2)
	    s = SS->rhostname;
	len2 = strlen(s);
#ifdef HAVE_ALLOCA
	fname = (char*)alloca(len1 + 1 + len2 + 1);
#else
	fname = malloc(len1 + 1 + len2 + 1);
#endif
	if (logstyle != 0)
	    sprintf(fname, "%s.%s", logfile, s);
	else
	    strcpy(fname, logfile);

	fd = open(fname, O_CREAT | O_APPEND | O_WRONLY, 0644);
	if (fd < 0) {
	    if (!insecure && daemon_flg)
		fprintf(stderr,
			"%s: cannot open logfile \"%s\": %s\n",
			progname, fname, strerror(errno));
	} else {
	    logfp = fdopen(fd, "a");
	    /* XX: */ setvbuf(logfp, NULL, _IOLBF, BUFSIZ);
	    /* Line-buffered */
	}
#ifndef HAVE_ALLOCA
	if (logstyle != 0)
	    free(fname);
#endif
    } else
	logfp = NULL;
}

extern int main __((int, char **));
int main(argc, argv)
int argc;
char **argv;
{
    int inetd, errflg, raddrlen, s, msgfd, version, i;
    const char *mailshare;
    char path[1024];
    u_short port = 0;
    int port_set = 0;
    int force_ipv4 = 0;
    int localsocksize;
    char *cfgpath = NULL;
    SmtpState SS;
    int childpid, sameipcount;
    time_t now;


    char *t, *syslogflg = getzenv("SYSLOGFLG");
    if (syslogflg == NULL)
      syslogflg = "";
    t = syslogflg;
    for ( ; *t ; ++t ) {
      if (*t == 's' || *t == 'S')
	break;
    }
    smtp_syslog = (*t != '\0');

    memset(&SS, 0, sizeof(SS));
    SS.mfp = NULL;
    SS.style = "ve";
    SS.state = Hello;
    SS.with_protocol = WITH_SMTP;

    SIGNAL_HANDLE(SIGPIPE, SIG_IGN);

    daemon_flg = 1;
    inetd = 0;
    errflg = 0;
    version = 0;
    logfile = NULL;
    logstyle = 0;
    progname = argv[0];
    cmdline = &argv[0][0];
    eocmdline = cmdline;
    for (i = 0; i < argc; ++i)
	eocmdline += strlen(argv[i]) + 1;
    *SS.myhostname = 0;
    if (getmyhostname(SS.myhostname, sizeof SS.myhostname) < 0) {
	fprintf(stderr, "%s: gethostname('%s'): %s\n",
		progname, SS.myhostname, strerror(errno));
	exit(1);
    }
    /* optarg = NULL; */
    while (1) {
	int c = getopt(argc, argv,
#ifndef __STDC__
#if defined(AF_INET6) && defined(INET6)
#ifdef USE_TRANSLATION
		       "?46aBC:d:ighl:np:L:M:P:R:s:S:VvX8"
#else /* xlate */
		       "?46aBC:d:ighl:np:L:M:P:R:s:S:Vv"
#endif /* xlate */
#else /* INET6 */
#ifdef USE_TRANSLATION
		       "?4aBC:d:ighl:np:L:M:P:R:s:S:VvX8"
#else
		       "?4aBC:d:ighl:np:L:M:P:R:s:S:Vv"
#endif /* xlate */
#endif /* INET6 */
#else /* __STDC__ */
		       "?"
		       "4"
#if defined(AF_INET6) && defined(INET6)
		       "6"
#endif
		       "aBC:d:ighl:n"
		       "p:"
		       "L:M:P:R:s:S:Vv"
#ifdef USE_TRANSLATION
		       "X8"
#endif /* USE_TRANSLATION */
#endif
		       );
	if (c == EOF)
	    break;
	if (c == '?') {
	  ++errflg;
	  break;
	}
	switch (c) {
	case '4':
	    force_ipv4 = 1;
	    break;
#if defined(AF_INET6) && defined(INET6)
	case '6':
	    use_ipv6 = 1;
	    break;
#endif
	case 'a':
	    ident_flag = 1;
	    break;
	case 'B':
	    SS.with_protocol = WITH_BSMTP;
	    break;
	case 'C':
	    cfgpath = optarg;
	    break;
	case 'd':
	    debug = atoi(optarg);
	    break;
	case 'M':
	    maxsize = atol(optarg);
	    if (maxsize < 0)
		maxsize = 0;
	    break;
	case 'i':		/* interactive */
	    daemon_flg = 0;
	    break;
	case 'v':
	    verbose = 1;	/* in conjunction with -i */
	    break;
	case 'g':		/* gullible */
	    skeptical = 0;
	    break;
	case 'h':		/* checkhelo */
	    checkhelo = 1;
	    break;
	case 'l':		/* log file(prefix) */
	    logfile = optarg;
	    break;
	case 'S':		/* Log-suffix style */
	    logstyle = 0;
	    if (cistrcmp(optarg, "remote") == 0)
		logstyle = 2;
	    else if (cistrcmp(optarg, "local") == 0)
		logstyle = 1;
	    break;
	case 'n':		/* running under inetd */
	    inetd = 1;
	    break;
	case 's':		/* checking style */
	    style = strdup(optarg);
	    break;
	case 'L':		/* Max LoadAverage */
	    maxloadavg = atoi(optarg);
	    if (maxloadavg < 1)
		maxloadavg = 10;	/* Humph.. */
	    break;
	case 'p':
	    port = htons(atoi(optarg));
	    port_set = 1;
	    break;
	case 'R':		/* router binary used for verification */
	    routerprog = strdup(optarg);
	    break;
	case 'P':
	    postoffice = strdup(optarg);
	    break;
	case 'V':
	    prversion("smtpserver");
	    exit(0);
	    break;		/* paranoia */
#ifdef USE_TRANSLATION
	case 'X':
	    X_translation = 1;
	    break;
	case '8':
	    X_8bit = 1;
	    break;
#endif				/* USE_TRANSLATION */
	default:
	    fprintf(stderr,
		    "%s: Unknown option, c=%d ('%c')\n", progname, c, c);
	    ++errflg;
	    break;
	}
    }
#ifdef CHECK42INETD
    /*
     * If no flags set and we have one argument, check
     * argument format to see if it's from the 4.2 inetd.
     */
    if (!errflg && daemon_flg && skeptical
	&& !inetd && port == 0 && optind == argc - 1)
	if (isit42inetd(argv[optind])) {
	    inetd = 1;
	    optind++;
	}
#endif				/* CHECK42INETD */
    if (errflg || optind != argc) {
	fprintf(stderr,
#ifndef __STDC__
		"Usage: %s [-46aBivgnV]\
 [-C cfgfile] [-s xx] [-L maxLoadAvg]\
 [-M SMTPmaxsize] [-R rtrprog] [-p port#]\
 [-P postoffice] [-l logfile] [-S 'local'|'remote']\n"
#else /* __STDC__ */
		"Usage: %s [-4"
#if defined(AF_INET6) && defined(INET6)
		"6"
#endif
		"aBivgnV"
#ifdef USE_TRANSLATION
		"X8"
#endif
		"] [-C cfgfile] [-s xx] [-L maxLoadAvg]"
		" [-M SMTPmaxsize] [-R rtrprog] [-p port#]"
		" [-P postoffice] [-l logfile] [-S 'local'|'remote']\n"
#endif /* __STDC__ */
		, progname);
	exit(1);
    }
    pid = getpid();
    if (!logfp)
	openlogfp(&SS, daemon_flg);

    mailshare = getzenv("MAILSHARE");
    if (mailshare == NULL)
	mailshare = MAILSHARE;
    if (cfgpath == NULL) {
      if (strchr(progname, '/') != NULL)
	sprintf(path, "%s/%s.conf", mailshare, strrchr(progname, '/') + 1);
      else
	sprintf(path, "%s/%s.conf", mailshare, progname);
    }

    if (cfgpath == NULL)
      cfhead = readcffile(path);
    else
      cfhead = readcffile(cfgpath);

    if (!allow_source_route)
      allow_source_route = (getzenv("ALLOWSOURCEROUTE") != NULL);

    netconnected_flg = 0;

    if (!daemon_flg) {

      raddrlen = sizeof SS.raddr;
      memset(&SS.raddr, 0, raddrlen);
      if (getpeername(SS.inputfd, (struct sockaddr *) &SS.raddr, &raddrlen))
	netconnected_flg = 0;
      else
	netconnected_flg = 1;

      strcpy(SS.rhostname, "stdin");
      SS.rport = -1;
      SS.ihostaddr[0] = '\0';
      sprintf(SS.ident_username, "uid#%d@localhost", (int)getuid());

      s_setup(&SS, FILENO(stdin), stdout);
      smtpserver(&SS, 0);

    } else
    if (inetd) {
#if 0
	if (maxloadavg != 999 &&
	    maxloadavg < loadavg_current()) {
	    write(1, msg_toohighload, strlen(msg_toohighload));
	    sleep(2);
	    exit(1);
	}
#endif
	raddrlen = sizeof SS.raddr;
	memset(&SS.raddr, 0, raddrlen);

	if (getpeername(SS.inputfd, (struct sockaddr *) &SS.raddr, &raddrlen))
	  netconnected_flg = 0;
	else
	  netconnected_flg = 1;

#if defined(AF_INET6) && defined(INET6)
	if (SS.raddr.v6.sin6_family == AF_INET6)
	  SS.rport = SS.raddr.v6.sin6_port;
	else
#endif
	  SS.rport = SS.raddr.v4.sin_port;

	setrhostname(&SS);

	/* Lets figure-out who we are this time around -- we may be on
	   a machine with multiple identities per multiple interfaces,
	   or via virtual IP-numbers, or ... */
	localsocksize = sizeof(SS.localsock);
	if (getsockname(FILENO(stdin), (struct sockaddr *) &SS.localsock,
			&localsocksize) != 0) {
	    /* XX: ERROR! */
	}
	zopenlog("smtpserver", LOG_PID, LOG_MAIL);

	s_setup(&SS, FILENO(stdin), stdout);

	if (ident_flag != 0)
	    setrfc1413ident(&SS);
	else
	    strcpy(SS.ident_username, "IDENT-NOT-QUERIED");

	sprintf(SS.ident_username + strlen(SS.ident_username),
		" [port %d]", SS.rport);

	if (smtp_syslog && ident_flag) {
#ifdef HAVE_WHOSON_H
	    zsyslog((LOG_INFO, "connection from %s@%s (whoson: $s)\n",
		     SS.ident_username, SS.rhostname, SS.whoson_data));
#else
	    zsyslog((LOG_INFO, "connection from %s@%s\n",
		     SS.ident_username, SS.rhostname));
#endif
	}

	pid = getpid();
	openlogfp(&SS, daemon_flg);
	if (logfp != NULL) {
#ifdef HAVE_WHOSON_H
	    fprintf(logfp, "%d#\tconnection from %s:%d ident: %s whoson: %s\n",
		    pid, SS.rhostname, SS.rport, SS.ident_username, SS.whoson_data);
#else
	    fprintf(logfp, "%d#\tconnection from %s:%d ident: %s\n",
		    pid, SS.rhostname, SS.rport, SS.ident_username);
#endif
	}

#if 0
	SIGNAL_HANDLE(SIGCHLD, SIG_DFL);
#else
	SIGNAL_HANDLE(SIGCHLD, reaper);
#endif
	SIGNAL_HANDLE(SIGALRM, timedout);
	SIGNAL_HANDLE(SIGHUP, SIG_IGN);
	SIGNAL_HANDLE(SIGTERM, SIG_DFL);

	smtpserver(&SS, 1);

    } else {			/* Not from under the inetd -- standalone server */
	if (postoffice == NULL
	    && (postoffice = getzenv("POSTOFFICE")) == NULL)
	    postoffice = POSTOFFICE;
	if (!port_set) {
	    if (killprevious(SIGTERM, PID_SMTPSERVER) != 0) {
		fprintf(stderr,
			"%s: Can't write my pidfile!  Disk full ?\n",
			progname);
		exit(2);
	    }
	    fflush(stdout);
	    fflush(stderr);
	}
#if defined(AF_INET6) && defined(INET6)

	/* Perhaps the system can grok the IPv6 - at least the headers
	   seem to indicate so, but like we know of Linux, the protocol
	   might not be loaded in, or some such...
	   If we are not explicitely told to use IPv6 only, we will try
	   here to use IPv6, and if successfull, register it!  */
	if (!use_ipv6 && !force_ipv4) {
	    s = socket(AF_INET6, SOCK_STREAM, 0 /* IPPROTO_IPV6 */ );
	    if (s >= 0) {
		use_ipv6 = 1;	/* We can do it! */
		close(s);
	    }
	}
	if (use_ipv6) {
	    s = socket(AF_INET6, SOCK_STREAM, 0 /* IPPROTO_IPV6 */ );
#if 0
	    if (s < 0) {	/* Fallback to the IPv4 mode .. */
		s = socket(AF_INET, SOCK_STREAM, 0 /* IPPROTO_IP   */ );
		use_ipv6 = 0;
	    }
#endif
	} else
	    s = socket(AF_INET, SOCK_STREAM, 0 /* IPPROTO_IP   */ );
#else
	s = socket(AF_INET, SOCK_STREAM, 0);
#endif
	if (s < 0) {
	    fprintf(stderr,
		    "%s: socket(AF_INET%s, SOCK_STREAM): %s\n",
		    progname, (use_ipv6 ? "6" : ""), strerror(errno));
	    exit(1);
	}
	i = 1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (caddr_t) & i, sizeof i) < 0) {
	    fprintf(stderr,
		    "%s: setsockopt(SO_REUSEADDR): %s\n",
		    progname, strerror(errno));
	    exit(1);
	}
#ifdef SO_REUSEPORT
	if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (caddr_t) & i, sizeof i) < 0) {
	    fprintf(stderr,
		    "%s: setsockopt(SO_REUSEPORT): %s\n",
		    progname, strerror(errno));
	    exit(1);
	}
#endif

#ifdef SO_RCVBUF
	if (TcpRcvBufferSize > 0)
	    if (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
			   (char *) &TcpRcvBufferSize,
			   sizeof(TcpRcvBufferSize)) < 0) {
		fprintf(stderr, "%s: setsockopt(SO_RCVBUF): %s\n",
			progname, strerror(errno));
		exit(1);
	    }
#endif
#ifdef SO_SNDBUF
	if (TcpXmitBufferSize > 0)
	    if (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
			   (char *) &TcpXmitBufferSize,
			   sizeof(TcpXmitBufferSize)) < 0) {
		fprintf(stderr, "%s: setsockopt(SO_SNDBUF): %s\n",
			progname, strerror(errno));
		exit(1);
	    }
#endif
	if (port <= 0) {
	    struct servent *service;
#ifdef	IPPORT_SMTP
	    port = htons(IPPORT_SMTP);
#endif				/* !IPPORT_SMTP */
	    if ((service = getservbyname("smtp", "tcp")) == NULL) {
		fprintf(stderr,
			"%s: no SMTP service entry, using default\n",
			progname);
	    } else
		port = service->s_port;
	}
#if defined(AF_INET6) && defined(INET6)
	if (use_ipv6) {

	    struct sockaddr_in6 si6;
	    memset(&si6, 0, sizeof(si6));
	    si6.sin6_family = AF_INET6;
	    si6.sin6_flowinfo = 0;
	    si6.sin6_port = port;
	    si6.sin6_addr = zin6addrany;

	    i = bind(s, (struct sockaddr *) &si6, sizeof si6);
	    if (i < 0) {
		fprintf(stderr, "%s: bind(IPv6): %s\n",
			progname, strerror(errno));
		exit(1);
	    }
	} else
#endif
	{
	    struct sockaddr_in si4;

	    memset(&si4, 0, sizeof(si4));
	    si4.sin_family = AF_INET;
	    si4.sin_addr.s_addr = INADDR_ANY;
	    si4.sin_port = port;

	    i = bind(s, (struct sockaddr *) &si4, sizeof si4);
	    if (i < 0) {
		fprintf(stderr, "%s: bind(IPv4): %s\n",
			progname, strerror(errno));
		exit(1);
	    }
	}

	/* Set the listen limit HIGH; there has been an active
	   denial-of-service attack where people send faked SYNs
	   to open a connection to our system who does not want to
	   talk with us at all -- or whose traffic goes thru a
	   routing black-hole, who just plain don't exist on some
	   existing network.  The net result being that our SYN-ACKs
	   will never get ACKed, and no connection built...
	   The SYN_RECV-queue can grow also due to a 'routing diode'
	   behind of which some poor fellow is trying to get our
	   attention, but our replies do not reach back to him/her. */
	/* Often the system enforces some upper bound for this
	   limit, and you can't exceed it -- but some new systems
	   allow rather high limits, lets try to use it!
	   (The classical default is: 5) */

	if (listen(s, ListenQueueSize) < 0) {
	    fprintf(stderr, "%s: listen(sock,%d): %s\n",
		    progname, ListenQueueSize, strerror(errno));
	    exit(1);
	}
	settrusteduser();	/* dig out the trusted user ID */
	zcloselog();		/* close the syslog too.. */
	detach();		/* this must NOT close fd's */
	/* Close fd's 0, 1, 2 now */
	close(0);
	close(1);
	close(2);

	open("/dev/null", O_RDWR, 0);
	dup(0);
	dup(0);			/* fd's 0, 1, 2 are in use again.. */

	if (!port_set || port != htons(25))
	    killprevious(0, PID_SMTPSERVER);	/* deposit pid */
#if 1
	pid = getpid();
	openlogfp(&SS, daemon_flg);
	if (logfp != NULL) {
	    char *cp;
	    time(&now);
	    cp = rfc822date(&now);
	    fprintf(logfp, "00000#\tstarted server pid %d at %s", pid, cp);
	    /*fprintf(logfp,"00000#\tfileno(logfp) = %d\n",fileno(logfp)); */
	    fclose(logfp);
	    logfp = NULL;
	}
#endif
#if 0
	SIGNAL_HANDLE(SIGCHLD, SIG_DFL);
#else
	SIGNAL_HANDLE(SIGCHLD, reaper);
#endif
	SIGNAL_HANDLE(SIGALRM, timedout);
	SIGNAL_HANDLE(SIGHUP, SIG_IGN);
	SIGNAL_HANDLE(SIGTERM, SIG_DFL);
	while (1) {
	    raddrlen = sizeof(SS.raddr);
	    msgfd = accept(s, (struct sockaddr *) &SS.raddr, &raddrlen);
	    if (msgfd < 0) {
		int err = errno;
		switch (err) {
		case EINTR:	/* very common.. */
		    continue;
#if 0
		case ECONNRESET:	/* seen to happen! */
		case ECONNABORTED:
		case ENETUNREACH:
		case ENETRESET:
		case ETIMEDOUT:	/* unlikely.. */
		case ECONNREFUSED:	/* unlikely.. */
		case EHOSTDOWN:
		case EHOSTUNREACH:
		case ECHILD:	/* Seen Solaris to do this! */
#ifdef ENOSR
		case ENOSR:
#endif
#ifdef EPROTO
		case EPROTO:
#endif
		    continue;
#endif
		default:
		    break;
		}
		/* Ok, all the WEIRD errors, continue life after
		   logging, NO exit(1) we used to do... */
		time(&now);
		fprintf(stderr, "%s: accept(): %s; %s",
			progname, strerror(err), rfc822date(&now));
		openlogfp(&SS, daemon_flg);
		if (logfp) {
		    fprintf(logfp, "000000#\taccept(): %s; %s",
			    strerror(err), (char *) rfc822date(&now));
		    fclose(logfp);
		    logfp = NULL;
		}
		continue;
	    }

	    sameipcount = childsameip(&SS.raddr);
	    /* We query, and warn the remote when
	       the count exceeds the limit, and we
	       simply -- and FAST -- reject the
	       remote when it exceeds 4 times the
	       limit */
	    if (sameipcount > 4 * MaxSameIpSource) {
	      close(msgfd);
	      continue;
	    }


	    SIGNAL_HOLD(SIGCHLD);
	    if ((childpid = fork()) < 0) {	/* can't fork! */
		close(msgfd);
		fprintf(stderr,
			"%s: fork(): %s\n",
			progname, strerror(errno));
		sleep(5);
		continue;
	    } else if (childpid > 0) {	/* Parent! */
		childregister(childpid, &SS.raddr);
		SIGNAL_RELEASE(SIGCHLD);
		reaper(0);
		close(msgfd);
	    } else {			/* Child */
		SIGNAL_RELEASE(SIGCHLD);

		netconnected_flg = 1;

		close(s);	/* Listening socket.. */
		pid = getpid();

		if (msgfd != 0)
		    dup2(msgfd, 0);
		dup2(0, 1);
		if (msgfd > 1)
		    close(msgfd);
		msgfd = 0;

		if (logfp)	/* Open the logfp latter.. */
		    fclose(logfp);
		logfp = NULL;


#if 0
		if (maxloadavg != 999 &&
		    maxloadavg < loadavg_current()) {
		    write(msgfd, msg_toohighload,
			  strlen(msg_toohighload));
		    sleep(2);
		    exit(1);
		}
#endif
		SIGNAL_HANDLE(SIGTERM, SIG_IGN);

#if defined(AF_INET6) && defined(INET6)

		if (SS.raddr.v6.sin6_family == AF_INET6)
		    SS.rport = SS.raddr.v6.sin6_port;
		else
#endif
		    SS.rport = SS.raddr.v4.sin_port;

		setrhostname(&SS);

		/* Lets figure-out who we are this time around -- we may be on
		   a machine with multiple identities per multiple interfaces,
		   or via virtual IP-numbers, or ... */
		localsocksize = sizeof(SS.localsock);
		if (getsockname(msgfd, (struct sockaddr *) &SS.localsock,
				&localsocksize) != 0) {
		    /* XX: ERROR! */
		}
		zopenlog("smtpserver", LOG_PID, LOG_MAIL);

		s_setup(&SS, msgfd, stdout);

		if (ident_flag != 0)
		    setrfc1413ident(&SS);
		else
		    strcpy(SS.ident_username, "IDENT-NOT-QUERIED");

		if (smtp_syslog && ident_flag) {
#ifdef HAVE_WHOSON_H
		  zsyslog((LOG_INFO, "connection from %s@%s (whoson: %s)\n",
			   SS.ident_username, SS.rhostname, SS.whoson_data));
#else /* WHOSON */
		  zsyslog((LOG_INFO, "connection from %s@%s\n",
			   SS.ident_username, SS.rhostname));
#endif
		}
		pid = getpid();

		openlogfp(&SS, daemon_flg);
		if (logfp != NULL) {
#ifdef HAVE_WHOSON_H
		    fprintf(logfp,
			    "%d#\tconnection from %s ipcnt %d ident: %s whoson: %s\n",
			    pid, SS.rhostname, sameipcount, SS.ident_username,
			    SS.whoson_data);
#else
		    fprintf(logfp,
			    "%d#\tconnection from %s ipcnt %d ident: %s\n",
			    pid, SS.rhostname, sameipcount, SS.ident_username);
#endif
		}
/* if (logfp) fprintf(logfp,"%d#\tInput fd=%d\n",getpid(),msgfd); */

		if (sameipcount > MaxSameIpSource && sameipcount > 1) {
		    int len;
		    char msg[200];
		    sprintf(msg, "450-Too many simultaneous connections from same IP address (%d max %d)\r\n", sameipcount, MaxSameIpSource);
		    len = strlen(msg);
		    if (write(msgfd, msg, len) != len) {
		      sleep(2);
		      exit(1);	/* Tough.. */
		    }
		    strcpy(msg, "450 Come again latter\r\n");
		    len = strlen(msg);
		    write(msgfd, msg, len);
		    close(0); close(1);
#if 1
		    sleep(2);	/* Not so fast!  We need to do this to
				   avoid (as much as possible) the child
				   to exit before the parent has called
				   childregister() -- not so easy to be
				   100% reliable (this isn't!) :-( */
#endif
		    exit(0);	/* Now exit.. */
		}
		smtpserver(&SS, 1);
		/* Expediated filehandle closes before
		   the mandatory sleep(2) below. */
		close(0); close(1);

		if (routerpid > 0)
		    killr(&SS, routerpid);

		sleep(2);
		_exit(0);
	    }
	}
    }
    if (routerpid > 0)
	killr(&SS, routerpid);
    sleep(2);
    exit(0);
    /* NOTREACHED */
    return 0;
}

#ifdef CHECK42INETD
/*
 * The 4.2 BSD inetd runs its servers with exactly one argument having
 * the form:
 *              xxxxxxxx.dddd
 *
 * where xxxxxxxxx is the remote IP host address in hexadecimal and
 * dddd is the remote port number in decimal.  While we don't use these
 * (the host has to support getpeername()), this routine checks for
 * the correct form of the argument.
 */

int isit42inetd(arg)
char *arg;
{
    register int i;

    for (i = 0; i < 8; i++)	/* exactly 8 hex digits */
	if (!isxdigit(arg[i]))
	    return 0;
    if (arg[8] != '.')		/* period next */
	return 0;
    for (i = 9; arg[i] != '\0'; i++)	/* now one or more decimal digits */
	if (!isdigit(arg[i]))
	    return 0;
    if (i == 9)
	return 0;
    return 1;			/* okay! */
}
#endif				/* CHECK42INETD */


/*
 * set the (default) remote host name, possibly based on the remote IP
 * host address if we are feeling untrusting.
 */

static void setrhostname(SS)
SmtpState *SS;
{
    struct hostent *hp = NULL;

    if (SS->raddr.v4.sin_family == AF_INET)
	inet_ntop(AF_INET, (void *) &SS->raddr.v4.sin_addr,	/* IPv4 */
		  SS->ihostaddr + 1, sizeof(SS->ihostaddr) - 2);
#if defined(AF_INET6) && defined(INET6)
    else if (SS->raddr.v6.sin6_family == AF_INET6) {
	strcpy(SS->ihostaddr + 1, "IPv6:");
	inet_ntop(AF_INET6, (void *) &SS->raddr.v6.sin6_addr,	/* IPv6 */
		  SS->ihostaddr + 6, sizeof(SS->ihostaddr) - 7);
    }
#endif
    else {
	;			/* XX: ??? Not AF_INET, nor AF_INET6 ??? */
    }
    SS->ihostaddr[0] = '[';
    sprintf(SS->ihostaddr + strlen(SS->ihostaddr), "]");

    if (skeptical) {
	if (SS->raddr.v4.sin_family == AF_INET)
	    hp = gethostbyaddr((char *) &SS->raddr.v4.sin_addr, 4, AF_INET);
#if defined(AF_INET6) && defined(INET6)
	else if (SS->raddr.v6.sin6_family == AF_INET6) {
	    struct in6_addr *ip6 = &SS->raddr.v6.sin6_addr;

	    /* If it is IPv4 mapped address to IPv6, then resolve
	       the IPv4 address... */

	    if (memcmp((void *) ip6, &zv4mapprefix, 12) == 0)
		hp = gethostbyaddr(((char *) ip6) + 12, 4, AF_INET);
	    else
		hp = gethostbyaddr((char *) ip6, 16, AF_INET6);
	}
#endif
	else {
	    ;			/* XX: ??? Not AF_INET, nor AF_INET6 ??? */
	}

	if (hp != NULL)
	    strcpy(SS->rhostname, hp->h_name);
	else
	    strcpy(SS->rhostname, SS->ihostaddr);
    } else {
	strcpy(SS->rhostname, SS->ihostaddr);
    }
}

static RETSIGTYPE
 timedout(sig)
int sig;
{
    /* Return to the smtpserver's mail-program.
       We are commiting a suicide, but we need
       data that exists only in that context... */
    longjmp(jmpalarm, 1);
    _exit(253);			/* We did return ?!?! Boo!! */
}

static RETSIGTYPE
 reaper(sig)
int sig;
{
    int status;
    int lpid;

#ifdef	HAVE_WAITPID
    while ((lpid = waitpid(-1, &status, WNOHANG)) > 0)
#else
#ifdef	HAVE_WAIT3
    while ((lpid = wait3(&status, WNOHANG, (struct rusage *) NULL)) > 0)
#else				/* ... plain simple waiting wait() ... */
    /* This can freeze at wait() ?  Who could test ?  A system
       without wait3()/waitpid(), but with BSD networking ??? */
    while ((lpid = wait(&status)) > 0)
#endif				/* WNOHANG */
#endif
    {
	if (lpid == routerpid && routerpid > 0) {
	  router_status = status;
	  routerpid = -1;
	}
	childreap(lpid);
    }
    SIGNAL_HANDLE(SIGCHLD, reaper);
}

void reporterr(SS, tell, msg)
SmtpState *SS;
long tell;
const char *msg;
{
    zsyslog((LOG_ERR,
	     "aborted (%ld bytes) from %s/%d: %s", tell, SS->rhostname, SS->rport, msg));
    if (logfp != NULL) {
	fprintf(logfp, "%d-\taborted (%ld bytes): %s\n", pid, tell, msg);
	fflush(logfp);
    }
}


/* Support routine: Our own buffering for stdinput */

int s_feof(SS)
SmtpState *SS;
{
    return SS->s_status;
}

int s_getc(SS)
SmtpState *SS;
{
    int rc = 0;

    if (SS->s_status)
	return SS->s_status;
    if (SS->s_readout >= SS->s_bufread) {
    redo:
	rc = read(SS->inputfd, SS->s_buffer, sizeof(SS->s_buffer));
	if (rc < 0) {
	  goto redo;
	    if (errno == EINTR || errno == EAGAIN)
		goto redo;
	    /* Other results are serious errors -- maybe */
	    SS->s_status = EOF;
	    return EOF;
	}
	if (rc == 0) {
	    SS->s_status = EOF;
	    return EOF;
	}
	SS->s_bufread = rc;
	SS->s_readout = 0;
    }
    /* if (rc) return EOF; XXX: Hmm.. what this was supposed to be ? */
    return ((SS->s_buffer)[SS->s_readout++]) & 0xFF;
}

int s_hasinput(SS)
SmtpState *SS;
{
    if (SS->s_readout >= SS->s_bufread) {
	/* So if it did dry up, try non-blocking read */
	int flags = fcntl(SS->inputfd, F_GETFL, 0);
	SS->s_readout = 0;
#if defined(O_NONBLOCK) || defined(FNDELAY)
#ifdef O_NONBLOCK
	fcntl(SS->inputfd, F_SETFL, flags | O_NONBLOCK);
#else
	fcntl(SS->inputfd, F_SETFL, flags | FNDELAY);
#endif
	SS->s_bufread = read(SS->inputfd, SS->s_buffer, sizeof(SS->s_buffer));
	fcntl(SS->inputfd, F_SETFL, flags);
	if (SS->s_bufread > 0)
	    return SS->s_bufread;
#endif
	return 0;
    }
    return (SS->s_bufread - SS->s_readout);
}

void s_setup(SS, infd, outfp)
SmtpState *SS;
int infd;
FILE *outfp;
{
    SS->inputfd = infd;
    SS->outfp = outfp;
    SS->s_status = 0;
    SS->s_bufread = -1;
    SS->s_readout = 0;
}



/* The SMTP-server itself */

static void smtpserver(SS, insecure)
SmtpState *SS;
int insecure;
{
    char *cp;
    time_t now;
    int rc;
    long tell;
    int policystatus;
    struct hostent *hostent;

#ifdef USE_TRANSLATION
    char lang[4];

    lang[0] = '\0';
#endif
    SS->VerboseCommand = 0;

    stashmyaddresses(NULL);

    pid = getpid();
    if (!logfp)
	openlogfp(SS, insecure);

    runastrusteduser();

    rc = setjmp(jmpalarm);
    if (rc != 0) {
	/* Oooo...  We are returning here via  longjmp(),
	   which means we just got a timeout (SIGALRM),
	   which for us is instant death.. */
	tell = 0;
	if (SS->mfp != NULL) {
	    fseek(SS->mfp, 0, SEEK_END);
	    tell = ftell(SS->mfp);
	}
	reporterr(SS, tell, "SMTP protocol timed out");

	/* If there is something going on, kill the file.. */
	if (SS->mfp != NULL) {
	  if (STYLE(SS->cfinfo,'D')) {
	    /* Says: DON'T DISCARD -- aka DEBUG ERRORS! */
	    mail_close_alternate(SS->mfp,"public",".SMTP-TIMEOUT");
	  } else
	    mail_abort(SS->mfp);
	}
	SS->mfp = NULL;

	if (routerpid > 0)
	    killr(SS, routerpid);
	exit(0);
    }
    report(SS, "(connected)");
    now = time((time_t *) 0);
    cp = (char *) rfc822date(&now);
    if (*(cp + strlen(cp) - 1) == '\n')
	*(cp + strlen(cp) - 1) = '\0';

#if defined(AF_INET6) && defined(INET6)
    if (SS->localsock.v6.sin6_family == AF_INET6) {
	struct in6_addr *ip6 = &SS->localsock.v6.sin6_addr;

	/* If it is IPv4 mapped address to IPv6, then resolve
	   the IPv4 address... */

	if (memcmp((void *) ip6, &zv4mapprefix, 12) == 0)
	    hostent = gethostbyaddr(((char *) ip6) + 12, 4, AF_INET);
	else
	    hostent = gethostbyaddr((char *) ip6, 16, AF_INET6);
    } else
#endif
	hostent = gethostbyaddr((void *) &SS->localsock.v4.sin_addr, 4, AF_INET);

    if (hostent) {
	strcpy(SS->myhostname, hostent->h_name);
#ifdef USE_TRANSLATION
	strncpy(lang, hostent->h_name, 3);
	lang[3] = '\0';
	X_settrrc = settrtab_byname(lang);
    }
    if (!(*lang) || (X_settrrc < 0)) {
	/* we don't know our codetable, hush client away */
	type(SS, 451, NULL, "Server could not setup translation.", NULL);
	typeflush(SS);
	sleep(2);
	exit(0);
#endif				/* USE_TRANSLATION */
    }
#ifdef HAVE_WHOSON_H
    {
	char buf[64];
	buf[0]='\0';
	if (SS->raddr.v4.sin_family == AF_INET) {
	  inet_ntop(AF_INET, (void *) &SS->raddr.v4.sin_addr,	/* IPv4 */
		    buf, sizeof(buf) - 1);
#if defined(AF_INET6) && defined(INET6)
	} else if (SS->raddr.v6.sin6_family == AF_INET6) {
	  inet_ntop(AF_INET6, (void *) &SS->raddr.v6.sin6_addr,  /* IPv6 */
		    buf, sizeof(buf) - 1);
#endif
	}
	if ((SS->whoson_result = wso_query(buf, SS->whoson_data,
					   sizeof(SS->whoson_data)))) {
	    strcpy(SS->whoson_data,"UNAVAILABLE");
	}
    }
    policystatus     = policyinit(&policydb, &SS->policystate,
				  SS->whoson_result);
#else
    policystatus     = policyinit(&policydb, &SS->policystate, 0);
#endif
    SS->policyresult = policytestaddr(policydb, &SS->policystate,
				      POLICY_SOURCEADDR,
				      (void *) &SS->raddr);
    SS->reject_net = (SS->policyresult < 0);
    if (SS->policyresult == 0) /* Alternates to this condition are:
				  Always reject, or Always freeze.. */
      SS->policyresult = policytest(policydb, &SS->policystate,
				    POLICY_SOURCEDOMAIN,
				    SS->rhostname,strlen(SS->rhostname));

    /* re-opening the log ?? */
    zopenlog("smtpserver", LOG_PID, LOG_MAIL);

#ifdef HAVE_TCPD_H		/* TCP-Wrapper code */
    if (wantconn(SS->inputfd, "smtp-receiver") == 0) {
	zsyslog((LOG_WARNING, "refusing connection from %s:%d/%s",
		 SS->rhostname, SS->rport, SS->ident_username));
	type(SS, 421, NULL, "%s ZMailer Server %s WILL NOT TALK TO YOU at %s",
	     SS->myhostname, VersionNumb, cp);
	typeflush(SS);
	sleep(2);
	exit(0);
    }
#endif

    if (SS->reject_net) {
	char *msg = policymsg(policydb, &SS->policystate);
	if (msg != NULL) {
	  type(SS, -553, NULL, "%s", msg);
	} else {
	  type(SS, -553, NULL, "%s - You are on our reject-IP-address -list, GO AWAY!",
	       SS->myhostname);
	}
	type(SS, -553, NULL, "If you feel we mistreat you, do contact us.");
	type(SS, 553, NULL, "Ask HELP for our contact information.");
    } else
#ifdef USE_TRANSLATION
	type(SS, 220, NULL, "%s ZMailer Server %s ESMTP%s (%s) ready at %s",
	     SS->myhostname, VersionNumb, ident_flag ? "+IDENT" : "",
	     X_settrrc ? "nulltrans" : lang, cp);
#else				/* USE_TRANSLATION */
	type(SS, 220, NULL, "%s ZMailer Server %s ESMTP%s ready at %s",
	     SS->myhostname, VersionNumb, ident_flag ? "+IDENT" : "", cp);
#endif				/* USE_TRANSLATION */
    typeflush(SS);

    SS->state = Hello;
    if ((!insecure
	 || (SS->ihostaddr[0] != '\0'
	     && strcmp(SS->ihostaddr, "[127.0.0.1]") == 0))
	&& ((cfinfo = findcf("127.0.0.1")) == NULL
	    || strcmp(cfinfo->flags, "-") == 0))
	SS->state = MailOrHello;

    cfinfo = NULL;
    if (logfp != NULL) {
	char *s = policymsg(policydb, &SS->policystate);
	if (insecure)
	    fprintf(logfp, "%d#\tremote from %s:%d\n",
		    pid, SS->ihostaddr, SS->rport);
	else
	    fprintf(logfp, "%d#\tlocal from uid#%d\n",
		    pid, (int)getuid());
	if (SS->policyresult != 0 || s != NULL)
	  fprintf(logfp, "%d#\t-- policyresult=%d initial policy msg: %s\n",
		  pid, SS->policyresult, (s ? s : "<NONE!>"));
	fflush(logfp);
    }
    while (1) {

	char buf[SMTPLINESIZE];	/* limits size of SMTP commands...
				   On the other hand, limit is asked
				   to be only 1000 chars, not 8k.. */
	int c, co = -1;
	int i;
	char *eobuf;
	rc = -1;

	if (!s_hasinput(SS))
	    typeflush(SS);
	else
	    /* if (verbose) */
	if (logfp)
	    fprintf(logfp, "%d#\t-- pipeline input exists %d bytes\n", pid, s_hasinput(SS));

	/* Alarm processing on the SMTP protocol channel */
	alarm(SMTP_COMMAND_ALARM_IVAL);

	/* Our own  fgets() -- gets also NULs, flags illegals.. */
	i = 0;
	while ((c = s_getc(SS)) != EOF && i < (sizeof(buf) - 1)) {
	    if (c == '\n') {
		/* *s++ = c; *//* Don't save it! No need */
		break;
	    } else if (co == '\r' && rc < 0)
		rc = i;		/* Spurious CR on the input.. */

	    if (c == '\0' && rc < 0)
		rc = i;
	    if ((c & 0x80) != 0 && rc < 0)
		rc = i;
	    if (c != '\r' && c != '\t' &&
		(c < 32 || c == 127) && rc < 0)
		rc = i;
	    buf[i++] = c;
	}
	buf[i] = '\0';
	eobuf = &buf[i];	/* Buf end ptr.. */
	alarm(0);		/* Cancel the alarm */
	if (c == EOF && i == 0) {
	    /* XX: ???  Uh, Hung up on us ? */
	    if (SS->mfp != NULL)
		mail_abort(SS->mfp);
	    SS->mfp = NULL;
	    break;
	}
	/* Zap the possible trailing  \r */
	if ((eobuf > buf) && (eobuf[-1] == '\r'))
	    *--eobuf = '\0';

	/* Chop the trailing spaces */
	while ((eobuf > buf) && (eobuf[-1] == ' ' ||
				 eobuf[-1] == '\t'))
	    *--eobuf = '\0';

	if (logfp != NULL) {
	    fprintf(logfp, "%dr\t%s\n", pid, buf);
	    fflush(logfp);
	}
	if (rc >= 0) {
	  if (cistrncmp(buf,"HELO",4) == 0 ||
	      cistrncmp(buf,"EHLO",4) == 0)
	    rc = -1; /* Sigh... Bloody windows users naming their
			machines with junky names, and M$ being
			its normal incompetent protocol cleaner... */
	}
	if (rc >= 0) {
	    rfc821_error_ptr = buf + rc;
	    type821err(SS, 500, m552, buf,
		       "Illegal input characters: %s",
		       ((buf[rc] == '\0') ? "NUL on SMTP input" :
			((buf[rc] & 0x80) ? "8-bit char on SMTP input" :
			 "Control chars on SMTP input")));
	    typeflush(SS);
	    continue;
	}
	if (c != '\n' && i > 3) {
	  /* Some bloody systems send:  "QUIT\r",
	     and then close the socket... */
	  if (cistrcmp(buf,"QUIT") == 0)
	    c = '\n'; /* Be happy... */
	}
	if (c != '\n') {
	    if (i < (sizeof(buf)-1))
	      type(SS, 500, m552, "Line not terminated with CRLF..");
	    else
	      type(SS, 500, m552, "Line too long (%d chars)", i);
	    continue;
	}
	if (verbose && !daemon_flg)
	    fprintf(stdout, "%s\n", buf);	/* XX: trace.. */
	report(SS, "%.100s", buf);

	for (cp = buf; isascii(*cp) && isalpha(*cp); ++cp)
	    continue;
	if (cp > buf + 6) {	/* "DEBUG" is longest of them.. */
	    type(SS, 550, m552, "Syntax error");
	    typeflush(SS);
	    continue;
	}
	c = *cp;
	if (c != '\0')
	    *cp = '\0';
	for (SS->carp = &command_list[0];
	     SS->carp->verb != NULL; SS->carp += 1) {
	    if (CISTREQ(SS->carp->verb, buf))
		break;
	}
	*cp++ = c;
	if (SS->carp->verb == NULL) {

	unknown_command:

	    type(SS, 550, m552, "Unknown command '%s'", buf);
	    zsyslog((LOG_WARNING,
		     "unknown SMTP command '%s' from %s/%d",
		     buf, SS->rhostname, SS->rport));
	    typeflush(SS);
	    continue;
	}

	if (SS->carp->cmd == DebugMode && ! debugcmdok)
	  goto unknown_command;
	if (SS->carp->cmd == Expand    && ! expncmdok)
	  goto unknown_command;
	if (SS->carp->cmd == Verify    && ! vrfycmdok)
	  goto unknown_command;

	if (policystatus != 0 &&
	    SS->carp->cmd != Quit && SS->carp->cmd != Help) {
	  type(SS, -400, "4.7.0", "Policy database problem, code=%d", policystatus);
	  type(SS,  400, "4.7.0", "With 'HELP' command you can get out contact information.");
	  typeflush(SS);
	  zsyslog((LOG_EMERG, "smtpserver policy database problem, code: %d", policystatus));
	  sleep(20);
	  continue;
	}
	if (SS->reject_net && SS->carp->cmd != Quit && SS->carp->cmd != Help) {
	    type(SS, -553, NULL, "You are on our reject-IP-address -list, GO AWAY!");
	    type(SS, -553, NULL, "If you feel we mistreat you, do contact us.");
	    type(SS, 553, NULL, "With 'HELP' command you can get out contact information.");
	    typeflush(SS);
	    continue;
	}

	switch (SS->carp->cmd) {
	case Null:
	    type(SS, 550, m550, "panic!");
	    typeflush(SS);
	    break;
	case Hello:
	case Hello2:
	    /* This code is LONG.. */
	    smtp_helo(SS, buf, cp);
	    typeflush(SS);
	    break;
	case Mail:
	case Mail2:
	case Send:
	case Send2:
	case SendOrMail:
	case SendAndMail:
	    /* This code is LONG.. */
	    smtp_mail(SS, buf, cp, insecure);
	    break;
	case Recipient:
	    /* This code is LONG.. */
	    smtp_rcpt(SS, buf, cp);
	    break;
	case Data:
	    if (smtp_data(SS, buf, cp) < 0)
		return;
	    break;
	case BData:
	    if (smtp_bdata(SS, buf, cp) < 0)
		return;
	    break;
	case Reset:
	    if (SS->mfp != NULL) {
		clearerr(SS->mfp);
		mail_abort(SS->mfp);
		SS->mfp = NULL;
	    }
	    if (SS->state != Hello)
		SS->state = MailOrHello;
	    type(SS, 250, m200, NULL);
	    typeflush(SS);
	    break;
	case Help:
	    help(SS, cfinfo, cp);
	    typeflush(SS);
	    break;
	case Verify:
	case Verify2:
	    smtp_verify(SS, buf, cp);
	    typeflush(SS);
	    break;
	case Expand:
	    smtp_expand(SS, buf, cp);
	    typeflush(SS);
	    break;
	case Turnme:
	    smtp_turnme(SS, SS->carp->verb, cp);
	    typeflush(SS);
	    break;
	case Turn:
	    type(SS, 502, m551, (char *) NULL);
	    typeflush(SS);
	    break;
	case NoOp:
	    type(SS, 250, m200, (char *) NULL);
	    typeflush(SS);
	    break;
	case Verbose:
	    type(SS, -250, m200, VerbID, Version);
	    type(SS, -250, m200, Copyright);
	    type(SS, 250, m200, Copyright2);
	    typeflush(SS);
	    SS->VerboseCommand = 1;
	    break;
	case DebugMode:
	    ++debug;
	    debug_report(SS, SS->VerboseCommand, SS->rhostname, buf);
	    typeflush(SS);
	    break;
	case DebugIdent:
	    setrfc1413ident(SS);
	    type(SS, 200, "", "RFC1413 identuser='%s'", SS->ident_username);
	    typeflush(SS);
	    break;
	case Tick:
	    type(SS, 250, m200, "%s", buf);
	    typeflush(SS);
	    SS->with_protocol = WITH_BSMTP;
	    break;
	case Quit:
	    if (SS->mfp != NULL)
		mail_abort(SS->mfp);
	    SS->mfp = NULL;
	    type(SS, 221, m200, NULL, "Out");
	    typeflush(SS);
	    return;
	default:
	    break;
	}
    }
    if (SS->mfp != NULL) {
	mail_abort(SS->mfp);
	SS->mfp = NULL;
	tell = lseek(0, 0, SEEK_CUR);
	reporterr(SS, tell, "session terminated");
    } else if (logfp != NULL) {
	fprintf(logfp, "%d-\tSession closed w/o QUIT\n", pid);
	fflush(logfp);
    }
}

#if 0				/* tmalloc() is in the library, isn't it ? */
univptr_t
tmalloc(n)
int n;
{
    return emalloc((u_int) n);
}
#endif


/* Flush the stdio (output) channel towards the SMTP client */

void typeflush(SS)
SmtpState *SS;
{
    fflush(SS->outfp);
}

/*
 * In theory, this should modify the command that ps shows for this process.
 * This is known to not be portable, hopefully it will break badly on systems
 * where it doesn't work.
 */

 void
#ifdef HAVE_STDARG_H
#ifdef __STDC__
 report(SmtpState * SS, const char *cp,...)
#else
 report(SS, cp)
SmtpState *SS;
const char *cp;
#endif
#else
/* VARARGS */
 report(va_alist)
va_dcl
#endif
{
    va_list ap;
    char buf[8192], *s;
    int cmdlen;

#ifdef HAVE_STDARG_H
    va_start(ap, cp);
#else
    SmtpState *SS;
    const char *cp;

    va_start(ap);
    SS = va_arg(ap, SmtpState *);
    cp = va_arg(ap, const char *);
#endif
    sprintf(buf, "<%s ", SS->rhostname);
    s = buf + strlen(buf);
#ifdef	HAVE_VPRINTF
    vsprintf(s, cp, ap);
#else				/* !HAVE_VPRINTF */
    sprintf(s, cp, va_arg(ap, char *));
#endif				/* HAVE_VPRINTF */
    cmdlen = (eocmdline - cmdline);
    if (cmdlen >= sizeof(buf))
	cmdlen = sizeof(buf) - 1;
    for (s = s + strlen(s); s < buf + cmdlen; ++s)
	*s = '\0';
    buf[cmdlen] = '\0';
    memcpy((char *) cmdline, buf, cmdlen);
    va_end(ap);
}

#ifdef HAVE_VPRINTF
#ifdef HAVE_STDARG_H
void
#ifdef __STDC__
 type(SmtpState * SS, const int Code, const char *status, const char *fmt,...)
#else				/* Non ANSI-C */
 type(SS, Code, status, fmt)
SmtpState *SS;
const int Code;
const char *status, *fmt;
#endif
#else
/* VARARGS2 */
void type(SS, Code, status, fmt, va_alist)
SmtpState *SS;
const int Code;
const char *status, *fmt;
va_dcl
#endif
#else				/* No VPRINTF */
/* VARARGS2 */
void type(SS, Code, status, fmt, s1, s2, s3, s4, s5, s6)
SmtpState *SS;
const int Code;
const char *status, *fmt, *s1, *s2, *s3, *s4, *s5, *s6;
#endif
{
    char format[256];		/* We limit the fill to 200+some */
    const char *text = NULL;
    char c;
    int code = Code;

    if (code < 0) {
	code = -code;
	c = '-';
    } else
	c = ' ';

    fprintf(SS->outfp, "%03d%c", code, c);
    if (status && status[0] != 0)
	fprintf(SS->outfp, "%s ", status);

    if (logfp != NULL) {
	fprintf(logfp, "%dw\t%03d%c", pid, code, c);
	if (status && status[0] != 0)
	    fprintf(logfp, "%s ", status);
    }
    switch (code) {
    case 211:			/* System status */
	text = "%s";
	break;
    case 214:			/* Help message */
	text = "%s";
	break;
    case 220:			/* Service ready */
	sprintf(format, "%.200s %%s", SS->myhostname);
	text = format;
	break;
    case 221:			/* Service closing transmission channel */
	sprintf(format, "%.200s %%s", SS->myhostname);
	text = format;
	break;
    case 250:			/* Requested mail action okay, completed */
	text = "Ok";
	break;
    case 251:			/* User not local; will forward to <forward-path> */
	text = "User not local; will forward to <%s>";
	break;
    case 252:			/* Cannot VRFY user, but will accept message and attempt delivery */
	text = "Cannot VRFY user, but will accept message and attempt delivery";
	break;
    case 354:			/* Start mail input; end with <CRLF>.<CRLF> */
	text = "Start mail input; end with <CRLF>.<CRLF>";
	break;
    case 421:			/* Service not available, closing transmission channel */
	sprintf(format, "%.200s %%s", SS->myhostname);
	text = format;
	break;
    case 450:			/* Requested mail action not taken: mailbox unavailable */
	text = "Requested mail action not taken: mailbox unavailable";
	break;
    case 451:			/* Requested action aborted: local error in processing */
	text = "Requested action aborted: local error in processing";
	break;
    case 452:			/* Requested action not taken: insufficient system storage */
	text = "Requested action not taken: insufficient storage";
	break;
    case 500:			/* Syntax error, command unrecognized */
	text = "Syntax error, command unrecognized";
	break;
    case 501:			/* Syntax error in parameters or arguments */
	text = "Syntax error in parameters or arguments";
	break;
    case 502:			/* Command not implemented */
	text = "Command not implemented";
	break;
    case 503:			/* Bad sequence of commands */
	text = "Bad sequence of commands";
	break;
    case 504:			/* Command parameter not implemented */
	text = "Command parameter not implemented";
	break;
    case 550:			/* Requested action not taken: mailbox unavailable */
	text = "Requested action not taken: mailbox unavailable";
	break;
    case 551:			/* User not local; please try <forward-path> */
	text = "User not local; please try <%s>";
	break;
    case 552:			/* Requested mail action aborted: exceeded storage allocation */
	text = "Requested mail action aborted: exceeded storage allocation";
	break;
    case 553:			/* Requested action not taken: mailbox name not allowed */
	text = "Requested action not taken: mailbox name not allowed";
	break;
    case 554:			/* Transaction failed */
	text = "Transaction failed";
	break;
    }
#ifdef HAVE_VPRINTF
    {
	va_list ap;
#ifdef HAVE_STDARG_H
	va_start(ap, fmt);
#else
	va_start(ap);
#endif
	if (fmt != NULL)
	    vfprintf(SS->outfp, fmt, ap);
	else
	    vfprintf(SS->outfp, text, ap);
	fprintf(SS->outfp, "\r\n");
	if (logfp != NULL) {
	    if (fmt != NULL)
		vfprintf(logfp, fmt, ap);
	    else
		vfprintf(logfp, text, ap);
	    fprintf(logfp, "\n");
	    fflush(logfp);
	}
	va_end(ap);
    }
#else
    if (fmt != NULL)
	fprintf(SS->outfp, fmt, s1, s2, s3, s4, s5, s6);
    else
	fprintf(SS->outfp, text, s1, s2, s3, s4, s5, s6);
    fprintf(SS->outfp, "\r\n");
    if (logfp != NULL) {
	if (fmt != NULL)
	    fprintf(logfp, fmt, s1, s2, s3, s4, s5, s6);
	else
	    fprintf(logfp, text, s1, s2, s3, s4, s5, s6);
	fprintf(logfp, "\n");
	fflush(logfp);
    }
#endif
}


void
#ifdef HAVE_STDARG_H
#ifdef __STDC__
 type821err(SmtpState * SS, const int code, const char *status,
	    const char *inbuf, const char *msg, ...)
#else
 type821err(SS, code, status, inbuf, msg)
SmtpState *SS;
const int code;
const char *status, *inbuf, *msg;
#endif
#else
/* VARARGS */
 type821err(va_alist)
va_dcl
#endif
{
    va_list ap;
    const char *s = inbuf + 3 + strlen(status) + 1;
    int maxcnt = 200;
    int abscode;
    const char *a1, *a2, *a3, *a4;

#ifdef HAVE_STDARG_H
    va_start(ap, msg);
#else
    SmtpState *SS;
    const int code;
    const char *status, *inbuf, *msg;

    SS = va_arg(ap, SmtpState *);
    code = va_arg(ap, const int);
    status = va_arg(ap, const char *);
    inbuf = va_arg(ap, const char *);
    msg = va_arg(ap, const char *);
#endif
    /* These are not always safe... but they should be ok
       if we are carrying  (char*)s or (int)s.. */
    a1 = va_arg(ap, const char *);
    a2 = va_arg(ap, const char *);
    a3 = va_arg(ap, const char *);
    a4 = va_arg(ap, const char *);

    abscode = (code < 0) ? -code : code;

    fprintf(SS->outfp, "%03d-%s ", abscode, status);
    if (logfp != NULL)
	fprintf(logfp, "%dw\t%03d-%s ", pid, abscode, status);
    while (s < rfc821_error_ptr && --maxcnt >= 0) {
	++s;
	putc(' ', SS->outfp);
	if (logfp != NULL)
	    putc(' ', logfp);
    }
    fprintf(SS->outfp, "^\r\n");
    if (logfp != NULL)
	fprintf(logfp, "^\n");

    type(SS, code, status, msg, a1, a2, a3, a4);

    va_end(ap);
}


static void setrfc1413ident(SS)
SmtpState *SS;
{
    volatile const char *cp;
    char identbuf[1024];

#if defined(AF_INET6) && defined(INET6)
    if (SS->raddr.v6.sin6_family == AF_INET6) {
	cp = ident_tcpuser9(AF_INET6, 16,
			    &SS->localsock.v6.sin6_addr,
			    &SS->raddr.v6.sin6_addr,
			    ntohs(SS->localsock.v6.sin6_port),
			    ntohs(SS->raddr.v6.sin6_port),
			    IDENT_TIMEOUT,
			    identbuf, sizeof(identbuf) - 1);
    } else
#endif
    if (SS->raddr.v4.sin_family == AF_INET)
	cp = ident_tcpuser9(AF_INET, 4,
			    &SS->localsock.v4.sin_addr,
			    &SS->raddr.v4.sin_addr,
			    ntohs(SS->localsock.v4.sin_port),
			    ntohs(SS->raddr.v4.sin_port),
			    IDENT_TIMEOUT,
			    identbuf, sizeof(identbuf) - 1);
    else {
	cp = "Unknown_type_of_remote_system_address!";
    }
    if (cp != NULL)
	strncpy(SS->ident_username, (char *) cp, MAXHOSTNAMELEN);
    else
	strncpy(SS->ident_username, "IDENT-CALL-FAULT", MAXHOSTNAMELEN);
}

void header_to_mime(buf, lenptr, maxlen)
char *buf;
int *lenptr;
int maxlen;
{
    /* XXX: HEADERS -> MIME-2 */
}

#ifdef USE_TRANSLATION
void header_from_mime(buf, lenptr, maxlen)
char *buf;
int *lenptr;
int maxlen;
{
    /* XXX: HEADERS -> MIME-2 */
}

#endif				/* USE_TRANSLATION */
