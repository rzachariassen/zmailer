/*
 *    Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *      This will be free software, but only when it is finished.
 */
/*
 *    Several extensive changes by Matti Aarnio <mea@nic.funet.fi>
 *      Copyright 1991-2002.
 */

/*
 * ZMailer SMTP server.
 */

#include "smtpserver.h"

const char *VerbID = "ZMailer SMTP server %s";
const char *Copyright = "Copyright 1990 Rayan S. Zachariassen";
const char *Copyright2 = "Copyright 1991-2000 Matti Aarnio";

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
    {"EHLO", Hello2},
			/* Normal stuff.. */
    {"HELO", Hello},
    {"LHLO", HelloL},
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
    {"TURNME", Turnme},
    {"ETRN", Turnme},	/* RFC 1985 */
			/* SMTP AUTH -- NetScape Way.. (RFC 2554) */
    {"AUTH", Auth},
			/* sendmail extensions */
    {"VERB", Verbose},
    {"ONEX", NoOp},
			/* Deprecated */
    {"SEND", Send},
    {"SOML", SendOrMail},
    {"SAML", SendAndMail},
    {"TURN", Turn},
			/* bsmtp extensions */
    {"TICK", Tick},
			/* 8-bit smtp extensions -- deprecated */
    {"EMAL", Mail2},
    {"ESND", Send2},
    {"ESOM", Send2},
    {"ESAM", Send2},
    {"EVFY", Verify2},
			/* To fool loosers.. */
    {"IDENT", DebugIdent},
    {"DEBUG", DebugMode},
			/* End of the list */
#ifdef HAVE_OPENSSL
    {"STARTTLS", StartTLS}, /* RFC 2487 */
#endif /* - HAVE_OPENSSL */

    {"550", Silent},	/* Some Windows SMTP systems are mixing their
			   threads - they send smtp server error messages
			   to stream where they should be sending SMTP
			   client verbs.. */

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
extern int contentpolicypid;
int router_status = 0;
FILE *logfp = NULL;
int   logfp_to_syslog = 0;
int D_alloc = 0;
int smtp_syslog = 0;
#ifdef USE_TRANSLATION
int X_translation = 0;
int X_8bit = 0;
int X_settrrc = 9;
#endif				/* USE_TRANSLATION */
int strict_protocol = 0;
int mustexit = 0;
int configuration_ok = 0;
int gotalarm;
int unknown_cmd_limit = 10;
int sum_sizeoption_value = 0;
int always_flush_replies = 0;

char   logtag[32];
time_t logtagepoch, now;

sigjmp_buf jmpalarm;		/* Return-frame for breaking smtpserver
				   when timeout hits.. */


char *helplines[HELPMAX + 2] = {NULL,};
char *hdr220lines[HDR220MAX + 2] = {NULL, };


const char *m200 = "2.0.0";
const char *m400 = "4.0.0";
const char *m430 = "4.3.0";
const char *m431 = "4.3.1";
const char *m443 = "4.4.3";
const char *m454 = "4.5.4";
const char *m471 = "4.7.1";
const char *m513 = "5.1.3";
const char *m517 = "5.1.7";
const char *m530 = "5.3.0";
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
long minimum_availspace = 5000000; /* 5 million bytes free, AT LEAST */
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
int MaxParallelConnections = 800; /* Total number of childs allowed */

int MaxErrorRecipients = 3;	/* Max number of recipients for a message
				   that has a "box" ( "<>" ) as its source
				   address. */
int percent_accept = -1;

int maxloadavg = 999;		/* Maximum load-average that is tolerated
				   with smtp-server actively receiving..
				   Default value of 999 is high enough
				   so that it will never block -- use
				   "-L 10" to define lower limit (10) */

int allow_source_route = 0;	/* When zero, do ignore source route address
				   "@a,@b:c@d" by collapsing it into "c@d" */

int rcptlimitcnt = 10000;	/* Allow up to 10 000 recipients for each
				   MAIL FROM. -- or tune this.. */

int debugcmdok = 0;
int expncmdok = 0;
int vrfycmdok = 0;
int use_ipv6 = 0;
int ident_flag = 0;
int do_whoson = 0;
int pipeliningok = 1;
int chunkingok = 1;
int enhancedstatusok = 1;
int multilinereplies = 1;
int enable_router = 0;		/* Off by default -- security */
int mime8bitok = 1;
int dsn_ok = 1;
int auth_ok = 0;
int ehlo_ok = 1;
int etrn_ok = 1;
int starttls_ok = 0;
int ssmtp_listen = 0;	   /* Listen on port TCP/465; deprecated SMTP in TLS */
int ssmtp_connected = 0;
int msa_mode = 0;
int deliverby_ok = -1;		/* FIXME: RFC 2852 */
etrn_cluster_ent etrn_cluster[MAX_ETRN_CLUSTER_IDX] = { {NULL,}, };
char *tls_cert_file = NULL;
char *tls_key_file  = NULL;
char *tls_CAfile    = NULL;
char *tls_CApath    = NULL;
int tls_loglevel    = 0;
int tls_enforce_tls = 0;
int tls_ccert_vd    = 1;
int tls_ask_cert    = 0;
int tls_req_cert    = 0;
int log_rcvd_whoson = 0;
int log_rcvd_ident  = 0;
int log_rcvd_authuser = 0;
int log_rcvd_tls_mode = 0;
int log_rcvd_tls_peer = 0;
int auth_login_without_tls = 0;
char *smtpauth_via_pipe = NULL;
Usockaddr bindaddr;
Usockaddr testaddr;
int bindaddr_set    = 0;
int testaddr_set    = 0;
u_short bindport = 0;
int bindport_set = 0;
int use_tcpwrapper = 0;
int tarpit_initial = 0;
int tarpit_exponent = 0;

int lmtp_mode = 0;	/* A sort-of RFC 2033 LMTP mode ;
			   this is MAINLY for debug purposes,
			   NOT for real use! */

int detect_incorrect_tls_use;
int force_rcpt_notify_never;

#ifndef	IDENT_TIMEOUT
#define	IDENT_TIMEOUT	5
#endif				/* IDENT_TIMEOUT */

#if defined(AF_INET6) && defined(INET6)
static const u_char zin6addrany[16] = 
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
const u_char zv4mapprefix[16] = 
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0};
#endif

static void setrfc1413ident __((SmtpState * SS));
static void setrhostname __((SmtpState *));
static RETSIGTYPE reaper __((int sig));
static RETSIGTYPE timedout __((int sig));
static RETSIGTYPE sigterminator __((int sig));
static void smtpserver __((SmtpState *, int insecure));


const char *msg_toohighload = "421 Sorry, the system is too loaded for email reception at the moment\r\n";	/* XX: ??? */

extern void type220headers __((SmtpState *SS, const int identflg, const char *xlatelang, const char *curtime));


extern void openlogfp __((SmtpState * SS, int insecure));
extern char taspid_encodechars[];

void openlogfp(SS, insecure)
SmtpState *SS;
int insecure;
{
    /* opening the logfile should be done before we reset the uid */
    struct tm *tt;

    time( & now );
    tt = gmtime(&now);
    pid = getpid();

    logtagepoch = now;

    /* %M%D%h%m%s_pid_ */

    sprintf( logtag, "%c%c%c%c%c%c%c",
	     taspid_encodechars[ tt->tm_mday-1 ],
	     taspid_encodechars[ tt->tm_hour   ],
	     taspid_encodechars[ tt->tm_min    ],
	     taspid_encodechars[ tt->tm_sec    ],
	     taspid_encodechars[ (pid >> 12) & 63 ],
	     taspid_encodechars[ (pid >>  6) & 63 ],
	     taspid_encodechars[ (pid      ) & 63 ] );

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
	    fcntl(fd, F_SETFD, fcntl(fd, F_GETFD, 0) | FD_CLOEXEC);
	    logfp = fdopen(fd, "a");
	    setvbuf(logfp, NULL, _IOFBF, BUFSIZ);
	    /* Line-buffered */
	}
#ifndef HAVE_ALLOCA
	if (logstyle != 0)
	    free(fname);
#endif
    } else
	logfp = NULL;
}

int main __((int, char **));

int main(argc, argv)
int argc;
char **argv;
{
    int inetd, errflg, raddrlen, s25, ssmtp, msgfd, version, i;
    const char *mailshare;
    char path[1024];
    int force_ipv4 = 0;
    int localsocksize;
    char *cfgpath = NULL;
    char *pidfile = PID_SMTPSERVER;
    int pidfile_set = 0;
    SmtpState SS;
    int childpid, sameipcount, childcnt;
    const char *t, *syslogflg;

    progname = argv[0] ? argv[0] : "smtpserver";
    cmdline = &argv[0][0];
    eocmdline = cmdline;
    for (i = 0; i < argc; ++i)
	eocmdline += strlen(argv[i]) + 1;


    setvbuf(stdout, NULL, _IOFBF, 8192);
    setvbuf(stderr, NULL, _IOLBF, 8192);

    syslogflg = getzenv("SYSLOGFLG");
    if (syslogflg == NULL)
      syslogflg = "";
    t = syslogflg;
    for ( ; *t ; ++t ) {
      if (*t == 's' || *t == 'S')
	break;
    }
    smtp_syslog = *t;

    memset(&SS, 0, sizeof(SS));
    memset(&bindaddr, 0, sizeof(bindaddr));
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
		       "?46aBC:d:ighl:np:tI:L:M:P:R:s:S:T:VvwX8"
#else /* xlate */
		       "?46aBC:d:ighl:np:tI:L:M:P:R:s:S:T:Vvw"
#endif /* xlate */
#else /* INET6 */
#ifdef USE_TRANSLATION
		       "?4aBC:d:ighl:np:tI:L:M:P:R:s:S:T:VvwX8"
#else
		       "?4aBC:d:ighl:np:tI:L:M:P:R:s:S:T:Vvw"
#endif /* xlate */
#endif /* INET6 */
#else /* __STDC__ */
		       "?"
		       "4"
#if defined(AF_INET6) && defined(INET6)
		       "6"
#endif
		       "aBC:d:ighl:n"
		       "p:t"
		       "I:L:M:P:R:s:S:T:Vvw"
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
	case 'g':		/* gullible */
	    skeptical = 0;
	    break;
	case 'h':		/* checkhelo */
	    checkhelo = 1;
	    break;
	case 'i':		/* interactive */
	    daemon_flg = 0;
	    break;
	case 'I':		/* PID file */
	    pidfile = optarg;
	    pidfile_set = 1;
	    break;
	case 'l':		/* log file(prefix) */

	    if (strcmp(optarg,"SYSLOG")==0) {
	      logfp_to_syslog = 1;
	      break;
	    }

	    logfile = optarg;

	    break;
	case 'L':		/* Max LoadAverage */
	    maxloadavg = atoi(optarg);
	    if (maxloadavg < 1)
		maxloadavg = 10;	/* Humph.. */
	    break;
	case 'M':
	    maxsize = atol(optarg);
	    if (maxsize < 0)
		maxsize = 0;
	    break;
	case 'n':		/* running under inetd */
	    inetd = 1;
	    break;
	case 'p':
	    bindport = atoi(optarg);
	    bindport_set = 1;
	    break;
	case 'P':
	    postoffice = strdup(optarg);
	    break;
	case 'R':		/* router binary used for verification */
	    routerprog = strdup(optarg);
	    break;
	case 's':		/* checking style */
	    if (strcmp(optarg,"strict")==0)
	      strict_protocol = 1;
	    else
	      style = strdup(optarg);
	    break;
	case 'S':		/* Log-suffix style */
	    logstyle = 0;
	    if (CISTREQ(optarg, "remote"))
		logstyle = 2;
	    else if (CISTREQ(optarg, "local"))
		logstyle = 1;
	    break;
	case 't':
	    ssmtp_connected = 1; /* If this connection should immediately
				    start the TLS negotiaion before SMTP
				    greeting -- and only then do SMTP greet. */
	    break;
	case 'T':
	  /* Enter in interactive mode claimed foreign source IPv4/IPv6
	     address, and then proceed to handle policy analysis as in
	     normal operational case. */

	    memset(&testaddr, 0, sizeof(testaddr));
	    testaddr_set = 1;
#if defined(AF_INET6) && defined(INET6)
	    if (CISTREQN(optarg,"[ipv6 ",6) ||
		CISTREQN(optarg,"[ipv6:",6) ||
		CISTREQN(optarg,"[ipv6.",6)) {
	      char *s = strchr(optarg,']');
	      if (s) *s = 0;
	      if (inet_pton(AF_INET6, optarg+6, &testaddr.v6.sin6_addr) < 1) {
		/* False IPv6 number literal */
		/* ... then we don't set the IP address... */
		testaddr_set = 0;
		fprintf(stderr,"smtpserver: -T option argument is not valid IPv6 address: [ipv6.hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:1.2.3.4]\n");
		++errflg;
	      }
	      testaddr.v6.sin6_family = AF_INET6;
	    } else
#endif
	      if (*optarg == '[') {
		char *s = strchr(optarg,']');
		if (s) *s = 0;
		if (inet_pton(AF_INET, optarg+1, &testaddr.v4.sin_addr) < 1) {
		  /* False IP(v4) number literal */
		  /* ... then we don't set the IP address... */
		  testaddr_set = 0;
		  fprintf(stderr,"smtpserver: -T option argument is not valid IPv4 address: [1.2.3.4]\n");
		  ++errflg;
		}
		testaddr.v4.sin_family = AF_INET;
	      } else {
		testaddr_set = 0;
		fprintf(stderr,"smtpserver: -T option argument must be wrapped inside brackets: [1.2.3.4]\n");
		++errflg;
	      }
	    break;
	case 'v':
	    verbose = 1;	/* in conjunction with -i */
	    break;
	case 'V':
	    prversion("smtpserver");
	    exit(0);
	    break; /* paranoia */
	case 'w':		/* Do Who-is-on query */
	    do_whoson = 1;
	    break;
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
		"Usage: %s [-46aBignVvw]\
 [-C cfgfile] [-s xx] [-L maxLoadAvg]\
 [-M SMTPmaxsize] [-R rtrprog] [-p port#]\
 [-P postoffice] [-l SYSLOG] [-l logfile] [-S 'local'|'remote']\
 [-I pidfile] [-T test-net-addr]\n"
#else /* __STDC__ */
		"Usage: %s [-4"
#if defined(AF_INET6) && defined(INET6)
		"6"
#endif
		"aBignVvw"
#ifdef USE_TRANSLATION
		"X8"
#endif
		"] [-C cfgfile] [-s xx] [-L maxLoadAvg]"
		" [-M SMTPmaxsize] [-R rtrprog] [-p port#]"
		" [-P postoffice] [-l logfile] [-S 'local'|'remote']"
		" [-I pidfile] [-T test-net-addr]\n"
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

    if (daemon_flg)
      if (lmtp_mode && (!bindport_set || (bindport_set && bindport == 25)))
	lmtp_mode = 0; /* Disable LMTP mode unless we are bound at other than
			  port 25. */

#ifdef HAVE_OPENSSL
    Z_init(); /* Some things for private processors */
#endif /* - HAVE_OPENSSL */
    if (!allow_source_route)
      allow_source_route = (getzenv("ALLOWSOURCEROUTE") != NULL);

    netconnected_flg = 0;

    if (!daemon_flg) {

      raddrlen = sizeof(SS.raddr);
      memset(&SS.raddr, 0, raddrlen);
      if (getpeername(SS.inputfd, (struct sockaddr *) &SS.raddr, &raddrlen)) {
	if (testaddr_set) {
	  netconnected_flg = 1;
	  memcpy(&SS.raddr, &testaddr, sizeof(testaddr));
	}
      } else {
	/* Got a peer name (it is a socket) */
	netconnected_flg = 1;
	if (SS.raddr.v4.sin_family != AF_INET
#ifdef AF_INET6
	    && SS.raddr.v4.sin_family != AF_INET6
#endif
	    ) {
	  /* well, but somebody uses socketpair(2)  which is
	     an AF_UNIX thing and sort of full-duplex pipe(2)... */
	  netconnected_flg = 0;
	}
	if (netconnected_flg) {
	  /* Lets figure-out who we are this time around -- we may be on
	     a machine with multiple identities per multiple interfaces,
	     or via virtual IP-numbers, or ... */
	  localsocksize = sizeof(SS.localsock);
	  if (getsockname(FILENO(stdin), (struct sockaddr *) &SS.localsock,
			  &localsocksize) != 0) {
	    /* XX: ERROR! */
	  }
	}
      }

      strcpy(SS.rhostname, "stdin");
      SS.rport = -1;
      SS.ihostaddr[0] = '\0';
      sprintf(SS.ident_username, "uid#%d@localhost", (int)getuid());

      /* INTERACTIVE */
      s_setup(&SS, FILENO(stdin), FILENO(stdout));
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
	raddrlen = sizeof(SS.raddr);
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

	if (netconnected_flg)
	  s_setup(&SS, FILENO(stdin), FILENO(stdin));
	else
	  s_setup(&SS, FILENO(stdin), FILENO(stdout));

	if (ident_flag != 0 && !daemon_flg)
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
	settrusteduser();	/* dig out the trusted user ID */
	openlogfp(&SS, daemon_flg);
#ifdef HAVE_WHOSON_H
	type(NULL,0,NULL,"connection from %s:%d ident: %s whoson: %s",
	     SS.rhostname, SS.rport, SS.ident_username, SS.whoson_data);
#else
	type(NULL,0,NULL,"connection from %s:%d ident: %s",
	     SS.rhostname, SS.rport, SS.ident_username);
#endif

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
	if (pidfile_set || (!bindport_set && !bindaddr_set)) {
	  /* Kill possible previous smtpservers now! */
	  if (killprevious(SIGTERM, pidfile) != 0) {
	    fprintf(stderr,
		    "%s: Can't write my pidfile!  Disk full ?\n",
		    progname);
	    exit(2);
	  }
	  fflush(stdout);
	  fflush(stderr);
	}

	ssmtp = -1;
#if defined(AF_INET6) && defined(INET6)

	/* Perhaps the system can grok the IPv6 - at least the headers
	   seem to indicate so, but like we know of Linux, the protocol
	   might not be loaded in, or some such...
	   If we are not explicitely told to use IPv6 only, we will try
	   here to use IPv6, and if successfull, register it!  */
	if (!use_ipv6 && !force_ipv4) {
	  s25 = socket(PF_INET6, SOCK_STREAM, 0 /* IPPROTO_IPV6 */ );
	  if (s25 >= 0) {
	    use_ipv6 = 1;	/* We can do it! */
	    close(s25);
	  }
	}
	if (force_ipv4) {
	  s25 = socket(PF_INET, SOCK_STREAM, 0 /* IPPROTO_IP   */ );
	  use_ipv6 = 0;
	} else if (use_ipv6) {
	  s25 = socket(PF_INET6, SOCK_STREAM, 0 /* IPPROTO_IPV6 */ );
	  if (s25 < 0) {	/* Fallback to the IPv4 mode .. */
	    s25 = socket(PF_INET, SOCK_STREAM, 0 /* IPPROTO_IP   */ );
	    use_ipv6 = 0;
	  }
	} else
	  s25 = socket(PF_INET, SOCK_STREAM, 0 /* IPPROTO_IP   */ );

	if (ssmtp_listen)
	  ssmtp = socket(use_ipv6 ? PF_INET6 : PF_INET, SOCK_STREAM, 0 );
#else
	s25 = socket(PF_INET, SOCK_STREAM, 0);
	if (ssmtp_listen)
	  ssmtp = socket(PF_INET, SOCK_STREAM, 0 );
#endif
	if (s25 < 0) {
	  fprintf(stderr,
		  "%s: socket(PF_INET%s, SOCK_STREAM): %s\n",
		  progname, (use_ipv6 ? "6" : ""), strerror(errno));
	  exit(1);
	}
	if (ssmtp_listen && ssmtp < 0) {
	  fprintf(stderr,
		  "%s: socket(PF_INET%s, SOCK_STREAM): %s\n",
		  progname, (use_ipv6 ? "6" : ""), strerror(errno));
	  exit(1);
	}
	i = 1;
	if (setsockopt(s25, SOL_SOCKET, SO_REUSEADDR, (caddr_t) & i, sizeof i) < 0) {
	  fprintf(stderr,
		  "%s: setsockopt(SO_REUSEADDR): %s\n",
		  progname, strerror(errno));
	  exit(1);
	}
	if (ssmtp >= 0 && setsockopt(ssmtp, SOL_SOCKET, SO_REUSEADDR, (caddr_t) & i, sizeof i) < 0) {
	  fprintf(stderr,
		  "%s: setsockopt(SO_REUSEADDR): %s\n",
		  progname, strerror(errno));
	  exit(1);
	}
#ifdef SO_REUSEPORT
	if (setsockopt(s25, SOL_SOCKET, SO_REUSEPORT, (caddr_t) & i, sizeof i) < 0) {
	  fprintf(stderr,
		  "%s: setsockopt(SO_REUSEPORT): %s\n",
		  progname, strerror(errno));
	  exit(1);
	}
	if (ssmtp >= 0 && setsockopt(ssmtp, SOL_SOCKET, SO_REUSEPORT, (caddr_t) & i, sizeof i) < 0) {
	  fprintf(stderr,
		  "%s: setsockopt(SO_REUSEPORT): %s\n",
		  progname, strerror(errno));
	  exit(1);
	}
#endif

#ifdef SO_RCVBUF
	if (TcpRcvBufferSize > 0)
	  if (setsockopt(s25, SOL_SOCKET, SO_RCVBUF,
			 (char *) &TcpRcvBufferSize,
			 sizeof(TcpRcvBufferSize)) < 0) {
	    fprintf(stderr, "%s: setsockopt(SO_RCVBUF): %s\n",
		    progname, strerror(errno));
	    exit(1);
	  }
	if (TcpRcvBufferSize > 0 && ssmtp >= 0)
	  if (setsockopt(ssmtp, SOL_SOCKET, SO_RCVBUF,
			 (char *) &TcpRcvBufferSize,
			 sizeof(TcpRcvBufferSize)) < 0) {
	    fprintf(stderr, "%s: setsockopt(SO_RCVBUF): %s\n",
		    progname, strerror(errno));
	    exit(1);
	  }
#endif
#ifdef SO_SNDBUF
	if (TcpXmitBufferSize > 0)
	  if (setsockopt(s25, SOL_SOCKET, SO_SNDBUF,
			 (char *) &TcpXmitBufferSize,
			 sizeof(TcpXmitBufferSize)) < 0) {
	    fprintf(stderr, "%s: setsockopt(SO_SNDBUF): %s\n",
		    progname, strerror(errno));
	    exit(1);
	  }
	if (TcpXmitBufferSize > 0 && ssmtp >= 0)
	  if (setsockopt(ssmtp, SOL_SOCKET, SO_SNDBUF,
			 (char *) &TcpXmitBufferSize,
			 sizeof(TcpXmitBufferSize)) < 0) {
	    fprintf(stderr, "%s: setsockopt(SO_SNDBUF): %s\n",
		    progname, strerror(errno));
	    exit(1);
	  }
#endif
	if (bindport <= 0) {
	  struct servent *service;
#ifdef	IPPORT_SMTP
	  bindport = IPPORT_SMTP;
#endif				/* !IPPORT_SMTP */
	  if ((service = getservbyname("smtp", "tcp")) == NULL) {
	    fprintf(stderr,
		    "%s: no SMTP service entry, using default\n",
		    progname);
	  } else
	    bindport = ntohs(service->s_port);
	}
#if defined(AF_INET6) && defined(INET6)
	if (use_ipv6) {

	  struct sockaddr_in6 si6;
	  memset(&si6, 0, sizeof(si6));
	  si6.sin6_family = AF_INET6;
	  si6.sin6_flowinfo = 0;
	  si6.sin6_port = htons(bindport);
	  memcpy( &si6.sin6_addr, zin6addrany, 16 );
	  if (bindaddr_set && bindaddr.v6.sin6_family == AF_INET6)
	    memcpy(&si6.sin6_addr, &bindaddr.v6.sin6_addr, 16);

	  i = bind(s25, (struct sockaddr *) &si6, sizeof si6);
	  if (i < 0) {
	    fprintf(stderr, "%s: bind(IPv6): %s\n",
		    progname, strerror(errno));
	    exit(1);
	  }
	  if (ssmtp >= 0) {
	    memset(&si6, 0, sizeof(si6));
	    si6.sin6_family = AF_INET6;
	    si6.sin6_flowinfo = 0;
	    si6.sin6_port = htons(465); /* Deprecated SMTP/TLS WKS port */
	    memcpy( &si6.sin6_addr, zin6addrany, 16 );
	    if (bindaddr_set && bindaddr.v6.sin6_family == AF_INET6)
	      memcpy(&si6.sin6_addr, &bindaddr.v6.sin6_addr, 16);
	    i = bind(ssmtp, (struct sockaddr *) &si6, sizeof si6);
	  }
	} else
#endif
	  {
	    struct sockaddr_in si4;

	    memset(&si4, 0, sizeof(si4));
	    si4.sin_family = AF_INET;
	    si4.sin_addr.s_addr = INADDR_ANY;
	    si4.sin_port = htons(bindport);
	    if (bindaddr_set && bindaddr.v4.sin_family == AF_INET)
	      memcpy(&si4.sin_addr, &bindaddr.v4.sin_addr, 4);

	    i = bind(s25, (struct sockaddr *) &si4, sizeof si4);
	    if (i < 0) {
	      fprintf(stderr, "%s: bind(IPv4): %s\n",
		      progname, strerror(errno));
	      exit(1);
	    }
	    if (ssmtp >= 0) {
	      memset(&si4, 0, sizeof(si4));
	      si4.sin_family = AF_INET;
	      si4.sin_addr.s_addr = INADDR_ANY;
	      si4.sin_port = htons(465); /* Deprecated SMTP/TLS WKS port */
	      if (bindaddr_set && bindaddr.v4.sin_family == AF_INET)
		memcpy(&si4.sin_addr, &bindaddr.v4.sin_addr, 4);

	      i = bind(ssmtp, (struct sockaddr *) &si4, sizeof si4);
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


	fd_nonblockingmode(s25);
	if (listen(s25, ListenQueueSize) < 0) {
	  fprintf(stderr, "%s: listen(smtp_sock,%d): %s\n",
		  progname, ListenQueueSize, strerror(errno));
	  exit(1);
	}

	if (ssmtp >= 0) {
	  fd_nonblockingmode(ssmtp);
	  if (listen(ssmtp, ListenQueueSize) < 0) {
	    fprintf(stderr, "%s: listen(ssmtp_sock,%d): %s\n",
		    progname, ListenQueueSize, strerror(errno));
	  }
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

	if (pidfile_set || (!bindport_set && !bindaddr_set)) {
	  sleep(3); /* Give a moment to possible previous server
		       to die away... */
	  killprevious(0, pidfile);	/* deposit pid */
	}
#if 1
	pid = getpid();
	openlogfp(&SS, daemon_flg);
	if (logfp != NULL) {
	  char *cp, *ssmtps = "";
	  char *tt;
	  if (ssmtp >= 0)
	    ssmtps = " including deprecated SMTP/TLS port TCP/465";
	  time(&now);
	  cp = rfc822date(&now);
	  tt = strchr(cp, '\n'); if (tt) *tt = 0;
	  zsyslog((LOG_INFO, "server started."));
	  fprintf(logfp, "000000000#\tstarted server pid %d at %s%s\n", pid, cp, ssmtps);
	  /*fprintf(logfp,"000000000#\tfileno(logfp) = %d",fileno(logfp)); */
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
	SIGNAL_HANDLE(SIGTERM, sigterminator);
	while (!mustexit) {
	  fd_set rdset;
	  int n;

	  _Z_FD_ZERO(rdset);
	  _Z_FD_SET(s25, rdset);
	  if (ssmtp >= 0)
	    _Z_FD_SET(ssmtp, rdset);
	  n = s25;
	  if (n < ssmtp) n = ssmtp;
	  ++n;
	  n = select(n, &rdset, NULL, NULL, NULL);

	  if (n == 0) /* Timeout can't really happen here.. */
	    continue;
	  if (n < 0) {
	    /* various interrupts can happen here.. */
	    if (errno == EBADF || errno == EINVAL) break;
	    if (errno == ENOMEM) sleep(1); /* Wait a moment, then try again */
	    continue;
	  }

	  /* Ok, here the  select()  has reported that we have something
	     appearing in the listening socket(s).
	     We are simple, and try them in order.. */

	  n = -1;
	  if (s25   >= 0 && _Z_FD_ISSET(s25,   rdset)) n = s25;
	  if (ssmtp >= 0 && _Z_FD_ISSET(ssmtp, rdset)) n = ssmtp;


	  raddrlen = sizeof(SS.raddr);
	  msgfd = accept(n, (struct sockaddr *) &SS.raddr, &raddrlen);
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
	    zsyslog((LOG_INFO, "accept() error=%d (%s)", err, strerror(err)));
	    if (logfp) {
	      fprintf(logfp, "0000000000#\taccept(): %s; %s",
		      strerror(err), (char *) rfc822date(&now));
	      fclose(logfp);
	      logfp = NULL;
	    }
	    continue;
	  }

	  sameipcount = childsameip(&SS.raddr, &childcnt);
	  /* We query, and warn the remote when
	     the count exceeds the limit, and we
	     simply -- and FAST -- reject the
	     remote when it exceeds 4 times the
	     limit */
	  if (sameipcount > 4 * MaxSameIpSource) {
	    close(msgfd);
	    continue;
	  }
	    
	  if (childcnt > 100+MaxParallelConnections) {
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

	    if (n == ssmtp) ssmtp_connected = 1;

	    close(s25);	/* Listening socket.. */
	    if (ssmtp >= 0)
	      close(ssmtp); /* another of them */

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

	    s_setup(&SS, msgfd, msgfd);

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
#ifdef HAVE_WHOSON_H
	    type(NULL,0,NULL,
		 "connection from %s ipcnt %d childs %d ident: %s whoson: %s",
		 SS.rhostname, sameipcount, childcnt,
		 SS.ident_username, SS.whoson_data);
#else
	    type(NULL,0,NULL,
		 "connection from %s ipcnt %d childs %d ident: %s",
		 SS.rhostname, sameipcount, childcnt,
		 SS.ident_username);
#endif

	    /* if (logfp) type(NULL,0,NULL,"Input fd=%d",getpid(),msgfd); */

	    if (childcnt > MaxParallelConnections) {
	      int len;
	      char msg[200];
	      sprintf(msg, "450-Too many simultaneous connections to this server (%d max %d)\r\n", childcnt, MaxParallelConnections);
	      len = strlen(msg);
	      if (write(msgfd, msg, len) != len) {
		sleep(2);
		exit(1);	/* Tough.. */
	      }
	      strcpy(msg, "450 Come again latter\r\n");
	      len = strlen(msg);
	      write(msgfd, msg, len);
	      close(0); close(1); close(2);
#if 1
	      sleep(2);	/* Not so fast!  We need to do this to
			   avoid (as much as possible) the child
			   to exit before the parent has called
			   childregister() -- not so easy to be
			   100% reliable (this isn't!) :-( */
#endif
	      exit(0);	/* Now exit.. */
	    }
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
	      close(0); close(1); close(2);
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
	    close(0); close(1); close(2);

	    if (routerpid > 0)
	      killr(&SS, routerpid);
	    if (contentpolicypid > 1)
	      killr(&SS, contentpolicypid);

	    if (netconnected_flg)
	      sleep(2);
	    _exit(0);
	  }
	}
	/* Stand-alone server, kill the pidfile at the exit! */
	killpidfile(pidfile);
	openlogfp(&SS, daemon_flg);
	zsyslog((LOG_INFO, "killed server."));
	if (logfp != NULL) {
	  char *cp;
	  time(&now);
	  cp = rfc822date(&now);
	  fprintf(logfp, "000000000#\tkilled server pid %d at %s", pid, cp);
	  fclose(logfp);
	  logfp = NULL;
	}
      }
    if (routerpid > 0)
	killr(&SS, routerpid);
    if (contentpolicypid > 1)
      killr(&SS, contentpolicypid);
    if (netconnected_flg)
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

	    if (memcmp((void *) ip6, zv4mapprefix, 12) == 0)
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
    /* Return to the smtpserver's main-program.
       We are commiting a suicide, but we need
       data that exists only in that context... */
    gotalarm = 1;
    mustexit = 1;

    siglongjmp(jmpalarm, 1);
    _exit(253);			/* We did return ?!?! Boo!! */
}

static RETSIGTYPE
 sigterminator(sig)
int sig;
{
  SIGNAL_HANDLE(sig, sigterminator);
  mustexit = 1;
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
	if (lpid == contentpolicypid && contentpolicypid > 1) {
	  contentpolicypid = -lpid;
	}

	childreap(lpid);
    }
    SIGNAL_HANDLE(SIGCHLD, reaper);
}

void reporterr(SS, tell, msg)
SmtpState *SS;
const long tell;
const char *msg;
{
    time( & now );

    zsyslog((LOG_ERR,
	     "%s%04d - aborted (%ld bytes) from %s/%d: %s",
	     logtag, (int)(now-logtagepoch), tell, SS->rhostname, SS->rport, msg));
    if (logfp != NULL) {
	fprintf(logfp, "%s%04d - aborted (%ld bytes): %s\n", logtag, (int)(now-logtagepoch), tell, msg);
	fflush(logfp);
    }
}


int
Z_write(SS, ptr, len)
     SmtpState * SS;
     const void *ptr;
     int len;
{
    int i, rc = 0;
    char *buf = (char *)ptr;

    while (len > 0) {
      i = SS->sslwrspace - SS->sslwrin; /* space */
      if (i == 0) {
	/* The buffer is full! Flush it */
	typeflush(SS);
	if (gotalarm) break;
	i = SS->sslwrspace;
      }
      /* Copy only as much as can fit into current space */
      if (i > len) i = len;
      memcpy(SS->sslwrbuf + SS->sslwrin, buf, i);
      SS->sslwrin += i;
      buf += i;
      len -= i;
      rc += i;
    }

    /* how much written out ? */
    return rc;
}

void typeflush(SS)
SmtpState *SS;
{
    int len = SS->sslwrin - SS->sslwrout;
    int rc;
    time_t expiry_epoch;

    time(&expiry_epoch);
    expiry_epoch += SMTP_REPLY_ALARM_IVAL;

    while (len > 0) {

#ifdef HAVE_OPENSSL
      if (SS->sslmode)
	rc = Z_SSL_flush(SS);
      else
#endif /* - HAVE_OPENSSL */
	rc = write(SS->outputfd, SS->sslwrbuf + SS->sslwrout, len);
      if (rc > 0) {
	len          -= rc;
	SS->sslwrout += rc;
	continue;
      }
      if (rc < 0 && (errno == EAGAIN || errno == EINTR)) {
	/* Wait for write-space, or timeout! */

	fd_set wrset;
	fd_set rdset;
	struct timeval tv;
	time_t now;
	int fd = SS->outputfd;

	_Z_FD_ZERO(rdset);
	_Z_FD_ZERO(wrset);
	time(&now);

	if (expiry_epoch <= now)
	  tv.tv_sec = 1;
	else
	  tv.tv_sec = expiry_epoch - now;
	tv.tv_usec = 0;

	if (rc == -1)
	  _Z_FD_SET(fd, wrset);
	else
	  _Z_FD_SET(SS->inputfd, rdset);  /* SSL Want Read! */

	if (SS->inputfd > fd)
	  fd = SS->inputfd;

	rc = select(fd+1, &rdset, &wrset, NULL, &tv);
	if (rc == 0) {
	  /* TIMEOUT! */
	  gotalarm = 1;
	  SS->s_status = EOF;
	  break;
	}
	/* rc < 0 --> redo.. */
	/* rc > 0 --> have write-space! */
      } else
	break;
    } /* ... while() */


    /* Even with errors -- we have  'gotalarm' and s_status set
       so that the connection should abort on spot... */

    SS->sslwrout = SS->sslwrin = 0; /* Buffer done */
}


#ifndef HAVE_OPENSSL

int
Z_read(SS, ptr, len)
     SmtpState * SS;
     void *ptr;
     int len;
{
    return read(SS->inputfd, ptr, len);
}

int
Z_pending(SS)
     SmtpState * SS;
{
    return 0;
}

#endif /* --HAVE_OPENSSL */

/* Support routine: Our own buffering for stdinput */

int s_feof(SS)
SmtpState *SS;
{
    return SS->s_status;
}

int s_getc(SS, timeout_is_fatal)
     SmtpState *SS;
     int timeout_is_fatal;
{
    int rc = 0;

    if (SS->s_ungetcbuf >= 0) {
      rc = SS->s_ungetcbuf;
      SS->s_ungetcbuf = -1;
      return rc;
    }

    if (SS->s_status)
	return SS->s_status;

    if (SS->s_readout >= SS->s_bufread) {

        time_t expiry_epoch = time(NULL) + SS->read_alarm_ival;

    redo:

        /* We are about to read... */

	if (rc < 0 && SS->inputfd >= 0) {
	
	  fd_set rdset;
	  fd_set wrset;
	  struct timeval tv;
	  time_t now;
	  int fd = SS->inputfd;

	  _Z_FD_ZERO(rdset);
	  _Z_FD_ZERO(wrset);
	  time(&now);

	  if (expiry_epoch <= now)
	    tv.tv_sec = 1;
	  else
	    tv.tv_sec = expiry_epoch - now;
	  tv.tv_usec = 0;

	  if (rc == -2) /* SSL Want Write ! */
	    _Z_FD_SET(SS->outputfd, wrset);
	  else
	    _Z_FD_SET(SS->inputfd, rdset);

	  if (SS->outputfd > fd)
	    fd = SS->outputfd;

	  rc = select(fd+1, &rdset, &wrset, NULL, &tv);

	  if (rc == 0) {
	    /* TIMEOUT! */
	    if (timeout_is_fatal) {
	      gotalarm = 1;
	      SS->s_status = EOF;
	    }
	    return EOF;
	  }
	  /* rc < 0 ??? */
	  /* rc > 0 --> we have something to read! */
	}

	rc = Z_read(SS, SS->s_buffer, sizeof(SS->s_buffer));
	SS->s_readerrno = 0;
	if (rc < 0) {
	  SS->s_readerrno = errno;
	  if (errno == EINTR || errno == EAGAIN) {
	    goto redo;
	  }
	  /* The read returned.. */
	  /* Other results are serious errors -- maybe */
	  SS->s_status = EOF;
	  return EOF;
	}
	/* We did read successfully! */
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
    int i = Z_pending(SS);
    if (i) return i;

    if (SS->s_readout >= SS->s_bufread) {
        /* So if it did dry up, try non-blocking read */
	SS->s_readout = 0;
	
	SS->s_bufread = Z_read(SS, SS->s_buffer, sizeof(SS->s_buffer));
	if (SS->s_bufread > 0)
	    return SS->s_bufread;
	return 0;
    }
    return (SS->s_bufread - SS->s_readout);
}

void s_ungetc(SS, ch)
     SmtpState *SS;
     int ch;
{
	SS->s_ungetcbuf = ch;
}


int s_gets(SS, buf, buflen, rcp, cop, cp)
SmtpState *SS;
char *buf, *cop, *cp;
int buflen, *rcp;
{
	int c, co = -1;
	int i = -1, rc = -1;

	if (!pipeliningok || !s_hasinput(SS))
	  typeflush(SS);

	/* Alarm processing on the SMTP protocol channel */
	SS->read_alarm_ival = SMTP_COMMAND_ALARM_IVAL;

	/* Our own  fgets() -- gets also NULs, flags illegals.. */
	--buflen;
	while ((c = s_getc(SS, 1)) != EOF && i < buflen) {
	    if (c == '\n') {
		buf[++i] = c;
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
	    buf[++i] = c;
	    co = c;
	}
	buf[++i] = '\0';

	if (c == EOF && i == 0) {
	    /* XX: ???  Uh, Hung up on us ? */
	    if (SS->mfp != NULL)
		mail_abort(SS->mfp);
	    SS->mfp = NULL;
	}

	/* Zap the ending newline */
	if (c  == '\n') buf[i-1] = '\0';
	/* Zap the possible preceeding \r */
	if (co == '\r') buf[i-2] = '\0';

	*cop = co;
	*cp  = c;
	*rcp = rc;

	if (i >= buflen && c != EOF && c != '\n') {
	  /* Huh, oversized input line ?? */
	  while ((c = s_getc(SS, 1)) != EOF && c != '\n')
	    ;
	  /* Input eaten until a NEWLINE, or EOF occurred at the input. */
	}

	return i;
}


void s_setup(SS, infd, outfd)
SmtpState *SS;
int infd;
{
    SS->inputfd  = infd;
    SS->outputfd = outfd;
    SS->s_status = 0;
    SS->s_bufread   = -1;
    SS->s_ungetcbuf = -1;
    SS->s_readout = 0;

    fd_nonblockingmode(infd);
    fd_nonblockingmode(outfd);
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
    int localport;

#ifdef USE_TRANSLATION
    char lang[4];

    lang[0] = '\0';
#endif
    SS->VerboseCommand = 0;

    SS->tarpit = tarpit_initial;

    stashmyaddresses(NULL);

    pid = getpid();
    if (!logfp)
	openlogfp(SS, insecure);

    runastrusteduser();

    if (!netconnected_flg)
      strict_protocol = 0;

    fd_nonblockingmode(SS->inputfd);  /* redundant ? */
    fd_nonblockingmode(SS->outputfd); /* redundant ? */

    rc = sigsetjmp(jmpalarm,1);
    if (rc != 0) {
	/* Oooo...  We are returning here via  longjmp(),
	   which means we just got a timeout (SIGALRM),
	   which for us is instant death.. */
	tell = 0;
	if (SS->mfp != NULL) {
	    fseek(SS->mfp, 0, SEEK_END);
	    tell = ftell(SS->mfp);
	}
	{
	  char msgbuf[40];
	  sprintf(msgbuf,"SMTP protocol timed out (%d sec)",
		  SS->read_alarm_ival);
	  reporterr(SS, tell, msgbuf);
	}

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
	if (contentpolicypid > 1)
	  killr(SS, contentpolicypid);
	exit(0);
    }
    report(SS, "(connected)");
    now = time((time_t *) 0);
    cp = (char *) rfc822date(&now);

    if (*(cp + strlen(cp) - 1) == '\n') {
      *(cp + strlen(cp) - 1) = '\0';
    }

#if defined(AF_INET6) && defined(INET6)
    if (SS->localsock.v6.sin6_family == AF_INET6) {
	struct in6_addr *ip6 = &SS->localsock.v6.sin6_addr;

	localport = ntohs(SS->localsock.v6.sin6_port);

	/* If it is IPv4 mapped address to IPv6, then resolve
	   the IPv4 address... */

	if (memcmp((void *) ip6, zv4mapprefix, 12) == 0)
	    hostent = gethostbyaddr(((char *) ip6) + 12, 4, AF_INET);
	else
	    hostent = gethostbyaddr((char *) ip6, 16, AF_INET6);
    } else
#endif
      {
	localport = ntohs(SS->localsock.v4.sin_port);

	hostent = gethostbyaddr((void *) &SS->localsock.v4.sin_addr, 4, AF_INET);
      }

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

    if (localport != 25 && detect_incorrect_tls_use) {
      int c;
      int aval = SS->read_alarm_ival;

      SS->read_alarm_ival = 2;
      c = s_getc(SS, 0);

      SS->read_alarm_ival = aval;

      if (c >= 0) {
	s_ungetc(SS, c);
#ifdef HAVE_OPENSSL
	/* THIS IS KLUDGE!!!
	   Microsoft Outlook sExpress (not sure if it was that,
	   and not one of those other Outlooks...) has a nasty
	   misfunction of starting the TLS right away when the
	   destination port at the server is not 25, and "USE TLS"
	   flag is set...
	 */

	if (c == 0x80) {
	  ssmtp_connected = 1;
	}
#endif /* - HAVE_OPENSSL */
      }
    }

    /* Actually all modes use this write-out buffer */
    SS->sslwrbuf = emalloc(8192);
    SS->sslwrspace = 8192;
    SS->sslwrin = SS->sslwrout = 0;

#ifdef HAVE_OPENSSL
    if (ssmtp_connected) {
      if (tls_start_servertls(SS)) {
	/* No dice... */
	exit(2);
      }
    }
#endif /* - HAVE_OPENSSL */


#ifdef HAVE_WHOSON_H
    if (do_whoson && netconnected_flg) {
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
    } else {
	strcpy(SS->whoson_data,"NOT-CHECKED");
	SS->whoson_result = -1;
    }
    policystatus     = policyinit(&policydb, &SS->policystate,
				  SS->whoson_result);
#else
    policystatus     = policyinit(&policydb, &SS->policystate, 0);
#endif
    if (!netconnected_flg && policystatus < 0)
      policystatus = 0; /* For internal - non-net-connected - mode
			   lack of PolicyDB is no problem at all.. */

    if (debug) typeflush(SS);
    SS->policyresult = policytestaddr(policydb, &SS->policystate,
				      POLICY_SOURCEADDR,
				      (void *) &SS->raddr);
    SS->reject_net = (SS->policyresult < 0);
    if (debug) typeflush(SS);
    if (SS->policyresult == 0) /* Alternates to this condition are:
				  Always reject, or Always freeze.. */
      SS->policyresult = policytest(policydb, &SS->policystate,
				    POLICY_SOURCEDOMAIN,
				    SS->rhostname,strlen(SS->rhostname),
				    SS->authuser);

    /* re-opening the log ?? */
    zopenlog("smtpserver", LOG_PID, LOG_MAIL);

#ifdef USE_TCPWRAPPER
#ifdef HAVE_TCPD_H		/* TCP-Wrapper code */
    if (use_tcpwrapper && netconnected_flg &&
	wantconn(SS->inputfd, "smtp-receiver") == 0) {
	zsyslog((LOG_WARNING, "refusing connection from %s:%d/%s",
		 SS->rhostname, SS->rport, SS->ident_username));
	type(SS, 421, NULL, "%s ZMailer Server %s WILL NOT TALK TO YOU at %s",
	     SS->myhostname, VersionNumb, cp);
	typeflush(SS);
	sleep(2);
	exit(0);
    }
#endif
#endif

    if (SS->reject_net) {
	char *msg = policymsg(policydb, &SS->policystate);
	smtp_tarpit(SS);
	if (msg != NULL) {
	  type(SS, -550, NULL, "%s", msg);
	} else {
	  type(SS, -550, NULL, "%s - You are on our reject-IP-address -list, GO AWAY!",
	       SS->myhostname);
	}
	type(SS, -550, NULL, "If you feel we mistreat you, do contact us.");
	type(SS, 550, NULL, "Ask HELP for our contact information.");
    } else
#ifdef USE_TRANSLATION
	if (hdr220lines[0] == NULL) {
	  hdr220lines[0] = "%H ZMailer Server %V ESMTP%I (%X) ready at %T";
	}
	type220headers(SS, ident_flag, X_settrrc ? "nulltrans" : lang, cp);
#if 0
	type(SS, 220, NULL, "%s ZMailer Server %s ESMTP%s (%s) ready at %s",
	     SS->myhostname, VersionNumb, ident_flag ? "+IDENT" : "",
	     X_settrrc ? "nulltrans" : lang, cp);
#endif
#else				/* USE_TRANSLATION */
	if (hdr220lines[0] == NULL) {
	  hdr220lines[0] = "%H ZMailer Server %V ESMTP%I ready at %T";
	}
	type220headers(SS, ident_flag, "", cp);
#if 0
	type(SS, 220, NULL, "%s ZMailer Server %s ESMTP%s ready at %s",
	     SS->myhostname, VersionNumb, ident_flag ? "+IDENT" : "", cp);
#endif
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
    {
	char *s = policymsg(policydb, &SS->policystate);
	if (insecure)
	  type(NULL,0,NULL,"remote from %s:%d", SS->ihostaddr, SS->rport);
	else
	  type(NULL,0,NULL,"local from uid#%d", (int)getuid());
	if (SS->policyresult != 0 || s != NULL)
	  type(NULL,0,NULL,"-- policyresult=%d initial policy msg: %s",
	       SS->policyresult, (s ? s : "<NONE!>"));
	if (logfp)
	  fflush(logfp);
    }
    while (1) {

	char buf[SMTPLINESIZE];	/* limits size of SMTP commands...
				   On the other hand, limit is asked
				   to be only 1000 chars, not 8k.. */
	char *eobuf;
	char c, co;
	int i;

	if (always_flush_replies)
	  typeflush(SS);

	i = s_gets(SS, buf, sizeof(buf), &rc, &co, &c );

	if (i <= 0)	/* EOF ??? */
	  break;

	if (s_hasinput(SS))
	  if (logfp || logfp_to_syslog)
	    type(NULL,0,NULL,
		 "-- pipeline input exists %d bytes", s_hasinput(SS));


	eobuf = &buf[i-1];	/* Buf end ptr.. */

	/* Chop the trailing spaces */
	if (!strict_protocol) {
	  while ((eobuf > buf) && (eobuf[-1] == ' ' ||
				   eobuf[-1] == '\t'))
	    *--eobuf = '\0';
	} else if (strict_protocol &&
		   eobuf > buf && (eobuf[-1] == ' ' ||
				   eobuf[-1] == '\t')) {
	  /* XX: Warn about trailing whitespaces on inputs!
	     ... except that this is likely *wrong* place, as
	     there are many varying input syntaxes... */
	}
				   
	if (logfp_to_syslog || logfp) time( & now );

	if (logfp_to_syslog)
	  zsyslog((LOG_DEBUG, "%s%04d r %s", logtag, (int)(now-logtagepoch), buf));

	if (logfp) {
	    fprintf(logfp, "%s%04dr\t%s\n", logtag, (int)(now-logtagepoch), buf);
	    fflush(logfp);
	}
	if (rc >= 0 && !strict_protocol) {
	  if (CISTREQN(buf,"HELO",4) ||
	      CISTREQN(buf,"EHLO",4))
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
	if (!strict_protocol && c != '\n' && i > 3) {
	  /* Some bloody systems send:  "QUIT\r",
	     and then close the socket... */
	  if (CISTREQ(buf,"QUIT") == 0) {
	    co = '\r';
	    c = '\n'; /* Be happy... */
	  }
	}
	if ((strict_protocol && (c != '\n' || co != '\r')) || (c != '\n')) {
	    if (i < (sizeof(buf)-1))
		type(SS, 500, m552, "Line not terminated with CRLF..");
	    else
		type(SS, 500, m552, "Line too long (%d chars)", i);
	    continue;
	}
	if (verbose && !daemon_flg)
	    fprintf(stdout, "%s\n", buf);	/* XX: trace.. */
	report(SS, "%.100s", buf);

	for (cp = buf; (c = *cp) && isascii(c & 0xFF) && isalnum(c & 0xFF); ++cp)
	    continue;

	if (cp > buf + 8)	/* "DEBUG" is longest of them.. */
	  goto unknown_command;

	c = *cp;
	if (c != '\0')
	    *cp = '\0';
	for (SS->carp = &command_list[0];
	     SS->carp->verb != NULL; SS->carp += 1) {
	    if (CISTREQ(SS->carp->verb, buf))
		break;
	}
	*cp = c;
	if (SS->carp->verb == NULL) {

	unknown_command:

	    ++SS->unknown_cmd_count;

	    if (SS->unknown_cmd_count >= unknown_cmd_limit) {
	      type(SS, 550, m552, "One too many unknown command '%s'", buf);
	      typeflush(SS);
	      break;
	    }

	    smtp_tarpit(SS);

	    type(SS, 550, m552, "Unknown command '%s'", buf);
	    zsyslog((LOG_WARNING,
		     "unknown SMTP command '%s' from %s/%d",
		     buf, SS->rhostname, SS->rport));
	    typeflush(SS);
	    continue;
	}

	/* RFC 2033 rules */
	if (!lmtp_mode && SS->carp->cmd == HelloL)
	  goto unknown_command;
	if (lmtp_mode && (SS->carp->cmd == Hello || SS->carp->cmd == Hello2))
	  goto unknown_command;

	if (SS->carp->cmd == DebugMode && ! debugcmdok)
	  goto unknown_command;
	if (SS->carp->cmd == Expand    && ! expncmdok)
	  goto unknown_command;
	if (SS->carp->cmd == Verify    && ! vrfycmdok)
	  goto unknown_command;
	if (SS->carp->cmd == Verify2   && ! vrfycmdok)
	  goto unknown_command;
	if (SS->carp->cmd == Hello2    && ! ehlo_ok)
	  goto unknown_command;
	if (SS->carp->cmd == Turnme    && ! etrn_ok)
	  goto unknown_command;
	if (SS->carp->cmd == Auth      && ! auth_ok)
	  goto unknown_command;
	if (SS->carp->cmd == BData     && ! chunkingok)
	  goto unknown_command;

	/* Lack of configuration is problem only with network connections */
	if (netconnected_flg && !configuration_ok) {
	  smtp_tarpit(SS);
	  type(SS, -400, "4.7.0", "This SMTP server has not been configured!");
	  typeflush(SS);
	  zsyslog((LOG_EMERG, "smtpserver configuration missing!"));
	  sleep(20);
	  continue;
	}
	if (policystatus != 0 &&
	    SS->carp->cmd != Quit && SS->carp->cmd != Help) {
	  smtp_tarpit(SS);
	  type(SS, -400, "4.7.0", "Policy database problem, code=%d", policystatus);
	  type(SS,  400, "4.7.0", "With 'HELP' command you can get our contact information.");
	  typeflush(SS);
	  zsyslog((LOG_EMERG, "smtpserver policy database problem, code: %d", policystatus));
	  sleep(20);
	  continue;
	}
	if (SS->reject_net && SS->carp->cmd != Quit && SS->carp->cmd != Help) {
	    smtp_tarpit(SS);
	    type(SS, -550, NULL, "You are on our reject-IP-address -list, GO AWAY!");
	    type(SS, -550, NULL, "If you feel we mistreat you, do contact us.");
	    type(SS, 550, NULL, "With 'HELP' command you can get out contact information.");
	    typeflush(SS);
	    continue;
	}


	if ( msa_mode && SS->authuser == NULL &&
	     !(SS->policystate.always_accept || SS->policystate.full_trust) ) {
	  switch (SS->carp->cmd) {
#ifdef HAVE_OPENSSL
	  case StartTLS:
#endif /* - HAVE_OPENSSL */
	  case Auth:
	  case Hello:
	  case Hello2:
	  case NoOp:
	  case Reset:
	  case Quit:
	    break;
	  default:
	    type(SS, 530, m530, "Authentication required" );
	    typeflush(SS);
	    continue;
	  }
	}

	switch (SS->carp->cmd) {
	case Silent:
	    /* We are SILENT - no response at all! */
	    break;
	case Null:
	    type(SS, 550, m550, "panic!");
	    typeflush(SS);
	    break;
#ifdef HAVE_OPENSSL
	case StartTLS:
#if 0 /* A debug thing.. */
	    always_flush_replies = 1;
#endif
	    smtp_starttls(SS, buf, cp);
	    break;
#endif /* - HAVE_OPENSSL */
	case Hello:
	case Hello2:
	case HelloL:
	    /* This code is LONG.. */
	    smtp_helo(SS, buf, cp);
	    typeflush(SS);
	    break;
	case Auth:
	    smtp_auth(SS, buf, cp);
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

	    if (smtp_data(SS, buf, cp) < 0) {
#ifdef HAVE_OPENSSL
	      Z_cleanup(SS);
#endif /* - HAVE_OPENSSL */
	      return;
	    }
	    break;
	case BData:

	    if (smtp_bdata(SS, buf, cp) < 0) {
#ifdef HAVE_OPENSSL
	      Z_cleanup(SS);
#endif /* - HAVE_OPENSSL */
	      return;
	    }
	    break;
	case Reset:
	    if (*cp != 0 && strict_protocol) {
	      type(SS, 501, m554, "Extra junk after 'RSET' verb");
	      break;
	    }
	    if (SS->mfp != NULL) {
		clearerr(SS->mfp);
		mail_abort(SS->mfp);
		SS->mfp = NULL;
	    }
	    if (SS->state != Hello)
		SS->state = MailOrHello;
	    type(SS, 250, m200, "Reset processed, now waiting for MAIL command");
	    SS->policyresult = 0; /* Clear this state too */
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
	    if (*cp != 0 && STYLE(SS->cfinfo,'R')) {
	      type(SS, -502, m554, "Extra junk after 'TURN' verb");
	    }
	    type(SS, 502, m551, (char *) NULL);
	    typeflush(SS);
	    break;
	case NoOp:
	    if (*cp != 0 && STYLE(SS->cfinfo,'R')) {
	      type(SS, 501, m554, "Extra junk after 'NOOP' verb");
	      break;
	    }
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
	    if (*cp != 0 && STYLE(SS->cfinfo,'R')) {
	      type(SS, -221, m554, "Extra junk after 'QUIT' verb");
	    }
	    if (SS->mfp != NULL)
		mail_abort(SS->mfp);
	    SS->mfp = NULL;
	    type(SS, 221, m200, NULL, "Out");
	    typeflush(SS);
#ifdef HAVE_OPENSSL
	    Z_cleanup(SS);
#endif /* - HAVE_OPENSSL */
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
	type(NULL,0,NULL,"Session closed w/o QUIT; read() errno=%d",
	     SS->s_readerrno);
	fflush(logfp);
    }
#ifdef HAVE_OPENSSL
    Z_cleanup(SS);
#endif /* - HAVE_OPENSSL */
}

#if 0				/* tmalloc() is in the library, isn't it ? */
univptr_t
tmalloc(n)
int n;
{
    return emalloc((u_int) n);
}
#endif


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
    memcpy((char *) cmdline, buf, cmdlen+1);
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
void
type(SS, Code, status, fmt, va_alist)
SmtpState *SS;
const int Code;
const char *status, *fmt;
va_dcl
#endif
#else				/* No VPRINTF */
/* VARARGS2 */
void
type(SS, Code, status, fmt, s1, s2, s3, s4, s5, s6)
SmtpState *SS;
const int Code;
const char *status, *fmt, *s1, *s2, *s3, *s4, *s5, *s6;
#endif
{
    char format[256];		/* We limit the fill to 200+some */
    const char *text = NULL;
    char c, *s;
    int code = Code, buflen;
    char buf[6000];

    if (code < 0) {
	code = -code;
	c = '-';
    } else
	c = ' ';

    if (!SS)
      *buf = 0;
    else {
      if (code >= 999)
	sprintf(buf, "000%c", c);
      else
	sprintf(buf, "%03d%c", code, c);
      if (enhancedstatusok && status && status[0] != 0)
	sprintf(buf+4, "%s ", status);
    }
    s = strlen(buf)+buf;

    switch (code) {
    case 211:			/* System status */
	text = "%s";
	break;
    case 214:			/* Help message */
	text = "%s";
	break;
    case 220:			/* Service ready */
    case 221:			/* Service closing transmission channel */
    case 421:			/* Service not available, closing transmission channel */
	if (SS)
	  sprintf(format, "%.200s %%s", SS->myhostname);
	else
	  strcpy(format,"hostname-unavailable %s");
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
    default:
	text = "code unknown, program bug!";
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
	    vsprintf(s, fmt, ap);
	else
	    vsprintf(s, text, ap);
	va_end(ap);
    }
#else
    if (fmt != NULL)
	sprintf(s, fmt, s1, s2, s3, s4, s5, s6);
    else
	sprintf(s, text, s1, s2, s3, s4, s5, s6);
#endif
    s += strlen(s);
    buflen = s - buf;

    if (buflen+4 > sizeof(buf)) {
      /* XXX: Buffer overflow ??!! Signal about it, and crash! */
    }

    if (logfp_to_syslog || logfp) time( & now );

    if (logfp_to_syslog)
      zsyslog((LOG_DEBUG,"%s%04d %c %s", logtag, (int)(now - logtagepoch), (SS ? 'w' : '#'), buf));

    if (logfp != NULL) {
      fprintf(logfp, "%s%04d%c\t%s\n", logtag, (int)(now - logtagepoch), (SS ? 'w' : '#'), buf);
      fflush(logfp);
    }
    if (!SS) return; /* Only to local log.. */
    memcpy(s, "\r\n", 2);
    Z_write(SS, buf, buflen+2); /* XX: check return value */
}

/*
 *  type220headers() outputs the initial greeting header(s), and
 *  does it without need for SSL wrapping.
 */

void
type220headers(SS, identflg, xlatelang, curtime)
     SmtpState *SS;
     const int identflg;
     const char *xlatelang;
     const char *curtime;
{
    char *s, **hh = hdr220lines;
    char linebuf[8000];
    char *l, *le;

    /* We collect the line into single buffer, then output it in one go
       with the code below.  This to ensure that it will (very likely)
       be written out in single syscall -- some systems get mighty upset
       when they receive multiple TCP segments of the initial greeting :-/ */

    for (; *hh ; ++hh) {
      char c = (hh[1] == NULL) ? ' ' : '-';
      
      le = linebuf + sizeof(linebuf) -1;
      l  = linebuf;

      /* The format meta-tags:
       *
       *  %% -- '%' character
       *  %H -- SS->myhostname
       *  %I -- '+IDENT' if 'identflg' is set
       *  %V -- VersionNumb
       *  %T -- curtime string
       *  %X -- xlatelang parameter
       */

      s = *hh;
      while (*s && l < le) {
	if (*s == '%') {
	  int freespc = le-l;
	  int len;

	  ++s;
	  switch (*s) {
	  case '%':
	    *l++ = '%';
	    break;
	  case 'H':
	    len = strlen(SS->myhostname);
	    memcpy(l, SS->myhostname, freespc < len ? freespc : len);
	    l += len;
	    break;
	  case 'I':
	    if (identflg) {
	      len = 6;
	      memcpy(l, "+IDENT", freespc < len ? freespc : len);
	      l += len;
	    }
	    break;
	  case 'V':
	    len = strlen(VersionNumb);
	    memcpy(l, VersionNumb, freespc < len ? freespc : len);
	    l += len;
	    break;
	  case 'T':
	    len = strlen(curtime);
	    memcpy(l, curtime, freespc < len ? freespc : len);
	    l += len;
	    break;
	  case 'X':
	    if (!xlatelang) xlatelang = "";
	    len = strlen(xlatelang);
	    memcpy(l, xlatelang, freespc < len ? freespc : len);
	    l += len;
	    break;
	  default:
	    /* Duh ?? */
	    break;
	  }
	} else {
	  *l++ = *s;
	}
	if (*s) ++s;
      }
      if (l < le)
	*l = 0;
      *le = 0;

      if (c == ' ')
	type(SS,  220, NULL, "%s", linebuf);
      else
	type(SS, -220, NULL, "%s", linebuf);
    }
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
    int maxcnt = 200;
    int abscode, buflen;
    const char *a1, *a2, *a3, *a4;
    const char *s;
    char buf[2000], *bp;

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

    s = inbuf + 3 + 1;

    /* These are not always safe... but they should be ok
       if we are carrying  (char*)s or (int)s.. */
    a1 = va_arg(ap, const char *);
    a2 = va_arg(ap, const char *);
    a3 = va_arg(ap, const char *);
    a4 = va_arg(ap, const char *);

    abscode = (code < 0) ? -code : code;

    if (multilinereplies) {
      if (enhancedstatusok) {
	sprintf(buf, "%03d-%s ", abscode, status);
	s += strlen(status) +1;
      } else { /* No status codes */
	sprintf(buf, "%03d- ", abscode);
	++s;
      }
      bp = buf + strlen(buf);
      while (s < rfc821_error_ptr && --maxcnt >= 0) {
	++s;
	*bp++ = ' ';
      }
      *bp++ = '^';
      *bp = 0;

      buflen = bp - buf;

      if (logfp_to_syslog || logfp) time( & now );

      if (logfp_to_syslog)
	zsyslog((LOG_DEBUG, "%s%04d w %s", logtag, (int)(now - logtagepoch), buf));
      if (logfp)
	fprintf(logfp, "%s%04dw\t%s\n", logtag, (int)(now - logtagepoch), buf);

      strcpy(bp, "\r\n");
      Z_write(SS, buf, buflen+2); /* XX: check return value */
    }

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


void smtp_tarpit(SS)
     SmtpState *SS;
{
    if (SS->tarpit) {
	if (SS->tarpit < 0 || SS->tarpit > 250)
	    SS->tarpit = 250;
	sleep(SS->tarpit);
	SS->tarpit += (SS->tarpit * tarpit_exponent);
    }
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
