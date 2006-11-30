/*
 *    Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *      This will be free software, but only when it is finished.
 */
/*
 *    Several extensive changes by Matti Aarnio <mea@nic.funet.fi>
 *      Copyright 1991-2006.
 */

/*
 * ZMailer SMTP server.
 */

#include "smtpserver.h"

const char *VerbID = "ZMailer SMTP server %s";
const char *Copyright = "Copyright 1990 Rayan S. Zachariassen";
const char *Copyright2 = "Copyright 1991-2004 Matti Aarnio";

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
    {"Z-IDENT", DebugIdent},
    {"Z-DEBUG", DebugMode},
			/* End of the list */
#ifdef HAVE_OPENSSL
    {"STARTTLS", StartTLS}, /* RFC 2487 */
#endif /* - HAVE_OPENSSL */
    {"Z-REPORT", Report},

    {"550", Silent},	/* Some Windows SMTP systems are mixing their
			   threads - they send smtp server error messages
			   to stream where they should be sending SMTP
			   client verbs.. */

    {0, Null}
};

struct smtpconf *cfhead;
struct smtpconf *cfinfo;

const char *progname, *cmdline, *eocmdline, *logfile;
char *routerprog;
int logstyle;		/* 0: no suffix, 1: 'myhostname', 2: 'rhostname' */
int debug;
int skeptical = 1;
int checkhelo;
int verbose;
int daemon_flg = 1;
int debug_no_stdout;
int pid;
int router_status;
int ident_flag;
int use_ipv6;
int msa_mode;

FILE *logfp;
int   logfp_to_syslog;
int D_alloc;
int smtp_syslog;
#ifdef USE_TRANSLATION
int X_translation;
int X_8bit;
int X_settrrc = 9;
#endif				/* USE_TRANSLATION */
int strict_protocol;
volatile int mustexit;		/* set from within signal handler */ 
int configuration_ok;
volatile int gotalarm;		/* set from within signal handler */ 
int unknown_cmd_limit = 10;
int sum_sizeoption_value;
int always_flush_replies;
volatile int sawsigchld;	/* set from within signal handler */ 

etrn_cluster_ent       etrn_cluster       [MAX_ETRN_CLUSTER_IDX];
smtpserver_cluster_ent smtpserver_cluster [MAX_SMTPSERVER_CLUSTER_IDX];

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
long minimum_availspace = 5000; /* 5 million bytes free, AT LEAST */
long maxsize;

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

int percent_accept = -1;


int maxloadavg = 999;		/* Maximum load-average that is tolerated
				   with smtp-server actively receiving..
				   Default value of 999 is high enough
				   so that it will never block -- use
				   "-L 10" to define lower limit (10) */

int allow_source_route;		/* When zero, do ignore source route address
				   "@a,@b:c@d" by collapsing it into "c@d" */

ConfigParams CPdefault;
ConfigParams *CP;  /* Config & Setup time pointer */
ConfigParams *OCP; /* Operational time pointer    */
ConfigParams **CPpSet;
int CPpSetSize;

static void CPdefault_init __((void));
static void CPdefault_init()
{

  CP = &CPdefault;
  CPpSet = (void*)malloc(sizeof(void**)*2);
  CPpSetSize = 1;
  CPpSet[0] = CP;
  CPpSet[1] = NULL;

  CP->ListenQueueSize  = 20000;
  CP->MaxErrorRecipients = 3;	/* Max number of recipients for a message
				   that has a "box" ( "<>" ) as its source
				   address. */

  CP->rcptlimitcnt = 10000;	/* Allow up to 10 000 recipients for each
				   MAIL FROM. -- or tune this.. */

  CP->pipeliningok = 1;
  CP->chunkingok = 1;
  CP->enhancedstatusok = 1;
  CP->multilinereplies = 1;
  CP->MaxSLBits = 1000000;	/* a HIGH value */
  CP->mime8bitok = 1;
  CP->dsn_ok = 1;
  CP->ehlo_ok = 1;
  CP->etrn_ok = 1;

  CP->deliverby_ok = -1;		/* FIXME: RFC 2852 */
  CP->tls_ccert_vd    = 1;
}

void ConfigParams_newgroup()
{
  ConfigParams *CPn = malloc(sizeof(*CP));
  if (CPn) {
    /* Copy everything from CPdefaults -- initially we did set defaults.. */
    *CPn = *(&CPdefault);
    CP = CPn;
    CPpSet = realloc(CPpSet, sizeof(void**)*(CPpSetSize+2));
    if (!CPpSet) {
    out_of_memory:;
      type(NULL,0,NULL,"OUT OF MEMORY!");
      exit(64);
    }
    CPpSet[CPpSetSize] = CP;
    ++CPpSetSize;

    /* Now clean/duplicate those set elements,
       that are reallocated at PARAM keyword processing */
    
    CP->bindaddr_set = 0;
    CP->bindaddrs       = NULL;
    CP->bindaddrs_types = NULL;
    CP->bindaddrs_ports = NULL;
    CP->bindaddrs_count = 0;

  } else
    goto out_of_memory;
}



/* int submit_connected; */
int ssmtp_connected;
int do_whoson;

int testaddr_set;
Usockaddr testaddr;

int bindport_set;
u_short bindport;

int lmtp_mode;	/* A sort-of RFC 2033 LMTP mode ;
		   this is MAINLY for debug purposes,
		   NOT for real use! */

int detect_incorrect_tls_use;
int force_rcpt_notify_never;

const char *contact_pointer_message="Ask HELP for our contact information.";

#define LSOCKTYPE_SMTP 0
#define LSOCKTYPE_SSMTP 1
#define LSOCKTYPE_SUBMIT 2



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

extern int pipeauthchild_pid; /* zpwmatch-pipe.c */
extern int pipeauthchild_status;

static RETSIGTYPE reaper   __((int sig));
static RETSIGTYPE timedout __((int sig));
static RETSIGTYPE sigterminator __((int sig));
static void smtpserver __((SmtpState *, int insecure));
static void s_setup  __((SmtpState * SS, int infd, int outfd));



const char *msg_toohighload = "421 Sorry, the system is too loaded for email reception at the moment\r\n";	/* XX: ??? */

extern void type220headers __((SmtpState *SS, const int identflg, const char *xlatelang, const char *curtime));


extern void openlogfp __((SmtpState * SS, int insecure));
extern const char taspid_encodechars[];

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

    if (SS) {
      sprintf( logtag, "%c%c%c%c%c%c%c",
	       taspid_encodechars[ tt->tm_mday-1 ],
	       taspid_encodechars[ tt->tm_hour   ],
	       taspid_encodechars[ tt->tm_min    ],
	       taspid_encodechars[ tt->tm_sec    ],
	       taspid_encodechars[ (pid >> 12) & 63 ],
	       taspid_encodechars[ (pid >>  6) & 63 ],
	       taspid_encodechars[ (pid      ) & 63 ] );
    } else {
      strcpy(logtag, "0000000");
      logtagepoch = 0;
    }

    if (logfp != NULL)
	fclose(logfp);
    logfp = NULL;

    if (logfile != NULL) {
	char *fname;
	int len1 = strlen(logfile);
	int len2, fd;
	const char *s = "";
	if (SS) {
	  if (logstyle == 1)
	    s = SS->myhostname;
	  if (logstyle == 2)
	    s = SS->rhostname;
	}
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


static void create_server_socket __((ConfigParams *, int *, int **, int **,
				     ConfigParams ***,
				     int, int, int, Usockaddr * ));

static void create_server_socket (CP, lscnt_p, ls_p, lst_p, lsCP_p, lsocktype, use_ipv6, portnum, bindaddr)
     ConfigParams *CP, ***lsCP_p;
     int *lscnt_p, **ls_p, **lst_p;
     int use_ipv6, portnum, lsocktype;
     Usockaddr *bindaddr;
{
	int s, i = use_ipv6;
	char buf[80];

	if (use_ipv6) {
	  if (bindaddr && bindaddr->v4.sin_family == AF_INET) {
#if 1
	    return; /* We are supposed to create IPv6 socket, but
		       have IPv4 address...  Lets not. */
#else
	    use_ipv6 = 0;
#endif
	  }
	}

	if (bindaddr) {
	  switch(bindaddr->v4.sin_family) {
	  case AF_INET:
	    inet_ntop(AF_INET, &bindaddr->v4.sin_addr, buf, sizeof(buf));
	    break;
#if defined(AF_INET6) && defined(INET6)
	  case AF_INET6:
	    inet_ntop(AF_INET6, &bindaddr->v6.sin6_addr, buf, sizeof(buf));
	    break;
#endif
	  default:
	    sprintf(buf, "Unknown socket address family: %d\n",
		    bindaddr->v4.sin_family);
	    break;
	  }
	} else {
#if defined(AF_INET6) && defined(INET6)
	  if (use_ipv6)
	    strcpy(buf, "0::0");
	  else
#endif
	    strcpy(buf, "0.0.0.0");
	}


	s = socket(
#ifdef PF_INET6
		   use_ipv6 ? PF_INET6 : PF_INET,
#else
		   PF_INET,
#endif
		   SOCK_STREAM, 0 /* IPPROTO_IP   */ );

	if (s < 0) {
	  fprintf(stderr,
		  "%s: socket(PF_INET%s, SOCK_STREAM): %s\n",
		  progname, (use_ipv6 ? "6" : ""), strerror(errno));
	  return;
	}

	*ls_p              = realloc( *ls_p,  sizeof(int) * ((*lscnt_p) +2));
	*lst_p             = realloc( *lst_p, sizeof(int) * ((*lscnt_p) +2));
	*lsCP_p            = realloc( *lsCP_p, sizeof(void*)*((*lscnt_p) +2));
	if (! *ls_p ||  ! *lst_p || ! *lsCP_p) {
	  fprintf(stderr, "%s: malloc() failure!\n", progname);
	  exit(1);
	}

	(*ls_p  )[ *lscnt_p ] = s;
	(*lst_p )[ *lscnt_p ] = lsocktype;
	(*lsCP_p)[ *lscnt_p ] = CP;

	*lscnt_p += 1;

	type(NULL,0,NULL,"setting up: bind(s=%d, v%d, addr='%s' port=%d)",
	     s, i ? 6 : 4, buf, portnum);


	i = 1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (caddr_t) & i, sizeof i) < 0) {
	  fprintf(stderr,
		  "%s: setsockopt(SO_REUSEADDR): %s\n",
		  progname, strerror(errno));
	}
#ifdef SO_REUSEPORT
	if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (caddr_t) & i, sizeof i) < 0) {
	  fprintf(stderr,
		  "%s: setsockopt(SO_REUSEPORT): %s\n",
		  progname, strerror(errno));
	}
#endif
#ifdef SO_RCVBUF
	if (CP->TcpRcvBufferSize > 0)
	  if (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
			 (char *) &CP->TcpRcvBufferSize,
			 sizeof(CP->TcpRcvBufferSize)) < 0) {
	    fprintf(stderr, "%s: setsockopt(SO_RCVBUF): %s\n",
		    progname, strerror(errno));
	  }
#endif
#ifdef SO_SNDBUF
	if (CP->TcpXmitBufferSize > 0)
	  if (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
			 (char *) &CP->TcpXmitBufferSize,
			 sizeof(CP->TcpXmitBufferSize)) < 0) {
	    fprintf(stderr, "%s: setsockopt(SO_SNDBUF): %s\n",
		    progname, strerror(errno));
	  }
#endif
#if defined(AF_INET6) && defined(INET6)
	if (use_ipv6) {

	  int on = 1;
	  struct sockaddr_in6 si6;
	  memset(&si6, 0, sizeof(si6));
	  si6.sin6_family = AF_INET6;
	  si6.sin6_flowinfo = 0;
	  si6.sin6_port = htons(portnum);
	  memcpy( &si6.sin6_addr, zin6addrany, 16 );
	  if (bindaddr && bindaddr->v6.sin6_family == AF_INET6)
	    memcpy(&si6.sin6_addr, &bindaddr->v6.sin6_addr, 16);

#ifdef IPV6_V6ONLY
	  /* Bind us only to IPv6, if we can... */
	  setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (void*)&on, sizeof(on));
#endif

	  i = bind(s, (struct sockaddr *) &si6, sizeof si6);
	  if (i < 0) {
	    type(NULL,0,NULL,"bind(s=%d, v6, port=%d) failed; errno=%s",
		 s, portnum, strerror(errno));
	    close(s);

	    *lscnt_p -= 1;
	  }

	} else
#endif
	  {
	    struct sockaddr_in si4;
	    
	    memset(&si4, 0, sizeof(si4));
	    si4.sin_family = AF_INET;
	    si4.sin_addr.s_addr = INADDR_ANY;
	    si4.sin_port = htons(portnum);
	    if (bindaddr && bindaddr->v4.sin_family == AF_INET)
	      memcpy(&si4.sin_addr, &bindaddr->v4.sin_addr, 4);
	    
	    i = bind(s, (struct sockaddr *) &si4, sizeof si4);
	    if (i < 0) {
	      type(NULL,0,NULL,"bind(s=%d, v4, port=%d) failed; errno=%s",
		   s, portnum, strerror(errno));
	      close(s);

	      *lscnt_p -= 1;
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


	fd_nonblockingmode(s);

	if (listen(s, CP->ListenQueueSize) < 0) {
	  fprintf(stderr, "%s: listen(smtp_sock,%d): %s\n",
		  progname, CP->ListenQueueSize, strerror(errno));
	}
}


int main __((const int, char **, const char **));

int main(argc, argv, envp)
     const int argc;
     char **argv;
     const char **envp;
{
	int inetd, errflg, version, i = 0;
	const char *mailshare;
	char path[1024];
	int force_ipv4 = 0;
	char *cfgpath = NULL;
	char *pidfile = PID_SMTPSERVER;
	int pidfile_set = 0;
	const char *t, *syslogflg;
	unsigned int localsocksize; /* Solaris: size_t, new BSD: socklen_t */
	unsigned int raddrlen;

	SmtpState SS;

	struct zmpollfd *pollfds = NULL;

	progname = argv[0] ? argv[0] : "smtpserver";
	cmdline = &argv[0][0];
	eocmdline = argv[argc-1] + strlen(argv[argc-1]) + 1;


	setvbuf(stdout, NULL, _IOFBF, 8192);
	setvbuf(stderr, NULL, _IOLBF, 8192);

	memset(&SS, 0, sizeof(SS));

	CPdefault_init();

	SS.mfp = NULL;
	SS.style = "ve";
	SS.with_protocol_set = 0;

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
			 "?46aBC:d:ighl:np:tI:L:M:P:R:s:S:T:VvwZ:X8"
#else /* xlate */
			 "?46aBC:d:ighl:np:tI:L:M:P:R:s:S:T:VvwZ:"
#endif /* xlate */
#else /* INET6 */
#ifdef USE_TRANSLATION
			 "?4aBC:d:ighl:np:tI:L:M:P:R:s:S:T:VvwZ:X8"
#else
			 "?4aBC:d:ighl:np:tI:L:M:P:R:s:S:T:VvwZ:"
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
			 "I:L:M:P:R:s:S:T:VvwZ:"
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
#if AF_INET6 == 0
	    ::ERROR::ERROR: AF_INET6 has CPP value ZERO!
#endif
	    use_ipv6 = AF_INET6;
	    break;
#endif
	  case 'a':
	    ident_flag = 1;
	    break;
	  case 'B':
	    SS.with_protocol_set |= WITH_BSMTP;
	    break;
	  case 'C':
	    cfgpath = strdup(optarg); /* leaks memory, but lets be
					 consistent and save all data .. */
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
	    /* The '-I' option has dual meaning! */
	    pidfile = strdup(optarg); /* Make a safe copy now */
	    pidfile_set = 1;
	    break;
	  case 'l':		/* log file(prefix) */

	    if (strcmp(optarg,"SYSLOG")==0) {
	      logfp_to_syslog = 1;
	      break;
	    }

	    logfile = strdup(optarg); /* We MAY overwrite argv[] data
					 latter!  Make safe copy now! */

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
	    else if (strcmp(optarg,"sloppy")==0)
	      strict_protocol = -1;
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
	  case 'Z':
	    if (readzenv(optarg) == 0)
	      ++errflg;
	    break;
	  default:
	    fprintf(stderr,
		    "%s: Unknown option, c=%d ('%c')\n", progname, c, c);
	    ++errflg;
	    break;
	  }
	}

	syslogflg = getzenv("SYSLOGFLG");
	if (syslogflg == NULL)
	  syslogflg = "";
	t = syslogflg;
	for ( ; *t ; ++t ) {
	  if (*t == 's' || *t == 'S')
	    break;
	}
	smtp_syslog = *t;


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
 [-I pidfile] [-T test-net-addr] [-Z zenvfile]\n"
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
		  " [-I pidfile] [-T test-net-addr] [-Z zenvfile]\n"
#endif /* __STDC__ */
		  , progname);
	  exit(1);
	}
	pid = getpid();
	if (!logfp)
	  openlogfp(NULL, daemon_flg);
	

	/* The automatic "system can do ipv6" testing controls
	   "use_ipv6" variable, which in turn controls what
	   may happen in  readcffile()  */

#if defined(AF_INET6) && defined(INET6)
	/* Perhaps the system can grok the IPv6 - at least the headers
	   seem to indicate so, but like we know of Linux, the protocol
	   might not be loaded in, or some such...
	   If we are not explicitely told to use IPv6 only, we will try
	   here to use IPv6, and if successfull, register it!  */
	if (!use_ipv6 && !force_ipv4) {
	  int s = socket(PF_INET6, SOCK_STREAM, 0 /* IPPROTO_IPV6 */ );
	  if (s >= 0) {
	    use_ipv6 = AF_INET6;	/* We can do it! */
	    close(s);
	  }
	}
	  
	if (use_ipv6) {
	  int s = socket(PF_INET6, SOCK_STREAM, 0 /* IPPROTO_IPV6 */ );
	  if (s < 0) {	/* Fallback to the IPv4 mode .. */
	    s = socket(PF_INET, SOCK_STREAM, 0 /* IPPROTO_IP   */ );
	    use_ipv6 = 0;
	  }
	  close(s);
	}
#endif


	mailshare = getzenv("MAILSHARE");
	if (mailshare == NULL)
	  mailshare = MAILSHARE;
	if (cfgpath == NULL) {
	  char *t = strrchr(progname, '/');
	  if (t != NULL)
	    sprintf(path, "%s/%s.conf", mailshare, t + 1);
	  else
	    sprintf(path, "%s/%s.conf", mailshare, progname);
	}

	if (cfgpath == NULL)
	  cfhead = readcffile(path);
	else
	  cfhead = readcffile(cfgpath);

	if (daemon_flg)
	  if (lmtp_mode && (!bindport_set || (bindport_set && bindport == 25)))
	    lmtp_mode = 0; /* Disable LMTP mode unless we are bound at other
			      than port 25. */

	resources_maximize_nofiles();


	/* The '-I' option has dual meaning .. */
	if (STREQ(pidfile,"sub-router"))
	  subdaemon_router(0);
	else if (STREQ(pidfile,"sub-ratetracker"))
	  subdaemon_ratetracker(0);
	else if (STREQ(pidfile,"sub-contentfilter"))
	  subdaemon_contentfilter(0);


#ifdef DO_PERL_EMBED
	if (perlhookpath) {
	  atexit(ZSMTP_hook_atexit);
	  ZSMTP_hook_init(argc, argv, envp, perlhookpath);
	}
#endif

	if (!allow_source_route)
	  allow_source_route = (getzenv("ALLOWSOURCEROUTE") != NULL);

	SS.netconnected_flg = 0;
	SS.lport = -1;

	if (!daemon_flg) {

	  raddrlen = sizeof(SS.raddr);
	  memset(&SS.raddr, 0, raddrlen);
	  if (getpeername(SS.inputfd, &SS.raddr.sa, &raddrlen)) {
	    if (testaddr_set) {
	      SS.netconnected_flg = 1;
	      memcpy(&SS.raddr, &testaddr, sizeof(testaddr));
#ifdef HAVE_WHOSON_H
	      {
		char buf[64];
		if (do_whoson && SS.netconnected_flg) {
		  buf[0]='\0';
		  if (SS.raddr.v4.sin_family == AF_INET) {  
		    inet_ntop(AF_INET, (void *) &SS.raddr.v4.sin_addr,    /* IPv4 */
			      buf, sizeof(buf) - 1);
#if defined(AF_INET6) && defined(INET6)
		  } else if (SS.raddr.v6.sin6_family == AF_INET6) {
		    inet_ntop(AF_INET6, (void *) &SS.raddr.v6.sin6_addr,  /* IPv6 */
			      buf, sizeof(buf) - 1);
#endif
		  }
		  if ((SS.whoson_result = wso_query(buf, SS.whoson_data,
						    sizeof(SS.whoson_data)))) {
	            strcpy(SS.whoson_data,"-unregistered-");
	          }
#if DO_PERL_EMBED
		  else {
		    int rc;
		    ZSMTP_hook_set_user(SS.whoson_data, "whoson", &rc);
		  }
#endif
		} else {
		  strcpy(SS.whoson_data,"NOT-CHECKED");
		  strcpy(buf,"NA");
		  SS.whoson_result = -1;
		}
		if (debug) 
		  type(NULL,0,NULL,"Whoson Initialized: IP Used: %s, whoson_result: %d, whoson_data: %s",
		       buf, SS.whoson_result, SS.whoson_data);
	      }
#endif /* HAVE_WHOSON_H */  
	    }
	  } else {
	    /* Got a peer name (it is a socket) */
	    SS.netconnected_flg = 1;
	    if (SS.raddr.v4.sin_family != AF_INET
#ifdef AF_INET6
		&& SS.raddr.v4.sin_family != AF_INET6
#endif
		) {
	      /* well, but somebody uses socketpair(2)  which is
		 an AF_UNIX thing and sort of full-duplex pipe(2)... */
	      SS.netconnected_flg = 0;
	    }
	    if (SS.netconnected_flg) {
	      /* Lets figure-out who we are this time around -- we may be on
		 a machine with multiple identities per multiple interfaces,
		 or via virtual IP-numbers, or ... */
	      localsocksize = sizeof(SS.localsock);
	      if (getsockname(FILENO(stdin), &SS.localsock.sa,
			      &localsocksize) != 0) {
		/* XX: ERROR! */
	      }
#if defined(AF_INET6) && defined(INET6)
	      if (SS.localsock.v6.sin6_family == AF_INET6)
		SS.lport = ntohs(SS.localsock.v6.sin6_port);
	      else
#endif
		SS.lport = ntohs(SS.localsock.v4.sin_port);
	    }
	  }
	  
	  strcpy(SS.rhostname, "stdin");
	  SS.rport = -1;
	  SS.rhostaddr[0] = '\0';
	  sprintf(SS.ident_username, "uid#%d@localhost", (int)getuid());
	  
	  /* INTERACTIVE */
	  OCP = CP;
#ifdef HAVE_OPENSSL
	  Z_init(); /* Some things for private processors */
#endif /* - HAVE_OPENSSL */

	  s_setup(&SS, FILENO(stdin), FILENO(stdout));
	  smtpserver(&SS, 0);

	} else if (inetd) {
#if 0
	  if (maxloadavg != 999 &&
	      maxloadavg < loadavg_current()) {
	    write(1, msg_toohighload, strlen(msg_toohighload));
	    zsleep(2);
	    exit(1);
	  }
#endif
	  raddrlen = sizeof(SS.raddr);
	  memset(&SS.raddr, 0, raddrlen);

	  if (getpeername(SS.inputfd, &SS.raddr.sa, &raddrlen))
	    SS.netconnected_flg = 0;
	  else
	    SS.netconnected_flg = 1;

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
	  if (getsockname(FILENO(stdin), &SS.localsock.sa,
			  &localsocksize) != 0) {
	    /* XX: ERROR! */
	  }
#if defined(AF_INET6) && defined(INET6)
	  if (SS.localsock.v6.sin6_family == AF_INET6)
	    SS.lport = ntohs(SS.localsock.v6.sin6_port);
	  else
#endif
	    SS.lport = ntohs(SS.localsock.v4.sin_port);

	  zopenlog("smtpserver", LOG_PID, LOG_MAIL);
	  
	  OCP = CP;
#ifdef HAVE_OPENSSL
	  Z_init(); /* Some things for private processors */
#endif /* - HAVE_OPENSSL */

	  if (SS.netconnected_flg)
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
	    zsyslog((LOG_INFO, "connection from %s@%s on port %d\n",
		     SS.ident_username, SS.rhostname, SS.lport));
	  }

	  pid = getpid();
	  settrusteduser();	/* dig out the trusted user ID */
	  openlogfp(NULL, daemon_flg);

	  type(NULL,0,NULL,"connection from %s:%d on port %d pid %d ident: %s",
	       SS.rhostname, SS.rport, SS.lport, pid, SS.ident_username);

	  SIGNAL_HANDLE(SIGCHLD, sigchld);
	  SIGNAL_HANDLE(SIGALRM, timedout);
	  SIGNAL_HANDLE(SIGHUP, SIG_IGN);
	  SIGNAL_HANDLE(SIGTERM, SIG_DFL);

	  smtpserver(&SS, 1);

	} else {			/* Not from under the inetd -- standalone server */

	  int j;
	  int childpid, sameipcount, childcnt;
	  int  listensocks_count = 0;
	  int *listensocks       = malloc( 3 * sizeof(int) );
	  int *listensocks_types = malloc( 3 * sizeof(int) );
	  ConfigParams **listensocks_CPs = malloc( 3 * sizeof(void**) );
	  int  msgfd;
	  int CPindex;

	  if (postoffice == NULL
	      && (postoffice = getzenv("POSTOFFICE")) == NULL)
	    postoffice = POSTOFFICE;

	  if (daemon_flg) {
	    int r;

	    /* Kill possible previous smtpservers now! */
	    if (killprevious(SIGTERM, pidfile) != 0) {
	      fprintf(stderr,
		      "%s: Can't write my pidfile!  Disk full ?\n",
		      progname);
	      exit(2);
	    }
	    fflush(stdout);
	    fflush(stderr);

	      
	    /* Daemon attaches the SHM block, and may complain, but will not
	       give up..  instead uses builtin fallback  */
	    
	    r = Z_SHM_MIB_Attach (1);  /* R/W mode */
	    if (r < 0) {
	      /* Error processing -- magic set of constants: */
	      switch (r) {
	      case -1:
		/* fprintf(stderr, "No ZENV variable: SNMPSHAREDFILE\n"); */
		break;
	      case -2:
		perror("Failed to open for exclusively creating of the SHMSHAREDFILE");
		break;
	      case -3:
		perror("Failure during creation fill of SGMSHAREDFILE");
		break;
	      case -4:
		perror("Failed to open the SHMSHAREDFILE at all");
		break;
	      case -5:
		perror("The SHMSHAREDFILE isn't of proper size! ");
		break;
	      case -6:
		perror("Failed to mmap() of SHMSHAREDFILE into memory");
		break;
	      case -7:
		fprintf(stderr, "The SHMSHAREDFILE  has magic value mismatch!\n");
		break;
	      default:
		break;
	      }
	      /* return; NO giving up! */
	    }
	  }

	  settrusteduser();	/* dig out the trusted user ID */
	  zcloselog();		/* close the syslog too.. */
	  if (debug < 2)
	    detach();		/* this must NOT close fd's */
	  /* Close fd's 0, 1, 2 now */
	  close(0);
	  close(1);
	  close(2);

	  open("/dev/null", O_RDWR, 0);
	  dup(0);
	  dup(0);			/* fd's 0, 1, 2 are in use again.. */

	  zsleep(3); /* Give a moment to possible previous server
		       to die away... */
	  killprevious(0, pidfile);	/* deposit pid */

	  /* Start our subdaemons here just before opening SMTP sockets */
	  subdaemons_init();

	  if (bindport <= 0) {
	    struct servent *service;
#ifdef	IPPORT_SMTP
	    bindport = IPPORT_SMTP;
#endif				/* !IPPORT_SMTP */
	    service = getservbyname("smtp", "tcp");
	    if (service == NULL) {
	      fprintf(stderr,
		      "%s: no SMTP service entry, using default\n",
		      progname);
	    } else
	      bindport = ntohs(service->s_port);
	  }

	  for (CPindex = 0; CPindex < CPpSetSize; ++CPindex) {

	    /* Pick groups.. */
	    CP = CPpSet[ CPindex ];

	    /* Without explicite bindings, pick up defaults.. */

	    if (!CP->bindaddrs || CP->bindaddrs_count <= 0) {

	      if (1 /* smtp_listen */ ) {
		if (use_ipv6)
		  create_server_socket( CP,
					& listensocks_count,
					& listensocks,
					& listensocks_types,
					& listensocks_CPs,
					LSOCKTYPE_SMTP,
					1,
					bindport,
					NULL );
		create_server_socket( CP,
				      & listensocks_count,
				      & listensocks,
				      & listensocks_types,
				      & listensocks_CPs,
				      LSOCKTYPE_SMTP,
				      0,
				      bindport,
				      NULL );
	      }

	      if (CP->ssmtp_listen) {
		if (use_ipv6)
		  create_server_socket( CP,
					& listensocks_count,
					& listensocks,
					& listensocks_types,
					& listensocks_CPs,
					LSOCKTYPE_SSMTP,
					1,
					465, /* Deprecated SMTP/TLS WKS port */
					NULL );
		create_server_socket( CP,
				      & listensocks_count,
				      & listensocks,
				      & listensocks_types,
				      & listensocks_CPs,
				      LSOCKTYPE_SSMTP,
				      0,
				      465, /* Deprecated SMTP/TLS WKS port */
				      NULL );
	      }

	      if (CP->submit_listen) {
		if (use_ipv6)
		  create_server_socket( CP,
					& listensocks_count,
					& listensocks,
					& listensocks_types,
					& listensocks_CPs,
					LSOCKTYPE_SUBMIT,
					1,
					587, /* SUBMIT port */
					NULL );
		create_server_socket( CP,
				      & listensocks_count,
				      & listensocks,
				      & listensocks_types,
				      & listensocks_CPs,
				      LSOCKTYPE_SUBMIT,
				      0,
				      587, /* SUBMIT port */
				      NULL );
	      }

	    }

	    /* With explicite bindings! */

	    for (j = 0; j < CP->bindaddrs_count; ++j) {
	      switch (CP->bindaddrs_types[j]) {
	      case BINDADDR_ALL:
	      /* Do it by the registered IP address' address family! */

	      if (1 /* smtp_listen */ ) {
		create_server_socket( CP,
				      & listensocks_count,
				      & listensocks,
				      & listensocks_types,
				      & listensocks_CPs,
				      LSOCKTYPE_SMTP,
				      CP->bindaddrs[j].v4.sin_family != AF_INET,
				      bindport, /* default: 25 .. */
				      &CP->bindaddrs[j]);
	      }
	      if (CP->ssmtp_listen) {
		create_server_socket( CP,
				      & listensocks_count,
				      & listensocks,
				      & listensocks_types,
				      & listensocks_CPs,
				      LSOCKTYPE_SSMTP,
				      CP->bindaddrs[j].v4.sin_family != AF_INET,
				      465, /* SMTPS port */
				      &CP->bindaddrs[j]);
	      }
	      if (CP->submit_listen) {
		create_server_socket( CP,
				      & listensocks_count,
				      & listensocks,
				      & listensocks_types,
				      & listensocks_CPs,
				      LSOCKTYPE_SUBMIT,
				      CP->bindaddrs[j].v4.sin_family != AF_INET,
				      587, /* SUBMISSION port */
				      &CP->bindaddrs[j]);
	      }
	      break;

	      case BINDADDR_SMTP:
		create_server_socket( CP,
				      & listensocks_count,
				      & listensocks,
				      & listensocks_types,
				      & listensocks_CPs,
				      LSOCKTYPE_SMTP,
				      CP->bindaddrs[j].v4.sin_family != AF_INET,
				      CP->bindaddrs_ports[j],
				      &CP->bindaddrs[j]);
		break;

	      case BINDADDR_SMTPS:
		create_server_socket( CP,
				      & listensocks_count,
				      & listensocks,
				      & listensocks_types,
				      & listensocks_CPs,
				      LSOCKTYPE_SSMTP,
				      CP->bindaddrs[j].v4.sin_family != AF_INET,
				      CP->bindaddrs_ports[j],
				      &CP->bindaddrs[j]);
		break;

	      case BINDADDR_SUBMIT:
		create_server_socket( CP,
				      & listensocks_count,
				      & listensocks,
				      & listensocks_types,
				      & listensocks_CPs,
				      LSOCKTYPE_SUBMIT,
				      CP->bindaddrs[j].v4.sin_family != AF_INET,
				      CP->bindaddrs_ports[j],
				      &CP->bindaddrs[j]);
		break;
	      default:
		break;
	      }
	      
	    }
	  }


	  MIBMtaEntry->sys.SmtpServerMasterPID         = getpid();
	  MIBMtaEntry->sys.SmtpServerMasterStartTime   = time(NULL);
	  MIBMtaEntry->sys.SmtpServerMasterStarts     += 1;

	  MIBMtaEntry->ss.IncomingSMTPSERVERprocesses    = 1; /* myself at first */
	  MIBMtaEntry->ss.IncomingParallelSMTPconnects   = 0;
	  MIBMtaEntry->ss.IncomingParallelSMTPSconnects  = 0;
	  MIBMtaEntry->ss.IncomingParallelSUBMITconnects = 0;
	  /* MIBMtaEntry->ss.IncomingParallelLMTPconnects   = 0; */

#if 1
	  pid = getpid();
	  openlogfp(NULL, daemon_flg);
	  if (logfp != NULL) {
	    char *cp;
	    char *tt;

	    time(&now);
	    cp = rfc822date(&now);
	    tt = strchr(cp, '\n'); if (tt) *tt = 0;
	    type(NULL,0,NULL,"started server pid %d at %s", pid, cp);
	    /*fprintf(logfp,"00000000000#\tfileno(logfp) = %d",fileno(logfp)); */
	    fclose(logfp);
	    logfp = NULL;
	  }
#endif

	  SIGNAL_HANDLE(SIGCHLD, sigchld);
	  SIGNAL_HANDLE(SIGALRM, timedout);
	  SIGNAL_HANDLE(SIGHUP, SIG_IGN);
	  SIGNAL_HANDLE(SIGTERM, sigterminator);

	  while (!mustexit) {
	    int n;
	    int socktag;
	    int socketcount = 0;
	    
	    if (sawsigchld) {
	      reaper(0);
	      continue;
	    }



	    for (i = 0; i < listensocks_count; ++i) {
	      zmpoll_addfd(&pollfds, &socketcount, listensocks[i], -1, NULL);
	    }
	    n = zmpoll(pollfds, socketcount, 10000 /* milliseconds */);

	    if (n == 0) /* Timeout is just to keep the loop alive... */
	      continue;

	    if (n < 0) {
	      /* various interrupts can happen here.. */
	      if (errno == EBADF || errno == EINVAL) break;
	      if (errno == ENOMEM) zsleep(1); /* Wait a moment, then try again */
	      continue;
	    }

	    /* Ok, here the  select()  has reported that we have something
	       appearing in the listening socket(s).
	       We are simple, and try them in order.. */

	    for (i = 0; i < socketcount; ++i) {

	      if (pollfds[i].revents & ZM_POLLIN) {

		n = listensocks[i];
		socktag = listensocks_types[i];
		OCP     = listensocks_CPs[i];
	  
		raddrlen = sizeof(SS.raddr);
		msgfd = accept(n, &SS.raddr.sa, &raddrlen);
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

		sameipcount = childsameip(&SS.raddr, socktag, &childcnt);

		switch (socktag) {
		case LSOCKTYPE_SMTP:
		  MIBMtaEntry->ss.IncomingSMTPconnects += 1;
		  MIBMtaEntry->ss.IncomingParallelSMTPconnects = childcnt;
		  break;
		case LSOCKTYPE_SSMTP:
		  MIBMtaEntry->ss.IncomingSMTPSconnects += 1;
		  MIBMtaEntry->ss.IncomingParallelSMTPSconnects = childcnt;
		  break;
		case LSOCKTYPE_SUBMIT:
		  MIBMtaEntry->ss.IncomingSUBMITconnects += 1;
		  MIBMtaEntry->ss.IncomingParallelSUBMITconnects = childcnt;
		  break;
		default:
		  break;
		}

		SS.sameipcount = sameipcount;
		/* We query, and warn the remote when
		   the count exceeds the limit, and we
		   simply -- and FAST -- reject the
		   remote when it exceeds 4 times the
		   limit */
		if (sameipcount > 4 * MaxSameIpSource) {
		  close(msgfd);
		  MIBMtaEntry->ss.MaxSameIpSourceCloses ++;
		  continue;
		}
		  
		if (childcnt > 100+MaxParallelConnections) {
		  close(msgfd);
		  MIBMtaEntry->ss.MaxParallelConnections ++;
		  continue;
		}

		SIGNAL_HOLD(SIGCHLD);
		if ((childpid = fork()) < 0) {	/* can't fork! */
		  SIGNAL_RELEASE(SIGCHLD);
		  close(msgfd);
		  MIBMtaEntry->ss.ForkFailures ++;
		  fprintf(stderr,
			  "%s: fork(): %s\n",
			  progname, strerror(errno));
		  zsleep(5);
		  continue;
		} else if (childpid > 0) {	/* Parent! */
		  childregister(childpid, &SS.raddr, socktag);
		  SIGNAL_RELEASE(SIGCHLD);
		  reaper(0);

		  close(msgfd); /* Child has it, close at parent */
		} else {			/* Child */
		  SIGNAL_RELEASE(SIGCHLD);
		  
		  disable_childreap(); /* Child does not do childreap..
					  it may do other reaps, though. */

		  SS.netconnected_flg = 1;
		  debug_no_stdout = 1;
		  
		  switch (socktag) {
		  case LSOCKTYPE_SMTP:
		    SS.with_protocol_set |= WITH_SMTP;
		    break;
		  case LSOCKTYPE_SSMTP:
		    ssmtp_connected = 1;
		    SS.with_protocol_set |= WITH_SMTPS;
		    SS.with_protocol_set |= WITH_TLS;
		    break;
		  case LSOCKTYPE_SUBMIT:
		    /* submit_connected = 1; */
		    msa_mode = 1;
		    SS.with_protocol_set |= WITH_SUBMIT;
		    break;
		  default:
		    break;
		  }

		  for (i = 0; i < listensocks_count; ++i)
		    close(listensocks[i]); /* Close listening sockets */
		    
		  pid = getpid();
		
		  if (msgfd != 0)
		    dup2(msgfd, 0);
		  dup2(0, 1);
		  if (msgfd > 1)
		    close(msgfd);
		  msgfd = 0;
		  
		  if (logfp)	/* Open the logfp later.. */
		    fclose(logfp);
		  logfp = NULL;
		  
#if 0
		  if (maxloadavg != 999 &&
		      maxloadavg < loadavg_current()) {
		    write(msgfd, msg_toohighload,
			  strlen(msg_toohighload));
		    zsleep(2);
		    exit(1);
		  }
#endif
		  /* SIGNAL_HANDLE(SIGTERM, SIG_IGN); */
		  SIGNAL_HANDLE(SIGTERM, sigterminator);
		    
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
		  if (getsockname(msgfd, &SS.localsock.sa,
				  &localsocksize) != 0) {
		    /* XX: ERROR! */
		  }
#if defined(AF_INET6) && defined(INET6)
		  if (SS.localsock.v6.sin6_family == AF_INET6)
		    SS.lport = ntohs(SS.localsock.v6.sin6_port);
		  else
#endif
		    SS.lport = ntohs(SS.localsock.v4.sin_port);

		  zopenlog("smtpserver", LOG_PID, LOG_MAIL);
		  
		  /* We have set the OCP above.. */
		  /* OCP = OCP; */
#ifdef HAVE_OPENSSL
		  Z_init(); /* Some things for private processors */
#endif /* - HAVE_OPENSSL */

		  s_setup(&SS, msgfd, msgfd);
		  
		  if (ident_flag != 0)
		    setrfc1413ident(&SS);
		  else
		    strcpy(SS.ident_username, "IDENT-NOT-QUERIED");

#ifdef HAVE_WHOSON_H
		  if (do_whoson && SS.netconnected_flg) {
		    char buf[64];
		    buf[0]='\0';
		    if (SS.raddr.v4.sin_family == AF_INET) {  
		      inet_ntop(AF_INET, (void *) &SS.raddr.v4.sin_addr,    /* IPv4 */
				buf, sizeof(buf) - 1);
#if defined(AF_INET6) && defined(INET6)
		    } else if (SS.raddr.v6.sin6_family == AF_INET6) {
		      inet_ntop(AF_INET6, (void *) &SS.raddr.v6.sin6_addr,  /* IPv6 */
				buf, sizeof(buf) - 1);
#endif
		    }
		    if ((SS.whoson_result = wso_query(buf, SS.whoson_data,
						      sizeof(SS.whoson_data)))) {
		      strcpy(SS.whoson_data,"-unregistered-");
		    }
#if DO_PERL_EMBED
		    else {
		      int rc;
		      ZSMTP_hook_set_user(SS.whoson_data, "whoson", &rc);
		    }
#endif
		  } else {
		    strcpy(SS.whoson_data,"NOT-CHECKED");
		    SS.whoson_result = -1;
		  }
#endif /* HAVE_WHOSON_H */  


		  if (smtp_syslog && ident_flag) {
#ifdef HAVE_WHOSON_H
		    zsyslog((LOG_INFO, "connection from %s@%s on port %d (whoson: %s)\n",
			     SS.ident_username, SS.rhostname, SS.lport, SS.whoson_data));
#else /* WHOSON */
		    zsyslog((LOG_INFO, "connection from %s@%s on port %d\n",
			     SS.ident_username, SS.rhostname, SS.lport));
#endif
		  }
		  pid = getpid();

		  openlogfp(&SS, daemon_flg);
#ifdef HAVE_WHOSON_H
		  type(NULL,0,NULL,
		       "connection from %s %s:%d on port %d ipcnt %d childs %d pid %d ident: %s whoson: %s",
		       SS.rhostname, SS.rhostaddr,SS.rport,SS.lport,
		       sameipcount, childcnt, pid,
		       SS.ident_username, SS.whoson_data);
#else
		  type(NULL,0,NULL,
		       "connection from %s %s:%d on port %d ipcnt %d childs %d pid %d ident: %s",
		       SS.rhostname, SS.rhostaddr,SS.rport,SS.lport,
		       sameipcount, childcnt, pid,
		       SS.ident_username);
#endif

		  /* if (logfp) type(NULL,0,NULL,"Input fd=%d",getpid(),msgfd); */
		  
		  if (childcnt > MaxParallelConnections) {
		    type(&SS, -450, m571, "%s", contact_pointer_message);
		    type(&SS, -450, m571, "Come again later");
		    type(&SS,  450, m571, "Too many simultaneous connections to this server (%d max %d)", childcnt, MaxParallelConnections);
		    typeflush(&SS);
		    MIBMtaEntry->ss.MaxParallelConnections ++;
		    close(0); close(1); close(2);
#if 1
		    zsleep(2);	/* Not so fast!  We need to do this to
				   avoid (as much as possible) the child
				   to exit before the parent has called
				   childregister() -- not so easy to be
				   100% reliable (this isn't!) :-( */
#endif
		    exit(0);	/* Now exit.. */
		  }
		  if (sameipcount > MaxSameIpSource && sameipcount > 1) {
		    type(&SS, -450, m571, "Come again later");
		    type(&SS, -450, m571, "%s", contact_pointer_message);
		    type(&SS,  450, m571, "Too many simultaneous connections from same IP address (%d max %d)", sameipcount, MaxSameIpSource);
		    typeflush(&SS);
		    MIBMtaEntry->ss.MaxSameIpSourceCloses ++;
		    close(0); close(1); close(2);
#if 1
		    zsleep(2);	/* Not so fast!  We need to do this to
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
		  
		  killcfilter(&SS);
		    
		  if (SS.netconnected_flg)
		    zsleep(2);
		  _exit(0);

		} /* .. end of child code */
	      } /* .. acceptance ok */
	    } /* .. listensocks */

	  } /* .. while (!mustexit) */

	  /* Stand-alone server, kill the pidfile at the exit! */
	  killpidfile(pidfile);
	  subdaemons_kill_cluster_listeners();

	  openlogfp(&SS, daemon_flg);
	  zsyslog((LOG_INFO, "killed server."));
	  if (logfp != NULL) {
	    char *cp;
	    time(&now);
	    cp = rfc822date(&now);
	    fprintf(logfp, "00000000000#\tkilled server pid %d at %s", pid, cp);
	    fclose(logfp);
	    logfp = NULL;
	  }

	} /* stand-alone server */

	killcfilter(&SS);
	if (SS.netconnected_flg)
	  zsleep(2);
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
		  SS->rhostaddr + 1, sizeof(SS->rhostaddr) - 2);
#if defined(AF_INET6) && defined(INET6)
    else if (SS->raddr.v6.sin6_family == AF_INET6) {
	strcpy(SS->rhostaddr + 1, "IPv6:");
	inet_ntop(AF_INET6, (void *) &SS->raddr.v6.sin6_addr,	/* IPv6 */
		  SS->rhostaddr + 6, sizeof(SS->rhostaddr) - 7);
    }
#endif
    else {
	;			/* XX: ??? Not AF_INET, nor AF_INET6 ??? */
    }
    SS->rhostaddr[0] = '[';
    sprintf(SS->rhostaddr + strlen(SS->rhostaddr), "]");

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
	    strcpy(SS->rhostname, SS->rhostaddr);
    } else {
	strcpy(SS->rhostname, SS->rhostaddr);
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

RETSIGTYPE
sigchld(sig)
     int sig;
{
	SIGNAL_HANDLE(sig, sigchld);
	sawsigchld = 1;
}

static RETSIGTYPE
reaper(sig)
     int sig;
{
    int status;
    pid_t lpid;
    int nologfp;

    SIGNAL_HOLD(SIGCHLD);

    sawsigchld = 0;

    /* The master loop does not have 'logfp' opened, but to log
       anything here, we need it open... 
       On the other hand, subprograms of master having their own
       subprograms shall not touch on the  'logfp' if it is open!  */
    nologfp = (logfp == NULL);
    if (nologfp)
      openlogfp(NULL, 1);

    for (;;) {
#ifdef	HAVE_WAITPID
	lpid = waitpid(-1, &status, WNOHANG);
#else
#ifdef	HAVE_WAIT4
	lpid = wait4(0, &status, WNOHANG, (struct rusage *) NULL);
#else
#ifdef	HAVE_WAIT3
	lpid = wait3(&status, WNOHANG, (struct rusage *) NULL);
#else				/* ... plain simple waiting wait() ... */
	/* This can freeze at wait() ?  Who could test ?  A system
	   without wait3()/waitpid(), but with BSD networking ??? */
	lpid = wait(&status);
#endif				/* WNOHANG */
#endif
#endif
	if (lpid <= 1) break; /* For whatever reason */

	/* type(NULL,0,NULL,"REAPER: pid %ld  status 0x%04lx", lpid, status); */

	if (lpid == pipeauthchild_pid && lpid > 0) {
	    pipeauthchild_status = status;
	    pipeauthchild_pid = -1;
	}

	if (lpid == ratetracker_server_pid) {
	    ratetracker_server_pid = 0;
	    if (ratetracker_rdz_fd >= 0)
	      close(ratetracker_rdz_fd);
	    ratetracker_rdz_fd = -1;
	    type(NULL,0,NULL,"Ratetracker subdaemon had died, reiniting..");
	    subdaemons_init_ratetracker();
	    continue;
	}
	if (lpid == router_server_pid) {
	    router_server_pid = 0;
	    if (router_rdz_fd >= 0)
	      close(router_rdz_fd);
	    router_rdz_fd = -1;
	    type(NULL,0,NULL,"Router subdaemon had died, reiniting..");
	    subdaemons_init_router();
	    continue;
	}
	if (lpid == contentfilter_server_pid) {
	    contentfilter_server_pid = 0;
	    if (contentfilter_rdz_fd >= 0)
	      close(contentfilter_rdz_fd);
	    contentfilter_rdz_fd = -1;
	    type(NULL,0,NULL,"Contentfilter subdaemon had died, reiniting..");
	    subdaemons_init_contentfilter();
	    continue;
	}

	childreap(lpid);
    }

    if (nologfp && logfp) {
      fclose(logfp);
      logfp = NULL;
    }

    SIGNAL_HANDLE(SIGCHLD, sigchld);
    SIGNAL_RELEASE(SIGCHLD);
}

void reporterr(SS, tell, msg)
SmtpState *SS;
const long tell;
const char *msg;
{
    int dt;
    time( & now );
    if (logtagepoch)
      dt = (int)(now-logtagepoch);
    else
      dt = 0;

    zsyslog((LOG_ERR,
	     "%s%04d - aborted (%ld bytes) from %s/%d: %s",
	     logtag, dt, tell, SS->rhostname, SS->rport, msg));
    if (logfp && (SS->tarpit > OCP->tarpit_initial)) {
        char *ts = rfc822date(&now);
	char *n = strchr(ts, '\n');
	if (n) *n = 0;

	type(NULL,0,NULL,"tarpit with delay %04d ends at %s", (int)(SS->tarpit_cval), ts );
        fflush(logfp);
    }
    if (logfp) {
	type(NULL,0,NULL,"aborted (%ld bytes): %s\n", tell, msg);
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

	struct zmpollfd *fds = NULL;
	time_t now;
	int fd = SS->outputfd;
	int n = 0;
	int tv_sec;

	time(&now);

	if (expiry_epoch <= now)
	  tv_sec = 1;
	else
	  tv_sec = expiry_epoch - now;

	if (rc == -1)
	  zmpoll_addfd(&fds, &n, -1, fd, NULL);
	else
	  zmpoll_addfd(&fds, &n, SS->inputfd, -1, NULL);  /* SSL Want Read! */

	rc = zmpoll( fds, 1, tv_sec * 1000 );

	if (fds)
	  free(fds);

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
    int rc;

    struct zmpollfd *fds = NULL;
    int fdcount = 0;

    zmpoll_addfd(&fds, &fdcount, SS->inputfd, -1, NULL);

    rc = zmpoll(fds, fdcount, 0);

    if (fds) free(fds);


    if (rc > 0) return 1;

    return 0;
}

#endif /* --HAVE_OPENSSL */

/* Support routine: Our own buffering for stdinput */

int s_feof(SS)
SmtpState *SS;
{
    return SS->s_status;
}

int s_seen_eof(SS)
SmtpState *SS;
{
    /* There can be up to  sizeof(SS->s_buffer)  data
       before this is actual reality!
    */
    return SS->s_seen_eof;
}

int s_getc(SS, timeout_is_fatal)
     SmtpState *SS;
     int timeout_is_fatal;
{
    int rc = 0;
    struct zmpollfd *fds = NULL;

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

	if (mustexit) return EOF;

        /* We are about to read... */

	if (rc < 0 && SS->inputfd >= 0) {
	
	  int pollfds = 0;

	  int tv_sec = 1;
	  time_t now;

	  time(&now);

	  if (expiry_epoch > now)
	    tv_sec = expiry_epoch - now;

	  if (rc == -2) /* SSL Want Write ! */
	    zmpoll_addfd(&fds, &pollfds, -1, SS->outputfd, NULL);
	  else
	    zmpoll_addfd(&fds, &pollfds, SS->inputfd, -1, NULL);


	  rc = zmpoll( fds, 1, tv_sec * 1000 );

	  if (fds) free(fds);
	  fds = NULL;

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

	rc = Z_read(SS, SS->s_buffer, SS->s_buffer_size);
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

    if (SS->s_readout >= SS->s_bufread)
      SS->s_readout = SS->s_bufread = 0;

    if ((SS->s_readout > 0) && (SS->s_readout < SS->s_bufread)) {
      /* Compact the buffer */
      memmove(SS->s_buffer, SS->s_buffer + SS->s_readout,
	      SS->s_bufread - SS->s_readout);
      SS->s_bufread -= SS->s_readout;
      SS->s_readout = 0;
    }

    /* No new input pending.. return buffer content */
    if (!i) return SS->s_bufread;

    if (SS->s_bufread < SS->s_buffer_size) {
      /* Can fit in some new data.. */
      i = sizeof(SS->s_buffer) - SS->s_bufread;
      i = Z_read(SS, SS->s_buffer + SS->s_bufread, i);
      if (i > 0)
	SS->s_bufread += i;
      if (i == 0)
	SS->s_seen_eof = 1;
    }

    return SS->s_bufread;
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

	if (!OCP->pipeliningok || !s_hasinput(SS))
	  typeflush(SS);

	/* Alarm processing on the SMTP protocol channel */
	SS->read_alarm_ival = SMTP_COMMAND_ALARM_IVAL;

	/* Our own  fgets() -- gets also NULs, flags illegals.. */
	--buflen;
	while ((c = s_getc(SS, 1)) != EOF && i < buflen) {
	    buf[++i] = c;
	    if (c == '\n')
		break;
	    if (rc < 0) {
	      if (co == '\r')
		rc = i;		/* Spurious CR on the input.. */
	      else if (c == '\0')
		rc = i;
	      else if ((c & 0x80))
		rc = i;
	      else {
		if (c != '\r' && c != '\t' && (c < 32 || c == 127))
		  rc = i;
	      }
	    }
	    co = c;
	}
	buf[++i] = '\0';

	if (c == EOF && i == 0) {
	    /* XX: ???  Uh, Hung up on us ? */
	    if (SS->mfp != NULL) {
		mail_abort(SS->mfp);
		policytest(&SS->policystate, POLICY_DATAABORT,
			   NULL, SS->rcpt_count, NULL);
	    }
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


static void s_setup(SS, infd, outfd)
SmtpState *SS;
int infd, outfd;
{
    SS->inputfd  = infd;
    SS->outputfd = outfd;
    SS->s_status = 0;
    SS->s_buffer_size = sizeof(SS->s_buffer);
    SS->s_bufread   = -1;
    SS->s_ungetcbuf = -1;
    SS->s_readout = 0;

    /* Actually all modes use this write-out buffer */
    SS->sslwrbuf   = emalloc(8192);
    SS->sslwrspace = 8192;
    SS->sslwrin = SS->sslwrout = 0;

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
    long maxsameip = 0;

#ifdef USE_TRANSLATION
    char lang[4];

    lang[0] = '\0';
#endif

    if (!OCP) OCP = CP; /* Backup setup.. */

    SS->VerboseCommand = 0;

    SS->tarpit      = OCP->tarpit_initial;
    SS->tarpit_cval = 0;

    stashmyaddresses(NULL);

    pid = getpid();
    if (!logfp)
	openlogfp(SS, insecure);

    runastrusteduser();

    if (!SS->netconnected_flg)
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
	  } else {
	    mail_abort(SS->mfp);
	  }
	  policytest(&SS->policystate, POLICY_DATAABORT,
		     NULL, SS->rcpt_count, NULL);
	}
	SS->mfp = NULL;

	killcfilter(SS);
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
#if 0 /* The SS state isn't fully initialized now, can't use type() yet!  Eugene Crosser <crosser@rol.ru>  Eh, really ? [mea] */
	/* we don't know our codetable, hush client away */
	type(SS, 451, NULL, "Server could not setup translation.", NULL);
	typeflush(SS);
#endif
	zsleep(2);
	exit(0);
#endif				/* USE_TRANSLATION */
    }

    smtpauth_init(SS);

#if DO_PERL_EMBED
    ZSMTP_hook_set_ipaddress(SS->rhostaddr, localport, &rc);
#endif

#ifdef HAVE_OPENSSL
    if (ssmtp_connected) {
      if (tls_start_servertls(SS)) {
	/* No dice... */
	type(NULL,0,NULL,"Implicite STARTTLS failed");
	exit(2);
      }
    }
#endif /* - HAVE_OPENSSL */

    if (localport != 25 && detect_incorrect_tls_use) {
      int c;
      int aval = SS->read_alarm_ival;

      SS->read_alarm_ival = 2;
      SS->s_buffer_size = 1;
      c = s_getc(SS, 0);
      SS->s_buffer_size = sizeof(SS->s_buffer);

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
	  if (tls_start_servertls(SS)) {
	    /* No dice... */
	    type(NULL,0,NULL,"Implicite STARTTLS failed");
	    exit(2);
	  }
	}
#endif /* - HAVE_OPENSSL */
      }
    }

#ifdef HAVE_WHOSON_H
    policystatus = policyinit(&SS->policystate, OCP->policydb, 
			      (SS->with_protocol_set & WITH_SUBMIT) ? 1 : 0,
			      (! SS->whoson_result && SS->whoson_data));
#else
    policystatus = policyinit(&SS->policystate, OCP->policydb,
			      (SS->with_protocol_set & WITH_SUBMIT) ? 1 : 0,
			      0);
#endif

    if (!SS->netconnected_flg) {
      policystatus = 0; /* For internal - non-net-connected - mode
			   lack of PolicyDB is no problem at all.. */
      SS->reject_net = 0;
    } else if (policystatus == 0) { /* net connected, and db opened ok */
      if (debug) typeflush(SS);
      SS->policyresult = policytestaddr(&SS->policystate,
					POLICY_SOURCEADDR,
					(void *) &SS->raddr);
      SS->reject_net = (SS->policyresult < 0);
      maxsameip = policysameiplimit(&SS->policystate);
      if (maxsameip == 0 && SS->netconnected_flg)
	SS->reject_net = 1; /* count=0 equivalent to reject */
      if (debug) typeflush(SS);
      if (SS->policyresult == 0) /* Alternates to this condition are:
				    Always reject, or Always freeze.. */
	SS->policyresult = policytest(&SS->policystate,
				      POLICY_SOURCEDOMAIN,
				      SS->rhostname,strlen(SS->rhostname),
				      SS->authuser);
    }
    /* re-opening the log ?? */
    zopenlog("smtpserver", LOG_PID, LOG_MAIL);

#ifdef USE_TCPWRAPPER
#ifdef HAVE_TCPD_H		/* TCP-Wrapper code */
    if (OCP->use_tcpwrapper && SS->netconnected_flg &&
	wantconn(SS->inputfd, "smtp-receiver") == 0) {
	zsyslog((LOG_WARNING, "refusing connection from %s:%d/%s",
		 SS->rhostname, SS->rport, SS->ident_username));
	type(SS, 421, NULL, "%s ZMailer Server %s WILL NOT TALK TO YOU at %s",
	     SS->myhostname, VersionNumb, cp);
	typeflush(SS);
	zsleep(2);
	exit(0);
    }
#endif
#endif

    if (SS->reject_net) {
	char *msg = policymsg(&SS->policystate);
	type(SS, -550, m571, "Hello %s; If you feel we mistreat you, do contact us.", SS->rhostaddr);
	type(SS, -550, m571, "Hello %s; %s", SS->rhostaddr, contact_pointer_message);
	typeflush(SS);
	smtp_tarpit(SS);
	if (msg != NULL) {
	  type(SS, 550, m571, "Hello %s; %s",SS->rhostaddr,  msg);
	} else {
	  type(SS, 550, m571, "Hello %s; %s - You are on our reject-IP-address -list, GO AWAY!",
	       SS->rhostaddr, SS->myhostname);
	}

    } else if ((maxsameip >= 0) && (SS->sameipcount > maxsameip)) {
	smtp_tarpit(SS);
	type(SS, 450, NULL, "%s - Come again latter, too many simultaneous connections from this IP address /ms(%li of %li)",
	       SS->myhostname, SS->sameipcount, maxsameip);
	MIBMtaEntry->ss.MaxSameIpSourceCloses ++;
    } else {
#ifdef USE_TRANSLATION
	if (hdr220lines[0] == NULL) {
	  hdr220lines[0] = "%H ZMailer Server %V ESMTP%I (%X) ready at %T";
	}
	type220headers(SS, ident_flag, X_settrrc ? "nulltrans" : lang, cp);
#else				/* USE_TRANSLATION */
	if (hdr220lines[0] == NULL) {
	  hdr220lines[0] = "%H ZMailer Server %V ESMTP%I ready at %T";
	}
	type220headers(SS, ident_flag, "", cp);
#endif				/* USE_TRANSLATION */
    }
    typeflush(SS);

    if (strict_protocol >= 0)
      SS->state = Hello;
    else
      SS->state = MailOrHello;

    if ((!insecure
	 || (SS->rhostaddr[0] != '\0'
	     && strcmp(SS->rhostaddr, "[127.0.0.1]") == 0))
	&& ((cfinfo = findcf("127.0.0.1")) == NULL
	    || strcmp(cfinfo->flags, "-") == 0))
	SS->state = MailOrHello;

    cfinfo = NULL;
    {
	char *s = policymsg(&SS->policystate);
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

	if (mustexit)
	  break;

	if (i <= 0)	/* EOF ??? */
	  break;

	MIBMtaEntry->ss.IncomingCommands ++;

	time( & now );

	if (s_hasinput(SS)) {
	  if (logfp || logfp_to_syslog)
	    type(NULL,0,NULL,
		 "-- pipeline input exists %d bytes%",
		 s_hasinput(SS), s_seen_eof(SS) ? "; seeing EOF" : "" );

	  if (s_seen_eof(SS) &&  (SS->tarpit > 0.9999)) {
	    type(NULL,0,NULL,"BAILING OUT");
	    /* Bail out! */
	    break;
	  }

	  if ((SS->with_protocol_set & WITH_EHLO) != WITH_EHLO) {
	    /* We have pipelining input, but greeted with EHLO.. */
	    type(SS, 550, m571, "HELLO %s, YOU ARE SENDING PIPELINED INPUT, BUT DIDN'T GREET PROPERLY WITH EHLO", SS->rhostaddr);
	    /* Bail out! */
	    break;
	  }

	  if (!SS->s_seen_pipeline)
	    MIBMtaEntry->ss.IncomingClientPipelines ++;
	  SS->s_seen_pipeline = 1;
	}

	eobuf = &buf[i-1];	/* Buf end ptr.. */

	/* Chop the trailing spaces */
	if (strict_protocol < 1) {
	  while ((eobuf > buf) && (eobuf[-1] == ' ' ||
				   eobuf[-1] == '\t'))
	    *--eobuf = '\0';
	} else if ((strict_protocol > 0) &&
		   eobuf > buf && (eobuf[-1] == ' ' ||
				   eobuf[-1] == '\t')) {
	  /* XX: Warn about trailing whitespaces on inputs!
	     ... except that this is likely *wrong* place, as
	     there are many varying input syntaxes... */
	}

	{
	  int dt;
	  if (logtagepoch)
	    dt = (int)(now-logtagepoch);
	  else
	    dt = 0;

	  if (logfp_to_syslog)
	    zsyslog((LOG_DEBUG, "%s%04d r %s", logtag, dt, buf));

	  if (logfp) {
	    fprintf(logfp, "%s%04dr\t%s\n", logtag, dt, buf);
	    fflush(logfp);
	  }
	}

	if (rc >= 0 && (strict_protocol < 1)) {
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
	    MIBMtaEntry->ss.IncomingCommands_unknown ++;
	    continue;
	}
	if (c != '\n' && i > 3) {
	  /* Some bloody systems send:  "QUIT\r",
	     and then close the socket... */
	  if (CISTREQ(buf,"QUIT") == 0) {
	    co = '\r';
	    c = '\n'; /* Be happy... */
	  }
	}
	if (((strict_protocol > 0) &&
	     (c != '\n' || co != '\r')) || (c != '\n')) {
	    if (i < (sizeof(buf)-1))
		type(SS, 500, m552, "Line not terminated with CRLF..");
	    else
		type(SS, 500, m552, "Line too long (%d chars)", i);
	    MIBMtaEntry->ss.IncomingCommands_unknown ++;
	    continue;
	}
	if (verbose && !daemon_flg)
	    fprintf(stdout, "%s\n", buf);	/* XX: trace.. */
	report(SS, "%.100s", buf);

	for (cp = buf; (c = *cp) && (c != ' ') && (c != '\t'); ++cp)
	    continue;

	if (cp > buf + 8)	/* "STARTTLS" is longest of them.. */
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

	    MIBMtaEntry->ss.IncomingCommands_unknown ++;
	    ++SS->unknown_cmd_count;

	    if (SS->unknown_cmd_count >= unknown_cmd_limit) {
	      type(SS, 550, m552, "Hi %s, One too many unknown command '%s'", SS->rhostaddr, buf);
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

	if (SS->carp->cmd == DebugMode && ! OCP->debugcmdok)
	  goto unknown_command;
	if (SS->carp->cmd == Expand    && ! OCP->expncmdok)
	  goto unknown_command;
	if (SS->carp->cmd == Verify    && ! OCP->vrfycmdok)
	  goto unknown_command;
	if (SS->carp->cmd == Verify2   && ! OCP->vrfycmdok)
	  goto unknown_command;
	if (SS->carp->cmd == Hello2    && ! OCP->ehlo_ok)
	  goto unknown_command;
	if (SS->carp->cmd == Turnme    && ! OCP->etrn_ok)
	  goto unknown_command;
	if (SS->carp->cmd == Auth      && ! OCP->auth_ok)
	  goto unknown_command;
	if (SS->carp->cmd == BData     && ! OCP->chunkingok)
	  goto unknown_command;

	/* Lack of configuration is problem only with network connections */
	if (SS->netconnected_flg && !configuration_ok) {
	  smtp_tarpit(SS);
	  type(SS, -400, "4.7.0", "This SMTP server has not been configured!");
	  typeflush(SS);
	  zsyslog((LOG_EMERG, "smtpserver configuration missing!"));
	  zsleep(20);
	  continue;
	}
	if (policystatus != 0 &&
	    SS->carp->cmd != Quit && SS->carp->cmd != Help) {
	  smtp_tarpit(SS);
	  type(SS, -400, "4.7.0", "%s", contact_pointer_message);
	  type(SS,  400, "4.7.0", "Policy database problem: %s",
	       (policystatus == 1 ? "Configuration bug" :
		(policystatus == 2 ? "db Open failure" : "NO BUG??")));
	  typeflush(SS);
	  zsyslog((LOG_EMERG, "smtpserver policy database problem, code: %d", policystatus));
	  zsleep(20);
	  continue;
	}
	if (SS->reject_net && SS->carp->cmd != Quit && SS->carp->cmd != Help) {
	    type(SS, -550, m571, "Hello %s; %s", SS->rhostaddr, contact_pointer_message);
	    type(SS, -550, m571, "If you feel we mistreat you, do contact us.");
	    typeflush(SS);

	    smtp_tarpit(SS);
	    type(SS,  550, m571, "Hello %s; you are on our reject-IP-address -list, GO AWAY!", SS->rhostaddr);

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
	    type(SS, 530, m530, "Sorry %s; Authentication required", SS->rhostaddr );
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
	case Report:
	    if (smtp_report(SS, buf, cp) < 0)
	      goto unknown_command;
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
	    MIBMtaEntry->ss.IncomingSMTP_MAIL += 1;
	    if (smtp_mail(SS, buf, cp, insecure) != 0 ||
		SS->mfp == NULL) {
	      if (! SS->mfp)
		policytest(&SS->policystate, POLICY_DATAABORT,
			   NULL, 1, NULL);
	      MIBMtaEntry->ss.IncomingSMTP_MAIL_bad += 1;
	    } else {
	      MIBMtaEntry->ss.IncomingSMTP_MAIL_ok += 1;
	    }
	    break;
	case Recipient:
	    /* This code is LONG.. */
	    MIBMtaEntry->ss.IncomingSMTP_RCPT += 1;
	    if (smtp_rcpt(SS, buf, cp) != 0 || SS->mfp == NULL)
	      MIBMtaEntry->ss.IncomingSMTP_RCPT_bad += 1;
	    else
	      MIBMtaEntry->ss.IncomingSMTP_RCPT_ok += 1;
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

	    MIBMtaEntry->ss.IncomingSMTP_RSET ++;

	    if (*cp != 0 && (strict_protocol > 0)) {
	      type(SS, 501, m554, "Extra junk after 'RSET' verb");
	      break;
	    }
	    if (SS->mfp != NULL) {
		clearerr(SS->mfp);
		mail_abort(SS->mfp);
		policytest(&SS->policystate, POLICY_DATAABORT,
			   NULL, SS->rcpt_count, NULL);
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
	    MIBMtaEntry->ss.IncomingSMTP_TURN ++;
	    if (*cp != 0 && STYLE(SS->cfinfo,'R')) {
	      type(SS, -502, m554, "Extra junk after 'TURN' verb");
	    }
	    type(SS, 502, m551, (char *) NULL);
	    typeflush(SS);
	    break;
	case NoOp:
	    MIBMtaEntry->ss.IncomingSMTP_NOOP ++;
	    if (*cp != 0 && STYLE(SS->cfinfo,'R')) {
	      type(SS, 501, m554, "Extra junk after 'NOOP' verb");
	      break;
	    }
	    type(SS, 250, m200, (char *) NULL);
	    typeflush(SS);
	    break;
	case Verbose:
	    MIBMtaEntry->ss.IncomingSMTP_VERBOSE ++;
	    type(SS, -250, m200, VerbID, Version);
	    type(SS, -250, m200, Copyright);
	    type(SS, 250, m200, Copyright2);
	    typeflush(SS);
	    SS->VerboseCommand = 1;
	    break;
	case DebugMode:
	    MIBMtaEntry->ss.IncomingSMTP_DEBUG ++;
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
	    MIBMtaEntry->ss.IncomingSMTP_TICK ++;
	    type(SS, 250, m200, "%s", buf);
	    typeflush(SS);
	    SS->with_protocol_set |= WITH_BSMTP;
	    break;
	case Quit:
	    MIBMtaEntry->ss.IncomingSMTP_QUIT ++;
	    if (*cp != 0 && STYLE(SS->cfinfo,'R')) {
	      type(SS, -221, m554, "Extra junk after 'QUIT' verb");
	    }
	    if (SS->mfp != NULL) {
		mail_abort(SS->mfp);
		policytest(&SS->policystate, POLICY_DATAABORT,
			   NULL, SS->rcpt_count, NULL);
	    }
	    SS->mfp = NULL;
	    type(SS, 221, m200, NULL, "Out");
	    typeflush(SS);
	    /* I want a log entry for when tarpit is complete - jmack Apr,2003 */
	    if (SS->tarpit > OCP->tarpit_initial ) {
		      char *ts = rfc822date(&now);
		      char *n = strchr(ts,'\n');
		      if (n) *n = 0;
		      type(NULL,0,NULL,"tarpit with delay %04d ends at %s", (int)(SS->tarpit_cval), ts );
	    }
		    
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
    }
    if (logfp != NULL) {
	type(NULL,0,NULL,"Session closed w/o QUIT; read() errno=%d",
	     SS->s_readerrno);
	fflush(logfp);
    }

    /* Report failed RCPT counts. */
    if (SS->rcpt_count)
      policytest(&SS->policystate, POLICY_DATAABORT,
		 NULL, SS->rcpt_count, NULL);

    if (logfp && (SS->tarpit > OCP->tarpit_initial)) {
         char *ts = rfc822date(&now);
	 char *n = strchr(ts, '\n');
	 if (n) *n = 0;

	 type(NULL,0,NULL,"tarpit with delay %04d ends at %s", (int)(SS->tarpit_cval), ts );
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
    int bufspace;

#ifdef HAVE_STDARG_H
    va_start(ap, cp);
#else
    SmtpState *SS;
    const char *cp;

    va_start(ap);
    SS = va_arg(ap, SmtpState *);
    cp = va_arg(ap, const char *);
#endif
    memset(buf, 0, sizeof(buf));

    if (SS) {
#ifdef HAVE_SNPRINTF
      snprintf(buf, sizeof(buf)-2, "<%s ", SS->rhostname);
#else
      sprintf(buf, "<%s ", SS->rhostname);
#endif
    }
    s = buf + strlen(buf);
    bufspace = sizeof(buf) - (s - buf) - 2;

#ifdef	HAVE_VSPRINTF
# ifdef HAVE_VSNPRINTF
    vsnprintf(s, bufspace, cp, ap);
# else
    vsprintf(s, cp, ap);
# endif
#else				/* !HAVE_VSPRINTF */
# ifdef HAVE_SNPRINTF
    snprintf(s, bufspace, cp, va_arg(ap, char *));
# else
    sprintf(s, cp, va_arg(ap, char *));
#endif
#endif				/* HAVE_VPRINTF */
#ifdef HAVE_SETPROCTITLE
    setproctitle("%s", buf);
#else
    cmdlen = (eocmdline - cmdline);
    buf[sizeof(buf)-1] = '\0';
    strncpy((char *) cmdline, buf, cmdlen+1);
#endif /* HAVE_SETPROCTITLE */
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

    if (code <= 0) {
	code = -code;
	c = '-';
    } else 
	c = ' ';

    if (!SS) {
      sprintf(buf, "%03d%c", code, c);
    } else {
      sprintf(buf, "%03d%c", code, c);
      if (OCP->enhancedstatusok && status && status[0] != 0)
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


#ifdef HAVE_VSNPRINTF
    {
        int  bufspc  = sizeof(buf) - (s - buf) - 8;

	va_list ap;
#ifdef HAVE_STDARG_H
	va_start(ap, fmt);
#else
	va_start(ap);
#endif
	if (fmt != NULL)
	    vsnprintf(s, bufspc, fmt, ap);
	else
	    vsnprintf(s, bufspc, text, ap);
	va_end(ap);
    }
#else
#ifdef HAVE_VSRINTF
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
#endif

    s += strlen(s);
    buflen = s - buf;

    if (buflen+4 > sizeof(buf)) {
      /* XXX: Buffer overflow ??!! Signal about it, and crash! */
    }

    if (logfp_to_syslog || logfp) time( & now );

    {
      int dt;
      if (logtagepoch)
	dt = (int)(now-logtagepoch);
      else
	dt = 0;

      if (logfp_to_syslog)
	zsyslog((LOG_DEBUG,"%s%04d %c %s", logtag, dt, (SS ? 'w' : '#'), buf));

      if (logfp != NULL) {
	fprintf(logfp, "%s%04d%c\t%s\n", logtag, dt, (SS ? 'w' : '#'), buf);
	fflush(logfp);
      }
    }

    if (debug && !SS && !debug_no_stdout) {
      fprintf(stdout, "%s\n", buf);
      fflush(stdout);
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
      
      le = linebuf + sizeof(linebuf) -8; /* Safety buffer */
      l  = linebuf;

      /* The format meta-tags:
       *
       *  %% -- '%' character
       *  %H -- SS->myhostname
       *  %I -- '+IDENT' if 'identflg' is set
       *  %i -- SS->rhostaddr
       *  %p -- SS->lport
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
	  case 'p':
	    {
	      char p[20];
	      sprintf(p, "%d", SS->lport);
	      len = strlen(p);
	      memcpy(l, p, freespc < len ? freespc : len);
	      l += len;
	    }
	    break;
	  case 'H':
	    len = strlen(SS->myhostname);
	    memcpy(l, SS->myhostname, freespc < len ? freespc : len);
	    l += len;
	    break;
	  case 'i':
	    len = strlen(SS->rhostaddr);
	    memcpy(l, SS->rhostaddr, freespc < len ? freespc : len);
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

    if (OCP->multilinereplies) {
      if (OCP->enhancedstatusok) {
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

      {
	int dt;
	if (logtagepoch)
	  dt = (int)(now-logtagepoch);
	else
	  dt = 0;

	if (logfp_to_syslog)
	  zsyslog((LOG_DEBUG, "%s%04d w %s", logtag, dt, buf));
	if (logfp)
	  fprintf(logfp, "%s%04dw\t%s\n", logtag, dt, buf);
      }

      memcpy(bp, "\r\n",2);
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
    char *ts, *n;

    if (SS->tarpit > 0.9999) {
	/* add this so we know when tarpit is active */
        if (logfp != NULL && SS->tarpit != 0 ) {
	  time(&now);
	  ts = rfc822date(&now);
	  n = strchr(ts, '\n');
	  if (n) *n = 0;

	  type(NULL,0,NULL,"tarpit delay:%04d sec. at %s",
	       (int)(SS->tarpit + 0.500), ts);
          fflush(logfp);
        }
	    
	SS->tarpit_cval += SS->tarpit;

	zsleep((int)(SS->tarpit + 0.500));

	/* adjust tarpit delay and limit here, "after!" the sleep */
	SS->tarpit += (SS->tarpit * OCP->tarpit_exponent);
	/* was 250 - set up to a config param in smtpserver.conf - jmack apr 2003 */
        if (SS->tarpit < 0.0 || SS->tarpit > OCP->tarpit_toplimit )
		SS->tarpit = OCP->tarpit_toplimit;


	/* XX: Count each tarpit call, or just once per connection ? */
	MIBMtaEntry->ss.IncomingSmtpTarpits ++;
    }
}

void
zsleep(delay)
     int delay;
{
#ifdef HAVE_SELECT
	struct timeval tv;
	int rc;

	tv.tv_sec = delay;
	tv.tv_usec = 0;

	rc = select(0, NULL, NULL, NULL, &tv);
#else
	sleep(delay); /* Sigh..  no select..  why we exist at all?? */
#endif
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
