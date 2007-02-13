/*
 *  Globals of the ZMailer  smtp-server
 *
 *  Matti Aarnio <mea@nic.funet.fi> 1997-2005
 */


#define SMTP_COMMAND_ALARM_IVAL 1200	/* 20 minutes.. */
#define SMTP_DATA_TIME_PER_LINE  600	/* 10 minutes of life.. */
#define SMTP_REPLY_ALARM_IVAL    300	/*  5 minutes to write to socket.. */

#define SUBSERVER_IDLE_TIMEOUT   600	/* 10 minutes of idle life.. */

/*
 * The smtpserver connects to the router to ask it various questions, like,
 * is this a valid address?  What is the alias expansion of that? etc.
 * This is done through a portal function called "server".  Its only standard
 * argument is a keyword for what we want done.  These are the definitions:
 */

#ifndef __STDC__
# define const
# define volatile
#endif

#define	ROUTER_SERVER	"server"	/* name of portal function */

#define	RKEY_INIT	"init"		/* initialize state of server	*/
#define	RKEY_FROM	"from"		/* mail from address verification */
#define	RKEY_TO		"to"		/* recipient to address verification */
#define	RKEY_VERIFY	"verify"	/* verify this address		*/
#define	RKEY_EXPAND	"expand"	/* expand this address		*/
#define RKEY_HELLO	"hello"		/* connection from a client	*/

#define SMTPLINESIZE	8192

#include "hostenv.h"

#include <stdio.h>
#ifndef FILE /* Some systems don't have this as a MACRO.. */
# define FILE FILE
#endif
#include <sfio.h>

#include "zmalloc.h"
#include <sys/types.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sysexits.h>
#ifdef HAVE_UNIDSTD_H
#include <unistd.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include "zmsignal.h"
#include <errno.h>
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>		/* If no  <stdarg.h>,  then presume <varargs.h> ... */
#endif

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifndef LONG_MAX
# define LONG_MAX 2147483647L /* For 32 bit machine! */
#endif

#include <netinet/in.h> /* In some systems needed before <arpa/inet.h> */
#include <arpa/inet.h>

#include "mail.h"

#include <setjmp.h>

#ifdef  HAVE_WAITPID
#include <sys/wait.h>
#else
#ifdef HAVE_WAIT4
#include <sys/wait.h>		/* Has BSD wait4() */
#else
#ifdef HAVE_WAIT3
#include <sys/wait.h>		/* Has BSD wait3() */
#else
#ifdef HAVE_SYS_WAIT_H		/* POSIX.1 compatible */
#include <sys/wait.h>
#else				/* Not POSIX.1 compatible, lets fake it.. */
extern int wait();
#endif
#endif
#endif
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifndef EAI_AGAIN
# include "netdb6.h"
#endif

#include <sys/socket.h>
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#include <netinet/in.h>
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#else
#ifdef HAVE_NETINET6_IN6_H
#include <netinet6/in6.h>
#else
#ifdef HAVE_LINUX_IN6_H
#include <linux/in6.h>
#endif
#endif
#endif
#include <arpa/inet.h>

#include "libc.h"
#include "libz.h"

#include "shmmib.h"

#ifndef	SIGCHLD
#define	SIGCHLD	SIGCLD
#endif				/* SIGCHLD */

#ifndef	MAXHOSTNAMELEN
#define	MAXHOSTNAMELEN 256
#endif				/* MAXHOSTNAMELEN */

#include "zsyslog.h"



#include <sys/time.h>

#include "zmpoll.h"

#ifdef HAVE_SPF2_SPF_H
#include <spf2/spf.h>
#else
#ifdef HAVE_SPF_ALT_SPF_H
#include <spf_alt/spf.h>
#endif
#endif

#include "policytest.h"

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#endif /* - HAVE_OPENSSL */

#ifdef HAVE_SASL2
#ifdef HAVE_SASL_SASL_H
#include <sasl/sasl.h>
#include <sasl/saslutil.h>
#else
# error "No <sasl/sasl.h> available!"
#endif
#endif


struct smtpconf {
    const char *pattern;
    int maxloadavg;
    const char *flags;
    struct smtpconf *next;
};

typedef enum {
    Null, Hello, Mail, MailOrHello, Recipient,
    RecipientOrData, Data, Send, SendOrMail,
    SendAndMail, Reset, Verify, Expand, Help,
    NoOp, Quit, Turn, Tick, Verbose, DebugIdent,
    Turnme, BData, DebugMode, Auth, Report,
#ifdef HAVE_OPENSSL
    StartTLS,
#endif /* - HAVE_OPENSSL */
    Hello2, Mail2, Send2, Verify2,	/* 8-bit extensions */
    HelloL,		/* RFC 2033 LHLO -- sort of */
    Silent		/* One particular client error trap.. */
} Command;


struct command {
    const char *verb;
    Command cmd;
};

extern struct command command_list[];

#ifdef HAVE_OPENSSL

#define CCERT_BUFSIZ 256

struct smtpserver_ssl_subset {
    SSL * ssl;

    const char *protocol;
    const char *cipher_name;
    int         cipher_usebits;
    int         cipher_algbits;

    int  peer_verified;

    const char *cipher_info;
    const char *issuer_CN;
    const char *peer_issuer;
    const char *peer_CN;
    const char *peer_subject;
    const char *peer_fingerprint;

    unsigned char peer_md[EVP_MAX_MD_SIZE];
};


#endif /* - HAVE_OPENSSL */

#ifdef HAVE_SASL2
struct SmtpSASLState {
    char  *volatile auth_type;
    const char *mechlist;
    sasl_conn_t *conn;
    int sasl_ok;
    unsigned int n_auth;	/* count of AUTH commands */
    unsigned int n_mechs;
    unsigned int len;
    sasl_security_properties_t ssp;
#if 0 /* Is in SASL-1, different/not in SASL-2 */
#ifdef SASL_SSF_EXTERNAL
    sasl_external_properties_t ext_ssf;
#endif
#endif
    sasl_ssf_t *ssf;
};
#endif /* HAVE_SASL2 */



typedef struct SmtpState {
    int  outputfd;		/* stdout */
    int  inputfd;		/* stdin  */
    FILE *mfp;			/* Storage-bound mail-file fp */
    long messagesize;		/* Reset at MAIL, add at BDATs / DATA */
    long sizeoptval;		/* "MAIL FROM:<xxx> SIZE=nnn" -value    */
    long sizeoptsum;

    int  with_protocol_set;	/* = WITH_SMTP */
#define WITH_HELO		0x0001
#define WITH_EHLO		0x0002
#define WITH_SMTP		0x0004
#define WITH_SUBMIT		0x0008
#define WITH_SMTPS		0x0010
#define WITH_TLS		0x0020
#define WITH_AUTH		0x0040
#define WITH_LMTP		0x0080
#define WITH_BSMTP		0x0100

    const char *style;		/* = "ve" */
    Command state;		/* = Hello */
    int  VerboseCommand;
    struct command *carp;
    struct policystate policystate;
    int  policyresult, reject_net;
    int  postmasteronly;
    int  netconnected_flg;
    double  tarpit;
    double  tarpit_cval;		/* current tarpit value */

    char myhostname[MAXHOSTNAMELEN + 1];
    char rhostname[MAXHOSTNAMELEN + 1];
    int  rhostflags;
#define RHOST_REVERSED_OK	0x0001
#define RHOST_REVERSED_FAIL	0x0002
#define RHOST_VERIFIED_OK	0x0010
#define RHOST_VERIFIED_FAIL	0x0020
#define RHOST_HELO_SYNTAX_OK	0x0100
#define RHOST_HELO_SYNTAX_FAIL	0x0200
#define RHOST_HELO_VERIFY_OK	0x1000
#define RHOST_HELO_VERIFY_FAIL	0x2000

    char rhostaddr[sizeof("[ipv6.ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]") + 8];
    int  rport;
    int  lport;
    Usockaddr raddr;
    Usockaddr localsock;

    const char * smtpfrom;	/* MAIL FROM:<...> */
    time_t  deliverby_time;	/* RFC 2852 */
    int	    deliverby_flags;
#define DELIVERBY_R  1
#define DELIVERBY_N  2
#define DELIVERBY_T  4

    char *sslwrbuf;		/* Despite of the name, all modes
				   use this write-out buffer.. */
    int   sslwrspace, sslwrin, sslwrout;
    /* space, how much stuff in, where the output cursor is */

    int   sslmode;		/* Set, when SSL/TLS in running */
#ifdef HAVE_OPENSSL
    struct smtpserver_ssl_subset TLS; /* TLS specific things */
#endif /* - HAVE_OPENSSL */

    int  read_alarm_ival;
    int  s_bufread;
    int  s_readout;
    int  s_status;
    int  s_readerrno;
    int  s_seen_eof;
    char s_buffer[64*1024];	/* 64 kB */
    int  s_buffer_size;		/* adjustable max size.. */
    int  s_ungetcbuf;
    int  s_seen_pipeline;

    int  from_box;		/* Set when:  MAIL FROM:<>  */
    int  rcpt_count;
    int  ok_rcpt_count;
    int  sender_ok;

    /* For BDAT -command */
    int  bdata_blocknum;
    int  mvbstate;

    /* Who have we been authenticated as ? */
    char *authuser;

    char ident_username[MAXHOSTNAMELEN + MAXHOSTNAMELEN + 2];
    char helobuf[200]; /* Carefully limited copy into this buffer */
    struct smtpconf *cfinfo;

#ifdef HAVE_WHOSON_H
    int whoson_result;
    char whoson_data[128];
#endif

    int unknown_cmd_count;
    long sameipcount;

#ifdef HAVE_SASL2
    struct SmtpSASLState sasl;
#endif

    void *irouter_state;
} SmtpState;


#define STYLE(i,c)	(strchr(((i)==NULL ? style : (i)->flags), (c)) != NULL)

#define HELPMAX 40
extern char *helplines[];
#define HDR220MAX 4
extern char *hdr220lines[];
extern char logtag[];
extern time_t logtagepoch, now;

/* Spool related counters */
extern long availspace;
extern long minimum_availspace;
extern long maxsize;


/* Global parameters */
extern int use_ipv6;
extern int MaxSameIpSource;
extern int MaxParallelConnections;
extern int percent_accept;
extern int smtp_syslog;
extern int allow_source_route;

extern char *contentfilter;
extern int debug_content_filter;
extern char *perlhookpath;
extern int use_perlhook;

extern int enable_router;
extern int enable_router_maxpar;
extern int configuration_ok;
extern int unknown_cmd_limit;

extern int msa_mode;  /* ?? */
extern int sum_sizeoption_value;
extern int lmtp_mode;


#define MAX_SMTPSERVER_CLUSTER_IDX 40
typedef struct {
  Usockaddr addr;
  char *secret;
} smtpserver_cluster_ent;
extern smtpserver_cluster_ent smtpserver_cluster[];

#define MAX_ETRN_CLUSTER_IDX       40
typedef struct {  /* Talks with SCHEDULER process */
  char *nodename;
  char *username;
  char *password;
} etrn_cluster_ent;
extern etrn_cluster_ent etrn_cluster[];

typedef struct ConfigParams_ {
  double tarpit_initial;
  double tarpit_exponent;
  double tarpit_toplimit;

  int MaxErrorRecipients;
  int TcpRcvBufferSize;
  int TcpXmitBufferSize;
  int ListenQueueSize;

  struct policytest *policydb; /* group, can default */

  int log_rcvd_whoson, log_rcvd_ident, log_rcvd_authuser;
  int log_rcvd_tls_mode, log_rcvd_tls_peer;

  int auth_ok;
  int auth_login_without_tls;
  int no_smtp_auth_on_25;
  char *smtp_auth_username_prompt; /* group, can default */
  char *smtp_auth_password_prompt; /* group, can default */
  int auth_failrate;

  char *smtpauth_via_pipe;		/* group, can default */
  const char *SASL_Auth_Mechanisms;	/* group, can default */
  int do_sasl;
  int MaxSLBits;
  char *AuthMechanisms;			/* group, can default */

  int ehlo_ok;
  int etrn_ok;
  int starttls_ok;
  int deliverby_ok;
  int ssmtp_listen;
  int submit_listen;
  int debugcmdok;
  int expncmdok;
  int vrfycmdok;
  int pipeliningok;
  int mime8bitok;
  int chunkingok;
  int enhancedstatusok;
  int multilinereplies;
  int dsn_ok;

	/* group, can default */
  const char *tls_cert_file, *tls_key_file, *tls_CAfile, *tls_CApath;
  const char *tls_dcert_file, *tls_dkey_file, *tls_dh1024_param;
  const char *tls_dh512_param;
  const char *tls_random_source;
  const char *tls_cipherlist;
  int tls_loglevel, tls_enforce_tls, tls_ccert_vd;
  int tls_ask_cert, tls_req_cert;

  int tls_scache_timeout, tls_use_scache;
  char *tls_scache_name;


  const char *contact_pointer_message; 	/* group, can default */

  const char *reportauthfile;		/* group, can default */

  int rcptlimitcnt;
  int use_tcpwrapper;

  int detect_incorrect_tls_use;
  int force_rcpt_notify_never;

  int use_spf, spf_received, spf_threshold, spf_whitelist_use_default;
  char *spf_localpolicy;		/* group, can default */

		/* group locals: */
  int bindaddr_set;
  Usockaddr *bindaddrs;
  int       *bindaddrs_types;
  int       *bindaddrs_ports;
  int        bindaddrs_count;
#define BINDADDR_ALL    0xFFFF
#define BINDADDR_SMTP   0x0001
#define BINDADDR_SMTPS  0x0002
#define BINDADDR_SUBMIT 0x0004
} ConfigParams;

extern ConfigParams CPdefault;
extern ConfigParams **CPpSet;
extern int CPpSetSize;
extern ConfigParams *CP;
extern ConfigParams *OCP;

extern int bindport_set;
extern u_short   bindport;

extern int strict_protocol;

extern int testaddr_set;
extern  Usockaddr testaddr;


extern const char *progname;
extern int debug, skeptical, checkhelo, ident_flag, verbose, daemon_flg;

extern const char *style;

extern struct smtpconf *readcffile __((const char *fname));
extern struct smtpconf *findcf __((const char *host));
extern void ConfigParams_newgroup __((void));

extern int loadavg_current __((void));

extern const char *rfc821_domain __((const char *s, int strict));
extern const char *rfc821_path __((const char *s, int strict));
extern const char *rfc821_path2 __((const char *s, int strict));
extern const char *rfc821_error;
extern const char *rfc821_error_ptr;
#ifdef HAVE_STDARG_H
extern void type821err __((SmtpState *, const int code, const char *status,
			   const char *inbuf, const char *fmt,...));
#else
extern void type821err __(());
#endif

extern struct smtpconf *cfhead;

extern void reporterr __((SmtpState *, long, const char *));

extern const char *Copyright;
extern const char *Copyright2;
extern FILE *logfp;
extern int   logfp_to_syslog;
extern int pid;

extern char *routerprog;
extern int routerpid;
extern int router_status;

extern const char *m200;
extern const char *m400;
extern const char *m410;
extern const char *m412;
extern const char *m413;
extern const char *m415;
extern const char *m417;
extern const char *m418;
extern const char *m430;
extern const char *m431;
extern const char *m433;
extern const char *m443;
extern const char *m454;
extern const char *m471;
extern const char *m510;
extern const char *m512;
extern const char *m513;
extern const char *m515;
extern const char *m517;
extern const char *m518;
extern const char *m530;
extern const char *m534;
extern const char *m540;
extern const char *m543;
extern const char *m550;
extern const char *m551;
extern const char *m552;
extern const char *m554;
extern const char *m571;

extern int getpeername();
extern int isit42inetd();

#ifdef USE_TRANSLATION
extern int X_8bit;
extern int X_translation;
extern int X_settrrc;
extern void header_from_mime __((char *, int *, int));
#endif				/* USE_TRANSLATION */

extern void killcfilter __((SmtpState * SS));
extern void typeflush __((SmtpState *));
#if defined(HAVE_STDARG_H) && defined(HAVE_VPRINTF)
extern void type __((SmtpState *, int code, const char *status, const char *fmt,...));
extern void Z_printf __(( SmtpState *, const char *fmt, ... ));
#else
extern void type __(( /* SmtpState *SS, int code, const char *status, const char *fmt, ... */ ));
extern void Z_printf __(( /* SmtpState *, const char *fmt, ... */ ));
#endif
extern void debug_report __((SmtpState *, int, const char *, const char *));
extern void header_to_mime __((char *, int *, int));
extern void help __((SmtpState *, struct smtpconf *, const char *));
extern time_t time __((time_t *));
extern char *router __((SmtpState *, const char *, const int, const char *, const int));
#ifndef MALLOC_TRACE		/* turns these into macroes.. */
#ifndef __XMALLOC_H__		/* at ../include/malloc.h */
extern univptr_t emalloc __((size_t));
extern univptr_t erealloc __((void *, size_t));
#endif
#endif
extern void runasrootuser __((void));
extern int runastrusteduser __((void));
extern char **environ;
extern int kill __((pid_t, int));
extern RETSIGTYPE sigchld  __((int sig));
extern volatile int sawsigchld;

extern const char *rfc822atom __((const char *str));
extern const char *xtext_string __((const char *str));

extern void s_ungetc __((SmtpState *SS, int ch));
extern int s_feof __((SmtpState * SS));
extern int s_seen_eof __((SmtpState * SS));
extern int s_getc __((SmtpState * SS, int timeout_is_fatal));
extern int s_hasinput __((SmtpState * SS));
extern int s_gets __((SmtpState *SS, char *buf, int buflen, int *rcp, char *cop, char *cp));

extern void zsleep __((int delay));

extern int errno;
extern int optind;
extern char *optarg;

#ifndef CISTREQN
#define   CISTREQN(x, y, n)  (cistrncmp((x), (y), n) == 0)
#endif
#ifndef CISTREQ
#define   CISTREQ(x, y)  (cistrcmp((x), (y)) == 0)
#endif

#ifdef	lint
#undef	putc
#define	putc	fputc
#endif				/* lint */

extern int  childsameip __((Usockaddr *addr, int, int *childcntp));
extern void childregister __((int cpid, Usockaddr *addr, int tag));
extern void childreap   __((int cpid));
extern void disable_childreap __((void));

extern void smtp_helo   __((SmtpState * SS, const char *buf, const char *cp));
extern int  smtp_mail   __((SmtpState * SS, const char *buf, const char *cp, int insecure));
extern int  smtp_rcpt   __((SmtpState * SS, const char *buf, const char *cp));
extern void smtp_turnme __((SmtpState * SS, const char *name, const char *cp));
extern void smtp_verify __((SmtpState * SS, const char *buf, const char *cp));
extern void smtp_expand __((SmtpState * SS, const char *buf, const char *cp));
extern int  smtp_data   __((SmtpState * SS, const char *buf, const char *cp));
extern int  smtp_bdata  __((SmtpState * SS, const char *buf, const char *cp));
extern void add_to_toplevels __((char *str));
extern void smtp_tarpit __((SmtpState * SS));

extern void smtp_auth __((SmtpState * SS, const char *buf, const char *cp));
extern void smtpauth_init __((SmtpState * SS));
extern void smtpauth_ehloresponse __((SmtpState * SS));
extern int  smtp_report __((SmtpState * SS, const char *buf, char *cp));

#ifdef HAVE_OPENSSL
extern int tls_start_servertls __((SmtpState *SS));
extern void smtp_starttls __((SmtpState * SS, const char *buf, const char *cp));
extern void Z_init    __(( void ));
extern void Z_cleanup __(( SmtpState * ));
extern int  Z_SSL_flush __(( SmtpState * ));
#endif /* - HAVE_OPENSSL */
extern int  Z_pending __(( SmtpState * ));
extern int  Z_write   __(( SmtpState *, const void *, int ));
extern int  Z_read    __(( SmtpState *, void *, int ));

#ifdef USE_TCPWRAPPER
#ifdef HAVE_TCPD_H		/* The hall-mark of having tcp-wrapper things around */
extern int wantconn __((int sock, char *prgname));
#endif
#endif

extern char *rfc822date __((time_t *));

#ifdef HAVE_STDARG_H		/* Fwd declaration */
 void report __((SmtpState *, const char *,...));
#else
 void report __(());
#endif

extern int encodebase64string __((const char *instr, int inlen, char *outstr, int outspc));
extern int decodebase64string __((const char *instr, int inlen, char *outstr, int outspc, const char **inleftover));

/* transports/libta/nonblocking.c */
extern int  fd_nonblockingmode __((int fd));
extern int  fd_blockingmode __((int fd));
extern void fd_restoremode __((int fd, int mode));

/* subdaemons.c */
extern int  subdaemons_init                   __((void));
extern int  subdaemons_init_router            __((void));
extern int  subdaemons_init_ratetracker       __((void));
extern int  subdaemons_init_contentfilter     __((void));
extern void subdaemons_kill_cluster_listeners __((void));

struct fdgets_fdbuf {
	int rdsize;
	char rdbuf[100];
};
extern int fdgets __((char **bufp, int endi, int *buflenp, struct fdgets_fdbuf *fdp, int fd, int timeout));

extern int  ratetracker_rdz_fd;
extern int  ratetracker_server_pid;

extern int  router_rdz_fd;
extern int  router_server_pid;

extern int  contentfilter_rdz_fd;
extern int  contentfilter_server_pid;


struct peerhead;           /* Forward declarator */
struct subdaemon_handler;  /* Forward declarator */

struct peerdata {
	int  fd;
	int  inlen;
	int  outlen, outptr;
	int  inpspace;
	int  outspace;
	int  in_job;		/* A job ready to send to server.. */
	time_t when_in;		/* Arrival time */
	char *inpbuf;		/* Grown to fit in an input line..
				   The input protocol shall be SINGLE
				   text line with '\n' at the end! */
	char *outbuf;		/* Written out "synchronously" to the
				   socket/pipe buffer space.
				   About 200 chars should be enough.
				   If not, adding automated buffer
				   expansion codes is trivialish...  */
	struct peerdata *prev, *next;	/* Job order.  Add to tail,
					   process from head. */
	struct peerhead *head;
	struct subdaemon_handler *handler;
	struct zmpollfd *pollfd;
};

struct peerhead {
	struct peerdata		* head;
	struct peerdata		* tail;
	int			  queuecount;
};

struct subdaemon_state {
  void *p; /* dummy */
};

struct subdaemon_handler {
	int (*init)      __((struct subdaemon_state **statepp));
	int (*input)     __((struct subdaemon_state *state, struct peerdata *));
	int (*prepoll)   __((struct subdaemon_state *state, struct zmpollfd **fds, int *fdcount));
	int (*postpoll)  __((struct subdaemon_state *state, struct zmpollfd *fds, int fdcount));
	int (*shutdown)  __((struct subdaemon_state *state));
        int (*killpeer)  __((struct subdaemon_state *state, struct peerdata *));
	int (*reaper)    __((struct subdaemon_state *state));
	int (*sigusr2)   __((struct subdaemon_state *state));
	Vuint *reply_delay_G;	/* MIB variable pointer */
	Vuint *reply_queue_G;   /* MIB variable pointer */
};

extern int subdaemon_send_to_peer __((struct peerdata *, const char *, int));


extern struct subdaemon_handler subdaemon_handler_ratetracker;
extern struct subdaemon_handler subdaemon_handler_contentfilter;

extern void subdaemon_router        __((int fd));
extern void subdaemon_ratetracker   __((int fd));
extern void subdaemon_contentfilter __((int fd));

/* subdaemon-rtr.c */
extern char * call_subdaemon_rtr __((void **, const char*, const char *, int, int*));
extern struct subdaemon_handler subdaemon_handler_router;

/* subdaemon-trk.c */
extern int call_subdaemon_trk __((void **statep,const char *cmd, char *retbuf, int retbuflen));
extern int call_subdaemon_trk_getmore __((void *statep,char *retbuf, int retbuflen));
extern int  smtp_report_ip __((SmtpState *SS, const char *ip));
extern int  smtp_report_dump __((SmtpState *SS));
extern int  call_rate_counter __((struct policystate *state, int incr, PolicyTest what, int *countp, int *countp2));




/* contentpolicy.c */
extern int contentpolicy __((struct policystate *ps, const char *fname));
/* subdaemon-ctf.c */
extern int contentfilter_maxctfs;
extern char *contentfilter_proc __((void **, const char *fname));
extern void  smtpcontentfilter_kill __((void *));

extern int mx_client_verify  __((struct policystate *, int, const char *, int));
extern int sender_dns_verify __((struct policystate *, int, const char *, int));
extern int client_dns_verify __((struct policystate *, int, const char *, int));
extern int rbl_dns_test __((struct policystate *, const int, const u_char *, char *, char **));

/* smtphook.c */
#ifdef DO_PERL_EMBED

#define ZSMTP_HOOK_HELO        "ZSMTP::hook::helo"
#define ZSMTP_HOOK_RSET        "ZSMTP::hook::rset"
#define ZSMTP_HOOK_MAILFROM    "ZSMTP::hook::mailfrom"
#define ZSMTP_HOOK_RCPTTO      "ZSMTP::hook::rcptto"
#define ZSMTP_HOOK_DATA        "ZSMTP::hook::data"

extern int  ZSMTP_hook_init          __((void));
extern void ZSMTP_hook_atexit        __((void));
extern void ZSMTP_hook_set_ipaddress __((const char *, int, const char *, const char *, int, const char *));
extern void ZSMTP_hook_set_user      __((const char *, const char *));
extern int  ZSMTP_hook_univ          __((const char *, struct policystate *, const char *, const int, int *));

#endif
