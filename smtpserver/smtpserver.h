/*
 *  Globals of the ZMailer  smtp-server
 *
 *  Matti Aarnio <mea@nic.funet.fi> 1997-1999
 */


#define SMTP_COMMAND_ALARM_IVAL 1200	/* 20 minutes.. */
#define SMTP_DATA_TIME_PER_LINE  600	/* 10 minutes of life.. */

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

#include <netinet/in.h> /* In some systems needed before <arpa/inet.h> */
#include <arpa/inet.h>

#include "mail.h"

#include <setjmp.h>

#ifdef  HAVE_WAITPID
#include <sys/wait.h>
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

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include <sys/socket.h>
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

#include "libc.h"
#include "libz.h"

#ifndef	SIGCHLD
#define	SIGCHLD	SIGCLD
#endif				/* SIGCHLD */

#ifndef	MAXHOSTNAMELEN
#define	MAXHOSTNAMELEN 256
#endif				/* MAXHOSTNAMELEN */

#include "zsyslog.h"


#ifndef __Usockaddr__
typedef union {
    struct sockaddr_in v4;
#ifdef INET6
    struct sockaddr_in6 v6;
#endif
} Usockaddr;
#define __Usockaddr__
#endif


#include "policytest.h"

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif /* - HAVE_OPENSSL */

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
    Turnme, BData, DebugMode, Auth,
#ifdef HAVE_OPENSSL
    StartTLS,
#endif /* - HAVE_OPENSSL */
    Hello2, Mail2, Send2, Verify2	/* 8-bit extensions */
} Command;


struct command {
    const char *verb;
    Command cmd;
};

extern struct command command_list[];

typedef struct {
    FILE *outfp;		/* stdout */
    int  inputfd;		/* stdin  */
    FILE *mfp;			/* Storage-bound mail-file fp */
    long sizeoptval;		/* "MAIL FROM:<xxx> SIZE=nnn" -value    */
    long sizeoptsum;
    char myhostname[MAXHOSTNAMELEN + 1];
    char rhostname[MAXHOSTNAMELEN + 1];
    const char *with_protocol;	/* = WITH_SMTP */
    const char *style;		/* = "ve" */
    Command state;		/* = Hello */
    int  VerboseCommand;
    struct command *carp;
    struct policystate policystate;
    int  policyresult, reject_net;
    int  postmasteronly;
    int  tarpit;
    int  rport;
    char ihostaddr[sizeof("[ipv6.ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]") + 8];
    Usockaddr raddr;
    Usockaddr localsock;

    int   sslmode;		/* Set, when SSL/TLS in running */
#ifdef HAVE_OPENSSL
    SSL * ssl;
    char *sslwrbuf;
    int   sslwrspace, sslwrin, sslwrout;
    /* space, how much stuff in, where the output cursor is */
#endif /* - HAVE_OPENSSL */
    char *tls_cipher_info;
    char *tls_peer_subject;
    char *tls_peer_issuer;
    char *tls_peer_fingerprint;

    int  s_bufread;
    int  s_readout;
    int  s_status;
    char s_buffer[SMTPLINESIZE];

    int  from_box;		/* Set when:  MAIL FROM:<>  */
    int  rcpt_count;
    int  sender_ok;
    /* For BDAT -command */
    int  bdata_blocknum;
    int  mvbstate;
    char *authuser;

    char ident_username[MAXHOSTNAMELEN + MAXHOSTNAMELEN + 2];
    char helobuf[200]; /* Carefully limited copy into this buffer */
    struct smtpconf *cfinfo;

#ifdef HAVE_WHOSON_H
    int whoson_result;
    char whoson_data[128];
#endif

} SmtpState;

#define STYLE(i,c)	(strchr(((i)==NULL ? style : (i)->flags), (c)) != NULL)

#define	WITH_SMTP	"SMTP"
#define	WITH_ESMTP	"ESMTP"
#define	WITH_BSMTP	"BSMTP"

#define HELPMAX 40
extern char *helplines[];
#define HDR220MAX 4
extern char *hdr220lines[];
extern char logtag[];

extern long availspace;
extern long minimum_availspace;
extern long maxsize;
extern int tarpit_initial;
extern int tarpit_exponent;
extern int MaxErrorRecipients;
extern int TcpRcvBufferSize;
extern int TcpXmitBufferSize;
extern int ListenQueueSize;
extern int MaxSameIpSource;
extern int MaxParallelConnections;
extern int percent_accept;
extern int smtp_syslog;
extern int allow_source_route;
extern int debugcmdok;
extern int expncmdok;
extern int vrfycmdok;
extern int pipeliningok;
extern int mime8bitok;
extern int chunkingok;
extern int enhancedstatusok;
extern int multilinereplies;
extern int dsn_ok;
extern int auth_ok;
extern int ehlo_ok;
extern int etrn_ok;
extern int starttls_ok;
extern int msa_mode;
extern char *tls_cert_file, *tls_key_file, *tls_CAfile, *tls_CApath;
extern int tls_loglevel, tls_enforce_tls, tls_ccert_vd, tls_use_scache;
extern int tls_ask_cert, tls_req_cert, tls_scache_timeout;
extern int log_rcvd_whoson, log_rcvd_ident, log_rcvd_authuser;
extern int log_rcvd_tls_mode, log_rcvd_tls_peer;
extern int auth_login_without_tls;
extern char *smtpauth_via_pipe;
extern int strict_protocol;
extern int rcptlimitcnt;
extern int enable_router;
extern int use_tcpwrapper;

extern int bindaddr_set, bindport_set;
extern u_short   bindport;
extern Usockaddr bindaddr;

extern const char *progname;
extern int debug, skeptical, checkhelo, ident_flag, verbose;

extern const char *style;

extern struct smtpconf *readcffile __((const char *fname));
extern struct smtpconf *findcf __((const char *host));

extern int loadavg_current __((void));
extern long fd_statfs __((int));

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

extern void killr __((SmtpState * SS, int rpid));
extern void typeflush __((SmtpState *));
#if defined(HAVE_STDARG_H) && defined(HAVE_VPRINTF)
extern void type __((SmtpState *, const int code, const char *status, const char *fmt,...));
#else
extern void type __(( /* SmtpState *SS, int code, const char *status, const char *fmt, ... */ ));
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

extern const char *rfc822atom __((const char *str));
extern const char *xtext_string __((const char *str));

extern void s_setup __((SmtpState * SS, int infd, int outfd));
extern int s_feof __((SmtpState * SS));
extern int s_getc __((SmtpState * SS));
extern int s_hasinput __((SmtpState * SS));
extern int s_gets __((SmtpState *SS, char *buf, int buflen, int *rcp, char *cop, char *cp));

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

extern int  childsameip __((Usockaddr *addr, int *childcntp));
extern void childregister __((int cpid, Usockaddr *addr));
extern void childreap   __((int cpid));

extern void smtp_helo   __((SmtpState * SS, const char *buf, const char *cp));
extern void smtp_mail   __((SmtpState * SS, const char *buf, const char *cp, int insecure));
extern void smtp_rcpt   __((SmtpState * SS, const char *buf, const char *cp));
extern void smtp_turnme __((SmtpState * SS, const char *name, const char *cp));
extern void smtp_verify __((SmtpState * SS, const char *buf, const char *cp));
extern void smtp_expand __((SmtpState * SS, const char *buf, const char *cp));
extern int  smtp_data   __((SmtpState * SS, const char *buf, const char *cp));
extern int  smtp_bdata  __((SmtpState * SS, const char *buf, const char *cp));
extern void add_to_toplevels __((char *str));
extern void smtp_tarpit __((SmtpState * SS));

extern void smtp_auth __((SmtpState * SS, const char *buf, const char *cp));

#ifdef HAVE_OPENSSL
extern void smtp_starttls __((SmtpState * SS, const char *buf, const char *cp));
extern void Z_init    __(( void ));
extern void Z_cleanup __(( SmtpState * ));
#endif /* - HAVE_OPENSSL */
extern int  Z_pending __(( SmtpState * ));
extern int  Z_write   __(( SmtpState *, const void *, int ));
extern int  Z_read    __(( SmtpState *, void *, int ));

#ifdef HAVE_TCPD_H		/* The hall-mark of having tcp-wrapper things around */
extern int wantconn __((int sock, char *prgname));
#endif
extern char *rfc822date __((time_t *));

#ifdef HAVE_STDARG_H		/* Fwd declaration */
 void report __((SmtpState *, const char *,...));
#else
 void report __(());
#endif

extern int encodebase64string __((const char *instr, int inlen, char *outstr, int outspc));
extern int decodebase64string __((const char *instr, int inlen, char *outstr, int outspc, const char **inleftover));
