/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include "hostenv.h"

#include <stdio.h>
#ifndef FILE /* Some systems don't have this as a MACRO.. */
# define FILE FILE
#endif
#include <sfio.h>

#ifndef __
# ifdef __STDC__
#  define __(x) x
# else
#  define __(x) ()
#  define const
#  define volatile
#  define void
# endif
#endif

#if !defined(S_IFMT) || defined(STDC_HEADERS)
#include <sys/stat.h>
#endif	/* S_IFMT */

/* #include "zmalloc.h" -- included also in begin of "listutils.h" */
#include "listutils.h"
#include "token.h"
#include "splay.h"

#if 0
#ifndef	HAVE_FCHOWN
#define	fchown	(void)
#endif	/* HAVE_FCHOWN */
#ifndef	HAVE_FCHMOD
#define	fchmod	(void)
#endif	/* HAVE_FCHMOD */
#ifndef	HAVE_LSTAT
#define	lstat	stat
#endif	/* HAVE_LSTAT */
#endif

#define	RFC974			/* enable RFC974 compatibility */
#define RFC976			/* enable RFC976 compatibility */

#ifndef	NULL
#define NULL	0
#endif	/* !NULL */

#ifndef	_IOLBF
#define _IOFBF	0
#define	_IONBF	04
#define	_IOLBF	0200
#endif	/* !_IOLBF */

#define	DOLLAR '\007'		/* What $ in the config file translates to */
#define	AMPERSAND '\010'	/* What & in the config file translates to */

#define	CROSSBAR	"crossbar"
#define ROUTER		"router"
#define SERVER		"server"
#define FREEZER		"freezer"

#define	DEFER		"defer"
#define	DEFER_IO_ERROR	"IO:error"

#define DEFERHDR	"header_defer"

#define DBLOOKUPNAME	"%dblookup"

#include "memtypes.h"

#define	PERR_OK			0
#define	PERR_USAGE		100
#define	PERR_BADOPEN		101
#define	PERR_BADCONTINUATION	102
#define	PERR_BADSUBMIT		103
#define	PERR_LOOP		104
#define	PERR_ENVELOPE		105
#define	PERR_DEFERRED		106
#define	PERR_HEADER		107
#define	PERR_NORECIPIENTS	108
#define	PERR_NOSENDER		109
#define	PERR_CTRLFILE		110

#define	FYI_BREAKIN		0
#define	FYI_BADHEADER		1
#define	FYI_ILLHEADER		2
#define	FYI_NOCHANNEL		3
#define	FYI_NOSENDER		4


extern char	*linebuf;

#define  TOKENLEN(t) ((t)->t_len > 0 ? (int) (t)->t_len : strlen((const char *)(t)->t_pname))

#if	defined(lint) && defined(putc)
#undef	putc
#define	putc	(void) fputc
#endif	/* lint */


typedef enum {
	aPhrase, aComment, aSpecial, aGroup, anAddress, aDomain, aWord,
	reSync, anError /*, aSpace*/
} AddrComponent;

struct addr {
	AddrComponent	p_type;
	token822	*p_tokens;
	struct addr	*p_next;
};

typedef enum { newAddress, BadAddress } AddressStamp;

struct notary {
	const char	*envid;
	const char	*ret;
	const char	*dsn;
};

struct address {
	const char	*a_pname;		/* printable representation */
	struct addr	*a_tokens;		/* RFC822 token list */
	AddressStamp	a_stamp;		/* what this is */
	/* XX: this should be changed to a list of tags */
	int		a_uid;			/* uid for delivery */
	struct address	*a_next;
	struct notary   *a_dsn;			/* NOTARY data for this addr */
};

/* These bits make sense in an a_flags field: */

struct received {
	struct address	*r_from;	
	struct address	*r_by;
	token822	*r_via;
	token822	*r_with;
	struct address	*r_id;
	struct address	*r_for;
	token822	*r_convert;
	time_t		r_time;
};

union misc {					/* what a header can be */
	struct address	*a;
	token822	*t;
	struct received	*r;
	time_t		d; 
};

#include "rfc822.entry"

/* Header ENVELOPE data names re listed in  SRC/router/libdb/header.c */

typedef enum {	nilUserType,	/* nil */
		Sender,		/* this is a sender address field */
		Recipient,	/* this is a recipient address field */
		killUserType	/* to be killed when sighted! */
} HeaderUserType;

typedef enum {	normal,		/* nil */
		Resent,		/* this is a resent- header field */
		eIdentinfo,	/* identification info		  */
		eChannel,	/* received by this transport channel (mailer)*/
		eExternal,	/* external source of info, untrustable */
		eEnvid,		/* SMTP-DSN ENVID string */
		eFrom,		/* envelope sender address */
		eFullname,	/* use this as my full name, for local users */
		eNotaryRet,	/* SMTP-DSN RET token: FULL/HDRS */
		ePrettyLogin,	/* use this as my pretty login name, ditto. */
		eRcvdFrom,	/* previous host/user in reverse route */
		eTo,		/* envelope recipient address */
		eToDSN,		/* DSN RCPT data entries (NOTIFY,ORCPT) */
		eUser,		/* user at previous host in rev route */
		eVerbose,	/* verbose log filename for "mail -v" */
		eVia,		/* received via <medium> */
		eWith,		/* received with <protocol> */
		eBodytype,	/* The user has given some sendmail -B -option */
		eComment,	/* just ignorable comments */
		eEnvEnd		/* Last of the envelope entries "env-end" */
} HeaderClass;

struct headerinfo {
	const char	*hdr_name;
	HeaderSemantics	semantics;	/* information on header type */
	HeaderUserType	user_type;	/* sender / recipient address */
	HeaderClass	class;		/* resent- or envelope header */
};

typedef enum {
	newHeader,
	BadHeader		/* one of the addresses are a BadAddress */
} HeaderStamp;

struct header {
	const char	*h_pname;	/* printable representation */
	union misc	h_contents;	/* contents depending on type */
	struct headerinfo *h_descriptor; /* characteristics of header */
	token822	*h_lines;	/* original header lines */
	HeaderStamp	h_stamp;	/* what this is */
	struct header	*h_next;
};

#if 0
struct triple {
	const char	*channel;	/* channel message arrived on */
	const char	*host;		/* host the mesg arrived from */
	const char	*user;		/* user address wrt that host */
};

struct msgident {
	struct triple	*trp;		/* the triple we have seen */
	int		flags;		/* flags for loop control */
	struct msgident *next;
};
#endif

struct envelope {
	struct header	*e_eHeaders;	/* envelope headers		*/
	struct header	*e_headers;	/* message headers		*/
	struct stat	e_statbuf;	/* stat information on file	*/
	struct tm	e_localtime;	/* local time message arrived	*/
	long		e_hdrOffset;	/* offset of start of headers	*/
	long		e_msgOffset;	/* offset of message body	*/
	time_t		e_nowtime;	/* time message processed	*/
	int		e_resent;	/* flag indicating resent msg	*/
	int		e_trusted;	/* is local agent trusted?	*/
	conscell	*e_from_trusted;  /* given (channel,host,user)	*/
	conscell	*e_from_resolved; /* found (channel,host,user)	*/
	const char	*e_file;	/* message file name		*/
	FILE		*e_fp;		/* message file pointer		*/
	const char	*e_messageid;	/* message id string		*/
};

#ifdef	RFC976
#define HDR_SCANNER(x)	scan822(&(x), strlen((const char *)x), '!', '%', 0, (token822 **)0)
#else	/* !RFC976 */
#define HDR_SCANNER(x)	scan822(&(x), strlen((const char *)x), 0, 0, 0, (token822 **)0)
#endif	/* RFC976 */

struct Zpasswd {
  /* Basic normal 'struct passwd' things */
  const char *pw_name;
  const char *pw_passwd;
  uid_t pw_uid;
  gid_t pw_gid;
  const char *pw_gecos;
  const char *pw_dir;
  const char *pw_shell;
  /* Our ``Z'' extensions */
  long quota1, quota2;
  const char *mail_forward;
};

struct Zgroup {
  const char *gr_name;
  const char *gr_passwd;
  gid_t gr_gid;
  const char **gr_mem;
};

/* lib/allocate.c: */
extern void      tfree __((const memtypes memtype));
extern univptr_t getlevel __((const memtypes memtype));
extern void      setlevel __((const memtypes memtype, const univptr_t up));
extern char *    strsave __((const char *s));
extern char *    strnsave __((const char *s, const size_t n));
extern memtypes	 stickymem;
extern univptr_t tmalloc __((const size_t n));
extern univptr_t smalloc __((const memtypes memtype, const size_t n));

/*
 * The following declarations are here only so we can consolidate
 * site-specific parameters in a single file (conf.c) instead of
 * having them all over the place.
 */

#if 0
/* list of hash table id's and the corresponding (log 2 of) table sizes */
struct htbl_init {
	u_int	*idp;
	u_int	log2size;
};
#endif

/* initialization of builtin functions */

#if 0
typedef enum { internal, interpreted, program, retvalue } funcType;
struct func_init {
	const char	*fnname;
	const char	*(*fnaddr)();
	funcType	fntype;
};
#endif

struct sptree_init {
	struct sptree	**spta;			/* address of sptree * */
	const char	*incore_name;		/* "name" of incore database */
};
