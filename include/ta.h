/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */
/*
 *	A plenty of changes, copyright Matti Aarnio 1990-2003
 */

#ifndef _Z_TA_H_
#define _Z_TA_H_

#ifdef HAVE_CONFIG_H
#include "hostenv.h"
#endif

#include <stdio.h>
#ifndef FILE /* Some systems don't have this as a MACRO.. */
# define FILE FILE
#endif
#include <sfio.h>


#define EX_DEFERALL 100 /* Outside <sysexits.h> codes */


struct taddress {
	struct taddress	*link;		/* next sender / sender for this rcpt */
	const char	*channel;
	const char	*host;
	const char	*user;
	const char	*misc;		/* expected to be uid privilege */
	const char	**routermxes;	/* [mea] hostpointers from router */
};

#define _DSN_NOTIFY_SUCCESS	0x001
#define _DSN_NOTIFY_FAILURE	0x002
#define _DSN_NOTIFY_DELAY	0x004
#define _DSN_NOTIFY_NEVER	0x008
#define _DSN_NOTIFY_TRACE	0x010

#define _DSN__DIAGDELAYMODE	 0x800 /* Internal magic for MAILBOX/SIEVE */
#define _DSN__TEMPFAIL_NO_UNLOCK 0x400 /* Internal magic for SMTP */

/* `convertmode' controls the behaviour of the message conversion:
     _CONVERT_NONE (0): send as is
     _CONVERT_QP   (1): Convert 8-bit chars to QUOTED-PRINTABLE
     _CONVERT_MULTIPARTQP (2): Convert substructures to QP - when not it..
     _CONVERT_8BIT (3): Convert QP-encoded chars to 8-bit
     _CONVERT_UNKNOWN (4): Turn message to charset=UNKNOWN-8BIT, Q-P..
*/
typedef enum {
  _CONVERT_NONE,
  _CONVERT_QP,
  _CONVERT_MULTIPARTQP,
  _CONVERT_8BIT,
  _CONVERT_UNKNOWN
} CONVERTMODE;

struct rcpt {
	struct rcpt	*next;
	struct taddress	*addr;		/* addr.link is the sender address */
	const char	*orcpt;		/*  DSN  ORCPT=  string */
	const char	*inrcpt;	/* "DSN" INRCPT= string */
	const char	*infrom;	/* "DSN" INFROM= string */
	const char	*notify;	/*  DSN  NOTIFY= flags  */
	const char	*ezmlm;		/* "DSN" EZMLM=  string */
	int		notifyflgs;
	time_t		deliverby;	/*  RFC 2852  DELIVERBY */
	int		deliverbyflgs;
#define _DELIVERBY_N 1
#define _DELIVERBY_R 2
#define _DELIVERBY_T 4
	char		***newmsgheader; /* message header line pointer ptr
					   that points to an address of
					      ctldesc->msgheaders[index]
					   which then points to a place
					   containing the header itself.
					   Thus enabling rewrite of the
					   header on the transport. */
	char		***newmsgheadercvt; /* the rewrite results */
	char		*top_received;
	int		id;		/* the index of this address */
	int		lockoffset;	/* the index of the address lock */
	int		headeroffset;
	int		drptoffset;
	int		status;		/* current delivery sysexit code */
	struct ctldesc	*desc;		/* backpointer to descriptor */
	/* XX: something needed for XOR address lists */

	char		*delayslot;
#if 0 /* not yet ?? */
	/* Delayed diagnostics */
	char		*diagdelaybuf;
	int		diagdelaysize;
	int		diagdelayspace;
#endif
};

struct ctldesc {
	const char	*msgfile;	/* message file name */
	const char	*logident;	/* message id for logging */
	const char	*verbose;	/* file for verbose logging */
	const char	*envid;		/* DSN ENVID data */
	const char	*dsnretmode;	/* DSN RET=-mode */
	const char	*taspoolid;
	time_t		msgmtime;	/* Message file arrival time */
	long		msgbodyoffset;	/* offset of message body in msgfile */
	long		msgsizeestimate; /* Estimate of the msg size */
	long		msginonumber;	/* message file inode number */
	int		msgfd;		/* message file I/O descriptor */
	int		ctlfd;		/* control file I/O descriptor */
	int		ctlid;		/* control file id (inode number) */
	char		*ctlmap;	/* control file mmap() block */
	const char	*contents;	/* message file data */
	long		contentsize;	/* message file size */
	long		*offset;	/* array of indices into contents */
	struct taddress	*senders;	/* list of sender addresses */
	struct rcpt	*recipients;	/* list of selected recipients */
	int		rcpnts_total;	/* number of recipients, total */
	int		rcpnts_remaining;/* .. how many yet to deliver */
	int		rcpnts_failed  ;/* .. how many failed ones */
	long		format;		/* _CF_FORMAT_xxx */
	char		***msgheaders;	/* pointer to all msg headers */
	char		***msgheaderscvt; /* converted headers */
#ifdef	HAVE_MMAP
	const char	*let_buffer;	/* MMAP()ed memory area containing */
	const char	*let_end;	/* the mail -- and its end..	   */
#endif
};


/* MIME-processing headers -- "Content-Transfer-Encoding:",
			  and "Content-Type:"			*/

struct cte_data {
	char	*encoder;
};

struct ct_data {
	char	*basetype;	/* "text"		*/
	char	*subtype;	/* "plain"		*/
	char	*charset;	/* charset="x-yzzy"	*/
	char	*boundary;	/* boundary="...."	*/
	char	*name;		/* name="..."		*/
	char	**unknown;	/* all unknown parameters */
};


struct mimestate {
	int	lastch;
	int	lastwasnl;
	int	convertmode;
	int	column;
	int	alarmcnt;
};


/* ctlopen.c: */
extern void            ctlfree __((struct ctldesc *dp, void *anyp));
extern void           *ctlrealloc __((struct ctldesc *dp, void *anyp, size_t size));
extern struct ctldesc *ctlopen __((const char *file, const char *channel, const char *host, int *exitflag, int (*selectaddr)(const char *, const char *, void *), void *saparam, int (*matchrouter)(const char *, struct taddress *, void *), void *mrparam));
extern void            ctlclose __((struct ctldesc *dp));
extern int	       ctlsticky __((const char *spec_host, const char *addr_host, void *cbparam));

/* diagnostic.c: */
extern const char     *notaryacct __((int rc, const char *okstr));
		/* NOTARY: addres / action / status / diagnostic  */
extern void 	       notaryreport __((const char*, const char*, const char*, const char*));
extern void            notary_setxdelay __((int));
extern void            notary_setwtt __(( const char *host ));
extern void            notary_setwttip __(( const char *ip ));
extern void            notary_settaid __(( const char *name, int ));
extern void            notary_setcvtmode __(( CONVERTMODE ));
#if defined(HAVE_STDARG_H)
extern void	       diagnostic __((FILE *verboselog, struct rcpt *rp, int rc, int timeout, const char *fmt, ... ));
#else
extern void	       diagnostic __((/* FILE *verboselog, struct rcpt *, int, int, char *,... */));
#endif


#ifdef HOST_NOT_FOUND /* Defines 'struct hostent' ... */
# include "dnsgetrr.h"
#endif

/* emptyline.c: */
extern int	       emptyline __(( char *line, int size ));

extern int zmalloc_failure;

/* lockaddr.c: */
extern int lockaddr __((int fd, char *map, int offset, int was, int new, const char *file, const char *host, const int mypid));

/* markoff.c: */
extern int markoff __((char *filecontents, int bytesleft, long offsets[], const char *filename));

/* mimeheaders.c: */
#if defined(HAVE_STDARG_H)
extern int append_header __((struct rcpt *rp, const char *fmt, ...));
#else
extern int append_header __(());
#endif
extern struct cte_data *parse_content_encoding __((const char *cte_line));
extern void             free_content_encoding  __((struct cte_data *cte));
extern struct ct_data  *parse_content_type __((const char *ct_line));
extern void		free_content_type  __((struct ct_data *ct));
extern void output_content_type __((struct rcpt *rp, struct ct_data *ct, char **oldpos));
extern int check_conv_prohibit __((struct rcpt *rp));
extern int cte_check __((struct rcpt *rp));
extern char **has_header __((struct rcpt *rp, const char *keystr));
extern void delete_header __((struct rcpt *rp, char **hdrp));
extern int  downgrade_charset __((struct rcpt *rp, FILE *verboselog));
extern int  downgrade_headers __((struct rcpt *rp, CONVERTMODE downgrade, FILE *verboselog));
extern int  header_received_for_clause __((struct rcpt *rp, int rcptcnt, FILE *verboselog));
extern int qp_to_8bit __((struct rcpt *rp));

/* mime2headers.c */
extern int headers_to_mime2 __((struct rcpt *rp, const char *defcharset, FILE *verboselog));
extern int headers_need_mime2 __(( struct rcpt *rp ));
 

/* fwriteheaders.c: */
extern int fwriteheaders __((struct rcpt *rp, FILE *fp, const char *newline, CONVERTMODE use_cvt, int maxwidth, char **chunkbufp));
/* swriteheaders.c: */
extern int swriteheaders __((struct rcpt *rp, Sfio_t *fp, const char *newline, CONVERTMODE use_cvt, int maxwidth, char **chunkbufp));

/* buildbndry.c: */
extern char *mydomain __((void));
extern char *buildboundary __((const char *what));

extern int getout;
extern RETSIGTYPE wantout __((int));

/* warning.c */
#ifdef HAVE_STDARG_H
extern void warning __((const char *fmt, ...));
#else
extern void warning __(());
#endif

/* lib/skip821address.c */
extern char *skip821address __((const char *s));

/* tasyslog.c */
extern void tatimestr __((char *buf, int dt));
extern void tasyslog __((struct rcpt *rp, int xdelay, const char *wtthost, const char *wttip, const char *stats, const char *msg));

extern int getmyuucename __((char *, int));

#endif
