/*
 *  mxverify-cgi  -- a ZMailer associated utility for doing web-based
 *                   analysis of ``is my incoming email working properly ?''
 *
 *  By Matti Aarnio <mea@nic.funet.fi> 19-Jan-2000
 *
 */


#include "hostenv.h"
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "zmsignal.h"

int timeout_conn = 30; /* 30 seconds for connection */
int timeout_tcpw = 20; /* 20 seconds for write      */
int timeout_tcpr = 60; /* 60 seconds for responses  */

/* Input by 'GET' method, domain-name at CGI URL */

extern void mxverifyrun();

int main(argc, argv)
int argc;
char argv[];
{
  char *getstr = getenv("QUERY_STRING");
  /* We PRESUME that in all conditions our input is of
     something which does not need decoding... */

  int err = 0;

  SIGNAL_HANDLE(SIGPIPE, SIG_DFL);


  if (!getstr) err = 1;
  if (!getstr) getstr = "--DESTINATION-DOMAIN-NOT-SUPPLIED--";

  setvbuf(stdout, NULL, _IOLBF, 0);
  setvbuf(stderr, NULL, _IOLBF, 0);

  fprintf(stdout, "Content-Type: TEXT/HTML\nPragma: no-cache\n\n");

  fprintf(stdout, "<HTML><HEAD><TITLE>\n");
  fprintf(stdout, "MX-VERIFY-CGI run for ``%s''\n</TITLE></HEAD>\n", getstr);
  fprintf(stdout, "<BODY BGCOLOR=\"WHITE\" TEXT=\"BLACK\" LINK=\"#0000EE\" VLINK=\"#551A8B\" ALINK=\"RED\">\n\n");

  fprintf(stdout, "<H1>MX-VERIFY-CGI run for ``%s''</H1>\n", getstr);
  fprintf(stdout, "<P>\n");
  fprintf(stdout, "<HR>\n");

  if (!err)
    mxverifyrun(getstr);
  else {
    fprintf(stdout, "<P>\n");
    fprintf(stdout, "Sorry, NO MX-VERIFY-CGI run with this input!<P>\n");
  }
  
  fprintf(stdout, "<P>\n");
  fprintf(stdout, "<HR>\n");
  fprintf(stdout, "</BODY></HTML>\n");
  return 0;
}


#include <sysexits.h>
/* #include <strings.h> */ /* poorly portable.. */
#ifdef HAVE_STDARG_H
# include <stdarg.h>
#else
# include <varargs.h>
#endif
#include <fcntl.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <setjmp.h>
#include <string.h>

#include "mail.h"
#include "zsyslog.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef HAVE_NETINET_IN6_H
# include <netinet/in6.h>
#endif
#ifdef HAVE_NETINET6_IN6_H
# include <netinet6/in6.h>
#endif
#ifdef HAVE_LINUX_IN6_H
# include <linux/in6.h>
#endif
#include <netdb.h>
#ifndef EAI_AGAIN
# include "netdb6.h"
#endif

#include "zmalloc.h"
#include "libz.h"
#include "libc.h"

#include "ta.h"  /* Well, not exactly a TA, but.. */



#ifdef _AIX /* Defines NFDBITS, et.al. */
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include <sys/time.h>

#ifndef	NFDBITS
/*
 * This stuff taken from the 4.3bsd /usr/include/sys/types.h, but on the
 * assumption we are dealing with pre-4.3bsd select().
 */

/* #error "FDSET macro susceptible" */

typedef long	fd_mask;

#ifndef	NBBY
#define	NBBY	8
#endif	/* NBBY */
#define	NFDBITS		((sizeof fd_mask) * NBBY)

/* SunOS 3.x and 4.x>2 BSD already defines this in /usr/include/sys/types.h */
#ifdef	notdef
typedef	struct fd_set { fd_mask	fds_bits[1]; } fd_set;
#endif	/* notdef */

#ifndef	_Z_FD_SET
/* #warning "_Z_FD_SET[1]" */
#define	_Z_FD_SET(n, p)   ((p)->fds_bits[0] |= (1 << (n)))
#define	_Z_FD_CLR(n, p)   ((p)->fds_bits[0] &= ~(1 << (n)))
#define	_Z_FD_ISSET(n, p) ((p)->fds_bits[0] & (1 << (n)))
#define _Z_FD_ZERO(p)	  memset((char *)(p), 0, sizeof(*(p)))
#endif	/* !FD_SET */
#endif	/* !NFDBITS */

#ifdef FD_SET
/* #warning "_Z_FD_SET[2]" */
#define _Z_FD_SET(sock,var) FD_SET(sock,&var)
#define _Z_FD_CLR(sock,var) FD_CLR(sock,&var)
#define _Z_FD_ZERO(var) FD_ZERO(&var)
#define _Z_FD_ISSET(i,var) FD_ISSET(i,&var)
#else
/* #warning "_Z_FD_SET[3]" */
#define _Z_FD_SET(sock,var) var |= (1 << sock)
#define _Z_FD_CLR(sock,var) var &= ~(1 << sock)
#define _Z_FD_ZERO(var) var = 0
#define _Z_FD_ISSET(i,var) ((var & (1 << i)) != 0)
#endif
#if	defined(TRY_AGAIN) && defined(HAVE_RESOLVER)
#define	BIND		/* Want BIND (named) nameserver support enabled */
#endif	/* TRY_AGAIN */
#ifdef	BIND
#ifdef NOERROR
#undef NOERROR		/* Several SysV-streams using systems have NOERROR,
			   which is not the same as  <arpa/nameser.h> has! */
#endif
#include <arpa/nameser.h>
#include <resolv.h>

#ifndef	BIND_VER
#ifdef	GETLONG
/* 4.7.3 introduced the {GET,PUT}{LONG,SHORT} macros in nameser.h */
#define	BIND_VER	473
#else	/* !GETLONG */
#define	BIND_VER	472
#endif	/* GETLONG */
#endif	/* !BIND_VER */
#endif	/* BIND */

/* Define all those things which exist on newer BINDs, and which may
   get returned to us, when we make a query with  T_ANY ... */

#ifndef	T_TXT
# define T_TXT 16	/* Text strings */
#endif
#ifndef T_RP
# define T_RP 17	/* Responsible person */
#endif
#ifndef T_AFSDB
# define T_AFSDB 18	/* AFS cell database */
#endif
#ifndef T_X25
# define T_X25 19	/* X.25 calling address */
#endif
#ifndef T_ISDN
# define T_ISDN 20	/* ISDN calling address */
#endif
#ifndef T_RT
# define T_RT 21	/* router */
#endif
#ifndef T_NSAP
# define T_NSAP 22	/* NSAP address */
#endif
#ifndef T_NSAP_PTR
# define T_NSAP_PTR 23	/* reverse NSAP lookup (depreciated) */
#endif
#ifndef	T_UINFO
# define T_UINFO 100
#endif
#ifndef T_UID
# define T_UID 101
#endif
#ifndef T_GID
# define T_GID 102
#endif
#ifndef T_UNSPEC
# define T_UNSPEC 103
#endif
#ifndef T_SA
# define T_SA 200		/* Shuffle addresses */
#endif



#ifndef	SEEK_SET
#define	SEEK_SET	0
#endif	/* SEEK_SET */
#ifndef SEEK_CUR
#define SEEK_CUR   1
#endif
#ifndef SEEK_XTND
#define SEEK_XTND  2
#endif

#ifndef	IPPORT_SMTP
#define	IPPORT_SMTP	25
#endif 	/* IPPORT_SMTP */

#define	PROGNAME	"smtpclient"	/* for logging */
#define	CHANNEL		"smtp"	/* the default channel name we deliver for */

#ifndef	MAXHOSTNAMELEN
#define	MAXHOSTNAMELEN 64
#endif	/* MAXHOSTNAMELEN */

#define MAXFORWARDERS	128	/* Max number of MX rr's that can be listed */


#if	defined(BIND_VER) && (BIND_VER >= 473)
typedef u_char msgdata;
#else	/* !defined(BIND_VER) || (BIND_VER < 473) */
typedef char msgdata;
#endif	/* defined(BIND_VER) && (BIND_VER >= 473) */

struct mxdata {
	msgdata		*host;
	int		 pref;
	time_t		 expiry;
};

typedef union {
	HEADER qb1;
	char qb2[PACKETSZ];
} querybuf;

int
getmxrr(host, mx, maxmx, depth)
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

	if (depth == 0)
	  h_errno = 0;

	if (depth > 3) {
	  fprintf(stdout,"<H1>ERROR:  RECURSIVE CNAME ON DNS LOOKUPS: domain=``%s''</H1>\n", host);
	  return EX_NOHOST;
	}


	qlen = res_mkquery(QUERY, host, C_IN, T_MX, NULL, 0, NULL,
			   (void*)&qbuf, sizeof qbuf);
	if (qlen < 0) {
	  fprintf(stdout,"<H1>ERROR:  res_mkquery() failed! domain=``%s''</H1>\n", host);
	  return EX_SOFTWARE;
	}

	fprintf(stdout,"<H1>Doing resolver lookup for T=MX domain=``%s''</H1>\n",host);

	n = res_send((void*)&qbuf, qlen, (void*)&answer, sizeof answer);
	if (n < 0) {
	  fprintf(stdout,"<H1>ERROR:  No resolver response for domain=``%s''</H1>\n", host);
	  return EX_TEMPFAIL;
	}

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
	    fprintf(stdout,"<H1>ERROR:  NO SUCH DOMAIN: ``%s''</H1>\n", host);
	    return EX_TEMPFAIL;
	  case SERVFAIL:
	    fprintf(stdout,"<H1>ERROR:  DNS Server Failure: domain=``%s''</H1>\n", host);
	    return EX_TEMPFAIL;
	  case NOERROR:
	    fprintf(stdout,"<H1>ERROR:  NO MX DATA: domain=``%s''</H1>\n", host);
	    mx[0].host = NULL;
	    return EX_TEMPFAIL;
	  case FORMERR:
	    fprintf(stdout,"<H1>ERROR:  DNS Internal FORMERR error: domain=``%s''</H1>\n", host);
	    return EX_NOPERM;
	  case NOTIMP:
	    fprintf(stdout,"<H1>ERROR:  DNS Internal NOTIMP error: domain=``%s''</H1>\n", host);
	    return EX_NOPERM;
	  case REFUSED:
	    fprintf(stdout,"<H1>ERROR:  DNS Internal REFUSED error: domain=``%s''</H1>\n", host);
	    return EX_NOPERM;
	  }
	  fprintf(stdout,"<H1>ERROR:  DNS Unknown Error! (rcode=%d) domain=``%s''</H1>\n", hp->rcode, host);
	  return EX_UNAVAILABLE;
	}
	nmx = 0;
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
	  mx[nmx].host = (msgdata *)strdup(buf);
	  ++nmx;
	}

	if (nmx == 0 && realname[0] != '\0' &&
	    cistrcmp(host,(char*)realname) != 0) {
	  /* do it recursively for the real name */
	  n = getmxrr((char *)realname, mx, maxmx, depth+1);
	  return n;
	} else if (nmx == 0) {
	  /* "give it the benefit of doubt" */
	  mx[0].host = NULL;
	  return EX_OK;
	}
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


	fprintf(stdout, "<P><H1>DNS yields following MX entries</H1>\n");
	fprintf(stdout, "<PRE>\n");
	for (i = 0; i < nmx; ++i)
	  fprintf(stdout,"  %s  IN MX %3d %s\n", host,mx[i].pref,mx[i].host);
	fprintf(stdout, "</PRE>\n<P>\n");

	mx[nmx].host = NULL;
	return EX_OK;
}

int
vcsetup(sa, fdp, myname, mynamemax)
	struct sockaddr *sa;
	int *fdp, mynamemax;
	char *myname;
{
	int af, gotalarm = 0;
	volatile int addrsiz;
	int sk;
	struct sockaddr_in *sai = (struct sockaddr_in *)sa;
	struct sockaddr_in sad;
#if defined(AF_INET6) && defined(INET6)
	struct sockaddr_in6 *sai6 = (struct sockaddr_in6 *)sa;
	struct sockaddr_in6 sad6;
#endif
	struct hostent *hp;
	union {
	  struct sockaddr_in sai;
#if defined(AF_INET6) && defined(INET6)
	  struct sockaddr_in6 sai6;
#endif
	} upeername;
	int upeernamelen = 0;

	int errnosave, flg;
	char *se;

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

	sk = socket(af, SOCK_STREAM, 0);
	if (sk < 0) {
	  se = strerror(errno);
	  fprintf(stdout,"<H2>ERROR: Failed to create %s type socket! err='%s'</H2>\n",
		  af == AF_INET ? "AF_INET" : "AF_INET6", se);
	  return EX_TEMPFAIL;
	}

	if (af == AF_INET)
	  sai->sin_port   = htons(25);
#if defined(AF_INET6) && defined(INET6)
	if (af == AF_INET6)
	  sai6->sin6_port = htons(25);
#endif

	/* The socket will be non-blocking for its entire lifetime.. */
#ifdef O_NONBLOCK
	fcntl(sk, F_SETFL, fcntl(sk, F_GETFL, 0) | O_NONBLOCK);
#else
#ifdef FNONBLOCK
	fcntl(sk, F_SETFL, fcntl(sk, F_GETFL, 0) | FNONBLOCK);
#else
	fcntl(sk, F_SETFL, fcntl(sk, F_GETFL, 0) | FNDELAY);
#endif
#endif

	errnosave = errno = 0;

	if (connect(sk, sa, addrsiz) < 0 &&
	    (errno == EWOULDBLOCK || errno == EINPROGRESS)) {

	  /* Wait for the connection -- or timeout.. */

	  struct timeval tv;
	  fd_set wrset;
	  int rc;

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

	  if (upeername.sai.sin_family == AF_INET)
	    hp = gethostbyaddr((char*)&upeername.sai.sin_addr,   4, AF_INET);
#if defined(AF_INET6) && defined(INET6)
	  else if (upeername.sai6.sin6_family == AF_INET6)
	    hp = gethostbyaddr((char*)&upeername.sai6.sin6_addr, 16, AF_INET6);
#endif
	  else
	    hp = NULL;

	  /* Ok, NOW we have a hostent with our IP-address reversed to a name */
	  if (hp)
	    strncpy(myname, hp->h_name, mynamemax);
	  else
	    getmyhostname(myname, mynamemax);
	}

	if (errnosave == 0 && !gotalarm) {
	  *fdp = sk;
	  fprintf(stdout,"<CODE>[ CONNECTED! ]</CODE><BR>\n");

	  return EX_OK;
	}

	close(sk);

	se = strerror(errnosave);
	fprintf(stdout,"<H2>ERROR: Connect failure reason: %s</H2><BR>\n",se);

	return EX_UNAVAILABLE;
}


int smtpgetc(sock, tout)
int sock, tout;
{
	static unsigned char buf[1024];
	static int bufin = 0, bufout = 0;
	static int eof = 0;

	if (sock < 0) {
	  bufin = bufout = eof = 0;
	  return 0;
	}

	if (eof) return -1;

	for (;;) {

	  /* Pick from input buffer */

	  if (bufin > bufout) {
	    return buf[bufout++];
	  }

	  if (bufin <= bufout)
	    bufin = bufout = 0;

	  if (bufin == 0) {
	    struct timeval tv;
	    fd_set rdset;
	    int rc;

	    rc = read(sock, buf, sizeof(buf));

	    if (rc > 0) {
	      bufin = rc;
	      continue;
	    }
	    if (rc == 0) { /* EOF! */
	      eof = 1;
	      return -1;
	    }
	    if (errno == EINTR) continue;
	    if (errno != EWOULDBLOCK && errno != EAGAIN) {
	      eof = 1;
	      return -errno;
	    }
	    
	    _Z_FD_ZERO(rdset);
	    _Z_FD_SET(sock, rdset);
	    tv.tv_sec  = tout ? 1 : timeout_tcpr;
	    tv.tv_usec = 0;

	    rc = select(sock+1, &rdset, NULL, NULL, &tv);
	    if (rc > 0) continue; /* THINGS TO READ! */
	    if (rc == 0) {
	      if (!tout)
		eof = 1;
	      return -ETIMEDOUT;
	    }
	    /* Errors ?? */
	    if (errno == EINTR) continue;
	    return -errno;
	  }

	}
}


int readsmtp(sock)
int sock;
{
	char linebuf[8192];
	int c = 0, i;
	int end_seen = 0;
	int no_more  = 0;

	while ( !no_more && c >= 0 ) {

	  int newline_seen = 0;
	  int linelen = 0;

	  while (!newline_seen) {
	    c = smtpgetc(sock, end_seen);
	    if (c < 0) {
	      if (end_seen && c == -ETIMEDOUT)
		/* Quick additional read timeout.. */
		no_more = 1;
	      else
		/* ERROR !!?? */
		;
	      break;
	    }
	    if (c == '\r') continue; /* Ignore that */
	    if (linelen < sizeof(linebuf))
	      linebuf[linelen ++] = c;
	    if (c == '\n')
	      newline_seen = 1;
	  }
	  /* Got a full line, now what it might be.. */
	  if (linelen > 3 &&
	      ('0' <= linebuf[0] && linebuf[0] <= '9') &&
	      ('0' <= linebuf[1] && linebuf[1] <= '9') &&
	      ('0' <= linebuf[2] && linebuf[2] <= '9') &&
	      (linebuf[3] == '\r' || linebuf[3] == '\n' ||
	       linebuf[3] == ' '  || linebuf[3] == '\t')) {
	    end_seen = atoi(linebuf);
	  }

	  if (linelen > 0) {
	    fprintf(stdout, " ");
	    for (i = 0; i < linelen; ++i) {
	      if (linebuf[i] == '\n' ||
		  (linebuf[i] >= ' ' && linebuf[i] < 127)) {
		if (linebuf[i] == '\n')
		  fprintf(stdout, "\n");
		else
		  fprintf(stdout, "&#%d;", linebuf[i]);
	      }
	      else
		fprintf(stdout, "\\0x%02X", linebuf[i]);
	    }
	  }
	}
	if (c < 0 && no_more) c = 0;

	return (c < 0) ? c : end_seen;
}


int writesmtp(sock, str)
int sock;
char *str;
{
	int rc, len, e;

	len = strlen(str);

	while (len > 0) {
	  SIGNAL_HANDLE(SIGPIPE, SIG_IGN);
	  rc = write(sock, str, len);
	  e = errno;
	  SIGNAL_HANDLE(SIGPIPE, SIG_DFL);
	  errno = e;
	  if (rc >= 0) {
	    len -= rc;
	    str += rc;
	    continue;
	  }
	  /* Right, now error handling.. */
	  if (errno == EINTR) continue;
	  if (errno == EAGAIN || errno == EWOULDBLOCK) {
	    fd_set wrset;
	    struct timeval tv;
	    _Z_FD_ZERO(wrset);
	    _Z_FD_SET(sock, wrset);
	    tv.tv_sec  = timeout_tcpw;
	    tv.tv_usec = 0;
	    rc = select(sock+1, NULL, &wrset, NULL, &tv);
	    if (rc > 0) continue;
	    if (rc == 0) {
	      /* TIMEOUT! */
	      return ETIMEDOUT;
	    }
	    /* Error processing! */
	    if (errno == EINTR) continue;
	  }
	  return errno;
	}
	return 0;
}


void smtptest(thatdomain, ai)
char *thatdomain;
struct addrinfo *ai;
{
	int sock, rc, wtout = 0;
	char myhostname[200];
	char smtpline[500];

	/* Try two sessions:
	   1) HELO + MAIL FROM:<> + RCPT TO:<postmaster@thatdomain> + close

	   --- and perhaps if it turns out to be becessary, also:

	   2) HELO + MAIL FROM:<postmaster@thisdomain> +
	             RCPT TO:<postmaster@thatdomain> + close
	*/

	smtpgetc(-1);

	rc = vcsetup(ai->ai_addr, &sock, myhostname, sizeof(myhostname));

	if (rc != EX_OK) return; /* D'uh! */


	fprintf(stdout, "<PRE>\n");


	/* Initial greeting */

	rc = readsmtp(sock); /* Read response.. */
	if (rc < 0 || rc > 299) goto end_test_1;


	sprintf(smtpline, "HELO %s\r\n", myhostname);
	fprintf(stdout, " HELO %s\n", myhostname);
	rc = writesmtp(sock, smtpline);

	if (rc == ETIMEDOUT) wtout = 1;
	if (rc != EX_OK) goto end_test_1;
	rc = readsmtp(sock); /* Read response.. */
	if (rc < 0 || rc > 299) goto end_test_1;

	sprintf(smtpline, "MAIL FROM:<>\r\n");
	fprintf(stdout, " MAIL FROM:&lt;&gt;\n");
	rc = writesmtp(sock, smtpline);
	if (rc == ETIMEDOUT) wtout = 1;
	if (rc != EX_OK) goto end_test_1;
	rc = readsmtp(sock); /* Read response.. */
	if (rc < 0 || rc > 299) goto end_test_1;

	sprintf(smtpline, "RCPT TO:<postmaster@%s>\r\n", thatdomain);
	fprintf(stdout, " RCPT TO:&lt;postmaster@%s&gt;\n", thatdomain);
	rc = writesmtp(sock, smtpline);
	if (rc == ETIMEDOUT) wtout = 1;
	if (rc != EX_OK) goto end_test_1;
	rc = readsmtp(sock); /* Read response.. */
	if (rc < 0 || rc > 299) goto end_test_1;

	rc = 0; /* All fine, no complaints! */

 end_test_1:
	sprintf(smtpline, "RSET\r\nQUIT\r\n");
	writesmtp(sock, smtpline);
	close(sock);
	fprintf(stdout,"\n</PRE>\n");
	/* fprintf(stdout, "RC = %d\n", rc); */
	if (wtout)
	  fprintf(stdout,"<H2> WRITE TIMEOUT!</H2>\n");
	else if (rc == 0)
	  fprintf(stdout,"<H2>Apparently OK!</H2>\n");
	else
	  fprintf(stdout,"<H2>Something WRONG!! rc=%d</H2>\n", rc);
}


void testmxsrv(thatdomain, hname)
char *thatdomain;
char *hname;
{
	struct addrinfo req, *ai, *ai2, *a;
	int i, i2;

	memset(&req, 0, sizeof(req));
	req.ai_socktype = SOCK_STREAM;
	req.ai_protocol = IPPROTO_TCP;
	req.ai_flags    = AI_CANONNAME;
	req.ai_family   = AF_INET;
	ai = ai2 = NULL;

	/* This resolves CNAME, it should not be done in case
	   of MX server, though..    */
	i = getaddrinfo(hname, "0", &req, &ai);

#if defined(AF_INET6) && defined(INET6)
	memset(&req, 0, sizeof(req));
	req.ai_socktype = SOCK_STREAM;
	req.ai_protocol = IPPROTO_TCP;
	req.ai_flags    = AI_CANONNAME;
	req.ai_family   = AF_INET6;

	i2 = getaddrinfo(hname, "0", &req, &ai2);

	if (i2 == 0 && i != 0) {
	  /* IPv6 address, but no IPv4 address ? */
	  i = i2;
	  ai = ai2;
	  ai2 = NULL;
	}
	if (ai2 && ai) {
	  /* BOTH ?!  Catenate them! */
	  a = ai;
	  while (a && a->ai_next) a = a->ai_next;
	  if (a) a->ai_next = ai2;
	}
#endif

	if (i) {
	  /* It is fucked up somehow.. */
	  fprintf(stdout, "<H2> --- sorry, address lookup for ``%s'' failed;<BR> code = %s</H2>\n", hname, gai_strerror(i));
	  return;
	}
	if (!ai) {
	  fprintf(stdout,"Address lookup <B>did not</B> yield any addresses!\n");
	  return;
	}
	fprintf(stdout,"Address lookup did yield following ones:\n<P>\n");
	fprintf(stdout,"<PRE>\n");
	for (a = ai; a; a = a->ai_next) {
	  char buf[200];
	  struct sockaddr_in *si;
#if defined(AF_INET6) && defined(INET6)
	  struct sockaddr_in6 *si6;
#endif

	  if (a->ai_family == AF_INET) {
	    si = (struct sockaddr_in *)a->ai_addr;
	    strcpy(buf, "IPv4 ");
	    inet_ntop(AF_INET, &si->sin_addr, buf+5, sizeof(buf)-5);
	  } else
#if defined(AF_INET6) && defined(INET6)
	  if (a->ai_family == AF_INET6) {
	    si6 = (struct sockaddr_in6*)a->ai_addr;
	    strcpy(buf, "IPv6 ");
	    inet_ntop(AF_INET6, &si6->sin6_addr, buf+5, sizeof(buf)-5);
	  } else
#endif
	    sprintf(buf,"UNKNOWN-ADDR-FAMILY-%d", a->ai_family);
	  
	  fprintf(stdout,"  %s\n", buf);
	}
	fprintf(stdout,"</PRE>\n");
	for (a = ai; a; a = a->ai_next) {
	  char buf[200];
	  struct sockaddr_in *si;
#if defined(AF_INET6) && defined(INET6)
	  struct sockaddr_in6 *si6;
#endif

	  if (a->ai_family == AF_INET) {
	    si = (struct sockaddr_in *)a->ai_addr;
	    strcpy(buf, "IPv4 ");
	    inet_ntop(AF_INET, &si->sin_addr, buf+5, sizeof(buf)-5);
	  } else
#if defined(AF_INET6) && defined(INET6)
	  if (a->ai_family == AF_INET6) {
	    si6 = (struct sockaddr_in6*)a->ai_addr;
	    strcpy(buf, "IPv6 ");
	    inet_ntop(AF_INET6, &si6->sin6_addr, buf+5, sizeof(buf)-5);
	  } else
#endif
	    sprintf(buf,"UNKNOWN-ADDR-FAMILY-%d", a->ai_family);
	  fprintf(stdout,"<P>\n");
	  fprintf(stdout,"<H2>Testing server at address: %s</H2>\n", buf);
	  fprintf(stdout,"<P>\n");
	  smtptest(thatdomain, a);
	}
}


void mxverifyrun(thatdomain)
char *thatdomain;
{
	struct mxdata mx[80+1];
	int rc, i;

	rc = getmxrr(thatdomain, mx, 80, 0);
	if (rc) return;

	for (i = 0; mx[i].host != NULL; ++i) {
	  fprintf(stdout, "<P>\n");
	  fprintf(stdout, "<HR>\n");
	  fprintf(stdout, "<P>\n");
	  fprintf(stdout,"<H1>Testing MX server: %s</H1>\n", mx[i].host);
	  fprintf(stdout,"<P>\n");
	  testmxsrv(thatdomain, mx[i].host);
	}
}
