/*
 *  mxverify-cgi  -- a ZMailer associated utility for doing web-based
 *                   analysis of ``is my incoming email working properly ?''
 *
 *  By Matti Aarnio <mea@nic.funet.fi> 20-Jan-2000, 2001, 2003
 *
 *  This program plays fast&loose with HTTP/CGI interface, and presumes
 *  quite exactly the <FORM ... > stuff that is present in the file
 *  mxverify-cgi.html
 *
 */


#include "hostenv.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include "zmsignal.h"
#include <string.h>
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

#include "zresolv.h"
#include "libc.h"

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


struct mxdata {
	const msgdata	*host;
	int		 pref;
	int		 ttl;
};



int timeout_conn = 30; /* 30 seconds for connection */
int timeout_tcpw = 20; /* 20 seconds for write      */
int timeout_tcpr = 60; /* 60 seconds for responses  */

int plaintext = 0;
int conn_ok   = 0;

int use_ipv6 = 1;


/* Input by 'GET' method, domain-name at CGI URL */

/* STDARG && STDC */
void htmlprintf(const char *fmt, ...)
{
  va_list ap;
  int in_tag = 0;

  va_start(ap, fmt);

  for ( ; *fmt ; ++fmt ) {

    if (!in_tag && *fmt == '<') {
      in_tag = 1;
    } else if (in_tag && *fmt == '>') {
      in_tag = 0;
    }

    if (in_tag && plaintext) continue;

    if (*fmt == '%') {
      int width = 0;
      ++fmt;
      while ('0' <= *fmt && *fmt <= '9') {
	width = width * 10 + (*fmt - '0');
	++fmt;
      }
      switch (*fmt) {
      case 's':
	{
	  const char *str = va_arg(ap, const char *);
	  if (plaintext) {
	    printf("%s",str);
	  } else
	    for (;str && *str; ++str) {
	      printf("&#%d;", 0xFF & *str);
	    }
	}
	break;
      case 'd':
	{
	  int d = va_arg(ap, int);
	  printf("%*d", width, d);
	}
	break;
      default:
	break;
      }

      continue;
    }

    printf("%c", *fmt);
  }
}


extern int mxverifyrun();



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
	  htmlprintf("<H1>ERROR:  RECURSIVE CNAME ON DNS LOOKUPS: domain=``%s''</H1>\n", host);
	  return EX_NOHOST;
	}


	qlen = res_mkquery(QUERY, host, C_IN, T_MX, NULL, 0, NULL,
			   (void*)&qbuf, sizeof qbuf);
	if (qlen < 0) {
	  htmlprintf("<H1>ERROR:  res_mkquery() failed! domain=``%s''</H1>\n", host);
	  return EX_SOFTWARE;
	}

	htmlprintf("<H1>Doing resolver lookup for T=MX domain=``%s''</H1>\n", host);

	n = res_send((void*)&qbuf, qlen, (void*)&answer, sizeof answer);
	if (n < 0) {
	  htmlprintf("<H1>ERROR:  No resolver response for domain=``%s''</H1>\n", host);
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
	    htmlprintf("<H1>ERROR:  NO SUCH DOMAIN: ``%s''</H1>\n", host);
	    return EX_TEMPFAIL;
	  case SERVFAIL:
	    htmlprintf("<H1>ERROR:  DNS Server Failure: domain=``%s''</H1>\n", host);
	    return EX_TEMPFAIL;
	  case NOERROR:
	    htmlprintf("<H1>Questionable:  NO MX DATA: domain=``%s''  We SIMULATE!</H1>\n", host);
	    htmlprintf("<H1>Do have at least one MX entry added!</H1>\n");
	    mx[0].host = host;
	    mx[0].pref = 999999;
	    mx[1].host = NULL;
	    return 0;
	  case FORMERR:
	    htmlprintf("<H1>ERROR:  DNS Internal FORMERR error: domain=``%s''</H1>\n", host);
	    return EX_NOPERM;
	  case NOTIMP:
	    htmlprintf("<H1>ERROR:  DNS Internal NOTIMP error: domain=``%s''</H1>\n", host);
	    return EX_NOPERM;
	  case REFUSED:
	    htmlprintf("<H1>ERROR:  DNS Internal REFUSED error: domain=``%s''</H1>\n", host);
	    return EX_NOPERM;
	  }
	  htmlprintf("<H1>ERROR:  DNS Unknown Error! (rcode=%d) domain=``%s''</H1>\n", hp->rcode, host);
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

	  NS_GET16(type, cp);        /* type  */
	  cp += NS_INT16SZ;          /* class */
	  NS_GET32(mx[nmx].ttl, cp); /* ttl */
	  NS_GET16(n, cp);           /* dlen */

	  if (type == T_CNAME) {
	    cp += dn_expand((msgdata *)&answer, eom, cp,
			    (void*)realname, sizeof realname);
	    saw_cname = 1;
	    continue;
	  } else if (type != T_MX)  {
	    cp += n;
	    continue;
	  }

	  NS_GET16(mx[nmx].pref, cp);  /* MX preference value */

	  n = dn_expand((msgdata *)&answer, eom, cp, (void*)buf, sizeof buf);
	  if (n < 0)
	    break;
	  cp += n;
	  mx[nmx].host = (msgdata *)strdup(buf);
	  ++nmx;
	}

	if (nmx == 0 && realname[0] != '\0' &&
	    strcasecmp(host,(char*)realname) != 0) {
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


	htmlprintf("<P><H1>DNS yields following MX entries\n</H1><PRE>\n");
	for (i = 0; i < nmx; ++i)
	  htmlprintf("  %s  (%ds) IN MX %3d %s\n", host,mx[i].ttl,mx[i].pref,mx[i].host);
	htmlprintf("</PRE>\n<P>\n");

	if (nmx == 1) {
	  htmlprintf("<H2>Only one MX record...\n<BR>Well, no backups, but as all systems are looking for MX record <I>in every case</I>, not bad..</H2>\n<P>\n");
	}

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
	  htmlprintf("<H2>ERROR: Failed to create %s type socket! err='%s'</H2>\n",
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

	if (sa->sa_family == AF_INET) {
	  struct sockaddr_in *si = (struct sockaddr_in*) sa;
	  unsigned long  ia = ntohl(si->sin_addr.s_addr);
	  int anet = ia >> 24;
	  if (anet <= 0 || anet == 127 ||  anet >= 224) {
	    close(sk);
	    errno = EADDRNOTAVAIL;
	    return EX_UNAVAILABLE;
	  }
	}

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
	  htmlprintf("<CODE>[ CONNECTED! ]</CODE><BR>\n");

	  ++conn_ok;

	  return EX_OK;
	}

	close(sk);

	se = strerror(errnosave);
	htmlprintf("<H2>ERROR: Connect failure reason: %s</H2><BR>(Still possibly all OK!)<BR>\n",se);

	return 0;
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

void htmlwrite(str, len)
     char *str;
{
	int i;
	if (plaintext)
	  fwrite(str, 1, len, stdout);
	else
	  for (i = 0; i < len; ++i) {
	    if (str[i] == '\n')
	      fprintf(stdout, "\n");
	    else
	      fprintf(stdout, "&#%d;", str[i]);
	  }
}


int readsmtp(sock)
     int sock;
{
	char linebuf[8192];
	int c = 0;
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
	      if (linelen > 0) {
		fprintf(stdout, " ");
		htmlwrite(linebuf, linelen);
		fprintf(stdout, "\n");
		linelen = 0;
	      }
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
	    htmlwrite(linebuf, linelen);
	    linelen = 0;
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


int smtptest(thatuser, ai)
     char *thatuser;
     struct addrinfo *ai;
{
	int sock, rc, wtout = 0;
	int nullreject = 0;
	char myhostname[200];
	char smtpline[500];

	char *thatdomain = strchr(thatuser, '@');
	if (!thatdomain) thatdomain = thatuser; else ++thatdomain;

	/* Try two sessions:
	   1) HELO + MAIL FROM:<> + RCPT TO:<postmaster@thatdomain> + close

	   --- and perhaps if it turns out to be becessary, also:

	   2) HELO + MAIL FROM:<postmaster@thisdomain> +
	             RCPT TO:<postmaster@thatdomain> + close
	*/

	smtpgetc(-1);

	sock = -1;
	rc = vcsetup(ai->ai_addr, &sock, myhostname, sizeof(myhostname));

	if (rc != EX_OK || sock < 0) return rc; /* D'uh! */


	if (!plaintext)
	  htmlprintf("<PRE>\n");

	/* Initial greeting */

	rc = readsmtp(sock); /* Read response.. */
	if (rc < 0 || rc > 299) goto end_test_1;


	sprintf(smtpline, "EHLO %s\r\n", myhostname);
	fprintf(stdout, " EHLO %s\n", myhostname);
	rc = writesmtp(sock, smtpline);

	if (rc == ETIMEDOUT) wtout = 1;
	if (rc != EX_OK) goto end_test_1;
	rc = readsmtp(sock); /* Read response.. */
	if (rc < 0 || rc > 299) {

	  htmlprintf("</PRE><P>\n<H2>Grrr...  Doesn't understand ESMTP EHLO greeting</H2><P>\n");

	  /* Close, and reconnect... */
	  close(sock);
	  sock = -1;
	  rc = vcsetup(ai->ai_addr, &sock, myhostname, sizeof(myhostname));
	  if (rc != EX_OK || sock < 0) return rc; /* D'uh! */

	  if (!plaintext)
	    htmlprintf("<PRE>\n");

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

	} else {
	  if (!plaintext) htmlprintf("</PRE><P>\n");
	  htmlprintf("<H3>Excellent! It speaks ESMTP!</H3>\n");
	  if (!plaintext) htmlprintf("<P><PRE>\n");
	}
	

	sprintf(smtpline, "MAIL FROM:<>\r\n");
	htmlprintf(" MAIL FROM:%s%s\n","<",">");
	rc = writesmtp(sock, smtpline);
	if (rc == ETIMEDOUT) wtout = 1;
	if (rc != EX_OK) goto end_test_1;
	rc = readsmtp(sock); /* Read response.. */

	if (!plaintext) htmlprintf("</PRE><P>");
	if (rc < 0 || rc > 299) { 
	  htmlprintf("<H2>Grr! Rejects NULL return path; see RFC 2821 section 6.1</H2>\n");
	  nullreject = 1;
	} else {
	  htmlprintf("<H4>Fine, it accepts NULL return-path as is mandated by RFC 2821 section 6.1</H4>\n");
	}
	if (!plaintext) htmlprintf("<P><PRE>");
	
	sprintf(smtpline, "RSET\r\n");
	htmlprintf(" RSET\n");
	rc = writesmtp(sock, smtpline);
	if (rc == ETIMEDOUT) wtout = 1;
	if (rc != EX_OK) goto end_test_1;
	rc = readsmtp(sock); /* Read response.. */
	/* Ignore the result ? */

	sprintf(smtpline, "MAIL FROM:<postmaster@%s>\r\n", myhostname);
	htmlprintf(" MAIL FROM:%spostmaster@%s%s\n","<",myhostname,">");
	rc = writesmtp(sock, smtpline);
	if (rc == ETIMEDOUT) wtout = 1;
	if (rc != EX_OK) goto end_test_1;
	rc = readsmtp(sock); /* Read response.. */
	if (rc < 0 || rc > 299) { 
	  goto end_test_1;
	}

	if (thatdomain != thatuser) {
	  sprintf(smtpline, "RCPT TO:<%s>\r\n", thatuser);
	  htmlprintf(" RCPT TO:%s%s%s\n","<",thatuser,">");
	  rc = writesmtp(sock, smtpline);
	  if (rc == ETIMEDOUT) wtout = 1;
	  if (rc != EX_OK) goto end_test_1;
	  rc = readsmtp(sock); /* Read response.. */
	  if (rc < 0 || rc > 299) goto end_test_1;
	}

	sprintf(smtpline, "RCPT TO:<postmaster@%s>\r\n", thatdomain);
	htmlprintf(" RCPT TO:%spostmaster@%s%s\n","<",thatdomain,">");
	rc = writesmtp(sock, smtpline);
	if (rc == ETIMEDOUT) wtout = 1;
	if (rc != EX_OK) goto end_test_1;
	rc = readsmtp(sock); /* Read response.. */
	if (rc < 0 || rc > 299) {
	  if (!plaintext) htmlprintf("\n</PRE>\n");
	  htmlprintf("<H2>Eh ? What ?  No ``postmaster'' supported there ?  That violates RFC 2821 section 4.5.1.</H2>\n");
	  if (!plaintext) htmlprintf("<PRE>\n");
	}


	rc = 0; /* All fine, no complaints! */


 end_test_1:
	sprintf(smtpline, "RSET\r\nQUIT\r\n");
	writesmtp(sock, smtpline);
	close(sock);

	htmlprintf("\n</PRE>\n");
	/* htmlprintf("RC = %d\n", rc); */
	if (wtout)
	  htmlprintf("<H2> WRITE TIMEOUT!</H2>\n");
	else if (rc == 0 && !nullreject)
	  htmlprintf("<H2>Apparently OK!</H2>\n");
	else if (rc == 0 && nullreject)
	  htmlprintf("<H2>Rejects RFC 2821 section 6.1 defined mandatorily supported source address format, otherwise appears to work!</H2>\n");
	else
	  htmlprintf("<H2>Something WRONG!! rc=%d</H2>\n", rc);

	return rc;
}


int testmxsrv(thatdomain, hname)
     char *thatdomain;
     char *hname;
{
	struct addrinfo req, *ai, *ai2, *a;
	int i, i2, rc = 0, rc2;

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
	if (use_ipv6) {
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
	}
#endif

	if (i) {
	  /* It is fucked up somehow.. */
	  htmlprintf("<H2> --- sorry, address lookup for ``%s'' failed;<BR>\n code = %s</H2>\n", hname, gai_strerror(i));
	  return i;
	}
	if (!ai) {
	  htmlprintf("Address lookup <B>did not</B> yield any addresses!\n");
	  return EX_DATAERR;
	}

	htmlprintf("Address lookup did yield following ones:\n<P>\n");
	htmlprintf("<PRE>\n");

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

	htmlprintf("</PRE>\n");

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

	  htmlprintf("<P>\n");
	  htmlprintf("<H2>Testing server at address: %s</H2>\n", buf);
	  htmlprintf("<P>\n");

	  rc2 = smtptest(thatdomain, a);
	  if (!rc) rc = rc2;
	}
	return rc;
}


int mxverifyrun(thatuser)
     char *thatuser;
{
	struct mxdata mx[80+1];
	int rc, rc2, i;
	char *thatdomain = strchr(thatuser,'@');
	if (!thatdomain) thatdomain = thatuser; else ++thatdomain;

	rc = getmxrr(thatdomain, mx, 80, 0);
	if (rc) return rc;

	for (i = 0; mx[i].host != NULL; ++i) {
	  htmlprintf("<P>\n");
	  if (plaintext)
	    fprintf(stdout, "-----------------------------------------------------------------------\n");
	  else
	    fprintf(stdout, "<HR>\n");
	  htmlprintf("<H1>Testing MX server: %s</H1>\n<P>\n", mx[i].host);
	  rc2 = testmxsrv(thatuser, mx[i].host);
	  if (!rc)  rc = rc2; /* Yield 'error' if any errs. */
	}

	if (!rc && !conn_ok) {
	  /* No SUCCESSFULL connections anywhere,
	     either the network is in trouble towards
	     all destination system MX sites, or
	     the site really is in trouble... */
	  rc = 1;
	}

	return rc;
}




int main(argc, argv)
int argc;
char *argv[];
{
  char *getstr = getenv("QUERY_STRING");
  /* We PRESUME that in all conditions our input is of
     something which does not need decoding... */

  int err = 0;

  SIGNAL_HANDLE(SIGPIPE, SIG_DFL);


#if defined(AF_INET6) && defined(INET6)
  {
    int sk = socket(AF_INET6, SOCK_STREAM, 0);
    if (sk > 0) close(sk);
    if (sk < 0)
      use_ipv6 = 0; /* No go :-(  Can't create IPv6 socket */
  }
#endif

  res_init();
#ifdef RES_USE_INET6
#if defined(AF_INET6) && defined(INET6)
  if (!use_ipv6)
    _res.options &= ~RES_USE_INET6;
#else
  _res.options &= ~RES_USE_INET6;
#endif
#endif


  if (!getstr) err = 1;
  if (!getstr) getstr = "--DESTINATION-DOMAIN-NOT-SUPPLIED--";

  if (!err) {
    char *s = strchr(getstr, '&');
    if (s) *s = 0;
    if (strncasecmp(getstr,"DOMAIN=",7)==0) {
      getstr += 7;
    } else
      err = 1;
  }

  if (argc == 3) {
    if (strcmp(argv[1],"-domain") == 0) {
      err = 0;
      getstr = argv[2];
      plaintext = 1;
    }
  }

  if (!err) {
    char *s, *p;
    /* Turn '+' to space */
    while ((s = strchr(getstr,'+')) != NULL) *s = ' ';
    p = s = getstr;
    while (*s) {
      if (*s == '%') {
	/* '%HH' -> a char */
	int c1 = *++s;
	int c2 = 0;
	if ('0' <= c1 && c1 <= '9')
	  c1 = c1 - '0';
	else if ('A' <= c1 && c1 <= 'F')
	  c1 = c1 - 'A' + 10;
	else if ('a' <= c1 && c1 <= 'f')
	  c1 = c1 - 'a' + 10;
	else
	  err = 1;
	if (*s) c2 = *++s;
	if ('0' <= c2 && c2 <= '9')
	  c2 = c2 - '0';
	else if ('A' <= c2 && c2 <= 'F')
	  c2 = c2 - 'A' + 10;
	else if ('a' <= c2 && c2 <= 'f')
	  c2 = c2 - 'a' + 10;
	else
	  err = 1;
	if (!err) {
	  c1 <<= 4;
	  c1 |= c2;
	  if (c1 < ' ' || c2 >= 127)
	    err = 1;
	}
	if (!err)
	  *p++ = c1;
	if (*s) ++s;
	continue;
      }
      /* Anything else, just copy.. */
      *p++ = *s++;
    }
    *p = 0;
  }

  setvbuf(stdout, NULL, _IOLBF, 0);
  setvbuf(stderr, NULL, _IOLBF, 0);

  if (!plaintext) {
    fprintf(stdout, "Content-Type: TEXT/HTML\nPragma: no-cache\n\n");
    fprintf(stdout, "\n");
  }
  htmlprintf("<HTML><HEAD><TITLE>MX-VERIFY-CGI run for ``%s''</TITLE></HEAD>\n", getstr);
  if (!plaintext) {
    fprintf(stdout, "<BODY BGCOLOR=WHITE TEXT=BLACK LINK=#0000EE VLINK=#551A8B ALINK=RED>\n\n");

    htmlprintf("<H1>MX-VERIFY-CGI run for ``%s''</H1>\n", getstr);
    fprintf(stdout, "<P><HR>\n");
  }

  if (!err)
    err = mxverifyrun(getstr);
  else {
    if (plaintext) {
      fprintf(stdout, "\n\nSorry, NO MX-VERIFY-CGI run with this input!\n");
      exit(EX_USAGE);
    }
    fprintf(stdout, "<P>\n");
    fprintf(stdout, "Sorry, NO MX-VERIFY-CGI run with this input!<P>\n");
  }
  if (!plaintext) {
    fprintf(stdout, "<P><HR></BODY></HTML>\n");
  }

  if ((err & 127) == 0 && err != 0) err = 1; /* Make sure that after an exit()
						the caller will see non-zero
						exit code. */
  return err;
}
