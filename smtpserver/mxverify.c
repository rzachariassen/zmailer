/*
 *   mx_client_verify() -- subroutine for ZMailer smtpserver
 *
 *   By Matti Aarnio <mea@nic.funet.fi> 1997
 */

#include "hostenv.h"
#include <stdio.h>
#ifdef linux
#define __USE_BSD 1
#endif
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include "zmsignal.h"
#include <sysexits.h>
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

#include <sys/socket.h>
#include <netinet/in.h>
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

#include "mail.h"
#include "zsyslog.h"
#include "ta.h"
#include "malloc.h"

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

extern int h_errno;
extern int res_mkquery(), res_send(), dn_skipname(), dn_expand();

#if	defined(BIND_VER) && (BIND_VER >= 473)
typedef u_char msgdata;
#else	/* !defined(BIND_VER) || (BIND_VER < 473) */
typedef char msgdata;
#endif	/* defined(BIND_VER) && (BIND_VER >= 473) */

static int dnsmxlookup __((const char*, int, int, int));

typedef union {
	HEADER qb1;
	char qb2[PACKETSZ];
} querybuf;


extern int debug;
static char * txt_buf = NULL;

static int
dnsmxlookup(host, depth, mxmode, qtype)
	const char *host;
	int depth;
	int mxmode;
	int qtype;
{
	HEADER *hp;
	msgdata *eom, *cp;
	querybuf qbuf, answer;
	msgdata buf[8192], realname[8192];
	int qlen, n, i, j, ancount, qdcount, maxpref;
	u_short type;
	int saw_cname = 0, had_mx_record = 0;
	int ttl;
	struct addrinfo req, *ai;

	if (depth == 0)
	  h_errno = 0;

	if (depth > 3) {
	  return -EX_NOHOST;
	}

	if (debug) {
	  if (qtype == T_TXT)
	    printf("TXT-lookup for domain: '%s'\n", host);
	  else if (mxmode)
	    printf("MX-Verify: Look MX for host '%s'\n", host);
	  else
	    printf("DNS-Verify: Look MX, or Addr for host '%s'\n", host);
	}

	qlen = res_mkquery(QUERY, host, C_IN, qtype, NULL, 0, NULL,
			   (void*)&qbuf, sizeof qbuf);
	if (qlen < 0) {
	  fprintf(stdout, "res_mkquery failed\n");
	  return -EX_SOFTWARE;
	}
	n = res_send((void*)&qbuf, qlen, (void*)&answer, sizeof answer);
	if (n < 0) {
	  return -EX_TEMPFAIL;
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
	    return -EX_NOHOST;
	  case SERVFAIL:
	    return -EX_TEMPFAIL;
#ifdef OLDJEEVES
	    /*
	     * Jeeves (TOPS-20 server) still does not
	     * support MX records.  For the time being,
	     * we must accept FORMERRs as the same as
	     * NOERROR.
	     */
	  case FORMERR:
#endif
	  case NOERROR:
	    goto perhaps_address_record;

#ifndef OLDJEEVES
	  case FORMERR:
#endif
	  case NOTIMP:
	  case REFUSED:
	    return -EX_NOPERM;
	  }
	  return -EX_UNAVAILABLE;
	}

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
	while (--ancount >= 0 && cp < eom) {
	  n = dn_expand((msgdata *)&answer, eom, cp, (void*)buf, sizeof buf);
	  if (n < 0)
	    break;
	  cp += n;
	  type = _getshort(cp);
	  cp += 2;
	  /* class = _getshort(cp); */
	  cp += 2;
	  /* ttl = _getlong(cp); */
	  cp += 4; /* "long" -- but keep in mind that some machines
		      have "funny" ideas about "long" -- those 64-bit
		      ones I mean ... */
	  n = _getshort(cp); /* dlen */
	  cp += 2;
	  if (type == T_CNAME) {
	    cp += dn_expand((msgdata *)&answer, eom, cp,
			    (void*)realname, sizeof realname);
	    saw_cname = 1;
	    continue;
	  } else if (type != qtype)  {
	    cp += n;
	    continue;
	  }

	  if (type == T_MX) {
	    cp += 2; /* MX preference value */
	    n = dn_expand((msgdata *)&answer, eom, cp, (void*)buf, sizeof buf);
	    if (n < 0)
	      break;
	    cp += n;

	    memset(&req, 0, sizeof(req));
	    req.ai_socktype = SOCK_STREAM;
	    req.ai_protocol = IPPROTO_TCP;
	    req.ai_flags    = AI_CANONNAME;
	    req.ai_family   = 0; /* Both OK (IPv4/IPv6) */
	    ai = NULL;

	    /* This resolves CNAME, it should not happen in case
	       of MX server, though..    */
#define GETADDRINFODEBUG 0
#if !GETADDRINFODEBUG
	    i = getaddrinfo((const char*)buf, "0", &req, &ai);
#else
	    i = _getaddrinfo_((const char*)buf, "0", &req, &ai,
			      debug ? stdout : NULL);
	    if (debug)
	      printf("  getaddrinfo('%s','0') -> r=%d, ai=%p\n",buf,i,ai);
#endif

	    if (debug)
	      printf("  getaddrinfo('%s') yields %d\n", buf, i);
	    
	    if (i != 0)
	      continue;		/* Well well.. spurious! */

	    if (!mxmode) /* Accept if found ANYTHING! */ {
	      if (debug) printf("  ... accepted!\n");
	      freeaddrinfo(ai);
	      return 1;
	    }
	  
	    {
	      struct addrinfo *ai2 = ai;
	      int i = 1, rc;
	    
	      for ( ; ai2 != NULL; ai2 = ai2->ai_next, ++i ) {
#if 0
		if (debug) {
		  struct sockaddr * sa = ai2->ai_addr;
		  char buf[60];
		  if (sa->sa_family == AF_INET) {
		    inet_ntop(AF_INET, & ((struct sockaddr_in *)sa)->sin_addr, buf, sizeof(buf));
		    printf("  matching address IPv4:[%s]\n", buf);
		  }
#if defined(AF_INET6) && defined(INET6)
		  else if (sa->sa_family == AF_INET6) {
		    inet_ntop(AF_INET6, ((struct sockaddr_in6 *)sa)->sin6_addr, buf, sizeof(buf));
		    printf("  matching address IPv6:[%s]\n", buf);
		  }
#endif
		  else
		    printf(" matching unknown address family address; AF=%d\n",
			   sa->sa_family);
		}
#endif
		rc = matchmyaddress(ai2->ai_addr);
		if (rc == 1) {
		  if (debug)
		    printf("  ADDRESS MATCH!\n");
		  freeaddrinfo(ai);
		  return 1; /* Found a match! */
		} else
		  if (debug)
		    printf("  matchmyaddress() yields: %d\n", rc);
	      }
	      if (debug)
		printf("  No address match among %d address!\n",i);
	    }
	    freeaddrinfo(ai);
	    had_mx_record = 1;
	  } /* ===== END OF MX DATA PROCESING ========= */

	  if (type == T_TXT) {
	    int len = (*cp++) & 0xFF; /* 0..255 chars */
	    if (txt_buf != NULL)
	      free(txt_buf);
	    txt_buf = emalloc(len+1);
	    memcpy(txt_buf, cp, len);
	    txt_buf[len] = '\0';
	    return 1; /* OK! */
	  }

	} /* ===== END OF DNS ANSWER PROCESSING ======= */

	/* Didn't find any, but saw CNAME ? Recurse with the real name */
	if (saw_cname)
	  return dnsmxlookup((void *)realname, depth+1, mxmode, qtype);

	if (had_mx_record && mxmode)
	    return 2; /* We have SOME date, but no match on ourselves! */

perhaps_address_record:
	if (qtype == T_MX) {
	  /* No MX, perhaps A ? */
	  memset(&req, 0, sizeof(req));
	  req.ai_socktype = SOCK_STREAM;
	  req.ai_protocol = IPPROTO_TCP;
	  req.ai_flags    = AI_CANONNAME;
	  req.ai_family   = 0; /* Both OK (IPv4/IPv6) */
	  ai = NULL;

	  /* This resolves CNAME, it should not happen in case
	     of MX server, though..    */
#if !GETADDRINFODEBUG
	  i = getaddrinfo((const char*)host, "0", &req, &ai);
#else
	  i = _getaddrinfo_((const char*)host, "0", &req, &ai, debug ? stdout : NULL);
#endif
	  if (debug)
	    printf("  getaddrinfo('%s','0') -> r=%d, ai=%p\n",host,i,ai);
	  if (i != 0) /* Found nothing! */
	    return 0;

	  i = matchmyaddresses(ai);
#if 0
	  /* With this we can refuse to accept any message with
	     source domain pointing back to loopback ! */
	  if (i == 2) {
	    /* Loopback ! */
	    freeaddrinfo(ai);
	    return 0;
	  }
#endif
	  if (i == 0 && mxmode) {
	    freeaddrinfo(ai);
	    return 2; /* Didn't find our local address in client-MX-mode */
	  }

	  freeaddrinfo(ai);
	  return 1; /* Found any address, or in client-MX-mode,
		       a local address! */
	}

	if (mxmode)
	  return 2; /* Not found, had no MX data either */
	
	return 0; /* Not found! */
}


/* For SOFT errors, return -102, for hard errors, -2.
   For 'we are MX', return 0.
   For (retmode == '+'), and without MX, return 1.
 */

int mx_client_verify(retmode, domain, alen)
     int retmode, alen;
     char *domain;
{
	char hbuf[2000];
	int rc;

	if (alen >= sizeof(hbuf)-2)
	  alen = sizeof(hbuf)-2;

	strncpy(hbuf, domain, alen);
	hbuf[alen] = 0; /* Chop off the trailers from the name */

	rc = dnsmxlookup(hbuf, 0, 1, T_MX);

	if (rc == 1) return 0; /* Found! */

	if (retmode == '+') {
	  if (rc == -EX_NOHOST ||
	      rc == -EX_UNAVAILABLE)
	    return -2; /* Definitely hard errors */
	  if (rc == 2)
	    return -103;
	  return -102; /* Soft error */
	}

	if (rc == 2)
	  return -3;
	return -2;     /* Reject */
}

int sender_dns_verify(retmode, domain, alen)
     int retmode, alen;
     char *domain;
{
	char hbuf[2000];
	int rc;

	if (alen >= sizeof(hbuf)-2)
	  alen = sizeof(hbuf)-2;

	strncpy(hbuf, domain, alen);
	hbuf[alen] = 0; /* Chop off the trailers from the name */

	rc = dnsmxlookup(hbuf, 0, 0, T_MX);

	if (rc == 1) return 0; /* Found! */

	if (retmode == '+') {
	  if (rc == -EX_NOHOST ||
	      rc == -EX_UNAVAILABLE)
	    return -2; /* Definitely hard errors */
	  if (rc == 2)
	    return -103;
	  return -102; /* Soft error */
	}

	if (rc == 2)
	  return -3;
	return -2;     /* Reject */
}

int client_dns_verify(retmode, domain, alen)
     int retmode, alen;
     char *domain;
{
	return sender_dns_verify(retmode, domain, alen);
}

int rbl_dns_test(ipv4addr, msgp)
     u_char *ipv4addr;
     char **msgp;
{
	char hbuf[2000], *s;
	int rc;

	sprintf (hbuf, "%d.%d.%d.%d.rbl.maps.vix.com",
		 ipv4addr[3], ipv4addr[2], ipv4addr[1], ipv4addr[0]);

	if (debug)
	  printf("looking up DNS A object: %s\n", hbuf);

	if (gethostbyname(hbuf) != NULL) {
	  /* XX: Should verify that the named object has A record: 127.0.0.2 */

	  /* Ok, then lookup for the TXT entry too! */
	  if (debug)
	    printf("looking up DNS TXT object: %s\n", hbuf);

	  if (dnsmxlookup(hbuf, 0, 0, T_TXT) == 1) {
	    if (*msgp != NULL)
	      free(*msgp);
	    *msgp = strdup(txt_buf);
	  }
	  return -1;
	}

	return 0;
}
