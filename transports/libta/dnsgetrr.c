/*
 *	DNSGETRR -- module for ZMailer; common stuff for DNS using
 *		    transport agents
 *
 *	A lot of changes all around over the years by Matti Aarnio
 *	<mea@nic.funet.fi>, copyright 1992-1997
 */


#include "hostenv.h"
#include <stdio.h>
#ifdef __linux__
#define __USE_BSD 1
#endif
#include <ctype.h>
#include <pwd.h>
#include <sysexits.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <errno.h>
#include "zmsignal.h"
#include "zmalloc.h"

#if	defined(HAVE_RESOLVER)
#include <netdb.h>
#ifndef EAI_AGAIN
# include "netdb6.h"
#endif
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
#endif	/* HAVE_RESOLVER */

#include <arpa/inet.h>

#include "ta.h"

#define DPRINTF(x)

#if	defined(TRY_AGAIN) && defined(HAVE_RESOLVER)
#define	BIND		/* Want BIND (named) nameserver support enabled */
#endif	/* TRY_AGAIN */
#ifdef	BIND
#undef NOERROR /* Solaris  <sys/socket.h>  has  NOERROR too.. */

#include <arpa/nameser.h>
#include <resolv.h>

#include "libc.h"

#ifndef HFIXEDSZ	/* An ancient resolver (arpa/nameser.h) file ? */
# define HFIXEDSZ 12
#endif
#ifndef NETDB_SUCCESS	/* Ancient <netdb.h> ? */
# define NETDB_SUCCESS   0
# define NETDB_INTERNAL -1
#endif

#ifndef	BIND_VER
#ifdef	GETLONG
/* 4.7.3 introduced the {GET,PUT}{LONG,SHORT} macros in nameser.h */
#define	BIND_VER	473
#else	/* !GETLONG */
#define	BIND_VER	472
#endif	/* GETLONG */
#endif	/* !BIND_VER */
#endif	/* BIND */

#if	defined(BIND_VER) && (BIND_VER >= 473)
typedef u_char msgdata;
#else	/* !defined(BIND_VER) || (BIND_VER < 473) */
typedef char msgdata;
#endif	/* defined(BIND_VER) && (BIND_VER >= 473) */


/* Define all those things which exist on newer BINDs, and which may
   get returned to us, when we make a query with  T_ANY ... */

#ifndef	T_TXT
# define T_TXT 16
#endif
#ifndef T_RP
# define T_RP 17
#endif
#ifndef T_AFSDB
# define T_AFSDB 18
#endif
#ifndef T_NSAP
# define T_NSAP 22
#endif
#ifndef T_NSAP_PTR
# define T_NSAP_PTR 23
#endif
#ifndef T_SIG
# define T_SIG		24		/* security signature */
#endif
#ifndef T_KEY
# define T_KEY		25		/* security key */
#endif
#ifndef T_PX
# define T_PX		26		/* X.400 mail mapping */
#endif
#ifndef T_GPOS
# define T_GPOS		27		/* geographical position (withdrawn) */
#endif
#ifndef T_AAAA
# define T_AAAA		28		/* IP6 Address */
#endif
#ifndef T_LOC
# define T_LOC		29		/* Location Information */
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
# define T_SA 200
#endif

extern int res_mkquery(), res_send(), dn_expand(), dn_skipname();

#ifndef	IPPORT_SMTP
#define	IPPORT_SMTP	25
#endif	/* IPPORT_SMTP */

extern char errormsg[];
#ifndef strchr
extern char *strchr();
#endif

#ifdef	BIND

#if PACKETSZ > 1024
#define	MAXPACKET	PACKETSZ
#else
#define	MAXPACKET	1024
#endif

#ifndef INADDRSZ
# define INADDRSZ 4
#endif
#ifndef IN6ADDRSZ
# define IN6ADDRSZ 16
#endif
#ifndef AF_INET6
# define AF_INET6 999 /* If the system does not define this,  we use a value
			 that nobody has as AF_ value -- I hope.. */
#endif
#ifndef INT16SZ
# define INT16SZ 2
#endif
#ifndef INT32SZ
# define INT32SZ 4
#endif

typedef union {
    HEADER hdr;
    u_char buf[MAXPACKET];
} querybuf;

#define ALIGN_A    4 /* IPv4 works ok with 32-bit alignment */
#define ALIGN_AAAA 8 /* IPv6 can use 64-bit machines more efficiently.. */

extern int h_errno;
extern FILE *verboselog;

int
getrr(host, ttlp, hbsize, rrtype, cnamelevel, vlog)	/* getrrtype with completion */
	char *host;
	int *ttlp;
	int hbsize;
	int rrtype;
	int cnamelevel;
	FILE *vlog;
{
	int rval;
	char buf[BUFSIZ], **domain;

	if ((rval = getrrtype(host, ttlp, hbsize, rrtype, cnamelevel, vlog)) > 0)
	  return rval;
	for (domain = _res.dnsrch; *domain != NULL; domain++) {
	  sprintf(buf, "%s.%s", host, *domain);
	  if ((rval = getrrtype(buf, ttlp, BUFSIZ, rrtype, cnamelevel, vlog)) > 0) {
	    strncpy(host, buf, hbsize<BUFSIZ?hbsize:BUFSIZ);
	    host[hbsize - 1] = '\0';
	    return rval;
	  }
	}
	return 0;
}


int
getrrtype(host, ttlp, hbsize, rrtype, cnamelevel, vlog)
	char *host;
	int *ttlp;
	int hbsize;
	int rrtype;
	int cnamelevel;
	FILE *vlog;
{

	HEADER *hp;
	msgdata *eom, *cp;
	querybuf buf, answer;
	int qlen, n, ancount, qdcount, ok;
	u_short type;
	msgdata nbuf[BUFSIZ];
	int first;

	*ttlp = 0;

	qlen = res_mkquery(QUERY, host, C_IN, rrtype, NULL, 0, NULL,
			   (void*)&buf, sizeof(buf));
	if (qlen < 0) {
	  fprintf(stderr, "res_mkquery failed\n");
	  h_errno = NO_RECOVERY;
	  strcpy(errormsg, "no recovery");
	  return -2;
	}
	n = res_send((void*)&buf, qlen, (void*)&answer, sizeof(answer));
	if (n < 0) {
	  h_errno = TRY_AGAIN;
	  strcpy(errormsg, "try again");
	  return -1;
	}
	eom = (msgdata *)&answer + n;
	/*
	 * find first satisfactory answer
	 */
	hp = (HEADER *) &answer;
	ancount = ntohs(hp->ancount);
	qdcount = ntohs(hp->qdcount);
	h_errno = 0;
	/*
	 * We don't care about errors here, only if we got an answer
	 */
	if (ancount == 0) {
	  if (rrtype == T_CNAME && hp->rcode == NOERROR) {
	    if (qdcount > 0 && strchr(host, '.') == NULL) {
	      cp = (msgdata *)&answer + sizeof(HEADER);
	      if (dn_expand((msgdata *)&answer, eom, cp, host, hbsize) >= 0) {
		if (host[0] == '\0') {
		  host[0] = '.';
		  host[1] = '\0';
		}
	      }
	    }
	    return 1;
	  }
	  return (hp->rcode == NOERROR || hp->rcode == NXDOMAIN) ? 0 : -3;
	}
	cp = (msgdata *)&answer + sizeof(HEADER);
	for (; qdcount > 0; --qdcount) {
#if	defined(BIND_VER) && (BIND_VER >= 473)
	  cp += dn_skipname(cp, eom) + QFIXEDSZ;
#else	/* !defined(BIND_VER) || (BIND_VER < 473) */
	  cp += dn_skip(cp) + QFIXEDSZ;
#endif	/* defined(BIND_VER) && (BIND_VER >= 473) */
	}
	first = 1;
	ok = (rrtype != T_WKS);
	while (--ancount >= 0 && cp < eom) {
	  if ((n = dn_expand((msgdata *)&answer, eom, cp, (void*)nbuf,
			     sizeof(nbuf))) < 0)
	    break;
	  if (first) {
	    strncpy(host, (char *)nbuf, hbsize);
	    host[hbsize - 1] = '\0';
	    first = 0;
	  }
	  cp += n;
	  type = _getshort(cp);
	  cp += 2;		/* type		-- "short" */
	  cp += 2;		/* class	-- "short" */
	  *ttlp = _getlong(cp);
	  cp += 4;		/* ttl		-- "long"  */
	  n = _getshort(cp);
	  cp += 2;		/* dlen		-- "short" */
	  if (type != rrtype) {
	    cp += n;
	    continue;
	  }
	  /*
	   * Assume that only one rrtype will be found.  More
	   * than one is undefined.
	   */
	  if (type == T_WKS) {
	    msgdata *nextcp = cp + n;
	    /* If we have seen a WKS, it had better have SMTP,
	     * however in absence of a WKS, assume SMTP.
	     */
	    if (n <= 4) {	/* IP address! */
	      cp = nextcp;	/* bad data.. */
	      continue;
	    }
	    ok = 0;
	    cp += 4;		/* skip the IP address */
	    if (*cp++ == IPPROTO_TCP) {	/* check protocol */
	      if (cp + (IPPORT_SMTP/8) < nextcp
		  && (*(cp+(IPPORT_SMTP/8))
		      & (0x80>>IPPORT_SMTP%8))) {
		if (vlog)
		  fprintf(vlog,"WKS: Found TCP/SMTP\n");
		return 1;
	      }
	      if (vlog)
		fprintf(vlog,"WKS: Found WKS of TCP, but not SMTP\n");
	    } else
	      if (vlog)
		fprintf(vlog,"WKS: Found WKS other protocol, than TCP\n");
	    cp = nextcp;
	    continue;
	  } else {
	    /* Special processing on T_CNAME ??? */
	    if ((n = dn_expand((msgdata *)&answer, eom, cp, (void*)nbuf,
			       sizeof(nbuf))) < 0)
	      break;
	    strncpy(host, (char *)nbuf, hbsize);
	    host[hbsize - 1] = '\0';
	  }
	  return ok;
	}
	return 0;
}


/* These are slightly tweaked versions of  gethostbyaddr(), and
   gethostbyname2() routines from  BIND 4.9.4 -- "slighly" by adding
   a state block into parameters, and thus removing blind static arrays. */

static int res_hnok(cp)const char *cp;{return 1;}
static int res_dnok(cp)const char *cp;{return 1;}

static const char AskedForGot[] =
			  "gethostby*.getanswer_r: asked for \"%s\", got \"%s\"";

static void
map_v4v6_address(src, dst)
	const char *src;
	char *dst;
{
	u_char *p = (u_char *)dst;
	char tmp[INADDRSZ];
	int i;

	/* Stash a temporary copy so our caller can update in place. */
	memcpy(tmp, src, INADDRSZ);
	/* Mark this ipv6 addr as a mapped ipv4. */
	for (i = 0; i < 10; i++)
		*p++ = 0x00;
	*p++ = 0xff;
	*p++ = 0xff;
	/* Retrieve the saved copy and we're done. */
	memcpy((void*)p, tmp, INADDRSZ);
}

static void
map_v4v6_hostent(hp, bpp, lenp)
	struct hostent *hp;
	char **bpp;
	int *lenp;
{
	char **ap;

	if (hp->h_addrtype != AF_INET || hp->h_length != INADDRSZ)
		return;
	hp->h_addrtype = AF_INET6;
	hp->h_length = IN6ADDRSZ;
	for (ap = hp->h_addr_list; *ap; ap++) {
		int i = ALIGN_AAAA - ((u_long)*bpp % ALIGN_AAAA);

		if (*lenp < (i + IN6ADDRSZ)) {
			/* Out of memory.  Truncate address list here.  XXX */
			*ap = NULL;
			return;
		}
		*bpp += i;
		*lenp -= i;
		map_v4v6_address(*ap, *bpp);
		*ap = *bpp;
		*bpp += IN6ADDRSZ;
		*lenp -= IN6ADDRSZ;
	}
}


static struct hostent *
getanswer_r(answer, anslen, qname, qtype, result)
	const querybuf *answer;
	int anslen;
	const char *qname;
	int qtype;
	struct dnsresult *result;
{
	register const HEADER *hp;
	register const u_char *cp;
	register int n;
	const u_char *eom;
	char *bp, **ap, **hap;
	int type, class, buflen, ancount, qdcount;
	int haveanswer, had_error;
	int toobig = 0;
	char tbuf[MAXDNAME+1];
	const char *tname;
	int (*name_ok) __((const char *));

	result->ttl = 0;

	tname = qname;
	result->host.h_name = NULL;
	eom = answer->buf + anslen;
	switch (qtype) {
	case T_A:
	case T_AAAA:
		name_ok = res_hnok;
		break;
	case T_PTR:
		name_ok = res_dnok;
		break;
	default:
		return (NULL);	/* XXX should be abort(); */
	}
	/*
	 * find first satisfactory answer
	 */
	hp = &answer->hdr;
	ancount = ntohs(hp->ancount);
	qdcount = ntohs(hp->qdcount);
	bp     = result->hostbuf;
	buflen = sizeof(result->hostbuf);
	cp = answer->buf + HFIXEDSZ;
	if (qdcount != 1) {
		h_errno = NO_RECOVERY;
		return (NULL);
	}
	n = dn_expand(answer->buf, eom, cp, bp, buflen);
	if ((n < 0) || !(*name_ok)(bp)) {
		h_errno = NO_RECOVERY;
		return (NULL);
	}
	cp += n + QFIXEDSZ;
	if (qtype == T_A || qtype == T_AAAA) {
		/* res_send() has already verified that the query name is the
		 * same as the one we sent; this just gets the expanded name
		 * (i.e., with the succeeding search-domain tacked on).
		 */
		n = strlen(bp) + 1;		/* for the \0 */
		result->host.h_name = bp;
		bp += n;
		buflen -= n;
		/* The qname can be abbreviated, but h_name is now absolute. */
		qname = result->host.h_name;
	}
	ap = result->host_aliases;
	*ap = NULL;
	result->host.h_aliases = result->host_aliases;
	hap = result->h_addr_ptrs;
	*hap = NULL;
	result->host.h_addr_list = result->h_addr_ptrs;
	haveanswer = 0;
	had_error = 0;
	while (ancount-- > 0 && cp < eom && !had_error) {
		n = dn_expand(answer->buf, eom, cp, bp, buflen);
		if ((n < 0) || !(*name_ok)(bp)) {
			had_error++;
			continue;
		}
		cp += n;			/* name */
		type = _getshort(cp);
 		cp += INT16SZ;			/* type */
		class = _getshort(cp);
 		cp += INT16SZ;			/* class */
		result->ttl = _getlong(cp);
		cp += INT32SZ;			/* TTL */
		n = _getshort(cp);
		cp += INT16SZ;			/* len */
		if (class != C_IN) {
			/* XXX - debug? syslog? */
			cp += n;
			continue;		/* XXX - had_error++ ? */
		}
		if ((qtype == T_A || qtype == T_AAAA) && type == T_CNAME) {
			if (ap >= &result->host_aliases[MAXALIASES-1])
				continue;
			n = dn_expand(answer->buf, eom, cp, tbuf, sizeof tbuf);
			if ((n < 0) || !(*name_ok)(tbuf)) {
				had_error++;
				continue;
			}
			cp += n;
			/* Store alias. */
			*ap++ = bp;
			n = strlen(bp) + 1;	/* for the \0 */
			bp += n;
			buflen -= n;
			/* Get canonical name. */
			n = strlen(tbuf) + 1;	/* for the \0 */
			if (n > buflen) {
				had_error++;
				continue;
			}
			strcpy(bp, tbuf);
			result->host.h_name = bp;
			bp += n;
			buflen -= n;
			continue;
		}
		if (qtype == T_PTR && type == T_CNAME) {
			n = dn_expand(answer->buf, eom, cp, tbuf, sizeof tbuf);
			if ((n < 0) || !res_hnok(tbuf)) {
				had_error++;
				continue;
			}
			cp += n;
			/* Get canonical name. */
			n = strlen(tbuf) + 1;	/* for the \0 */
			if (n > buflen) {
				had_error++;
				continue;
			}
			strcpy(bp, tbuf);
			tname = bp;
			bp += n;
			buflen -= n;
			continue;
		}
		if (type != qtype) {
#if 0
			zsyslog((LOG_NOTICE|LOG_AUTH,
	       "gethostby*.getanswer: asked for \"%s %s %s\", got type \"%s\"",
			       qname, p_class(C_IN), p_type(qtype),
			       p_type(type)));
#endif
			cp += n;
			continue;		/* XXX - had_error++ ? */
		}
		switch (type) {
		case T_PTR:
			if (strcasecmp(tname, bp) != 0) {
#if 0
				zsyslog((LOG_NOTICE|LOG_AUTH,
				         AskedForGot, qname, bp));
#endif
				cp += n;
				continue;	/* XXX - had_error++ ? */
			}
			n = dn_expand(answer->buf, eom, cp, bp, buflen);
			if ((n < 0) || !res_hnok(bp)) {
				had_error++;
				break;
			}
#ifdef MULTI_PTRS_ARE_ALIASES
			cp += n;
			if (!haveanswer)
				host.h_name = bp;
			else if (ap < &host_aliases[MAXALIASES-1])
				*ap++ = bp;
			else
				n = -1;
			if (n != -1) {
				n = strlen(bp) + 1;	/* for the \0 */
				bp += n;
				buflen -= n;
			}
			break;
#else
			result->host.h_name = bp;
#ifndef RES_USE_INET6
# define RES_USE_INET6 0
#endif
			if (_res.options & RES_USE_INET6) {
				n = strlen(bp) + 1;	/* for the \0 */
				bp += n;
				buflen -= n;
				map_v4v6_hostent(&result->host, &bp, &buflen);
			}
			h_errno = NETDB_SUCCESS;
			return (&result->host);
#endif
		case T_A:
		case T_AAAA:
			if (strcasecmp(result->host.h_name, bp) != 0) {
#if 0
				zsyslog((LOG_NOTICE|LOG_AUTH,
				         AskedForGot, result->host.h_name, bp));
#endif
				cp += n;
				continue;	/* XXX - had_error++ ? */
			}
			if (haveanswer) {
				if (n != result->host.h_length) {
					cp += n;
					continue;
				}
			} else {
				register int nn;

				result->host.h_name = bp;
				nn = strlen(bp) + 1;	/* for the \0 */
				bp += nn;
				buflen -= nn;
			}

			if (type == T_A)
			  bp += ALIGN_A    - ((u_long)bp % ALIGN_A   );
			else
			  bp += ALIGN_AAAA - ((u_long)bp % ALIGN_AAAA);

			if (bp + n >= &result->hostbuf[sizeof(result->hostbuf)]) {
				DPRINTF(("size (%d) too big\n", n));
				had_error++;
				continue;
			}
			if (hap >= &result->h_addr_ptrs[MAXADDRS-1]) {
				if (!toobig++) {
					DPRINTF(("Too many addresses (%d)\n",
						 MAXADDRS));
				}
				cp += n;
				continue;
			}
			memcpy(*hap++ = bp, cp,  n);
			bp += n;
			buflen -= n;
			cp += n;
			break;
		default:
			abort();
		}
		if (!had_error)
			haveanswer++;
	}
	if (haveanswer) {
		*ap = NULL;
		*hap = NULL;
# if defined(RESOLVSORT)
		/*
		 * Note: we sort even if host can take only one address
		 * in its return structures - should give it the "best"
		 * address in that case, not some random one
		 */
		if (_res.nsort && haveanswer > 1 && qtype == T_A)
			addrsort(h_addr_ptrs, haveanswer);
# endif /*RESOLVSORT*/
		if (!result->host.h_name) {
			n = strlen(qname) + 1;	/* for the \0 */
			if (n > buflen)
				goto try_again;
			strcpy(bp, qname);
			result->host.h_name = bp;
			bp += n;
			buflen -= n;
		}
		if (_res.options & RES_USE_INET6)
			map_v4v6_hostent(&result->host, &bp, &buflen);
		h_errno = NETDB_SUCCESS;
		return (&result->host);
	}
 try_again:
	h_errno = TRY_AGAIN;
	return (NULL);
}

struct hostent *
gethostbyname2_rz(name, af, result)
	const char *name;
	int af;
	struct dnsresult *result;
{
	querybuf buf;
	register const char *cp;
	char *bp;
	int n, size, type, len;
	extern struct hostent *_gethtbyname2();

	if ((_res.options & RES_INIT) == 0 && res_init() == -1) {
		h_errno = NETDB_INTERNAL;
		return (NULL);
	}

	switch (af) {
	case AF_INET:
		size = INADDRSZ;
		type = T_A;
		break;
	case AF_INET6:
		size = IN6ADDRSZ;
		type = T_AAAA;
		break;
	default:
		h_errno = NETDB_INTERNAL;
		errno = EAFNOSUPPORT;
		return (NULL);
	}

	result->host.h_addrtype = af;
	result->host.h_length = size;

#if 0
	/*
	 * if there aren't any dots, it could be a user-level alias.
	 * this is also done in res_query() since we are not the only
	 * function that looks up host names.
	 */
	if (!strchr(name, '.') && (cp = __hostalias(name)))
		name = cp;
#endif

	/*
	 * disallow names consisting only of digits/dots, unless
	 * they end in a dot.
	 */
	if (isdigit(name[0]))
		for (cp = name;; ++cp) {
			if (!*cp) {
				if (*--cp == '.')
					break;
				/*
				 * All-numeric, no dot at the end.
				 * Fake up a hostent as if we'd actually
				 * done a lookup.
				 */
				if (inet_pton(af, name, result->host_addr) <= 0) {
					h_errno = HOST_NOT_FOUND;
					return (NULL);
				}
				strncpy(result->hostbuf, name, MAXDNAME);
				result->hostbuf[MAXDNAME] = '\0';
				bp = result->hostbuf + MAXDNAME;
				len = sizeof(result->hostbuf) - MAXDNAME;
				result->host.h_name = result->hostbuf;
				result->host.h_aliases = result->host_aliases;
				result->host_aliases[0] = NULL;
				result->h_addr_ptrs[0] = (char *)result->host_addr;
				result->h_addr_ptrs[1] = NULL;
				result->host.h_addr_list = result->h_addr_ptrs;
				if (_res.options & RES_USE_INET6)
					map_v4v6_hostent(&result->host, &bp, &len);
				h_errno = NETDB_SUCCESS;
				return (&result->host);
			}
			if (!isdigit(*cp) && *cp != '.') 
				break;
		}

	if ((n = res_search(name, C_IN, type, buf.buf, sizeof(buf))) < 0) {
		DPRINTF(("res_search failed (%d)\n", n));
#if 0
		if (errno == ECONNREFUSED)
			return (_gethtbyname2(name, af));
#endif
		return (NULL);
	}
	return (getanswer_r(&buf, n, name, type, result));
}

struct hostent *
gethostbyaddr_rz(addr, len, af, result)
	const char *addr;	/* XXX should have been def'd as u_char! */
	int len, af;
	struct dnsresult *result;
{
	const u_char *uaddr = (const u_char *)addr;
	static const u_char mapped[] = { 0,0, 0,0, 0,0, 0,0, 0,0, 0xff,0xff };
	static const u_char tunnelled[] = { 0,0, 0,0, 0,0, 0,0, 0,0, 0,0 };
	int n, size;
	querybuf buf;
	register struct hostent *hp;
	char qbuf[MAXDNAME+1], *qp;
#ifdef SUNSECURITY
	register struct hostent *rhp;
	char **haddr;
	u_long old_options;
	char hname2[MAXDNAME+1];
#endif /*SUNSECURITY*/
	extern struct hostent *_gethtbyaddr();

	if ((_res.options & RES_INIT) == 0 && res_init() == -1) {
		h_errno = NETDB_INTERNAL;
		return (NULL);
	}
	if (af == AF_INET6 && len == IN6ADDRSZ &&
	    (!memcmp(uaddr, mapped, sizeof mapped) ||
	     !memcmp(uaddr, tunnelled, sizeof tunnelled))) {
		/* Unmap. */
		addr += sizeof mapped;
		uaddr += sizeof mapped;
		af = AF_INET;
		len = INADDRSZ;
	}
	switch (af) {
	case AF_INET:
		size = INADDRSZ;
		break;
	case AF_INET6:
		size = IN6ADDRSZ;
		break;
	default:
		errno = EAFNOSUPPORT;
		h_errno = NETDB_INTERNAL;
		return (NULL);
	}
	if (size != len) {
		errno = EINVAL;
		h_errno = NETDB_INTERNAL;
		return (NULL);
	}
	switch (af) {
	case AF_INET:
		(void) sprintf(qbuf, "%u.%u.%u.%u.in-addr.arpa",
			       (uaddr[3] & 0xff),
			       (uaddr[2] & 0xff),
			       (uaddr[1] & 0xff),
			       (uaddr[0] & 0xff));
		break;
	case AF_INET6:
		qp = qbuf;
		for (n = IN6ADDRSZ - 1; n >= 0; n--) {
		  sprintf(qp, "%x.%x.",
			  uaddr[n] & 0xf,
			  (uaddr[n] >> 4) & 0xf);
		  /* Older sprintf()s return end ptr, newer len ..*/
		  qp += strlen(qp);
		}
		strcpy(qp, "ip6.int");
		break;
	default:
		abort();
	}
	n = res_query(qbuf, C_IN, T_PTR, (u_char *)buf.buf, sizeof buf.buf);
	if (n < 0) {
		DPRINTF(("res_query failed (%d)\n", n));
#if 0 /* No fallback to file! */
		if (errno == ECONNREFUSED)
			return (_gethtbyaddr(addr, len, af));
#endif
		return (NULL);
	}
	if (!(hp = getanswer_r(&buf, n, qbuf, T_PTR, result)))
		return (NULL);	/* h_errno was set by getanswer_r() */
#ifdef SUNSECURITY
	if (af == AF_INET) {
	    /*
	     * turn off search as the name should be absolute,
	     * 'localhost' should be matched by defnames
	     */
	    strncpy(hname2, hp->h_name, MAXDNAME);
	    hname2[MAXDNAME] = '\0';
	    old_options = _res.options;
	    _res.options &= ~RES_DNSRCH;
	    _res.options |= RES_DEFNAMES;
	    if (!(rhp = gethostbyname(hname2))) {
#if 0
		zsyslog((LOG_NOTICE|LOG_AUTH,
		         "gethostbyaddr: No A record for %s (verifying [%s])",
		         hname2, inet_ntoa(*((struct in_addr *)addr))));
#endif
		_res.options = old_options;
		h_errno = HOST_NOT_FOUND;
		return (NULL);
	    }
	    _res.options = old_options;
	    for (haddr = rhp->h_addr_list; *haddr; haddr++)
		if (!memcmp(*haddr, addr, INADDRSZ))
			break;
	    if (!*haddr) {
#if 0
		zsyslog(LOG_NOTICE|LOG_AUTH,
		        "gethostbyaddr: A record of %s != PTR record [%s]",
		        hname2, inet_ntoa(*((struct in_addr *)addr))));
#endif
		h_errno = HOST_NOT_FOUND;
		return (NULL);
	    }
	}
#endif /*SUNSECURITY*/
	hp->h_addrtype = af;
	hp->h_length = len;
	memcpy(result->host_addr, addr, len);
	result->h_addr_ptrs[0] = (char *)result->host_addr;
	result->h_addr_ptrs[1] = NULL;
	if (af == AF_INET && (_res.options & RES_USE_INET6)) {
		map_v4v6_address((char*)result->host_addr,
				 (char*)result->host_addr);
		hp->h_addrtype = AF_INET6;
		hp->h_length = IN6ADDRSZ;
	}
	h_errno = NETDB_SUCCESS;
	return (hp);
}

#endif	/* BIND */
