/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/* LINTLIBRARY */

#include "mailer.h"
#ifdef	HAVE_RESOLVER

#undef	RFC974		/* MX/WKS/A processing according to RFC974 */

#include <sys/socket.h>

#include <netdb.h>
#ifndef EAI_AGAIN
# include "netdb6.h" /* IPv6 API stuff */
#endif

#define CUC const u_char

/* ================ do we have a normal nameserver? ================ */
#ifdef	TRY_AGAIN

#ifdef	BSDTYPES_H
#include BSDTYPES_H
#endif	/* BSDTYPES_H */

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

#ifdef NOERROR
#undef NOERROR /* On Solaris 2.3 the  netinet/in.h  includes
		  sys/stream.h, which has DIFFERENT "NOERROR" in it.. */
#endif

#ifdef __linux__
#define __USE_BSD 1	/* Linux headers ... Auch..  <endian.h> */
#endif
#include <arpa/nameser.h>
#include <resolv.h>
#include <string.h>
#include "search.h"

#include "libz.h"
#include "libc.h"
#include "libsh.h"
#include "dnsgetrr.h"


/*
 * Query a BIND standard (version 4.7 or later) nameserver.
 */


/* For use by WKS lookup, we need to know the SMTP port number. */

#ifndef	IPPORT_SMTP
#define	IPPORT_SMTP	25
#endif	/* !IPPORT_SMTP */

#ifndef	MAXNAME
#define	MAXNAME		BUFSIZ
#endif	/* !MAXNAME */

#define	MAXVALIDTTL	(60*60*24*365)	/* any ttl over this is ignored */

#ifndef	BIND_VER
#ifdef	GETLONG
/* 4.7.3 introduced the {GET,PUT}{LONG,SHORT} macros in arpa/nameser.h */
#define	BIND_VER	473
#else	/* !GETLONG */
#define	BIND_VER	472
#endif	/* GETLONG */
#endif	/* !BIND_VER */

#if	defined(BIND_VER) && (BIND_VER >= 473)
const char * conffile;
#endif	/* defined(BIND_VER) && (BIND_VER >= 473) */


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
#ifndef T_AAAA
# define T_AAAA 28	/* IPv6 Address */
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


extern int D_bind, D_resolv;

extern int	h_errno;
char h_errhost[MAXNAME];

struct qtypes {
	const char *typename;
	int	value;
} qt[] = {
	{	"cname",	T_CNAME		},
	{	"any",		T_ANY		},
	{	"mx",		T_MX		},
	{	"a",		T_A		},
	{	"aaaa",		T_AAAA		},
#ifdef	T_MP
	{	"mp",		T_MP		},
#endif	/* T_MP */
#ifdef	T_UNAME
	{	"uname",	T_UNAME		},
#endif	/* T_UNAME */
	{	"txt",		T_TXT		},
	{	"uinfo",	T_UINFO		},
	{	"wks",		T_WKS		},
	{	"ptr",		T_PTR		},
	{	0,		0		}
};

const char *zh_errlist[] = {
	"Error 0",
	"unknown host/not findable at all",	/* 1 - HOST_NOT_FOUND	*/
	"host name lookup/try again",		/* 2 - TRY_AGAIN	*/
	"unknown server/no recovery",		/* 3 - NO_RECOVERY	*/
	"no address associated with name"	/* 4 - NO_ADDRESS	*/
};

static conscell * getmxrr    __((const char *, const char *, time_t *, int));
static conscell * getcrrtype __((const char *, int, time_t *, int));
static conscell * getrrtypec __((const char *, int, time_t *, int));

extern const char * myhostname;
extern int deferit;
extern int cistrcmp __((const char *, const char *));

#if 0
void
zherror(s)
	char *s;
{
	if (h_errno >= 0 && h_errno < (sizeof zh_errlist/sizeof zh_errlist[0]))
	  fprintf(stderr, "%s: resolver error: %s\n",
		  s, zh_errlist[h_errno]);
	else
	  fprintf(stderr, "%s: resolver error: %d\n", s, h_errno);
}
#endif

conscell *
search_res(sip)
	search_info *sip;
{
	struct qtypes *qtp;
	conscell *rval;
	const char *host;
	char        buf[BUFSIZ];

	if (!(_res.options & RES_INIT)) {
	  if (sip->file != NULL)
	    conffile = sip->file;
	  if (res_init() < 0) {
	    fprintf(stderr,
		    "search_res: nameserver initialization failure!\n");
	    die(1, "res_init failure");
	  }
	}
	if (D_resolv)
	  _res.options |= RES_DEBUG;
	else
	  _res.options &= ~RES_DEBUG;
	/* [Edwin Allum]
	 * Turn down the resolver's retry count.
	 * The default (4) will cause the router to fall
	 * hopelessly behind in the face of broken DNS data.
	 */
	/* _res.retry   = 2; */
	/* Lets not, but lets not use DNS at router, lets use it only
	   at SMTP channels */

	if (sip->subtype == NULL || *(sip->subtype) == '\0') {
	  fprintf(stderr, "search_res: missing subtype to BIND query!\n");
	  return NULL;
	}
	for (qtp = qt; qtp->value != 0; ++qtp)
	  if (CISTREQ(qtp->typename, sip->subtype))
	    break;
	if (qtp->value == 0) {
	  fprintf(stderr,
		  "search_res: unknown subtype '%s' to BIND query!\n",
		  sip->subtype);
	  return NULL;
	}
	h_errno = 0;
	h_errhost[0] = '\0';
	switch (qtp->value) {
	case T_MX:
		rval = getmxrr(sip->key, myhostname, &sip->ttl, 0);
		break;
	case T_WKS:
	case T_PTR:
	case T_A:
	case T_SA:
#ifdef	T_MP
	case T_MP:
#endif	/* T_MP */
#ifdef	T_UNAME
	case T_UNAME:
#endif	/* T_UNAME */
	case T_TXT:
	case T_UINFO:
		rval = getrrtypec(sip->key, qtp->value,
				  &sip->ttl, 0);
		break;
	case T_ANY:
	case T_CNAME:
		rval = getcrrtype(sip->key, qtp->value,
				  &sip->ttl, 0);
		break;
	default:
		rval = NULL;
	}
	if (h_errno > 0) {
	  if (h_errhost[0] == '\0')
	    host = sip->key;
	  else
	    host = h_errhost;

	  deferit++;

	  if (h_errno >= 0 &&
	      h_errno < (sizeof zh_errlist/sizeof zh_errlist[0]))
	    fprintf(stderr,
		    "search_res: deferred: %s: %s (%s) error\n",
		    host, qtp->typename, zh_errlist[h_errno]);
	  else
	    fprintf(stderr,
		    "search_res: deferred: %s: %s (%d) error\n",
		    host, qtp->typename, h_errno);

	  sprintf(buf, "NS:%s/%s", host, qtp->typename);
	  v_set(DEFER, buf);
	}
	return rval;
}


typedef union {
	HEADER qb1;
	char qb2[PACKETSZ];
} querybuf;

struct mxdata {
	char *host;
	int	pref;
	time_t	ttl;
};

static conscell *
getmxrr(host, localhost, ttlp, depth)
	const char *host;
	const char *localhost;
	time_t *ttlp;
	int depth;
{
	HEADER *hp;
	CUC *eom, *cp;
	querybuf buf, answer;
	int n, qlen, nmx, i, ancount, qdcount, maxpref;
	conscell *lhead, *l, *tmp;
	struct mxdata mx[20];
	char hbuf[MAXNAME], realname[MAXNAME];
	int type;
	time_t ttl, maxttl;

	if (depth > 4) {
	  fprintf(stderr,
		  "search_res: CNAME chain length exceeded (%s)\n",
		  host);
	  strcpy(h_errhost, host); /* use strcat on purpose */
	  h_errno = TRY_AGAIN;
	  return NULL;
	}
	qlen = res_mkquery(QUERY, host, C_IN, T_MX, NULL, 0, NULL,
			   (void *)&buf, sizeof(buf));
	if (qlen < 0) {
		fprintf(stderr, "search_res: res_mkquery (%s) failed\n", host);
		strcpy(h_errhost, host);	/* use strcat on purpose */
		h_errno = NO_RECOVERY;
		return NULL;
	}
	n = res_send((void *)&buf, qlen, (void *)&answer, sizeof(answer));
	if (n < 0) {
	  /* Retry it ONCE.. */
	  n = res_send((void *)&buf, qlen, (void *)&answer, sizeof(answer));
	  if (n < 0) {
	    if (D_bind || _res.options & RES_DEBUG)
	      fprintf(stderr,
		      "search_res: res_send (%s) failed\n", host);
	    strcpy(h_errhost, host); /* use strcat on purpose */
	    h_errno = TRY_AGAIN;
	    return NULL;
	  }
	}
	eom = (CUC *)&answer + n;
	/*
	 * find first satisfactory answer
	 */
	hp = (HEADER *) &answer;
	ancount = ntohs(hp->ancount);
	qdcount = ntohs(hp->qdcount);
	if (hp->rcode != NOERROR || ancount == 0) {
		if (D_bind || _res.options & RES_DEBUG)
			fprintf(stderr,
				"search_res: rcode = %d, ancount=%d, aa=%d\n",
				hp->rcode, ancount, hp->aa);
		switch (hp->rcode) {
			case NXDOMAIN:
				return NULL;
			case SERVFAIL:
				strcpy(h_errhost, host);
				h_errno = TRY_AGAIN;
				return NULL;
#ifdef	OLDJEEVES
			/*
			 * Jeeves (TOPS-20 server) still does not
			 * support MX records.  For the time being,
			 * we must accept FORMERRs as the same as
			 * NOERROR.
			 */
			case FORMERR:
#endif	/* OLDJEEVES */
			case NOERROR:
				/* if we got this, then ancount == 0! */
				return NULL /*getrrtypec(host, T_A, ttlp)*/;
#ifndef	OLDJEEVES
			case FORMERR:
#endif	/* !OLDJEEVES */
			case NOTIMP:
			case REFUSED:
				strcpy(h_errhost, host);
				h_errno = NO_RECOVERY;
				return NULL;
		}
		return NULL;
	}
	cp = (CUC *)&answer + sizeof(HEADER);
	for (; qdcount > 0; --qdcount)
#if	defined(BIND_VER) && (BIND_VER >= 473)
		cp += dn_skipname((CUC*)cp, (CUC*)eom) + QFIXEDSZ;
#else	/* !defined(BIND_VER) || (BIND_VER < 473) */
		cp += dn_skip((CUC*)cp) + QFIXEDSZ;
#endif	/* defined(BIND_VER) && (BIND_VER >= 473) */
	nmx = 0;
	maxttl = ttl = 0;
	realname[0] = '\0';
	maxpref = -1;
	/* assert: stickymem == MEM_MALLOC;  for storing RHS of MX RR's */
	while (--ancount >= 0 && cp < eom && nmx < (sizeof mx/sizeof mx[0])) {
		n = dn_expand((CUC*)&answer, (CUC*)eom, (CUC*)cp,
			      (void*)hbuf, sizeof hbuf);
		if (n < 0)
			break;
		cp += n;
		type = _getshort(cp);
 		cp += 2;				/* type -- short */
 		cp += 2;				/* class -- short */
		ttl = (time_t) _getlong(cp);
		cp += 4;				/* ttl -- "long" */
		n = _getshort(cp);
		cp += 2;				/* dlen -- short */
		if (type == T_CNAME) {
			cp += dn_expand((CUC*)&answer, (CUC*)eom, (CUC*)cp,
					(void*)realname, sizeof realname);
			continue;
		} else if (type != T_MX)  {
			if (D_bind || _res.options & RES_DEBUG)
				fprintf(stderr,
					"search_res: bad mx query answer type %d, size %d\n",
					type, n);
			cp += n;
			continue;
		}
		mx[nmx].ttl = ttl;
		mx[nmx].pref = _getshort(cp);
		cp += 2; /* "short" */		/* MX preference value */
		n = dn_expand((CUC*)&answer, (CUC*)eom, (CUC*)cp,
			      (void*)hbuf, sizeof hbuf);
		if (n < 0)
			break;
		cp += n;
		mx[nmx].host = (char *)strsave((char*)hbuf);
		if (localhost != NULL && CISTREQ(hbuf, localhost))
		    if ((maxpref < 0) || (maxpref > (int)mx[nmx].pref))
			maxpref = mx[nmx].pref;
		++nmx;
	}
	if (nmx == 0 && realname[0] != '\0' &&
	    !CISTREQ(host,(char*)realname)) {
		/* do it recursively for the real name */
		return getmxrr((char *)realname, localhost, ttlp, depth+1);
	} else if (nmx == 0)
		return NULL;
	/* discard MX RRs with a value >= that of localdomain */
	if (maxpref >= 0) {
		for (n = 0; n < nmx; ++n) {
			if (((int)mx[n].pref >= maxpref) && (mx[n].host != NULL)) {
				free((char *)mx[n].host);
				mx[n].host = NULL;
			}
		}
	}
#ifdef	RFC974
	/* discard MX's that do not support SMTP service */
	for (n = 0; n < nmx; ++n) {
		if (mx[n].host == NULL)
			continue;
		strcpy(hbuf, mx[n].host);
		if (!getrrtypec(hbuf, T_WKS, ttlp, 0)) {
			free(mx[n].host);
			mx[n].host = NULL;
		}
	}
#endif	/* RFC974 */
	/* determine how many are left, and their max ttl */
	n = 0;
	lhead = l = NULL;
	for (i = 0; i < nmx; ++i) {
		if (mx[i].host == NULL)
			continue;
		++n; /* found one! */
		if (mx[i].ttl > maxttl && mx[i].ttl < MAXVALIDTTL)
			maxttl = ttl;
		if (D_bind || _res.options & RES_DEBUG)
			fprintf(stderr, "search_res: %s: mx[%d] = %s\n",
				host, n, mx[i].host);
		if (lhead == NULL)
			lhead = l = newstring(mx[i].host);
		else {
			cdr(l) = newstring(mx[i].host);
			l = cdr(l);
		}
	}
	if (D_bind || _res.options & RES_DEBUG)
		fprintf(stderr, "search_res: %s: %d valid MX RR's\n", host, n);
	if (n == 0) /* MX's exist, but their WKS's show no TCP smtp service */
		return NULL;
	else if (maxttl > 0)
		*ttlp = maxttl;
	return ncons(lhead);
}

static conscell *
getcrrtype(host, rrtype, ttlp, depth)	/* getrrtypec() with completion */
	const char *host;
	int rrtype;
	time_t *ttlp;
	int depth;
{
	conscell *rval;
	char buf[BUFSIZ];
	char *domain;
	int i;

	if (depth > 4) {
		fprintf(stderr,
			"search_res: CNAME chain length exceeded (%s)\n",
			host);
		strcpy(h_errhost, host);	/* use strcat on purpose */
		h_errno = TRY_AGAIN;
		return NULL;
	}

	if (strchr(host, '.') != NULL) {
		rval = getrrtypec(host, rrtype, ttlp, depth+1);
		if (rval != NULL)
			return rval;
		if (*host != '\0' && *(host+strlen(host)-1) == '.')
			return NULL;
	}
	for (i = 0, domain = _res.dnsrch[i];
	     h_errno == 0 && (domain = _res.dnsrch[i]) != NULL; ++i) {
		sprintf(buf, "%s.%s", host, domain);
		rval = getrrtypec(buf, rrtype, ttlp, depth+1);
		if (rval != NULL)
			return rval;
	}
	strcpy(h_errhost, host);
	return NULL;
}

static conscell *
getrrtypec(host, rrtype, ttlp, depth)
	const char *host;
	int rrtype;
	time_t *ttlp;
	int depth;
{
	conscell *lhead, *l, *tmp;
	char *s;
	HEADER *hp;
	CUC *eom, *cp, *nextcp;
	querybuf buf, answer;
	int qlen, n, ancount, qdcount, ok, first;
	struct in_addr inaddr;
	time_t maxttl, ttl;
	int type;
	char nbuf[BUFSIZ];
	char hb[MAXNAME];

	if (depth > 4) {
		fprintf(stderr,
			"search_res: CNAME chain length exceeded (%s)\n",
			host);
		strcpy(h_errhost, host);	/* use strcat on purpose */
		h_errno = TRY_AGAIN;
		return NULL;
	}

	qlen = res_mkquery(QUERY, host, C_IN, rrtype, NULL, 0, NULL,
			   (void *)&buf, sizeof(buf));
	if (qlen < 0) {
		if (D_bind || _res.options & RES_DEBUG)
			fprintf(stderr,
				"search_res: res_mkquery (%s) failed\n", host);
		strcpy(h_errhost, host);
		h_errno = NO_RECOVERY;
		return NULL;
	}
	n = res_send((void *)&buf, qlen, (void *)&answer, sizeof(answer));
	if (n < 0) {
	  /* Retry it ONCE.. */
	  n = res_send((void*)&buf, qlen, (void *)&answer, sizeof(answer));
	  if (n < 0) {
	    if (D_bind || _res.options & RES_DEBUG)
	      fprintf(stderr,
		      "search_res: res_send (%s) failed\n", host);
	    strcpy(h_errhost, host);
	    h_errno = TRY_AGAIN;
	    return NULL;
	  }
	}
	eom = (CUC *)&answer + n;
	/*
	 * find first satisfactory answer
	 */
	hp = (HEADER *) &answer;
	ancount = ntohs(hp->ancount);
	qdcount = ntohs(hp->qdcount);
	/*
	 * We don't care about errors here, only if we got an answer
	 */
	if (ancount == 0) {
		if (D_bind || _res.options & RES_DEBUG)
			fprintf(stderr,
				"search_res: rcode=%d, ancount=%d, rrtype=%d\n",
				hp->rcode, ancount, rrtype);
		if (rrtype == T_CNAME && hp->rcode == NOERROR) {
		  if (qdcount > 0 && strchr(host, '.') == NULL) {
		    cp = (CUC*) &answer + sizeof(HEADER);
		    if (dn_expand((CUC*)&answer, (CUC*)eom, (CUC*)cp,
				  (void*)hb, sizeof hb)>=0) {
		      if (hb[0] == '\0') {
			hb[0] = '.'; hb[1] = '\0';
		      }
		      return newstring(strsave(hb));
		    }
		  }
		  return newstring(strsave(host));
		}
		if (rrtype == T_WKS) /* absence of WKS means YES ... */
			return newstring(strsave(host));
		return NULL;
	}
	cp = (CUC *)&answer + sizeof(HEADER);
	for (; qdcount > 0; --qdcount)
#if	defined(BIND_VER) && (BIND_VER >= 473)
		cp += dn_skipname((CUC*)cp, (CUC*)eom) + QFIXEDSZ;
#else	/* !defined(BIND_VER) || (BIND_VER < 473) */
		cp += dn_skip((CUC*)cp) + QFIXEDSZ;
#endif	/* defined(BIND_VER) && (BIND_VER >= 473) */
	first = 1;
	ok = rrtype != T_WKS;
	maxttl = 0;
	l = NULL;
	for (lhead = NULL; --ancount >= 0 && cp < eom; cp = nextcp) {
		n = dn_expand((CUC*)&answer, (CUC*)eom, (CUC*)cp,
			      (void*)nbuf, sizeof(nbuf));
		if (n < 0)
			break;
		if (first) {
			if (strlen(nbuf) < sizeof hb)
				strcpy(hb, nbuf);
			else {
				strncpy(hb, nbuf, sizeof hb);
				hb[(sizeof hb) - 1] = '\0';
			}
			first = 0;
		}
		cp += n;
		type = _getshort((const u_char*)cp);
 		cp += 2;			/* type  -- short */
 		cp += 2;			/* class -- short */
		ttl = (time_t) _getlong((const u_char*)cp);
		cp += 4;			/* ttl -- "long" */
		n = _getshort((const u_char*)cp);
		cp += 2;			/* dlen -- short */
		nextcp = cp + n;

		if (rrtype != T_ANY && type != rrtype)
			continue;
		/*
		 * Assume that only one rrtype will be found.  More
		 * than one is undefined. T_ANY is a bit special..
		 */

		if (ttl > maxttl && ttl < MAXVALIDTTL)
			maxttl = ttl;
		switch (type) {
		case T_TXT:
		case T_UINFO:
#ifdef	T_UNAME
		case T_UNAME:
#endif	/* T_UNAME */
#ifdef	T_MP
		case T_MP:
#endif	/* T_MP */
			if (rrtype == T_ANY)
				continue;	/* Not our time.. */

			*ttlp = maxttl;
			n = (*cp) & 0xFF;
			if (0 < n && n < sizeof hb)
			  return newstring(strnsave((const char *)cp+1, n));
			break;

		case T_WKS:
			/*
			 * If we have seen a WKS, it had better have SMTP,
			 * however in absence of a WKS, assume SMTP.
			 */
			if (rrtype != T_WKS)	/* Take it only if it was */
			  continue;		/* explicitely asked for! */

			if (n < (4/*"long"*/ + 1))
				continue;
			ok = 0;
			cp += 4;		/* skip IP address */
			if (*cp++ == IPPROTO_TCP) {	/* check protocol */
			  if (cp + (IPPORT_SMTP/8) < nextcp &&
			      *(cp+(IPPORT_SMTP/8)) & (0x80>>IPPORT_SMTP%8)) {
			    *ttlp = maxttl;
			    return newstring(strsave(hb));
			  }
			}
			continue;
		case T_A:
		case T_SA:
		case T_AAAA:
			*ttlp = maxttl;
			if (rrtype == T_ANY) {
			  return newstring(strsave(host));
			} else {
			  char tb[80];
			  const char *ss;

#if defined(AF_INET6) && defined(INET6)
			  if (type == T_AAAA)
			    ss = inet_ntop(AF_INET6, cp, tb, sizeof(tb));
			  else
#endif
			    ss = inet_ntop(AF_INET, cp, tb, sizeof(tb));
			  s = strsave(ss);
			  if (lhead == NULL)
			    lhead = l = newstring(s);
			  else {
			    cdr(l) = newstring(s);
			    l = cdr(l);
			  }
			}
			continue;

		case T_CNAME:
		case T_PTR:
			if (rrtype == T_ANY && type == T_PTR)
				/* if asking for something particular,
				   don't yield wrong data. Asking
				   "ANY sara.nl"  yielded following:
					NS ...
					NS ...
					...
					MX ...
					MX ...
					...
					PTR ...
					PTR ...
					...
					SOA ...
				   which really caused headaches, when
				   the PTR data was taken in as CNAME.. */
				continue;

			n = dn_expand((CUC*)&answer, (CUC*)eom, (CUC*)cp,
				      (void*)nbuf, sizeof(nbuf));
			if (n < 0)
				break;

			if (type == T_CNAME && rrtype != T_ANY &&
			    !CISTREQ(nbuf, host))
				/* chase it down */
				getrrtypec(nbuf, rrtype, ttlp, depth+1);
			*ttlp = maxttl;
			return newstring(strsave(nbuf));

		case T_SOA:
		case T_NS:
		case T_RP:
		case T_AFSDB:
		case T_X25:
		case T_ISDN:
		case T_RT:
		case T_NSAP:
		case T_NSAP_PTR:
		case T_HINFO:
		case T_UID:
		case T_GID:
		case T_UNSPEC:
			continue; /* Just forget it */

		case T_MX:
			if (rrtype == T_ANY) {
			    return newstring(strsave(host));
			}
		default:
			fprintf(stderr,"search_res: getrrtypec: non-processed RR type for host='%s' query=%d, result=%d\n",host,rrtype,type);

			break;
		}
	}
	if (lhead)
		return ncons(lhead);
	if (ok) {
		const char *cs = first ? host : hb;
		*ttlp = maxttl;
		return newstring(strsave(cs));
	}
	return NULL;
}
#endif	/* TRY_AGAIN */
#endif	/* HAVE_RESOLVER */
