/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */
/*
 *	Lots of modifications (new guts, more or less..) by
 *	Matti Aarnio <mea@nic.funet.fi>  (copyright) 1992-2003
 */

/* LINTLIBRARY */

#include "mailer.h"
#ifdef	HAVE_RESOLVER

#define	RFC974		/* MX/WKS/A processing according to RFC974 */

#include "zresolv.h"

#include <string.h>
#include "search.h"

#include "libz.h"
#include "libc.h"
#include "libsh.h"
#include "dnsgetrr.h"


/*
 * Query a BIND standard (version 4.7 or later) nameserver.
 */


const char *conffile;

extern int D_bind, D_resolv;

char *h_errhost = NULL;

#define T_MXWKS    0x00010000
#define T_MXLOCAL  0x00020000

struct qtypes {
	const char *typename;
	int	value;
} qt[] = {
	{	"cname",	T_CNAME		},
	{	"any",		T_ANY		},
	{	"mx",		T_MX		},
	{	"mxwks",	T_MX|T_MXWKS	},
	{	"mxlocal",	T_MX|T_MXLOCAL	},
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

static const char *zh_errlist[] = {
	"Error 0",
	"unknown host/not findable at all",	/* 1 - HOST_NOT_FOUND	*/
	"host name lookup/try again",		/* 2 - TRY_AGAIN	*/
	"unknown server/no recovery",		/* 3 - NO_RECOVERY	*/
	"no address associated with name"	/* 4 - NO_ADDRESS	*/
};

static const char *res_respcodes[] = {
	"NOERROR",
	"FORMERR",
	"SERVFAIL",
	"NXDOMAIN",
	"NOTIMP",
	"REFUSED",
	"Resp6",
	"Resp7",
	"Resp8"
};

static conscell * getmxrr    __((const char *, time_t *, int, int));
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

	h_errno = 0;

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
	if (h_errhost) free(h_errhost);
	h_errhost = NULL;
	switch (0xFF & qtp->value) {
	case T_MX:
		if (qtp->value & T_MXLOCAL)
		  stashmyaddresses(myhostname); /* Need to know my local
						   interface addresses! */
		rval = getmxrr(sip->key, &sip->ttl, 0, qtp->value);
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
	  if (!h_errhost)
	    host = sip->key;
	  else
	    host = h_errhost;

	  deferit++;

	  if (h_errno >= 0 &&
	      h_errno < (sizeof zh_errlist/sizeof zh_errlist[0]))
	    fprintf(stderr,
		    "search_res: deferred: %s: %s (%s) error; errhost=%s\n",
		    host, qtp->typename, zh_errlist[h_errno], h_errhost);
	  else
	    fprintf(stderr,
		    "search_res: deferred: %s: %s (%d) error\n",
		    host, qtp->typename, h_errno);

	  sprintf(buf, "NS:%.500s/%.20s", host, qtp->typename);
	  v_set(DEFER, buf);
	}
	return rval;
}


struct mxdata {
	char *host;
	int	pref;
	time_t	ttl;
};

static conscell *
getmxrr(host, ttlp, depth, flags)
	const char *host;
	time_t *ttlp;
	int depth;
	int flags;
{
	HEADER *hp;
	CUC *eom, *cp;
	querybuf buf, answer;
	int n, qlen, nmx, i, ancount, qdcount, maxpref;
	conscell *lhead, *l;
	struct mxdata mx[20];
	char hbuf[MAXNAME], realname[MAXNAME];
	int type;
	time_t ttl, maxttl;
	GCVARS1;

	h_errno = 0;

	nmx = 0;
	maxttl = ttl = 0;
	maxpref = -1;
	lhead = l = NULL;

	if (depth > 4) {
	  fprintf(stderr,
		  "search_res: CNAME chain length exceeded (%s)\n",
		  host);
	  h_errhost = realloc(h_errhost, strlen(host)+1);
	  strcpy(h_errhost, host);
	  h_errno = TRY_AGAIN;
	  return NULL;
	}
	qlen = res_mkquery(QUERY, host, C_IN, T_MX, NULL, 0, NULL,
			   (void *)&buf, sizeof(buf));
	if (qlen < 0) {
		fprintf(stderr, "search_res: res_mkquery (%s) failed\n", host);
		h_errhost = realloc(h_errhost, strlen(host)+1);
		strcpy(h_errhost, host);
		h_errno = NO_RECOVERY;
		return NULL;
	}
	n = res_send((void *)&buf, qlen, (void *)&answer, sizeof(answer));
	if (n < 0) {
	  /* Retry it ONCE.. */
	  n = res_send((void *)&buf, qlen, (void *)&answer, sizeof(answer));
	  if (n < 0) {
	    if (D_bind || (_res.options & RES_DEBUG))
	      fprintf(stderr,
		      "search_res: res_send (%s) failed\n", host);
	    h_errhost = realloc(h_errhost, strlen(host)+1);
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
	if (hp->rcode != NOERROR || ancount == 0) {
		if (D_bind || _res.options & RES_DEBUG)
			fprintf(stderr,
				"search_res: rcode = %d, ancount=%d, aa=%d\n",
				hp->rcode, ancount, hp->aa);
		switch (hp->rcode) {
			case NXDOMAIN:
				h_errno = HOST_NOT_FOUND;
				return NULL;
			case SERVFAIL:
				h_errhost = realloc(h_errhost, strlen(host)+1);
				strcpy(h_errhost, host);
				h_errno = TRY_AGAIN;
				return NULL;
			case NOERROR:
				/* if we got this, then ancount == 0! */
				h_errno = 0;
				return NULL /*getrrtypec(host, T_A, ttlp)*/;
			case FORMERR:
			case NOTIMP:
			case REFUSED:
				h_errhost = realloc(h_errhost, strlen(host)+1);
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
	realname[0] = '\0';
	while (--ancount >= 0 && cp < eom && nmx < (sizeof mx/sizeof mx[0])) {
		n = dn_expand((CUC*)&answer, (CUC*)eom, (CUC*)cp,
			      (void*)hbuf, sizeof hbuf);
		if (n < 0)
			break;
		cp += n;

		NS_GET16(type,  cp);		/* type -- short */
 		cp += NS_INT16SZ;		/* class -- short */
		NS_GET32(ttl, cp);		/* ttl -- "long" */
		NS_GET16(n, cp);		/* dlen -- short */

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

		NS_GET16(mx[nmx].pref, cp);	/* MX preference value */

		n = dn_expand((CUC*)&answer, (CUC*)eom, (CUC*)cp,
			      (void*)hbuf, sizeof hbuf);
		if (n < 0)
			break;
		cp += n;
		mx[nmx].host = (char *)strdup((char*)hbuf);
		if (myhostname != NULL && CISTREQ(hbuf, myhostname)) {
		    if ((maxpref < 0) || (maxpref > (int)mx[nmx].pref))
			maxpref = mx[nmx].pref;
		} else
		  if (flags & T_MXLOCAL) {
		    struct addrinfo req, *ai;
		    int herr = h_errno;

		    memset(&req, 0, sizeof(req));
		    req.ai_socktype = SOCK_STREAM;
		    req.ai_protocol = IPPROTO_TCP;
		    req.ai_flags    = AI_CANONNAME;
		    req.ai_family   = AF_INET;
		    ai = NULL;
		  
#if !defined(GETADDRINFODEBUG)
		    i = getaddrinfo((const char*)hbuf, "0", &req, &ai);
#else
		    i = _getaddrinfo_((const char*)hbuf,"0",&req,&ai,stderr);
#endif
		    if (matchmyaddresses(ai) != 0)
		      if ((maxpref < 0) || (maxpref > (int)mx[nmx].pref))
			maxpref = mx[nmx].pref;
		    if (ai)
		      freeaddrinfo(ai);
#if defined(AF_INET6) && defined(INET6)
		    memset(&req, 0, sizeof(req));
		    req.ai_socktype = SOCK_STREAM;
		    req.ai_protocol = IPPROTO_TCP;
		    req.ai_flags    = AI_CANONNAME;
		    req.ai_family   = AF_INET6;
		    ai = NULL;
		  
#if !defined(GETADDRINFODEBUG)
		    i = getaddrinfo((const char*)hbuf, "0", &req, &ai);
#else
		    i = _getaddrinfo_((const char*)hbuf,"0",&req,&ai,stderr);
#endif
		    if (matchmyaddresses(ai) != 0)
		      if ((maxpref < 0) || (maxpref > (int)mx[nmx].pref))
			maxpref = mx[nmx].pref;
		    if (ai)
		      freeaddrinfo(ai);
#endif /* INET6 */
		    h_errno = herr;
		  }
		++nmx;
	}
	if (nmx == 0 && realname[0] != '\0' &&
	    !CISTREQ(host,(char*)realname)) {
		/* do it recursively for the real name */
		return getmxrr((char *)realname, ttlp, depth+1, flags);
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
	if (flags & T_MXWKS)
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
	GCPRO1(lhead);
	for (i = 0; i < nmx; ++i) {
		int slen;
		char *s;
		if (mx[i].host == NULL)
			continue;
		++n; /* found one! */
		if (mx[i].ttl > maxttl && mx[i].ttl < MAXVALIDTTL)
			maxttl = ttl;
		if (D_bind || _res.options & RES_DEBUG)
			fprintf(stderr, "search_res: %s: mx[%d] = %s [%d]\n",
				host, n, mx[i].host, mx[i].pref);
		if (!(flags & T_MXLOCAL)) {
		  slen = strlen(mx[i].host);
		  s = dupnstr(mx[i].host, slen);
		  if (lhead == NULL)
		    lhead = l = newstring(s,slen);
		  else {
		    cdr(l) = newstring(s,slen);
		    l = cdr(l);
		  }
		}
		if (mx[i].host) free(mx[i].host);
		mx[i].host = NULL;
	}
	if (flags & T_MXLOCAL) {
	  /* Did find MXes, and we were the lowest of them all... */
	  if (n == 0 && nmx > 0) {
	    int slen = strlen(host);
	    char  *s = dupnstr(host, slen);
	    lhead = newstring(s, slen);
	  }
	}
	if (lhead)
		lhead = ncons(lhead);
	UNGCPRO1;

	if (D_bind || _res.options & RES_DEBUG)
		fprintf(stderr, "search_res: %s: %d valid MX%s RR's out of %d\n", host, n, (flags & T_MXLOCAL) ? "(LOCAL)":"", nmx);
	if (maxttl > 0)
		*ttlp = maxttl;
	return lhead;
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
		h_errhost = realloc(h_errhost, strlen(host)+1);
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
		sprintf(buf, "%.200s.%.300s", host, domain);
		rval = getrrtypec(buf, rrtype, ttlp, depth+1);
		if (rval != NULL)
			return rval;
	}
	h_errhost = realloc(h_errhost, strlen(host)+1);
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
	conscell *lhead, *l;
	char *s;
	HEADER *hp;
	CUC *eom, *cp, *nextcp;
	querybuf buf, answer;
	int qlen, n, ancount, qdcount, ok, first;
	time_t maxttl, ttl;
	int type;
	char nbuf[BUFSIZ];
	char hb[MAXNAME];
	GCVARS1;

	if (depth > 4) {
		fprintf(stderr,
			"search_res: CNAME chain length exceeded (%s)\n",
			host);
		h_errhost = realloc(h_errhost, strlen(host)+1);
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
		h_errhost = realloc(h_errhost, strlen(host)+1);
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
	    h_errhost = realloc(h_errhost, strlen(host)+1);
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
		int slen; char *s;
		if (D_bind || _res.options & RES_DEBUG)
			fprintf(stderr,
				"search_res: rcode=%s, ancount=%d, rrtype=%d\n",
				res_respcodes[hp->rcode], ancount, rrtype);
		if (rrtype == T_CNAME && hp->rcode == NOERROR) {
		  if (qdcount > 0 && strchr(host, '.') == NULL) {
		    cp = (CUC*) &answer + sizeof(HEADER);
		    if (dn_expand((CUC*)&answer, (CUC*)eom, (CUC*)cp,
				  (void*)hb, sizeof hb)>=0) {
		      if (hb[0] == '\0') {
			hb[0] = '.'; hb[1] = '\0';
		      }
		      slen = strlen(hb);
		      s = dupnstr(hb, slen);
		      return newstring(s, slen);
		    }
		  }
		  slen = strlen(host);
		  s = dupnstr(host, slen);
		  return newstring(s, slen);
		}
		if (rrtype == T_WKS) { /* absence of WKS means YES ... */
		  slen = strlen(host);
		  s = dupnstr(host, slen);
		  return newstring(s, slen);
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
	first = 1;
	ok = rrtype != T_WKS;
	maxttl = 0;
	l = NULL;
	lhead = NULL;
	GCPRO1(lhead);
	for (; --ancount >= 0 && cp < eom; cp = nextcp) {
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

		NS_GET16(type,  cp);	/* type  -- short */
 		cp += NS_INT16SZ;	/* class -- short */
		NS_GET32(ttl, cp);	/* ttl -- "long" */
		NS_GET16(n,   cp);	/* dlen -- short */

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
			if (0 < n && n < (int)sizeof(hb)) {
			  int slen; char *s;
			  UNGCPRO1;
			  *(char*)(cp+1+n) = 0;
			  slen = strlen((const char *)(cp+1));
			  s = dupnstr((const char *)(cp+1), slen);
			  return newstring(s, slen);
			}
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
			    int slen = strlen(hb);
			    char *s = dupnstr(hb, slen);
			    *ttlp = maxttl;
			    UNGCPRO1;
			    return newstring(s, slen);
			  }
			}
			continue;
		case T_A:
		case T_SA:
		case T_AAAA:
			*ttlp = maxttl;
			if (rrtype == T_ANY) {
			  int slen = strlen(host);
			  char *s = dupnstr(host, slen);
			  UNGCPRO1;
			  return newstring(s, slen);
			} else {
			  char tb[80];
			  const char *ss;
			  int slen;

#if defined(AF_INET6) && defined(INET6)
			  if (type == T_AAAA)
			    ss = inet_ntop(AF_INET6, cp, tb, sizeof(tb));
			  else
#endif
			    ss = inet_ntop(AF_INET, cp, tb, sizeof(tb));
			  slen = strlen(ss);
			  s = dupnstr(ss, slen);
			  if (lhead == NULL)
			    lhead = l = newstring(s, slen);
			  else {
			    cdr(l) = newstring(s, slen);
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
			UNGCPRO1;
			{
			  int slen = strlen(nbuf);
			  char *s = dupnstr(nbuf, slen);
			  return newstring(s, slen);
			}

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
			  int slen = strlen(host);
			  char *s = dupnstr(host, slen);
			  UNGCPRO1;
			  return newstring(s, slen);
			}
		default:
			fprintf(stderr,"search_res: getrrtypec: non-processed RR type for host='%s' query=%d, result=%d\n",host,rrtype,type);

			break;
		}
	}
	if (lhead)
		lhead = ncons(lhead);
	UNGCPRO1;
	if (lhead)
		return lhead;
	if (ok) {
		const char *cs = first ? host : hb;
		int slen = strlen(cs);
		char *s = dupnstr(cs, slen);
		*ttlp = maxttl;
		return newstring(s, slen);
	}
	return NULL;
}
#endif	/* HAVE_RESOLVER */
