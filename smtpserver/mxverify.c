/*
 *   mx_client_verify() -- subroutine for ZMailer smtpserver
 *
 *   By Matti Aarnio <mea@nic.funet.fi> 1997-1999
 */

#include "smtpserver.h"

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

#ifndef	T_TXT
# define T_TXT 16	/* Text strings */
#endif

extern int h_errno;
extern int res_mkquery(), res_send(), dn_skipname(), dn_expand();

extern int use_ipv6;

#if	defined(BIND_VER) && (BIND_VER >= 473)
typedef u_char msgdata;
#else	/* !defined(BIND_VER) || (BIND_VER < 473) */
typedef char msgdata;
#endif	/* defined(BIND_VER) && (BIND_VER >= 473) */


static int dnsmxlookup __((const char*, int, int, int));

typedef union {
	HEADER qb1;
	char qb2[8000];
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
	int qlen, n, i, qdcount, ancount, nscount, arcount, maxpref, class;
	u_short type;
	int saw_cname = 0, had_mx_record = 0;
	/* int ttl; */
	struct addrinfo req, *ai;
#define MAXMX 128
	char *mx[MAXMX];
	int   mxtype[MAXMX];
	int mxcount;
	querybuf qbuf, answer;
	msgdata buf[8192], realname[8192];

	if (depth == 0)
	  h_errno = 0;

	if (depth > 3)
	  return -EX_NOHOST;

	if (debug) {
	  printf("000- dnsmxlookup('%s', depth=%d mxmode=%d qtype=%s)\n",
		 host, depth, mxmode,
		 ((qtype == T_TXT) ? "T_TXT" :
		  ((qtype == T_MX) ? "T_MX" : "other")));
	}

	qlen = res_mkquery(QUERY, host, C_IN, qtype, NULL, 0, NULL,
			   (void*)&qbuf, sizeof qbuf);
	if (qlen < 0) {
	  if (debug)
	    printf("000- res_mkquery failed\n");
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
	qdcount = ntohs(hp->qdcount);
	ancount = ntohs(hp->ancount);
	nscount = ntohs(hp->nscount);
	arcount = ntohs(hp->arcount);

	if (debug)
	  printf("000-  len=%d rcode=%d qdcount=%d ancount=%d nscount=%d arcount=%d TC=%d\n",
		 n, hp->rcode, qdcount, ancount, nscount, arcount, hp->tc);

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
	  case NOERROR:
	    goto perhaps_address_record;

	  case FORMERR:
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
	maxpref = 70000;
	mxcount = 0;
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
	    /* Not looked for .. */
	    cp += n;
	    continue;
	  }

	  if (type == T_MX) {
	    cp += 2; /* MX preference value */
	    n = dn_expand((msgdata *)&answer, eom, cp, (void*)buf, sizeof buf);
	    if (n < 0)
	      break;
	    cp += n;

	    if (debug)
	      printf("000  MX[%d] = '%s'\n", mxcount, buf);

	    if (mxcount < MAXMX) {
	      mx[mxcount] = strdup(buf);
	      if (!mx[mxcount]) break; /* Out of memory ?? */
	      mxtype[mxcount] = 0;
	      ++mxcount;
	    }
	    /* If too many MXes, just skip the rest.. */

	    had_mx_record = 1;
	    continue;
	  } /* ===== END OF MX DATA PROCESING ========= */

	  if (type == T_TXT) {
	    int len = (*cp++) & 0xFF; /* 0..255 chars */
	    if (txt_buf != NULL)
	      free(txt_buf);
	    txt_buf = emalloc(len+1);
	    memcpy(txt_buf, cp, len);
	    txt_buf[len] = '\0';
	    for (i = 0; i < mxcount; ++i) if (mx[i]) free(mx[i]);
	    return 1; /* OK! */
	  }

	  /* If reached here, skip the data tail */
	  /* In theory could be an abort even..  */
	  cp += n;
	} /* ===== END OF DNS ANSWER PROCESSING ======= */


	if (ancount > 0) {
	  /* Sigh, waste of time :-( */
	  for (i = 0; i < mxcount; ++i) if (mx[i]) free(mx[i]);
	  return -EX_SOFTWARE;
	}


	if (qtype == T_MX && !mxmode && had_mx_record) {
	  /* Accept if found ANYTHING! */
	  if (debug) printf("000-  ... accepted!\n");
	  for (i = 0; i < mxcount; ++i) if (mx[i]) free(mx[i]);
	  return 1;
	}


	/* Now skip the AUTHORITY SECTION data */

	while (nscount > 0 && cp < eom) {
#if	defined(BIND_VER) && (BIND_VER >= 473)
	  n = dn_skipname(cp, eom);
#else	/* !defined(BIND_VER) || (BIND_VER < 473) */
	  n = dn_skip(cp);
#endif	/* defined(BIND_VER) && (BIND_VER >= 473) */
	  if (n < 0)
	    break;
	  cp += n;
	  if (cp+10 > eom) { cp = eom; break; }
	  /* type = _getshort(cp); */
	  cp += 2;
	  /* class = _getshort(cp); */
	  cp += 2;
	  /* mx[nmx].expiry = now + _getlong(cp); */ /* TTL */
	  cp += 4; /* "long" -- but keep in mind that some machines
		      have "funny" ideas about "long" -- those 64-bit
		      ones, I mean ... */
	  n = _getshort(cp); /* dlen */
	  cp += 2;
	  cp += n; /* We simply skip this data.. */
	  if (cp <= eom)
	    --nscount;
	}

	if (debug)
	  printf("000-  nscount=%d (== 0 ?)  arcount=%d cp<eom ? (%d)\n",
		 nscount, arcount, cp < eom);

	/* Ok, can continue to pick the ADDITIONAL SECTION data */

	/* To be sure that all ADDITIONAL SECTION data is valid, we
	   look for the 'AA' bit.  If it isn't set, we don't use this
	   data, but do explicite lookups below. */

	while (hp->aa && nscount == 0 && arcount > 0 && cp < eom) {
	  n = dn_expand((msgdata *)&answer, eom, cp, (void*)buf, sizeof buf);
	  if (n < 0) { cp = eom; break; }
	  cp += n;
	  if (cp+10 > eom) { cp = eom; break; }
	  type = _getshort(cp);
	  cp += 2;
	  class = _getshort(cp);
	  cp += 2;
	  /* mx[nmx].expiry = now + _getlong(cp); */ /* TTL */
	  cp += 4; /* "long" -- but keep in mind that some machines
		      have "funny" ideas about "long" -- those 64-bit
		      ones, I mean ... */
	  n = _getshort(cp); /* dlen */
	  cp += 2;

	  if (cp + n > eom) { cp = eom; break; }

	  if (class != C_IN) {
	    cp += n; --nscount;
	    continue;
	  }

	  /* Ok, we have Type IN data in the ADDITIONAL SECTION */


	  /* A and AAAA are known here! */

	  if (type == T_A
#if defined(AF_INET6) && defined(INET6)
	      || (type == T_AAAA)
#endif
	      ) {

	    Usockaddr usa;

	    /* Pick the address data */
	    for (i = 0; i < mxcount; ++i) {
	      /* Is this known (wanted) name ?? */
	      if (strcasecmp(buf, mx[i]) == 0) {
		/* YES! */

		mxtype[i] |= (type == T_A) ? 1 : 2 ; /* bitflag: 1 or 2 */

		/* We do have a wanted name! */

		/* build addrinfo block, pick addresses */

		/* WARNING! WARNING! WARNING! WARNING! WARNING! WARNING!
		   This assumes intimate knowledge of the system
		   implementation of the  ``struct addrinfo'' !  */

		memset(&usa, 0, sizeof(usa));

		switch (type) {
#if defined(AF_INET6) && defined(INET6)
		case T_AAAA:
		  usa.v6.sin6_family = PF_INET6;
		  memcpy(&usa.v6.sin6_addr, cp, 16);
		  break;
#endif
		case T_A:
		  usa.v4.sin_family = PF_INET;
		  memcpy(&usa.v4.sin_addr, cp, 4);
		  break;
		default:
		  break;
		}

#if 1
		if (debug) {
		  struct sockaddr * sa = (struct sockaddr*) &usa;
		  if (sa->sa_family == AF_INET) {
		    inet_ntop(AF_INET, (void*) & ((struct sockaddr_in *)sa)->sin_addr, buf, sizeof(buf));
		    printf("000-  matching %s AR address IPv4:[%s]\n", mx[i], buf);
		  }
#if defined(AF_INET6) && defined(INET6)
		  else if (sa->sa_family == AF_INET6) {
		    inet_ntop(AF_INET6, (void*) & ((struct sockaddr_in6 *)sa)->sin6_addr, buf, sizeof(buf));
		    printf("000-  matching %s AR address IPv6:[%s]\n", mx[i], buf);
		  }
#endif
		  else
		    printf("000- matching unknown %s AR address family address; AF=%d\n",
			   mx[i], sa->sa_family);
		}
#endif

		i = matchmyaddress( (struct sockaddr *)&usa );
		if (i == 1) {
		  if (debug)
		    printf("000-   AR ADDRESS MATCH!\n");
		  for (i = 0; i < mxcount; ++i) if (mx[i]) free(mx[i]);
		  return 1; /* Found a match! */
		} else
		  if (debug)
		    printf("000-   AR matchmyaddress() yields: %d\n", i);

		break; /* Name matched, no need to spin more here.. */
	      } /* Matched name! */
	    } /* Name matching loop */
	  } /* type = T_A or T_AAAA */

	  cp += n;
	  --arcount;
	} /* Additional data collected! */

	/* Now scan thru all MXes, if there are cases WITHOUT A or AAAA
	   records, look them up here. */

	for (n = 0; n < mxcount; ++n) {

	  struct addrinfo *ai2;
	  int k = 0, rc;

	  memset(&req, 0, sizeof(req));

	  switch(mxtype[n]) {
	  case 0: /* no addresses seen! */
	    req.ai_family   = 0; /* Both OK (IPv4/IPv6) */
	    /* Definitely ask for it! */
	    break;
	  case 1: /* T_A only seen */
#if defined(AF_INET6) && defined(INET6)
	    if (use_ipv6)
	      req.ai_family = AF_INET6;
	    else
	      continue; /* AF_INET address already seen, skip it.. */
#else
	    continue; /* Skip it! */
#endif
	    break;
	  case 2: /* T_AAAA only seen */
	    req.ai_family = AF_INET;
	    break;
	  case 3: /* T_A and T_AAAA seen */
	  default: /* BUG! */
	    continue; /* No need for any lookup, if this is not 0..2 */
	    break;
	  }

	  req.ai_socktype = SOCK_STREAM;
	  req.ai_protocol = IPPROTO_TCP;
	  req.ai_flags    = AI_CANONNAME;
	  ai = NULL;
	  /* This resolves CNAME, it should not happen in case
	     of MX server, though..    */
#define GETADDRINFODEBUG 0
#if !GETADDRINFODEBUG
	  i = getaddrinfo(mx[n], "0", &req, &ai);
#else
	  i = _getaddrinfo_(mx[n], "0", &req, &ai,
			    debug ? stdout : NULL);
	  if (debug)
	    printf("000-  getaddrinfo('%s','0') -> r=%d, ai=%p\n",mx[n],i,ai);
#endif

	  if (debug)
	    printf("000-  getaddrinfo('%s') yields %d\n", mx[n], i);
	    
	  if (i != 0)
	    continue;		/* Well well.. spurious! */

	  if (!mxmode) /* Accept if found ANYTHING! */ {
	    if (debug) printf("000-  ... accepted!\n");
	    freeaddrinfo(ai);
	    for (i = 0; i < mxcount; ++i) if (mx[i]) free(mx[i]);

	    return 1;
	  }
	  
	    
	  for ( ai2 = ai ; ai2 != NULL; ai2 = ai2->ai_next) {
	    ++k;
#if 1
	    if (debug) {
	      struct sockaddr * sa = ai2->ai_addr;
	      char buf[60];
	      if (sa->sa_family == AF_INET) {
		inet_ntop(AF_INET, (void*) & ((struct sockaddr_in *)sa)->sin_addr, buf, sizeof(buf));
		printf("000-  matching %s address IPv4:[%s]\n", mx[n], buf);
	      }
#if defined(AF_INET6) && defined(INET6)
	      else if (sa->sa_family == AF_INET6) {
		inet_ntop(AF_INET6, (void*) & ((struct sockaddr_in6 *)sa)->sin6_addr, buf, sizeof(buf));
		printf("000-  matching %s address IPv6:[%s]\n", mx[n], buf);
	      }
#endif
	      else
		printf("000- matching %s unknown address family address; AF=%d\n",
		       mx[n], sa->sa_family);
	    }
#endif
	    rc = matchmyaddress(ai2->ai_addr);
	    if (rc == 1) {
	      if (debug)
		printf("000-   ADDRESS MATCH!\n");
	      freeaddrinfo(ai);
	      for (i = 0; i < mxcount; ++i) if (mx[i]) free(mx[i]);
	      return 1; /* Found a match! */
	    } else
	      if (debug)
		printf("000-   matchmyaddress() yields: %d\n", rc);
	  }
	  if (debug)
	    printf("000-   No address match among %d address!\n", k);

	  freeaddrinfo(ai);
	}

	for (i = 0; i < mxcount; ++i) if (mx[i]) free(mx[i]);


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
	    printf("000-   perhaps A? getaddrinfo('%s','0') -> r=%d, ai=%p\n",host,i,ai);
	  if (i != 0) /* Found nothing! */
	    return i;

	  i = matchmyaddresses(ai);
#if 1
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
     const char *domain;
{
	char hbuf[2000];
	int rc;

	if (alen >= sizeof(hbuf)-2)
	  alen = sizeof(hbuf)-2;

	strncpy(hbuf, domain, alen);
	hbuf[alen] = 0; /* Chop off the trailers from the name */

	rc = dnsmxlookup(hbuf, 0, 1, T_MX);

	if (rc == 1) return 0; /* Found! */

	if (rc == -EX_TEMPFAIL) {
	  return -104;
	}
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
     const char *domain;
{
	char hbuf[500];
	int rc;

	if (alen >= sizeof(hbuf)-2)
	  alen = sizeof(hbuf)-2;

	strncpy(hbuf, domain, alen);
	hbuf[alen] = 0; /* Chop off the trailers from the name */

	rc = dnsmxlookup(hbuf, 0, 0, T_MX);

	if (debug)
	  printf("000- dnsmxlookup() did yield: %d, retmode='%c'\n",
		 rc,retmode);

	if (rc == 1) return 0; /* Found! */

	if (rc == -EX_TEMPFAIL) {
	  return -104;
	}
	if (retmode == '+') {
	  if (rc == -EX_NOHOST      ||
	      rc == -EX_UNAVAILABLE ||
	      rc == EAI_NODATA      ||
	      rc == EAI_NONAME)
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
     const char *domain;
{
	return sender_dns_verify(retmode, domain, alen);
}

int rbl_dns_test(ipaf, ipaddr, rbldomain, msgp)
     const int ipaf;
     const u_char *ipaddr;
     char *rbldomain;
     char **msgp;
{
	char hbuf[2000], *s, *suf;
	/* int hspc; */
	struct hostent *hp;
	int has_ok = 0;

	if (ipaf == P_K_IPv4) {
	  sprintf(hbuf, "%d.%d.%d.%d.",
		  ipaddr[3], ipaddr[2], ipaddr[1], ipaddr[0]);

	} else { /* Ok, the other variant is IPv6 ... */

	  int i;
	  for (i = 15; i >= 0; --i) {
	    sprintf(hbuf + ((15-i) << 2),
		    "%x.%x.", ipaddr[i] & 0x0F, (ipaddr[i] >> 4) & 0x0F);
	  }
	  strcpy(hbuf+32,"ip6."); /* Fixed length of hex nybbles */
	}

	suf = hbuf + strlen(hbuf);
	/* hspc = sizeof(hbuf)-strlen(hbuf)-1; */

	while (*rbldomain) {
	  /* "rbldomain" is possibly a COLON-demarked set of
	     domain names:  rbl.maps.vix.com:dul.maps.vix.com
	     which isn't so easy to read, but ... */
	  s = strchr(rbldomain, ':');
	  if (s) *s = 0;
	  if (strcmp(rbldomain,"+") == 0)
	    strcpy (suf, "rbl.maps.vix.com");
	  else
	    strcpy (suf, rbldomain);

	  if (s) {
	    *s = ':';
	    rbldomain = s+1;
	  } else {
	    rbldomain += strlen(rbldomain);
	  }

	  if (debug)
	    printf("000- looking up DNS A object: %s\n", hbuf);


	  hp = gethostbyname(hbuf);
	  if (hp != NULL) {
	    /* XX: Should verify that the named object has A record: 127.0.0.2
	       D'uh.. alternate dataset has A record: 127.0.0.3 */
	    char abuf[30];

	    inet_ntop(AF_INET, (void*) hp->h_addr, abuf, sizeof(abuf));

	    type(NULL,0,NULL, "Looked up DNS A object: %s -> %s", hbuf, abuf);

	    if (strncmp("127.0.0.",abuf,8) != 0) {
	      has_ok = 1;
	      continue; /* Isn't  127.0.0.* */
	    }
	    if (strcmp("127.0.0.4",abuf) == 0) {
	      /* ORBS NETBLOCK */
	      if (has_ok) continue;
	    }

	    /* Ok, then lookup for the TXT entry too! */
	    if (debug)
	      printf("000- looking up DNS TXT object: %s\n", hbuf);

	    if (dnsmxlookup(hbuf, 0, 0, T_TXT) == 1) {
	      if (*msgp != NULL)
		free(*msgp);
	      *msgp = strdup(txt_buf);
	    }
	    return -1;
	  }
	  /* Didn't find A record */
	  type(NULL,0,NULL, "Looking up DNS A object: %s", hbuf);
	}

	return 0;
}
