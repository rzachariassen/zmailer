/*
 *   mx_client_verify() -- subroutine for ZMailer smtpserver
 *
 *   By Matti Aarnio <mea@nic.funet.fi> 1997-1999,2002-2004
 */

#include "smtpserver.h"
#include "zresolv.h"

extern int use_ipv6;

static int dnsmxlookup __((struct policystate *, const char*, int, int, int));

extern int debug;
static char * txt_buf = NULL;

struct mxset {
  int pref;
  char islocal;
  char type; /* bitset: 1 | 2 */
  char *mx;
};

/*
 * return values:
 *   state->islocaldomain
 *   ret: 0 = not found ( = reject )
 *   ret: 1 = FOUND MX MATCH ( = ACCEPT )
 *   ret: 2 = reject by MX rule
 */

static int
dnsmxlookup(state, host, depth, mxmode, qtype)
	struct policystate *state;
	const char *host;
	int depth;
	int mxmode;
	int qtype;
{
	HEADER *hp;
	msgdata *eom, *cp, *cpnext;
	int qlen, n, j, qdcount, ancount, nscount, arcount, maxpref, class;
	u_short type;
	int saw_cname = 0, had_mx_record = 0;
	int ttl;
	struct addrinfo req, *ai;
#define MAXMX 128
	struct mxset mxs[MAXMX];
	int mxcount;
	querybuf qbuf, answer;
	msgdata buf[8192], realname[8192];

	memset( mxs, 0, sizeof(mxs) );

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

	for ( ; --ancount >= 0 && cp < eom; cp = cpnext) {

	  n = dn_expand((msgdata *)&answer, eom, cp, (void*)buf, sizeof buf);
	  if (n < 0)
	    break;
	  cp += n;

	  NS_GET16(type,  cp); /* type  */
	  NS_GET16(class, cp); /* class */
	  NS_GET32(ttl,   cp); /* ttl   */
	  NS_GET16(n,     cp); /* dlen  */

	  cpnext = cp + n;

	  if (cpnext > eom) {
	    /* BAD data.. */
	    break;
	  }

	  if (type == T_CNAME) {
	    dn_expand((msgdata *)&answer, eom, cp,
		      (void*)realname, sizeof realname);
	    saw_cname = 1;
	    continue;
	  }

	  if (type != qtype)  {
	    /* Not looked for .. */
	    continue;
	  }

	  if (type == T_MX) {
	    int pref;
	    NS_GET16(pref, cp); /* MX preference value */
	    n = dn_expand((msgdata *)&answer, eom, cp, (void*)buf, sizeof buf);
	    if (n < 0)
	      break;

	    if (debug)
	      printf("000  MX[%d] = '%s'\n", mxcount, buf);

	    if (mxcount < MAXMX) {
	      mxs[mxcount].mx   = strdup((const char *)buf);
	      mxs[mxcount].pref = pref;
	      mxs[mxcount].type = 0;
	      if (!mxs[mxcount].mx) break; /* Out of memory ?? */
	      ++mxcount;
	    }
	    /* If too many MXes, just skip the rest.. */

	    had_mx_record = 1;
	    continue;
	  } /* ===== END OF MX DATA PROCESING ========= */

	  if (type == T_TXT) {
	    int i, len = (*cp) & 0xFF; /* 0..255 chars */

	    /* Mal-formed inputs are possible overflowing the buffer.. */
	    if (len > (eom - cp))
	      len = (eom - cp);
	    if (len > n - 1)
	      len = n - 1;

	    if (txt_buf != NULL)
	      free(txt_buf);
	    txt_buf = emalloc(len+1);
	    ++cp;
	    memcpy(txt_buf, cp, len);
	    txt_buf[len] = '\0';
	    for (i = 0; i < mxcount; ++i) {
	      if (mxs[i].mx) free(mxs[i].mx);
	      mxs[i].mx = NULL;
	    }
	    return 1; /* OK! */
	  }

	  /* If reached here, skip the data tail */
	  /* In theory could be an abort even..  */

	} /* ===== END OF DNS ANSWER PROCESSING ======= */


	if (ancount > 0) {
	  /* Sigh, waste of time :-( */
	  int i;
	  for (i = 0; i < mxcount; ++i) if (mxs[i].mx) free(mxs[i].mx);
	  return -EX_SOFTWARE;
	}


#if 0
	if (qtype == T_MX && !mxmode && had_mx_record) {
	  /* Accept if found ANYTHING! */
	  if (debug) printf("000-  ... accepted!\n");
	  for (i = 0; i < mxcount; ++i) if (mxs[i].mx) free(mxs[i].mx);
	  return 1;
	}
#endif

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

	  NS_GET16(type,  cp); /* type  - short */
	  NS_GET16(class, cp); /* class - short */
	  cp += NS_INT32SZ;    /* ttl   - long  */
	  NS_GET16(n, cp);     /* dlen  - short */

	  cp += n; /* We simply skip this data.. */
	  if (cp <= eom)
	    --nscount;
	}

	if (debug)
	  printf("000-  nscount=%d (== 0 ?)  arcount=%d  eom-cp=%d\n",
		 nscount, arcount, eom-cp);

	/* Ok, can continue to pick the ADDITIONAL SECTION data */

	/* To be sure that all ADDITIONAL SECTION data is valid, we
	   look for the 'AA' bit.  If it isn't set, we don't use this
	   data, but do explicite lookups below. */

	for ( ;
	      hp->aa && nscount == 0 && arcount > 0 && cp < eom;
	      cp = cpnext) {

	  n = dn_expand((msgdata *)&answer, eom, cp, (void*)buf, sizeof buf);
	  if (n < 0) { cp = eom; break; }
	  cp += n;
	  if (cp+10 > eom) { cp = eom; break; }

	  NS_GET16(type,  cp); /* type  - short */
	  NS_GET16(class, cp); /* class - short */
	  cp += NS_INT32SZ;    /* ttl   - long  */
	  NS_GET16(n, cp);     /* dlen  - short */

	  cpnext = cp + n;

	  if (cpnext > eom)    { continue; /* BAD BAD! */ }

	  if (class != C_IN) {
	    --arcount;
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
	    
	    --arcount;

	    /* Pick the address data */
	    for (n = 0; n < mxcount; ++n) {
	      /* Is this known (wanted) name ?? */
	      if (strcasecmp((const char *)buf, mxs[n].mx) == 0) {
		/* YES! */

		mxs[n].type |= (type == T_A) ? 1 : 2 ; /* bitflag: 1 or 2 */

		/* We do have a wanted name! */

		/* build addrinfo block, pick addresses */

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
		  if (usa.v4.sin_family == AF_INET) {
		    inet_ntop(AF_INET, (void*) & usa.v4.sin_addr, (char *)buf, sizeof(buf));
		    printf("000-  matching %s AR address IPv4:[%s]\n", mxs[n].mx, buf);
		  }
#if defined(AF_INET6) && defined(INET6)
		  else if (usa.v6.sin6_family == AF_INET6) {
		    inet_ntop(AF_INET6, (void*) & usa.v6.sin6_addr, (char*)buf, sizeof(buf));
		    printf("000-  matching %s AR address IPv6:[%s]\n", mxs[n].mx, buf);
		  }
#endif
		  else
		    printf("000- matching unknown %s AR address family address; AF=%d\n",
			   mxs[n].mx, usa.v4.sin_family);
		}
#endif

		j = matchmyaddress( &usa );
		if (j == 1) {
		  if (debug)
		    printf("000-   AR ADDRESS MATCH!\n");
		  mxs[n].islocal = 1;
		  /* Found a match! */
		  goto ponder_mx_result;
		} else if (j == 2) {
		  if (debug)
		    printf("000-   AR ADDRESS LOOPBACK MATCH!\n");
		  mxs[n].islocal = 2;
		  /* Found a match! */
		  goto ponder_mx_result;
		} else
		  if (debug)
		    printf("000-   AR matchmyaddress() yields: %d\n", j);

		break; /* Name matched, no need to spin more here.. */
	      } /* Matched name! */
	    } /* Name matching loop */
	    continue;
	  } /* type = T_A or T_AAAA */

	  /* All other cases.. */
	  --arcount;
	} /* Additional data collected! */

	/* Now scan thru all MXes, if there are cases WITHOUT A or AAAA
	   records, look them up here. */

	for (n = 0; n < mxcount; ++n) {

	  struct addrinfo *ai2;
	  int k = 0, rc;

	  memset(&req, 0, sizeof(req));

	  switch(mxs[n].type) {
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
	  /*  ai_family  set above. */
	  ai = NULL;
	  /* This resolves CNAME, it should not happen in case
	     of MX server, though..    */
#ifdef HAVE__GETADDRINFO_
	  rc = _getaddrinfo_(mxs[n].mx, "0", &req, &ai,
			    debug ? stdout : NULL);
#else
	  rc = getaddrinfo(mxs[n].mx, "0", &req, &ai);
#endif
	  if (debug)
	    printf("000-  getaddrinfo('%s','0') -> r=%d, ai=%p\n",
		   mxs[n].mx,rc,(void*)ai);
	    
	  if (rc != 0)
	    continue;		/* Well well.. spurious! */

	  for ( ai2 = ai ; ai2 != NULL; ai2 = ai2->ai_next) {
	    ++k;
#if 1
	    if (debug) {
	      Usockaddr * usa = (Usockaddr *) ai2->ai_addr;
	      char buf[60];

	      if (usa->v4.sin_family == AF_INET) {
		inet_ntop(AF_INET, (void*) & usa->v4.sin_addr, buf, sizeof(buf));
		printf("000-  matching %s address IPv4:[%s]\n",
		       mxs[n].mx, buf);
	      }
#if defined(AF_INET6) && defined(INET6)
	      else if (usa->v6.sin6_family == AF_INET6) {
		inet_ntop(AF_INET6, (void*) & usa->v6.sin6_addr, buf, sizeof(buf));
		printf("000-  matching %s address IPv6:[%s]\n",
		       mxs[n].mx, buf);
	      }
#endif
	      else
		printf("000- matching %s unknown address family address; AF=%d\n",
		       mxs[n].mx, usa->v4.sin_family);
	    }
#endif
	    rc = matchmyaddress((Usockaddr *)ai2->ai_addr);
	    if (rc == 1) {
	      if (debug)
		printf("000-   ADDRESS MATCH!\n");
	      freeaddrinfo(ai);
	      mxs[n].islocal = 1;
	      /* Found a match! */
	      goto ponder_mx_result;
	    } else if (rc == 2) {
	      if (debug)
		printf("000-   LOOPBACK ADDRESS MATCH!\n");
	      freeaddrinfo(ai);
	      mxs[n].islocal = 2;
	      /* Found a match! */
	      goto ponder_mx_result;
	    } else
	      if (debug)
		printf("000-   matchmyaddress() yields: %d\n", rc);
	  }
	  if (debug)
	    printf("000-   No address match among %d address!\n", k);

	  freeaddrinfo(ai);

	  if (!mxmode) /* Accept if found ANYTHING! */ {
	    int i;

	    if (debug) printf("000-  ... accepted!\n");
	    for (i = 0; i < mxcount; ++i)
	      if (mxs[i].mx)
		free(mxs[i].mx);

	    return 1;
	  }
	} /* Thru all MXS[] ... */


	/* No MX match found.. */
	for (n = 0; n < mxcount; ++n) {
	  if (mxs[n].mx)
	    free(mxs[n].mx);
	  mxs[n].mx = NULL;
	}

	if (debug)
	  printf("000-   saw_cname=%d  had_mx_record=%d  mxmode=%d\n",
		 saw_cname, had_mx_record, mxmode);

	/* Didn't find any, but saw CNAME ? Recurse with the real name */
	if (saw_cname)
	  return dnsmxlookup(state, (void *)realname, depth+1, mxmode, qtype);

	if (had_mx_record && mxmode)
	    return 2; /* We have SOME date, but no match on ourselves! */

	if (!mxmode)
	  return 1; /* Accept anything! */

	return 0; /* No match, but had MXes.. */

perhaps_address_record:
	if (qtype == T_MX) {
	  int i;

	  /* No MX, perhaps A ? */
	  memset(&req, 0, sizeof(req));
	  req.ai_socktype = SOCK_STREAM;
	  req.ai_protocol = IPPROTO_TCP;
	  req.ai_flags    = AI_CANONNAME;
	  req.ai_family   = PF_INET;
	  ai = NULL;

	  /* This resolves CNAME, it should not happen in case
	     of MX server, though..    */
#ifdef HAVE__GETADDRINFO_
	  if (debug)
	    printf("000-  perhaps A?\n");
	  i = _getaddrinfo_((const char*)host, "0", &req, &ai, debug ? stdout : NULL);
#else
	  i = getaddrinfo((const char*)host, "0", &req, &ai);
#endif
	  if (debug)
	    printf("000-   getaddrinfo('%s','0') (PF_INET) -> r=%d (%s), ai=%p\n",host,i,gai_strerror(i),(void*)ai);

#if defined(AF_INET6) && defined(INET6)
	  if (use_ipv6) {

	    /* Want, but not have AAAA, ask for it. */

	    int n2;
	    struct addrinfo *ai2 = NULL;

	    memset(&req, 0, sizeof(req));
	    req.ai_socktype = SOCK_STREAM;
	    req.ai_protocol = IPPROTO_TCP;
	    req.ai_flags    = AI_CANONNAME;
	    req.ai_family   = PF_INET6;

	  /* This resolves CNAME, it should not happen in case
	     of MX server, though..    */
#ifdef HAVE__GETADDRINFO_
	    n2 = _getaddrinfo_((const char *)host, "0", &req, &ai2,
			       debug ? stdout : NULL);
#else
	    n2 = getaddrinfo((const char *)host, "0", &req, &ai2);
#endif
	    if (debug)
	      printf("000-   getaddrinfo('%s','0') (PF_INET6) -> r=%d (%s), ai=%p\n",host,n2,gai_strerror(n2),(void*)ai2);


	    if (i != 0 && n2 == 0) {
	      /* IPv6 address, no IPv4 (or error..) */
	      i = n2;
	      ai = ai2; ai2 = NULL;
	    }
	    if (ai2 && ai) {
	      /* BOTH ?!  Catenate them! */
	      struct addrinfo **aip;
	      aip = &ai->ai_next;
	      while (*aip) aip = &((*aip)->ai_next);
	      *aip = ai2;
	    }
	  }
#endif

	  if (i)
	    return 0; /* Bad lookup result -> no match */

	  i = matchmyaddresses(ai);

	  freeaddrinfo(ai);

	  if (i > 0)
	    state->islocaldomain = 1;
#if 1
	  /* With this we can refuse to accept any message with
	     source domain pointing back to loopback ! */
	  if (i == 2) {
	    /* Loopback ! */
	    state->islocaldomain = 2;
	    return 2;
	  }
#endif
	  if (i == 0 && mxmode) {
	    return 2; /* Didn't find our local address in client-MX-mode */
	  }

	  return 1; /* Found any address, or in client-MX-mode,
		       a local address! */
	}

	if (mxmode)
	  return 2; /* Not found, had no MX data either */
	
	return 0; /* Not found! */

 ponder_mx_result:;
	/* Ok, we have some MX match, lets see closer..
	   If we have...
	   - TODO: What shall we do with MX server sets ?
	   - Can we set  state->islocaldomain   ??
	*/
#if 0
	{
	  int lowpref = 100000;

	  for (n = 0; n < mxcount; ++n) {
	    if ((mxs[n].pref < lowpref) && mxs[n].islocal)
	      lowpref = mxs[n].pref;
	  }

	  for (n = 0; n < mxcount; ++n) {
	    if (mxs[n].pref < lowpref)
	      return 0;
	  }

	}
#endif

	for (n = 0; n < mxcount; ++n) {
	  if (mxs[n].mx)
	    free(mxs[n].mx);
	}

	/* Report as successfull match, didn't set  'state->islocaldomain' */
	return 1;
}


/* For SOFT errors, return -102, for hard errors, -2.
   For 'we are MX', return 0.
   For (retmode == '+'), and without MX, return 1.
 */

int mx_client_verify(state, retmode, domain, alen)
     struct policystate *state;
     int retmode, alen;
     const char *domain;
{
	char hbuf[2000];
	int rc;

	if (alen >= sizeof(hbuf)-2)
	  alen = sizeof(hbuf)-2;

	strncpy(hbuf, domain, alen);
	hbuf[alen] = 0; /* Chop off the trailers from the name */

	rc = dnsmxlookup(state, hbuf, 0, 1, T_MX);

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

int sender_dns_verify(state, retmode, domain, alen)
     struct policystate *state;
     int retmode, alen;
     const char *domain;
{
	char hbuf[500];
	int rc;

	if (alen >= sizeof(hbuf)-2)
	  alen = sizeof(hbuf)-2;

	strncpy(hbuf, domain, alen);
	hbuf[alen] = 0; /* Chop off the trailers from the name */

	rc = dnsmxlookup(state, hbuf, 0, 0, T_MX);

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
#ifdef EAI_NODATA
	      rc == EAI_NODATA      ||
#endif
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

int client_dns_verify(state, retmode, domain, alen)
     struct policystate *state;
     int retmode, alen;
     const char *domain;
{
	return sender_dns_verify(state,retmode, domain, alen);
}

int rbl_dns_test(state, ipaf, ipaddr, rbldomain, msgp)
     struct policystate *state;
     const int ipaf;
     const u_char *ipaddr;
     char *rbldomain;
     char **msgp;
{
	char hbuf[2000], *s, *suf;
	int hspc;
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
	  strcpy(hbuf+64,"ip6."); /* Fixed length of hex nybbles */
	}

	suf = hbuf + strlen(hbuf);
	hspc = sizeof(hbuf) - strlen(hbuf) - 2;

	while (*rbldomain) {
	  /* "rbldomain" is possibly a COLON-demarked set of
	     domain names:  rbl.maps.vix.com:dul.maps.vix.com
	     which isn't so easy to read, but ... */
	  /* The 2000 char buffer should be way oversized
	     for this routine's needs..  And it is managerial
	     input at the policy database, which has the "unpredictable"
	     size...  */
	  s = strchr(rbldomain, ':');
	  if (s) *s = 0;
#if 0 /* Remove the old hard-coded "+" macro ... */
	  if (strcmp(rbldomain,"+") == 0)
	    strncpy (suf, "rbl.maps.vix.com", hspc);
	  else
#endif
	    strncpy (suf, rbldomain, hspc);
	  suf[hspc] = '\0';

	  if (s) {
	    *s = ':';
	    rbldomain = s+1;
	  } else {
	    rbldomain += strlen(rbldomain);
	  }

	  /* Add explicite DOT into the tail of the lookup object.
	     That way the lookup should never use resolver's  SEARCH
	     suffix set. */

	  s = suf + strlen(suf) - 1;
	  if (*s != '.') {
	    *(++s) = '.';
	    *(++s) = 0;
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
#if 0
	    if (strcmp("127.0.0.4",abuf) == 0) {
	      /* ORBS NETBLOCK */
	      if (has_ok) continue;
	    }
#endif
	    /* Ok, then lookup for the TXT entry too! */
	    if (debug)
	      printf("000- looking up DNS TXT object: %s\n", hbuf);

	    if (dnsmxlookup(state, hbuf, 0, 0, T_TXT) == 1) {
	      if (*msgp != NULL)
		free(*msgp);
	      *msgp = strdup(txt_buf);
	      s = *msgp;
	      if (s) {
		for ( ;*s; ++s) {
		  int c = ((*s) & 0xFF);
		  /* Characters not printable in ISO-8859-*
		     are masked with space. */
		  if (c < ' ' || (c >= 127 && c < 128+32) || c == 255)
		    *s = ' ';
		}
	      }
	      type(NULL,0,NULL,"Found DNS TXT object: %s\n",
		   (*msgp ? *msgp : "<nil>"));
	    }
	    return -1;
	  }
	  /* Didn't find A record */
	  type(NULL,0,NULL, "Didn't find DNS A object: %s", hbuf);
	}

	return 0;
}
