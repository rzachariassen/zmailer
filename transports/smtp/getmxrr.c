/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *	Copyright 1991-2000 by Matti Aarnio -- modifications, including MIME
 */

#include "smtp.h"

typedef union {
	HEADER qb1;
	char qb2[8000];
} querybuf;

int
getmxrr(SS, host, mx, maxmx, depth)
	SmtpState *SS;
	const char *host;
	struct mxdata mx[];
	int maxmx, depth;
{
	HEADER *hp;
	msgdata *eom, *cp;
	struct mxdata mxtemp;
	int qlen, n, i, j, nmx, qdcount, ancount, nscount, arcount, maxpref;
	int class;
	u_short type;
	int saw_cname = 0;
	int ttl;
	int had_eai_again = 0;
	struct addrinfo req, *ai, *ai2, **aip;
	querybuf qbuf, answer;
	msgdata buf[8192], realname[8192];
	char mxtype[MAXFORWARDERS];

	h_errno = 0;

	notary_setwtt  (NULL);
	notary_setwttip(NULL);

	if (depth == 0)
	  SS->mxcount = 0;

	if (depth > 3) {
	  sprintf(SS->remotemsg,"smtp; 500 (DNS: Recursive CNAME on '%.200s')",host);
	  time(&endtime);
	  notary_setxdelay((int)(endtime-starttime));
	  notaryreport(NULL,FAILED,"5.4.3 (Recursive DNS CNAME)",SS->remotemsg);
	  fprintf(stderr, "%s\n", SS->remotemsg);
	  return EX_NOHOST;
	}


	qlen = res_mkquery(QUERY, host, C_IN, T_MX, NULL, 0, NULL,
			   (void*)&qbuf, sizeof qbuf);
	if (qlen < 0) {
	  fprintf(stderr, "res_mkquery failed\n");
	  sprintf(SS->remotemsg,
		  "smtp; 466 (Internal: res_mkquery failed on host: %.200s)",host);
	  if (SS->verboselog)
	    fprintf(SS->verboselog,"  %s\n", SS->remotemsg);

	  time(&endtime);
	  notary_setxdelay((int)(endtime-starttime));
	  notaryreport(NULL,FAILED,"5.4.3 (DNS-failure)",SS->remotemsg);
	  return EX_SOFTWARE;
	}
	n = res_send((void*)&qbuf, qlen, (void*)&answer, sizeof answer);
	if (n < 0) {
	  sprintf(SS->remotemsg,
		  "smtp; 466 (No DNS response for host: %.200s; h_errno=%d)",
		  host, h_errno);
	  if (SS->verboselog)
	    fprintf(SS->verboselog,"  %s\n", SS->remotemsg);

	  time(&endtime);
	  notary_setxdelay((int)(endtime-starttime));
	  notaryreport(NULL,FAILED,"5.4.3 (DNS-failure)",SS->remotemsg);
	  return EX_TEMPFAIL;
	}

	time(&now);

	eom = (msgdata *)&answer + n;
	/*
	 * find first satisfactory answer
	 */
	hp = (HEADER *) &answer;
	qdcount = ntohs(hp->qdcount);
	ancount = ntohs(hp->ancount);
	nscount = ntohs(hp->nscount);
	arcount = ntohs(hp->arcount);

	if (SS->verboselog)
	  fprintf(SS->verboselog, "DNS lookup reply: len=%d rcode=%d qdcount=%d ancount=%d nscount=%d arcount=%d RD=%d TC=%d AA=%d QR=%d RA=%d\n",
		  n, hp->rcode, qdcount, ancount, nscount, arcount,
		  hp->rd, hp->tc, hp->aa, hp->qr, hp->ra);

	if (hp->rcode != NOERROR || ancount == 0) {
	  switch (hp->rcode) {
	  case NXDOMAIN:
	    /* Non-authoritative iff response from cache.
	     * Old BINDs used to return non-auth NXDOMAINs
	     * due to a bug; if that is the case by you,
	     * change to return EX_TEMPFAIL iff hp->aa == 0.
	     */
	    sprintf(SS->remotemsg, "smtp; 500 (DNS: no such domain: %.200s)", host);
	    if (SS->verboselog)
	      fprintf(SS->verboselog," NXDOMAIN %s\n", SS->remotemsg);
	    endtime = now;
	    notary_setxdelay((int)(endtime-starttime));
	    notaryreport(NULL,FAILED,"5.4.4 (DNS lookup report)",SS->remotemsg);
	    return EX_NOHOST;
	  case SERVFAIL:
	    sprintf(SS->remotemsg, "smtp; 500 (DNS: server failure: %.200s)", host);
	    if (SS->verboselog)
	      fprintf(SS->verboselog," SERVFAIL %s\n", SS->remotemsg);
	    endtime = now;
	    notary_setxdelay((int)(endtime-starttime));
	    notaryreport(NULL,FAILED,"5.4.4 (DNS lookup report)",SS->remotemsg);
	    return EX_TEMPFAIL;
	  case NOERROR:
	    mx[0].host = NULL;
	    return EX_OK;
	  case FORMERR:
	  case NOTIMP:
	  case REFUSED:
	    sprintf(SS->remotemsg, "smtp; 500 (DNS: unsupported query: %.200s)", host);
	    if (SS->verboselog)
	      fprintf(SS->verboselog," FORMERR/NOTIMP/REFUSED(%d) %s\n",
		      hp->rcode, SS->remotemsg);
	    endtime = now;
	    notary_setxdelay((int)(endtime-starttime));
	    notaryreport(NULL,FAILED,"5.4.4 (DNS lookup report)",SS->remotemsg);
	    return EX_NOPERM;
	  }
	  sprintf(SS->remotemsg, "smtp; 500 (DNS: unknown error, MX info unavailable: %.200s)", host);
	  if (SS->verboselog)
	    fprintf(SS->verboselog,"  %s\n", SS->remotemsg);
	  endtime = now;
	  notary_setxdelay((int)(endtime-starttime));
	  notaryreport(NULL,FAILED,"5.4.4 (DNS lookup report)",SS->remotemsg);

	  if (had_eai_again)
	    return EX_TEMPFAIL;
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
	maxpref = 66000;
	while (ancount > 0 && cp < eom && nmx < maxmx-1) {
	  n = dn_expand((msgdata *)&answer, eom, cp, (void*)buf, sizeof buf);
	  if (n < 0)
	    break;
	  cp += n;
	  if (cp+10 > eom) { cp = eom; break; }
	  type = _getshort(cp);
	  cp += 2;
	  class = _getshort(cp);
	  cp += 2;
	  mx[nmx].expiry = now + _getlong(cp); /* TTL */
	  cp += 4; /* "long" -- but keep in mind that some machines
		      have "funny" ideas about "long" -- those 64-bit
		      ones, I mean ... */
	  n = _getshort(cp); /* dlen */
	  cp += 2;
	  if (cp + n > eom) { cp = eom; break; }

	  if (class != C_IN) {
	    cp += n;
	    if (cp > eom) break;
	    --ancount;
	    continue;
	  }
	  if (type == T_CNAME) {
	    cp += dn_expand((msgdata *)&answer, eom, cp,
			    (void*)realname, sizeof realname);
	    if (cp > eom) break;
	    saw_cname = 1;
	    --ancount;
	    if (SS->verboselog)
	      fprintf(SS->verboselog, " -> CNAME: '%s'\n", realname);
	    continue;
	  } else if (type != T_MX)  {
	    cp += n;
	    if (cp > eom) break;
	    --ancount;
	    continue;
	  }
	  if (cp + n /* dlen */ >= eom) { cp = eom; break; }
	  mx[nmx].pref = _getshort(cp);
	  cp += 2; /* MX preference value */
	  n = dn_expand((msgdata *)&answer, eom, cp, (void*)buf, sizeof buf);
	  if (n < 0) break;
	  cp += n;
	  if (cp >= eom) break;

	  mx[nmx].ai   = NULL;
	  mx[nmx].host = (msgdata *)strdup((void*)buf);
	  if (mx[nmx].host == NULL) {
	    fprintf(stderr, "Out of virtual memory!\n");
	    exit(EX_OSERR);
	  }
	  if (SS->verboselog)
	    fprintf(SS->verboselog, " -> MX[%d] pref=%d host=%s\n",
		    nmx, mx[nmx].pref, buf);
	  mxtype[nmx] = 0;
	  ++nmx;
	  --ancount;
	} /* Gone thru all answers */

	if (nmx >= maxmx-1 && ancount > 0) {

	  /* If the MAXFORWARDERS count has been exceeded
	     (quite a feat!)  skip over the rest of the
	     answers, as long as we have them, and the
	     reply-buffer has not been exhausted...

	     These are in fact extremely pathological cases of
	     the DNS datasets, and most MTA systems will simply
	     barf at this scale of things far before ZMailer... */

	  if (SS->verboselog)
	    fprintf(SS->verboselog, "  collected MX count matches maximum supported (%d) with still some (%d) answers left to pick, we discard them.\n",
		    maxmx, ancount);

	  while (ancount > 0 && cp < eom) {
#if	defined(BIND_VER) && (BIND_VER >= 473)
	    n = dn_skipname(cp, eom);
#else	/* !defined(BIND_VER) || (BIND_VER < 473) */
	    n = dn_skip(cp);
#endif	/* defined(BIND_VER) && (BIND_VER >= 473) */
	    if (n < 0)
	      break;
	    cp += n;
	    if (cp+10 > eom) { cp = eom; break; }
	    cp += 2;
	    cp += 2;
	    cp += 4; /* "long" -- but keep in mind that some machines
			have "funny" ideas about "long" -- those 64-bit
			ones, I mean ... */
	    n = _getshort(cp); /* dlen */
	    cp += 2;
	    cp += n;
	    --ancount;
	  } /* Skipped thru all remaining answers */
	}

	if (ancount > 0) {
	  /* URGH!!!!   Still answers left over, WHAT ?!?!?! */
	  for (i = 0; i < nmx; ++i) {
	    if (mx[i].host) free(mx[i].host);
	    mx[i].host = NULL;
	  }
	  if (hp->tc) {
	    /* Yes, it is TRUNCATED reply!   Must retry with e.g.
	       by using TCP! */
	    /* FIXME: FIXME! FIXME! Truncated reply handling! */
	  }

	  if (SS->verboselog)
	    fprintf(SS->verboselog,"  left-over ANCOUNT=%d != 0! TC=%d\n",
		    ancount, hp->tc);

	  return EX_TEMPFAIL; /* FIXME?? FIXME?? */
	}

	if (nmx == 0 && realname[0] != 0) {
	  /* do it recursively for the real name */
	  n = getmxrr(SS, (char *)realname, mx, maxmx, depth+1);
	  if (had_eai_again)
	    return EX_TEMPFAIL;
	  return n;
	} else if (nmx == 0) {
	  /* "give it the benefit of doubt" */
	  mx[0].host = NULL;
	  mx[0].ai   = NULL;
	  SS->mxcount = 0;
	  if (had_eai_again)
	    return EX_TEMPFAIL;
	  return EX_OK;
	}

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

	/* If nscount isn't zero here, then (cp >= eom) is true ... */

	/* Ok, can continue to pick the ADDITIONAL SECTION data */
	/* BUT ONLY IF THE REPLY HAD 'AA' BIT SET! If it didn't,
	   we must always ask A/AAAA separately.. */
	while (hp->aa && arcount > 0 && cp < eom) {
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
	      || (type == T_AAAA && use_ipv6)
#endif
	      ) {

	    struct addrinfo *ai;
	    Usockaddr *usa;
	    char *canon;
	    int   nlen = strlen(buf);

	    /* Pick the address data */
	    for (i = 0; i < nmx; ++i) {
	      /* Is this known (wanted) name ?? */
	      if (CISTREQ(buf, mx[i].host)) {
		/* YES! */

		/* We do have a wanted name! */

		/* build addrinfo block, pick addresses */

		/* WARNING! WARNING! WARNING! WARNING! WARNING! WARNING!
		   This assumes intimate knowledge of the system
		   implementation of the  ``struct addrinfo'' !  */

		ai = (void*)malloc(sizeof(*ai) + sizeof(*usa) + nlen + 1);
		if (ai == NULL) exit(EX_OSERR);
		memset(ai, 0, sizeof(*ai) + sizeof(*usa) + nlen + 1);

		usa   = (void*)((char *) ai + sizeof(*ai));

		canon = ((char *)usa) + sizeof(*usa);
		memcpy(canon, buf, nlen);

		ai->ai_flags    = 0;
		ai->ai_socktype = SOCK_STREAM;
		ai->ai_protocol = IPPROTO_TCP;
		ai->ai_addr     = (struct sockaddr *)usa;
		ai->ai_addrlen  = sizeof(*usa);
		ai->ai_canonname = canon;

		ai->ai_next     = mx[i].ai;
		mx[i].ai        = ai;

		mxtype[i] |= (type == T_A) ? 1 : 2;

		switch (type) {
#if defined(AF_INET6) && defined(INET6)
		case T_AAAA:
		  ai->ai_family = PF_INET6;
		  usa->v6.sin6_family = PF_INET6;
		  memcpy(&usa->v6.sin6_addr, cp, 16);
		  break;
#endif
		case T_A:
		  ai->ai_family = PF_INET;
		  usa->v4.sin_family = PF_INET;
		  memcpy(&usa->v4.sin_addr, cp, 4);
		  break;
		default:
		  break;
		}
	      } /* Matched name! */
	    } /* Name matching loop */
	  } /* type = T_A or T_AAAA */

	  cp += n;
	  --arcount;
	} /* Additional data collected! */

	if (SS->verboselog)
	  for (i = 0; i < nmx; ++i) {
	    if (mx[i].ai == NULL)
	      fprintf(SS->verboselog, " MX lookup lacked ADDITIONAL SECTION Address for entry: MX %d %s\n",
		      mx[i].pref, mx[i].host);
	  }

	/* Collect addresses for all those who don't have them from
	   the ADDITIONAL SECTION data */

	for (i = 0; i < nmx; ++i) {

	  if (SS->verboselog)
	    fprintf(SS->verboselog, "  mx[%d] mxtype=%s%s(%d) host='%s'\n",
		    i, (mxtype[i]&1)?"4":"-", (mxtype[i]&2)?"6":"-",
		    mxtype[i], mx[i].host);

#if defined(AF_INET6) && defined(INET6)
	  /* If not IPv6 speaker, and already have A, skip it. */
	  if (!use_ipv6 && (mxtype[i] & 1))
	    continue;

	  if (mxtype[i] == 3)
	    continue; /* Have both A and AAAA */
#endif
	  
	  memset(&req, 0, sizeof(req));
	  req.ai_socktype = SOCK_STREAM;
	  req.ai_protocol = IPPROTO_TCP;
	  req.ai_flags    = AI_CANONNAME;
	  req.ai_family   = PF_INET;
	  ai = NULL;
	  n = 0;

	  if (! (mxtype[i] & 1)) {  /* Not have A */

	    /* This resolves CNAME, it should not happen in case
	       of MX server, though..    */
#if !GETADDRINFODEBUG
	    n = getaddrinfo(mx[i].host, "0", &req, &ai);
#else
	    n = _getaddrinfo_(mx[i].host, "0", &req, &ai, SS->verboselog);
#endif
	    if (SS->verboselog)
	      fprintf(SS->verboselog,"  getaddrinfo('%s','0') (PF_INET) -> r=%d (%s), ai=%p\n",
		      mx[i].host, n, gai_strerror(n), ai);
	  }

#if defined(AF_INET6) && defined(INET6)
	  if (use_ipv6 && !(mxtype[i] & 2) ) {

	    /* Want, but not have AAAA, ask for it. */

	    struct addrinfo *a;
	    int n2;
	    ai2 = NULL;

	    memset(&req, 0, sizeof(req));
	    req.ai_socktype = SOCK_STREAM;
	    req.ai_protocol = IPPROTO_TCP;
	    req.ai_flags    = AI_CANONNAME;
	    req.ai_family   = PF_INET6;

	  /* This resolves CNAME, it should not happen in case
	     of MX server, though..    */
#if !GETADDRINFODEBUG
	    n2 = getaddrinfo(mx[i].host, "0", &req, &ai2);
#else
	    n2 = _getaddrinfo_(mx[i].host, "0", &req, &ai2,
			       SS->verboselog);
#endif
	    if (SS->verboselog)
	      fprintf(SS->verboselog,"  getaddrinfo('%s','0') (PF_INET6) -> r=%d (%s), ai=%p\n",
		      mx[i].host, n2, gai_strerror(n2), ai2);

	    if (n != 0 && n2 == 0) {
	      /* IPv6 address, no IPv4 (or error..) */
	      n = n2;
	      ai = ai2; ai2 = NULL;
	    }
	    if (ai2 && ai) {
	      /* BOTH ?!  Catenate them! */
	      aip = &ai->ai_next;
	      while (*aip) aip = &((*aip)->ai_next);
	      *aip = ai2;
	    }
	  }
#endif

	  /* Catenate new stuff into the tail of the old ... */
	  aip = &(mx[i].ai);
	  while (*aip) aip = &((*aip)->ai_next);
	  *aip = ai;

	  if (n != 0) {
	    if (n == EAI_AGAIN) {
	      sprintf(SS->remotemsg, "smtp; 500 (DNS: getaddrinfo<%.200s> got EAI_AGAIN)", buf);
	      endtime = now;
	      notary_setxdelay((int)(endtime-starttime));
	      notaryreport(NULL,FAILED,"5.4.4 (DNS lookup report)",SS->remotemsg);

	      had_eai_again = 1;
	    }
	  }
	} /* ... i < nmx ... */


	/* Separate all addresses into their own MXes */

	for (i = 0; i < nmx && nmx < maxmx-1; ++i) {
	  struct addrinfo *ai = mx[i].ai;
	  if (ai) ai = ai->ai_next; /* If more than one.. */
	  while (ai && nmx < maxmx-1) {
	    memcpy(&mx[nmx], &mx[i], sizeof(mx[0]));
	    mx[nmx].ai = ai;
	    ai         = ai->ai_next;
	    mx[nmx].ai->ai_next = NULL;
	    mx[nmx].host = (msgdata *)strdup(mx[i].host);
	    if (mx[nmx].host == NULL) {
	      fprintf(stderr, "Out of virtual memory!\n");
	      exit(EX_OSERR);
	    }
	    ++nmx;
	  }

	  /* If there was something, it has been split out..
	     Hmm.. except if nmx >= maxmx-1, which is pathological
	     anyway...  100+ addressed server entities.. */

	  if (mx[i].ai) mx[i].ai->ai_next = NULL;
	}

	for (i = 0; i < nmx; ++i) {
	  if (mx[i].ai == NULL && mx[i].host != NULL) {
	    free(mx[i].host);
	    mx[i].host = NULL;
	    continue;
	  }
	  if (CISTREQ(mx[i].ai->ai_canonname, myhostname) ||
	      matchmyaddresses(mx[i].ai) == 1) {

	    if (SS->verboselog)
	      fprintf(SS->verboselog,"  matchmyaddresses(): matched!  canon='%s', myname='%s'\n", ai->ai_canonname, myhostname);
	    if (maxpref > (int)mx[nmx].pref)
	      maxpref = mx[nmx].pref;
	  }
	} /* ... i < nmx ... */

	SS->mxcount = nmx;

	if (SS->verboselog)
	  fprintf(SS->verboselog,"  getmxrr('%s') -> nmx=%d, maxpref=%d, realname='%s'\n", host, nmx, maxpref, realname);

	/* discard MX RRs with a value >= that of  myhost */
	for (n = i = 0; n < nmx; ++n) {
	  if ((int)mx[n].pref >= maxpref && mx[n].host) {
	    free(mx[n].host);
	    freeaddrinfo(mx[n].ai);
	    mx[n].host = NULL;
	    mx[n].ai   = NULL;
	    ++i; /* discard count */
	  }
	}
	if (i == nmx) {	/* All discarded, we are the best MX :-( */
	  mx[0].host = NULL;
	  SS->mxcount = 0;
	  if (had_eai_again)
	    return EX_TEMPFAIL;
	  return EX_OK;
	}
#ifdef	RFC974
	/* discard MX's that do not support SMTP service */
	if (checkwks)
	  for (n = 0; n < nmx; ++n) {
	    if (mx[n].host == NULL)
	      continue;
	    strncpy((char*)buf, (char*)mx[n].host, sizeof(buf));
	    buf[sizeof(buf)-1] = 0;
	    /* It is an MX, it CAN'T have CNAME ! */
	    if (!getrrtype((void*)buf, &ttl, sizeof buf, T_WKS,
			   0, SS->verboselog)) {
	      free(mx[n].host);
	      mx[n].host = NULL;
	      freeaddrinfo(mx[n].ai);
	      mx[n].ai   = NULL;
	    }
	  }
#endif	/* RFC974 */
	/* determine how many are left */
	for (i = 0, n = 0; i < nmx; ++i) {
	  if (mx[i].host == NULL)
	    continue;
	  if (n < i) {
	    memcpy(&mx[n], &mx[i], sizeof(mx[0]));
	    memset(&mx[i], 0, sizeof(mx[0]));
	  }
	  ++n;			/* found one! */
	}
	if (n == 0) {/* MX's exist, but their WKS's show no TCP smtp service */
	  sprintf(SS->remotemsg,
		  "smtp; 500 (DNS: MX host does not support SMTP: %.200s)", host);
	  time(&endtime);
	  notary_setxdelay((int)(endtime-starttime));
	  notaryreport(NULL,FAILED,"5.4.4 (DNS lookup report)",SS->remotemsg);
	  if (had_eai_again)
	    return EX_TEMPFAIL;
	  return EX_UNAVAILABLE;
	}
	nmx = n;
	SS->mxcount = nmx;

	/* sort the records per preferrence value */
	for (i = 0; i < nmx; i++) {
	  for (j = i + 1; j < nmx; j++) {
	    if (mx[i].pref > mx[j].pref) {
	      memcpy(&mxtemp, &mx[i],  sizeof(mxtemp));
	      memcpy(&mx[i],  &mx[j],  sizeof(mxtemp));
	      memcpy(&mx[j],  &mxtemp, sizeof(mxtemp));
	    }
	  }
	}

	/* Randomize the order of those of same preferrence.
	   This will do some sort of load-balancing on large sites
	   which have multiple mail-servers at the same priority.  */
	for (i = 0, maxpref = mx[0].pref; i < nmx; ++i) {
	  /* They are in numerical order, now we can
	     detect when a new preferrence group steps in */
	  j = i;
	  while (j < nmx && maxpref == mx[j].pref) ++j;
	  if ((j-i) > 1) {
	    /* At least two of the same preferrence */
	    int k, len = j-i;
	    for (k = 0; k < len; ++k) {
	      int l = ranny(len-1);
	      memcpy(&mxtemp,  &mx[i+k], sizeof(mxtemp));
	      memcpy(&mx[i+k], &mx[i+l], sizeof(mxtemp));
	      memcpy(&mx[i+l], &mxtemp,  sizeof(mxtemp));
	    }
#if defined(AF_INET6) && defined(INET6)
	    if (prefer_ip6) {
	      int l; /* Bring IPv6 addresses before IPv4 ones */
	      for (l = 0, k = 1; k < len; ++k) {
		if (mx[l].ai->ai_family == PF_INET &&
		    mx[k].ai->ai_family == PF_INET6) {
		  memcpy(&mxtemp,  &mx[k],  sizeof(mxtemp));
		  memcpy(&mx[k],   &mx[l],  sizeof(mxtemp));
		  memcpy(&mx[l],   &mxtemp, sizeof(mxtemp));
		  ++l;
		}
	      }
	    }
#endif
	  }
	  /* Processed that preference, now next */
	  i = j-1;
	  if (j < nmx)		/* If within the array */
	    maxpref = mx[j].pref;
	}
	if (SS->verboselog) {
	  fprintf(SS->verboselog,"Target has following MXes (cnt=%d):\n",nmx);
	  for (i=0; i<nmx; ++i) {
	    struct addrinfo *ai = mx[i].ai;
	    for (n = 0; ai; ai = ai->ai_next) ++n;
	    fprintf(SS->verboselog,"  MX %3d %-30.200s  (%d %saddrs)\n",
		    mx[i].pref, mx[i].host, n,
		    n == 1 ?
		    (mx[i].ai->ai_family == PF_INET ? "AF_INET ":"AF_INET6 "):
		    "");
	  }
	}
	mx[nmx].host = NULL;
	SS->mxcount = nmx;
	if (had_eai_again)
	  return EX_TEMPFAIL;
	return EX_OK;
}


#ifdef TEST

time_t endtime, starttime, now;
const char *FAILED = "failed";

int use_ipv6 = 1;
int prefer_ip6 = 1;
int checkwks = 0;

char myhostname[MAXHOSTNAMELEN+1] = "my.host.name";
const char *progname;
char errormsg[ZBUFSIZ]; /* Global for the use of  dnsgetrr.c */

int main(argc, argv)
     int argc;
     char *argv[];
{
	int c, rc;
	SmtpState SS;
	char *host, *s;
	struct mxdata mx[100];

	progname = argv[0];

	memset(&SS, 0, sizeof(SS));
	SS.verboselog = stdout;

	host = argv[1];

	if (argc != 2) {
	  printf("Usage: getmxrr-test domain.name\n");
	  exit(EX_USAGE);
	}


	rc = getmxrr(&SS, host, mx, 100, 0);

	switch (rc) {
	case EX_OK:
	  s = "EX_OK";
	  break;
	case EX_USAGE:
	  s = "EX_USAGE";
	  break;
	case EX_DATAERR:
	  s = "EX_DATAERR";
	  break;
	case EX_NOINPUT:
	  s = "EX_NOINPUT";
	  break;
	case EX_NOUSER:
	  s = "EX_NOUSER";
	  break;
	case EX_NOHOST:
	  s = "EX_NOHOST";
	  break;
	case EX_UNAVAILABLE:
	  s = "EX_UNAVAILABLE";
	  break;
	case EX_SOFTWARE:
	  s = "EX_SOFTWARE";
	  break;
	case EX_OSERR:
	  s = "EX_OSERR";
	  break;
	case EX_OSFILE:
	  s = "EX_OSFILE";
	  break;
	case EX_CANTCREAT:
	  s = "EX_CANTCREAT";
	  break;
	case EX_IOERR:
	  s = "EX_IOERR";
	  break;
	case EX_TEMPFAIL:
	  s = "EX_TEMPFAIL";
	  break;
	case EX_PROTOCOL:
	  s = "EX_PROTOCOL";
	  break;
	case EX_NOPERM:
	  s = "EX_NOPERM";
	  break;
	default:
	  s = "UNKNOWN!";
	}


	printf("getmxrr() rc=%d %s\n", rc, s);

	return 0;
}

#endif
