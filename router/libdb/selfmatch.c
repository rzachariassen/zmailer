/*
 *	Copyright 1997 Matti Aarnio <mea@nic.funet.fi>
 */
/*
 *	Lots of modifications (new guts, more or less..) by
 *	Matti Aarnio <mea@nic.funet.fi>  (copyright) 1992-2002
 */

/* LINTLIBRARY */

#include "mailer.h"
#include "listutils.h"

#include <netdb.h>
#ifndef EAI_AGAIN
# include "netdb6.h" /* IPv6 API stuff */
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

#include <arpa/inet.h>

#ifdef NOERROR
#undef NOERROR /* On Solaris 2.3 the  netinet/in.h  includes
		  sys/stream.h, which has DIFFERENT "NOERROR" in it.. */
#endif


#include "search.h"
#include "libc.h"
#include "libz.h"


conscell *
search_selfmatch(sip)
	search_info *sip;
{
	int rc;
	char rbuf[8], *s;
	int slen;
	Usockaddr si;

	/* Pick up current set of interface addresses ...
	   ... or from the ZENV variable  SELFADDRESSES. */
	stashmyaddresses(NULL);

	memset(&si, 0, sizeof(si));

	if (cistrncmp(sip->key,"IPv6 ",5)==0 ||
	    cistrncmp(sip->key,"IPv6:",5)==0 ||
	    cistrncmp(sip->key,"IPv6.",5)==0) {
#if defined(AF_INET6) && defined(INET6)

	  si.v6.sin6_family = AF_INET6;
	  rc = inet_pton(AF_INET6, sip->key+5, (void*)&si.v6.sin6_addr);
	  if (rc < 1)
	    return NULL;
	  rc = matchmyaddress(&si);
#else
	  return NULL; /* Sorry, we do not have it! */
#endif
	} else {

	  si.v4.sin_family = AF_INET;
	  rc = inet_pton(AF_INET, sip->key, (void*)&si.v4.sin_addr);
	  if (rc < 1)
	    return NULL;
	  rc = matchmyaddress(&si);
	}
	if (rc == 0)
	  return NULL;
	sprintf(rbuf, "%d", rc);
	slen = strlen(rbuf);
	s = dupnstr(rbuf, slen);
	return newstring(s, slen);
}

static void freeaddresses __((Usockaddr **, int));
static void
freeaddresses(sap,cnt)
     Usockaddr **sap;
     int cnt;
{
	int i;
	for (i = 0; i < cnt && sap[i] != NULL; ++i)
	  free(sap[i]);
	free(sap);
}

void
print_selfmatch(sip, outfp)
     search_info *sip;
     FILE *outfp;
{
	Usockaddr **sa = NULL;
	int i, cnt;
	char buf[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")+2];

	cnt = loadifaddresses(&sa);
	for (i = 0; i < cnt; ++i) {
	  if (sa[i]->v4.sin_family == AF_INET) {
	    inet_ntop(AF_INET, (void*)&sa[i]->v4.sin_addr, buf, sizeof(buf));
	    fprintf(outfp,"[%s]\n",buf);
	  }
#if defined(AF_INET6) && defined(INET6)
	  else if (sa[i]->v6.sin6_family == AF_INET) {
	    inet_ntop(AF_INET6, (void*)&sa[i]->v6.sin6_addr, buf, sizeof(buf));
	    fprintf(outfp,"[ipv6 %s]\n",buf);
	  }
#endif
	  else {
	    /* XX: ???? */
	  }
	}
	if (sa)
	  freeaddresses(sa,cnt);
}

void
count_selfmatch(sip, outfp)
search_info *sip;
FILE *outfp;
{
	Usockaddr **sa = NULL;
	int cnt;

	cnt = loadifaddresses(&sa);
	if (sa)
	  freeaddresses(sa,cnt);

	fprintf(outfp,"%d\n", cnt);
}
