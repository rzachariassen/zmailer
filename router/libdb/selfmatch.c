/*
 *	Copyright 1997 Matti Aarnio <mea@nic.funet.fi>
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
	char rbuf[8];

	/* Pick up current set of interface addresses ...
	   ... or from the ZENV variable  SELFADDRESSES. */
	stashmyaddresses(NULL);

	if (cistrncmp(sip->key,"IPv6 ",5)==0 ||
	    cistrncmp(sip->key,"IPv6:",5)==0 ||
	    cistrncmp(sip->key,"IPv6.",5)==0) {
#if defined(AF_INET6) && defined(INET6)
	  struct sockaddr_in6 si6;

	  memset(&si6, 0, sizeof(si6));
	  si6.sin6_family = AF_INET6;
	  rc = inet_pton(AF_INET6, sip->key+5, (void*)&si6.sin6_addr);
	  if (rc < 1)
	    return NULL;
	  rc = matchmyaddress((struct sockaddr *)&si6);
#else
	  return NULL; /* Sorry, we do not have it! */
#endif
	} else {
	  struct sockaddr_in si4;

	  memset(&si4, 0, sizeof(si4));
	  si4.sin_family = AF_INET;
	  rc = inet_pton(AF_INET, sip->key, (void*)&si4.sin_addr);
	  if (rc < 1)
	    return NULL;
	  rc = matchmyaddress((struct sockaddr *)&si4);
	}
	if (rc == 0)
	  return NULL;
	sprintf(rbuf,"%d",rc);
	return newstring(dupstr(rbuf));
}

static void freeaddresses __((struct sockaddr **, int));
static void
freeaddresses(sap,cnt)
struct sockaddr **sap;
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
	struct sockaddr **sa = NULL;
	int i, cnt;
	char buf[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")+2];

	cnt = loadifaddresses(&sa);
	for (i = 0; i < cnt; ++i) {
	  if (sa[i]->sa_family == AF_INET) {
	    inet_ntop(AF_INET, (void*)&((struct sockaddr_in*)sa[i])->sin_addr, buf, sizeof(buf));
	    fprintf(outfp,"[%s]\n",buf);
	  }
#if defined(AF_INET6) && defined(INET6)
	  else if (sa[i]->sa_family == AF_INET) {
	    inet_ntop(AF_INET6, (void*)&((struct sockaddr_in6*)sa[i])->sin6_addr, buf, sizeof(buf));
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
	struct sockaddr **sa = NULL;
	int cnt;

	cnt = loadifaddresses(&sa);
	if (sa)
	  freeaddresses(sa,cnt);

	fprintf(outfp,"%d\n", cnt);
}
