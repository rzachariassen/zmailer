/*
 * selfaddresses() routines handle recognition of our own IP addresses,
 * so that we won't talk with ourself from smtp sender, and recognize,
 * when the SMTP target is ourself, even when using alternate IP
 * addresses that are not matched with our own name.
 *
 *
 * We try at first to get the current setup via  SIOCGIFCONF  ioctl, and
 * if it yields nothing, we try other method:  We rely on the system
 * configurer to do the right thing, and list them at the ZENV file
 * SELFADDRESSES= -entry  as a string of style:
 *
 *    "[1.2.3.4],[6.7.8.9],[IPv6:::ffff:1.2.3.4],my.domain.name"
 *              ^---------^---------------------^---- commas to separate them!
 *
 */

/*  loadifaddresses() -- for ZMailer

    A piece of code from  sendmail-8.7.1:src/conf.c
    with serious mutations...  We want a list of ADDRESSES,
    not hostnames per se...  Also unlike sendmail, we keep
    redoing this query every so often -- in fact for EVERY
    smtp connection open!

    Original copyright SunSoft/Berkeley/Almann, modifications
    by Matti Aarnio <mea@nic.funet.fi> 1997
*/

#include "mailer.h"
#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if (defined(__svr4__) || defined(__SVR4)) && defined(__sun)
# define BSD_COMP /* Damn Solaris, and its tricks... */
#endif
#include <sys/ioctl.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifndef EAI_AGAIN
# include "netdb6.h" /* IPv6 API stuff */
#endif
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
#include <string.h>

#include "libz.h"

extern char  *getzenv     __((const char *));

/*
**  LOADIFADDRESSES -- load interface-specific addresses
*/

/* autoconfig test script!

AC_CACHE_CHECK([for 'sa_len' in 'struct sockaddr'], ac_cv_struct_sa_len,
[AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/socket.h>], [struct sockaddr sa; sa.sa_len = 0; ],
	ac_cv_struct_sa_len=yes, ac_cv_struct_sa_len=no)])
if test "$ac_cv_struct_sa_len" = yes; then
  AC_DEFINE(HAVE_SA_LEN)
fi

*/

#include "hostenv.h"

struct rtentry; /* Dummies for BSD systems */
struct mbuf;
#include <arpa/inet.h>
#include <net/if.h>


int
loadifaddresses(sockaddrp)
struct sockaddr ***sockaddrp;
{
#ifdef SIOCGIFCONF
	int s;
	int i;
	int ifcount = 0;
	int af = AF_INET;
        struct ifconf ifc;
	int ifbufsize = 4 * sizeof(struct ifreq) + 4;
	char *interfacebuf = (void*)malloc(ifbufsize);
	struct sockaddr **sap;

	sap = (void*)malloc(sizeof(struct sockaddr*) * (ifcount + 2));
	if (! sap || !interfacebuf) {
	  if (interfacebuf)
	    free(interfacebuf);
	  if (sap)
	    free(sap);
	  return -3; /* UAARGH! */
	}

#if defined(AF_INET6) && defined(INET6)
other_socktype:
#endif

	s = socket(af, SOCK_DGRAM, 0);
	if (s < 0) {
	  free(interfacebuf);
	  free(sap);
	  return -1;
	}

	/* Redo the buffer size increase until we get response size to
	   be something of LESS THAN the buffer size minus two-times
	   the sizeof(struct ifreq) -- because then we don't have
	   a potential case of having larger block of addresses in
	   system, but us being unable to get them all..
	   Usually system has TWO interfaces -- loopback, and the LAN,
	   thus the following loop is executed exactly once! */

	/* Some utilities seem to do this probing also with sockets of
	   AF_X25, AF_IPX, AF_AX25, AF_INET6, etc. -address families,
	   but on Linux (very least) it can be done with any of them,
	   thus we use the one that is most likely available: AF_INET */

	for (;;) {

	  /* get the list of known IP address from the kernel */
	  ifbufsize <<= 1;
	  interfacebuf = (void*)realloc(interfacebuf,ifbufsize);
	  ifc.ifc_buf = interfacebuf;
	  ifc.ifc_len = ifbufsize;
	  if (ioctl(s, SIOCGIFCONF, (char *)&ifc) < 0) {
		close(s);
		free(interfacebuf);
		free(sap);
		return -2;
	  }

	  if (ifc.ifc_len < (ifbufsize - 2*sizeof(struct ifreq)))
	    break;

	  /* Redo the query, perhaps didn't get them all.. */
	}


	/* Count how many addresses listed */

	for (i = 0; i < ifc.ifc_len; ) {

	  struct ifreq *ifr = (struct ifreq *) &ifc.ifc_buf[i];
	  struct sockaddr *sa = &ifr->ifr_addr;
#ifdef SIOCGIFFLAGS
	  struct ifreq ifrf;
#endif

#ifdef HAVE_SA_LEN
	  if (sa->sa_len > sizeof ifr->ifr_addr)
	    i += sizeof ifr->ifr_name + sa->sa_len;
	  else
#endif
	    i += sizeof *ifr;

	  /* Known address families ? */

	  if (ifr->ifr_addr.sa_family != AF_INET
#if defined(AF_INET6) && defined(INET6)
	      &&
	      ifr->ifr_addr.sa_family != AF_INET6
#endif
	      )
	    continue; /* Not IPv4, nor IPv6 */


	  /* Now, what do the flags say ? Are they alive ? */

#ifdef SIOCGIFFLAGS

	  memset(&ifrf, 0, sizeof(struct ifreq));
	  strncpy(ifrf.ifr_name, ifr->ifr_name, sizeof(ifrf.ifr_name));

	  if (ioctl(s, SIOCGIFFLAGS, (char *) &ifrf) < 0)
	    continue; /* Failed.. */
#if 0
	   printf("name='%s'  ifrf_flags=0x%x\n",
	     ifr->ifr_name,ifrf.ifr_flags);
#endif
	  if (!(IFF_UP & ifrf.ifr_flags))
	    continue;
#else

	  /* printf("ifr_flags=0x%x\n",ifr->ifr_flags); */

	  if (!(IFF_UP & ifr->ifr_flags))
	    continue;
#endif

	  sap = (void*)realloc(sap, sizeof(struct sockaddr*) * (ifcount + 2));
	  if (! sap) {
	    close(s);
	    free(interfacebuf);
	    return -4; /* UAARGH! */
	  }

	  /* XX: Use sa_len on BSD44 ??? */
	  if (sa->sa_family == AF_INET) {
	    struct sockaddr_in *si4 = (void*)malloc(sizeof(*si4));
	    if (si4 == NULL)
	      break;
	    /* pick the whole sockaddr package! */
	    memcpy(si4, &ifr->ifr_addr, sizeof(struct sockaddr_in));
	    sap[ifcount] = (struct sockaddr*)si4;
	  }
#if defined(AF_INET6) && defined(INET6)
	  if (sa->sa_family == AF_INET6) {
	    struct sockaddr_in6 *si6 = (void*)malloc(sizeof(*si6));
	    if (si6 == NULL)
	      break;

	    /* XX: MUST DO AN  ioctl(s, SIOCGIFADDR, ...) HERE ! */

	    /* pick the whole sockaddr package! */
	    memcpy(si6, &ifr->ifr_addr, sizeof(struct sockaddr_in6));
	    sap[ifcount] = (struct sockaddr*)si6;
	  }
#endif
	  ++ifcount;
	}
	sap[ifcount] = NULL;
	close(s);

#if defined(AF_INET6) && defined(INET6)
	if (af != AF_INET6) {
	  af = AF_INET6;
	  goto other_socktype;
	}
#endif

	free(interfacebuf);
	*sockaddrp = sap;

	return ifcount;
#else
	return -1;
#endif
}

#ifndef TESTMODE /* We test ONLY of  loadifaddresses() routine! */

static             int    nmyaddrs = 0;
static struct sockaddr  ** myaddrs = NULL;

static void stashmyaddress __((const char *));
static void
stashmyaddress(host)
	const char *host;
{
	int naddrs;
	struct hostent *hp, hent;
	union {
	  struct in_addr ia4;
#if defined(AF_INET6) && defined(INET6)
	  struct in6_addr ia6;
#endif
	} au;
	int addrsiz, af, rc;
	void *addrs[2];

	if (host == NULL) return;

	hp = NULL;
	if (*host != '[')
	  hp = gethostbyname(host);

	if (hp == NULL) { /* No such host ?? */

#ifndef INADDRSZ
#define INADDRSZ 4
#endif
#ifndef IN6ADDRSZ
#define IN6ADDRSZ 16
#endif

#if defined(AF_INET6) && defined(INET6)
	  if (strncasecmp(host,"[IPv6:",6)==0) {
	    af = AF_INET6;
	    addrsiz = IN6ADDRSZ;
	    rc = inet_pton(af, host+6, &au.ia6);
	  } else
#endif
	    if (*host == '[') {
	      af = AF_INET;
	      addrsiz = INADDRSZ;
	      rc = inet_pton(af, host+1, &au.ia4);
	    } else
	      return;

	  if (rc <= 0)
	    return; /* Umm.. Failed ? */


	  hp = &hent;
	  /* don't really care about gethostbyaddr() here */
	  hp->h_name     = (char*)host;
	  hp->h_addrtype = af;
	  hp->h_aliases  = NULL;
	  hp->h_length   = addrsiz;
	  addrs[0] = (void *)&au;
	  addrs[1] = NULL;
	  hp_setalist(hp, addrs);
	  naddrs = 1;
	} else {
	  naddrs = 0;
	  for (hp_init(hp); *hp_getaddr() != NULL; hp_nextaddr())
	    ++naddrs;
	  if (hp->h_addrtype == AF_INET)
	    addrsiz = sizeof(struct sockaddr_in);
#if defined(AF_INET6) && defined(INET6)
	  else if (hp->h_addrtype == AF_INET6)
	    addrsiz = sizeof(struct sockaddr_in6);
#endif
	  else
	    addrsiz = -1;
	}
	if (myaddrs == NULL) {
	  nmyaddrs = 0;
	  myaddrs = (void*)malloc((nmyaddrs + naddrs +1) * sizeof(struct sockaddr*));
	} else
	  myaddrs = (void*)realloc((void*)myaddrs,
				   (nmyaddrs + naddrs +1) * sizeof(struct sockaddr*));

	if (!myaddrs) return; /* Uurgh.... */

	for (hp_init(hp); *hp_getaddr() != NULL; hp_nextaddr()) {
	  if (hp->h_addrtype == AF_INET) {
	    struct sockaddr_in *si;
	    si = (void*)malloc(sizeof(*si));
	    if (!si) {
	      return;
	    }
	    myaddrs[nmyaddrs++] = (struct sockaddr *) si;
	    memset(si,0,sizeof(*si));
	    si->sin_family = AF_INET;
	    memcpy(&si->sin_addr.s_addr, *hp_getaddr(), hp->h_length);
	  }
#if defined(AF_INET6) && defined(INET6)
	  if (hp->h_addrtype == AF_INET6) {
	    struct sockaddr_in6 *si6;
	    si6 = (void*)malloc(sizeof(*si6));
	    if (!si6) {
	      return;
	    }
	    myaddrs[nmyaddrs++] = (struct sockaddr *) si6;
	    memset(si6,0,sizeof(*si6));
	    si6->sin6_family = AF_INET;
	    memcpy(&si6->sin6_addr.s6_addr, *hp_getaddr(), hp->h_length);
	  }
#endif
	}
	myaddrs[nmyaddrs] = NULL;
}

void
stashmyaddresses(host)
const char *host;
{
	char *s1, *s2, *zenv;
	struct sockaddr **sa;
	int sacnt;

	/* Clear them all away */
	if (myaddrs != NULL) {
	  int i;
	  for (i = 0; i < nmyaddrs; ++i)
	    if (myaddrs[i] != NULL)
	      free(myaddrs[i]);
	  free(myaddrs);
	  myaddrs = NULL;
	  nmyaddrs = 0;
	}

	/* Now start fillig -- interface addresses, if you can get them */

	sacnt = loadifaddresses(&sa);

	if (sacnt > 0) {
	  /* Okay, we GOT some addresses, I bet we got them all!
	     (All interfaces that we currently have active!) */
	  myaddrs = sa;
	  nmyaddrs = sacnt;

	  return;
	}

	/* Didn't get any by probeing interfaces ?! Lets use environment .. */

	zenv = getzenv("SELFADDRESSES");

	if (host && *host)
	  stashmyaddress(host);

	s1 = zenv;
	while (s1) {
	  s2 = strchr(s1,',');
	  if (s2) *s2 = 0;
	  stashmyaddress(s1);
	  if (s2) *s2 = ',';
	  if (s2)
	    s1 = s2+1;
	  else
	    s1 = NULL;
	}
}


int
matchmyaddress(sa)
	struct sockaddr *sa;
{
	int i;

	if (!myaddrs)
		stashmyaddresses(NULL);
	if (!myaddrs) return 0; /* Don't know my addresses ! */
	
	/* Match loopback net.. */
	if (sa->sa_family == AF_INET) {
	  struct sockaddr_in *si;
	  int net;
	  si = (struct sockaddr_in *)sa;

	  net = (ntohl(si->sin_addr.s_addr) >> 24) & 0xFF;
	  if (net == 127)
	    return 2; /* Loopback network */
	  if (net == 0 || net == 127 || net > 223)
	    return 3;
	}

	/* ... and then the normal thing -- listed interfaces */

	for (i = 0; i < nmyaddrs; ++i) {
	  /* if this is myself, skip to next MX host */
	  if (sa->sa_family == myaddrs[i]->sa_family) {
	    if (sa->sa_family == AF_INET && memcmp(sa, myaddrs[i], 4) == 0)
	      return 1;
#if defined(AF_INET6) && defined(INET6)
	    if (sa->sa_family == AF_INET6 && memcmp(sa, myaddrs[i], 16) == 0)
	      return 1;
#endif
	  }
	}
	return 0;
}

int
matchmyaddresses(ai)
	struct addrinfo *ai;
{
	for ( ; ai ; ai = ai->ai_next ) {
	  int i = matchmyaddress(ai->ai_addr);
	  if (i != 0)
	      return i;
	}
	return 0;
}
#endif /* TESTMODE */

#ifdef TESTMODE

char *progname = "selfaddrstest";

int main(argc,argv)
int argc;
char *argv[];
{
  int cnt, i;
  struct sockaddr **sa;
  char buf[80];

  cnt = loadifaddresses(&sa);

  printf("loadifaddresses rc=%d\n", cnt);

  for (i = 0; i < cnt; ++i) {
    switch(sa[i]->sa_family) {
    case AF_INET:
      inet_ntop(AF_INET, &((struct sockaddr_in **) sa)[i]->sin_addr, buf, sizeof(buf));
      printf("IPv4: [%s]\n", buf);
      break;
#if defined(AF_INET6) && defined(INET6)
    case AF_INET6:
      inet_ntop(AF_INET6, &((struct sockaddr_in6 **) sa)[i]->sin6_addr, buf, sizeof(buf));
      printf("IPv6: [IPv6:%s]\n",buf);
      break;
#endif
    default:
      printf("Unknown socket address family: %d\n", sa[i]->sa_family);
      break;
    }
  }

  free(sa);

  return 0;
}
#endif /* TESTMODE */
