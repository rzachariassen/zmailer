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

#include "hostenv.h"
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
#include <errno.h>

union sockaddr_uni {
    struct sockaddr     sa;
    struct sockaddr_in  v4;
#if defined(AF_INET6) && defined(INET6)
    struct sockaddr_in6 v6;
#endif
};

#include "libc.h"
#include "zmalloc.h"
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

/* #include "l-if.h" --- just some fake test stuff for SIOCGLIF*** */

#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif

int
loadifaddresses(sockaddrp)
struct sockaddr ***sockaddrp;
{
	int i;
	int sapcount = -1;
	int sapspace = 2;
	union sockaddr_uni **sap;

	sap = (void*)malloc(sizeof(union sockaddr_uni*) * (sapspace + 2));

	if (! sap)
	  return -3; /* UAARGH! */

#ifdef HAVE_GETIFADDRS
	{
	  struct ifaddrs *ifar = NULL, *ifa;

	  i = getifaddrs( &ifar );
	  if (i < 0) {
	    free(sap);
	    return i;
	  }

	  for (i = 0, ifa = ifar; ifa ; ++i, ifa = ifa->ifa_next) {
	    if ((ifa->ifa_flags & IFF_UP) &&
		(ifa->ifa_addr != NULL)) {

	      struct sockaddr *sa = ifa->ifa_addr;

	      if (sapcount +2 >= sapspace) {
		sapspace <<= 1;
		sap = (void*)realloc(sap, (sizeof(union sockaddr_uni*) *
					   (sapspace + 2)));
	      }

	      if (! sap) {
		return -5; /* UAARGH! */
	      }

	      if (sa->sa_family == AF_INET) {
		struct sockaddr_in *si4 = (void*)malloc(sizeof(*si4));
		if (si4 == NULL)
		  break;

		/* pick the whole sockaddr package! */
		memcpy(si4, sa, sizeof(*si4));
		sap[++sapcount] = (union sockaddr_uni *)si4;
	      }

#if defined(AF_INET6) && defined(INET6)
	      if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *si6 = (void*)malloc(sizeof(*si6));
		if (si6 == NULL)
		  break;

		/* pick the whole sockaddr package! */
		memcpy(si6, sa, sizeof(*si6));
		sap[++sapcount] = (union sockaddr_uni *)si6;
	      }
#endif
	    }
	  }


#ifdef HAVE_FREEIFADDRS
	  freeifaddrs(ifar);
#else
	  free(ifar);
#endif
	}
#else /* not HAVE_GETIFADDRS */

#if defined(SIOCGLIFCONF) && defined(AF_INET6) && defined(INET6)
	/*#warning "experimental INET6 related SIOCGLIFCONF code activated!"*/
	{
	  struct lifconf lifc;
	  struct ifconf ifc;
	  int ifbufsize = 4 * sizeof(struct lifreq) + 4;
	  char *interfacebuf = NULL;
	  int s;

	  if (!interfacebuf) {
	    free(sap);
	    return -2;
	  }

	  s = socket(PF_INET6, SOCK_DGRAM, 0);
	  if (s < 0)
	    goto done_this_ipv6;


	  /* Some utilities seem to do this probing also with sockets of
	     AF_X25, AF_IPX, AF_AX25, AF_INET6, etc. -address families,
	     but on Linux (very least) it can be done with any of them,
	     thus we use the one that is most likely available: AF_INET */

	  for (;;) {

	    /* get the list of known IP address from the kernel */
	    ifbufsize <<= 1;
	    interfacebuf = (void*)realloc(interfacebuf,ifbufsize);
	    memset(&lifc, 0, sizeof(lifc));
	    lifc.lifc_buf    = interfacebuf;
	    lifc.lifc_len    = ifbufsize;
	    lifc.lifc_family = AF_UNSPEC;
	    lifc.lifc_flags  = 0;
	    if (ioctl(s, SIOCGLIFCONF, (char *)&lifc) < 0) {
	      if (errno == EINTR)
		continue;
	      if (errno == EINVAL)
		continue;
	      goto done_this_ipv6; /* HUH!! ??? */
	    }

	    if (lifc.lifc_len < (ifbufsize - 2*sizeof(struct lifreq)))
	      break;

	    /* Redo the query, perhaps didn't get them all.. */
	  }

	  /* Likely got them all.. */

	  /* Count how many addresses listed */

	  for (i = 0; i < lifc.lifc_len; ) {

	    struct lifreq *lifr = (struct lifreq *) &lifc.lifc_buf[i];
	    union sockaddr_uni *sa = (union sockaddr_uni *) &lifr->lifr_addr;
#ifdef SIOCGLIFFLAGS
	    struct lifreq lifrf;
#endif

#if defined(SA_LEN)
	    if (SA_LEN(((struct sockaddr *)sa)) > sizeof(lifr->lifr_addr))
	      i += sizeof lifr->lifr_name + SA_LEN(((struct sockaddr *)sa));
	    else
#elif defined(HAVE_SA_LEN)
	      if (sa->sa.sa_len > sizeof lifr->lifr_addr)
		i += sizeof lifr->lifr_name + sa->sa.sa_len;
	      else
#endif
		i += sizeof *lifr;

	    /* Known address families ?
	       The one we scanned for ??*/

	    if ( sa->sa.sa_family != AF_INET &&
		 sa->sa.sa_family != AF_INET6 )
		/* Skip if not either of used protocols.. */
		continue;

	    /* Now, what do the flags say ? Are they alive ? */

#ifdef SIOCGLIFFLAGS

	    memset(&lifrf, 0, sizeof(struct lifreq));
	    /* lifrf.lifr_index = 0;
	       -- Solaris has _index, Linux has _ifindex */
	    strncpy(lifrf.lifr_name, lifr->lifr_name, sizeof(lifrf.lifr_name));

	    if (ioctl(s, SIOCGLIFFLAGS, (char *) &lifrf) < 0)
	      continue; /* Failed.. */

#if 0
	    printf("name='%s'  lifrf_flags=0x%x\n",
		   lifr->lifr_name,lifrf.lifr_flags);
#endif
	    if (!(IFF_UP & lifrf.lifr_flags))
	      continue;
#else

	    /* printf("lifr_flags=0x%x\n",lifr->lifr_flags); */

	    if (!(IFF_UP & lifr->lifr_flags))
	      continue;
#endif

	    if (sapcount +2 >= sapspace) {
	      sapspace <<= 1;
	      sap = (void*)realloc(sap, (sizeof(union sockaddr_uni*) *
					 (sapspace + 2)));
	    }

	    if (! sap) {
	      close(s);
	      free(interfacebuf);
	      return -5; /* UAARGH! */
	    }

	    if (sa->sa.sa_family == AF_INET) {
	      struct sockaddr_in *si4 = (void*)malloc(sizeof(*si4));
	      if (si4 == NULL)
		break;

	      /* pick the whole sockaddr package! */
	      memcpy(si4, sa, sizeof(*si4));
	      sap[++sapcount] = (union sockaddr_uni *)si4;
	    } else if (sa->sa.sa_family == AF_INET6) {
	      struct sockaddr_in6 *si6 = (void*)malloc(sizeof(*si6));
	      if (si6 == NULL)
		break;

	      /* pick the whole sockaddr package! */
	      memcpy(si6, sa, sizeof(*si6));
	      sap[++sapcount] = (union sockaddr_uni *)si6;
	    }
	  }

done_this_ipv6:

	  if (s >= 0) close(s);
	  free(interfacebuf);

	}
#else /* SIOCGLIFCONF && IPv6 */

#ifdef SIOCGIFCONF
	{
	  struct ifconf ifc;
	  int ifbufsize = 4 * sizeof(struct ifreq) + 4;
	  char *interfacebuf = NULL;
	  int s;

	  if (!interfacebuf) {
	    free(sap);
	    return -2;
	  }

	  s = socket(PF_INET, SOCK_DGRAM, 0);

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
	    memset(&ifc, 0, sizeof(ifc));
	    ifc.ifc_buf = interfacebuf;
	    ifc.ifc_len = ifbufsize;
	    if (ioctl(s, SIOCGIFCONF, (char *)&ifc) < 0)
	      if (errno == EINVAL)
		continue;

	    if (ifc.ifc_len < (ifbufsize - 2*sizeof(struct ifreq)))
	      break;

	    /* Redo the query, perhaps didn't get them all.. */
	  }


	  /* Count how many addresses listed */

	  for (i = 0; i < ifc.ifc_len; ) {

	    struct ifreq *ifr = (struct ifreq *) &ifc.ifc_buf[i];
	    union sockaddr_uni *sa = (union sockaddr_uni *) &ifr->ifr_addr;
#ifdef SIOCGIFFLAGS
	    struct ifreq ifrf;
#endif

#if defined(SA_LEN)
	    if (SA_LEN(((struct sockaddr*)sa)) > sizeof ifr->ifr_addr)
	      i += sizeof ifr->ifr_name + SA_LEN(((struct sockaddr *)sa));
	    else
#elif defined(HAVE_SA_LEN)
	      if (sa->sa.sa_len > sizeof ifr->ifr_addr)
		i += sizeof ifr->ifr_name + sa->sa.sa_len;
	      else
#endif
		i += sizeof *ifr;

	    /* Known address families ?
	       The one we scanned for ??*/

	    if (ifr->ifr_addr.sa_family != PF_INET)
	      continue;

	    /* Now, what do the flags say ? Are they alive ? */

#ifdef SIOCGIFFLAGS

	    memset(&ifrf, 0, sizeof(struct ifreq));
	    /* ifrf.ifr_index = 0;
	       -- Solaris has _index, Linux has _ifindex */
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

	    if (sapcount +2 >= sapspace) {
	      sapspace <<= 1;
	      sap = (void*)realloc(sap, (sizeof(union sockaddr_uni*) *
					 (sapspace + 2)));
	    }
	    if (! sap) {
	      close(s);
	      free(interfacebuf);
	      return -4; /* UAARGH! */
	    }

	    if (sa->sa.sa_family == AF_INET) {
	      struct sockaddr_in *si4 = (void*)malloc(sizeof(*si4));
	      if (si4 == NULL)
		break;
	      /* pick the whole sockaddr package! */
	      memcpy(si4, &ifr->ifr_addr, sizeof(*si4));
	      sap[++sapcount] = (union sockaddr_uni *)si4;
	    }
	  }
	  close(s);
	  free(interfacebuf);
	}
#endif /* defined(SIOCGIFCONF) */
#endif /* SIOCGLIFCONF / SIOCGIFCONF */

#endif /* not HAVE_GETIFADDRS */

	  *sockaddrp = (struct sockaddr **)sap;

	  sap[++sapcount] = NULL;

	  return sapcount;
	}

#ifndef TESTMODE /* We test ONLY of  loadifaddresses() routine! */

static             int    nmyaddrs = 0;
static union sockaddr_uni  ** myaddrs = NULL;

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

	if (host == NULL || *host == 0) return;

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
	/* malloc(size) == realloc(NULL, size) */
	myaddrs = (void*)realloc((void*)myaddrs,
				 (nmyaddrs + naddrs +1) *
				 sizeof(union sockaddr_uni*));

	if (!myaddrs) return; /* Uurgh.... */

	for (hp_init(hp); *hp_getaddr() != NULL; hp_nextaddr()) {
	  if (hp->h_addrtype == AF_INET) {
	    struct sockaddr_in *si;
	    si = (void*)malloc(sizeof(*si));
	    if (!si) {
	      return;
	    }
	    myaddrs[nmyaddrs++] = (union sockaddr_uni *) si;
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
	    myaddrs[nmyaddrs++] = (union sockaddr_uni *) si6;
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
	union sockaddr_uni **sa;
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

	sacnt = loadifaddresses((struct sockaddr ***)&sa);

	if (sacnt > 0) {
	  /* Okay, we GOT some addresses, I bet we got them all!
	     (All interfaces that we currently have active!) */
	  myaddrs = sa;
	  nmyaddrs = sacnt;

	}

	/* Independent of getting (or not) of interface data, stash in
	   also whatever we can get from our environment.  Thus was
	   we can block CLUSTER input addresses, for example. */

	zenv = getzenv("SELFADDRESSES");

	if (host && *host)
	  stashmyaddress(host);

	s1 = zenv;
	while (s1 && *s1) {
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


/* Here we compare only the address portion, not ports, nor anything else! */


int
matchmyaddress(_sa)
	struct sockaddr *_sa;
{
	int i;
	union sockaddr_uni *sau = (union sockaddr_uni *) _sa;

	if (!myaddrs)
		stashmyaddresses(NULL);
	if (!myaddrs) return 0; /* Don't know my addresses ! */
	
	/* Match loopback net.. */
	if (sau->sa.sa_family == AF_INET) {
	  int net;

	  net = (ntohl(sau->v4.sin_addr.s_addr) >> 24) & 0xFF;
	  if (net == 127)
	    return 2; /* Loopback network */
	  if (net == 0 || net > 223)
	    return 3;
	}

	/* ... and then the normal thing -- listed interfaces */

	for (i = 0; i < nmyaddrs; ++i) {
	  /* if this is myself, skip to next MX host */
	  if (sau->sa.sa_family == myaddrs[i]->sa.sa_family) {
	    if (sau->sa.sa_family == AF_INET &&
		memcmp(&sau->v4.sin_addr, &myaddrs[i]->v4.sin_addr, 4) == 0)
	      return 1;
#if defined(AF_INET6) && defined(INET6)
	    if (sau->sa.sa_family == AF_INET6 &&
		memcmp(&sau->v6.sin6_addr, &myaddrs[i]->v6.sin6_addr, 16) == 0)
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

const char *progname = "selfaddrstest";

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
