/*
 * int zgetifaddress(int af, char *ifname, struct sockaddr *)
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

/* #include "l-if.h"  --- just some fake test stuff for SIOCGLIF*** */

#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif

int
zgetifaddress(af, ifname, sap)
     int af;
     const char *ifname;
     struct sockaddr * sap;
{
	int i;

#ifdef HAVE_GETIFADDRS
	/* #warning "GETIFADDRS() code chosen" */
	{
	  struct ifaddrs *ifar = NULL, *ifa;

	  i = getifaddrs( &ifar );
	  if (i < 0) {
	    free(sap);
	    return i;
	  }

	  i = -1;

	  for (ifa = ifar; ifa ; ifa = ifa->ifa_next) {
	    if ((ifa->ifa_flags & IFF_UP) &&
		(ifa->ifa_addr != NULL)) {

	      struct sockaddr *sa = ifa->ifa_addr;

	      if (strcasecmp(ifname, ifa->ifa_name) != 0)
		continue; /* next ... */

	      /* We have matching name, do we have matching AF ?? */

	      if (sa->sa.sa_family != af)
		continue; /* Nope.. */

	      if (sa->sa.sa_family == AF_INET) {
		struct sockaddr_in *si4 = (void*)sap;

		if (si4 == NULL) break; /* Bad param! */

		/* pick the whole sockaddr package! */
		memcpy(si4, sa, sizeof(*si4));
		i = 0; /* Found! */
		break;
	      }

#if defined(AF_INET6) && defined(INET6)
	      if (sa->sa.sa_family == AF_INET6) {
		struct sockaddr_in6 *si6 = (void*)sap;

		if (si6 == NULL) break;

		/* pick the whole sockaddr package! */
		memcpy(si6, sa, sizeof(*si6));
		i = 0;
		break;
	      }
#endif
	    }
	  }


#ifdef HAVE_FREEIFADDRS
	  freeifaddrs(ifar);
#else
	  free(ifar);
#endif
	  return i;
	}

#elif defined(SIOCGLIFADDR)
	/* #warning "SIOCGLIFADDR code chosen" */
	{
	  /* Named IPv4 interface */
	  int sk2 = socket(af, SOCK_DGRAM, 0);
	  struct lifreq lifr;

	  memset(&lifr, 0, sizeof(lifr));
	  strncpy(lifr.lifr_name, ifname, sizeof(lifr.lifr_name));
	  lifr.lifr_addr.ss_family = af;
	  i = -1;
	  if (ioctl(sk2, SIOCGLIFADDR, &lifr) == 0) {
	    /* Got the IP address of the interface */
	    i = 0;
	    if (af == AF_INET)
	      memcpy(sap, &lifr.lifr_addr, sizeof(struct sockaddr_in));
#if defined(AF_INET6) && defined(INET6)
	    else if (af == AF_INET6)
	      memcpy(sap, &lifr.lifr_addr, sizeof(struct sockaddr_in6));
#endif
	    else
	      i = -1;
	  }
	  close(sk2);
	  return i;
	}

#elif defined(SIOCGIFADDR)
	/* #warning "SIOCGIFADDR code chosen" */
	{
	  int sk2 = socket(af, SOCK_DGRAM, 0);
	  struct ifreq ifr;

	  memset(&ifr, 0, sizeof(ifr));
	  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	  ifr.ifr_name[IFNAMSIZ-1] = 0;

	  ifr.ifr_addr.sa_family = af;

	  i = -1;
	  if (ioctl(sk2, SIOCGIFADDR, &ifr) == 0) {
	    /* Got the IP address of the interface */
	    i = 0;
	    if (af == AF_INET)
	      memcpy(sap, &ifr.ifr_addr, sizeof(struct sockaddr_in));
#if defined(AF_INET6) && defined(INET6)
	    else if (af == AF_INET6)
	      memcpy(sap, &ifr.ifr_addr, sizeof(struct sockaddr_in6));
#endif
	    else
	      i = -1;
	  }
	  close(sk2);
	  return i;
	}
#elif defined(SIOCGLIFCONF)

	/* #warning "SIOCGLIFCONF code chosen" */
	{
	  struct lifconf ifc;
	  int ifbufsize = 4 * sizeof(struct lifreq) + 4;
	  char *interfacebuf = (void*)malloc(ifbufsize);
	  int s, n;

	  if (!interfacebuf) {
	    return -2;
	  }

	  s = socket(af, SOCK_DGRAM, 0);

	  if (s < 0) {
	    free(interfacebuf);
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
	    interfacebuf = (void*)realloc(interfacebuf, ifbufsize);
	    memset(&lifc, 0, sizeof(lifc));
	    lifc.lifc_buf    = interfacebuf;
	    lifc.lifc_len    = ifbufsize;
	    lifc.lifc_family = af;
	    lifc.lifc_flags  = 0;
	    if (ioctl(s, SIOCGLIFCONF, (char *)&lifc) < 0) {
	      if (errno == EINVAL)
		continue;
	      if (errno == EINTR)
		continue;
	    }

	    if (lifc.lifc_len < (ifbufsize - 2*sizeof(struct lifreq)))
	      break;

	    /* Redo the query, perhaps didn't get them all.. */
	  }


	  /* Count how many addresses listed */

	  n = -1; /* return code ... */

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

	    if (strcasecmp(lifr->lifr_name, ifname) != 0)
	      continue; /* Not this interface.. */

	    /* Known address families ?
	       The one we scanned for ??*/

	    if (lifr->lifr_addr.sa_family != af)
	      continue; /* Not desired address family! */

	    /* Now, what do the flags say ? Are they alive ? */

#ifdef SIOCGLIFFLAGS
	    memset(&lifrf, 0, sizeof(struct lifreq));
	    strncpy(lifrf.lifr_name, ifname, sizeof(lifrf.lifr_name));

	    if (ioctl(s, SIOCGLIFFLAGS, (char *) &lifrf) < 0)
	      continue; /* Failed.. */

	    if (!(IFF_UP & lifrf.lifr_flags))
	      continue; /* Not alive */
#else
	    /* printf("ifr_flags=0x%x\n",lifr->lifr_flags); */

	    if (!(IFF_UP & lifr->lifr_flags))
	      continue; /* Not alive */
#endif

	    if (af == AF_INET) {
	      /* pick the whole sockaddr package! */
	      memcpy(sap, sa, sizeof(struct sockaddr_in));
	      n = 0;
	      break,
	    }

#if defined(AF_INET6) && defined(INET6)
	    if (af == AF_INET6) {
	      /* pick the whole sockaddr package! */
	      memcpy(sap, sa, sizeof(struct sockaddr_in6));
	      n = 0;
	      break,
	    }
#endif
	    break; /* 't was desired address family... */
	  }
	  close(s);
	  free(interfacebuf);
	  return n;
	}

#elif defined(SIOCGIFCONF)
	/* #warning "SIOCGIFCONF code chosen" */
	{
	  struct ifconf ifc;
	  int ifbufsize = 4 * sizeof(struct ifreq) + 4;
	  char *interfacebuf = (void*)malloc(ifbufsize);
	  int s, n;

	  if (!interfacebuf) {
	    return -2;
	  }

	  s = socket(af, SOCK_DGRAM, 0);

	  if (s < 0) {
	    free(interfacebuf);
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
	    interfacebuf = (void*)realloc(interfacebuf, ifbufsize);
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

	  n = -1; /* return code ... */

	  for (i = 0; i < ifc.ifc_len; ) {

	    struct ifreq *ifr = (struct ifreq *) &ifc.ifc_buf[i];
	    union sockaddr_uni *sa = (union sockaddr_uni *) &ifr->ifr_addr;
#ifdef SIOCGIFFLAGS
	    struct ifreq ifrf;
#endif

#if defined(SA_LEN)
	    if (SA_LEN(((struct sockaddr *)sa)) > sizeof(ifr->ifr_addr))
	      i += sizeof ifr->ifr_name + SA_LEN(((struct sockaddr *)sa));
	    else
#elif defined(HAVE_SA_LEN)
	      if (sa->sa.sa_len > sizeof ifr->ifr_addr)
		i += sizeof ifr->ifr_name + sa->sa.sa_len;
	      else
#endif
		i += sizeof *ifr;

	    if (strcasecmp(ifr->ifr_name, ifname) != 0)
	      continue; /* Not this interface.. */

	    /* Known address families ?
	       The one we scanned for ??*/

	    if (ifr->ifr_addr.sa_family != af)
	      continue; /* Not desired address family! */

	    /* Now, what do the flags say ? Are they alive ? */

#ifdef SIOCGIFFLAGS
	    memset(&ifrf, 0, sizeof(struct ifreq));
	    strncpy(ifrf.ifr_name, ifr->ifr_name, sizeof(ifrf.ifr_name));

	    if (ioctl(s, SIOCGIFFLAGS, (char *) &ifrf) < 0)
	      continue; /* Failed.. */

	    if (!(IFF_UP & ifrf.ifr_flags))
	      continue; /* Not alive */
#else
	    /* printf("ifr_flags=0x%x\n",ifr->ifr_flags); */

	    if (!(IFF_UP & ifr->ifr_flags))
	      continue; /* Not alive */
#endif

	    if (af == AF_INET) {
	      struct sockaddr_in *si4 = (void*)sa;
	      if (si4 == NULL) break;
	      /* pick the whole sockaddr package! */
	      memcpy(sap, &ifr->ifr_addr, sizeof(struct sockaddr_in));
	      n = 0;
	      break,
	    }

#if defined(AF_INET6) && defined(INET6)
	    if (af == AF_INET6) {
	      struct sockaddr_in6 *si6 = (void*)sa;
	      if (si6 == NULL) break;
	      /* pick the whole sockaddr package! */
	      memcpy(sap, &ifr->ifr_addr, sizeof(struct sockaddr_in6));
	      n = 0;
	      break,
	    }
#endif
	    break; /* 't was desired address family... */
	  }
	  close(s);
	  free(interfacebuf);
	  return n;
	}
#endif

}
