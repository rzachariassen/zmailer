/*
%%% copyright-cmetz
This software is Copyright 1996 by Craig Metz, All Rights Reserved.
The Inner Net License Version 2 applies to this software.
You should have received a copy of the license with this software. If
you didn't get a copy, you may request one from <license@inner.net>.

v0.02
*/
#include "hostenv.h"
#include <sys/types.h>
#include <sys/socket.h>

#ifdef __linux__ /* 2.0 series of Linux kernels has this, but wrong.. */
# define in_addr6 in6_addr
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

#include <sys/un.h>
#include <sys/utsname.h>

#include <netdb.h>
#ifndef EAI_AGAIN
# include "netdb6.h"
#endif
#include <errno.h>
#include <string.h>

/* #include "support.h" */

#ifndef AF_LOCAL
#define AF_LOCAL AF_UNIX
#endif /* AF_LOCAL */

#ifndef MAXHOSTNAMELEN
# define MAXHOSTNAMELEN 256
#endif

#if HOSTTABLE
struct hostent *_addr2hostname_hosts(const char *, int, int);
#endif /* HOSTTABLE */

#ifndef min 
#define min(x,y) (((x) > (y)) ? (y) : (x))
#endif /* min */

extern char *inet_ntop ();

static char *domain = NULL;
static char domainbuffer[MAXHOSTNAMELEN] = "";

char *nrl_domainname(void)
{
  static int first = 1;

  if (first) {
    char *c, buf[MAXHOSTNAMELEN];
    struct hostent *h;

    first = 0;

    if ((h = gethostbyname("localhost")) && (c = strchr(h->h_name, '.')))
      return strcpy(domain = domainbuffer, ++c);

    if (!gethostname(domainbuffer, sizeof(domainbuffer))) {
      if (c = strchr(domainbuffer, '.'))
        return (domain = ++c);

      if ((h = gethostbyname(domainbuffer)) && (c = strchr(h->h_name, '.')))
        return strcpy(domain = domainbuffer, ++c);
    }

    {
      struct in_addr in_addr;

      in_addr.s_addr = htonl(0x7f000001);

      if ((h = gethostbyaddr((const char *)&in_addr, sizeof(struct in_addr), AF_INET)) && (c = strchr(h->h_name, '.')))
        return strcpy(domain = domainbuffer, ++c);
    }

    return NULL;
  }

  return domain;
}


int getnameinfo(const struct sockaddr *sa, size_t addrlen, char *host, size_t hostlen, char *serv, size_t servlen, int flags)
{
  int serrno = errno;

  if (!sa || (addrlen != NRL_SA_LEN(sa)))
    return -1;

  if (host && (hostlen > 0))
    switch(sa->sa_family) {
      case AF_INET:
#ifdef AF_INET6
      case AF_INET6:
#endif /* AF_INET6 */
	if (!(flags & NI_NUMERICHOST)) {
	  struct hostent *h = NULL;
#if HOSTTABLE
#ifdef AF_INET6
	  if (sa->sa_family == AF_INET6)
	    h = _addr2hostname_hosts((void *)&(((struct sockaddr_in6 *)sa)->sin6_addr), sizeof(struct in6_addr), AF_INET6);
	  else
#endif /* AF_INET6 */
	    h = _addr2hostname_hosts((void *)&(((struct sockaddr_in *)sa)->sin_addr), sizeof(struct in_addr), AF_INET);
#endif /* HOSTTABLE */

	  if (!h) {
#ifdef AF_INET6
	    if (sa->sa_family == AF_INET6)
	      h = gethostbyaddr((void *)&(((struct sockaddr_in6 *)sa)->sin6_addr), sizeof(struct in6_addr), AF_INET6);
	    else
#endif /* INET6 */
	      h = gethostbyaddr((void *)&(((struct sockaddr_in *)sa)->sin_addr), sizeof(struct in_addr), AF_INET);
	    endhostent();
	  };
	  
	  if (h) {
	    if (flags & NI_NOFQDN) {
	      char *c, *c2;
	      if ((c = nrl_domainname()) && (c = strstr(h->h_name, c)) && (c != h->h_name) && (*(--c) == '.')) {
		strncpy(host, h->h_name, min(hostlen, (c - h->h_name)));
		break;
	      };
	    };
	    strncpy(host, h->h_name, hostlen);
	    break;
	  }
	}
	
	if (flags & NI_NAMEREQD)
	  goto fail;
	
        {
	  const char *c;
#ifdef AF_INET6
	  if (sa->sa_family == AF_INET6)
	    c = inet_ntop(AF_INET6, (void *)&(((struct sockaddr_in6 *)sa)->sin6_addr), host, hostlen);
	  else
#endif /* INET6 */
	    c = inet_ntop(AF_INET, (void *)&(((struct sockaddr_in *)sa)->sin_addr), host, hostlen);

	  if (!c)
	    goto fail;
	}
	break;
      case AF_LOCAL:
	if (!(flags & NI_NUMERICHOST)) {
	  struct utsname utsname;
	  
	  if (!uname(&utsname)) {
	    strncpy(host, utsname.nodename, hostlen);
	    break;
	  };
	};
	
	if (flags & NI_NAMEREQD)
	  goto fail;
	
	strncpy(host, "localhost", hostlen);
	break;
      default:
        return -1;
    }

  if (serv && (servlen > 0))
    switch(sa->sa_family) {
      case AF_INET:
#ifdef AF_INET6
      case AF_INET6:
#endif /* INET6 */
	if (!(flags & NI_NUMERICSERV)) {
	  struct servent *s;
	  if (s = getservbyport(((struct sockaddr_in *)sa)->sin_port, (flags & NI_DGRAM) ? "udp" : "tcp")) {
	    strncpy(serv, s->s_name, servlen);
	    break;
	  };
	};
	snprintf(serv, servlen, "%d", ntohs(((struct sockaddr_in *)sa)->sin_port));
	break;
      case AF_LOCAL:
	strncpy(serv, ((struct sockaddr_un *)sa)->sun_path, servlen);
	break;
    }

  if (host && (hostlen > 0))
    host[hostlen-1] = 0;
  if (serv && (servlen > 0))
    serv[servlen-1] = 0;
  errno = serrno;
  return 0;

fail:
  errno = serrno;
  return -1;
}
