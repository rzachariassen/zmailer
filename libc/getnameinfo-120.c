/*
%%% copyright-cmetz-96
This software is Copyright 1996-1997 by Craig Metz, All Rights Reserved.
The Inner Net License Version 2 applies to this software.
You should have received a copy of the license with this software. If
you didn't get a copy, you may request one from <license@inner.net>.

*/
/* getnameinfo() v1.20 */
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#if INET6
#include <netinet6/in6.h>
#endif /* INET6 */
#if LOCAL
#include <sys/un.h>
#include <sys/utsname.h>
#endif /* LOCAL */
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "support.h"

#ifndef AF_LOCAL
#define AF_LOCAL AF_UNIX
#endif /* AF_LOCAL */

#ifndef min 
#define min(x,y) (((x) > (y)) ? (y) : (x))
#endif /* min */

#if HOSTTABLE
static int hosttable_lookup_name(int family, void *addr, char *name, int namelen, int flags)
{
  FILE *f;
  char buffer[1024];
  char addrbuf[16];
  char *c, *c2;
  int i;
  char *prevcname = NULL;

  if (!(f = fopen("/etc/hosts", "r")))
    return -EAI_SYSTEM;

  while(fgets(buffer, sizeof(buffer), f)) {
    if (c = strchr(buffer, '#'))
      *c = 0;

    c = buffer;
    while(*c && !isspace(*c)) c++;
    if (!*c)
      continue;

    *(c++) = 0;

    if (family == AF_INET)
      if (inet_pton(AF_INET, buffer, addrbuf) > 0)
	if (!memcmp(addrbuf, addr, sizeof(struct in_addr)))
	  goto build;

#if INET6
    if (family == AF_INET6)
      if (inet_pton(AF_INET6, buffer, addrbuf) > 0)
	if (!memcmp(addrbuf, addr, sizeof(struct in6_addr)))
	  goto build;
#endif /* INET6 */

    continue;

build:
    while(*c && isspace(*c)) c++;
    if (!*c)
      continue;

    c2 = c;
    while(*c2 && !isspace(*c2)) c2++;
    if (!*c2)
      continue;
    *c2 = 0;

    if ((flags & NI_NOFQDN) && (_res.options & RES_INIT) && _res.defdname[0] && (c2 = strstr(c + 1, _res.defdname)) && (*(--c2) == '.')) {
      *c2 = 0;
      i = min(c2 - c, namelen);
      strncpy(name, c, i);
    } else
      strncpy(name, c, namelen);

    fclose(f);
    return 0;
  };

  fclose(f);
  return 1;
};
#endif /* HOSTTABLE */

#if RESOLVER
#if INET6
static char hextab[] = { '0', '1', '2', '3', '4', '5', '6', '7',
                         '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
#endif /* INET6 */

struct rrheader {
  int16_t type;
  int16_t class;
  u_int32_t ttl;
  int16_t size;
};
#define RRHEADER_SZ 10

int resolver_lookup_name(const char *ptrname, char *name, int namelen, int flags)
{
  char answer[PACKETSZ];
  int answerlen;
  char dn[MAXDNAME];
  char *prevcname = NULL;
  void *p, *ep;
  int answers, i;

  if ((answerlen = res_search(ptrname, C_IN, T_PTR, answer, sizeof(answer))) < 0) {
    switch(h_errno) {
    case NETDB_INTERNAL:
      return -EAI_SYSTEM;
    case HOST_NOT_FOUND:
      return 1;
    case TRY_AGAIN:
      return -EAI_AGAIN; /* XXX */
    case NO_RECOVERY:
      return -EAI_FAIL;
    case NO_DATA:
      return 1;
    default:
      return -EAI_FAIL;
    };
  };

  p = answer;
  ep = answer + answerlen;
  
  if (answerlen < sizeof(HEADER))
    return -EAI_FAIL;
  {
    HEADER *h = (HEADER *)p;
    if (!h->qr || (h->opcode != QUERY) || (h->qdcount != htons(1)) || !h->ancount)
      return -EAI_FAIL;
    answers = ntohs(h->ancount);
  };
  p += sizeof(HEADER);

  if ((i = dn_expand(answer, ep, p, dn, sizeof(dn))) < 0)
    return -EAI_FAIL;
  p += i;

  if (p + 2*sizeof(u_int16_t) >= ep)
    return -EAI_FAIL;
  if ((ntohs(((u_int16_t *)p)[0]) != T_PTR) || (ntohs(((u_int16_t *)p)[1]) != C_IN))
    return -EAI_FAIL;
  p += 2*sizeof(u_int16_t);

  if ((i = dn_expand(answer, ep, p, dn, sizeof(dn))) < 0)
    return -EAI_FAIL;
  p += i;
  
  if (p + RRHEADER_SZ >= ep)
    return -EAI_FAIL;
  {
    struct rrheader *rrheader = (struct rrheader *)p;

    if ((ntohs(rrheader->type) != T_PTR) || (ntohs(rrheader->class) != C_IN))
      return -EAI_FAIL;
    i = ntohs(rrheader->size);
  };
  p += RRHEADER_SZ;
  
  if (p + i >= ep)
    return -EAI_FAIL;
  
  if (dn_expand(answer, ep, p, dn, sizeof(dn)) != i)
    return -EAI_FAIL;

  {
    char *c2;

    if ((flags & NI_NOFQDN) && (_res.options & RES_INIT) && _res.defdname[0] && (c2 = strstr(dn + 1, _res.defdname)) && (*(--c2) == '.')) {
      *c2 = 0;
      i = min(c2 - dn, namelen);
      strncpy(name, dn, i);
    } else
      strncpy(name, dn, namelen);
  };

  return 0;
};
#endif /* RESOLVER */

int getnameinfo(const struct sockaddr *sa, size_t addrlen, char *host, size_t hostlen, char *serv, size_t servlen, int flags)
{
  int serrno = errno;
  int rval;

  if (!sa || (addrlen != NRL_SA_LEN(sa)))
    return -EAI_FAIL;

  if (host && (hostlen > 0))
    switch(sa->sa_family) {
#if INET6
      case AF_INET6:
	if (flags & NI_NUMERICHOST)
	  goto inet6_noname;

	if (IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)sa)->sin6_addr)) {
	  struct sockaddr_in sin;
	  memset(&sin, 0, sizeof(struct sockaddr_in));
#if SALEN
	  sin.sin_len = sizeof(struct sockaddr_in);
#endif /* SALEN */
	  sin.sin_family = AF_INET;
	  sin.sin_port = ((struct sockaddr_in6 *)sa)->sin6_port;
	  sin.sin_addr.s_addr = ((u_int32_t *)&((struct sockaddr_in6 *)sa)->sin6_addr)[3];
	  if (!(rval = getnameinfo((struct sockaddr *)&sin, sizeof(struct sockaddr_in), host, hostlen, serv, servlen, flags | NI_NAMEREQD)))
	    return 0;
	  if (rval != -EAI_NONAME)
	    return rval;
	  goto inet6_noname;
	};

#if HOSTTABLE
	if ((rval = hosttable_lookup_name(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr, host, hostlen, flags)) < 0)
	  goto fail;
	
	if (!rval)
	  break;
#endif /* HOSTTABLE */
#if RESOLVER
	{
	  char ptrname[73];
	  {
	    int i;
	    char *c = ptrname;
	    u_int8_t *p = (u_int8_t *)&((struct sockaddr_in6 *)sa)->sin6_addr + sizeof(struct in6_addr) - 1;
	    
	    for (i = sizeof(struct in6_addr) / sizeof(u_int8_t); i > 0; i--, p--) {
	      *(c++) = hextab[*p & 0x0f];
	      *(c++) = '.';
	      *(c++) = hextab[(*p & 0xf0) >> 4];
	      *(c++) = '.';
	    };
	    strcpy(c, "ip6.int.");
	  };
	  
	  if ((rval = resolver_lookup_name(ptrname, host, hostlen, flags)) < 0)
	    goto fail;
	  
	  if (!rval)
	    break;
	};
#endif /* RESOLVER */

inet6_noname:
	if (flags & NI_NAMEREQD)
	  goto fail;
	
	if (!inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr, host, hostlen))
	  goto fail;
	break;
#endif /* INET6 */
      case AF_INET:
	if (flags & NI_NUMERICHOST)
	  goto inet_noname;

#if HOSTTABLE
	if ((rval = hosttable_lookup_name(AF_INET, &((struct sockaddr_in *)sa)->sin_addr, host, hostlen, flags)) < 0)
	  goto fail;

	if (!rval)
	  break;
#endif /* HOSTTABLE */
#if RESOLVER
	{
	  char ptrname[30];
	  u_int8_t *p = (u_int8_t *)&((struct sockaddr_in *)sa)->sin_addr;
	  sprintf(ptrname, "%d.%d.%d.%d.in-addr.arpa.", p[3], p[2], p[1], p[0]);
	  
	  if ((rval = resolver_lookup_name(ptrname, host, hostlen, flags)) < 0)
	    goto fail;

	  if (!rval)
	    break;
	};
#endif /* RESOLVER */

inet_noname:
	if (flags & NI_NAMEREQD) {
	  rval = -EAI_NONAME;
	  goto fail;
	};
	
	if (!inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr, host, hostlen))
	  goto fail;
	break;
#if LOCAL
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
#endif /* LOCAL */
      default:
        return -EAI_FAMILY;
    };

  if (serv && (servlen > 0))
    switch(sa->sa_family) {
      case AF_INET:
#if INET6
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
#if LOCAL
      case AF_LOCAL:
	strncpy(serv, ((struct sockaddr_un *)sa)->sun_path, servlen);
	break;
#endif /* LOCAL */
    };

  if (host && (hostlen > 0))
    host[hostlen-1] = 0;
  if (serv && (servlen > 0))
    serv[servlen-1] = 0;
  errno = serrno;
  return 0;

fail:
  errno = serrno;
  if (rval == 1)
    return EAI_FAIL;
  else
    return -rval;
};
