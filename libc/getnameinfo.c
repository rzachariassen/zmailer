/*
 * Generalized adaptation to ZMailer libc fill-in use by
 * Matti Aarnio <mea@nic.funet.fi> 1997
 *
 * The original version was a bit too much Linux specific...
 */

/*
%%% copyright-cmetz-96
This software is Copyright 1996-1997 by Craig Metz, All Rights Reserved.
The Inner Net License Version 2 applies to this software.
You should have received a copy of the license with this software. If
you didn't get a copy, you may request one from <license@inner.net>.

*/
/* getnameinfo() v1.20 */

#include "hostenv.h"

#include <sys/types.h>
#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
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

#include <sys/un.h>
#include <sys/utsname.h>

#include <netdb.h>
#if !defined(EAI_AGAIN) || !defined(NI_NOFQDN)
#include "netdb6.h"
#endif

#include <errno.h>
#include <string.h>
#include <arpa/nameser.h>
#include <resolv.h>

extern int h_errno;

#ifndef AF_LOCAL
#define AF_LOCAL AF_UNIX
#endif /* AF_LOCAL */

#include <ctype.h>
#include "libc.h"

#ifndef min 
#define min(x,y) (((x) > (y)) ? (y) : (x))
#endif /* min */

static int hosttable_lookup_name __((int, void*, char *, int, int));

static int
hosttable_lookup_name(family, addr, name, namelen, flags)
int family;
void *addr;
char *name;
int namelen;
int flags;
{
  FILE *f;
  char buffer[1024];
  char addrbuf[16];
  char *c, *c2;
  int i;

  f = fopen("/etc/hosts", "r");
  if (f == NULL)
    return -(EAI_SYSTEM);

  while (fgets(buffer, sizeof(buffer), f)) {
    c = strchr(buffer, '#');
    if (c != NULL)
      *c = 0;

    c = buffer;
    while (*c && !isspace(*c)) c++;
    if (!*c)
      continue;

    *(c++) = 0;

    if (family == AF_INET)
      if (inet_pton(AF_INET, buffer, (void*)addrbuf) > 0)
	if (memcmp(addrbuf, addr, sizeof(struct in_addr)) != 0)
	  goto build;

#if defined(INET6) && defined(AF_INET6)
    if (family == AF_INET6)
      if (inet_pton(AF_INET6, buffer, (void*)addrbuf) > 0)
	if (memcmp(addrbuf, addr, sizeof(struct in6_addr)) != 0)
	  goto build;
#endif /* INET6 */

    continue;

  build:
    while (*c && isspace(*c)) c++;
    if (!*c)
      continue;

    c2 = c;
    while (*c2 && !isspace(*c2)) c2++;
    if (!*c2)
      continue;
    *c2 = 0;

    if ((flags & NI_NOFQDN) && (_res.options & RES_INIT) && _res.defdname[0] &&
	((c2 = strstr(c + 1, _res.defdname)) != NULL) && (*(--c2) == '.')) {
      *c2 = 0;
      i = min(c2 - c, namelen);
      strncpy(name, c, i);
    } else
      strncpy(name, c, namelen);

    fclose(f);
    return 0;
  }

  fclose(f);
  return 1;
}

#if defined(INET6) && defined(AF_INET6)
static char hextab[] = { '0', '1', '2', '3', '4', '5', '6', '7',
                         '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
#endif /* INET6 */

struct rrheader {
  short type;
  short class;
#if SIZEOF_INT == 4
#define UINT4 unsigned int
  UINT4 ttl;
#else
#if SIZEOF_LONG == 4
#define UINT4 unsigned long
  UINT4 ttl;
#else
  ERROR:ERROR: "Can't determine proper type for 4 byte words.."
#endif
#endif
  short size;
};

#define RRHEADER_SZ 10
#ifndef HFIXEDSZ
#define HFIXEDSZ 12
#endif

static int resolver_lookup_name __((const char *, char *, int, int));

static int
resolver_lookup_name(ptrname, name, namelen, flags)
const char *ptrname;
char *name;
int namelen;
int flags;
{
  char answer[PACKETSZ];
  int answerlen;
  char dn[MAXDNAME];
  char *p, *ep;
  int answers, qdcount, i;

  answerlen = res_search(ptrname, C_IN, T_PTR, (void*)answer, sizeof(answer));

  if (answerlen < 0) {
    switch(h_errno) {
#ifdef NETDB_INTERNAL
    case NETDB_INTERNAL:
      return -(EAI_SYSTEM);
#endif
    case HOST_NOT_FOUND:
      return 1;
    case TRY_AGAIN:
      return -(EAI_AGAIN); /* XXX */
    case NO_RECOVERY:
      return -(EAI_FAIL);
    case NO_DATA:
      return 1;
    default:
      return -(EAI_FAIL);
    }
  }

  p = answer;
  ep = answer + answerlen;

  if (answerlen < HFIXEDSZ) {
    return -(EAI_FAIL);
  } else {
    HEADER *h = (HEADER *)p;
    qdcount = ntohs(h->qdcount);
    answers = ntohs(h->ancount);
    if (!h->qr || (h->opcode != QUERY) || (qdcount != 1) || !answers) {
      return -(EAI_FAIL);
    }
  }
  p += HFIXEDSZ;

  /* question(s) to skip.. */
  for (; qdcount > 0; --qdcount) {
    int qt, qc;
    i = dn_expand((void*)answer, (void*)ep, (void*)p, dn, sizeof(dn));
#if 0
#if	defined(BIND_VER) && (BIND_VER >= 473)
#else	/* !defined(BIND_VER) || (BIND_VER < 473) */
    i = dn_skip((const unsigned char*)p);
#endif	/* defined(BIND_VER) && (BIND_VER >= 473) */
#endif
    p += i;
    if (i < 0) {
      return -(EAI_FAIL);
    }
    qt = _getshort(p); p += 2;
    qc = _getshort(p); p += 2;
#if 0
    if (qt != T_PTR || qc != C_IN) {
      return -(EAI_FAIL);
    }
#endif
  }

  while (answers-- > 0) {

    int atype, aclass;

    i = dn_expand((void*)answer, (void*)ep, (void*)p, dn, sizeof(dn));
    if (i < 0)
      return -(EAI_FAIL);
    p += i;

    if (p + 10 > ep) { /* Too little data! */

      return -(EAI_FAIL);

    } else {

      atype  = _getshort(p); p += 2; /* type */
      aclass = _getshort(p); p += 2; /* class */
      if (aclass != C_IN) {
	return -(EAI_FAIL);
      }
      p += 4;              /* TTL  */
      i = _getshort(p); p += 2;      /* size */

    }

    if (p + i > ep) /* Too little data! */
      return -(EAI_FAIL);

    if (dn_expand((void*)answer, (void*)ep, (void*)p, dn, sizeof(dn)) != i)
      return -(EAI_FAIL);

    else {
      /* XXX: see if the object is T_CNAME !
	 (and what others you may encounter here..) */
      char *c2;

      if ((flags & NI_NOFQDN) && (_res.options & RES_INIT) && _res.defdname[0] &&
	  ((c2 = strstr(dn + 1, _res.defdname)) != NULL) && (*(--c2) == '.')) {
	*c2 = 0;
	i = min(c2 - dn, namelen);
	strncpy(name, dn, i);
      } else
	strncpy(name, dn, namelen);
    }

    p += i;

  } /* All answers */

  return 0;
}

int getnameinfo(sa, addrlen, host, hostlen, serv, servlen, flags)
const struct sockaddr *sa;
size_t addrlen;
char *host;
size_t hostlen;
char *serv;
size_t servlen;
int flags;
{
  int serrno = errno;
  int rval = 0;
  int my_alen;

  if (!sa || addrlen < 1)
    return -(EAI_FAIL);

  /* my_alen = NRL_SA_LEN(sa); */
#ifdef HAVE_SA_LEN
  my_alen = sa->sa_len;
#else
  my_alen = -1; /* Totally invalid value */
  if (sa->sa_family == AF_INET)
    my_alen = sizeof(struct sockaddr_in);
#if defined(INET6) && defined(AF_INET6)
  if (sa->sa_family == AF_INET6)
    my_alen = sizeof(struct sockaddr_in6);
#endif
#endif

  if (addrlen != my_alen)
    return -(EAI_FAIL);

  if (host && (hostlen > 0))
    switch (sa->sa_family) {
#if defined(INET6) && defined(AF_INET6)
    case AF_INET6:
      {
	struct in6_addr *sa6;
	sa6 = &((struct sockaddr_in6 *)sa)->sin6_addr;

	if (flags & NI_NUMERICHOST)
	  goto inet6_noname;

#ifndef IN6_IS_ADDR_UNSPECIFIED
# define IN6_IS_ADDR_UNSPECIFIED(a) /* Alignment guaranteed.. */ \
	((((UINT4 *)(a))[0] == 0) && (((UINT4 *)(a))[1] == 0) && \
	 (((UINT4 *)(a))[2] == 0) && (((UINT4 *)(a))[3] == 0))
#endif

	if (IN6_IS_ADDR_UNSPECIFIED(sa6)) {
	  strncpy(host, "*", hostlen);
	  break;
	}

#ifndef IN6_IS_ADDR_V4MAPPED
# define IN6_IS_ADDR_V4MAPPED(a) /* Alignment guaranteed.. */ \
	((((UINT4 *)(a))[0] == 0) && (((UINT4 *)(a))[1] == 0) && \
	 (((UINT4 *)(a))[2] == htonl(0xffff)))
#endif

	  if (IN6_IS_ADDR_V4MAPPED(sa6)) {
	    struct sockaddr_in si4;
	    memset(&si4,  0, sizeof(struct sockaddr_in));
#if HAVE_SA_LEN
	    si4.sin_len    = sizeof(struct sockaddr_in);
#endif /* SALEN */
	    si4.sin_family = AF_INET;
	    si4.sin_port   = ((struct sockaddr_in6 *)sa)->sin6_port;
	    si4.sin_addr.s_addr = ((UINT4 *)sa6)[3];
	    rval = getnameinfo((struct sockaddr *)&si4,
			       sizeof(struct sockaddr_in),
			       host, hostlen,
			       serv, servlen,
			       flags | NI_NAMEREQD);
	    if (rval == 0)
	      return 0;
	    if (rval != -(EAI_NONAME))
	      return rval;
	    goto inet6_noname;
	  }

	rval = hosttable_lookup_name(AF_INET6,(void*)sa6,host,hostlen,flags);
	if (rval < 0)
	  goto fail;

	if (!rval)
	  break;
	else {
	  char ptrname[73];
	  int i;
	  char *c = ptrname;
	  unsigned char *p = (unsigned char *)sa6 + sizeof(struct in6_addr) - 1;

	  i = sizeof(struct in6_addr) / sizeof(unsigned char);
	  for (; i > 0; --i, --p) {
	    *(c++) = hextab[*p & 0x0f];
	    *(c++) = '.';
	    *(c++) = hextab[(*p & 0xf0) >> 4];
	    *(c++) = '.';
	  }
	  strcpy(c, "ip6.int.");

	  rval = resolver_lookup_name(ptrname, host, hostlen, flags);
	  if (rval < 0)
	    goto fail;

	  if (rval == 0)
	    break;
	}

      inet6_noname:
	if (flags & NI_NAMEREQD)
	  goto fail;

	if (!inet_ntop(AF_INET6, (void*)sa6, host, hostlen))
	  goto fail;
      }
      break;
#endif /* INET6 */
    case AF_INET:
      {
	const struct in_addr *sa4;
	sa4 = &((const struct sockaddr_in *)sa)->sin_addr;

	if (flags & NI_NUMERICHOST)
	  goto inet_noname;

        if (sa4->s_addr == 0) {
          strncpy(host, "*", hostlen);
          break;
        }

	rval = hosttable_lookup_name(AF_INET,(void*)sa4, host, hostlen, flags);
	if (rval < 0)
	  goto fail;

	if (rval == 0)
	  break;
	else {
	  char ptrname[30];
	  unsigned char *p = (unsigned char *)sa4;
	  sprintf(ptrname, "%d.%d.%d.%d.in-addr.arpa.",
		  p[3], p[2], p[1], p[0]);
	  
	  rval = resolver_lookup_name(ptrname, host, hostlen, flags);
	  if (rval < 0)
	    goto fail;

	  if (rval == 0)
	    break;
	}

      inet_noname:
	if (flags & NI_NAMEREQD) {
	  rval = -(EAI_NONAME);
	  goto fail;
	}

	if (!inet_ntop(AF_INET, (void*)sa4, host, hostlen))
	  goto fail;
      }
      break;

    case AF_LOCAL:
      if (!(flags & NI_NUMERICHOST)) {
	struct utsname utsname;
	  
	if (!uname(&utsname)) {
	  strncpy(host, utsname.nodename, hostlen);
	  break;
	}
      }
	
      if (flags & NI_NAMEREQD)
	goto fail;
	
      strncpy(host, "localhost", hostlen);
      break;

    default:
      return -(EAI_FAMILY);
    }

  if (serv && (servlen > 0))
    switch(sa->sa_family) {
    case AF_INET:
#if defined(INET6) && defined(AF_INET6)
    case AF_INET6:
#endif /* INET6 */
      if (!(flags & NI_NUMERICSERV)) {
	struct servent *s;
	s = getservbyport(((const struct sockaddr_in *)sa)->sin_port,
			  (flags & NI_DGRAM) ? "udp" : "tcp");
	if (s != NULL) {
	  strncpy(serv, s->s_name, servlen);
	  break;
	}
	if (((struct sockaddr_in *)sa)->sin_port == 0) {
	  strncpy(serv, "*", servlen);
	  break;
	}
      }
      if (servlen >= 6)
	sprintf(serv, "%u", ntohs(((const struct sockaddr_in *)sa)->sin_port));
      else
	strncpy(serv, "*99999", servlen);
      break;

    case AF_LOCAL:
      strncpy(serv, ((const struct sockaddr_un *)sa)->sun_path, servlen);
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
  if (rval == 1)
    return EAI_FAIL;
  else
    return -rval;
}
