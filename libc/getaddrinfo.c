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
/* getaddrinfo() v1.22; v1.26, v1.27(w/o debug code) */

/* To do what POSIX says, even when it's broken, define: */
/* #define BROKEN_LIKE_POSIX 1 */
/* Note: real apps will break if you define this, while nothing other than a
   conformance test suite should have a problem with it undefined */

#include "hostenv.h"
#include <sys/types.h>
#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <sys/socket.h>

#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/un.h>

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

#include <netdb.h>
#if !defined(EAI_AGAIN) || !defined(AI_NONAME)
#include "netdb6.h"
#endif

#include <arpa/nameser.h>
#include <resolv.h>

extern int h_errno;

#ifndef AF_LOCAL
#define AF_LOCAL AF_UNIX
#endif /* AF_LOCAL */
#ifndef PF_LOCAL
#define PF_LOCAL PF_UNIX
#endif /* PF_LOCAL */
#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif /* UNIX_PATH_MAX */

#undef AF_LOCAL /* We DO NOT do AF_LOCAL/AF_UNIX stuff... */

#include <ctype.h>
#include "libc.h"

#ifndef T_AAAA
# define T_AAAA 28 /* IPv6 address record.  Codeless w/o INET6 */
#endif

#define GAIH_OKIFUNSPEC 0x0100
#define GAIH_EAI        ~(GAIH_OKIFUNSPEC)

static struct addrinfo nullreq =
{ 0, PF_UNSPEC, 0, 0, 0, NULL, NULL, NULL };

struct gaih_service {
  char *name;
  int num;
};

struct gaih_servtuple {
  struct gaih_servtuple *next;
  int socktype;
  int protocol;
  int port;
};

static struct gaih_servtuple nullserv = {
  NULL, 0, 0, 0
};

struct gaih_addrtuple {
  struct gaih_addrtuple *next;
  int family;
  char addr[16];
  char *cname;
};

struct gaih_typeproto {
  int socktype;
  int protocol;
  char *name;
};

static int hosttable_lookup_addr __((const char *name,
				     const struct addrinfo *req,
				     struct gaih_addrtuple **pat));

static int
hosttable_lookup_addr(name, req, pat)
const char *name;
const struct addrinfo *req;
struct gaih_addrtuple **pat;
{
  FILE *f;
  char buffer[1024];
  char *c, *c2;
  int rval = 1;
  char *prevcname = NULL;

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

    while (*c && isspace(*c)) c++;
    if (!*c)
      continue;

    c2 = strstr(c, name);
    if (c2 == NULL)
      continue;

    if (*(c2 - 1) && !isspace(*(c2 - 1)))
      continue;

    c2 += strlen(name);
    if (*c2 && !isspace(*c2))
      continue;

    c2 = c;
    while (*c2 && !isspace(*c2)) c2++;
    if (!*c2)
      continue;
    *c2 = 0;

    if (*pat == NULL) {
      *pat = malloc(sizeof(struct gaih_addrtuple));
      if (*pat == NULL)
	return -(EAI_MEMORY);
    }

    memset(*pat, 0, sizeof(struct gaih_addrtuple));

    if (!req->ai_family || (req->ai_family == AF_INET))
      if (inet_pton(AF_INET, buffer, (void*)((*pat)->addr)) > 0) {
	(*pat)->family = AF_INET;
	goto build;
      }

#if defined(INET6) && defined(AF_INET6)
    if (!req->ai_family || (req->ai_family == AF_INET6))
      if (inet_pton(AF_INET6, buffer, (void*)((*pat)->addr)) > 0) {
	(*pat)->family = AF_INET6;
	goto build;
      }
#endif /* INET6 */

    continue;

build:
    if (req->ai_flags & AI_CANONNAME) {
      if (prevcname && !strcmp(prevcname, c))
	(*pat)->cname = prevcname;
      else
	prevcname = (*pat)->cname = strdup(c);
    }

    pat = &((*pat)->next);

    rval = 0;
  }

  fclose(f);
  return (rval);
}

#ifndef HFIXEDSZ
#define HFIXEDSZ 12
#endif
#ifndef RRHEADER_SZ
#define RRHEADER_SZ 10
#endif

static int resolver_lookup_addr __((const char *name, int type,
				    const struct addrinfo *req,
				    struct gaih_addrtuple **pat,
				    FILE *vlog));

static int
resolver_lookup_addr(name, type, req, pat, vlog)
const char *name;
int type;
const struct addrinfo *req;
struct gaih_addrtuple **pat;
FILE *vlog;
{
  char answer[PACKETSZ];
  int answerlen;
  char dn[/* MAXDNAME */ 128];
  char *prevcname = NULL;
  char *p, *ep;
  int answers, qdcount, i, j;
  int rclass;

  answerlen = res_search(name, C_IN, type, (void*)answer, sizeof(answer));
  if (answerlen < 0) {
    switch(h_errno) {
#ifdef NETDB_INTERNAL
    case NETDB_INTERNAL:
      if (vlog)
	fprintf(vlog,"res_search() yields NETDB_INTERNAL error for lookup of name='%s', type=%d\n",name,type);
      return -(EAI_SYSTEM);
#endif
    case HOST_NOT_FOUND:
      return 1;
    case TRY_AGAIN:
      return -(EAI_AGAIN); /* XXX */
    case NO_RECOVERY:
      if (vlog) fprintf(vlog, "res_search('%s',C_IN,type=%d) -> NO_RECOVERY error\n", name, type);
      return -(EAI_FAIL);
    case NO_DATA:
      return 1;
    default:
      if (vlog) fprintf(vlog, "res_search() yields unknown h_errno value: %d\n", h_errno);
      return -(EAI_FAIL);
    }
  }

  p  = answer;
  ep = answer + answerlen;

  if (answerlen < HFIXEDSZ) {
    if (vlog)
      fprintf(vlog,"res_search() yielded answer with too small reply: %d ( < 10 )\n", answerlen);
    return -(EAI_FAIL);
  } else {
    HEADER *h = (HEADER *)p; /* This is aligned block, anything after this
				may be nonaligned */
    qdcount = ntohs(h->qdcount);
    answers = ntohs(h->ancount);
    if (!h->qr || (h->opcode != QUERY) || (qdcount != 1) || !answers) {
      if (vlog) fprintf(vlog, "eaifail%d\n",__LINE__);
      return -(EAI_FAIL);
    }
  }
  p += HFIXEDSZ;

  dn[0] = 0;
  /* Question playback analysis */
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
      if (vlog) fprintf(vlog, "eaifail%d\n",__LINE__);
      return -(EAI_FAIL);
    }
    qt = _getshort(p); p += 2;
    qc = _getshort(p); p += 2;
#if 0
    if (qt != type || qc != C_IN) {
      if (vlog) fprintf(vlog, "eaifail%d\n",__LINE__);
      return -(EAI_FAIL);
    }
#endif
    if (qc != C_IN)
      return -(EAI_FAIL);
  }

  if (vlog)
    fprintf(vlog,"resolver(): question skipped, dn='%s', first answer at p=%d  answers=%d\n", dn, (int)(p-answer), (int)answers);

  /* Answer analysis */
  for ( ; answers > 0; --answers) {
    i = dn_expand((void*)answer, (void*)ep, (void*)p, dn, sizeof(dn));
    if (i < 0) {
      if (vlog)
	fprintf(vlog, "resolver() dn_expand() fail; eof-p=%d, p-start=%d\n",
		(int)(ep-p), (int)(p-answer));
      return -(EAI_FAIL);
    }
    p += i;

    if (p + RRHEADER_SZ > ep) { /* Too little data! */
      if (vlog) fprintf(vlog, "resolver(): Out of data in reply [1]\n");
      return -(EAI_FAIL);
    } else {
      j = _getshort(p);      p += 2; /* type */
      rclass = _getshort(p); p += 2; /* class */
      if (rclass != C_IN) {
	if (vlog) fprintf(vlog, "resolver() reply block class info != C_IN: %d\n", rclass );
	return -(EAI_FAIL);
      }
      p += 4;              /* TTL  */
      i = _getshort(p); p += 2;      /* size */
    }

    if (p + i > ep) {
      if (vlog) fprintf(vlog, "resolver(): Out of data in reply [2]\n");
      return -(EAI_FAIL);
    }

    if (j == type) {
      while (*pat)
	pat = &((*pat)->next);

      switch (type) {
        case T_A:
	  if (i != 4) {
	    if (vlog) fprintf(vlog, "eaifail@%s:%d; A size = %d != 4\n",__FILE__, __LINE__, i);
	    return -(EAI_FAIL);
	  }

	  *pat = malloc(sizeof(struct gaih_addrtuple));
	  if (*pat == NULL)
	    return -(EAI_MEMORY);
	  memset(*pat, 0, sizeof(struct gaih_addrtuple));

	  (*pat)->family = AF_INET;
	  break;

#if defined(INET6) && defined(AF_INET6)
        case T_AAAA:
	  if (i != 16) {
	    if (vlog) fprintf(vlog, "eaifail@%s:%d; AAAA size = %d != 16\n",__FILE__,__LINE__, i);
	    return -(EAI_FAIL);
	  }

	  *pat = malloc(sizeof(struct gaih_addrtuple));
	  if (*pat == NULL)
	    return -(EAI_MEMORY);
	  memset(*pat, 0, sizeof(struct gaih_addrtuple));

	  (*pat)->family = AF_INET6;
	  break;
#endif /* INET6 */
        default:
	  p += i;
	  continue; /* Skip non T_A / T_AAAA entries */
	  break;
      }
      memcpy((*pat)->addr, p, i);
    
      if (req->ai_flags & AI_CANONNAME) {
	if (prevcname && !strcmp(prevcname, dn))
	  (*pat)->cname = prevcname;
	else
	  prevcname = (*pat)->cname = strdup(dn);
      }
    }
    p += i;
  }

  return 0;
}

#ifdef AF_LOCAL
static int gaih_local __((const char *name, const struct gaih_service *service,
			  const struct addrinfo *req, struct addrinfo **pai,
			  FILE *vlog));

static int
gaih_local(name, service, req, pai, vlog)
const char *name;
const struct gaih_service *service;
const struct addrinfo *req;
struct addrinfo **pai;
FILE *vlog;
{
  struct utsname utsname;
  int newsize;
  struct sockaddr_un *saun;

  if (name || (req->ai_flags & AI_CANONNAME))
    if (uname(&utsname) != 0) {
      return -(EAI_SYSTEM);
    }

  if (name != NULL) {
    if (strcmp(name, "localhost") != 0 &&
	strcmp(name, "local")     != 0 &&
	strcmp(name, "unix")      != 0 &&
	strcmp(name, utsname.nodename) != 0)
      return (GAIH_OKIFUNSPEC | -(EAI_NONAME));
  }

  /* I am conservative, and suspect (seriously) compiler qualities
     in handling complex convoluted "t:a?b" expressions... [mea] */
  newsize  = sizeof(struct addrinfo) + sizeof(struct sockaddr_un);
  newsize += ((req->ai_flags & AI_CANONNAME) ?
	      (strlen(utsname.nodename) + 1): 0);
  *pai = malloc(newsize);
  if (*pai == NULL)
    return -(EAI_MEMORY);

  (*pai)->ai_next     = NULL;
  (*pai)->ai_flags    = req->ai_flags;
  (*pai)->ai_family   = AF_LOCAL;
  (*pai)->ai_socktype = req->ai_socktype ? req->ai_socktype : SOCK_STREAM;
  (*pai)->ai_protocol = req->ai_protocol;
  (*pai)->ai_addrlen  = sizeof(struct sockaddr_un);
  (*pai)->ai_addr     = (void *)((char *)(*pai) + sizeof(struct addrinfo));
  saun = (struct sockaddr_un *) (*pai)->ai_addr;
#if HAVE_SA_LEN
  saun->sun_len = sizeof(struct sockaddr_un);
#endif /* SALEN */
  saun->sun_family = AF_LOCAL;
  memset(saun->sun_path, 0, UNIX_PATH_MAX);
  if (service != NULL) {
    char *c = strchr(service->name, '/');
    if (c != NULL) {
      if (strlen(service->name) >= sizeof(saun->sun_path))
        return (GAIH_OKIFUNSPEC | -(EAI_SERVICE));
      strcpy(saun->sun_path, service->name);
    } else {
      if (strlen(P_tmpdir "/") + 1 + strlen(service->name) >= sizeof(saun->sun_path))
        return (GAIH_OKIFUNSPEC | -(EAI_SERVICE));
      strcpy(saun->sun_path, P_tmpdir "/");
      strcat(saun->sun_path, service->name);
    }
  } else {
    if (!tmpnam(saun->sun_path))
      return (-(EAI_SYSTEM) | GAIH_OKIFUNSPEC);
  }
  if (req->ai_flags & AI_CANONNAME) {
    (*pai)->ai_canonname = ((char *)(*pai) + sizeof(struct addrinfo) +
			    sizeof(struct sockaddr_un));
    strcpy((*pai)->ai_canonname, utsname.nodename);
  } else
    (*pai)->ai_canonname = NULL;
  return 0;
}
#endif

static struct gaih_typeproto gaih_inet_typeproto[] = {
  { 0, 0, NULL },
  { SOCK_STREAM, IPPROTO_TCP, "tcp" },
  { SOCK_DGRAM, IPPROTO_UDP, "udp" },
  { 0, 0, NULL }
};

static int gaih_inet_serv __((char *servicename, struct gaih_typeproto *tp,
			      struct gaih_servtuple **st));

static int
gaih_inet_serv(servicename, tp, st)
char *servicename;
struct gaih_typeproto *tp;
struct gaih_servtuple **st;
{
  struct servent *s;

  s = getservbyname(servicename, tp->name);
  if (s == NULL)
    return (GAIH_OKIFUNSPEC | -(EAI_SERVICE));

  *st = malloc(sizeof(struct gaih_servtuple));
  if (*st == NULL)
    return -(EAI_MEMORY);

  (*st)->next     = NULL;
  (*st)->socktype = tp->socktype;
  (*st)->protocol = tp->protocol;
  (*st)->port     = s->s_port;

  return 0;
}

static int gaih_inet __((const char *name, const struct gaih_service *service,
			 const struct addrinfo *req, struct addrinfo **pai,
			 FILE *vlog));

static int
gaih_inet(name, service, req, pai, vlog)
const char *name;
const struct gaih_service *service;
const struct addrinfo *req;
struct addrinfo **pai;
FILE *vlog;
{
  struct gaih_typeproto *tp = gaih_inet_typeproto;
  struct gaih_servtuple *st = &nullserv;
  struct gaih_addrtuple *at = NULL;
  int i;

  if (req->ai_protocol || req->ai_socktype) {
    for (tp++; tp->name &&
	   ((req->ai_socktype != tp->socktype) || !req->ai_socktype) && 
	   ((req->ai_protocol != tp->protocol) || !req->ai_protocol); tp++);
    if (!tp->name) {
      if (req->ai_socktype)
	return (GAIH_OKIFUNSPEC | -(EAI_SOCKTYPE));
      else
	return (GAIH_OKIFUNSPEC | -(EAI_SERVICE));
    }
  }

  if (service) {
    if (service->num < 0) {
      if (tp->name) {
	i = gaih_inet_serv(service->name, tp, &st);
	if (i != 0)
	  return i;
      } else {
	struct gaih_servtuple **pst = &st;
	for (tp++; tp->name; tp++) {
	  i = gaih_inet_serv(service->name, tp, pst);
	  if (i != 0) {
	    if (i & GAIH_OKIFUNSPEC)
	      continue;
	    goto ret;
	  }
	  pst = &((*pst)->next);
	}
	if (st == &nullserv) {
	  i = (GAIH_OKIFUNSPEC | -(EAI_SERVICE));
	  goto ret;
	}
      }
    } else {
      st = malloc(sizeof(struct gaih_servtuple));
      if (st == NULL)
	return -(EAI_MEMORY);

      st->next     = NULL;
      st->socktype = tp->socktype;
      st->protocol = tp->protocol;
      st->port     = htons(service->num);
    }
  }

  if (!name) {
    at = malloc(sizeof(struct gaih_addrtuple));
    if (at == NULL) {
      i = -(EAI_MEMORY);
      goto ret;
    }

    memset(at, 0, sizeof(struct gaih_addrtuple));

#if defined(INET6) && defined(AF_INET6)
    at->next = malloc(sizeof(struct gaih_addrtuple));
    if (at->next == NULL) {
      i = -(EAI_MEMORY);
      goto ret;
    }

    memset(at->next, 0, sizeof(struct gaih_addrtuple));
    at->next->family = AF_INET;

    at->family = AF_INET6;
#else
    at->family = AF_INET;
#endif /* INET6 */

    goto build;
  }

  if (!req->ai_family || (req->ai_family == AF_INET)) {
    struct in_addr in_addr;
    if (inet_pton(AF_INET, name, (void*)&in_addr) > 0) {
      at = malloc(sizeof(struct gaih_addrtuple));
      if (at == NULL)
	return -(EAI_MEMORY);
      
      memset(at, 0, sizeof(struct gaih_addrtuple));
      
      at->family = AF_INET;
      memcpy(at->addr, &in_addr, sizeof(struct in_addr));
      goto build;
    }
  }

#if defined(INET6) && defined(AF_INET6)
  if (!req->ai_family || (req->ai_family == AF_INET6)) {
    struct in6_addr in6_addr;
    if (inet_pton(AF_INET6, name, (void*)&in6_addr) > 0) {
      if (!(at = malloc(sizeof(struct gaih_addrtuple))))
	return -(EAI_MEMORY);
      
      memset(at, 0, sizeof(struct gaih_addrtuple));
      
      at->family = AF_INET6;
      memcpy(at->addr, &in6_addr, sizeof(struct in6_addr));
      goto build;
    }
  }
#endif /* INET6 */

  if ((req->ai_flags & AI_NONAME) == 0) {
    i = hosttable_lookup_addr(name, req, &at);
if (vlog)
  fprintf(vlog,"hosttable_lookup_addr(name='%s') returns %d\n", name, i);

    if (i < 0)
      goto ret;
    if (i == 0)
      goto build;

#if defined(INET6) && defined(AF_INET6)
    if (!req->ai_family || (req->ai_family == AF_INET6)) {
      i = resolver_lookup_addr(name, T_AAAA, req, &at, vlog);
if (vlog)
  fprintf(vlog,"resolver_lookup_addr(name='%s', T_AAAA) returns %d\n",name, i);
      if (i < 0)
	goto ret;
    }
#endif /* INET6 */
    if (!req->ai_family || (req->ai_family == AF_INET)) {
      i = resolver_lookup_addr(name, T_A, req, &at, vlog);
if (vlog)
  fprintf(vlog,"resolver_lookup_addr(name='%s', T_A) returns %d\n",name, i);
      if (i < 0)
	goto ret;
    }

    if (i == 0)
      goto build;
  }

  if (at == NULL)
    return (GAIH_OKIFUNSPEC | -(EAI_NONAME));

build:
  {
    char *prevcname = NULL;
    struct gaih_servtuple *st2;
    struct gaih_addrtuple *at2 = at;
    int j;

    while (at2 != NULL) {
      if (req->ai_flags & AI_CANONNAME) {
	if (at2->cname != NULL)
	  j = strlen(at2->cname) + 1;
	else
	  if (name)
	    j = strlen(name) + 1;
	  else
	    j = 2;
      } else
	j = 0;

#if defined(INET6) && defined(AF_INET6)
      if (at2->family == AF_INET6)
	i = sizeof(struct sockaddr_in6);
      else
#endif /* INET6 */
	i = sizeof(struct sockaddr_in);

      st2 = st;
      while (st2) {

	*pai = malloc(sizeof(struct addrinfo) + i + j);
	if (*pai == NULL) {
	  i = -(EAI_MEMORY);
	  goto ret;
	}
	memset(*pai, 0, sizeof(struct addrinfo) + i + j);

	(*pai)->ai_flags     = req->ai_flags;
	(*pai)->ai_family    = at2->family;
	(*pai)->ai_socktype  = st2->socktype;
	(*pai)->ai_protocol  = st2->protocol;
	(*pai)->ai_addrlen   = i;
	(*pai)->ai_addr      = (void*)((char*)(*pai)+sizeof(struct addrinfo));

#if defined(INET6) && defined(AF_INET6)
	if (at2->family == AF_INET6) {
	  struct sockaddr_in6 *si6;
	  si6 = (struct sockaddr_in6 *) (*pai)->ai_addr;
#ifdef HAVE_SA_LEN
	  si6->sin6_len      = i;
#endif /* SALEN */
	  si6->sin6_family   = at2->family;
	  si6->sin6_flowinfo = 0;
	  si6->sin6_port     = st2->port;
	  memcpy(&si6->sin6_addr, at2->addr, sizeof(struct in6_addr));
	} else
#endif /* INET6 */
	  {
	    struct sockaddr_in  *si4;
	    si4 = (struct sockaddr_in *) (*pai)->ai_addr;
#ifdef HAVE_SA_LEN
	    si4->sin_len     = i;
#endif /* SALEN */
	    si4->sin_family  = at2->family;
	    si4->sin_port    = st2->port;
	    memcpy(&si4->sin_addr, at2->addr, sizeof(struct in_addr));
	  }

	if (j != 0) {
	  (*pai)->ai_canonname = (char *)(*pai) + sizeof(struct addrinfo) + i;
	  if (at2->cname != NULL) {
	    strcpy((*pai)->ai_canonname, at2->cname);
	    if (prevcname != at2->cname) {
	      if (prevcname != NULL)
		free(prevcname);
	      prevcname = at2->cname;
	    }
	  } else
	    strcpy((*pai)->ai_canonname, name ? name : "*");
	}

	pai = &((*pai)->ai_next);

	st2 = st2->next;
      }
      at2 = at2->next;
    }
  }

  i = 0;

ret:
  if (st != &nullserv) {
    struct gaih_servtuple *st2 = st;
    while (st != NULL) {
      st2 = st->next;
      free(st);
      st = st2;
    }
  }
  if (at) {
    struct gaih_addrtuple *at2 = at;
    while (at != NULL) {
      at2 = at->next;
      free(at);
      at = at2;
    }
  }
  return i;
}

struct gaih {
  int family;
  int (*gaih) __((const char *name, const struct gaih_service *service,
		  const struct addrinfo *req, struct addrinfo **pai,
		  FILE *vlog));
};

static struct gaih gaih[] = {
  { PF_INET,   gaih_inet  },
#if defined(INET6) && defined(AF_INET6)
  { PF_INET6,  gaih_inet  },
#endif /* INET6 */
#ifdef AF_LOCAL
  { PF_LOCAL,  gaih_local },
#endif
  { PF_UNSPEC, NULL }
};

int
_getaddrinfo_(name, service, req, pai, vlog)
const char		*name;
const char		*service;
const struct addrinfo	*req;
struct addrinfo		**pai;
FILE *vlog;
{
  int i = 0, j = 0;
  int anyok;
  struct addrinfo *p = NULL, **end;
  struct gaih *g = gaih, *pg = NULL;
  struct gaih_service gaih_service, *pservice;

  if (name && (name[0] == '*') && !name[1])
    name = NULL;

  if (service && (service[0] == '*') && !service[1])
    service = NULL;

#ifdef BROKEN_LIKE_POSIX
  if (!name && !service)
    return EAI_NONAME;
#endif /* BROKEN_LIKE_POSIX */

  if (!req)
    req = &nullreq;

  if (req->ai_flags & ~(AI_CANONNAME | AI_PASSIVE | AI_NONAME))
    return EAI_BADFLAGS;

#ifdef BROKEN_LIKE_POSIX
  if ((req->ai_flags & AI_CANONNAME) && !name)
    return EAI_BADFLAGS;
#endif

  if (service && *service) {
    char *c;
    gaih_service.name = (void *)service;
    gaih_service.num = strtoul(service, &c, 10);
    if (*c)
      gaih_service.num = -1;
#ifdef BROKEN_LIKE_POSIX
    else
      if (!req->ai_socktype)
	return EAI_SERVICE;
#endif /* BROKEN_LIKE_POSIX */
    pservice = &gaih_service;
  } else
    pservice = NULL;

  if (pai)
    end = &p;
  else
    end = NULL;

  anyok = 0;
  for ( ; g->gaih; ++g) {
    if ((req->ai_family == g->family) || !req->ai_family) {
      j++;
      if (!((pg && (pg->gaih == g->gaih)))) {
	pg = g;
	i = g->gaih(name, pservice, req, end, vlog);
	if (i == 0)
	  anyok = 1;

if (vlog)
  fprintf(vlog,"getaddrinfo(): g->family=%d g->gaih(name='%s', service='%s') returns: %d\n", g->family, name, service ? service : "<NULL>", i);

	if (i != 0 && !anyok) {
	  if (!req->ai_family && (i & GAIH_OKIFUNSPEC))
	    continue;
	  goto gaih_err;
	}
	if (end)
          while (*end) end = &((*end)->ai_next);
      }
    }
  }

  if (!j)
    return EAI_FAMILY;

  if (p) {
    *pai = p;
    return 0;
  }

  if (!pai && !i)
    return 0;

gaih_err:
  if (p)
    freeaddrinfo(p);

  if (i)
    return -(i & GAIH_EAI);

  return EAI_NONAME;
}

int
getaddrinfo(name, service, req, pai)
const char		*name;
const char		*service;
const struct addrinfo	*req;
struct addrinfo		**pai;
{
  return _getaddrinfo_(name, service, req, pai, NULL);
}

void
freeaddrinfo(ai)
struct addrinfo *ai;
{
  struct addrinfo *p;

  while (ai != NULL) {
    p = ai;
    ai = ai->ai_next;
    free((void *)p);
  }
}
