/*
%%% copyright-cmetz-96
This software is Copyright 1996-1997 by Craig Metz, All Rights Reserved.
The Inner Net License Version 2 applies to this software.
You should have received a copy of the license with this software. If
you didn't get a copy, you may request one from <license@inner.net>.

*/
/* getaddrinfo() v1.21 */

/* To do what POSIX says, even when it's broken, define: */
/* #define BROKEN_LIKE_POSIX 1 */
/* Note: real apps will break if you define this, while nothing other than a
   conformance test suite should have a problem with it undefined */

#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#if LOCAL
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/un.h>
#endif /* LOCAL */
#include <netinet/in.h>
#if INET6
#include <netinet6/in6.h>
#endif /* INET6 */
#include <netdb.h>
#if RESOLVER
#include <arpa/nameser.h>
#endif /* RESOLVER */

#ifndef AF_LOCAL
#define AF_LOCAL AF_UNIX
#endif /* AF_LOCAL */
#ifndef PF_LOCAL
#define PF_LOCAL PF_UNIX
#endif /* PF_LOCAL */
#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif /* UNIX_PATH_MAX */

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

#if HOSTTABLE
static int hosttable_lookup_addr(const char *name, const struct addrinfo *req, struct gaih_addrtuple **pat)
{
  FILE *f;
  char buffer[1024];
  char *c, *c2;
  int rval = 1;
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

    while(*c && isspace(*c)) c++;
    if (!*c)
      continue;

    if (!(c2 = strstr(c, name)))
      continue;

    if (!isspace(*(c2 - 1)))
      continue;

    c2 += strlen(name);
    if (*c2 && !isspace(*c2))
      continue;

    c2 = c;
    while(*c2 && !isspace(*c2)) c2++;
    if (!*c2)
      continue;
    *c2 = 0;

    if (!*pat) {
      if (!(*pat = malloc(sizeof(struct gaih_addrtuple))))
	return -EAI_MEMORY;
    };

    memset(*pat, 0, sizeof(struct gaih_addrtuple));

    if (!req->ai_family || (req->ai_family == AF_INET))
      if (inet_pton(AF_INET, buffer, (*pat)->addr) > 0) {
	(*pat)->family = AF_INET;
	goto build;
      };

#if INET6
    if (!req->ai_family || (req->ai_family == AF_INET6))
      if (inet_pton(AF_INET6, buffer, (*pat)->addr) > 0) {
	(*pat)->family = AF_INET6;
	goto build;
      };
#endif /* INET6 */

    continue;

build:
    if (req->ai_flags & AI_CANONNAME)
      if (prevcname && !strcmp(prevcname, c))
	(*pat)->cname = prevcname;
      else
	prevcname = (*pat)->cname = strdup(c);

    pat = &((*pat)->next);

    rval = 0;
  };

  fclose(f);
  return rval;
};
#endif /* HOSTTABLE */

#if RESOLVER
struct rrheader {
  int16_t type;
  int16_t class;
  u_int32_t ttl;
  int16_t size;
};
#define RRHEADER_SZ 10

int resolver_lookup_addr(const char *name, int type, const struct addrinfo *req, struct gaih_addrtuple **pat)
{
  char answer[PACKETSZ];
  int answerlen;
  char dn[MAXDNAME];
  char *prevcname = NULL;
  void *p, *ep;
  int answers, i, j;

  if ((answerlen = res_search(name, C_IN, type, answer, sizeof(answer))) < 0) {
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
  if ((ntohs(((u_int16_t *)p)[0]) != type) || (ntohs(((u_int16_t *)p)[1]) != C_IN))
    return -EAI_FAIL;
  p += 2*sizeof(u_int16_t);

  while(answers--) {
    if ((i = dn_expand(answer, ep, p, dn, sizeof(dn))) < 0)
      return -EAI_FAIL;
    p += i;

    if (p + RRHEADER_SZ >= ep)
      return -EAI_FAIL;
    {
      struct rrheader *rrheader = (struct rrheader *)p;

      if (ntohs(rrheader->class) != C_IN)
	return -EAI_FAIL;
      j = ntohs(rrheader->type);
      i = ntohs(rrheader->size);
    };
    p += RRHEADER_SZ;

    if (p + i >= ep)
      return -EAI_FAIL;

    if (j == type) {
      while(*pat)
	pat = &((*pat)->next);

      if (!(*pat = malloc(sizeof(struct gaih_addrtuple))))
	return -EAI_MEMORY;

      memset(*pat, 0, sizeof(struct gaih_addrtuple));
      
      switch(type) {
        case T_A:
	  if (i != sizeof(struct in_addr))
	    return -EAI_FAIL;
	  (*pat)->family = AF_INET;
	  break;
#if INET6
        case T_AAAA:
	  if (i != sizeof(struct in6_addr))
	    return -EAI_FAIL;
	  (*pat)->family = AF_INET6;
	  break;
#endif /* INET6 */
        default:
	  return -EAI_FAIL;
      };

      memcpy((*pat)->addr, p, i);
    
      if (req->ai_flags & AI_CANONNAME)
	if (prevcname && !strcmp(prevcname, dn))
	  (*pat)->cname = prevcname;
	else
	  prevcname = (*pat)->cname = strdup(dn);
    };
    p += i;
  };

  return 0;
};
#endif /* RESOLVER */

#if LOCAL
static int gaih_local(const char *name, const struct gaih_service *service,
		     const struct addrinfo *req, struct addrinfo **pai)
{
  struct utsname utsname;

  if (name || (req->ai_flags & AI_CANONNAME))
    if (uname(&utsname))
      return -EAI_SYSTEM;
  if (name) {
    if (strcmp(name, "localhost") && strcmp(name, "local") && strcmp(name, "unix") && strcmp(name, utsname.nodename))
      return (GAIH_OKIFUNSPEC | -EAI_NONAME);
  };

  if (!(*pai = malloc(sizeof(struct addrinfo) + sizeof(struct sockaddr_un) + ((req->ai_flags & AI_CANONNAME) ? (strlen(utsname.nodename) + 1): 0))))
    return -EAI_MEMORY;

  (*pai)->ai_next = NULL;
  (*pai)->ai_flags = req->ai_flags;
  (*pai)->ai_family = AF_LOCAL;
  (*pai)->ai_socktype = req->ai_socktype ? req->ai_socktype : SOCK_STREAM;
  (*pai)->ai_protocol = req->ai_protocol;
  (*pai)->ai_addrlen = sizeof(struct sockaddr_un);
  (*pai)->ai_addr = (void *)(*pai) + sizeof(struct addrinfo);
#if SALEN
  ((struct sockaddr_un *)(*pai)->ai_addr)->sun_len = sizeof(struct sockaddr_un);
#endif /* SALEN */
  ((struct sockaddr_un *)(*pai)->ai_addr)->sun_family = AF_LOCAL;
  memset(((struct sockaddr_un *)(*pai)->ai_addr)->sun_path, 0, UNIX_PATH_MAX);
  if (service) {
    char *c;
    if (c = strchr(service->name, '/')) {
      if (strlen(service->name) >= sizeof(((struct sockaddr_un *)(*pai)->ai_addr)->sun_path))
        return (GAIH_OKIFUNSPEC | -EAI_SERVICE);
      strcpy(((struct sockaddr_un *)(*pai)->ai_addr)->sun_path, service->name);
    } else {
      if (strlen(P_tmpdir "/") + 1 + strlen(service->name) >= sizeof(((struct sockaddr_un *)(*pai)->ai_addr)->sun_path))
        return (GAIH_OKIFUNSPEC | -EAI_SERVICE);
      strcpy(((struct sockaddr_un *)(*pai)->ai_addr)->sun_path, P_tmpdir "/");
      strcat(((struct sockaddr_un *)(*pai)->ai_addr)->sun_path, service->name);
    };
  } else {
    if (!tmpnam(((struct sockaddr_un *)(*pai)->ai_addr)->sun_path))
      return -EAI_SYSTEM;
  };
  if (req->ai_flags & AI_CANONNAME)
    strcpy((*pai)->ai_canonname = (char *)(*pai) + sizeof(struct addrinfo) + sizeof(struct sockaddr_un), utsname.nodename);
  else
    (*pai)->ai_canonname = NULL;
  return 0;
};
#endif /* LOCAL */

static struct gaih_typeproto gaih_inet_typeproto[] = {
  { 0, 0, NULL },
  { SOCK_STREAM, IPPROTO_TCP, "tcp" },
  { SOCK_DGRAM, IPPROTO_UDP, "udp" },
  { 0, 0, NULL }
};

static int gaih_inet_serv(char *servicename, struct gaih_typeproto *tp, struct gaih_servtuple **st)
{
  struct servent *s;

  if (!(s = getservbyname(servicename, tp->name)))
    return (GAIH_OKIFUNSPEC | -EAI_SERVICE);

  if (!(*st = malloc(sizeof(struct gaih_servtuple))))
    return -EAI_MEMORY;

  (*st)->next = NULL;
  (*st)->socktype = tp->socktype;
  (*st)->protocol = tp->protocol;
  (*st)->port = s->s_port;

  return 0;
}

static int gaih_inet(const char *name, const struct gaih_service *service,
		     const struct addrinfo *req, struct addrinfo **pai)
{
  struct hostent *h = NULL;
  struct gaih_typeproto *tp = gaih_inet_typeproto;
  struct gaih_servtuple *st = &nullserv;
  struct gaih_addrtuple *at = NULL;
  int i;

  if (req->ai_protocol || req->ai_socktype) {
    for (tp++; tp->name &&
	  ((req->ai_socktype != tp->socktype) || !req->ai_socktype) && 
	  ((req->ai_protocol != tp->protocol) || !req->ai_protocol); tp++);
    if (!tp->name)
      if (req->ai_socktype)
	return (GAIH_OKIFUNSPEC | -EAI_SOCKTYPE);
      else
	return (GAIH_OKIFUNSPEC | -EAI_SERVICE);
  }

  if (service) {
    if (service->num < 0) {
      if (tp->name) {
	if (i = gaih_inet_serv(service->name, tp, &st))
	  return i;
      } else {
	struct gaih_servtuple **pst = &st;
	for (tp++; tp->name; tp++) {
	  if (i = gaih_inet_serv(service->name, tp, pst)) {
	    if (i & GAIH_OKIFUNSPEC)
	      continue;
	    goto ret;
	  }
	  pst = &((*pst)->next);
	}
	if (st == &nullserv) {
	  i = (GAIH_OKIFUNSPEC | -EAI_SERVICE);
	  goto ret;
	}
      }
    } else {
      if (!(st = malloc(sizeof(struct gaih_servtuple))))
	return -EAI_MEMORY;

      st->next = NULL;
      st->socktype = tp->socktype;
      st->protocol = tp->protocol;
      st->port = htons(service->num);
    }
  }

  if (!name) {
    if (!(at = malloc(sizeof(struct gaih_addrtuple)))) {
      i = -EAI_MEMORY;
      goto ret;
    };

    memset(at, 0, sizeof(struct gaih_addrtuple));

#if INET6
    if (!(at->next = malloc(sizeof(struct gaih_addrtuple)))) {
      i = -EAI_MEMORY;
      goto ret;
    };

    at->family = AF_INET6;

    memset(at->next, 0, sizeof(struct gaih_addrtuple));
    at->next->family = AF_INET;
#else /* INET6 */
    at->family = AF_INET;
#endif /* INET6 */

    goto build;
  };

  if (!req->ai_family || (req->ai_family == AF_INET)) {
    struct in_addr in_addr;
    if (inet_pton(AF_INET, name, &in_addr) > 0) {
      if (!(at = malloc(sizeof(struct gaih_addrtuple))))
	return -EAI_MEMORY;
      
      memset(at, 0, sizeof(struct gaih_addrtuple));
      
      at->family = AF_INET;
      memcpy(at->addr, &in_addr, sizeof(struct in_addr));
      goto build;
    };
  };

#if INET6
  if (!req->ai_family || (req->ai_family == AF_INET6)) {
    struct in6_addr in6_addr;
    if (inet_pton(AF_INET6, name, &in6_addr) > 0) {
      if (!(at = malloc(sizeof(struct gaih_addrtuple))))
	return -EAI_MEMORY;
      
      memset(at, 0, sizeof(struct gaih_addrtuple));
      
      at->family = AF_INET6;
      memcpy(at->addr, &in6_addr, sizeof(struct in6_addr));
      goto build;
    };
  };
#endif /* INET6 */

  if (!(req->ai_flags & AI_NONAME)) {
#if HOSTTABLE
    if ((i = hosttable_lookup_addr(name, req, &at)) < 0)
      goto ret;

    if (!i)
      goto build;
#endif /* HOSTTABLE */

#if RESOLVER
#if INET6
    if (!req->ai_family || (req->ai_family == AF_INET6))
      if ((i = resolver_lookup_addr(name, T_AAAA, req, &at)) < 0)
	goto ret;
#endif /* INET6 */
    if (!req->ai_family || (req->ai_family == AF_INET))
      if ((i = resolver_lookup_addr(name, T_A, req, &at)) < 0)
	goto ret;

    if (!i)
      goto build;
#endif /* RESOLVER */
  };

  if (!at)
    return (GAIH_OKIFUNSPEC | -EAI_NONAME);

build:
  {
    char *prevcname = NULL;
    struct gaih_servtuple *st2;
    struct gaih_addrtuple *at2 = at;
    int j;

    while(at2) {
      if (req->ai_flags & AI_CANONNAME) {
	if (at2->cname)
	  j = strlen(at2->cname) + 1;
	else
	  j = strlen(name) + 1;
      } else
	j = 0;

#if INET6
      if (at2->family == AF_INET6)
	i = sizeof(struct sockaddr_in6);
      else
#endif /* INET6 */
	i = sizeof(struct sockaddr_in);

      st2 = st;
      while(st2) {
	if (!(*pai = malloc(sizeof(struct addrinfo) + i + j))) {
	  i = -EAI_MEMORY;
	  goto ret;
	}
	memset(*pai, 0, sizeof(struct addrinfo) + i + j);

	(*pai)->ai_flags = req->ai_flags;
	(*pai)->ai_family = at2->family;
	(*pai)->ai_socktype = st2->socktype;
	(*pai)->ai_protocol = st2->protocol;
	(*pai)->ai_addrlen = i;
	(*pai)->ai_addr = (void *)(*pai) + sizeof(struct addrinfo);
#if SALEN
	((struct sockaddr_in *)(*pai)->ai_addr)->sin_len = i;
#endif /* SALEN */
	((struct sockaddr_in *)(*pai)->ai_addr)->sin_family = at2->family;
	((struct sockaddr_in *)(*pai)->ai_addr)->sin_port = st2->port;

#if INET6
	if (at2->family == AF_INET6)
	  memcpy(&((struct sockaddr_in6 *)(*pai)->ai_addr)->sin6_addr, at2->addr, sizeof(struct in6_addr));
	else
#endif /* INET6 */
	  memcpy(&((struct sockaddr_in *)(*pai)->ai_addr)->sin_addr, at2->addr, sizeof(struct in_addr));

	if (j) {
	  (*pai)->ai_canonname = (void *)(*pai) + sizeof(struct addrinfo) + i;
	  if (at2->cname) {
	    strcpy((*pai)->ai_canonname, at2->cname);
	    if (prevcname != at2->cname) {
	      if (prevcname)
		free(prevcname);
	      prevcname = at2->cname;
	    };
	  } else
	    strcpy((*pai)->ai_canonname, name);
	};

	pai = &((*pai)->ai_next);

	st2 = st2->next;
      };
      at2 = at2->next;
    };
  };

  i = 0;

ret:
  if (st != &nullserv) {
    struct gaih_servtuple *st2 = st;
    while(st) {
      st2 = st->next;
      free(st);
      st = st2;
    }
  }
  if (at) {
    struct gaih_addrtuple *at2 = at;
    while(at) {
      at2 = at->next;
      free(at);
      at = at2;
    }
  }
  return i;
}

struct gaih {
  int family;
  int (*gaih)(const char *name, const struct gaih_service *service,
	      const struct addrinfo *req, struct addrinfo **pai);
};

static struct gaih gaih[] = {
#if INET6
  { PF_INET6, gaih_inet },
#endif /* INET6 */
  { PF_INET, gaih_inet },
#if LOCAL
  { PF_LOCAL, gaih_local },
#endif /* LOCAL */
  { PF_UNSPEC, NULL }
};

int getaddrinfo(const char *name, const char *service,
		const struct addrinfo *req, struct addrinfo **pai)
{
  int i, j = 0;
  struct addrinfo *p = NULL, **end;
  struct gaih *g = gaih, *pg = NULL;
  struct gaih_service gaih_service, *pservice;

  if (name && (name[0] == '*') && !name[1])
    name = NULL;

  if (service && (service[0] == '*') && !service[1])
    service = NULL;

#if BROKEN_LIKE_POSIX
  if (!name && !service)
    return EAI_NONAME;
#endif /* BROKEN_LIKE_POSIX */

  if (!req)
    req = &nullreq;

  if (req->ai_flags & ~3)
    return EAI_BADFLAGS;

  if ((req->ai_flags & AI_CANONNAME) && !name)
    return EAI_BADFLAGS;

  if (service && *service) {
    char *c;
    gaih_service.num = strtoul(gaih_service.name = (void *)service, &c, 10);
    if (*c) {
      gaih_service.num = -1;
    }
#if BROKEN_LIKE_POSIX
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

  while(g->gaih) {
    if ((req->ai_family == g->family) || !req->ai_family) {
      j++;
      if (!((pg && (pg->gaih == g->gaih)))) {
	pg = g;
	if (i = g->gaih(name, pservice, req, end)) {
	  if (!req->ai_family && (i & GAIH_OKIFUNSPEC))
	    continue;
	  goto gaih_err;
	}
	if (end)
          while(*end) end = &((*end)->ai_next);
      }
    }
    g++;
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

void freeaddrinfo(struct addrinfo *ai)
{
  struct addrinfo *p;

  while(ai) {
    p = ai;
    ai = ai->ai_next;
    free((void *)p);
  }
}
