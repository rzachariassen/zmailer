/*
%%% copyright-cmetz
This software is Copyright 1996 by Craig Metz, All Rights Reserved.
The Inner Net License Version 2 applies to this software.
You should have received a copy of the license with this software. If
you didn't get a copy, you may request one from <license@inner.net>.

*/
/* getaddrinfo() v1.13 */

/* To do what POSIX says, even when it's broken: */
/* #define BROKEN_LIKE_POSIX 1 */

#include "hostenv.h"
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
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
#ifndef EAI_AGAIN
#include "netdb6.h"
#endif

extern void freeaddrinfo (); /* ((struct addrinfo *)); */
extern char *inet_ntop ();

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

struct hostent *gethostbyname2(const char *, int);

struct hostent *_hostname2addr_hosts(const char *name, int);
struct hostent *_addr2hostname_hosts(const char *name, int, int);

#ifdef AF_INET6
const struct in6_addr in6addr_any      = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
const struct in6_addr in6addr_loopback = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };
#endif


static struct addrinfo nullreq = { 0, PF_UNSPEC, 0, 0, 0, NULL, NULL, NULL };

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
};

struct gaih_typeproto {
  int socktype;
  int protocol;
  char *name;
};

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
  (*pai)->ai_addr = (void*)((char *)(*pai) + sizeof(struct addrinfo));
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
}

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

  if (name) {
    if (!(at = malloc(sizeof(struct gaih_addrtuple)))) {
      i = -EAI_MEMORY;
      goto ret;
    }

    at->family = 0;
    at->next = NULL;

    if (!at->family || !req->ai_family || (req->ai_family == AF_INET))
      if (inet_pton(AF_INET, name, at->addr) > 0)
	at->family = AF_INET;

#ifdef AF_INET6
    if (!at->family && (!req->ai_family || (req->ai_family == AF_INET6)))
      if (inet_pton(AF_INET6, name, at->addr) > 0)
	at->family = AF_INET6;
#endif /* AF_INET6 */

#if HOSTTABLE
    if (!at->family) {
      struct hostent *h;
      struct gaih_addrtuple **pat = &at;

#ifdef AF_INET6
      if (!req->ai_family || (req->ai_family == AF_INET6))
	if (h = _hostname2addr_hosts(name, AF_INET6)) {
	  for (i = 0; h->h_addr_list[i]; i++) {
	    if (!*pat) {
	      if (!(*pat = malloc(sizeof(struct gaih_addrtuple)))) {
		i = -EAI_MEMORY;
		goto ret;
	      }
	    }
	    (*pat)->next = NULL;
	    (*pat)->family = AF_INET6;
	    memcpy((*pat)->addr, h->h_addr_list[i], sizeof(struct in6_addr));
	    pat = &((*pat)->next);
	  }
	}
#endif /* AF_INET6 */

      if (!req->ai_family || (req->ai_family == AF_INET))
	if (h = _hostname2addr_hosts(name, AF_INET)) {
	  for (i = 0; h->h_addr_list[i]; i++) {
	    if (!*pat) {
	      if (!(*pat = malloc(sizeof(struct gaih_addrtuple)))) {
		i = -EAI_MEMORY;
		goto ret;
	      }
	    }
	    (*pat)->next = NULL;
	    (*pat)->family = AF_INET;
	    memcpy((*pat)->addr, h->h_addr_list[i], sizeof(struct in_addr));
	    pat = &((*pat)->next);
	  }
	}
    }
#endif /* HOSTTABLE */

#if RESOLVER
    if (!at->family) {
      struct hostent *h;
      struct gaih_addrtuple **pat = &at;

#if AF_INET6
      if (!req->ai_family || (req->ai_family == AF_INET6))
	if (h = gethostbyname2(name, AF_INET6)) {
	  for (i = 0; h->h_addr_list[i]; i++) {
	    if (!*pat) {
	      if (!(*pat = malloc(sizeof(struct gaih_addrtuple)))) {
		i = -EAI_MEMORY;
		goto ret;
	      }
	    }
	    (*pat)->next = NULL;
	    (*pat)->family = AF_INET6;
	    memcpy((*pat)->addr, h->h_addr_list[i], sizeof(struct in6_addr));
	    pat = &((*pat)->next);
	  }
	}
#endif /* AF_INET6 */

      if (!req->ai_family || (req->ai_family == AF_INET))
	if (h = gethostbyname2(name, AF_INET)) {
	  for (i = 0; h->h_addr_list[i]; i++) {
	    if (!*pat) {
	      if (!(*pat = malloc(sizeof(struct gaih_addrtuple)))) {
		i = -EAI_MEMORY;
		goto ret;
	      }
	    }
	    (*pat)->next = NULL;
	    (*pat)->family = AF_INET;
	    memcpy((*pat)->addr, h->h_addr_list[i], sizeof(struct in_addr));
	    pat = &((*pat)->next);
	  }
	}
    }
#endif /* RESOLVER */

    if (!at->family)
      return (GAIH_OKIFUNSPEC | -EAI_NONAME);
  } else {
    if (!(at = malloc(sizeof(struct gaih_addrtuple)))) {
      i = -EAI_MEMORY;
      goto ret;
    };

    memset(at, 0, sizeof(struct gaih_addrtuple));

#ifdef AF_INET6
    if (!(at->next = malloc(sizeof(struct gaih_addrtuple)))) {
      i = -EAI_MEMORY;
      goto ret;
    };

    at->family = AF_INET6;

    memset(at->next, 0, sizeof(struct gaih_addrtuple));
    at->next->family = AF_INET;
#else /* AF_INET6 */
    at->family = AF_INET;
#endif /* !AF_INET6 */
  };

  if (!pai) {
    i = 0;
    goto ret; 
  };

  {
    const char *c = NULL;
    struct gaih_servtuple *st2;
    struct gaih_addrtuple *at2 = at;
    int j;
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 128
#endif /* MAXHOSTNAMELEN */
    char buffer[MAXHOSTNAMELEN];

    while(at2) {
      if (req->ai_flags & AI_CANONNAME) {
        struct hostent *h = NULL;

	h = gethostbyaddr(at2->addr,
#ifdef AF_INET6
	    (at2->family == AF_INET6) ? sizeof(struct in6_addr) : 
#endif /* AF_INET6 */
	    sizeof(struct in_addr), at2->family);
#if HOSTTABLE
	if (!h)
	  h = _addr2hostname_hosts(at2->addr,
#ifdef AF_INET6
	    (at2->family == AF_INET6) ? sizeof(struct in6_addr) : 
#endif /* AF_INET6 */
	    sizeof(struct in_addr), at2->family);
#endif /* HOSTTABLE */

	if (!h)
          c = inet_ntop(at2->family, at2->addr, buffer, sizeof(buffer));
	else
          c = h->h_name;

	if (!c) {
	  i = (GAIH_OKIFUNSPEC | -EAI_NONAME);
	  goto ret;
	}

	j = strlen(c) + 1;
      } else
	j = 0;

#ifdef AF_INET6
      if (at2->family == AF_INET6)
	i = sizeof(struct sockaddr_in6);
      else
#endif /* AF_INET6 */
	i = sizeof(struct sockaddr_in);

      st2 = st;
      while(st2) {
	if (!(*pai = malloc(sizeof(struct addrinfo) + i + j))) {
	  i = -EAI_MEMORY;
	  goto ret;
	}
	(*pai)->ai_flags = req->ai_flags;
	(*pai)->ai_family = at2->family;
	(*pai)->ai_socktype = st2->socktype;
	(*pai)->ai_protocol = st2->protocol;
	(*pai)->ai_addrlen = i;
	(*pai)->ai_addr = (void*)((char *)(*pai) + sizeof(struct addrinfo));
#if SALEN
	((struct sockaddr_in *)(*pai)->ai_addr)->sin_len = i;
#endif /* SALEN */
	((struct sockaddr_in *)(*pai)->ai_addr)->sin_family = at2->family;
	((struct sockaddr_in *)(*pai)->ai_addr)->sin_port = st2->port;

#ifdef AF_INET6
	if (at2->family == AF_INET6) {
	  ((struct sockaddr_in6 *)(*pai)->ai_addr)->sin6_flowinfo = 0;
	  memcpy(&((struct sockaddr_in6 *)(*pai)->ai_addr)->sin6_addr, at2->addr, sizeof(struct in6_addr));
	} else
#endif /* AF_INET6 */
	{
	  memcpy(&((struct sockaddr_in *)(*pai)->ai_addr)->sin_addr, at2->addr, sizeof(struct in_addr));
	  memset(((struct sockaddr_in *)(*pai)->ai_addr)->sin_zero, 0, sizeof(((struct sockaddr_in *)(*pai)->ai_addr)->sin_zero));
	}
	
	if (c) {
	  (*pai)->ai_canonname = (char *)(*pai) + sizeof(struct addrinfo) + i;
	  strcpy((*pai)->ai_canonname, c);
	} else
	  (*pai)->ai_canonname = NULL;
	(*pai)->ai_next = NULL;

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
#ifdef AF_INET6
  { PF_INET6, gaih_inet },
#endif /* AF_INET6 */
  { PF_INET, gaih_inet },
  { PF_LOCAL, gaih_local },
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

#if 0
/*
 * hostname2addr.c  --  Name to address translation.  For now, only consults
 *                      /etc/hosts, but DNS stuff will go here eventually.
 *
 * Copyright 1995 by Randall Atkinson, Bao Phan, and Dan McDonald
 *	All Rights Reserved.  
 *      All Rights under this copyright have been assigned to NRL.
 */

/*----------------------------------------------------------------------
#	@(#)COPYRIGHT	1.1a (NRL) 17 August 1995

COPYRIGHT NOTICE

All of the documentation and software included in this software
distribution from the US Naval Research Laboratory (NRL) are
copyrighted by their respective developers.

This software and documentation were developed at NRL by various
people.  Those developers have each copyrighted the portions that they
developed at NRL and have assigned All Rights for those portions to
NRL.  Outside the USA, NRL also has copyright on the software
developed at NRL. The affected files all contain specific copyright
notices and those notices must be retained in any derived work.

NRL LICENSE

NRL grants permission for redistribution and use in source and binary
forms, with or without modification, of the software and documentation
created at NRL provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. All advertising materials mentioning features or use of this software
   must display the following acknowledgement:

	This product includes software developed at the Information
	Technology Division, US Naval Research Laboratory.

4. Neither the name of the NRL nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THE SOFTWARE PROVIDED BY NRL IS PROVIDED BY NRL AND CONTRIBUTORS ``AS
IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL NRL OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation
are those of the authors and should not be interpreted as representing
official policies, either expressed or implied, of the US Naval
Research Laboratory (NRL).

----------------------------------------------------------------------*/

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>

#endif

extern struct hostent _hostent_buffer;
extern int _hostent_parse(char *line, int af, int addrsize);
extern int _hostent_linelen;
extern char *_hostent_linebuf;
extern char *_hostent_file;
extern FILE *_hostent_fh;

/* Using the /etc/hosts file, find the (first) hostent entry matching the
   hostname given (may be either primary or an alias) */
struct hostent *_hostname2addr_hosts(name, af)
const char *name;
int af;
{
  int addrsize, foo;

  /* Only open the /etc/hosts file once and keep it open. Is this a 
     Good Thing? (performance vs. memory/resources) */
  if (_hostent_fh) 
    rewind(_hostent_fh);
  else {
    if ((_hostent_fh = fopen(_hostent_file, "r")) == NULL)
      return (struct hostent *)NULL;
    if ((_hostent_linebuf = malloc(_hostent_linelen)) == NULL)
      return (struct hostent *)(_hostent_fh = NULL);
  }

  switch (af) {
    case AF_INET:
      addrsize = sizeof(struct in_addr);
      break;
#if AF_INET6
    case AF_INET6:
      addrsize = sizeof(struct in6_addr);
      break;
#endif /* AF_INET6 */
    default:
      return (struct hostent *)NULL;
  }

  /* Read the file, line by line, and feed the lines to the parser.
     If the hostname or an alias matches what we were given to look
     for, it's a winner. */
  do 
    if (fgets(_hostent_linebuf, _hostent_linelen, _hostent_fh) 
	== _hostent_linebuf)
      if (_hostent_parse(_hostent_linebuf, af, addrsize))
        if (!strcmp(_hostent_buffer.h_name, name)) 
          return &_hostent_buffer;
        else 
          for (foo = 0; _hostent_buffer.h_aliases[foo]; foo++)
            if (!strcmp(_hostent_buffer.h_aliases[foo], name)) 
              return &_hostent_buffer;
  while (!feof(_hostent_fh));

  return NULL;
}

#if 0
/* Standard API entry point. We only really handle the Internet protocols,
   though I really don't see why it wouldn't work for the rest, since the
   parser uses ascii2addr to do the job. */
/* Eventually, we'll probably want to look at /etc/hosts first, then,
   if we don't find anything, try DNS... ? (or maybe a config file?) */
/* The addresses in the returned hostent structure need to point into
   a buffer such that we can transform an in_addr into an in6_addr.
   The current functions do this; look at them before implementing
   other resolvers. */
struct hostent *hostname2addr(name, af)
const char *name;
int af;
{
  struct hostent *rval = (struct hostent *)NULL;

  switch (af) {
#if AF_INET6
    case AF_INET6:
      rval = _hostname2addr_hosts(name, AF_INET6);
      if (rval)
	break;
      /* do DNS here */

      /* If there's an IPv4 address available, return it as a IPv4-as-IPv6
	 mapped address */
      rval = hostname2addr(name, AF_INET); 
      if (rval) {
	int i;
	struct in6_addr in6_v4map_prefix;
	IN6_ADDR_ASSIGN(in6_v4map_prefix, 0, 0, htonl(0xffff), 0);
	for (i = 0; rval->h_addr_list[i]; i++) {
	  rval->h_addr_list[i] -= (sizeof(struct in6_addr) - 
				  sizeof(struct in_addr));
	  memcpy(rval->h_addr_list[i], &in6_v4map_prefix, 
		 (sizeof(struct in6_addr) - sizeof(struct in_addr)));
	}
	rval->h_addrtype = AF_INET6;
	rval->h_length = sizeof(struct in6_addr);
      }
      break;
#endif /* AF_INET6 */
    case AF_INET:
      rval = _hostname2addr_hosts(name, AF_INET);
      if (rval)
	break;
      /* do DNS here */
  }

  return rval;
}
#endif /* 0 */

#if 0
/*
 * _hostent_com.c  -- Common routines between the /etc/hosts lookup functions
 *
 *
 * Copyright 1995 by Randall Atkinson, Bao Phan, and Dan McDonald
 *	All Rights Reserved.  
 *      All Rights under this copyright have been assigned to NRL.
 */

/*----------------------------------------------------------------------
#	@(#)COPYRIGHT	1.1a (NRL) 17 August 1995

COPYRIGHT NOTICE

All of the documentation and software included in this software
distribution from the US Naval Research Laboratory (NRL) are
copyrighted by their respective developers.

This software and documentation were developed at NRL by various
people.  Those developers have each copyrighted the portions that they
developed at NRL and have assigned All Rights for those portions to
NRL.  Outside the USA, NRL also has copyright on the software
developed at NRL. The affected files all contain specific copyright
notices and those notices must be retained in any derived work.

NRL LICENSE

NRL grants permission for redistribution and use in source and binary
forms, with or without modification, of the software and documentation
created at NRL provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. All advertising materials mentioning features or use of this software
   must display the following acknowledgement:

	This product includes software developed at the Information
	Technology Division, US Naval Research Laboratory.

4. Neither the name of the NRL nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THE SOFTWARE PROVIDED BY NRL IS PROVIDED BY NRL AND CONTRIBUTORS ``AS
IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL NRL OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation
are those of the authors and should not be interpreted as representing
official policies, either expressed or implied, of the US Naval
Research Laboratory (NRL).

----------------------------------------------------------------------*/

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>

#include "support.h"
#endif

/* Arbitrary limits */
#define MAX_ALIAS 4
#define MAX_ADDR 8

/* If this isn't big enough to store any address you're going to parse using
this function, you're gonna lose. */
#if AF_INET6
#define MAX_ADDR_SZ  sizeof(struct in6_addr)
#else /* AF_INET6 */
#define MAX_ADDR_SZ  sizeof(struct in_addr)
#endif /* AF_INET6 */

/* These are the buffers that become the returned static buffer */
static char h_addr_buf[MAX_ADDR_SZ * MAX_ADDR];
static char *h_addr_list[MAX_ADDR];
static char *h_aliases[MAX_ALIAS];
struct hostent _hostent_buffer;

int _hostent_linelen = 128;
char *_hostent_linebuf;
FILE *_hostent_fh;
char *_hostent_file = "/etc/hosts";

/* Take a line from /etc/hosts, parse it, and put the results in the hostent
   buffer. Assumes that anything not a valid address is a name. Handles 
   comments. */
int _hostent_parse(char *line, int af, int addrsize)
{
  char *head, *tail;
  int c, naddr, nname;

  head = tail = line;
  c = naddr = nname = 0;

  _hostent_buffer.h_aliases = h_aliases;
  _hostent_buffer.h_addr_list = h_addr_list;
  _hostent_buffer.h_length = addrsize;
  _hostent_buffer.h_addrtype = af;

  while (1) {
    switch (*tail) {
      case '#':
      case '\0':
      case '\n':
	c++;
      case ' ':
      case '\t':
	*tail = 0;
	if (tail != head) {
          void *addr = (char *)h_addr_buf + (MAX_ADDR_SZ * naddr) + 
			(MAX_ADDR_SZ - addrsize);
	  memset(&(h_addr_buf[MAX_ADDR_SZ * naddr]), 0, MAX_ADDR_SZ);
	  if (inet_pton(af, head, addr) == addrsize) {
	    h_addr_list[naddr++] = addr;
	  } else {
	    if (nname)
	      h_aliases[nname - 1] = head;
	    else
	      _hostent_buffer.h_name = head;
	    nname++;
	  }
	}
	if (c) {
	  memset(&(h_addr_buf[MAX_ADDR_SZ * naddr]), 0, MAX_ADDR_SZ);
	  h_addr_list[naddr] = NULL;
	  h_aliases[nname - 1] = NULL;
	  return (naddr && nname);
	}
	head = tail + 1;;
    }
    tail++;
  }
}
