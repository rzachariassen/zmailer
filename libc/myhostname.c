/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * Perhaps a single interface to discovering the real system name.
 */

#include "hostenv.h"
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#if	defined(HAVE_RESOLVER)
#include <netdb.h>
#if !defined(EAI_AGAIN) || !defined(AI_NUMERICHOST)
# include "netdb6.h"
#endif
#include <netinet/in.h>
#endif
#ifdef	HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif
#include "libc.h"

int
getmyhostname(namebuf, len)
	char *namebuf;
	int len;
{
	struct addrinfo req, *ai;
	int i, rc;
#ifdef	HAVE_SYS_UTSNAME_H
	struct utsname id;
	extern int uname();

	if (uname(&id) < 0)
	  return -1;
	strncpy(namebuf, id.nodename, len);
	namebuf[len - 1] = 0;
#else	/* !HAVE_SYS_UTSNAME_H */
	extern int gethostname();
	
	if (gethostname(namebuf, len) < 0)
	  return -1;
#endif	/* USE_UNAME */

	ai = NULL;
	memset(&req, 0, sizeof(req));
	req.ai_socktype = SOCK_STREAM;
	req.ai_protocol = IPPROTO_TCP;
	req.ai_flags    = AI_CANONNAME;
	req.ai_family   = 0;

	for (i = 0; i < 5; ++i) {
	  rc = getaddrinfo(namebuf, "0", &req, &ai);
	  if (rc != EAI_AGAIN)
	    break; /* We try it again if we fail here with EAI_AGAIN */
	}
	if (ai != NULL) {
	  if (ai->ai_canonname != NULL)
	    strncpy(namebuf, ai->ai_canonname, len);
	  namebuf[len-1] = 0;
	  freeaddrinfo(ai);
	}
#if 0
	/* enable this code if for some reason your PTR name is primary */
	{ /* XXX:XXX:XXX: FIX TO USE  GETNAMEINFO()  CALL! */
	  struct in_addr hpaddr;
	  if (hp != NULL)
	    memcpy(&hpaddr,hp->h_addr,hp->h_length);
	  if (hp != NULL
	      && (hp = gethostbyaddr((void*)&hpaddr, hp->h_length,
				     hp->h_addrtype)) != NULL) {
	    strcpy(namebuf,hp->h_name);
	  } else
	    return 0; /* Hmm.. Didn't quite knack it ? */
	}
#endif
	return 0;
}
