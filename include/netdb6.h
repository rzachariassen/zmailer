/*
	IPv6 API additions for the ZMailer at those machines
	without proper libraries and includes.
	By Matti Aarnio <mea@nic.funet.fi> 1997
 */

#ifndef AI_PASSIVE

struct addrinfo {
  int    ai_flags;	/* AI_PASSIVE | AI_CANONNAME */
  int    ai_family;	/* PF_xxx */
  int    ai_socktype;	/* SOCK_xxx */
  int    ai_protocol;	/* 0, or IPPROTO_xxx for IPv4 and IPv6 */
  size_t ai_addrlen;	/* Length of ai_addr */
  char  *ai_canonname;	/* canonical name for hostname */
  struct sockaddr *ai_addr; /* binary address */
  struct addrinfo *ai_next; /* next structure in linked list */
};

#define AI_PASSIVE	0x01
#define AI_CANONNAME	0x02
#endif
#ifndef AI_NONAME
#define AI_NONAME	0x04 /* (extension) Don't even try nameservice */
#endif

#ifndef EAI_ADDRFAMILY
#define EAI_ADDRFAMILY	 -1
#define EAI_AGAIN	 -2
#define EAI_BADFLAGS	 -3
#define EAI_FAIL	 -4
#define EAI_FAMILY	 -5
#define EAI_MEMORY	 -6
#define EAI_NODATA	 -7
#define EAI_NONAME	 -8
#define EAI_SERVICE	 -9
#define EAI_SOCKTYPE	-10
#define EAI_SYSTEM	-11
#endif

#ifndef NI_MAXHOST
#define NI_MAXHOST	1025
#define NI_MAXSERV	  32

#define NI_NUMERICHOST	0x01
#define NI_NUMERICSERV	0x02
#define NI_NAMEREQD	0x04
#define NI_NOFQDN	0x08
#define NI_DGRAM	0x10
#endif
