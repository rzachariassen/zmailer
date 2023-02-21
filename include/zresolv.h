/*
 *	Centralized resolver related includes for ZMailer
 *	Matti Aarnio <mea@nic.funet.fi>  (copyright) 2003
 */


#ifdef HAVE_RESOLVER
# define BIND /* Want BIND */
#endif

#include <sys/socket.h>

#include <netdb.h>
#ifndef EAI_AGAIN
# include "netdb6.h" /* IPv6 API stuff */
#endif

#define CUC const u_char

/* ================ do we have a normal nameserver? ================ */
#ifdef	TRY_AGAIN

#ifdef	BSDTYPES_H
#include BSDTYPES_H
#endif	/* BSDTYPES_H */

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

#ifdef NOERROR
#undef NOERROR /* On Solaris 2.3 the  netinet/in.h  includes
		  sys/stream.h, which has DIFFERENT "NOERROR" in it.. */
#endif

#ifdef __linux__
#define __USE_BSD 1	/* Linux headers ... Auch..  <endian.h> */
#endif

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>

/* For use by WKS lookup, we need to know the SMTP port number. */

#ifndef	IPPORT_SMTP
#define	IPPORT_SMTP	25
#endif	/* !IPPORT_SMTP */

#ifndef	MAXNAME
#define	MAXNAME		BUFSIZ
#endif	/* !MAXNAME */

#ifndef MAXHOSTNAMELEN
# define MAXHOSTNAMELEN 256
#endif

#define	MAXVALIDTTL	(60*60*24*365)	/* any ttl over this is ignored */

#ifndef HFIXEDSZ	/* An ancient resolver (arpa/nameser.h) file ? */
# define HFIXEDSZ 12
#endif
#ifndef NETDB_SUCCESS	/* Ancient <netdb.h> ? */
# define NETDB_SUCCESS   0
# define NETDB_INTERNAL -1
#endif


#ifndef	BIND_VER
#ifdef	GETLONG
/* 4.7.3 introduced the {GET,PUT}{LONG,SHORT} macros in nameser.h */
#define	BIND_VER	473
#else	/* !GETLONG */
#define	BIND_VER	472
#endif	/* GETLONG */
#endif	/* !BIND_VER */
#endif	/* BIND */

#if	defined(BIND_VER) && (BIND_VER >= 473)
typedef u_char msgdata;
#else	/* !defined(BIND_VER) || (BIND_VER < 473) */
typedef char msgdata;
#endif	/* defined(BIND_VER) && (BIND_VER >= 473) */

#if	defined(BIND_VER) && (BIND_VER >= 473)
extern const char * conffile;
#endif	/* defined(BIND_VER) && (BIND_VER >= 473) */


/* Define all those things which exist on newer BINDs, and which may
   get returned to us, when we make a query with  T_ANY ... */

#ifndef	T_TXT
# define T_TXT 16	/* Text strings */
#endif
#ifndef T_RP
# define T_RP 17	/* Responsible person */
#endif
#ifndef T_AFSDB
# define T_AFSDB 18	/* AFS cell database */
#endif
#ifndef T_X25
# define T_X25 19	/* X.25 calling address */
#endif
#ifndef T_ISDN
# define T_ISDN 20	/* ISDN calling address */
#endif
#ifndef T_RT
# define T_RT 21	/* router */
#endif
#ifndef T_NSAP
# define T_NSAP 22	/* NSAP address */
#endif
#ifndef T_NSAP_PTR
# define T_NSAP_PTR 23	/* reverse NSAP lookup (depreciated) */
#endif
#ifndef T_AAAA
# define T_AAAA 28	/* IPv6 Address */
#endif
#ifndef	T_UINFO
# define T_UINFO 100
#endif
#ifndef T_UID
# define T_UID 101
#endif
#ifndef T_GID
# define T_GID 102
#endif
#ifndef T_UNSPEC
# define T_UNSPEC 103
#endif
#ifndef T_SA
# define T_SA 200		/* Shuffle addresses */
#endif


#if PACKETSZ > 1024
#define	MAXPACKET	PACKETSZ
#else
#define	MAXPACKET	1024
#endif

#ifndef INADDRSZ
# define INADDRSZ 4
#endif
#ifndef IN6ADDRSZ
# define IN6ADDRSZ 16
#endif
#ifndef AF_INET6
# define AF_INET6 999 /* If the system does not define this,  we use a value
			 that nobody has as AF_ value -- I hope.. */
#endif


typedef union {
    HEADER hdr;
    u_char buf[MAXPACKET];
} querybuf;

#define ALIGN_A    4 /* IPv4 works ok with 32-bit alignment */
#define ALIGN_AAAA 8 /* IPv6 can use 64-bit machines more efficiently.. */

#ifndef NS_INT16SZ
# define NS_INT16SZ 2
#endif
#ifndef NS_INT32SZ
# define NS_INT32SZ 4
#endif

#if !HAVE_U_INT16_T
# if !HAVE_UINT16_T
typedef uint16_t u_int16_t;
# else
typedef unsigned short u_int16_t;
# endif
#endif

#if !HAVE_U_INT32_T
# if !HAVE_UINT32_T
typedef uint32_t u_int32_t;
# else
typedef unsigned int u_int32_t;
# endif
#endif

#ifndef NS_GET16
#define NS_GET16(s, cp) do { \
        register u_char *t_cp = (u_char *)(cp); \
        (s) = ((u_int16_t)t_cp[0] << 8) \
            | ((u_int16_t)t_cp[1]) \
            ; \
        (cp) += NS_INT16SZ; \
} while (0)

#define NS_GET32(l, cp) do { \
        register u_char *t_cp = (u_char *)(cp); \
        (l) = ((u_int32_t)t_cp[0] << 24) \
            | ((u_int32_t)t_cp[1] << 16) \
            | ((u_int32_t)t_cp[2] << 8) \
            | ((u_int32_t)t_cp[3]) \
            ; \
        (cp) += NS_INT32SZ; \
} while (0)
#endif


extern int	h_errno;

extern int res_mkquery(), res_send(), dn_skipname(), dn_expand();

