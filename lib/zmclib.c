/*
 *  Various IP(v4/v6) multicast related functions for ZMailer
 *
 *  Part of ZMailer;  copyright Matti Aarnio <mea@nic.funet.fi> 2003
 *
 * - zmc_join()
 * - zmc_leave()
 *
 */

#include "hostenv.h"
#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <sys/ioctl.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
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

#include "libc.h"
#include "zmalloc.h"
#include "libz.h"

#include "hostenv.h"

#include <arpa/inet.h>
#include <net/if.h>

#include "zmclib.h"

/* These functions are after
   Stevens: UNIX Network Programming, Volume 1, 2nd edition

   Difference is mainly the addition of 'sf' as 'socket family'
   parameter.

*/

int
zmcast_join(zmc, sa, ifsa, ifindex)
     ZMC *zmc;
     const int ifindex;
     const Usockaddr *sa, *ifsa;
{
	if (zmc) {
	  switch (zmc->pf) {
	  case AF_INET:
	    {
	      struct ip_mreq mreq;
	      memcpy( & mreq.imr_multiaddr,
		      & sa->v4.sin_addr,
		      sizeof(sa->v4.sin_addr) );

#if 0 /* We don't have  if_indextoname()  code at hand! */
	      if (ifindex > 0) {
		struct ifreq ifreq;
		if (if_indextoname(ifindex, ifreq.ifr_name) == NULL) {
		  errno = ENXIO; /* i/f index not found */
		  return -1;
		  goto doioctl;
		}
	      } else
		struct ifreq ifreq;
	      if (ifname) {
		strncpy(ifreq.ifr_name, ifname, IFNAMSIZ);
	      doioctl:
		if (ioctl(fd, SIOCGIFADDR, &ifreq) < 0)
		  return -1;
		memcpy( & mreq.imr_interface,
			& ((struct sockaddr_in *) &ifreq.ifr_addr)->sin_addr,
			sizeof(struct in_addr) );
	      } else
		;
#endif
	      if (ifsa && ifsa->v4.sin_family != AF_INET)
		break; /* BAD! */
	      if (ifsa)
		mreq.imr_interface = ifsa->v4.sin_addr;
	      else
		mreq.imr_interface.s_addr = htonl(INADDR_ANY);

	      return setsockopt( zmc->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
				 (const void*) & mreq, sizeof(mreq) );
	    }

#if defined(AF_INET6) && defined(INET6)
	  case AF_INET6:
	    {
	      struct ipv6_mreq mreq6;

	      memcpy( &mreq6.ipv6mr_multiaddr,
		      & sa->v6.sin6_addr,
		      sizeof(sa->v6.sin6_addr) );
	      
	      mreq6.ipv6mr_interface = ifindex;
	      
	      return setsockopt( zmc->fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
				 (const void*) & mreq6, sizeof(mreq6) );
	    }
#endif
	  default:
	    break;
	  }
	}

	errno = EPROTONOSUPPORT;
	return -1;
}


int
zmcast_set_loop(zmc, onoff)
     ZMC *zmc;
     const int onoff;
{
	if (zmc) {
	  switch (zmc->pf) {
	  case AF_INET:
	    {
	      u_char flag = onoff;
	      
	      return setsockopt( zmc->fd, IPPROTO_IP, IP_MULTICAST_LOOP,
				 (const void *) &flag, sizeof(flag) );
	    }

#if defined(AF_INET6) && defined(INET6)
	  case AF_INET6:
	    {
	      u_int flag = onoff;
	      return setsockopt( zmc->fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
				 (const void *) &flag, sizeof(flag) );
	    }
#endif

	  default:
	    break;
	  }
	}
	errno = EPROTONOSUPPORT;
	return -1;
}


int
zmcast_set_if(zmc, ifsa)
     ZMC *zmc;
     const Usockaddr *ifsa;
{
	if (zmc && ifsa && ifsa->v4.sin_family == zmc->pf) {
	  /* We have proper address family value in IFSA for our SF.. */
	  switch (zmc->pf) {
	  case AF_INET:
	    {
	      struct in_addr ifaddr = ifsa->v4.sin_addr;
	      if (ifsa->v4.sin_family != AF_INET) break; /* BAD ADDR! */
	      
	      return setsockopt( zmc->fd, IPPROTO_IP, IP_MULTICAST_IF,
				 (const void*) & ifaddr, sizeof(ifaddr) );
	    }

#if defined(AF_INET6) && defined(INET6)
	  case AF_INET6:
	    {
	      struct in6_addr if6addr = ifsa->v6.sin6_addr;
	      if (ifsa->v6.sin6_family != AF_INET6) break; /* BAD ADDR! */
	      
	      return setsockopt( zmc->fd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
				 (const void*) &if6addr, sizeof(if6addr) );
	    }
#endif

	  default:
	    break;
	  }
	}
	errno = EPROTONOSUPPORT;
	return -1;
}



int
zmcast_set_ttl(zmc, ttl)
     ZMC *zmc;
     const int ttl;
{
	switch (zmc->pf) {
	case AF_INET:
	  {
	    u_int flag = ttl;

	    return setsockopt( zmc->fd, IPPROTO_IP, IP_MULTICAST_TTL,
			       (const void*) &flag, sizeof(flag) );
	  }

#if defined(AF_INET6) && defined(INET6)
	case AF_INET6:
	  {
	    u_int flag = ttl;

	    return setsockopt( zmc->fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
			       (const void*) &flag, sizeof(flag) );
	  }
#endif

	default:
	  errno = EPROTONOSUPPORT;
	  return -1;
	}
}



ZMC *
zmcast_new(pf, ifsa, port)
     const int pf, port;
     const Usockaddr *ifsa;
{
	ZMC *zmc;
	Usockaddr sa;
	int rc;
	int flag;

	if (ifsa && ifsa->v4.sin_family != pf) return NULL;

	zmc = malloc( sizeof(ZMC) );
	if (!zmc) return NULL; /* AARG! */

	zmc->fd   = socket(pf, SOCK_DGRAM, 0);
	zmc->pf   = pf;
	zmc->port = port;

	if (zmc->fd < 0) { /* Failed to open a socket! */
	  free(zmc);
	  return NULL;
	}

	/* Must set this reuse-of-address here! */
	flag = 1;
	setsockopt( zmc->fd, SOL_SOCKET, SO_REUSEADDR,
		    (const void*) &flag, sizeof(flag));

	memset( &sa, 0, sizeof(sa) );

	if (ifsa)
	  sa = *ifsa;

	switch (pf) {
	case AF_INET:
	  sa.v4.sin_family = AF_INET;
	  sa.v4.sin_port   = htons(port);

	  rc = bind(zmc->fd, (const void*)& sa.v4, sizeof(sa.v4));
	  if (rc != 0) break;

	  return zmc;

#if defined(AF_INET6) && defined(INET6)
	case AF_INET6:
	  sa.v6.sin6_family = AF_INET6;
	  sa.v6.sin6_port   = htons(port);
	  /* sa.v6.sin6_scope_id = ZZ; ????? */

	  rc = bind(zmc->fd, (const void*)& sa.v6, sizeof(sa.v6));
	  if (rc != 0) break;

	  return zmc;
#endif

	default:
	  break;
	}

	/* Failed, throw away the block, and fd.. */

	rc = errno;

	close(zmc->fd);
	free(zmc);

	errno = rc;

	return NULL;
}

void
zmcast_delete(zmc)
     ZMC *zmc;
{
	close(zmc->fd);
	free(zmc);
}

#if 0

/**********************************************************************
 *
 * $Id$
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 **********************************************************************/

#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "start_msock.h"
#include "listeners.h"

int
start_msock(char *address,char *s_address,int port, int reuse, uchar_t ttl,uchar_t loop){
  int sock;
  int status;
  struct sockaddr_in local_addr;
  struct ip_mreq mreq;
#ifdef IP_ADD_SOURCE_MEMBERSHIP
	struct ip_mreq_source mreqs;
#endif

  /*get a datagram socket*/
  if( (sock=socket(AF_INET,SOCK_DGRAM,0)) < 0 ){
	 perror("socket()");
	 return -1;
  }
  
  /*set reuse*/
  if( (setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(&reuse))) < 0 ){
	 perror("setsockopt(SO_REUSEADDR)");
	 return -1;
  }
  
  /* set ttl=127 */
  if( setsockopt(sock,IPPROTO_IP,IP_MULTICAST_TTL,(char *)&ttl,
                 sizeof(ttl)) <0 ){
	 printf("error in setting ttl value\n");
	 return -1;
  }
  
  /*name the socket and bind*/
  local_addr.sin_family=AF_INET;
  local_addr.sin_addr.s_addr=htonl(INADDR_ANY);
  local_addr.sin_port=htons(port);
  status=bind(sock,(struct sockaddr *)&local_addr,sizeof(local_addr));
  if( status < 0 ){
	 perror("bind()");
	 return -1;
  }
  
  /*join multicast group*/
#ifdef IP_ADD_SOURCE_MEMBERSHIP
	if (strcmp(s_address, "0")!=0) {
		mreqs.imr_sourceaddr.s_addr = inet_addr(s_address);
		mreqs.imr_multiaddr.s_addr = inet_addr(address);
		mreqs.imr_interface.s_addr = INADDR_ANY;

		if (setsockopt(sock, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP,
			(char *)&mreqs, sizeof(mreqs)) < 0) {
			perror("start_msock.c :: setsocksopt(IP_ADD_SOURCE_MEMBERSHIP)");
			return -1;
		}
	} else {
#endif
		mreq.imr_multiaddr.s_addr=inet_addr(address);
		mreq.imr_interface.s_addr=htonl(INADDR_ANY);
		
		if( (setsockopt(sock,IPPROTO_IP,IP_ADD_MEMBERSHIP,
							(char *)&mreq,sizeof(mreq))) < 0 ){
		 perror("start_msock.c :: setsockopt(IP_ADD_MEMBERSHIP)");
		 return -1;
		}
#ifdef IP_ADD_SOURCE_MEMBERSHIP
	}
#endif
  
  if( setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP,(char *)&loop,
					  sizeof(loop)) <0 ){
	 printf("error in setting loopback\n");
	 return -1;
  }
  
  return sock;
}

int 
stop_msock(aMediaSource_t *s){
  struct ip_mreq mreq;
  
  mreq.imr_multiaddr.s_addr=inet_addr(s->address);
  mreq.imr_interface.s_addr=htonl(INADDR_ANY);
  if( (setsockopt(s->rtpsock,IPPROTO_IP,IP_DROP_MEMBERSHIP,
						(char *)&mreq,sizeof(mreq))) < 0 ){
	 //perror("setsockopt(IP_DROP_MEMBERSHIP)");
	 return -1;
  }
  if( (setsockopt(s->rtcpsock,IPPROTO_IP,IP_DROP_MEMBERSHIP,
						(char *)&mreq,sizeof(mreq))) < 0 ){
	 //perror("setsockopt(IP_DROP_MEMBERSHIP)");
	 return -1;
  }
  
  return 1;
}



#endif

#if 0
// SAMPLE CODE from  mdnsd
// create multicast 224.0.0.251:5353 socket
int msock()
{
    int s, flag = 1, ittl = 255;
    struct sockaddr_in in;
    struct ip_mreq mc;
    char ttl = 255;

    bzero(&in, sizeof(in));
    in.sin_family = AF_INET;
    in.sin_port = htons(5353);
    in.sin_addr.s_addr = 0;

    if((s = socket(AF_INET,SOCK_DGRAM,0)) < 0) return 0;
#ifdef SO_REUSEPORT
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (char*)&flag, sizeof(flag));
#endif
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&flag, sizeof(flag));
    if(bind(s,(struct sockaddr*)&in,sizeof(in))) { close(s); return 0; }

    mc.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
    mc.imr_interface.s_addr = htonl(INADDR_ANY);
    setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mc, sizeof(mc)); 
    setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &ittl, sizeof(ittl));

    flag =  fcntl(s, F_GETFL, 0);
    flag |= O_NONBLOCK;
    fcntl(s, F_SETFL, flag);

    return s;
}


#endif
