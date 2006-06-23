/*
 *  zmpoll() -- A routine for ZMailer  libz.a -library.
 *
 *  All former  select()  things are now done thru  zmpoll()  interface,
 *  even in machines that don't have real poll underneath.
 *  (Most do, which is good..)
 *
 *  Copyright Matti Aarnio, 2006
 */

#include "hostenv.h"

#include "zmpoll.h"

/* 
   #define ZM_POLLIN   0x001
   #define ZM_POLLPRI  0x002
   #define ZM_POLLOUT  0x004

   #define ZM_POLLERR  0x008
   #define ZM_POLLHUP  0x010
   #define ZM_POLLNVAL 0x020

   struct zmpollfd {
     int fd;
     short events;
     short revents;
     void **backptr;
   };

   extern int zmpoll __((struct zmpollfd *__fds, int __nfds, long __timeout));
*/

#include <errno.h>

#ifdef HAVE_POLL

#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#endif

#if (((ZM_POLLIN  - POLLIN)  == 0) && ((ZM_POLLPRI - POLLPRI) == 0) &&	\
     ((ZM_POLLOUT - POLLOUT) == 0) && ((ZM_POLLERR - POLLERR) == 0) &&	\
     ((ZM_POLLHUP - POLLHUP) == 0) && ((ZM_POLLNVAL - POLLNVAL) == 0))
#define __zmpoll_one_on_one_mapping 1
#endif

int zmpoll(__fds, __nfds, __timeout)
	struct zmpollfd *__fds;
	int              __nfds;
	long             __timeout;
{
#ifdef __zmpoll_one_on_one_mapping
	int i, rc;
	struct pollfd *fds = malloc(sizeof(*fds) * (__nfds > 0 ? __nfds : 1));
	for (i = 0; i < __nfds; ++i) {
	  fds[i].fd     = __fds[i].fd;
	  fds[i].events = __fds[i].events;
	  fds[i].revents = 0;
	}
	rc = poll( fds, __nfds, __timeout );
	for (i = 0; i < __nfds; ++i) {
	  fds[i].revents = __fds[i].revents;
	}
	free(fds);
	return rc;
#else
	/* Map input-bits to output-bits.. */
	int i, rc, e;
	struct pollfd *fds = malloc(sizeof(*fds) * (__nfds > 0 ? __nfds : 1));
	for (i = 0; i < __nfds; ++i) {
	  fds[i].fd     = __fds[i].fd;
	  fds[i].events = ((__fds[i].events & ZM_POLLIN) ? POLLIN : 0 |
			   (__fds[i].events & ZM_POLLPRI) ? POLLPRI : 0 |
			   (__fds[i].events & ZM_POLLOUT) ? POLLOUT : 0);
	  fds[i].revents = 0;
	}
	rc = poll( fds, __nfds, __timeout );
	e = errno;
	for (i = 0; i < __nfds; ++i) {
	  __fds[i].revents = ((fds[i].revents & ZM_POLLIN) ? POLLIN : 0 |
			      (fds[i].revents & ZM_POLLPRI) ? POLLPRI : 0 |
			      (fds[i].revents & ZM_POLLOUT) ? POLLOUT : 0 |
			      (fds[i].revents & ZM_POLLERR) ? POLLERR : 0 |
			      (fds[i].revents & ZM_POLLHUP) ? POLLHUP : 0 |
			      (fds[i].revents & ZM_POLLNVAL) ? POLLNVAL : 0);
	}
	free(fds);
	errno = e;
	return rc;
#endif
}


#else  /* Not HAVE_POLL ... */

int zmpoll(__fds, __nfds, __timeout)
	struct zmpollfd *__fds;
	int              __nfds;
	long             __timeout;
{

#error "Lacking code to map POLL(2) API to SELECT(2) API!"

}


#endif




int zmpoll_addfd(fdsp, nfdsp, rdfd, wrfd, backptr)
	struct zmpollfd **fdsp;
	int *nfdsp;
	int rdfd;
	int wrfd;
	void **backptr;
{
	int nfds = *nfdsp +1, i;
	struct zmpollfd * fdp = realloc(*fdsp, sizeof(*fdp) * nfds);

	fdp[nfds-1].fd      = -1;
	fdp[nfds-1].events  =  0;
	fdp[nfds-1].revents =  0;
	fdp[nfds-1].backptr =  backptr;
	if (backptr)
	  *backptr = & fdp[nfds-1];

	if (rdfd > 0){
	  fdp[nfds-1].fd      = rdfd;
	  fdp[nfds-1].events |= ZM_POLLIN;
	}
	if (wrfd > 0){
	  fdp[nfds-1].fd      = wrfd;
	  fdp[nfds-1].events |= ZM_POLLOUT;
	}

	if (*fdsp != fdp) {
	  /* fairly common, not always, though.. */
	  for (i = 0; i < nfds; ++i) {
	    /* If set, points to a pointer pointing to
	       this fdp! */
	    if (fdp[i].backptr)
	      *(fdp[i].backptr) = & fdp[i];
	  }
	}

	*fdsp  = fdp;
	*nfdsp = nfds;

	return 0; /* Hmm..  error indications ?  */
}
