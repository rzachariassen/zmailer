/*
 *    Copyright 2004 Matti Aarnio
 *      This is part of the ZMailer (2.99+), and available with
 *      the rules of the main program itself
 *
 *	Setup FD passing sockets, and pass them...
 *	Uses  code copied from  pipes.c  for underlying
 *	socketpair implementation.
 *
 *	Part of the code is copied from:
 *		W.RICHARD STEVENS: UNIX NETWORK PROGRAMMING
 */

#include "hostenv.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/param.h>
#include <errno.h>

#include "libz.h"

#ifdef HAVE_SOCKETPAIR

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>     /* struct iovec */

/*
 *  Life is easy, we have a system with socketpair, we shall use them...
 */

int fdpass_create(tochild)
     int tochild[2];
{
	int rc = socketpair(PF_UNIX, SOCK_STREAM, 0, tochild);

	if (rc == 0 && tochild[0] >= 0)
	  fcntl(tochild[0], F_SETFD, FD_CLOEXEC);
	if (rc == 0 && tochild[1] >= 0)
	  fcntl(tochild[1], F_SETFD, FD_CLOEXEC);

	return rc;
}

void fdpass_close_parent(tochild)
     int tochild[2];
{
	close(tochild[0]); /*  same fd as  fromchild[1] */
}

#if 0
void fdpass_to_child_fds(tochild)
     int tochild[2];
{
	if (tochild[0] != 0)
	  dup2(tochild[0],0);
	dup2(0,1);
	dup2(0,2);
	close(tochild[1]); /* Same as fromchild[0] */
}
#endif

void fdpass_shutdown_child(fd)
     int fd;
{
	/* We close the parent->child writer channel */
	shutdown(fd, 1 /* disable further send operations */);
}


/* Adapted from W.RICHARD STEVENS: UNIX NETWORK PROGRAMMING; lib/read_fd.c */
int fdpass_receivefd(fd, newfdp)
     int fd;
     int *newfdp;
{
	int n;
	char buf[32];
	struct iovec iov[1];
	struct msghdr msg;

#ifdef CMSG_SPACE /* HAVE_MSGHDR_MSG_CONTROL */
	union {
	  struct cmsghdr cm;
	  char control[CMSG_SPACE(sizeof(int))];
	} control_un;
	struct cmsghdr *cmptr;

	msg.msg_control = control_un.control;
	msg.msg_controllen = sizeof(control_un.control);
#else
	int newfd;	

	msg.msg_accrights    = (void*) &newfd;
	msg.msg_accrightslen = sizeof(newfd);
#endif

	msg.msg_name  = NULL;
	msg.msg_namelen = 0;

	iov[0].iov_base = buf;
	iov[0].iov_len  = sizeof(buf);

	msg.msg_iov     = iov;
	msg.msg_iovlen  = 1;

	*newfdp = -1;

	n = recvmsg(fd,  &msg, 0);
	if (n <= 0)  return n;

#ifdef CMSG_SPACE /* HAVE_MSGHDR_MSG_CONTROL */
	cmptr = CMSG_FIRSTHDR(&msg);
	if (cmptr  &&  cmptr->cmsg_len == CMSG_LEN(sizeof(int))) {
	  if ( (cmptr->cmsg_level == SOL_SOCKET) &&
	       (cmptr->cmsg_type  == SCM_RIGHTS) ) {
	    *newfdp = *((int*) CMSG_DATA(cmptr));
	    fcntl(*newfdp, F_SETFD, FD_CLOEXEC);
	  }
	}
#else
	if (msg.msg_accrightslen == sizeof(int)) {
	  *newfdp = newfd;
	  fcntl(*newfdp, F_SETFD, FD_CLOEXEC);
	}
#endif
	return n;
}

/* Adapted from W.RICHARD STEVENS: UNIX NETWORK PROGRAMMING; lib/read_fd.c */
int fdpass_sendfd(passfd, sendfd)
     int sendfd, passfd;
{
	struct msghdr msg;
	struct iovec iov[1];
	int rc;

#ifdef CMSG_SPACE /* HAVE_MSGHDR_MSG_CONTROL */
	union {
	  struct cmsghdr cm;
	  char	control[CMSG_SPACE(sizeof(int))];
	} control_un;
	struct cmsghdr *cmptr;

	msg.msg_control    = control_un.control;
	msg.msg_controllen = sizeof(control_un.control);

	cmptr = CMSG_FIRSTHDR(&msg);
	cmptr->cmsg_len   =  CMSG_LEN(sizeof(int));
	cmptr->cmsg_level = SOL_SOCKET;
	cmptr->cmsg_type  = SCM_RIGHTS;
	*((int*) CMSG_DATA(cmptr)) = sendfd;
#else
	msg.msg_accrights    = (void*) &sendfd;
	msg.msg_accrightslen = sizeof(sendfd);
#endif

	msg.msg_name    = NULL;
	msg.msg_namelen = 0;

	iov[0].iov_base = "";
	iov[0].iov_len  = 1;  /* send 1 byte */
	msg.msg_iov     = iov;
	msg.msg_iovlen  = 1;

	errno = 0;
	rc = sendmsg(passfd, &msg, 0);
	if (rc == 1) return 0;
	return -1;
}


#else

FIXME:FIXME:FIXME:  Can not handle here a case without AF_UNIX sockets!
/* SysVr4 apparently has another solution, but all SysVr4
   systems have also AF_UNIX capable to fd-passing... */


#endif
