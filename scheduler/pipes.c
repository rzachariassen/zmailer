/*
 *	ZMailer 2.99.16+ Scheduler "bi-directional-pipe" routines
 *
 *	Copyright Matti Aarnio <mea@nic.funet.fi> 1995
 *
 */

#include "hostenv.h"
#include "libz.h"

#ifdef HAVE_SOCKETPAIR

#include <sys/types.h>
#include <sys/socket.h>

/*
 *  Life is easy, we have a system with socketpair, we shall use them...
 */

int pipes_create(tochild, fromchild)
int tochild[2];
int fromchild[2];
{
	int rc = socketpair(PF_UNIX, SOCK_STREAM, 0, tochild);
	if (rc < 0) return rc;
	fromchild[0] = tochild[1];
	fromchild[1] = tochild[0];
	return 0;
}

void pipes_close_parent(tochild, fromchild)
int tochild[2];
int fromchild[2];
{
	close(tochild[0]); /*  same fd as  fromchild[1] */
}

void pipes_to_child_fds(tochild, fromchild)
int tochild[2];
int fromchild[2];
{
	if (tochild[0] != 0)
	  dup2(tochild[0],0);
	dup2(0,1);
	dup2(0,2);
	close(tochild[1]); /* Same as fromchild[0] */
}

void pipes_shutdown_child(fd)
int fd;
{
	/* We close the parent->child writer channel */
	shutdown(fd, 1 /* disable further send operations */);
}
#else /* not HAVE_SOCKETPAIR -- we have ordinary pipes then..
	 (someday we can add here SysV streams-pipes..)		*/

/*
 * Life is not sweet and simple, but rather hard as we have only
 * uni-directional FIFO-like pipes...
 */

int pipes_create(tochild, fromchild)
int tochild[2];
int fromchild[2];
{
	int rc;
	rc = epipe(tochild);
	if (rc < 0) {
	  return rc;
	}
	rc = epipe(fromchild);
	if (rc < 0) {
	  close(tochild[0]);
	  close(tochild[1]);
	}
	return rc;
}

void pipes_close_parent(tochild, fromchild)
int tochild[2];
int fromchild[2];
{
	close(tochild[0]);
	close(fromchild[1]);
}

void pipes_to_child_fds(tochild, fromchild)
int tochild[2];
int fromchild[2];
{
	if (tochild[0] != 0) {
	  dup2(tochild[0], 0);	/* STDIN channel */
	  close(tochild[0]);
	}
	if (fromchild[1] != 1) {
	  dup2(fromchild[1],1); /* STDOUT channel */
	  close(fromchild[1]);
	}
	dup2(1,2);		/* STDERR channel */
}

void pipes_shutdown_child(fd)
int fd;
{
	close(fd);
}
#endif
