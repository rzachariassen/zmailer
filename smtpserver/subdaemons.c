/*
 *    Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *      This will be free software, but only when it is finished.
 */
/*
 *    Several extensive changes by Matti Aarnio <mea@nic.funet.fi>
 *      Copyright 1991-2004.
 */

/*
 * Protocol from client to server is of TEXT LINES that end with '\n'
 * and are without '\r'... (that are meaningless inside the system.)
 *
 * The fd-passing system sends one byte of random junk, and a bunch
 * of ancilliary data (the fd.)
 */


#include "smtpserver.h"

static int subdaemon_nofiles = 32;

int  ratetracker_rdz_fd  [2] = {-1, -1};
int  ratetracker_server_pid  = 0;

int  router_rdz_fd       [2] = {-1, -1};
int  router_server_pid       = 0;

int  contentfilter_rdz_fd[2] = {-1, -1};
int  contentfilter_server_pid = 0;


static int subdaemon_loop __((int, struct subdaemon_handler *));

int subdaemons_init __((void))
{
	int rc;
	int to[2], from[2];

	subdaemon_nofiles = resources_query_nofiles();
	if (subdaemon_nofiles < 32) subdaemon_nofiles = 32; /* failsafe */

	rc = fdpass_create(to,from);
	if (rc == 0) {
	  ratetracker_rdz_fd[0] = to[0];
	  ratetracker_rdz_fd[1] = to[1];

	  ratetracker_server_pid = fork();
	  if (ratetracker_server_pid == 0) { /* CHILD */

	    report(NULL," [smtpserver ratetracker subsystem]");

	    fdpass_to_child_fds(to, from);

	    subdaemon_loop(0, & subdaemon_handler_ratetracker);

	    sleep(10);
	    exit(0);
	  }
	  pipes_close_parent(to,from);
	}

	rc = fdpass_create(to,from);
	if (rc == 0) {
	  router_rdz_fd[0] = to[0];
	  router_rdz_fd[1] = to[1];

	  router_server_pid = fork();
	  if (router_server_pid == 0) { /* CHILD */

	    report(NULL," [smtpserver router subsystem]");

	    fdpass_to_child_fds(to, from);

	    subdaemon_loop(0, & subdaemon_handler_router);

	    sleep(10);
	    exit(0);
	  }
	  pipes_close_parent(to,from);
	}

	rc = fdpass_create(to,from);
	if (rc == 0) {
	  contentfilter_rdz_fd[0] = to[0];
	  contentfilter_rdz_fd[1] = to[1];

	  contentfilter_server_pid = fork();
	  if (contentfilter_server_pid == 0) { /* CHILD */

	    report(NULL," [smtpserver contentfilter subsystem]");

	    fdpass_to_child_fds(to, from);

	    subdaemon_loop(0, & subdaemon_handler_contentfilter);

	    sleep(10);
	    exit(0);
	  }
	  pipes_close_parent(to,from);
	}

	return 0;
}


int subdaemon_loop(rendezvous_socket, subdaemon_handler)
     int rendezvous_socket;
     struct subdaemon_handler *subdaemon_handler;
{
	int n, rc;
	struct peerdata *peers, *peer;
	void *statep = NULL;
	int ppid, myparent = getppid();
	int top_peer = 0, topfd, newfd;

	fd_set rdset, wrset;
	struct timeval tv;

	/* Close all (possible) FDs above magic value of ZERO */
	for (n = 0; n < subdaemon_nofiles; ++n)
	  if (n != rendezvous_socket) close(n);

	peers = malloc(sizeof(*peers) * subdaemon_nofiles);
	if (!peers) return -1; /* ENOMEM ?? */

	memset(peers, 0, sizeof(*peers) * subdaemon_nofiles);

	for (n = 0; n < subdaemon_nofiles; ++n)
	  peers[n].fd = -1;

	fd_nonblockingmode(rendezvous_socket);

	rc = (subdaemon_handler->init)( & statep );


	for (;;) {

	  ppid = getppid();
	  if ( (ppid != myparent) &&
	       (rendezvous_socket < 0) &&
	       (top_peer <= 0)) break; /* parent is gone, clients are gone
					  -> kill self! */

	  _Z_FD_ZERO(rdset);
	  _Z_FD_ZERO(wrset);

	  tv.tv_sec  = 10;
	  tv.tv_usec =  0;

	  topfd = 0;
	  if (rendezvous_socket >= 0) {
	    _Z_FD_SET(rendezvous_socket, rdset);
	    topfd = rendezvous_socket;
	  }

	  for (n = 0; n < top_peer; ++n) {
	    if (peers[n].fd >= 0) {
	      if (topfd < peers[n].fd)
		topfd = peers[n].fd;
	      if (peers[n].inlen == 0)
		_Z_FD_SET(peers[n].fd, rdset);
	      if (peers[n].outlen > 0)
		_Z_FD_SET(peers[n].fd, wrset);
	    }
	  }

	  rc = (subdaemon_handler->preselect)( statep, & rdset, & wrset, &topfd );


	  rc = select( topfd+1, &rdset, &wrset, NULL, &tv );

	  if (rc > 0) { /* Things have been read or written.. */


	    rc = (subdaemon_handler->postselect)( statep, & rdset, & wrset );

	    /* The rendezvous socket ?? */

	    if (rendezvous_socket >= 0 &&
		_Z_FD_ISSET(rendezvous_socket, rdset)) {
	      /* We have (possibly) something to receive.. */
	      rc = fdpass_receivefd(rendezvous_socket, &newfd);
	      if (rc == 0) {
		close(rendezvous_socket);
		rendezvous_socket = -1;
	      } else {
		/* Ok, we have 'newfd', now we need a new peer slot.. */
		for (n = 0; n < subdaemon_nofiles; ++n) {
		  peer = & peers[n];
		  if (peer->fd < 0) {
		    /* FREE SLOT! */
		    if (n > top_peer)  top_peer = n;
		    memset( peer, 0, sizeof(peers[0]) );
		    peer->fd = newfd;
		    fd_nonblockingmode(newfd);
		    /* We write our greeting right away .. semi fake state! */
		    _Z_FD_SET(peer->fd, wrset);

		    strcpy(peer->outbuf, "#hungry\n");
		    peer->outlen = 8;
		    newfd = -1;
		  }
		}
		if (newfd >= 0) {
		  /* Oh no...  We had no place to put this in... */
		  close(newfd);
		  /* XXX: syslog this situation ???? */
		}
	      }
	    }

	    /* Now all of my peers.. */

	    for (n = 0; n < top_peer; ++n) {
	      peer = & peers[n];
	      if (peer->fd >= 0) {

		/* If we have things to output, and write is doable ? */
		if (peer->outlen > 0 && _Z_FD_ISSET(peer->fd, wrset)) {
		  for (;;) {
		    rc = write(peer->fd,
			       peer->outbuf + peer->outptr,
			       peer->outlen - peer->outptr);
		    if ((rc < 0) && (errno == EINTR))
		      continue; /* try again */
		    break;
		  }
		  if (rc > 0) {
		    if (rc == peer->outlen) {
		      peer->outlen = peer->outptr = 0;
		    } else {
		      /* Sigh..  partial write :-( */
		      peer->outptr += rc;
		    }
		  }
		} /* ... Writability testing */

		/* Now if we have something to read ?? */
		if (_Z_FD_ISSET(peer->fd, rdset)) {
		  for (;;) {
		    rc = read( peer->fd, peer->inpbuf + peer->inlen,
			       sizeof(peer->inpbuf) - peer->inlen );
		    if ((rc < 0) && (errno == EINTR))
		      continue; /* try again */
		    break;
		  }
		  if (rc == 0) { /* EOF! */
		    close(peer->fd);
		    memset( peer, 0, sizeof(peer) );
		    peer->fd = -1;
		    continue;
		  }
		  if (rc > 0) {
		    peer->inlen += rc;
		    if (peer->inpbuf[ peer->inlen -1 ] == '\n') {
		      rc = (subdaemon_handler->input)( peer, statep );
		      if (rc > 0) {
			/* XOFF .. busy right now, come back again.. */
		      } else if (rc == 0) {
			/* XON .. give me more jobs */
		      } else {
			/* Xnone .. ??
			   Can't handle ?? */
		      }
		    }
		  }

		} /* ... read things */

	      } /* peers with valid fd */
	    } /* all peers */
	  } /* readability or writeability detected */

	} /* ... for(;;) ... */

	return -1;
}
