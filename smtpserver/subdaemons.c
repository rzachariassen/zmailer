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

int  ratetracker_rdz_fd = -1;
int  ratetracker_server_pid  = 0;

int  router_rdz_fd = -1;
int  router_server_pid       = 0;

int  contentfilter_rdz_fd = -1;
int  contentfilter_server_pid = 0;


static int subdaemon_loop __((int, struct subdaemon_handler *));



int subdaemons_init __((void))
{
	int rc;
	int to[2];

	subdaemon_nofiles = resources_query_nofiles();
	if (subdaemon_nofiles < 32) subdaemon_nofiles = 32; /* failsafe */

	rc = fdpass_create(to);
	if (rc == 0) {
	  ratetracker_rdz_fd = to[1];
	  ratetracker_server_pid = fork();
	  if (ratetracker_server_pid == 0) { /* CHILD */

	    if (logfp) fclose(logfp); logfp = NULL;

	    report(NULL," [smtpserver ratetracker subsystem]");

	    close(to[1]); /* Close the parent (called) end */
	    subdaemon_loop(to[0], & subdaemon_handler_ratetracker);

	    sleep(10);
	    exit(0);
	  }
	  MIBMtaEntry->ss.SubsysRateTrackerPID = ratetracker_server_pid;
	  fdpass_close_parent(to);
	}

	rc = fdpass_create(to);
	if (rc == 0) {
	  router_rdz_fd = to[1];
	  router_server_pid = fork();
	  if (router_server_pid == 0) { /* CHILD */

	    if (logfp) fclose(logfp); logfp = NULL;

	    report(NULL," [smtpserver router subsystem]");

	    close(ratetracker_rdz_fd); /* Our sister server's handle */

	    close(to[1]); /* Close the parent (called) end */
	    subdaemon_loop(to[0], & subdaemon_handler_router);

	    sleep(10);
	    exit(0);
	  }
	  MIBMtaEntry->ss.SubsysRouterMasterPID = router_server_pid;
	  fdpass_close_parent(to);
	}

	rc = fdpass_create(to);
	if (rc == 0) {
	  contentfilter_rdz_fd = to[1];
	  contentfilter_server_pid = fork();
	  if (contentfilter_server_pid == 0) { /* CHILD */

	    if (logfp) fclose(logfp); logfp = NULL;

	    report(NULL," [smtpserver contentfilter subsystem]");

	    close(ratetracker_rdz_fd); /* Our sister server's handle */
	    close(router_rdz_fd);      /* Our sister server's handle */

	    close(to[1]); /* Close the parent (called) end */
	    subdaemon_loop(to[0], & subdaemon_handler_contentfilter);

	    sleep(10);
	    exit(0);
	  }
	  MIBMtaEntry->ss.SubsysContentfilterMasterPID = contentfilter_server_pid;
	  fdpass_close_parent(to);
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
	int ppid;
	int top_peer = 0, top_peer2, topfd, newfd;

	fd_set rdset, wrset;
	struct timeval tv;


	SIGNAL_HANDLE(SIGPIPE, SIG_IGN);

	/* Don't close files/handles, the system shuts down
	   without it just fine */
#if 0
	/* Close all FDs, except our rendezvous socket..
	   We use 'EOF' indication on it to detect when last
	   potential client has gone, and therefore it is not
	   good to inherit these to other subdaemon instances..
	 */
	for (n = 0; n < subdaemon_nofiles; ++n)
	  if (n != rendezvous_socket)
	    close(n);
#endif
#if 0
	{
	  extern int logstyle;
	  extern char *logfile;
	  extern void openlogfp __((SmtpState * SS, int insecure));

	  logstyle = 0;
	  if (logfp) fclose(logfp); logfp = NULL;
	  logfile = "smtpserver-subdaemons.log";
	  openlogfp(NULL, 1);
	}
#endif
	peers = calloc(subdaemon_nofiles, sizeof(*peers));
	if (!peers) return -1; /* ENOMEM ?? */

	for (n = 0; n < subdaemon_nofiles; ++n)
	  peers[n].fd = -1;

	fd_nonblockingmode(rendezvous_socket);

	rc = (subdaemon_handler->init)( & statep );


	for (;;) {

	  ppid = getppid();
	  if ( (rendezvous_socket < 0) &&
	       (top_peer <= 0)) break; /* parent is gone, clients are gone
					  -> kill self! */

	  _Z_FD_ZERO(rdset);
	  _Z_FD_ZERO(wrset);

	  tv.tv_sec  = 10; /* 10 second tick.. */
	  tv.tv_usec =  0;

	  topfd = 0;
	  if (rendezvous_socket >= 0) {
	    _Z_FD_SET(rendezvous_socket, rdset);
	    topfd = rendezvous_socket;
	  }

	  top_peer2 = 0;
	  for (n = 0; n < top_peer; ++n) {
	    if (peers[n].fd >= 0) {
	      top_peer2 = n+1;
	      if (topfd < peers[n].fd)
		topfd = peers[n].fd;
	      if (peers[n].inlen == 0)
		_Z_FD_SET(peers[n].fd, rdset);
	      if (peers[n].outlen > 0)
		_Z_FD_SET(peers[n].fd, wrset);
	    }
	  }
	  top_peer = top_peer2; /* New topmost peer index */

	  rc = (subdaemon_handler->preselect)( statep, & rdset, & wrset, &topfd );

	  rc = select( topfd+1, &rdset, &wrset, NULL, &tv );
	  time(&now);

	  if (rc == 0) {
	    /* Select timeout.. */
	    rc = (subdaemon_handler->postselect)( statep, & rdset, & wrset );
	    continue;
	  }

	  if (rc > 0) { /* Things have been read or written.. */

	    rc = (subdaemon_handler->postselect)( statep, & rdset, & wrset );


	    /* The rendezvous socket ?? */

	    if (rendezvous_socket >= 0 &&
		_Z_FD_ISSET(rendezvous_socket, rdset)) {
	      /* We have (possibly) something to receive.. */
	      newfd = -1;
	      rc = fdpass_receivefd(rendezvous_socket, &newfd);

	      /* type(NULL,0,NULL,"fdpass_received(%d) -> rc=%d newfd = %d",
		 rendezvous_socket, rc, newfd); */

	      if (rc == 0) {
		close(rendezvous_socket);
		rendezvous_socket = -1;

	      } else if ((rc > 0)  && (newfd >= 0)) { /* Successfully received something */

		/* Ok, we have 'newfd', now we need a new peer slot.. */
		for (n = 0; n < subdaemon_nofiles; ++n) {
		  peer = & peers[n];
		  if (peer->fd < 0) {
		    /* FREE SLOT! */
		    if (top_peer <= n)  top_peer = n + 1;
		    memset( peer, 0, sizeof(*peer) );
		    peer->fd = newfd;
		    fd_nonblockingmode(newfd);
		    /* We write our greeting right away .. semi fake state! */
		    _Z_FD_SET(peer->fd, wrset);

		    strcpy(peer->outbuf, "#hungry\n");
		    peer->outlen = 8;
		    peer->outptr = 0;
		    newfd = -1;

		    break; /* Out of the for-loop! */
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
		    if ((rc < 0) && (errno == EPIPE)) {
		      /* SIGPIPE from writing to the socket..  */
		      break;  /* Lets ignore it, and reading from
				 the same socket will be EOF - I hope.. */
		    }
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
		      rc = (subdaemon_handler->input)( statep, peer );
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
