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

static int subdaemon_nofiles = 256;

int  ratetracker_rdz_fd = -1;
int  ratetracker_server_pid  = 0;

int  router_rdz_fd = -1;
int  router_server_pid       = 0;

int  contentfilter_rdz_fd = -1;
int  contentfilter_server_pid = 0;


static int subdaemon_loop __((int, struct subdaemon_handler *));
static void subdaemon_pick_next_job __(( struct peerdata *peers, int top_peer, struct subdaemon_handler *subdaemon_handler, void *statep));



void subdaemon_ratetracker(fd)
     int fd;
{
  if (logfp) fclose(logfp); logfp = NULL;
  report(NULL,"[smtpserver ratetracker subsystem]");

  subdaemon_loop(fd, & subdaemon_handler_ratetracker);
  zsleep(10);
  exit(0);
}

void subdaemon_contentfilter(fd)
     int fd;
{
  if (logfp) fclose(logfp); logfp = NULL;
  report(NULL,"[smtpserver contentfilter subsystem]");

  subdaemon_loop(fd, & subdaemon_handler_contentfilter);
  zsleep(10);
  exit(0);
}

void subdaemon_router(fd)
     int fd;
{
  if (logfp) fclose(logfp); logfp = NULL;
  report(NULL,"[smtpserver router subsystem]");
	      
  subdaemon_loop(fd, & subdaemon_handler_router);
  zsleep(10);
  exit(0);
}





int subdaemons_init __((void))
{
	int rc;
	int to[2];
	const char *zconf = getzenv("ZCONFIG");
	const char *mailbin = getzenv("MAILBIN");
	char *smtpserver = NULL;

	if (mailbin) {
	  smtpserver = malloc(strlen(mailbin) + 20);
	  sprintf(smtpserver, "%s/smtpserver", mailbin);
	}

	resources_maximize_nofiles();

	rc = fdpass_create(to);
	if (rc == 0) {
	  ratetracker_rdz_fd = to[1];
	  ratetracker_server_pid = fork();
	  if (ratetracker_server_pid == 0) { /* CHILD */

	    close(to[1]); /* Close the parent (called) end */
	    if (to[0]) {
	      dup2(to[0], 0);
	      close(to[0]);
	    }
	    /* exec here ??? */
	    if (smtpserver)
	      execl(smtpserver, "smtpserver", "-I", "sub-ratetracker",
		    "-Z", zconf, NULL);
	    subdaemon_ratetracker(0);
	    /* never reached */
	  }
	  MIBMtaEntry->ss.SubsysRateTrackerPID = ratetracker_server_pid;
	  fdpass_close_parent(to);
	}

	if (contentfilter) {
	  rc = fdpass_create(to);
	  if (rc == 0) {
	    contentfilter_rdz_fd = to[1];
	    contentfilter_server_pid = fork();
	    if (contentfilter_server_pid == 0) { /* CHILD */

	      close(ratetracker_rdz_fd); /* Our sister server's handle */
	      close(to[1]); /* Close the parent (called) end */
	      if (to[0]) {
		dup2(to[0], 0);
		close(to[0]);
	      }
	      /* exec here ??? */
	      if (smtpserver)
		execl(smtpserver, "smtpserver", "-I", "sub-contentfilter",
		      "-Z", zconf, NULL);
	      subdaemon_contentfilter(0);
	      /* never reached */
	    }
	    MIBMtaEntry->ss.SubsysContentfilterMasterPID = contentfilter_server_pid;
	    fdpass_close_parent(to);
	  }
	}

	if (enable_router) {
	  rc = fdpass_create(to);
	  if (rc == 0) {
	    router_rdz_fd = to[1];
	    router_server_pid = fork();
	    if (router_server_pid == 0) { /* CHILD */
	      
	      close(ratetracker_rdz_fd);     /* Our sister server's handle */
	      if (contentfilter_rdz_fd >= 0)
		close(contentfilter_rdz_fd); /* Our sister server's handle */
	      close(to[1]); /* Close the parent (called) end */
	      if (to[0]) {
		dup2(to[0], 0);
		close(to[0]);
	      }
	      /* exec here ??? */
	      if (smtpserver)
		execl(smtpserver, "smtpserver", "-I", "sub-router",
		      "-Z", zconf, NULL);
	      subdaemon_router(0);
	      /* never reached */
	    }
	    MIBMtaEntry->ss.SubsysRouterMasterPID = router_server_pid;
	    fdpass_close_parent(to);
	  }
	} else {
	  /* We may not be started, mark the situation! */
	  MIBMtaEntry->ss.SubsysRouterMasterPID = 0;
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

	subdaemon_nofiles = resources_query_nofiles();
	if (subdaemon_nofiles < 32) subdaemon_nofiles = 32; /* failsafe */

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
	  if (rc > 0) tv.tv_sec = 0; /* RAPID select */

	  rc = select( topfd+1, &rdset, &wrset, NULL, &tv );
	  time(&now);

	  if (rc == 0) {
	    /* Select timeout.. */
	    rc = (subdaemon_handler->postselect)( statep, & rdset, & wrset );
	    if (rc > 0) {
	      /* The subprocess became HUNGRY! */
	      subdaemon_pick_next_job( peers, top_peer, subdaemon_handler, statep );
	    }
	    continue;
	  }

	  if (rc > 0) { /* Things have been read or written.. */

	    rc = (subdaemon_handler->postselect)( statep, & rdset, & wrset );
	    if (rc > 0) {
	      /* The subprocess became HUNGRY! */
	      subdaemon_pick_next_job( peers, top_peer, subdaemon_handler, statep );
	    }


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
		    char *p = peer->inpbuf;
		    char *o = peer->outbuf;
		    int  sp = peer->inpspace;
		    int  so = peer->outspace;
		    if (top_peer <= n)  top_peer = n + 1;
		    memset( peer, 0, sizeof(*peer) );
		    peer->inpbuf   = p;
		    peer->inpspace = sp;
		    peer->outbuf   = o;
		    peer->outspace = so;

		    if (!peer->inpbuf) {
		      peer->inpspace = 64;
		      peer->inpbuf = calloc(1, peer->inpspace);
		    }
		    if (!peer->outbuf) {
		      peer->outspace = 250;
		      peer->outbuf = calloc(1, 250); /* FIXME: MAGIC! */
		    }

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
		    if ((peer->inpspace - peer->inlen) < 32) {
		      /* Enlarge the buffer! */
		      peer->inpspace += 64;
		      peer->inpbuf = realloc(peer->inpbuf,
					     peer->inpspace);
		    }
		    rc = read( peer->fd, peer->inpbuf + peer->inlen,
			       peer->inpspace - peer->inlen );
		    if (rc > 0) {
		      peer->inlen += rc;
		      if (peer->inpbuf[ peer->inlen -1 ] == '\n')
			break; /* Stop here! */
		      continue; /* read more, if there is.. */
		    }
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
		    if (peer->inpbuf[ peer->inlen -1 ] == '\n') {
		      rc = (subdaemon_handler->input)( statep, peer );
		      if (rc > 0) {
			/* XOFF .. busy right now, come back again.. */
		      } else if (rc == 0) {
			/* XON .. give me more jobs */
			subdaemon_pick_next_job( peers, top_peer,
						 subdaemon_handler, statep );
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

	if (subdaemon_handler->shutdown)
	  (subdaemon_handler->shutdown)( statep );

	return -1;
}

/* ------------------------------------------------------------------ */

void
subdaemon_kill_peer(peer)
     struct peerdata *peer;
{
	close(peer->fd);
	peer->fd = -1;
}


/* Send to peer, synchronously wait for buffer to clear,
   if everything didn't fit into outbound buffer.
 */

int
subdaemon_send_to_peer(peer, buf, len)
     struct peerdata *peer;
     const char *buf;
     int len;
{
	int rc, fit;

#if 0
	if (logfp) {
	  fprintf(logfp, "subrtr\tsend_to_peer() peerfd=%d outlen=%d outptr=%d  len=%d\n",
		  peer->fd, peer->outlen, peer->outptr, len);
	}
#endif

	/* If 'peer' is NULL, crash here, and study the core file
	   to determine the bug.. */

	while (len > 0) {

	  if (peer->outptr > 0) {
	    /* Compact the buffer a bit! */
	    memmove( peer->outbuf,
		     peer->outbuf + peer->outptr,
		     peer->outlen - peer->outptr );
	    peer->outlen -= peer->outptr;
	    peer->outptr = 0;
	  }

	  fit = peer->outspace - peer->outlen; /* outptr == 0 */
	  if (fit > len) fit = len; /* But no more than what we have.. */

	  if (fit > 0) {
	    memcpy(peer->outbuf + peer->outlen, buf, fit);
	    peer->outlen += fit;
	    buf += fit;
	    len -= fit;
	  }

	  /* "SYNC" writing to the FD... */

	  rc = write( peer->fd,
		      peer->outbuf + peer->outptr,
		      peer->outlen - peer->outptr );
	  if (rc > 0) {
	    peer->outptr += rc;
	    if (peer->outptr == peer->outlen)
	      peer->outlen = peer->outptr = 0;
	    continue; /* Written all.. */
	  }
	  if ((rc < 0) && (errno == EBADFD)) {
	    subdaemon_kill_peer(peer);
	    return -1;
	  }
	  if ((rc < 0) && (errno == EINTR))
	    continue; /* try again */

	  if ((rc < 0) && (errno == EPIPE)) {
	    /* SIGPIPE from writing to the socket..  */
	    peer->outlen =  peer->outptr = len = 0;
	    break;  /* Lets ignore it, and reading from
		       the same socket will be EOF - I hope.. */
	  }

	  if ((len > 0) && (rc < 0) && (errno == EAGAIN)) {
	    /* Select on it, if there is still unprocessed input left! */

	    struct timeval tv;
	    fd_set wrset;
	    _Z_FD_ZERO(wrset);
	    _Z_FD_SET(peer->fd, wrset);
	    tv.tv_sec = 10; /* FIXME: 10 seconds ?? */
	    tv.tv_usec = 0;
	    rc = select ( peer->fd+1, NULL, &wrset, NULL, &tv );
	    if ((rc < 0) && (errno == EINTR)) continue;
	    if (rc < 0) {
	      /* ???? What ?????   FIXME:  */
	      subdaemon_kill_peer(peer);
	      return -1;
	    }
	    if (rc == 0) {
	      /* FIXME: TIMEOUT! */
	      subdaemon_kill_peer(peer);
	      return -1;
	    }
	    continue; /* Did successfully select for writing */
	  }
	  /* If  len > 0  in here, we have something BROKEN! */
	  if ((len > 0) && (rc < 0)) {
	    /* Mainly we should have no wowwies...
	       but all kinds of surprising error modes
	       do creep up..*/
	      subdaemon_kill_peer(peer);
	      return -1;
	  }
	}

	if (peer->outptr > 0) {
	  /* Compact memory.. */
	  memmove( peer->outbuf,
		   peer->outbuf + peer->outptr,
		   peer->outlen - peer->outptr );
	  peer->outlen -= peer->outptr;
	  peer->outptr = 0;
	}

	return 0; /* Stored successfully for outgoing traffic.. */
}


/* ------------------------------------------------------------------ */

void subdaemon_pick_next_job( peers, top_peer, subdaemon_handler, statep )
     struct peerdata *peers;
     int top_peer;
     struct subdaemon_handler *subdaemon_handler;
     void *statep;
{
	int i, rc;
	struct peerdata *peer;

	for (i = 0; i < top_peer; ++i) {
	  peer = & peers[i];
	  if ((peer->fd >= 0) && (peer->inlen > 0) &&
	      peer->inpbuf && 
	      (peer->inpbuf[ peer->inlen -1 ] == '\n')) {

	    rc = (subdaemon_handler->input)( statep, peer );
	    return;
	  }
	}
}


/* ------------------------------------------------------------------ */

/*
 *  fdgets() -- allocate a buffer, read one chat at the time from
 *              the fd, in non-blocking mode, 
 *	Return number of characters read, -1 for errors, 0 for EOF!
 */

static int
fdgetc(fdp, fd, timeout)
     struct fdgets_fdbuf *fdp;
     int fd, timeout;
{
	int c, rc;
	int rdspace;
	char *p;

	if (fdp->rdsize > sizeof(fdp->rdbuf)) fdp->rdsize = 0;

 extract_from_buffer:
	if (fdp->rdsize > 0) {
	  /* Have buffered data! */
	  c = 255 & (fdp->rdbuf[0]);
	  fdp->rdsize -= 1;
	  if (fdp->rdsize > 0)
	    memmove(fdp->rdbuf, fdp->rdbuf+1, fdp->rdsize);
	  return c;
	}

	/* The buffer is empty.. */
	rdspace = sizeof(fdp->rdbuf);
	fdp->rdsize = 0;
	p = fdp->rdbuf;

	for (;;) {
	    /* if (logfp)
	       fprintf(logfp, "to read() fd=%d len=%d\n",fd, rdspace);
	    */
	    rc = read(fd, p, rdspace);
	    c = errno;

	    /* if (logfp)
	       fprintf(logfp, "fdgetc() read(fd=%d rdspc=%d) -> rc=%d\n",
	       fd, rdspace, rc);
	    */

	    errno = c;

	    if (rc > 0) {
	      fdp->rdsize += rc;
	      goto extract_from_buffer;
	    }
	    if (rc == 0) return -1; /* EOF */
	    if (errno == EBADFD) return -1; /* Simulate EOF! */
	    if (errno == EINTR) continue;
	    if (errno == EAGAIN) {
		fd_set rdset;
		struct timeval tv;

		if (timeout < 0) {
		  errno = EAGAIN;
		  return -2; /* EAGAIN.. */
		}

		_Z_FD_ZERO(rdset);
		tv.tv_sec = timeout;
		tv.tv_usec = 0;
		_Z_FD_SET(fd, rdset);
		rc = select( fd+1, &rdset, NULL, NULL, &tv );
		if (rc == 0) {
		  errno = EBUSY;
		  return -3; /* TIMEOUT!  D'UH! */
		}
	    }
	}
	return (255 & c);
}

int
fdgets (bufp, endi, buflenp, fdp, fd, timeout)
     char **bufp;
     struct fdgets_fdbuf *fdp;
     int *buflenp, endi, fd, timeout;
{
	int i;
	char c;
	char *buf  = *bufp;
	int buflen = *buflenp;

	if (fd < 0) return -1;
	fd_nonblockingmode(fd);

	i = endi;
	for (;;) { /* Accumulate a line */
	    c = fdgetc(fdp, fd, timeout);

	    /* if (logfp)
	       fprintf(logfp, "fdgetc() ret=%d c='%c'\n",c,c);
	    */

	    if ((i + 4 > buflen) || !buf) {
		buflen += 64;
		buf = realloc(buf, buflen);
	    }

	    if (c < 0) break; /* Any of break reasons.. */

	    buf[i++] = c;
	    if (c == '\n') break;
	}

	if ((i >= 0) && buf)
	    buf[i] = 0;

	fd_blockingmode(fd);

	*bufp = buf;
	*buflenp = buflen;

	if (i == 0) return c;
	return i;
}
