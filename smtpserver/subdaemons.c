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
/* static void subdaemon_pick_next_job __(( struct peerdata *peers, int top_peer, struct subdaemon_handler *subdaemon_handler, void *statep)); */



void subdaemon_ratetracker(fd)
     int fd;
{
  Vuint i1, i2;

  if (logfp) fclose(logfp); logfp = NULL;
  /* report(NULL,"[smtpserver ratetracker subsystem]"); */

  subdaemon_handler_ratetracker.reply_queue_G = & i1;
  subdaemon_handler_ratetracker.reply_delay_G = & i2;
  
  subdaemon_loop(fd, & subdaemon_handler_ratetracker);
  zsleep(10);
  exit(0);
}

void subdaemon_contentfilter(fd)
     int fd;
{
  if (logfp) fclose(logfp); logfp = NULL;
  /* report(NULL,"[smtpserver contentfilter subsystem]"); */

  subdaemon_handler_contentfilter.reply_queue_G = & MIBMtaEntry->ss.Cfilter_queue_G;
  subdaemon_handler_contentfilter.reply_delay_G = & MIBMtaEntry->ss.Cfilter_reply_delay_G;

  subdaemon_loop(fd, & subdaemon_handler_contentfilter);
  zsleep(10);
  exit(0);
}

void subdaemon_router(fd)
     int fd;
{
  if (logfp) fclose(logfp); logfp = NULL;
  /* report(NULL,"[smtpserver router subsystem]"); */

  subdaemon_handler_router.reply_queue_G = & MIBMtaEntry->ss.Irouter_queue_G;
  subdaemon_handler_router.reply_delay_G = & MIBMtaEntry->ss.Irouter_reply_delay_G;

  subdaemon_loop(fd, & subdaemon_handler_router);
  zsleep(10);
  exit(0);
}


int subdaemons_init_router __((void))
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

	if (enable_router) {
	  rc = fdpass_create(to);
	  if (rc == 0) {
	    router_rdz_fd = to[1];
	    router_server_pid = fork();
	    if (router_server_pid == 0) { /* CHILD */
	      
	      if (router_rdz_fd >= 0)
		close(router_rdz_fd); /* Our sister server's handle */
	      if (ratetracker_rdz_fd >= 0)
		close(ratetracker_rdz_fd); /* Our sister server's handle */
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

int subdaemons_init_ratetracker __((void))
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

	    if (router_rdz_fd >= 0)
	      close(router_rdz_fd); /* Our sister server's handle */
	    if (contentfilter_rdz_fd >= 0)
	      close(contentfilter_rdz_fd); /* Our sister server's handle */

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
	return 0;
}

int subdaemons_init_contentfilter __((void))
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

	while (contentfilter) {
	  struct stat stbuf;

	  if (stat(contentfilter, &stbuf)) {
	    type(NULL,0,NULL, "contentfilter stat(%s) error %d",
		 contentfilter, errno);
	    return 0;
	  }

	  if (!S_ISREG(stbuf.st_mode))
	    break;  /* Do not start contentfilter subdaemon. */

	  rc = fdpass_create(to);
	  if (rc == 0) {
	    contentfilter_rdz_fd = to[1];
	    contentfilter_server_pid = fork();
	    if (contentfilter_server_pid == 0) { /* CHILD */
	      
	      if (router_rdz_fd >= 0)
		close(router_rdz_fd); /* Our sister server's handle */
	      if (ratetracker_rdz_fd >= 0)
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
	  break;
	}  /* .. while contentfilter */

	return 0;
}

int subdaemons_init __((void))
{
	subdaemons_init_ratetracker();
	subdaemons_init_contentfilter();
	subdaemons_init_router();

	return 0;
}


static RETSIGTYPE
default_reaper(sig)
     int sig;
{
    int status;
    pid_t lpid;

    SIGNAL_HOLD(SIGCHLD);

    sawsigchld = 0;

    for (;;) {
#ifdef	HAVE_WAITPID
	lpid = waitpid(-1, &status, WNOHANG);
#else
#ifdef	HAVE_WAIT4
	lpid = wait4(0, &status, WNOHANG, (struct rusage *) NULL);
#else
#ifdef	HAVE_WAIT3
	lpid = wait3(&status, WNOHANG, (struct rusage *) NULL);
#else				/* ... plain simple waiting wait() ... */
	/* This can freeze at wait() ?  Who could test ?  A system
	   without wait3()/waitpid(), but with BSD networking ??? */
	lpid = wait(&status);
#endif				/* WNOHANG */
#endif
#endif
	if (lpid <= 1) break; /* For whatever reason */
    }

    SIGNAL_HANDLE(SIGCHLD, sigchld);
    SIGNAL_RELEASE(SIGCHLD);
}


void job_linkin( head, peer )
     struct peerhead *head;
     struct peerdata *peer;
{
	peer->head = head;
	if (head->tail) {
	  peer->prev = head->tail;
	  head->tail->next = peer;
	  peer->next = NULL;
	  head->tail = peer;
	} else {
	  /* head->tail == NULL -- which means that also  head->head == NULL */
	  head->tail = peer;
	  head->head = peer;
	  peer->next = NULL;
	  peer->prev = NULL;
	}
	++ peer->head->queuecount;
	*(peer->handler->reply_queue_G) = peer->head->queuecount;
}

void job_unlink( peer )
     struct peerdata *peer;
{
	if (!peer || !peer->head) return;

	if (peer->head->head == peer)
	  peer->head->head = peer->next;
	if (peer->head->tail == peer)
	  peer->head->tail = peer->prev;

	if (peer->next)
	  peer->next->prev = peer->prev;
	if (peer->prev)
	  peer->prev->next = peer->next;

	-- peer->head->queuecount;
	*(peer->handler->reply_queue_G) = peer->head->queuecount;

	peer->next = NULL;
	peer->prev = NULL;
	peer->head = NULL;

}


void
subdaemon_kill_peer(peer)
     struct peerdata *peer;
{
	close(peer->fd);
	peer->fd = -1;
	peer->in_job = 0;

	job_unlink( peer );
}


int subdaemon_loop(rendezvous_socket, subdaemon_handler)
     int rendezvous_socket;
     struct subdaemon_handler *subdaemon_handler;
{
	int n, rc;
	struct peerdata *peers, *peer;
	struct peerhead job_head;
	void *statep = NULL;
	/* int ppid; */
	int top_peer = 0, top_peer2, topfd, newfd;
	/* int last_peer_index = 0; */

	fd_set rdset, wrset;
	struct timeval tv;

	SIGNAL_HANDLE(SIGCHLD, sigchld);
	SIGNAL_RELEASE(SIGCHLD);

	memset( & job_head, 0, sizeof(job_head) );

	SIGNAL_HANDLE(SIGPIPE, SIG_IGN);

	subdaemon_nofiles = resources_query_nofiles();
	if (subdaemon_nofiles < 32) subdaemon_nofiles = 32; /* failsafe */

	/* Don't close files/handles, the system shuts down
	   without it just fine */
	/* .. except that it doesn't, if the main smtpserver process
	   has detected some subsystem dying, and has been doing recovery.. */
#if 1
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

	  /* ppid = getppid(); -- not used anymore */

	  if (sawsigchld) {
	    if (subdaemon_handler->reaper)
	      subdaemon_handler->reaper( &statep );
	    else
	      default_reaper(SIGCHLD);
	  }

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
	      /* if (peers[n].inlen == 0) */
	      /* Always check for readability:
		 There might have been timeout and connection close! */
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
	      goto talk_with_subprocesses;
	    }
	    continue;
	  }

	  if (rc > 0) { /* Things have been read or written.. */

	    rc = (subdaemon_handler->postselect)( statep, & rdset, & wrset );
#if 0 /* No need to do anything more in here.. */
	    if (rc > 0) {
	      /* The subprocess became HUNGRY! */
	      subdaemon_pick_next_job( peers, top_peer, subdaemon_handler, statep );
	    }
#endif

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
		    peer->handler  = subdaemon_handler;

		    if (!peer->inpbuf) {
		      peer->inpspace = 250;
		      peer->inpbuf = calloc(1, peer->inpspace+1);
		    }
		    if (!peer->outbuf) {
		      peer->outspace = 250;  /* FIXME: MAGIC! - big enough ? */
		      peer->outbuf = calloc(1, peer->outspace+1);
		    }

		    peer->fd = newfd;
		    fd_nonblockingmode(newfd);
		    /* We write our greeting right away .. semi fake state! */
		    _Z_FD_SET(peer->fd, wrset);

		    memcpy(peer->outbuf, "#hungry\n", 8);
		    peer->outlen = 8;
		    peer->outptr = 0;
		    newfd = -1;

		    break; /* Out of the for-loop! */
		  }
		}
	      }
	      if (newfd >= 0) {
		/* Oh no...  We had no place to put this in... */
		close(newfd);
		/* XXX: syslog this situation ???? */
	      }
	    }

	    /* Now I/O of all of my peers.. */

	    for (n = 0; n < top_peer; ++n) {
	      peer = & peers[n];
	      if (peer->fd >= 0) {

		/* If we have things to output, and write is doable ? */
		if (peer->outlen > 0 && _Z_FD_ISSET(peer->fd, wrset)) {
		  rc = 0;
		  for (;;) {
#ifdef DEBUG_WITH_UNLINK
		    {
		      char pp[50];
		      sprintf(pp,"/tmp/-write-to-peer-%d",peer->fd);
		      unlink(pp);
		    }
#endif
		    rc = write(peer->fd,
			       peer->outbuf + peer->outptr,
			       peer->outlen - peer->outptr);
		    if ((rc < 0) && (errno == EINTR))
		      continue; /* try again -- later */
		    if ((rc < 0) && (errno == EPIPE)) {
		      /* SIGPIPE from writing to the socket..
			 Abort it completely! */
		      subdaemon_kill_peer(peer);
		      if (subdaemon_handler->killpeer)
			(subdaemon_handler->killpeer)( statep, peer );
		      break;
		    }
		    break;
		  }
		  if (rc > 0) {
		    if (rc == peer->outlen) {
		      peer->outlen = peer->outptr = 0;
		    } else {
		      /* Sigh..  partial write :-( */
		      peer->outptr += rc;
		      rc = peer->outlen - peer->outptr;
		      /* (rc > 0) */
		      memmove(peer->outbuf, peer->outbuf+peer->outptr, rc);
		      peer->outptr = 0;
		      peer->outlen = rc;
		    }
		    /* Clean debug outputs */
		    peer->outbuf[ peer->outlen ] = 0;
		  }
		} /* ... Writability testing */

		/* Now if we have something to read ?? */
		if (peer->fd >= 0 && _Z_FD_ISSET(peer->fd, rdset)) {
		  for (;;) {
		    if ((peer->inpspace - peer->inlen) < 32) {
		      /* Enlarge the buffer! */
		      peer->inpspace *= 2; /* Double the size */
		      peer->inpbuf = realloc( peer->inpbuf,
					      peer->inpspace+1 );
		    }
		    rc = read( peer->fd, peer->inpbuf + peer->inlen,
			       peer->inpspace - peer->inlen );
		    if (rc > 0) {
		      peer->inlen += rc;
		      if (peer->inpbuf[ peer->inlen -1 ] == '\n') {
			peer->in_job = 1;
			peer->when_in = now;
			job_linkin( &job_head, peer );
			break; /* Stop here! */
		      }
		      continue; /* read more, if there is.. */
		    }
		    if ((rc < 0) && (errno == EINTR))
		      continue; /* try again */
		    break; /* Something else wrong.. */
		  }
		  if (rc == 0) { /* EOF! */
		    subdaemon_kill_peer(peer);
		    if (subdaemon_handler->killpeer)
		      (subdaemon_handler->killpeer)( statep, peer );
		    continue;
		  }
		} /* ... read things */

	      } /* peers with valid fd */
	    } /* all peers */
	  } /* readability or writeability detected */


	  /* Now I/O of all peers with subdaemon
	     Track the point where subprocess said: XOF! */

	talk_with_subprocesses:;

	  for (n = 0; n < top_peer; ++n) {

#if 1
	    peer = job_head.head;
	    if (!peer) break;

	    rc = (subdaemon_handler->input)( statep, peer );

	    if (rc > 0) {
	      /* XOFF .. busy right now, come back again.. */
	      /* Do NOT advance the job pointer! */
	      break;
	    } else if (rc == 0) {
	      /* XON .. give me more jobs */
	      job_unlink( peer );
	      peer->in_job = 0; /* Done that one.. */
	      continue; /* go and pick next task talker, if any */
	    } /* ELSE ??? */

	    break; /* Err ??? */
#else
	    if (last_peer_index >= top_peer)
	      last_peer_index = 0;             /* Wrap around */

#if 1
	    peer = & peers[ last_peer_index ]; /* Round-robin;
						  in abominal overload
						  this means that nobody
						  gets service.
					       */
#if 0
#define CONTINUOUS_RR_COUNTING 1
	    ++ last_peer_index;		/* Continuous RR index counting,
					   sending may stop at somewhere,
					   but the counter progresses.. */
#endif
#else
	    peer = & peers[ n ];     /* Low slots get service;
					in abominal overload this means
					that some get service, while
					some others don't get it.
				     */
#endif
	    if (peer->in_job) {

	      /* Has a job, advance only, if was able to process it */

	      rc = (subdaemon_handler->input)( statep, peer );
#ifdef DEBUG_WITH_UNLINK
	      {
		char pp[50];
		sprintf(pp,"/tmp/-input-from-peer-%d->%d",peer->fd,rc);
		unlink(pp);
	      }
#endif
	      if (rc > 0) {
		/* XOFF .. busy right now, come back again.. */
		/* Do NOT advance the job pointer! */
		break;
	      } else if (rc == 0) {
		/* XON .. give me more jobs */
		peer->in_job = 0; /* Done that one.. */

#ifndef CONTINUOUS_RR_COUNTING
		/* Sent it ok, go to next task */
		++last_peer_index;
#endif
		continue; /* go and pick next task talker, if any */
	      } else {
		/* Xnone .. ??
		   Can't handle ??
		   Won't happen ??
		   Code Bug ?? */
#ifndef CONTINUOUS_RR_COUNTING
		/* Advance, just in case */
		++last_peer_index;
#endif
	      }
	    } else {

#ifndef CONTINUOUS_RR_COUNTING
	      /* No job to be processed,
		 advance in every case */
	      ++last_peer_index;
#endif
	    }
#endif
	  }
	} /* ... for(;;) ... */

	if (subdaemon_handler->shutdown)
	  (subdaemon_handler->shutdown)( statep );

	return -1;
}

/* ------------------------------------------------------------------ */

/* Send to peer, synchronously wait for buffer to clear,
   IF EVERYTHING DIDN'T FIT INTO OUTBOUND BUFFER.
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

	if (!peer) return -1; /* No peer! possibly killed at some point.. */

#ifdef DEBUG_WITH_UNLINK
	{
	  char pp[50];
	  sprintf(pp,"/tmp/-send-to-peer-%d",peer->fd);
	  unlink(pp);
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
	  if ((rc < 0) && ((errno == EBADF)
#ifdef EBADFD /* linux & Solaris, not FreeBSD ... */
			   || (errno == EBADFD)
#endif
			   )) {
	    subdaemon_kill_peer(peer);
	    return -1;
	  }
	  if ((rc < 0) && (errno == EINTR))
	    continue; /* try again */

	  if ((rc < 0) && (errno == EPIPE)) {
	    /* SIGPIPE from writing to the socket..  */
	    subdaemon_kill_peer(peer);
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
	peer->outbuf[ peer->outlen ] = 0; /* Debugging time buffer cleanup */

	time(&now);
	*(peer->handler->reply_delay_G) = now - peer->when_in;

	return 0; /* Stored successfully for outgoing traffic.. */
}


/* ------------------------------------------------------------------ */

#if 0
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
#endif

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
	    if (rc == 0) return 0; /* EOF */
	    if (errno == EBADF) return 0; /* Simulate EOF! */
#ifdef EBADFD /* linux & Solaris, not FreeBSD ... */
	    if (errno == EBADFD) return 0; /* Simulate EOF! */
#endif
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

	    if (c <= 0) break; /* Any of break reasons.. */

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
