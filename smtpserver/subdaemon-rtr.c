/*
 *    Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *      This will be free software, but only when it is finished.
 */
/*
 *    Several extensive changes by Matti Aarnio <mea@nic.funet.fi>
 *      Copyright 1991-2004.
 */

/*  SMTPSERVER  ROUTER MULTIPLEXER-SERVER  SUBDAEMON    */

/*
 * Protocol from client to server is of TEXT LINES that end with '\n'
 * and are without '\r'... (that are meaningless inside the system.)
 *
 * The fd-passing system sends one byte of random junk, and a bunch
 * of ancilliary data (the fd.)
 */


#include "smtpserver.h"

static const char *Hungry = "#hungry\n";

static int subdaemon_handler_rtr_init  __((void**));
static int subdaemon_handler_rtr_input __((void *, struct peerdata*));
static int subdaemon_handler_rtr_preselect  __((void*, fd_set *, fd_set *, int *));
static int subdaemon_handler_rtr_postselect __((void*, fd_set *, fd_set *));
static int subdaemon_handler_rtr_shutdown   __((void*));
static int subdaemon_handler_rtr_killpeer __((void *, struct peerdata*));

struct subdaemon_handler subdaemon_handler_router = {
	subdaemon_handler_rtr_init,
	subdaemon_handler_rtr_input,
	subdaemon_handler_rtr_preselect,
	subdaemon_handler_rtr_postselect,
	subdaemon_handler_rtr_shutdown,
	subdaemon_handler_rtr_killpeer
};

#define MAXRTRS 20

static int MaxRtrs = 2;
int enable_router_maxpar = 2;

typedef struct state_rtr {
	struct peerdata *replypeer;
	int   routerpid;
	FILE *tofp;
	int   fromfd;
	char *buf;
	int   inlen;
	int   bufsize;
	int   sawhungry;
	time_t last_cmd_time;
	struct fdgets_fdbuf fdb;
} RtState;


static void subdaemon_killr __(( RtState * RTR ));

static void
subdaemon_killr(RTR)
     RtState *RTR;
{
	if (RTR->routerpid > 1) {
	  if (RTR->tofp == NULL)
	    fclose(RTR->tofp);
	  RTR->tofp   = NULL;
	  if (RTR->fromfd >= 0)
            close(RTR->fromfd);
	  RTR->fromfd = -1;
	  kill(RTR->routerpid, SIGTERM);
	  RTR->routerpid = 0;

	  subdaemon_send_to_peer(RTR->replypeer,
				 "400 i-router killr\n", 19);

	  RTR->replypeer = NULL;
	}
}


/* ============================================================ */

/*
 * The way VRFY and EXPN are implemented, and even MAIL FROM and RCPT TO
 * checking, we somehow connect to a router and ask it to do stuff for us.
 * There are three routines, one to connect to the router, one to kill it
 * off again, and the line-getting routine that gets everything the router
 * prints at us, one line at a time.
 */


#ifndef HAVE_PUTENV
static const char *newenviron[] =
  { "SMTPSERVER=y", NULL };
#endif

static int subdaemon_callr __((RtState * RTR));
static int subdaemon_callr (RTR)
     RtState *RTR;
{
	int rpid = 0, to[2], from[2], rc;
	char *cp;

	/* We want to write to blocking socket/pipe, while
	   reading from non-blocking one.. */

	if (pipe(to) < 0 || pipe(from) < 0)
	  return -1;

	if (routerprog == NULL) {
	  cp = (char *)getzenv("MAILBIN");
	  if (cp == NULL) {
	    zsyslog((LOG_ERR, "MAILBIN unspecified in zmailer.conf"));
	    return -1;
	  }
	  routerprog = emalloc(strlen(cp) + sizeof "router" + 2);
	  if (!routerprog) return -1; /* malloc failed! */
	  sprintf(routerprog, "%s/router", cp);
	}

	fcntl(to[1],   F_SETFD, FD_CLOEXEC);
	fcntl(from[0], F_SETFD, FD_CLOEXEC);

	rpid = fork();
	if (rpid == 0) {	/* child */
	  rpid = getpid();
	  if (to[0] != 0)
	    dup2(to[0], 0);
	  if (from[1] != 1)
	    dup2(from[1], 1);
	  dup2(1, 2);
	  if (to[0] > 2)   close(to[0]);
	  if (from[1] > 2) close(from[1]);

	  runasrootuser();	/* XXX: security alert! */
#ifdef HAVE_PUTENV
	  putenv("SMTPSERVER=y");
#else
	  environ = (char **) newenviron;
#endif
	  execl(routerprog, "router", "-io-i", "-Ismtpserver", NULL);

#define	BADEXEC	"#BADEXEC\n\n"
	  write(1, BADEXEC, sizeof(BADEXEC)-1);
	  _exit(1);

	} else if (rpid < 0)
	  return -1;

	RTR->routerpid = rpid;

	close(to[0]);
	close(from[1]);

	RTR->tofp   = fdopen(to[1], "w");
	fd_blockingmode(to[1]);
	if (! RTR->tofp ) return -1; /* BAD BAD! */

	RTR->fromfd = from[0];
	fd_blockingmode(RTR->fromfd);
	
	for (;;) {
	  rc = fdgets( & RTR->buf, 0, & RTR->bufsize,
		       & RTR->fdb, RTR->fromfd, 10);

	  /* type(NULL,0,NULL,"fdgets-RTR-1: bufsize=%d '%s' rc=%d lastc=%d",
	     RTR->bufsize, RTR->buf, rc, RTR->buf[rc-1]);
	  */

	  if ( rc <= 0 ) {
	    /* EOF.. */
	    subdaemon_killr(RTR);
	    return -1;
	  }
	  if ( rc < 1 || ! RTR->buf ) {
	    /* FIXME: ERROR PROCESSING ?? */
	    continue;
	  }
	  if (strncmp( RTR->buf, BADEXEC, sizeof(BADEXEC) - 3) == 0) {
	    subdaemon_killr(RTR);
	    return -1;
	  }

	  if (strcmp( RTR->buf, Hungry ) == 0) {
	    RTR->sawhungry = 1;
	    break;
	  }
	}
	fd_nonblockingmode(RTR->fromfd);

	time( &RTR->last_cmd_time );

	return rpid;
}


/* ------------------------------------------------------------ */


static int
subdaemon_handler_rtr_init (statep)
     void **statep;
{
	RtState *state;
	int idx;

	MaxRtrs = enable_router_maxpar;
	if (MaxRtrs < 1)       MaxRtrs = 1;
	if (MaxRtrs > MAXRTRS) MaxRtrs = MAXRTRS;

	*statep = state  = calloc(MaxRtrs, sizeof(RtState));


	if (state) {
	  for (idx = 0; idx < MaxRtrs; ++idx) {
	    state[idx].routerpid = 0;
	    state[idx].fromfd    = -1;
	  }
	}

#if 0
	{
	  extern int logstyle;
	  extern char *logfile;
	  extern void openlogfp __((SmtpState * SS, int insecure));

	  logstyle = 0;
	  if (logfp) fclose(logfp); logfp = NULL;
	  logfile = "smtpserver-rtr-subdaemons.log";
	  openlogfp(NULL, 1);
	  setlinebuf(logfp);
	}
#endif
	SIGNAL_HANDLE(SIGCHLD,SIG_IGN);

	return 0;
}

/*
 * subdaemon_handler_xx_input()
 *   ret > 0:  XOFF... busy right now!
 *   ret == 0: XON... give me more work!
 */
static int
subdaemon_handler_rtr_input (state, peerdata)
     void *state;
     struct peerdata *peerdata;
{
	RtState *RTstate = state;
	int rc = 0;
	int idx;

	if (!state) exit(EX_USAGE); /* things are BADLY BROKEN! */

	for (idx = 0; idx < MaxRtrs; ++idx) {
	  RtState *RTR = & RTstate[idx];

	  if (RTR->replypeer)
	    continue; /* Busy talking with somebody.. */

	  /* If we have an empty slot,
	     start a subserver process! */

	  if (RTR->routerpid <= 1) {
	    rc = subdaemon_callr(RTR);
	    if (rc < 2) {
	      /* FIXME: error processing! */
	      struct timeval tv;
	      tv.tv_sec = 1;
	      tv.tv_usec = 0;
	      select(0, NULL, NULL, NULL, &tv); /* Sleep about 1 sec.. */
	      return 2; /* WAIT!  actually this is an error situation.. */
	    }

	    /* Now   RTR->fromfd   is in NON-BLOCKING MODE!
	       However  RTR->tofp  is definitely in blocking! */
	  }

	  if (!RTR->sawhungry) /* Not yet ready for use */
	    continue;

	  /* We have a router sub-process ready for action! */

	  RTR->replypeer = peerdata;

	  fwrite(peerdata->inpbuf, peerdata->inlen, 1, RTR->tofp);
	  fflush(RTR->tofp);

	  time( &RTR->last_cmd_time );

	  RTR->bufsize    = 0;
	  RTR->sawhungry  = 0;
	  peerdata->inlen = 0;
	  peerdata->inpbuf[0] = 0;

	  return 0; /* I _MAY_ be able to take more work! */
	}

	return 1;  /* Do come again! */
}


static int
subdaemon_handler_rtr_killpeer (state, peerdata)
     void *state;
     struct peerdata *peerdata;
{
	int idx;
	RtState *RTstate = state;

	for (idx = 0; idx < MaxRtrs; ++idx) {

	  RtState *RTR = & RTstate[idx];

	  if (RTR->replypeer != peerdata)
	    continue; /* not me */

	  RTR->replypeer = NULL;

	  RTR->bufsize        = 0;
	  RTR->sawhungry      = 0;
	  peerdata->inlen     = 0;
	  peerdata->inpbuf[0] = 0;

	  break;
	}

	return 0;
}


static int
subdaemon_handler_rtr_preselect (state, rdset, wrset, topfdp)
     void *state;
     fd_set *rdset, *wrset;
     int *topfdp;
{
	int rc = -1;
	int idx;
	RtState *RTstate = state;

	if (! state) return 0; /* No state to monitor */

	/* If we have a router underneath us,
	   check if it has something to say! */
 
	for (idx = 0; idx < MaxRtrs; ++idx) {
	  RtState *RTR = & RTstate[idx];

	  if (RTR->fromfd >= 0) {
	    _Z_FD_SETp(RTR->fromfd, rdset);
	    if (*topfdp < RTR->fromfd)
	      *topfdp = RTR->fromfd;
	    if (RTR->fdb.rdsize)
	      rc = 1;
	  }
	}

	return rc;
}

static int
subdaemon_handler_rtr_postselect (state, rdset, wrset)
     void *state;
     fd_set *rdset, *wrset;
{
	int rc = 0;
	int idx;
	int sawhungry = 0;
	RtState *RTstate = state;

	if (! state) return -1; /* No state to monitor */

	for (idx = 0; idx < MaxRtrs; ++idx) {

	  RtState *RTR = & RTstate[idx];

	  if (RTR->fromfd < 0)
	    continue; /* No router at this slot */

	  if ( _Z_FD_ISSETp(RTR->fromfd, rdset) ||
	       RTR->fdb.rdsize ) {
	    /* We have something to read ! */

	    rc = fdgets( & RTR->buf, RTR->inlen,
			 & RTR->bufsize,
			 & RTR->fdb, RTR->fromfd, -1);

	    /* type(NULL,0,NULL,
	       "fdgets-RTR-2: bufsize=%d '%s' rc=%d lastc=%d",
	       RTR->bufsize, RTR->buf, rc, RTR->buf[rc-1]);
	    */

	    if (rc < 0 && errno == EAGAIN) 
	      /* Let the loop to spin ...
		 actually the select has said: readable!
		 but still that is sometimes wrong...
	      */
	      continue;

	    if (rc <= 0) { /* EOF - timeout, or something.. */
	      /* EOFed, KILL IT! */
	      subdaemon_killr(RTR);
	      /* Start it again! */
	      if (subdaemon_callr(RTR) > 1)
		sawhungry = 1;
	      continue;
	    }

	    if (rc > 0) {
	      RTR->inlen = rc;
	      if (RTR->buf[rc-1] == '\n') {
		/* Whole line accumulated, send it out! */

		if (RTR->replypeer)
		  subdaemon_send_to_peer(RTR->replypeer, RTR->buf, rc);
		RTR->inlen = 0; /* Zap it.. */
	      }

	      if (strcmp( RTR->buf, Hungry ) == 0) {
		RTR->sawhungry = 1;
		sawhungry = 1;
		RTR->replypeer = NULL;
	      }
	    }
	  }

	  if ((now - RTR->last_cmd_time) > SUBSERVER_IDLE_TIMEOUT) {
	    subdaemon_killr(RTR);
	    continue;
	  }

	}

	return sawhungry;
}



static int
subdaemon_handler_rtr_shutdown (state)
     void *state;
{
	return -1;
}


/* --------------------------------------------------------------- */
/*  client caller interface                                        */
/* --------------------------------------------------------------- */

/* extern int  router_rdz_fd; */

struct rtr_state {
	int fd_io;
	FILE *outfp;
	int buflen;
	char *buf;
	char *pbuf;
	int sawhungry; /* remote may yield  N  lines of output, 
			  until  Hungry  */
	struct fdgets_fdbuf fdb;
};


static void smtprouter_kill __((struct rtr_state *));
static void
smtprouter_kill ( state )
     struct rtr_state * state;
{
	if (state->outfp) fclose(state->outfp);
	state->outfp = NULL;

	if (state->fd_io >= 0) {
	  close(state->fd_io);
	  state->fd_io = -1;
	}
	if (state->buf)  free(state->buf);
	state->buf = NULL;
}


static int smtprouter_init __((struct rtr_state **));

static int
smtprouter_init ( statep )
     struct rtr_state **statep;
{
	struct rtr_state *state = *statep;
	int toserver[2];
	int rc;

	if (router_rdz_fd <0) return -1; /* The irouter is not available */


	if (!state)
	  state = *statep = calloc(1, sizeof(*state));
	if (!state) return -1;

	state->fd_io = -1;
	state->fdb.rdsize = 0;

	/* Abusing the thing, to be exact, but... */
	rc = socketpair(PF_UNIX, SOCK_STREAM, 0, toserver);
	if (rc != 0) return -2; /* create fail */

	state->fd_io = toserver[1];
	rc = fdpass_sendfd(router_rdz_fd, toserver[0]);

	if (debug)
	  type(NULL,0,NULL,"smtprouter_init: fdpass_sendfd(%d,%d) rc=%d, errno=%s",
	       ratetracker_rdz_fd, toserver[0], rc, strerror(errno));

	if (rc != 0) {
	  /* did error somehow */
	  close(toserver[0]);
	  close(toserver[1]);
	  return -3;
	}
	close(toserver[0]); /* Sent or not, close the remote end
			       from our side. */

	if (debug)
	  type(NULL,0,NULL,"smtprouter_init; 9");

	fd_blockingmode(state->fd_io);

	state->outfp = fdopen(state->fd_io, "w");

	if (debug)
	  type(NULL,0,NULL,"smtprouter_init; 10");
	errno = 0;

	if (state->buf) state->buf[0] = 0;
	if (fdgets( & state->buf, 0, & state->buflen, & state->fdb, state->fd_io, 10 ) <= 0) {
	  /* something failed! -- timeout in 10 secs ?? */
	  if (debug)
	    type(NULL,0,NULL,"smtprouter_init; FAILURE 10-B");
	  smtprouter_kill( state );
	  return -4;
	}

	if (debug)
	  type(NULL,0,NULL,"smtprouter_init; 11; errno=%s",
	       strerror(errno));

	if ( !state->buf  || (strcmp(state->buf, Hungry) != 0) )
	  return -5; /* Miserable failure.. Not getting proper protocol! */

	if (debug)
	  type(NULL,0,NULL,"smtprouter_init; 12");

	state->sawhungry = 1;

	return 0;

}



/*
 * The way VRFY and EXPN are implemented, and even MAIL FROM and RCPT TO
 * checking, we somehow connect to a router and ask it to do stuff for us.
 * There are three routines, one to connect to the router, one to kill it
 * off again, and the line-getting routine that gets everything the router
 * prints at us, one line at a time.
 */


/*
 * Now we can do VRFY et al using the router we have connected to.
 */

char *
router(SS, function, holdlast, arg, len)
     SmtpState *SS;
     const char *function, *arg;
     const int holdlast, len;
{
	int rc;
	struct rtr_state *state;
	unsigned char *p;
	time_t then;

	time( &then );

	if (arg == NULL) {
	  type(SS, 501, NULL, NULL);
	  return NULL;
	}
	if (!enable_router) {
	  type(SS, 400, "4.4.0","Interactive routing subsystem is not enabled");
	  return NULL;
	}

	state = SS->irouter_state;
	if (! state || !state->outfp) {
	  smtprouter_init( &state );
	  if (! state || !state->outfp || !state->sawhungry) {

	    if (!daemon_flg)
	      return strdup("200 No interactive router run;");

	    type(SS, 440, "4.4.0", "Failed to init interactive router subsystem");
	    smtprouter_kill( state );
	    return NULL;
	  }
	}
	/* if (state && state->outfp)  <<-- always true here ... */
	SS->irouter_state = state;

	if (! state->sawhungry ) {
	  /* Wrong initial state at this point in call! */
	  smtprouter_kill( state );
	  type(SS, 440, "4.4.0", "Interactive router subsystem lost internal sync ??");
	  return NULL;
	}

	/* We have seen  "#hungry\n",  now we go and send our little thingie
	   down the pipe... */

	fprintf(state->outfp, "%s\t", function);
	fwrite(arg, len, 1, state->outfp);
	fprintf(state->outfp, "\n");
	fflush(state->outfp);
	if (ferror(state->outfp)) {
	  fclose(state->outfp);
	  state->outfp = NULL;
	  return NULL;
	}

	/* Now we collect replies, until we see "#hungry" again.. */
	/* .. we do strip the trailing newline first.. */
	state->sawhungry = 0;

	while ( ! state->sawhungry ) {

	  /* The reply is better to reach us within 60 seconds.. */

	  if (state->buf) state->buf[0] = 0;
	  rc = fdgets( & state->buf, 0, & state->buflen, & state->fdb, state->fd_io, 60 );

	  time( &now );
	  if ((now - then) > 30)
	    type(NULL,0,NULL, "I-ROUTER DELAY %d SECONDS!",
		 (int)(now - then));

	  if (state->buf && (rc > 0))
	    if (state->buf[rc-1] == '\n')
	      state->buf[--rc] = 0;

	  if (debug)
	    type(NULL,0,NULL, "fdgets()->%p rc=%d buf=\"%s\"",
		 state->buf, rc, (state->buf ? state->buf : "<NULL>"));

	  if (rc <= 0) {
	    /* TIMED OUT !  BRR... */
	    smtprouter_kill( state );
	    type(SS, 450, "4.5.0", "Interactive router %s!",
		 (rc < 0) ? "timed out" : "EOFed" );
	    return NULL;
	  }

	  if ( strcmp(state->buf, "#hungry") == 0 ) {
	    state->sawhungry = 1;
	    /* Got "#hungry",  bail out, and yield pbuf .. */
	    if (debug)
	      type(NULL,0,NULL," GOT #hungry !");
	    break;
	  }


	  /* We have a new reply line here.. 
	     do present the previous one, if it exists... */

	  if (state->pbuf) {
	    p = (unsigned char *)state->pbuf; /* Previous buffer */
	    if (strlen(state->pbuf) > 3 &&
		isdigit(p[0]) && isdigit(p[1]) && isdigit(p[2]) && 
		(p[3] == ' ' || p[3] == '-')) {
	      int code = atoi(state->pbuf);
	      char *s = (char*) p + 4;
	      p += 4;
	      while (*p && (isdigit(*p) || *p == '.')) ++p;
	      if(*p == ' ') *p++ = 0;

	      if ((code / 100) != 2)
		type(SS, -code, s, "Hi %s, %s", SS->rhostaddr, p);
	      else
		type(SS, -code, s, "%s", p);
	    } else {
	      type(SS, -250, NULL, "%s", p);
	    }
	    free(state->pbuf);
	    state->pbuf = NULL;
	  }

	  state->pbuf = state->buf;
	  state->buf = NULL;

	}

	/* End of reply collection loop, here  state->pbuf  should
	   have content! */
	if (! state->pbuf ) {
	  smtprouter_kill( state );
	  if (holdlast)
	    return strdup("250 2.7.1 Interactive policy router failed, letting this thru...");
	  type(SS, 250, "2.7.1", "Interactive policy router failed, letting this thru...");
	  return NULL;
	}

	if (holdlast) {
	  /* Caller wants to have this! */
	  char *retp = state->pbuf;
	  state->pbuf = NULL;
	  return retp;

	} else {

	  /* Not holding last, type out the final thing */
	  p = (unsigned char *)state->pbuf; /* Previous buffer */
	  if (strlen(state->pbuf) > 3 &&
	      isdigit(p[0]) && isdigit(p[1]) && isdigit(p[2]) && 
	      (p[3] == ' ' || p[3] == '-')) {
	    int code = atoi(state->pbuf);
	    unsigned char *s = p + 4;
	    p += 4;
	    while (*p && (isdigit(*p) || *p == '.')) ++p;
	    if(*p == ' ') *p++ = 0;

	    if ((code / 100) != 2)
	      type(SS, code, (char*)s, "Hi %s, %s", SS->rhostaddr, p);
	    else
	      type(SS, code, (char*)s, "%s", p);
	  } else {
	    type(SS, 250, NULL, "%s", p);
	  }
	  free(state->pbuf);
	  state->pbuf = NULL;

	}
	typeflush(SS);
	return malloc(1); /* Just something freeable.. */
}
