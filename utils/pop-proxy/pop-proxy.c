/*
 * pop-proxy   --  POP3 proxy for Sonera Corporation (Finland)
 *		   (ex name: Telecom Finland) internet services
 *
 * Written by Matti Aarnio <matti.aarnio@sonera.fi> 1998/March
 *
 *  Copyright Sonera Corporation
 *
 *  This has been merged into ZMailer sources because:
 *  - Sonera Corp uses ZMailer at POP-mailbox operations
 *  - There are integration items in between these message-store
 *    access systems (POP and IMAP proxies) and outbound smtp services
 *    in form of using authenticated POP or IMAP access as temporary
 *    key for successfull acceptance of smtp traffic for outbound relay
 *    from any address in the known netaddress universe.
 *  The integration is not complete (into autoconfig), because
 *  our low-level libraries are not so easily autoconfigurable :-/
 *
 */
/*
 * TODO:
 * - Do more complex protocol recognition phase so that USER+PASS
 *   commands are both recognized, and are reported back to user
 *   thru code that analyzes WHAT the server really said. That way
 *   this proxy can recognize, when the USER+PASS has been accepted.
 *   If the PASS is not accepted, QUIT the server, and humm around
 *   locally asking for a new USER.  If the PASS is accepted, only
 *   then do 
 * - Log successfull connections to SMTP server's IP-source opening
 *   system for temporary acceptance of outbound SMTP relaying.
 * - SSLeay tunneling integration
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <syslog.h>

#ifdef USE_AA0		/* Sonera Corp. backend db access v-1 */
#include "aa0client.h"
#else
#ifdef USE_AA_ARB	/* Sonera Corp. backend db access v-2 */
#include "arblib.h"
#else
#endif
#endif

int serverport = 10110;
int timeout    = 10*60; /* The default timeout for select and alarm() */
int debug      = 0;

time_t t0 = 0;
long pop_in_bytes = 0;
long pop_out_bytes = 0;
char *username = "<NOT-LOGGED-IN>";
char *popserver = "<NOT-LOGGED-IN>";
#ifdef LOGFAC
const int facility = LOGFAC;
#else
const int facility = LOG_MAIL;
#endif

struct sockaddr_in raddr;

void syslog_stats(int rc)
{
  time_t t1 = time(NULL);
  openlog("pop3-proxy", LOG_PID, facility);
  syslog(LOG_INFO, "from=%s fromport=%d user=%s host=%s  duration=%d  char-in=%ld char-out=%ld  rc=%d",
	 inet_ntoa(raddr.sin_addr), ntohs(raddr.sin_port),
	 username, popserver, (int)(t1 - t0), pop_in_bytes, pop_out_bytes, rc);
}


void sigalrm(int sig)
{
  if (debug) printf("*** SIGALRM !!! Timeout death...\r\n");
  syslog_stats(90);
  _exit(90);
}


int user_to_server_fd(char *username)
{
	/* XXXX: lookup from AA0/ARB, connect there, and
	   issue "USER nnnn\r\n" command.  Return fd.
	   In case of failure to find server, to connect to
	   it, return -1 (and close possibly open socket) */

	int fd = -1;
	int rc, i;
	struct sockaddr_in sin;
	char keybuf[200];
	char aa0result[9000];
	char *hname, *s;
	struct hostent *hp;
#define userread aa0result
	int userrdspc, userrdcnt;
#define userwrite aa0result
	int userwrspc, userwrcnt;

#ifdef USE_AA0
	AA0DB *aa0db;

	if (aa_locate("MBOX", &aa0db, "QUERY", 0) == 0) {
	  if (debug) printf("** backend db access error 1\r\n");
	  return -1; /* No database ? */
	}

	sprintf(keybuf,"MBOX:%.60s_ipro", username);
	rc = -1;
	for (i = 0; i < 3; ++i) {
	  rc = aa0get(aa0db, keybuf, aa0result);
	  if (rc == AA0RET_OK)
	    break;
	}
	aa0close(aa0db);
	if (rc != AA0RET_OK) {
	  if (debug) printf("** backend db access error 2\r\n");
	  return -1;
	}
#else
#ifdef USE_AA_ARB
	sprintf(keybuf,"%.60s_ipro", username);
	for (i = 0; i < 3; ++i) {
	  rc = arbget ("mbox", keybuf, aa0result, sizeof (aa0result));
	  if (rc == AAS_SUCCESS)
	    break;
	}
	closearb();
	if (rc != AAS_SUCCESS) {
	  if (debug) printf("** backend db access error 2\r\n");
	  return -1;
	}
#else
# error "Neither AA0 nor ARB in use ??!!  What database do you use ?"
#endif
#endif

#if defined(USE_AA0) || defined(USE_AA_ARB)
	/* Data in AA0RESULT buffer, scan for the 7th ":" separated field */
	s = aa0result;
	for (i = 0; i < 6; ++i) {
	  if (s != NULL)
	    s = strchr(s+1,':');
	}
	if (s) {
	  ++s;
	} else {
	  if (debug) printf("** backend db access error - bad data\r\n");
	  return -1;
	}
	hname = s;
	s = strchr(s,':');
	if (s) *s = '\0';
#else
# error "Neither AA0 nor ARB in use ??!!  What database do you use ?"
#endif

	/* Now 'hname' has the hostname */
	if (*hname == 0) {
	  if (debug) printf("** backend db access error - bad data\r\n");
	  return -1; /* Invalid! */
	}

	hp = gethostbyname(hname);
	if (!hp) {
	  if (debug) printf("** backend db access error - bad data\r\n");
	  return -1;
	}

	popserver = strdup(hname);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
	  if (debug) printf("** Proxy failed to create socket ???\r\n");
	  return -1;
	}
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port   = htons(serverport);
	memcpy(&sin.sin_addr.s_addr,hp->h_addr,4); /* TCP/IP */

	if (connect(fd, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
	  if (debug) printf("** connect to real server (%s:%d) failed: %s\r\n",
			    inet_ntoa(sin.sin_addr), serverport,
			    strerror(errno));
	  return -1;
	}

	/* Now we have successfull connect -- to somewhere */

	/* We pull in stuff from there until \n, and then
	   send there string:  "USER username\r\n" */

	userrdspc = userrdcnt = 0;
	*userread = 0;
	for (;;) {
	  rc = read(fd, userread+userrdspc, sizeof(userread)-userrdspc-1);
	  /* We use VERY DANGEROUS assumptions here, but this protocol
	     is supposedly half-duplex at this moment anyway.. */
	  if (rc < 0) {
	    /* Hmm.. */
	    if (errno == EINTR)
	      continue; /* Again... */
	    /* XXX: HUH!? */
	  }
	  if (rc == 0) {
	    /* EOF -- damn..  Ah well. */
	    syslog_stats(22);
	    exit(22);
	  }
	  userrdspc += rc;
	  userread[userrdspc] = 0; /* Make sure there is \0 */
	  if (memchr(userread + userrdspc - rc, '\n', rc) != NULL)
	    break; /* Found \n there, great.. */
	}

	/* Now build the output, and write it! */
	
	userwrspc = sprintf(userwrite, "USER %.200s\r\n", username);
	userwrcnt = 0;

	while (userwrspc > userwrcnt) {
	  rc = write(fd, userwrite + userwrcnt, userwrspc - userwrcnt);
	  if (rc < 0) {
	    rc = 0;
	    /* XX: which  errno  values may happen ? */
	    if (errno == EPIPE) {
	      syslog_stats(33);
	      exit(0);
	    }
	  }
	  userwrcnt += rc;
	}

	/* It is written!  We are free to continue with PROXY operation */

	return fd;

#undef userread
#undef userwrite
}

void server(int fd, int issock)
{
	/* I/O buffers:				*/
	char userread[512];
	char servread[512];
	char *userwrite = servread;
	/* How much data in those buffers:	*/
	int userrdcnt = 0, userrdspc = 0;
	int userwrcnt = 0, userwrspc = 0;
	int servrdcnt = 0, servrdspc = 0;
	int rc;

	int serverfd = -1;
	int quitnow  = 0;
	int highfd;

	userwrspc = sprintf(userwrite, "+OK POP3 proxy\r\n");
	userwrcnt = 0; 

	while (serverfd < 0) {
	  /* Pull in commandlines, recognize some commands,
	     and do processing */
	  char command[20+1], param[500+1];

	  alarm(timeout);

	  while (userwrspc > userwrcnt) {
	    rc = write(fd, userwrite + userwrcnt, userwrspc - userwrcnt);
	    if (rc < 0) {
	      rc = 0;
	      /* XX: which  errno  values may happen ? */
	      if (errno == EPIPE) {
		syslog_stats(55);
		exit(0);
	      }
	    }
	    userwrcnt += rc;
	  }
	  userwrspc = userwrcnt = 0;
	  /* Ok, output buffer written */

	  if (quitnow) {
	    syslog_stats(0);
	    exit(0);
	  }

	  /* Now we live a bit dangerously, and presume the input
	     to be line oriented.  The danger being, the input
	     MAY get more than line's data if the remote sends
	     input in a burst -- "USER nnn\r\nPASS mmm\r\n"
	     without waiting for +OK/-ERR in between. */

	  userrdspc = userrdcnt = 0;
	  *userread = 0;
	  for (;;) {
	    rc = read(fd, userread+userrdspc, sizeof(userread)-userrdspc-1);
	    /* We use VERY DANGEROUS assumptions here, but this protocol
	       is supposedly half-duplex at this moment anyway.. */
	    if (rc < 0) {
	      /* Hmm.. */
	      if (errno == EINTR)
		continue; /* Again... */
	      /* XXX: HUH!? */
	    }
	    if (rc == 0) {
	      /* EOF -- damn..  Ah well. */
	      syslog_stats(20);
	      exit(20);
	    }
	    userrdspc += rc;
	    userread[userrdspc] = 0; /* Make sure there is \0 */
	    if (memchr(userread + userrdspc - rc, '\n', rc) != NULL)
	      break; /* Found \n there, great.. */
	  }
	  userrdspc = userrdcnt = 0;

	  *command = 0;
	  *param   = 0;
	  sscanf(userread, "%20s %500[^\r\n]", command, param);

	  if (strcasecmp(command,"user") == 0) {
	    /* Talk with user's socket to pull in "USER xxxx" */
	    serverfd = user_to_server_fd(param);
	    username = strdup(param);
	    if (serverfd < 0) {
	      /* No success, claim such anyway.. */
	      userwrspc = sprintf(userwrite, "+OK Give PASS\r\n");
	      userwrcnt = 0;
	      continue;
	    }
	  } else if (strcasecmp(command,"pass")==0) {
	    userwrspc = sprintf(userwrite, "-ERR Sorry, something failed, bad username, password mismatch\r\n");
	    userwrcnt = 0;
	  } else if (strcasecmp(command,"quit")==0) {
	    userwrspc = sprintf(userwrite, "+OK Bye bye\r\n");
	    userwrcnt = 0;
	    quitnow = 1;
	  } else if (strcasecmp(command,"debug")==0) {
	    userwrspc = sprintf(userwrite, "*** DEBUG TURNED ON, POP-PROTOCOL BREAKS\r\n");
	    userwrcnt = 0;
	    debug = 1;
	  } else {
	    userwrspc = sprintf(userwrite, "-ERR Don't know that command, I am Proxy\r\n");
	    userwrcnt = 0; 
	  }

	} /* Server acquisition loop ends */

	alarm(0);

	/* Now we have a server on  serverfd */

	fcntl(fd,       F_SETFL, fcntl(fd,       F_GETFL, 0) | O_NONBLOCK);
	fcntl(serverfd, F_SETFL, fcntl(serverfd, F_GETFL, 0) | O_NONBLOCK);

	/* Copy from  serverfd to fd, and the other way.
	   Exit if either yields EOF */

	highfd = fd;
	if (serverfd > highfd)
	  highfd = serverfd;
	++highfd;

	for (;;) {

	  /* Do we need timeout monitoring ?
	     Propably not, but one never knows, thus we rig
	     an alarm of 10 minutes at each select call.
	     If it expires, we close both sockets, and exit. */

	  struct timeval tv;
	  fd_set rdset, wrset;

	  FD_ZERO(&rdset); FD_ZERO(&wrset);
	  tv.tv_sec = timeout; tv.tv_usec = 0; /* 10 minutes */

	  if (userrdspc > 0) /* fd -> serverfd */
	    FD_SET(serverfd, &wrset); /* Things to write */
	  else
	    FD_SET(fd, &rdset); /* Just watch for read then */

	  if (servrdspc > 0) /* serverfd -> fd */
	    FD_SET(fd, &wrset); /* Things to write */
	  else
	    FD_SET(serverfd, &rdset); /* Just watch for read then */


	  rc = select(highfd, &rdset, &wrset, NULL, &tv);
	  if (rc == 0) {
	    /* Timeout! */
	    close(fd);
	    close(serverfd);
	    syslog_stats(40);
	    exit(40);
	  }
	  if (rc < 0) {
	    if (errno == EINTR)
	      continue;
	    /* Other errs ?? */
	    continue;
	  }
	  if (FD_ISSET(fd, &rdset)) { /* READ: <-- user */
	    /* To read from user */
	    rc = read(fd, userread, sizeof(userread));
	    if (rc == 0) { /* EOF ! */
	      syslog_stats(60);
	      exit(60);
	    }
	    if (rc < 0) {
	      rc = 0;
	    }
	    userrdcnt = 0;
	    userrdspc = rc;
	  }
	  if (FD_ISSET(serverfd, &rdset)) { /* READ: <-- server */
	    /* To read from server */
	    rc = read(serverfd, servread, sizeof(servread));
	    if (rc == 0) { /* EOF ! */
	      syslog_stats(61);
	      exit(61);
	    }
	    if (rc < 0) {
	      rc = 0;
	    }
	    pop_out_bytes += rc;
	    servrdcnt = 0;
	    servrdspc = rc;
	  }
	  if (FD_ISSET(fd, &wrset)) { /* WRITE: server -> user */
	    /* We have stuff to write, and space for it */
	    rc = write(fd, servread + servrdcnt, servrdspc - servrdcnt);
	    if (rc < 0) {
	      rc = 0;
	      /* Errs ? */
	      if (errno == EPIPE) { /* Closed */
		close(fd);
		close(serverfd);
		syslog_stats(62);
		exit(62);
	      }
	    }
	    servrdcnt += rc;
	    if (servrdcnt >= servrdspc)
	      servrdcnt = servrdspc = 0;
	  }
	  if (FD_ISSET(serverfd, &wrset)) { /* WRITE: user -> server */
	    /* We have stuff to write, and space for it */
	    rc = write(serverfd, userread + userrdcnt, userrdspc - userrdcnt);
	    if (rc < 0) {
	      rc = 0;
	      /* Errs ? */
	      if (errno == EPIPE) { /* Closed */
		close(fd);
		close(serverfd);
		syslog_stats(64);
		exit(64);
	      }
	    }
	    userrdcnt += rc;
	    pop_in_bytes += rc;
	    if (userrdcnt >= userrdspc)
	      userrdcnt = userrdspc = 0;
	  }
	}
	/* NOT REACHED */
}

int main(int argc, char *argv[])
{
	int c;
	int raddrlen;
	int issock = 1;

	while ((c = getopt(argc,argv,"p:T:?")) != EOF) {
	  /* Reserved options:
	      -S            This is SSLeay POP3 proxy
	      -P host:port  Where to report successfull connects for
	                    temporary opening SMTP acceptance for
			    outbound SMTP relaying.
	  */
	  switch (c) {
	  case 'p':
	    serverport = atoi(optarg);
	    break;
	  case 'T':
	    timeout = atoi(optarg); /* In minutes, value range: 1 .. 30 */
	    if (timeout < 1)
	      timeout = 1;
	    if (timeout > 30)
	      timeout = 30;
	    timeout = timeout * 60;
	    break;
	  case '?':
	    break;
	  default:
	    break;
	  }
	}

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	setvbuf(stdin,  NULL, _IONBF, 0);

	time(&t0);

	raddrlen = sizeof(raddr);
	if (getpeername(0, (struct sockaddr *) & raddr, &raddrlen) < 0) {
	  issock = 0;
	  memset(&raddr, 0, sizeof(raddr));
	  /* In theory: (errno == ENOTSOCK)  when not socket.. */
	}

	signal(SIGPIPE, SIG_IGN); /* socket remote close can cause SIGPIPE
				     to be fed back to the socket fd ... */
	signal(SIGALRM, sigalrm);

	server(0, issock);
	return 0;
}
