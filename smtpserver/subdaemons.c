/*
 *    Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *      This will be free software, but only when it is finished.
 */
/*
 *    Several extensive changes by Matti Aarnio <mea@nic.funet.fi>
 *      Copyright 1991-2004.
 */




#include "smtpserver.h"

static int  ratetracker_rdz_fd  [2] = {-1, -1};
static int  ratetracker_server_pid  = 0;

static int  router_rdz_fd       [2] = {-1, -1};
static int  router_server_pid       = 0;

static int  contentfilter_rdz_fd[2] = {-1, -1};
static int  contentfilter_server_pid = 0;

struct peerdata {
	int fd;
	int inlen;
	int outlen;
	char inpbuf[200];
	char outbuf[500];
};

static int subdaemon_nofiles = 32;


static int subdaemon_handler_rtr __((struct peerdata *, void*));
static int subdaemon_handler_trk __((struct peerdata *, void*));
static int subdaemon_handler_ctf __((struct peerdata *, void*));

static void subdaemon_loop __((int, int (*subdaemonhandler)(struct peerdata *, void *) ));

int subdaemon_init __((void))
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

	    fdpass_to_child_fds(to, from);

	    subdaemon_loop(0, subdaemon_handler_trk);

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

	    fdpass_to_child_fds(to, from);

	    subdaemon_loop(0, subdaemon_handler_rtr);

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

	    fdpass_to_child_fds(to, from);

	    subdaemon_loop(0, subdaemon_handler_ctf);

	    exit(0);
	  }
	  pipes_close_parent(to,from);
	}

	return 0;
}


int subdaemon_loop(fd, subdaemon_handler)
     int fd;
     int (*subdaemon_handler)__((struct peerdata *, void *));
{
	int n;
	struct peerdata *peers;

	peers = malloc(sizeof(*peers) * subdaemon_nofiles);

	for (;;) {

	  sleep(1000);
	}
}


static int
subdaemon_handler_rtr (peerdata, state)
     struct peerdata *peerdata;
     void *state;
{
}

static int
subdaemon_handler_trk (peerdata, state)
     struct peerdata *peerdata;
     void *state;
{
}

static int
subdaemon_handler_ctf (peerdata, state)
     struct peerdata *peerdata;
     void *state;
{
}
