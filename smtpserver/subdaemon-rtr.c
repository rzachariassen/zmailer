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


static int subdaemon_handler_rtr_init  __((void**));
static int subdaemon_handler_rtr_input __((void *, struct peerdata*));
static int subdaemon_handler_rtr_preselect  __((void*, fd_set *, fd_set *, int *));
static int subdaemon_handler_rtr_postselect __((void*, fd_set *, fd_set *));

struct subdaemon_handler subdaemon_handler_router = {
	subdaemon_handler_rtr_init,
	subdaemon_handler_rtr_input,
	subdaemon_handler_rtr_preselect,
	subdaemon_handler_rtr_postselect,
};

/* ============================================================ */

static int
subdaemon_handler_rtr_init (statep)
     void **statep;
{
	int i;

	return -1;
}

static int
subdaemon_handler_rtr_input (state, peerdata)
     void *state;
     struct peerdata *peerdata;
{
	int i;

	peerdata->inlen = 0;

	return -1;
}

static int
subdaemon_handler_rtr_preselect (state, rdset, wrset, topfd)
     void *state;
     fd_set *rdset, *wrset;
     int *topfd;
{
	int i;

	return -1;
}

static int
subdaemon_handler_rtr_postselect (state, rdset, wrset)
     void *state;
     fd_set *rdset, *wrset;
{
	int i;

	return -1;
}
