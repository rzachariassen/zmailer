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
 */

/* *** INITIALLY HERE IS NO IPv6 SUPPORT IN THIS CODE!
 * ***
 * *** Especially RFC 3041 may doom simple "account by IP address"
 * *** thing...  After all, those who have something to hide do
 * *** most certainly use all possible ways to anonymize themselves.
 * *** It MIGHT make sense to track a /64 subsets of addresses, and
 * *** count things with that granularity (when counting at all.)
 */


#include "smtpserver.h"
#include "splay.h"

#define SLOTINTERVAL 512  /* There are 8 slots, slow sliding
			     bucket accounter.. */
/* Temporary testing stuff: */
#undef  SLOTINTERVAL
#define SLOTINTERVAL 10

extern int ratetracker_rdz_fd;
extern int ratetracker_server_pid;

static int subdaemon_handler_trk_init  __((void**));
static int subdaemon_handler_trk_input __((void *, struct peerdata *));
static int subdaemon_handler_trk_preselect  __((void*, fd_set *, fd_set *, int *));
static int subdaemon_handler_trk_postselect __((void*, fd_set *, fd_set *));


struct subdaemon_handler subdaemon_handler_ratetracker = {
	subdaemon_handler_trk_init,
	subdaemon_handler_trk_input,
	subdaemon_handler_trk_preselect,
	subdaemon_handler_trk_postselect,
};


/* ============================================================ */


#if 0 /* from splay.h */
struct spblk {
	struct spblk	*leftlink;
	struct spblk	*rightlink;
	struct spblk	*uplink;
	spkey_t		key;		/*  <--  IPv4 address     */
	const char	*data;		/*  (struct ipv4_regs *)  */
	long		mark;
};
#endif

struct ipv4_regs {
	struct spblk *spl;	/* == NULL  -> free */
	struct ipv4_regs *next;
	int countset[8];
};

struct ipv4_regs_head {
	int	count;
	struct ipv4_regs_head *next;
	struct  ipv4_regs *ipv4;
};

#if 0
struct ipv6_regs {
	struct ipv6_regs *next;
	struct spblk *spl;
	struct in6_addr ip6addr;
	int countset[8];
};

struct ipv6_regs_head {
	int	count;
	struct ipv6_regs_head *next;
	struct  ipv6_regs *ipv6;
};
#endif


struct trk_state {
	time_t	next_slotchange;
	int	slotindex;		/* = 0..7 */

	int	alloccount_v4;
	int	allocgauge_v4;

	struct ipv4_regs * ipv4;
	struct ipv4_regs * ipv4_free;
	struct ipv4_regs_head *ipv4_regs_head;
	struct sptree *spt4;

#if 0
	struct ipv6_regs * ipv6;
	struct ipv6_regs * ipv6_free;
	struct ipv6_regs_head * ipv6_regs_head;
	struct sptree *spt6;
#endif
};


/* Allocate a free ipv4_regs block for given IP addr,
   does also allocate splay-block item, plus interlinks
   spblk, and ipv4_regs structures with each other.
   MUST NOT BE CALLED, IF  ipv4addr  OBJECT EXIST IN
   THE DATABASE (e.g. the  lookup_ipv4_reg() just prior
   this function call!
*/

static struct ipv4_regs * alloc_ipv4_reg( state, ipv4addr )
     struct trk_state *state;
     long ipv4addr;
{
	int i;
	struct ipv4_regs *r;
	struct spblk *spl;

	if (! state->ipv4_free) {
	  /* No free entries, alloc a new block.. */

	  struct ipv4_regs_head *rh = calloc(1, sizeof(*rh));
	  if (!rh) return NULL;

	  r = calloc(1000, sizeof(*r));
	  if (!r) {
	    free(rh);
	    return NULL;
	  }
	  for (i=1; i < 1000; ++i) {
	    r[i-1].next = & r[i];
	  }
	  state->ipv4_free = r;

	  rh->count = 1000;
	  rh->ipv4  = r;
	  rh->next  = state->ipv4_regs_head;
	  state->ipv4_regs_head = rh;
	}

	++ state->alloccount_v4;
	++ state->allocgauge_v4;

	r = state->ipv4_free;
	state->ipv4_free = r->next;
	r->next = NULL; /* Remove this from the free list */

	spl = sp_install( ipv4addr, r, 0, state->spt4 );
	r->spl = spl;

	return r;
}

/* Return the  ipv4_regs  block into the free list,
   free the splay in here if it is non-NULL !        */

static void free_ipv4_reg( state, reg )
     struct trk_state *state;
     struct ipv4_regs *reg;
{
	if ( reg->spl ) {
	  sp_delete(reg->spl, state->spt4);
	  /* reg->spl = NULL; */
	}

	-- state->allocgauge_v4;

	memset(reg, 0, sizeof(*reg));

	reg->next = state->ipv4_free;
	state->ipv4_free = reg;
}

/* Find 'regs' for given spkey_t value (of IP address */

static struct ipv4_regs * lookup_ipv4_reg( state, ipv4addr )
     struct trk_state *state;
     unsigned int ipv4addr;
{
	struct spblk *spl;
	struct ipv4_regs *reg;

	spl = sp_lookup(ipv4addr, state->spt4);
	if (!spl) return NULL;

	reg = (struct ipv4_regs *) spl->data;

	return reg;
}

static int count_ipv4( state, ipv4addr, incr /* , counterlistspecs ? */ )
     struct trk_state *state;
     unsigned int ipv4addr;
     int incr;
{
	struct ipv4_regs *reg = lookup_ipv4_reg( state, ipv4addr );
	int i, sum;

	if (!reg) {
	  reg = alloc_ipv4_reg( state, ipv4addr );
	  if (!reg) return -1;    /*  D'UH!  */
	}

	reg->countset[ state->slotindex ] += incr;

	sum = 0;
	for (i = 0; i < 8; ++i)
	  sum += reg->countset[ i ];

	return sum;
}


static void new_ipv4_timeslot( state )
     struct trk_state *state;
{
	struct ipv4_regs *r;
	struct ipv4_regs_head *rhead;
	int i;

	static const int zerocountset[8] = {0,};

	state->slotindex += 1;
	if (state->slotindex > 7) state->slotindex = 0;

	state->next_slotchange = now + SLOTINTERVAL;

	rhead = state->ipv4_regs_head;

	for ( ; rhead ; rhead = rhead->next ) {

	  r = rhead->ipv4;

	  for (i = 0; i < rhead->count; ++i) {

	    /* Clear this just now changed head of slots! */
	    r[i].countset[ state->slotindex ] = 0;

	    /* See if now ALL slots are ZERO value.. */
	    if (memcmp(zerocountset, r[i].countset,
		       sizeof(zerocountset)) == 0 ) {

	      /* It is all-zero counter set */
	      free_ipv4_reg( state, & r[i] );

	    }
	  }
	}
}


/* ---------------------------------------------------------------------- */

static int got_sigusr1;

static RETSIGTYPE subdaemon_trk_sigusr1(sig)
     int sig;
{
	got_sigusr1 = 1;

	SIGNAL_HANDLE(sig, subdaemon_trk_sigusr1);
}

static void subdaemon_trk_checksigusr1(state)
     struct trk_state *state;
{
	struct ipv4_regs *r;
	struct ipv4_regs_head *rhead;
	int i, j;
	unsigned int ip4key;
	FILE *fp;

	if (!got_sigusr1) return;  /* Nothing to do, bail out */


	/* We are running as 'trusted' user, which is somebody
	   else, than root. */
	fp = fopen("/var/tmp/smtpserver-ratetracker.dump", "w");

	if (!fp) return;

	rhead = state->ipv4_regs_head;

	for ( ; rhead ; rhead = rhead->next ) {

	  r = rhead->ipv4;

	  for (i = 0; i < rhead->count; ++i) {

	    if (r[i].spl == NULL) {
	      fprintf(fp, "0.0.0.0\n");
	    } else {
	      ip4key = r[i].spl->key;
	      fprintf(fp, "%u.%u.%u.%u\t",
		      (ip4key >> 24) & 255,  (ip4key >> 16) & 255,
		      (ip4key >>  8) & 255,   ip4key & 255 );
	      for (j = 0; j < 8; ++j) {
		fprintf(fp, "%-4d  ", r[i].countset[j]);
	      }
	      fprintf(fp, "\n");
	    }
	  } /* All entries in this block */
	} /* All blocks.. */


	fclose(fp);
}


static int
subdaemon_handler_trk_init (statep)
     void **statep;
{
	struct trk_state *state = calloc(1, sizeof(*state));
	*statep = state;

        runastrusteduser();

	SIGNAL_HANDLE(SIGUSR1, subdaemon_trk_sigusr1);

	if (!state) return -1;

	state->spt4 = sp_init();


	return 0;
}

static int
subdaemon_handler_trk_input (statep, peerdata)
     struct peerdata *peerdata;
     void *statep;
{
	struct trk_state *state = statep;
	char actionlabel[8], iplabel[20], typelabel[10];
	int i, incr;
	long ipv4addr;

	time(&now);

	subdaemon_trk_checksigusr1(state);

	/* If it is about time to handle next slot, we flip to it,
	   and run garbage collect run on system. */

	if (now >= state->next_slotchange)
	  new_ipv4_timeslot( state );

	/*
	 * Protocol:
	 *
	 * C: <actionlabel> <ipaddrlabel> <typelabel>
	 * S: 200 <value>
	 *
	 * Where:
	 *  <actionlabel>: "RATE" or "INCR"
	 *  <ipaddrlabel>: "4:12345678", or "6:123456789abcdef0"
	 *  <typelabel>:   "CONNECT" or "MAIL"
	 *
	 */


	actionlabel[0] = iplabel[0] = typelabel[0] = 0;

	i = sscanf(peerdata->inpbuf, "%7s %19s %9s",
		   actionlabel, iplabel, typelabel);
	if (i != 3) goto bad_input;

	actionlabel[sizeof(actionlabel)-1] = 0;
	typelabel[sizeof(typelabel)-1] = 0;
	iplabel[sizeof(iplabel)-1] = 0;

	incr = 0;
	if (strcmp(actionlabel,"INCR") == 0)
	  incr = 1;
	else if (strcmp(actionlabel,"RATE") != 0)
	  goto bad_input;

	if (iplabel[0] == '4' && iplabel[1] == ':') {

	  ipv4addr = strtol( iplabel+2, NULL, 16);
	  /* FIXME: - htonl() ???  */

	  i = count_ipv4( state, ipv4addr, incr );

	  sprintf(peerdata->outbuf, "200 %d\n", i);
	  peerdata->outlen = strlen(peerdata->outbuf);

	} else
	  goto bad_input;

	if (0) {
	bad_input:
	  sprintf(peerdata->outbuf,"500 bad input\n");
	  peerdata->outlen = strlen(peerdata->outbuf);
	}

	peerdata->inlen = 0;
	return 0;
}


/* Nothing is done in  pre-select(),  and same is true with post-select().. */

static int
subdaemon_handler_trk_preselect (state, rdset, wrset, topfd)
     void *state;
     fd_set *rdset, *wrset;
     int *topfd;
{
	subdaemon_trk_checksigusr1(state);

	return 0;
}

static int
subdaemon_handler_trk_postselect (state, rdset, wrset)
     void *state;
     fd_set *rdset, *wrset;
{
	subdaemon_trk_checksigusr1(state);

	return 0;
}


/* ------------------------------------------------------------------ */
struct trk_client_state {
	int fd_io;
};

int
call_subdaemon_trk (statep, cmd, retbuf, retbuflen)
     void **statep;
     const char *cmd;
     char *retbuf;
     int retbuflen;
{
	struct trk_client_state * state = *statep;
	int rc;
	char buf[2000];

	if (! state) {
	  state = *statep = calloc(1, sizeof(struct trk_client_state));
	  if (!state) return -1; /* alloc failure! */

	  state->fd_io = -1;
	}

	if (state->fd_io < 0) {
	  int tochild[2];

	  /* Abusing the thing, to be exact, but... */
	  rc = socketpair(PF_UNIX, SOCK_STREAM, 0, tochild);
	  if (rc != 0) return -1; /* create fail */


	  state->fd_io = tochild[1];
	  if (fdpass_sendfd(ratetracker_rdz_fd, tochild[0])) {
	    /* did error somehow */
	    return -1;
	  }

	  fd_blockingmode(state->fd_io);

	  /* FIXME: Read the '#hungry\n' message ! */
	  /* readbuf(); */

	}

	/* FIXME: actual calls! */

	
}
