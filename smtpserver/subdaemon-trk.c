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
#define SLOTCOUNT 8
#if 0
/* Temporary testing stuff: */
#undef  SLOTINTERVAL
#define SLOTINTERVAL 10
#endif

extern int ratetracker_rdz_fd;
extern int ratetracker_server_pid;

static int subdaemon_handler_trk_init  __((void**));
static int subdaemon_handler_trk_input __((void *, struct peerdata*));
static int subdaemon_handler_trk_preselect  __((void*, fd_set *, fd_set *, int *));
static int subdaemon_handler_trk_postselect __((void*, fd_set *, fd_set *));
static int subdaemon_handler_trk_shutdown   __((void*));


struct subdaemon_handler subdaemon_handler_ratetracker = {
	subdaemon_handler_trk_init,
	subdaemon_handler_trk_input,
	subdaemon_handler_trk_preselect,
	subdaemon_handler_trk_postselect,
	subdaemon_handler_trk_shutdown
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
	int mails, slots;
	int lastlimit;
	time_t alloc_time, last_excess, last_recipients;
	int excesses, excesses2, excesses3;
	int recipients, recipients2, recipients3;
	int countset[SLOTCOUNT];
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
	int countset[SLOTCOUNT];
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

	time_t	slot_starts[SLOTCOUNT];

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
	r->alloc_time = time(NULL);

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

static int count_ipv4( state, ipv4addr, lastlimit,
		       incr /* , counterlistspecs ? */ )
     struct trk_state *state;
     unsigned int ipv4addr;
     int incr, lastlimit;
{
	struct ipv4_regs *reg = lookup_ipv4_reg( state, ipv4addr );
	int i, sum;

	/* Don't allocate until an INCR is called for! */
	if (!reg && incr) {
	  reg = alloc_ipv4_reg( state, ipv4addr );
	  if (reg) reg->mails = 1;
	}
	if (!reg) return 0;    /*  not INCR, or alloc failed!  */

	if (incr == 0)  ++ reg->mails;

	if (lastlimit >= 0)
	  reg->lastlimit = lastlimit;
	reg->countset[ state->slotindex ] += incr;

	sum = 0;
	for (i = 0; i < SLOTCOUNT; ++i)
	  sum += reg->countset[ i ];

	return sum;
}


static void new_ipv4_timeslot( state )
     struct trk_state *state;
{
	struct ipv4_regs *r;
	struct ipv4_regs_head *rhead;
	int i;

	static const int zerocountset[SLOTCOUNT] = {0,};

	state->slotindex += 1;
	if (state->slotindex > SLOTCOUNT-1) state->slotindex = 0;

	state->next_slotchange = now + SLOTINTERVAL;
	state->slot_starts[ state->slotindex ] = now;

	rhead = state->ipv4_regs_head;

	for ( ; rhead ; rhead = rhead->next ) {

	  r = rhead->ipv4;

	  for (i = 0; i < rhead->count; ++i) {

	    /* Clear this just now changed head of slots! */
	    r[i].countset[ state->slotindex ] = 0;

	    ++ r[i].slots;
	    if (r[i].slots > SLOTCOUNT) {
	      r[i].excesses3 += r[i].excesses2;
	      r[i].excesses2  = r[i].excesses;
	      r[i].excesses   = 0;
	      r[i].recipients3 += r[i].recipients2;
	      r[i].recipients2  = r[i].recipients;
	      r[i].recipients   = 0;
	      r[i].slots = 0;
	    }

	    if (r[i].excesses2 || r[i].excesses3) continue;

	    /* See if now ALL slots are ZERO value.. */
	    if (memcmp(zerocountset, r[i].countset,
		       sizeof(zerocountset)) == 0 ) {

	      /* It is all-zero counter set */
	      free_ipv4_reg( state, & r[i] );
	    }
	  }
	}
}


static int count_excess_ipv4( state, ipv4addr )
     struct trk_state *state;
     unsigned int ipv4addr;
{
	struct ipv4_regs *reg = lookup_ipv4_reg( state, ipv4addr );
	if (!reg) return 0;    /*  not alloced!  */

	++ reg->excesses;
	reg->last_excess = now;

	return reg->excesses;
}

static int count_rcpts_ipv4( state, ipv4addr, incr )
     struct trk_state *state;
     unsigned int ipv4addr;
     int incr;
{
	struct ipv4_regs *reg = lookup_ipv4_reg( state, ipv4addr );
	if (!reg) return 0;    /*  not alloced!  */

	reg->recipients += incr;
	reg->last_recipients = now;

	return reg->recipients;
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
	int i, j, tr[SLOTCOUNT];
	unsigned int ip4key;
	FILE *fp = NULL;
	const char  *fn = "/var/tmp/smtpserver-ratetracker.dump";
	char buf[60];

	if (!got_sigusr1) return;  /* Nothing to do, bail out */
	got_sigusr1 = 0;

	time(&now);

	/* We are running as 'trusted' user, which is somebody
	   else, than root. */

	unlink(fn);
	i = open(fn, O_EXCL|O_CREAT|O_WRONLY,0666);
	if (i >= 0)
	  fp = fdopen(i, "w");

	if (!fp) return;

	for (i = 0, j = state->slotindex; i < SLOTCOUNT; ++i) {
	  tr[i] = j;
	  --j; if (j < 0) j = SLOTCOUNT-1;
	}


	rhead = state->ipv4_regs_head;

	for ( ; rhead ; rhead = rhead->next ) {

	  r = rhead->ipv4;

	  for (i = 0; i < rhead->count; ++i) {

	    if (r[i].spl != NULL) {
	      ip4key = r[i].spl->key;
	      sprintf(buf, "%u.%u.%u.%u",
		      (ip4key >> 24) & 255,  (ip4key >> 16) & 255,
		      (ip4key >>  8) & 255,   ip4key & 255 );
	      fprintf(fp, "%-16s", buf);
	      for (j = 0; j < SLOTCOUNT; ++j) {
		fprintf(fp, "%3d  ", r[i].countset[tr[j]]);
	      }
	      fprintf(fp, "\t");
	      fprintf(fp, "Lmt: %4d ", r[i].lastlimit);
	      fprintf(fp, "AllocAge: %6.3fh ", (double)(now-r[i].alloc_time)/3600.0);
	      fprintf(fp, "Mails: %6d ", r[i].mails);
	      fprintf(fp, "Excesses: %d %d %d ",
		      r[i].excesses, r[i].excesses2, r[i].excesses3);
	      fprintf(fp, "LastExcess: %ld", r[i].last_excess);
	      fprintf(fp, "\n");
	    }
	  } /* All entries in this block */
	} /* All blocks.. */


	fclose(fp);
}

static void dump_trk __(( struct trk_state *state, struct peerdata *peerdata ));
static void
dump_trk(state, peerdata)
     struct trk_state *state;
     struct peerdata *peerdata;
{
	int pid;
	FILE *fp;
	struct ipv4_regs *r;
	struct ipv4_regs_head *rhead;
	int i, j, tr[SLOTCOUNT];
	unsigned int ip4key;
	char buf[60];

	pid = fork();
	if (pid > 0) {
	  /* Parent.. */
	  if (peerdata->fd >= 0)
	    close(peerdata->fd);
	  peerdata->fd = -1;
	  peerdata->outlen = peerdata->outptr = 0;
	  return;
	}
	if (pid < 0) {
	  /* D'uh.. report error! */
	  sprintf(peerdata->outbuf, "500 DUMP failed to start!\n");
	  peerdata->outlen = strlen(peerdata->outbuf);
	  peerdata->outptr = 0;
	  return;
	}

	/* Child ..  We process things SYNCHRONOUSLY HERE,
	   and finally exit() ourself ..
	 */

	fd_blockingmode(peerdata->fd);
	fp = fdopen(peerdata->fd, "w");
	
	time(&now);

	for (i = 0, j = state->slotindex; i < SLOTCOUNT; ++i) {
	  tr[i] = j;
	  --j; if (j < 0) j = SLOTCOUNT-1;
	}

	rhead = state->ipv4_regs_head;

	fprintf(fp, "200-DUMP BEGINS\n");
	fflush(fp);

	for ( ; rhead ; rhead = rhead->next ) {

	  r = rhead->ipv4;

	  for (i = 0; i < rhead->count; ++i) {

	    if (r[i].spl != NULL) {
	      ip4key = r[i].spl->key;
	      sprintf(buf, "%u.%u.%u.%u",
		      (ip4key >> 24) & 255,  (ip4key >> 16) & 255,
		      (ip4key >>  8) & 255,   ip4key & 255 );
	      fprintf(fp, "200- %-16s", buf);
	      for (j = 0; j < SLOTCOUNT; ++j) {
		fprintf(fp, "%3d ", r[i].countset[tr[j]]);
	      }
	      fprintf(fp, "\t");
	      fprintf(fp, "Lmt: %4d", r[i].lastlimit);
	      fprintf(fp, " AllocAge: %6.3fh", (double)(now-r[i].alloc_time)/3600.0);
	      fprintf(fp, " Mails: %6d", r[i].mails);
	      fprintf(fp, " Excesses: %d %d %d",
		      r[i].excesses, r[i].excesses2, r[i].excesses3);
	      fprintf(fp, " LastExcess: %ld", r[i].last_excess);
	      fprintf(fp, " Rcpts: %d %d %d",
		      r[i].recipients, r[i].recipients2, r[i].recipients3);
	      fprintf(fp, "\n");
	      fflush(fp);
	    }
	  } /* All entries in this block */
	} /* All blocks.. */

	fprintf(fp, "200 DUMP ENDS\n");
	fflush(fp);
	fclose(fp);

	exit(0);
}


static void
slot_ages(state, outbuf)
     struct trk_state *state;
     char *outbuf; /* BAD style, we just PRESUME we have enough space.. */
{
	int i, j, tr[SLOTCOUNT];
	char *s = outbuf;

	for (i = 0, j = state->slotindex; i < SLOTCOUNT; ++i) {
	  tr[i] = j;
	  --j; if (j < 0) j = SLOTCOUNT-1;
	}

	strcpy(s, "200 Slot-ages: ");
	s += strlen(s);
	for (i = 0; i < SLOTCOUNT; ++i) {
	  if (state->slot_starts[tr[i]])
	    sprintf(s, " %d", (int)(now - state->slot_starts[tr[i]]));
	  else
	    sprintf(s, " 0");
	  s += strlen(s);
	}
	strcat(s, "\n");
}

static void
slot_ipv4_data(state, outbuf, ipv4addr)
     struct trk_state *state;
     char *outbuf; /* BAD style, we just PRESUME we have enough space.. */
     unsigned int ipv4addr;
{
	struct ipv4_regs *reg = lookup_ipv4_reg( state, ipv4addr );
	int i, j, tr[SLOTCOUNT];
	char *s = outbuf;

	if (!reg) {
	  strcpy(outbuf,"200 Slot-IPv4-data: 0 0 0 0  0 0 0 0  MAILs: 0 SLOTAGE: 0 Limit: 0 Excesses: 0 0 0 Latest: 0 Rcpts: 0 0 0\n");
	  s = strlen(outbuf)+outbuf;
#if 0
	  sprintf(s, "    [%d.%d.%d.%d]",
		  (ipv4addr >> 24) & 255,
		  (ipv4addr >> 16) & 255,
		  (ipv4addr >>  8) & 255,
		  (ipv4addr      ) & 255);
#endif
	  strcat(s, "\n");
	  return;
	}

	for (i = 0, j = state->slotindex; i < SLOTCOUNT; ++i) {
	  tr[i] = j;
	  --j; if (j < 0) j = SLOTCOUNT-1;
	}

	strcpy(s, "200 Slot-IPv4-data: ");
	s += strlen(s);
	for (j = 0; j < SLOTCOUNT; ++j) {
	  sprintf(s, " %d", reg->countset[tr[j]]);
	  s += strlen(s);
	}
	sprintf(s, " MAILs: %d", reg->mails);
	s += strlen(s);
	sprintf(s, " SLOTAGE: %d", (int)(now - reg->alloc_time));
	s += strlen(s);
	sprintf(s, " Limit: %d", reg->lastlimit);
	s += strlen(s);
	sprintf(s, " Excesses: %d %d %d Latest: %ld",
		reg->excesses, reg->excesses2, reg->excesses3,
		reg->last_excess);
	s += strlen(s);
	sprintf(s, " Rcpts: %d %d %d",
		reg->recipients, reg->recipients2, reg->recipients3);
	s += strlen(s);
	sprintf(s, "\n");
}


static int
subdaemon_handler_trk_init (statep)
     void **statep;
{
	struct trk_state *state = calloc(1, sizeof(*state));

#if 0
	{
	  extern int logstyle;
	  extern char *logfile;
	  extern void openlogfp __((SmtpState * SS, int insecure));

	  logstyle = 0;
	  if (logfp) fclose(logfp); logfp = NULL;
	  logfile = "smtpserver-trk-subdaemons.log";
	  openlogfp(NULL, 1);
	  setlinebuf(logfp);
	}
#endif


	*statep = state;

        /* runastrusteduser(); */

	SIGNAL_HANDLE(SIGUSR1, subdaemon_trk_sigusr1);
	SIGNAL_HANDLE(SIGCHLD,SIG_IGN);

	if (!state) return -1;

	state->spt4 = sp_init();

	time(&now);

	state->next_slotchange = now + SLOTINTERVAL;
	state->slot_starts[0]  = now;

	return 0;
}

static int
subdaemon_handler_trk_input (statep, peerdata)
     void *statep;
     struct peerdata *peerdata;
{
	struct trk_state *state = statep;
	char actionlabel[8], iplabel[40], typelabel[10];
	char lastlimits[12], countstr[10], *s1, *s2, *s3, *s4, *s5;
	int i, lastlimitval, countval;
	long ipv4addr;

	subdaemon_trk_checksigusr1(state);

	/* If it is about time to handle next slot, we flip to it,
	   and run garbage collect run on system. */

	if (now >= state->next_slotchange)
	  new_ipv4_timeslot( state );

	/*
	 * Protocol:
	 *
	 * C: <actionlabel> <ipaddrlabel> <lastlimit> <typelabel> <count>
	 * S: 200 <value>
	 *
	 * Where:
	 *  <actionlabel>: "RATE", "MSGS", "RATES", "AGES"
	 *  <ipaddrlabel>: "4:12345678", or "6:123456789abcdef0"
	 *  <typelabel>:   "CONNECT" or "MAIL" ?   (ignored)
	 *
	 */


	actionlabel[0] = iplabel[0] = lastlimits[0] = typelabel[0] = 0;
	countstr[0] = 0;

	s1 = strtok(peerdata->inpbuf, " \n");
	s2 = strtok(NULL, " \n");
	s3 = strtok(NULL, " \n");
	s4 = strtok(NULL, " \n");
	s5 = strtok(NULL, " \n");

	if (s1) strncpy(actionlabel, s1, sizeof(actionlabel));
	if (s2) strncpy(iplabel,     s2, sizeof(iplabel));
	if (s3) strncpy(lastlimits,  s3, sizeof(lastlimits));
	if (s4) strncpy(typelabel,   s4, sizeof(typelabel));
	if (s5) strncpy(countstr,    s5, sizeof(countstr));

	actionlabel[sizeof(actionlabel)-1] = 0;
	lastlimits[sizeof(lastlimits)-1] = 0;
	typelabel[sizeof(typelabel)-1] = 0;
	countstr[sizeof(countstr)-1] = 0;
	iplabel[sizeof(iplabel)-1] = 0;

	lastlimitval = atoi(lastlimits);
	countval     = atoi(countstr);

	/* type(NULL,0,NULL,"Got: '%s' '%s' '%s'=%d '%s'", 
	   actionlabel, iplabel, lastlimits,lastlimitval, typelabel); */

	i = -1;
	if (STREQ(actionlabel,"MSGS")) {
	  i = 1;
	} else if (STREQ(actionlabel,"RATES")) {
	  i = -2;
	} else if (STREQ(actionlabel,"AGES")) {
	  i = -3;
	} else if (STREQ(actionlabel,"EXCESS")) {
	  i = -4;
	} else if (STREQ(actionlabel,"DUMP")) {
	  i = -5;
	} else if (STREQ(actionlabel,"RCPT")) {
	  i = -6;
	} else
	  goto bad_input;

	if (iplabel[0] == '4' && iplabel[1] == ':') {

	  ipv4addr = strtoul( iplabel+2, NULL, 16);
	  /* FIXME ? - htonl() ???  */

	  if (i >= 0) {		/* "MSGS" data */
	    i = count_ipv4( state, ipv4addr, lastlimitval, countval );
	    sprintf(peerdata->outbuf, "200 %d\n", i);
	  } else if (i == -2) {	/* "RATES" report */
	    slot_ipv4_data(statep, peerdata->outbuf, ipv4addr);
	  } else if (i == -3) {	/* "AGES" report */
	    slot_ages(statep, peerdata->outbuf);
	  } else if (i == -4) {	/* "EXCESS" data */
	    i = count_excess_ipv4( state, ipv4addr, countval );
	    sprintf(peerdata->outbuf, "200 %d\n", i);
	  } else if (i == -5) {	/* "DUMP" report */
	    dump_trk( state, peerdata );
	  } else if (i == -6) {	/* "RCPT" data */
	    i = count_ipv4( state, ipv4addr, lastlimitval, 1 );
	    i = count_rcpts_ipv4( state, ipv4addr, countval );
	    sprintf(peerdata->outbuf, "200 %d\n", i);
	  }
	  peerdata->outlen = strlen(peerdata->outbuf);

	} else
	  goto bad_input;

	if (0) {
	bad_input:
	  sprintf(peerdata->outbuf,"500 bad input; unsupported mode\n");
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
subdaemon_handler_trk_postselect (statep, rdset, wrset)
     void *statep;
     fd_set *rdset, *wrset;
{
	struct trk_state *state = statep;

	if (now >= state->next_slotchange)
	  new_ipv4_timeslot( state );

	subdaemon_trk_checksigusr1(state);

	return 0;
}




static int
subdaemon_handler_trk_shutdown (state)
     void *state;
{
	return -1;
}


/* ------------------------------------------------------------------ */


struct trk_client_state {
	int fd_io;
	FILE *outfp;
	char *buf;
	int buflen;
	struct fdgets_fdbuf fdb;
};


void
discard_subdaemon_trk( state )
     struct trk_client_state *state;
{
	if (!state) return;
	if (state->outfp) fclose(state->outfp);
	if (state->fd_io >= 0) close(state->fd_io);
	if (state->buf) free(state->buf);
	free(state);
}

/* The 'cmd' buffer in this call shall not have a '\n' in it! */

int
call_subdaemon_trk (statep, cmd, retbuf, retbuflen)
     void **statep;
     const char *cmd;
     char *retbuf;
     int retbuflen;
{
	struct trk_client_state * state = *statep;
	int rc;

	if (ratetracker_rdz_fd < 0)  return -99; /* No can do.. */

	if (! state) {
	  state = *statep = calloc(1, sizeof(struct trk_client_state));
	  if (!state) return -1; /* alloc failure! */
	  state->fd_io = -1;
	  state->buf = calloc(1,10);
	}

 retry_io_tests:

	if ((state->outfp && ferror(state->outfp)) ) {
	  if (state->outfp) fclose(state->outfp);
	  state->outfp = NULL;
	  close(state->fd_io); /* closed already twice.. most likely */
	  state->fd_io = -1;
	}

	if (state->fd_io < 0) {
	  int toserver[2];

	  /* Abusing the thing, to be exact, but... */
	  rc = socketpair(PF_UNIX, SOCK_STREAM, 0, toserver);
	  if (rc != 0) return -2; /* create fail */

	  state->fd_io = toserver[1];
	  rc = fdpass_sendfd(ratetracker_rdz_fd, toserver[0]);

	  /* type(NULL,0,NULL,"fdpass_sendfd(%d,%d) rc=%d, errno=%s",
	     ratetracker_rdz_fd, toserver[0], rc, strerror(errno)); */

	  if (rc != 0) {
	    /* did error somehow */
	    close(toserver[0]);
	    close(toserver[1]);
	    return -3;
	  }
	  close(toserver[0]); /* Sent or not, close the remote end
				 from our side. */

	  /* type(NULL,0,NULL,"call_subdaemon_trk; 9"); */

	  fd_blockingmode(state->fd_io);

	  state->outfp = fdopen(state->fd_io, "w");

	  /* type(NULL,0,NULL,"call_subdaemon_trk; 10"); */
	  errno = 0;

	  if (state->buf) state->buf[0] = 0;
	  state->buflen = 0;
	  if (fdgets( & state->buf, & state->buflen, & state->fdb, state->fd_io, 5 ) < 0) {
	    /* something failed! */
	    /* type(NULL,0,NULL,"call_subdaemon_trk; 10-B");*/
	  }

	  /* type(NULL,0,NULL,"call_subdaemon_trk; 11; errno=%s",
	     strerror(errno)); */

	  if ( !state->buf  || (strcmp(state->buf, "#hungry\n") != 0) )
	    return -4; /* Miserable failure.. */

	  /* type(NULL,0,NULL,"call_subdaemon_trk; 12"); */

	  goto retry_io_tests; /* FEOF/FERROR checks.. */
	}

	/* type(NULL,0,NULL,"call_subdaemon_trk; 13"); */

	if (!state->outfp) return -51;

	/* type(NULL,0,NULL,"call_subdaemon_trk; 14; cmd='%s'", cmd); */

	fprintf(state->outfp, "%s\n", cmd);
	fflush(state->outfp);

	/* type(NULL,0,NULL,"call_subdaemon_trk; 15"); */

	if (state->outfp && ferror(state->outfp))
	  return -5; /* Uh ok.. */

	/* type(NULL,0,NULL,"call_subdaemon_trk; 16"); */

	if (state->buf) state->buf[0] = 0;
	state->buflen = 0;
	fdgets( & state->buf, & state->buflen, & state->fdb, state->fd_io, 5 );

	if (! state->buf || (state->outfp && ferror(state->outfp)))
	  return -6; /* Uh ok.. */

	/* type(NULL,0,NULL,"call_subdaemon_trk; 17"); */


	strncpy( retbuf, state->buf, retbuflen );
	retbuf[retbuflen-1] = 0;

	/* type(NULL,0,NULL,"call_subdaemon_trk; -last-"); */

	return 0;
}


int
call_subdaemon_trk_getmore (statep, retbuf, retbuflen)
     void *statep;
     char *retbuf;
     int retbuflen;
{
	struct trk_client_state * state = statep;
	int rc;

	if (state->fd_io < 0) {
	  return -1;  /* TOUGH! */
	}

	if (state->buf) state->buf[0] = 0;
	state->buflen = 0;
	rc = fdgets( & state->buf, & state->buflen, & state->fdb, state->fd_io, 5 );

	if (! state->buf || (state->outfp && ferror(state->outfp)))
	  return -6; /* Uh ok.. */

	/* type(NULL,0,NULL,"call_subdaemon_trk; 17"); */


	strncpy( retbuf, state->buf, retbuflen );
	retbuf[retbuflen-1] = 0;

	/* type(NULL,0,NULL,"call_subdaemon_trk; -last-"); */

	return 0;
}


int
smtp_report_ip(SS, ip)
     SmtpState *SS;
     const char *ip;
{
	char buf1[500];
	char buf2[500];
	char *s;
	int rc, i, rc1, rc2;
	void *statep;
	unsigned char ipaddr[16];
	int addrtype = 4;
	FILE *logfp_orig = logfp;

	/* type(NULL,0,NULL,"smtp_report_ip() ip='%s'",ip); */

	s = strchr(ip, ':'); /* IPv6 address! */
	if (s) addrtype = 6;

	rc = -1;
	if (addrtype == 4) {
	  rc = inet_pton(AF_INET, ip, ipaddr);
	}
#if defined(AF_INET6) && defined(INET6)
	else {
	  rc = inet_pton(AF_INET6, ip, ipaddr);
	}
#endif

	/* type(NULL,0,NULL,"smtp_report_ip() inet_pton(); addrtype=%d rc=%d",
	   addrtype,rc); */

	if (rc != 1) return -1; /* Bad address.. */

	sprintf(buf1, "AGES 4:00000000");
	/* type(NULL,0,NULL,"call_subdaemon_trk('%s')...",buf1); */
	rc = call_subdaemon_trk( & statep, buf1, buf1, sizeof(buf1));
	/* type(NULL,0,NULL,"call_subdaemon_trk(..) rc=%d bufs='%s'",
	   rc,buf1); */
	if (rc == 0) {
	  s = strchr(buf1,'\n'); if (s) *s = 0;
	} else
	  *buf1 = 0;

	sprintf(buf2, "RATES ");

	s = buf2 + strlen(buf2);
	if (addrtype == 4) {
	  /* IPv4 address.. */
	  strcat(s, "4:");
	  s += strlen(s);
	  for (i = 0; i < 4; ++i) {
	    sprintf(s, "%02X", ipaddr[i]);
	    s += strlen(s);
	  }
	} else {
	  /* IPv6 address.. */
	  strcat(s, "6:");
	  s += strlen(s);
	  for (i = 0; i < 16; ++i) {
	    sprintf(s, "%02X", ipaddr[i]);
	    s += strlen(s);
	  }
	}

	/* type(NULL,0,NULL,"call_subdaemon_trk('%s')...",buf2); */
	rc = call_subdaemon_trk( & statep, buf2, buf2, sizeof(buf2));
	/* type(NULL,0,NULL,"call_subdaemon_trk(..) rc=%d bufs='%s'",
	   rc,buf2);*/
	if (rc == 0) {
	  s = strchr(buf2,'\n'); if (s) *s = 0;
	} else
	  *buf2 = 0;

	rc1 = *buf1;
	rc2 = *buf2;

	switch (rc1) {
	case '5':
	  rc1 = 500;
	  break;
	case '2':
	  rc1 = 200;
	  break;
	default:
	  break;
	}

	switch (rc2) {
	case '5':
	  rc2 = 500;
	  break;
	case '2':
	  rc2 = 200;
	  break;
	default:
	  break;
	}

	logfp = NULL; /* Temporarily DO NOT DUMP OUTPUT DATA! */

	if (rc2 && rc1)
	  type(SS, -rc1, NULL, "%s", buf1+4);
	if (!rc2 && rc1)
	  type(SS, rc1, NULL, "%s", buf1+4);
	if (rc2)
	  type(SS, rc2, NULL, "%s", buf2+4);

	if (!rc1 && !rc2)
	  type(SS, 450, NULL, "No reply from tracking subsystem");

	logfp = logfp_orig;

	type(NULL,0,NULL,"Reported %d lines", (rc1 != 0) + (rc2 != 0));

	discard_subdaemon_trk( statep );

	return 0;
}


int
smtp_report_dump(SS)
     SmtpState *SS;
{
	char buf1[900];
	char *s;
	int rc, lines = 1;
	void *statep;
	FILE *logfp_orig = logfp;

	logfp = NULL; /* Temporarily DO NOT DUMP OUTPUT DATA! */

	/* type(NULL,0,NULL,"smtp_report_dump()"); */

	sprintf(buf1, "DUMP 4:00000000 xxx");
	/* type(NULL,0,NULL,"call_subdaemon_trk('%s')...",buf1); */

	rc = call_subdaemon_trk( & statep, buf1, buf1, sizeof(buf1));
	/* type(NULL,0,NULL,"call_subdaemon_trk(..) rc=%d bufs='%s'",
	   rc,buf1); */

	if (rc == 0) {
	  s = strchr(buf1,'\n'); if (s) *s = 0;
	} else
	  *buf1 = 0;

	for (;;) {

	  /* type(SS, -100, NULL, "%s", buf1); */

	  if (*buf1) {
	    if (buf1[3] == '-') {
	      rc = atoi(buf1);
	      if (rc < 0) 
		break;
	      rc = -rc;
	    } else
	      rc = atoi(buf1);
	  } else
	    break; /* No reply! */

	  type(SS, rc, NULL, "%s", buf1+4);
	  /* if (rc > 0) break; */

	  *buf1 = 0;
	  if (call_subdaemon_trk_getmore( statep, buf1, sizeof(buf1) ) < 0)
	    break; /* failure.. */
	  
	  s = strchr(buf1,'\n'); if (s) *s = 0;
	  ++lines;
	}

	discard_subdaemon_trk( statep );
	type(NULL,0,NULL, "Output %d lines", lines);

	logfp = logfp_orig;

	return 0;
}
