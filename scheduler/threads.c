/*
 *	ZMailer 2.99.16+ Scheduler "threads" routines
 *
 *	Copyright Matti Aarnio <mea@nic.funet.fi> 1995-1999
 *
 *
 *	These "threads" are for book-keeping of information
 *	regarding schedulable recipient vertices
 */

#include <stdio.h>
#include <sfio.h>
#include <ctype.h>
#include <unistd.h>
#include "scheduler.h"
#include "prototypes.h"
#include "zsyslog.h"
/* #include <stdlib.h> */

/*
   Each vertex arrives into SOME thread, each of which belong to
   SOME thread-group, among which groups the transport channel
   programs started for any member thread can be shared among
   their members.
*/


#define MAX_HUNGER_AGE 600 /* Sign of an error ... */


struct thread      *thread_head = NULL;
struct thread      *thread_tail = NULL;

static struct threadgroup *thrg_root   = NULL;
int idleprocs = 0;
extern int global_wrkcnt;
extern int syncstart;
extern int freeze;
extern int slow_shutdown;
extern time_t now;
extern char *procselect, *procselhost;
extern time_t sched_starttime; /* From main() */
extern int mailqmode;	/* 1 or 2 */

static long groupid  = 0;
static long threadid = 0;

struct threadgroup *
create_threadgroup(cep, wc, wh, withhost, ce_fillin)
struct config_entry *cep;
struct web *wc, *wh;
int withhost;
void (*ce_fillin) __((struct threadgroup*, struct config_entry *));
{
	struct threadgroup *thgp;

	/* Create a thread-group and link it into group-ring */

	thgp = (struct threadgroup*)malloc(sizeof(*thgp));
	if (!thgp) return NULL;
	memset(thgp,0,sizeof(*thgp));

	++groupid;
	thgp->groupid  = groupid;

	thgp->cep      = cep;
	thgp->withhost = withhost;
	thgp->wchan    = wc;
	thgp->whost    = wh;

	ce_fillin(thgp,cep);

	wc->linkcnt += 1;
	wh->linkcnt += 1;

	if (thrg_root == NULL) {
	  thrg_root     = thgp;
	  thgp->nextthg = thgp;
	  thgp->prevthg = thgp;
	} else {
	  thgp->nextthg       = thrg_root->nextthg;
	  thgp->prevthg       = thrg_root->nextthg->prevthg;
	  thgp->prevthg->nextthg = thgp;
	  thgp->nextthg->prevthg = thgp;
	}

	return thgp;
}

void
delete_threadgroup(thgp)
struct threadgroup *thgp;
{
	struct threadgroup *tgp;

	/* Time to say good-bye to this group, delete it.
	   We shall not have any threads under us, nor
	   idle processes!				  */

	/* However we may be called with either of these values
	   still non-zero... */
	if (thgp->transporters || thgp->threads) return;

if (verbose) sfprintf(sfstdout,"delete_threadgroup(%s/%d/%s)\n",
		      thgp->wchan->name,thgp->withhost,thgp->whost->name);

	if (thgp->idleproc != NULL || thgp->thread != NULL)
	  abort(); /* Deleting non-empty thread-group! */
	if (thrg_root == NULL) abort(); /* No thread-group root! */


	/* We are possibly the last to keep these web links */

	thgp->wchan->linkcnt -= 1;
	unweb(L_CHANNEL,thgp->wchan);

	thgp->whost->linkcnt -= 1;
	unweb(L_HOST,thgp->whost);

	/* Unlink this thread-group from the ring */

	tgp                    = thgp->nextthg;
	thgp->prevthg->nextthg = thgp->nextthg;
	tgp->prevthg           = thgp->prevthg;

	/* are we at the ring root pointer ? */
	if (thrg_root == thgp)
	  thrg_root = tgp;
	if (tgp == thgp) {
	  /* We were the only one! */
	  thrg_root = NULL;
	}
	free(thgp);
}

static void _thread_timechain_unlink __((struct thread *));
static void _thread_timechain_unlink(thr)
struct thread *thr;
{
	struct threadgroup *thg = thr->thgrp;

	/* Doubly linked linear list */

	if (thr->prevtr != NULL)
	  thr->prevtr->nexttr = thr->nexttr;
	if (thr->nexttr != NULL)
	  thr->nexttr->prevtr = thr->prevtr;

	if (thread_head == thr)
	  thread_head = thr->nexttr;
	if (thread_tail == thr)
	  thread_tail = thr->prevtr;

	thr->nexttr = NULL;
	thr->prevtr = NULL;

	/* Doubly linked circullar list */

	thr->prevthg->nextthg = thr->nextthg;
	thr->nextthg->prevthg = thr->prevthg;

	thg->threads -= 1;

	if (thg->thread == thr)
	  thg->thread = thr->nextthg;	/* pick other */
	if (thg->thread == thr)
	  thg->thread = NULL;		/* was the only one! */

	if (thg->thrtail == thr)
	  thg->thrtail = thr->prevthg;	/* pick other */
	if (thg->thrtail == thr)
	  thg->thrtail = NULL;		/* was the only one! */

	thr->prevthg = NULL;
	thr->nextthg = NULL;
}

static void _thread_timechain_append __((struct thread *));
static void _thread_timechain_append(thr)
struct thread *thr;
{
	struct threadgroup *thg = thr->thgrp;

	/* Doubly linked linear list */

	if (thread_head == NULL) {

	  thread_head = thr;
	  thread_tail = thr;
	  thr->nexttr = NULL;
	  thr->prevtr = NULL;

	} else {

	  thread_tail->nexttr = thr;
	  thr->nexttr = NULL;
	  thr->prevtr = thread_tail;
	  thread_tail = thr;

	}

	/* Doubly linked circullar list */

	if (thg->thread == NULL) {

	  thg->thread  = thr;
	  thg->thrtail = thr;
	  thr->nextthg = thr;
	  thr->prevthg = thr;

	} else {

	  thr->nextthg = thg->thrtail->nextthg;
	  thg->thrtail->nextthg = thr;
	  thr->prevthg = thr->nextthg->prevthg;
	  thr->nextthg->prevthg = thr;

	  thg->thrtail = thr;

	}

	thg->threads += 1;
}


static struct thread *create_thread __((struct threadgroup *thgrp,
					struct vertex *vtx,
					struct config_entry *cep));

static struct thread *
create_thread(thgrp, vtx, cep)
struct threadgroup *thgrp;
struct vertex *vtx;
struct config_entry *cep;
{
	/* Create a thread-block, link in the group pointer,
	   and link the thread into thread-ring, plus APPEND
	   to the thread time-chain				*/

	struct thread *thr;
	thr = (struct thread *)emalloc(sizeof(*thr));
	if (!thr) return NULL;

	memset(thr,0,sizeof(*thr));

	++threadid;
	thr->threadid = threadid;

	/* thr->attempts = 0;
	   thr->nextthg = NULL;
	   thr->prevthg = NULL; */

	thr->thgrp   = thgrp;
	thr->wchan   = vtx->orig[L_CHANNEL];
	thr->whost   = vtx->orig[L_HOST];

	if (thgrp->cep->flags & CFG_QUEUEONLY) {
		/* Start with the first retry */
		if(thgrp->cep->nretries) {
			mytime(&now);
			thr->wakeup = now + thgrp->cep->retries[0];
		}
	}

	thr->thvertices   = vtx;
	thr->lastthvertex = vtx;
	thr->jobs       = 1;
	vtx->thread     = thr;
	thr->channel    = strsave(vtx->orig[L_CHANNEL]->name);
	thr->host       = strsave(vtx->orig[L_HOST   ]->name);

	if (verbose) sfprintf(sfstdout,"create_thread(%s/%d/%s) -> %p\n",
			      thr->channel,thgrp->withhost,thr->host,thr);

	_thread_timechain_append(thr);

	return thr;
}


/*
 * Pick next thread from the group which this process serves.
 *
 * Result is  proc->pthread and proc->pvertex being updated to
 * new thread, and function returns 1.
 * If no new thread can be picked (all are active, and whatnot),
 * return 0.
 */

int
pick_next_thread(proc)
     struct procinfo *proc;
{
	struct thread	    *thr;
	struct thread       *thr0 = proc->pthread;
	struct threadgroup  *thg  = proc->thg;
	int once;

	if (thr0 && thr0->proc) /* Anybody ? */
	  thr0->proc = NULL; /* Remove it */

	proc->pthread = NULL;
	proc->pvertex = NULL;

	if (thg->cep->flags & CFG_QUEUEONLY)
	  return 0; /* We are QUEUE ONLY group, no auto-switch! */

	mytime(&now);

	for ( thr = thg->thread, once = 1;
	      thr && (once || (thr != thg->thread));
	      thr = thr->nextthg, once = 0 ) {

	  if (thr == thr0)
	    continue; /* No, can't be what we just were! */

	  if ((thr->wakeup > now) && (thr->attempts > 0))
	    continue; /* wakeup in future, unless first time around! */

	  if (thr->proc == NULL) {

	    struct vertex  * vp = thr->thvertices;
	    struct web     * ho = vp->orig[L_HOST];
	    struct web     * ch = vp->orig[L_CHANNEL];

	    thr->proc     = proc;
	    proc->pthread = thr;
	    proc->pvertex = vp;

	    if (proc->ho != NULL && proc->ho != ho) {
	      /* Get rid of the old host web */
	      proc->ho->kids -= 1;
	      unweb(L_HOST,proc->ho);
	      proc->ho = NULL;
	    }

	    /* Move the kid to this host web */
	    
	    if (proc->ho != ho) {
	      proc->ho = ho;
	      proc->ho->kids += 1;
	    }

	    /* In theory the CHANNEL could be different, in practice -- NOT! */
	    proc->ch      = ch;

	    /* Move the pickup pointer forward.. */
	    thg->thread = thg->thread->nextthg;

	    return (proc->pvertex != NULL);
	  }
	}
	/* No result :-( */
	return 0;
}


static void delete_thread __((struct thread *, int));
static void
delete_thread(thr, ok)
     struct thread *thr;
     int ok;
{
	/* Unlink this thread from thread-chain, and thread
	   group.  Decrement thread-group count		    */

	struct threadgroup *thg = thr->thgrp;

	if (verbose)
	  sfprintf(sfstdout,"delete_thread(%p:%s/%s) (thg=%p) jobs=%d\n",
		   thr,thr->channel,thr->host,thg, thr->jobs);

	free(thr->channel);
	free(thr->host);

	if (thr->jobs != 0) {
	  sfprintf(sfstdout," DELETE_THREAD() WITH JOBS=%d\n",thr->jobs);
	  abort(); /* Delete only when no vertices */
	}

	/* Unlink us from the thread time-chain */
	/* ... and thread-group-ring */
	_thread_timechain_unlink(thr);

	if (thr->proc) {
	  /* If this thread has a process, we detach it! */
	  thr->proc->pthread = NULL;
	  thr->proc->pvertex = NULL;
	  /* These are handled by  transport.c:reclaim():
	     thr->proc->ho = NULL;
	     thr->proc->ch = NULL;
	  */
	}

	/* If threads count goes zero.. */

	if (verbose)
	  sfprintf(sfstderr,"delete_thread() thr->proc=%p pid=%d OF=%d\n",
		   thr->proc, thr->proc ? (int)thr->proc->pid : 0,
		   thr->proc ? thr->proc->overfed : 0);

	free(thr);
}

static void _thread_linkfront __((struct thread *, struct vertex *, struct vertex *));
static void _thread_linkfront(thr,ap,vp)
struct thread *thr;
struct vertex *ap, *vp;
{
	/* Link the VP in front of AP */
	vp->previtem = ap->previtem;
	if (ap->previtem != NULL)
	  ap->previtem->nextitem = vp;
	ap->previtem = vp;
	vp->nextitem = ap;
	if (ap == thr->thvertices)
	  thr->thvertices = vp;
	vp->thread = thr;
}


/* the  _thread_linktail()  links a vertex into thread */
static void _thread_linktail __((struct thread *, struct vertex *));

static void _thread_linktail(thr,vp)
struct thread *thr;
struct vertex *vp;
{
	if (thr->thvertices != NULL) {
	  thr->lastthvertex->nextitem = vp;
	  vp->previtem    = thr->lastthvertex;
	} else {
	  thr->thvertices = vp;
	  vp->previtem    = NULL;
	}
	vp->nextitem      = NULL;
	vp->thread        = thr;
	thr->lastthvertex = vp;
}

void thread_linkin(vp,cep,cfgid, ce_fillin)
struct vertex *vp;
struct config_entry *cep;
int cfgid;
void (*ce_fillin) __((struct threadgroup*, struct config_entry *));
{
	struct threadgroup *thg;
	struct thread *thr;

	/* int matched = 0; */
	int thg_once;

	struct web *wc = vp->orig[L_CHANNEL];
	struct web *wh = vp->orig[L_HOST];

	mytime(&now);

	if (verbose)
	  sfprintf(sfstdout,"thread_linkin([%s/%s],%s/%d/%s,%d)\n",
		   wc->name, wh->name, cep->channel,
		   cep->flags & CFG_WITHHOST, cep->host, cfgid);

	/* char const *vp_chan = wc->name; */
	/* char const *vp_host = wh->name; */

	if (thrg_root == NULL)
	  create_threadgroup(cep,wc,wh,cep->flags & CFG_WITHHOST,ce_fillin);

	/*
	 *  Search for matching config-entry, AND matching channel,
	 *  AND matching host (depending how the thread-group formation
	 *  is allowed to happen..)
	 *
	 */
	for (thg = thrg_root, thg_once = 1;
	     thg && (thg_once || thg != thrg_root);
	     thg = thg->nextthg, thg_once = 0) {

	  int thr_once;

	  if (thg->cep != cep)	/* Config entries don't match */
	    continue;

	  if (thg->wchan != wc)	/* Channels don't match */
	    continue;

	  if (thg->withhost) {
	    if (thg->whost != wh) /* Tough, must have host match! */
	      continue;
	  }
	  
	  /* The config-entry matches, we have changes to match group */

	  for (thr = thg->thread, thr_once = 1;
	       thr && (thr_once || (thr != thg->thread));
	       thr = thr->nextthg, thr_once = 0) {

#if 0
	    if (!thr->vertex) abort();	/* No vertices ?? */

	    /* no need ? (Channels within a group are identical..) */
	    if (wc != thr->wchan)  abort();
#endif
	    /* Nice! What about host ? */
	    if (wh != thr->whost)  continue;
	    
	    /* We have matching channel, AND matching host */

	    /* Link the vertex into this thread! */

	    if (verbose)
	      sfprintf(sfstdout,"thread_linkin() to thg=%p[%s/%d/%s]; added into existing thread [%s/%s] thr->jobs=%d\n",
		       thg,cep->channel,thg->withhost,cep->host,
		       wc->name,wh->name,thr->jobs+1);

	    _thread_linktail(thr,vp);
	    vp->thgrp = thg;
	    thr->jobs += 1;

	    /* Hookay..  Try to start it, in case it isn't yet running */
	    if (!thr->proc)
	      thread_start(thr, 0);

	    return;
	  }

	  /* No matching thread, however this GROUP matches (or does it?) */

	  /* Add a new thread into this group */
	  thr = create_thread(thg,vp,cep);
	  vp->thgrp = thg;

	  if (verbose)
	    sfprintf(sfstdout,"thread_linkin() to thg=%p[%s/%d/%s]; created a new thread %p [%s/%s]\n",
		     thg,cep->channel,thg->withhost,cep->host,
		     thr,wc->name,wh->name);

	  /* Try to start it too */
	  thread_start(thr, 0);

	  return;
	}

	/* Add a new group - and its thread .. */
	thg = create_threadgroup(cep, wc, wh, cep->flags & CFG_WITHHOST, ce_fillin);
	thr = create_thread(thg,vp,cep);
	vp->thgrp = thg;

	if (verbose)
	  sfprintf(sfstdout,"thread_linkin() to thg=%p[%s/%d/%s]; created a new thread group, and thread [%s/%s]\n",
		 thg,cep->channel,thg->withhost,cep->host,
		 wc->name,wh->name);
	/* Try to start it too */
	thread_start(thr, 0);
}

struct web *
web_findcreate(flag, s)
int flag;
const char *s;
{
	struct spblk *spl;
	struct web *wp;
	spkey_t spk;

	/* caller has done 'strlower()' to our input.. */

	spk = symbol_db(s, spt_mesh[flag]->symbols);
	spl = sp_lookup(spk, spt_mesh[flag]);
	if (spl == NULL || (wp = (struct web *)spl->data) == NULL) {
	  /* Not found, create it */
	  wp = (struct web *)emalloc(sizeof (struct web));
	  memset((void*)wp, 0, sizeof (struct web));
	  sp_install(spk, (void *)wp, 0, spt_mesh[flag]);
	  wp->name     = strsave(s);
	  wp->kids     = 0;
	  wp->link     = NULL;
	  wp->linkcnt  = 0;
	}
	if (spl != NULL)
	  wp = (struct web*)spl->data;

	return wp;
}


/*
 * Deallocate a web entry (host or channel vertex header structure).
 */

void
unweb(flag, wp)
int flag;
	struct web *wp;
{
	struct spblk *spl = NULL;
	spkey_t spk;

if (verbose)
  sfprintf(sfstderr,"unweb(flag=%d wp=%p); linkcnt=%d kids=%d\n",
	   flag,wp,wp->kids,wp->linkcnt);

	if (wp->linkcnt > 0)	/* Yet objects holding it */
	  return;
	if (wp->kids > 0)	/* too early to actually remove it */
	  return;

	spk = symbol_lookup_db((u_char *)wp->name, spt_mesh[flag]->symbols);
	if ((spkey_t)0 == spk)	/* Not in the symbol table */
	  return;
	spl = sp_lookup(spk, spt_mesh[flag]);
	if (spl != NULL)	/* Should always have this ... */
	  sp_delete(spl, spt_mesh[flag]);
	symbol_free_db((u_char *)wp->name, spt_mesh[flag]->symbols);
	free(wp->name);
	free((char *)wp);
}


/*
 * unthread(vtx) -- detach this vertex from its thread
 */
static void unthread __((struct vertex *vtx));
static void unthread(vtx)
struct vertex *vtx;
{
	struct thread *thr = vtx->thread;

	if (vtx->previtem != NULL)
	  vtx->previtem->nextitem = vtx->nextitem;
	if (vtx->nextitem != NULL)
	  vtx->nextitem->previtem = vtx->previtem;

	if (thr) {
	  thr->jobs -= 1;

	  if (thr->thvertices   == vtx)
	    thr->thvertices     = vtx->nextitem;
	  if (thr->lastthvertex == vtx)
	    thr->lastthvertex   = vtx->previtem;
	}

	vtx->nextitem = NULL;
	vtx->previtem = NULL;
}

void
assert_pvertex_null(vtx)
     struct vertex *vtx;
{
  if (vtx->thread->proc->pvertex == vtx) abort();
}


/*
 * Detach the vertex from its chains
 *
 * If here is a process, limbo it!
 */
void
web_detangle(vp, ok)
	struct vertex *vp;
	int ok;
{
	/* If it was in processing, remove process node binding.
	   We do this only when we have reaped the channel program. */

	struct thread *thr = vp->thread;

	if (thr && thr->proc)
	  assert_pvertex_null(vp);

	unthread(vp);

	/* The thread can now be EMPTY! */

	if (thr && (thr->thvertices == NULL))
	  delete_thread(thr, ok);
}

static int vtx_mtime_cmp __((const void *, const void *));
static int vtx_mtime_cmp(ap, bp)
     const void *ap, *bp;
{
	const struct vertex **a = (const struct vertex **)ap;
	const struct vertex **b = (const struct vertex **)bp;

	if ((*a)->cfp->mtime < (*b)->cfp->mtime)
	  return -1;
	else if ((*a)->cfp->mtime == (*b)->cfp->mtime)
	  return 0;
	else
	  return 1;
}


void thread_vertex_shuffle(thr)
struct thread *thr;
{
	register struct vertex *vp;
	register int n, i, ni;
	static u_int           ur_size = 0;
	static struct vertex **ur_arr  = NULL;

	/* Randomize the order of vertices in processing, OR
	   sort them by spool-file MTIME, if the thread has
	   AGEORDER -flag set. */

	/* 1) Create storage array for the vertex re-arrange */
	if (ur_size == 0) {
	  ur_size = 100;
	  ur_arr = (struct vertex **)
	    emalloc(ur_size * sizeof (struct vertex *));
	}
	/* 2) Store the vertices into a re-arrange array (and count) */
	for (n = 0, vp = thr->thvertices; vp != NULL; vp = vp->nextitem) {
	  if (n >= ur_size) {
	    ur_size *= 2;
	    ur_arr = (struct vertex **)realloc((char *)ur_arr,
					       ur_size *
					       sizeof (struct vertex *));
	  }
	  ur_arr[n++] = vp;
	}

	/* 3) re-arrange pointers */
	if (thr->thgrp->ce.flags & CFG_AGEORDER) {
	  /* mtime order */
	  if (n > 1)
	    qsort((void*)ur_arr, n, sizeof(struct vertex *), vtx_mtime_cmp);
	} else
	  /* Random order */
	  for (i = 0; i < n; ++i) {
	    ni = ranny(n-1);
	    vp = ur_arr[i];
	    ur_arr[i] = ur_arr[ni];
	    ur_arr[ni] = vp;
	  }
	/* 4) Relink previtem/nextitem pointers */
	for (i = 0; i < n; ++i) {
	  if (i > 0)
	    ur_arr[i]->previtem = ur_arr[i-1];
	  if (i < (n-1))
	    ur_arr[i]->nextitem = ur_arr[i+1];
#if 1
	  /* 4c) Clear wakeup timer; the feed_child() will refuse
	     to feed us, if this one is not cleared.. */
	  ur_arr[i]->wakeup = 0;
#endif
	}
	ur_arr[  0]->previtem = NULL;
	ur_arr[n-1]->nextitem = NULL;
	/* 5) Finish the re-arrangement by saving the head,
	      and tail pointers */
	thr->thvertices   = ur_arr[  0];
	thr->lastthvertex = ur_arr[n-1];
}



/*
 * thread_start() -- start the thread, if:
 *   - if the thread is not already running
 *   - thread-group has idle processor (feed immediately)
 *   - if no resource limits are exceeded for starting it
 *
 * Return non-zero, if did start something.
 */

int
thread_start(thr, queue_only_too)
     struct thread *thr;
     int queue_only_too;
{
	int rc;
	struct vertex      *vp  = thr->thvertices;
	struct threadgroup *thg = thr->thgrp;
	struct config_entry *ce = &(thr->thgrp->ce);
	struct web         *ho  = vp->orig[L_HOST];
	struct web         *ch  = vp->orig[L_CHANNEL];


	if (!queue_only_too && (thg->cep->flags & CFG_QUEUEONLY)) return 0;

	if (syncstart || (freeze && !slow_shutdown)) return 0;
	if (procselect) {
	  if (*procselect != '*' &&
	      strcmp(procselect,ch->name) != 0)
	    return 0;
	  if (*procselhost != '*' &&
	      strcmp(procselhost,ho->name) != 0)
	    return 0;
	}

	if (verbose)
	  sfprintf(sfstderr,"thread_start(thr=%s/%d/%s) (dt=%d thr=%p jobs=%d)\n",
		   ch->name, thg->withhost, ho->name, (int)(thr->wakeup-now),
		   thr, thr->jobs);

	if (thr->proc) {
	  if (verbose)
	    sfprintf(sfstderr," -- already running; proc=%p\n", thr->proc);
	  return 0; /* Already running */
	}

      re_pick:
	if (thg->idleproc) {
	  struct procinfo *proc, **ipp;

	  /* Idle processor(s) exists, try to optimize by finding
	     an idle proc with matching channel & host from previous
	     activity. If not found, pick any. */
	  
	  ipp = &(thg->idleproc);
	  /* There is at least one.. */
	  proc  = *ipp;

	  for (;proc && (proc->ho != ho || proc->ch != ch); ipp  = &(proc->pnext), proc = *ipp) ;

	  if (proc == NULL) {
	    /* None of the previous ones matched, pick the first anyway */
	    ipp = &(thg->idleproc);
	    /* Well... after all, there is at least one.. */
	    proc  = *ipp;
	  }
	  /* Selected one of them.. */
	  thr->proc     = proc;
	  *ipp          = proc->pnext;
	  proc->pnext   = NULL;

	  thg->idlecnt -= 1;
	  --idleprocs;
	  
	  /* It may be that while we idled it, it died at the idle queue.. */
	  if (proc->pid <= 0 || proc->tofd < 0) {

	    sfprintf(sfstderr,"%% thread_start(thr=%s/%d/%s) (proc=%p ->pid=%d ->tofd=%d)\n",
		     ch->name, thg->withhost, ho->name, proc,
		     proc->pid, proc->tofd);

	    goto re_pick;
	  }

	  proc->pthread  = thr;
	  proc->pvertex  = thr->thvertices;

	  /* Thread-groups are made such that here at thread_start() we
	     can always switch over in between threads */

	  if (proc->ho != NULL && proc->ho != ho) {
	    /* Get rid of the old host web */
	    proc->ho->kids -= 1;
	    unweb(L_HOST,proc->ho);
	    proc->ho = NULL;
	  }

	  /* Move the kid to this host web */
	    
	  if (proc->ho != ho) {
	    proc->ho = ho;
	    proc->ho->kids += 1;
	  }

	  /* In theory the CHANNEL could be different -- in practice NOT! */
	  proc->ch = ch;

	  /* Clean vertices 'proc'-pointers,  randomize the
	     order of thread vertices  (or sort by spool file
	     mtime, if in AGEORDER..) */

	  thread_vertex_shuffle(thr);

	  thr->attempts += 1;

	  /* Its idle process, feed it! */

	  proc->state   = CFSTATE_LARVA;
	  proc->overfed = 1; /* A simulated state.. */

	  proc->pvertex = thr->thvertices;
	  proc->pthread = thr;

	  thr->proc             = proc;

	  sfprintf(sfstderr,"%% thread_start(thr=%s/%d/%s) (proc=%p dt=%d thr=%p jobs=%d)\n",
		   ch->name, thg->withhost, ho->name, thr->proc,
		   (int)(thr->wakeup-now), thr, thr->jobs);


	  ta_hungry(proc);

	  return 1;
	}

	/* Check resource limits - MaxTa, MaxChan, MaxThrGrpTa */
	/* If resources are exceeded, reschedule.. */

	vp = thr->thvertices;

	if (numkids >= ce->maxkids)
	  vp->ce_pending = SIZE_L;
	else if (vp->orig[L_CHANNEL]->kids >= ce->maxkidChannel)
	  vp->ce_pending = L_CHANNEL;
	else if (thg->transporters >= ce->maxkidThreads)
	  vp->ce_pending = L_HOST;
	else
	  vp->ce_pending = 0;

	if (vp->ce_pending) {
	  if (verbose)
	    sfprintf(sfstdout,"%s: (%d %dC %dT) >= (%d %dC %dT)\n",
		     ce->command,
		     numkids,
		     vp->orig[L_CHANNEL]->kids,
		     thg->transporters,
		     ce->maxkids,
		     ce->maxkidChannel,
		     ce->maxkidThreads);
	  /*
	   * Would go over limit.  Rescheduling for the next
	   * (single) interval works ok in many situation.
	   * However when the scheduler is very busy one can
	   * run into systemic problems with some set of messages
	   * blocking another set of messages.  The only way
	   * around that is a roundrobin scheme, implemented
	   * by the fifo nature of the thread scheduling.
	   */
	  reschedule(vp, 0, -1);
	  return 0;
	}

	/* Now we are ready to start a new child to run our bits */
	
	/* Clean vertices 'proc'-pointers,  randomize the
	   order of thread vertices  (or sort by spool file
	   mtime, if in AGEORDER..) */
	thread_vertex_shuffle(thr);

	rc = start_child(thr->thvertices,
			 thr->thvertices->orig[L_CHANNEL],
			 thr->thvertices->orig[L_HOST]);

	if (rc) /* non-zero when child has started */
	  thr->attempts += 1;

	if (thr->proc)
	  sfprintf(sfstderr,"%% thread_start(thr=%s/%d/%s) (proc=%p dt=%d thr=%p jobs=%d)\n",
		   ch->name, thg->withhost, ho->name, thr->proc,
		   (int)(thr->wakeup-now), thr, thr->jobs);


	return rc;
}


/*
 * pick_next_vertex() -- pick next free to process vertex in this thread
 *
 * This is called *only* by  feed_child(), and  proc->vertex  directs
 * then caller of feed_child() to tune the process state.
 * (From STUFFING to FINISHING and possibly to IDLE.)
 * 
 * - if (proc->pvertex != NULL) proc->pvertex = proc->pvertex->nextitem;
 * - return (proc->pvertex != NULL);
 *
 */

/* Return 0 for errors, 1 for success; result is at  proc->pvertex */

int
pick_next_vertex(proc)
     struct procinfo *proc;
{
	struct thread * thr = proc->pthread;
	struct vertex * vtx = proc->pvertex;

	if (verbose)
	  sfprintf(sfstdout,"pick_next_vertex(proc=%p) proc->tofd=%d, thr=%p, pvtx=%p, jobs=%d OF=%d S=%d\n",
		   proc, proc->tofd, thr, proc->pvertex,
		   thr ? thr->jobs : 0, proc->overfed, (int)proc->state);

	if (proc->pid < 0 || proc->tofd < 0) {	/* "He is dead, Jim!"	*/
#if 0
	  if (proc->pthread) {
	    proc->pthread->proc = NULL;
	    proc->pthread       = NULL;
	  }
#endif
	  if (proc->pvertex)
	    proc->pvertex       = NULL;

	  if (verbose) sfprintf(sfstdout," ... NONE, 'He is dead, Jim!'\n");
	  return 0;
	}

	if (vtx) /* Pick next item */
	  proc->pvertex = vtx->nextitem;

	return (proc->pvertex != NULL);
}

/*
 * The  thread_reschedule()  updates threads time-chain to match the
 * new value of wakeup for the  doagenda()  to latter use.
 */

void
thread_reschedule(thr, retrytime, index)
struct thread *thr;
int index;
time_t retrytime;
{
	struct vertex *vtx = thr->thvertices;
	time_t wakeup = 0;
	int skew;

	if (verbose)
	  sfprintf(sfstdout,"thread_reschedule() ch=%s ho=%s jobs=%d thr=%p proc=%p\n",
		   thr->channel,thr->host,thr->jobs,thr,thr->proc);

	if (thr->proc) {
	  /* We also disjoin possible current TA process */
	  thr->proc->pvertex = NULL;
	  thr->proc->pthread = NULL;
	  thr->proc = NULL;
	}

	/* find out when to retry */
	mytime(&now);

	/* if we are already scheduled for the future, don't reschedule */
	if (vtx->wakeup > now) {
	  thr->wakeup = vtx->wakeup;
	  if (verbose)
	    sfprintf(sfstdout,"...prescheduled\n");
	  goto timechain_handling;
	} else if (vtx->wakeup < now-7200 /* more than 2h in history .. */ )
	  vtx->wakeup = now;

	if (vtx->thgrp->ce.nretries <= 0) {
	  if (verbose)
	    sfprintf(sfstdout,"...ce->retries = %d\n", vtx->thgrp->ce.nretries);
	  goto timechain_handling;
	}

	if (thr->retryindex >= vtx->thgrp->ce.nretries) {
	  if (vtx->thgrp->ce.nretries > 1)
	    thr->retryindex = ranny(vtx->thgrp->ce.nretries-1);
	  else
	    thr->retryindex = 0;
	}

	/*
	 * clamp retry time to a predictable interval so we
	 * eventually bunch up deliveries.
	 */
	if (retrytime > 100000 && retrytime < now+63)
	  vtx->wakeup = now;
#if 0
	skew = vtx->wakeup % vtx->thgrp->ce.interval;
	if (skew <= vtx->thgrp->ce.interval / 2)
	  skew = - (skew + (vtx->thgrp->ce.skew - 1));
	else
	  skew = skew + (vtx->thgrp->ce.skew - 1);
	skew = skew / vtx->thgrp->ce.skew; /* want int div truncation */
	
	vtx->wakeup += (skew +
			vtx->thgrp->ce.retries[thr->retryindex] * vtx->thgrp->ce.interval);
#else
	/* Actually we do NOT want to have synchronization of threads,
	   as such causes simultaneous start of transporters, which
	   causes "somewhat" spiky load behaviour */

	skew = vtx->thgrp->ce.retries[thr->retryindex] * vtx->thgrp->ce.interval;
	if (retrytime <= 100000 &&
	    (int)retrytime > skew)
	  skew = retrytime;
	vtx->wakeup += skew;
#endif
	thr->retryindex++;

	/* If history, move forward by ``ce.interval'' multiple */
	if (vtx->wakeup < now)
	  vtx->wakeup += ((((now - vtx->wakeup) / vtx->thgrp->ce.interval)+1)
			  * vtx->thgrp->ce.interval);

	wakeup = vtx->wakeup;

	if (retrytime < now+63)
	  retrytime = wakeup;

	/* Reschedule ALL vertices on this thread */
	while (vtx) {

	  /* Time to expire ? */
	  if (vtx->ce_expiry > 0 && vtx->ce_expiry <= now &&
	      vtx->attempts  > 0) {
	    struct vertex *nvtx = vtx->nextitem;

	    /* ... and now expire it! */
	    /* this MAY invalidate also the THREAD object! */

	    if (thr->jobs > 1) {
	      expire(vtx,index);
	    } else {
	      expire(vtx,index);
	      thr = NULL; /* The THR-pointed object is now invalid */
	    }
	    vtx = nvtx;
	    continue;
	  }

	  if (vtx->wakeup < retrytime)
	    vtx->wakeup = retrytime;
	  if (wakeup > vtx->wakeup || wakeup == 0)
	    wakeup = vtx->wakeup;

	  vtx = vtx->nextitem;
	}
	if (thr != NULL)
	  thr->wakeup = wakeup;

 timechain_handling:
	/* In every case the rescheduling means we move this thread
	   to the end of the thread_head chain.. */

	if (thr != NULL) {
	  _thread_timechain_unlink(thr);
	  _thread_timechain_append(thr);
	}
}


/*
 * reschedule() operates WITHIN a thread, but does *not* move things!
 *
 */

#define SALARM(N)  (verbose ? sfprintf(sfstdout,"alarm(%d) = %d\n", (N),alarm(N)):alarm(N))

void
reschedule(vp, factor, index)
	struct vertex *vp;
	int factor, index;
{
	int skew;
	struct vertex *ap = NULL, *pap = NULL;
	struct thread *thr = vp->thread;
	struct threadgroup *thg = vp->thgrp;
	struct config_entry *ce = &(thg->ce);

	/* Hmm.. The reschedule() is called only when we have a reason
	   to call it, doesn't it ?  */
	/* *** assert_pvertex_null(vp); *** */

	/* find out when to retry */
	mytime(&now);

	if (verbose)
	  sfprintf(sfstdout,"reschedule %p now %d expiry in %d attempts %d factor %d inum %d (%s/%s: %s)\n",
		   vp, (int)now,
		   (int)((vp->ce_expiry > 0) ? (vp->ce_expiry - now) : -999),
		   vp->attempts,
		   factor, (int)(vp->cfp->id),
		   vp->orig[L_CHANNEL]->name,
		   vp->orig[L_HOST]->name,
		   vp->cfp->mid);
	/* if we are already scheduled for the future, don't reschedule */
	if (vp->wakeup > now) {
	  if (verbose)
	    sfprintf(sfstdout,"prescheduled\n");
	  return;
	} else if (vp->wakeup < now-7200 /* more than 2h .. */ )
	  vp->wakeup = now;

	if (ce->nretries <= 0) {
	  if (verbose)
	    sfprintf(sfstdout,"ce->retries = %d\n", ce->nretries);
	  return;
	}
	if (factor == -1 && vp->attempts) {
	  if (thr->retryindex >= ce->nretries) {
	    if (ce->nretries > 1)
	      thr->retryindex = ranny(ce->nretries-1);
	    else
	      thr->retryindex = 0;
	  }

	  /*
	   * clamp retry time to a predictable interval so we
	   * eventually bunch up deliveries.
	   */
	  skew = vp->wakeup % ce->interval;
	  if (skew <= ce->interval / 2)
	    skew = - (skew + (ce->skew - 1));
	  else
	    skew = skew + (ce->skew - 1);
	  skew = skew / ce->skew; /* want int div truncation */

	  vp->wakeup += (skew +
			 ce->retries[thr->retryindex] * ce->interval);
	  thr->retryindex++;
	} else if (factor < -1) {
	  vp->wakeup = -factor;
	} else
	  vp->wakeup += factor * ce->interval;

	if (vp->attempts == 0)
	  vp->wakeup = now;

	/* XX: change this to a mod expression */
	if (vp->wakeup < now)
	  vp->wakeup = ((((now - vp->wakeup) / ce->interval)+1)
			* ce->interval);

	if (vp->ce_expiry > 0
	    && vp->ce_expiry <= vp->wakeup
	    && vp->attempts > 0) {
	  if (verbose)
	    sfprintf(sfstdout,"ce_expiry = %d, %d attempts\n",
		     (int)(vp->ce_expiry), vp->attempts);

	  /* expire() will delete this vertex in due time */
	  expire(vp, index);

	  return;
	}
}


/*
 * With the  idle_cleanup()  we clean up idle processes, that have
 * been idle for too long (idlemax=nnnns)
 *
 * Because during its progress the thread-groups can disappear,
 * (as is one of its mandates) this code looks a bit peculiar..
 */
int
idle_cleanup()
{
	/* global: time_t now */
	struct threadgroup *thg, *nthg;
	int thg_once;
	int freecount = 0;

	mytime(&now);

	if (verbose) sfprintf(sfstdout,"idle_cleanup()\n");

	if (!thrg_root) return 0; /* No thread group! */

	for (thg = thrg_root, thg_once = 1;
	     thg_once || (thg != thrg_root);
	     thg = nthg, thg_once = 0) {

	  nthg = thg->nextthg;

	  if (thg->thread != NULL) {
	    struct procinfo *p;
	    struct thread *thr, *nthr;
	    int thr_once;
	    
	    /* Clean-up faulty client  --  KLUDGE :-(  --  OF=0, HA > much */

	    for (thr = thg->thread, thr_once = 1;
		 thr && (thr_once || (thr != thg->thread));
		 thr = nthr, thr_once = 0) {

	      nthr = thr->nextthg;

	      p = thr->proc;
	      if (thr->thgrp != thg) /* Not of this group ? */
		continue; /* Next! */
	      if (!p) /* No process */
		continue;
	      if ((p->cmdlen == 0) && (p->overfed == 0) && (p->tofd >= 0) &&
		  (p->hungertime != 0) && (p->hungertime + MAX_HUNGER_AGE <= now)) {

		/* Close the command channel, let it die itself.
		   Rest of the cleanup happens via mux() service. */
		if (verbose)
		  sfprintf(sfstdout,"idle_cleanup() killing TA on tofd=%d pid=%d\n",
			 p->tofd, (int)p->pid);

		thr->wakeup = now-1; /* reschedule immediately! */

		write(p->tofd,"\n",1); /* XXXX: should this be removed ?? */

		pipes_shutdown_child(p->tofd);
		p->tofd = -1;

		++freecount;

		/* Reclaim will (in due time) detect dead child, and
		   decrement child counters. */

		zsyslog((LOG_ERR, "ZMailer scheduler kludge shutdown of TA channel (info for debug only); %s/%s/%d HA=%ds",
			 thr->channel, thr->host, thr->thgrp->withhost,
			 now - p->hungertime));
	      }
	    }
	  }

	  if (thg->idleproc) {
	    struct procinfo *p;
	    
	    p  =  thg->idleproc;

	    while (p != NULL) {
	      if ((thg->cep->idlemax + p->hungertime < now) &&
		  (p->cmdlen == 0) && (p->tofd >= 0)) {
		/* It is old enough -- ancient, one might say.. */

		/* Close the command channel, let it die itself.
		   Rest of the cleanup happens via mux() service. */
		if (verbose)
		  sfprintf(sfstdout,"idle_cleanup() killing TA on tofd=%d pid=%d\n",
			   p->tofd, (int)p->pid);
		write(p->tofd,"\n",1);
		pipes_shutdown_child(p->tofd);
		p->tofd       = -1;
		++freecount;
	      }

	      /* Move to the next possible idle process */
	      p = p->pnext;
	    }
	  }
	  /* If there are no threads, nor transporters, delete the thg */
	  delete_threadgroup(thg);
	}
	return freecount;
}

static time_t oldest_age_on_thread __((struct thread *));
static time_t oldest_age_on_thread(th) /* returns the AGE in seconds.. */
struct thread *th;
{
	register time_t oo = now+1;
	register struct vertex *vp;

	vp = th->thvertices;
	while (vp) {
	  if (vp->cfp->mtime < oo)
	    oo = vp->cfp->mtime;
	  vp = vp->nextitem;
	}
	return (now - oo);
}

void thread_report(fp,mqmode)
     Sfio_t *fp;
     int mqmode;
{
	struct threadgroup *thg;
	int thg_once = 1;
	int jobsum = 0, jobtotal = 0;
	int threadsum = 0;
	char timebuf[20];

	int width;
	int cnt, procs;
	int rcptsum = 0;
	struct procinfo *p;
	struct thread *thr;

	mytime(&now);

#if 0
	if (thrg_root == NULL) {
	  *timebuf = 0;
	  saytime((long)(now - sched_starttime), timebuf, 1);
	  sfprintf(fp,"No threads/processes.  Uptime: %s\n",timebuf);
	  return;
	}
#endif

	for (thg = thrg_root;
	     thg && (thg_once || thg != thrg_root);
	     thg = thg->nextthg) {

	  int thr_once;

	  thg_once = 0;
	  if (mqmode & (MQ2MODE_FULL | MQ2MODE_QQ)) {
	    sfprintf(fp,"%s/%s/%d\n",
		     thg->cep->channel, thg->cep->host, thg->withhost);
	  }

	  cnt   = 0;
	  procs = 0;
	  jobsum = 0;

#if 1 /* XX: zero for verifying of modified system; turn to 1 for running! */

	  /* We scan thru the local ring of threads */

	  for (thr = thg->thread, thr_once = 1;
	       thr && (thr_once || (thr != thg->thread));
	       thr = thr->nextthg, thr_once = 0)
#else
	  /* We scan there in start order from the  thread_head
	     chain! */

	  for (thr = thread_head;
	       thr != NULL;
	       thr = thr->nexttr)
#endif
	  {
	    if (thr->thgrp != thg) /* Not of this group ? */
	      continue; /* Next! */

	    {
	      struct vertex *vp = thr->thvertices;
	      while (vp != NULL) {
		rcptsum += vp->ngroup;
		vp = vp->nextitem;
	      }
	    }

	    if (mqmode & MQ2MODE_FULL) {
	      width = sfprintf(fp,"    %s/%s/%d",
			       /* thr->thvertices->orig[L_CHANNEL]->name */
			       thr->channel,
			       /* thr->thvertices->orig[L_HOST]->name */
			       thr->host,
			       thr->thgrp->withhost);
	      if (width < 0) break; /* error.. */
	      width += 7;
	      if (width < 16-1)
		sfprintf(fp,"\t");
	      if (width < 24-1)
		sfprintf(fp,"\t");
	      if (width < 32-1)
		sfprintf(fp,"\t");
	      if (width < 40-1)
		sfprintf(fp,"\t");
	      else
		sfprintf(fp," ");
	    }

	    jobsum += thr->jobs;

	    if (mqmode & MQ2MODE_FULL)
	      sfprintf(fp,"R=%-3d A=%-2d", thr->jobs, thr->attempts);

	    ++cnt;
	    if (thr->proc != NULL &&
		thr->proc->pthread == thr) {
	      ++procs;

	      if (mqmode & MQ2MODE_FULL) {
		sfprintf(fp, " P=%-5d HA=%ds", (int)thr->proc->pid,
			 (int)(now - thr->proc->hungertime));

		if (thr->proc->feedtime == 0)
		  sfprintf(fp, " FA=never");
		else {
		  sfprintf(fp," FA=%ds",(int)(now - thr->proc->feedtime));
		}
		sfprintf(fp," OF=%d S=%d", thr->proc->overfed,
			 (int)thr->proc->state);
	      }

	    } else if (thr->wakeup > now) {
	      if (mqmode & MQ2MODE_FULL) {
		sfprintf(fp," W=%ds",(int)(thr->wakeup - now));
	      }
	    }

	    if (mqmode & MQ2MODE_FULL) {
	      *timebuf = 0;
	      saytime((long)oldest_age_on_thread(thr), timebuf, 1);
	      sfprintf(fp, " QA=%s", timebuf);

	      if (thr->thvertices && thr->thvertices->ce_pending)
		if (thr->thvertices->ce_pending != SIZE_L)
		  sfprintf(fp, "%s",
			   (thr->thvertices->ce_pending ==
			    L_CHANNEL ? " channelwait" : " threadwait"));
	      sfprintf(fp, "\n");
	    }
	  }

	  if (mqmode & (MQ2MODE_FULL | MQ2MODE_QQ)) {

	    sfprintf(fp,"\tThreads: %4d",thg->threads);

	    if (thg->threads != cnt)
	      sfprintf(fp,"/%d",cnt);

	    sfprintf(fp, " Msgs: %5d Procs: %3d", jobsum, thg->transporters);

	    /* 	  if (thg->transporters != procs)
		  sfprintf(fp,"/%d",procs);		*/
	  }

	  cnt = 0;
	  for (p = thg->idleproc; p != 0; p = p->pnext) ++cnt;

	  if (mqmode & (MQ2MODE_FULL | MQ2MODE_QQ)) {
	    sfprintf(fp," Idle: %3d",thg->idlecnt);
	    if (thg->idlecnt != cnt)
	      sfprintf(fp, "/%d", cnt);

	    sfprintf(fp, " Plim: %3d Flim: %3d\n",
		     thg->ce.maxkidThreads,thg->ce.overfeed);
	  }

	  jobtotal  += jobsum;
	  threadsum += thg->threads;
	}

	if (mqmode & (MQ2MODE_FULL | MQ2MODE_QQ | MQ2MODE_SNMP)) {
	  *timebuf = 0;
	  saytime((long)(now - sched_starttime), timebuf, 1);
	  sfprintf(fp,"Kids: %d  Idle: %2d  Msgs: %3d  Thrds: %3d  Rcpnts: %4d  Uptime: ",
		   numkids, idleprocs, global_wrkcnt, threadsum, jobtotal);
	  if (mqmode & MQ2MODE_SNMP)
	    sfprintf(fp, "%ld sec\n",(long)(now - sched_starttime));
	  else
	    sfprintf(fp, "%s\n",timebuf);

	  sfprintf(fp, "Msgs in %lu out %lu stored %lu ",
		   (u_long)MIBMtaEntry->mtaReceivedMessagesSc,
		   (u_long)MIBMtaEntry->mtaTransmittedMessagesSc,
		   (u_long)MIBMtaEntry->mtaStoredMessages);

	  sfprintf(fp, "Rcpnts in %lu out %lu stored %lu",
		   (u_long)MIBMtaEntry->mtaReceivedRecipientsSc,
		   (u_long)MIBMtaEntry->mtaTransmittedRecipientsSc,
		   (u_long)MIBMtaEntry->mtaStoredRecipients);

	  if (rcptsum != MIBMtaEntry->mtaStoredRecipients)
	    sfprintf(fp, " (%d)", rcptsum);

	  sfprintf(fp, "\n");
	}
	sfsync(fp);
}


int thread_count_recipients()
{
	struct threadgroup *thg;
	struct thread *thr;
	int thg_once;
	int jobtotal = 0;

	if (thrg_root == NULL)
	  return 0;

	if (thrg_root)
	  for (thg = thrg_root, thg_once = 1;
	       thg_once || thg != thrg_root;
	       thg = thg->nextthg, thg_once = 0) {

	    int thr_once;
	    int jobsum = 0;

	    if (thg->thread)
	      for (thr = thg->thread, thr_once = 1;
		   thr_once || (thr != thg->thread);
		   thr = thr->nextthg, thr_once = 0) {

		jobsum += thr->jobs;

	      }
	    jobtotal += jobsum;
	  }
	return jobtotal;
}
