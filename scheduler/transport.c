/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */
/*
 *	Lots of modifications (new guts, more or less..) by
 *	Matti Aarnio <mea@nic.funet.fi>  (copyright) 1992-2000
 */


#include "hostenv.h"
#include <sfio.h>
#include <sys/param.h>
#include "scheduler.h"
#include "mail.h"
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <sys/stat.h>
#include <errno.h>
#include <sys/file.h>
#include "zmsignal.h"
/* #include <stdlib.h> */
#include <unistd.h>

#include "prototypes.h"
#include "zsyslog.h"
#include <sysexits.h>
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#include "ta.h"
#include "libz.h"

extern int forkrate_limit;
extern int freeze;
extern int mailqmode;

static int  scheduler_nofiles = -1; /* Will be filled below */
static int  runcommand   __((char * const argv[], char * const env[], struct vertex *, struct web *, struct web*));
static void stashprocess __((int, int, int, struct web*, struct web*, struct vertex *, char * const argv[]));
static void reclaim      __((int, int));
static void waitandclose __((int));
static void readfrom     __((int));

extern FILE *vfp_open __((struct ctlfile *));

#ifdef  HAVE_WAITPID
# include <sys/wait.h>
#else
# ifdef HAVE_WAIT3
#  include <sys/wait.h> /* Has BSD wait3() */
# else
#  ifdef HAVE_SYS_WAIT_H /* POSIX.1 compatible */
#   include <sys/wait.h>
#  else /* Not POSIX.1 compatible, lets fake it.. */
extern int wait();
#  endif
# endif
#endif

#ifndef WEXITSTATUS
# define WEXITSTATUS(s) (((s) >> 8) & 0377)
#endif
#ifndef WSIGNALSTATUS
# define WSIGNALSTATUS(s) ((s) & 0177)
#endif

struct procinfo *cpids = NULL;

#define	MAXFILESPERTRANSPORT	1000

int	numkids = 0;
int	readsockcnt = 0; /* Count how many childs to read there are;
			    this for the SLOW Shutdown */

static void cmdbufalloc __((int, char **, int *));

static void
cmdbufalloc(newlen, bufp, spcp)
     int newlen;
     char **bufp;
     int *spcp;
{
  if (*bufp == NULL) {
    *bufp = emalloc(newlen+1);
    *spcp = newlen;
  }
  if (newlen > *spcp) {
    *bufp = erealloc(*bufp, newlen+1);
    *spcp = newlen;
  }
}

extern int errno;
extern int slow_shutdown;



/* 
 * Flush to child;
 * return -1 for failures and incomplete writes, 0 for success!
 */
static int  flush_child     __((struct procinfo *cpidp));

static int
flush_child(proc)
     struct procinfo *proc;
{
	if (proc->pid < 0 && proc->tofd >= 0) {
	  pipes_shutdown_child(proc->tofd);
	  proc->tofd = -1;

	  if (verbose)
	    sfprintf(sfstderr,
		     "%% shutdown of proc=%p pid=%d flush_child() pid<0 && tofd>=0\n",
		     proc, proc->pid);

	}
	if (proc->tofd < 0) {
	  proc->cmdlen = 0;
	  proc->state = CFSTATE_ERROR;

	  if (verbose)
	    sfprintf(sfstderr,
		     "%% disconnect of flush_child(proc=%p pid=%d) pid<0 && tofd<0 BAD?? \n",
		     proc, proc->pid);

	  return -1;
	}
#if 0
	/* Make sure the buffer exists.. */
	if (proc->cmdbuf == NULL)
	  cmdbufalloc(120, &proc->cmdbuf, &proc->cmdspc);
#endif
	if (proc->cmdlen == 0 && proc->tofd >= 0)
	  return 0; /* All done! */

	/* We have some leftovers from previous feed..
	   .. feed them now.  */

	/* sfprintf(sfstderr,
	   "flushing to child pid %d, cmdlen=%d, cmdbuf='%s'\n",
	   proc->pid, proc->cmdlen, proc->cmdbuf);  */

	while (proc->tofd >= 0 && proc->cmdlen > 0) {

	  int rc = write(proc->tofd, proc->cmdbuf, proc->cmdlen);

	  if (rc < 0 && (errno != EAGAIN && errno != EINTR &&
			 errno != EWOULDBLOCK)) {
	    int e = errno;
	    /* Some real failure :-( */
	    pipes_shutdown_child(proc->tofd);
	    proc->tofd = -1;
	    proc->cmdlen = 0;
	    proc->state = CFSTATE_ERROR;

	    if (verbose)
	      sfprintf(sfstderr,
		       "%% shutdown of proc=%p pid=%d flush_child() write() errno=%d\n",
		       proc, proc->pid, e);

	    return -1;
	  }
	  if (rc > 0) {
	    memcpy(proc->cmdbuf, proc->cmdbuf + rc, proc->cmdlen - rc);
	    proc->feedtime = now;
	  } else
	    break; /* Zero or negative.. let the writing
		      proceed latter... */
	  proc->cmdlen -= rc;
	}
	if (proc->cmdlen) return 1; /* Incomplete write */
	return 0;
}


/*
 * The 'feed_child()' sends whatever is pointed by   proc->pthread->nextfeed;
 * return -1 for failures or "EOT", 1 for incomplete writes, 0 for success!
 */

static int  feed_child      __((struct procinfo *cpidp));

static int
feed_child(proc)
     struct procinfo *proc;
{
	struct vertex *vtx;
	int cmdlen;

	static char *cmdbuf = NULL;
	static int cmdbufspc = 0;

	if (proc->pthread == NULL) {
	  proc->state = CFSTATE_ERROR;
	  pipes_shutdown_child(proc->tofd);
	  proc->tofd = -1;

	  if (verbose)
	    sfprintf(sfstderr,
		     "%% shutdown of proc=%p pid=%d feed_child() proc->pthread == NULL\n",
		     proc, proc->pid);

	  return -1; /* BUG if called without next THREAD.. */
	}
	if (proc->pthread->nextfeed == NULL) {

	  if (verbose)
	    sfprintf(sfstderr,
		     "%% feed_child(proc=%p pid=%d) proc->pthread->nextfeed == NULL\n",
		     proc, proc->pid);

	  return -1; /* Might be called without next thing to process.. */
	}
	if (proc->pid <= 0 || proc->tofd < 0) {
	  proc->state = CFSTATE_ERROR;

	  if (verbose)
	    sfprintf(sfstderr,
		     "%% feed_child(proc=%p pid=%d tofd=%d) pid<0 || tofd<0 BAD??\n",
		     proc, proc->pid, proc->tofd);

	  return -1; /* No process../No write channel.. */
	}

	vtx = proc->pthread->nextfeed;

	mytime(&now);
#if 0
	if (vtx->lastfeed + 10 >= now)
	  return -1; /* Force at least 10 seconds in between feeds! */
#endif
	vtx->lastfeed = now;

	if (slow_shutdown) {

	  cmdlen = 1;
	  cmdbufalloc(cmdlen, & cmdbuf, & cmdbufspc);
	  strcpy(cmdbuf,"\n");

	} else if (vtx->cfp->dirind > 0) {

	  const char *d = cfpdirname(vtx->cfp->dirind);
	  if (proc->thg->withhost) { /* cmd-line was with host */
	    cmdlen = 2 + strlen(d) + strlen(vtx->cfp->mid);
	    cmdbufalloc(cmdlen, & cmdbuf, & cmdbufspc);
	    sprintf(cmdbuf, "%s/%s\n", d, vtx->cfp->mid);
	  } else {
	    cmdlen = 3+strlen(d)+strlen(vtx->cfp->mid)+strlen(proc->ho->name);
	    cmdbufalloc(cmdlen, & cmdbuf, & cmdbufspc);
	    sprintf(cmdbuf, "%s/%s\t%s\n", d, vtx->cfp->mid, proc->ho->name);
	  }
	} else {

	  if (proc->thg->withhost) { /* cmd-line was with host */
	    cmdlen = 1 + strlen(vtx->cfp->mid);
	    cmdbufalloc(cmdlen, & cmdbuf, & cmdbufspc);
	    sprintf(cmdbuf, "%s\n", vtx->cfp->mid);
	  } else {
	    cmdlen = 2+strlen(vtx->cfp->mid)+strlen(proc->ho->name);
	    cmdbufalloc(cmdlen, & cmdbuf, & cmdbufspc);
	    sprintf(cmdbuf, "%s\t%s\n", vtx->cfp->mid, proc->ho->name);
	  }
	}

	if ((proc->cmdlen + cmdlen) >= proc->cmdspc)
	  cmdbufalloc(proc->cmdlen + cmdlen + 1, &proc->cmdbuf, &proc->cmdspc);

	/* Ok, copy it there.. */
	memcpy(proc->cmdbuf + proc->cmdlen, cmdbuf, cmdlen+1);
	proc->cmdlen += cmdlen;

	if (verbose) {
	  sfprintf(sfstdout,
		   "feed: tofd=%d, chan='%s', proc=%p, vtx=%p thr=%p ",
		   proc->tofd, proc->ch->name, proc, vtx, vtx->thread);
	}

	if (vtx->cfp->vfpfn != NULL) {
	  Sfio_t *vfp = vfp_open(vtx->cfp);
	  int i;
	  if (vfp) {
	    sfprintf(vfp, "Feeding to child; ce.argv = \"");
	    for (i = 0; vtx->thgrp->ce.argv[i] != NULL; ++i) {
	      if (i == 0)
		sfprintf(vfp, "'%s'", vtx->thgrp->ce.argv[i]);
	      else
		sfprintf(vfp, " '%s'", vtx->thgrp->ce.argv[i]);
	    }
	    sfprintf(vfp, "\" chan = '%s' cmd: %s", proc->ch->name, cmdbuf);
	    sfclose(vfp);
	  }
	}

	vtx->ce_pending  = 0; /* and clear the pending..       */
	vtx->attempts   += 1;
	
	/* It was fed (to buffer), clear this flag.. */
	proc->overfed        += 1;
	proc->pthread->unfed -= 1;

	if (verbose)
	  sfprintf(sfstdout,"len=%d buf=%s", cmdlen, cmdbuf);

	mytime(&proc->feedtime);


	pick_next_vertex(proc);

	return flush_child(proc);
}


char *proc_state_names[] = {
  "ERROR", "LARVA", "STUFF", "FINISH", "IDLE"
};

void
ta_hungry(proc)
     struct procinfo *proc;
{
	/* This is an "actor model" behaviour,
	   where actor tells, when it needs a new
	   job to be fed to it. */

	struct thread *thr0;
	int i;

	mytime(&proc->hungertime);

	if (verbose)
	  sfprintf(sfstdout,"%% ta_hungry(%p) OF=%d S=%s tofd=%d\n",
		   proc, proc->overfed, proc_state_names[proc->state],
		   proc->tofd);

	/* If ``proc->tofd'' is negative, we can't feed anyway.. */

	if (proc->tofd < 0) {

	  --proc->overfed;

	  if (proc->overfed == 0 && proc->pthread)
	    /* If we have a thread here still, reschedule it... */
	    thread_reschedule(proc->pthread,0,-1);

	  return;
	}

	/* We have valid child-feed state */

	proc->overfed -= 1;

	switch(proc->state) {
	case CFSTATE_LARVA: /* "1" */

	  /* Thread selected already along with its first vertex,
	     which is pointer by  proc->pthread->nextfeed  */

	  proc->overfed = 0; /* Should not need setting ... */

	  if (feed_child(proc) < 0)
	    /* We got some error :-/  D'uh! */
	    goto feed_error_handler;

	  proc->state = CFSTATE_STUFFING;
	  return;

	case CFSTATE_STUFFING: /* "2" */

	  if (proc->overfed > 0) return;

	  if (proc->pthread && proc->pthread->nextfeed) {

	    while ((proc->state == CFSTATE_STUFFING) &&
		   proc->pthread && proc->pthread->nextfeed) {

	      /* As long as:
		 - we have next vertex to feed
		 - there is no command buffer backlog
		 - state stays in STUFFING
	      */

	      i = feed_child(proc);
	      if (i < 0)
		goto feed_error_handler; /* Outch! */

	      if (proc->tofd >= 0 && proc->cmdlen != 0)
		break; /* Incomplete feed -- stop feeding here */

	      if (proc->overfed > proc->thg->ce.overfeed)
		break; /* Or over limit ...       */

	    }
	    /* As long as we have things to feed (or have fed anything!),
	       we stay in the STUFFING state.  This was if we latter get
	       new workitems,  thread_linkin() can simply put them into
	       the 'nextfeed' pointer, and we feed them right away. */
	    return;
	  }

	  /* Didn't have anything to feed :-( */

	  proc->state = CFSTATE_FINISHING;
	  /* FALL THRU! */

	case CFSTATE_FINISHING: /* "3" */

	  /* "retryat" may have kicked us into this state also.. */

	  if (proc->overfed > 0) return;

	  /* Well, this thread was done, so long!
	     This TA may have other things to poke at! */

	  thr0 = proc->pthread;
	  proc->pthread = NULL;

	  /* Disconnect the previous thread from the proc. */

	  thr0->thrkids -= 1;

	  if (thr0 && thr0->proc == proc) /* Thread Process Chain Leader */
	      thr0->proc = proc->pnext;

	  /* Disconnect from process chain */
	  if (proc->pnext) proc->pnext->pprev = proc->pprev;
	  if (proc->pprev) proc->pprev->pnext = proc->pnext;
	  proc->pnext = proc->pprev = NULL;

	  /* Next: either the thread changes, or
	     the process moves into IDLE state. */

	  if (pick_next_thread(proc)) {
	    struct thread *thr = proc->pthread;
	    /* We have WORK !  We are reconnected to the new thread! */

	    if (thr0 && thread_reschedule(thr0, 0, -1))
	      delete_thread(thr0);

	    if (verbose)
	      sfprintf(sfstdout, "%% pick_next_thread(proc=%p) gave thread %p\n",
		       proc, proc->pthread);

	    thr->attempts += 1;

	    if (feed_child(proc))
	      /* non-zero return means things went wrong somehow.. */
	      goto feed_error_handler;

	    proc->state = CFSTATE_STUFFING;
	    return;
	  }

	  /* proc->pthread == NULL  now */
	  /* thr0->thrkids has been decremented */
	  /* No work in sight, queue up '#idle\n' string. */

	  if (thr0) {

	    /* Previously we were disconnected from the thread,
	     now join back so that IDLE will disconnect us... */

	    proc->pthread = thr0;
	    thr0->thrkids += 1;
	    proc->pnext   = thr0->proc;
	    if (proc->pnext) proc->pnext->pprev = proc;
	    thr0->proc = proc;
	  }

	  if ((proc->cmdlen + 7) >= proc->cmdspc) {
	    cmdbufalloc(proc->cmdlen+7, &proc->cmdbuf, &proc->cmdspc);
	  }
	  if (slow_shutdown) {
	    proc->cmdbuf[ proc->cmdlen ] = '\n';
	    proc->cmdlen += 1;
	  } else {
	    memcpy(proc->cmdbuf + proc->cmdlen, "#idle\n", 6);
	    proc->cmdlen += 6;
	  }
	  proc->state = CFSTATE_IDLE;
	  proc->overfed += 1;
	  flush_child(proc);  /* May flip the state to CFSTATE_ERROR */
	  return;

	case CFSTATE_IDLE: /* "4" */
	  /* The process has arrived into IDLE pool! */

	  if (proc->overfed > 0) abort();
	  /* We have seen at least once that this value went NEGATIVE! */

	  if (verbose)
	    sfprintf(sfstdout, " ... IDLE THE PROCESS %p (of=%d).\n",
		     proc, proc->overfed);

	  /* Unlink me from the active chain */
	  if (proc->pnext) proc->pnext->pprev = proc->pprev;
	  if (proc->pprev) proc->pprev->pnext = proc->pnext;
	  proc->pnext = proc->pprev = NULL;

	  thr0 = proc->pthread;
	  if (thr0) {

	    proc->pthread = NULL;

	    if (thr0->proc == proc) /* Was chain head */
	      thr0->proc = proc->pnext;

	    thr0->thrkids -= 1;
	  }

	  proc->pnext = proc->thg->idleproc;
	  if (proc->pnext) proc->pnext->pprev = proc;
	  proc->pprev = NULL;
	  proc->thg->idleproc = proc;

	  proc->thg->idlecnt += 1;
	  ++idleprocs;
	  
	  if (thr0 && thread_reschedule(thr0, 0, -1))
	    delete_thread(thr0);

	  return;

	default: /* CFSTATE_ERROR: "0" */
	  /* Some error was encountered at  feed_child()  at some
	     point, we do nothing! */

	  /* Some (real?) failure :-( */

	feed_error_handler:

	  if (verbose)
	    sfprintf(sfstdout,"%% ta_hungry(%p) OF=%d S=%s tofd=%d\n",
		     proc, proc->overfed, proc_state_names[proc->state],
		     proc->tofd);

	  proc->state = CFSTATE_ERROR;

	  /* We shut-down the child feed pipe */
	  pipes_shutdown_child(proc->tofd);
	  proc->tofd = -1;
	  break;
	}
	return;
}

/*
 * start_child() -- build argv[], and do other inits for fork()ing
 *                  and execve()ing a new transport program for us.
 */

int
start_child(vhead, chwp, howp)
	struct vertex *vhead;
	struct web *chwp, *howp;
{
#define MAXARGC 40
	char *av[1+MAXARGC], *ev[1+MAXARGC], *s, *os, *cp, *ocp;
	char buf[MAXPATHLEN*4];
	char buf2[MAXPATHLEN];

	int	 i, avi, evi;
	static time_t prev_time = 0;
	static int startcnt = 0; /* How many childs per second (time_t tick..) ? */
	time_t this_time;


	if (freeze) {
	  vhead->thread->pending = "Frozen";
	  return 0;
	}

	if (verbose)
	  sfprintf(sfstdout,"transport(vhead=%p,chan=%s,host=%s)\n",
		   vhead,chwp->name,howp->name);

	++startcnt;
	this_time = mytime(NULL);
	if (this_time != prev_time) {
	  startcnt = 0;
	  prev_time = this_time;
	} else if (startcnt > forkrate_limit) {
	  if (verbose)
	    sfprintf(sfstdout," ... too many forks per second!\n");
	  vhead->thread->pending = "ForkRateLimit";
	  return 0;
	}

	if (vhead->thgrp->ce.argv == NULL) {
	  sfprintf(sfstderr, "No command defined for %s/%s!\n",
		  chwp->name, howp->name);
	  vhead->thread->pending = "ConfBUG:NoCmdDefined!";
	  return 0;
	}

	/*
	 * Replace the $host and $channel strings in the command line.
	 * (also any ${ZENV} variable)
	 */
	os = buf;
	avi = evi = 0;
	for (i = 0; vhead->thgrp->ce.argv[i] != NULL; ++i) {
	  if (strcmp(vhead->thgrp->ce.argv[i], replhost) == 0) {
	    av[avi] = howp->name;
	  } else if (strcmp(vhead->thgrp->ce.argv[i], replchannel) == 0) {
	    av[avi] = chwp->name;
	  } else if (strchr(vhead->thgrp->ce.argv[i], '$') != NULL) {
	    s = os;
	    for (cp = vhead->thgrp->ce.argv[i]; *cp != '\0'; ++cp) {
	      if (*cp == '$' && *(cp+1) == '{') {
		cp += 2;
		ocp = cp;
		while (*cp != '\0' && *cp != '}')
		  ++cp;
		if (*cp == '}') {
		  *cp = '\0';
		  if (strcmp(ocp,"host")==0) {
		    strcpy(s,howp->name);
		  } else if (strcmp(ocp,"channel")==0) {
		    strcpy(s,chwp->name);
		  } else {
		    char *t = getzenv(ocp);
		    if (t)
		      strcpy(s, t);
		  }
		  s += strlen(s);
		  *cp = '}';
		} else
		  --cp;
	      } else
		*s++ = *cp;
	    }
	    *s = '\0';
	    av[avi] = os;
	    os = s + 1;
	  } else
	    av[avi] = vhead->thgrp->ce.argv[i];

	  if (os >= (buf+sizeof(buf))) {
	    sfprintf(sfstderr,"BUFFER OVERFLOW IN ARGV[] SUBSTITUTIONS!\n");
	    sfsync(sfstderr);
	    abort();
	  }

	  if (avi == 0 && strchr(av[0],'=') != NULL) {
	    ev[evi] = av[0];
	    ++evi;
	  } else if (avi == 0 && av[0][0] != '/') {
	    /* Must add ${MAILBIN}/ta/ to be the prefix.. */

	    static char *mailbin = NULL;

	    if (!mailbin) mailbin = getzenv("MAILBIN");
	    if (!mailbin) mailbin = MAILBIN;

	    sprintf(buf2,"%s/%s/%s", mailbin, qdefaultdir, av[0]);
	    av[avi++] = buf2;
	    if (strlen(buf2) > sizeof(buf2)) {
	      /* Buffer overflow ! This should not happen, but ... */
	      sfprintf(sfstderr,"BUFFER OVERFLOW IN ARGV[0] CONSTRUCTION!\n");
	      sfsync(sfstderr);
	      abort();
	    }
	  } else
	    ++avi;
	  if (avi >= MAXARGC) avi = MAXARGC;
	  if (evi >= MAXARGC) evi = MAXARGC;
	}
	av[avi] = NULL;
	if ((s = getenv("TZ")))       ev[evi++] = s-3; /* Pass the TZ      */
	if ((s = getzenv("PATH")))    ev[evi++] = s-5; /* Pass the PATH    */
	if ((s = getzenv("ZCONFIG"))) ev[evi++] = s-8; /* Pass the ZCONFIG */
	ev[evi] = NULL;

	/* fork off the appropriate command with the appropriate stdin */
	if (verbose) {
	  sfprintf(sfstdout,"${");
	  for (i = 0; ev[i] != NULL; ++i)
	    sfprintf(sfstdout," %s", ev[i]);
	  sfprintf(sfstdout," }");
	  for (i = 0; ev[i] != NULL; ++i)
	    sfprintf(sfstdout," %s", av[i]);
	  sfprintf(sfstdout,"\n");
	}
	return runcommand(av, ev, vhead, chwp, howp);
}

static int runcommand(argv, env, vhead, chwp, howp)
	char * const argv[];
	char * const env[];
	struct vertex *vhead;
	struct web *chwp, *howp;
{
	int	i, pid, to[2], from[2], uid, gid, prio;
	char	*cmd;
	static int pipesize = 0;


	uid = vhead->thgrp->ce.uid;
	gid = vhead->thgrp->ce.gid;
	cmd = argv[0];
	prio= vhead->thgrp->ce.priority;

	if (pipes_create(to,from) < 0) return 0;
	if (pipesize == 0)
	  pipesize = resources_query_pipesize(to[0]);

	if (verbose)
	  sfprintf(sfstderr, "to %d/%d from %d/%d\n",
		  to[0],to[1],from[0],from[1]);

	pid = fork();
	if (pid == 0) {	/* child */

	  pipes_to_child_fds(to,from);

	  /* keep current stderr for child stderr */
	  /* close all other open filedescriptors */

	  /* ... if detach() did its job, there shouldn't be any! */
	  /* ... no, the 'querysock' is there somewhere!   */
	  if (scheduler_nofiles < 1)
	    scheduler_nofiles = resources_query_nofiles();
	  for (i = 3; i < scheduler_nofiles; ++i)
	    close(i);

#ifdef HAVE_SETPRIORITY
	  if (prio >= 80) { /* MAGIC LIMIT VALUE FOR ABSOLUTE SET! */
	    setpriority(PRIO_PROCESS, 0, i - 100);
	  } else
#endif
	    if (prio != 0) {
	      nice(prio);
	    }

	  resources_limit_nofiles(transportmaxnofiles);
	  setgid(gid);	/* Do GID setup while still UID 0..   */
	  setuid(uid);	/* Now discard all excessive powers.. */
	  execve(cmd, argv, env);
	  sfprintf(sfstderr, "Exec of %s failed!\n", cmd);
	  _exit(1);
	} else if (pid < 0) {	/* fork failed - yell and forget it */
	  close(to[0]); close(to[1]);
	  close(from[0]); close(from[1]);
	  sfprintf(sfstderr, "Fork failed!\n");
	  vhead->thread->pending = "System:ForkFailure!";
	  return 0;
	}

	/* parent */

	pipes_close_parent(to,from);

	/* save from[0] away as a descriptor to watch */
	stashprocess(pid, from[0], to[1], chwp, howp, vhead, argv);
	/* We wait for the child to report "#hungry", then we feed it.. */
	return 1;
}


static void stashprocess(pid, fromfd, tofd, chwp, howp, vhead, argv)
	int pid, fromfd, tofd;
	struct web *chwp, *howp;
	struct vertex *vhead;
	char * const argv[];
{
	int i, l, j;
	struct procinfo *proc;

	if (cpids == NULL) {
	  if (scheduler_nofiles < 1)
	    scheduler_nofiles = resources_query_nofiles();
	  i = scheduler_nofiles;
	  cpids = (struct procinfo *)
	    emalloc((unsigned)(i * sizeof (struct procinfo)));
	  memset(cpids, 0, sizeof(struct procinfo) * i);
	}
	proc = &cpids[fromfd];

	/* Free these buffers in case they exist from last use.. */
	if (proc->cmdbuf)  free(proc->cmdbuf);
	if (proc->cmdline) free(proc->cmdline);

	memset(proc,0,sizeof(struct procinfo));
#if 0 /* the memset() does this more efficiently.. */
	proc->pnext   = NULL;
	proc->pprev   = NULL;
	proc->cmdlen = 0;
	proc->reaped = 0;
	proc->carryover = NULL;
#endif

	proc->overfed = 1;
	proc->state   = CFSTATE_LARVA;

	proc->pid     = pid;

	proc->ch      = chwp;
	chwp->kids   += 1;

	proc->ho      = howp;
	howp->kids   += 1;

	proc->pthread            = vhead->thread;

	proc->thg           = vhead->thread->thgrp;
	proc->thg->transporters += 1;
	proc->pthread->thrkids  += 1;
	++numkids;
	proc->tofd          = tofd;
	proc->pnext         = proc->pthread->proc;
	proc->pthread->proc = proc;
	if (proc->pnext) proc->pnext->pprev = proc;

	mytime(&proc->hungertime); /* Actually it is not yet 'hungry' as
				      per reporting so, but we store the
				      time-stamp anyway */

	cmdbufalloc(200, &proc->cmdbuf,  &proc->cmdspc);
	cmdbufalloc(200, &proc->cmdline, &proc->cmdlspc);

	fd_nonblockingmode(fromfd);
	if (fromfd != tofd)
	  fd_nonblockingmode(tofd);

	/* Construct a faximille of the argv[] in a single string.
	   This is entirely for debug porposes in some rare cases
	   where transport subprocess returns EX_SOFTWARE, and we
	   send out LOG_EMERG alerts thru syslog.  */
	proc->cmdline[0] = 0;
	l = 0;
	for (i = 0; argv[i] != NULL; ++i) {
	  if (i > 0)
	    proc->cmdline[l++] = ' ';
	  j = strlen(argv[i]);
	  cmdbufalloc(l+j+1, &proc->cmdline, &proc->cmdlspc);
	  memcpy(proc->cmdline+l, argv[i], j);
	  l += j;
	}
	proc->cmdline[l] = '\0';

	if (verbose)
	  sfprintf(sfstderr,
		   "stashprocess(%d, %d, %d, %s, %s, '%s' proc=%p)\n",
		   pid, fromfd, tofd, chwp ? chwp->name : "nil",
		   howp ? howp->name : "nil", proc->cmdline, proc);
}

/*
 * shutdown all kids that we have
 */
void
shutdown_kids()
{
	int i;
	struct procinfo *proc = cpids;

	if (!cpids) return; /* Nothing to do! */

	for (i = 0; i < scheduler_nofiles; ++i,++proc)
	  if (proc->pid > 0 && proc->tofd >= 0) {
	    /* Send the death-marker to the kid, and
	       then close the command channel */
	    write(proc->tofd,"\n\n",2);
	    pipes_shutdown_child(proc->tofd);
	    proc->tofd = -1;
	    /* Signals may happen... */
	    if (proc->pid > 1)
	      kill(proc->pid, SIGQUIT);
	  }
}

/* 
 *  Reclaim the process slot -- this process is dead now.
 */
static void reclaim(fromfd, tofd)
	int fromfd, tofd;
{
	struct procinfo *proc = &cpids[fromfd];

if (verbose)
  sfprintf(sfstderr,"reclaim(%d,%d) pid=%d, reaped=%d, chan=%s, host=%s\n",
	   fromfd, tofd, (int)proc->pid, proc->reaped,
	   proc->ch->name, proc->ho->name);

	if (proc->reaped &&
	    ((WIFEXITED(proc->waitstat) && WEXITSTATUS(proc->waitstat)) ||
	     WIFSIGNALED(proc->waitstat))) {

	  /* Child sig-faulted, or had non-zero exit status! */

	  sfprintf(sfstderr,
		   "reclaim(%d,%d) pid=%d, reaped=%d, chan=%s, host=%s ",
		   fromfd, tofd, (int)proc->pid, proc->reaped,
		   proc->ch->name, proc->ho->name);
	  if (WIFEXITED(proc->waitstat))
	    sfprintf(sfstderr,"EXIT=%d\n", WEXITSTATUS(proc->waitstat));
	  else if (WIFSIGNALED(proc->waitstat))
	    sfprintf(sfstderr,"SIGNAL=%d\n", WTERMSIG(proc->waitstat));
	  else
	    sfprintf(sfstderr,"WAITSTAT=0x%04x\n", proc->waitstat);
	}

	proc->pid = 0;
	proc->reaped = 0;
	if (proc->carryover != NULL) {
	  sfprintf(sfstderr, "%s: HELP! Lost %d bytes: '%s'\n",
		  progname, (int)strlen(proc->carryover), proc->carryover);
	  free(proc->carryover);
	  proc->carryover = NULL;
	}
	if (proc->ch) {
	  proc->ch->kids -= 1;
	  unweb(L_CHANNEL, proc->ch);
	  proc->ch = NULL;
	}
	if (proc->ho) {
	  proc->ho->kids -= 1;
	  unweb(L_HOST, proc->ho);
	  proc->ho = NULL;
	}
	if (tofd >= 0)
	  pipes_shutdown_child(tofd);
	close(fromfd);

	/* Reschedule the vertices that are left
	   (that were not reported on).		*/

	/* ... but only if we were not in IDLE chain! */
	if (proc->pthread) {

	  /* Remove this entry from the chains */
	  if (proc->pthread->proc == proc)
	    proc->pthread->proc = proc->pnext;

	  /* Disjoin the thread from the proc */
	  proc->pthread->thrkids -= 1;

	  /* Conditionally reschedule the thread */
	  if (thread_reschedule(proc->pthread,0,-1))
	    /* possibly need to delete it too! */
	    delete_thread(proc->pthread);

	  proc->pthread = NULL;

	} else {

	  /* Maybe we were in idle chain! */
	  struct procinfo *p;

	  p  =  proc->thg->idleproc;
	  while (p && p != proc) p = p->pnext;
	  if (p == proc) {
	    proc->thg->idlecnt -= 1;
	    --idleprocs;

	    /* Remove this entry from the chains */
	    if (proc == proc->thg->idleproc)
	      proc->thg->idleproc = proc->pnext;
	  }
	}

	/* Remove this entry from the chains */
	if (proc->pnext) proc->pnext->pprev = proc->pprev;
	if (proc->pprev) proc->pprev->pnext = proc->pnext;

	/* If e.g. RESCHEDULE has not destroyed this thread-group.. */
	if (proc->thg) {
	  proc->thg->transporters -= 1;
	  /* It may go down to zero and be deleted.. */
	  delete_threadgroup(proc->thg);
	  proc->thg    = NULL;
	}
	--numkids;
	proc->thg    = NULL;
}

static void waitandclose(fd)
	int	fd;
{
	/* This is called when
	   - fd return 0 (EOF)
	   - fd returns -1, and errno != {EAGAIN|EWOULDBLOCK|EINTR}
	 */
	reclaim(fd, cpids[fd].tofd);
}

#ifdef	HAVE_SELECT

#ifdef _AIX /* The select.h  defines NFDBITS, etc.. */
# include <sys/types.h>
# include <sys/select.h>
#endif


#if	defined(BSD4_3) || defined(sun)
#include <sys/file.h>
#endif
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>

#ifndef	NFDBITS
/*
 * This stuff taken from the 4.3bsd /usr/include/sys/types.h, but on the
 * assumption we are dealing with pre-4.3bsd select().
 */

typedef long	fd_mask;

#ifndef	NBBY
#define	NBBY	8
#endif	/* NBBY */
#define	NFDBITS		((sizeof fd_mask) * NBBY)

/* SunOS 3.x and 4.x>2 BSD already defines this in /usr/include/sys/types.h */
#ifdef	notdef
typedef	struct fd_set { fd_mask	fds_bits[1]; } fd_set;
#endif	/* notdef */

#ifndef	_Z_FD_SET
#define	_Z_FD_SET(n, p)   ((p)->fds_bits[0] |= (1 << (n)))
#define	_Z_FD_CLR(n, p)   ((p)->fds_bits[0] &= ~(1 << (n)))
#define	_Z_FD_ISSET(n, p) ((p)->fds_bits[0] & (1 << (n)))
#define _Z_FD_ZERO(p)	  memset((char *)(p), 0, sizeof(*(p)))
#endif	/* !FD_SET */
#endif	/* !NFDBITS */

#ifdef FD_SET
#define _Z_FD_SET(sock,var) FD_SET(sock,&var)
#define _Z_FD_CLR(sock,var) FD_CLR(sock,&var)
#define _Z_FD_ZERO(var) FD_ZERO(&var)
#define _Z_FD_ISSET(i,var) FD_ISSET(i,&var)
#else
#define _Z_FD_SET(sock,var) var |= (1 << sock)
#define _Z_FD_CLR(sock,var) var &= ~(1 << sock)
#define _Z_FD_ZERO(var) var = 0
#define _Z_FD_ISSET(i,var) ((var & (1 << i)) != 0)
#endif


int in_select = 0;

int
mux(timeout)
time_t timeout;
{
	int	i, n, maxf;
	fd_set	rdmask;
	fd_set	wrmask;
	struct timeval tv;
	struct procinfo *proc = cpids;

	if (in_select) {
	  sfprintf(sfstderr,"**** recursed into mux()! ***\n");
	  return 0;
	}

	queryipccheck();

	tv.tv_sec = timeout - now; /* Timeout in seconds */
	if (timeout < now)
	  tv.tv_sec = 0;
	tv.tv_usec = 0;

	maxf = -1;
	_Z_FD_ZERO(rdmask);
	_Z_FD_ZERO(wrmask);
	readsockcnt = 0;
	if (cpids != NULL)
	  for (proc = cpids,i = 0; i < scheduler_nofiles ; ++i,++proc)
	    if (proc->pid != 0) {
	      /* Something can be read ? */
	      _Z_FD_SET(i, rdmask);
	      if (maxf < i)
		maxf = i;

	      ++readsockcnt;
	      /* Something to write ? */
	      if (proc->cmdlen > 0 && proc->tofd >= 0) {
		_Z_FD_SET(proc->tofd, wrmask);
		if (maxf < proc->tofd)
		  maxf = proc->tofd;
	      }

	    }

	if (querysocket >= 0) {
	  _Z_FD_SET(querysocket, rdmask);
	  if (maxf < querysocket)
	    maxf = querysocket;
	}

	/* Although we don't react on the results of these MQ2 fd's,
	   getting them to break timeouts is important for MAILQv2
	   responsiveness. ! */

	if (mailqmode == 2)
	  maxf = mq2add_to_mask(&rdmask, &wrmask, maxf);

	if (maxf < 0)
	  return -1;

	++maxf;
	/*sfprintf(sfstderr, "about to select on %x [%d]\n",
			  mask.fds_bits[0], maxf); */

	in_select = 1;

	n = select(maxf, &rdmask, &wrmask, NULL, &tv);
	if (n < 0) {
	  int err = errno;
	  /* sfprintf(sfstderr, "got an interrupt (%d)\n", errno); */
	  in_select = 0;
	  if (errno == EINTR || errno == EAGAIN)
	    return 0;
	  if (errno == EINVAL || errno == EBADF) {
	    sfprintf(sfstderr, "** select() returned errno=%d\n", err);
	    for (i = 0; i < maxf; ++i) {
	      if (_Z_FD_ISSET(i,rdmask)  &&  fcntl(i,F_GETFL,0) < 0)
		sfprintf(sfstderr,"** Invalid fd on a select() rdmask: %d\n",i);
	      if (_Z_FD_ISSET(i,wrmask)  &&  fcntl(i,F_GETFL,0) < 0)
		sfprintf(sfstderr,"** Invalid fd on a select() wrmask: %d\n",i);
	    }
	    sfsync(sfstderr);
	    abort(); /* mux() select() error EINVAL or EBADF !? */
	  }
	  perror("select() returned unknown error ");
	  fflush(stderr);
	  sfsync(sfstderr);
	  abort(); /* Select with unknown error */
	} else if (n == 0) {
	  /* sfprintf(sfstderr, "abnormal 0 return from select!\n"); */
	  /* -- just a timeout -- fast or long */
	  in_select = 0;
	  return 1;
	} else {
	  /*sfprintf(sfstderr, "got %d ready (%x)\n", n, rdmask.fds_bits[0]);*/

	  /* In case we really should react.. */
	  queryipccheck();

	  if (cpids != NULL) {

	    for (proc = cpids, i = 0; i < maxf; ++i, ++proc) {

	      if (proc->pid != 0 && _Z_FD_ISSET(i, rdmask)) {
		_Z_FD_CLR(i, rdmask);
		/*sfprintf(sfstderr,"that is fd %d\n",i);*/
		/* do non-blocking reads from this fd */
		readfrom(i);
	      }

	      /* In case we have non-completed 'feeds', try feeding them */
	      if (proc->pid > 0    &&  proc->tofd >= 0   &&
		  proc->cmdlen > 0 &&  _Z_FD_ISSET(proc->tofd, wrmask))
		flush_child(proc);

	      /* Because this loop might take a while ... */
	      queryipccheck();
	    }
	  }

	  in_select = 0;
	}
	/* sfprintf(sfstderr, "return from mux\n"); */
	return 0;
}

/* Call it how often you wish, but act it only once a second, or so.. */
static time_t lastqueryipccheck;
static time_t qipcretry;

void
queryipccheck()
{
	int	n;
	fd_set	rdmask;
	fd_set	wrmask;
	struct timeval tv;
	int maxfd;

	mytime(&now);
	if (!mq2_active() && (lastqueryipccheck == now)) return;
	lastqueryipccheck = now;

	if (qipcretry > 0 && qipcretry <= now) {
	  qipcretry = 0;
	  queryipcinit();
	  /*
	   * If qipcretry is set here, the value will be ignored, but
	   * that's ok since sweepretry is active by now
	   */
	}

	if (querysocket >= 0) {

	  maxfd = querysocket;

	  tv.tv_sec = 0;
	  tv.tv_usec = 0;

	  _Z_FD_ZERO(rdmask);
	  _Z_FD_ZERO(wrmask);
	  _Z_FD_SET(querysocket, rdmask);

	  if (mailqmode == 2) {
	    maxfd = mq2add_to_mask(&rdmask, &wrmask, maxfd);
	    n = select(maxfd+1, &rdmask, &wrmask, NULL, &tv);
	    if (n > 0)
	      mq2_areinsets(&rdmask, &wrmask);
	  } else 
	    n = select(maxfd+1, &rdmask, &wrmask, NULL, &tv);


	  if (n > 0 &&
	      _Z_FD_ISSET(querysocket, rdmask)) {
	    struct sockaddr_in raddr;
	    int raddrlen = sizeof(raddr);

	    n = accept(querysocket, (struct sockaddr *)&raddr, &raddrlen);
	    if (n >= 0) {
	      if (mailqmode == 1) {
		int pid = fork();
		if (pid == 0) {
#if defined(F_SETFD)
		  fcntl(n, F_SETFD, 1); /* close-on-exec */
#endif
#ifdef HAVE_TCPD_H /* TCP-Wrapper code */
		  if (wantconn(n, "mailq") == 0) {
		    char *msg = "refusing 'mailq' query from your whereabouts\r\n";
		    int   len = strlen(msg);
		    write(n,msg,len);
		    _exit(0);
		  }
#endif
		  qprint(n);
		  /* Silence memory debuggers about this child's
		     activities by doing exec() on the process.. */
		  /* execl("/bin/false","false",NULL); */
		  _exit(0); /* _exit() should be silent, too.. */
		}
		close(n);
	      } else {
		/* mailqmode == 2 */
		mq2_register(n);
	      }
	    }
	  }
	}
}

void
queryipcinit()
{
	int modecode = 1; /* Modes: 1=TCP, 2=UNIX, default=TCP */
	char *modedata = NULL;

	if (querysocket >= 0)
		return;

	if (mailqsock) {
	  if (cistrncmp(mailqsock,"UNIX:",5)==0) {
	    modedata = mailqsock+5;
	    modecode = 2;
	  } else if (*mailqsock == '/') {
	    /* If it begins with '/', it is AF_UNIX socket */
	    modedata = mailqsock;
	    modecode = 2;
	  } else if (cistrncmp(mailqsock,"TCP:",4)==0) {
	    modedata = mailqsock+4;
	    modecode = 1;
	  } else {
	    /* The default mode is TCP/IP socket */
	    modedata = mailqsock;
	    modecode = 1;
	  }
	}

#ifdef  AF_UNIX
	if (modecode == 2) {
	  struct sockaddr_un sad;
	  int on = 1;

	  mytime(&now);
	  qipcretry = now + 5;

	  sad.sun_family = AF_UNIX;
	  strncpy(sad.sun_path, modedata, sizeof(sad.sun_path));
	  sad.sun_path[ sizeof(sad.sun_path)-1 ] = 0;

	  if ((querysocket = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
	    perror("querysocket: socket(PF_UNIX)");
	    return;
	  }

	  setsockopt(querysocket, SOL_SOCKET, SO_REUSEADDR, (void*)&on, sizeof(on));

	  /* In case that one already exists.. */
	  unlink(sad.sun_path);

	  if (bind(querysocket, (struct sockaddr *)&sad, sizeof sad) < 0) {
	    perror("bind:mailq socket");
	    close(querysocket);
	    querysocket = -1;
	    return;
	  }
#if defined(F_SETFD)
	  fcntl(querysocket, F_SETFD, 1); /* close-on-exec */
#endif

	  if (listen(querysocket, 5) < 0) {
	    perror("listen:mailq socket");
	    close(querysocket);
	    querysocket = -1;
	    return;
	  }
	  qipcretry = 0;
	}
#endif
#ifdef	AF_INET
	if (modecode == 1) {
	  struct servent *serv;
	  struct sockaddr_in sad;
	  int on = 1;
	  int port = 174; /* MAGIC knowledge */

	  mytime(&now);
	  if (!modedata || !*modedata || sscanf(modedata,"%d",&port) != 1) {
	    if ((serv = getservbyname(modedata ? modedata : "mailq", "tcp")) == NULL) {
	      sfprintf(sfstderr, "No 'mailq' tcp service defined!\n");
	    } else
	      port = ntohs(serv->s_port);
	  }
	  qipcretry = now + 5;
	  sad.sin_port        = htons(port);
	  sad.sin_family      = AF_INET;
	  sad.sin_addr.s_addr = htonl(INADDR_ANY);
	  if ((querysocket = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	    perror("querysocket: socket(PF_INET)");
	    return;
	  }
	  setsockopt(querysocket, SOL_SOCKET, SO_REUSEADDR, (void*)&on, sizeof(on));

	  if (bind(querysocket, (struct sockaddr *)&sad, sizeof sad) < 0) {
	    perror("bind:mailq socket");
	    close(querysocket);
	    querysocket = -1;
	    return;
	  }

#if defined(F_SETFD)
	  fcntl(querysocket, F_SETFD, 1); /* close-on-exec */
#endif

	  if (listen(querysocket, 5) < 0) {
	    perror("listen:mailq socket");
	    close(querysocket);
	    querysocket = -1;
	    return;
	  }
	  qipcretry = 0;
	}
#endif	/* AF_INET */
}

#else	/* !HAVE_SELECT */

int
mux(timeout)
time_t timeout;
{
	int	fd;

	/*
	 * Nice'n easy and simpleminded: grab a random file descriptor,
	 * and sit and read off it until something happens.
	 * Some very complicated mux'ing schemes (with shared pipes'n stuff)
	 * are possible in the absence of async i/o like select() or the
	 * simulation USG supplies, but it ain't worth the hassle.
	 */
	readsockcnt = 0;
	if (cpids != NULL)
	  for (fd = 0; fd < scheduler_nofiles ; ++fd)
	    if (cpids[fd].pid != 0) {
	      readfrom(fd);
	      ++readsockcnt;
	    }

	mytime(&now);
	if (timeout > now)
	  sleep(1);
	return 1;
}

void queryipccheck()
{
	/* NOTHING AT ALL -- No select(), no querysocket.. */
}

void
queryipcinit()
{
}
#endif	/* HAVE_SELECT */

static void readfrom(fd)
	int fd;
{
	int	n, e, bufsize = 2048;
	char	*cp, *eobuf, *buf;
	struct procinfo *proc = &cpids[fd];

	cp = buf = (char *)emalloc(bufsize);

	if (proc->carryover != NULL) {
	  int carrylen = strlen(proc->carryover);
	  if (carrylen > bufsize) {
	    while (carrylen > bufsize)
	      bufsize += 1024;
	    buf = erealloc(buf,bufsize);
	  }
	  strcpy(buf, proc->carryover);
	  cp = buf+strlen(buf);
	  free(proc->carryover);
	  proc->carryover = NULL;
	}

	/* Note that if we get an alarm() call, the read will return -1, TG */
	errno = 0;
	while ((n = read(fd, cp, bufsize - (cp - buf))) > 0) {

	  if (verbose)
	    sfprintf(sfstderr, "read from %d returns %d\n", fd, n);

	  eobuf = cp + n;

	  for (cp = buf; cp < eobuf;) {
	    if (*cp == '\n') {
	      int rlen = eobuf - (cp+1);
	      *cp = '\0';
	      if (verbose)
		sfprintf(sfstderr, "%p %d fd=%d processed: %s\n",
			 proc, (int)proc->pid, fd, buf);
	      update(fd,buf);
	      ++cp;
	      if (rlen > 0)
		memcpy(buf, cp, rlen);
	      else
		rlen = 0;
	      cp = buf;
	      eobuf = buf + rlen;

	    } else

	      ++cp;
	  }

	  if (cp == (buf + bufsize)) {
	    /* 
	     * can't happen, this would mean a status report line 
	     * that is rather long...
	     * (oh no! it did happen, it did, it did!...)
	     */
	    int oldsize = bufsize;
	    bufsize <<= 1;
	    buf = erealloc(buf,bufsize);
	    cp = buf + oldsize;
	    *cp = '\0';
	  }

	}
	e = errno;

	if (verbose) {
	  if (!(e == EAGAIN || e == EWOULDBLOCK))
	    sfprintf(sfstderr,
		    "read from %d returns %d, errno=%d\n", fd, n, e);
	}
	if (n == 0 || (n < 0 && !(e == EWOULDBLOCK ||
				  e == EAGAIN || e == EINTR))) {
	  /*sfprintf(sfstdout,
	    "about to call waitandclose(), n=%d, errno=%d\n",n,e);*/

	  if (proc->tofd >= 0)
	    pipes_shutdown_child(proc->tofd);
	  proc->tofd = -1;
	  waitandclose(fd);
	}

	/* sfprintf(sfstderr, "n = %d, errno = %d\n", n, errno); */
	/*
	 * if n < 0, then either we got an interrupt or the read would
	 * block (EINTR or EWOULDBLOCK). In both cases we basically just
	 * want to get back to whatever we were doing. We just need to
	 * make darned sure that a newline was the last character we saw,
	 * or else some report may get lost somewhere.
	 */
	if (proc->pid != 0) {
	  proc->carryover = emalloc(cp - buf + 1);
	  memcpy(proc->carryover, buf, cp - buf);
	  proc->carryover[cp - buf] = '\0';
	} else if (cp > buf)
	  sfprintf(sfstderr,
		   "HELP! Lost %ld bytes (n=%d/%d): '%s'\n",
		   (long)(cp - buf), n, errno, buf);
	free(buf);
}

#if defined(USE_BINMKDIR) || defined(USE_BINRMDIR)

/*
 * From Ross Ridge's Xenix port:
 * - A nasty problem occurs with scheduler if rmdir (and mkdir also I think),
 *   is implented as system("/bin/rmdir ...").  When system() calls wait()
 *   it can reap the scheduler's children without it knowing.  I fixed this
 *   problem by writing a replacement system() function for scheduler.
 *
 */

int
system(name)
	char *name;
{
	char *sh;
	int st, r;
	int pid;
	int i;

	pid = fork();
	switch(pid) {
	case -1:
		return -1;
	case 0:
		sh = getenv("SHELL");
		if (sh == NULL) {
		  sh = "/bin/sh";
		}
		execl(sh, sh, "-c", name, NULL);
		_exit(1);
	default:
#ifndef USE_SIGREAPER
		while(1) {
		  r = wait(&st);
		  if (r == -1) {
		    if (errno != EINTR) {
		      return -1;
		      if (errno != EINTR) {
			return -1;
		      }
		    } else if (r == pid) {
		      break;
		    }
		    for(i = 0; i < scheduler_nofiles; i++) {
		      if (cpids[i].pid == r) {
			cpids[i].pid = -r;
			break;
		      }
		    }
		  }

		  if ((st & 0x00ff) == 0) {
		    return st >> 8;
		  }
		  return 1;
		}
#endif
		break;
	   }
}

#endif


#ifdef USE_SIGREAPER
/*
 *	Catch each child-process death, and reap them..
 */
RETSIGTYPE sig_chld(signum)
int signum;
{
	int pid;
	int ok = 0;
	int i;
	int statloc;

	for (;;) {

#ifdef	HAVE_WAITPID
	  pid = waitpid(-1,&statloc,WNOHANG);
#else
#ifdef  HAVE_WAIT3
	  pid = wait3(&statloc,WNOHANG,NULL);
#else
	  pid = wait(&statloc);
#endif
#endif
	  if (pid <= 0) break;

	  if (WIFEXITED  (statloc)) ok = 1;
	  if (WIFSIGNALED(statloc)) ok = 1;

	  if (verbose) {
	    sfprintf(sfstderr,"sig_chld() pid=%d, ok=%d, stat=0x%x ",
		    pid,ok,statloc);
	    if (WIFEXITED  (statloc))
	      sfprintf(sfstderr,"EXIT=%d\n", WEXITSTATUS(statloc));
	    if (WIFSIGNALED(statloc))
	      sfprintf(sfstderr,"SIGNAL=%d\n", WTERMSIG(statloc));
	  }

	  if (ok && cpids != NULL) {
	    /* Only EXIT and SIGxx DEATHS accepted */

	    for (i = scheduler_nofiles-1; i >= 0; --i) {
	      if (cpids[i].pid == pid) {
		cpids[i].pid = -pid; /* Mark it as reaped.. */
		cpids[i].reaped = 1;
		cpids[i].waitstat = statloc;
		ok = 0;
		if (WSIGNALSTATUS(statloc) == 0 &&
		    WEXITSTATUS(statloc)   == EX_SOFTWARE) {
		  zsyslog((LOG_EMERG, "Transporter process %d exited with EX_SOFTWARE!", pid));
		  sfprintf(sfstderr, "Transporter process %d exited with EX_SOFTWARE; cmdline='%s'\n", pid, cpids[i].cmdline);
		}
		break;
	      }
	      if (cpids[i].pid == -pid) {
		sfprintf(sfstdout," .. already reaped ??\n");
		cpids[i].pid = -pid; /* Mark it as reaped.. */
		cpids[i].reaped = 1;
		cpids[i].waitstat = statloc;
		ok = 0;
		break;
	      }
	    }
	  }
	}

	/* re-instantiate the signal handler.. */
#ifdef SIGCLD
	SIGNAL_HANDLE(SIGCLD,  sig_chld);
#else
	SIGNAL_HANDLE(SIGCHLD, sig_chld);
#endif
}
#endif /* USE_SIGREAPER */
