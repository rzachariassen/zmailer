/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */
/*
 *	Lots of modifications (new guts, more or less..) by
 *	Matti Aarnio <mea@nic.funet.fi>  (copyright) 1992-1998
 */


#include "hostenv.h"
#include <stdio.h>
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
#include "ta.h"

extern int forkrate_limit;
extern int freeze;
extern int mailqmode;

static int  scheduler_nofiles = -1; /* Will be filled below */
static int  runcommand   __((char * const argv[], char * const env[], struct vertex *, struct web *, struct web*));
static void stashprocess __((int, int, int, struct web*, struct web*, struct vertex *, char * const argv[]));
static void reclaim      __((int, int));
static void waitandclose __((int));
static void readfrom     __((int));

static struct mailq *mq2root  = NULL;
static int           mq2count = 0;
static int	     mq2max   = 20; /* How many can live simultaneously */

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

/* Send "#idle\n" -string to the child.. */

void
idle_child(proc)
struct procinfo *proc;
{
	int len, rc;

	if (proc->tofd < 0) return; /* can't write... */

	/* we are NOT to be called while there is something
	   left in the cmdbuf[] ! */
	if (proc->cmdbuf == NULL)
	  cmdbufalloc(2000, &proc->cmdbuf, &proc->cmdspc);
	if (proc->cmdlen != 0) {
	  if (proc->cmdlen >= proc->cmdspc)
	    cmdbufalloc(proc->cmdlen, &proc->cmdbuf, &proc->cmdspc);
	  proc->cmdbuf[proc->cmdlen] = 0;
	  fprintf(stderr,"idle_child(proc->cmdbuf=\"%s\") -> abort()!\n",proc->cmdbuf);
	  fflush(stderr);
	  /* abort(); */ /* Hmm.. ??? */
	  return;
	}
	if (slow_shutdown) {
	  proc->cmdbuf[0] = '\n';
	  len = 1;
	} else {
	  strcpy(proc->cmdbuf,"#idle\n");
	  len = strlen(proc->cmdbuf);
	  /* Count this feed as one of normal inputs.
	     At least we WILL get a "#hungry" message for this */
	  proc->overfed += 1;
	}
	rc = write(proc->tofd, proc->cmdbuf, len);
	if (rc < 0 &&
	    (errno != EAGAIN && errno != EINTR &&
	     errno != EWOULDBLOCK)) {
	  /* Some real failure :-( */
	  pipes_shutdown_child(proc->tofd);
	  proc->tofd = -1;
	  if (proc->vertex)
	    proc->vertex->proc = NULL;
	  if (proc->thread)
	    proc->thread->proc = NULL;
	  proc->thread         = NULL;
	  proc->cmdlen = 0;
	  return;
	}
	proc->cmdlen = 0;
}

int
flush_child(proc)
struct procinfo *proc;
{
	int rc;

	if (proc->tofd < 0) {
	  if (proc->vertex)
	    proc->vertex->proc = NULL;
	  if (proc->thread) {
	    proc->thread->proc = NULL;
	    proc->thread       = NULL;
	  }
	  proc->cmdlen = 0;
	  return 0;
	}

	/* Make sure the buffer exists.. */
	if (proc->cmdbuf == NULL)
	  cmdbufalloc(2000, &proc->cmdbuf, &proc->cmdspc);

	/* Make sure it is zero terminated! */
	proc->cmdbuf[proc->cmdlen] = 0;

	if (proc->cmdlen != 0 && proc->tofd >= 0) {
	  /* We have some leftovers from previous feed..
	     .. feed them now.  */

	  /* fprintf(stderr,
	     "flushing to child pid %d, cmdlen=%d, cmdbuf='%s'\n",
	     proc->pid, proc->cmdlen, proc->cmdbuf);  */

	  rc = write(proc->tofd, proc->cmdbuf, proc->cmdlen);
	  if (rc != proc->cmdlen) {
	    if (rc < 0 && (errno != EAGAIN && errno != EINTR &&
			   errno != EWOULDBLOCK)) {
	      /* Some real failure :-( */
	      pipes_shutdown_child(proc->tofd);
	      proc->tofd = -1;
	      if (proc->vertex)
		proc->vertex->proc = NULL;
	      if (proc->thread) {
		proc->thread->proc = NULL;
		proc->thread       = NULL;
	      }
	      proc->cmdlen = 0;
	      return -1;
	    }
	    if (rc < 0) rc = 0;
	    if (rc > 0)
	      strcpy(proc->cmdbuf, proc->cmdbuf+rc);
	    proc->cmdlen -= rc;
	  } else {
	    proc->cmdlen = 0; /* Clean the pending info.. */
	  }
	  proc->feedtime = now;
	  return proc->cmdlen; /* We return latter.. */
	}
	return 0;
}

void
feed_child(proc)
struct procinfo *proc;
{
	struct vertex *vtx;
	int rc;
	static char *cmdbuf = NULL;
	static int cmdbufspc = 0;
	int cmdlen;

	if (proc->thread == NULL) {
	  return; /* Might be called without next process.. */
	}
	if (proc->pid <= 0 || proc->tofd < 0) {
	  return; /* No process../No write channel.. */
	}
	if (proc->fed) {
	  /* DON'T RE-FEED! */
	  if (verbose)
	    printf(" ... no refeeding\n");
	  return;
	}

	vtx = proc->vertex;

	if (!vtx) { /* No active vertex left, child is in inactive
		       chain, but has leftover stuff at the output
		       buffer */
	  flush_child(proc);
	  return;
	}

	if (vtx->wakeup > now)
	  return; /* No, not yet! */

	if (slow_shutdown) {
	  cmdlen = 1;
	  cmdbufalloc(cmdlen, &cmdbuf, &cmdbufspc);
	  strcpy(cmdbuf,"\n");
	} else if (vtx->cfp->dirind > 0) {
	  const char *d = cfpdirname(vtx->cfp->dirind);
	  if (proc->thg->withhost) { /* cmd-line was with host */
	    cmdlen = 2 + strlen(d) + strlen(vtx->cfp->mid);
	    cmdbufalloc(cmdlen, &cmdbuf, &cmdbufspc);
	    sprintf(cmdbuf, "%s/%s\n", d, vtx->cfp->mid);
	  } else {
	    cmdlen = 3+strlen(d)+strlen(vtx->cfp->mid)+strlen(proc->ho->name);
	    cmdbufalloc(cmdlen, &cmdbuf, &cmdbufspc);
	    sprintf(cmdbuf, "%s/%s\t%s\n", d, vtx->cfp->mid, proc->ho->name);
	  }
	} else {
	  if (proc->thg->withhost) { /* cmd-line was with host */
	    cmdlen = 1 + strlen(vtx->cfp->mid);
	    cmdbufalloc(cmdlen, &cmdbuf, &cmdbufspc);
	    sprintf(cmdbuf, "%s\n", vtx->cfp->mid);
	  } else {
	    cmdlen = 2+strlen(vtx->cfp->mid)+strlen(proc->ho->name);
	    cmdbufalloc(cmdlen, &cmdbuf, &cmdbufspc);
	    sprintf(cmdbuf, "%s\t%s\n", vtx->cfp->mid, proc->ho->name);
	  }
	}

	if (cmdlen >= (proc->cmdspc - proc->cmdlen)) {
	  /* Does not fit there, flush it! */
	  rc = flush_child(proc);
	  if (proc->cmdlen == 0 && cmdlen >= proc->cmdspc) {
	    /* Wow, this command is bigger than that buffer! */
	    cmdbufalloc(cmdlen+1, &proc->cmdbuf, &proc->cmdspc);
	  }
	  if (cmdlen >= (proc->cmdspc - proc->cmdlen)) {
	    /* STILL does not fit there, come back latter.. */
	    return;
	  }
	}
	/* Ok, it does fit in, copy it there.. */
	memcpy(proc->cmdbuf+proc->cmdlen,cmdbuf, cmdlen+1);
	proc->cmdlen += cmdlen;

	if (verbose) {
	  printf("feed: tofd=%d, fed=%d, chan=%s, proc=0x%p, vtx=0x%p, ",
		 proc->tofd, proc->fed, proc->ch->name, proc, vtx);
	  fflush(stdout);
	}

	vtx->proc = proc;    /* Flag that it is in processing */
	vtx->ce_pending = 0; /* and clear the pending.. */
	
	if (proc->hungry) --hungry_childs;
	/* It was fed (to buffer), clear this flag.. */
	proc->hungry = 0;
	proc->fed = 1;

	if (verbose)
	  printf("len=%d buf=%s", cmdlen, cmdbuf);

	proc->feedtime = now;
	if (vtx)
	  vtx->attempts += 1; /* We may get it closed above.. */
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


	if (freeze) return 0;

	if (verbose)
	  printf("transport(vhead,chan=%s,host=%s)\n",
		 chwp->name,howp->name);

	++startcnt;
	this_time = mytime(NULL);
	if (this_time != prev_time) {
	  startcnt = 0;
	  prev_time = this_time;
	} else if (startcnt > forkrate_limit) {
	  if (verbose)
	    printf(" ... too many forks per second!\n");
	  return 0;
	}

	if (vhead->thgrp->ce.argv == NULL) {
	  fprintf(stderr, "No command defined for %s/%s!\n",
		  chwp->name, howp->name);
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
	    fprintf(stderr,"BUFFER OVERFLOW IN ARGV[] SUBSTITUTIONS!\n");
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
	      fprintf(stderr,"BUFFER OVERFLOW IN ARGV[0] CONSTRUCTION!\n");
	      abort();
	    }
	  } else
	    ++avi;
	  if (avi >= MAXARGC) avi = MAXARGC;
	  if (evi >= MAXARGC) evi = MAXARGC;
	}
	av[avi] = NULL;
	if ((s = getenv("TZ")))       ev[evi++] = s; /* Pass the TZ      */
	if ((s = getzenv("PATH")))    ev[evi++] = s; /* Pass the PATH    */
	if ((s = getzenv("ZCONFIG"))) ev[evi++] = s; /* Pass the ZCONFIG */
	ev[evi] = NULL;

	/* fork off the appropriate command with the appropriate stdin */
	if (verbose) {
	  printf("${ ");
	  for (i = 0; ev[i] != NULL; ++i)
	    printf(" %s", ev[i]);
	  printf(" }");
	  for (i = 0; ev[i] != NULL; ++i)
	    printf(" %s", av[i]);
	  printf("\n");
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
	  fprintf(stderr, "to %d/%d from %d/%d\n",
		  to[0],to[1],from[0],from[1]);

	if ((pid = fork()) == 0) {	/* child */

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
	  fprintf(stderr, "Exec of %s failed!\n", cmd);
	  _exit(1);
	} else if (pid < 0) {	/* fork failed - yell and forget it */
	  close(to[0]); close(to[1]);
	  close(from[0]); close(from[1]);
	  fprintf(stderr, "Fork failed!\n");
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
	proc->next   = NULL;
	proc->cmdlen = 0;
	proc->reaped = 0;
	proc->carryover = NULL;
	proc->hungry = 0;
	proc->fed    = 0;
	proc->overfed = 0;
#endif
	proc->pid    = pid;
	proc->ch     = chwp;
	proc->ho     = howp;
	proc->vertex = vhead;
	proc->thread = vhead->thread;
	proc->thread->proc = proc;
	proc->thg    = vhead->thread->thgrp;
	proc->thg->transporters += 1;
	++numkids;
	if (chwp != NULL) chwp->kids += 1;
	if (howp != NULL) howp->kids += 1;
	proc->tofd   = tofd;
	vhead->proc  = proc;
	mytime(&proc->hungertime); /* Actually it is not yet 'hungry' as
				      per reporting so, but we store the
				      time-stamp anyway */

	cmdbufalloc(2000, &proc->cmdbuf, &proc->cmdspc);
	cmdbufalloc(200, &proc->cmdline, &proc->cmdlspc);

	fd_nonblockingmode(fromfd);
	if (fromfd != tofd)
	  fd_nonblockingmode(tofd);

	/* Costruct a faximille of the argv[] in a single string.
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
	  fprintf(stderr, "stashprocess(%d, %d, %d, %s, %s, '%s')\n",
		  pid, fromfd, tofd, chwp ? chwp->name : "nil",
		  howp ? howp->name : "nil", proc->cmdline);
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
  fprintf(stderr,"reclaim(%d,%d) pid=%d, reaped=%d, chan=%s, host=%s\n",
	  fromfd,tofd,(int)proc->pid,proc->reaped,
	  proc->ch->name,proc->ho->name);

	proc->pid = 0;
	proc->reaped = 0;
	if (proc->carryover != NULL) {
	  fprintf(stderr, "%s: HELP! Lost %d bytes: '%s'\n",
		  progname, (int)strlen(proc->carryover), proc->carryover);
	  free(proc->carryover);
	  proc->carryover = NULL;
	}
	if (proc->ch != NULL) {
	  proc->ch->kids -= 1;
	  if (proc->ch->kids == 0 && proc->ch->link == NULL) {
	    unweb(L_CHANNEL, proc->ch);
	    proc->ch = NULL;
	  }
	}
	if (proc->ho != NULL) {
	  proc->ho->kids -= 1;
	  if (proc->ho->kids == 0 && proc->ho->link == NULL) {
	    unweb(L_HOST, proc->ho);
	    proc->ho = NULL;
	  }
	}
	if (tofd >= 0)
	  pipes_shutdown_child(tofd);
	close(fromfd);

	/* Reschedule the vertices that are left
	   (that were not reported on).		*/

	/* ... but only if we were not in IDLE chain! */
	if (proc->thread != NULL) {
	  /* Reschedule them all .. */
	  thread_reschedule(proc->thread,0,-1);
	  /* Bookkeeping about dead transporters */
	  proc->thg->transporters -= 1;
	  --numkids;
	  if (proc->vertex != NULL)
	    proc->vertex->proc = NULL;
	  proc->vertex = NULL;
	  if (proc->thread)
	    proc->thread->proc = NULL;
	  proc->thread = NULL;
	  proc->thg    = NULL;
	} else {
	  /* Maybe we were in idle chain! */
	  if (proc->thg != NULL /* And not killed by  idle_cleanup() */) {
	    struct procinfo *p, **pp;
	    p  =  proc->thg->idleproc;
	    pp = &proc->thg->idleproc;

	    while (p && p != proc) {
		/* Move to the next possible idle process */
		pp = &p->next;
		p = p->next;
	    }
	    if (p == proc) {
	      /* Remove this entry from the chains */
	      *pp = p->next;
	      p = p->next;
	      proc->thg->idlecnt      -= 1;
	      --idleprocs;
	      proc->thg->transporters -= 1;
	      --numkids;
	      /* It may go down to zero.. */
	      if (proc->thg->transporters == 0 && proc->thg->threads == 0)
		delete_threadgroup(proc->thg);
	    } else {
	      /* It is not in idle chain, it has died somehow else.. */
	      if (proc->vertex != NULL)
		proc->vertex->proc = NULL;
	      proc->vertex = NULL;
	      if (proc->thread != NULL)
		proc->thread->proc = NULL;
	      proc->thread = NULL;
	      proc->thg->transporters -= 1;
	      --numkids;
	    }
	  } else {
	    /* We are killed by the idle_cleanup() !   */
	    /* proc->thg == NULL, proc->thread == NULL */
	    /* idle_cleanup() did all decrementing..   */
	  }
	}
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


extern int mq2add_to_rdmask __((fd_set *, int));

int mq2add_to_rdmask(maskp, maxfd)
fd_set *maskp;
int maxfd;
{
  return maxfd;
}

int in_select = 0;

int
mux(timeout)
time_t timeout;
{
	int	i, n, rc, maxf;
	fd_set	rdmask;
	fd_set	wrmask;
	struct timeval tv;
	struct procinfo *proc = cpids;

	if (in_select) {
	  fprintf(stderr,"**** recursed into mux()! ***\n");
	  return 0;
	}

	mytime(&now);

	tv.tv_sec = timeout - now; /* Timeout in seconds */
	if (timeout < now)
	  tv.tv_sec = 0;
	tv.tv_usec = 0;

	maxf = 0;
	_Z_FD_ZERO(rdmask);
	_Z_FD_ZERO(wrmask);
	readsockcnt = 0;
	if (cpids != NULL)
	  for (proc = cpids,i = 0; i < scheduler_nofiles ; ++i,++proc)
	    if (proc->pid != 0) {
	      _Z_FD_SET(i, rdmask);
	      maxf = i;
	      ++readsockcnt;
	      if (proc->cmdlen != 0)
		_Z_FD_SET(i, wrmask);
	    }
	if (querysocket >= 0) {
	  _Z_FD_SET(querysocket, rdmask);
	  if (maxf < querysocket)
	    maxf = querysocket;
	}
	if (maxf < 0)
	  return -1;

	++maxf;
	/*fprintf(stderr, "about to select on %x [%d]\n",
			  mask.fds_bits[0], maxf); */

	in_select = 1;

	if ((n = select(maxf, &rdmask, &wrmask, NULL, &tv)) < 0) {
	  int err = errno;
	  /* fprintf(stderr, "got an interrupt (%d)\n", errno); */
	  in_select = 0;
	  if (errno == EINTR || errno == EAGAIN)
	    return 0;
	  if (errno == EINVAL || errno == EBADF) {
	    fprintf(stderr, "** select() returned errno=%d\n", err);
	    for (i = 0; i < maxf; ++i) {
	      if (_Z_FD_ISSET(i,rdmask)  &&  fcntl(i,F_GETFL,0) < 0)
		fprintf(stderr,"** Invalid fd on a select() rdmask: %d\n",i);
	      if (_Z_FD_ISSET(i,wrmask)  &&  fcntl(i,F_GETFL,0) < 0)
		fprintf(stderr,"** Invalid fd on a select() wrmask: %d\n",i);
	    }
	    fflush(stderr);
	    abort(); /* mux() select() error EINVAL or EBADF !? */
	  }
	  perror("select() returned unknown error ");
	  fflush(stderr);
	  abort(); /* Select with unknown error */
	} else if (n == 0) {
	  /* fprintf(stderr, "abnormal 0 return from select!\n"); */
	  /* -- just a timeout -- fast or long */
	  in_select = 0;
	  return 1;
	} else {
	  /*fprintf(stderr, "got %d ready (%x)\n", n, rdmask.fds_bits[0]);*/
	  if (querysocket >= 0 && _Z_FD_ISSET(querysocket, rdmask)) {
	    struct sockaddr_in raddr;
	    int	raddrlen;

	    --n;
	    _Z_FD_CLR(querysocket, rdmask);
	    raddrlen = sizeof raddr;
	    i = accept(querysocket, (struct sockaddr *)&raddr, &raddrlen);
	    if (i < 0) {
	      perror("accept");
	    } else if (mailqmode == 1) {
	      rc = fork();
	      if (rc == 0) { /* Child! */
		close(querysocket);
#ifdef HAVE_TCPD_H /* TCP-Wrapper code */
		if (wantconn(i, "mailq") == 0) {
		  char *msg = "refusing 'mailq' query from your whereabouts\r\n";
		  int   len = strlen(msg);
		  write(i,msg,len);
		  _exit(0);
		}
#endif
		qprint(i);
		/* Silence memory debuggers about this child's
		   activities by doing exec() on the process.. */
		/* execl("/bin/false","false",NULL); */
		_exit(0); /* _exit() should be silent too.. */
	      }
	      /* if (rc > 0)
		 ++numkids; */
	      close(i);
	    } else {
	      /* XXX: mailqmode == 2 ?? */
	    }
	  }
	  if (cpids != NULL) {
	    for (i = 0; i < maxf; ++i) {
	      if (cpids[i].pid != 0 && _Z_FD_ISSET(i, rdmask)) {
		--n;
		_Z_FD_CLR(i, rdmask);
		/*fprintf(stderr,"that is fd %d\n",i);*/
		/* do non-blocking reads from this fd */
		readfrom(i);
		/* Because this loop might take a while ... */
		queryipccheck();
	      }
	    }
	    /* In case we have non-completed 'feeds', try feeding them */
	    for (i = 0; i < scheduler_nofiles; ++i)
	      if (cpids[i].pid > 0
		  && cpids[i].cmdlen != 0
		  && _Z_FD_ISSET(i, wrmask)) {
		flush_child(&cpids[i]);
		/* Because this loop might take a while ... */
		queryipccheck();
	      }
	  }
	  in_select = 0;
	}
	/* fprintf(stderr, "return from mux\n"); */
	return 0;
}

void
queryipccheck()
{
	if (querysocket >= 0) {
	  int	n;
	  fd_set	mask;
	  struct timeval tv;
	  int maxfd = querysocket;

	  tv.tv_sec = 0;
	  tv.tv_usec = 0;

	  _Z_FD_ZERO(mask);
	  _Z_FD_SET(querysocket, mask);

	  if (mailqmode == 2) {
	    maxfd = mq2add_to_rdmask(&mask, maxfd);
	  }

	  n = select(maxfd+1, &mask, NULL, NULL, &tv);
	  if (n > 0 &&
	      _Z_FD_ISSET(querysocket, mask)) {
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
		  _exit(0); /* _exit() should be silent too.. */
		}
	      } else {
		/* XXX: mailqmode == 2 */
	      }
	      close(n);
	    }
	  }
	}
}

void
queryipcinit()
{
#ifdef	AF_INET
	struct servent *serv;
	struct sockaddr_in sad;
	int on = 1;

	if (querysocket >= 0)
		return;
	mytime(&now);
	if ((serv = getservbyname("mailq", "tcp")) == NULL) {
	  fprintf(stderr, "No 'mailq' tcp service defined!\n");
	  /* try again in 5 minutes or so */
	  qipcretry = now + 300;
	  return;
	}
	qipcretry = now + 5;
	sad.sin_port        = serv->s_port;
	sad.sin_family      = AF_INET;
	sad.sin_addr.s_addr = htonl(INADDR_ANY);
	if ((querysocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	  perror("socket");
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
	int	n, dontbreak, bufsize = 2048;
	char	*cp, *pcp, *eobuf, *buf;
	struct procinfo *proc = &cpids[fd];

	dontbreak = 0;
	cp = pcp = NULL;

	buf = (char *)emalloc(bufsize);

	if (proc->carryover != NULL) {
	  int carrylen = strlen(proc->carryover);
	  if (carrylen > bufsize) {
	    while (carrylen > bufsize)
	      bufsize += 1024;
	    buf = erealloc(buf,bufsize);
	  }
	  strcpy(buf, proc->carryover);
	  cp = buf+strlen(buf);
	  pcp = buf;
	  free(proc->carryover);
	  proc->carryover = NULL;
	  dontbreak = 1;
	}

	/* Note that if we get an alarm() call, the read will return -1, TG */
	errno = 0;
	while ((n = read(fd, dontbreak ? cp : buf,
			 bufsize - (dontbreak ? (cp - buf) : 0))) > 0) {
	  if (verbose)
	    fprintf(stderr, "read from %d returns %d\n", fd, n);
	  eobuf = (dontbreak ? cp : buf) + n;

	  for (cp = buf, pcp = buf; cp < eobuf; ++cp) {
	    if (*cp == '\n') {
	      *cp = '\0';
	      if (verbose)
		fprintf(stderr, "%d fd=%d processed: %s\n",
			(int)proc->pid,fd, pcp);
	      update(fd,pcp);
	      *cp = '_';
	      pcp = cp + 1;
	      dontbreak = 0;
	    } else
	      dontbreak = 1;
	  }

	  if (dontbreak && cp == buf + bufsize) {
	    if (pcp == buf) {
	      /* XX:
	       * can't happen, this would mean a status report line 
	       * that is rather long...
	       * (oh no! it did happen, it did, it did!...)
	       */
	      bufsize += 1024;
	      pcp = buf = erealloc(buf,bufsize);
	      cp = buf + (bufsize - 1024);
	      *cp = '\0';
	    } else {
	      memcpy(buf, pcp, cp-pcp);
	      cp = buf + (cp-pcp);
	      *cp = '\0';
	      pcp = buf;	/* may be used below */
	    }
	  }
	  if (!dontbreak)
	    break;
	}

	if (verbose) {
	  if (!(errno == EAGAIN || errno == EWOULDBLOCK))
	    fprintf(stderr,
		    "read from %d returns %d, errno=%d\n", fd, n, errno);
	}
	if (n == 0 || (n < 0 && errno != EWOULDBLOCK && errno != EAGAIN &&
		       errno != EINTR)) {
	  /*printf("about to call waitandclose(), n=%d, errno=%d\n",n,errno);*/
	  if (proc->tofd >= 0)
	    pipes_shutdown_child(proc->tofd);
	  proc->tofd = -1;
	  waitandclose(fd);
	}
	/* fprintf(stderr, "n = %d, errno = %d\n", n, errno); */
	/*
	 * if n < 0, then either we got an interrupt or the read would
	 * block (EINTR or EWOULDBLOCK). In both cases we basically just
	 * want to get back to whatever we were doing. We just need to
	 * make darned sure that a newline was the last character we saw,
	 * or else some report may get lost somewhere.
	 */
	if (dontbreak) {
	  if (proc->pid != 0) {
	    proc->carryover = emalloc(cp-pcp+1);
	    memcpy(proc->carryover, pcp, cp-pcp);
	    proc->carryover[cp-pcp] = '\0';
	  } else
	    fprintf(stderr,
		    "HELP! Lost %ld bytes (n=%d/%d, off=%ld): '%s'\n",
		    (long)(cp - pcp), n, errno, (long)(pcp-buf), pcp);
	}
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

	  if (WEXITSTATUS  (statloc) != 0) ok = 1;
	  if (WSIGNALSTATUS(statloc) != 0) ok = 1;

	  if (verbose)
	    fprintf(stderr,"sig_chld() pid=%d, ok=%d, stat=0x%x\n",
		    pid,ok,statloc);

	  if (ok && cpids != NULL) {
	    /* Only EXIT and SIGxx DEATHS accepted */

	    for (i = scheduler_nofiles-1; i >= 0; --i) {
	      if (cpids[i].pid == pid) {
		cpids[i].pid = -pid; /* Mark it as reaped.. */
		cpids[i].reaped = 1;
		ok = 0;
		if (WSIGNALSTATUS(statloc) == 0 &&
		    WEXITSTATUS(statloc) == EX_SOFTWARE) {
		  zsyslog((LOG_EMERG, "Transporter process %d exited with EX_SOFTWARE!", pid));
		  fprintf(stderr, "Transporter process %d exited with EX_SOFTWARE; cmdline='%s'\n", pid, cpids[i].cmdline);
	  }
		break;
	      }
	      if (cpids[i].pid == -pid) {
		printf(" .. already reaped ??\n");
		cpids[i].pid = -pid; /* Mark it as reaped.. */
		cpids[i].reaped = 1;
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
