/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */
/*
 *	Lots of modifications (new guts, more or less..) by
 *	Matti Aarnio <mea@nic.funet.fi>  (copyright) 1992-1999
 */

#include "hostenv.h"
#include <stdio.h>
#include "scheduler.h"
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>

#include "prototypes.h"
#include "libz.h"

/* define NO_VERBOSE_MAILQ, if you don't want to output potentially HUGE
   mailq report -- necessary at some sites, while definitely undesirable
   at others..  We need to change this mechanism.. */
extern int mailq_Q_mode; /* Argument 'Q' means: output only 'mailq -Q' -data.. */
/* #define NO_VERBOSE_MAILQ */

extern int errno;

static int qpctlfile __((struct spblk *spl));
static int qpchannel __((struct spblk *spl));
static int qphost __((struct spblk *spl));

#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif	/* !HAVE_UTIMES */
#ifdef HAVE_UTIME_H
# include <utime.h>
#else
/* XXX: struct utimbuf defined ??? */
#endif

static FILE *qpfp;
static char qpch;
static time_t qpnow;

static int qid = 0;

void
qprint(fd)
	int fd;
{
#ifdef	HAVE_UTIME
	struct utimbuf tvp;
#else	/* !HAVE_UTIMES */
	struct timeval tvp[2];
#endif	/* !HAVE_UTIMES */

	/*
	 * The O_NDELAY flag is needed so we don't block
	 * if the file is a FIFO (which is recommended).
	 */
	if (fd < 0) {
#ifndef O_NDELAY
#define O_NDELAY 0	/* you lose */
#endif
		fd = open(rendezvous, O_WRONLY|O_CREAT|O_TRUNC|O_NDELAY, 0644);
		if (fd < 0) {
			fprintf(stderr,
				"open(%s): %d\n", rendezvous, errno);
			return;
		}
	}
	if ((qpfp = fdopen(fd, "w")) == NULL) {
		fprintf(stderr, "hmmm\n");
		close(fd);
		return;
	}
	qpch = '\0';
	qid  = 0;

	fprintf(qpfp, "version zmailer 1.0\nVertices:\n");
	mytime(&qpnow);
#ifndef NO_VERBOSE_MAILQ
	if (!mailq_Q_mode)
	  sp_scan(qpctlfile, (struct spblk *)NULL, spt_mesh[L_CTLFILE]); 
#endif
	if (qpch != '\0') {
		fprintf(qpfp, "Channels:\n");
#ifndef NO_VERBOSE_MAILQ
		if (!mailq_Q_mode)
		  sp_scan(qpchannel, (struct spblk *)NULL, spt_mesh[L_CHANNEL]);
#endif
		fprintf(qpfp, "Hosts:\n");
#ifndef NO_VERBOSE_MAILQ
		if (!mailq_Q_mode)
		  sp_scan(qphost, (struct spblk *)NULL, spt_mesh[L_HOST]);
#endif
	}
	fprintf(qpfp, "End:\n");

	thread_report(qpfp, 1);
	
	fclose(qpfp);

	/* XX: I suppose we don't really need to do this if we use TCP. */
	if (rendezvous != NULL) {
	  now = mytime(NULL) - 1;
#ifdef	HAVE_UTIME
	  tvp.actime = tvp.modtime = now;
	  utime(rendezvous, &tvp);
#else	/* !HAVE_UTIMES */
	  tvp[0].tv_sec = tvp[1].tv_sec = now;
	  tvp[0].tv_usec = tvp[1].tv_usec = 0;
	  utimes(rendezvous, tvp);
#endif	/* !HAVE_UTIMES */
	}
}

static int qpctlfile(spl)
	struct spblk *spl;
{
	register struct ctlfile *cfp = (struct ctlfile *)spl->data;
	register struct vertex *vp;
	register int i;
	char buf[100];

	/* assert cfp != NULL */
	for (vp = cfp->head; vp != NULL; vp = vp->next[L_CTLFILE]) {
	  vp->qid = ++qid;
	  if (cfp->dirind >= 0)
	    fprintf(qpfp, "%d:\t%s/%s\t%d;",
		    vp->qid, cfpdirname(cfp->dirind), cfp->mid, vp->ngroup);
	  else
	    fprintf(qpfp, "%d:\t%s\t%d;", vp->qid, cfp->mid, vp->ngroup);
	  qpch = ' ';
	  for (i = 0; i < vp->ngroup; ++i) {
	    fprintf(qpfp, "%c%ld", qpch, (long)cfp->offset[vp->index[i]]);
	    qpch = ',';
	  }
	  if (vp->message != NULL)
	    fprintf(qpfp, "\t#%s ", vp->message);
	  else
	    fprintf(qpfp, "\t#");

	  i = 0;
	  if (vp->wakeup > qpnow) {
	    buf[0] = '\0';
	    saytime((u_long)(vp->wakeup - qpnow), buf, 1);
	    fprintf(qpfp, "(retry in %s", buf);
	    ++i;
	  } else if (vp->ce_pending) {
	    fprintf(qpfp, "(waiting for %sslot",
		    vp->ce_pending == SIZE_L ? "" :
		    vp->ce_pending == L_CHANNEL ? "channel " :
		    "thread ");
	    ++i;
	  } else {
	    if (vp->proc) {
	      fprintf(qpfp,"(running now, pid=%d ", (int)vp->proc->pid);
	      if (vp->proc->vertex == vp)
		fprintf(qpfp,"active");
	      else
		if (vp->proc->vertex == NULL)
		  fprintf(qpfp,"vtx=NULL??");
		else
		  fprintf(qpfp,"touched");
	    } else {
	      fprintf(qpfp, "(activation pending, thread");
	      /* A vertex is always on some thread.. */
	      if (vp->thread && vp->thread->proc) {
		fprintf(qpfp," pid=%d ", (int)vp->thread->proc->pid);
		if (vp->thread->proc->thread == vp->thread)
		  fprintf(qpfp,"expected");
		else
		  fprintf(qpfp,"bygone");
	      } else {
		if (vp->thread == NULL)
		  fprintf(qpfp," NO_THREAD!");
		else
		  fprintf(qpfp," inactive");
	      }
	    }
	    ++i;
	  }
	  if (vp->ce_expiry > 0) {
	    /* [mea] Want to know when it expires.. */
	    buf[0] = '\0';
	    saytime((long)(vp->ce_expiry - qpnow), buf, 1);
	    fprintf(qpfp,"%sexpires in %s, tries=%d",
		    i ? ", " : "(", buf, vp->attempts);
	    }
	    if (i)
	      putc(')', qpfp);

	    putc('\n', qpfp);
	  }
	  return 0;
	}

static int qpchannel(spl)
	struct spblk *spl;
{
	register struct web *wc = (struct web *)spl->data;
	register struct vertex *vp;

	if (wc->link != NULL) {
	  fprintf(qpfp, "%s:\t", wc->name);
	  for (vp = wc->link; vp != NULL; vp = vp->next[L_CHANNEL])
	    if (vp->qid)
	      fprintf(qpfp, ">%d", vp->qid);
	    else
	      fprintf(qpfp, ">999%04d", (int)vp->cfp->id);
	  fprintf(qpfp, "\n");
	}
	return 0;
}

static int qphost(spl)
	struct spblk *spl;
{
	register struct web *wc = (struct web *)spl->data;
	register struct vertex *vp;

	if (wc->link != NULL) {
	  fprintf(qpfp, "%s:\t", wc->name);
	  for (vp = wc->link; vp != NULL; vp = vp->next[L_HOST])
	    if (vp->qid)
	      fprintf(qpfp, ">%d", vp->qid);
	    else
	      fprintf(qpfp, ">999%04d", (int)vp->cfp->id);
	  fprintf(qpfp, "\n");
	}
	return 0;
}
