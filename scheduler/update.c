/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *
 */
/*
 *	Lots of modifications (new guts, more or less..) by
 *	Matti Aarnio <mea@nic.funet.fi>  (copyright) 1992-1998
 */

#include "hostenv.h"
#include <stdio.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/stat.h>
#include "zsyslog.h"
#include "splay.h"
#include "mail.h"
#include "scheduler.h"

#include "prototypes.h"
#include "libz.h"

static struct vertex *findvertex __((long, long, int*));
static int ctlowner __((struct ctlfile *));
static void vtxupdate __((struct vertex *, int, int));
static void expaux __((struct vertex *, int, const char *));

extern FILE *vfp_open __((struct ctlfile *));

#if 0
extern int ermdir();
extern int rmdir();
extern int eunlink();
extern struct spblk *sp_fhead(), *sp_fnext();
#endif
extern time_t now;
extern int global_wrkcnt;
extern char *procselect;

/*
 * Parse a diagnostic string from a transport agent, and do whatever is
 * necessary to update our model of the world to reflect the new reality.
 *
 *	#hungry
 *	#resync 18453-321
 *	# other debug comment
 *	18453/3527\tIETF-NOTARY\tok Quick SMTP connection!
 *	18453/3527\tIETF-NOTARY\tdeferred Unable to contact host!
 *	18453/3527\tIETF-NOTARY\terror Unknown user name "fred".
 *	18453/3527\tIETF-NOTARY\tretryat [+]NNNN circuit unavailable.
 */

/* dispatch table for diagnostic types */

#define DARGS __((struct vertex *, long, long, long, const char*, const char*))

static int u_ok       DARGS ;
static int u_ok2      DARGS ;
static int u_ok3      DARGS ;
static int u_deferred DARGS ;
static int u_error    DARGS ;
static int u_error2   DARGS ;
static int u_retryat  DARGS ;

static struct diagcodes {
	const char	*name;
	int		(*fcn) DARGS ;
} diags[] = {
		{	"ok",		u_ok		},
		{	"ok2",		u_ok2		},
		{	"ok3",		u_ok3		},
		{	"deferred",	u_deferred	},
		{	"error",	u_error		},
		{	"error2",	u_error2	},
		{	"retryat",	u_retryat	},
		{	NULL,		NULL		}
};

void
update(fd, diagnostic)
	int fd;
	char	*diagnostic;
{
	register char	*cp;
	const char	*type, *message, *notary;
	long	offset;
	long	inum;
	int	index;
	struct vertex *vp;
	struct diagcodes *dcp;
	struct procinfo *proc = &cpids[fd];

	if (*diagnostic == 0) {
	  /* Lone newline.. old-style indications from the transporter */
	  if (proc->tofd >= 0 &&
	      proc->hungry == 0) {
	    proc->hungry = 1;
	    mytime(&now);
	    proc->hungertime = now;
	    ++hungry_childs;
	  }
	  /* Things are known to DIE from under us! */
	  /* .. propably not a good idea to try to pick any next.. */
	  if (proc->overfed > 0)
	    proc->overfed -= 1;
	  pick_next_vertex(proc, 1, 0);
	  if (proc->hungry)
	    feed_child(proc);
	  if (proc->fed)
	    ++proc->overfed;
	  flush_child(proc);
	  return;
	}
	if (*diagnostic != '#') { /* Not debug diagnostic message */
	  inum = atol(diagnostic);
	  if ((cp = strchr(diagnostic, '/')) == NULL) {
	    fprintf(stderr, "%s Misformed diagnostic: %s\n",
		    timestring(), diagnostic);
	    return;
	  }
	  offset = atol(++cp);
	  if ((cp = strchr(cp, '\t')) == NULL) {
	    fprintf(stderr, "%s Misformed diagnostic: %s\n",
		    timestring(), diagnostic);
	    return;
	  }
	  notary = ++cp;
	  if ((cp = strchr(cp, '\t')) == NULL) {
	    fprintf(stderr, "%s Misformed diagnostic: %s\n",
		    timestring(), diagnostic);
	    return;
	  }
	  *cp = 0; /* Trailing TAB after notary string, NULL it */
	  type = ++cp;
	  while (*cp != '\0' && isascii(*cp) && !isspace(*cp))
	    ++cp;
	  if (*cp == '\0') {
	    message = NULL;
	  } else {
	    *cp++ = '\0';
	    message = cp;
	  }
	  if (verbose)
	    printf("diagnostic: %ld/%ld\t%s\t%s\n",inum,offset,notary,type);

	  if ((vp = findvertex(inum, offset, &index)) == NULL)
	    return;

	  if (vp->notary != NULL)
	    free(vp->notary);
	  vp->notary = NULL;
	  if (*notary)
	    vp->notary = strsave(notary);

	  /* Select function by the type name: ok/error/retryat/deferred */

	  for (dcp = &diags[0]; dcp->name != NULL; ++dcp) {
	    /* XX: replace strcmp() with cistrcmp() ??  Should not need,
	       unless something is wrong with the transporters. */
	    if (strcmp(dcp->name, type) == 0) {
	      (dcp->fcn)(vp, index, inum, offset, notary, message);
	      break;
	    }
	  }
	  if (dcp->name == NULL)
	    fprintf(stderr, "%s Unknown diagnostic type ignored: %s\n",
		    timestring(), type);
	  return;
	}

	/* Now (*diagnostic == '#') */

	if (strncmp(diagnostic,"#hungry",7)==0) {
	  /* This is an "actor model" behaviour,
	     where actor tells, when it needs a new
	     job to be fed to it. */
	  if (proc->tofd   >= 0) {
	    proc->hungry = 1;
	    mytime(&proc->hungertime);
	    if (proc->overfed > 0)
	      /* It was overfed, decrement that counter first.. */
	      proc->overfed -= 1;
	    if (!proc->overfed) {
	      ++hungry_childs;
	      /* Unless it is still overfed,
		 Pick next, and feed it! */
	      pick_next_vertex(proc, 1, 0);
	      /* While we have a thread, and things to feed.. */
	      while (!proc->fed && proc->thread) {
		if (proc->hungry)
		  feed_child(proc);
		if (proc->fed)
		  proc->overfed += 1;
		else
		  break; /* Huh! Feed/flush failure! */
		/* See if we should, and can feed more! */
		if (proc->thg == NULL ||
		    proc->pid == 0    ||
		    proc->thread == NULL)
		  break;	/* No new active threads/vertices/proc.. */
		if (proc->overfed >= proc->thg->ce.overfeed)
		  break;	/* if the limit is zero, don't overfeed ever.*/
		/* Ok, increment the counter, and loop back.. */
		proc->hungry = 1; /* Simulate hunger.. */
		pick_next_vertex(proc, 1, 0);
		/* If it got next,  ``proc->fed'' is now zero.. */
	      }
	      flush_child(proc);
	      proc->hungry = 0; /* ... satiated.. */
	    } else {
	      if (verbose)
		printf("... child pid %d overfed=%d\n",
		       proc->pid, proc->overfed);
	    }
	  } else
	    if (verbose)
	      printf("'#hungry' from child without forward-channel\n");
	  return;
	} /* end of '#hungry' processing */

	if (strncmp(diagnostic,"#resync",7)==0) {
	  /* The transporter has noticed that the scheduler
	     gave it a job spec, which does not have anything
	     left for processing, it is time for the scheduler
	     to recheck the job file. */
	  char *p, *s = diagnostic + 7;
	  while (*s == ' ' || *s == '\t') ++s;
	  p = strchr(s,'\n');
	  if (p) *p = 0; /* newline AFTER filename */
	  if (*s != 0)
	    resync_file(proc, s);
	  return;
	}

	fprintf(stderr, "%s DBGdiag: %s\n", timestring(), diagnostic);
	return;
}

/*
 * Deallocate a control file descriptor.
 */

void
unctlfile(cfp, no_unlink)
	struct ctlfile *cfp;
	int no_unlink;
{
	char	path[MAXPATHLEN+1];

	if (cfp->dirind > 0)
	  sprintf(path, "%s/%s", cfpdirname(cfp->dirind), cfp->mid);
	else
	  strcpy(path, cfp->mid);

	if (!no_unlink && !procselect) {
	  reporterrs(cfp);

	  if (do_syslog) {
	    char taspid[30],fnam[30];
	    sprintf(fnam,"%lu",(long)cfp->id);
	    taspoolid(taspid, sizeof(taspid), cfp->ctime, fnam);
	    zsyslog((LOG_INFO, "%s: complete (total %d recepients, %d failed)",
		     taspid, cfp->rcpnts_total, cfp->rcpnts_failed));
	  }

	  eunlink(path);
	  if (verbose)
	    printf("%s: unlink %s (mid=0x%p)", cfp->logident, path, cfp->mid);

	  if (cfp->dirind > 0)
	    sprintf(path, "../%s/%s/%s",
		    QUEUEDIR, cfpdirname(cfp->dirind), cfp->mid);
	  else
	    sprintf(path, "../%s/%s",
		    QUEUEDIR, cfp->mid);

	  eunlink(path);
	  if (verbose)
	    printf("   and %s/\n", path);

	  if (cfp->vfpfn != NULL) {
	    FILE *vfp = vfp_open(cfp);
	    if (vfp) {
	      fprintf(vfp, "scheduler done processing %s\n", cfp->mid);
	      fclose(vfp);
	    }
	  }
	} else {
#if 0
	  /* We will LOOSE this from the schedules -- add info about
	     it into the indirscanqueue -- at the tail... */
	  dq_insert(NULL, atol(cfp->mid), path, 30);
#endif
	}

	if (cfp->id != 0) {
	  struct spblk *spl;
	  spl = sp_lookup(cfp->id, spt_mesh[L_CTLFILE]);
	  if (spl != NULL)
	    sp_delete(spl, spt_mesh[L_CTLFILE]);
	}
	--global_wrkcnt;

	free_cfp_memory(cfp);
}

/* unvertex() .. the ``vp'' CAN'T be invalid.. */
void unvertex(vp, justfree, ok)
	register struct vertex *vp;
	int justfree, ok;
{
	int	i, removeme;

	if (vp->ngroup > 0)
	  return;

	if (verbose && justfree < 0)
	  fprintf(stderr,
		  "unvertex(vtx=0x%p (thr=0x%p proc=0x%p, ng=%d) ,%d,%d)\n",
		  vp,vp->thread,vp->proc,vp->ngroup,justfree,ok);

	if (vp->thread != NULL &&
	    vp->thread->vertices == vp && vp->thread->proc &&
	    vp->thread->proc->vertex == vp) {
	    /* Whoops, we are the active first on thread.. */
	  if (vp->proc == NULL)
	    vp->proc = vp->thread->proc;
	  vp->proc->vertex = vp;
	}

	if (vp->proc && vp->proc->vertex == vp) {
	  vp->proc->fed     = 1; /* Mark it fed just in case.. */
#if 0 /* No need ? Wrong place ? Propably wrong place/thing! */
	  vp->proc->overfed = 0; /* .. and clear this .. */
#endif
	  /* Pick next, but don't feed it (yet)! */
	  pick_next_vertex(vp->proc, ok, justfree);
	  if (vp->proc && vp->proc->vertex == vp){
	    /* Sigh... Lets see, if we can move the vertex
	       pointer somewhere. */

	    /* Pick the first one you can find */
	    vp->proc->vertex = vp->proc->thread->vertices;
	    if (vp->proc->vertex == vp) {
	      /* Damn! */
	      vp->proc->vertex = vp->proc->vertex->nextitem;
	    }
	    /* Ok, now the 'vertex' will either differ
	       from 'vp', or it is NULL. */
#if 0
	    fprintf(stderr,
		    "unvertex(vtx=0x%p,%d,%d) failed to pick_next_vertex() file=%s!\n",
		    vp, justfree, ok, vp->cfp->mid);
	    /* We may become called with child feeder yet unflushed;
	       shall we kill the kid ? (pick_next_vertex won't change
	       vertex then..) */
	    /* abort(); */
#endif
	  }
	}
	if (vp->thread != NULL &&
	    vp->thread->proc && vp->thread->proc->vertex == vp) {
	  /* XX: This is actually vestigal from somewhere, and
	         should not occur at all.. */
	  vp->thread->proc->vertex = NULL;
	}

	for (i = 0; i < SIZE_L; ++i) {
	  if (vp->next[i] != NULL)
	    vp->next[i]->prev[i] = vp->prev[i];
	  if (vp->prev[i] != NULL)
	    vp->prev[i]->next[i] = vp->next[i];
	  if (i == L_CTLFILE)
	    continue;
	  removeme = 0;
	  if (vp->orig[i]->link == vp)
	    if ((vp->orig[i]->link = vp->next[i]) == NULL)
	      removeme = 1;
	  if (vp->orig[i]->lastlink == vp)
	    if ((vp->orig[i]->lastlink = vp->prev[i]) == NULL)
	      removeme = 1;
	  if (removeme) {
	    vp->orig[i]->linkcnt -= 1;
	    unweb(i, vp->orig[i]);
	    vp->orig[i] = NULL;
	  }
	}

	if (vp->cfp->head == vp)
	  if ((vp->cfp->head = vp->next[L_CTLFILE]) == NULL) 
	    unctlfile(vp->cfp, justfree);

	web_disentangle(vp, ok); /* does also unthread() */

	if (vp->message != NULL) free(vp->message);
	if (vp->notary  != NULL) free(vp->notary);
	/* if (vp->sender != NULL) free(vp->sender); */ /* XX: cache !! ?? */
	free((char *)vp);
}

static struct vertex *findvertex(inum, offset, idx)
	long	inum;
	long	offset;
	int	*idx;
{
	struct spblk *spl;
	struct ctlfile *cfp;
	struct vertex *vp;
	int	i;

	/* It is NOT POSSIBLE to cache cfp, based on the inum */
	spl = sp_lookup((u_long)inum, spt_mesh[L_CTLFILE]);
	if (spl == NULL || (cfp = (struct ctlfile *)spl->data) == NULL) {
	  /* It may have been kicked into input queue */
	  if (!in_dirscanqueue(NULL,(long)inum))
	    fprintf(stderr, "%s: cannot find control file for %ld!\n",
		    progname, inum);
	  return NULL;
	}
	for (i = 0; i < cfp->nlines; ++i) {
	  if (cfp->offset[i] == offset) {
	    *idx = i;
	    break;
	  }
	}
	if (i >= cfp->nlines) {
	  fprintf(stderr,
		  "%s: unknown address offset %ld in control file %ld!\n",
		  progname, offset, inum);
	  return NULL;
	}
	for (vp = cfp->head; vp != NULL; vp = vp->next[L_CTLFILE])
	  for (i = 0; i < vp->ngroup; ++i)
	    if (vp->index[i] == *idx)
	      return vp;
	fprintf(stderr,
		"%s: multiple processing of address at %ld in control file %ld!\n",
		progname, offset, inum);
	return NULL;
}

/*
 * To implement the CF_OBSOLETES command, we need to map a message-id to
 * a control file structure, unlink the unprocessed addresses from the web,
 * and physically get rid of the message.  We also need to implement some
 * form of security here; same file ownership and error return address might
 * be a good approximation.
 */

static int ctlowner(cfp)
	struct ctlfile *cfp;
{
	char *path;
	struct stat stbuf;
	static int nope = -9;
	int rc = nope;

	if (cfp->mid == NULL)
	  abort(); /* calling-convention error! */
#ifdef USE_ALLOCA
	path = alloca(5+strlen(cfp->mid)+sizeof QUEUEDIR+8);
#else
	path = emalloc(5+strlen(cfp->mid)+sizeof QUEUEDIR+8);
#endif
	if (cfp->dirind > 0)
	  sprintf(path, "../%s/%s/%s",
		  QUEUEDIR, cfpdirname(cfp->dirind), cfp->mid);
	else
	  sprintf(path, "../%s/%s",
		  QUEUEDIR, cfp->mid);
	if (stat(path, &stbuf) == 0)
	  rc = stbuf.st_uid;
#ifndef USE_ALLOCA
	free(path);
#endif
	return rc;
}

void
deletemsg(msgid, curcfp)
	const char *msgid;
	struct ctlfile *curcfp;
{
	struct ctlfile *cfp = NULL;
	struct spblk *spl;

	/* map message id to ctl structure */
	for (spl = sp_fhead(spt_mesh[L_CTLFILE]); spl != NULL ;
	     spl = sp_fnext(spl)) {
	  cfp = (struct ctlfile *)spl->data;
	  /* XX: message-id comparison is a Hard Problem. Approximate. */
	  if (strcmp(cfp->logident, msgid) == 0)
	    break;
	}
	if (spl == NULL)
		return;
	/* security checks */
	/* XX: address comparison is also a Hard Problem... sigh */
	if ((cfp->erroraddr == NULL && curcfp->erroraddr != NULL)
	    || (cfp->erroraddr != NULL && curcfp->erroraddr == NULL)
	    || (cfp->erroraddr != curcfp->erroraddr
		&& strcmp(cfp->erroraddr, curcfp->erroraddr) != 0))
		return;
	if (ctlowner(cfp) != ctlowner(curcfp))
		return;
	/*
	 * It might be useful to return a report about what happened, but
	 * for mailing lists this is dangerous.  Let's not, until we can
	 * test for some 'return-receipt-requested' flag.
	 */

	if (do_syslog)
	  zsyslog((LOG_INFO, "%s: obsoleted by %s", cfp->mid, curcfp->mid));

	/*
	 * unvertex() will do unctlfile() on the last vertex, hence
	 * this strange way of doing the unlink.
	 */
	while (cfp->head->next[L_CTLFILE] != NULL) {
	  cfp->head->ngroup = 0;
	  unvertex(cfp->head,0,1);
	}
	cfp->head->ngroup = 0;
	unvertex(cfp->head,0,1);
}


/* Lifted from BIND res/res_debug.c */
/*
 * Return a mnemonic for a time to live
 */
char *
saytime(value, buf, shortform)
	long value;
	char *buf;
	int shortform;
{
	int secs, mins, hours, fields = 0;
	register char *p;

	p = buf;

	while (*p) ++p;
	if (value < 0) {
	  *p++ = '-'; *p = 0;
	  value = -value;
	}

	if (value == 0) {
	  if (shortform)
	    strcpy(p,"0s");
	  else
	    strcpy(p,"0 sec");
	  return buf;
	}

	secs = value % 60;
	value /= 60;
	mins = value % 60;
	value /= 60;
	hours = value % 24;
	value /= 24;

#define	PLURALIZE(x)	x, (x == 1) ? "" : "s"
	if (value) {
	  if (shortform)
	    sprintf(p, "%ldd", value);
	  else
	    sprintf(p, "%ld day%s", PLURALIZE(value));
	  ++fields;
	  while (*++p);
	}
	if (hours) {
	  if (shortform)
	    sprintf(p, "%dh", hours);
	  else {
	    if (value && p != buf)
	      *p++ = ' ';
	    sprintf(p, "%d hour%s", PLURALIZE(hours));
	  }
	  ++fields;
	  while (*++p);
	}
	if (mins && fields < 2) {
	  if (shortform)
	    sprintf(p, "%dm", mins);
	  else {
	    if ((hours || value) && p != buf)
	      *p++ = ' ';
	    sprintf(p, "%d min%s", PLURALIZE(mins));
	  }
	  while (*++p);
	}
	if (secs && fields < 2) {
	  if (shortform)
	    sprintf(p, "%ds", secs);
	  else {
	    if ((mins || hours || value) && p != buf)
	      *p++ = ' ';
	    sprintf(p, "%d sec%s", PLURALIZE(secs));
	  }
	  while (*++p);
	}
	*p = '\0';
	return buf;
}

/*
 * vtxupdate() -- delete the vertex matching our (sub)index
 */

static void vtxupdate(vp, index, ok)
	struct vertex *vp;
	int index, ok;
{
	int i;

	for (i = 0; i < vp->ngroup; ++i)
	  if (vp->index[i] == index) {
	    /* remove us from the vertex indices */
	    vp->ngroup -= 1;
	    /* compact the index array */
	    for (++i; i <= vp->ngroup; ++i)
	      vp->index[i-1] = vp->index[i];
	    /* if none are left, unvertex() it.. */
	    if (vp->ngroup <= 0)
	      unvertex(vp, 0, ok);
	    break;
	  }
}

static void logstat __((FILE *, struct vertex *, const char *));

static void logstat(fp,vp,reason)
	FILE *fp;
	struct vertex *vp;
	const char *reason;
{
	mytime(&now);
	fprintf(fp,"%ld %s %ld %ld %s %s/%s\n",
		(long)vp->cfp->ctime, vp->cfp->mid,
		(long)(vp->cfp->envctime - vp->cfp->ctime),
		(long)(now - vp->cfp->envctime), reason,
		vp->orig[L_CHANNEL]->name,vp->orig[L_HOST]->name);
	fflush(fp);
}


static void expaux(vp, index, buf)
	struct vertex *vp;
	int index;
	const char *buf;
{
	int i;

	/* Report expiry */
	for (i = 0 ; i < vp->ngroup; ++i)
	  if (vp->index[i] == index) {
	    msgerror(vp, vp->cfp->offset[index], buf);
	    break;
	  }

	/* Log something into the scheduler log */
	fprintf(stderr, "%s %s: %s/%s from %s %s\n", timestring(), progname,
		vp->orig[L_CHANNEL]->name, vp->orig[L_HOST]->name,
		vp->cfp->erroraddr == NULL ? "?" : vp->cfp->erroraddr, buf);

	if (statuslog)
	  logstat(statuslog,vp,"expire");

	/* Delete this vertex from scheduling datasets */
	vtxupdate(vp, index, 0);
}

void
expire(vp, index)
	struct vertex *vp;
	int index;
{
	int i;
	char *emsg, buf[BUFSIZ];
	const char *fmt = "\r%s, problem was:\r%s";

	if (vp->notary == NULL) {
	  /* addres / action / status / diagnostic / wtt */
	  sprintf(buf,"%s\001%s\001%s\001%s",
		  "\003", /* XX: recipient address! XX: MAGIC INFO! */
		  "failed",
		  "5.4.7 (unspecified timeout failure)",
		  "smtp; 500 (Expired after ");
	  saytime((u_long)(vp->ce_expiry - vp->cfp->ctime), buf, 0);
	  strcat(buf,")\001");
	  vp->notary = strsave(buf);
	}

	strcpy(buf, "expired after ");
	saytime((u_long)(vp->ce_expiry - vp->cfp->ctime), buf, 0);

	if (vp->message != NULL && *(vp->message) != '\0') {
	  emsg = emalloc(strlen(buf) + strlen(vp->message) + strlen(fmt));
	  sprintf(emsg, fmt, buf, vp->message);
	} else
	  emsg = buf;

	if (index < 0) {
	  /* Expire from the LAST index to the first, this way
	     we won't do the mistake of referring indixes after
	     they have been deleted.. */
	  for (i = vp->ngroup -1; i >= 0; --i)
	    expaux(vp, vp->index[i], emsg);
	} else
	  expaux(vp, index, emsg);

	if (emsg != buf)
	  free(emsg);
}


/*ARGSUSED*/
static int u_ok(vp, index, inum, offset, notary, message)
	struct vertex *vp;
	long	index, inum, offset;
	const char	*notary;
	const char	*message;
{
	if (verbose)
	  fprintf(stderr,"%s: %ld/%ld/%s/ok %s\n", vp->cfp->logident, inum,
		  offset, notary, message ? message : "-");
#if 0
	if (vp->cfp->vfp != NULL && vp->cfp->contents != NULL) {
	  fseek(vp->cfp->vfp, (off_t)0, SEEK_END);
	  fprintf(vp->cfp->vfp, "%s: ok %s\n",
		  vp->cfp->contents + offset + 2 + _CFTAG_RCPTPIDSIZE,
		  message == NULL ? "(sent)" : message);
	}
#endif
	if (vp->notaryflg & NOT_SUCCESS) {
	  /* Save/process info regarding delivery receipts! */
	  msgerror(vp, offset, message);
	}

	if (statuslog)
	  logstat(statuslog,vp,"ok");

	/* Delete this vertex from scheduling datasets */
	vtxupdate(vp, index, 1);
	return 1;
}

/*ARGSUSED*/
static int u_ok2(vp, index, inum, offset, notary, message)
	struct vertex *vp;
	long	index, inum, offset;
	const char	*notary;
	const char	*message;
{
	if (vp->notaryflg & NOT_SUCCESS) {
	  vp->cfp->haderror = 1; /* The transporter logged it for us! */
	}
	if (verbose)
	  fprintf(stderr,"%s: %ld/%ld/%s/ok2 %s\n", vp->cfp->logident, inum,
		  offset, notary, message ? message : "-");
#if 0
	if (vp->cfp->vfp != NULL && vp->cfp->contents != NULL) {
	  fseek(vp->cfp->vfp, (off_t)0, SEEK_END);
	  fprintf(vp->cfp->vfp, "%s: ok %s\n",
		  vp->cfp->contents + offset + 2 + _CFTAG_RCPTPIDSIZE,
		  message == NULL ? "(sent)" : message);
	}
#endif
	if (statuslog)
	  logstat(statuslog,vp,"ok2");

	/* Delete this vertex from scheduling datasets */
	vtxupdate(vp, index, 1);
	return 1;
}

/*ARGSUSED*/
static int u_ok3(vp, index, inum, offset, notary, message)
	struct vertex *vp;
	long	index, inum, offset;
	const char	*notary;
	const char	*message;
{
	/* Success, but the transporter was able to relay the DSN info
	   to another system, thus no diagnostics here! */
	if (verbose)
	  fprintf(stderr,"%s: %ld/%ld/%s/ok3 %s\n", vp->cfp->logident, inum,
		  offset, notary, message ? message : "-");
#if 0
	if (vp->cfp->vfp != NULL && vp->cfp->contents != NULL) {
	  fseek(vp->cfp->vfp, (off_t)0, SEEK_END);
	  fprintf(vp->cfp->vfp, "%s: ok %s\n",
		  vp->cfp->contents + offset + 2 + _CFTAG_RCPTPIDSIZE,
		  message == NULL ? "(sent)" : message);
	}
#endif
	if (statuslog)
	  logstat(statuslog,vp,"ok3");

	/* Delete this vertex from scheduling datasets */
	vtxupdate(vp, index, 1);
	return 1;
}


static int u_deferred(vp, index, inum, offset, notary, message)
	struct vertex *vp;
	long	index, inum, offset;
	const char	*notary;
	const char	*message;
{
	/* fprintf(stderr,"%s: %ld/%ld/%s/deferred %s\n", vp->cfp->logident,
	   inum, offset, notary, message ? message : "-"); */
	if (message != NULL) {
	  if (vp->message != NULL)
	    free(vp->message);
	  /* fprintf(stderr, "add message '%s' to node %s/%s\n",
	     message, vp->orig[L_CHANNEL]->name,
	     vp->orig[L_HOST]->name); */
	  vp->message = strsave(message);
	}
#if 0
	if (vp->cfp->vfp != NULL && vp->cfp->contents != NULL) {
	  fseek(vp->cfp->vfp, (off_t)0, SEEK_END);
	  fprintf(vp->cfp->vfp, "%s: deferred %s\n",
		  vp->cfp->contents + offset + 2 + _CFTAG_RCPTPIDSIZE,
		  message == NULL ? "(unknown)" : message);
	}
#endif
	/*
	 * Even though we may get several of these per web entry,
	 * the heuristic in reschedule() to ignore the request if
	 * the time is already in the future should help out.
	 */
	reschedule(vp, -1, index);
	return 1;
}

static int u_error(vp, index, inum, offset, notary, message)
	struct vertex  *vp;
	long		index, inum, offset;
	const char	*notary;
	const char	*message;
{
	if (message == NULL)
	  message = "(unknown)";
	fprintf(stderr,
		"%s %s: %ld/%ld/%s/error %s\n", timestring(),
		vp->thgrp->ce.command, inum, offset, notary, message);

	if (!procselect && vp->notaryflg & NOT_FAILURE)
	  msgerror(vp, offset, message);
#if 0
	if (vp->cfp->vfp != NULL && vp->cfp->contents != NULL) {
	  fseek(vp->cfp->vfp, (off_t)0, SEEK_END);
	  fprintf(vp->cfp->vfp, "%s: error %s\n",
		  vp->cfp->contents + offset + 2 + _CFTAG_RCPTPIDSIZE,
		  message);
	}
#endif
	if (statuslog)
	  logstat(statuslog,vp,"error");

	/* Delete this vertex from scheduling datasets */
	vtxupdate(vp, index, 0);
	return 1;
}

/* A variant where the TRANSPORT AGENT has logged the report into
   the file! */
static int u_error2(vp, index, inum, offset, notary, message)
	struct vertex *vp;
	long	index, inum, offset;
	const char	*notary;
	const char	*message;
{
	if (message == NULL)
	  message = "(unknown)";
	fprintf(stderr,
		"%s %s: %ld/%ld/%s/error2 %s\n", timestring(),
		vp->thgrp->ce.command, inum, offset, notary, message);

	/* We don't need to log it! */
	vp->cfp->haderror = 1; /* Mark it into the incore dataset */
#if 0
	if (vp->cfp->vfp != NULL && vp->cfp->contents != NULL) {
	  fseek(vp->cfp->vfp, (off_t)0, SEEK_END);
	  fprintf(vp->cfp->vfp, "%s: error %s\n",
		  vp->cfp->contents + offset + 2 + _CFTAG_RCPTPIDSIZE,
		  message);
	}
#endif
	if (statuslog)
	  logstat(statuslog,vp,"error");

	/* Delete this vertex from scheduling datasets */
	vtxupdate(vp, index, 0);
	return 1;
}


/*
 * specify relative (w/ leading +) or absolute (w/o leading +) retry time.
 */

static int u_retryat(vp, index, inum, offset, notary, message)
	struct vertex *vp;
	long	index, inum, offset;
	const char	*notary;
	const char	*message;
{
	time_t	retrytime;
	long    dtvalue;
	const char * cp;

	if (*message == '+')
	  ++message;
	dtvalue = 0;
	sscanf(message, "%ld", &dtvalue);
	for (cp = message; *cp != '\0' && isdigit(*cp); ++cp)
	  continue;
	if (*cp != '\0')
	  ++cp;
	retrytime = dtvalue;
	message = cp;
	if (*message == '\0')
	  message = NULL;
	
	if (message != NULL) {
	  if (vp->message != NULL)
	    free(vp->message);
	  /* fprintf(stderr, "add message '%s' to node %s/%s\n",
	     message, vp->orig[L_CHANNEL]->name,
	     vp->orig[L_HOST]->name); */
	  vp->message = strsave(message);
	}
#if 0
	if (vp->cfp->vfp != NULL && vp->cfp->contents != NULL) {
	  fseek(vp->cfp->vfp, (off_t)0, SEEK_END);
	  fprintf(vp->cfp->vfp, "%s: retryat %d %s\n",
		  vp->cfp->contents + offset + 2 + _CFTAG_RCPTPIDSIZE,
		  (int)retrytime, message == NULL ? "(unknown)" : message);
	}
#endif
	/*
	 * Even though we may get several of these per web entry,
	 * the heuristic in reschedule() to ignore the request if
	 * the time is already in the future should help out.
	 */

	/* ``vp'' might become expired by  thread_reschedule() .. */
	if (vp->proc && vp->proc->vertex == vp)
	  /* Pick next, but don't feed it (yet)! */
	  pick_next_vertex(vp->proc, 0, 0);

	thread_reschedule(vp->thread, retrytime, index);

	return 1;
}
