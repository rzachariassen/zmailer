/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *
 */
/*
 *	Lots of modifications (new guts, more or less..) by
 *	Matti Aarnio <mea@nic.funet.fi>  (copyright) 1992-1999
 */

#include "hostenv.h"
#include <sfio.h>
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

#define DARGS __((struct procinfo *, struct vertex *, long, long, long, const char*, const char*))

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
	  ta_hungry(proc);
	  return;
	}

	if (*diagnostic == '#') {
	  /* Now (*diagnostic == '#') */

	  if (strncmp(diagnostic,"#hungry",7)==0) {
	    ta_hungry(proc);
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

	  sfprintf(sfstderr, "%s DBGdiag: %s\n", timestring(), diagnostic);
	  return;
	}

	/* Not debug diagnostic message */

	inum = atol(diagnostic);
	if ((cp = strchr(diagnostic, '/')) == NULL) {
	  sfprintf(sfstderr, "%s Misformed diagnostic1: %s\n",
		   timestring(), diagnostic);
	  return;
	}
	offset = atol(++cp);
	if ((cp = strchr(cp, '\t')) == NULL) {
	  sfprintf(sfstderr, "%s Misformed diagnostic2: %s\n",
		   timestring(), diagnostic);
	  return;
	}
	notary = ++cp;
	if ((cp = strchr(cp, '\t')) == NULL) {
	  sfprintf(sfstderr, "%s Misformed diagnostic3: %s\n",
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
	  sfprintf(sfstdout,"diagnostic: %ld/%ld\t%s\t%s\n",
		   inum, offset, notary, type);

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
	    (dcp->fcn)(proc, vp, index, inum, offset, notary, message);
	    break;
	  }
	}

	if (dcp->name == NULL)
	  sfprintf(sfstderr, "%s Unknown diagnostic type ignored: %s\n",
		   timestring(), type);

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
	    char taspid[30];
	    taspoolid(taspid, cfp->mtime, (long)cfp->id);
	    zsyslog((LOG_INFO, "%s: complete (total %d recepients, %d failed)",
		     taspid, cfp->rcpnts_total, cfp->rcpnts_failed));
	  }
	  ++MIBMtaEntry->mtaTransmittedMessagesSc;

	  eunlink(path);
	  if (verbose)
	    sfprintf(sfstdout,"%s: unlink %s (mid=%p)",
		     cfp->logident, path, cfp->mid);

	  if (cfp->dirind > 0)
	    sprintf(path, "../%s/%s/%s",
		    QUEUEDIR, cfpdirname(cfp->dirind), cfp->mid);
	  else
	    sprintf(path, "../%s/%s",
		    QUEUEDIR, cfp->mid);

	  eunlink(path);
	  if (verbose)
	    sfprintf(sfstdout, "   and %s/\n", path);

	  if (cfp->vfpfn != NULL) {
	    Sfio_t *vfp = vfp_open(cfp);
	    if (vfp) {
	      sfprintf(vfp, "scheduler done processing %s\n", cfp->mid);
	      sfclose(vfp);
	    }
	  }
	} else {
#if 1
	  /* We will LOOSE this from the schedules -- add info about
	     it into the indirscanqueue -- at the tail... */
	  dq_insert(NULL, cfp->id, path, 30);
#endif
	}

	if (cfp->id != 0) {
	  struct spblk *spl;
	  spl = sp_lookup(cfp->id, spt_mesh[L_CTLFILE]);
	  if (spl != NULL)
	    sp_delete(spl, spt_mesh[L_CTLFILE]);
	}

	--global_wrkcnt;
	--MIBMtaEntry->mtaStoredMessages;
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

	if (verbose)
	  sfprintf(sfstderr,
		   "unvertex(vtx=%p (thr=%p proc=%p, ng=%d) ,%d,%d)\n",
		   vp, vp->thread, vp->proc, vp->ngroup, justfree, ok);

	if (vp->proc) {
	  /* Somebody here, move it elsewere! */
	  pick_next_vertex(vp->proc, vp);
	  vp->proc = NULL;
	}

	for (i = 0; i < SIZE_L; ++i) {

	  if (vp->next[i])
	    vp->next[i]->prev[i] = vp->prev[i];
	  if (vp->prev[i])
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

	if (vp->cfp->head == vp) {
	  vp->cfp->head = vp->next[L_CTLFILE];
	  if (vp->cfp->head == NULL && justfree >= 0)
	    unctlfile(vp->cfp, justfree);
	}

	web_detangle(vp, ok); /* does also unthread() */

	if (vp->message != NULL) free(vp->message);
	if (vp->notary  != NULL) free(vp->notary);
	/* if (vp->sender != NULL) free(vp->sender); */ /* XX: cache !! ?? */
	free((char *)vp);

	return;
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
	    sfprintf(sfstderr, "%s: cannot find control file for %ld!\n",
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
	  sfprintf(sfstderr,
		   "%s: unknown address offset %ld in control file %ld!\n",
		   progname, offset, inum);
	  return NULL;
	}
	for (vp = cfp->head; vp != NULL; vp = vp->next[L_CTLFILE])
	  for (i = 0; i < vp->ngroup; ++i)
	    if (vp->index[i] == *idx)
	      return vp;
	sfprintf(sfstderr,
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
	path = (char*)alloca(5+strlen(cfp->mid)+sizeof QUEUEDIR+8);
#else
	path = (char*)emalloc(5+strlen(cfp->mid)+sizeof QUEUEDIR+8);
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
	  MIBMtaEntry->mtaStoredRecipients -= cfp->head->ngroup;
	  cfp->head->ngroup = 0;
	  unvertex(cfp->head,0,1);
	}
	MIBMtaEntry->mtaStoredRecipients -= cfp->head->ngroup;
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

	    MIBMtaEntry->mtaStoredRecipients -= 1;

	    /* compact the index array */
	    for (++i; i <= vp->ngroup; ++i)
	      vp->index[i-1] = vp->index[i];
	    /* if none are left, unvertex() it.. */
	    if (vp->ngroup <= 0)
	      unvertex(vp, 0, ok);
	    break;
	  }
}

static void logstat __((struct vertex *, const char *));

static void logstat(vp,reason)
	struct vertex *vp;
	const char *reason;
{
	if (!statuslog) return;

	mytime(&now);
	sfprintf(statuslog, "%ld %s %ld %ld %s %s/%s\n",
		 (long)vp->cfp->mtime, vp->cfp->mid,
		 (long)(vp->cfp->envctime - vp->cfp->mtime),
		 (long)(now - vp->cfp->envctime), reason,
		 vp->orig[L_CHANNEL]->name,vp->orig[L_HOST]->name);
	sfsync(statuslog);
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
	sfprintf(sfstderr, "%s %s: %s/%s from %s %s\n", timestring(), progname,
		 vp->orig[L_CHANNEL]->name, vp->orig[L_HOST]->name,
		 vp->cfp->erroraddr == NULL ? "?" : vp->cfp->erroraddr, buf);

	logstat(vp,"expire");

	/* Delete this vertex from scheduling datasets */
	vtxupdate(vp, index, 0);
	++MIBMtaEntry->mtaTransmittedRecipientsSc;
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
	  saytime((u_long)(vp->ce_expiry - vp->cfp->mtime), buf, 0);
	  strcat(buf,")\001");
	  vp->notary = strsave(buf);
	}

	strcpy(buf, "expired after ");
	saytime((u_long)(vp->ce_expiry - vp->cfp->mtime), buf, 0);

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
static int u_ok(proc, vp, index, inum, offset, notary, message)
     struct procinfo *proc;
     struct vertex *vp;
     long   index, inum, offset;
     const char	*notary;
     const char	*message;
{
	if (verbose)
	  sfprintf(sfstderr,"%s: %ld/%ld/%s/ok %s\n", vp->cfp->logident, inum,
		   offset, notary, message ? message : "-");
#if 0
	if (vp->cfp->contents != NULL) {
	  Sfio_t *vfp = vfp_open(vp->cfp);
	  if (vfp) {
	    sfprintf(vfp, "%s: ok %s\n",
		     vp->cfp->contents + offset + 2 + _CFTAG_RCPTPIDSIZE,
		     message == NULL ? "(sent)" : message);
	    sfclose(vfp);
	  }
	}
#endif
	if (vp->notaryflg & NOT_SUCCESS) {
	  /* Save/process info regarding delivery receipts! */
	  msgerror(vp, offset, message);
	}

	logstat(vp,"ok");

	/* Delete this vertex from scheduling datasets */
	vtxupdate(vp, index, 1);
	++MIBMtaEntry->mtaTransmittedRecipientsSc;
	return 1;
}

/*ARGSUSED*/
static int u_ok2(proc, vp, index, inum, offset, notary, message)
     struct procinfo *proc;
     struct vertex *vp;
     long   index, inum, offset;
     const char	*notary;
     const char	*message;
{
	if (vp->notaryflg & NOT_SUCCESS) {
	  vp->cfp->haderror = 1; /* The transporter logged it for us! */
	}
	if (verbose)
	  sfprintf(sfstderr,"%s: %ld/%ld/%s/ok2 %s\n", vp->cfp->logident, inum,
		   offset, notary, message ? message : "-");
#if 0
	if (vp->cfp->contents != NULL) {
	  Sfio_t *vfp = vfp_open(vp->cfp);
	  if (vfp) {
	    sfprintf(vfp, "%s: ok2 %s\n",
		     vp->cfp->contents + offset + 2 + _CFTAG_RCPTPIDSIZE,
		     message == NULL ? "(sent)" : message);
	    sfclose(vfp);
	  }
	}
#endif
	logstat(vp,"ok2");

	/* Delete this vertex from scheduling datasets */
	vtxupdate(vp, index, 1);
	++MIBMtaEntry->mtaTransmittedRecipientsSc;
	return 1;
}

/*ARGSUSED*/
static int u_ok3(proc, vp, index, inum, offset, notary, message)
     struct procinfo *proc;
     struct vertex *vp;
     long   index, inum, offset;
     const char	*notary;
     const char	*message;
{
	/* Success, but the transporter was able to relay the DSN info
	   to another system, thus no diagnostics here! */
	if (verbose)
	  sfprintf(sfstderr,"%s: %ld/%ld/%s/ok3 %s\n", vp->cfp->logident, inum,
		   offset, notary, message ? message : "-");
#if 0
	if (vp->cfp->contents != NULL) {
	  Sfio_t *vfp = vfp_open(vp->cfp);
	  if (vfp) {
	    sfprintf(vfp, "%s: ok3 %s\n",
		     vp->cfp->contents + offset + 2 + _CFTAG_RCPTPIDSIZE,
		     message == NULL ? "(sent)" : message);
	    sfclose(vfp);
	  }
	}
#endif
	logstat(vp,"ok3");

	/* Delete this vertex from scheduling datasets */
	vtxupdate(vp, index, 1);
	++MIBMtaEntry->mtaTransmittedRecipientsSc;
	return 1;
}


static int u_deferred(proc, vp, index, inum, offset, notary, message)
     struct procinfo *proc;
     struct vertex *vp;
     long   index, inum, offset;
     const char	*notary;
     const char	*message;
{
	/* sfprintf(sfstderr,"%s: %ld/%ld/%s/deferred %s\n", vp->cfp->logident,
	   inum, offset, notary, message ? message : "-"); */
	if (message != NULL) {
	  if (vp->message != NULL)
	    free(vp->message);
	  /* sfprintf(sfstderr, "add message '%s' to node %s/%s\n",
	     message, vp->orig[L_CHANNEL]->name,
	     vp->orig[L_HOST]->name); */
	  vp->message = strsave(message);
	}
#if 0
	if (vp->cfp->contents != NULL) {
	  Sfio_t *vfp = vfp_open(vp->cfp);
	  if (vfp) {
	    sfprintf(vfp, "%s: deferred %s\n",
		     vp->cfp->contents + offset + 2 + _CFTAG_RCPTPIDSIZE,
		     message == NULL ? "(sent)" : message);
	    sfclose(vfp);
	  }
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

static int u_error(proc, vp, index, inum, offset, notary, message)
     struct procinfo *proc;
     struct vertex *vp;
     long   index, inum, offset;
     const char	*notary;
     const char	*message;
{
	if (message == NULL)
	  message = "(unknown)";
	sfprintf(sfstderr,
		 "%s %s: %ld/%ld/%s/error %s\n", timestring(),
		 vp->thgrp->ce.command, inum, offset, notary, message);

	if (!procselect && vp->notaryflg & NOT_FAILURE)
	  msgerror(vp, offset, message);
#if 0
	if (vp->cfp->contents != NULL) {
	  Sfio_t *vfp = vfp_open(vp->cfp);
	  if (vfp) {
	    sfprintf(vfp, "%s: error %s\n",
		     vp->cfp->contents + offset + 2 + _CFTAG_RCPTPIDSIZE,
		     message == NULL ? "(sent)" : message);
	    sfclose(vfp);
	  }
	}
#endif
	logstat(vp,"error");

	/* Delete this vertex from scheduling datasets */
	vtxupdate(vp, index, 0);
	++MIBMtaEntry->mtaTransmittedRecipientsSc;
	return 1;
}

/* A variant where the TRANSPORT AGENT has logged the report into
   the file! */
static int u_error2(proc, vp, index, inum, offset, notary, message)
     struct procinfo *proc;
     struct vertex *vp;
     long   index, inum, offset;
     const char	*notary;
     const char	*message;
{
	if (message == NULL)
	  message = "(unknown)";
	sfprintf(sfstderr,
		"%s %s: %ld/%ld/%s/error2 %s\n", timestring(),
		vp->thgrp->ce.command, inum, offset, notary, message);

	/* We don't need to log it! */
	vp->cfp->haderror = 1; /* Mark it into the incore dataset */
#if 0
	if (vp->cfp->contents != NULL) {
	  Sfio_t *vfp = vfp_open(vp->cfp);
	  if (vfp) {
	    sfprintf(vfp, "%s: error2 %s\n",
		     vp->cfp->contents + offset + 2 + _CFTAG_RCPTPIDSIZE,
		     message == NULL ? "(sent)" : message);
	    sfclose(vfp);
	  }
	}
#endif
	logstat(vp,"error");

	/* Delete this vertex from scheduling datasets */
	vtxupdate(vp, index, 0);
	++MIBMtaEntry->mtaTransmittedRecipientsSc;
	return 1;
}


/*
 * specify relative (w/ leading +) or absolute (w/o leading +) retry time.
 */

static int u_retryat(proc, vp, index, inum, offset, notary, message)
     struct procinfo *proc;
     struct vertex *vp;
     long   index, inum, offset;
     const char	*notary;
     const char	*message;
{
	time_t	retrytime;
	long    dtvalue;
	const char * cp;

	/* If a message gets a "retryat" signal, kick this thread at
	   next  "#hungry"  into FINISHING state */

	if (verbose)
	  sfprintf(sfstdout,
		   "RETRYAT: proc=%p (S=%d OF=%d tofd=%d) vp=%p[%d] message='%s'\n",
		   proc, (int)proc->state, proc->overfed, proc->tofd, vp, index, message);

	if ((proc->state   == CFSTATE_LARVA) &&
	    (proc->overfed == 1) &&
	    (proc->tofd    >= 0))
	  proc->state = CFSTATE_FINISHING;
	if ((proc->state   == CFSTATE_STUFFING) &&
	    (proc->tofd    >= 0))
	  proc->state = CFSTATE_FINISHING;


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
	  /* sfprintf(sfstderr, "add message '%s' to node %s/%s\n",
	     message, vp->orig[L_CHANNEL]->name,
	     vp->orig[L_HOST]->name); */
	  vp->message = strsave(message);
	}
#if 0
	if (vp->cfp->contents != NULL) {
	  Sfio_t *vfp = vfp_open(vp->cfp);
	  if (vfp) {
	    sfprintf(vfp, "%s: retryat %d %s\n",
		     vp->cfp->contents + offset + 2 + _CFTAG_RCPTPIDSIZE,
		     (int)retrytime, message == NULL ? "(unknown)" : message);
	    sfclose(vfp);
	  }
	}
#endif
	/*
	 * Even though we may get several of these per web entry,
	 * the heuristic in reschedule() to ignore the request if
	 * the time is already in the future should help out.
	 */
#if 0
	/* ``vp'' might become expired by  thread_reschedule() .. */
	if (vp->proc) {
	  /* Pick next, but don't feed it (yet)! */
	  pick_next_vertex(vp->proc, vp);
	  vp->proc = NULL;
	}
#endif

	if (vp->thread != NULL)
	  thread_reschedule(vp->thread, retrytime, index);

	return 1;
}
