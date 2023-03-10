/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */
/*
 *	Lots of modifications (new guts, more or less..) by
 *	Matti Aarnio <mea@nic.funet.fi>  (copyright) 1992-2003
 *
 *	We produce RFC 1894 format reports with everything it contains.
 */

#include "hostenv.h"
#include <sfio.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "mail.h"
#include "scheduler.h"
#include "zsyslog.h"
#include "ta.h"

#include "prototypes.h"
#include "libz.h"

extern char *rfc822date __((time_t *));

#ifndef strnsave /* unless it is a debugging macro.. */
extern char *strnsave();
#endif
extern int errno;

int store_error_on_error;

extern int default_full_content; /* at conf.c */

/*
 * There has to be some way of collecting the error messages produced during
 * delivery, and this is it. Each message is appended to the control file.
 * Just before the control file is to be unlinked (or at other times by
 * external programs), we check to see if we had any diagnostic messages.
 * If so, we need to submit a message to the router using the standard
 * routines. This scheme is ugly in that it modifies the control file rather
 * drastically (at least its forced-appends), but elegant in most every other
 * respect (knock wood).
 */

typedef enum { ACTSET_DELIVERED = 0, ACTSET_FAILED = 1,
	       ACTSET_RELAYED   = 2, ACTSET_DELAYED = 3,
	       ACTSET_EXPANDED  = 4, ACTSET_NONE = 5 } ACTSETENUM;

struct not {
	char	    *not;
	const char  *message;
	const char  *orcpt;
	const char  *inrcpt;
	const char  *notify;
	int          notifyflgs;
	char	    *rcpntp;
	time_t       tstamp;
	ACTSETENUM   thisaction;
};

static void decodeXtext __((Sfio_t *, const char *));
static void
decodeXtext(fp,xtext)
     Sfio_t *fp;
     const char *xtext;
{
	for (;*xtext;++xtext) {
	  if (*xtext == '+') {
	    int c = '?';
	    sscanf(xtext+1,"%02X",&c);
	    sfputc(fp,c);
	    if (*xtext) ++xtext;
	    if (*xtext) ++xtext;
	  } else
	    sfputc(fp,*xtext);
	}
}

static void scnotaryreport __((Sfio_t *, struct not *, int *, int, int));

static void	/* There is notaryreport() on transporters also.. */
scnotaryreport(errfp,notary,haserrsp,notifyrespectflg,headstyle)
	Sfio_t *errfp;
	struct not *notary;
	int *haserrsp;
	int notifyrespectflg;
	int headstyle;
{
	char *rcpt, *action, *status, *diagstr, *wtt;
	char *taid;
	char *rcpt_end, *action_end, *status_end, *diagstr_end, *wtt_end, *taid_end;
	char *cp, *prespace, *postspace;
	const char *typetag;

	static char const *type_rfc   = "RFC822";
	static char const *type_local = "X-LOCAL";

	/* NOTARY: addres / action / status / diagstr / wtt */
	/* NOTARY: addres / action / diagstr */

	if (notary == NULL) {
	  return; /* XX: ?? call into here should not happen.. */
	}

	if ((notary->notifyflgs & NOT_NEVER) && (notifyrespectflg >= 0))
	  return; /* We ignore this recipient, because so has been
		     asked, and this is not a double-fault... */

	rcpt     = notary->not;
	if (*rcpt == 0)
	  return;	/* XX: ?? eh, well.. we should not be called.. */

	cp     = strchr(rcpt,'\001');
	rcpt_end = cp;
	*cp++  = 0;
	action = cp;
	cp     = strchr(action,'\001');
	action_end = cp;
	*cp++  = 0;
	status = cp;
	cp     = strchr(status,'\001');
	diagstr = cp;
	if (cp == NULL) {
	  diagstr = status;
	  status = NULL;
	  wtt    = NULL;
	  diagstr_end = NULL;
	  status_end = NULL;
	  wtt_end = NULL;
	} else {
	  status_end = cp;
	  *cp++  = 0;
	  diagstr = cp;
	  cp    = strchr(diagstr,'\001');
	  diagstr_end = cp;
	  if (cp) { *cp++ = 0; }
	  wtt = cp;
	  if (cp)  cp   = strchr(cp,'\001');
	  wtt_end = cp;
	  if (cp) { *cp++ = 0; }
	}
	taid = cp;
	if (taid) {
	  cp = strchr(cp+1, '\001'); /* Chop it.. */
	  taid_end = cp;
	  if (cp) { *cp++ = 0; }
	}

	if (*rcpt == '\003' /* XX: MAGIC! */) {
	  /* Tough, scheduler internal expiry didn't know our target address!
	     Lets scan it from  rcpntp .. We can mush the string pointed
	     by the rcpntp.. */
	  char *s = notary->rcpntp;
	  char *p;
	  /* Channel name */
	  s = skip821address(s);
	  while (*s && (*s == ' ' || *s == '\t')) ++s;
	  /* "Host" component */
	  s = skip821address(s);
	  while (*s && (*s == ' ' || *s == '\t')) ++s;
	  /* "User" component */
	  p = skip821address(s);
	  *p = 0; /* Either it points to a NIL, or to a white-space */
	  rcpt = s;
	}

	prespace = headstyle ? "  " : "";
	postspace = headstyle ? "\n      " : " ";
	if (strchr(rcpt,'@') != NULL) {
	  typetag = type_rfc;
	  if (strncmp(rcpt,"ns:",3)==0) /* 'hold'-channel stuff */
	    typetag = type_local;
	} else
	  typetag = type_local;
	if (notary->orcpt) {
	  sfprintf(errfp, "%sOriginal Recipient:%s", prespace, postspace);
	  decodeXtext(errfp,notary->orcpt);
	  sfputc(errfp,'\n');
	}
	sfprintf(errfp, "%sFinal Recipient:%s%s;%s\n", prespace, postspace, typetag, rcpt);
	if (headstyle)
	  sfprintf(errfp, "%sAction:%s%s\n", prespace, postspace, action);
	if (status) {
	  if (*status == '4' || *status == '5')
	    *haserrsp = 1;
	  sfprintf(errfp, "%sStatus:%s%s\n", prespace, postspace, status);
	}
	if (wtt && wtt[0] != 0) {
	  sfprintf(errfp, "%sRemote-MTA:%s%s\n", prespace, postspace, wtt);
	}
	if (notary->tstamp != 0) {
	  sfprintf(errfp, "%sLast-Attempt-Date:%s%s", prespace, postspace, rfc822date(&notary->tstamp));
	}
	if (taid && headstyle)
	  sfprintf(errfp, "%sX-ZTAID:%s%s\n", prespace, postspace, taid);
	sfprintf(errfp, "%sDiagnostic-Code:%s%s\n\n", diagstr);

	if (rcpt_end) *rcpt_end = '\001';
	if (action_end) *action_end = '\001';
	if (status_end) *status_end = '\001';
	if (diagstr_end) *diagstr_end = '\001';
	if (wtt_end)  *wtt_end  = '\001';
	if (taid_end) *taid_end = '\001';
}


/* deposit the error message */

void
msgerror(vp, offset, message)
	struct vertex *vp;
	long offset;
	const char *message;
{
	Sfio_t *fp;
	const char *notary = "";
	char path[410];

	if (vp->notary) notary = vp->notary;

	sprintf(path, "%s%.400s", cfpdirname(vp->cfp->dirind), vp->cfp->mid);

	/* exclusive access required, but we're the only scheduler... */
	fp = sfopen(NULL, path, "a");
	if (fp == NULL) {

	  timed_log_reinit();

	  sfprintf(sfstderr,
		   "Cannot open control file %s to deposit", vp->cfp->mid);
	  sfprintf(sfstderr,
		   " error message for offset %ld:\n", offset);
	  sfprintf(sfstderr, "\t%s\n", message);
	  return;
	}
	vp->cfp->haderror = 1;
	sfprintf(fp, "%c%c%ld:%ld:%ld::%ld\t%s\t%s\n",
		 _CF_DIAGNOSTIC, _CFTAG_NORMAL, offset,
		 (long)vp->headeroffset, (long)vp->drptoffset,
		 time(NULL), notary, message);
	sfsync(fp);
#ifdef HAVE_FSYNC
	while (fsync(sffileno(fp)) < 0) {
	  if (errno == EINTR || errno == EAGAIN)
	    continue;
	  break;
	}
#endif
	sfclose(fp);
}

void printenvaddr __((Sfio_t *, const char *));
void printenvaddr(fp, addr)
     Sfio_t *fp;
     const char *addr;
{
	const char *s;

	sfprintf(fp, "todsn ORCPT=rfc822;");
	s = addr;
	for  (; *s; ++s) {
	  char c = (*s) & 0xFF;
	  if ('!' <= c && c <= '~' && c != '+' && c != '=')
	    sfputc(fp,c);
	  else
	    sfprintf(fp,"+%02X",c);
	}
	sfputc(fp,'\n');
	sfprintf(fp, "to <%s>\n", addr);
}

/* Pick recipient address from the input line.
   EXTREMELY Simple minded parsing.. */

static void pick_env_addr __((char *, Sfio_t *));
static void pick_env_addr(buf,mfp)
     char *buf;
     Sfio_t *mfp;
{
	char *s = buf;

	while (*s != 0 && *s != ' ' && *s != '\t' && *s != ':') ++s;
	if (*s != ':') return; /* BAD INPUT! */
	buf = ++s; /* We have skipped the initial header.. */

	s = strchr(buf,'\n');
	if (s) *s = 0;
	s = strchr(buf,'<');
	if (s != NULL) {
	  /*  Cc:  The Postoffice managers <postoffice> */
	  buf = ++s;
	  s = strrchr(buf,'>');
	  if (s) *s = 0;
	  else return; /* No trailing '>' ? BAD BAD! */
	  printenvaddr(mfp, buf);
	} else {
	  /*  Cc: some-address  */
	  printenvaddr(mfp, buf);
	}
}


static void writeheader __((Sfio_t *, const char *, int *, const char *, const char *, int *actionset));

static void
writeheader(errfp, eaddr, no_error_reportp, deliveryform, boundary, actionset)
     Sfio_t *errfp;
     const char *eaddr;
     int *no_error_reportp;
     const char *deliveryform;
     const char *boundary;
     int *actionset;
{
	Sfio_t *fp;
	char path[MAXPATHLEN];
	char buf[BUFSIZ];

	if (*eaddr == '|' /* Nobody's address starts with a pipe ? */ ||
	    (*eaddr == '/' &&
	     (strchr(eaddr,'@') == NULL ||
	      strchr(eaddr,'=') == NULL /*Smells of X.400*/)))
	  eaddr = "postmaster"; /* Paranoid, eh ? */
	sfprintf(errfp, "channel error\n");
	sfprintf(errfp, "errormsg\n"); /* SCHEDULER WROTE THIS! */

	if (!*no_error_reportp)
	  printenvaddr(errfp, eaddr);
	sprintf(path, "%s/%s/%s", mailshare, FORMSDIR, deliveryform);
	fp = sfopen(NULL, path, "r");
	if (fp != NULL) {
	  int inhdr = 1, hadsubj =0;
	  buf[sizeof(buf)-1] = 0;
	  while (csfgets(buf,sizeof(buf)-1,fp) >= 0) {
	    if (strncmp(buf,"HDR",3)==0) {
	      continue;
	    } else if (strncmp(buf,"ADR",3)==0) {
	      if (*no_error_reportp)
		*no_error_reportp = -1;
	      pick_env_addr(buf+4,errfp);
	    } else if (strncmp(buf,"SUB",3)==0) {
	      continue;
	    } else
	      break;
	  }
	  sfprintf(errfp,"env-end\n"); /* Envelope ends */
	  sfseek(fp, (off_t)0, SEEK_SET); /* Rewind! Start building the report */

	  if (*no_error_reportp == 0)
	    sfprintf(errfp, "To: %s\n", eaddr);
	  else if (*no_error_reportp < 0)
	    sfprintf(errfp, "To: dummy:; (error trapped source)\n");
	  while (csfgets(buf,sizeof(buf)-1,fp) >= 0) {
	    if (strncmp(buf,"HDR",3)==0) {
	      sfprintf(errfp, "%s", buf+4);
	    } else if (strncmp(buf,"ADR",3)==0) {
	      sfprintf(errfp, "%s", buf+4);
	    } else if (strncmp(buf,"SUB",3)==0) {
	      char *s = strchr(buf+4, '\n');
	      if (s) *s = 0;
	      s = buf+4;
	      hadsubj = 1;
	      if (*no_error_reportp < 0) {
		/* We modify the subject string... */
		while (*s && *s != ':') ++s;
		if (*s == ':') {
		  ++s;
		  if (*s) *s++ = 0;
		  sfprintf(errfp,"%s Double-fault: %s", buf+4, s);
		} else {
		  sfprintf(errfp,"Subject: Double-fault: unknown delivery error");
		}
	      } else
		sfprintf(errfp, "%s", buf+4);
	      s = " [";
	      if (actionset[ACTSET_FAILED]) {
		sfprintf(errfp,"%sFAILED(%d)",s,
			 actionset[ACTSET_FAILED]);
		s = ",";
	      }
	      if (actionset[ACTSET_DELAYED]) {
		sfprintf(errfp,"%sDELAYED(%d)",s,
			 actionset[ACTSET_DELAYED]);
		s = ",";
	      }
	      if (actionset[ACTSET_RELAYED]) {
		sfprintf(errfp,"%sRELAYED-OK(%d)",s,
			 actionset[ACTSET_RELAYED]);
		s = ",";
	      }
	      if (actionset[ACTSET_DELIVERED]) {
		sfprintf(errfp,"%sDELIVERED-OK(%d)",s,
			 actionset[ACTSET_DELIVERED]);
		s = ",";
	      }
	      if (actionset[ACTSET_EXPANDED]) {
		sfprintf(errfp,"%sEXPANDED-OK(%d)",s,
			 actionset[ACTSET_EXPANDED]);
		s = ",";
	      }
	      s = (*s == ',') ? "]" : "";
	      sfprintf(errfp,"%s\n", s);
	    } else {
	      if (inhdr) {
		inhdr = 0;
		sfprintf(errfp,"MIME-Version: 1.0\n");
		sfprintf(errfp,"Content-Type: multipart/report; report-type=delivery-status;\n");
		sfprintf(errfp,"\tboundary=\"%s\"\n\n",boundary);
		sfprintf(errfp, "This is MULTIPART/REPORT structured message as defined at RFC 1894.\n\n");
		sfprintf(errfp, "Ask your email client software vendor, when will they support this\nreport format by showing its formal part in your preferred language.\n\n");
		sfprintf(errfp, "--%s\n", boundary);
		sfprintf(errfp, "Content-Type: text/plain\n");
	      }
	      sfprintf(errfp,"%s",buf);
	    }
	  } /* ... while() ends.. */
	  sfclose(fp);
	} else {
	  /* NO error report boilerplate file available ! */
	  /* Always report to postmaster as well! */
	  sfprintf(errfp, "todsn ORCPT=rfc822;postmaster\nto <postmaster>\n");
	  sfprintf(errfp, "env-end\n");

	  if (*no_error_reportp == 0)
	    sfprintf(errfp, "To: %s\n", eaddr);
	  else if (*no_error_reportp < 0)
	    sfprintf(errfp, "To: dummy:; (error trapped source)\n");

	  sfprintf(errfp,"Subject: Multiple-fault: Report template missing\n");

	  sfprintf(errfp,"MIME-Version: 1.0\n");
	  sfprintf(errfp,"Content-Type: multipart/report; report-type=delivery-status;\n");
	  sfprintf(errfp,"\tboundary=\"%s\"\n\n",boundary);
	  sfprintf(errfp, "--%s\n", boundary);
	  sfprintf(errfp, "Content-Type: text/plain\n\n");
	  sfprintf(errfp, "This report is classified as 'Multiple-fault', because\n");
	  sfprintf(errfp, "the error report template file (%s) was not found.\n\n",path);
	  sfprintf(errfp, "Please report this to this system's postmaster.\n\n");
	  sfprintf(errfp, "Here are report messages regarding email you (probably) sent:\n\n");
	}
}

/* called to process errors at sensible intervals */

void
reporterrs(cfpi, delayreports)
	struct ctlfile *cfpi;
	const int delayreports;
{
	int i, n, wroteheader, byteidx, headeridx = -1, drptidx, fd;
	int *lp, ignored = 0;
	time_t tstamp;
	char *cp, *cp2, *action, *eaddr;
	char *deliveryform;
	Sfio_t *errfp, *fp;
	char *notary;
	struct not *notaries = NULL;
	char *envid;
	int notarycnt = 0;
	int notaryspc = 0;
	struct ctlfile *cfp = NULL;
	char *rcpntpointer;
	int no_error_report = 0;
	int has_errors = 0;
	int lastoffset;
	int mypid;
	long format;
	char boundarystr[400];
	char rptspoolid[30];
	time_t mtime;
	long ino, mtimens;
	int actionsets[5]; /* 0:DELIVERED, 1:FAILED, 2:RELAYED, 3:DELAYED,
			      4:EXPANDED */
	ACTSETENUM thisaction;
	char path[MAXPATHLEN], mpath[MAXPATHLEN];

	if (cfpi->haderror == 0) {
	  if (verbose > 1)
	    sfprintf(sfstdout, "reporterrs: No errors! bailing out!\n");
	  return;
	}
	if (cfpi->erroraddr == NULL) {
	  if (verbose)
	    sfprintf(sfstdout, "reporterrs: No error address! bailing out!\n");
	  return;
	}
	no_error_report = cfpi->iserrmesg;

	eaddr        = cfpi->erroraddr;
	deliveryform = cfpi->deliveryform ? cfpi->deliveryform : "delivery";
	envid        = cfpi->envid;

	/* exclusive access required, but we're the only scheduler... */
	sprintf(mpath,"%s%.400s", cfpdirname(cfpi->dirind), cfpi->mid);

	fd = open(mpath, O_RDWR, 0);
	if (fd < 0 ||
	    (cfp = slurp(fd, cfpi->id)) == NULL) {
	  sfprintf(sfstderr,
		   "%s: unexpected absence of control file %s for error processing (%s)!\n",
		   progname, mpath, cfpi->spoolid ? cfpi->spoolid : "-");
	  if (fd >= 0)
	    close(fd);
	  return;
	}
	lp = &cfp->offset[0];
	mypid = getpid();
	wroteheader = 0;
	lastoffset = cfp->offset[cfp->nlines-1];
	format = 0L;
	actionsets[0] = actionsets[1] = actionsets[2] = 0;
	actionsets[3] = actionsets[4] = 0;

	for (i = 0; i < cfp->nlines; ++i, ++lp) {
	  cp = cfp->contents + *lp;

	  if (*cp == _CF_FORMAT) {
	    ++cp;
	    sscanf(cp,"%li",&format);
	    continue;
	  }

	  /* FIXME: FIXME: DELAYED reporting must check entries:
	     _CF_RECIPIENT && _CFTAG_NORMAL */

	  if (!(*cp == _CF_DIAGNOSTIC && *++cp == _CFTAG_NORMAL))
	    continue;

	  /* Line fmt:
	     <TAGS> offset ':' headeroffset ':' drptidx ':' dnsrcpnt ':' timestamp  <TAB> NOTARY-DATA <TAB> MESSAGE <NL> */

	  cp = cfp->contents + *lp + 2;

	  byteidx = atoi(cp);
	  if (byteidx < 0 || byteidx > lastoffset)
	    byteidx = 0; /* Invalid offset ?! */
	  while (*cp  && isascii(*cp) && isdigit(*cp))
	    ++cp;
	  headeridx = -1;
	  if (*cp == ':') {
	    ++cp;
	    headeridx = atoi(cp);
	    if (headeridx > lastoffset)
	      headeridx = 0;
	    while (*cp && isascii(*cp) && (isdigit(*cp) || *cp == '-'))
	      ++cp;
	  }
	  drptidx = -1;
	  if (*cp == ':') {
	    ++cp;
	    drptidx = atoi(cp);
	    if (drptidx > lastoffset)
	      drptidx = -1;
	    while (isascii(*cp) && (isdigit(*cp) || *cp == '-'))
	      ++cp;
	  }
	  if (*cp == ':') {
	    /* This was a field called DNSRECIPIENT -- which
	       was never used in actuality ... */
	    ++cp;
	    while (isascii(*cp) && (isdigit(*cp) || *cp == '-'))
	      ++cp;
	  }
	  tstamp = 0;
	  if (*cp == ':') {
	    ++cp;
	    tstamp = atol(cp);
	    while (isascii(*cp) && (isdigit(*cp) || *cp == '-'))
	      ++cp;
	  }
	  /* If ever need to add more integer offsets, add them
	     here with a colon prefix... */
	  notary = NULL;
	  action = NULL;
	  /* If this is nothing, this is about FAILURE */
	  thisaction = ACTSET_FAILED;
	  if (*cp == '\t') {
	    notary = ++cp;
	    while (*cp && *cp != '\t') ++cp;
	    notary = strnsave(notary, cp-notary); /* Make a copy of it */
	    ++cp;
	    action = strchr(notary,'\001');

	    if (action) {
	      ++action;
	      cp2 = strchr(action,'\001');

	      if        (memcmp(action,"delayed",  7)==0) {
		thisaction = ACTSET_DELAYED;
	      } else if (memcmp(action,"delivered",9)==0) {
		thisaction = ACTSET_DELIVERED;
	      } else if (memcmp(action,"expanded", 8)==0) {
		thisaction = ACTSET_EXPANDED;
	      } else if (memcmp(action,"relayed",  7)==0) {
		thisaction = ACTSET_RELAYED;
	      } else if (memcmp(action,"failed",   6)==0) {
		thisaction = ACTSET_FAILED;
	      } else
		thisaction = ACTSET_NONE;
	    }
	  }

	  rcpntpointer = cfp->contents + byteidx + 2 + _CFTAG_RCPTPIDSIZE;
	  if (format & _CF_FORMAT_DELAY1)
	    rcpntpointer += _CFTAG_RCPTDELAYSIZE;

	  if (do_syslog > 1)
	    zsyslog((LOG_INFO, "%s: <%s>: %s",
		     cfpi->spoolid ? cfpi->spoolid:"-", rcpntpointer, cp));

	  if (notary != NULL && *notary != 0) {
	    if (!notaries) {
	      notaryspc = 8;
	      notaries = (void*)emalloc(sizeof(struct not)*(notaryspc+1));
	    }
	    if (notarycnt >= notaryspc) {
	      notaryspc += 8;
	      notaries = (void*)erealloc((void*)notaries,
					 sizeof(struct not)*(notaryspc+1));
	    }
	    notaries[notarycnt].not        = notary;
	    notaries[notarycnt].orcpt      = NULL;
	    notaries[notarycnt].inrcpt     = NULL;
	    notaries[notarycnt].notify     = NULL;
	    notaries[notarycnt].message    = NULL;
	    /* If NOTIFY= is not defined, default is: NOTIFY=FAILURE */
	    notaries[notarycnt].notifyflgs = NOT_FAILURE;
	    notaries[notarycnt].rcpntp     = rcpntpointer;
	    notaries[notarycnt].tstamp     = tstamp;
	    if (drptidx > 0) {
	      char *d = cfp->contents + drptidx;
	      while (*d) {
		while (*d != 0 && (*d == ' ' || *d == '\t')) ++d;
		if (CISTREQN(d,"ORCPT=",6)) {
		  notaries[notarycnt].orcpt = d+6;
		  d += 6;
		  while (*d != 0 && (*d != ' ' && *d != '\t')) ++d;
		  if (*d) *d++ = 0;
		  continue;
		}
		if (CISTREQN(d,"INRCPT=",7)) {
		  notaries[notarycnt].inrcpt = d+7;
		  d += 7;
		  while (*d != 0 && (*d != ' ' && *d != '\t')) ++d;
		  if (*d) *d++ = 0;
		  continue;
		}
		if (CISTREQN(d,"NOTIFY=",7)) {
		  char *p;
		  notaries[notarycnt].notify = d+7;
		  notaries[notarycnt].notifyflgs = 0;
		  d += 7;
		  p = d;
		  while (*d != 0 && (*d != ' ' && *d != '\t')) ++d;
		  if (*d) *d++ = 0;
		  while (*p) {
		    if (CISTREQN(p,"NEVER",5)) {
		      notaries[notarycnt].notifyflgs |= NOT_NEVER;
		      p += 5;
		    } else if (CISTREQN(p,"DELAY",5)) {
		      notaries[notarycnt].notifyflgs |= NOT_DELAY;
		      p += 5;
		    } else if (CISTREQN(p,"SUCCESS",7)) {
		      notaries[notarycnt].notifyflgs |= NOT_SUCCESS;
		      p += 7;
		    } else if (CISTREQN(p,"FAILURE",7)) {
		      notaries[notarycnt].notifyflgs |= NOT_FAILURE;
		      p += 7;
		    } else if (CISTREQN(p,"TRACE",5)) {
		      notaries[notarycnt].notifyflgs |= NOT_TRACE;
		      p += 5;
		    } else
		      break; /* Burp.. Junk! */
		    if (*p == ',') ++p;
		  }
		  continue;
		}
		/* XX: Other junk at DSN parameter string ? */
		while (*d != 0 && (*d != ' ' && *d != '\t')) ++d;
		if (*d) *d++ = 0;
		continue;
	      }
	      /* Report conditional testing in the later phases */
	    }
	    while (*cp == ' ' || *cp == '\t') ++cp;
	    notaries[notarycnt].message = cp;

	    switch (thisaction) {
	    case ACTSET_EXPANDED:
	    case ACTSET_DELIVERED:
	    case ACTSET_RELAYED:
	      if (notaries[notarycnt].notifyflgs & NOT_SUCCESS)
		actionsets[thisaction] += 1;
	      else {
		thisaction = ACTSET_NONE;
		++ignored;
	      }
	      break;
	    case ACTSET_DELAYED:
	      if (notaries[notarycnt].notifyflgs & NOT_DELAY)
		actionsets[thisaction] += 1;
	      else {
		thisaction = ACTSET_NONE;
		++ignored;
	      }
	      break;
	    case ACTSET_FAILED:
	      if (notaries[notarycnt].notifyflgs & NOT_FAILURE)
		actionsets[thisaction] += 1;
	      else {
		thisaction = ACTSET_NONE;
		++ignored;
	      }
	      break;
	    default:
	      thisaction = ACTSET_NONE;
	      ++ignored;
	      break;
	    }
	    notaries[notarycnt].thisaction = thisaction;

	    ++notarycnt;
	    notaries[notarycnt].not = NULL;

	  } else {
	    /* No notaries ?!  What ?  Store the CP pointer anyway.. */
	    /* End of failure list processing */
	  }

	  lockaddr(cfp->fd, NULL, *lp + 1, _CFTAG_NORMAL, _CFTAG_OK, mpath, "diagmsg", mypid);
	}
	/* End of all diagnostics message lines */

	if (notaries == NULL) {
	  /* Oops!  No recipients on which to report anything ?! */

	  if (verbose)
	    sfprintf(sfstdout, "No reports! bailing out!\n");

	  close(cfp->fd);
	  free_cfp_memory(cfp);

	  if (do_syslog)
	    zsyslog((LOG_INFO, "%s: Abnormal: No notaries to report; 1",
		     cfpi->spoolid ? cfpi->spoolid:"-"));

	  return;
	}

	if (!(actionsets[ACTSET_FAILED]   |
	      actionsets[ACTSET_RELAYED]  |
	      actionsets[ACTSET_DELAYED]  |
	      actionsets[ACTSET_EXPANDED] |
	      actionsets[ACTSET_DELIVERED] )) {

	  /* No reports what so ever ? */

	  /* Release 'notaries' datasets */
	  for (i = 0; i < notarycnt; ++i) {
	    if (notaries[i].not != NULL)
	      free(notaries[i].not);
	  }
	  free((void*)notaries);
	  close(cfp->fd);
	  free_cfp_memory(cfp);

	  if (verbose > 1)
	    sfprintf(sfstdout, "reporterrs: No reports! bailing out!\n");

	  if (do_syslog)
	    zsyslog((LOG_INFO, "%s: Nothing to report, ignorecount: %d",
		     cfpi->spoolid ? cfpi->spoolid:"-", ignored));


	  return;
	}

	errfp = sfmail_open(MSG_RFC822);
	if (errfp == NULL) {
	  sfprintf(sfstderr,
		  "%s: cannot open output mail file to return diagnostics! errno=%d, errstr='%s'\n",
		  progname, errno, strerror(errno));
	  /* Release 'notaries' datasets */
	  for (i = 0; i < notarycnt; ++i) {
	    if (notaries[i].not != NULL)
	      free(notaries[i].not);
	  }
	  free((void*)notaries);
	  close(cfp->fd);
	  free_cfp_memory(cfp);

	  if (do_syslog)
	    zsyslog((LOG_INFO, "%s: ABNORMAL: Failed to open report file!",
		     cfpi->spoolid ? cfpi->spoolid:"-"));

	  return;
	}

	{
	  char *dom = mydomain(); /* transports/libta/buildbndry.c */
	  struct stat stbuf;

	  fstat(sffileno(errfp),&stbuf); /* doesn't matter exactly what,
					  as long as unique */

	  taspoolid(boundarystr, (long)stbuf.st_ino, stbuf.st_mtime,
#ifdef HAVE_STRUCT_STAT_ST_ATIM_TV_NSEC
		    stbuf.st_mtim.tv_nsec
#else
#ifdef HAVE_STRUCT_STAT_ST_ATIM___TV_NSEC
		    stbuf.st_mtim.__tv_nsec
#else
#ifdef HAVE_STRUCT_STAT_ST_ATIMENSEC
		    stbuf.st_mtimensec
#else
		    0
#endif
#endif
#endif
		    );

	  strcat(boundarystr, "=_/");
	  strcat(boundarystr, dom);
	}

	writeheader(errfp, eaddr, &no_error_report, deliveryform, boundarystr,
		    actionsets);


	if (mydomain() != NULL) {
	  sfprintf(errfp, "Reporting-MTA: dns; %s\n", mydomain() );
	} else {
	  sfprintf(errfp, "Reporting-MTA: x-local-hostname; -unknown-\n");
	}
	sfprintf(errfp, "Return-Path: <%s>\n", eaddr);
	if (envid != NULL) {
	  sfprintf(errfp, "Original-Envelope-Id: ");
	  decodeXtext(errfp,envid);
	  sfputc(errfp, '\n');
	}
	/* rfc822date() returns a string with trailing newline! */
	sfprintf(errfp, "Arrival-Date: %s", rfc822date(&cfpi->mtime));
	if (cfpi->spoolid)
	  sfprintf(errfp, "Local-Spool-ID: %s\n", cfpi->spoolid);
	sfprintf(errfp, "\n\n");



	n = 0;
	for (i = 0; i < notarycnt; ++i) {
	  /* Scan to the start of the message text */
	  const char *ccp, *s;
	  if ((notaries[i].notifyflgs & NOT_NEVER) && (no_error_report >= 0))
	    continue;
	  /* Report is not outright rejected, or this is double fault */
	  ++n;
	  switch (notaries[i].thisaction) {
	  case ACTSET_DELAYED:
	    sfprintf(errfp,"DELAYED (still in queue):\n");
	    break;
	  case ACTSET_RELAYED:
	    sfprintf(errfp,"RELAYED (into system not supporting DSN facility):\n");
	    break;
	  case ACTSET_FAILED:
	    sfprintf(errfp,"FAILED:\n");
	    break;
	  case ACTSET_DELIVERED:
	    sfprintf(errfp,"DELIVERED (successfully):\n");
	    break;
	  case ACTSET_EXPANDED:
	    sfprintf(errfp,"EXPANDED (to some list or alias):\n");
	    break;
	  case ACTSET_NONE:
	    sfprintf(errfp,"BUG (unknown ACTSET value: %d):\n",
		     notaries[i].thisaction);
	    --n;
	    break;
	  }
	  if (notaries[i].inrcpt) {
	    sfprintf(errfp, "  Arrived Recipient:\n      ");
	    decodeXtext(errfp, notaries[i].inrcpt);
	    sfputc(errfp,'\n');
	  }
	  scnotaryreport(errfp, &notaries[i], &has_errors, no_error_report, 1);

	  sfprintf(errfp, "  Control data:\n      %s\n", notaries[i].rcpntp);
	  sfprintf(errfp, "  Diagnostic texts:\n      ");
	  ccp = notaries[i].message;
	  s = ccp;
	  while (*s == '\r') ++s; /* Skip possible first '\r' */
	  for (; *s != '\0'; ++s) {
	    if (*s == '\r') {
	      sfprintf(errfp,"\n     ");
	    } else {
	      sfputc(errfp, *s);
	    }
	  }
	  sfputc(errfp, '\n');

	}

	sfprintf(errfp,"\n\
Following is a copy of MESSAGE/DELIVERY-STATUS format section below.\n\
It is copied here in case your email client is unable to show it to you.\n\
The information here below is in  Internet Standard  format designed to\n\
assist automatic, and accurate presentation and usage of said information.\n\
In case you need human assistance from the Postmaster(s) of the system which\n\
sent you this report, please include this information in your question!\n\
\n\
    Virtually Yours,\n\
        Automatic Email Delivery Software\n\
\n");


	if (mydomain() != NULL) {
	  sfprintf(errfp, "Reporting-MTA: dns; %s\n", mydomain() );
	} else {
	  sfprintf(errfp, "Reporting-MTA: x-local-hostname; -unknown-\n");
	}
	if (envid != NULL) {
	  sfprintf(errfp, "Original-Envelope-Id: ");
	  decodeXtext(errfp,envid);
	  sfputc(errfp, '\n');
	}
	/* rfc822date() returns a string with trailing newline! */
	sfprintf(errfp, "Arrival-Date: %s", rfc822date(&cfpi->mtime));
	if (cfpi->spoolid)
	  sfprintf(errfp, "Local-Spool-ID: %s\n", cfpi->spoolid);
	sfprintf(errfp, "\n");

	/* Now scan 'em all again for IETF-NOTARY */
	for (i = 0; i < notarycnt; ++i)
	  scnotaryreport(errfp, &notaries[i],&has_errors,no_error_report, 0);

	sfprintf(errfp,"\n\
Following is copy of the message headers. Original message content may\n\
be in subsequent parts of this MESSAGE/DELIVERY-STATUS structure.\n\n");

	/* path to the message body */
	sprintf(path, "../%s/%s%.300s",
		QUEUEDIR, cfpdirname(cfpi->dirind), cfpi->mid);

	fp = sfopen(NULL, path, "r");
	if (fp != NULL) {

	  char buf[BUFSIZ];

	  if (cfp->msgbodyoffset > 0 && headeridx > 0 ) {
	    /* We have knowledge about the headers of errored email,
	       use those headers on output ! */
	    if (strncmp(cfp->contents + headeridx, "m\n", 2) == 0)
	      headeridx += 2;
	    sfprintf(errfp, "%s\n", cfp->contents + headeridx);
	    /* With a newline in between headers and the body.. */
	  } else {
	    /* Scan the input, and drop off the ZMailer
	       envelope headers */
	    while (csfgets(buf,sizeof(buf),fp) >= 0) {
	      const char *s = buf;
	      while (*s && *s != ':' && *s != ' ' && *s != '\t') ++s;
	      if (*s == ':') break;
	      *buf = 0;
	    }
	    /* We leave the first scan-phase with  buf[]  containing some
	       valid RFC-822 -style header, probably "Received:" */
	    if (*buf)
	      sfprintf(errfp, "%s", buf);
	    else {
	      sfprintf(errfp,"< Eh, no content in the ORIGINAL message ???  >\n");
	      sfprintf(errfp,"< We will dump also transporter envelope here >\n");
	      sfseek(fp, (Sfoff_t)0, SEEK_SET);
	    }
	  }
	}

	sfprintf(errfp, "\n");
	sfprintf(errfp, "--%s\n", boundarystr);
	sfprintf(errfp, "Content-Type: message/delivery-status\n\n");

	if (mydomain() != NULL) {
	  sfprintf(errfp, "Reporting-MTA: dns; %s\n", mydomain() );
	} else {
	  sfprintf(errfp, "Reporting-MTA: x-local-hostname; -unknown-\n");
	}
	if (envid != NULL) {
	  sfprintf(errfp, "Original-Envelope-Id: ");
	  decodeXtext(errfp,envid);
	  sfputc(errfp, '\n');
	}
	/* rfc822date() returns a string with trailing newline! */
	sfprintf(errfp, "Arrival-Date: %s", rfc822date(&cfpi->mtime));
	if (cfpi->spoolid)
	  sfprintf(errfp, "Local-Spool-ID: %s\n", cfpi->spoolid);
	sfprintf(errfp, "\n");

	/* Now scan 'em all again for IETF-NOTARY */
	for (i = 0; i < notarycnt; ++i) {
	  scnotaryreport(errfp, &notaries[i],&has_errors,no_error_report, 0);
	  if (notaries[i].not != NULL)
	    free(notaries[i].not);
	}
	free((void*)notaries);

	sfprintf(errfp, "--%s\n", boundarystr);
	sfprintf(errfp, "Content-Type: message/rfc822\n\n");

	if (fp != NULL) {

	  char buf[BUFSIZ];

	  if (cfp->msgbodyoffset > 0 && headeridx > 0 ) {
	    /* We have knowledge about the headers of errored email,
	       use those headers on output ! */
	    if (strncmp(cfp->contents + headeridx, "m\n", 2) == 0)
	      headeridx += 2;
	    sfprintf(errfp, "%s\n", cfp->contents + headeridx);
	    /* With a newline in between headers and the body.. */
	    sfseek(fp, (Sfoff_t)(cfp->msgbodyoffset), SEEK_SET);
	  } else {
	    /* Scan the input, and drop off the Zmailer
	       envelope headers */
	    sfseek(fp, (Sfoff_t)0, SEEK_SET);
	    while (csfgets(buf,sizeof(buf),fp) >= 0) {
	      const char *s = buf;
	      while (*s && *s != ':' && *s != ' ' && *s != '\t') ++s;
	      if (*s == ':') break;
	      *buf = 0;
	    }
	    /* We leave the first scan-phase with  buf[]  containing some
	       valid RFC-822 -style header, probably "Received:" */
	    if (*buf)
	      sfprintf(errfp, "%s", buf);
	    else {
	      sfprintf(errfp,"< Eh, no content in the ORIGINAL message ???  >\n");
	      sfprintf(errfp,"< We will dump also transporter envelope here >\n");
	      sfseek(fp, (Sfoff_t)0, SEEK_SET);
	    }
	  }
	  if (has_errors &&
	      ((no_error_report < 0) ||
	       (default_full_content && !cfp->dsnretmode) ||
	       (cfp->dsnretmode && CISTREQN(cfp->dsnretmode,"FULL",4)))) {
	    /* Copy out the rest (=body) with somewhat more efficient method */

	    while ((n = sfread(fp, buf, sizeof buf)) > 0)
	      sfwrite(errfp, buf, n);
	  }
	  sfclose(fp);
	} else {
	  sfprintf(sfstderr,"Could not open message body file: '%s'\n",path);
	}
	/* And cap the tail with paired MIME boundary.. */
	sfprintf(errfp, "--%s--\n", boundarystr);

	ino = 0; mtime = mtimens = 0;
	close(cfp->fd);
	free_cfp_memory(cfp);

	if (no_error_report > 0) {
	  if (store_error_on_error)
	    sfmail_close_alternate_async(errfp,POSTMANDIR,":error-on-error", msgwriteasync);
	  else
	    sfmail_abort(errfp);
	  sprintf(rptspoolid, "POSTMAN :error-on-error"); /* < 30 chr ! */
	} else {
	  _sfmail_close_async(errfp, &ino, &mtime, &mtimens, msgwriteasync);	/* XX: check for error */
	  taspoolid(rptspoolid, ino, mtime, mtimens);
	}

	if (do_syslog)
	  zsyslog((LOG_INFO, "%s: Created '%s' report on spoolid: %s",
		   cfpi->spoolid ? cfpi->spoolid:"-",
		   deliveryform, rptspoolid));

}


/* ---------------- DELAYED reporter --------------------------*/

void
msgdelayed(vp, offset, notary, message)
	struct vertex *vp;
	long offset;
	char *notary;
	const char *message;
{
	Sfio_t *fp;
	char path[410];
	char *not[20], *s;
	int i;

	/* Split the notary string into components. */
	for (i = 0; i < 20; ++i) not[i] = NULL;
	s = notary;
	i = 0;
	while (i < 20 && s) {
	  not[i++] = s;
	  s = strchr(s, '\001');
	  if (s) *s++ = 0;
	}

	sprintf(path, "%s%.300s", cfpdirname(vp->cfp->dirind), vp->cfp->mid);

	/* exclusive access required, but we're the only scheduler... */
	fp = sfopen(NULL, path, "a");
	if (fp == NULL) {
	  sfprintf(sfstderr,
		   "Cannot open control file %s to deposit", vp->cfp->mid);
	  sfprintf(sfstderr,
		   " error message for offset %ld:\n", offset);
	  sfprintf(sfstderr, "\t%s\n", message);
	  return;
	}
	vp->cfp->haderror = 1;
	sfprintf(fp, "%c%c%ld:%ld:%ld::%ld\t",
		 _CF_DIAGNOSTIC, _CFTAG_NORMAL, offset,
		 (long)vp->headeroffset, (long)vp->drptoffset,
		 time(NULL));
	s = "";

	/* Mark this DELAYED */
	if (not[1]) {
	  strcpy(path,"_delayed");
	  not[1] = path+1;
	}

	for (i = 0; i < 20 && not[i]; ++i) {
	  sfprintf(fp, "%s%s", s, not[i]);
	  s = "\001";
	  if (i > 0) not[i][-1] = '\001';
	}
	sfprintf(fp, "%s", notary);
	sfprintf(fp, "\t%s\n", message);
	sfsync(fp);
#ifdef HAVE_FSYNC
	while (fsync(sffileno(fp)) < 0) {
	  if (errno == EINTR || errno == EAGAIN)
	    continue;
	  break;
	}
#endif
	sfclose(fp);
}



static void delayaux(vp, index, notary, buf)
	struct vertex *vp;
	int index;
	char *notary;
	const char *buf;
{
	int i;

	/* Mark the delay info in.. */
	for (i = 0 ; i < vp->ngroup; ++i)
	  if (vp->index[i] == index) {
	    msgdelayed(vp, vp->cfp->offset[index], notary, buf);
	    break;
	  }
}

/* FIXME: FIXME:  delayreport() calling, report times
   control and tracking, etc... */

void
delayreport(vp)
	struct vertex *vp;
{
	int i;
	char *emsg;
	char buf[BUFSIZ];
	char notbuf[BUFSIZ];
	const char *fmt = "\r%s, problem was:\r%s";
	char *notary = vp->notary;

	if (vp->nextdlyrprttime > now) return; /* Nothing yet! */

	if (notary == NULL) {
	  /* addres / action / status / diagnostic / wtt */
	  sprintf(notbuf, "%s\001%s\001%s\001%s",
		  "\003", /* XX: recipient address! XX: MAGIC INFO! */
		  "delayed",
		  "4.4.7 (no attempt done yet; long queue?)",
		  "smtp; 400 (no delivery attempt done in ");
	  saytime((u_long)(vp->nextdlyrprttime - vp->cfp->mtime), notbuf, 0);
	  strcat(notbuf,")\001");
	  notary = notbuf;
	}

	strcpy(buf, "delayed; no successfull delivery in ");
	saytime((u_long)(vp->nextdlyrprttime - vp->cfp->mtime), buf, 0);

	if (vp->message != NULL && *(vp->message) != '\0') {
	  emsg = emalloc(strlen(buf) + strlen(vp->message) + strlen(fmt));
	  sprintf(emsg, fmt, buf, vp->message);
	} else
	  emsg = buf;

	/* Report all vertices having had a delay.. */
	for (i = vp->ngroup -1; i >= 0; --i)
	  delayaux(vp, vp->index[i], notary, emsg);

	if (emsg != buf)
	  free(emsg);
}


/* FIXME: reporting subsystem needs tuning! */
/*        ... implementing/tuning DELAYED reports! */

static int ctl_report_1 __((void *, struct spblk *spl));
static int ctl_report_1(p, spl)
	void *p;
	struct spblk *spl;
{
	struct vertex *vp, *nvp;
	struct ctlfile * cfp = (struct ctlfile *)spl->data;
	int doreport = 0;

	queryipccheck(); /* Sets 'now', among other things */

	for (vp = cfp->head; vp != NULL; vp = nvp) {
	  nvp = vp->next[L_CTLFILE];

	  /* We essentially report accumulated reports every
	     ``global_report_interval'' seconds (2 minutes by default) */

	  if (vp->nextrprttime <= now)
	    doreport = 1;
	}

	if (doreport) {
	  reporterrs(cfp, 0);

	  for (vp = cfp->head; vp != NULL; vp = nvp) {

	    nvp = vp->next[L_CTLFILE];
	    vp->nextrprttime = now + global_report_interval;

	  }
	}

	return 0;
}


void
interim_report_run __((void))
{
	sp_scan(ctl_report_1, NULL, NULL, spt_mesh[L_CTLFILE]);
}


/*
char *
mail_alloc(n)
	u_int n;
{
	return emalloc(n);
}

int
mail_free(s)
	char *s;
{
	free(s);
	return 0;
}
*/
