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

extern int never_full_content; /* at conf.c */

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

struct not {
	char	    *not;
	const char  *message;
	const char  *orcpt;
	const char  *notify;
	int          notifyflgs;
	char	    *rcpntp;
	time_t       tstamp;
};

static void decodeXtext __((FILE *, const char *));
static void
decodeXtext(fp,xtext)
	FILE *fp;
	const char *xtext;
{
	for (;*xtext;++xtext) {
	  if (*xtext == '+') {
	    int c = '?';
	    sscanf(xtext+1,"%02X",&c);
	    putc(c,fp);
	    if (*xtext) ++xtext;
	    if (*xtext) ++xtext;
	  } else
	    putc(*xtext,fp);
	}
}

static void scnotaryreport __((FILE *, struct not *, int *, int));

static void	/* There is notaryreport() on transporters also.. */
scnotaryreport(errfp,notary,haserrsp,notifyrespectflg)
	FILE *errfp;
	struct not *notary;
	int *haserrsp;
	int notifyrespectflg;
{
	char *rcpt, *action, *status, *diagstr, *wtt;
	char *cp;
	const char *typetag;

	static char const *type_rfc   = "RFC822";
	static char const *type_local = "X-LOCAL";

	/* NOTARY: addres / action / status / diagstr / wtt */

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
	*cp++  = 0;
	action = cp;
	cp     = strchr(action,'\001');
	*cp++  = 0;
	status = cp;
	cp     = strchr(status,'\001');
	diagstr = cp;
	if (cp == NULL) {
	  diagstr = status;
	  status = NULL;
	  wtt    = NULL;
	} else {
	  *cp++  = 0;
	  diagstr = cp;
	  cp    = strchr(diagstr,'\001');
	  if (cp) /* Uhh... Mal-formed input from the transporters ? */
	    *cp++    = 0;
	  wtt = cp;
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

	if (strchr(rcpt,'@') != NULL) {
	  typetag = type_rfc;
	  if (strncmp(rcpt,"ns:",3)==0) /* 'hold'-channel stuff */
	    typetag = type_local;
	} else
	  typetag = type_local;
	if (notary->orcpt) {
	  fprintf(errfp, "Original-Recipient: ");
	  decodeXtext(errfp,notary->orcpt);
	  putc('\n',errfp);
	}
	fprintf(errfp, "Final-Recipient: %s;%s\n", typetag, rcpt);
	fprintf(errfp, "Action: %s\n", action);
	if (status) {
	  if (*status == '4' || *status == '5')
	    *haserrsp = 1;
	  fprintf(errfp, "Status: %s\n", status);
	}
	fprintf(errfp, "Diagnostic-Code: %s\n", diagstr);
	if (wtt && wtt[0] != 0)
	  fprintf(errfp, "Remote-MTA: %s\n", wtt);
	if (notary->tstamp != 0)
	  fprintf(errfp, "Last-Attempt-Date: %s", rfc822date(&notary->tstamp));
	fprintf(errfp, "\n");
	action[-1] = '\001';
	if (status)
	  status[-1] = '\001';
	diagstr[-1] = '\001';
	if (wtt)
	  wtt[-1]    = '\001';
}


/* deposit the error message */

void
msgerror(vp, offset, message)
	struct vertex *vp;
	long offset;
	const char *message;
{
	FILE *fp;
	const char *notary = "";
	char path[128];

	if (vp->notary) notary = vp->notary;

	if (vp->cfp->dirind > 0) {
	  sprintf(path,"%s/%s", cfpdirname(vp->cfp->dirind), vp->cfp->mid);
	} else {
	  strcpy(path,vp->cfp->mid);
	}

	/* exclusive access required, but we're the only scheduler... */
	fp = fopen(path, "a");
	if (fp == NULL) {
	  fprintf(stderr,
		  "Cannot open control file %s to deposit", vp->cfp->mid);
	  fprintf(stderr,
		  " error message for offset %ld:\n", offset);
	  fprintf(stderr, "\t%s\n", message);
	  return;
	}
	vp->cfp->haderror = 1;
	fprintf(fp, "%c%c%ld:%ld:%ld::%ld\t%s\t%s\n",
		_CF_DIAGNOSTIC, _CFTAG_NORMAL, offset,
		(long)vp->headeroffset, (long)vp->drptoffset,
		time(NULL), notary, message);
	fflush(fp);
#ifdef HAVE_FSYNC
	fsync(FILENO(fp));
#endif
	fclose(fp);
}

void printenvaddr __((FILE *, const char *));
void printenvaddr(fp, addr)
FILE *fp;
const char *addr;
{
	const char *s;

	fprintf(fp, "todsn ORCPT=rfc822;");
	s = addr;
	for  (; *s; ++s) {
	  char c = (*s) & 0xFF;
	  if ('!' <= c && c <= '~' && c != '+' && c != '=')
	    putc(c,fp);
	  else
	    fprintf(fp,"+%02X",c);
	}
	putc('\n',fp);
	fprintf(fp, "to <%s>\n", addr);
}

/* Pick recipient address from the input line.
   EXTREMELY Simple minded parsing.. */
static void pick_env_addr __((char *, FILE *));
static void pick_env_addr(buf,mfp)
char *buf;
FILE *mfp;
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


static void writeheader __((FILE *, const char *, int *, const char *, const char *));

static void
writeheader(errfp, eaddr, no_error_reportp, deliveryform, boundary)
	FILE *errfp;
	const char *eaddr;
	int *no_error_reportp;
	const char *deliveryform;
	const char *boundary;
{
	FILE *fp;
	char path[MAXPATHLEN];
	char buf[BUFSIZ];

	if (*eaddr == '|' /* Nobody's address starts with a pipe ? */ ||
	    (*eaddr == '/' &&
	     (strchr(eaddr,'@') == NULL ||
	      strchr(eaddr,'=') == NULL /*Smells of X.400*/)))
	  eaddr = "postmaster"; /* Paranoid, eh ? */
	fprintf(errfp, "channel error\n");

	if (!*no_error_reportp)
	  printenvaddr(errfp, eaddr);
	sprintf(path, "%s/%s/%s", mailshare, FORMSDIR,
		deliveryform ? deliveryform : "delivery");
	fp = fopen(path, "r");
	if (fp != NULL) {
	  int inhdr = 1, hadsubj =0;
	  buf[sizeof(buf)-1] = 0;
	  while (fgets(buf,sizeof(buf)-1,fp) != NULL) {
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
	  fputs("env-end\n",errfp); /* Envelope ends */
	  fseek(fp, (off_t)0, SEEK_SET); /* Rewind! Start building the report */

	  if (*no_error_reportp == 0)
	    fprintf(errfp, "To: %s\n", eaddr);
	  else if (*no_error_reportp < 0)
	    fprintf(errfp, "To: dummy:; (error trapped source)\n");
	  while (fgets(buf,sizeof(buf)-1,fp) != NULL) {
	    if (strncmp(buf,"HDR",3)==0) {
	      fputs(buf+4,errfp);
	    } else if (strncmp(buf,"ADR",3)==0) {
	      fputs(buf+4,errfp);
	    } else if (strncmp(buf,"SUB",3)==0) {
	      hadsubj = 1;
	      if (*no_error_reportp < 0) {
		/* We modify the subject string... */
		char *s = buf+4;
		while (*s && *s != ':') ++s;
		if (*s == ':') {
		  ++s;
		  if (*s) *s++ = 0;
		  fprintf(errfp,"%s Double-fault: %s", buf+4, s);
		} else {
		  fputs("Subject: Double-fault: unknown delivery error\n",errfp);
		}
	      } else
		fputs(buf+4,errfp);
	    } else {
	      if (inhdr) {
		inhdr = 0;
		fprintf(errfp,"MIME-Version: 1.0\n");
		fprintf(errfp,"Content-Type: multipart/report; report-type=delivery-status;\n");
		fprintf(errfp,"\tboundary=\"%s\"\n\n",boundary);
		fprintf(errfp, "--%s\n", boundary);
		fprintf(errfp, "Content-Type: text/plain\n");
	      }
	      fputs(buf,errfp);
	    }
	  } /* ... while() ends.. */
	  fclose(fp);
	} else {
	  /* NO error report boilerplate file available ! */
	  /* Always report to postmaster as well! */
	  fprintf(errfp, "todsn ORCPT=rfc822;postmaster\nto <postmaster>\n");
	  fprintf(errfp, "env-end\n");

	  if (*no_error_reportp == 0)
	    fprintf(errfp, "To: %s\n", eaddr);
	  else if (*no_error_reportp < 0)
	    fprintf(errfp, "To: dummy:; (error trapped source)\n");

	  fprintf(errfp,"Subject: Multiple-fault: Report template missing\n");

	  fprintf(errfp,"MIME-Version: 1.0\n");
	  fprintf(errfp,"Content-Type: multipart/report; report-type=delivery-status;\n");
	  fprintf(errfp,"\tboundary=\"%s\"\n\n",boundary);
	  fprintf(errfp, "--%s\n", boundary);
	  fprintf(errfp, "Content-Type: text/plain\n\n");
	  fprintf(errfp, "This report is classified as 'Multiple-fault', because\n");
	  fprintf(errfp, "the error report template file (%s) was not found.\n\n",path);
	  fprintf(errfp, "Please report this to this system's postmaster.\n\n");
	  fprintf(errfp, "Here are report messages regarding email you (propably) sent:\n\n");
	}
}

/* called to process errors at sensible intervals */

void
reporterrs(cfpi)
	struct ctlfile *cfpi;
{
	int i, n, wroteheader, byteidx, headeridx = -1, drptidx, fd;
	int *lp;
	time_t tstamp;
	char *midbuf, *cp, *eaddr;
	char *deliveryform;
	FILE *errfp, *fp;
	char *notary;
	struct not *notaries = NULL;
	char *envid;
	int notarycnt = 0;
	int notaryspc = 0;
	struct ctlfile *cfp;
	char *rcpntpointer;
	int no_error_report = 0;
	int has_errors = 0;
	int lastoffset;
	char path[MAXPATHLEN], mpath[MAXPATHLEN];
	int mypid;
	char boundarystr[400];

	if (cfpi->haderror == 0)
		return;
	if (cfpi->erroraddr == NULL)
		return;
	no_error_report = cfpi->iserrmesg;

	eaddr        = cfpi->erroraddr;
	deliveryform = cfpi->deliveryform;
	envid        = cfpi->envid;
	/* re-read the control file to get some unstashed information */
	midbuf       = cfpi->mid;

	/* exclusive access required, but we're the only scheduler... */
	if (cfpi->dirind > 0)
	  sprintf(mpath,"%s/%s", cfpdirname(cfpi->dirind), cfpi->mid);
	else
	  strcpy(mpath,cfpi->mid);

	fd = open(mpath, O_RDWR, 0);
	if (fd < 0 ||
	    (cfp = slurp(fd, cfpi->id)) == NULL) {
	  fprintf(stderr,
		  "%s: unexpected absence of control file %s for error processing!\n",
		  progname, mpath);
	  if (fd >= 0)
	    close(fd);
	  return;
	}
	lp = &cfp->offset[0];
	mypid = getpid();
	if (cfp->mid) free(cfp->mid);
	cfp->mid = midbuf; /* This is the original one! */
	wroteheader = 0;
	lastoffset = cfp->offset[cfp->nlines-1];
	for (i = 0; i < cfp->nlines; ++i, ++lp) {
	  cp = cfp->contents + *lp;

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
	  if (*cp == '\t') {
	    notary = ++cp;
	    while (*cp && *cp != '\t') ++cp;
	    notary = strnsave(notary, cp-notary); /* Make a copy of it */
	    ++cp;
	  }
	  rcpntpointer = cfp->contents + byteidx + 2 + _CFTAG_RCPTPIDSIZE;
	  if (do_syslog)
	    zsyslog((LOG_INFO, "%s: <%s>: %s", cfp->mid, rcpntpointer, cp));

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
	    notaries[notarycnt].not     = notary;
	    notaries[notarycnt].orcpt   = NULL;
	    notaries[notarycnt].notify  = NULL;
	    notaries[notarycnt].message = NULL;
	    notaries[notarycnt].notifyflgs = 0;
	    notaries[notarycnt].rcpntp  = rcpntpointer;
	    notaries[notarycnt].tstamp  = tstamp;
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
		if (CISTREQN(d,"NOTIFY=",7)) {
		  char *p;
		  notaries[notarycnt].notify = d+7;
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
	      /* Report conditional testing in the latter phases */
	    }
	    while (isascii(*cp) && isspace(*cp))
	      ++cp;
	    notaries[notarycnt].message = cp;
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
	  close(cfp->fd);
	  cfp->mid = NULL; /* we don't want to loose the original one! */
	  free_cfp_memory(cfp);
	  return;
	}

	errfp = mail_open(MSG_RFC822);
	if (errfp == NULL) {
	  fprintf(stderr,
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
	  return;
	}

	{
	  char *dom = mydomain(); /* transports/libta/buildbndry.c */
	  char fname[20];
	  struct stat stbuf;

	  fstat(fileno(errfp),&stbuf);
	  sprintf(fname,"%ld",(long)stbuf.st_ino);
	  taspoolid(boundarystr, sizeof(boundarystr), stbuf.st_ctime, fname);
	  strcat(boundarystr, "=_/");
	  strcat(boundarystr, dom);
	}

	writeheader(errfp, eaddr, &no_error_report, deliveryform, boundarystr);

	for (i = 0; i < notarycnt; ++i) {
	  /* Scan to the start of the message text */
	  const char *ccp, *s;
	  if ((notaries[i].notifyflgs & NOT_NEVER) && (no_error_report >= 0))
	    continue;
	  /* Report is not outright rejected, or this is double fault */
	  fprintf(errfp, "<%s>: ", notaries[i].rcpntp);
	  ccp = notaries[i].message;
	  if (strchr(ccp, '\r')) {
	    fprintf(errfp, "...\\\n\t");
	    for (s = ccp; *s != '\0'; ++s) {
	      if (*s == '\r')
		putc('\n', errfp), putc('\t', errfp);
	      else
		putc(*s, errfp);
	    }
	    putc('\n', errfp);
	  } else
	    fprintf(errfp, "%s\n", ccp);
	}

	fprintf(errfp, "\n");
	fprintf(errfp, "--%s\n", boundarystr);
	fprintf(errfp, "Content-Type: message/delivery-status\n\n");

	if (mydomain() != NULL) {
	  fprintf(errfp, "Reporting-MTA: dns; %s\n", mydomain() );
	} else {
	  fprintf(errfp, "Reporting-MTA: x-local-hostname; -unknown-\n");
	}
	if (envid != NULL) {
	  fprintf(errfp, "Original-Envelope-Id: ");
	  decodeXtext(errfp,envid);
	  putc('\n',errfp);
	}
	/* rfc822date() returns a string with trailing newline! */
	fprintf(errfp, "Arrival-Date: %s", rfc822date(&cfpi->ctime));
	fprintf(errfp, "\n");

	/* Now scan 'em all again for IETF-NOTARY */
	for (i = 0; i < notarycnt; ++i) {
	  scnotaryreport(errfp, &notaries[i],&has_errors,no_error_report);
	  if (notaries[i].not != NULL)
	    free(notaries[i].not);
	}
	free((void*)notaries);

	fprintf(errfp, "--%s\n", boundarystr);
	fprintf(errfp, "Content-Type: message/rfc822\n\n");

	/* path to the message body */
	if (cfpi->dirind > 0)
	  sprintf(path, "../%s/%s/%s",
		  QUEUEDIR, cfpdirname(cfpi->dirind), cfpi->mid);
	else
	  sprintf(path, "../%s/%s",
		  QUEUEDIR, cfpi->mid);

	fp = fopen(path, "r");
	if (fp != NULL) {

	  char buf[BUFSIZ];

	  if (cfp->msgbodyoffset > 0 && headeridx > 0 ) {
	    /* We have knowledge about the headers of errored email,
	       use those headers on output ! */
	    if (strncmp(cfp->contents + headeridx, "m\n", 2) == 0)
	      headeridx += 2;
	    fputs(cfp->contents + headeridx, errfp);
	    putc('\n', errfp); /* Newline in between headers and the body.. */
	    fseek(fp, (off_t)(cfp->msgbodyoffset), SEEK_SET);
	  } else {
	    /* Scan the input, and drop off the Zmailer
	       envelope headers */
	    while (fgets(buf,sizeof(buf),fp) != NULL) {
	      const char *s = buf;
	      while (*s && *s != ':' && *s != ' ' && *s != '\t') ++s;
	      if (*s == ':') break;
	      *buf = 0;
	    }
	    /* We leave the first scan-phase with  buf[]  containing some
	       valid RFC-822 -style header, propably "Received:" */
	    if (*buf)
	      fputs(buf,errfp);
	    else {
	      fputs("< Eh, no content in the ORIGINAL message ???  >\n",errfp);
	      fputs("< We will dump also transporter envelope here >\n",errfp);
	      fseek(fp, (off_t)0, SEEK_SET);
	    }
	  }
	  if (has_errors &&
	      ((no_error_report < 0) ||
	       (!never_full_content &&
		(!cfp->dsnretmode || CISTREQN(cfp->dsnretmode,"FULL",4))))) {
	    /* Copy out the rest (=body) with somewhat more efficient method */

	    while ((n = fread(buf, sizeof buf[0], sizeof buf, fp)) > 0)
	      fwrite(buf, sizeof buf[0], n, errfp);
	  }
	  fclose(fp);
	} else {
	  fprintf(stderr,"Could not open message body file: '%s'\n",path);
	}
	/* And cap the tail with paired MIME boundary.. */
	fprintf(errfp, "--%s--\n", boundarystr);

	if (no_error_report > 0)
	  mail_close_alternate(errfp,POSTMANDIR,":error-on-error");
	else
	  mail_close(errfp);	/* XX: check for error */
	close(cfp->fd);
	cfp->mid = NULL; /* we don't want to loose the original one! */
	free_cfp_memory(cfp);
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
