/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 *	Copyright 1994-2001 by Matti Aarnio
 *
 * To really understand how headers (and their converted versions)
 * are processed you do need to draw a diagram.
 * Basically:
 *    rp->desc->headers[]    is index to ALL of the headers, and
 *    rp->desc->headerscvt[] is index to ALL of the CONVERTED headers.
 * Elements on these arrays are  "char *strings[]" which are the
 * actual headers.
 * There are multiple-kind headers depending upon how they have been
 * rewritten, and those do tack together for each recipients (rp->)
 * There
 *    rp->newmsgheader    is a pointer to an element on  rp->desc->headers[]
 *    rp->newmsgheadercvt is respectively an elt on  rp->desc->headerscvt[]
 *
 * The routine-collection   mimeheaders.c  creates converted headers,
 * if the receiving system needs them. Converted data is created only
 * once per  rewrite-rule group, so there should not be messages which
 * report  "Received: ... convert XXXX convert XXXX convert XXXX; ..."
 * for as many times as there there are recipients for the message.
 * [mea@utu.fi] - 25-Jul-94
 */

#include "hostenv.h"
#include <ctype.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#include <sysexits.h>

#include "ta.h"

#include "mail.h"
#include "zmalloc.h"
#include "libz.h"

#if defined(HAVE_MMAP) && defined(TA_USE_MMAP)
#include <sys/mman.h>
#endif

#include <errno.h>

extern char *routermxes __((char *, struct taddress *));
extern int errno;

#ifndef strrchr
extern char *strrchr();
#endif

static struct taddress *ctladdr __((char *cp));


#ifndef	MAXPATHLEN
#define	MAXPATHLEN 1024
#endif	/* !MAXPATHLEN */


void
ctlfree(dp,anyp)
	struct ctldesc *dp;
	void *anyp;
{
	void * lowlim  = (void *) dp->contents;
	void * highlim = (void *)(((char*)lowlim) + dp->contentsize);
#if 0
	fprintf(stderr,"# ctlfree(%p) (%p,%p] @%p\n", anyp,
		lowlim, highlim, __builtin_return_address(0));
#endif
	if (anyp && (anyp < lowlim || anyp >= highlim))
	  free(anyp);	/* It isn't within DP->CONTENTS data.. */
}

void *
ctlrealloc(dp,anyp,size)
	struct ctldesc *dp;
	void *anyp;
	size_t size;
{
	void * lowlim  = (void *) dp->contents;
	void * highlim = (void *)(((char*)lowlim) + dp->contentsize);
	void *anyp2;
#if 0
	fprintf(stderr,"# ctlrealloc(%p,%lu) (%p,%p] @%p\n", anyp, size,
		lowlim, highlim, __builtin_return_address(0));
#endif
	/* If old one isn't our local thing, delete it! */
	if (anyp < lowlim || anyp >= highlim)
	  return realloc(anyp, size); /* realloc(); it isn't within DP->CONTENTS data.. */

	/* Allocate a new storage.. */
	anyp2 = (void*) malloc(size);
	if (!anyp) return NULL;

	memcpy(anyp2,anyp,size);

	return anyp2;
}

void
ctlclose(dp)
	struct ctldesc *dp;
{
	struct taddress *ap, *nextap;
	struct rcpt *rp, *nextrp;
	char ***msghpp;

	for (rp = dp->recipients; rp != NULL; rp = rp->next) {
	  if (rp->lockoffset == 0)
	    continue;
	  diagnostic(NULL, rp, EX_TEMPFAIL, 0, "address was left locked!!");
	}
#if defined(HAVE_MMAP) && defined(TA_USE_MMAP)
	if (dp->let_buffer != NULL)
	  munmap((void*)dp->let_buffer, dp->let_end - dp->let_buffer);
	dp->let_buffer = NULL;
	if (dp->ctlmap != NULL)
	  munmap((void*)dp->ctlmap, dp->contentsize);
	dp->ctlmap = NULL;
#endif
	if (dp->ctlfd >= 0)
	  close(dp->ctlfd);
	if (dp->msgfd >= 0)
	  close(dp->msgfd);
	for (ap = dp->senders; ap != NULL; ap = nextap) {
	  nextap = ap->link;
	  free((char *)ap);
	}
	dp->senders = NULL;
	for (rp = dp->recipients; rp != NULL; rp = nextrp) {
	  nextrp = rp->next;
	  ap = rp->addr;
	  if (ap->routermxes) {
	    free((char *)ap->routermxes);
	  }
	  if (rp->top_received) ctlfree(dp, rp->top_received);
	
	  free((char *)rp);
	}
	dp->recipients = NULL;
	/* Free ALL dp->msgheader's, if they have been reallocated.
	   Don't free on individual recipients, only on this global set.. */
	for (msghpp = dp->msgheaders; msghpp &&  *msghpp; ++msghpp) {
	  char **msghp = *msghpp;
	  for ( ; msghp && *msghp ; ++msghp )
	    ctlfree(dp,*msghp);
	  free(*msghpp);
	}
	free(dp->msgheaders);
	dp->msgheaders = NULL;
	for (msghpp = dp->msgheaderscvt; msghpp &&  *msghpp; ++msghpp) {
	  char **msghp = *msghpp;
	  for ( ; msghp && *msghp ; ++msghp )
	    free(*msghp); /* These CVTs are always malloc()ed strings */
	  free(*msghpp);
	}
	free(dp->msgheaderscvt);
	dp->msgheaderscvt = NULL;

	if (dp->offset != NULL)
	  free((void*)dp->offset);
	dp->offset = NULL;

	if (dp->contents != NULL)
	  free((void*)dp->contents);
	dp->contents = NULL;
	if (dp->taspoolid)
	  free((void*)dp->taspoolid);
	dp->taspoolid = NULL;
}


static struct taddress *
ctladdr(cp)
	char *cp;
{
	struct taddress *ap;

	ap = (struct taddress *)malloc(sizeof (struct taddress));
	if (ap == NULL)
		return NULL;
	ap->link = NULL;

	/* While space: */
	while (*cp == ' ' || *cp == '\t') ++cp;

	/* CHANNEL: */
	ap->channel = cp;
	cp = skip821address(cp);
	if (*cp) *cp++ = '\0';

	/* While space: */
	while (*cp == ' ' || *cp == '\t') ++cp;

	/* HOST: */
	ap->host = cp;
	ap->routermxes = NULL;
	if (*cp == '(')
	  cp = routermxes(cp,ap);  /* It is a bit complex.. */
	else {
	  /* While not space: */
	  cp = skip821address(cp);
	  if (*cp) *cp++ = '\0';
	}

	/* While space: */
	while (*cp == ' ' || *cp == '\t') ++cp;

	/* USER: */
	ap->user = cp;
	cp = skip821address(cp);
	if (*cp) *cp++ = '\0';

	/* PRIVILEGE: */
	ap->misc = cp;
	return ap;
}

#ifdef __STDC__

struct ctldesc *
ctlopen(const char *file, const char *channel, const char *host,
	int *exitflagp, int (*selectaddr)(const char *, const char *, void *),
	void *saparam,  int (*matchrouter)(const char *, struct taddress *, void *),
	void *mrparam)

#else

struct ctldesc *
ctlopen(file, channel, host, exitflagp, selectaddr, saparam, matchrouter, mrparam)
	const char *file, *channel, *host;
	int *exitflagp;
	int (*selectaddr)  __((const char *, const char *, void *));
	void *saparam;
	int (*matchrouter) __((const char *, struct taddress *, void *));
	void *mrparam;

#endif
{
	register char *s, *contents;
	char *mfpath, *delayslot;
	int  i, n;
	struct taddress *ap;
	struct rcpt *rp = NULL, *prevrp = NULL;
	struct stat stbuf;
	char ***msgheaders = NULL;
	char ***msgheaderscvt = NULL;
	int  headers_cnt;
	int  headers_spc;
	int  largest_headersize = 80; /* Some magic minimum.. */
	char dirprefix[8];
	char spoolid[30];
	int  mypid = getpid();
	long format = 0;

	static struct ctldesc d; /* ONLY ONE OPEN AT THE TIME! */

	if (selectaddr == ctlsticky)
	  ctlsticky(NULL,NULL,NULL); /* Reset the internal state.. */

	memset(&d,0,sizeof(d));
	if (*file >= 'A') {
	  char *p;
	  /* Has some hash subdirectory in front of itself */
	  strncpy(dirprefix,file,sizeof(dirprefix));
	  dirprefix[sizeof(dirprefix)-1] = 0;
	  p = strrchr(dirprefix,'/');
	  if (p) *++p = 0;
	  /*  "A/B/"  */
	} else
	    dirprefix[0] = 0;


	d.msgfd = -1; /* The zero is not always good for your health .. */
	d.ctlfd = open(file, O_RDWR, 0);
	if (d.ctlfd < 0) {
	  char cwd[MAXPATHLEN], buf[MAXPATHLEN+MAXPATHLEN+100];
	  int e = errno;	/* Save it over the getwd() */

#ifdef	HAVE_GETCWD
	  getcwd(cwd,MAXPATHLEN);
#else
	  getwd(cwd);
#endif
	  sprintf(buf,
		  "Cannot open control file \"%%s\" from \"%s\" for \"%%s/%%s\" as uid %d!",
		  cwd, (int)geteuid());
	  errno = e;
	  if (host == NULL)
	    host = "-";
	  warning(buf, file, channel, host);
	  return NULL;
	}
	if (fstat(d.ctlfd, &stbuf) < 0) {
	  warning("Cannot stat control file \"%s\"! (%m)", file);
	  close(d.ctlfd);
	  return NULL;
	}
	if (!S_ISREG(stbuf.st_mode)) {
	  warning("Control file \"%s\" is not a regular file!", file);
	  close(d.ctlfd);
	  return NULL;
	}
	/* 4 is the minimum number of characters per line */
	n = sizeof (long) * (stbuf.st_size / 4);
	d.contents = contents = s = malloc((u_int)stbuf.st_size+1);
	if (d.contents == NULL) {
	  warning("Out of virtual memory!", (char *)NULL);
	  exit(EX_SOFTWARE);
	}
	d.offset = (long *)malloc((u_int)n);
	if (d.offset == NULL) {
	  warning("Out of virtual memory!", (char *)NULL);
	  exit(EX_SOFTWARE);
	}

	fcntl(d.ctlfd, F_SETFD, 1); /* Close-on-exec */

#if defined(HAVE_MMAP) && defined(TA_USE_MMAP)
#ifndef MAP_VARIABLE
# define MAP_VARIABLE 0
#endif
#ifndef MAP_FILE
# define MAP_FILE 0
#endif
	/* We do recipient locking via MMAP_SHARED RD/WR ! Less syscalls.. */
	d.ctlmap = (char *)mmap(NULL, stbuf.st_size,
				PROT_READ|PROT_WRITE,
				MAP_FILE|MAP_SHARED|MAP_VARIABLE,
				d.ctlfd, 0);
	if ((int)d.ctlmap == -1)
	  d.ctlmap = NULL; /* Failed ?? */
#else
	d.ctlmap = NULL;
#endif
	d.contentsize = (int) stbuf.st_size;
	contents[ d.contentsize ] = 0; /* Treat it as a long string.. */
	if (read(d.ctlfd, contents, d.contentsize) != d.contentsize) {
	  warning("Wrong size read from control file \"%s\"! (%m)",
		  file);
	  free((void*)d.contents);
	  d.contents = NULL;
	  free((void*)d.offset);
	  d.offset = NULL;
	  close(d.ctlfd);
	  return NULL;
	}
	n = markoff(contents, d.contentsize, d.offset, file);
	if (n < 4) {
	  /*
	   * If it is less than the minimum possible number of control
	   * lines, then there is something wrong...
	   */
	  free((void*)d.contents);
	  d.contents = NULL;
	  free((void*)d.offset);
	  d.offset = NULL;
	  close(d.ctlfd);
#if defined(HAVE_MMAP) && defined(TA_USE_MMAP)
	  if (d.ctlmap != NULL)
	    munmap((void*)d.ctlmap, d.contentsize);
#endif	  
	  /* Is it perhaps just the ETRN request file ?
	     and manual expirer gave it to us ?  Never mind then.. */
	  if (contents[0] == _CF_TURNME)
	    return NULL;

	  warning("Truncated or illegal control file \"%s\"!", file);
	  /* exit(EX_PROTOCOL); */
	  sleep(60);
	  return NULL;
	}

	s = strrchr(file,'/');	/* In case the file in in a subdir.. */
	if (s)
	  d.ctlid = atol(s+1);
	else
	  d.ctlid = atol(file);
	d.senders = NULL;
	d.recipients = NULL;
	d.rcpnts_total = 0;
	d.rcpnts_remaining = 0;
	d.rcpnts_failed = 0;
	d.logident   = "none";
	d.envid      = NULL;
	d.dsnretmode = NULL;
	d.verbose    = NULL;

	headers_cnt = 0;
	headers_spc = 2;
	for (i = 0; i < n; ++i)
	  if (contents[ d.offset[i] ] == _CF_MSGHEADERS)
	    ++headers_spc;

	msgheaders = (char***)malloc(sizeof(char***) *
				     (headers_spc+1));
	msgheaderscvt = (char***)malloc(sizeof(char***) *
					(headers_spc+1));

	/* run through the file and set up the information we need */
	for (i = 0; i < n; ++i) {
	  if (*exitflagp && d.recipients == NULL)
	    break;
	  /* Shudder... we trash the memory block here.. */
	  s = contents + d.offset[i];
	  switch (*s) {
	  case _CF_FORMAT:
	    ++s;
	    format = 0;
	    sscanf(s,"%li",&format);
	    if (format & (~_CF_FORMAT_KNOWN_SET)) {
	      warning("Unsupported SCHEDULER file format flags seen: 0x%x at file '%s'",
		      format, file);
	      *exitflagp = 1;
	      break;
	    }
	    break;
	  case _CF_SENDER:
	    ap = ctladdr(s+2);
	    ap->link  = d.senders;
	    /* Test if this is "error"-channel..
	       If it is,  ap->user  points to NUL string. */
	    /* mea: altered the scheme, we must detect the "error" channel
	       otherwise */
	    /* if (strcmp(ap->channel,"error")==0)
	         ap->user = ""; */
	    d.senders = ap;
	    break;
	  case _CF_RECIPIENT:
	    ++s;
	    /* Calculate statistics .. Scheduler asks for it.. */
	    d.rcpnts_total += 1;
	    if (*s == _CFTAG_NOTOK) {
	      d.rcpnts_failed    += 1;
	      prevrp = NULL;
	    } else if (*s != _CFTAG_OK) {
	      d.rcpnts_remaining += 1;
	    }

	    if (*s != _CFTAG_NORMAL || d.senders == NULL)
	      break;

	    ++s;
	    /* Unconditionally expecting _CF_FORMAT_TA_PID !! */
	    s += _CFTAG_RCPTPIDSIZE;
	    delayslot = NULL;
	    if ((format & _CF_FORMAT_DELAY1) || *s == ' ' ||
		(*s >= '0' && *s <= '9')) {
	      /* Newer DELAY data slot - _CFTAG_RCPTDELAYSIZE bytes */
	      delayslot = s;
	      s += _CFTAG_RCPTDELAYSIZE;
	    }
	    if ((ap = ctladdr(s)) == NULL) {
	      warning("Out of virtual memory!", (char *)NULL);
	      *exitflagp = 1;
	      break;
	    }

	    /* [mea] understand  'host' of type:
	       "((mxer)(mxer mxer))"   */
	    if ((channel != NULL
		 && strcmp(channel, ap->channel) != 0)
#if 1
		|| (ap->routermxes != NULL && matchrouter != NULL
		    && !(*matchrouter)(host, ap, mrparam))
#endif
		|| (ap->routermxes == NULL && selectaddr != NULL
		    && !(*selectaddr)(host, (const char *)ap->host, saparam))
		|| (ap->routermxes == NULL && selectaddr == NULL
		    && host != NULL && cistrcmp(host,ap->host) !=0)
		|| !lockaddr(d.ctlfd, d.ctlmap, d.offset[i]+1,
			     _CFTAG_NORMAL, _CFTAG_LOCK, file, host, mypid)) {
	      if (ap->routermxes)
		free((char *)ap->routermxes);
	      ap->routermxes = NULL;
	      free((char *)ap);
	      break;
	    }
	    ap->link = d.senders; /* point at sender address */
	    rp = (struct rcpt *)malloc(sizeof (struct rcpt));
	    if (rp == NULL) {
	      lockaddr(d.ctlfd, d.ctlmap, d.offset[i]+1,
		       _CFTAG_LOCK, _CFTAG_DEFER, file, host, mypid);
	      warning("Out of virtual memory!", (char *)NULL);
	      *exitflagp = 1;
	      break;
	    }
	    memset(rp, 0, sizeof(*rp));
	    rp->addr = ap;
	    rp->delayslot = delayslot;
	    rp->id = d.offset[i];
	    /* XX: XOR locks are different */
	    rp->lockoffset = rp->id + 1;
	    rp->next = d.recipients;
	    rp->desc = &d;
	    /* rp->orcpt  = NULL;
	       rp->inrcpt = NULL;
	       rp->ezmlm  = NULL;
	       rp->notify = NULL; */
	    rp->notifyflgs = _DSN_NOTIFY_FAILURE; /* Default behaviour */
	    d.recipients = rp;
	    rp->status = EX_OK;
	    /* rp->newmsgheader = NULL; */
	    rp->drptoffset   = -1;
	    rp->headeroffset = -1;
	    prevrp = rp;
	    break;
	  case _CF_RCPTNOTARY:
	    /*  IETF-NOTARY-DSN  DATA */
	    ++s;
	    if (prevrp != NULL) {
	      prevrp->drptoffset = d.offset[i];
	      while (*s) {
		while (*s && (*s == ' ' || *s == '\t')) ++s;
		if (CISTREQN("NOTIFY=",s,7)) {
		  char *p;
		  s += 7;
		  prevrp->notify = p = s;
		  while (*s && *s != ' ' && *s != '\t') ++s;
		  if (*s) *s++ = 0;
		  prevrp->notifyflgs = 0;
		  while (*p) {
		    if (CISTREQN("NEVER",p,5)) {
		      p += 5;
		      prevrp->notifyflgs |= _DSN_NOTIFY_NEVER;
		    } else if (CISTREQN("DELAY",p,5)) {
		      p += 5;
		      prevrp->notifyflgs |= _DSN_NOTIFY_DELAY;
		    } else if (CISTREQN("SUCCESS",p,7)) {
		      p += 7;
		      prevrp->notifyflgs |= _DSN_NOTIFY_SUCCESS;
		    } else if (CISTREQN("FAILURE",p,7)) {
		      p += 7;
		      prevrp->notifyflgs |= _DSN_NOTIFY_FAILURE;
		    } else if (CISTREQN("TRACE",p,5)) {
		      p += 5;
		      prevrp->notifyflgs |= _DSN_NOTIFY_TRACE;
		    } else
		      break; /* Burp !? */
		    if (*p == ',') ++p;
		  }
		  continue;
		}
		if (CISTREQN("BY=",s,3)) {
		  long val = 0;
		  int  neg = 0, cnt = 0;
		  s += 3;
		  if (*s == '-') neg = 1, ++s;
		  while ('0' <= *s && *s <= '9') {
		    val = val * 10L + (*s - '0');
		    ++cnt;
		    ++s;
		  }
		  if (neg) val = -val;
		  prevrp->deliverby = val;
		  if (*s == ';') ++s;
		  while (*s && *s != ' ' && *s != '\t') {
		    switch (*s) {
		    case 'R': case 'r':
		      prevrp->deliverbyflgs |= _DELIVERBY_R;
		      break;
		    case 'N': case 'n':
		      prevrp->deliverbyflgs |= _DELIVERBY_N;
		      break;
		    case 'T': case 't':
		      prevrp->deliverbyflgs |= _DELIVERBY_T;
		      break;
		    default:
		      break;
		    }
		    ++s;
		  }
		  while (*s && *s != ' ' && *s != '\t') ++s;
		  if (*s) *s++ = 0;
		  continue;
		}
		if (CISTREQN("ORCPT=",s,6)) {
		  s += 6;
		  prevrp->orcpt = s;
		  while (*s && *s != ' ' && *s != '\t') ++s;
		  if (*s) *s++ = 0;
		  continue;
		}
		if (CISTREQN("INRCPT=",s,7)) {
		  s += 7;
		  prevrp->inrcpt = s;
		  while (*s && *s != ' ' && *s != '\t') ++s;
		  if (*s) *s++ = 0;
		  continue;
		}
		if (CISTREQN("INFROM=",s,7)) {
		  s += 7;
		  prevrp->infrom = s;
		  while (*s && *s != ' ' && *s != '\t') ++s;
		  if (*s) *s++ = 0;
		  continue;
		}
		if (CISTREQN("EZMLM=",s,6)) {
		  s += 6;
		  prevrp->ezmlm = s;
		  while (*s && *s != ' ' && *s != '\t') ++s;
		  if (*s) *s++ = 0;
		  continue;
		}
		/* XX: BOO! Unknown value! */
		while (*s && *s != ' ' && *s != '\t') ++s;
	      }
	      /* Previous entry added, no more..! */
	      prevrp = NULL;
	    }
	    break;
	  case _CF_MSGHEADERS:
	    {
	      char **msgheader = NULL;
	      char *ss;
	      int  headerlines = 0;
	      int  headerspace = 0;
	      int  headersize  = strlen(s);

	      if (headersize > largest_headersize)
		largest_headersize = headersize;
	      /* position pointer at start of the header */
	      while (*s && *s != '\n')
		++s;
	      ++s;

	      /* Collect all the headers into individual "lines",
		 keep folding information ('\n' chars) in them,
		 if some particular header happens to be a folded one.. */

	      while (*s) {
		if (headerlines == 0) {
		  msgheader = (char **)malloc(sizeof(char**) * 8);
		  headerspace = 7;
		}
		if (headerlines >= headerspace) {
		  headerspace += 8;
		  msgheader = (char**)realloc((void*) msgheader,
					      sizeof(void*) * (headerspace+1));
		}
		ss = s;
		/* Scan the string, until we see a newline *not* followed
		   by a SPACE, or a TAB. */
		while (*ss) {
		  while (*ss && *ss != '\n') ++ss;
		  if (*ss == '\n' && (ss[1] == ' ' || ss[1] == '\t'))
		    ++ss;
		  else
		    break;
		}
		if (*ss == '\n') *ss++ = '\0';
		msgheader[headerlines++] = s;
		msgheader[headerlines  ] = NULL;
		s = ss;
	      }

	      /* And the global connection.. */
	      msgheaders   [headers_cnt] = msgheader;
	      msgheaderscvt[headers_cnt] = NULL;

	      /* fill in header * of recent recipients */
	      for (rp = d.recipients;
		   rp != NULL && rp->newmsgheader == NULL;
		   rp = rp->next) {
		rp->newmsgheader    = &msgheaders   [headers_cnt];
		rp->newmsgheadercvt = &msgheaderscvt[headers_cnt];
		rp->headeroffset    = d.offset[i] + 2;
	      }

	      msgheaders   [++headers_cnt] = NULL;
	      msgheaderscvt[  headers_cnt] = NULL;
	    }
	    break;
	  case _CF_MESSAGEID:
	    d.msgfile = s+2;
	    break;
	  case _CF_DSNENVID:
	    d.envid = s+2;
	    break;
	  case _CF_DSNRETMODE:
	    d.dsnretmode = s+2;
	    break;
	  case _CF_BODYOFFSET:
	    d.msgbodyoffset = (long)atoi(s+2);
	    break;
	  case _CF_LOGIDENT:
	    d.logident = s+2;
	    break;
	  case _CF_VERBOSE:
	    d.verbose = s+2;
	    break;
	  default:		/* We don't use them all... */
	    break;
	  }
	}

	/* Sometimes we bail out before terminating NULLs are added..
	   probably before anything is added. */
	msgheaders   [headers_cnt] = NULL;
	msgheaderscvt[headers_cnt] = NULL;

	d.msgheaders    = msgheaders;		/* Original headers	*/
	d.msgheaderscvt = msgheaderscvt;	/* Modified set		*/

	if (d.recipients == NULL) {
	  ctlclose(&d);
	  return NULL;
	}

#ifdef USE_ALLOCA
	mfpath = alloca((u_int)5 + sizeof(QUEUEDIR)
			+ strlen(dirprefix) + strlen(d.msgfile));
#else
	mfpath = malloc((u_int)5 + sizeof(QUEUEDIR)
			+ strlen(dirprefix) + strlen(d.msgfile));
#endif
	sprintf(mfpath, "../%s/%s%s", QUEUEDIR, dirprefix, d.msgfile);
	if ((d.msgfd = open(mfpath, O_RDONLY, 0)) < 0) {
	  int e = errno;
	  for (rp = d.recipients; rp != NULL; rp = rp->next) {
	    diagnostic(NULL, rp, EX_UNAVAILABLE, 0,
		       "message file is missing(!) -- possibly due to delivery scheduler restart.  Consider resending your message");
	  }
	  errno = e;
	  warning("Cannot open message file \"%s\"! (errno=%d)", mfpath, errno);
#ifndef USE_ALLOCA
	  free(mfpath);
#endif
	  ctlclose(&d);
	  return NULL;
	}
	if (fstat(d.msgfd,&stbuf) < 0) {
	  stbuf.st_mode = S_IFCHR; /* Make it to be something what it
				      clearly can't be.. */
	}
	if (!S_ISREG(stbuf.st_mode)) {
	  for (rp = d.recipients; rp != NULL; rp = rp->next) {
	    diagnostic(NULL, rp, EX_UNAVAILABLE, 0,
		       "Message file is not a regular file!");
	  }
	  warning("Cannot open message file \"%s\"! (%m)", mfpath);
#ifndef USE_ALLOCA
	  free(mfpath);
#endif
	  ctlclose(&d);
	  close(d.msgfd);
	  return NULL;
	}

	d.msginonumber = (long)stbuf.st_ino;

	fcntl(d.msgfd, F_SETFD, 1); /* Close-on-exec */

#if defined(HAVE_MMAP) && defined(TA_USE_MMAP)
	d.let_buffer = (char *)mmap(NULL, stbuf.st_size, PROT_READ,
				    MAP_FILE|MAP_SHARED|MAP_VARIABLE,
				    d.msgfd, 0);
	if ((long)d.let_buffer == -1L) {
	  warning("Out of MMAP() memory! Tried to map in (r/o) %d bytes (%m)",
		  stbuf.st_size);
#ifndef USE_ALLOCA
	  free(mfpath);
#endif
	  ctlclose(&d);
	  close(d.msgfd);
	  return NULL;
	}
	d.let_end    = d.let_buffer + stbuf.st_size;
#endif

#ifndef USE_ALLOCA
	  free(mfpath);
#endif

	/* The message file mtime -- arrival of the message to the system */
	d.msgmtime = stbuf.st_mtime;

	/* Estimate the size of the message file when sent out.. */
	d.msgsizeestimate  = stbuf.st_size - d.msgbodyoffset;
	d.msgsizeestimate += largest_headersize;
	/* A nice fudge factor, usually this is enough..                 */
	/* Add 3% for CRLFs.. -- assume average line length of 35 chars. */
	d.msgsizeestimate += (3 * d.msgsizeestimate) / 100;

	taspoolid(spoolid, d.msgmtime, d.msginonumber);
	d.taspoolid = strdup(spoolid);
	if (!d.taspoolid) {
	  ctlclose(&d);
	  close(d.msgfd);
	  return NULL;
	}

	return &d;
}

int
ctlsticky(spec_host, addr_host, cbparam)
	const char *spec_host, *addr_host;
	void *cbparam;
{
	static const char *hostref = NULL;

	if (hostref == NULL) {
	  if (spec_host != NULL)
	    hostref = spec_host;
	  else
	    hostref = addr_host;
	}
	if (spec_host == NULL && addr_host == NULL) {
	  hostref = NULL;
	  return 0;
	}
	return cistrcmp(hostref, addr_host) == 0;
}
