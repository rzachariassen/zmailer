/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * This file contains most of the RFC822-specific message manipulation.
 */

#include "mailer.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <fcntl.h>
#include <sys/file.h>
#include <errno.h>
#include "mail.h"
#include "libz.h"
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include "zsyslog.h"

#include "prototypes.h"
#include "libsh.h"

#ifndef _IOFBF
#define _IOFBF  0
#endif  /* !_IOFBF */
#ifndef _IOLBF
#define _IOLBF  0200
#endif  /* !_IOFBF */

#ifdef	HAVE_LOCKF
#ifdef	F_OK
#undef	F_OK
#endif	/* F_OK */
#ifdef	X_OK
#undef	X_OK
#endif	/* X_OK */
#ifdef	W_OK
#undef	W_OK
#endif	/* W_OK */
#ifdef	R_OK
#undef	R_OK
#endif	/* R_OK */

#endif	/* HAVE_LOCKF */

static void	reject __((struct envelope *e, const char *msgfile));

static const char * prctladdr __((conscell *info, FILE *fp, int cfflag, const char *comment));
static void	prdsndata __((conscell *info, FILE *fp, const char *comment));
static conscell	*find_errto __((conscell *list));

#define dprintf	if (D_sequencer) printf

#define	QCHANNEL(x)	(x)
#define	QHOST(x)	cdr(x)
#define	QUSER(x)	cddr(x)
#define	QATTRIBUTES(x)	cdr(cddr(x))


conscell *
makequad()
{
	conscell *l;
	GCVARS1;

	l = NULL;
	GCPRO1(l);

	l = conststring(NULL, 0);
	cdr(l) = conststring(NULL, 0);
	cddr(l) = conststring(NULL, 0);
	cdr(cddr(l)) = conststring(NULL, 0);

	UNGCPRO1;
	return l;
}

struct envelope *qate;

int
iserrmessage()
{
	return (qate      &&   qate->e_from_trusted   &&
		(QCHANNEL(qate->e_from_trusted)->cstring == NULL ||
		 CISTREQ(QCHANNEL(qate->e_from_trusted)->cstring, "error")));
}


static int zunlink __((const char *));
static int zunlink(path)
     const char *path;
{
  int rc;
  while ((rc = unlink(path)) < 0 && (errno == EBUSY || errno == EINTR))
    ;
  return rc;
}




/*
 * Apply RFC822 parsing and processing to the message in the file in argv[1].
 */

int
run_rfc822(argc, argv)
	int argc;
	const char *argv[];
{
	struct envelope *e; /* TWO GC PROTECTABLE ITEMS! */
	const char *file;
	char buf[8196];   /* FILE* buffer, will be released at fclose() */
	int status = PERR_OK, errflg;
	memtypes oval;
	GCVARS2;

	errflg = 0;
#if 0
	{
	  int c;
	  while ((c = getopt(argc, argv, "")) != EOF) {
	    switch (c) {
	    default:
	      ++errflg;
	      break;
	    }
	  }
	}
	if (errflg || optind != (argc - 1))
#endif
	if (argc != 2)
	  {
		fprintf(stderr, "Usage: %s messagefile\n", argv[0]);
		return PERR_USAGE;
	}

	/* file = argv[optind]; */
	file = argv[1];

#ifdef	XMEM
	mal_contents(stdout);
#endif	/* XMEM */
	oval = stickymem;
	stickymem = MEM_TEMP;	/* per-message space */

	e = (struct envelope *)tmalloc(sizeof (struct envelope));
	/* XXX: If this tmalloc() fails, we crash! */
	memset(e, 0, sizeof(*e)); /* Lots of pointers, etc here! */
	GCPRO2(e->e_from_trusted, e->e_from_resolved);
	qate = e;

	if ((e->e_fp = fopen(file, "r")) == NULL) {
	  fprintf(stderr, "router: cannot open %s\n", file);
	  status = PERR_BADOPEN;
	} else {
	  /* XX: DEBUG STUFF! */
	  if (FILENO(e->e_fp) < 3) {
	    fprintf(stderr,"RFC822: While opening mail-file '%s', got fd=%d  AARGH! (fds 0..2 should never close on us!)",
		    file, FILENO(e->e_fp));
	    fflush(stderr);
	    /* abort(); */
	  }
	  status = PERR_OK;
	  setvbuf(e->e_fp, buf, _IOFBF, sizeof buf);
	  e->e_file = file;
	  status = makeLetter(e, 0);
	}

	if (status == PERR_OK)
	  /* passing the file is redundant but nice for backtraces */
	  status = sequencer(e, file);

	switch (status) {
	case PERR_OK:		/* 0 */
		break;
	case PERR_BADOPEN:
		break;
	case PERR_BADCONTINUATION:	/* fatal */
		squirrel(e, "badenvelope", "continuation line prior to header");
		break;
	case PERR_BADSUBMIT:		/* fatal */
		squirrel(e, "badsubmit", "unrecognized envelope information");
		break;
	case PERR_LOOP:			/* fatal */
		reject(e, "loopexceeded");
		squirrel(e, "_looped", "loop count exceeded");
		break;
	case PERR_ENVELOPE:		/* fatal */
		reject(e, "envelope");
		break;
	case PERR_DEFERRED:
		if (deferuid)
		  defer(e, "deferuid");
		else
		  defer(e, "deferred");
		break;
	case PERR_HEADER:		/* fatal */
		reject(e, "header");
		break;
	case PERR_NORECIPIENTS:		/* fatal */
		reject(e, "norecipients");
		break;
	case PERR_NOSENDER:
		squirrel(e, "nosender", "really truly Unknown Sender");
		break;
	case PERR_CTRLFILE:
		defer(e, "ctrlfile");
		break;
	default:
		abort(); /* Impossible processing status */
	}

	if (D_final > 0)
		dumpInfo(e);

	/* This will always make some noise in successfull case,
	   except that it is SILENT code... */

	if (status != PERR_CTRLFILE && status != PERR_DEFERRED && !savefile)
		(void) zunlink(file); /* SILENT! */

	if (e->e_fp)
		fclose(e->e_fp);
	tfree(MEM_TEMP);
	stickymem = oval;
#ifdef	XMEM
	mal_contents(stdout);
#endif	/* XMEM */
	UNGCPRO2;
	return status;
}

/*
 * Read, store, and parse the message control information (envelope + header).
 */

int
makeLetter(e, octothorp)
	register struct envelope *e;
	int octothorp;		/* does # at start of word start a comment? */
{
	register int	i;
	register char	*cp;
	struct header	*h;
	int		n, inheader;
	struct header	*ph, *nh;

	e->e_eHeaders = 0;
	e->e_headers = 0;
	e->e_hdrOffset = 0;
	e->e_msgOffset = 0;
	e->e_nowtime = now = time(NULL);
	if (efstat(FILENO(e->e_fp), &(e->e_statbuf)) < 0) {
#ifdef	HAVE_ST_BLKSIZE
		e->e_statbuf.st_blksize = 0;
#endif	/* !HAVE_ST_BLKSIZE */
		e->e_statbuf.st_mtime = e->e_nowtime;
	}
	e->e_localtime = *(localtime(&(e->e_statbuf.st_mtime)));
#ifdef	HAVE_ST_BLKSIZE
	initzline((int)e->e_statbuf.st_blksize);
#else	/* !HAVE_ST_BLKSIZE */
	initzline(4096);
#endif	/* !HAVE_ST_BLKSIZE */

	inheader = 0;
	while ((n = zgetline(e->e_fp)) > !octothorp) {
		/* We do kludgy processing things in case the input
		   does have a CRLF at the end of the line.. */
		if (n > 1 &&
		    zlinebuf[n-2] == '\r' &&
		    zlinebuf[n-1] == '\n') {
			--n;
			zlinebuf[n-1] = '\n';
			if (n <= !octothorp) break;
		}
		/* Ok, now we can proceed with the original agenda.. */
		i = hdr_status(zlinebuf, zlinebuf, n, octothorp);
		if (i > 0) {		/* a real message header */
			if (octothorp && zlinebuf[0] == '#')
				continue;
			/* record start of headers for posterity */
			if (!inheader)
			  e->e_hdrOffset = zlineoffset(e->e_fp)-n;
			/* cons up a new one at top of header list */
			h = makeHeader(spt_headers, zlinebuf, i);
			h->h_next = e->e_headers;
			e->e_headers = h;
			h->h_lines = makeToken(zlinebuf+i+1, n-i-2);
			h->h_lines->t_type = Line;
			++inheader;
		} else if (i == 0) {	/* a continuation line */
			if (inheader && zlinebuf[0] == ':') {
				optsave(FYI_ILLHEADER, e);
				/* cons up a new one at top of header list */
				h = makeHeader(spt_headers,"X-Null-Field",12);
				h->h_next = e->e_headers;
				e->e_headers = h;
				h->h_lines = makeToken(zlinebuf+i+1, n-i-2);
				h->h_lines->t_type = Line;
			} else if (inheader && n > 1) {
				/* append to the header we just saw */
				token822 *t;
				if (e->e_headers == NULL) {
				  /* Wow, continuation without previous header! */
				  /* It must be body.. */
				  repos_zgetline(e->e_fp,
						 zlineoffset(e->e_fp) - n);
				  break;
				}
				t = e->e_headers->h_lines;
				while (t->t_next)
					t = t->t_next;
				t->t_next = makeToken(zlinebuf, n-1);
				t->t_next->t_type = Line;
			} else if (!octothorp) {
				return PERR_BADCONTINUATION;
			}
		} else if (!inheader		/* envelope information */
			   && (*(cp=zlinebuf-i) == ' ' || *cp == '\t'
				|| *cp == '\n')) {
			HeaderSemantics osem;

			if (octothorp && zlinebuf[0] == '#')
				continue;
			/* cons up a new one at top of envelope header list */
			h = makeHeader(spt_eheaders, zlinebuf, -i);
			h->h_next = e->e_eHeaders;
			e->e_eHeaders = h;
			h->h_lines = makeToken(zlinebuf-i+1, n > 1-i ? n+i-2: 0);
			h->h_lines->t_type = Line;
			switch (h->h_descriptor->class) {

			case normal:
			case Resent:
				/* error */
				fprintf(stderr,
					"%s: unknown envelope header (class %d): ",
					progname, h->h_descriptor->class);
				fwrite((char *)zlinebuf, sizeof (char), -i, stderr);
				putc('\n', stderr);
				h->h_contents = hdr_scanparse(e, h, octothorp, 0);
				h->h_stamp = hdr_type(h);
				return PERR_BADSUBMIT;
				/* break; */
			case eFrom:		/* pity to break the elegance */
				osem = h->h_descriptor->semantics;
				h->h_descriptor->semantics = Mailbox;
				h->h_contents = hdr_scanparse(e, h, octothorp, 0);
				h->h_stamp = hdr_type(h);
				h->h_descriptor->semantics = osem;
				break;
			case eEnvEnd:		/* more elegance breaks */
				inheader = 1;
				/* record start of headers for posterity */
				e->e_hdrOffset = zlineoffset(e->e_fp);
				e->e_eHeaders = h->h_next;
				break;
			default:		/* a real envelope header */
				h->h_contents = hdr_scanparse(e, h, octothorp, 0);
				h->h_stamp = hdr_type(h);
				break;
			}
		} else if (!octothorp) {
			/* Expected RFC-822 header, and got something else.
			   We play as if it was the end of the headers, and
			   start of the body.  Keep the first faulty input
			   around by reseeking into its start.		    */
			repos_zgetline(e->e_fp, zlineoffset(e->e_fp) - n);
			break;
		}
	}
	/* reverse the list of headers so we keep them in the original order */
	for (ph = NULL, h = e->e_eHeaders; h != NULL; h = nh) {
		nh = h->h_next;
		h->h_next = ph;
		if (h->h_descriptor->semantics == nilHeaderSemantics
		    || !hdr_nilp(h))
			ph = h;
	}
	e->e_eHeaders = ph;
	/* parse the message headers -- we already took care of envelope info */
	for (ph = NULL, h = e->e_headers; h != NULL; h = nh) {
		nh = h->h_next;
		h->h_next = ph;
		if (!octothorp && h->h_descriptor) {
			h->h_contents = hdr_scanparse(e, h, 0, 0);
			h->h_stamp = hdr_type(h);
			if (!hdr_nilp(h))	/* excise null-valued headers */
				ph = h;
		} else
			ph = h;
	}
	e->e_headers = ph;
	/* record the start of the message body for posterity */
	e->e_msgOffset = zlineoffset(e->e_fp);

	return PERR_OK;
}

void
dumpInfo(e)
	struct envelope *e;
{
	printf("Message header starts at byte %ld.\n", e->e_hdrOffset);
	printf("Message body starts at byte %ld.\n", e->e_msgOffset);
	printf("ENVELOPE:\n");
	dumpHeaders(e->e_eHeaders);
	printf("HEADERS:\n");
	dumpHeaders(e->e_headers);
}

void
dumpHeaders(h)
	struct header *h;
{
	for (; h != NULL; h = h->h_next)
		dumpHeader(h);
}

void
dumpHeader(h)
	struct header *h;
{
	token822	*t;
	struct address	*a;
	struct addr	*p;

	if (h->h_stamp == BadHeader)
		hdr_errprint(NULL, h, stdout, "header");
	printf("%s\n", h->h_pname);
	if (h->h_descriptor == NULL)
		return;
	switch (h->h_descriptor->semantics) {
	case DateTime:
		printf("\tUNIX time %ld, local time %s",
			h->h_contents.d, ctime(&(h->h_contents.d)));
		break;
	case nilHeaderSemantics:
		for (t = h->h_lines; t != NULL; t = t->t_next)
			printf("\t%s\n", formatToken(t));
		for (t = h->h_contents.t; t != NULL; t = t->t_next)
			printf("\t%s\n", formatToken(t));
		break;
	case Received:
		if (h->h_contents.r == NULL)
			break;
		if ((a = h->h_contents.r->r_from) != NULL) {
			printf("\tFrom:\n");
			for (p = a->a_tokens; p != NULL; p=p->p_next) {
				printf("\t%s:\n", formatAddr(p->p_type));
				for (t = p->p_tokens; t != NULL; t = t->t_next)
					printf("\t\t%s\n", formatToken(t));
			}
		}
		if ((a = h->h_contents.r->r_by) != NULL) {
			printf("\tBy:\n");
			for (p = a->a_tokens; p != NULL; p=p->p_next) {
				printf("\t%s:\n", formatAddr(p->p_type));
				for (t = p->p_tokens; t != NULL; t = t->t_next)
					printf("\t\t%s\n", formatToken(t));
			}
		}
		if ((t = h->h_contents.r->r_via) != NULL)
			printf("\tVia: %s\n", formatToken(t));
		for (t = h->h_contents.r->r_with; t != NULL; t = t->t_next)
			printf("\tWith: %s\n", formatToken(t));
		if ((t = h->h_contents.r->r_convert) != NULL)
			printf("\tConvert: %s\n", formatToken(t));
		printf("\tUNIX time %ld, local time %s",
			h->h_contents.r->r_time,
			ctime(&(h->h_contents.r->r_time)));
		break;
	default:
		for (a = h->h_contents.a; a != NULL; a = a->a_next) {
			for (p = a->a_tokens; p != NULL; p=p->p_next) {
				printf("\t%s:\n", formatAddr(p->p_type));
				for (t = p->p_tokens; t != NULL; t = t->t_next)
					printf("\t\t%s\n", formatToken(t));
			}
			printf("--- end of address ---\n");
		}
		break;
	}
}


/*
 * The following two variables are set so header address rewriting functions
 * can find out whether they are dealing with a sender or recipient address.
 * The variables are accessed through C coded config file functions.
 */
int	isSenderAddr = 0;
int	isRecpntAddr = 0;


#define FindEnvelope(X)	\
	for (h = e->e_eHeaders; h != NULL; h = h->h_next) \
	    if (h->h_descriptor->class == X) \
		break;
#define FindEnvelopeLast(X)	\
	{ struct header *__h_1 = NULL;			\
	  for (h = e->e_eHeaders; h != NULL; h = h->h_next) \
	    if (h->h_descriptor->class == X)		\
		__h_1 = h;				\
	  h = __h_1;					\
	}


#define RESENT_SIZE (sizeof "resent-" - 1)

#define	FindHeader(X,RESENT) \
	for (h = e->e_headers; h != NULL; h = h->h_next) \
	    if ((RESENT ? (h->h_descriptor->class == Resent) : \
		          (h->h_descriptor->class != Resent)   ) \
		&& h->h_descriptor->hdr_name != NULL \
		&& STREQ(h->h_descriptor->hdr_name+(RESENT?RESENT_SIZE:0), X))\
		    break;

/* we insert the new header just before this point */
#define InsertHeader(IH, EXPR) \
	{ for (ph = e->e_headers; ph != NULL; ph = ph->h_next) \
		if (ph->h_next == IH) \
			break; \
	nh = EXPR; \
	if (ph) { \
		nh->h_next = IH; \
		ph->h_next = nh; \
	} else { \
		nh->h_next = e->e_headers; \
		e->e_headers = nh; \
	} }

/* Make it possible to do real override of Errors-To: with  $(listaddress ...) */
char *errors_to = NULL;



/* Save the message in a directory for the postmaster to view it later */

void
squirrel(e, keyw, text)
	struct envelope *e;
	const char *keyw, *text;
{
	char *path;

#ifndef	USE_ALLOCA
	path = (char*)emalloc(5+sizeof(POSTMANDIR)+10+strlen(keyw));
#else
	path = (char*)alloca(5+sizeof(POSTMANDIR)+10+strlen(keyw));
#endif
	sprintf(path, "../%s/%d.%s",
		POSTMANDIR, (int)e->e_statbuf.st_ino, keyw);

	/* XX: We make a copy by link()ing file to two dirs, some
	       systems (Andrew-FS in mind) can't do it! Copying is
	       ok in their case.. */

	/* If linking to  /postman/  fails, link it to router dir with
	   two dots at the begin of the name + keyword at the end */
	if (elink(e->e_file, path) < 0) {
		sprintf(path, "..%d.%s", (int)e->e_statbuf.st_ino, keyw);
		elink(e->e_file, path);
	}

	/* The successfull squirrel MUST NOT delete the original message! */

	fprintf(stderr, "squirrel: %d.%s saved for inspection: %s\n",
		(int) e->e_statbuf.st_ino, keyw, text);
	zsyslog((LOG_ERR, "%d.%s saved for inspection: %s\n",
		 (int) e->e_statbuf.st_ino, keyw, text));
#ifndef	USE_ALLOCA
	free(path);
#endif
}

struct header *
erraddress(e)
	struct envelope *e;
{
	register struct header *h;
	struct header *best;
	int minval;
	char **cpp;
	const char *cp;

	best = NULL;
	minval = 10000;
	for (h = e->e_headers; h != NULL; h = h->h_next) {
		if ((e->e_resent != 0 && h->h_descriptor->class != Resent)
		    || h->h_descriptor->hdr_name == NULL
		    || h->h_stamp == BadHeader)
			continue;
		cp = h->h_descriptor->hdr_name + e->e_resent;
		/* char *err_prio_list[] = { "sender", "errors-to", 0 }; */
		for (cpp = err_prio_list; *cpp != NULL; ++cpp) {
			if (CISTREQ(*cpp, cp)
			    && (cpp - err_prio_list) < minval) {
				best = h;
				minval = cpp - err_prio_list;
			}
		}
	}
	if (best == NULL) {
		FindEnvelope(eFrom);	/* should never be NULL */
		/* but might still be problematic */
		if (h  &&  h->h_stamp == BadHeader)
		  FindHeader("from",e->e_resent);
	} else
		h = best;
	if (h  &&  h->h_stamp == BadHeader)
		h = NULL;
	if (h == NULL) {
		/* everything else failed, so use the owner of the file */
		if (!e->e_trusted)
			h = mkSender(e, uidpwnam(e->e_statbuf.st_uid), 1);
#if	0
		else
			h = mkSender(e, POSTMASTER, 1);
#endif
	}
	return h;
}


/* Pick recipient address from the input line.
   EXTREMELY Simple minded parsing.. */
static void pick_env_addr __((char *buf, FILE *mfp));
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
	if (s) {
	  /*  Cc:  The Postoffice managers <postoffice> */
	  buf = ++s;
	  s = strrchr(buf,'>');
	  if (s) *s = 0;
	  else return; /* No trailing '>' ? BAD BAD! */
	  fprintf(mfp,"to <%s>\n",buf);
	} else {
	  /*  Cc: some-address  */
	  fprintf(mfp,"to <%s>\n",buf);
	}
}

static int nullhost __((conscell *cs));
static int
nullhost(cs)
	conscell *cs;
{
	const char *s = cs->cstring;

	return (s == NULL || *s == '\0' || strcmp(s, "-") == 0);
	/* actually we should also check for localhostness, but lets not
	   get carried away... */
}

/* Send the message back to originator with user-friendly chastizing errors */

static void
reject(e, msgfile)
	struct envelope *e;
	const char *msgfile;
{
	register struct header *h;
	char *path, lastCh, nextToLastCh;
	const char *c_cp;
	int n;
	FILE *mfp, *fp;
	char buf[BUFSIZ], vbuf[BUFSIZ];

	fprintf(stderr, "Rejecting because of %s\n", msgfile);
	
	h = erraddress(e);
	if (h == NULL) {
		squirrel(e, "noerraddr", "No one to return an error to!");
		return;
	}
	/*
	 * turn all (possibly more than one) the addresses in whatever h
	 * is pointing at, into recipient addresses.
	 */
#ifndef	USE_ALLOCA
	path = (char*)emalloc(3+strlen(mailshare)+strlen(FORMSDIR)+strlen(msgfile));
#else
	path = (char*)alloca(3+strlen(mailshare)+strlen(FORMSDIR)+strlen(msgfile));
#endif
	sprintf(path, "%s/%s/%s", mailshare, FORMSDIR, msgfile);
	fp = fopen(path, "r");
	if (fp == NULL) {
		perror(path);
		squirrel(e, "norejform", "Couldn't open reject form file");
#ifndef	USE_ALLOCA
		free(path);
#endif
		return;
	}
#ifndef	USE_ALLOCA
	free(path);
#endif
	mfp = mail_open(MSG_RFC822);
	if (mfp == NULL) {
	  squirrel(e, "mailcreatefail", "Couldn't open reject message file");
	  return;
	}
	setvbuf(fp, vbuf, _IOFBF, sizeof vbuf);
	while (fgets(buf,sizeof(buf),fp)) {
	  if (strncmp("ADR",buf,3)==0) {
	    pick_env_addr(buf+4,mfp);
	  } else if (strncmp("HDR",buf,3)==0 ||
		     strncmp("SUB",buf,3)==0) {
	    continue;
	  } else
	    break;
	}
	fputs("env-end\n",mfp);
	fseek(fp,(off_t)0,0);

	/* who is it from? */
	c_cp = h->h_pname;
	h->h_pname = "To";
	hdr_print(h, mfp);
	h->h_pname = c_cp;
	lastCh = nextToLastCh = '\0';
	while (fgets(buf,sizeof(buf),fp)) {
	  int rc;
	  n = strlen(buf);
	  if (strncmp("HDR",buf,3)==0 ||
	      strncmp("ADR",buf,3)==0 ||
	      strncmp("SUB",buf,3)==0) {
	    rc = fputs(buf+4,mfp);
	    n -= 4;
	  } else
	    rc = fputs(buf,mfp);
	  if (n > 1) {	  
	    nextToLastCh = buf[n-2];
	    lastCh = buf[n-1];
	  } else {
	    nextToLastCh = lastCh;
	    lastCh = buf[0];
	  }
	}
	fclose(fp);
	if (lastCh == '\n') {
		if (nextToLastCh != '\n')
			putc('\n', mfp);
	} else {
		putc('\n', mfp);
		putc('\n', mfp);
	}
	/* print the headers that had errors in them, with annotations */
	for (h = e->e_eHeaders; h != NULL; h = h->h_next)
		if (h->h_stamp == BadHeader) {
			hdr_errprint(e, h, mfp, "envelope");
			putc('\n', mfp);
		}
	for (h = e->e_headers; h != NULL; h = h->h_next)
		if (h->h_stamp == BadHeader) {
			hdr_errprint(e, h, mfp, "header");
			putc('\n', mfp);
		}
	fprintf(mfp, "\nThe entire original message file follows.\n");
	fprintf(mfp, "\n-----------------------------------------\n");
	rewind(e->e_fp);
	while ((n = fread(buf, 1, sizeof buf, e->e_fp)) > 0) {
		if (fwrite(buf, 1, n, mfp) != n) {
			squirrel(e, "mailcreafail", "Couldn't include rejected input message");
			mail_abort(mfp);
			return;
		}
	}
	if (mail_close(mfp) < 0) {
		squirrel(e, "mailcreafail", "Couldn't close reject message file");
		mail_abort(mfp);
	}
}

/* Save a message file away because something went wrong during routing */

void
defer(e, why)
	struct envelope *e;
	const char *why;
{
	int i;
	char *path, *s;
	struct stat stbuf;

	if (e->e_fp  &&  files_gid >= 0) {
		fchown(FILENO(e->e_fp), -1, files_gid);
		fchmod(FILENO(e->e_fp),
			(0440|e->e_statbuf.st_mode) & 0660);
		fstat(fileno(e->e_fp),&stbuf);
	}
	if (stbuf.st_ino > 0) {
#ifdef	USE_ALLOCA
	  path = (char*)alloca(5+sizeof(DEFERREDDIR)+6+strlen(why));
#else
	  path = (char*)emalloc(5+sizeof(DEFERREDDIR)+6+strlen(why));
#endif
	  sprintf(path,"../%s/%d.%s", DEFERREDDIR, (int)stbuf.st_ino, why);
	} else {
#ifdef	USE_ALLOCA
	  path = (char*)alloca(5+sizeof(DEFERREDDIR)+strlen(e->e_file)+2+strlen(why));
#else
	  path = (char*)emalloc(5+sizeof(DEFERREDDIR)+strlen(e->e_file)+2+strlen(why));
#endif
	  sprintf(path, "../%s/%s.%s", DEFERREDDIR, e->e_file, why);
	}
	s = path;
	while ((s = strchr(s, ' '))) /* remap blanks to '-':es.. */
	  *s = '-';
#ifndef HAVE_RENAME
	zunlink(path);
#endif

	/* try renameing every few seconds for a minute */
	for (i = 0; erename(e->e_file, path) < 0 && i < 10 && errno != ENOENT;++i)
		sleep(6);
	if (i >= 10) {
	  zsyslog((LOG_ALERT, "cannot defer %s (%m)", e->e_file));
	  fprintf(stderr, "cannot defer %s\n", e->e_file);
	  /* XX: make sure file is not zunlink()ed in main() */
	} else {
	  zsyslog((LOG_NOTICE, "%s; %sing deferred", e->e_file,
		   (deferit || deferuid) ? "schedul" : "rout"));
	}
#ifndef	USE_ALLOCA
	free(path);
#endif
}


/*
 * Construct a header line that contains a given sender name.
 */

struct header *
mkSender(e, name, flag)
	struct envelope *e;
	const char *name;
	int flag;
{
	register struct header	*sh, *h;
	struct addr *pp, *qp, **ppp;
	conscell *l;
	int didbracket;
	GCVARS1;

	l = NULL;
	GCPRO1(l);

	sh = (struct header *)tmalloc(sizeof (struct header));
	sh->h_pname = e->e_resent ? "Resent-From" : "From";
	sh->h_descriptor = senderDesc();
	sh->h_stamp = newHeader;
	sh->h_lines = 0;
	sh->h_next = 0;
	sh->h_contents.a = (struct address *)tmalloc(sizeof (struct address));
	sh->h_contents.a->a_tokens = NULL;
	sh->h_contents.a->a_next = NULL;
	sh->h_contents.a->a_stamp = newAddress;
	sh->h_contents.a->a_dsn   = NULL;
	ppp = &sh->h_contents.a->a_tokens;
	didbracket = 0;
	FindEnvelope(eFullname);
	if (h  &&  h->h_contents.a) {
		sh->h_contents.a->a_tokens = h->h_contents.a->a_tokens;
		/* 'Full Name' */
		for (pp = h->h_contents.a->a_tokens;
		     pp != NULL; pp = pp->p_next) {
			qp = (struct addr *)tmalloc(sizeof (struct addr));
			*qp = *pp;
			*ppp = qp;
			ppp = &qp->p_next;
			if (pp->p_next == NULL)
				break;
		}
	} else {
	  spkey_t spk = symbol_lookup_db(name, spt_fullnamemap->symbols);
	  struct spblk *spl = NULL;
	  if (spk)
	    spl = sp_lookup(spk, spt_fullnamemap);
	  if (spk  &&  spl  &&  spl->data) {
		*ppp = (struct addr *)tmalloc(sizeof (struct addr));
		pp = *ppp;
		ppp = &pp->p_next;
		pp->p_tokens = makeToken((char *)spl->data,
					 strlen((char *)spl->data));
		pp->p_tokens->t_type = Word;
		pp->p_type = aPhrase;
	  }
	}
	if (sh->h_contents.a->a_tokens) {	/* 'Full Name <' */
		*ppp = (struct addr *)tmalloc(sizeof (struct addr));
		pp = *ppp;
		ppp = &pp->p_next;
		pp->p_tokens = makeToken("<", 1);
		didbracket = 1;
		pp->p_tokens->t_type = Special;
		pp->p_type = aSpecial;
	}
	FindEnvelope(ePrettyLogin);
	if (h  &&  h->h_contents.a == NULL)
		h = NULL;
	if (h  &&  !flag  &&  !e->e_trusted) {
		/* make sure the pretty login is valid. see thesender() */
		l = router(h->h_contents.a, e->e_statbuf.st_uid, "sender", NULL);
		if (l) {
			l = pickaddress(l);
			flag = (QUSER(l) == NULL || !nullhost(QHOST(l)));
			if (!flag)
			  flag = !CISTREQ(QUSER(l)->cstring, name);
		} else
			flag = 1;
	} else
		l = NULL;
	if (h  &&  (!flag || e->e_trusted)) {
		/* 'Full Name <Pretty.Login' */
		if (l) {
			if (e->e_trusted)
				e->e_from_trusted = l;
			else
				e->e_from_resolved = l;
		}
		for (pp = h->h_contents.a->a_tokens;
		     pp != NULL; pp = pp->p_next) {
			qp = (struct addr *)tmalloc(sizeof (struct addr));
			*qp = *pp;
			*ppp = qp;
			ppp = &qp->p_next;
			if (pp->p_next == NULL)
				break;
		}
	} else {
		/* 'Full Name <login' */
		*ppp = (struct addr *)tmalloc(sizeof (struct addr));
		pp = *ppp;
		ppp = &pp->p_next;
		pp->p_tokens = makeToken(name, strlen(name));
		pp->p_tokens->t_type = Atom;
		pp->p_type = anAddress;
		l = NULL;
	}
	if (didbracket) {
		/* 'Full Name <Pretty.Login>' */
		*ppp = (struct addr *)tmalloc(sizeof (struct addr));
		pp = *ppp;
		ppp = &pp->p_next;
		pp->p_tokens = makeToken(">", 1);
		pp->p_tokens->t_type = Special;
		pp->p_type = aSpecial;
	}
	*ppp = NULL;
	if (l == NULL && !e->e_trusted) {
		l = router(sh->h_contents.a, e->e_statbuf.st_uid, "sender", NULL);
		if (l)
			e->e_from_trusted = pickaddress(l);
	}

#ifdef	notdef
	/* X: sprintf(buf, "%s <%s>", fullname, name); more or less */
	sh->h_lines = makeToken(name, strlen((char *)name));
	sh->h_lines->t_type = Line;
	sh->h_contents = hdr_scanparse(e, sh, 0, 0);
#endif
	/* X: optimize: save this in a hashtable somewhere */
	UNGCPRO1;
	return sh;
}

/*
 * Construct a trace header line.
 */

static const struct headerinfo	traceDesc =
	{ "received", Received, nilUserType, normal };

struct header *
mkTrace(e, rcvdhdr)
	struct envelope *e;
	struct header *rcvdhdr;
{
	register struct header	*h, *th;
	struct addr *na;
	struct address *ap;
	
	th = (struct header *)tmalloc(sizeof (struct header));
	th->h_pname = "Received";
	th->h_descriptor = (struct headerinfo *)&traceDesc;
	th->h_stamp = newHeader;
	th->h_next = 0;
	th->h_contents.r = (struct received *)tmalloc(sizeof (struct received));
	th->h_lines = NULL;

	h = rcvdhdr; /* FindEnvelopeLast(eRcvdFrom); */
	/* from */
	if (h)
		th->h_contents.r->r_from = h->h_contents.a;
	else
		th->h_contents.r->r_from = NULL;
	/* by */
	if (myhostname) {
		na = (struct addr *)tmalloc(sizeof (struct addr));
		/* prepend now -- reverse later */
		na->p_tokens = makeToken(myhostname, strlen(myhostname));
		na->p_next = NULL;
		na->p_type = anAddress;
		ap = (struct address *)tmalloc(sizeof (struct address));
		ap->a_tokens = na;
		ap->a_next = NULL;
		/* we don't need to fill in the other structure elements */
		/* but, just in case... */
		ap->a_stamp = newAddress;
		ap->a_dsn  = NULL;
		th->h_contents.r->r_by = ap;
	} else
		th->h_contents.r->r_by = NULL;
	/* via */
	FindEnvelope(eVia);
	if (h  &&  h->h_contents.a->a_tokens) {
		th->h_contents.r->r_via = h->h_contents.a->a_tokens->p_tokens;
	} else
		th->h_contents.r->r_via = NULL;
	/* with */
	FindEnvelope(eWith);
	if (h  &&  h->h_contents.a->a_tokens) {
		th->h_contents.r->r_with = h->h_contents.a->a_tokens->p_tokens;
	} else
		th->h_contents.r->r_with = NULL;
	/* id */
	{
	  char taspid[32];
	  taspoolid(taspid, e->e_statbuf.st_mtime, (long)e->e_statbuf.st_ino);

	  na = (struct addr *)tmalloc(sizeof (struct addr));
	  na->p_tokens = makeToken(taspid, strlen(taspid));
	  na->p_next = NULL;
	  na->p_type = anAddress;	/* really a message id */
	}
	ap = (struct address *)tmalloc(sizeof (struct address));
	ap->a_tokens = na;
	ap->a_next = NULL;
	ap->a_dsn  = NULL;
	ap->a_stamp = newAddress;
	th->h_contents.r->r_id = ap;
	/* for */
	th->h_contents.r->r_for = NULL;
	/* time */
	th->h_contents.r->r_time = e->e_statbuf.st_mtime;
	/* looks like:sprintf(buf, "from %s by %s via %s with %s id %s; %s"); */
	th->h_contents.r->r_convert = NULL;
	return th;
}

struct rwmatrix {
	struct rwmatrix	*next;
	struct rwmatrix	*down;
	conscell *info;	/* rewrite, sender, or recipient list info */
	conscell *errto;
	union {
		int	number;	/* XOR address id number for recipients */
		struct header *h;	/* for rewritings */
	} urw;
};

static struct rwmatrix * rwalloc __((struct rwmatrix **));
static struct rwmatrix *
rwalloc(rwpp)
	struct rwmatrix **rwpp;
{
	struct rwmatrix *p;

	p = (struct rwmatrix *)tmalloc(sizeof (struct rwmatrix));
	p->down = NULL;
	p->errto = NULL;
	p->urw.number = 0;			/* unused but why not */
	if (*rwpp)
		p->next = *rwpp;
	else
		p->next = NULL;
	*rwpp = p;
	return p;
}

conscell *
pickaddress(l)
	conscell *l;
{
	conscell *la, *lx, *p;

	/*
	 * Given an AND-XOR tree returned from the router, pick one address
	 * quad to become *the* resolved address.
	 */

	for (p = NULL, la = car(l); la != NULL && LIST(la) ; la = cdr(la)) {
		/* AND addresses; i.e. exploded address list or one address */
		for (lx = car(la); lx != NULL && LIST(lx) ; lx = cdr(lx)) {
			if (STRING(cdar(lx)) && nullhost(cdar(lx))) {
				p = lx;
				break;
			}
		}
	}
	if (p == NULL)
		p = caar(l);
	if (!LIST(p))
		return NULL;
	return car(p);
}

int
thesender(e, a)
	struct envelope *e;
	struct address *a;
{
	conscell *l; /* Var life ends after return.. no GC protection */

	l = router(a, e->e_statbuf.st_uid, "sender", NULL);
	if (l == NULL)
		return 0;
	e->e_from_resolved = pickaddress(l);

	if (QUSER(e->e_from_resolved)->cstring == NULL ||
	    !nullhost(QHOST(e->e_from_resolved)))
		return 0;
	/*
	 * We assume here, that local mailbox id's correspond to user
	 * login names. If this is not the case, trp->user needs to be
	 * canonicalized at this point... the problem is that the algorithm
	 * must be the same here and in the local mail delivery program
	 * which is outside the router. Maybe that should be a C library
	 * routine, but for now, ignore such complications. This check is
	 * only done if the message file wasn't created by a trusted user,
	 * so in practise this is less of a problem than it might appear to be.
	 */
	return CISTREQ(QUSER(e->e_from_resolved)->cstring,
		       uidpwnam(e->e_statbuf.st_uid));
}

extern conscell *rwmappend __((conscell *, conscell *, conscell *));
conscell *rwmappend(rwmroot,info,errtop)
     conscell *rwmroot, *info, *errtop;
{
  conscell *p = NULL;
  GCVARS4;

  GCPRO4(p, rwmroot, info, errtop);

  if (info) {
    p = ncons(info);
    cdr(p) = rwmroot;
    rwmroot = p;
  }
  if (errtop) {
    p = ncons(info);
    cdr(p) = rwmroot;
    rwmroot = p;
  }

  UNGCPRO4;
  return rwmroot;
}



/*
 * The sequencer takes care of doing the right things with the right headers
 * in the right order. It implements the semantics of message processing.
 */

int ReceivedCount = 0;
static int schedulersubdirhash = -1;

int
sequencer(e, file)
	struct envelope *e;
	const char *file;
{
	struct header  *h, *ph, *nh = NULL, *oh, *msgidh, **hp;
	struct header  *rcvdhdr;
	struct address *a, *ap;
	struct addr    *p = NULL;
	char	       *ofpname, *path, *qpath;
	conscell       *l, *routed_addresses, *sender, *to;
	conscell       *rwmchain;
	struct rwmatrix *rwhead, *nsp, *rwp = NULL, *rcp = NULL;
	token822   *t = NULL;
	int   idnumber = 0, nxor = 0, i, slen;
	int   def_uid, header_error, perr;
	FILE	       *ofp, *vfp;
	int		ofperrors = 0;
	char  vbuf[2048], verbosefile[1024];
	const char     *envid;
	const char     *notaryret;
	int   nrcpts = 0;
	const char     *fromaddr = "?from?";
	const char     *msgidstr = "?msgid?";
	const char     *smtprelay = NULL;
	const char     *senderstr;
	char subdirhash[8];
	struct notary *DSN;
	GCVARS5;

	if (schedulersubdirhash < 0) {
	  char *s = getzenv("SCHEDULERDIRHASH");
	  if (s && ((s[0] == '1' || s[0] == '2') && s[1] == 0))
	    schedulersubdirhash = s[0] - '0';
	  else
	    schedulersubdirhash = 0;
	}

	if (schedulersubdirhash) {
	  long ino = e->e_statbuf.st_ino;
	  if (schedulersubdirhash > 1) {
	    int h1 = (ino / 26) % 26;
	    int h2 = ino % 26;
	    sprintf(subdirhash, "%c/%c/", h1 + 'A', h2 + 'A');
	  } else {
	    int h2 = ino % 26;
	    sprintf(subdirhash, "%c/", h2 + 'A');
	  }
	} else
	  *subdirhash = 0;

	deferuid = 0;

	errors_to = NULL; /* to be gotten rid off.. */

	if (e == NULL) {
		/* No envelope ??? */
		return PERR_OK;
	}

	dprintf("Sender authentication\n");
	e->e_trusted = isgoodguy(e->e_statbuf.st_uid);
	dprintf("Sender is%s trusted\n", e->e_trusted ? "" : "n't");

	if (deferuid)
	  return PERR_DEFERRED;

	FindEnvelopeLast(eRcvdFrom);
	rcvdhdr = h;
	if (e->e_trusted) {
	  if (rcvdhdr)
	    smtprelay = rcvdhdr->h_lines->t_pname;
	  else {
	    const char *s  = uidpwnam(e->e_statbuf.st_uid);
	    char *sr = strnsave("",strlen(s)+20);
	    sprintf(sr, "%s@localhost", s);
	    smtprelay = sr;
	  }
	} else {
	  const char *s, *ps;
	  char *ts;
	  int totlen;

	  if (rcvdhdr) {

	    /* Ok, we don't trust it!  In fact we might overrule the data
	       that the message writer coded in... */

	    dprintf("Message has 'rcvdfrom' envelope header, but we don't trust it!\n");
	    s = uidpwnam(e->e_statbuf.st_uid);
	    ps = "";
	    totlen = 10 + strlen(s) + 60;
	    if (rcvdhdr) {
	      ps = rcvdhdr->h_lines->t_pname;
	      totlen += strlen(ps) + 10;
	    }
	    /* ts = strnsave("", totlen); */
	    ts = tmalloc(totlen); /* Alloc the space */
	    if (rcvdhdr) {
	      sprintf(ts, "rcvdfrom STDIN (from localhost user: '%s' uid#%ld fake: %s)",
		      s, (long) e->e_statbuf.st_uid, rcvdhdr->h_lines->t_pname);
	    } else
	      sprintf(ts, "rcvdfrom STDIN (from localhost user: '%s' uid#%ld)",
		      s, (long) e->e_statbuf.st_uid);

	  } else {

	    /* No "rcvdfrom" envelope header */
	    s = uidpwnam(e->e_statbuf.st_uid);
	    totlen = 60 + strlen(s);
	    ts = tmalloc(totlen);
	    sprintf(ts, "rcvdfrom STDIN (from localhost user: '%s', uid#%ld)",
		    s, (long) e->e_statbuf.st_uid);
	  }

	  rcvdhdr = makeHeader(spt_eheaders, ts, 8);
	  rcvdhdr->h_next = e->e_eHeaders;
	  e->e_eHeaders = rcvdhdr;

	  rcvdhdr->h_lines    = makeToken(ts+9, strlen(ts+9));
	  rcvdhdr->h_lines->t_type = Line;
	  rcvdhdr->h_contents = hdr_scanparse(e, rcvdhdr, 0, 0);
	  rcvdhdr->h_stamp    = hdr_type(rcvdhdr);

	  smtprelay     = ts+9;
	}

	if (deferuid)
	  return PERR_DEFERRED;

	dprintf("Parse envelope and message header\n");
	e->e_messageid = NULL;
	perr = 0;
	if (myhostname) {	/* appease honeyman et al groupies */
		dprintf("Stamp it with a trace header\n");
		h = mkTrace(e, rcvdhdr);
		if (h) {
			h->h_next = e->e_headers;
			e->e_headers = h;
		}
	}
	/* gross loop checking */
	ReceivedCount = 0;
	for (h = e->e_headers, i = 0; h != NULL; h = h->h_next) {
		if (h->h_descriptor->semantics == Received
		    || (h->h_descriptor->semantics == nilHeaderSemantics
			&& CISTREQ(h->h_pname, "Received"))) {
			if (++ReceivedCount >= maxReceived) {
			   if (ReceivedCount == maxReceived)
				fprintf(stderr,
				     "%s: looping message, rejected!\n",
					progname);
				perr = PERR_LOOP;
			}
		}
	}

	if (deferuid)
	  return PERR_DEFERRED;

	dprintf("Determine if message is a Resent-* type thing\n");
	e->e_resent = 0;
	for (h = e->e_headers; h != NULL; h = h->h_next)
		if (h->h_descriptor->class == Resent) {
			e->e_resent = 1;
			break;
		}
	dprintf("It is%s...\n", e->e_resent ? "" : "n't");

	dprintf("Generate an error message if an error occurred in parsing\n");
	for (h = e->e_eHeaders; h != NULL; h = h->h_next)
		if (h->h_stamp == BadHeader)
			break;
	if (h  &&  h->h_stamp == BadHeader) {
		/*
		 * There's an error in the envelope; this implies a system
		 * problem that must be brought to the attention of the
		 * postmaster ASAP. Hopefully the postmaster will resubmit
		 * the message when the problem is fixed, so we don't tell
		 * the originator that anything went wrong.
		 */
		/* We give precedence to loop-trap error */
		if (perr == 0)
			perr = PERR_ENVELOPE;
	}
	e->e_from_trusted  = makequad();
	e->e_from_resolved = makequad();

	if (myhostname) {	/* we care about message id's */
		dprintf("Make sure Message-Id exists, for loop control\n");
		/* it may be  message-id, or resent-message-id */
		FindHeader("message-id",e->e_resent);
		if (h == NULL) /* Ok, wasn't, how about resent-message-id ? */
		  FindHeader("message-id",!e->e_resent);
		if (h == NULL) {
			/* the time used must be the same as for trace header */
			InsertHeader(h, mkMessageId(e, e->e_nowtime));
			/* or: e->e_statbuf.st_mtime */
			dprintf("We added one\n");
			msgidh = nh;
		} else
			msgidh = h;
		if (msgidh->h_contents.a  &&  msgidh->h_contents.a->a_tokens)
		  e->e_messageid = saveAddress(msgidh->h_contents.a->a_tokens);
	}

	if (perr)
		return perr;

	/* put pertinent message information in the zsh environment */
	setenvinfo(e);

	FindEnvelope(eEnvid);
	envid = NULL;
	if (h  &&  h->h_contents.a  &&  h->h_contents.a->a_pname) {
		envid = h->h_contents.a->a_pname;
	}
	FindEnvelope(eNotaryRet);
	notaryret = NULL;
	if (h  &&  h->h_contents.a  &&  h->h_contents.a->a_pname) {
		notaryret = h->h_contents.a->a_pname;
	}

	rwmchain = l = routed_addresses = sender = to = NULL;
	GCPRO5(l, routed_addresses, sender, to, rwmchain);

	FindEnvelope(eFrom);
	if (h == NULL && e->e_trusted) {
		/* Perhaps  'channel error' ??? */
		FindEnvelope(eChannel);
		if (h) {
			dprintf("A channel was specified\n");
			if ((ap = h->h_contents.a) != NULL
			    && (p = ap->a_tokens) != NULL
			    && p->p_tokens != NULL) {
				t = p->p_tokens;
				slen = TOKENLEN(t);
				l = cdr(QCHANNEL(e->e_from_trusted));
				QCHANNEL(e->e_from_trusted) =
				  newstring(dupnstr(t->t_pname, slen), slen);
				cdr(QCHANNEL(e->e_from_trusted)) = l;
			} else {
				/*
				 * No origination channel, or channel
				 * has no name, or ...
				 */
				optsave(FYI_NOCHANNEL, e);
			}
		}
	}

	if (deferuid) {
	  UNGCPRO5;
	  return PERR_DEFERRED;
	}

	if (h == NULL) {
		dprintf("A sender was NOT specified in the envelope\n");
		for (h = e->e_headers; h != NULL; h = h->h_next)
			if (h->h_descriptor->user_type == Sender
			    && (e->e_resent == 0
				|| h->h_descriptor->class == Resent))
			break;
		if (h  &&  e->e_trusted) {
			dprintf("Use the Sender: or From: field from header\n");
			h = copySender(e);
		} else {
			dprintf("Generate a sender based on owner of file\n");
			h = mkSender(e, uidpwnam(e->e_statbuf.st_uid), 0);
		}
		if (h == NULL)
			h = mkSender(e, POSTMASTER, 1);
		/* assert h != NULL */
		h->h_next = e->e_eHeaders;
		e->e_eHeaders = h;
	} else if (!e->e_trusted
		   || ((ap = h->h_contents.a) != NULL &&
		       ap->a_tokens != NULL &&
		       ap->a_tokens->p_next == NULL &&
		       ap->a_tokens->p_type == anAddress &&
		       (t = ap->a_tokens->p_tokens) != NULL &&
		       t->t_next == NULL)) {
		dprintf("A sender was specified in the envelope\n");
		if (!e->e_trusted) {
			dprintf("Replace the sender based on owner of file\n");
			h = mkSender(e, uidpwnam(e->e_statbuf.st_uid), 0);
		} else {
			dprintf("Provide a full name for the originator\n");
			/* ensure there is a fullnamemap entry */
			login_to_uid(t->t_pname);
			h = mkSender(e, t->t_pname, 0);
		}
		h->h_next = e->e_eHeaders;
		e->e_eHeaders = h;
		/*
		 * No need to delete other header since there can only
		 * be one sender in the message envelope and in other
		 * places in the code we will use the first one found.
		 */
	}

	for (h = e->e_headers; h != NULL; h = h->h_next)
		if (h->h_stamp == BadHeader)
			break;
	if (h  &&  h->h_stamp == BadHeader) {
		/*
		 * There's an error in the message header; we save the message
		 * for the future amusement of the postmaster, and also send
		 * back a nasty note to the originator.
		 */
		optsave(FYI_BADHEADER, e);
		/* continue on with address rewriting - emit warning there */
		/* return e; */
		header_error = 1;
	} else
		header_error = 0;
	dprintf("Originating channel determination\n");
	def_uid = nobody;

	if (e->e_trusted) {
		/* The sender uid is known */
		FindEnvelope(eChannel);
		if (h) {
			dprintf("A channel was specified\n");
			if ((ap = h->h_contents.a) != NULL
			    && (p = ap->a_tokens) != NULL
			    && p->p_tokens != NULL) {
				t = p->p_tokens;
				slen = TOKENLEN(t);
				l = cdr(QCHANNEL(e->e_from_trusted));
				QCHANNEL(e->e_from_trusted) =
				  newstring(dupnstr(t->t_pname, slen), slen);
				cdr(QCHANNEL(e->e_from_trusted)) = l;
			}
			if (QCHANNEL(e->e_from_trusted)->cstring == NULL) {
				/*
				 * the mailer is supposed to know about
				 * all valid channel identifiers. Gripe.
				 */
				optsave(FYI_NOCHANNEL, e);
			}
		}

		h = rcvdhdr; /* FindEnvelopeLast(eRcvdFrom); */
		if (h && h->h_contents.a && h->h_contents.a->a_pname) {
			/* a previous host was specified */
			slen = strlen(h->h_contents.a->a_pname);
			l = cdr(QHOST(e->e_from_trusted));
			QHOST(e->e_from_trusted) =
			  newstring(dupnstr(h->h_contents.a->a_pname, slen),slen);
			cdr(QHOST(e->e_from_trusted)) = l;
		}
		FindEnvelope(eUser);
		if (h  && h->h_contents.a->a_pname) {
			/* a previous user was specified */
			slen = strlen(h->h_contents.a->a_pname);
			l = cdr(QHOST(e->e_from_trusted));
			QHOST(e->e_from_trusted) =
			  newstring(dupnstr(h->h_contents.a->a_pname, slen),slen);
			cdr(QHOST(e->e_from_trusted)) = l;
		}
		if (QCHANNEL(e->e_from_trusted)->cstring == NULL
		    || QHOST(e->e_from_trusted)->cstring == NULL
		    || QUSER(e->e_from_trusted)->cstring == NULL) {
			FindEnvelope(eFrom);
			/* X: assert h != NULL */
			if (h == NULL || h->h_stamp == BadHeader) {
			  /* XX: perhaps should be other way around? */
			  FindHeader("sender",e->e_resent);
			  if (h == NULL || h->h_stamp == BadHeader)
			    FindHeader("from",e->e_resent);
			  if (h == NULL || h->h_stamp == BadHeader)
			    FindHeader("sender",!e->e_resent);
			  if (h == NULL || h->h_stamp == BadHeader)
			    FindHeader("from",!e->e_resent);
			  if (h == NULL || h->h_stamp == BadHeader)
			    h = mkSender(e,uidpwnam(e->e_statbuf.st_uid),0);
			}
			if (h == NULL)
				abort(); /* Failed to make sender header */

			/* This conscell lifetime is limited.. */
			l = router(h->h_contents.a,
				   e->e_statbuf.st_uid, "sender", NULL);
			if (l == NULL) {
			  /* From: <>,  and no envelope 'from' .. */
			  h = mkSender(e,uidpwnam(e->e_statbuf.st_uid),0);
			  if (h == NULL)
			    abort(); /* Can't make Sender header ?? */
			  l = router(h->h_contents.a,
				     e->e_statbuf.st_uid, "sender", NULL);
			}
			if (l) {
				/*
				 * In case the router returns several addresses,
				 * we pick one at random to use for sender priv
				 * determination.
				 */
				e->e_from_resolved = pickaddress(l);
			}
		}
		if (nullhost(QHOST(e->e_from_resolved)) &&
		    nullhost(QHOST(e->e_from_trusted))) {
			/* local user */
			FindEnvelope(eExternal);
			if (h || (e->e_statbuf.st_mode & 022)) {
			  optsave(FYI_BREAKIN, e);
			} else if (QUSER(e->e_from_resolved)->cstring)
			  def_uid =
			    login_to_uid(QUSER(e->e_from_resolved)->cstring);
			else if (QUSER(e->e_from_trusted)->cstring)
			  def_uid =
			    login_to_uid(QUSER(e->e_from_trusted)->cstring);
		}
	} else {
		dprintf("We know sender is local and one of the peons\n");
		def_uid = e->e_statbuf.st_uid;
		FindHeader("from",e->e_resent);
		nh = h;
		FindHeader("sender",e->e_resent);
		if (h && !nh) {
			dprintf("A Sender w/o a From is bad; fixed\n");
			h->h_descriptor = senderDesc();
			set_pname(e, h, "From");
			nh = h;
			h = NULL;
		}
		if (h && h->h_contents.a) {
			/* a Sender: was given */
			if (!thesender(e, h->h_contents.a)) {
				/* but it is fake, so correct it */
				dprintf("The Sender: is not the sender\n");
				set_pname(e, h, "Fake-Sender");
			} else /* it is correct and we don't care about From: */
				h = NULL;
		} else if (nh  &&  nh->h_contents.a) {
			/* only a From: was given */
			if (!thesender(e, nh->h_contents.a)) {
			  /* but it is fake, so add a Sender: */
			  dprintf("The From: is not the sender\n");
			  if (h) {
			    /* use our empty Sender: */
			    ph = mkSender(e,uidpwnam(e->e_statbuf.st_uid),0);
			    h->h_contents.a = ph->h_contents.a;
			    h = NULL;
			  } else
			    h = nh;
			} else
			  h = NULL;
		}
		if (h) {
		  InsertHeader(h,mkSender(e, uidpwnam(e->e_statbuf.st_uid),0));
		  set_pname(e, nh, "Sender");
		}
	}
	if (QCHANNEL(e->e_from_trusted)->cstring == NULL) {
	  l = cdr(QCHANNEL(e->e_from_trusted));
	  QCHANNEL(e->e_from_trusted) = copycell(QCHANNEL(e->e_from_resolved));
	  cdr(QCHANNEL(e->e_from_trusted)) = l;
	}
	if (QHOST(e->e_from_trusted)->cstring == NULL) {
	  l = cdr(QHOST(e->e_from_trusted));
	  QHOST(e->e_from_trusted) = copycell(QHOST(e->e_from_resolved));
	  cdr(QHOST(e->e_from_trusted)) = l;
	}
	if (QUSER(e->e_from_trusted)->cstring == NULL) {
	  l = cdr(QUSER(e->e_from_trusted));
	  QUSER(e->e_from_trusted) = copycell(QUSER(e->e_from_resolved));
	  cdr(QUSER(e->e_from_trusted)) = l;
	}
	if (QATTRIBUTES(e->e_from_trusted)->cstring == NULL) {
	  l = cdr(QATTRIBUTES(e->e_from_trusted));
	  QATTRIBUTES(e->e_from_trusted) = copycell(QATTRIBUTES(e->e_from_resolved));
	  cdr(QATTRIBUTES(e->e_from_trusted)) = l;
	}

	if (deferuid) {
	  UNGCPRO5;
	  return PERR_DEFERRED;
	}

	dprintf("Recipient determination\n");
	FindEnvelope(eTo);
	if (h == NULL) {
		dprintf("No recipient(s) specified in the envelope\n");
		if (header_error) {
			dprintf("Due to header error, we ignore message\n");
			UNGCPRO5;
			return PERR_HEADER;
		}
		ph = e->e_eHeaders;
		dprintf("Add all To:,Cc:,Bcc: to envelope recipients\n");
		oh = NULL;
		for (h = e->e_headers; h != NULL; oh = h, h = h->h_next) {
			if (h->h_descriptor->user_type != Recipient
			    || (e->e_resent != 0
				&& h->h_descriptor->class != Resent))
				continue;
			for(a = h->h_contents.a; a!=NULL; a = a->a_next)
				for (p=a->a_tokens;p!=NULL; p=p->p_next)
					if (p->p_type == anAddress)
						goto ok;
			continue;
		ok:
			nh = copyRecipient(h);
			nh->h_next = e->e_eHeaders;
			e->e_eHeaders = nh;
		}
		dprintf("Are we supposed to be psychic?\n");
		if (ph == e->e_eHeaders) {
		  UNGCPRO5;
		  return PERR_NORECIPIENTS;
		}
	}

	dprintf("Nuke Bcc/Return-Path/X-Orcpt/X-Envid headers, if any\n");
	hp = & e->e_headers;
	while (*hp) {
	  h = *hp;
	  if (h->h_descriptor->hdr_name != NULL &&
	      ((h->h_descriptor->user_type == killUserType)
	       || (h->h_descriptor->class == normal &&
		   (CISTREQ(h->h_descriptor->hdr_name,"bcc")))
	       || (h->h_descriptor->class == Resent &&
		   (CISTREQ(h->h_descriptor->hdr_name,"resent-bcc"))))) {
	    /* Skip this one */
	    *hp = h->h_next;
	  } else {
	    /* No header dropping here */
	    hp = & h->h_next;
	  }
	}

	/*
	 * Log the message after we find the envelope From address, otherwise
	 * log entries might have empty sender fields.
	 */
	if (e->e_messageid)
		logmessage(e);

	if (header_error) {
		/* only send back if local originator, until we fix gweansm */
		if (def_uid != nobody) {
			reject(e, "headerwarn");
			printf("def_uid = %d\n", def_uid);
		}
		dprintf("Emit warning headers\n");
		for (ph = NULL, h = e->e_headers; h != NULL; ph=h,h=h->h_next) {
			if (h->h_stamp == BadHeader && do_hdr_warning) {
				if (ph == NULL)
					e->e_headers = hdr_warning(h);
				else
					ph->h_next = hdr_warning(h);
			}
		}
	}
	dprintf("Make sure a From: line exists...");
	FindHeader("from",e->e_resent);
	if (h == NULL) {
		FindEnvelope(eFrom);
		oh = h;
		if (h == NULL) {	/* panic... can't happen... */
			dprintf(" none available!\n");
			optsave(FYI_NOSENDER, e);
		} else {
			FindEnvelope(eChannel);
			if (h) {
			  if ((ap = h->h_contents.a) != NULL
			      && (p = ap->a_tokens) != NULL
			      && (p->p_tokens != NULL)) {
			    t = p->p_tokens;
			    if (TOKENLEN(t) == 5 &&
				strncmp(t->t_pname,"error",5)==0) {

			      char *ss = (char*)tmalloc(10);
			      strcpy(ss, "From: <>");

			      nh = makeHeader(spt_headers, ss, 4);
			      nh->h_lines = makeToken(ss+5,3);
			      nh->h_lines->t_type = Line;
			      nh->h_contents = hdr_scanparse(e, nh, 0, 0);
			      nh->h_stamp = hdr_type(nh);
			      FindHeader("to",e->e_resent);
			      if (h == NULL) {
				for (h = e->e_headers; h != NULL; h = h->h_next)
				  if (CISTREQ(h->h_pname, "subject"))
				    break;
			      }
			      InsertHeader(h, nh);
			      dprintf(" nope (added)!\n");
			    }
			  }
			} else {

			  /* We make a copy of eFrom envelope header
			     to be our new  From:  header */

			  nh = makeHeader(spt_headers, "From", 4);
			  nh->h_lines    = oh->h_lines;
			  nh->h_contents = oh->h_contents;
			  nh->h_stamp    = hdr_type(nh);
			  
			  FindHeader("to",e->e_resent);
			  if (h == NULL) {
			    for (h = e->e_headers; h != NULL; h = h->h_next)
			      if (CISTREQ(h->h_pname, "subject"))
				break;
			  }
			  InsertHeader(h, nh);
			  dprintf(" nope (added)!\n");
			}
		}
	} else
		dprintf(" yup!\n");
	/* Any 'To:' in the headers ? */
	FindHeader("to",e->e_resent);
	if (h == NULL)
	  FindHeader("to",!e->e_resent);
	if (h == NULL) {
#if 1
		dprintf("No 'To:' -header, creating our own\n");
		InsertHeader(h, mkToHeader(e,"unlisted-recipients:; (no To-header on input)"));
#else
		dprintf("Insert the To: header lines\n");
		for (h = e->e_headers; h != NULL; h = h->h_next)
			if (CISTREQ(h->h_pname, "subject"))
				break;
		if (h == NULL) {
			FindHeader("from",e->e_resent);
			if (h)
				h = h->h_next;
		}
		ph = h;
		for (h = e->e_headers; h != NULL; h = h->h_next)
			if (h->h_next == ph)
				break;
		ph = h;	/* assert ph != NULL */
		for (h = e->e_eHeaders; h != NULL; h = h->h_next) {
			if (h->h_descriptor->class == eTo) {
				nh = (struct header *)tmalloc(sizeof (struct header));
				*nh = *h;
				set_pname(e, nh, "To");
				nh->h_next = ph->h_next;
				ph->h_next = nh;
				/* so we add them in reverse order... */
			}
		}
#endif
	}
#ifdef notdef
	rewrite all addresses in the message according to the
	incoming-rewriting rules for the originating channel.
#endif
	dprintf("Route recipient addresses\n");

	if (errors_to) free(errors_to);
	errors_to = NULL;
	senderstr = NULL;
	if (e->e_from_trusted) {
	  if (CISTREQ("error",QCHANNEL(e->e_from_trusted)->cstring)) {
	    senderstr = "<>"; /* From "BOX" -- from an error channel! */
	  } else {
	    senderstr = QUSER(e->e_from_trusted)->cstring;
	  }
	}

	DSN = NULL;

	for (h = e->e_eHeaders; h != NULL; h = h->h_next) {

		if (h->h_descriptor->class != eTo &&
		    h->h_descriptor->class != eToDSN) {
			DSN = NULL;
			continue;
		}
		if (D_sequencer) dumpHeader(h);
		if (h->h_descriptor->class == eToDSN) {
			DSN = NULL;
			if (h->h_contents.a == NULL ||
			    h->h_contents.a->a_pname == NULL ||
			    h->h_contents.a->a_pname[0] == 0) {
			  /* HUH!  How come ? "todsn" w/o data ?? */
			  continue;
			}
			DSN = (struct notary *)tmalloc(sizeof(struct notary));
			DSN->envid = envid;
			DSN->ret   = notaryret;
			DSN->dsn = h->h_contents.a->a_pname;
			continue;
		}
		if (DSN) {
			h->h_contents.a->a_dsn = DSN;
			DSN = NULL;
		}
		for (a = h->h_contents.a; a != NULL; a = a->a_next) {
			l = router(a, def_uid, "recipient", senderstr);
			if (l == NULL)
				continue;

			if (routed_addresses == NULL) {
				routed_addresses = ncons(car(l));
			} else {
				cdr(s_last(car(l))) = car(routed_addresses);
				car(routed_addresses) = car(l);
			}
			/* freecell(l) */
			l = NULL;
		}
		if (deferuid) {
		  UNGCPRO5;
		  return PERR_DEFERRED;
		}
	}

	dprintf("Crossbar to be applied to all (sender,routed-address) pairs\n");

	sender = ncons(e->e_from_trusted);

#if 0
	if (LIST(sender) && LIST(car(sender)))
		sender = caar(sender);
#endif

	if (routed_addresses == NULL)	/* they were probably all deferred */ {
		printf("No routed addresses -> deferred\n");
		UNGCPRO5;
		return PERR_DEFERRED;
	}

	rwhead = NULL;
	for (idnumber = 0, l = car(routed_addresses); l != NULL ; l = cdr(l)) {
		/* first level is ANDs */
		++idnumber, nxor = 0;
		for (to = car(l); to != NULL; to = cdr(to)) {
			conscell *x, *tmp, *errto, *gg;
			conscell *sender1, *z;
			GCVARS6;

			/* secondlevel is XORs */
			if (D_sequencer) {
			  printf("crossbar sender: ");
			  s_grind(sender, stdout);
			  putchar('\n');
			  printf("crossbar to: ");
			  s_grind(to, stdout);
			  putchar('\n');
			}

			if ((x = crossbar(sender, to)) == NULL)
			  continue;

	/*
	 * We expect to see something like
	 * (rewrite (fc fh fu) (tc th tu)) or
	 * ((address-rewrite header-rewrite) (fc fh fu) (tc th tu))
	 * back from the crossbar function.
	 */

			errto = gg = sender1 = tmp = z = NULL;
			GCPRO6(x, errto, gg, sender1, tmp, z);


			if (D_sequencer) {
			  printf("crossbar returns: ");
			  s_grind(x, stdout);
			  putchar('\n');
			}
			
			++nxor;
			tmp   = copycell(car(x));

			cdr(tmp) = NULL;
			sender1 = cdar(x);
			gg = cdr(cddr(car(sender1))); /* recipient attrib! */
			errto = find_errto(gg);   /* Possible 'ERR' value */
			if (!errto)
				errto = cddar(sender1);  /* Sender 'user' */

			/* Rewriter level: */
			for (rwp = rwhead; rwp != NULL; rwp = rwp->next)
			  if (s_equal(rwp->info, tmp)) {
			    break;
			  }
			if (rwp == NULL) {
				rwp = rwalloc(&rwhead);
				rwp->info  = tmp;	/* rewritings */
				rwp->errto = NULL;
				rwmchain = rwmappend(rwmchain,tmp,NULL);
			}
			/* else the 'tmp' leaks for a moment ? */
			
			tmp = cdr(sender1); /* recipient */
			cdr(sender1) = NULL; /* detach from sender */

			/* Sender (and errto) level: */
			for (nsp = rwp->down; nsp != NULL; nsp = nsp->next)
				if (s_equal(nsp->info, sender1) &&
				    s_equal1(nsp->errto,errto))
					break;
			if (nsp == NULL) {
				nsp = rwalloc(&rwp->down);
				nsp->info  = sender1;	/* new sender */
				nsp->errto = errto;
				rwmchain = rwmappend(rwmchain,sender1,errto);
			}
#if 0
			else {
				printf("==comparing: ");
				s_grind(nsp->info, stdout);
				printf("\n\tand: ");
				s_grind(cdar(x), stdout);
				printf("\n");
				fflush(stdout);
			}
#endif
			rcp = rwalloc(&nsp->down);
			rcp->info = tmp;		/* new recipient */
			rcp->urw.number = idnumber;
			rcp->errto = errto;
			rwmchain = rwmappend(rwmchain,tmp,errto);
#if 0
			for (rwp = rwhead; rwp != NULL; rwp = rwp->next) {
				printf("**");
				s_grind(rwp->info, stdout);
				printf("\n");
				fflush(stdout);
				for (nsp = rwp->down; nsp != NULL; nsp = nsp->next) {
					struct rwmatrix *rp;
					printf("**\t");
					s_grind(nsp->info, stdout);
					printf("\n");
					fflush(stdout);
					for (rp = nsp->down; rp != NULL;
					     rp = rp->next) {
						printf("**\t\t");
						s_grind(rp->info, stdout);
						printf("\n");
						fflush(stdout);
					}
				}
			}
#endif
			UNGCPRO6;
		}
		if (nxor <= 1) {
			--idnumber;
			if (nxor == 1)
				rcp->urw.number = 0; /* 0 means no XOR addrs */
		}
	}

	if (deferuid) {
	  UNGCPRO5;
	  return PERR_DEFERRED;
	}

	isSenderAddr = isRecpntAddr = 0;
	dprintf("Make sure Date, From, To, are in the header\n");
	FindHeader("date",e->e_resent);
	if (h == NULL)
		InsertHeader(h, mkDate(e->e_resent, e->e_statbuf.st_mtime));

	dprintf("Rewrite message headers\n");
	for (rwp = rwhead; rwp != NULL; rwp = rwp->next) {
		hp = &rwp->urw.h;
		for (h = e->e_headers; h != NULL; h = h->h_next) {
			isSenderAddr = h->h_descriptor->user_type == Sender;
			isRecpntAddr = h->h_descriptor->user_type == Recipient;
			if (isSenderAddr || isRecpntAddr) {
				if (!STRING(rwp->info))	/* just addresses */
					continue;
				*hp = hdr_rewrite(rwp->info->string, h);
				hp = &(*hp)->h_next;
			}
		}
		*hp = NULL;
	}
 
	if (deferuid) {
	  UNGCPRO5;
	  return PERR_DEFERRED;
	}

	if (rwhead == NULL) {
	  UNGCPRO5;
	  return PERR_NORECIPIENTS;
	}

	dprintf("Emit specification to the transport system\n");
#ifdef	USE_ALLOCA
	ofpname = (char *)alloca((u_int)(strlen(file)+9));
#else
	ofpname = (char *)emalloc((u_int)(strlen(file)+9));
#endif
	/* Guaranteed unique within this machine */
	sprintf(ofpname,".%s.%d", file, (int)getpid());
	if ((ofp = fopen(ofpname, "w+")) == NULL) {
#ifndef USE_ALLOCA
		free(ofpname);
#endif
		printf("Creation of control file failed\n");
		UNGCPRO5;
		return PERR_CTRLFILE;
	}
	setvbuf(ofp, vbuf, _IOFBF, sizeof vbuf);
	if (files_gid >= 0) {
		fchown(FILENO(ofp), e->e_statbuf.st_uid, files_gid);
		fchmod(FILENO(ofp), 0460);
	}

	FindEnvelope(eVerbose);
	if (h  &&  h->h_contents.a  &&  h->h_contents.a->a_tokens) {
		if (h->h_contents.a->a_tokens->p_tokens    &&
		    h->h_contents.a->a_tokens->p_tokens->t_type == String)
			h->h_contents.a->a_tokens->p_tokens->t_type = Atom;
		printToken(verbosefile, verbosefile + sizeof verbosefile,
			   h->h_contents.a->a_tokens->p_tokens,
			   (token822 *)NULL, 0);
		/*
		 * We have to be careful how we open this file, since one might
		 * imagine someone trying to append to /etc/passwd using this
		 * stuff.  The only safe way is to open it with the permissions
		 * of the owner of the message file.
		 */
		setreuid(0, e->e_statbuf.st_uid);

		vfp = fopen(verbosefile, "a");
		if (vfp) {
			fseek(vfp, (off_t)0, 2);
			setvbuf(vfp, NULL, _IOLBF, 0);
			fprintf(vfp, "router processed message %s\n", file);
			fprintf(ofp, "%c%c%s\n", _CF_VERBOSE, _CFTAG_NORMAL,
				verbosefile);
		}
		setreuid(0, 0);
	} else
		vfp = NULL;

	fprintf(ofp, "%c%c0x%08lx\n",
		_CF_FORMAT, _CFTAG_NORMAL, (long)_CF_FORMAT_KNOWN_SET);

	fprintf(ofp, "%c%c%s\n",
		_CF_MESSAGEID, _CFTAG_NORMAL, file);
	fprintf(ofp, "%c%c%d\n",
		_CF_BODYOFFSET, _CFTAG_NORMAL, (int)(e->e_msgOffset));
	if (e->e_messageid) {
		fprintf(ofp, "%c%c%s\n",
			_CF_LOGIDENT, _CFTAG_NORMAL, e->e_messageid);
		msgidstr = e->e_messageid;
	}
	/* else { we don't want to log anything } */
	if (vfp) {
	  if (e->e_messageid)
	    fprintf(vfp, "%c%c%s\n",
		    _CF_LOGIDENT, _CFTAG_NORMAL, e->e_messageid);
	  /* else { we don't want to log anything } */
	}
	/*
	 * If this message came from an error channel, then
	 * do NOT produce an error message if something goes
	 * wrong. It can quickly lead to Bad Things happening
	 * to your disk space.
	 */

	if (!iserrmessage()) {
#if 1
                if (errors_to) {        /* [mea@utu.fi] Stupid, but workable.. */
                        putc(_CF_ERRORADDR, ofp);
                        putc(_CFTAG_NORMAL, ofp);
                        fprintf(ofp,"%s\n",errors_to);
			if (vfp) {
			  putc(_CF_ERRORADDR, vfp);
			  putc(_CFTAG_NORMAL, vfp);
			  fprintf(vfp,"%s\n",errors_to);
			}
                        free(errors_to);
                        errors_to = NULL;
                } else
#endif
		if ((h = erraddress(e)) != NULL) {
			putc(_CF_ERRORADDR, ofp);
			putc(_CFTAG_NORMAL, ofp);
			for (ap = h->h_contents.a;
			     ap != NULL; ap = ap->a_next) {
				if (ap != h->h_contents.a)
					putc(' ', ofp);
				printAddress(ofp, ap->a_tokens, 0);
				if (ap->a_next)
					putc(',', ofp);
			}
			putc('\n', ofp);
			if (vfp) {
			  putc(_CF_ERRORADDR, vfp);
			  putc(_CFTAG_NORMAL, vfp);
			  for (ap = h->h_contents.a;
			       ap != NULL; ap = ap->a_next) {
			    if (ap != h->h_contents.a)
			      putc(' ', vfp);
			    printAddress(vfp, ap->a_tokens, 0);
			    if (ap->a_next)
			      putc(',', vfp);
			  }
			  putc('\n', vfp);
			}
		}
	}
	/*
	 * If this message might obsolete another we need to tell
	 * the scheduler.
	 */

	for (h = e->e_headers; h != NULL; h = h->h_next) {
		ofperrors |= ferror(ofp);
		if (ofperrors) break; /* Sigh.. */
		if (h->h_descriptor->hdr_name == NULL
		    || !CISTREQ(h->h_descriptor->hdr_name, "obsoletes"))
			continue;
		for (ap = h->h_contents.a; ap != NULL; ap = ap->a_next) {
			putc(_CF_OBSOLETES, ofp);
			putc(_CFTAG_NORMAL, ofp);
			printAddress(ofp, ap->a_tokens, 0);
			putc('\n', ofp);
		}
	}

	/*
	 * If this message might trigger scheduler to give target (smtp),
	 * we must tell the scheduler.
	 */

	for (h = e->e_headers; h != NULL; h = h->h_next) {
		ofperrors |= ferror(ofp);
		if (ofperrors) break; /* Sigh.. */
		if (h->h_descriptor->hdr_name == NULL
		    || !CISTREQ(h->h_descriptor->hdr_name, "turnme"))
			continue;
		for (ap = h->h_contents.a; ap != NULL; ap = ap->a_next) {
			putc(_CF_TURNME, ofp);
			putc(_CFTAG_NORMAL, ofp);
			printAddress(ofp, ap->a_tokens, 0);
			putc('\n', ofp);
		}
	}

	for (rwp = rwhead; rwp != NULL; rwp = rwp->next) {

		ofperrors |= ferror(ofp);
		if (ofperrors) break; /* Sigh.. */

		for (nsp = rwp->down; nsp != NULL; nsp = nsp->next) {

			ofperrors |= ferror(ofp);
			if (ofperrors) break; /* Sigh.. */

			if (!iserrmessage() && nsp->errto &&
			    nsp->errto->string) {
				/* print envelope sender address */
				putc(_CF_ERRORADDR, ofp);
				putc(_CFTAG_NORMAL, ofp);
				fprintf(ofp,"%s\n",nsp->errto->string);
				if (vfp) {
				  putc(_CF_ERRORADDR, vfp);
				  putc(_CFTAG_NORMAL, vfp);
				  fprintf(vfp,"%s\n",nsp->errto->string);
				}
			}

			fprintf(ofp, "%c%c", _CF_SENDER, _CFTAG_NORMAL);
			fromaddr = prctladdr(nsp->info, ofp, _CF_SENDER, "sender");
			if (!fromaddr) {
			  UNGCPRO5;
			  goto bad_addrdata;
			}
			
			putc('\n', ofp);
			if (vfp) {
				fprintf(vfp, "%c%c",
					_CF_SENDER, _CFTAG_NORMAL);
				prctladdr(nsp->info, vfp,
					  _CF_SENDER, "sender");
				putc('\n', vfp);
			}

			/* print recipient addresses */
			for (rcp = nsp->down; rcp != NULL; rcp = rcp->next) {

				ofperrors |= ferror(ofp);
				if (ofperrors) break; /* Sigh.. */

				if (rcp->urw.number > 0)
				  putc(_CF_XORECIPIENT, ofp);
				else
				  putc(_CF_RECIPIENT, ofp);
				putc(_CFTAG_NORMAL, ofp);
				fprintf(ofp,"%*s",(_CFTAG_RCPTPIDSIZE +
						   _CFTAG_RCPTDELAYSIZE),"");
				if (rcp->urw.number > 0)
					fprintf(ofp, "%d ", rcp->urw.number);
				if (! prctladdr(rcp->info, ofp,
						_CF_RECIPIENT, "recipient")) {
				  UNGCPRO5;
				  goto bad_addrdata;
				}
				
				putc('\n', ofp);
				++nrcpts;
				/* DSN data output ! */
				prdsndata(rcp->info, ofp, "recipient");
				if (vfp) {
				  if (rcp->urw.number > 0)
				    putc(_CF_XORECIPIENT, vfp);
				  else
				    putc(_CF_RECIPIENT, vfp);
				  putc(_CFTAG_NORMAL, vfp);
				  fprintf(vfp,"%*s",(_CFTAG_RCPTPIDSIZE +
						     _CFTAG_RCPTDELAYSIZE),"");
				  if (rcp->urw.number > 0)
				    fprintf(vfp, "%d ", rcp->urw.number);
				  prctladdr(rcp->info, vfp,
					    _CF_RECIPIENT, "recipient");
				  putc('\n', vfp);
				  /* DSN data output ! */
				  prdsndata(rcp->info, vfp, "recipient");
				}
			}
		}
		/* print header */
		putc(_CF_MSGHEADERS, ofp);
		putc('\n', ofp);
		if (vfp)
		  fprintf(vfp, "headers rewritten using '%s' function:\n",
			  rwp->info->string);

		/* print the header, replacing all To:, Cc:, fields with
		   the corresponding fields as stored with the rewrite set. */
		nh = rwp->urw.h;
		for (h = e->e_headers; h != NULL; h = h->h_next) {

			ofperrors |= ferror(ofp);
			if (ofperrors) break; /* Sigh.. */

			if (nh 
			    && (h->h_descriptor->user_type == Sender
			     || h->h_descriptor->user_type == Recipient)) {
				hdr_print(nh, ofp);
				if (vfp)
				  hdr_print(nh, vfp);
				nh = nh->h_next;
			} else {
				hdr_print(h, ofp);
				if (vfp)
				  hdr_print(h, vfp);
			}
		}
		putc('\n', ofp);
		if (vfp)
		  putc('\n', vfp);
	}

	UNGCPRO5;

	if (e->e_fp  &&  files_gid >= 0) {
		fchown(FILENO(e->e_fp), -1, files_gid);
		fchmod(FILENO(e->e_fp),
		       (0440|e->e_statbuf.st_mode) & 0660);
	}
	/* all is nirvana -- link the input file to somewhere safe */
#ifdef	USE_ALLOCA
	qpath = (char*)alloca(12+strlen(QUEUEDIR)+strlen(file));
#else
	qpath = (char*)emalloc(12+strlen(QUEUEDIR)+strlen(file));
#endif
	sprintf(qpath, "../%s/%s%s", QUEUEDIR, subdirhash, file);
	fflush(ofp);
#ifdef HAVE_FSYNC
	while (fsync(FILENO(ofp)) < 0) {
	  if (errno == EINTR || errno == EAGAIN)
	    continue;
	  break;
	}
#endif
	ofperrors |= ferror(ofp);

	if ((fclose(ofp) != 0) || ofperrors || (erename(file, qpath) != 0)) {
	  zunlink(qpath);
	  zunlink(ofpname);
#ifndef	USE_ALLOCA
	  free(ofpname);
	  free(qpath);
#endif
	  return PERR_CTRLFILE;
	}

#ifndef USE_ALLOCA
	path = (char*)emalloc(14+strlen(TRANSPORTDIR)+strlen(file));
#else
	/* This actually reallocs more space from stack, but then it
	   is just stack space and will disappear.. */
	path = (char*)alloca(14+strlen(TRANSPORTDIR)+strlen(file));
#endif
	sprintf(path, "../%s/%s%s", TRANSPORTDIR, subdirhash, file);
#ifndef HAVE_RENAME
	zunlink(path);	/* Should actually always fail.. */
#endif
	if (erename(ofpname, path) < 0) {
	  zunlink(qpath);
	  zunlink(path);
#ifndef	USE_ALLOCA
	  free(ofpname);
	  free(qpath);
	  free(path);
#endif
	  return PERR_CTRLFILE;
	}

	if (vfp) {
		fprintf(vfp, "router done processing; F='%s' TF='%s'\n", file, path);
		fflush(vfp);
#ifdef HAVE_FSYNC
		while (fsync(FILENO(vfp)) < 0) {
		  if (errno == EINTR || errno == EAGAIN)
		    continue;
		  break;
		}
#endif
		fclose(vfp);
	}

	rtsyslog(e->e_statbuf.st_mtime, (long)e->e_statbuf.st_ino,
		 fromaddr, smtprelay, (int) e->e_statbuf.st_size,
		 nrcpts, msgidstr);

#ifndef	USE_ALLOCA
	free(ofpname);
	free(qpath);
	free(path);
#endif

	/* we did it! */
	return PERR_OK;

 bad_addrdata:;

	/* Bad data in routing results, can't do it now, must defer! */

	fclose(ofp);
	zunlink(ofpname); /* created file is thrown away.. */
#ifndef	USE_ALLOCA
	free(ofpname);
#endif
	return PERR_CTRLFILE;
}

static const char *
prctladdr(info, fp, cfflag, comment)
	conscell *info; /* No conscell allocs down here */
	FILE *fp;
	int cfflag;
	const char *comment;
{
	int i = 0;
	register conscell *l, *x;
	const char *user = "?user?";
	const char *channel = NULL;
	const char *privilege = NULL, *p;

	/* We print the quad of  channel/host/user/privilege  information
	   with this routine, and we return pointer to the user info.
	   For an "error" channel we return an empty string for the user. */

	for (l = car(info); l != NULL; l = cdr(l)) {
	  ++i;
	  if (STRING(l)) {
	    if (cdr(l) == NULL /* No next == this is the last */
		&& (x = v_find(l->string)) != NULL /* can find ? */
		&& (x = cdr(x)) != NULL /* found, ... */
		&& LIST(x)) {	    /* ... and it is a list */
	      /* Find the 'privilege' item */
	      for (x = car(x); x != NULL; x = cddr(x)) {
		if (STRING(x)
		    && strcmp((char *)x->string,
			      "privilege") == 0) {
		  x = cdr(x);
		  break;
		}
	      }
	      /* if x == NULL, no privilege was specified */
	    } else
	      x = l;
	    if (x) {
	      if (x->string == NULL || *x->string == '\0')
		putc('-', fp);
	      else {
		char *s = x->string;
		int quote = 0;
		/* Do same scanner as  skip821address()  will do with
		   our result.  Does it arrive to the end-of-string ?
		   Does it do it with 'quote' state CLEAR ? */
		for ( ; *s; ++s) {
		  int c = *s;
		  if (c == '\\') {
		    ++s;
		    if (*s == 0) break;
		  }
		  if (c == quote) /* 'c' is non-zero here */
		    quote = 0;
		  else if (c == '"')
		    quote = c;
		  else if (!quote && (c == ' ' || c == '\t'))
		    break;
		}

		if (*s || quote) {
		  /* Didn't arrive to the end-of-string with quote clear! */

		  putc('"',fp);
		  for (s = x->string; *s; ++s) {
		    if (*s == '"' || *s == '\\')
		      putc('\\',fp);
		    putc(*s,fp);
		  }
		  putc('"',fp);
		} else
		  /* It is clean string not needing extra quotes */
		  fprintf(fp, "%s", x->string);
	      }
	      if (i == 4 && x->string)
		privilege = x->string;
	      if (i == 3 && x->string)
		user = x->string;
	      if (i == 1 && x->string)
		channel = x->string;
	    }
	    if (cdr(l))
	      putc(' ', fp);
	  } else if (channel && strcmp(channel,"error")!=0)
	    fprintf(stderr, "Malformed %s\n", comment);
	}
	if ((cfflag == _CF_SENDER) && channel && strcmp(channel,"error") == 0)
		user = ""; /* error channel source address -> no user! */

	if (!privilege) {
	  fprintf(stderr, "Malformed (missing) %s privilege data!\n", comment);
	  return NULL;
	}
	p = privilege;
	if (*p == '-') ++p;
	while ('0' <= *p && *p <= '9') ++p;
	if (*p) {
	  fprintf(stderr, "Malformed ('%s') %s privilege data!\n",
		  privilege, comment);
	  return NULL;
	}

	return user;
}

static void
prdsndata(info, fp, comment)
	conscell   *info;
	FILE       *fp;
	const char *comment;
{
	int i = 0;
	register conscell *l, *x = NULL; /* No allocs down here */
	const char *DSN = NULL;
	const char *ENV = NULL;
	const char *RET = NULL;

	for (l = car(info); l != NULL; l = cdr(l)) {
	  ++i;
	  if (STRING(l)) {
	    if (cdr(l) == NULL
		&& (x = v_find(l->cstring)) != NULL
		&& (x = cdr(x)) != NULL
		&& LIST(x)) {
	      for (x = car(x); x != NULL; x = cddr(x)) {
		if (STRING(x) && cdr(x) && STRING(cdr(x))) {
		  if (memcmp(x->cstring,"DSN",4) == 0) {
		    DSN = cdr(x)->cstring;
		  } else if (memcmp(x->cstring,"DSNr",5) == 0) {
		    RET = cdr(x)->cstring;
		  } else if (memcmp(x->cstring,"DSNe",5) == 0) {
		    ENV = cdr(x)->cstring;
		  }
		}
	      }
	      /* if x == NULL, no DSN was specified */
	    }
	  } else
	    fprintf(stderr, "Malformed DSN %s\n", comment);
	}
	if (DSN && *DSN)
	  fprintf(fp, "%c%c%s\n", _CF_RCPTNOTARY, _CFTAG_NORMAL, DSN);
	if (RET && *RET)
	  fprintf(fp, "%c%c%s\n", _CF_DSNRETMODE, _CFTAG_NORMAL, RET);
	if (ENV && *ENV)
	  fprintf(fp, "%c%c%s\n", _CF_DSNENVID,   _CFTAG_NORMAL, ENV);
}


static conscell *
find_errto(info)
     conscell *info;	/* No allocs under here */
{
	register conscell *x = NULL;

	if (STRING(info))
	  info = v_find(info->string);
	if (!info) return NULL;

	for (x = cadr(info); x != NULL; x = cddr(x)) {
	  if (!STRING(x))
	    return NULL; /* error in data */
	  if (strcmp((char *)x->string,"ERR") == 0) {
	    x = cdr(x);
	    break;
	  }
	}
	return x;
}
