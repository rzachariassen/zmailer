/*
 *	Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include "hostenv.h"
#include <stdio.h>
#include <ctype.h>
#include "malloc.h"
#include <pwd.h>
#include <sysexits.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include "mail.h"
#include "zmsignal.h"
#include "zsyslog.h"

#include "ta.h"
#include "libz.h"

#define	PROGNAME	"errormail"
#define	CHANNEL		"error"	/* the default channel name we deliver for */

const char *dfltform[] = {
		"From: The Post Office <postmaster>",
		"Subject: email delivery error",
		"Cc: The Postmaster <postmaster>",
		"MIME-Version: 1.0",
		"Precedence: junk", /* BSD sendmail */
		"Content-Type: multipart/report; report-type=delivery-status;",
		"",
		"Processing your mail message caused the following errors:",
		NULL
};

char *progname;

extern char *optarg;
extern int  optind;
extern void process __((struct ctldesc *));

#ifndef strchr
extern char *strrchr(), *strchr();
#endif

#ifndef	MAXPATHLEN
#define	MAXPATHLEN 1024
#endif	/* MAXPATHLEN */

int D_alloc = 0; /* For tmalloc() from libz.a ... */


int
main(argc, argv)
	int argc;
	char *argv[];
{
	const char *channel;
	char msgfilename[MAXPATHLEN+1];
	int errflg, c;
	struct ctldesc *dp;
	RETSIGTYPE (*oldsig) __((int));

	SIGNAL_HANDLESAVE(SIGINT, SIG_IGN, oldsig);
	if (oldsig != SIG_IGN)
	  SIGNAL_HANDLE(SIGINT, wantout);
	SIGNAL_HANDLESAVE(SIGHUP, SIG_IGN, oldsig);
	if (oldsig != SIG_IGN)
	  SIGNAL_HANDLE(SIGHUP, wantout);
	SIGNAL_HANDLESAVE(SIGTERM, SIG_IGN, oldsig);
	if (oldsig != SIG_IGN)
	  SIGNAL_HANDLE(SIGTERM, wantout);
	SIGNAL_HANDLESAVE(SIGQUIT, SIG_IGN, oldsig);
	if (oldsig != SIG_IGN)
	  SIGNAL_HANDLE(SIGQUIT, wantout);
	SIGNAL_IGNORE(SIGPIPE);

	if ((progname = strrchr(argv[0], '/')) == NULL)
	  progname = argv[0];
	else
	  ++progname;
	errflg = 0;
	channel = CHANNEL;
	while (1) {
	  c = getopt(argc, argv, "c:V");
	  if (c == EOF)
	    break;
	  switch (c) {
	  case 'c':		/* specify channel scanned for */
	    channel = optarg;
	    break;
	  case 'V':
	    prversion(PROGNAME);
	    exit(EX_OK);
	    break;
	  default:
	    ++errflg;
	    break;
	  }
	}
	if (errflg || optind != argc) {
	  fprintf(stderr, "Usage: %s [-V] [-c channel]\n",
		  argv[0]);
	  exit(EX_USAGE);
	}

	/* We need this latter on .. */
	zopenlog("errormail", LOG_PID, LOG_MAIL);

	while (!getout) {
	  char *host;

	  printf("#hungry\n");
	  fflush(stdout);

	  if (fgets(msgfilename, sizeof msgfilename, stdin) == NULL) break;
	  if (strchr(msgfilename, '\n') == NULL) break; /* No ending '\n' !
							   Must have been
							   partial input! */
	  if (strcmp(msgfilename, "#idle\n") == 0)
	    continue; /* Ah well, we can stay idle.. */

	  /* Input:
	       spool/file/name [ \t host.info ] \n
	   */

	  if (emptyline(msgfilename, sizeof msgfilename))
	    break;

	  host = strchr(msgfilename,'\t');
	  if (host != NULL)
	    *host++ = 0;

	  dp = ctlopen(msgfilename, channel, host, &getout, ctlsticky, NULL, NULL, NULL);
	  if (dp != NULL) {
	    process(dp);
	    ctlclose(dp);
	  } else {
	    printf("#resync %s\n",msgfilename);
	    fflush(stdout);
	  }
	}
	return 0;
}

/*
#ifndef MALLOC_TRACE
univptr_t
tmalloc(n)
	size_t n;
{
	return emalloc((u_int)n);
}
#endif
*/

void encodeXtext __((FILE *, const char *, int));
void encodeXtext(mfp,s,len)
	FILE *mfp;
	const char *s;
	int len;
{
	while (*s && len > 0) {
	  int c = (*s) & 0xFF;
	  if ('!' <= c && c <= '~' && c != '+' && c != '=')
	    putc(c,mfp);
	  else
	    fprintf(mfp,"+%02X",c);
	  ++s;
	  --len;
	}
}

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


/* Pick recipient address from the input line.
   EXTREMELY Simple minded parsing.. */
static void pick_env_addr __((const char *buf, FILE *mfp));
static void pick_env_addr(buf,mfp)
const char *buf;
FILE *mfp;
{
	const char *s = buf;

	while (*s != 0 && *s != ' ' && *s != '\t' && *s != ':') ++s;
	if (*s != ':') return; /* BAD INPUT! */
	buf = ++s; /* We have skipped the initial header.. */

	s = strchr(buf,'<');
	if (s != NULL) {
	  /*  Cc:  The Postoffice managers <postoffice> */
	  buf = ++s;
	  s = strrchr(buf,'>');
	  if (s == NULL)
	    return; /* No trailing '>' ? BAD BAD! */
	  fprintf(mfp,"todsn NOTIFY=NEVER ORCPT=rfc822;");
	  encodeXtext(mfp, buf, (int)(s - buf));
	  fprintf(mfp,"\nto <%.*s>\n",(int)(s - buf), buf);
	} else {
	  /*  Cc: some-address  */
	  fprintf(mfp,"todsn NOTIFY=NEVER ORCPT=rfc822;");
	  s = buf + strlen(buf) - 1;
	  encodeXtext(mfp,buf,strlen(buf));
	  fprintf(mfp,"\nto <%s>\n",buf);
	}
}

void
process(dp)
	struct ctldesc *dp;
{
	char buf[BUFSIZ];
	const char **cpp, *mailshare, *mfpath;
	FILE *mfp, *efp;
	int n;
	struct rcpt *rp;
	char boundarystr[400];
	char lastchar;
	int reportcnt = 0;
	struct stat stbuf;

	if (fstat(dp->msgfd, &stbuf) != 0)
	  abort(); /* This is a "CAN'T FAIL" case.. */

	/* recipient host field is the error message file name in FORMSDIR */
	/* recipient user field is the address causing the error */

	if (dp->senders == NULL) {
	  /*
	   * If there was no error return address
	   * it might be because this message was
	   * an error message being bounced back.
	   * We do NOT want to bounce this, but
	   * instead just drop it on the floor.
	   */
	  for (rp = dp->recipients; rp != NULL; rp = rp->next)
	    diagnostic(rp, EX_OK, 0, "error bounce dropped");
	  return;
	}

	if ((mfp = mail_open(MSG_RFC822)) == NULL) {
	  for (rp = dp->recipients; rp != NULL; rp = rp->next)
	    diagnostic(rp, EX_TEMPFAIL, 0, "mail_open failure");
	  warning("Cannot open mail file!");
	  return;
	}

	{
	  char *dom = mydomain(); /* transports/libta/buildbndry.c */
	  char fname[20];
	  struct stat stbuf;

	  fstat(fileno(mfp),&stbuf);
	  sprintf(fname,"%ld",(long)stbuf.st_ino);
	  taspoolid(boundarystr, sizeof(boundarystr), stbuf.st_ctime, fname);
	  strcat(boundarystr, "=_/errmail/");
	  strcat(boundarystr, dom);
	}

	fprintf(mfp, "channel error\n");

	rp = dp->recipients;

	fprintf(mfp, "todsn NOTIFY=NEVER ORCPT=RFC822;");
	encodeXtext(mfp, rp->addr->link->user, strlen(rp->addr->link->user));
	fprintf(mfp, "\nto <%s>\n",rp->addr->link->user);

	/* copy error message file itself */
	mailshare = getzenv("MAILSHARE");
	if (mailshare == NULL)
	  mailshare = MAILSHARE;

	mfpath = emalloc(3 + strlen(mailshare) + strlen(FORMSDIR) +
			 strlen(rp->addr->host));
	sprintf((char*)mfpath, "%s/%s/%s", mailshare, FORMSDIR, rp->addr->host);

	efp = fopen(mfpath, "r");
	if (efp != NULL) {
	  int inhdr = 1;
	  buf[sizeof(buf)-1] = 0;
	  while (fgets(buf,sizeof(buf)-1,efp) != NULL) {
	    if (strncmp(buf,"HDR",3)==0)
	      continue;
	    else if (strncmp(buf,"ADR",3)==0)
	      pick_env_addr(buf+4,mfp);
	    else if (strncmp(buf,"SUB",3)==0)
	      continue;
	    else
	      break;
	  }
	  fseek(efp,(off_t)0,0); /* Rewind! */
	  fputs("env-end\n",mfp);

	  /* copy To: from error return address */
	  fprintf(mfp, "To: <%s>\n", rp->addr->link->user);

	  while (fgets(buf,sizeof(buf)-1,efp) != NULL) {
	    if (strncmp(buf,"HDR",3)==0) {
	      fputs(buf+4,mfp);
	    } else if (strncmp(buf,"ADR",3)==0) {
	      fputs(buf+4,mfp);
	    } else if (strncmp(buf,"SUB",3)==0) {
	      fputs(buf+4,mfp);
	    } else {
	      if (inhdr) {
		inhdr = 0;
		fprintf(mfp,"MIME-Version: 1.0\n");
		fprintf(mfp,"Content-Type: multipart/report; report-type=delivery-status;\n");
		fprintf(mfp,"\tboundary=\"%s\"\n\n\n",boundarystr);
		fprintf(mfp, "--%s\n", boundarystr);
		fprintf(mfp, "Content-Type: text/plain\n");
	      }
	      fputs(buf,mfp);
	    }
	  } /* ... while() ends.. */
	  fclose(efp);
	} else {
	  fputs("to <postmaster>\n",mfp); /* Default-form Cc: ... */
	  fputs("env-end\n",mfp);
	  for (cpp = &dfltform[0]; *cpp != NULL; ++cpp)
	    if (**cpp == '\0') {
	      fprintf(mfp, "\tboundary=\"%s\"\n\n\n", boundarystr);
	      fprintf(mfp, "--%s\n", boundarystr);
	      fprintf(mfp, "Content-Type: text/plain\n");
	    } else
	      fprintf(mfp, "%s\n", *cpp);
	}
	/* print out errors in standard format */
	fputc('\n', mfp);
	for (rp = dp->recipients; rp != NULL; rp = rp->next) {
	  /* If not prohibited, print it! */
	  if ( rp->notifyflgs & _DSN_NOTIFY_FAILURE ) {
	    fprintf(mfp, "error: %s: %s\n",
		    rp->addr->host, rp->addr->user);
	    ++reportcnt;
	  }
	}

	/* Did we report anything ? */
	if (reportcnt == 0){
	  /* No, throw it away and ack success. */
	  mail_abort(mfp);
	  for (rp = dp->recipients; rp != NULL; rp = rp->next)
	    if (!(rp->notifyflgs & _DSN_NOTIFY_FAILURE))
	      diagnostic(rp, EX_OK, 0, NULL);
	  return;
	}

	fprintf(mfp, "\n--%s\n", boundarystr);
	fprintf(mfp, "Content-Type: message/delivery-status\n\n");

	/* Print out errors in IETF-NOTARY format as well! */

	if (mydomain() != NULL) {
	  fprintf(mfp, "Reporting-MTA: dns; %s\n", mydomain() );
	} else {
	  fprintf(mfp, "Reporting-MTA: x-local-hostname; -unknown-\n");
	}
	if (dp->envid != NULL) {
	  fprintf(mfp, "Original-Envelope-Id: ");
	  decodeXtext(mfp,dp->envid);
	  putc('\n',mfp);
	}
	/* rfc822date() returns a string with trailing newline! */
	fprintf(mfp, "Arrival-Date: %s", rfc822date(&stbuf.st_ctime));
	fprintf(mfp, "\n");

	for (rp = dp->recipients; rp != NULL; rp = rp->next) {
	  /* If not prohibited, print it! */
	  const char *typetag;
	  const char *rcpt;
	  static const char *type_rfc   = "RFC822";
	  static const char *type_local = "X-LOCAL";

	  if (rp->notify != NULL && CISTREQN(rp->notify,"NEVER",5))
	    continue;
	  rcpt = rp->addr->user;
	  if (strchr(rcpt,'@') != NULL) {
	    typetag = type_rfc;
	    if (strncmp(rcpt,"ns:",3)==0) /* 'hold'-channel stuff */
	      typetag = type_local;
	  } else
	    typetag = type_local;
	  if (rp->orcpt != NULL) {
	    fprintf(mfp, "Original-Recipient: ");
	    decodeXtext(mfp,rp->orcpt);
	    putc('\n',mfp);
	  }
	  fprintf(mfp, "Final-Recipient: %s; %s\n", typetag, rcpt);
	  fprintf(mfp, "Action: failed\n");
	  fprintf(mfp, "Status: 5.0.0\n");
	  fprintf(mfp, "Diagnostic-Code: X-LOCAL; 500 (%s)\n", rp->addr->host );
	  fprintf(mfp, "\n");
	}

	fprintf(mfp, "--%s\n", boundarystr);
	fprintf(mfp, "Content-Type: message/rfc822\n\n");

	/* Skip over the delivery envelope lines! */

	rp = dp->recipients;
	/* copy original message file */

	/* seek to message body -- try it anyway */
	lseek(dp->msgfd, (off_t)(dp->msgbodyoffset), SEEK_SET);

	/* write the (new) headers with local "Received:"-line.. */
	writeheaders(rp,mfp,"\n",0,0,NULL);
	fprintf(mfp,"\n");

	/* If the DSN RET=HDRS is in effect, don't copy the msg body! */
	if (!dp->dsnretmode || CISTREQN(dp->dsnretmode,"FULL",4)) {

	  /* Copy out the rest with somewhat more efficient method */
	  lastchar = 0;
	  while ((n = read(dp->msgfd, buf, sizeof(buf))) > 0) {
	    fwrite(buf, sizeof buf[0], n, mfp);
	    lastchar = buf[n-1];
	  }
	  if (lastchar != '\n')
	    fputs("\n",mfp);
	}

	fprintf(mfp, "--%s--\n", boundarystr);
	if (ferror(mfp)) {
	  mail_abort(mfp);
	  n = EX_IOERR;
	} else if (mail_close(mfp) == EOF)
	  n = EX_IOERR;
	else
	  n = EX_OK;
	for (rp = dp->recipients; rp != NULL; rp = rp->next) {
	  diagnostic(rp, n, 0, (char *)NULL);
	}
}
