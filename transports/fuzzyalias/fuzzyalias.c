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
#include "ta.h"
#include "fuzzy.h"


#ifndef SEEK_SET
#define SEEK_SET  0
#endif

#define	PROGNAME	"fuzzyalias"
#define	CHANNEL		"fuzzy"	/* the default channel name we deliver for */

char *dfltform[] = {
		"From: The Post Office <postmaster>",
		"Subject: Unknown user",
		"MIME-Version: 1.0",
		"Content-Type: multipart/report; report-type=delivery-status;",
		"Precedence: junk", /* BSD sendmail */
		"",
		"Processing your mail message caused the following errors:",
		"The given recipient is unknown.",
		NULL
};

char *progname;

char *logfile;
FILE *logfp;

extern char *optarg;
extern int optind;
extern int emptyline();
extern void prversion();
extern void process();

#ifndef strchr
extern char *strrchr();
extern char *strchr();
#endif

extern char *mydomain();

#ifndef	MAXPATHLEN
#define	MAXPATHLEN 1024
#endif	/* MAXPATHLEN */

int D_alloc = 0; /* For tmalloc() from libz.a ... */


int
main(argc, argv)
	int argc;
	char *argv[];
{
	char *channel, msgfilename[MAXPATHLEN+1];
	int errflg, c;
	struct ctldesc *dp;
	RETSIGTYPE (*oldsig)();
	NAMELIST *answer;
	int old_dbm, thresh, pw;
	struct rcpt *rp;
	int fd;
	char **files, **ptr;

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
	pw = 0;
	thresh = 50;
	logfile = NULL;
	while ((c = getopt(argc, argv, "c:l:pt:V")) != EOF) {
	  switch (c) {
	  case 'c':		/* specify channel scanned for */
	    channel = optarg;
	    break;
	  case 'l':		/* log file */
	    logfile = emalloc(strlen(optarg)+1);
	    strcpy(logfile, optarg);
	    break;
	  case 'p':		/* scan passwd file for user */
	    pw++;
	    break;
	  case 't':
	    thresh = atoi(optarg);
	    if (thresh<10 || thresh>90)
	    	++errflg;
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
	  fprintf(stderr,
		"Usage: %s [-V] [-c channel] [-l logfile] [-p] [-t thresh] file [file ...]\n",
		progname);
	  exit(EX_USAGE);
	}

	old_dbm = (strcmp("dbm", getzenv("DBTYPE")) == 0);

	if (logfile != NULL) {
		if ((fd = open(logfile, O_CREAT|O_APPEND|O_WRONLY, 0644)) < 0) {
			fprintf(stderr, "%s: cannot open logfile \"%s\"!\n",
				progname, logfile);
		}
		else {
		    logfp = (FILE *)fdopen(fd, "a");
		}
	}
	else {
		logfp = NULL;
	}
	
	files = (char **) emalloc((argc-optind+1)*sizeof(char *));
	for (ptr=files; optind < argc; optind++, *++ptr)
		*ptr = argv[optind];
	*ptr = NULL;

	while (!getout) {
	  char *s;

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

	  s = strchr(msgfilename,'\t');
	  if (s != NULL)
	    *s = 0;	/* Ignore the host-selector */

	  dp = ctlopen(msgfilename, channel, (char *)NULL, &getout, NULL, NULL, ctlsticky, NULL);
	  if (dp != NULL) {
	    rp = dp->recipients;
	    answer = fuzzy(rp->addr->user, thresh, pw, old_dbm, files);
	    process(dp, answer);
	    ctlclose(dp);
	  } else {
	    printf("#resync %s\n",msgfilename);
	    fflush(stdout);
	  }
	}
	if (logfp != NULL)
		fclose(logfp);

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

/* Pick recipient address from the input line.
   EXTREMELY Simple minded parsing.. */
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
	  if (s)
	    *s = 0;
	  else
	    return; /* No trailing '>' ? BAD BAD! */
	  fprintf(mfp,"to <%s>\n",buf);
	} else {
	  /*  Cc: some-address  */
	  fprintf(mfp,"to <%s>\n",buf);
	}
}

void
process(dp, answer)
	struct ctldesc *dp;
	NAMELIST *answer;
{
	char buf[BUFSIZ];
	char **cpp, *mailshare, *mfpath;
	FILE *mfp, *efp;
	int n;
	struct rcpt *rp;
	char boundarystr[400];
	char lastchar;
	int reportcnt = 0;
	struct stat stbuf;
	char *formname;
	NAMELIST *ptr;

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

	  fstat(FILENO(mfp),&stbuf);
	  sprintf(fname,"%d",stbuf.st_ino);
	  taspoolid(boundarystr, sizeof(boundarystr), stbuf.st_ctime, fname);
	  strcat(boundarystr, "=_/fuzzy/");
	  strcat(boundarystr, dom);
	}

	fprintf(mfp, "channel error\n");

	rp = dp->recipients;

	/* [Thomas Knott]
	 * Wenn der "Errors-To"-Header in der Mail angegeben war, so
	 * wird diese E-Mail-Adresse zur Ruecksendung der Fehlermeldung
	 * benutzt.
	 */
	fprintf(mfp, "to <%s>\n", rp->addr->link->user);

	/* copy error message file itself */
	if ((mailshare = getzenv("MAILSHARE")) == NULL)
	  mailshare = MAILSHARE;

	formname = (char *)((answer == NULL) ? (rp->addr->host) : progname);
	mfpath = emalloc(3 + strlen(mailshare) + strlen(FORMSDIR) +
			 strlen(formname));
	sprintf(mfpath, "%s/%s/%s", mailshare, FORMSDIR, formname);

	if ((efp = fopen(mfpath, "r")) != NULL) {
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

	  fseek(efp,0,0); /* Rewind! */
	  fputs("env-end\n",mfp);

	  /* copy To: from error return address */
	  /* [Thomas Knott]
	   * Wenn der "Errors-To"-Header in der Mail angegeben war, so
	   * wird diese E-Mail-Adresse zur Ruecksendung der Fehlermeldung
	   * benutzt, ansonsten die in der "from"-Enveloppe angegebenen
	   * Adresse.
	   */
	  fprintf(mfp, "To: %s\n",
		  (*rp->addr->link->user != '\0') ? rp->addr->link->user :
		  "postmaster");

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
	  for (cpp = &dfltform[0]; *cpp != NULL; ++cpp)
	    if (*cpp[0] == 0) {
	      fprintf(mfp, "\tboundary=\"%s\"\n\n\n",boundarystr);
	      fprintf(mfp, "--%s\n", boundarystr);
	      fprintf(mfp, "Content-Type: text/plain\n");
	    } else
	      fprintf(mfp, "%s\n", *cpp);
	}
	/* print out fuzzy matches in standard format */
	fputc('\n', mfp);
	if (answer != NULL) {
		fprintf(mfp, "The following addresses are the nearest matches of known recipients:\n");
		if (logfp != NULL) {
		    fprintf(logfp, "%s: %s ->", dp->logident, rp->addr->user);
		}
		for (ptr=answer; ptr!=NULL; ptr=ptr->next) {
		    fprintf(mfp, "\t%s\n", ptr->name);
		    if (logfp != NULL) {
		    	fprintf(logfp, " %s", ptr->name);
		    }
		}
		++reportcnt;
	}
	else {
		if (logfp != NULL) {
		    fprintf(logfp, "%s: no fuzzy matches found", dp->logident);
		}

		/* print out errors in standard format */
		for (rp = dp->recipients; rp != NULL; rp = rp->next) {
		  /* If not prohibited, print it! */
		if (rp->notify == NULL || !CISTREQN(rp->notify,"NEVER",5)) {
		    fprintf(mfp, "error: %s: %s\n",
			    rp->addr->host, rp->addr->user);
		    ++reportcnt;
		  }
		}
	}
	if (logfp != NULL) {
		rp = dp->recipients;
		fprintf(logfp, "\n%s: Sent to %s\n", dp->logident,
			(*rp->addr->link->user == '\0') ? "postmaster" :
			rp->addr->link->user);
	}

	/* Did we report anything ? */
	if (reportcnt == 0){
	  /* No, throw it away and ack success. */
	  mail_abort(mfp);
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
	if (dp->envid != NULL)
	  fprintf(mfp, "Original-Envelope-Id: %s\n",dp->envid);
	/* rfc822date() returns a string with trailing newline! */
	fprintf(mfp, "Arrival-Date: %s", rfc822date(&stbuf.st_ctime));
	fprintf(mfp, "\n");

	for (rp = dp->recipients; rp != NULL; rp = rp->next) {
	  /* If not prohibited, print it! */
	  const char *typetag;
	  const char *rcpt;
	  static char const *type_rfc   = "RFC822";
	  static char const *type_local = "X-LOCAL";

	if (rp->notify != NULL || CISTREQN(rp->notify,"NEVER",5)) 
	    continue;
	  rcpt = rp->addr->user;
	  if (strchr(rcpt,'@') != NULL) {
	    typetag = type_rfc;
	    if (strncmp(rcpt,"ns:",3)==0) /* 'hold'-channel stuff */
	      typetag = type_local;
	  } else
	    typetag = type_local;
	  fprintf(mfp, "Final-Recipient: %s; %s\n", typetag, rcpt);
	  fprintf(mfp, "Action: failed\n");
	  fprintf(mfp, "Diagnostic-Code: X-LOCAL; 500 (%s)\n", rp->addr->host );
	  if (rp->orcpt != NULL)
	    fprintf(mfp, "Original-Rcpt: %s\n",rp->orcpt);
	  fprintf(mfp, "\n");
	}

	fprintf(mfp, "--%s\n", boundarystr);
	fprintf(mfp, "Content-Type: message/rfc822\n\n");

	/* Skip over the delivery envelope lines! */

	rp = dp->recipients;
	/* copy original message file */

	/* seek to message body -- try it anyway */
	lseek(dp->msgfd, dp->msgbodyoffset, SEEK_SET);

	/* write the (new) headers with local "Received:"-line.. */
	writeheaders(rp,mfp,"\n",0,0);
	fprintf(mfp,"\n");

	/* If the DSN RET=NO is in effect, don't copy the msg body! */
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
