/*
 *    Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *      This will be free software, but only when it is finished.
 */
/*
 *    Several extensive changes by Matti Aarnio <mea@nic.funet.fi>
 *      Copyright 1991-2004.
 */
/*
 * Zmailer SMTP-server divided into bits
 *
 * The basic commands:
 *
 *  - DATA (RFC 821)
 *  - BDAT (RFC 1830)
 *
 */

/* XX: for anti-spam hack */
/* #define USE_ANTISPAM_HACKS */
/* #define USE_STRICT_MSGID_FREEZING */

#define FREEZE__X_ADVERTISEMENT_FOUND                   951
#ifdef  USE_ANTISPAM_HACKS
#define FREEZE__X_UIDL_FOUND                            952
#define FREEZE__IMPROBABLE_RECEIVED_HEADER_FOUND        952
#define FREEZE__MALFORMED_MESSAGE_ID_HEADER             953
#endif

#include "smtpserver.h"

#ifdef USE_TRANSLATION
#include <libtrans.h>
#endif				/* USE_TRANSLATION */

#define SKIPSPACE(Y) while (*Y == ' ' || *Y == '\t') ++Y
#define SKIPDIGIT(Y) while ('0' <= *Y && *Y <= '9') ++Y
#define SKIPTEXT(Y)  while (*Y && *Y != ' ' && *Y != '\t') ++Y

static int mvdata __((SmtpState *, char *));
static int mvbdata __((SmtpState *, char *, long));

static int parsestatcode __((const char **ss, const char **statcode));
static int parsestatcode(ssp, statcodep)
     const char **ssp;
     const char **statcodep;
{
    int code = -1;
    const unsigned char *ss = (const unsigned char *) *ssp;
    static char statcodebuf[6];

    *statcodep = NULL;

    for (;'0' <= *ss && *ss <= '9'; ++ss) {
      if (code < 0) code = 0;
      code = code * 10 + (*ss - '0');
    }
    SKIPSPACE(ss);
    if (isdigit(ss[0]) && ss[1] == '.' &&
	isdigit(ss[2]) && ss[3] == '.' &&
	isdigit(ss[4])) {
      memcpy(statcodebuf, ss, 5);
      statcodebuf[5] = 0;
      *statcodep = statcodebuf;
      ss += 5;
    }
    SKIPSPACE(ss);
    *ssp = (const char *) ss;
    if (code < 200 || code > 599) code = 0;
    return code;
}

int smtp_data(SS, buf, cp)
SmtpState *SS;
const char *buf, *cp;
{
    int filsiz;
    long tell = 0;
    int i, j;
    char msg[2048];

    struct stat stbuf;
    char *fname;
    char taspid[30];

    MIBMtaEntry->ss.ReceivedMessagesSs  += 1;
    MIBMtaEntry->ss.ReceivedRecipientsSs += SS->ok_rcpt_count;
    MIBMtaEntry->ss.IncomingSMTP_DATA   += 1;

    while ((strict_protocol < 1) && (*cp == ' ' || *cp == '\t')) ++cp;
    if ((strict_protocol > 0) && *cp != 0) {
	MIBMtaEntry->ss.IncomingSMTP_DATA_bad += 1;
	type(SS, 501, m554, "Extra junk after 'DATA' verb");
	return 0;
    }

    if (SS->state != RecipientOrData) {
	switch (SS->state) {
	case Hello:
	    cp = "Waiting for HELO command";
	    break;
	case Mail:
	case MailOrHello:
	    cp = "Waiting for MAIL command";
	    break;
	case Recipient:
	    cp = "Waiting for RCPT command";
	    break;
	case BData:
	    cp = "Must not intermix BDAT and DATA in same transaction!";
	    break;
	default:
	    cp = NULL;
	    break;
	}
	MIBMtaEntry->ss.IncomingSMTP_DATA_bad += 1;
	type(SS, 503, m552, "Hi %s, %s", SS->rhostaddr, cp);
	typeflush(SS);
	if (SS->mfp) {
	  mail_abort(SS->mfp);
	  policytest(&SS->policystate, POLICY_DATAABORT,
		     NULL, SS->rcpt_count, NULL);
	  SS->rcpt_count = 0;
	}
	return 0;
    }

    if (ferror(SS->mfp)) {
	type(SS, 452, m430, (char *) NULL);
	typeflush(SS);
	clearerr(SS->mfp);
	mail_abort(SS->mfp);
	policytest(&SS->policystate, POLICY_DATAABORT,
		   NULL, SS->rcpt_count, NULL);

	MIBMtaEntry->ss.IncomingSMTP_DATA_bad += 1;
	SS->mfp = NULL;
	reporterr(SS, tell, "message file error");
	return 0;
    }
    if (SS->sender_ok == 0) {
	type(SS, 550, "5.1.7", "No valid sender, rejecting all recipients");
	typeflush(SS);
	SS->state = MailOrHello;
	if (SS->mfp) {
	  mail_abort(SS->mfp);
	  policytest(&SS->policystate, POLICY_DATAABORT,
		     NULL, SS->rcpt_count, NULL);
	}
	MIBMtaEntry->ss.IncomingSMTP_DATA_bad += 1;
	SS->mfp = NULL;
	return 0;
    }
    if (SS->rcpt_count == 0) {
	/* No valid recipients! */
	type(SS, 550, "5.1.3", "No valid recipients at RCPT addresses, or no RCPT addresses at all");
	typeflush(SS);
	SS->state = MailOrHello;
	mail_abort(SS->mfp);
	MIBMtaEntry->ss.IncomingSMTP_DATA_bad += 1;
	SS->mfp = NULL;
	return 0;
    }
    if ((SS->from_box != 0) && (SS->rcpt_count > MaxErrorRecipients)) {
	/* Too many recipients for a  "MAIL FROM:<>" */
	type(SS, 550, "5.7.1", "SPAM trap -- too many recipients for an empty source address!");
	typeflush(SS);
	SS->state = MailOrHello;
	mail_abort(SS->mfp);
	policytest(&SS->policystate, POLICY_DATAABORT,
		   NULL, SS->rcpt_count, NULL);
	MIBMtaEntry->ss.IncomingSMTP_DATA_bad += 1;
	SS->mfp = NULL;
	return 0;
    }
    type(SS, 354, NULL, (char *) NULL);
    typeflush(SS);
    fputs("env-end\n", SS->mfp);

    if (msa_mode && SS->authuser != NULL ) {
      fprintf(SS->mfp, "X-Comment: RFC 2476 MSA function at %s logged sender identity as: %s\n", SS->myhostname, SS->authuser);
    }

#ifdef HAVE_SPF_ALT_SPF_H
    if (spf_received && policyspfhdr(policydb, &SS->policystate)) {
      fprintf(SS->mfp,"%s\n", policyspfhdr(policydb, &SS->policystate));
    }
#endif

    /* We set alarm()s inside the mvdata() */
    *msg = 0;
    filsiz = mvdata(SS, msg);
    SS->messagesize = filsiz;

    fflush(SS->mfp);
    fname = mail_fname(SS->mfp);
    fstat(FILENO(SS->mfp), &stbuf);

    taspoolid(taspid, stbuf.st_mtime, stbuf.st_ino);
    tell = stbuf.st_size,

    report(SS, "Got '.'; tell=%ld", tell);

    {
      long bavail, bused, iavail, iused;
      if (0 == fd_statfs(FILENO(SS->mfp), &bavail, &bused, &iavail, &iused)) {
	MIBMtaEntry->sys.SpoolUsedSpace = bused;
	MIBMtaEntry->sys.SpoolFreeSpace = bavail;

	availspace = bavail - minimum_availspace;
	if (availspace > (LONG_MAX / 1024))
	  availspace = LONG_MAX / 1024;
	availspace *= 1024;
	
	MIBMtaEntry->sys.SpoolUsedFiles = iused;
	MIBMtaEntry->sys.SpoolFreeFiles = iavail;
      }
    }

    if (*msg != 0) {
	mail_abort(SS->mfp);
	policytest(&SS->policystate, POLICY_DATAABORT,
		   NULL, SS->rcpt_count, NULL);
	MIBMtaEntry->ss.IncomingSMTP_DATA_bad += 1;
	SS->mfp = NULL;
	type(SS, 452, m430, "%s", msg);
	if (lmtp_mode) for(i = 1; i < SS->ok_rcpt_count; ++i)
	    type(SS, 452, m430, "%s", msg);
	typeflush(SS);
    } else if (s_feof(SS)) {
	if (STYLE(SS->cfinfo,'D')) {
	  /* Says: DON'T DISCARD -- aka DEBUG ERRORS! */
	  mail_close_alternate(SS->mfp,"public",".DATA-EOF");
	} else {
	  mail_abort(SS->mfp);
	  policytest(&SS->policystate, POLICY_DATAABORT,
		     NULL, SS->rcpt_count, NULL);
	}
	MIBMtaEntry->ss.IncomingSMTP_DATA_bad += 1;
	SS->mfp = NULL;
	reporterr(SS, tell, "premature EOF on DATA input");
	typeflush(SS);
	return -1;
    } else if (availspace < 0 || ferror(SS->mfp)) {
	type(SS, 452, m430, NULL); /* insufficient system storage */
	if (lmtp_mode) for(i = 1; i < SS->ok_rcpt_count; ++i)
	  type(SS, 452, m430, NULL); /* insufficient system storage */
	typeflush(SS);
	reporterr(SS, tell, ferror(SS->mfp) ? "write to spool file failed" : "system free storage under limit");
	clearerr(SS->mfp);
	mail_abort(SS->mfp);
	policytest(&SS->policystate, POLICY_DATAABORT,
		   NULL, SS->rcpt_count, NULL);
	MIBMtaEntry->ss.IncomingSMTP_DATA_bad += 1;
	SS->mfp = NULL;
    } else if (maxsize > 0 && filsiz > maxsize) {
	mail_abort(SS->mfp);
	policytest(&SS->policystate, POLICY_DATAABORT,
		   NULL, SS->rcpt_count, NULL);
	MIBMtaEntry->ss.IncomingSMTP_DATA_bad += 1;
	SS->mfp = NULL;
	type(SS, 552, "5.3.4", "Size of this message exceeds the fixed maximum size of  %ld  chars for received email ", maxsize);
	if (lmtp_mode) for(i = 1; i < SS->ok_rcpt_count; ++i)
	  type(SS, 552, "5.3.4", "Size of this message exceeds the fixed maximum size of  %ld  chars for received email ", maxsize);
	typeflush(SS);
    } else {

	/* Things have been good thus far, now we store
	   the resulting file into router spool area;
	   pending a few things we do at first.. */

	const char *statcode = NULL, *ss, *ss0;
	int code = 0;
	const char *sslines[20];
	int sslinecnt = 0;


	/* Lets see what the content-policy will tell now ? */

	if (debug) typeflush(SS);
	SS->policyresult = contentpolicy(&SS->policystate, fname);

	ss0 = ss  = policymsg(&SS->policystate);

	if (ss)
	  type(NULL,0,NULL,
	       "Content-policy analysis ordered message %s. (code=%d); msg='%s'",
	       (SS->policyresult < 0 ? "rejection" :
		(SS->policyresult > 0 ? "freezing" : "acceptance")),
	       SS->policyresult, ss);

	if (ss) {
	  char *p, *s;
	  code = parsestatcode(&ss,&statcode);
	  s = (char *)ss;
	  p = strchr(s,'\r');
	  sslinecnt = 0;
	  if (p) {
	    /* Multiline! CRs in message text... */
	    while (p && sslinecnt < 17) { /* Arbitrary fixed limit.. */
	      *p++ = '\0';
	      sslines[sslinecnt++] = s;
	      sslines[sslinecnt+0] = p;
	      sslines[sslinecnt+1] = NULL;
	      s = p;
	      p = strchr(s,'\r');
	    }
	  }
	}
	if (!ss || *ss == 0) {
	  if (SS->policyresult < 0)
	    sslines[0] = ss = "rejected, no further explanations";
	  else  if (SS->policyresult == 0)
	    sslines[0] = ss = "accepted";
	  else
	    sslines[0] = ss = "accepted into freezer, no explanations";
	  sslines[1] = NULL;
	}

	if (SS->policyresult < 0) {

	  if (!statcode)  statcode = m571;
	  if (!code)      code = 552;

	  type(SS, -code, statcode, "Content-Policy msg: %s; %s", ss, taspid);
	  for (j= 1; j <= sslinecnt; ++j)
	    type(SS, -code, statcode, "msg: %s", sslines[j]);
	  type(SS, code, statcode, "Content-Policy analysis rejected this message");

	  if (lmtp_mode) for(i = 1; i < SS->ok_rcpt_count; ++i) {
	    type(SS, -code, statcode, "Content-Policy msg: %s; %s", ss, taspid);
	    for (j= 1; j <= sslinecnt; ++j)
	      type(SS, -code, statcode, "msg: %s", sslines[j]);
	    type(SS, code, statcode, "Content-Policy analysis rejected this message");
	  }

	  mail_abort(SS->mfp);
	  policytest(&SS->policystate, POLICY_DATAABORT,
		     NULL, SS->rcpt_count, NULL);
	  MIBMtaEntry->ss.IncomingSMTP_DATA_bad += 1;
	  SS->mfp = NULL;
	} else if (SS->policyresult > 0) {
	  char polbuf[20];

	  runasrootuser();
	  sprintf(polbuf,"policy-%d",SS->policyresult);
	  if (mail_close_alternate(SS->mfp, FREEZERDIR, polbuf) != 0) {
	    type(NULL,0,NULL,
		 "mail_close_alternate(..'FREEZER','%s') failed, errno=%d (%s)",
		 polbuf, errno, strerror(errno));
	    type(SS, 452, m430, "Message file disposition failed; %s", taspid);
	    if (lmtp_mode) for(i = 1; i < SS->ok_rcpt_count; ++i)
	      type(SS, 452, m430, "Message file disposition failed; %s", taspid);
	    typeflush(SS);
	    SS->mfp = NULL;
	    reporterr(SS, tell, "message file close failed");
	  } else {

	    smtp_tarpit(SS);

	    if (!statcode)  statcode = "2.7.1";
	    if (!code)      code = 250;

	    type(SS, -code, statcode, "%s; %s", ss, taspid);
	    for (j= 1; j <= sslinecnt; ++j)
	      type(SS, -code, statcode, "%s", sslines[j]);
	    type(SS, code, statcode, "Content-Policy accepted this message into freezer-%d; %s", SS->policyresult, taspid);
	    
	    if (lmtp_mode) for(i = 1; i < SS->ok_rcpt_count; ++i) {
	      type(SS, -code, statcode, "%s; %s", ss, taspid);
	      for (j= 1; j <= sslinecnt; ++j)
		type(SS, -code, statcode, "%s", sslines[j]);
	      type(SS, code, statcode, "Content-Policy accepted this message into freezer-%d; %s", SS->policyresult, taspid);
	    }

	    typeflush(SS);
	    SS->mfp = NULL;
	    zsyslog((LOG_INFO, "accepted  %s (%ldc) from %s/%d into freeze[%d]",
		     taspid, tell, SS->rhostname, SS->rport, SS->policyresult));
	  }
	  MIBMtaEntry->ss.IncomingSMTP_DATA_bad += 1;

	  runastrusteduser();
	} else {

	  /*  Ok, we didn't have smtp-policy defined freezer action,
	      lets see if we do it some other way.. */

	  if (mail_close(SS->mfp) == EOF) {
	    type(SS, 452, m430, (char *) NULL);
	    if (lmtp_mode) for(i = 1; i < SS->ok_rcpt_count; ++i)
	      type(SS, 452, m430, (char *) NULL);
	    typeflush(SS);
	    SS->mfp = NULL;
	    reporterr(SS, tell, "message file close failed");
	    MIBMtaEntry->ss.IncomingSMTP_DATA_bad += 1;

	  } else {
	    /* Ok, build response with proper "spoolid" */

	    SS->mfp = NULL;
	    if (!ss || *ss == 0) {
	      type(SS, 250, "2.0.0", "Message accepted; %s", taspid);
	      if (lmtp_mode) for(i = 1; i < SS->ok_rcpt_count; ++i)
		type(SS, 250, "2.0.0", "Message accepted; %s", taspid);
	    } else {
	      if (!statcode)  statcode = "2.0.0";
	      if (!code)      code = 250;

	      if (sslinecnt < 1)
		type(SS,  code, statcode, "%s; %s", ss, taspid);
	      else
		type(SS, -code, statcode, "%s; %s", ss, taspid);
	      for (j= 1; j <= sslinecnt; ++j)
		type(SS, -code, statcode, "%s", sslines[j]);
	      if (sslinecnt >= 1)
		type(SS, code, statcode, "Content-Policy accepted this message; %s", taspid);
	      if (lmtp_mode) for(i = 1; i < SS->ok_rcpt_count; ++i) {
		if (sslinecnt < 1)
		  type(SS,  code, statcode, "%s; %s", ss, taspid);
		else
		  type(SS, -code, statcode, "%s; %s", ss, taspid);
		for (j= 1; j <= sslinecnt; ++j)
		  type(SS, -code, statcode, "%s", sslines[j]);
		if (sslinecnt >= 1)
		  type(SS, code, statcode, "Content-Policy accepted this message; %s", taspid);
	      }
	    }
	    typeflush(SS);

	    if (smtp_syslog)
	      zsyslog((LOG_INFO,
		       "%s: (%ldc) accepted from %s/%d", taspid, tell,
		       SS->rhostname, SS->rport));
		
	    policytest(&SS->policystate, POLICY_DATAOK,
		       NULL, SS->rcpt_count, NULL);

	    MIBMtaEntry->ss.IncomingSMTP_DATA_ok    += 1;

	    MIBMtaEntry->ss.TransmittedMessagesSs   += 1;
	    MIBMtaEntry->ss.TransmittedRecipientsSs += SS->ok_rcpt_count;

	    MIBMtaEntry->ss.IncomingSMTP_DATA_KBYTES  += (SS->messagesize+1023)/1024;
	    MIBMtaEntry->ss.IncomingSMTP_spool_KBYTES += (tell + 1023)/1024;

	    type(NULL,0,NULL,"%s: %ld bytes", taspid, tell);
	    if (logfp)
	      fflush(logfp);
	  }
	}
    }

    SS->state = MailOrHello;
    typeflush(SS);
    return 0;
}

int smtp_bdata(SS, buf, cp)
SmtpState *SS;
const char *buf, *cp;
{
    int filsiz, rc;
    long tell;
    char msg[2048];
    long bdata_chunksize;
    int bdata_last, i, j;

    struct stat stbuf;
    char *fname;
    char taspid[30];

    
    MIBMtaEntry->ss.ReceivedMessagesSs  += 1;
    MIBMtaEntry->ss.ReceivedRecipientsSs += SS->ok_rcpt_count;
    MIBMtaEntry->ss.IncomingSMTP_BDAT   += 1;

    if (SS->state == RecipientOrData) {
	SS->state = BData;
	SS->bdata_blocknum = 0;
	SS->mvbstate = -1;
    }
    *msg = 0;
    rc = sscanf(cp, "%ld %7s %7s", &bdata_chunksize, msg, msg + 20);
    SS->bdata_blocknum += 1;
    bdata_last = CISTREQ(msg, "LAST");
    if (!(bdata_chunksize >= 0L
	  && (rc == 1 || (rc == 2 && bdata_last)))) {
	type(SS, 501, m552, NULL);
	typeflush(SS);
	MIBMtaEntry->ss.IncomingSMTP_BDAT_bad += 1;
	return 0;
    }
    if (SS->bdata_blocknum == 1 && SS->mfp) {
	fputs("env-end\n", SS->mfp);
	if (msa_mode && SS->authuser != NULL ) {
	  fprintf(SS->mfp, "X-Comment: RFC 2476 MSA function at %s logged sender identity as: %s\n", SS->myhostname, SS->authuser);
	}
#ifdef HAVE_SPF_ALT_SPF_H
	if (spf_received && policyspfhdr(policydb, &SS->policystate)) {
	  fprintf(SS->mfp,"%s\n", policyspfhdr(policydb, &SS->policystate));
	}
#endif
    }
    /* We set alarm()s inside the mvbdata() */
    *msg = 0;
    filsiz = mvbdata(SS, msg, bdata_chunksize);
    SS->messagesize += filsiz;

    tell = 0;

    if (SS->mfp) {

      fflush(SS->mfp);
      fname = mail_fname(SS->mfp);
      fstat(FILENO(SS->mfp), &stbuf);

      taspoolid(taspid, stbuf.st_mtime, stbuf.st_ino);
      tell = stbuf.st_size;

    } else {

      tell = 0;
      fname = "<NIL>";
      strcpy(taspid, "<NIL>");

    }

    report(SS, "BDAT %ld%s; tell=%ld", bdata_chunksize,
	   bdata_last ? " LAST":"", tell);

    if (SS->state != BData) {
	switch (SS->state) {
	case Hello:
	    cp = "Waiting for HELO command";
	    break;
	case Mail:
	case MailOrHello:
	    cp = "Waiting for MAIL command";
	    break;
	case Recipient:
	    cp = "Waiting for RCPT command";
	    break;
	default:
	    cp = NULL;
	    break;
	}

	type(SS, 503, m552, cp);
	if (lmtp_mode && bdata_last) for(i = 1; i < SS->ok_rcpt_count; ++i)
	  type(SS, 503, m552, cp);

	typeflush(SS);
	if (SS->mfp) {
	    mail_abort(SS->mfp);
	    policytest(&SS->policystate, POLICY_DATAABORT,
		       NULL, SS->rcpt_count, NULL);
	}
	MIBMtaEntry->ss.IncomingSMTP_BDAT_bad += 1;
	SS->mfp = NULL;
	return 0;
    }
    if (SS->bdata_blocknum == 1) {
	if (SS->sender_ok == 0 || SS->rcpt_count == 0) {
	    cp = "No valid sender, rejecting all recipients";
	    if (SS->sender_ok != 0)
		cp = "No valid recipient at RCPT addresses, or no RCPT addresses at all";

	    type(SS, 550, "5.1.3", cp);
	    if (lmtp_mode && bdata_last) for(i = 1; i < SS->ok_rcpt_count; ++i)
	      type(SS, 550, "5.1.3", cp);

	    typeflush(SS);
	    SS->state = MailOrHello;
	    if (SS->mfp) {
	      mail_abort(SS->mfp);
	      policytest(&SS->policystate, POLICY_DATAABORT,
			 NULL, SS->rcpt_count, NULL);
	    }
	    MIBMtaEntry->ss.IncomingSMTP_BDAT_bad += 1;
	    SS->mfp = NULL;
	    return 0;
	}
	if ((SS->from_box != 0) && (SS->rcpt_count > MaxErrorRecipients)) {

	  /* Too many recipients for a  "MAIL FROM:<>" */
	  type(SS, 550, "5.7.1", "SPAM trap -- too many recipients for an empty source address!");
	  if (lmtp_mode && bdata_last) for(i = 1; i < SS->ok_rcpt_count; ++i)
	    type(SS, 550, "5.7.1", "SPAM trap -- too many recipients for an empty source address!");

	  typeflush(SS);
	  SS->state = MailOrHello;
	  mail_abort(SS->mfp);
	  policytest(&SS->policystate, POLICY_DATAABORT,
		     NULL, SS->rcpt_count, NULL);
	  MIBMtaEntry->ss.IncomingSMTP_BDAT_bad += 1;
	  SS->mfp = NULL;
	  return 0;
	}
	SS->rcpt_count = 0;	/* now we can zero them.. */
	SS->sender_ok = 0;
    }

    {
      long bavail, bused, iavail, iused;
      if (0 == fd_statfs(FILENO(SS->mfp), &bavail, &bused, &iavail, &iused)) {
	MIBMtaEntry->sys.SpoolUsedSpace = bused;
	MIBMtaEntry->sys.SpoolFreeSpace = bavail;

	availspace = bavail - minimum_availspace;
	if (availspace > (LONG_MAX / 1024))
	  availspace = LONG_MAX / 1024;
	availspace *= 1024;
	
	MIBMtaEntry->sys.SpoolUsedFiles = iused;
	MIBMtaEntry->sys.SpoolFreeFiles = iavail;
      }
    }

    /* The common typeflush() is at the end... */
    if (SS->mfp == NULL) {
      type(SS, 452, m430, "BDAT block discarded due to earlier error");
	if (lmtp_mode && bdata_last) for(i = 1; i < SS->ok_rcpt_count; ++i)
	  type(SS, 452, m430, "BDAT block discarded due to earlier error");
	MIBMtaEntry->ss.IncomingSMTP_BDAT_bad += 1;
    } else if (*msg != 0) {
	mail_abort(SS->mfp);
	policytest(&SS->policystate, POLICY_DATAABORT,
		   NULL, SS->rcpt_count, NULL);
	SS->mfp = NULL;
	type(SS, 452, "%s", msg);
	if (lmtp_mode && bdata_last) for(i = 1; i < SS->ok_rcpt_count; ++i)
	  type(SS, 452, "%s", msg);
	MIBMtaEntry->ss.IncomingSMTP_BDAT_bad += 1;
    } else if (s_feof(SS)) {
	/* [mea@utu.fi] says this can happen */
	if (STYLE(SS->cfinfo,'D')) {
	  /* Says: DON'T DISCARD -- aka DEBUG ERRORS! */
	  mail_close_alternate(SS->mfp,"public",".BDAT-EOF");
	} else {
	  mail_abort(SS->mfp);
	  policytest(&SS->policystate, POLICY_DATAABORT,
		     NULL, SS->rcpt_count, NULL);
	}
	MIBMtaEntry->ss.IncomingSMTP_BDAT_bad += 1;
	SS->mfp = NULL;
	reporterr(SS, tell, "premature EOF on BDAT input");
	typeflush(SS); /* Pointless ?? */
	return -1;
    } else if (availspace < 0 || ferror(SS->mfp)) {
	type(SS, 452, m400, (char *) NULL);
	if (lmtp_mode && bdata_last) for(i = 1; i < SS->ok_rcpt_count; ++i)
	  type(SS, 452, m400, (char *) NULL);
	reporterr(SS, tell,
		  ferror(SS->mfp) ? "write to spool file failed" :
				    "system free storage under limit");
	clearerr(SS->mfp);
	mail_abort(SS->mfp);
	policytest(&SS->policystate, POLICY_DATAABORT,
		   NULL, SS->rcpt_count, NULL);
	MIBMtaEntry->ss.IncomingSMTP_BDAT_bad += 1;
	SS->mfp = NULL;
    } else if (maxsize > 0 && tell > maxsize) {
	mail_abort(SS->mfp);
	policytest(&SS->policystate, POLICY_DATAABORT,
		   NULL, SS->rcpt_count, NULL);
	MIBMtaEntry->ss.IncomingSMTP_BDAT_bad += 1;
	SS->mfp = NULL;
	type(SS, 552, "5.3.4", "Size of this message exceeds the fixed maximum size of  %ld  chars for received email ", maxsize);
	if (lmtp_mode && bdata_last) for(i = 1; i < SS->ok_rcpt_count; ++i)
	  type(SS, 552, "5.3.4", "Size of this message exceeds the fixed maximum size of  %ld  chars for received email ", maxsize);
	
    } else if (bdata_last) {

	/* Things have been good thus far, now we store
	   the resulting file into router spool area;
	   pending a few things we do at first.. */

	const char *statcode = NULL, *ss, *ss0;
	int code = 0;
	const char *sslines[20];
	int sslinecnt = 0;

	/* Lets see what the content-policy will tell now ? */

	if (debug) typeflush(SS);
	SS->policyresult = contentpolicy(&SS->policystate, fname);
	ss0 = ss  = policymsg(&SS->policystate);

	if (ss)
	  type(NULL,0,NULL,
	       "Content-policy analysis ordered message %s. (code=%d); msg='%s'",
	       (SS->policyresult < 0 ? "rejection" :
		(SS->policyresult > 0 ? "freezing" : "acceptance")),
	       SS->policyresult, ss);

	if (ss) {
	  char *p, *s;
	  code = parsestatcode(&ss,&statcode);
	  s = (char *) ss;
	  p = strchr(s,'\r');
	  sslinecnt = 0;
	  if (p) {
	    /* Multiline! CRs in message text... */
	    while (p && sslinecnt < 17) { /* Arbitrary fixed limit.. */
	      *p++ = '\0';
	      sslines[sslinecnt++] = s;
	      sslines[sslinecnt+0] = p;
	      sslines[sslinecnt+1] = NULL;
	      s = p;
	      p = strchr(s,'\r');
	    }
	  }
	}
	if (!ss || *ss == 0) {
	  if (SS->policyresult < 0)
	    sslines[0] = ss = "rejected, no further explanations";
	  else  if (SS->policyresult == 0)
	    sslines[0] = ss = "accepted";
	  else
	    sslines[0] = ss = "accepted into freezer, no explanations";
	  sslines[1] = NULL;
	}

	if (SS->policyresult < 0) {
	  
	  if (!statcode)  statcode = m571;
	  if (!code)      code = 552;

	  type(SS, -code, statcode, "Content-Policy msg: %s; %s", ss, taspid);
	  for (j= 1; j <= sslinecnt; ++j)
	    type(SS, -code, statcode, "msg: %s", sslines[j]);
	  type(SS, code, statcode, "Content-Policy analysis rejected this message");

	  if (lmtp_mode) for(i = 1; i < SS->ok_rcpt_count; ++i) {
	    type(SS, -code, statcode, "Content-Policy msg: %s; %s", ss, taspid);
	    for (j= 1; j <= sslinecnt; ++j)
	      type(SS, -code, statcode, "msg: %s", sslines[j]);
	    type(SS, code, statcode, "Content-Policy analysis rejected this message");
	  }

	  mail_abort(SS->mfp);
	  policytest(&SS->policystate, POLICY_DATAABORT,
		     NULL, SS->rcpt_count, NULL);
	  MIBMtaEntry->ss.IncomingSMTP_BDAT_bad += 1;
	  SS->mfp = NULL;

	} else if (SS->policyresult > 0) {

	  runasrootuser();
	  if (mail_close_alternate(SS->mfp, FREEZERDIR, "policy") != 0) {
	    type(NULL,0,NULL,
		 "mail_close_alternate(..'FREEZER','%s') failed, errno=%d (%s)",
		 "policy", errno, strerror(errno));
	    if (logfp)
	      fflush(logfp);

	    type(SS, 452, m430, "Message file disposition failed; %s", taspid);
	    if (lmtp_mode) for(i = 0; i < SS->ok_rcpt_count; ++i)
	      type(SS, 452, m430, "Message file disposition failed; %s",taspid);

	    SS->mfp = NULL;
	    reporterr(SS, tell, "message file close failed");
	  } else {

	    smtp_tarpit(SS);

	    if (!statcode)  statcode = "2.7.1";
	    if (!code)      code = 250;

	    type(SS, -code, statcode, "%s; %s", ss, taspid);
	    for (j= 1; j <= sslinecnt; ++j)
	      type(SS, -code, statcode, "%s", sslines[j]);
	    type(SS, code, statcode, "Content-Policy accepted this message into freezer-%d; %s", SS->policyresult, taspid);
	    
	    if (lmtp_mode) for(i = 1; i < SS->ok_rcpt_count; ++i) {
	      type(SS, -code, statcode, "%s; %s", ss, taspid);
	      for (j= 1; j <= sslinecnt; ++j)
		type(SS, -code, statcode, "%s", sslines[j]);
	      type(SS, code, statcode, "Content-Policy accepted this message into freezer-%d; %s", SS->policyresult, taspid);
	    }

	    typeflush(SS);
	    SS->mfp = NULL;
	    zsyslog((LOG_INFO, "accepted  %s (%ldc) from %s/%d into freeze[%d]",
		     taspid, tell, SS->rhostname, SS->rport, SS->policyresult));
	  }
	  MIBMtaEntry->ss.IncomingSMTP_BDAT_bad += 1;
	  runastrusteduser();
	} else if (mail_close(SS->mfp) == EOF) {

	  type(SS, 452, m400, (char *) NULL);
	  if (lmtp_mode) for(i = 1; i < SS->ok_rcpt_count; ++i)
	    type(SS, 452, m400, (char *) NULL);

	  SS->mfp = NULL;
	  reporterr(SS, tell, "message file close failed");
	  MIBMtaEntry->ss.IncomingSMTP_BDAT_bad += 1;
	} else {
	  /* Ok, build response with proper "spoolid" */

	  SS->mfp = NULL;

#if 1
	  type(SS, 250, "2.0.0", "%s Roger, got %ld bytes in the last chunk, stored %ld bytes into spool",
	       taspid, bdata_chunksize, (long) tell);
	  if (lmtp_mode) for(i = 1; i < SS->ok_rcpt_count; ++i)
	    type(SS, 250, "2.0.0", "%s Roger, got %ld bytes in the last chunk, stored %ld bytes into spool",
	       taspid, bdata_chunksize, (long) tell);

	  type(NULL,0,NULL,"-- pipeline input: %d bytes",s_hasinput(SS));

#else
	  if (!statcode)  statcode = "2.0.0";
	  if (!code)      code = 250;

	  if (sslinecnt < 1)
	    type(SS,  code, statcode, "%s; %s", ss, taspid);
	  else
	    type(SS, -code, statcode, "%s; %s", ss, taspid);
	  for (j= 1; j <= sslinecnt; ++j)
	    type(SS, -code, statcode, "%s", sslines[j]);
	  if (sslinecnt >= 1)
	    type(SS, code, statcode, "Content-Policy accepted this message; %s", taspid);
	  if (lmtp_mode) for(i = 1; i < SS->ok_rcpt_count; ++i) {
	    if (sslinecnt < 1)
	      type(SS,  code, statcode, "%s; %s", ss, taspid);
	    else
	      type(SS, -code, statcode, "%s; %s", ss, taspid);
	    for (j= 1; j <= sslinecnt; ++j)
	      type(SS, -code, statcode, "%s", sslines[j]);
	    if (sslinecnt >= 1)
	      type(SS, code, statcode, "Content-Policy accepted this message; %s", taspid);
	  }
#endif

	  policytest(&SS->policystate, POLICY_DATAOK,
		     NULL, SS->rcpt_count, NULL);


	  MIBMtaEntry->ss.IncomingSMTP_BDAT_ok    += 1;

	  MIBMtaEntry->ss.TransmittedMessagesSs   += 1;
	  MIBMtaEntry->ss.TransmittedRecipientsSs += SS->ok_rcpt_count;

	  MIBMtaEntry->ss.IncomingSMTP_BDAT_KBYTES  += (SS->messagesize+1023)/1024;
	  MIBMtaEntry->ss.IncomingSMTP_spool_KBYTES += (tell + 1023)/1024;

	  if (smtp_syslog)
	    zsyslog((LOG_INFO,
		     "%s: (%ldc) accepted from %s/%d", taspid, tell,
		     SS->rhostname, SS->rport));
	  type(NULL,0,NULL,"%s: %ld bytes", taspid, tell);

	  if (logfp)
	    fflush(logfp);
	}
    } else {			/* Not last chunk! */
      type(SS, 250, "2.0.0", "Received %ld bytes", bdata_chunksize);
      if (lmtp_mode && bdata_last) for(i = 1; i < SS->ok_rcpt_count; ++i)
	type(SS, 250, "2.0.0", "Received %ld bytes", bdata_chunksize);
    }
    if (bdata_last) {
	SS->state = MailOrHello;
    }
    typeflush(SS);
    return 0;
}


/* Implement SMTP DATA filter */

/*
 * The state table is indexed by the current character (across), and
 * the current state (down). Column 0 is for any character that is not
 * a '\r', '\n', or '.'.  The table entries encode the next state, and
 * what to output. An entry of EOF means exit. The next state is encoded
 * in the l.s.byte, and what to output is encoded in the next-l.s.byte.
 * If the next-l.s.byte is null, the current input character is output,
 * if the high bit is set, nothing is output, else the entire byte is
 * output followed by the current character.
 */

#define	O_	(0200 << 8)	/* don't print anything flag */
#define N_	('\r' << 8)	/* print '\r' then current input */
#define X_	~0		/* exit. must have (X_&O_) != 0 */

static int states[] =
{
/*        current input character       */
/*      *       '\r'    '\n'    '.'     EOF        states */
    0, O_ | 15, 10, 0, X_,	/* 0: during line */
    0, O_ | 20, X_, 0, X_,	/* 5: "^." */
    0, O_ | 15, 10, O_ | 5, X_,	/* 10: "^" (start state) */
    N_ | 0, 15, 10, N_ | 0, X_,	/* 15: seen a \r */
    N_ | 0, 15, X_, N_ | 0, X_,	/* 20: "^.\r" */
};

/*
 * Quick way of getting the column number of the state table,
 * that corresponds to the input character.
 */

static char indexnum[256 + 1] =
{
  /*
     #if 0
     idxnum['\r'] = 1;
     idxnum['\n'] = 2;
     idxnum['.'] = 3;
     #if EOF == -1
     idxnum[EOF] = 4;
     #endif
     #endif
   */
    4,				/* EOF */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 1, 0, 0,	/* ...'\n'..'\r'.. */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0,	/* ... '.' .. */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * BASE64 DECODER index table, and ENCODER map array...
 */
static int base64decode_index[128] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
	-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
	-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
};
#define decodechar64(c)  (((c) < 0 || (c) > 127) ? -1 : base64decode_index[(c)])

static char base64encode_array[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int decodebase64string(instr,inlen,outstr,outspc,inleftover)
     const char * instr;
     char * outstr;
     const char ** inleftover;
     int inlen, outspc;
{
    int b64decoding = 1, outlen = 0;
    int b64eod = 0, b64i = 0, i, c;
    char b64c[4];

    while (inlen > 0 && outlen < outspc && !b64eod) {
      c = *instr++; --inlen;

      if (c == '=' || !b64decoding) {
	b64eod = 1;
	continue;
      }
      i = decodechar64(c);
      if (i < 0) continue;

      b64c[b64i++] = i;
      if (b64i < 2)
	continue;
      if (b64i == 2) {
	c = (b64c[0] << 2) | ((b64c[1] & 0x30) >> 4);
      } else if (b64i == 3) {
	c = ((b64c[1] & 0x0f) << 4) | ((b64c[2] & 0x3c) >> 2);
      } else {
	c = (b64c[2] << 6) | b64c[3];
	b64i = 0;
	if (b64eod)
	  b64decoding = 0;
      }

      outstr[outlen] = c;
      ++outlen;
    }
    if (outlen < outspc)
      outstr[outlen] = 0;
    while (*instr == '=') ++instr;
    if (inleftover)
      *inleftover = instr;
    return outlen;
}

int encodebase64string(instr,inlen,outstr,outspc)
     const char * instr;
     char *outstr;
     int inlen, outspc; /* Always positive values .. */
{
    /* Build groups of 3 bytes, encode them in 4 chars; if some byte
       is not filled, mark the incomplete byte with '=' */
    u_char b64out[4];
    int b64i, outlen = 0, b64val;
    while (inlen > 0 && outlen < outspc) {
      b64i = inlen > 3 ? 3 : inlen;

      b64val    = ((unsigned char) instr[0]) << 16;
      if (b64i > 1)
	b64val |= ((unsigned char) instr[1]) << 8;
      if (b64i > 2)
	b64val |= ((unsigned char) instr[2]);

      b64out[3] = base64encode_array[ b64val & 63 ]; b64val >>= 6;
      b64out[2] = base64encode_array[ b64val & 63 ]; b64val >>= 6;
      b64out[1] = base64encode_array[ b64val & 63 ]; b64val >>= 6;
      b64out[0] = base64encode_array[ b64val & 63 ];

      switch(b64i) {
      case 1:
	b64out[2] = '=';
      case 2:
	b64out[3] = '=';
      }

      instr += b64i;
      inlen -= b64i;

      b64i = (b64i == 1) ? 3 : 4;
      if ((outlen + b64i) < outspc) {	/* Can fit in .. */
	memcpy(outstr+outlen, b64out, b64i);
	outlen += b64i;
      } else {				/* Can't fit in :-( */
	memcpy(outstr+outlen, b64out, outspc-outlen);
	outlen = outspc;
      }
    }
    return outlen;
}

/*
 * Copy bytes from stdin to out, obeying sensible SMTP DATA input heuristics.
 *
 * Rayan back in 1988:
 *  "If you can improve on this heavily optimized routine, I'd like to see it.
 *   This version goes at better than 100kB/cpu-sec on a Sun 3/180."
 *   (with 68030 CPU running at 33 MHz -- about 10-15 MIPS)
 */

static int /* count of bytes */ mvdata(SS, msg)
SmtpState *SS;
char *msg;
{
    register int c, state, *sts, endstate, cnt;
    register char *idxnum;

#ifdef NO_INCOMING_HEADER_PROCESSING
    idxnum = indexnum + 1;

    state = 10;
    endstate = X_;
    sts = states;
    cnt = 0;

    SS->read_alarm_ival = SMTP_DATA_TIME_PER_LINE;
#else
    char linebuf[4000], *s, *eol;
    int col;
    int insubject = 0;
    int has8bit = 0;		/* In headers */
    int has8bitsum = 0;
    /* int from__err = 0; */
    int linecnt = 0;
#ifdef USE_TRANSLATION
    int wi;
    char hdr_cte[4000], hdr_ct[4000];
    int delay_cte = 0, delay_ct = 0, append_hdr_ct = 0, append_hdr_cte = 0;
    int ct_is_text = 1;
#define CTE_8BIT 0
#define CTE_BASE64 1
#define CTE_QP 2
    int cte = CTE_8BIT;
    int do_decode = 0, do_translate = 0;
    int qp_chars = 0, qp_hex = 0;
    int b64decoding = 1, b64eod = 0, b64i = 0;
    char b64c[4];
#endif				/* USE_TRANSLATION */

    typeflush(SS);

    idxnum = indexnum + 1;

    state = 10;
    endstate = X_;
    sts = states;
    cnt = 0;
    col = 0;

    SS->read_alarm_ival = SMTP_DATA_TIME_PER_LINE;

    /* ================ Input the email headers ================ */
    /*           and analyze them a bit (Precedence:)            */
    /*        ... that only "Subject:" has 8-bit chars ...       */
    mail_priority = _MAILPRIO_NORMAL;
    for (;;) {
	c = s_getc(SS, 1);
	/* An EOF in here is an error! */
#if EOF != -1
	if (c == EOF)
	    return EOF;
#else
	if (c < 0)
	    return EOF;
#endif
	++cnt;
	state = sts[state + idxnum[c]];
	if (state & ~0xff) {
	    if (state & O_) {
		if (state == endstate) {
		    if (col > 0) {
#ifdef USE_TRANSLATION
			if (has8bit && !X_8bit)
			    header_to_mime(linebuf, &col, sizeof(linebuf));
			else
			    header_from_mime(linebuf, &col, sizeof(linebuf));
			for (wi = 0; wi < col; ++wi)
			    fputc(TR_IN(linebuf[wi]), SS->mfp);
#else				/* USE_TRANSLATION */
			if (has8bit)
			    header_to_mime(linebuf, &col, sizeof(linebuf));
			fwrite(linebuf, 1, col, SS->mfp);
#endif				/* USE_TRANSLATION */
		    }
		    return cnt;
		}
		state = state & 0xFF;
		continue;
	    }
	    if (col < (sizeof(linebuf) - 1))
		linebuf[col++] = (state >> 8);
	    state = state & 0xFF;
	}
	if (0x80 & c)
	    has8bit = 1;

	if (col < (sizeof(linebuf) - 1))
	    linebuf[col++] = c;

	/* LF, or something else ?  Here the else.. */
	if (c != '\n')
	    continue;

	if (col < sizeof(linebuf))
	    linebuf[col] = 0;

	/* We have a string - header line - in ``col'' first
	   char positions of the ``linebuf'' array  */

	/* See what this header is about -- or if the body starts.. */
	if (col > sizeof(linebuf) - 1)
	    col = sizeof(linebuf) - 1;

	eol = linebuf + col;
	*eol = 0;

	/* See if the line is all white-space: */
	for (s = linebuf; s < eol; ++s)
	    if (*s != ' ' && *s != '\t' &&
		*s != '\r' && *s != '\n')
		break;
	if (s == eol) {		/* All-blank line */
#ifdef USE_TRANSLATION
	    /* We have all info from the headers, time to make decision */
	    if (X_8bit && ct_is_text && cte)
		do_decode = cte;
	    if (X_translation && X_8bit && ct_is_text && (X_settrrc == 0))
		do_translate = 1;

	    type(NULL,0,NULL,"(8bit decode: %s, translate: %s) [%s%s,%s]",
		 do_decode ? "YES" : "NO", do_translate ? "YES" : "NO",
		 X_translation ? "-X " : "",
		 X_8bit ? "-8" : "",
		 ct_is_text ? "text" : "non-text");

	    /* write out content-type and content-transfer-encoding */
	    if (delay_ct) {
		if (do_translate) {
		    /* Remove "charset=xxx".  It is mismatching anyway */
		    char *p, *q, *r;
		    p = hdr_ct;
		    while (*p && (*p != ';'))
			p++;	/* skip to attrs */
		    q = p;
		    while (*p == ';') {		/* check attributes */
			r = p + 1;
			while (*r && ((*r == ' ') || (*r == '\t')))
			    r++;
			if (CISTREQN(r, "CHARSET=", 8)) {	/* skip it */
			    p++;
			    while (*p && (*p != ';') && (*p != '\n'))
				p++;
#ifdef USE_TRANSLATION
			    /* if forced charset specified, insert it. */
			    r = "; CHARSET=";
			    while (*r)
				*(q++) = *(r++);
			    r = USE_TRANSLATION;
			    while (*r)
				*(q++) = *(r++);
#endif				/* USE_TRANSLATION */
			} else {	/* copy it */
			    *(q++) = *(p++);
			    while (*p && (*p != ';'))
				*(q++) = *(p++);
			}
		    }
		    while (*p)
			*(q++) = *(p++);
		    *q = '\0';
		}
		fwrite(hdr_ct, 1, strlen(hdr_ct), SS->mfp);
	    }
	    if (delay_cte) {
		if (do_decode) {
		    /* Transfer-encoding changed to 8bit */
		    fputs("Content-Transfer-Encoding: 8bit\n", SS->mfp);
		} else {
		    fwrite(hdr_cte, 1, strlen(hdr_cte), SS->mfp);
		}
	    }
#endif				/* USE_TRANSLATION */
	    if (col > 0)
		fwrite(linebuf, 1, col, SS->mfp);
	    break;		/* Into the body processing */
	}
	++linecnt;
	if (*linebuf == ' ' || *linebuf == '\t') {
#ifdef USE_TRANSLATION
	    if (append_hdr_ct) {
		strcat(hdr_ct, linebuf);
		col = 0;
		continue;
	    }
	    if (append_hdr_cte) {
		strcat(hdr_cte, linebuf);
		col = 0;
		continue;
	    }
	    if (has8bit && !X_8bit)
		header_to_mime(linebuf, &col, sizeof(linebuf));
	    else
		header_from_mime(linebuf, &col, sizeof(linebuf));
	    if (col > 0)
		for (wi = 0; wi < col; wi++)
		    fputc(TR_IN(linebuf[wi]), SS->mfp);
#else				/* USE_TRANSLATION */
	    if (has8bit)
		header_to_mime(linebuf, &col, sizeof(linebuf));
	    if (col > 0)
		fwrite(linebuf, 1, col, SS->mfp);
#endif				/* USE_TRANSLATION */
	    has8bit = 0;
	    col = 0;
	    continue;		/* continuation line.. */
	}
#ifdef USE_TRANSLATION
	append_hdr_ct = 0;
	append_hdr_cte = 0;
#endif				/* USE_TRANSLATION */

	/* ================ PROCESS THE HEADERS! ================ */
	if (CISTREQN(linebuf, "Subject:", 8)) {
	    insubject = 1;
	} else {
	    if (!insubject) {
#if 0
		if (has8bit)
		    sprintf(msg, "Header line \"%.200s\" contains illegal 8-bit chars", linebuf);
#endif
		has8bitsum += has8bit;
	    }
	}
	/* XX: The anti-spam hacks. To differentiate between the auto-freeze of
	 * allegedly-spam messages and freezes resulting from user-specified
	 * smtp-policy.src, we do not use 1 to freeze the messages.
	 */
	if (CISTREQN(linebuf, "X-Advertisement:",16)) {
	  /* Gee... Only SPAMmers (Cyberpromo!) use this .. (I hope..) */
	  SS->policyresult = FREEZE__X_ADVERTISEMENT_FOUND;
	  type(NULL,0,NULL,"Found X-Advertisement header");
	}
	if (CISTREQN(linebuf, "X-Advertisment:",15)) {
	  /* Gee... Only SPAMmers (Cyberpromo!) use this .. (I hope..) */
	  SS->policyresult = FREEZE__X_ADVERTISEMENT_FOUND;
	  type(NULL,0,NULL,"Found X-Advertisment header");
	}
#ifdef USE_ANTISPAM_HACKS
	if (strncmp(linebuf, "X-UIDL:", 7)==0) {
	  /* Sigh... SPAMmers use this .. but it is valid AOL too.. */
	  SS->policyresult = FREEZE__X_UIDL_FOUND;
	}
#endif
#ifdef USE_ANTISPAM_HACKS
	/* This test probably doesn't work */
	if (CISTREQN(linebuf, "Received:", 9)) {
	  /* Scan for "(really ". Anything with this string in the Received
	   * header is highly likely to have a forged Received header
	   * characteristic of spams. Unfortunately this string may
	   * also be a result of pure coincidence.
	   */
	  s = linebuf + 11;
	  while (*s) {
	    if (CISTREQN(s, "(really ", 8)) {
	      SS->policyresult = FREEZE__IMPROBABLE_RECEIVED_HEADER_FOUND;
	      type(NULL,0,NULL,"Improbable Received: header");
	      break;
	    }
	    ++s;
	  }
	}
#endif
#ifdef USE_ANTISPAM_HACKS
	if (CISTREQN(linebuf, "Message-ID:", 11)) {
	  /* Freeze any mail with no message id in the message-id header,
	   * or a message id with obvious syntax errors, or message id
	   * with junk after it. These are highly likely to be spam, though
	   * they might only be a result of buggy software. (MS Exchange?)
	   */
	  s = linebuf + 11;
	  while (*s == ' ' || *s == '\t')
	    ++s;
	  if (*s != '<') {
	    SS->policyresult = FREEZE__MALFORMED_MESSAGE_ID_HEADER;
	    type(NULL,0,NULL,"No <> around Message-Id");
	  } else if (s[1] == '@') {
	    SS->policyresult = FREEZE__MALFORMED_MESSAGE_ID_HEADER;
	    type(NULL,0,NULL,"Source route in Message-Id:");
	  } else if (s[1] == '>') {
	    SS->policyresult = FREEZE__MALFORMED_MESSAGE_ID_HEADER;
	    type(NULL,0,NULL,"Empty Message-Id:");
	  } else {
	    const char *t = rfc821_path(s, 1);
	    if (s == t) { /* error */
#ifdef USE_STRICT_MSGID_FREEZING
	      SS->policyresult = FREEZE__MALFORMED_MESSAGE_ID_HEADER;
	      type(NULL,0,NULL,"Message-Id: syntax error");
#endif
	    } else {
	      while (*t == ' ' || *t == '\t' || *t == '\r' || *t == '\n')
		++t;
	      if (*t) {
		SS->policyresult = FREEZE__MALFORMED_MESSAGE_ID_HEADER;
		type(NULL,0,NULL,"Spurious junk after Message-Id:");
	      }
	    }
	  }
	}
#endif
	if (CISTREQN(linebuf, "Precedence:", 11)) {
	    s = linebuf + 11;
	    while (*s == ' ' || *s == '\t')
		++s;
	    if ((eol - s) < 4)
		continue;	/* Hmm.. */
	    if (CISTREQN("high", s, 4))
		mail_priority = _MAILPRIO_HIGH;
	    else if (CISTREQN("junk", s, 4))
		mail_priority = _MAILPRIO_JUNK;
	    else if (CISTREQN("bulk", s, 4))
		mail_priority = _MAILPRIO_BULK;
	    else if (((eol - s) >= 6) && CISTREQN("normal", s, 6))
		mail_priority = _MAILPRIO_NORMAL;
	}
#if 0 /* Nice in theory - impractical in reality */
	if (msa_mode && CISTREQN(linebuf, "Sender:", 7)) {
	    if ( SS->authuser != NULL ) {
	      fprintf(SS->mfp, "Sender: %s@%s\n", SS->authuser, SS->myhostname);
	      fprintf(SS->mfp, "Old-");
	    }
        }
#endif
#ifdef USE_TRANSLATION
	if (X_translation && (X_settrrc == 0)) {
	    if (CISTREQN(linebuf, "Content-Transfer-Encoding:", 26)) {
		if (1) {
		    strcpy(hdr_cte, linebuf);
		    delay_cte = 1;
		    append_hdr_cte = 1;
		    col = 0;
		    has8bit = 0;
		    s = linebuf + 26;
		    while (*s == ' ' || *s == '\t')
			++s;
		    if ((eol - s) < 4)
			continue;	/* Hmm.. */
		    if (CISTREQN("8bit", s, 4))
			cte = CTE_8BIT;
		    else if (CISTREQN("base64", s, 6))
			cte = CTE_BASE64;
		    else if (CISTREQN("quoted-printable", s, 16))
			cte = CTE_QP;
		    continue;	/* do not write out this one */
		}
	    } else if (CISTREQN(linebuf, "Content-Type:", 13)) {
		if (1) {
		    strcpy(hdr_ct, linebuf);
		    delay_ct = 1;
		    append_hdr_ct = 1;
		    col = 0;
		    has8bit = 0;
		    s = linebuf + 13;
		    while (*s == ' ' || *s == '\t')
			++s;
		    if ((eol - s) < 10)
			continue;	/* Hmm.. */

		    /* Must ALWAYS check for C-T: TEXT/any ! */
		    /* #ifdef PARANOID_TRANSLATION */
		    if (CISTREQN("text", s, 4))
			ct_is_text = 1;
		    else
			ct_is_text = 0;
		    /* #endif */ /* PARANOID_TRANSLATION */

		    continue;	/* do not write out this one */
		}
	    }
	}
#endif				/* USE_TRANSLATION */

	if (linecnt == 1 && (strncmp("From ", linebuf, 5) == 0 ||
			     strncmp(">From ", linebuf, 6) == 0)) {
#if 0
	    from__err = 1;
	    sprintf(msg, "Message starts with illegal \"%.200s\" line", linebuf);
#endif
	    /* DO NOT WRITE THIS LINE OUT! */
	    col = 0;
	    has8bit = 0;
	    continue;
	}
#ifdef USE_TRANSLATION
	if (has8bit && !X_8bit)
	    header_to_mime(linebuf, &col, sizeof(linebuf));
	else
	    header_from_mime(linebuf, &col, sizeof(linebuf));
	/* Write the line out */
	if (col > 0)
	    for (wi = 0; wi < col; ++wi)
		fputc(TR_IN(linebuf[wi]), SS->mfp);
#else				/* USE_TRANSLATION */
	if (has8bit)
	    header_to_mime(linebuf, &col, sizeof(linebuf));
	/* Write the line out */
	if (col > 0)
	    fwrite(linebuf, 1, col, SS->mfp);
#endif				/* USE_TRANSLATION */
	has8bit = 0;
	col = 0;
    }
    if (verbose)
      type(NULL,0,NULL,"(mail_priority=%d)", mail_priority);
#endif

    /* ================ Normal email BODY input.. ================ */
    for (;;) {
	c = s_getc(SS, 1);
#if EOF != -1
	if (c == EOF)		/* a little slower... */
	    break;
#endif

	++cnt;
	state = sts[state + idxnum[c]];
	if (state & ~0xff) {
	    if (state & O_) {
		if (state == endstate)
		    break;
		state = (char) state;
		continue;
	    }
	    if (!ferror(SS->mfp))
		fputc((state >> 8), SS->mfp);
	    state = state & 0xFF;
	}
	if (!ferror(SS->mfp)) {
#ifdef USE_TRANSLATION
	    if (do_decode == CTE_QP) {
		if (!qp_chars && c == '=') {
		    qp_chars = 2;
		    qp_hex = 0;
		    continue;
		}
		if (qp_chars && c == '\n') {
		    qp_chars = 0;
		    continue;
		}
		if (qp_chars == 2 && (c == ' ' || c == '\t')) {
		    continue;
		}
		if (qp_chars && ((c >= '0' && c <= '9') ||
				 (c >= 'A' && c <= 'F') ||
				 (c >= 'a' && c <= 'f'))) {
		    qp_hex <<= 4;
		    if (c >= '0' && c <= '9')
			qp_hex += (c - '0');
		    if (c >= 'A' && c <= 'F')
			qp_hex += (c - 'A' + 10);
		    if (c >= 'a' && c <= 'f')
			qp_hex += (c - 'a' + 10);
		    --qp_chars;
		    if (!qp_chars)
			c = qp_hex;
		    else
			continue;
		} else if (qp_chars)
		    qp_chars = 0;
	    } else if (do_decode == CTE_BASE64) {
		if (b64decoding) {
		    if ((c == ' ') || (c == '\t') ||
			(c == '\n') || (c == '\r'))
			continue;
		    b64c[b64i++] = decodechar64(c);
		    if (c == '=') {
			b64eod = 1;
			continue;
		    }
		    if (b64i < 2)
			continue;
		    if (b64i == 2) {
			c = (b64c[0] << 2) |
			    ((b64c[1] & 0x30) >> 4);
		    } else if (b64i == 3) {
			c = ((b64c[1] & 0x0f) << 4) |
			    ((b64c[2] & 0x3c) >> 2);
		    } else {
			c = (b64c[2] << 6) |
			    b64c[3];
			b64i = 0;
			if (b64eod)
			    b64decoding = 0;
		    }
		}
	    }
	    if (do_translate)
		fputc(TR_IN(c), SS->mfp);
	    else
#endif				/* USE_TRANSLATION */
		fputc(c, SS->mfp);
	}
    }
    typeflush(SS);
    return cnt;
}

/*
 *  BDAT -- For ESMTP CHUNKING extension (rfc 1830)
 */
static int /* count of bytes */ mvbdata(SS, msg, incount)
SmtpState *SS;
char *msg;
register long incount;
{
    register int c, cnt;

    cnt = 0;

    /* XX: header processing REMOVED from BDAT processing */

    SS->read_alarm_ival = SMTP_DATA_TIME_PER_LINE;

    /* ================ Normal email BODY input.. ================ */
    for (; incount > 0; --incount) {
	c = s_getc(SS, 1);
	if (c == EOF)
	    break;
	++cnt;
	/* Canonize CR+LF --> LF (UNIX style) */
	if (c == '\r') {	/* Suspend sending, this is our 'mvbstate' */
	    /* do nothing, 'mvbstate = c' is done after this if-else */
	} else if (SS->mvbstate == '\r') {
	    if (c != '\n') {
		/* Suspended lone CR */
		if (SS->mfp) {	/* We just discard it, if no output stream */
		    if (!ferror(SS->mfp))
			fputc(SS->mvbstate, SS->mfp);
		    if (!ferror(SS->mfp))
			fputc(c, SS->mfp);
		}
	    } else {
		/* CR + LF -- forget the CR */
		if (SS->mfp && !ferror(SS->mfp))
		    fputc(c, SS->mfp);
	    }
	} else {
	    /* Anything else, just output it! */
	    if (SS->mfp && !ferror(SS->mfp))
		fputc(c, SS->mfp);
	}
	SS->mvbstate = c;
    }
    return cnt;
}
