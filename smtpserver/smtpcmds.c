/*
 *    Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *      This will be free software, but only when it is finished.
 */
/*
 *    Several extensive changes by Matti Aarnio <mea@nic.funet.fi>
 *      Copyright 1991-1998.
 */
/*
 * Zmailer SMTP-server divided into bits
 *
 * The basic commands:
 *
 *  - HELO/EHLO
 *  - MAIL 
 *  - RCPT
 *  - ETRN/TURNME
 *  - VRFY
 *  - EXPN
 *
 */

#include "smtpserver.h"

extern int netconnected_flg;


static const char *orcpt_string __((const char *));

static const char *orcpt_string(str)
const char *str;
{
    /* Verify that the input is valid RFC 1981 XTEXT string! */
    const char *stro = rfc822atom(str);
    const char *s2;

    if (stro == str)
	return NULL;
    if (*stro != ';') {
	rfc821_error_ptr = stro - 1;
	return NULL;
    }
    s2 = xtext_string(++stro);
    if (s2 == stro)
	return NULL;
    return s2;
}


static void rfc822commentprint __((FILE *, const char *));
static void
rfc822commentprint(mfp, str)
FILE *mfp;
const char *str;
{
  putc('"', mfp);
  for ( ; *str ; ++str ) {
    int c = (*str) & 0xFF;
    if (c == '"' || c == '\\' || c == '(' || c == ')')
      putc('\\', mfp);
    putc(c, mfp);
  }
  putc('"', mfp);
}


/* If the argument is not in valid domain name syntax, return 1 */

static int partridge __((SmtpState *, const char *));

static int partridge(SS, s)
SmtpState *SS;
const char *s;
{
    const char *p = rfc821_domain(s, STYLE(SS->cfinfo, 'R'));
    if (p == s)
	return 1;
    while (*p == ' ' || *p == '\n')
	++p;
    if (*p == 0)
	return 0;

    rfc821_error_ptr = p;
    rfc821_error = "Spurious junk after the DOMAIN in HELO/EHLO argument";

    return 1;
}

/* The input this macro gets is already verified to be in RFC-821 form.
   In it we can have double-quotes in the input, but only \ -quoted!
   Therefore it is highly unlikely to need even more than two chars
   longer form for the RFC-822 format string. */

static void rfc821to822quote(cpp,newcpp,alenp)
     char **cpp, **newcpp;
     int *alenp;
{
	char *cp    = *cpp;
	char *newcp = *newcpp;
	int alen    = *alenp;
	if (cp && memchr(cp,'\\',alen) != NULL && *cp != '"') {
	  int i;
	  const char *s1 = cp;
	  char *s2 = emalloc(alen+8);
	  newcp = s2;
	  *s2++ = '"';
	  for (i = 0; i < alen; ++i) {
	    if (*s1 == '@')
	      break; /* Unquoted AT --> move to plain copying! */
	    if (*s1 == '\\' && s1[1] != 0)
	      { *s2++ = *s1++; ++i; }
	    /* Normal copy */
	    *s2++ = *s1++;
	  }
	  *s2++ = '"';
	  /* The possible final copying of '@hostpart' */
	  for ( ; i < alen; ++i)
	    *s2++ = *s1++;
	  alen = s2 - newcp;
	  cp = newcp;
	}
	*cpp    = cp;
	*newcpp = newcp;
	*alenp  = alen;
}
#define RFC821_822QUOTE(cp,newcp,alen) \
	rfc821to822quote(&cp,&newcp,&alen)


/* SMTP-server verb subroutines */

void smtp_helo(SS, buf, cp)
SmtpState *SS;
const char *buf, *cp;
{
    const char *msg = NULL;
    if (SS->state != Hello && SS->state != MailOrHello) {
	switch (SS->state) {
	case Mail:
	    msg = "Waiting for MAIL command";
	    break;
	case Recipient:
	    msg = "Waiting for RCPT command";
	    break;
	default:
	    break;
	}
    }

    /* HELO/EHLO is also implicite RSET ! */
    if (SS->mfp != NULL) {
      clearerr(SS->mfp);
      mail_abort(SS->mfp);
      SS->mfp = NULL;
    }

    strncpy(SS->helobuf, buf, sizeof(SS->helobuf));
    SS->helobuf[sizeof(SS->helobuf)-1] = 0;

    while (*cp == ' ' || *cp == '\t')
	++cp;

    SS->policyresult = policytest(policydb, &SS->policystate,
				  POLICY_HELONAME, cp, strlen(cp));
    if (logfp) {
      char *s = policymsg(policydb, &SS->policystate);
      if (SS->policyresult != 0 || s != NULL) {
	fprintf(logfp, "%d\t-- policy result=%d, msg: %s\n", pid,
		SS->policyresult, (s ? s : "<NONE!>"));
	fflush(logfp);
      }
    }

    /* actually we accept here about anything, and mark
       our decissions up into the 'policystate' variables */


    /*
     * Craig P. says we have to spit back syntactically
     * invalid helo parameters at this stage, which is
     * hard to do right since it requires a full '822
     * tokenizer.  We do a half-hearted attempt here.
     */
    /*
     * Matti A. says we have a more-than-half-hearted
     * tokenizer -- RFC821SCN.C, lets use it :)
     * We need it for proper handling of ESMTP anyway
     */
    if (checkhelo && skeptical && partridge(SS, cp)) {
	type821err(SS, -501, "", buf,
		   "Invalid `%.200s' parameter!",
		   buf);
	if (msg != NULL)
	  type(SS, -501, "", "%s", msg);
	type(SS, 501, "", "Err: %s", rfc821_error);
	strcpy(SS->helobuf, "Bad.Helo.Input");
	return;
    }
    /* At least check the input, though say "Ok, Master" while
       complaining.. */
    if (!checkhelo && partridge(SS, cp)) {
	if (SS->carp->cmd != Hello) {
	    type821err(SS, -250, "", buf, "Invalid `%.200s' parameter!", buf);
	    type(SS, -250, NULL, "Err: %s", rfc821_error);
	    if (msg != NULL)
	      type(SS, -250, "", "%s", msg);
	}
    }
    SS->cfinfo = findcf(cp);
    if (SS->cfinfo != NULL && *(SS->cfinfo->flags) == '!') {
	if (SS->cfinfo->flags[1] != '\0')
	    type(SS, 501, NULL, "%s", (SS->cfinfo->flags) + 1);
	else
	    type(SS, 501, NULL, "Sorry, access denied.");
	return;
    }

    /* Router interacting policy analysis functions */
    /* Note, these are orthogonal to those of smtp-server
       internal policy functions! */
    if (STYLE(SS->cfinfo, 'h')) {
      char argbuf[MAXHOSTNAMELEN+30];
      char *s;
      sprintf(argbuf,"%s %s", SS->rhostname,
	      ((SS->ihostaddr && (SS->ihostaddr[0] != '\0'))
	       ? SS->ihostaddr : "[0.0.0.0]"));
      if ((s = router(SS, RKEY_HELLO, 1, argbuf, strlen(argbuf))) == NULL)
	/* the error was printed in router() */
	return;
      if (atoi(s) / 100 != 2) {
	/* verification failed */
	type(SS, atoi(s), s+4, "Failed", "Failed");
	free(s);
	return;
      }
      else {
	type(SS, -atoi(s), s+4, "Ok", "Ok");
	free(s);
      }
    }

    /* Check `cp' corresponds to the reverse address */
    if (skeptical && SS->ihostaddr[0] != '\0'
	&& SS->rhostname[0] != '\0' && SS->rhostname[0] != '['
	&& !CISTREQ(cp, SS->rhostname)) {
	if (checkhelo) {
	    type(SS, -250, NULL, "%s That hostname is inconsistent with",
		 SS->myhostname);
	    type(SS, -250, NULL, "%s your address to name mapping.",
		 SS->myhostname);
	}
	if (msg != NULL)
	  type(SS, -250, "", "%s", msg);
	type(SS, SS->carp->cmd == Hello2 ? -250 : 250, NULL,
	     "%s expected \"%s %s\"", SS->myhostname,
	     SS->carp->verb, SS->rhostname);
    } else {
	if (msg != NULL)
	  type(SS, -250, "", "%s", msg);
	type(SS, SS->carp->cmd == Hello2 ? -250 : 250, NULL,
	     "%s Hello %s", SS->myhostname, cp);
    }
    if (SS->carp->cmd == Hello2) {

	/* ESMTP -- RFC 1651,1652,1653,1428 thingies */
	char sizebuf[20];
	long policyinlimit = policyinsizelimit(policydb, &SS->policystate);
	long maxinlimit = maxsize;

	if (policyinlimit >= 0)  /* defined if non-negative value */
	  maxinlimit = policyinlimit;
	if (maxsize != 0 && maxsize < maxinlimit)
	  maxinlimit = maxsize;
	if (maxsize != 0 && maxinlimit == 0)
	  maxinlimit = maxsize; /* Lower from infinite */

	sprintf(sizebuf, "SIZE %ld", maxinlimit); /* 0: No fixed max size
						     in force, else:
						     The FIXED maximum */
	type(SS, -250, NULL, sizebuf);
	type(SS, -250, NULL, "8BITMIME");
	type(SS, -250, NULL, "PIPELINING");
	type(SS, -250, NULL, "CHUNKING");	/* RFC 1830: BDAT */
	type(SS, -250, NULL, "ENHANCEDSTATUSCODES");
	if (expncmdok && STYLE(SS->cfinfo, 'e'))
	  type(SS, -250, NULL, "EXPN");
	if (vrfycmdok && STYLE(SS->cfinfo, 'v'))
	  type(SS, -250, NULL, "VRFY");
	type(SS, -250, NULL, "DSN");
#if 1 /* This causes problems for the router, will fix router
	 performance first, then enable this again.. */
	type(SS, -250, NULL, "X-RCPTLIMIT 10000");	/* VERY HIGH figure, normal is 100 */
#endif
	type(SS, -250, NULL, "ETRN");
	type(SS, 250, NULL, "HELP");
	SS->with_protocol = WITH_ESMTP;
    }
    SS->state = MailOrHello;
}

void smtp_mail(SS, buf, cp, insecure)
SmtpState *SS;
const char *buf, *cp;
int insecure;
{
    const char *s;
    int rc;
    const char *drpt_envid;
    const char *drpt_ret;
    const char *bodytype = NULL;
    const char *newcp = NULL;
    const char *srcrtestatus = "";
    int addrlen, drptret_len, drptenvid_len;
    int strict = STYLE(SS->cfinfo, 'R');
    int sloppy = STYLE(SS->cfinfo, 'S');

    addrlen = 0;
    drptret_len = 0;
    drptenvid_len = 0;

    SS->sender_ok = 0;		/* Set it, when we are sure.. */

    /* For ESMTP SIZE-option use we need to know
       how much space we have, it is easiest by
       opening the spool file here, and asking
       filesystem to report free space..
       We use at most half of the free space,
       and each recipient will use the claimed
       size, thus marking up its reception..        */

    if (SS->carp->cmd == Mail2 || SS->carp->cmd == Send2) {
	SS->with_protocol = WITH_ESMTP;
    }
    if (SS->state != Mail && SS->state != MailOrHello) {
	switch (SS->state) {
	case Hello:
	    cp = "Waiting for HELO/EHLO command";
	    break;
	case Recipient:
	    cp = "Waiting for RCPT command";
	    break;
	default:
	    cp = NULL;
	    break;
	}
	type(SS, 503, m551, cp);
	return;
    }
    if (!CISTREQN(cp, "From:", 5)) {
	type(SS, 501, m552, "where is From: in that?");
	return;
    }
    for (cp = cp + 5; *cp != '\0' && *cp != '<'; ++cp)
	/* Skip white-space */
	if (!isascii(*cp) || !isspace(*cp)) {
	  if (!sloppy) {
	    type(SS, 501, m517, "where is <...> in that?");
	    return;
	  }
	  break; /* Sigh, be sloppy.. */
	}
    if (*cp == '\0') {
	type(SS, 501, m517, "where is <...> in that?");
	return;
    } else if (*cp != '<' && !sloppy) {
	type(SS, 501, m517, "strangeness between : and <");
	return;
    }
    if (*(cp + 1) == '<') {
	type(SS, 501, m517, "there are too many <'s in that!");
	return;
    }
    /* "<" [ <a-t-l> ":" ] <localpart> "@" <domain> ">" */
    if (*cp == '<') {
      s = rfc821_path(cp, strict);
      if (s == cp) {
	/* Failure.. */
	type821err(SS, 501, m517, buf, "Path data: %.200s", rfc821_error);
	return;
      }
      if (*s == '>') {
	type(SS, 501, m517, "there are too many >'s in that!");
	return;
      }
      /* Ok, now it is a moment to see, if we have source routes: @a,@b:c@d */
      if (cp[1] == '@') {
	/* Yup, Starting with an "@" ..  scan until ":", which must be
	   in there as this is valid RFC-821 object. */
	if (!allow_source_route) {
	  while (*cp != ':') ++cp; 
	  srcrtestatus = ", source route ignored";
	}
      }
      ++cp;			/* Skip the initial '<' */
      addrlen = s - 1 - cp;	/* Length until final  '>' */
    } else {
      /* We can be here only with non-strict mode (i.e. Sloppy..) */

      s = rfc821_path2(cp, strict);
      if (s == cp) {
	/* Failure.. */
	type821err(SS, 501, m517, buf, "Path data: %.200s", rfc821_error);
	return;
      }

      if (*s == '>') {
	type(SS, 501, m517, "there are too many >'s in that!");
	return;
      }

      /* Ok, now it is a moment to see, if we have source routes: @a,@b:c@d */
      if (cp[0] == '@') {
	/* Yup, Starting with an "@" ..  scan until ":", which must be
	   in there as this is valid RFC-821 object. */
	if (!allow_source_route) {
	  while (*cp != ':') ++cp; 
	  srcrtestatus = ", source route ignored";
	}
      }
      addrlen = s - cp;	/* Length */
    }

    /* BODY=8BITMIME SIZE=nnnn ENVID=xxxxxx RET=xxxx */
    SS->sizeoptval = -1;
    SS->sizeoptsum = -1;
    drpt_envid = NULL;
    drpt_ret = NULL;
    rc = 0;
    while (*s) {
	while (*s && (*s == ' ' || *s == '\t'))
	    ++s;
	if (CISTREQN("RET=", s, 4)) {
	    if (drpt_ret) {
		type(SS, 501, m554, "RET-param double defined!");
		return;
	    }
	    s += 4;
	    drpt_ret = s;
	    if (CISTREQN("FULL", s, 4) ||
		CISTREQN("HDRS", s, 4))
		s += 4;
	    if (*s && *s != ' ' && *s != '\t') {
		type(SS, 501, m454, "RET-param data error");
		return;
	    }
	    drptret_len = (s - drpt_ret);
	    continue;
	}
	if (CISTREQN("BODY=", s, 5)) {
	    /* Actually we do not use this data... */
	    s += 5;
	    if (bodytype != NULL) {
		type(SS, 501, m554, "BODY= double definition!");
		rc = 1;
		break;
	    }
	    if (CISTREQN(s, "8BITMIME", 8)) {
		bodytype = "8BITMIME";
		s += 8;
	    } else if (CISTREQN(s, "BINARYMIME", 10)) {
		bodytype = "BINARYMIME";
		s += 10;
	    } else if (CISTREQN(s, "7BIT", 4)) {
		bodytype = "7BIT";
		s += 4;
	    }
	    if (*s && *s != ' ' && *s != '\t') {
		type(SS, 501, m554, "BODY-param data error, must be one of: 8BITMIME/BINARYMIME/7BIT");
		rc = 1;
		break;
	    }
	    continue;
	}
	if (CISTREQN("SIZE=", s, 5)) {
	    s += 5;
	    if (SS->sizeoptval != -1) {
		type(SS, 501, m554, "SIZE-param double definition!");
		rc = 1;
		break;
	    }
	    /* This data we use, gather the value */
	    SS->sizeoptval = 0;
	    while (isascii(*s) && isdigit(*s)) {
		SS->sizeoptval *= 10;
		SS->sizeoptval += (*s - '0');
		++s;
	    }
	    if (*s && *s != ' ' && *s != '\t') {
		type(SS, 501, m554, "SIZE-param data error");
		rc = 1;
		break;
	    }
	    continue;
	}
	/* IETF-NOTARY  SMTP-DRPT extensions */
	if (CISTREQN("ENVID=", s, 6)) {
	    if (drpt_envid != NULL) {
		type(SS, 501, m554, "ENVID double definition!");
		rc = 1;
		break;
	    }
	    drpt_envid = s + 6;
	    s = xtext_string(s + 6);
	    if (s == s + 6) {
		type821err(SS, -501, m554, buf, "Invalid ENVID value '%.200s'", drpt_envid);
		type(SS, 501, m554, "ENVID data contains illegal characters!");
		rc = 1;
		break;
	    }
	    drptenvid_len = s - drpt_envid;
	    s++;
	    if (*drpt_envid == 0) {
		type(SS, 501, m554, "ENVID= without data!");
		rc = 1;
		break;
	    }
	    continue;
	}
	type(SS, 501, m554, "Unknown MAIL FROM:<> parameter: %s", s);
	rc = 1;
	break;
    }
    if (rc != 0)
	return;			/* Error(s) in previous loop.. */

    /*printf("  <path>: len=%d \"%s\"\n",cp-s,cp); */

    RFC821_822QUOTE(cp, newcp, addrlen);

    SS->policyresult = policytest(policydb, &SS->policystate,
				  POLICY_MAILFROM, cp, addrlen);
    if (logfp) {
      char *ss = policymsg(policydb, &SS->policystate);
      if (SS->policyresult != 0 || ss != NULL) {
	fprintf(logfp, "%d#\t-- policy result=%d, msg: %s\n", pid,
		SS->policyresult, (ss ? ss : "<NONE!>"));
	fflush(logfp);
      }
    }

    if (SS->policyresult < 0) {
      char *ss = policymsg(policydb, &SS->policystate);
      if (s != NULL) {
	type(SS,-453, m471, "Policy analysis reported:");
	type(SS, 453, m471, "%s", ss);
      } else if (SS->policyresult < -99) {
	if (SS->policyresult < -103) { /* -104 */
	  type(SS, -453, m443, "Policy analysis reports temporary DNS error");
	  type(SS, -453, m443, "with your source domain.  Retrying may help,");
	  type(SS, -453, m443, "or if the condition persists, you may need");
	  type(SS,  453, m443, "to get somebody to fix your DNS servers.");
	} else if (SS->policyresult < -100) {
	  type(SS, -453, m443, "Policy analysis reports DNS error with your");
	  type(SS, -453, m443, "source domain.   Please correct your source");
	  type(SS,  453, m443, "address and/or the info at the DNS.");
	} else {
	  type(SS, -453, m471, "Access denied by the policy analysis functions.");
	  type(SS, -453, m471, "This may be due to your source IP address,");
	  type(SS, -453, m471, "the IP reversal domain, the data you gave for");
	  type(SS, -453, m471, "the HELO/EHLO parameter, or address/domain you");
	  type(SS,  453, m471, "gave at the MAIL FROM:<...> address.");
	}
      } else {
	char *ss = policymsg(policydb, &SS->policystate);
	if (s != NULL) {
	  type(SS,-553, m571, "Policy analysis reported:");
	  type(SS, 553, m571, "%s", ss);
	} else if (SS->policyresult < -1) {
	  type(SS, -553, m543, "Policy analysis reports DNS error with your");
	  type(SS, -553, m543, "source domain.   Please correct your source");
	  type(SS,  553, m543, "address and/or the info at the DNS.");
	} else {
	  type(SS, -553, m571, "Access denied by the policy analysis functions.");
	  type(SS, -553, m571, "This may be due to your source IP address,");
	  type(SS, -553, m571, "the IP reversal domain, the data you gave for");
	  type(SS, -553, m571, "the HELO/EHLO parameter, or address/domain you");
	  type(SS,  553, m571, "gave at the MAIL FROM:<...> address.");

	}
      }
      if (newcp)
	free((void*)newcp);
      return;
    }
    s = NULL;
    if (/* addrlen > 0 && */ STYLE(SS->cfinfo, 'f')) {
	s = router(SS, RKEY_FROM, 1, cp, addrlen);
	if (s == NULL) {
	    /* the error was printed in router() */
	    if (newcp)
		free((void*)newcp);
	    return;
	}
	if (atoi(s) / 100 != 2) {
	    /* verification failed */
	    type(SS, atoi(s), s + 4, "Failed", "Failed");
	    free((void *) s);
	    if (newcp)
		free((void *) newcp);
	    return;
	}
	/* The 's' goes to use below */
    }
    if (SS->mfp == NULL &&
	(SS->mfp = mail_open(MSG_RFC822)) == NULL) {
	if (s)
	    free((void *) s);
	type(SS, 452, m430, (char *) NULL);
	if (newcp)
	    free((void *) newcp);
	return;
    }
    fflush(SS->mfp);
    rewind(SS->mfp);
#ifdef HAVE_FTRUNCATE
    ftruncate(FILENO(SS->mfp), 0);
#endif
    if (insecure)
	fprintf(SS->mfp, "external\n");

    if (netconnected_flg) {

      /* Produce the 'rcvdfrom' header only when connected
	 to network socket */

      fprintf(SS->mfp, "rcvdfrom %s (", SS->rhostname);
      if (SS->ihostaddr[0] != 0)
	fprintf(SS->mfp, "%s:%d ", SS->ihostaddr, SS->rport);
      rfc822commentprint(SS->mfp, SS->helobuf);
      if (ident_flag) {
	fprintf(SS->mfp, " ident: ");
	rfc822commentprint(SS->mfp, SS->ident_username);
      }
      fprintf(SS->mfp, ")\n");
    }

    if (bodytype != NULL)
	fprintf(SS->mfp, "bodytype %s\n", bodytype);
    fprintf(SS->mfp, "with %s\n", SS->with_protocol);
    if (ident_flag)
	fprintf(SS->mfp, "identinfo %s\n", SS->ident_username);

    if (addrlen == 0)
	fputs("channel error\n", SS->mfp);	/* Empty  MAIL FROM:<> */
    else {
	fputs("from <", SS->mfp);
	fwrite(cp, 1, addrlen, SS->mfp);
	fputs(">\n", SS->mfp);
    }
    if (SS->policyresult > 0)
      fprintf(SS->mfp,"comment policytest() reported freeze state\n");

    if (newcp)
	free((void *)newcp);

    if (drpt_envid != NULL) {
	fprintf(SS->mfp, "envid ");
	fwrite(drpt_envid, 1, drptenvid_len, SS->mfp);
	fputs("\n", SS->mfp);
    }
    if (drpt_ret != NULL) {
	fprintf(SS->mfp, "notaryret ");
	fwrite(drpt_ret, 1, drptret_len, SS->mfp);
	fputs("\n", SS->mfp);
    }

    availspace = fd_statfs(FILENO(SS->mfp));
    if (availspace < 0)
	availspace = 2000000000;	/* Over 2G ? */
    availspace >>= 1;

    if (ferror(SS->mfp)) {
	type(SS, 452, m430, (char *) NULL);
	mail_abort(SS->mfp);
	SS->mfp = NULL;
    } else if (SS->sizeoptval > maxsize && maxsize > 0) {
	type(SS, -552, "5.3.4", "This message is larger, than our maximum acceptable");
	type(SS,  552, "5.3.4", "incoming message size of  %d  chars.", maxsize);
	mail_abort(SS->mfp);
	SS->mfp = NULL;
    } else if (SS->sizeoptval > availspace) {
	type(SS, 452, "4.3.1", "Try again later, insufficient storage available at the moment");
	mail_abort(SS->mfp);
	SS->mfp = NULL;
    } else {
	if (s) {
	    int rrc = atoi(s);
	    type(SS, rrc, s + 4, "Ok");
	    if (rc >= 400) {
	      mail_abort(SS->mfp);
	      SS->mfp = NULL;
	    }
	} else
	    type(SS, 250, "2.1.0", "Sender syntax Ok%s", srcrtestatus);
	SS->sender_ok = 1;
    }
    if (s)
	free((void *) s);
    SS->state = Recipient;
    SS->rcpt_count = 0;
    SS->from_box = (*cp == 0);
}


void smtp_rcpt(SS, buf, cp)
SmtpState *SS;
const char *buf, *cp;
{
    const char *s;
    const char *drpt_notify, *drpt_orcpt;
    const char *newcp = NULL;
    const char *srcrtestatus = "";
    int addrlen = 0, notifylen = 0, orcptlen = 0;
    int strict = STYLE(SS->cfinfo, 'R');
    int sloppy = STYLE(SS->cfinfo, 'S');

    /* some smtp clients don't get the 503 right and try again, so
       tell the spammers exactly what's happening. */
    if ( (SS->state == MailOrHello || SS->state == Mail) &&
	 policydb != NULL && SS->policyresult < 0 ) {
      type(SS, -553, m571, "Access denied by the policy analysis functions.");
      type(SS, -553, m571, "This may be due to your source IP address,");
      type(SS, -553, m571, "the IP reversal domain, the data you gave for");
      type(SS, -553, m571, "the HELO/EHLO parameter, or address/domain");
      type(SS,  553, m571, "you gave at the MAIL FROM:<...> address.");
      return;
    }

    if (SS->state != Recipient && SS->state != RecipientOrData) {
	switch (SS->state) {
	case Hello:
	    cp = "Waiting for HELO command";
	    break;
	case Mail:
	case MailOrHello:
	    cp = "Waiting for MAIL command";
	    break;
	default:
	    cp = NULL;
	    break;
	}
	type(SS, 503, m551, cp);
	return;
    }
    if (!CISTREQN(cp, "To:", 3)) {
	type(SS, 501, m552, "where is To: in that?");
	return;
    }
    for (cp = cp + 3; *cp != '\0' && *cp != '<'; ++cp)
	if (!isspace(*cp)) {
	  if (!sloppy) {
	    type(SS, 501, m513, "where is <...> in that?");
	    return;
	  }
	  break; /* Sigh, be sloppy.. */
	}
    if (*cp == '\0') {
	type(SS, 501, m513, "where is <...> in that?");
	return;
    } else if (*cp != '<' && !sloppy) {
	type(SS, 501, m513, "strangeness between : and <");
	return;
    } else if (*(cp+1) == '>') {
	type(SS, 501, m513, "Null address valid only as source");
	return;
    }
    if (*(cp + 1) == '<') {
	type(SS, 501, m513, "there are too many <'s in that!");
	return;
    }
    if (*cp == '<') {
      /* "<" [ <a-t-l> ":" ] <localpart> "@" <domain> ">" */
      s = rfc821_path(cp, strict);
      if (s == cp) {
	/* Failure ?  Perhaps we are RESTRICTIVE, and the address
	   is '<postmaster>' without domain ? */
	if (CISTREQN(cp, "<POSTMASTER>", 12)) {
	  s += 12;
	} else {
	  /* Genuine failure.. */
	  type821err(SS, 501, m513, buf, "Path data: %s", rfc821_error);
	  return;
	}
      }
      if (*s == '>') {
	type(SS, 501, m513, "there are too many >'s in that!");
	return;
      }
      /* Ok, now it is a moment to see, if we have source routes: @a,@b:c@d */
      if (cp[1] == '@') {
	/* Yup, Starting with an "@" ..  scan until ":", which must be
	   in there as this is valid RFC-821 object. */
	if (!allow_source_route) {
	  while (*cp != ':') ++cp; 
	  srcrtestatus = ", source route ignored";
	}
      }
      ++cp;			/* Skip the initial '<' */
      addrlen = s - 1 - cp;	/* Length until final  '>' */
    } else {
      /* We can be here only with non-strict mode (i.e. Sloppy..) */

      s = rfc821_path2(cp, strict);
      if (s == cp) {
	/* Failure.. */
	type821err(SS, 501, m513, buf, "Path data: %.200s", rfc821_error);
	return;
      }

      if (*s == '>') {
	type(SS, 501, m513, "there are too many >'s in that!");
	return;
      }

      /* Ok, now it is a moment to see, if we have source routes: @a,@b:c@d */
      if (cp[0] == '@') {
	/* Yup, Starting with an "@" ..  scan until ":", which must be
	   in there as this is valid RFC-821 object. */
	if (!allow_source_route) {
	  while (*cp != ':') ++cp; 
	  srcrtestatus = ", source route ignored";
	}
      }
      addrlen = s - cp;	/* Length */
    }

#if 0
    if (debug)
      type(SS, 000, "", "<path>: len=%d \"%.*s\"\r\n", addrlen, addrlen, cp);
#endif

    if (addrlen < 1) {
	type(SS, 501, m513, "What is an empty recipient?");
	return;
    }
    drpt_notify = NULL;
    drpt_orcpt = NULL;

    while (*s) {
	while (isascii(*s) && isspace(*s))
	    ++s;
	/* IETF-NOTARY  SMTP-RCPT-DRPT extensions */
	if (CISTREQN("NOTIFY=", s, 7)) {
	    if (drpt_notify) {
		type(SS, 501, m554, "NOTIFY-param double defined!");
		return;
	    }
	    drpt_notify = s;
	    s += 7;
	    while (*s) {
		if (CISTREQN("SUCCESS", s, 7))
		    s += 7;
		else if (CISTREQN("FAILURE", s, 7))
		    s += 7;
		else if (CISTREQN("DELAY", s, 5))
		    s += 5;
		else if (CISTREQN("NEVER", s, 5))
		    s += 5;
		if (*s != ',')
		    break;
		++s;
	    }
	    if (*s && *s != ' ' && *s != '\t') {
		type(SS, 455, m454, "NOTIFY-param data error");
		return;
	    }
	    notifylen = s - drpt_notify;
	    continue;
	}
	if (CISTREQN("ORCPT=", s, 6)) {
	    if (drpt_orcpt) {
		type(SS, 501, m554, "ORCPT-param double defined!");
		return;
	    }
	    drpt_orcpt = s;
	    s = orcpt_string(s + 6);
	    if (s == NULL) {
		type821err(SS, -501, m454, buf, "Invalid ORCPT value '%s'", drpt_orcpt);
		type(SS, 501, m454, "ORCPT-param data error!");
		return;
	    }
	    orcptlen = s - drpt_orcpt;
	    continue;
	}
	type(SS, 555, "Unknown RCPT TO:<> parameter: %s", s);
	return;
    }


    RFC821_822QUOTE(cp, newcp, addrlen);

    SS->policyresult = policytest(policydb, &SS->policystate,
				  POLICY_RCPTTO, cp, addrlen);
    if (logfp) {
      char *ss = policymsg(policydb, &SS->policystate);
      if (SS->policyresult != 0 || ss != NULL) {
	fprintf(logfp, "%d#\t-- policy result=%d, msg: %s\n", pid,
		SS->policyresult, (ss ? ss : "<NONE!>"));
	fflush(logfp);
      }
    }

    if (SS->postmasteronly || SS->policyresult < 0) {
      if (CISTREQN(cp, "postmaster", 10)) {
	/* Rejected, but it seems to be a postmaster ??? */
	if (addrlen == 10)
	  SS->policyresult = 0; /* Plain <postmaster> */
	else
	  if (policydb != NULL && SS->policyresult > -100) {
	    int rc = policytest(policydb, &SS->policystate,
				POLICY_RCPTPOSTMASTER, cp, addrlen);
	    if (rc == 0)
	      SS->policyresult = 0;

	    if (logfp) {
	      char *ss = policymsg(policydb, &SS->policystate);
	      if (SS->policyresult != 0 || ss != NULL) {
		fprintf(logfp, "%d#\t-- policy result=%d, msg: %s\n", pid,
			SS->policyresult, (ss ? ss : "<NONE!>"));
		fflush(logfp);
	      }
	    }
	  }
      }
    }
    if (SS->policyresult < 0) {
	char *ss = policymsg(policydb, &SS->policystate);

	fprintf(SS->mfp, "comment policytest() rejected rcptaddr: <");
	fwrite(cp, 1, addrlen, SS->mfp);
	fprintf(SS->mfp,">\n");

	if (SS->policyresult < -99) { /* "soft error, 4XX code */
	  if (ss != NULL) {
	    type(SS,-453, m471, "Policy analysis reported:");
	    type(SS, 453, m471, "%s", ss);
	  } else if (SS->policyresult < -103) { /* -104 */
	    type(SS, -453, m443, "Policy analysis reports temporary DNS error");
	    type(SS, -453, m443, "with this target domain. Retrying may help,");
	    type(SS, -453, m443, "or if the condition persists, some further");
	    type(SS, -453, m443, "work may be in need with the target domain");
	    type(SS,  453, m443, "DNS servers.");

	  } else if (SS->policyresult < -102) {
	    /* Code: -103 */
	    type(SS,-453, m471, "This target address is not our MX service");
	    type(SS,-453, m471, "client, nor you are connecting from address");
	    type(SS,-453, m471, "that is allowed to openly use us to relay");
	    type(SS,-453, m471, "to any arbitary address thru us.");
	    type(SS, 453, m471, "We don't accept this recipient.");
	  } else if (SS->policyresult < -100) {
	    /* Code: -102 */
	    type(SS,-453, m443, "Policy analysis found DNS error on");
	    type(SS,-453, m443, "the target address. This address is");
	    type(SS, 453, m443, "not currently acceptable.");
	  } else {
	    type(SS, 453, m443, "Policy rejection on the target address");
	  }
	} else {
	  if (ss != NULL) {
	    type(SS,-553, m571, "Policy analysis reported:");
	    type(SS, 553, m571, "%s", s);
	  } else if (SS->policyresult < -2) {
	    /* Code: -3 */
	    type(SS,-553, m571, "This target address is not our MX service");
	    type(SS,-553, m571, "client, nor you are connecting from address");
	    type(SS,-553, m571, "that is allowed to openly use us to relay");
	    type(SS,-553, m571, "to any arbitary address thru us.");
	    type(SS, 553, m571, "We don't accept this recipient.");

	  } else if (SS->policyresult < -1) {
	    /* Code: -2 */
	    type(SS,-553, m543, "Policy analysis found DNS error on");
	    type(SS,-553, m543, "the target address. This address is");
	    type(SS, 553, m543, "not currently acceptable.");
	  } else {
	    type(SS, 553, m571, "Policy rejection on the target address");
	  }
	}
	if (newcp)
	    free((void *) newcp);
	return;
    }

    s = NULL;
    if (STYLE(SS->cfinfo, 't')) {
	s = router(SS, RKEY_TO, 1, cp, addrlen);
	if (s == NULL)
	    /* the error was printed in router() */
	    return;
	if (atoi(s) / 100 != 2) {
	    /* verification failed */
	    type(SS, atoi(s), s + 4, "Failed", "Failed");
	    free((void *) s);
	    if (newcp)
		free((void *) newcp);
	    return;
	}
	/* The 's' goes to use below */
    }
    /* FIRST 'todsn', THEN 'to' -HEADER */

    /* IETF-NOTARY DSN data: */
    fputs("todsn", SS->mfp);
    if (drpt_notify) {
	putc(' ', SS->mfp);
	fwrite(drpt_notify, 1, notifylen, SS->mfp);
    }
    if (drpt_orcpt) {
	putc(' ', SS->mfp);
	fwrite(drpt_orcpt, 1, orcptlen, SS->mfp);
    } else {
	const char *p = cp;
	const char *ep = cp + addrlen;
	fputs(" ORCPT=rfc822;", SS->mfp);
	while (*p && p < ep) {
	    char c = (*p) & 0xFF;
	    if ('!' <= c && c <= '~' && c != '+' && c != '=')
		putc(c, SS->mfp);
	    else
		fprintf(SS->mfp, "+%02X", c);
	    ++p;
	}
    }
    putc('\n', SS->mfp);

    /* Normal "RCPT TO:<>" data: */
    fprintf(SS->mfp, "to <");
    fwrite(cp, 1, addrlen, SS->mfp);
    fprintf(SS->mfp, ">\n");

    if (SS->policyresult > 0)
      fprintf(SS->mfp,"comment policytest() reported freeze state %d\n",
	      SS->policyresult);

    if (newcp)
	free((void *)newcp);

    if (SS->sizeoptval < 0)
	SS->sizeoptval = 0;
    SS->sizeoptsum += SS->sizeoptval;
    if (ferror(SS->mfp)) {
	type(SS, 452, m430, (char *) NULL);
    } else if (maxsize > 0 && SS->sizeoptsum > maxsize) {
	type(SS, 552, m534, "Message size exceeds fixed maximum size of %ld chars for acceptable email", maxsize);
    } else if (SS->sizeoptsum > availspace) {
	type(SS, 452, m431, "insufficient storage space, try again later");
    } else if (s) {
	if (SS->from_box && SS->rcpt_count > MaxErrorRecipients) {
	    type(SS, 552, m571, "SPAM trap -- too many recipients for an empty source address!");
	} else
	    type(SS, atoi(s), s + 4, "Ok");
	SS->rcpt_count += 1;
    } else {
	if (SS->from_box && SS->rcpt_count > MaxErrorRecipients) {
	    type(SS, 552, m571, "SPAM trap -- too many recipients for an empty source address!");
	} else if (SS->sizeoptval)
	    type(SS, 250, "2.1.5", "Ok; can accomodate %d byte message%s",
		 SS->sizeoptval, srcrtestatus);
	else
	    type(SS, 250, "2.1.5", "Recipient address syntax Ok%s",
		 srcrtestatus);
	SS->rcpt_count += 1;
    }
    if (s)
	free((void *) s);
    SS->state = RecipientOrData;
}

void smtp_turnme(SS, name, cp)
SmtpState *SS;
const char *name, *cp;
{
    FILE *mfp = mail_open(MSG_RFC822);
    if (!mfp) {
	type(SS, 452, m400, "Failed to initiate ETRN request;  Disk full?");
	typeflush(SS);
	return;
    }
    fprintf(mfp, "%c%c%s\n", _CF_TURNME, _CFTAG_NORMAL, cp);
    /* printf("050-My uid=%d/%d\r\n",getuid(),geteuid()); */
    runasrootuser();
    if (mail_close_alternate(mfp, TRANSPORTDIR, "")) {
	type(SS, 452, m400, "Failed to initiate ETRN request;  Permission denied?");
    } else {
	type(SS, -250, m200, "An ETRN request is initiated - lets hope the system");
	type(SS, -250, m200, "has resources to honour it.   We call the remote, if");
	type(SS, 250, m200, "we have anything to send there.");
    }
    runastrusteduser();
    typeflush(SS);
}

void smtp_verify(SS, buf, cp)
SmtpState *SS;
const char *buf, *cp;
{
    char *s;
    int cfi;
    const char *newcp = NULL;
    int addrlen;

    if (SS->state == Hello) {
	type(SS, 503, m551, "Waiting for HELO/EHLO command");
	return;
    }
    while (*cp == ' ' || *cp == '\t')
	++cp;

    cfi = STYLE(SS->cfinfo, 'v');

#if 0				/* The input string is ARBITARY STRING (shudder..) */
    if (*cp == '<')
	s = rfc821_path(cp, cfi);	/* with < > */
    else
	s = rfc821_path2(cp, cfi);	/* Without < > */
    if (s == cp) {
	type821err(SS, 501, m552, buf, "Path data: %s", rfc821_error);
	return;
    }
    while (*s == ' ' || *s == '\t')
	++s;
    if (*s != 0) {
	type(SS, 501, m552, "Growl! Extra junk after the VRFY argument!");
	return;
    }
    addrlen = s - cp;
#else
    addrlen = strlen(cp);
#endif

    RFC821_822QUOTE(cp, newcp, addrlen);

    if (cfi) {
	s = router(SS, RKEY_VERIFY, 0, cp, addrlen);
	if (s != NULL) {
	    /* printf("%s\r\n", s); */
	    free(s);
	} else
	    type(SS, 501, m540, "Unable to verify that address");
    } else
	type(SS, 252, "2.5.2", (char *) NULL);	/* Syntax ok */

    if (newcp)
	free((void *)newcp);
}

void smtp_expand(SS, buf, cp)
SmtpState *SS;
const char *buf, *cp;
{
    char *s;
    int cfi, addrlen;
    char *newcp = NULL;

    if (SS->state == Hello) {
	type(SS, 503, m551, "Waiting for HELO/EHLO command");
	return;
    }
    while (*cp == ' ' || *cp == '\t')
	++cp;

    cfi = STYLE(SS->cfinfo, 'e');
    if (cfi != 0) {
#if 0				/* The input string is an arbitary string! */
	if (*cp == '<')
	    s = rfc821_path(cp, cfi);	/* with < > */
	else
	    s = rfc821_path2(cp, cfi);	/* Without < > */
	if (s == cp) {
	    type821err(SS, 501, m552, buf, "Path data: %s", rfc821_error);
	    return;
	}
	while (*s == ' ' || *s == '\t')
	    ++s;
	if (*s != 0) {
	    type(SS, 501, m552, "Growl! Extra junk after the EXPN argument!");
	    return;
	}
	addrlen = s - cp;
#else
	addrlen = strlen(cp);
#endif

	RFC821_822QUOTE(cp, newcp, addrlen);

	s = router(SS, RKEY_EXPAND, 0, cp, addrlen);
	if (s != NULL) {
	    /* printf("%s\r\n", s); */
	    free(s);
	} else
	    type(SS, 501, m540, "Unable to expand that address");
	if (newcp)
	    free((void *)newcp);
    } else
	type(SS, 502, m540, (char *) NULL);
}
