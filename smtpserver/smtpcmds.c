/*
 *    Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *      This will be free software, but only when it is finished.
 */
/*
 *    Several extensive changes by Matti Aarnio <mea@nic.funet.fi>
 *      Copyright 1991-2000.
 */
/*
 * Zmailer SMTP-server divided into bits
 *
 * The basic commands:
 *
 *  - HELO/EHLO
 *  - MAIL 
 *  - RCPT
 *  - VRFY
 *  - EXPN
 *
 */

#include "smtpserver.h"

extern int netconnected_flg;
extern int do_whoson;

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
  fputc('"', mfp);
  for ( ; *str ; ++str ) {
    int c = (*str) & 0xFF;
    if (c == '"' || c == '\\' || c == '(' || c == ')')
      fputc('\\', mfp);
    fputc(c, mfp);
  }
  fputc('"', mfp);
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
    if (!strict_protocol)
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

    if (strict_protocol && *cp == ' ')
      ++cp;
    else
      while (*cp == ' ' || *cp == '\t') ++cp;

    if (debug) typeflush(SS);
    SS->policyresult = policytest(policydb, &SS->policystate,
				  POLICY_HELONAME, cp, strlen(cp),
				  SS->authuser);
    if (logfp) {
      char *s = policymsg(policydb, &SS->policystate);
      if (SS->policyresult != 0 || s != NULL) {
	fprintf(logfp, "%s#\t-- policy result=%d, msg: %s\n", logtag,
		SS->policyresult, (s ? s : "<NONE!>"));
	fflush(logfp);
      }
    }
    if (logfp_to_syslog) {
      char *s = policymsg(policydb, &SS->policystate);
      if (SS->policyresult != 0 || s != NULL) {
	zsyslog((LOG_DEBUG, "%s # policy result=%d, msg: %s", logtag,
		SS->policyresult, (s ? s : "<NONE!>")));
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
	smtp_tarpit(SS);
	type821err(SS, -501, "", buf, "Invalid `%.200s' parameter!", buf);
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
	smtp_tarpit(SS);
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
	smtp_tarpit(SS);
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
	int multiline = multilinereplies;
	multilinereplies = 1;

	if (policyinlimit >= 0)  /* defined if non-negative value */
	  maxinlimit = policyinlimit;
	if (maxsize != 0 && maxsize < maxinlimit)
	  maxinlimit = maxsize;
	if (maxsize != 0 && maxinlimit == 0)
	  maxinlimit = maxsize; /* Lower from infinite */

	sprintf(sizebuf, "SIZE %ld", maxinlimit); /* 0: No fixed max size
						     in force, else:
						     The FIXED maximum */

	type(SS, -250, NULL, sizebuf);		/* RFC 1427/1653/1870 */
	if (mime8bitok)
	  type(SS, -250, NULL, "8BITMIME");	/* RFC 1426/1652 */
	if (pipeliningok)
	  type(SS, -250, NULL, "PIPELINING");	/* RFC 1854/2197 */
	if (chunkingok)
	  type(SS, -250, NULL, "CHUNKING");	/* RFC 1830: BDAT */
	if (enhancedstatusok)
	  type(SS, -250, NULL, "ENHANCEDSTATUSCODES"); /* RFC 2034 */
	if (expncmdok && STYLE(SS->cfinfo, 'e'))
	  type(SS, -250, NULL, "EXPN");		/* RFC 821 */
	if (vrfycmdok && STYLE(SS->cfinfo, 'v'))
	  type(SS, -250, NULL, "VRFY");		/* RFC 821 */
	if (dsn_ok)
	  type(SS, -250, NULL, "DSN");		/* RFC 1891 */

	if (deliverby_ok == 0)
	  type(SS, -250, NULL, "DELIVERBY");	/* RFC 2852 */
	else if (deliverby_ok > 0)
	  type(SS, -250, NULL, "DELIVERBY %d", deliverby_ok);

	if (rcptlimitcnt > 100)
	  type(SS, -250, NULL, "X-RCPTLIMIT %d", rcptlimitcnt);

	if (auth_login_without_tls || SS->sslmode) {
	  if (auth_ok)
	    type(SS, -250, NULL, "AUTH=LOGIN"); /* RFC 2554, NetScape/
						   Sun Solstice/ ? */
	  if (auth_ok)
	    type(SS, -250, NULL, "AUTH LOGIN"); /* RFC 2554, M$ Exchange ? */
	}
#ifdef HAVE_OPENSSL
	/* NOTE: This seems to require TLS and STARTTLS facilities,
	   better known as SSL..  TLS: RFC 2246, STARTTLS: RFC 2487 */
	if (starttls_ok && !SS->sslmode) {
	  type (SS, -250, NULL, "STARTTLS"); /* RFC 2487 */
	}
#endif /* - HAVE_OPENSSL */
	if (etrn_ok && !msa_mode)
	  type(SS, -250, NULL, "ETRN");		/* RFC 1985 */
	type(SS, 250, NULL, "HELP");		/* RFC 821 ? */
	SS->with_protocol = WITH_ESMTP;
	multilinereplies = multiline;
    }
    SS->state = MailOrHello;
}

void smtp_mail(SS, buf, cp, insecure)
SmtpState *SS;
const char *buf, *cp;
int insecure;
{
    const char *s, *p;
    int rc;
    const char *drpt_envid;
    const char *drpt_ret;
    const char *bodytype = NULL;
    const char *newcp = NULL;
    const char *srcrtestatus = "";
    const char *auth_param;
    int addrlen, drptret_len, drptenvid_len, authparam_len;
    int strict = STYLE(SS->cfinfo, 'R');
    int sloppy = STYLE(SS->cfinfo, 'S');

    if (strict && sloppy) /* If misconfigured, SLOPPY takes precedence! */
      strict = 0;

    addrlen = 0;
    drptret_len = 0;
    drptenvid_len = 0;
    authparam_len = 0;

    SS->sender_ok = 0;		/* Set it, when we are sure.. */

    SS->deliverby_time  = 0;		/* RFC 2852 */
    SS->deliverby_flags = 0;

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
	smtp_tarpit(SS);
	type(SS, 503, m551, cp);
	return;
    }

    if (*cp == ' ') ++cp;
    if (!strict_protocol || sloppy) while (*cp == ' ' || *cp == '\t') ++cp;
    if (!CISTREQN(cp, "From:", 5)) {
	smtp_tarpit(SS);
	type(SS, 501, m552, "where is From: in that?");
	return;
    }
    cp += 5;
    if (!strict_protocol || sloppy)
      for (; *cp != '\0' && *cp != '<'; ++cp)
	/* Skip white-space */
	if (!isascii(*cp) || !isspace(*cp)) {
	  if (!sloppy) {
	    smtp_tarpit(SS);
	    type(SS, 501, m517, "where is <...> in that?");
	    return;
	  }
	  break; /* Sigh, be sloppy.. */
	}
    if (*cp == '\0') {
	smtp_tarpit(SS);
	type(SS, 501, m517, "where is <...> in this: %s", cp);
	return;
    } else if (*cp != '<' && !sloppy) {
	smtp_tarpit(SS);
	type(SS, 501, m517, "strangeness between ':' and '<': %s", cp);
	return;
    }
    if (*(cp + 1) == '<') {
	smtp_tarpit(SS);
	type(SS, 501, m517, "there are too many <'s in this: %s", cp);
	return;
    }
    /* "<" [ <a-t-l> ":" ] <localpart> "@" <domain> ">" */
    if (*cp == '<') {
      if (!sloppy) {
	s = rfc821_path(cp, strict || strict_protocol);
	if (s == cp) {
	  /* Failure.. ? */
	  type(SS, -501, m517, "For input: %s", cp);
	  type821err(SS, 501, m517, buf, "Path data: %.200s", rfc821_error);
	  return;
	}
	if (*s == '>') {
	  smtp_tarpit(SS);
	  type(SS, 501, m517, "there are too many >'s in this: <%s", cp);
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
      } else { /* Sloppy processing */
	++cp;
	while (*cp == ' ' || *cp == '\t') ++cp;
	s = rfc821_path2(cp, 0);
	if (s == cp && *s != '>') {
	  /* Failure.. ? */
	  type(SS, -501, m517, "For input: %s", cp);
	  type821err(SS, 501, m517, buf, "Path data: %.200s", rfc821_error);
	  return;
	}
	/* Now it is a moment to see, if we have source routes: @a,@b:c@d */
	if (*cp == '@') {
	  /* Yup, Starting with an "@" ..  scan until ":", which must be
	     in there as this is valid RFC-821 object. */
	  if (!allow_source_route) {
	    while (*cp != ':') ++cp; 
	    if (*cp == ':') ++cp; /* Should be ALWAYS */
	    srcrtestatus = ", source route ignored";
	  }
	}
	addrlen = s - cp;
	while (*s == ' ' || *s == '\t') ++s;
	if (*s != '>') {
	  rfc821_error_ptr = s;
	  type(SS, -501, m517, "For input: %s", cp);
	  type821err(SS, 501, m517, buf, "Missing ending '>' bracket");
	  return;
	}
	++s;
      }
    } else {
      /* We can be here only with non-strict mode (i.e. Sloppy..) */

      s = rfc821_path2(cp, strict);
      if (s == cp) {
	/* Failure.. */
	type(SS, -501, m517, "For input: %s", cp);
	type821err(SS, 501, m517, buf, "Path data: %.200s", rfc821_error);
	return;
      }

      if (*s == '>') {
	smtp_tarpit(SS);
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

    /* BODY=8BITMIME SIZE=nnnn ENVID=xxxxxx RET=xxxx BY=nnnn;FF */
    SS->sizeoptval = -1;
    SS->sizeoptsum = -1;
    drpt_envid = NULL;
    drpt_ret   = NULL;
    auth_param = NULL;
    rc = 0;
    while (*s) {
	while (*s == ' ' || (sloppy && *s == '\t')) {
	    ++s;
	    if (strict_protocol) break;
	    if (strict && !sloppy) break;
	}
	if (dsn_ok && CISTREQN("RET=", s, 4)) {
	    if (drpt_ret) {
		smtp_tarpit(SS);
		type(SS, 501, m554, "RET-param double defined!");
		return;
	    }
	    s += 4;
	    drpt_ret = s;
	    if (CISTREQN("FULL", s, 4) ||
		CISTREQN("HDRS", s, 4))
		s += 4;
	    if (*s && *s != ' ' && *s == '\t') {
		smtp_tarpit(SS);
		type(SS, 501, m454, "RET-param data error");
		return;
	    }
	    drptret_len = (s - drpt_ret);
	    continue;
	}
	if (mime8bitok && CISTREQN("BODY=", s, 5)) {
	    /* Actually we do not use this data... */
	    s += 5;
	    if (bodytype != NULL) {
		smtp_tarpit(SS);
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
		smtp_tarpit(SS);
		type(SS, 501, m554, "BODY-param data error, must be one of: 8BITMIME/BINARYMIME/7BIT");
		rc = 1;
		break;
	    }
	    continue;
	}
	if (CISTREQN("SIZE=", s, 5)) {
	    s += 5;
	    if (SS->sizeoptval != -1) {
		smtp_tarpit(SS);
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
		if (SS->sizeoptval > 999999999) /* 1GB or more? */
		  break;
	    }
	    if ((*s && *s != ' ' && *s != '\t') ||
		(SS->sizeoptval > 999999999) /* 1GB */ ) {
		smtp_tarpit(SS);
		type(SS, 501, m554, "SIZE-param data error");
		rc = 1;
		break;
	    }
	    continue;
	}
	/* IETF-NOTARY  SMTP-DSN extensions */
	if (dsn_ok && CISTREQN("ENVID=", s, 6)) {
	    if (drpt_envid != NULL) {
		smtp_tarpit(SS);
		type(SS, 501, m554, "ENVID double definition!");
		rc = 1;
		break;
	    }
	    drpt_envid = s + 6;
	    p = xtext_string(s + 6);
	    if (p == (s + 6)) {
		smtp_tarpit(SS);
		type821err(SS, -501, m554, buf, "Invalid ENVID value '%.200s'", drpt_envid);
		type(SS, 501, m554, "ENVID data contains illegal characters!");
		rc = 1;
		break;
	    }
	    s = p;
	    drptenvid_len = s - drpt_envid;
	    ++s;
	    if (drptenvid_len == 0) {
		smtp_tarpit(SS);
		type(SS, 501, m554, "ENVID= without data!");
		rc = 1;
		break;
	    }
	    continue;
	}
	if (auth_ok && CISTREQN("AUTH=", s, 5)) {
	    /* RFC 2554 AUTH extension */
	    auth_param = s + 5;
	    p = xtext_string(s + 5);
	    if (p == (s + 5)) {
		smtp_tarpit(SS);
		type821err(SS, -501, m554, buf, "Invalid AUTH value '%.200s'", auth_param);
		type(SS, 501, m554, "AUTH data contains illegal characters!");
		rc = 1;
		break;
	    }
	    s = p;
	    authparam_len = s - auth_param;
	    ++s;
	    if (authparam_len == 0) {
		smtp_tarpit(SS);
		type(SS, 501, m554, "AUTH= without data!");
		rc = 1;
		break;
	    }
	    continue;
	}
	if (deliverby_ok >= 0 && CISTREQN("BY=", s, 3)) {
	    /* RFC 2852: DELIVERBY extension */
	    int neg = 0;
	    int val = 0;
	    int cnt = 0;
	    p = s + 3;
	    if (*p == '-') neg = *p++; /* non-zero flag */
	    while ('0' <= *p && *p <= '9') {
	      val = val * 10 + (*p - '0');
	      ++p; ++cnt;
	    }
	    if (cnt > 9) {
	    invalid_by_data:
	      smtp_tarpit(SS);
	      type821err(SS, 501, m554, buf, "Invalid data at BY= parameter: '%.200s'", s);
	      rc = 1;
	      break;
	    }
	    if (neg) val = -val;
	    if (*p != ';') goto invalid_by_data;
	    ++p;
	    neg = 0;
	    while (*p && *p != ' ' && *p != '\t') {
	      switch(*p) {
	      case 'T': case 't':
		if (neg & DELIVERBY_T) goto invalid_by_data;
		neg |= DELIVERBY_T;
		break;
	      case 'N': case 'n':
		if (neg & (DELIVERBY_R|DELIVERBY_N)) goto invalid_by_data;
		/* N and R are exclusive */
		neg |= DELIVERBY_N;
		break;
	      case 'R': case 'r':
		if (neg & (DELIVERBY_R|DELIVERBY_N)) goto invalid_by_data;
		/* R and N are exclusive */
		neg |= DELIVERBY_R;
		break;
	      default:
		goto invalid_by_data;
		break;
	      }
	      ++p;
	    }
	    if ((neg & (DELIVERBY_N|DELIVERBY_R)) == 0)
	      goto invalid_by_data; /* Neither N or R ?! */
	    if ((neg & DELIVERBY_R) && val <= 0) {
	      type(SS, 501, m554,
		   "The strict delivery deadline is already past: BY=%d;R%s",
		   val, (neg & DELIVERBY_T) ? "T":"");
	      rc = 1;
	      break;
	    }
	    if ((neg & DELIVERBY_R) &&
		deliverby_ok > 0 && val < deliverby_ok) {
	      type(SS, 553, m571, "Too small short delivery deadline value given: %d\n", val);
	      rc = 1;
	      break;
	    }
	    SS->deliverby_time  = time(NULL) + val;
	    SS->deliverby_flags = neg;
	    s = p;
	    continue;
	}

	smtp_tarpit(SS);
	type(SS, 501, m554, "Unknown MAIL FROM:<> parameter: %s", s);
	rc = 1;
	break;
    }
    if (rc != 0)
	return;			/* Error(s) in previous loop.. */

    /*printf("  <path>: len=%d \"%s\"\n",cp-s,cp); */

    RFC821_822QUOTE(cp, newcp, addrlen);

    if (debug) typeflush(SS);
    SS->policyresult = policytest(policydb, &SS->policystate,
				  POLICY_MAILFROM, cp, addrlen,
				  SS->authuser);
    if (logfp || logfp_to_syslog) {
      char *ss = policymsg(policydb, &SS->policystate);
      if (SS->policyresult != 0 || ss != NULL) {
	type(NULL,0,NULL,"-- policy result=%d, msg: %s",
	     SS->policyresult, (ss ? ss : "<NONE!>"));
	if (logfp)
	  fflush(logfp);
      }
    }

    if (SS->policyresult < 0) {
      char *ss = policymsg(policydb, &SS->policystate);
      if (ss != NULL) {
	int code = 450;
	const char *mcode = m471;
	if (SS->policyresult >= -99) {
	  code = 553;
	  mcode = m571;
	}
	smtp_tarpit(SS);
	type(SS, code, mcode, "For MAIL FROM address <%.*s> policy analysis reported: %s",
	     addrlen, cp, ss);
      } else if (SS->policyresult < -99) {
	smtp_tarpit(SS);
	if (SS->policyresult < -103) { /* -104 */
	  if (!multilinereplies) {
	    type(SS,450,m443, "For input: <%.*s> policy analysis reports temporary DNS error with your source domain.", addrlen, cp);
	  } else {
	    type(SS, -450, m443, "Policy analysis reports temporary DNS error");
	    type(SS, -450, m443, "with your source domain.  Retrying may help,");
	    type(SS, -450, m443, "or if the condition persists, you may need");
	    type(SS,  450, m443, "to get somebody to fix your DNS servers: <%.*s>",
		 addrlen, cp);
	  }
	} else if (SS->policyresult < -100) {
	  if (!multilinereplies) {
	    type(SS,450,m443, "For input: <%.*s> policy analysis reports DNS error with your source domain.", addrlen, cp);
	  } else {
	    type(SS, -450, m443, "Policy analysis reports DNS error with your");
	    type(SS, -450, m443, "source domain.   Please correct your source");
	    type(SS,  450, m443, "address and/or the info at the DNS: <%.*s>",
		 addrlen, cp);
	  }
	} else {
	  if (!multilinereplies) {
	    type(SS,450,m471, "For address <%.*s> access denied by the policy analysis functions.", addrlen, cp);
	  } else {
	    type(SS, -450, m471, "Access denied by the policy analysis functions.");
	    type(SS, -450, m471, "This may be due to your source IP address,");
	    type(SS, -450, m471, "the IP reversal domain, the data you gave for");
	    type(SS, -450, m471, "the HELO/EHLO parameter, or address/domain you");
	    type(SS,  450, m471, "gave at the MAIL FROM:<%.*s> address.",
		 addrlen, cp);
	  }
	}
      } else {
	char *ss = policymsg(policydb, &SS->policystate);
	smtp_tarpit(SS);
	if (ss != NULL) {
	  type(SS, 553, m571, "For input address <%.*s> Policy analysis reported: %s", addrlen, cp, ss);
	} else if (SS->policyresult < -1) {
	  if (!multilinereplies) {
	    type(SS,553,m543,"For MAIL FROM address <%.*s> the policy analysis reports DNS error with your source domain.", addrlen, cp);
	  } else {
	    type(SS, -553, m543, "Policy analysis reports DNS error with your");
	    type(SS, -553, m543, "source domain.   Please correct your source");
	    type(SS,  553, m543, "address and/or the info at the DNS: <%.*s>",
		 addrlen, cp);
	  }
	} else {
	  if (!multilinereplies) {
	    type(SS,553,m571,"For MAIL FROM address <%.*s> access is denied by the policy analysis functions.", addrlen, cp);
	  } else {
	    type(SS, -553, m571, "Access denied by the policy analysis functions.");
	    type(SS, -553, m571, "This may be due to your source IP address,");
	    type(SS, -553, m571, "the IP reversal domain, the data you gave for");
	    type(SS, -553, m571, "the HELO/EHLO parameter, or address/domain you");
	    type(SS,  553, m571, "gave at the MAIL FROM:<%.*s> address.",
		 addrlen, cp);
	  }
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
	    smtp_tarpit(SS);
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
	smtp_tarpit(SS);
	type(SS, 452, m430, (char *) NULL);
	if (newcp)
	    free((void *) newcp);
	return;
    }
    fflush(SS->mfp);
    rewind(SS->mfp);
#ifdef HAVE_FTRUNCATE
    while (ftruncate(FILENO(SS->mfp), 0) < 0)
      if (errno != EINTR && errno != EAGAIN)
	break;
#endif
    if (insecure)
	fprintf(SS->mfp, "external\n");

    if (netconnected_flg) {

      /* Produce the 'rcvdfrom' header only when connected
	 to network socket */

      fprintf(SS->mfp, "rcvdfrom %.200s (", SS->rhostname);
      if (SS->ihostaddr[0] != 0)
	fprintf(SS->mfp, "%s:%d ", SS->ihostaddr, SS->rport);
      rfc822commentprint(SS->mfp, SS->helobuf);

      if (ident_flag && log_rcvd_ident) {
	fprintf(SS->mfp, " ident: ");
	rfc822commentprint(SS->mfp, SS->ident_username);
      }
#ifdef HAVE_WHOSON_H
      if (log_rcvd_whoson && do_whoson) {
	fprintf(SS->mfp, " whoson: ");
	rfc822commentprint(SS->mfp,
			   ((SS->whoson_result == 0) ? SS->whoson_data :
			    ((SS->whoson_result == 1) ? "-unregistered-" : 
			     "-unavailable-")));
      }
#endif
      if (log_rcvd_authuser) {
	fprintf(SS->mfp, " smtp-auth: ");
	if (SS->authuser) {
	  rfc822commentprint(SS->mfp,SS->authuser);
	} else {
	  fprintf(SS->mfp, "<none>");
	}
      }
      if (SS->sslmode) {
	if (log_rcvd_tls_mode) {
	  fprintf(SS->mfp, " TLS-CIPHER: ");
	  if (SS->tls_cipher_info)
	    rfc822commentprint(SS->mfp, SS->tls_cipher_info);
	  else
	    fprintf(SS->mfp, "<none>");
	}
	if (log_rcvd_tls_peer) {
	  fprintf(SS->mfp, " TLS-PEER: ");
	  if (SS->tls_peer_subject)
	    rfc822commentprint(SS->mfp, SS->tls_peer_subject);
	  else
	    fprintf(SS->mfp, "<none>");
	}
      } else {
	if (log_rcvd_tls_mode)
	  fprintf(SS->mfp, " TLS-CIPHER: <none>");
	if (log_rcvd_tls_peer)
	  fprintf(SS->mfp, " TLS-PEER: <none>");
      }
      fprintf(SS->mfp, ")\n");

      /* COMMENT SECTION GETTING IT ALL IN EVERY CASE! */

      fprintf(SS->mfp, "comment %s ", SS->rhostname);
      if (SS->ihostaddr[0] != 0)
	fprintf(SS->mfp, "%s:%d ", SS->ihostaddr, SS->rport);
      rfc822commentprint(SS->mfp, SS->helobuf);

#ifdef HAVE_WHOSON_H
      if (do_whoson) {
	fprintf(SS->mfp, " whoson: ");
	rfc822commentprint(SS->mfp,
			   ((SS->whoson_result == 0) ? SS->whoson_data :
			    ((SS->whoson_result == 1) ? "-unregistered-" : 
			     "-unavailable-")));
      }
#endif
      fprintf(SS->mfp, " smtp-auth: ");
      if (SS->authuser) {
	rfc822commentprint(SS->mfp,SS->authuser);
      } else {
	fprintf(SS->mfp, "<none>");
      }
      if (SS->sslmode) {
	fprintf(SS->mfp, " TLS-CIPHER: ");
	if (SS->tls_cipher_info)
	  rfc822commentprint(SS->mfp, SS->tls_cipher_info);
	else
	  fprintf(SS->mfp, "<none>");

	fprintf(SS->mfp, " TLS-PEER: ");
	if (SS->tls_peer_subject)
	  rfc822commentprint(SS->mfp, SS->tls_peer_subject);
	else
	  fprintf(SS->mfp, "<none>");
      } else {
	fprintf(SS->mfp, " TLS-CIPHER: <none>");
	fprintf(SS->mfp, " TLS-PEER: <none>");
      }
      fprintf(SS->mfp, ")\n");

    }

    if (bodytype != NULL)
	fprintf(SS->mfp, "bodytype %s\n", bodytype);
    fprintf(SS->mfp, "with %s\n", SS->with_protocol);
    if (ident_flag)
	fprintf(SS->mfp, "identinfo %s\n", SS->ident_username);

    if (SS->smtpfrom) free((void*)SS->smtpfrom);
    SS->smtpfrom = malloc(addrlen+1);
    memcpy((void*)(SS->smtpfrom), cp, addrlen);
    *((char*)(&SS->smtpfrom[addrlen])) = 0;

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
    availspace -= minimum_availspace;

    if (ferror(SS->mfp)) {
	smtp_tarpit(SS);
	type(SS, 452, m430, (char *) NULL);
	mail_abort(SS->mfp);
	SS->mfp = NULL;
    } else if (SS->sizeoptval > maxsize && maxsize > 0) {
	smtp_tarpit(SS);
	type(SS, 552, m534, "This message is larger, than our maximum acceptable incoming message size of  %d  chars.", maxsize);
	mail_abort(SS->mfp);
	SS->mfp = NULL;
    } else if (SS->sizeoptval > availspace) {
	smtp_tarpit(SS);
	type(SS, 452, m431, "Try again later, insufficient storage available at the moment");
	mail_abort(SS->mfp);
	SS->mfp = NULL;
    } else {
	if (s) {
	    int rrc = atoi(s);
	    if (rrc >= 400) {
	      smtp_tarpit(SS);
	      mail_abort(SS->mfp);
	      SS->mfp = NULL;
	    }
	    type(SS, rrc, s + 4, "Ok");
	} else
	    type(SS, 250, "2.1.0", "Sender syntax Ok%s", srcrtestatus);
	SS->sender_ok = 1;
    }
    if (s)
	free((void *) s);

    if (SS->mfp) /* State change only, if we still have the mfp */
      SS->state = Recipient;

    SS->rcpt_count = 0;
    SS->ok_rcpt_count = 0;
    SS->from_box = (addrlen == 0);
}


void smtp_rcpt(SS, buf, cp)
SmtpState *SS;
const char *buf, *cp;
{
    const char *s;
    const char *drpt_notify, *drpt_orcpt;
    const char *newcp = NULL;
    const char *srcrtestatus = "";
    int addrlen = 0, notifylen = 0, orcptlen = 0, notifyflgs;
    int strict = STYLE(SS->cfinfo, 'R');
    int sloppy = STYLE(SS->cfinfo, 'S');
    int err;

    if (strict && sloppy) /* If misconfigured, SLOPPY takes precedence! */
      strict = 0;

    /* some smtp clients don't get the 503 right and try again, so
       tell the spammers exactly what's happening. */
    if ( (SS->state == MailOrHello || SS->state == Mail) &&
	 policydb != NULL && SS->policyresult < 0 ) {
      smtp_tarpit(SS);
      if (!multilinereplies)
	type(SS, 550, m571, "Access denied by the policy analysis functions by earlier rejection");
      else {
	type(SS, -550, m571, "Access denied by the policy analysis functions.");
	type(SS, -550, m571, "This may be due to your source IP address,");
	type(SS, -550, m571, "the IP reversal domain, the data you gave for");
	type(SS, -550, m571, "the HELO/EHLO parameter, or address/domain");
	type(SS,  550, m571, "you gave at the MAIL FROM:<...> address.");
      }
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
	smtp_tarpit(SS);
	type(SS, 503, m551, cp);
	return;
    }

    if (*cp == ' ') ++cp;
    if (!strict_protocol) while (*cp == ' ' || *cp == '\t') ++cp;

    if (!CISTREQN(cp, "To:", 3)) {
	smtp_tarpit(SS);
	type(SS, 501, m552, "where is To: in this?  %s", cp);
	return;
    }
    cp += 3;
    if (!strict_protocol || sloppy)
      for (; *cp != '\0' && *cp != '<'; ++cp)
	if (!isspace(*cp)) {
	  if (!sloppy) {
	    smtp_tarpit(SS);
	    type(SS, 501, m513, "where is <...> in this?  %s", cp);
	    return;
	  }
	  break; /* Sigh, be sloppy.. */
	}
    if (*cp == '\0') {
	smtp_tarpit(SS);
	type(SS, 501, m513, "where is <...> in this?  %s", cp);
	return;
    } else if (*cp != '<' && !sloppy) {
	smtp_tarpit(SS);
	type(SS, 501, m513, "strangeness between ':' and '<': %s", cp);
	return;
    } else if (*(cp+1) == '>') {
	smtp_tarpit(SS);
	type(SS, 501, m513, "Null address valid only as source: %s", cp);
	return;
    }
    if (*(cp + 1) == '<') {
	smtp_tarpit(SS);
	type(SS, 501, m513, "there are too many <'s in this: %s", cp);
	return;
    }
    if (*cp == '<') {
      /* "<" [ <a-t-l> ":" ] <localpart> "@" <domain> ">" */
      s = rfc821_path(cp, strict || strict_protocol);
      if (!sloppy) {
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
	  smtp_tarpit(SS);
	  type(SS, 501, m513, "there are too many >'s in this: %s", cp);
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
      } else { /* Sloppy processing */
	/* Sigh, lets try recovery... */
	++cp;
	while (*cp == ' ' || *cp == '\t') ++cp;
	s = rfc821_path2(cp, 0);
	if (s == cp) {
	  /* Failure.. ? */
	  type821err(SS, 501, m517, buf, "Path data: %.200s", rfc821_error);
	  return;
	}
	/* Now it is a moment to see, if we have source routes: @a,@b:c@d */
	if (*cp == '@') {
	  /* Yup, Starting with an "@" ..  scan until ":", which must be
	     in there as this is valid RFC-821 object. */
	  if (!allow_source_route) {
	    while (*cp != ':') ++cp; 
	    if (*cp == ':') ++cp; /* Should be ALWAYS */
	    srcrtestatus = ", source route ignored";
	  }
	}
	addrlen = s - cp;
	while (*s == ' ' || *s == '\t') ++s;
	if (*s != '>') {
	  rfc821_error_ptr = s;
	  type821err(SS, 501, m517, buf, "Missing ending '>' bracket: %s", cp);
	  return;
	}
	++s;
      }
    } else {
      /* We can be here only with non-strict mode (i.e. Sloppy..) */

      s = rfc821_path2(cp, strict || strict_protocol);
      if (s == cp) {
	/* Failure.. */
	type821err(SS, 501, m513, buf, "Path data: %.200s", rfc821_error);
	return;
      }

      if (*s == '>') {
	smtp_tarpit(SS);
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
	smtp_tarpit(SS);
	type(SS, 501, m513, "What is an empty recipient?");
	return;
    }
    drpt_notify = NULL;
    notifyflgs  = 0;
    drpt_orcpt = NULL;

    while (*s) {
	while (*s == ' ' || (sloppy && *s == '\t')) {
	    ++s;
	    if (strict_protocol) break;
	    if (strict && !sloppy) break;
	}
	/* IETF-NOTARY  SMTP-DSN extensions */

#define NOTIFY_SUCCESS 1
#define NOTIFY_FAILURE 2
#define NOTIFY_DELAY   4
#define NOTIFY_NEVER   8

	if (dsn_ok && CISTREQN("NOTIFY=", s, 7)) {
	    if (drpt_notify) {
		smtp_tarpit(SS);
		type(SS, 501, m554, "NOTIFY-param double defined!");
		return;
	    }
	    drpt_notify = s;
	    s += 7;
	    while (*s) {
		if (CISTREQN("SUCCESS", s, 7))
		    s += 7, notifyflgs |= NOTIFY_SUCCESS;
		else if (CISTREQN("FAILURE", s, 7))
		    s += 7, notifyflgs |= NOTIFY_FAILURE;
		else if (CISTREQN("DELAY", s, 5))
		    s += 5, notifyflgs |= NOTIFY_DELAY;
		else if (CISTREQN("NEVER", s, 5))
		    s += 5, notifyflgs |= NOTIFY_NEVER;
		if (*s != ',')
		    break;
		++s;
	    }
	    if (*s && *s != ' ' && *s != '\t') {
		smtp_tarpit(SS);
		type(SS, 455, m454, "NOTIFY-param data error");
		return;
	    }
	    notifylen = s - drpt_notify;
	    continue;
	}
	if (dsn_ok && CISTREQN("ORCPT=", s, 6)) {
	    if (drpt_orcpt) {
		smtp_tarpit(SS);
		type(SS, 501, m554, "ORCPT-param double defined!");
		return;
	    }
	    drpt_orcpt = s;
	    s = orcpt_string(s + 6);
	    if (s == NULL) {
		smtp_tarpit(SS);
		type821err(SS, -501, m454, buf, "Invalid ORCPT value '%s'", drpt_orcpt);
		type(SS, 501, m454, "ORCPT-param data error!");
		return;
	    }
	    orcptlen = s - drpt_orcpt;
	    continue;
	}
	smtp_tarpit(SS);
	type(SS, 555, m554, "Unknown RCPT TO:<> parameter: %s", s);
	return;
    }

    if (SS->rcpt_count >= rcptlimitcnt) {
      smtp_tarpit(SS);
      type(SS, 452, "4.5.2", "Too many recipients in one go!");
      return;
    }

    RFC821_822QUOTE(cp, newcp, addrlen);

    if (debug) typeflush(SS);
    SS->policyresult = policytest(policydb, &SS->policystate,
				  POLICY_RCPTTO, cp, addrlen,
				  SS->authuser);
    if (logfp || logfp_to_syslog) {
      char *ss = policymsg(policydb, &SS->policystate);
      if (SS->policyresult != 0 || ss != NULL) {
	type(NULL,0,NULL,"-- policy result=%d, msg: %s",
	     SS->policyresult, (ss ? ss : "<NONE!>"));
	if (logfp)
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
	    int rc;
	    if (debug) typeflush(SS);
	    rc = policytest(policydb, &SS->policystate,
			    POLICY_RCPTPOSTMASTER, cp, addrlen,
			    SS->authuser);
	    if (rc == 0)
	      SS->policyresult = 0;

	    if (logfp || logfp_to_syslog) {
	      char *ss = policymsg(policydb, &SS->policystate);
	      if (SS->policyresult != 0 || ss != NULL) {
		type(NULL,0,NULL,"-- policy result=%d, msg: %s",
		     SS->policyresult, (ss ? ss : "<NONE!>"));
		if (logfp)
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

	smtp_tarpit(SS);

	if (SS->policyresult < -99) { /* "soft error, 4XX code */
	  if (ss != NULL) {
	    type(SS, 450, m471, "For recipient address <%.*s> the policy analysis reported: %s", addrlen, cp, ss);
	  } else if (SS->policyresult < -103) { /* -104 */
	    if (!multilinereplies)
	      type(SS, 450, m443, "Policy analysis reports temporary DNS error with the target domain: <%.*s>", addrlen, cp);
	    else {
	      type(SS, -450, m443, "Policy analysis reports temporary DNS error");
	      type(SS, -450, m443, "with this target domain. Retrying may help,");
	      type(SS, -450, m443, "or if the condition persists, some further");
	      type(SS, -450, m443, "work may be in need with the target domain");
	      type(SS,  450, m443, "DNS servers; RCPT TO:<%.*s>", addrlen, cp);
	    }

	  } else if (SS->policyresult < -102) {
	    /* Code: -103 */
	    if (!multilinereplies) {
	      type(SS,450, m471, "This target address is not our MX service client: <%.*s>", addrlen, cp);
	    } else {
	      type(SS,-450, m471, "This target address is not our MX service");
	      type(SS,-450, m471, "client, nor you are connecting from address");
	      type(SS,-450, m471, "that is allowed to openly use us to relay");
	      type(SS,-450, m471, "to any arbitrary address thru us.");
	      type(SS, 450, m471, "We don't accept this recipient: <%.*s>",
		   addrlen, cp);
	    }
	  } else if (SS->policyresult < -100) {
	    /* Code: -102 */
	    if (!multilinereplies)
	      type(SS, 450, m443, "Policy analysis found DNS error on the target address: <%.*s>", addrlen, cp);
	    else {
	      type(SS,-450, m443, "Policy analysis found DNS error on");
	      type(SS,-450, m443, "the target address. This address is");
	      type(SS, 450, m443, "not currently acceptable: <%.*s>",
		   addrlen, cp);
	    }
	  } else {
	    type(SS,450,m443, "Policy rejection on the target address: <%.*s>",
		 addrlen, cp);
	  }
	} else {
	  if (ss != NULL) {
	    type(SS, 550, m571, "Policy analysis reported: %s rcpt=<%.*s>",
		 ss, addrlen, cp);
	  } else if (SS->policyresult < -2) {
	    /* Code: -3 */
	    if (!multilinereplies)
	      type(SS,550,m571, "This target address is not our MX service client: <%.*s>", addrlen, cp);
	    else {
	      type(SS,-550, m571, "This target address is not our MX service");
	      type(SS,-550, m571, "client, nor you are connecting from address");
	      type(SS,-550, m571, "that is allowed to openly use us to relay");
	      type(SS,-550, m571, "to any arbitrary address thru us.");
	      type(SS, 550, m571, "We don't accept this recipient: <%.*s>",
		   addrlen, cp);
	    }

	  } else if (SS->policyresult < -1) {
	    /* Code: -2 */
	    if (!multilinereplies) {
	      type(SS,550,m543, "Policy analysis found DNS error on the target domain: <%.*s>", addrlen, cp);
	    } else {
	      type(SS,-550, m543, "Policy analysis found DNS error on");
	      type(SS,-550, m543, "the target address. This address is");
	      type(SS, 550, m543, "not currently acceptable: <%.*s>",
		   addrlen, cp);
	    }
	  } else {
	    type(SS,550,m571, "Policy rejection on the target address: <%.*s>",
		 addrlen, cp);
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
	    smtp_tarpit(SS);
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
	fputc(' ', SS->mfp);
	fwrite(drpt_notify, 1, notifylen, SS->mfp);
	if (!(notifyflgs & NOTIFY_NEVER) /* Not 'NEVER' */ &&
	    !(notifyflgs & NOTIFY_DELAY) /* Not 'DELAY' */ &&
	    (SS->deliverby_flags & DELIVERBY_N) /* 'N' mode */)
	  /* RFC 2852: 4.1.4.2: */
	  fwrite(",DELAY", 1, 6, SS->mfp);
	if (SS->deliverby_flags & DELIVERBY_T)
	  fwrite(",TRACE", 1, 6, SS->mfp);
    } else {
	fprintf(SS->mfp, " NOTIFY=FAILURE,DELAY");
	if (SS->deliverby_flags & DELIVERBY_T)
	  fwrite(",TRACE", 1, 6, SS->mfp);
    }
    if (SS->deliverby_time) {
      fprintf(SS->mfp, " BY=%ld;", SS->deliverby_time);
      if (SS->deliverby_flags & DELIVERBY_R)
	fputc('R', SS->mfp);
      if (SS->deliverby_flags & DELIVERBY_N)
	fputc('N', SS->mfp);
      if (SS->deliverby_flags & DELIVERBY_T)
	fputc('T', SS->mfp);
    }
    if (drpt_orcpt) {
	fputc(' ', SS->mfp);
	fwrite(drpt_orcpt, 1, orcptlen, SS->mfp);
    } else {
	const char *p = cp;
	const char *ep = cp + addrlen;
	fputs(" ORCPT=rfc822;", SS->mfp);
	while (*p && p < ep) {
	    char c = (*p) & 0xFF;
	    if ('!' <= c && c <= '~' && c != '+' && c != '=')
		fputc(c, SS->mfp);
	    else
		fprintf(SS->mfp, "+%02X", c);
	    ++p;
	}
    }
    { /* Our received inbound RCPT value */
	const char *p = cp;
	const char *ep = cp + addrlen;
	fputs(" INRCPT=rfc822;", SS->mfp);
	while (*p && p < ep) {
	    char c = (*p) & 0xFF;
	    if ('!' <= c && c <= '~' && c != '+' && c != '=')
		fputc(c, SS->mfp);
	    else
		fprintf(SS->mfp, "+%02X", c);
	    ++p;
	}

	fputs(" INFROM=rfc822;", SS->mfp);
	p = SS->smtpfrom;
	while (*p) {
	    char c = (*p) & 0xFF;
	    if ('!' <= c && c <= '~' && c != '+' && c != '=')
		fputc(c, SS->mfp);
	    else
		fprintf(SS->mfp, "+%02X", c);
	    ++p;
	}
    }
    fputc('\n', SS->mfp);

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

    if (sum_sizeoption_value)
      SS->sizeoptsum += SS->sizeoptval;
    else
      SS->sizeoptsum = SS->sizeoptval;

    err = 1;
    SS->rcpt_count += 1;

    if (ferror(SS->mfp)) {
	smtp_tarpit(SS);
	type(SS, 452, m430, (char *) NULL);
    } else if (maxsize > 0 && SS->sizeoptval > maxsize) {
	smtp_tarpit(SS);
	type(SS, 552, m534, "Message size exceeds fixed maximum size of %ld chars for acceptable email; rcpt=<%.*s>", maxsize, addrlen, cp);
    } else if (SS->sizeoptsum > availspace) {
	smtp_tarpit(SS);
	type(SS, 452, m431, "insufficient storage space, try again later");
    } else if (s) {
	if (SS->from_box && SS->rcpt_count > MaxErrorRecipients) {
	    smtp_tarpit(SS);
	    type(SS, 552, m571, "SPAM trap -- too many recipients for an empty source address!");
	} else {
	    err = atoi(s);
	    type(SS, err, "%s", s + 4);
	    if (err < 400)
	      err = 0;
	}
    } else {
	if (SS->from_box && SS->rcpt_count > MaxErrorRecipients) {
	    smtp_tarpit(SS);
	    type(SS, 552, m571, "SPAM trap -- too many recipients for an empty source address!");
	} else if (SS->sizeoptval)
	    type(SS, 250, "2.1.5", "Ok; can accomodate %d byte message%s for <%.*s>",
		 SS->sizeoptval, srcrtestatus, addrlen, cp);
	else
	    type(SS, 250, "2.1.5", "Recipient address syntax Ok%s; rcpt=<%.*s>",
		 srcrtestatus, addrlen, cp);
	err = 0;
    }
    if (s)
	free((void *) s);

    if (!err) {
      SS->ok_rcpt_count += 1;
      SS->state = RecipientOrData;
    }
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

#if 0				/* The input string is ARBITRARY STRING (shudder..) */
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
#if 0				/* The input string is an arbitrary string! */
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
