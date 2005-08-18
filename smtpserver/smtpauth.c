/*
 *  ZMailer smtpserver,  AUTH command things (RFC 2554, sort of);
 *  part of ZMailer.
 *
 *  by Matti Aarnio <mea@nic.funet.fi> 1999,2002,2003,2005
 *
 *  The basis of SASL[2] code is from Sendmail 8.12.3
 *
 */

#include "smtpserver.h"

int SASLSecOpts;
const char *SASL_Auth_Mechanisms;


/* "AUTH LOGIN" command per
   http://help.netscape.com/products/server/messaging/3x/info/smtpauth.html

Authenticated SMTP

When the client submits a message to the server using SMTP, the server
supports an SMTP Service Extension for Authentication (SMTP Authentication),
as proposed by John Myers as part of the Simple Authentication and Security
Layer [SASL].  Specifically, the Netscape Messaging products support the
"AUTH LOGIN" extension, which uses a base64 encoding of username and password.
While this is a very simplistic authentication method that is little better
than cleartext passwords, it is supported by a number of other messaging
programs (including Sun's Solstice IMAP products, the UW IMAP server,
NetManage's IMAP client, Sun's java IMAP client.)  In future messaging
products, Netscape plans to support stronger authentication methods such
as pklogin. 

Here is a sample of the dialog between client and server: 

    S: 220 jimi-hendrix.mcom.com ESMTP server (Netscape Messaging Server - Version 3.0) ready Fri, 2 May 1997 09:38:41 -0700 
    C: ehlo jimi 
    S: 250-jimi-hendrix.mcom.com 
    S: 250-HELP 
    S: 250-ETRN 
    S: 250-PIPELINING 
    S: 250-DSN 
    S: 250 AUTH=LOGIN 
    C: auth login 
    S: 334 VXNlcm5hbWU6                  base64 "Username:" 
    C: bXluYW1l                          base64 "myname" 
    S: 334 Uc2VjcmV0                     base64 "Password:" 
    C: GFzc3dvcmQ6                       base64 "secret" 
    S: 235 Authentication successful

For server exchanges at this point, the sending server (C:) would put: 

    C: MAIL FROM: <mymailaddress> AUTH=<mymailaddress>

and receiving server (S:) would reply with: 

    S: 250 Sender <mymailaddress> and extensions (AUTH=<mymailaddress>) Ok

*/

extern char * zpwmatch __((char *, char *, long *uidp));
extern char * pipezpwmatch __((char *, char *, char *, long *uidp));

#if 0 /* DUMMY BEAST... */

/* This is *NOT* universal password matcher!
   Consider Shadow passwords, PAM systems, etc.. */

#include <pwd.h>
#include <unistd.h>

/* Return NULL for OK, and error text for failure */

char * zpwmatch(uname,password,uidp)
     char *uname, *password;
     long *uidp;
{
	struct Zpasswd *pw = zgetpwnam(uname); /* ... */
	char *cr;

	if (!pw) return -1; /* No such user */
	cr = crypt(password, pw->pw_passwd);
	*uidp = pw->pw_uid;

	return (strcmp(cr, pw->pw_passwd) == 0) ? NULL : "Authentication Failure";
}
#endif

#ifdef HAVE_SASL2
/*
**  ITEMINLIST -- does item appear in list?
**
**	Check whether item appears in list (which must be separated by a
**	character in delim) as a "word", i.e. it must appear at the begin
**	of the list or after a space, and it must end with a space or the
**	end of the list.
**
**	Parameters:
**		item -- item to search.
**		list -- list of items.
**		delim -- list of delimiters.
**
**	Returns:
**		pointer to occurrence (NULL if not found).
*/

static const char * iteminlist __((const char *, const char *, const char *));
static const char *
iteminlist(item, list, delim)
	const char *item;
	const char *list;
	const char *delim;
{
	const char *s;
	int len;

	if (list == NULL || *list == '\0')
		return NULL;
	if (item == NULL || *item == '\0')
		return NULL;
	s = list;
	len = strlen(item);
	while (s != NULL && *s != '\0')
	{
		if (strncasecmp(s, item, len) == 0 &&
		    (s[len] == '\0' || strchr(delim, s[len]) != NULL))
			return s;
		s = strpbrk(s, delim);
		if (s != NULL)
			while (*++s == ' ')
				continue;
	}
	return NULL;
}

/*
**  INTERSECT -- create the intersection between two lists
**
**	Parameters:
**		s1, s2 -- lists of items (separated by single blanks).
**		rpool -- resource pool from which result is allocated.
**
**	Returns:
**		the intersection of both lists.
*/


static const char * intersect __((const char *, const char *));
static const char *
intersect(s1, s2)
	const char *s1, *s2;
{
	char *hr, *h1, *h, *res;
	int l1, l2, rl;

	if (s1 == NULL || s2 == NULL)	/* NULL string(s) -> NULL result */
		return NULL;
	l1 = strlen(s1);
	l2 = strlen(s2);
	rl = (l1 < l2 ? l1 : l2);
	res = (char *) malloc(rl + 1);
	if (res == NULL)
		return NULL;
	*res = '\0';
	if (rl == 0)	/* at least one string empty? */
		return res;
	hr = res;
	h1 = (char *) s1;
	h  = (char *) s1;

	/* walk through s1 */
	while (h != NULL && *h1 != '\0')
	{
		/* is there something after the current word? */
		if ((h = strchr(h1, ' ')) != NULL)
			*h = '\0';
		l1 = strlen(h1);

		/* does the current word appear in s2 ? */
		if (iteminlist(h1, s2, " ") != NULL)
		{
			/* add a blank if not first item */
			if (hr != res)
				*hr++ = ' ';

			/* copy the item */
			memcpy(hr, h1, l1);

			/* advance pointer in result list */
			hr += l1;
			*hr = '\0';
		}
		if (h != NULL)
		{
			/* there are more items */
			*h = ' ';
			h1 = h + 1;
		}
	}
	return res;
}
#endif


void smtp_auth(SS,buf,cp)
     SmtpState * SS;
     const char *buf;
     const char *cp;
{
	char abuf[SMTPLINESIZE];	/* limits size of SMTP commands...
					   On the other hand, limit is asked
					   to be only 1000 chars, not 8k.. */
	char bbuf[SMTPLINESIZE];

	char c, co;
	int i, rc;
	char *uname = NULL;
	long uid;
	char *zpw;

	if (OCP->no_smtp_auth_on_25 &&
	    (SS->with_protocol_set & WITH_SMTP)) {
	  smtp_tarpit(SS); /* Double tarpit.. */
	  smtp_tarpit(SS);
	  type(SS, 503, m551, "Hi %s, AUTH NOT SUPPORTED AT PORT 25!", SS->rhostaddr);
	  return;
	}

	rc = policytest(&SS->policystate, POLICY_AUTHFAIL,
			uname, 0, SS->authuser);
	if (rc < 0) {
	  smtp_tarpit(SS);
	  type(SS, 503, m551, "Hi %s, Too many authentication failures from your IP this hour..", SS->rhostaddr);
	  return;
	}

	if (SS->state == Hello) {
	  policytest(&SS->policystate, POLICY_AUTHFAIL,
		     uname, 1, SS->authuser);
	  smtp_tarpit(SS);
	  type(SS, 503, m551, "Hi %s, EHLO first, then - perhaps - AUTH!", SS->rhostaddr);
	  return;
	}
	if (SS->state != MailOrHello && SS->state != Mail) {
	  policytest(&SS->policystate, POLICY_AUTHFAIL,
		     uname, 1, SS->authuser);
	  smtp_tarpit(SS);
	  type(SS, 503, m551, "Hi %s, AUTH not allowed during MAIL transaction!", SS->rhostaddr);
	  return;
	}
	if (SS->authuser) {
	  policytest(&SS->policystate, POLICY_AUTHFAIL,
		     uname, 1, SS->authuser);
	  smtp_tarpit(SS);
	  type(SS, 503, m551, "Hello %s, already authenticated, second attempt rejected!",SS->rhostaddr);
	  return;
	}

	if (*cp == ' ') ++cp;
	if (strict_protocol < 1)
	  while (*cp == ' ' || *cp == '\t') ++cp;

#ifdef HAVE_SASL2
	if (!OCP->do_sasl)
#endif
	  {
	    if (!CISTREQN(cp, "LOGIN", 5)) {
	      policytest(&SS->policystate, POLICY_AUTHFAIL,
			 uname, 1, SS->authuser);
	      smtp_tarpit(SS);
	      type(SS, 504, m571, "Hello %s, Only 'AUTH LOGIN' supported.", SS->rhostaddr);
	      return;
	    }

#ifdef HAVE_OPENSSL
	    if (!OCP->auth_login_without_tls && !SS->sslmode) {
	      policytest(&SS->policystate, POLICY_AUTHFAIL,
			 uname, 1, SS->authuser);
	      smtp_tarpit(SS);
	      type(SS, 503, m571,
		   "Hello %s, Plaintext password authentication must be run under SSL/TLS", SS->rhostaddr);
	      return;
	    }
#endif /* - HAVE_OPENSSL */
#ifndef HAVE_OPENSSL
	    if (!OCP->auth_login_without_tls) {
	      policytest(&SS->policystate, POLICY_AUTHFAIL,
			 uname, 1, SS->authuser);
	      smtp_tarpit(SS);
	      type(SS, 503, m571,
		   "Hello %s, Plaintext password authentication is not enabled in this system",
		   SS->rhostaddr);
	      return;
	    }
#endif /* --HAVE_OPENSSL */

	    cp += 5;
	    if (*cp == ' ') ++cp;
	    if (strict_protocol < 1)
	      while (*cp == ' ' || *cp == '\t') ++cp;

	    uname = NULL;
	    
	    if (*cp != 0) {

	      const char *ccp;
	      rc = decodebase64string(cp, strlen(cp), bbuf, sizeof(bbuf), &ccp);
	      bbuf[sizeof(bbuf)-1] = 0;
	      if (debug)
		type(SS, 0, NULL, "-> %s", bbuf);

	      if (*ccp != 0) {
		policytest(&SS->policystate, POLICY_AUTHFAIL,
			   uname, 1, SS->authuser);
		smtp_tarpit(SS);
		type(SS, 501, m552, "unrecognized input/extra junk ??");
		return;
	      }

	      uname = strdup(bbuf);

	    } else {
	      
	      if (!OCP->smtp_auth_username_prompt)
		OCP->smtp_auth_username_prompt = "Username:";

	      i = encodebase64string(OCP->smtp_auth_username_prompt,
				     strlen(OCP->smtp_auth_username_prompt),
				     abuf, sizeof(abuf));
	      if (i >= sizeof(abuf)) i = sizeof(abuf)-1;
	      abuf[i] = 0;
	      type(SS, 334, NULL, "%s", abuf);
	      
	      i = s_gets(SS, abuf, sizeof(abuf), &rc, &co, &c );
	      abuf[sizeof(abuf)-1] = 0;

	      if (logfp_to_syslog || logfp) time( & now );

	      if (logfp_to_syslog)
		zsyslog((LOG_DEBUG, "%s%04d r %s", logtag, (int)(now - logtagepoch), abuf));

	      if (logfp != NULL) {
		fprintf(logfp, "%s%04dr\t%s\n", logtag, (int)(now - logtagepoch), abuf);
		fflush(logfp);
	      }
	      if (i == 0) {	/* EOF ??? */
		type(SS, 501, NULL, "Err... Seen EOF during AUTH ??");
		return;
	      }
	      if (strcmp(abuf, "*") == 0) {
		policytest(&SS->policystate, POLICY_AUTHFAIL,
			   uname, 1, SS->authuser);
		smtp_tarpit(SS);
		type(SS, 501, NULL, "AUTH command cancelled");
		return;
	      }
	      rc = decodebase64string(abuf, i, bbuf, sizeof(bbuf), NULL);
	      bbuf[sizeof(bbuf)-1] = 0;
	      if (debug)
		type(SS, 0, NULL, "-> %s", bbuf);
	      uname = strdup(bbuf);
	    }

	    if (!OCP->smtp_auth_password_prompt)
	      OCP->smtp_auth_password_prompt = "Password:";
	    i = encodebase64string(OCP->smtp_auth_password_prompt,
				   strlen(OCP->smtp_auth_password_prompt),
				   abuf, sizeof(abuf));
	    if (i >= sizeof(abuf)) i = sizeof(abuf)-1;
	    abuf[i] = 0;
	    type(SS, 334, NULL, "%s", abuf);

	    i = s_gets(SS, abuf, sizeof(abuf), &rc, &co, &c );
	    abuf[sizeof(abuf)-1] = 0;
      
	    if (logfp_to_syslog || logfp) time( & now );

#if 0
	    /* This logs encoded password, usually that is *not* desired */
      
	    if (logfp_to_syslog)
	      zsyslog((LOG_DEBUG, "%s%04d r %s", logtag, (int)(now - logtagepoch), abuf));

	    if (logfp != NULL) {
	      fprintf(logfp, "%s%04dr\t%s\n", logtag, (int)(now - logtagepoch), abuf);
	      fflush(logfp);
	    }
#else
	    if (logfp_to_syslog)
	      zsyslog((LOG_DEBUG, "%s%04d r **base64-password**",
		       logtag, (int)(now - logtagepoch) ));

	    if (logfp != NULL) {
	      fprintf(logfp, "%s%04dr\t**base64-password**\n",
		      logtag, (int)(now - logtagepoch) );
	      fflush(logfp);
	    }
#endif
	    if (i == 0)	{ /* EOF ??? */
	      if (uname) free(uname);
	      type(SS, 501, NULL, "Err... Seen EOF during AUTH ??");
	      return;
	    }
	    if (strcmp(abuf, "*") == 0) {
	      if (uname) free(uname);
	      policytest(&SS->policystate, POLICY_AUTHFAIL,
			 uname, 1, SS->authuser);
	      smtp_tarpit(SS);
	      type(SS, 501, NULL, "AUTH command cancelled");
	      return;
	    }

	    rc = decodebase64string(abuf, i, bbuf, sizeof(bbuf), NULL);
	    bbuf[sizeof(bbuf)-1] = 0;
	    if (debug)
	      type(SS, 0, NULL, "-> %s", bbuf);

	    if (OCP->tls_loglevel > 3) {
	      /* The TLS debugging dump does reveal arrived frame
		 data content as is, so it tells also the password.. */
	      type(NULL,0,NULL,"zpwmatch: user '%s' password '%s'", uname, bbuf);
	    } else if (OCP->tls_loglevel > 0)
	      type(NULL,0,NULL,"zpwmatch: user '%s' (password: *not so easy*!)", uname);
	    
	    if (OCP->smtpauth_via_pipe)
	      zpw = pipezpwmatch(OCP->smtpauth_via_pipe, uname, bbuf, &uid);
	    else
	      zpw = zpwmatch(uname, bbuf, &uid);

	    if (zpw == NULL) {
	      SS->authuser = uname;
	      type(SS, 235, NULL, "Authentication successful.");
	      SS->with_protocol_set |= WITH_AUTH;
#if DO_PERL_EMBED
	      {
		int rc;
		ZSMTP_hook_set_user(SS->authuser, "login", &rc);
	      }
#endif
	    } else {
	      policytest(&SS->policystate, POLICY_AUTHFAIL,
			 uname, 1, SS->authuser);
	      smtp_tarpit(SS);
	      type(SS, 535, NULL, "%s", zpw);
	      if (uname) free(uname);
	    }
	  }

#ifdef HAVE_SASL2

	else {
	  /* Here we support CMU Cyrus-SASL-2 server side code.
	     Unlike sendmail, we keep state here by spinning around
	     where necessary.. */

#define SASL_NOT_AUTH  0
#define SASL_PROC_AUTH 1
#define SASL_IS_AUTH   2
      
	  int authenticating = SASL_PROC_AUTH;
	  int ismore = 0;
	  char *q, *in, *out, *out2;
	  int len, inlen, outlen, out2len;
	  int result;
	  char *auth_type;

	  if (SS->authuser) {
	    policytest(&SS->policystate, POLICY_AUTHFAIL,
		       uname, 1, SS->authuser);
	    smtp_tarpit(SS);
	    type(SS, 503, m551, "Hello %s, already authenticated, second attempt rejected!",SS->rhostaddr);
	    return;
	  }

	  /* make sure mechanism (p) is a valid string */
	  for (q = (char*)cp; *q != '\0' && isascii(*q); q++) {
	    if (isspace(*q)) {
	      *q = '\0';
	      while (*++q != '\0' &&
		     isascii(*q) && isspace(*q))
		continue;
	      *(q - 1) = '\0';
	      ismore = (*q != '\0');
	      break;
	    }
	  }

	  /* check whether mechanism is available */
	  if (iteminlist(cp, SS->sasl.mechlist, " ") == NULL) {
	    policytest(&SS->policystate, POLICY_AUTHFAIL,
		       uname, 1, SS->authuser);
	    smtp_tarpit(SS);
	    type(SS, 503, "5.3.3", "AUTH mechanism %.32s not available", cp);
	    return;
	  }

	  if (ismore) {
	    /* could this be shorter? XXX */
	    len = 1+strlen(q);
	    in = malloc(len);
	    result = sasl_decode64(q, len-1, in, len, &inlen);
	    if (result != SASL_OK) {
	      authenticating = SASL_NOT_AUTH;
	      free(in);
	      policytest(&SS->policystate, POLICY_AUTHFAIL,
			 uname, 1, SS->authuser);
	      smtp_tarpit(SS);
	      type(SS, 501, "5.5.4", "cannot BASE64 decode '%s'", q);
	      return;
	    }
	  } else {
	    in = NULL;
	    inlen = 0;
	  }
	  
	  auth_type = strdup(cp);

	  /* see if that auth type exists */
	  result = sasl_server_start(SS->sasl.conn, auth_type,
				     in, (unsigned) inlen,
				     (const char **) & out, (unsigned*) & outlen);

	  if (result != SASL_OK && result != SASL_CONTINUE) {

	    policytest(&SS->policystate, POLICY_AUTHFAIL,
		       uname, 1, SS->authuser);
	    if (logfp){
	      const char * e = sasl_errdetail(SS->sasl.conn);
	      if (!e) e = "<-no-detail->";
	      fprintf(logfp, "%s%04d#\tAUTH failure (%s): %s (%d) %s\n",
		      logtag, (int)(now - logtagepoch),
		      cp, sasl_errstring(result, NULL, NULL), result, e);
	      fflush(logfp);
	    }
	    smtp_tarpit(SS);
	    type(SS, 500, "5.7.0", "authentication failed");
	    return;
	  }

	  if (result == SASL_OK) {
	    /* ugly, but same code */
	    goto authenticated;
	    /* authenticated by the initial response */
	  }

	  /* len is at least 2 */
	  len = (4*outlen)/3+2;
	  out2 = malloc(len);
	  result = sasl_encode64(out, outlen, out2, len, &out2len);

	  if (result != SASL_OK) {
	    if (logfp) {
	      fprintf(logfp, "%s%d#\tAUTH encode64 error [%d for \"%s\"]\n",
		      logtag, (int)(now - logtagepoch),
		      result, out);
	      fflush(logfp);
	    }
	    policytest(&SS->policystate, POLICY_AUTHFAIL,
		       uname, 1, SS->authuser);
	    smtp_tarpit(SS);
	    type(SS, 454, "4.5.4", "Temporary authentication failure");
	    /* start over? */
	    authenticating = SASL_NOT_AUTH;
	  } else {
	    type(SS, 334, "", "%s", out2);
	    authenticating = SASL_PROC_AUTH;
	  }




	  /* Now we start spinning the SASL call state.. */

	  while (authenticating == SASL_PROC_AUTH) {

	    i = s_gets( SS, abuf, sizeof(abuf), &rc, &co, &c );
	    abuf[sizeof(abuf)-1] = 0;
	    if (i >= sizeof(abuf)) i = sizeof(abuf)-1;

	    if (logfp != NULL) {
#if 1
	      fprintf(logfp, "%s%04dr\t**user-response**  -- len=%d\n",
		      logtag, (int)(now - logtagepoch), i );
#else
	      fprintf(logfp, "%s%04dr\t%s\n",
		      logtag, (int)(now - logtagepoch), abuf );
#endif
	      fflush(logfp);
	    }

	    if (abuf[0] == '\0' || i == 0) {
	      authenticating = SASL_NOT_AUTH;
	      policytest(&SS->policystate, POLICY_AUTHFAIL,
			 uname, 1, SS->authuser);
	      smtp_tarpit(SS);
	      type(SS,  501, "5.5.2", "missing input");
	      break;
	    }

	    if (abuf[0] == '*' && abuf[1] == '\0') {
	      authenticating = SASL_NOT_AUTH;
	      
	      /* rfc 2254 4. */
	      policytest(&SS->policystate, POLICY_AUTHFAIL,
			 uname, 1, SS->authuser);
	      smtp_tarpit(SS);
	      type(SS, 501, "5.0.0", "AUTH aborted");
	      break;
	    }

	    /* could this be shorter? XXX */
	    result = sasl_decode64(abuf, i, bbuf, sizeof(bbuf), &outlen);
	    if (result != SASL_OK) {
	      authenticating = SASL_NOT_AUTH;
	      /* rfc 2254 4. */
	      policytest(&SS->policystate, POLICY_AUTHFAIL,
			 uname, 1, SS->authuser);
	      smtp_tarpit(SS);
	      type(SS, 501, "5.5.4", "cannot decode AUTH parameter %s", abuf);
	      continue;
	    }

	    result = sasl_server_step(SS->sasl.conn,  (const char *) bbuf, (unsigned) outlen,
				      (const char **) & out2, (unsigned *) & out2len );

	    /* get an OK if we're done */
	    if (result == SASL_OK) {

	    authenticated:
	      
	      type(SS, 235, m200, "OK Authenticated");
	      authenticating = SASL_IS_AUTH;
	      /* macdefine(&BlankEnvelope.e_macro, A_TEMP,
		 macid("{auth_type}"), auth_type); */
	      
	      result = sasl_getprop(SS->sasl.conn, SASL_USERNAME,
				    (const void **)&SS->authuser); 
	      /* XX: check result == SASL_OK ?? */
	      SS->with_protocol_set |= WITH_AUTH;
	      if (result == SASL_OK) {
#if DO_PERL_EMBED
		int rc;
		ZSMTP_hook_set_user(SS->authuser, "saslauth", &rc);
#endif
	      }

# if 0
	      /* get realm? */
	      sasl_getprop(SS->sasl.conn, SASL_REALM, (const void **) &data);
# endif /* 0 */
	  
	      /* get security strength (features) */
	      result = sasl_getprop(SS->sasl.conn, SASL_SSF, (const void **) &SS->sasl.ssf);
#if 0
	      if (result == SASL_OK) {
		char pbuf[8];
		(void) sm_snprintf(pbuf, sizeof pbuf, "%u", *ssf);
		macdefine(&BlankEnvelope.e_macro,
			  A_TEMP,  macid("{auth_ssf}"), pbuf);
		if (tTd(95, 8))
		  sm_dprintf("AUTH auth_ssf: %u\n", *ssf);
	      }

	      /*
	      **  Only switch to encrypted connection
	      **  if a security layer has been negotiated
	      */
	  
	      if (SS->sasl.ssf != NULL && SS->sasl.ssf[0] > 0) {
		/*
		**  Convert I/O layer to use SASL.
		**  If the call fails, the connection
		**  is aborted.
		*/
	      
		if (sfdcsasl(&InChannel, &OutChannel,
			     conn) == 0)
		  {
		    /* restart dialogue */
		    n_helo = 0;
# if PIPELINING
		    (void) sm_io_autoflush(InChannel,
					   OutChannel);
# endif /* PIPELINING */
		  }
		else
		  syserr("503 5.3.3 SASL TLS failed");
	      }
#endif
#if 0	      
	      /* NULL pointer ok since it's our function */
	      if (LogLevel > 8)
		sm_syslog(LOG_INFO, NOQID,
			  "AUTH=server, relay=%.100s, authid=%.128s, mech=%.16s, bits=%d",
			  CurSmtpClient,
			  shortenstring(user, 128),
			  auth_type, *ssf);
#endif
	    } else if (result == SASL_CONTINUE) {

	      len = (4*outlen)/3+2;
	      out2 = malloc(len);
	      result = sasl_encode64(out, outlen, out2, len, &out2len);
	      if (result != SASL_OK) {
		
		/* correct code? XXX */
		/* 454 Temp. authentication failure */
		type(SS, 454, "4.5.4", "Internal error: unable to encode64");
		policytest(&SS->policystate, POLICY_AUTHFAIL,
			   uname, 1, SS->authuser);
#if 0
		if (LogLevel > 5)
		  sm_syslog(LOG_WARNING, e->e_id,
			    "AUTH encode64 error [%d for \"%s\"]",
			    result, out);
#endif
		/* start over? */
		authenticating = SASL_NOT_AUTH;
		
	      } else {
		
		type(SS, 334, "", "%s", out2);
#if 0
		if (tTd(95, 2))
		  sm_dprintf("AUTH continue: msg='%s' len=%u\n",
			     out2, out2len);
#endif
	      }

	    } else {

	      /* not SASL_OK or SASL_CONT */
	      policytest(&SS->policystate, POLICY_AUTHFAIL,
			 uname, 1, SS->authuser);
	      smtp_tarpit(SS);
	      type(SS, 500, "5.7.0", "authentication failed");
#if 0
	      if (LogLevel > 9)
		sm_syslog(LOG_WARNING, e->e_id,
			  "AUTH failure (%s): %s (%d) %s",
			  auth_type,
			  sasl_errstring(result, NULL,
					 NULL),
			  result,
			  errstr == NULL ? "" : errstr);
#endif
	      authenticating = SASL_NOT_AUTH;
	    }
	  }

	exit_cleanup:
	  free(auth_type);
	  if (in) free(in);

	}
#endif /* HAVE_SASL2 */

}


#ifdef HAVE_SASL2
/*
**  PROXY_POLICY -- define proxy policy for AUTH
**
**	Parameters:
**		context -- unused.
**		auth_identity -- authentication identity.
**		requested_user -- authorization identity.
**		user -- allowed user (output).
**		errstr -- possible error string (output).
**
**	Returns:
**		ok?
*/

int
proxy_policy(context, auth_identity, requested_user, user, errstr)
	void *context;
	const char *auth_identity;
	const char *requested_user;
	const char **user;
	const char **errstr;
{
	if (user == NULL || auth_identity == NULL)
		return SASL_FAIL;
	*user = strdup(auth_identity);
	return SASL_OK;
}


#if 1
static sasl_callback_t srvcallbacks[] =
{
	{	SASL_CB_PROXY_POLICY,	&proxy_policy,	NULL	},
	{	SASL_CB_LIST_END,	NULL,		NULL	}
};
#else
static sasl_callback_t srvcallbacks[] =
{
	{	SASL_CB_VERIFYFILE,	&safesaslfile,	NULL	},
	{	SASL_CB_PROXY_POLICY,	&proxy_policy,	NULL	},
	{	SASL_CB_LIST_END,	NULL,		NULL	}
};
#endif

#endif /* HAVE_SASL2 */



void
smtpauth_init(SS)
     SmtpState *SS;
{
#ifdef HAVE_SASL2
      int result;

      if (OCP->do_sasl) {

	SS->sasl.n_mechs = 0;

	/* SASL server new connection */

	result = sasl_server_init(srvcallbacks, "smtpserver");
	SS->sasl.sasl_ok = (result == SASL_OK);
	if (result != SASL_OK)
	  type(NULL,0,NULL, "sasl_server_init() failed; result=%d", result);


	if (SS->sasl.sasl_ok) {
	  /* use empty realm: only works in SASL > 1.5.5 */
	  /* Will it works with SASL 2.x ? */

	  result = sasl_server_new("smtpserver",   /* service    */
				   SS->myhostname, /* serverFQDN */
				   "",   /* user_realm           */
				   NULL, /* iplocalport literal  */
				   NULL, /* ipremoteport literal */
				   NULL, /* callbacks            */
				   0,	 /* flags                */
				   &SS->sasl.conn);

	  SS->sasl.sasl_ok = (result == SASL_OK);
	  if (result != SASL_OK)
	    type(NULL,0,NULL, "sasl_server_new() failed; result=%d", result);
	}

#ifdef SASL_IP_REMOTE  /* Cyrus Sasl 1.x, only. Not in 2.x */
	if (SS->sasl.sasl_ok) {

	  /*
	  **  SASL set properties for sasl
	  **  set local/remote IP
	  **  XXX only IPv4: Cyrus SASL doesn't support anything else
	  **
	  **  XXX where exactly are these used/required?
	  **  Kerberos_v4
	  */

	  sasl_setprop(SS->sasl.conn, SASL_IP_REMOTE, &SS->raddr);
	  sasl_setprop(SS->sasl.conn, SASL_IP_LOCAL,  &SS->localsock);

	}
#endif
	SS->sasl.auth_type = NULL;
	SS->sasl.mechlist = NULL;

	/* clear sasl security properties */
	(void) memset(&SS->sasl.ssp, 0, sizeof(SS->sasl.ssp));

	/* XXX should these be options settable via .cf ? */
	/* ssp.min_ssf = 0; is default due to memset() */
# if STARTTLS
# endif /* STARTTLS */
	SS->sasl.ssp.max_ssf    = 0; /* XX: no security-strength-factor supported! */
	SS->sasl.ssp.maxbufsize = 1024; /* MAGIC! */
      }
#endif
}

void
smtpauth_ehloresponse(SS)
     SmtpState *SS;
{

	if (OCP->no_smtp_auth_on_25 &&
	    (SS->with_protocol_set & WITH_SMTP)) return;

#ifdef HAVE_SASL2
	if (OCP->do_sasl) {

	int result;

	  if (SS->sasl.sasl_ok) {
	    SS->sasl.ssp.security_flags = (SASLSecOpts & SASL_SEC_MAXIMUM);
	    if (!(OCP->auth_login_without_tls || SS->sslmode)) {
	      SS->sasl.ssp.security_flags |= SASL_SEC_NOPLAINTEXT;
	    }
	    SS->sasl.ssp.security_flags |= SASL_SEC_NOANONYMOUS;
	    
	    result = sasl_setprop(SS->sasl.conn, SASL_SEC_PROPS, &SS->sasl.ssp);
	    SS->sasl.sasl_ok = (result == SASL_OK);
	    
#if 0 /* Is in SASL-1, different/not in SASL-2 */
#ifdef SASL_SSF_EXTERNAL
	    if (SS->sasl.sasl_ok) {
	      /*
	      **  external security strength factor;
	      **	currently we have none so zero
	      */
	      
	      SS->sasl.ext_ssf.ssf = 0;
	      SS->sasl.ext_ssf.auth_id = NULL;
	      result = sasl_setprop(SS->sasl.conn, SASL_SSF_EXTERNAL, &SS->sasl.ext_ssf);
	      SS->sasl.sasl_ok = (result == SASL_OK);
	    }
#endif
#endif
	  }
	  if (SS->sasl.sasl_ok) {
	    int len, num;
	    
	    /* "user" is currently unused */
	    result = sasl_listmech(SS->sasl.conn, "user", /* XXX */
				   "", " ", "", &SS->sasl.mechlist,
				   (unsigned int *)&len, (unsigned int *)&num);
	    if (result != SASL_OK) {
	      type(NULL,0,NULL, "AUTH error: listmech=%d, num=%d", result, num);
	      num = 0;
	    }
	    if (num > 0) {
	      type(NULL,0,NULL, "AUTH: available mech=%s, allowed mech=%s",
		   SS->sasl.mechlist, 
		   SASL_Auth_Mechanisms ? SASL_Auth_Mechanisms : "<-nil->" );
	      if (SASL_Auth_Mechanisms)
		SS->sasl.mechlist = intersect( SASL_Auth_Mechanisms,
					       SS->sasl.mechlist );
	    } else {
	      SS->sasl.mechlist = NULL;	/* be paranoid... */
	      type(NULL,0,NULL, "AUTH warning: no mechanisms");
	    }
	    SS->sasl.n_mechs = num;
	  }
	  
	  if (SS->sasl.sasl_ok && (SS->sasl.n_mechs > 0) &&
	      SS->sasl.mechlist && SS->sasl.mechlist[0]) {
	    result = (NULL != strstr(SS->sasl.mechlist, "LOGIN"));
	  } else
	    result =0;

	  if (SS->sasl.sasl_ok && SS->sasl.mechlist && SS->sasl.mechlist[0]) {
	    type(SS, -250, NULL, "AUTH %s", SS->sasl.mechlist);
	    if (result) {
	      type(SS, -250, NULL, "AUTH=LOGIN"); /* RFC 2554, NetScape/
						     Sun Solstice/ ? */
	      type(SS, -250, NULL, "AUTH LOGIN"); /* RFC 2554, M$ Exchange ? */
	    }
	  } else
	    type(NULL,0,NULL, "AUTH -- no mechlist!");
	} else
#endif
	  if (OCP->auth_ok) {
	    if (OCP->auth_login_without_tls || SS->sslmode) {
	      type(SS, -250, NULL, "AUTH=LOGIN"); /* RFC 2554, NetScape/
						     Sun Solstice/ ? */
	      type(SS, -250, NULL, "AUTH LOGIN"); /* RFC 2554, M$ Exchange ? */
	    }
	  }
}
