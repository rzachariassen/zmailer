/*
 *  ZMailer smtpserver,  AUTH command things (RFC 2554, sort of);
 *  part of ZMailer.
 *
 *  by Matti Aarnio <mea@nic.funet.fi> 1999,2002,2003
 *
 *  The basis of SASL[2] code is from Sendmail 8.12.3
 *
 */

#include "smtpserver.h"

int SASLSecOpts;

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
	char *uname;
	long uid;
	char *zpw;

	if (SS->authuser != NULL) {
	  type(SS, 503, m551, "Already authenticated, second attempt rejected!");
	  return;
	}

	if (SS->state == Hello) {
	  type(SS, 503, m551, "EHLO first, then - perhaps - AUTH!");
	  return;
	}
	if (SS->state != MailOrHello && SS->state != Mail) {
	  type(SS, 503, m551, "AUTH not allowed during MAIL transaction!");
	  return;
	}

	if (*cp == ' ') ++cp;
	if (!strict_protocol) while (*cp == ' ' || *cp == '\t') ++cp;

#ifdef HAVE_SASL2
	if (!do_sasl)
#endif
	  {
	    if (!CISTREQN(cp, "LOGIN", 5)) {
	      type(SS, 504, m571, "Only 'AUTH LOGIN' supported.");
	      return;
	    }

#ifdef HAVE_OPENSSL
	    if (!auth_login_without_tls && !SS->sslmode) {
	      type(SS, 503, m571,
		   "Plaintext password authentication must be run under SSL/TLS");
	      return;
	    }
#endif /* - HAVE_OPENSSL */
#ifndef HAVE_OPENSSL
	    if (!auth_login_without_tls) {
	      type(SS, 503, m571,
		   "Plaintext password authentication is not enabled in this system");
	      return;
	    }
#endif /* --HAVE_OPENSSL */

	    cp += 5;
	    if (*cp == ' ') ++cp;
	    if (!strict_protocol) while (*cp == ' ' || *cp == '\t') ++cp;
	    
	    if (*cp != 0) {

	      const char *ccp;
	      rc = decodebase64string(cp, strlen(cp), bbuf, sizeof(bbuf), &ccp);
	      bbuf[sizeof(bbuf)-1] = 0;
	      if (debug)
		type(SS, 0, NULL, "-> %s", bbuf);
	      uname = strdup(bbuf);
	      if (*ccp != 0) {
		type(SS, 501, m552, "unrecognized input/extra junk ??");
		return;
	      }

	    } else {
	      
	      i = encodebase64string("Username:", 9, abuf, sizeof(abuf));
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
	      if (i == 0)	/* EOF ??? */
		return;
	      if (strcmp(abuf, "*") == 0) {
		type(SS, 501, NULL, "AUTH command cancelled");
		return;
	      }
	      rc = decodebase64string(abuf, i, bbuf, sizeof(bbuf), NULL);
	      bbuf[sizeof(bbuf)-1] = 0;
	      if (debug)
		type(SS, 0, NULL, "-> %s", bbuf);
	      uname = strdup(bbuf);
	    }

	    i = encodebase64string("Password:", 9, abuf, sizeof(abuf));
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
	      return;
	    }
	    if (strcmp(abuf, "*") == 0) {
	      if (uname) free(uname);
	      type(SS, 501, NULL, "AUTH command cancelled");
	      return;
	    }

	    rc = decodebase64string(abuf, i, bbuf, sizeof(bbuf), NULL);
	    bbuf[sizeof(bbuf)-1] = 0;
	    if (debug)
	      type(SS, 0, NULL, "-> %s", bbuf);

	    if (tls_loglevel > 3)
	      type(NULL,0,NULL,"zpwmatch: user ´%s' password '%s'", uname, bbuf);
	    else if (tls_loglevel > 0)
	      type(NULL,0,NULL,"zpwmatch: user ´%s' (password: *not so easy*!)", uname);
	    
	    if (smtpauth_via_pipe)
	      zpw = pipezpwmatch(smtpauth_via_pipe, uname, bbuf, &uid);
	    else
	      zpw = zpwmatch(uname, bbuf, &uid);

	    if (zpw == NULL) {
	      SS->authuser = uname;
	      type(SS, 235, NULL, "Authentication successful.");
	    } else {
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
#if 0 /* this test happens also in  sasl_server_start() */
	  /* check whether mechanism is available */
	  if (iteminlist(cp, SS->sasl.mechlist, " ") == NULL) {
	    type(SS, 503, "5.3.3", "AUTH mechanism %.32s not available", cp);
	    return;
	  }
#endif
	  if (ismore) {
	    /* could this be shorter? XXX */
	    len = 1+strlen(q);
	    in = malloc(len);
	    result = sasl_decode64(q, len-1, in, len, &inlen);
	    if (result != SASL_OK) {
	      type(SS, 501, "5.5.4", "cannot BASE64 decode '%s'", q);
	      authenticating = SASL_NOT_AUTH;
	      free(in);
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

	    type(SS, 500, "5.7.0", "authentication failed");
	    if (logfp){
	      const char * e = sasl_errdetail(SS->sasl.conn);
	      if (!e) e = "<-no-detail->";
	      fprintf(logfp, "%s%04d#\tAUTH failure (%s): %s (%d) %s\n",
		      logtag, (int)(now - logtagepoch),
		      cp, sasl_errstring(result, NULL, NULL), result, e);
	      fflush(logfp);
	    }
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
	    type(SS, 454, "4.5.4", "Temporary authentication failure");
	    if (logfp) {
	      fprintf(logfp, "%s%d#\tAUTH encode64 error [%d for \"%s\"]\n",
		      logtag, (int)(now - logtagepoch),
		      result, out);
	      fflush(logfp);
	    }
	    /* start over? */
	    authenticating = SASL_NOT_AUTH;
	  } else {
	    type(SS, 334, "", "%s", out2);
	    authenticating = SASL_PROC_AUTH;
	  }

	  while (authenticating == SASL_PROC_AUTH) {

	    i = s_gets( SS, abuf, sizeof(abuf), &rc, &co, &c );
	    abuf[sizeof(abuf)-1] = 0;

	    if (logfp != NULL) {
	      fprintf(logfp, "%s%04dr\t**user-response**  -- len=%d\n",
		      logtag, (int)(now - logtagepoch), i );
	      fflush(logfp);
	    }

	    if (abuf[0] == '\0' || i == 0) {
	      authenticating = SASL_NOT_AUTH;
	      type(SS,  501, "5.5.2", "missing input");
	      break;
	    }

	    if (abuf[0] == '*' && abuf[1] == '\0') {
	      authenticating = SASL_NOT_AUTH;
	      
	      /* rfc 2254 4. */
	      type(SS, 501, "5.0.0", "AUTH aborted");
	      break;
	    }

	    /* could this be shorter? XXX */
	    result = sasl_decode64(abuf, i, bbuf, sizeof(bbuf), &outlen);
	    if (result != SASL_OK) {
	      authenticating = SASL_NOT_AUTH;
	      /* rfc 2254 4. */
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

      if (do_sasl) {

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
	int result;

#ifdef HAVE_SASL2
	if (do_sasl) {
	  if (SS->sasl.sasl_ok) {
	    SS->sasl.ssp.security_flags = (SASLSecOpts & SASL_SEC_MAXIMUM);
	    if (!(auth_login_without_tls || SS->sslmode)) {
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
		   SS->sasl.mechlist, "-ignored-" /* AuthMechanisms */);
	      /* XXX: intersect the mechlist with AuthMechanisms ??? */
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
	  if (auth_ok) {
	    if (auth_login_without_tls || SS->sslmode) {
	      type(SS, -250, NULL, "AUTH=LOGIN"); /* RFC 2554, NetScape/
						     Sun Solstice/ ? */
	      type(SS, -250, NULL, "AUTH LOGIN"); /* RFC 2554, M$ Exchange ? */
	    }
	  }
}



#if 0
 ---------------------------------------------
#if SASL
	bool ismore;
	int result;
	volatile int authenticating;
	char *user;
	char *in, *out, *out2;
	const char *errstr;
	unsigned int inlen, out2len;
	unsigned int outlen;
	char *volatile auth_type;
	char *mechlist;
	sasl_conn_t *conn;
	volatile bool sasl_ok;
	volatile unsigned int n_auth = 0;	/* count of AUTH commands */
	volatile unsigned int n_mechs;
	unsigned int len;
	sasl_security_properties_t ssp;
	sasl_external_properties_t ext_ssf;
	sasl_ssf_t *ssf;
#endif /* SASL */
 ---------------------------------------------

#if SASL
		else
		{
			/* don't want to do any of this if authenticating */
#endif /* SASL */
 ---------------------------------------------
#if SASL
		  case CMDAUTH: /* sasl */
			DELAY_CONN("AUTH");
			if (!sasl_ok || n_mechs <= 0)
			{
				message("503 5.3.3 AUTH not available");
				break;
			}
			if (authenticating == SASL_IS_AUTH)
			{
				message("503 5.5.0 Already Authenticated");
				break;
			}
			if (smtp.sm_gotmail)
			{
				message("503 5.5.0 AUTH not permitted during a mail transaction");
				break;
			}
			if (tempfail)
			{
				if (LogLevel > 9)
					sm_syslog(LOG_INFO, e->e_id,
						  "SMTP AUTH command (%.100s) from %.100s tempfailed (due to previous checks)",
						  p, CurSmtpClient);
				usrerr("454 4.7.1 Please try again later");
				break;
			}

			ismore = false;

			/* crude way to avoid crack attempts */
			(void) checksmtpattack(&n_auth, n_mechs + 1, true,
					       "AUTH", e);

			/* make sure mechanism (p) is a valid string */
			for (q = p; *q != '\0' && isascii(*q); q++)
			{
				if (isspace(*q))
				{
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
			if (iteminlist(p, mechlist, " ") == NULL)
			{
				message("503 5.3.3 AUTH mechanism %.32s not available",
					p);
				break;
			}

			if (ismore)
			{
				/* could this be shorter? XXX */
				in = sm_rpool_malloc(e->e_rpool, strlen(q));
				result = sasl_decode64(q, strlen(q), bbuf, sizeof(bbuf)
						       &inlen);
				if (result != SASL_OK)
				{
					message("501 5.5.4 cannot BASE64 decode '%s'",
						q);
					if (LogLevel > 5)
						sm_syslog(LOG_WARNING, e->e_id,
							  "AUTH decode64 error [%d for \"%s\"]",
							  result, q);
					/* start over? */
					authenticating = SASL_NOT_AUTH;
					in = NULL;
					inlen = 0;
					break;
				}
			}
			else
			{
				in = NULL;
				inlen = 0;
			}

			/* see if that auth type exists */
			result = sasl_server_start(conn, p, in, inlen,
						   &out, &outlen, &errstr);

			if (result != SASL_OK && result != SASL_CONTINUE)
			{
				message("500 5.7.0 authentication failed");
				if (LogLevel > 9)
					sm_syslog(LOG_ERR, e->e_id,
						  "AUTH failure (%s): %s (%d) %s",
						  p,
						  sasl_errstring(result, NULL,
								 NULL),
						  result,
						  errstr);
				break;
			}
			auth_type = newstr(p);

			if (result == SASL_OK)
			{
				/* ugly, but same code */
				goto authenticated;
				/* authenticated by the initial response */
			}

			/* len is at least 2 */
			len = ENC64LEN(outlen);
			out2 = xalloc(len);
			result = sasl_encode64(out, outlen, out2, len,
					       &out2len);

			if (result != SASL_OK)
			{
				message("454 4.5.4 Temporary authentication failure");
				if (LogLevel > 5)
					sm_syslog(LOG_WARNING, e->e_id,
						  "AUTH encode64 error [%d for \"%s\"]",
						  result, out);

				/* start over? */
				authenticating = SASL_NOT_AUTH;
			}
			else
			{
				message("334 %s", out2);
				authenticating = SASL_PROC_AUTH;
			}
			break;
#endif /* SASL */
 ---------------------------------------------
			  /* EHLO response: */
#if SASL
			if (sasl_ok && mechlist != NULL && *mechlist != '\0')
				message("250-AUTH %s", mechlist);
#endif /* SASL */

 ---------------------------------------------
			  /* STARTTLS processing: */
# if SASL
			if (sasl_ok)
			{
				char *s;

				s = macvalue(macid("{cipher_bits}"), e);
				if (s != NULL && (ext_ssf.ssf = atoi(s)) > 0)
				{
					ext_ssf.auth_id = macvalue(macid("{cert_subject}"),
								   e);
					sasl_ok = sasl_setprop(conn, SASL_SSF_EXTERNAL,
							       &ext_ssf) == SASL_OK;
					mechlist = NULL;
					if (sasl_ok)
						n_mechs = saslmechs(conn,
								    &mechlist);
				}
			}
# endif /* SASL */

 ---------------------------------------------
			  /* QUIT processing: */
#if SASL
			if (authenticating == SASL_IS_AUTH)
			{
				sasl_dispose(&conn);
				authenticating = SASL_NOT_AUTH;
				/* XXX sasl_done(); this is a child */
			}
#endif /* SASL */
 ---------------------------------------------
			  /* MAIL FROM  AUTH= processing: */
#if SASL
	else if (sm_strcasecmp(kp, "auth") == 0)
	{
		int len;
		char *q;
		char *auth_param;	/* the value of the AUTH=x */
		bool saveQuickAbort = QuickAbort;
		bool saveSuprErrs = SuprErrs;
		bool saveExitStat = ExitStat;
		char pbuf[256];

		if (vp == NULL)
		{
			usrerr("501 5.5.2 AUTH= requires a value");
			/* NOTREACHED */
		}
		if (e->e_auth_param != NULL)
		{
			usrerr("501 5.5.0 Duplicate AUTH parameter");
			/* NOTREACHED */
		}
		if ((q = strchr(vp, ' ')) != NULL)
			len = q - vp + 1;
		else
			len = strlen(vp) + 1;
		auth_param = xalloc(len);
		(void) sm_strlcpy(auth_param, vp, len);
		if (!xtextok(auth_param))
		{
			usrerr("501 5.5.4 Syntax error in AUTH parameter value");
			/* just a warning? */
			/* NOTREACHED */
		}

		/* XXX this might be cut off */
		(void) sm_strlcpy(pbuf, xuntextify(auth_param), sizeof pbuf);
		/* xalloc() the buffer instead? */

		/* XXX define this always or only if trusted? */
		macdefine(&e->e_macro, A_TEMP, macid("{auth_author}"), pbuf);

		/*
		**  call Strust_auth to find out whether
		**  auth_param is acceptable (trusted)
		**  we shouldn't trust it if not authenticated
		**  (required by RFC, leave it to ruleset?)
		*/

		SuprErrs = true;
		QuickAbort = false;
		if (strcmp(auth_param, "<>") != 0 &&
		     (rscheck("trust_auth", pbuf, NULL, e, true, false, 9,
			      NULL, NOQID) != EX_OK || Errors > 0))
		{
			if (tTd(95, 8))
			{
				q = e->e_auth_param;
				sm_dprintf("auth=\"%.100s\" not trusted user=\"%.100s\"\n",
					pbuf, (q == NULL) ? "" : q);
			}

			/* not trusted */
			e->e_auth_param = "<>";
# if _FFR_AUTH_PASSING
			macdefine(&BlankEnvelope.e_macro, A_PERM,
				  macid("{auth_author}"), NULL);
# endif /* _FFR_AUTH_PASSING */
		}
		else
		{
			if (tTd(95, 8))
				sm_dprintf("auth=\"%.100s\" trusted\n", pbuf);
			e->e_auth_param = sm_rpool_strdup_x(e->e_rpool,
							    auth_param);
		}
		sm_free(auth_param); /* XXX */

		/* reset values */
		Errors = 0;
		QuickAbort = saveQuickAbort;
		SuprErrs = saveSuprErrs;
		ExitStat = saveExitStat;
	}
#endif /* SASL */

 ---------------------------------------------
			  /* MAIL FROM  AUTH= processing: */
#endif
