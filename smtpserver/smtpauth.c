/*
 *  ZMailer smtpserver,  AUTH command things;
 *  part of ZMailer.
 *
 *  by Matti Aarnio <mea@nic.funet.fi> 1999
 */

#include "smtpserver.h"

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

extern int zpwmatch __((char *, char *));

#if 0 /* DUMMY BEAST... */

/* This is *NOT* universal password matcher!
   Consider Shadow passwords, PAM systems, etc.. */

#include <pwd.h>
#include <unistd.h>

int zpwmatch(uname,password)
     char *uname, *password;
{
    struct passwd *pw = getpwnam(uname);
    char *cr;

    if (!pw) return 0; /* No such user */
    cr = crypt(password, pw->pw_passwd);

    return (strcmp(cr, pw->pw_passwd) == 0);
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

    if (SS->authuser != NULL) {
      type(SS, 503, m551, "Already authenticated, second attempt rejected!");
      return;
    }

    if (SS->state != MailOrHello && SS->state != Mail) {
      type(SS, 503, m551, "AUTH not allowed during MAIL transaction!");
      return;
    }

    if (*cp == ' ') ++cp;
    if (!strict_protocol) while (*cp == ' ' || *cp == '\t') ++cp;
    if (!CISTREQN(cp, "LOGIN", 5)) {
      type(SS, 501, m552, "where is LOGIN in that?");
      return;
    }
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
      if (*cp != 0) {
	type(SS, 501, m552, "unrecognized input/extra junk ??");
	return;
      }

      i = encodebase64string("Username:", 9, abuf, sizeof(abuf));
      if (i >= sizeof(abuf)) i = sizeof(abuf)-1;
      abuf[i] = 0;
      type(SS, 334, NULL, "%s", abuf);

      i = s_gets(SS, abuf, sizeof(abuf), &rc, &co, &c );
      abuf[sizeof(abuf)-1] = 0;
      if (logfp != NULL) {
	fprintf(logfp, "%dr\t%s\n", pid, abuf);
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
    if (logfp != NULL) {
      fprintf(logfp, "%dr\t%s\n", pid, abuf);
      fflush(logfp);
    }
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

    if (zpwmatch(uname, bbuf)) {
	SS->authuser = uname;
	type(SS, 253, NULL, "Authentication successfull");
    } else {
	type(SS, 535, NULL, "Authentication failed");
	if (uname) free(uname);
    }
}
