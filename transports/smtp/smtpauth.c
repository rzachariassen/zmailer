/*
 *	SMTP authentication client code for SMTP client.
 *	This is intended to do authentication for things
 *	like Cyrus IMAP LMTP sockets.
 *
 *	Copyright 2003 by Matti Aarnio
 *
 */

#include "smtp.h"


/* We are doing this in application specific and very
   sloppy manner!  We presume following interaction to
   happen and be valid for this session:

   C: AUTH LOGIN 
   S: 334 VXNlcm5hbWU6                  base64 "Username:" 
   C: bXluYW1l                          base64 "myname" 
   S: 334 Uc2VjcmV0                     base64 "Password:" 
   C: GFzc3dvcmQ6                       base64 "secret" 
   S: 235 Authentication successful

   Where 'myname' and 'secret' are those of CYRUS IMAP server
   system... (or whatever is applicable to your case)
   Possibly this shall happen under TLS encryption.
*/


extern char *authpasswdfile;

/* In named file, we have authentication secrets for remote hosts,
   keep the file well protected!

   Any empty line, or mere whitespace line, is ignored.
   Lines with first non-whitespace char being '#' are comments.

   Other lines are presumed to be whitespace separated quads:
       channel   remotehost   remoteuser   remotesecret

   The 'channel' can be either "*" matching any runtime channel
   parameter, or literal something, like: "smtp-lmtp".

   The 'remotehost' is remote host name on which the connection
   has gone to (e.g. by MXes, or whatever means).

   The 'remoteuser' is BASE64 encoded string to be sent to the
   remote system in SMTP-auth transaction.

   The 'remotesecter' is BASE64 encoded string to be sent to the
   remote system in SMTP-auth transaction.

*/


static int
pick_secrets(SS, ru, ruspace, rs, rsspace)
     SmtpState *SS;
     char *ru, *rs;
     int ruspace, rsspace;
{
	FILE *fp;
	char lbuf[2000];
	char *p;
	char *chp, *rhp, *up, *sp;
	int linenum = 0;

	*ru = *rs = 0;

	if (!authpasswdfile) {
	  if (SS->verboselog)
	    fprintf(SS->verboselog,"smtpauth()::pick_secrets() called without defined  authpasswdfile !\n");
	  return EX_OSFILE;
	}

	fp = fopen(authpasswdfile, "r");
	if (!fp) {
	  if (SS->verboselog)
	    fprintf(SS->verboselog,"smtpauth()::pick_secrets() failed to open '%s' file for reading!\n", authpasswdfile);
	  /* no-perm ? -> TEMPFILE ? */
	  return EX_OSFILE;
	}

	while (!ferror(fp) && !feof(fp)) {

	  if (! fgets(lbuf, sizeof(lbuf)-1, fp))
	    break; /* oer... EOF ? */
	  lbuf[sizeof(lbuf)-1] = 0;

	  ++linenum;

	  for (p = lbuf; *p; ++p) {
	    if (*p != ' ' && *p != '\t' && *p != '\n')
	      break; /* Scan over leading whitespace,
			including trailing \n, if any */
	  }
	  if (! *p)      continue; /* Blank line */
	  if (*p == '#') continue; /* comment    */
	  
	  chp = p; /* Channel */

	  /* skip over non-whitespace stuff.. */
	  for (;*p && *p != ' ' && *p != '\t' && *p != '\n'; ++p) ;

	  if (*p) *p++ = 0; /* Mark end of that */
	  /* skip over whitespace stuff .. */
	  for (; *p == ' ' || *p == '\t' || *p == '\n'; ++p) ;

	  rhp = p; /* Remote Host */

	  /* skip over non-whitespace stuff.. */
	  for (;*p && *p != ' ' && *p != '\t' && *p != '\n'; ++p) ;

	  if (*p) *p++ = 0; /* Mark end of that */
	  /* skip over whitespace stuff .. */
	  for (; *p == ' ' || *p == '\t' || *p == '\n'; ++p) ;

	  up = p; /* Remote User */

	  /* skip over non-whitespace stuff.. */
	  for (;*p && *p != ' ' && *p != '\t' && *p != '\n'; ++p) ;

	  if (*p) *p++ = 0; /* Mark end of that */
	  /* skip over whitespace stuff .. */
	  for (; *p == ' ' || *p == '\t' || *p == '\n'; ++p) ;

	  sp = p; /* Remote Secret */

	  /* skip over non-whitespace stuff.. */
	  for (;*p && *p != ' ' && *p != '\t' && *p != '\n'; ++p) ;

	  if (*p) *p++ = 0; /* Mark end of that */
	  /* skip over whitespace stuff .. */
	  /* ... not needed here ... */

	  if (!*sp || !*up || !*rhp || !*chp) {
	    /* FIXME: log this ?? */
	    if (SS->verboselog)
	      fprintf(SS->verboselog,"smtpauth()::auth-secrets.txt:%d: bad data!\n", linenum);
	    continue; /* Bad input data.. */
	  }

	  if ((chp[0] == '*' && chp[1] == 0) ||
	      (SS->sel_channel && strcmp(chp, SS->sel_channel) == 0)) {
	    /* Have matching Channel Selector */

	    if (! CISTREQ(SS->remotehost, rhp))
	      continue; /* Not matching host */

	    /* Ok, we have it! lets publish it! */

	    strncpy(ru, up, ruspace);
	    ru[ruspace -1] = 0;

	    strncpy(rs, sp, rsspace);
	    rs[rsspace -1] = 0;

	    /* And bail out... */
	    break;
	  }
	}
	fclose(fp);

	if (*rs && *ru) return EX_OK; /* Both set ? */

	return EX_UNAVAILABLE; /* Not set - not found! */
}



int
smtpauth(SS)
     SmtpState *SS;
{
	int rc;
	char remoteuser[256];
	char remotesecret[256];

	if (SS->verboselog)
	  fprintf(SS->verboselog, "smtpauth(ch='%s' remhost='%s')\n",
		  SS->sel_channel, SS->remotehost);

	*remoteuser=0;
	rc = pick_secrets(SS,
			  remoteuser, sizeof(remoteuser),
			  remotesecret, sizeof(remotesecret));

	if (SS->verboselog)
	  fprintf(SS->verboselog, " ... secrets pickup rc=%d; remoteuser='%s'\n",
		  rc, remoteuser);


	if (rc != EX_OK) {
	  if (rc == EX_UNAVAILABLE) rc = EX_OK;
	  return rc; /* Failed to pick anything.. */
	}


	smtp_flush(SS);
	SS->rcptstates = 0;
	rc = smtpwrite(SS, 0, "AUTH LOGIN", 0, NULL);
	if (rc != EX_OK) {
	  /* ??? how to do aborts ? Not do ? */
	  return rc;
	}

	/* PRESUMING HERE!  "334 VXNlcm5hbWU6" (as Cyrus does) */

	SS->rcptstates = 0;
	rc = smtpwrite(SS, 0, remoteuser, 0, NULL);
	if (rc != EX_OK) {
	  /* ??? how to do aborts ? Not do ? */
	  return rc;
	}

	/* PRESUMING HERE!  "334 Uc2VjcmV0" (as Cyrus does) */

	SS->rcptstates = 0;
	rc = smtpwrite(SS, 0, remotesecret, 0, NULL);
	if (rc != EX_OK) {
	  /* ??? how to do aborts ? Not do ? */
	  return rc;
	}

	return rc;
}
