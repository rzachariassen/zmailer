/*
 *  ZMailer smtpserver,  Support for TLS / STARTTLS (RFC 2487)
 *  part of ZMailer.
 *
 *  by Matti Aarnio <mea@nic.funet.fi> 1999
 */

#include "smtpserver.h"

#ifdef HAVE_OPENSSL

void smtp_starttls(SS, buf, cp)
     SmtpState *SS;
     const char *buf, *cp;
{
    int x;

    if (!starttls_ok) {
      /* Ok, then 'command not implemented' ... */
      type(SS, 502, m540, NULL);
      return;
    }

    if (SS->sslmode) {
      type(SS, 554, m540, "TLS already active, restart not allowed!");
      return;
    }

    if (!strict_protocol) while (*cp == ' ' || *cp == '\t') ++cp;
    if (*cp != 0) {
      type(SS, 501, m513, "Extra junk following 'STARTTLS' command!");
      return;
    }
    /* XX: engine ok ?? */
    type(SS, 220, NULL, "Ok to start TLS");
    typeflush(SS);
    if (SS->mfp != NULL) {
      clearerr(SS->mfp);
      mail_abort(SS->mfp);
      SS->mfp = NULL;
    }
    /* XX: start_servertls(SS) */

    SS->sslwrbuf = emalloc(8192);
    SS->sslwrspace = 8192;
    SS->sslwrin = SS->sslwrout = 0;
}

int Z_SSL_flush(SS)
     SmtpState * SS;
{
    int in = SS->sslwrin;
    int ou = SS->sslwrout;

    SS->sslwrin = SS->sslwrout = 0;

    if (ou >= in)
      return 0;

    /* this is blocking write */
    return SSL_write(SS->ssl, SS->sslwrbuf + ou, in - ou);
}

int Z_SSL_write(SS, ptr, len)
     SmtpState * SS;
     const void *ptr;
     int len;
{
    int i, rc = 0;
    char *buf = (char *)ptr;

    while (len > 0) {
      i = SS->sslwrspace - SS->sslwrin; /* space */
      if (i == 0) {
	/* The buffer is full! Flush it */
	i = Z_SSL_flush(SS);
	if (i < 0) return rc;
	rc += i;
	i = SS->sslwrspace;
      }
      /* Copy only as much as can fit into current space */
      if (i > len) i = len;
      memcpy(SS->sslwrbuf + SS->sslwrin, buf, i);
      SS->sslwrin += i;
      buf += i;
      len -= i;
      rc += i;
    }

    /* how much written out ? */
    return rc;
}

#endif
