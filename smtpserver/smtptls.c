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
}

#endif
