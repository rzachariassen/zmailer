/*
 *  ZMailer smtpserver,  Support for TLS / STARTTLS (RFC 2487)
 *  part of ZMailer.
 *
 *  Contains ALSO code for SMTP Transport Agent!
 *
 *  by Matti Aarnio <mea@nic.funet.fi> 1999, 2003-2005
 *
 *  Reusing TLS code for POSTFIX by:
 *     Lutz Jaenicke <Lutz.Jaenicke@aet.TU-Cottbus.DE>
 *  URL  http://www.aet.tu-cottbus.de/personen/jaenicke/pfixtls/
 *
 */

#include "smtpserver.h"

#ifdef HAVE_OPENSSL

#ifdef HAVE_DISTCACHE
#include <distcache/dc_client.h>

static DC_CTX *dc_ctx;

static const char MAIL_TLS_SRVR_CACHE[] = "TLSsrvrcache";
static const int id_maxlength = 32;	/* Max ID length in bytes */
static char server_session_id_context[] = "ZMailer/TLS"; /* anything will do */
#endif

static int do_dump = 0;
static int verify_depth = 1;
static int verify_error = X509_V_OK;

#define SSL_SESSION_MAX_DER 10*1024


/* We must keep some of info available */
static const char hexcodes[] = "0123456789ABCDEF";

/* Structure used for random generator seeding.. */
struct _randseed {
	int pid;
	int ppid;
	struct timeval tv;
} tls_randseed;


void
smtp_starttls(SS, buf, cp)
     SmtpState *SS;
     const char *buf, *cp;
{
    if (!OCP->starttls_ok) {
      /* Ok, then 'command not implemented' ... */
      type(SS, 502, m540, NULL);
      return;
    }


    MIBMtaEntry->ss.IncomingSMTP_STARTTLS += 1;

    if (SS->sslmode) {
      type(SS, 554, m540, "TLS already active, restart not allowed!");
      MIBMtaEntry->ss.IncomingSMTP_STARTTLS_fail += 1;
      return;
    }

    if (strict_protocol < 1) /* Skip extra white-spaces */
      while (*cp == ' ' || *cp == '\t') ++cp;
    if (*cp != 0) {
      type(SS, 501, m513, "Extra junk following 'STARTTLS' command!");
      MIBMtaEntry->ss.IncomingSMTP_STARTTLS_fail += 1;
      return;
    }
    /* XX: engine ok ?? */
    type(SS, 220, NULL, "Ready to start TLS");
    typeflush(SS);
    if (SS->mfp != NULL) {
      clearerr(SS->mfp);
      mail_abort(SS->mfp);
      policytest(&SS->policystate, POLICY_DATAABORT,
		 NULL, SS->rcpt_count, NULL);
      SS->mfp = NULL;
    }

    if (tls_start_servertls(SS)) {
      /*
       * typically the connection is hanging at this point, so
       * we should try to shut it down by force!
       */
      if (SS->mfp != NULL) {
	clearerr(SS->mfp);
	mail_abort(SS->mfp);
	policytest(&SS->policystate, POLICY_DATAABORT,
		   NULL, SS->rcpt_count, NULL);
	SS->mfp = NULL;
      }
      MIBMtaEntry->ss.IncomingSMTP_STARTTLS_fail += 1;
      exit(2);
    }
    SS->with_protocol_set |= WITH_TLS;
}


int
Z_read(SS, ptr, len)
     SmtpState * SS;
     void *ptr;
     int len;
{
    if (SS->sslmode) {
      /* This can be Non-Blocking READ */
      int rc = SSL_read(SS->TLS.ssl, (char*)ptr, len);
      int e  = SSL_get_error(SS->TLS.ssl, rc);
      switch (e) {
      case SSL_ERROR_WANT_READ:
	errno = EAGAIN;
	rc = -1;
	break;
      case SSL_ERROR_WANT_WRITE:
	errno = EAGAIN;
	rc = -2;
	break;
      default:
	break;
      }
      return rc;
    } else
      return read(SS->inputfd, (char*)ptr, len);
}

int
Z_pending(SS)
     SmtpState * SS;
{
    int rc;
    struct timeval tv;
    fd_set rdset;

    if (SS->sslmode)
      return SSL_pending(SS->TLS.ssl);

    _Z_FD_ZERO(rdset);
    _Z_FD_SET(SS->inputfd, rdset);
    tv.tv_sec = tv.tv_usec = 0;

    rc = select(SS->inputfd+1, &rdset, NULL, NULL, &tv);

    if (rc > 0) return 1;

    return 0;
}



int
Z_SSL_flush(SS)
     SmtpState * SS;
{
    int in = SS->sslwrin;
    int ou = SS->sslwrout;
    int rc, e;

    if (ou >= in)
      return 0;

    rc = SSL_write(SS->TLS.ssl, SS->sslwrbuf + ou, in - ou);
    e  = SSL_get_error(SS->TLS.ssl, rc);
    switch (e) {
    case SSL_ERROR_WANT_READ:
      errno = EAGAIN;
      rc = -2;
      break;
    case SSL_ERROR_WANT_WRITE:
      errno = EAGAIN;
      rc = -1;
      break;
    default:
      break;
    }

    return rc;
}


#ifdef HAVE_DISTCACHE


static DC_CTX      *ssl_scache_dc_init     __((void));
static SSL_SESSION *ssl_scache_dc_retrieve __((SSL *, unsigned char *, int));
static int          ssl_scache_dc_store    __((SSL_SESSION *, unsigned char *, int, time_t));
static void         ssl_scache_dc_remove   __((SSL_SESSION *, unsigned char *, int));


/* we initialize this index at startup time
 * and never write to it at request time,
 * so this static is thread safe.
 * also note that OpenSSL increments at static variable when
 * SSL_get_ex_new_index() is called, so we _must_ do this at startup.
 */
static int TLScontext_index = -1;


/*
 * Callback to retrieve a session from the external session cache.
 */
static SSL_SESSION *get_session_cb(SSL *ssl, unsigned char *SessionID,
				   int length, int *copy)
{
    SSL_SESSION *session;

    session = ssl_scache_dc_retrieve(ssl, SessionID, length);

    *copy = 0;

    return (session);
}


/*
 * Save a new session to the external cache
 */
static int new_session_cb(SSL *ssl, SSL_SESSION *session)
{
    unsigned char *id;
    unsigned int idlen;
    int rc;
    long timeout = OCP->tls_scache_timeout;

    SSL_set_timeout(session, timeout);
    id    = session->session_id;
    idlen = session->session_id_length;

    timeout += SSL_SESSION_get_time(session);

    rc = ssl_scache_dc_store(session,id,idlen,timeout);

    return rc;
}

/*
 * Remove a session from the external cache
 */
static void remove_session_cb(SSL_CTX *ssl, SSL_SESSION *session)
{
    unsigned char *id;
    unsigned int idlen;

    id    = session->session_id;
    idlen = session->session_id_length;

    ssl_scache_dc_remove(session,id,idlen);
}



static void tls_scache_init(ssl_ctx)
     SSL_CTX *ssl_ctx;
{

	/*
	 * Initialize the DISTCACHE context.
	 */

	dc_ctx = ssl_scache_dc_init();
	if (!dc_ctx) return; /* No can do.. */

	/*
	 * Initialize the session cache. We only want external caching to
	 * synchronize between server sessions, so we set it to a minimum value
	 * of 1. If the external cache is disabled, we won't cache at all.
	 * The recall of old sessions "get" and save to disk of just created
	 * sessions "new" is handled by the appropriate callback functions.
	 *
	 * We must not forget to set a session id context to identify to which
	 * kind of server process the session was related. In our case, the
	 * context is just the name of the patchkit: "Postfix/TLS".
	 */

	SSL_CTX_sess_set_cache_size(ssl_ctx, 1);
	SSL_CTX_set_timeout(ssl_ctx, OCP->tls_scache_timeout);

	SSL_CTX_set_session_id_context(ssl_ctx,
				       (void*)&server_session_id_context,
				       sizeof(server_session_id_context));

	/*
	 * The session cache is realized by distcache, if at all..
	 */
	if (OCP->tls_scache_name) {
	    SSL_CTX_set_session_cache_mode(ssl_ctx,
					   ( SSL_SESS_CACHE_SERVER |
					     SSL_SESS_CACHE_NO_INTERNAL ));
	    SSL_CTX_sess_set_get_cb(ssl_ctx,    get_session_cb);
	    SSL_CTX_sess_set_new_cb(ssl_ctx,    new_session_cb);
	    SSL_CTX_sess_set_remove_cb(ssl_ctx, remove_session_cb);
	}
	
	/*
	 * Finally create the global index to access TLScontext information
	 * inside verify_callback.
	 */
	if (TLScontext_index < 0) {
	  /* we _do_ need to call this twice */
	  TLScontext_index = SSL_get_ex_new_index(0,
						  "TLScontext ex_data index",
						  NULL, NULL, NULL);
	  TLScontext_index = SSL_get_ex_new_index(0,
						  "TLScontext ex_data index",
						  NULL, NULL, NULL);
	}
}
#endif


/* skeleton taken from OpenSSL crypto/err/err_prn.c */


static void tls_print_errors __((void));

static void
tls_print_errors()
{
    unsigned long l;
    char    buf[256];
    const char *file;
    const char *data;
    int     line;
    int     flags;
    unsigned long es;

    es = CRYPTO_thread_id();
    while ((l = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
	if (flags & ERR_TXT_STRING)
	    type(NULL,0,NULL,"%lu:%s:%s:%d:%s:", es, ERR_error_string(l, buf),
		 file, line, data);
	else
	    type(NULL,0,NULL,"%lu:%s:%s:%d:", es, ERR_error_string(l, buf),
		 file, line);
    }
}

 /*
  * Set up the cert things on the server side. We do need both the
  * private key (in key_file) and the cert (in cert_file).
  * Both files may be identical.
  *
  * This function is taken from OpenSSL apps/s_cb.c
  */

static int set_cert_stuff __((SSL_CTX * ctx, const char *cert_file, const char *key_file));

static int
set_cert_stuff(ctx, cert_file, key_file)
     SSL_CTX * ctx;
     const char *cert_file, *key_file;
{
    if (cert_file != NULL) {
	if (SSL_CTX_use_certificate_file(ctx, cert_file,
					 SSL_FILETYPE_PEM) <= 0) {
	    type(NULL,0,NULL,"unable to get certificate from '%s'", cert_file);
	    tls_print_errors();
	    return (0);
	}
	if (key_file == NULL)
	    key_file = cert_file;
	if (SSL_CTX_use_PrivateKey_file(ctx, key_file,
					SSL_FILETYPE_PEM) <= 0) {
	    type(NULL,0,NULL,"unable to get private key from '%s'", key_file);
	    tls_print_errors();
	    return (0);
	}
	/* Now we know that a key and cert have been set against
         * the SSL context */
	if (!SSL_CTX_check_private_key(ctx)) {
	    type(NULL,0,NULL,"Private key does not match the certificate public key");
	    return (0);
	}
    }
    return (1);
}

/* taken from OpenSSL apps/s_cb.c */

static RSA * tmp_rsa_cb __((SSL * s, int export, int keylength));

static RSA *
tmp_rsa_cb(s, export, keylength)
     SSL * s;
     int export, keylength;

{
    static RSA *rsa_tmp = NULL;

    if (rsa_tmp == NULL) {
	if (OCP->tls_loglevel >= 2)
	    type(NULL,0,NULL,"Generating temp (%d bit) RSA key...", keylength);
	rsa_tmp = RSA_generate_key(keylength, RSA_F4, NULL, NULL);
    }
    return (rsa_tmp);
}

/*
 * Skeleton taken from OpenSSL apps/s_cb.c
 *
 * The verify_callback is called several times (directly or indirectly) from
 * crypto/x509/x509_vfy.c. It is called as a last check for several issues,
 * so this verify_callback() has the famous "last word". If it does return "0",
 * the handshake is immediately shut down and the connection fails.
 *
 * Postfix/TLS has two modes, the "use" mode and the "enforce" mode:
 *
 * In the "use" mode we never want the connection to fail just because there is
 * something wrong with the certificate (as we would have sent happily without
 * TLS).  Therefore the return value is always "1".
 *
 * In the "enforce" mode we can shut down the connection as soon as possible.
 * In server mode TLS itself may be enforced (e.g. to protect passwords),
 * but certificates are optional. In this case the handshake must not fail
 * if we are unhappy with the certificate and return "1" in any case.
 * Only if a certificate is required the certificate must pass the verification
 * and failure to do so will result in immediate termination (return 0).
 * In the client mode the decision is made with respect to the peername
 * enforcement. If we strictly enforce the matching of the expected peername
 * the verification must fail immediatly on verification errors. We can also
 * immediatly check the expected peername, as it is the CommonName at level 0.
 * In all other cases, the problem is logged, so the SSL_get_verify_result()
 * will inform about the verification failure, but the handshake (and SMTP
 * connection will continue).
 *
 * The only error condition not handled inside the OpenSSL-Library is the
 * case of a too-long certificate chain, so we check inside verify_callback().
 * We only take care of this problem, if "ok = 1", because otherwise the
 * verification already failed because of another problem and we don't want
 * to overwrite the other error message. And if the verification failed,
 * there is no such thing as "more failed", "most failed"... :-)
 */

static int verify_callback __((int ok, X509_STORE_CTX * ctx));

static int
verify_callback(ok, ctx)
     int ok;
     X509_STORE_CTX * ctx;
{
    char    buf[256];
    X509   *err_cert;
    int     err;
    int     depth;

    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);
    if (OCP->tls_loglevel >= 1)
	type(NULL,0,NULL,"Client cert verify depth=%d %s", depth, buf);
    if (!ok) {
	type(NULL,0,NULL,"verify error:num=%d:%s", err,
		 X509_verify_cert_error_string(err));
	if (verify_depth >= depth) {
	    ok = 1;
	    verify_error = X509_V_OK;
	} else {
	    ok = 0;
	    verify_error = X509_V_ERR_CERT_CHAIN_TOO_LONG;
	}
    }
    switch (ctx->error) {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
	X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), buf, 256);
	type(NULL,0,NULL,"issuer= %s", buf);
	break;
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
	type(NULL,0,NULL,"cert not yet valid");
	break;
    case X509_V_ERR_CERT_HAS_EXPIRED:
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
	type(NULL,0,NULL,"cert has expired");
	break;
    }
    if (OCP->tls_loglevel >= 1)
	type(NULL,0,NULL,"verify return:%d", ok);
    return (ok);
}

/* taken from OpenSSL apps/s_cb.c */

static void apps_ssl_info_callback __((const SSL * s, int where, int ret));

static void
apps_ssl_info_callback(s, where, ret)
     const SSL * s;
     int where, ret;
{
    char   *str;
    int     w;

    w = where & ~SSL_ST_MASK;

    if (w & SSL_ST_CONNECT)
	str = "SSL_connect";
    else if (w & SSL_ST_ACCEPT)
	str = "SSL_accept";
    else
	str = "undefined";

    if (where & SSL_CB_LOOP) {
	if (OCP->tls_loglevel >= 2)
	    type(NULL,0,NULL,"%s:%s", str, SSL_state_string_long(s));
    } else if (where & SSL_CB_ALERT) {
	str = (where & SSL_CB_READ) ? "read" : "write";
	type(NULL,0,NULL,"SSL3 alert %s:%s:%s", str,
		 SSL_alert_type_string_long(ret),
		 SSL_alert_desc_string_long(ret));
    } else if (where & SSL_CB_EXIT) {
	if (ret == 0)
	    type(NULL,0,NULL,"%s:failed in %s",
		     str, SSL_state_string_long(s));
	else if (ret < 0) {
	    type(NULL,0,NULL,"%s:error in %s",
		     str, SSL_state_string_long(s));
	}
    }
}

/* taken from OpenSSL crypto/bio/b_dump.c */

#define TRUNCATE
#define DUMP_WIDTH	16

static int tls_dump __((const char *s, int len));

static int
tls_dump(s, len)
     const char *s;
     int len;
{
    int     ret = 0;
    char    buf[160 + 1], *ss;
    int     i;
    int     j;
    int     rows;
    int     trunc;
    unsigned char ch;

    trunc = 0;

#ifdef TRUNCATE
    for (; (len > 0) && ((s[len - 1] == ' ') || (s[len - 1] == '\0')); len--)
	trunc++;
#endif

    rows = (len / DUMP_WIDTH);
    if ((rows * DUMP_WIDTH) < len)
	rows++;

    for (i = 0; i < rows; i++) {
	ss = buf;
	*ss = 0;	/* start with empty string */

	sprintf(ss, "%04x ", i * DUMP_WIDTH);
	ss += strlen(ss);
	for (j = 0; j < DUMP_WIDTH; j++) {
	    if (((i * DUMP_WIDTH) + j) >= len) {
		strcpy(ss, "   ");
		ss += 3;
	    } else {
		ch = ((unsigned char) *((char *) (s) + i * DUMP_WIDTH + j))
		    & 0xff;
		sprintf(ss, "%02x%c", ch, j == 7 ? '|' : ' ');
		ss += 3;
	    }
	}
	ss += strlen(ss);
	*ss++ = ' ';
	for (j = 0; j < DUMP_WIDTH; j++) {
	    if (((i * DUMP_WIDTH) + j) >= len)
		break;
	    ch = ((unsigned char) *((char *) (s) + i * DUMP_WIDTH + j)) & 0xff;
	    *ss++ = (((ch >= ' ') && (ch <= '~')) ? ch : '.');
	    if (j == 7) *ss++ = ' ';
	}
	*ss = 0;
	/* if this is the last call then update the ddt_dump thing so that
         * we will move the selection point in the debug window
         */
	type(NULL,0,NULL,"%s", buf);
	ret += strlen(buf);
    }
#ifdef TRUNCATE
    if (trunc > 0) {
	sprintf(buf, "%04x - <SPACES/NULS>", len + trunc);
	type(NULL,0,NULL,"%s", buf);
	ret += strlen(buf);
    }
#endif
    return (ret);
}



/* taken from OpenSSL apps/s_cb.c */

static long bio_dump_cb __((BIO * bio, int cmd, const char *argp, int argi, long argl, long ret));

static long
bio_dump_cb(bio, cmd, argp, argi, argl, ret)
     BIO * bio;
     int cmd;
     const char *argp;
     int argi;
     long argl;
     long ret;
{
#if 0 /* NOT proper code!  must do in  bio->method->bread()  */
    static int once = 1;

    if (cmd == BIO_CB_READ && once) {
      /* This callback is done ONCE per process lifetime ...
	 ... thus we optimize a bit.  */
      SmtpState *SS = (SmtpState *)BIO_get_callback_arg(bio);

      once = 0;
      if (SS->s_ungetcbuf >= 0) {
	*(char*)argp = SS->s_ungetcbuf;
	SS->s_ungetcbuf = -1;
	return 1;
      }
    }
#endif

    if (!do_dump)
	return (ret);

    if (cmd == (BIO_CB_READ | BIO_CB_RETURN)) {
	type(NULL,0,NULL,"read from %08X [%08lX] (%d bytes => %ld (0x%X))",
	     bio, argp, argi, ret, ret);
	tls_dump(argp, (int) ret);
	return (ret);
    } else if (cmd == (BIO_CB_WRITE | BIO_CB_RETURN)) {
	type(NULL,0,NULL,"write to %08X [%08lX] (%d bytes => %ld (0x%X))",
	     bio, argp, argi, ret, ret);
	tls_dump(argp, (int) ret);
    }
    return (ret);
}



/* taken from OpenSSL apps/s_server.c */

static DH *load_dh_param(const char *dhfile)
{
	DH *ret=NULL;
	BIO *bio;

	bio = BIO_new_file(dhfile,"r");
	if (bio != NULL) {
	  ret = PEM_read_bio_DHparams(bio,NULL,NULL,NULL);
	  BIO_free(bio);
	}
	return(ret);
}

/* Cloned from Postfix MTA's TLS code */
/*
 * Finally some "backup" DH-Parameters to be loaded, if no parameters are
 * explicitely loaded from file.
 */
static unsigned char dh512_p[] = {
  0x88, 0x3F, 0x00, 0xAF, 0xFC, 0x0C, 0x8A, 0xB8, 0x35, 0xCD, 0xE5, 0xC2,
  0x0F, 0x55, 0xDF, 0x06, 0x3F, 0x16, 0x07, 0xBF, 0xCE, 0x13, 0x35, 0xE4,
  0x1C, 0x1E, 0x03, 0xF3, 0xAB, 0x17, 0xF6, 0x63, 0x50, 0x63, 0x67, 0x3E,
  0x10, 0xD7, 0x3E, 0xB4, 0xEB, 0x46, 0x8C, 0x40, 0x50, 0xE6, 0x91, 0xA5,
  0x6E, 0x01, 0x45, 0xDE, 0xC9, 0xB1, 0x1F, 0x64, 0x54, 0xFA, 0xD9, 0xAB,
  0x4F, 0x70, 0xBA, 0x5B,
};

static unsigned char dh512_g[] = {
    0x02,
};

static unsigned char dh1024_p[] = {
  0xB0, 0xFE, 0xB4, 0xCF, 0xD4, 0x55, 0x07, 0xE7, 0xCC, 0x88, 0x59, 0x0D,
  0x17, 0x26, 0xC5, 0x0C, 0xA5, 0x4A, 0x92, 0x23, 0x81, 0x78, 0xDA, 0x88,
  0xAA, 0x4C, 0x13, 0x06, 0xBF, 0x5D, 0x2F, 0x9E, 0xBC, 0x96, 0xB8, 0x51,
  0x00, 0x9D, 0x0C, 0x0D, 0x75, 0xAD, 0xFD, 0x3B, 0xB1, 0x7E, 0x71, 0x4F,
  0x3F, 0x91, 0x54, 0x14, 0x44, 0xB8, 0x30, 0x25, 0x1C, 0xEB, 0xDF, 0x72,
  0x9C, 0x4C, 0xF1, 0x89, 0x0D, 0x68, 0x3F, 0x94, 0x8E, 0xA4, 0xFB, 0x76,
  0x89, 0x18, 0xB2, 0x91, 0x16, 0x90, 0x01, 0x99, 0x66, 0x8C, 0x53, 0x81,
  0x4E, 0x27, 0x3D, 0x99, 0xE7, 0x5A, 0x7A, 0xAF, 0xD5, 0xEC, 0xE2, 0x7E,
  0xFA, 0xED, 0x01, 0x18, 0xC2, 0x78, 0x25, 0x59, 0x06, 0x5C, 0x39, 0xF6,
  0xCD, 0x49, 0x54, 0xAF, 0xC1, 0xB1, 0xEA, 0x4A, 0xF9, 0x53, 0xD0, 0xDF,
  0x6D, 0xAF, 0xD4, 0x93, 0xE7, 0xBA, 0xAE, 0x9B,
};

static unsigned char dh1024_g[] = {
    0x02,
};

static DH *dh_512 = NULL;

static DH *get_dh512(void)
{
    DH *dh;

    if (dh_512 == NULL) {
	/* No parameter file loaded, use the compiled in parameters */
	if ((dh = DH_new()) == NULL) return(NULL);
	dh->p = BN_bin2bn(dh512_p, sizeof(dh512_p), NULL);
	dh->g = BN_bin2bn(dh512_g, sizeof(dh512_g), NULL);
	if ((dh->p == NULL) || (dh->g == NULL))
	    return(NULL);
	else
	    dh_512 = dh;
    }
    return (dh_512);
}

static DH *dh_1024 = NULL;

static DH *get_dh1024(void)
{
    DH *dh;

    if (dh_1024 == NULL) {
	/* No parameter file loaded, use the compiled in parameters */
	if ((dh = DH_new()) == NULL) return(NULL);
	dh->p = BN_bin2bn(dh1024_p, sizeof(dh1024_p), NULL);
	dh->g = BN_bin2bn(dh1024_g, sizeof(dh1024_g), NULL);
	if ((dh->p == NULL) || (dh->g == NULL))
	    return(NULL);
	else
	    dh_1024 = dh;
    }
    return (dh_1024);
}

/* partly inspired by mod_ssl */

static DH *tmp_dh_cb(SSL *s, int export, int keylength)
{
    DH *dh_tmp = NULL;
   
    if (export) {
	if (keylength == 512)
	    dh_tmp = get_dh512();	/* export cipher */
	else if (keylength == 1024)
	    dh_tmp = get_dh1024();	/* normal */
	else
	    dh_tmp = get_dh1024();	/* not on-the-fly (too expensive) */
					/* so use the 1024bit instead */
    }
    else {
	dh_tmp = get_dh1024();		/* sign-only certificate */
    }
    return (dh_tmp);
}




static int tls_randseeder(const char *source)
{
	int rand_bytes;
	unsigned char buffer[255];

	int var_tls_rand_bytes = 255;
	
	/*
	 * Access the external sources for random seed. We may not be able to
	 * access them again if we are sent to chroot jail, so we must leave
	 * dev: and egd: type sources open.
	 */

	if (source && *source) {
	  if (!strncmp(source, "dev:", 4)) {

	    /*
	     * Source is a random device
	     */
	    int fd = open(source + 4, 0, 0);
	    if (fd < 0)     return -2;
	    if (var_tls_rand_bytes > 255)
	      var_tls_rand_bytes = 255;
	    rand_bytes = read(fd, buffer, var_tls_rand_bytes);
	    close(fd);

	    RAND_seed(buffer, rand_bytes);

	  } else if (!strncmp(source, "egd:", 4)) {
	    /*
	     * Source is a EGD compatible socket
	     */
	    struct sockaddr_un un;
	    int rc;
	    int fd = socket(PF_UNIX, SOCK_STREAM, 0);

	    if (fd < 0) return -1; /* URGH.. */

	    memset(&un, 0, sizeof(un));
	    un.sun_family = AF_UNIX;
	    strncpy(un.sun_path, source+4, sizeof(un.sun_path));
	    un.sun_path[sizeof(un.sun_path)-1] = 0;
	    for (;;) {
	      rc = connect(fd, (struct sockaddr *)&un, sizeof(un));
	      if (rc < 0 && (errno == EWOULDBLOCK || errno == EINTR || errno == EINPROGRESS))
		continue;
	      break;
	    }

	    if (rc < 0) {
	      close(fd);
	      return -2;
	    }
	    if (var_tls_rand_bytes > 255)
	      var_tls_rand_bytes = 255;

	    buffer[0] = 1;
	    buffer[1] = var_tls_rand_bytes;

	    if (write(fd, buffer, 2) != 2) {
	      close(fd);
	      return -3;
	    }

	    if (read(fd, buffer, 1) != 1) {
	      close(fd);
	      return -4;
	    }

	    rand_bytes = buffer[0];
	    rc = read(fd, buffer, rand_bytes);
	    close(fd);

	    if (rc != rand_bytes)
	      return -5;

	    RAND_seed(buffer, rand_bytes);

	  } else {
	    rand_bytes = RAND_load_file(source, var_tls_rand_bytes);
	  }
	} else
	  return -99; /* Bad call! */

	return 0; /* Success.. */
}

 /*
  * This is the setup routine for the SSL server. As smtpd might be called
  * more than once, we only want to do the initialization one time.
  *
  * The skeleton of this function is taken from OpenSSL apps/s_server.c.
  */

static int tls_serverengine = 0;
static SSL_CTX * ssl_ctx;

int
tls_init_serverengine(verifydepth, askcert, requirecert)
     int verifydepth;
     int askcert;
     int requirecert;
{
	int     off = 0;
	int     verify_flags;
	const char   *CApath;
	const char   *CAfile;
	const char   *s_cert_file;
	const char   *s_key_file;
	const char   *s_dcert_file;
	const char   *s_dkey_file;

	if (tls_serverengine)
	  return (0);				/* already running */

	if (OCP->tls_loglevel >= 1)
	  type(NULL,0,NULL,"starting TLS engine");
	
	/*
	 * Initialize the OpenSSL library by the book!
	 * To start with, we must initialize the algorithms.
	 * We want cleartext error messages instead of just error codes, so we
	 * load the error_strings.
	 */
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
	
#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
	/*
	 * Side effect, call a non-existing function to disable TLS usage with
	 * an outdated OpenSSL version. There is a security reason
	 * (verify_result is not stored with the session data).
	 */
	needs_openssl_095_or_later();
#endif


	/*
	 * Initialize the PRNG Pseudo Random Number Generator with some seed.
	 */

	if (1) {
	  /*
	   * Initialize the PRNG Pseudo Random Number Generator with some seed.
	   */
	  tls_randseed.pid  = getpid();
	  tls_randseed.ppid = getppid();
	  gettimeofday(&tls_randseed.tv, NULL);
	  RAND_seed(&tls_randseed, sizeof(tls_randseed));
	}

	/*
	 * Access the external sources for random seed.
	 * We will only query them once, this should be sufficient.
	 * For reliability, we don't consider failure to access the additional
	 * source fatal, as we can run happily without it (considering that we
	 * still have the exchange-file). We also don't care how much entropy
	 * we get back, as we must run anyway. We simply stir in the buffer
	 * regardless how many bytes are actually in it.
	 */

	while ( 1 ) {

	  /* Parametrized version ? */
	  if (OCP->tls_random_source &&
	      tls_randseeder(OCP->tls_random_source) >= 0)
	    break;
	  
	  /* How about  /dev/urandom  ?  */
	  if (tls_randseeder("dev:/dev/urandom") >= 0) break;

	  /* How about  EGD at /var/run/egd-seed  ?  */
	  if (tls_randseeder("egd:/var/run/egd-pool") >= 0) break;

	  break;
	}

	if (1) {
	  /*
	   * Initialize the PRNG Pseudo Random Number Generator with some seed.
	   */
	  tls_randseed.pid = getpid();
	  tls_randseed.ppid = getppid();
	  gettimeofday(&tls_randseed.tv, NULL);
	  RAND_seed(&tls_randseed, sizeof(tls_randseed));
	}

	/*
	 * The SSL/TLS speficications require the client to send a message in
	 * the oldest specification it understands with the highest level it
	 * understands in the message.
	 * Netscape communicator can still communicate with SSLv2 servers, so
	 * it sends out a SSLv2 client hello. To deal with it, our server must
	 * be SSLv2 aware (even if we don´t like SSLv2), so we need to have the
	 * SSLv23 server here. If we want to limit the protocol level, we can
	 * add an option to not use SSLv2/v3/TLSv1 later.
	 */
	ssl_ctx = SSL_CTX_new(SSLv23_server_method());
	if (ssl_ctx == NULL) {
	  tls_print_errors();
	  return (-1);
	}

	/*
	 * Here we might set SSL_OP_NO_SSLv2, SSL_OP_NO_SSLv3, SSL_OP_NO_TLSv1.
	 * Of course, the last one would not make sense, since RFC2487 is only
	 * defined for TLS, but we also want to accept Netscape communicator
	 * requests, and it only supports SSLv3.
	 */
	off |= SSL_OP_ALL;		/* Work around all known bugs */
	SSL_CTX_set_options(ssl_ctx, off);

	/*
	 * Set the info_callback, that will print out messages during
	 * communication on demand.
	 */
	SSL_CTX_set_info_callback(ssl_ctx, apps_ssl_info_callback);


	/*
	 * Set the list of ciphers, if explicitely given; otherwise the
	 * (reasonable) default list is kept.
	 */
	if (OCP->tls_cipherlist) {
	  if (SSL_CTX_set_cipher_list(ssl_ctx, OCP->tls_cipherlist) == 0) {
	    tls_print_errors();
	    return (-1);
	  }
	}

	/*
	 * Now we must add the necessary certificate stuff: A server key, a
	 * server certificate, and the CA certificates for both the server
	 * cert and the verification of client certificates.
	 * As provided by OpenSSL we support two types of CA certificate
	 * handling:
	 *
	 * One possibility is to add all CA certificates to one large CAfile,
	 * the other possibility is a directory pointed to by CApath,
	 * containing seperate files for each CA pointed on by softlinks
	 * named by the hash values of the certificate.
	 * The first alternative has the advantage, that the file is opened and
	 * read at startup time, so that you don´t have the hassle to maintain
	 * another copy of the CApath directory for chroot-jail. On the other
	 * hand, the file is not really readable.
	 */

	if (!OCP->tls_CAfile || *OCP->tls_CAfile == 0)
	  CAfile = NULL;
	else
	  CAfile = OCP->tls_CAfile;
	if (!OCP->tls_CApath || *OCP->tls_CApath == 0)
	  CApath = NULL;
	else
	  CApath = OCP->tls_CApath;
	
	/*
	 * Now we load the certificate and key from the files and check,
	 * whether the cert matches the key (internally done by
	 * set_cert_stuff().   We cannot run without.
	 */

	if (OCP->tls_ask_cert && (!CApath && !CAfile)) {
	  type(NULL,0,NULL,"TLS engine: No CA certificate file/directory defined, and asking for client certs");
	  return (-1);
	}

	if ((!SSL_CTX_load_verify_locations(ssl_ctx, CAfile, CApath)) ||
	    (!SSL_CTX_set_default_verify_paths(ssl_ctx))) {
	  /* Consider this to be fatal ONLY if client
	     certificates really are required ( = hardly ever) */
	  if (OCP->tls_ask_cert && OCP->tls_req_cert) {
	    type(NULL,0,NULL,"TLS engine: cannot load CA data");
	    tls_print_errors();
	    return (-1);
	  }
	}

	/*
	 * Now we load the certificate and key from the files and check,
	 * whether the cert matches the key (internally done by
	 * set_cert_stuff().   We cannot run without (we do not support
	 * ADH anonymous Diffie-Hellman ciphers as of now).
	 * We can use RSA certificates ("cert") and DSA certificates ("dcert"),
	 * both can be made available at the same time. The CA certificates for
	 * both are handled in the same setup already finished.
	 * Which one is used depends on the cipher negotiated (that is:
	 * the first cipher listed by the client which does match the server).
	 * A client with RSA only (e.g. Netscape) will use the RSA certificate
	 * only.
	 * A client with openssl-library will use RSA first if not especially
	 * changed in the cipher setup.
	 */

	if (!OCP->tls_cert_file || *OCP->tls_cert_file == 0)
	  s_cert_file = NULL;
	else
	  s_cert_file = OCP->tls_cert_file;
	if (!OCP->tls_key_file  || *OCP->tls_key_file == 0)
	  s_key_file = NULL;
	else
	  s_key_file = OCP->tls_key_file;

	if (!OCP->tls_dcert_file || *OCP->tls_dcert_file == 0)
	  s_dcert_file = NULL;
	else
	  s_dcert_file = OCP->tls_dcert_file;

	if (!OCP->tls_dkey_file || *OCP->tls_dkey_file == 0)
	  s_dkey_file = NULL;
	else
	  s_dkey_file = OCP->tls_dkey_file;

	if (s_cert_file) {
	  if (!set_cert_stuff(ssl_ctx, s_cert_file, s_key_file)) {
	    type(NULL,0,NULL,"TLS engine: cannot load cert/key data");
	    return (-1);
	  }
	}
	if (s_dcert_file) {
	  if (!set_cert_stuff(ssl_ctx, s_dcert_file, s_dkey_file)) {
	    type(NULL,0,NULL,"TLS engine: cannot load DSA cert/key data");
	    return (-1);
	  }
	}
	if (!s_cert_file && !s_dcert_file) {
	  type(NULL,0,NULL,"TLS engine: do need at least RSA _or_ DSA cert/key data");
	  return (-1);
	}

	/*
	 * Sometimes a temporary RSA key might be needed by the OpenSSL
	 * library. The OpenSSL doc indicates, that this might happen when
	 * export ciphers are in use. We have to provide one, so well, we
	 * just do it.
	 */
	SSL_CTX_set_tmp_rsa_callback(ssl_ctx, tmp_rsa_cb);

	/*
	 * We might also need dh parameters, which can either be
	 * loaded from file (preferred) or we simply take the compiled
	 * in values.
	 *
	 * First, set the callback that will select the values when
	 * requested, then load the (possibly) available DH parameters
	 * from files.
	 *
	 * We are generous with the error handling, since we do have
	 * default values compiled in, so we will not abort but just
	 * log the error message.
	 */

	SSL_CTX_set_tmp_dh_callback(ssl_ctx, tmp_dh_cb);
	
	if (OCP->tls_dh1024_param) {
	  dh_1024 = load_dh_param(OCP->tls_dh1024_param);
	  if (!dh_1024) {
	    type(NULL,0,NULL,"TLS engine: could not load 1024bit DH parameters from given file; will use built-in default value");
	    tls_print_errors();
	  }
	}
	if (OCP->tls_dh512_param) {
	  dh_512 = load_dh_param(OCP->tls_dh512_param);
	  if (!dh_512) {
	    type(NULL,0,NULL,"TLS engine: could not load 512bit DH parameters from given file; will use builtin default value");
	    tls_print_errors();
	  }
	}


	if (s_cert_file && !dh_1024 && !dh_512) {
	  dh_512 = load_dh_param(s_cert_file);
	  type(NULL,0,NULL,"TLS engine: could not load DH parameters from our cert file; old-style certificate ?  will use built-in default value");
	  tls_print_errors();
	}


	/*
	 * If we want to check client certificates, we have to indicate it
	 * in advance. By now we only allow to decide on a global basis.
	 * If we want to allow certificate based relaying, we must ask the
	 * client to provide one with SSL_VERIFY_PEER. The client now can
	 * decide, whether it provides one or not. We can enforce a failure
	 * of the negotiation with SSL_VERIFY_FAIL_IF_NO_PEER_CERT, if we
	 * do not allow a connection without one.
	 * In the "server hello" following the initialization by the
	 * "client hello" the server must provide a list of CAs it is
	 * willing to accept.
	 *
	 * Some clever clients will then select one from the list of available
	 * certificates matching these CAs. Netscape Communicator will present
	 * the list of certificates for selecting the one to be sent, or it 
	 * will issue a warning, if there is no certificate matching the 
	 * available CAs.
	 *
	 * With regard to the purpose of the certificate for relaying, we might
	 * like a later negotiation, maybe relaying would already be allowed
	 * for other reasons, but this would involve severe changes in the
	 * internal postfix logic, so we have to live with it the way it is.
	 */

	verify_depth = verifydepth;
	verify_flags = SSL_VERIFY_NONE;
	if (askcert)
	  verify_flags = ( SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE );
	if (requirecert)
	  verify_flags = ( SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE |
			   SSL_VERIFY_FAIL_IF_NO_PEER_CERT );

	SSL_CTX_set_verify(ssl_ctx, verify_flags, verify_callback);
	SSL_CTX_set_client_CA_list(ssl_ctx, SSL_load_client_CA_file(CAfile));
	


#ifdef HAVE_DISTCACHE
	tls_scache_init(ssl_ctx);
#endif

	tls_serverengine = 1;
	return (0);
}


/*
 * Shut down the TLS connection, that does mean: remove all the information
 * and reset the flags! This is needed if the actual running smtpd is to
 * be restarted. We do not give back any value, as there is nothing to
 * be reported.
 * Since our session cache is external, we will remove the session from
 * memory in any case. The SSL_CTX_flush_sessions might be redundant here,
 * I however want to make sure nothing is left.
 * RFC2246 requires us to remove sessions if something went wrong, as
 * indicated by the "failure" value, so we remove it from the external
 * cache, too. 
 */

static void
tls_stop_servertls(SS, failure)
     SmtpState *SS;
     int failure;
{
    type(NULL,0,NULL,"TLS stopping; mode was: %s", SS->sslmode ? "ON" : "OFF");
    if (SS->sslmode) {
	SSL_shutdown(SS->TLS.ssl);
	SSL_clear(SS->TLS.ssl);
    }
    if (SS->TLS.ssl) SSL_free(SS->TLS.ssl);

#define ZCONDFREE(var) if (var) free((void*)(var))

    ZCONDFREE(SS->TLS.protocol);
    ZCONDFREE(SS->TLS.cipher_name);
    ZCONDFREE(SS->TLS.cipher_info);
    ZCONDFREE(SS->TLS.issuer_CN);
    ZCONDFREE(SS->TLS.peer_issuer);
    ZCONDFREE(SS->TLS.peer_CN);
    ZCONDFREE(SS->TLS.peer_subject);
    ZCONDFREE(SS->TLS.peer_fingerprint);

    memset( &SS->TLS, 0, sizeof(SS->TLS));

    SS->sslmode = 0;
}

#if 0
static void tls_reset(SMTPD_STATE *state)
{
    int failure = 0;

    if (state->reason && state->where && strcmp(state->where, SMTPD_AFTER_DOT))
	failure = 1;
#ifdef HAS_SSL
    vstream_fflush(state->client);
    if (state->tls_active)
	tls_stop_servertls(failure);
#endif
    state->tls_active = 0;
    state->tls_peer_subject = NULL;
    state->tls_peer_issuer = NULL;
    state->tls_peer_fingerprint = NULL;
    state->tls_client_CN = NULL;
    state->tls_issuer_CN = NULL;
    state->tls_protocol = NULL;
    state->tls_cipher_name = NULL;
    state->tls_usebits = 0;
    state->tls_algbits = 0;
}
#endif


static int z_rbio_bread __((BIO*, char *, int));
static int
z_rbio_bread(b, out, outl)
	BIO *b;
	char *out;
	int outl;
{
	int ret=0;
	SmtpState *SS = (SmtpState *)b->cb_arg;

	/* type(NULL,0,NULL,"z_bio_bread(b, 0x%p, %d)", out, outl); */

	if (out) {
	  /* errno = 0; */
	  if (SS && SS->s_ungetcbuf >= 0) {
	    *out = SS->s_ungetcbuf;
	    SS->s_ungetcbuf = -1;
	    BIO_clear_retry_flags(b);
	    /* BIO_set_retry_read(b); */
	    return 1;
	  }

	  ret = read (b->num,out,outl);
	  BIO_clear_retry_flags(b);
	  if (ret <= 0) {
	    if (BIO_sock_should_retry(ret))
	      BIO_set_retry_read(b);
	  }
	}
	return(ret);
}

int
tls_start_servertls(SS)
     SmtpState *SS;
{
    int		  sts, j;
    unsigned int  n;
    SSL_SESSION * session;
    SSL_CIPHER  * cipher;
    X509	* peer;
    char	  cbuf[ 4000 ];
    const char  * kp;

    BIO		*wbio, *rbio;
    BIO_METHOD  *rbiomethod_old;
    static BIO_METHOD  rbiomethod_new;

    /*
     * If necessary, setup a new SSL structure for a connection.
     * We keep old ones on closure, so it might not be always necessary.
     * We however reset the old one, just in case.
     */
    if (SS->TLS.ssl) {
      SSL_clear(SS->TLS.ssl);
    } else {
      SS->TLS.ssl = SSL_new(ssl_ctx);
      if (! SS->TLS.ssl) {
	type(SS,0,NULL,"Could not allocate 'con' with SSL_new()");
	return -1;
      }
    }

#if 0
    /*
     * Allocate a new TLScontext for the new connection and get an SSL
     * structure. Add the location of TLScontext to the SSL to later
     * retrieve the information inside the verify_callback().
     */
    TLScontext = (TLScontext_t *)mymalloc(sizeof(TLScontext_t));
    if (!TLScontext) {
      msg_fatal("Could not allocate 'TLScontext' with mymalloc");
    }
    if ((TLScontext->con = (SSL *) SSL_new(ctx)) == NULL) {
	msg_info("Could not allocate 'TLScontext->con' with SSL_new()");
	pfixtls_print_errors();
	myfree((char *)TLScontext);
	return (-1);
    }
    if (!SSL_set_ex_data(TLScontext->con, TLScontext_index, TLScontext)) {
	msg_info("Could not set application data for 'TLScontext->con'");
	pfixtls_print_errors();
	SSL_free(TLScontext->con);
	myfree((char *)TLScontext);
	return (-1);
    }

    /*
     * Set the verification parameters to be checked in verify_callback().
     */
    if (requirecert) {
	verify_flags = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
	verify_flags |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
	TLScontext->enforce_verify_errors = 1;
        SSL_set_verify(TLScontext->con, verify_flags, verify_callback);
    }
    else {
	TLScontext->enforce_verify_errors = 0;
    }
    TLScontext->enforce_CN = 0;

#endif

    /*
     * Now, connect the filedescripter set earlier to the SSL connection
     * (this is for clean UNIX environment, for example windows "sockets"
     *  need somewhat different approach with customized BIO_METHODs.)
     */
    if (!SSL_set_fd(SS->TLS.ssl, SS->outputfd)) {
	type(SS,0,NULL,"SSL_set_fd failed");
	return (-1);
    }


    /*
     * Now we do deep magic in rbio methods.
     * We need to have our own low-level read routine
     * so that we can do ungetc processing properly..
     *
     */
    rbio = SSL_get_rbio(SS->TLS.ssl);
    rbiomethod_old = rbio->method;
    rbiomethod_new = *rbiomethod_old;
    rbiomethod_new.bread = z_rbio_bread;
    rbio->method = &rbiomethod_new;

    BIO_set_callback_arg(rbio, SS);


#if 0
    /*
     * Before really starting anything, try to seed the PRNG a little bit
     * more.
     */
    pfixtls_stir_seed();
    pfixtls_exchange_seed();
#endif

    /*
     * Initialize the SSL connection to accept state. This should not be
     * necessary anymore since 0.9.3, but the call is still in the library
     * and maintaining compatibility never hurts.
     */
    SSL_set_accept_state(SS->TLS.ssl);

    /*
     * If the debug level selected is high enough, all of the data is
     * dumped: 3 will dump the SSL negotiation, 4 will dump everything.
     *
     * We do have an SSL_set_fd() and now suddenly a BIO_ routine is called?
     * Well there is a BIO below the SSL routines that is automatically
     * created for us, so we can use it for debugging purposes.
     */
    /* if (OCP->tls_loglevel >= 3) */
      BIO_set_callback(SSL_get_rbio(SS->TLS.ssl), bio_dump_cb);

    /* Dump the negotiation for loglevels 3 and 4*/
    if (OCP->tls_loglevel >= 3)
	do_dump = 1;

    /*
     * Now we expect the negotiation to begin. This whole process is like a
     * black box for us. We totally have to rely on the routines build into
     * the OpenSSL library. The only thing we can do we already have done
     * by choosing our own callbacks for session caching and certificate
     * verification.
     *
     * Error handling:
     * If the SSL handhake fails, we print out an error message and remove
     * everything that might be there. A session has to be removed anyway,
     * because RFC2246 requires it.
     */
    for (;;) {
	int sslerr, rc, i;
	fd_set rdset, wrset;
	struct timeval tv;
	int wantreadwrite = 0;

    ssl_accept_retry:;

	wbio = SSL_get_wbio(SS->TLS.ssl);
	rbio = SSL_get_rbio(SS->TLS.ssl);

	sts = SSL_accept(SS->TLS.ssl);
	sslerr = SSL_get_error(SS->TLS.ssl, sts);

	switch (sslerr) {

	case SSL_ERROR_WANT_READ:
	    wantreadwrite = -1;
	    sslerr = EAGAIN;
	    break;
	case SSL_ERROR_WANT_WRITE:
	    wantreadwrite =  1;
	    sslerr = EAGAIN;
	    break;

	case SSL_ERROR_WANT_X509_LOOKUP:
	    goto ssl_accept_retry;
	    break;

	case SSL_ERROR_NONE:
	    goto ssl_accept_done;
	    break;

	default:
	    wantreadwrite =  0;
	    break;
	}

	if (BIO_should_read(rbio))
	    wantreadwrite = -1;
	else if (BIO_should_write(wbio))
	    wantreadwrite =  1;

	if (! wantreadwrite) {
	  /* Not proper retry by read or write! */

	ssl_accept_error_bailout:;

	  type(NULL,0,NULL,"SSL_accept error %d/%d", sts, sslerr);

	  tls_print_errors();
	  session = SSL_get_session(SS->TLS.ssl);
	  if (session) {
#if 0
	    remove_clnt_session(session->session_id,
			        session->session_id_length);
#endif
	    SSL_CTX_remove_session(ssl_ctx, session);
	    type(NULL,0,NULL,"SSL session removed");
	  }
	  tls_stop_servertls(SS, 1);
	  return (-1);
	}

	i = SSL_get_fd(SS->TLS.ssl);
	_Z_FD_ZERO(wrset);
	_Z_FD_ZERO(rdset);

	if (wantreadwrite < 0)
	  _Z_FD_SET(i, rdset); /* READ WANTED */
	else if (wantreadwrite > 0)
	  _Z_FD_SET(i, wrset); /* WRITE WANTED */

	tv.tv_sec = 300;
	tv.tv_usec = 0;

	rc = select(i+1, &rdset, &wrset, NULL, &tv);
	sslerr = errno;

	if (rc == 0) {
	  /* TIMEOUT! */
	  sslerr = ETIMEDOUT;
	  goto ssl_accept_error_bailout;
	}

	if (rc < 0) {
	  if (sslerr == EINTR || sslerr == EAGAIN)
	    continue;

	  /* Bug time ?! */
	  goto ssl_accept_error_bailout;
	}
	/* Default is then success for either read, or write.. */
    }

 ssl_accept_done:;



    /* Only loglevel==4 dumps everything */
    if (OCP->tls_loglevel < 4)
	do_dump = 0;
    /*
     * Lets see, whether a peer certificate is available and what is
     * the actual information. We want to save it for later use.
     */
    peer = SSL_get_peer_certificate(SS->TLS.ssl);

    if (peer != NULL) {

        if (SSL_get_verify_result(SS->TLS.ssl) == X509_V_OK)
	  SS->TLS.peer_verified = 1;

	X509_NAME_oneline(X509_get_subject_name(peer),
			  cbuf, sizeof(cbuf));
	if (OCP->tls_loglevel >= 1)
	    type(NULL,0,NULL,"subject=%s", cbuf);
	SS->TLS.peer_subject = strdup(cbuf);

	X509_NAME_oneline(X509_get_issuer_name(peer),
			  cbuf, sizeof(cbuf));
	if (OCP->tls_loglevel >= 1)
	    type(NULL,0,NULL,"issuer=%s", cbuf);
	SS->TLS.peer_issuer = strdup(cbuf);

	if (X509_digest(peer, EVP_md5(), SS->TLS.peer_md, &n)) {
	  unsigned char *md = SS->TLS.peer_md;
	  int k = -1;
	  for (j = 0; j < (int) n; ++j) {
	    cbuf[++k] = hexcodes[(md[j] & 0xf0) >> 4];
	    cbuf[++k] = hexcodes[(md[j] & 0x0f)];
	    cbuf[++k]   = '-';
	  }
	  cbuf[k] = 0;
	  SS->TLS.peer_fingerprint = strdup(cbuf);

	  if (OCP->tls_loglevel >= 1)
	    type(NULL,0,NULL,"fingerprint=%s", SS->TLS.peer_fingerprint);
	}

	X509_NAME_get_text_by_NID(X509_get_subject_name(peer),
				  NID_commonName, cbuf, sizeof(cbuf));
 	SS->TLS.peer_CN = strdup(cbuf);

 	X509_NAME_get_text_by_NID(X509_get_issuer_name(peer),
				  NID_commonName, cbuf, sizeof(cbuf));
 	SS->TLS.issuer_CN = strdup(cbuf);

 	if (OCP->tls_loglevel >= 3)
	  type(NULL,0,NULL, "subject_CN=%s, issuer_CN=%s",
	       SS->TLS.peer_CN ? SS->TLS.peer_CN : "",
	       SS->TLS.issuer_CN ? SS->TLS.issuer_CN : "");

	X509_free(peer);
    }

    /*
     * Finally, collect information about protocol and cipher for logging
     */
    kp = SSL_get_version(SS->TLS.ssl);
    if (kp)
      SS->TLS.protocol = strdup(kp); /* This data belongs to SSL library,
					make a copy of it for ourselves.
					Darryl L. Miles */
    else
      SS->TLS.protocol = NULL;
    cipher = SSL_get_current_cipher(SS->TLS.ssl);
    kp    = SSL_CIPHER_get_name(cipher);
    if (kp)
      SS->TLS.cipher_name = strdup(kp); /* This data belongs to SSL library,
					   make a copy of it for ourselves.
					   Darryl L. Miles */
    else
      SS->TLS.cipher_name = NULL;
    SS->TLS.cipher_usebits = SSL_CIPHER_get_bits(cipher,
						 &SS->TLS.cipher_algbits);

    SS->sslmode = 1;
    type(NULL,0,NULL,"TLS connection established");

    if (cipher)
      sprintf(cbuf, "%s keybits %d/%d version %s",
	      SSL_CIPHER_get_name(cipher),
	      SS->TLS.cipher_usebits, SS->TLS.cipher_algbits,
	      SSL_CIPHER_get_version(cipher));
    else
      strcpy(cbuf,"<no-cipher-in-use!>");
    SS->TLS.cipher_info = strdup(cbuf);
    
    type(NULL,0,NULL,"Cipher: %s", cbuf);

    SSL_set_read_ahead(SS->TLS.ssl, 1); /* Improves performance */

    return (0);
}

void
Z_init __((void))
{
    if (OCP->starttls_ok)
	tls_init_serverengine(OCP->tls_ccert_vd,
			      OCP->tls_ask_cert,
			      OCP->tls_req_cert);
}

void
Z_cleanup(SS)
     SmtpState *SS;
{
    if (SS->sslmode)
	tls_stop_servertls(SS, 0);
}

#ifdef HAVE_DISTCACHE
/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  ssl_scache_dc.c
**  Distributed Session Cache (client support)
*/

/* ====================================================================
 * THIS SOFTWARE IS PROVIDED BY GEOFF THORPE ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL RALF S. ENGELSCHALL OR
 * HIS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

/* Only build this code if it's enabled at configure-time. */

#if !defined(DISTCACHE_CLIENT_API) || (DISTCACHE_CLIENT_API < 0x0001)
#error "You must compile with a more recent version of the distcache-base package"
#endif

/*
 * This cache implementation allows modssl to access 'distcache' servers (or
 * proxies) to facilitate distributed session caching. It is based on code
 * released as open source by Cryptographic Appliances Inc, and was developed by
 * Geoff Thorpe, Steve Robb, and Chris Zimmerman.
 */

/*
**
** High-Level "handlers" as per ssl_scache.c
**
*/

static void ssl_scache_dc_kill(void)
{
  if (dc_ctx)
    DC_CTX_free(dc_ctx);
  dc_ctx = NULL;
}

static DC_CTX *ssl_scache_dc_init()
{
    DC_CTX *ctx;

    if (!OCP->tls_scache_name) return NULL;

    /*
     * Create a session context
     */
#if 0
    /* If a "persistent connection" mode of operation is preferred, you *must*
     * also use the PIDCHECK flag to ensure fork()'d processes don't interlace
     * comms on the same connection as each other. */
#define SESSION_CTX_FLAGS	SESSION_CTX_FLAG_PERSISTENT | \
	    			SESSION_CTX_FLAG_PERSISTENT_PIDCHECK | \
	    			SESSION_CTX_FLAG_PERSISTENT_RETRY | \
	    			SESSION_CTX_FLAG_PERSISTENT_LATE
#else
    /* This mode of operation will open a temporary connection to the 'target'
     * for each cache operation - this makes it safe against fork()
     * automatically. This mode is preferred when running a local proxy (over
     * unix domain sockets) because overhead is negligable and it reduces the
     * performance/stability danger of file-descriptor bloatage. */
#define SESSION_CTX_FLAGS	0
#endif
    ctx = DC_CTX_new(OCP->tls_scache_name, SESSION_CTX_FLAGS);
    if(!ctx) {
      type(NULL,0,NULL,"distributed scache failed to obtain context");
      exit(1);
    }
    type(NULL,0,NULL, "distributed scache context initialised");

    atexit(ssl_scache_dc_kill);

    /* 
     * Success .. we return the cache content to the caller
     * :-)
     */
    return ctx;
}


static int ssl_scache_dc_store(pSession, id, idlen, timeout)
     SSL_SESSION * pSession;
     unsigned char *id;
     int idlen;
     time_t timeout;
{
    unsigned char der[SSL_SESSION_MAX_DER];
    int der_len;
    unsigned char *pder = der;
    DC_CTX *ctx  =  dc_ctx;

    if (!ctx) return FALSE;

    /* Serialise the SSL_SESSION object */
    der_len = i2d_SSL_SESSION(pSession, NULL);
    if (der_len > SSL_SESSION_MAX_DER)
        return FALSE;
    i2d_SSL_SESSION(pSession, &pder);
    /* !@#$%^ - why do we deal with *absolute* time anyway??? */
    timeout -= time(NULL);
    /* Send the serialised session to the distributed cache context */
    if(!DC_CTX_add_session(ctx, id, idlen, der, der_len,
			    (unsigned long)timeout * 1000)) {
	/* ERROR INDICATION! */
	type(NULL,0,NULL, "distributed scache 'add_session' failed");
	return FALSE;
    }
    type(NULL,0,NULL, "distributed scache 'add_session' successful");
    return TRUE;
}

static SSL_SESSION *ssl_scache_dc_retrieve(s, id, idlen)
     SSL *s;
     unsigned char *id;
     int idlen;
{
    unsigned char der[SSL_SESSION_MAX_DER];
    unsigned int der_len;
    SSL_SESSION *pSession;
    unsigned char *pder = der;
    DC_CTX *ctx = dc_ctx;

    if (!ctx) return FALSE;

    /* Retrieve any corresponding session from the distributed cache context */
    if(!DC_CTX_get_session(ctx, id, idlen, der, SSL_SESSION_MAX_DER,
			    &der_len)) {
	type(NULL,0,NULL,"distributed scache 'get_session' MISS");
	return NULL;
    }
    if(der_len > SSL_SESSION_MAX_DER) {
	type(NULL,0,NULL,"distributed scache 'get_session' OVERFLOW");
	return NULL;
    }
    pSession = d2i_SSL_SESSION(NULL, &pder, der_len);
    if(!pSession) {
	type(NULL,0,NULL,"distributed scache 'get_session' CORRUPT");
	return NULL;
    }
    type(NULL,0,NULL,"distributed scache 'get_session' HIT");
    return pSession;
}


static void ssl_scache_dc_remove(s, id, idlen)
     SSL_SESSION *s;
     unsigned char *id;
     int idlen;
{
    DC_CTX *ctx = dc_ctx;

    if (!ctx) return;

    /* Remove any corresponding session from the distributed cache context */
    if(!DC_CTX_remove_session(ctx, id, idlen)) {
	type(NULL,0,NULL, "distributed scache 'remove_session' MISS");
    } else {
	type(NULL,0,NULL, "distributed scache 'remove_session' HIT");
    }
}


#endif

#endif /* - HAVE_OPENSSL */
