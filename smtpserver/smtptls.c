/*
 *  ZMailer smtpserver,  Support for TLS / STARTTLS (RFC 2487)
 *  part of ZMailer.
 *
 *  Contains ALSO code for SMTP Transport Agent!
 *
 *  by Matti Aarnio <mea@nic.funet.fi> 1999
 *
 *  Reusing TLS code for POSTFIX by:
 *     Lutz Jaenicke <Lutz.Jaenicke@aet.TU-Cottbus.DE>
 *  URL  http://www.aet.tu-cottbus.de/personen/jaenicke/pfixtls/
 *
 */

#include "smtpserver.h"

#ifdef HAVE_OPENSSL

/*
 * We are saving sessions to disc, we want to make sure, that the lenght of
 * the filename is somehow limited. When saving client sessions, the hostname
 * is transformed to an MD5-hash, which is defined by RFC to be 16 bytes long.
 * The length of the actual session id is however not defined in RFC2246.
 * OpenSSL defines a SSL_MAX_SSL_SESSION_ID_LENGTH of 32, but nobody
 * guarantees, that a client might not try to resume a session with a longer
 * session id. So to make sure, we define an upper bound of 32.
 */

static const char MAIL_TLS_SRVR_CACHE[] = "TLSsrvrcache";
static const int id_maxlength = 32;	/* Max ID length in bytes */
static char server_session_id_context[] = "ZMailer/TLS"; /* anything will do */

static int do_dump = 0;
static int verify_depth = 1;
static int verify_error = X509_V_OK;

int tls_scache_timeout = 3600;
int tls_use_scache = 0;

/* We must keep some of info available */
static const char hexcodes[] = "0123456789ABCDEF";

const char *tls_random_source = NULL;

/* Structure used for random generator seeding.. */
struct _randseed {
	int pid;
	int ppid;
	struct timeval tv;
} tls_randseed;


static void
mail_queue_path(buf, subdir, filename)
     char *buf;
     char *subdir;
     char *filename;
{
  const char *po = getzenv("POSTOFFICE");
  if (!po) po = POSTOFFICE;

  sprintf(buf, "%s/%s/%s", po, subdir, filename);
}

void
smtp_starttls(SS, buf, cp)
     SmtpState *SS;
     const char *buf, *cp;
{
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
    type(SS, 220, NULL, "Ready to start TLS");
    typeflush(SS);
    if (SS->mfp != NULL) {
      clearerr(SS->mfp);
      mail_abort(SS->mfp);
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
	SS->mfp = NULL;
      }
      exit(2);
    }
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
    if (SS->sslmode)
      return SSL_pending(SS->TLS.ssl);
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



/*
 * Callback to retrieve a session from the external session cache.
 */
static SSL_SESSION *get_session_cb(SSL *ssl, unsigned char *SessionID,
				   int length, int *copy)
{
    SSL_SESSION *session;
    char *buf;
    FILE *fp;
    struct stat st;
    char *idstring;
    int n;
    int uselength;
    int verify_result;

    if (length > id_maxlength)
	uselength = id_maxlength;	/* Limit length of ID */
    else
	uselength = length;

    idstring = (char *)malloc(2 * uselength + 1);
    if (!idstring) {
	type(NULL,0,NULL, "could not allocate memory for IDstring");
	return (NULL);
    }

    for(n=0 ; n < uselength ; n++)
	sprintf(idstring + 2 * n, "%02X", SessionID[n]);
    if (tls_loglevel >= 3)
      type(NULL,0,NULL, "Trying to reload Session from disc: %s", idstring);

    /*
     * The constant "100" is taken from mail_queue.c and also used there.
     * It must hold the name the postfix spool directory (if not chrooted)
     * and the hash directory forest.
     */
    buf = malloc(100 + 2 * uselength + 1);
    mail_queue_path(buf, MAIL_TLS_SRVR_CACHE, idstring);

    /*
     * Try to read the session from the file. If the file exists, but its
     * mtime is so old, that the session has already expired, we don´t
     * waste time anymore, we rather delete the session file immediately.
     */
    session = NULL;
    if (stat(buf, &st) == 0) {
	if (st.st_mtime + tls_scache_timeout < time(NULL))
            unlink(buf);
	else if ((fp = fopen(buf, "r")) != 0) {
	    if (fscanf(fp, "%d", &verify_result) <= 0)
		verify_result = X509_V_ERR_APPLICATION_VERIFICATION;
	    SSL_set_verify_result(ssl, verify_result);
	    session = PEM_read_SSL_SESSION(fp, NULL, NULL, NULL);
	    fclose(fp);
	}
    }

    free(buf);
    free(idstring);

    if (session && (tls_loglevel >= 3))
      type(NULL,0,NULL, "Successfully reloaded session from disc");

    return (session);
}


/*
 * Save a new session to the external cache
 */
static int new_session_cb(SSL *ssl, SSL_SESSION *session)
{
    char *buf;
    FILE *fp;
    char *myname = "new_session_cb";
    char *idstring;
    int n;
    int uselength;
    int fd;
    int success;

    if (session->session_id_length > id_maxlength)
	uselength = id_maxlength;	/* Limit length of ID */
    else
	uselength = session->session_id_length;

    idstring = (char *)malloc(2 * uselength + 1);
    if (!idstring) {
      type(NULL,0,NULL, "could not allocate memory for IDstring");
      return -1;
    }

    for(n=0 ; n < uselength ; n++)
	sprintf(idstring + 2 * n, "%02X", session->session_id[n]);

    if (tls_loglevel >= 3)
      type(NULL,0,NULL, "Trying to save Session to disc: %s", idstring);

    buf = malloc(100 + 2 * uselength + 1);
    mail_queue_path(buf, MAIL_TLS_SRVR_CACHE, idstring);

    /*
     * Now open the session file in exclusive and create mode. If it
     * already exists, we don´t touch it and silently omit the save.
     * We cannot use Wietse´s VSTREAM code here, as PEM_write uses
     * C´s normal buffered library and we better don´t mix.
     * The return value of PEM_write_SSL_SESSION is nowhere documented,
     * but from the source it seems to be something like the number
     * of lines or bytes written. Anyway, success is positiv and
     * failure is zero.
     */
    if ((fd = open(buf, O_WRONLY | O_CREAT | O_EXCL, 0600)) >= 0) {
      if ((fp = fdopen(fd, "w")) == 0) {
	type(NULL,0,NULL, "%s: could not fdopen %s: %s",
	     myname, buf, strerror(errno));
	return -1;
      }
      fprintf(fp, "%lu\n", (unsigned long)SSL_get_verify_result(ssl));
      success = PEM_write_SSL_SESSION(fp, session);
      fclose(fp);
      if (success == 0)
	unlink(buf);
      else if (tls_loglevel >= 3)
	type(NULL,0,NULL, "Successfully saved session to disc");
    }

    free(buf);
    free(idstring);

    return (0);
}


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
	if (tls_loglevel >= 2)
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
    if (tls_loglevel >= 1)
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
    if (tls_loglevel >= 1)
	type(NULL,0,NULL,"verify return:%d", ok);
    return (ok);
}

/* taken from OpenSSL apps/s_cb.c */

static void apps_ssl_info_callback __((SSL * s, int where, int ret));

static void
apps_ssl_info_callback(s, where, ret)
     SSL * s;
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
	if (tls_loglevel >= 2)
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
static SSL_CTX *ssl_ctx = NULL;

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

	if (tls_loglevel >= 1)
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
	  if (tls_random_source && tls_randseeder(tls_random_source) >= 0)
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
	if (tls_cipherlist) {
	  if (SSL_CTX_set_cipher_list(ssl_ctx, tls_cipherlist) == 0) {
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

	if (!tls_CAfile || *tls_CAfile == 0)
	  CAfile = NULL;
	else
	  CAfile = tls_CAfile;
	if (!tls_CApath || *tls_CApath == 0)
	  CApath = NULL;
	else
	  CApath = tls_CApath;
	
	/*
	 * Now we load the certificate and key from the files and check,
	 * whether the cert matches the key (internally done by
	 * set_cert_stuff().   We cannot run without.
	 */

	if ((!SSL_CTX_load_verify_locations(ssl_ctx, CAfile, CApath)) ||
	    (!SSL_CTX_set_default_verify_paths(ssl_ctx))) {
	  type(NULL,0,NULL,"TLS engine: cannot load CA data");
	  tls_print_errors();
	  return (-1);

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

	if (!tls_cert_file || *tls_cert_file == 0)
	  s_cert_file = NULL;
	else
	  s_cert_file = tls_cert_file;
	if (!tls_key_file  || *tls_key_file == 0)
	  s_key_file = NULL;
	else
	  s_key_file = tls_key_file;

	if (!tls_dcert_file || *tls_dcert_file == 0)
	  s_dcert_file = NULL;
	else
	  s_dcert_file = tls_dcert_file;

	if (!tls_dkey_file || *tls_dkey_file == 0)
	  s_dkey_file = NULL;
	else
	  s_dkey_file = tls_dkey_file;

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
	 * We might also need dh parameters, which can either be loaded from
	 * file (preferred) or we simply take the compiled in values.
	 * First, set the callback that will select the values when requested,
	 * then load the (possibly) available DH parameters from files.
	 * We are generous with the error handling, since we do have default
	 * values compiled in, so we will not abort but just log the error
	 * message.
	 */

	SSL_CTX_set_tmp_dh_callback(ssl_ctx, tmp_dh_cb);
	
	if (tls_dh1024_param) {
	  dh_1024 = load_dh_param(tls_dh1024_param);
	  if (!dh_1024) {
	    type(NULL,0,NULL,"TLS engine: cannot load 1024bit DH parameters");
	    tls_print_errors();
	  }
	}
	if (tls_dh512_param) {
	  dh_512 = load_dh_param(tls_dh512_param);
	  if (!dh_512) {
	    type(NULL,0,NULL,"TLS engine: cannot load 512bit DH parameters");
	    tls_print_errors();
	  }
	}


	if (s_cert_file && !dh_1024 && !dh_512) {
	  dh_512 = load_dh_param(s_cert_file);
	  type(NULL,0,NULL,"TLS engine: cannot load DH parameters from our cert file");
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
	SSL_CTX_set_timeout(ssl_ctx, tls_scache_timeout);
	{
	  static char server_session_id_context[] = "ZMailer/Smtpserver/TLS"; /* anything will do */

	  SSL_CTX_set_session_id_context(ssl_ctx,
					 (void*)&server_session_id_context,
					 sizeof(server_session_id_context));
	}


#if 0
	/*
	 * The session cache is realized by an external database file, that
	 * must be opened before going to chroot jail. Since the session cache
	 * data can become quite large, "[n]dbm" cannot be used as it has a
	 * size limit that is by far too small.
	 */
	if (*var_smtpd_tls_scache_db) {
	  /*
	   * Insert a test against other dbms here, otherwise while writing
	   * a session (content to large), we will receive a fatal error!
	   */
	  if (strncmp(var_smtpd_tls_scache_db, "sdbm:", 5))
	    msg_warn("Only sdbm: type allowed for %s",
		     var_smtpd_tls_scache_db);
	  else
	    scache_db = dict_open(var_smtpd_tls_scache_db, O_RDWR,
				  ( DICT_FLAG_DUP_REPLACE | DICT_FLAG_LOCK |
				    DICT_FLAG_SYNC_UPDATE ));
	  if (scache_db) {
	    SSL_CTX_set_session_cache_mode(ctx,
					   ( SSL_SESS_CACHE_SERVER |
					     SSL_SESS_CACHE_NO_AUTO_CLEAR ));
	    SSL_CTX_sess_set_get_cb(ctx, get_session_cb);
	    SSL_CTX_sess_set_new_cb(ctx, new_session_cb);
	    SSL_CTX_sess_set_remove_cb(ctx, remove_session_cb);
	  }
	  else
	    msg_warn("Could not open session cache %s",
		     var_smtpd_tls_scache_db);
	}
	
	/*
	 * Finally create the global index to access TLScontext information
	 * inside verify_callback.
	 */
	TLScontext_index = SSL_get_ex_new_index(0, "TLScontext ex_data index",
						NULL, NULL, NULL);
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


int
tls_start_servertls(SS)
     SmtpState *SS;
{
    int		  sts, j;
    unsigned int  n;
    SSL_SESSION * session;
    SSL_CIPHER  * cipher;
    X509	* peer;
    char	cbuf[4000];

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
    if (tls_loglevel >= 3)
	BIO_set_callback(SSL_get_rbio(SS->TLS.ssl), bio_dump_cb);

    /* Dump the negotiation for loglevels 3 and 4*/
    if (tls_loglevel >= 3)
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
	BIO *wbio, *rbio;
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
    if (tls_loglevel < 4)
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
	if (tls_loglevel >= 1)
	    type(NULL,0,NULL,"subject=%s", cbuf);
	SS->TLS.peer_subject = strdup(cbuf);

	X509_NAME_oneline(X509_get_issuer_name(peer),
			  cbuf, sizeof(cbuf));
	if (tls_loglevel >= 1)
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

	  if (tls_loglevel >= 1)
	    type(NULL,0,NULL,"fingerprint=%s", SS->TLS.peer_fingerprint);
	}

	X509_NAME_get_text_by_NID(X509_get_subject_name(peer),
				  NID_commonName, cbuf, sizeof(cbuf));
 	SS->TLS.peer_CN = strdup(cbuf);

 	X509_NAME_get_text_by_NID(X509_get_issuer_name(peer),
				  NID_commonName, cbuf, sizeof(cbuf));
 	SS->TLS.issuer_CN = strdup(cbuf);

 	if (tls_loglevel >= 3)
	  type(NULL,0,NULL, "subject_CN=%s, issuer_CN=%s",
	       SS->TLS.peer_CN ? SS->TLS.peer_CN : "",
	       SS->TLS.issuer_CN ? SS->TLS.issuer_CN : "");

	X509_free(peer);
    }

    /*
     * Finally, collect information about protocol and cipher for logging
     */
    SS->TLS.protocol = SSL_get_version(SS->TLS.ssl);
    cipher = SSL_get_current_cipher(SS->TLS.ssl);
    SS->TLS.cipher_name    = SSL_CIPHER_get_name(cipher);
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
    if (starttls_ok)
	tls_init_serverengine(tls_ccert_vd,tls_ask_cert,tls_req_cert);
}

void
Z_cleanup(SS)
     SmtpState *SS;
{
    if (SS->sslmode)
	tls_stop_servertls(SS, 0);
}
#endif /* - HAVE_OPENSSL */
