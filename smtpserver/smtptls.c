/*
 *  ZMailer smtpserver,  Support for TLS / STARTTLS (RFC 2487)
 *  part of ZMailer.
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

static int do_dump = 0;
static int verify_depth = 1;
static int verify_error = X509_V_OK;

#define CCERT_BUFSIZ 256

static char ccert_subject[CCERT_BUFSIZ];
static char ccert_issuer[CCERT_BUFSIZ];
static unsigned char md[EVP_MAX_MD_SIZE];
static char fingerprint[EVP_MAX_MD_SIZE * 3];

/* We must keep some of info available */
static const char hexcodes[] = "0123456789ABCDEF";

static int start_servertls __((SmtpState *SS));

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

    start_servertls(SS);

    SS->sslwrbuf = emalloc(8192);
    SS->sslwrspace = 8192;
    SS->sslwrin = SS->sslwrout = 0;
}

static int
Z_SSL_flush(SS)
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


int
Z_read(SS, ptr, len)
     SmtpState * SS;
     void *ptr;
     int len;
{
    if (SS->sslmode)
      return SSL_read(SS->ssl, (char*)ptr, len);
    return read(SS->inputfd, (char*)ptr, len);
}

int
Z_pending(SS)
     SmtpState * SS;
{
    if (SS->sslmode)
      return SSL_pending(SS->ssl);
    return 0;
}


int
Z_write(SS, ptr, len)
     SmtpState * SS;
     const void *ptr;
     int len;
{
    int i, rc = 0;
    char *buf = (char *)ptr;

    if (!SS->sslmode)
      return fwrite(ptr, len, 1, SS->outfp);

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

void typeflush(SS)
SmtpState *SS;
{
    if (SS->sslmode)
      Z_SSL_flush(SS);
    else
      fflush(SS->outfp);
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

static int set_cert_stuff __((SSL_CTX * ctx, char *cert_file, char *key_file));

static int
set_cert_stuff(ctx, cert_file, key_file)
     SSL_CTX * ctx;
     char *cert_file, *key_file;
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

/* taken from OpenSSL apps/s_cb.c */

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
    int     verify_flags = SSL_VERIFY_NONE;
    char   *CApath;
    char   *CAfile;
    char   *s_cert_file;
    char   *s_key_file;

    if (tls_serverengine)
	return (0);				/* already running */

    if (tls_loglevel >= 1)
	type(NULL,0,NULL,"starting TLS engine");

    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    if (ssl_ctx == NULL) {
	tls_print_errors();
	return (-1);
    }
    SSL_CTX_set_quiet_shutdown(ssl_ctx, 1);

    SSL_CTX_set_options(ssl_ctx, off);
    SSL_CTX_set_info_callback(ssl_ctx, apps_ssl_info_callback);
    SSL_CTX_sess_set_cache_size(ssl_ctx, 128);

    if (tls_CAfile && strlen(tls_CAfile) == 0)
	CAfile = NULL;
    else
	CAfile = tls_CAfile;
    if (tls_CApath && strlen(tls_CApath) == 0)
	CApath = NULL;
    else
	CApath = tls_CApath;

    if ((!SSL_CTX_load_verify_locations(ssl_ctx, CAfile, CApath)) ||
	(!SSL_CTX_set_default_verify_paths(ssl_ctx))) {
	type(NULL,0,NULL,"TLS engine: cannot load CA data");
	tls_print_errors();
	return (-1);
    }
    if (tls_cert_file && strlen(tls_cert_file) == 0)
	s_cert_file = NULL;
    else
	s_cert_file = tls_cert_file;
    if (tls_key_file && strlen(tls_key_file) == 0)
	s_key_file = NULL;
    else
	s_key_file = tls_key_file;

    if (!set_cert_stuff(ssl_ctx, s_cert_file, s_key_file)) {
	type(NULL,0,NULL,"TLS engine: cannot load cert/key data");
	return (-1);
    }
    SSL_CTX_set_tmp_rsa_callback(ssl_ctx, tmp_rsa_cb);

    verify_depth = verifydepth;
    if (askcert)
	verify_flags |= SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
    if (requirecert)
	verify_flags |= SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
	    | SSL_VERIFY_CLIENT_ONCE;
    SSL_CTX_set_verify(ssl_ctx, verify_flags, verify_callback);

    SSL_CTX_set_client_CA_list(ssl_ctx, SSL_load_client_CA_file(CAfile));

    tls_serverengine = 1;
    return (0);
}


 /*
  * Shut down the TLS connection, that does mean: remove all the information
  * and reset the flags! This is needed if the actual running smtpd is to
  * be restarted. We do not give back any value, as there is nothing to
  * be reported.
  */

static void
tls_stop_servertls(SS)
     SmtpState *SS;
{
    type(NULL,0,NULL,"TLS stopping; mode was: %s", SS->sslmode ? "ON" : "OFF");
    if (SS->sslmode) {
	SSL_shutdown(SS->ssl);
	SSL_clear(SS->ssl);
    }
    if (SS->ssl)
      SSL_free(SS->ssl);
    SS->ssl = NULL;

    SS->tls_ccert_subject     = NULL;
    SS->tls_ccert_issuer      = NULL;
    SS->tls_ccert_fingerprint = NULL;

    SS->sslmode = 0;
}

static int
start_servertls(SS)
     SmtpState *SS;
{
    int		  sts, j;
    unsigned int  n;
    SSL_SESSION * session;
    X509	* peer;

    SS->ssl = (SSL *) SSL_new(ssl_ctx);
    SSL_clear(SS->ssl);

    if (!SSL_set_fd(SS->ssl, fileno(SS->outfp))) {
	type(SS,0,NULL,"SSL_set_fd failed");
	return (-1);
    }
    /*
     * This is the actual handshake routine. It will do all the negotiations
     * and will check the client cert etc.
     */
    SSL_set_accept_state(SS->ssl);

    /*
     * We do have an SSL_set_fd() and now suddenly a BIO_ routine is called?
     * Well there is a BIO below the SSL routines that is automatically
     * created for us, so we can use it for debugging purposes.
     */
    if (tls_loglevel >= 3)
	BIO_set_callback(SSL_get_rbio(SS->ssl), bio_dump_cb);

    /* Dump the negotiation for loglevels 3 and 4*/
    if (tls_loglevel >= 3)
	do_dump = 1;
    if ((sts = SSL_accept(SS->ssl)) <= 0) {
	type(NULL,0,NULL,"SSL_accept error %d", sts);
	session = SSL_get_session(SS->ssl);
	if (session) {
	    SSL_CTX_remove_session(ssl_ctx, session);
	    type(NULL,0,NULL,"SSL session removed");
	}
	if (SS->ssl)
	    SSL_free(SS->ssl);
	SS->ssl = NULL;
	return (-1);
    }
    /* Only loglevel==4 dumps everything */
    if (tls_loglevel < 4)
	do_dump = 0;
    /*
     * Lets see, whether a peer certificate is available and what is
     * the actual information. We want to save it for later use.
     */
    peer = SSL_get_peer_certificate(SS->ssl);
    if (peer != NULL) {
	X509_NAME_oneline(X509_get_subject_name(peer),
			  ccert_subject, CCERT_BUFSIZ);
	if (tls_loglevel >= 1)
	    type(NULL,0,NULL,"subject=%s", ccert_subject);
	SS->tls_ccert_subject = ccert_subject;
	X509_NAME_oneline(X509_get_issuer_name(peer),
			  ccert_issuer, CCERT_BUFSIZ);
	if (tls_loglevel >= 1)
	    type(NULL,0,NULL,"issuer=%s", ccert_issuer);
	SS->tls_ccert_issuer = ccert_issuer;
	if (X509_digest(peer, EVP_md5(), md, &n)) {
	    for (j = 0; j < (int) n; j++) {
		fingerprint[j * 3] = hexcodes[(md[j] & 0xf0) >> 4];
		fingerprint[(j * 3) + 1] = hexcodes[(md[j] & 0x0f)];
		if (j + 1 != (int) n)
		    fingerprint[(j * 3) + 2] = '_';
		else
		    fingerprint[(j * 3) + 2] = '\0';
	    }
	    if (tls_loglevel >= 1)
		type(NULL,0,NULL,"fingerprint=%s", fingerprint);
	    SS->tls_ccert_fingerprint = fingerprint;
	}
	X509_free(peer);
    }
    SS->sslmode = 1;
    type(NULL,0,NULL,"TLS connection established");
    {
      SSL_CIPHER *cp = SSL_get_current_cipher(SS->ssl);
      int n, cb;
      static char cbuf[2000];

      if (cp) {
	cb = SSL_CIPHER_get_bits(cp, &n);
	sprintf(cbuf, "%s keybits %d version %s",
		SSL_CIPHER_get_name(cp), cb, SSL_CIPHER_get_version(cp));
      } else {
	strcpy(cbuf,"<no-cipher-in-use!>");
      }
      SS->tls_cipher_info = cbuf;
      type(NULL,0,NULL,"Cipher: %s",cbuf);
    }

    SSL_set_read_ahead(SS->ssl, 1); /* Improves performance */

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
	tls_stop_servertls(SS);
}
#endif /* - HAVE_OPENSSL */
