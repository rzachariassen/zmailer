/* This is heavily bastardized TLS code for SMTP client (POSTFIX) by:
 *	Lutz Jaenicke
 *	BTU Cottbus
 *	Allgemeine Elektrotechnik
 *	Universitaetsplatz 3-4
 *	D-03044 Cottbus, Germany
 *
 * Adaptation to ZMailer is by Matti Aarnio <mea@nic.funet.fi> (c) 1999-2003
 */

#include "smtp.h"

extern int timeout_tcpw;

/* Global variables -- BOO! */

static FILE *vlog = NULL;

/* more further down (in OpenSSL specific code..) */

#ifdef HAVE_STDARG_H
#ifdef __STDC__
void msg_info(SmtpState *SS, char *fmt, ...)
#else /* Not ANSI-C */
void msg_info(SS, fmt)
	SmtpState *SS;
	char *fmt;
#endif
#else
/* VARARGS */
void
msg_info(SS, va_alist)
	SmtpState *SS;
	va_dcl
#endif
{
	va_list	ap;
	FILE *fp;
#ifdef HAVE_STDARG_H
	va_start(ap, fmt);
#else
	char *fmt;
	va_start(ap);
	fmt = va_arg(ap, char *);
#endif

	if (vlog) {
	  fp = vlog;
	  fprintf(fp, "# ");
	} else if (logfp) {
	  fp = logfp;
	  fprintf(fp, "%s#\t", logtag());
	} else {
	  fp = stderr; /* No LOGFP, to STDERR with DBGdiag prefix.. */
	  fprintf(fp, "# ");
	}

#ifdef	HAVE_VPRINTF
	vfprintf(fp, fmt, ap);
#else	/* !HAVE_VPRINTF */
 ERROR:ERROR:ERROR:No 
#endif	/* HAVE_VPRINTF */

	fprintf(fp,"\n");
	fflush(fp);

	va_end(ap);
}



#ifdef HAVE_OPENSSL

/* Global variables -- BOO! */

static int TLScontext_index = -1;
static int TLSpeername_index = -1;
static int tls_clientengine = 0;

/* Other global static data */
static const char MAIL_TLS_CLNT_CACHE[] = "TLSclntcache";
/*
 * When saving sessions, we want to make sure, that the lenght of
 * the key is somehow limited. When saving client sessions, the hostname
 * is used as key. According to HP-UX 10.20, MAXHOSTNAMELEN=64. Maybe new
 * standards will increase this value, but as this will break
 * compatiblity with existing implementations, we won't see this
 * for long. We therefore choose a limit of 64 bytes.
 * The length of the (TLS) session id can be up to 32 bytes according to
 * RFC2246, so it fits well into the 64bytes limit.
 */
static const int id_maxlength = 32;	/* Max ID length in bytes */

/* Configuration variables */

static int do_dump = 0;

int	tls_scache_timeout = 3600;	/* One hour */
int	tls_use_scache     = 0;

extern int demand_TLS_mode;
extern int tls_available;

const char *tls_random_source;
const char *tls_cipherlist;

const char *tls_CAfile;
const char *tls_CApath;
const char *tls_cert_file;
const char *tls_key_file;
const char *tls_dcert_file;
const char *tls_dkey_file;

int	tls_use_read_ahead = 0;
int	tls_protocol_tlsv1_only = 0;
int     tls_enforce_peername = 0;

int	tls_loglevel = 0;


/* Structure used for random generator seeding.. */
struct _randseed {
	int pid;
	int ppid;
	struct timeval tv;
} tls_randseed;


static char *zdupnstr(const void *p, const int len)
{
	char *dup = malloc(len+1);
	if (!dup) return NULL;
	memcpy(dup, p, len);
	dup[len] = 0; /* return a 0-terminated string */

	return dup;
}


void mail_queue_path(buf, subdir, filename)
     char *buf;
     char *subdir;
     char *filename;
{
  const char *po = getzenv("POSTOFFICE");
  if (!po) po = POSTOFFICE;

  sprintf(buf, "%s/%s/%s", po, subdir, filename);
}


/* skeleton taken from OpenSSL crypto/err/err_prn.c */

static void tls_print_errors(SmtpState *SS)
{
    unsigned long l;
    char    buf[256];
    const char   *file;
    const char   *data;
    int     line;
    int     flags;
    unsigned long es;

    es = CRYPTO_thread_id();
    while ((l = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
      if (flags & ERR_TXT_STRING)
	msg_info(SS, "%lu:%s:%s:%d:%s:", es, ERR_error_string(l, buf),
		 file, line, data);
      else
	msg_info(SS, "%lu:%s:%s:%d:", es, ERR_error_string(l, buf),
		 file, line);
    }
}



/*
 * Function to perform the handshake for SSL_accept(), SSL_connect(),
 * and SSL_shutdown().
 * Call the underlying network_biopair_interop-layer to make sure the
 * write buffer is flushed after every operation (that did not fail with
 * a fatal error).
 */
static int do_tls_operation( SmtpState *SS, int timeout,
			     int (*hsfunc)(SSL *), const char *action )
{
    int status;
    int sslerr;
    int retval = 0;
    int done = 0;

    while (!done) {

	int rc, i;
	fd_set rdset, wrset;
	struct timeval tv;
	int wantread, wantwrit;

    ssl_connect_retry:;

        status = hsfunc(SS->TLS.ssl);
	sslerr = SSL_get_error(SS->TLS.ssl, status);

#if (OPENSSL_VERSION_NUMBER <= 0x0090581fL)
	/*
	 * There is a bug up to and including OpenSSL-0.9.5a:
	 * if an error occurs while checking the peers certificate
	 * due to some certificate error (e.g. as happend with
	 * a RSA-padding error), the error is put  onto the error stack.
	 * If verification is not enforced, this error should be ignored,
	 * but the error-queue is not cleared, so we can find this error
	 * here. The bug has been fixed on May 28, 2000.
	 *
	 * This bug so far has only manifested as
	 * 4800:error:0407006A:rsa routines:RSA_padding_check_PKCS1_type_1:block type is not 01:rsa_pk1.c:100:
	 * 4800:error:04067072:rsa routines:RSA_EAY_PUBLIC_DECRYPT:padding check failed:rsa_eay.c:396:
	 * 4800:error:0D079006:asn1 encoding routines:ASN1_verify:bad get asn1 object call:a_verify.c:109:
	 * so that we specifically test for this error.
	 * We print the errors to the logfile and automatically clear
	 * the error queue. Then we retry to get another error code.
	 * We cannot do better, since we can only retrieve the last
	 * entry of the error-queue without actually cleaning it on
	 * the way.
	 *
	 * This workaround is secure, as verify_result is set to "failed"
	 * anyway.
	 */
	if (sslerr == SSL_ERROR_SSL) {
	  if (ERR_peek_error() == 0x0407006AL) {
	    tls_print_errors(SS); /* Keep information for the logfile */
	    msg_info(SS,"OpenSSL <= 0.9.5a workaround called: certificate errors ignored");
	    sslerr = SSL_get_error(SS->TLS.ssl, status);
	  }
	}
#endif
	switch (sslerr) {

	case SSL_ERROR_WANT_READ:
	    SS->TLS.wantreadwrite = -1;
	    sslerr = EAGAIN;
	    break;
	case SSL_ERROR_WANT_WRITE:
	    SS->TLS.wantreadwrite =  1;
	    sslerr = EAGAIN;
	    break;

	case SSL_ERROR_WANT_X509_LOOKUP:
	    goto ssl_connect_retry;
	    break;

	case SSL_ERROR_NONE: /* successfull completition.. */
	    retval = status;
	    break; /* But do flush writes and reads at first.. */

	default: /* and all else.. */
	    retval = status;
	    goto ssl_operation_done;
	}

	wantread = (BIO_should_read(SSL_get_rbio(SS->TLS.ssl)));
	wantwrit = (BIO_should_write(SSL_get_wbio(SS->TLS.ssl)));

	if (!wantread && !wantwrit) {
	  /* Not proper retry by read or write! */

	ssl_connect_error_bailout:;

	  msg_info(SS, "SSL_%s error %d/%d", action, status, sslerr);
	  tls_print_errors(SS);

	  return (-1);
	}

	i = SSL_get_fd(SS->TLS.ssl);
	_Z_FD_ZERO(wrset);
	_Z_FD_ZERO(rdset);

	if (wantread)
	  _Z_FD_SET(i, rdset); /* READ WANTED */
	if (wantwrit)
	  _Z_FD_SET(i, wrset); /* WRITE WANTED */

	tv.tv_sec = timeout;
	tv.tv_usec = 0;

	rc = select(i+1, &rdset, &wrset, NULL, &tv);
	sslerr = errno;

	if (rc == 0) {
	  /* TIMEOUT! */
	  sslerr = ETIMEDOUT;
	  goto ssl_connect_error_bailout;
	}

	if (rc < 0) {
	  if (sslerr == EINTR || sslerr == EAGAIN)
	    continue;

	  /* Bug time ?! */
	  goto ssl_connect_error_bailout;
	}
	/* Default is then success for either read, or write.. */
    }

 ssl_operation_done:;


    return retval;
}



 /*
  * Set up the cert things on the CLIENT side. We do need both the
  * private key (in key_file) and the cert (in cert_file).
  * Both files may be identical.
  *
  * This function is taken from OpenSSL apps/s_cb.c
  */

static int set_cert_stuff(SmtpState *SS,
			  const char *cert_file, const char *key_file)
{
    SSL_CTX * ctx = SS->TLS.ctx;

    if (cert_file && *cert_file) {

	if (SSL_CTX_use_certificate_file(ctx, cert_file,
					 SSL_FILETYPE_PEM) <= 0) {
	    msg_info(NULL, "unable to get certificate from '%s'", cert_file);
	    tls_print_errors(SS);
	    return (0);
	}
	if (!key_file || !*key_file )
	    key_file = cert_file;
	if (SSL_CTX_use_PrivateKey_file(ctx, key_file,
					SSL_FILETYPE_PEM) <= 0) {
	    msg_info(NULL, "unable to get private key from '%s'", key_file);
	    tls_print_errors(SS);
	    return (0);
	}
	/* Now we know that a key and cert have been set against
         * the SSL context */
	if (!SSL_CTX_check_private_key(ctx)) {
	    msg_info(NULL, "Private key does not match the certificate public key");
	    return (0);
	}
    }
    return (1);
}


/* taken from OpenSSL apps/s_cb.c */

static RSA *tmp_rsa_cb(SSL * s, int export, int keylength)
{
    static RSA *rsa_tmp = NULL;

    if (rsa_tmp == NULL) {
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


static int verify_callback(int ok, X509_STORE_CTX * ctx)
{
    char    buf[4000];
    char   *peername_left;
    X509   *err_cert;
    int     err;
    int     depth;
    int     verify_depth;
    int     hostname_matched;
    SSL    *con;
    SmtpState *SS;

    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err      = X509_STORE_CTX_get_error(ctx);
    depth    = X509_STORE_CTX_get_error_depth(ctx);

    con = X509_STORE_CTX_get_ex_data(ctx,
				     SSL_get_ex_data_X509_STORE_CTX_idx());

    SS = SSL_get_ex_data(con, TLScontext_index);


    X509_NAME_oneline(X509_get_subject_name(err_cert), buf, sizeof(buf));

    if (tls_loglevel >= 1)
      msg_info(SS, "Peer cert verify depth=%d %s", depth, buf);

    verify_depth = SSL_get_verify_depth(con);

    if (ok && (verify_depth >= 0) && (depth > verify_depth)) {
	ok = 0;
	err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
	X509_STORE_CTX_set_error(ctx, err);
    }
    if (!ok) {
      msg_info(SS, "verify error:num=%d:%s", err,
	       X509_verify_cert_error_string(err));
    }

    if (ok && (depth == 0) && SS->TLS.sslmode) {
	/*
	 * Check out the name certified against the hostname expected.
	 * In case it does not match, print an information about the result.
	 * If a matching is enforced, bump out with a verification error
	 * immediately.
	 */
	buf[0] = '\0';
	if (!X509_NAME_get_text_by_NID(X509_get_subject_name(err_cert),
				       NID_commonName, buf, sizeof(buf))) {
	  msg_info(SS,"Could not parse server's subject CN");
	  tls_print_errors(SS);
	}

	hostname_matched = 0;
	if (cistrcmp(SS->TLS.peername_save, buf) == 0)
	    hostname_matched = 1;
	else if ((strlen(buf) > 2) &&
		 (buf[0] == '*') && (buf[1] == '.')) {
	    /*
	     * Allow wildcard certificate matching.
	     * The proposed rules in RFCs (2818: HTTP/TLS,
	     * 2830: LDAP/TLS) are different, RFC2874
	     * does not specify a rule, so here the strict
	     * rule is applied.
	     * An asterisk '*' is allowed as the leftmost
	     * component and may replace the left most part
	     * of the hostname. Matching is done by removing
	     * '*.' from the wildcard name and the `name.`
	     * from the peername and compare what is left.
	     */
	    peername_left = strchr(SS->TLS.peername_save, '.');
	    if (peername_left) {
		if (cistrcmp(peername_left + 1, buf + 2) == 0)
		    hostname_matched = 1;
	    }
	}

	if (!hostname_matched) {
	  msg_info(SS,"Peer verification: CommonName in certificate does not match: '%s' != '%s'", buf, SS->TLS.peername_save);
	  if (SS->TLS.enforce_verify_errors && SS->TLS.enforce_CN) {
	    err = X509_V_ERR_CERT_REJECTED;
	    X509_STORE_CTX_set_error(ctx, err);
	    msg_info(SS,"Verify failure: Hostname mismatch");
	    ok = 0;
	  }
	}
    }

    switch (ctx->error) {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
	X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert),
			  buf, sizeof(buf));
	msg_info(SS, "issuer= %s", buf);
	break;
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
	msg_info(SS, "cert not yet valid");
	break;
    case X509_V_ERR_CERT_HAS_EXPIRED:
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
	msg_info(SS, "cert has expired");
	break;
    }
    if (tls_loglevel >= 1)
	msg_info(SS, "verify return:%d", ok);
    if (SS->TLS.enforce_verify_errors)
	return (ok); 
    else
	return (1);
}

/* taken from OpenSSL apps/s_cb.c */

static void apps_ssl_info_callback(const SSL * s, int where, int ret)
{
    char   *str;
    int     w;
    void *SS = NULL; /* FIXME! use context-saved ptr.. */

    w = where & ~SSL_ST_MASK;

    if (w & SSL_ST_CONNECT)
	str = "SSL_connect";
    else if (w & SSL_ST_ACCEPT)
	str = "SSL_accept";
    else
	str = "undefined";

    if (where & SSL_CB_LOOP) {
	if (tls_loglevel >= 2)
	    msg_info(SS, "%s:%s", str, SSL_state_string_long(s));
    } else if (where & SSL_CB_ALERT) {
	str = (where & SSL_CB_READ) ? "read" : "write";
	if (tls_loglevel >= 2 ||
	    ((ret & 0xff) != SSL3_AD_CLOSE_NOTIFY))
	msg_info(SS, "SSL3 alert %s:%s:%s", str,
		 SSL_alert_type_string_long(ret),
		 SSL_alert_desc_string_long(ret));
    } else if (where & SSL_CB_EXIT) {
	if (ret == 0)
	    msg_info(SS, "%s:failed in %s",
		     str, SSL_state_string_long(s));
	else if (ret < 0) {
	    msg_info(SS, "%s:error in %s",
		     str, SSL_state_string_long(s));
	}
    }
}

/*
 * taken from OpenSSL crypto/bio/b_dump.c, modified to save a lot of strcpy
 * and strcat by Matti Aarnio.
 */

#define TRUNCATE
#define DUMP_WIDTH	16

int tls_dump(SmtpState *SS, const char *s, int len)
{
    int     ret = 0;
    char    buf[160 + 1];
    char    *ss;
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
	buf[0] = '\0';				/* start with empty string */
	ss = buf;

	sprintf(ss, "%04x ", i * DUMP_WIDTH);
	ss += strlen(ss);
	for (j = 0; j < DUMP_WIDTH; j++) {
	    if (((i * DUMP_WIDTH) + j) >= len) {
		strcpy(ss, "   ");
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
	/* 
	 * if this is the last call then update the ddt_dump thing so that
         * we will move the selection point in the debug window
         */
	msg_info(SS, "%s", buf);
	ret += strlen(buf);
    }
#ifdef TRUNCATE
    if (trunc > 0) {
	sprintf(buf, "%04x - <SPACES/NULS>", len + trunc);
	msg_info(SS, "%s", buf);
	ret += strlen(buf);
    }
#endif
    return (ret);
}



/* taken from OpenSSL apps/s_cb.c */

static long bio_dump_cb(BIO * bio, int cmd, const char *argp, int argi,
			long argl, long ret)
{
    void * SS = NULL; /* FIXME: use stored state local thingie ??? */
    if (!do_dump)
	return (ret);

    if (cmd == (BIO_CB_READ | BIO_CB_RETURN)) {
	msg_info(SS, "read from %08X [%08lX] (%d bytes => %ld (0x%X))",
		 bio, argp, argi, ret, ret);
	tls_dump(NULL, argp, (int) ret);
	return (ret);
    } else if (cmd == (BIO_CB_WRITE | BIO_CB_RETURN)) {
	msg_info(SS, "write to %08X [%08lX] (%d bytes => %ld (0x%X))",
		 bio, argp, argi, ret, ret);
	tls_dump(NULL, argp, (int) ret);
    }
    return (ret);
}


/*
 * We need space to save the peername into the SSL_SESSION, as we must
 * look up the external database for client sessions by peername, not
 * by session id. We therefore allocate place for the peername string,
 * when a new SSL_SESSION is generated. It is filled later.
 */
static int new_peername_func(void *parent, void *ptr,
			     CRYPTO_EX_DATA *ad,
			     int idx, long argl, void *argp)
{
    char *peername;

    peername = (char *)malloc(id_maxlength + 1);
    if (!peername)
	return 0;
    peername[0] = '\0'; 	/* initialize */
    return CRYPTO_set_ex_data(ad, idx, peername);
}

/*
 * When the SSL_SESSION is removed again, we must free the memory
 * to avoid leaks.
 */
static void free_peername_func(void *parent, void *ptr,
			       CRYPTO_EX_DATA *ad,
			       int idx, long argl, void *argp)
{
    free(CRYPTO_get_ex_data(ad, idx));
}

/*
 * Duplicate application data, when a SSL_SESSION is duplicated
 */
static int dup_peername_func(CRYPTO_EX_DATA *to,
			     CRYPTO_EX_DATA *from,
			     void *from_d, int idx,
			     long argl, void *argp)
{
    char *peername_old, *peername_new;

    peername_old = CRYPTO_get_ex_data(from, idx);
    peername_new = CRYPTO_get_ex_data(to, idx);
    if (!peername_old || !peername_new)
	return 0;
    memcpy(peername_new, peername_old, id_maxlength + 1);
    return 1;
}


#if 0 /* some day */
static SSL_SESSION *load_clnt_session(const char *hostname,
				      int enforce_peername)
{
    SSL_SESSION *session = NULL;
    int n;
    int uselength;
    int length;
    int hex_length;
    const char *session_hex;
    pfixtls_scache_info_t scache_info;
    unsigned char nibble, *data, *sess_data;
    char *idstring[ID_MAXLENGTH + 1]; /* ALLOCA!! */

    length = strlen(hostname); 
    if (length > id_maxlength)
	uselength = id_maxlength;	/* Limit length of ID */
    else
	uselength = length;

    for(n=0 ; n < uselength ; n++)
	idstring[n] = tolower(hostname[n]);
    idstring[uselength] = '\0';
    if (var_smtp_tls_loglevel >= 3)
	msg_info("Trying to reload Session from disc: %s", idstring);

    session_hex = dict_get(scache_db, idstring);
    if (session_hex) {
	hex_length = strlen(session_hex);
	data = (unsigned char *)mymalloc(hex_length / 2);
	if (!data) {
	    msg_info("could not allocate memory for session reload");
	    return(NULL);
	}

	memset(data, 0, hex_length / 2);
	for (n = 0; n < hex_length; n++) {
	    if ((session_hex[n] >= '0') && (session_hex[n] <= '9'))
		nibble = session_hex[n] - '0';
	    else
		nibble = session_hex[n] - 'A' + 10;
	    if (n % 2)
		data[n / 2] |= nibble;
	    else
		data[n / 2] |= (nibble << 4);
	}

	/*
	 * First check the version numbers, since wrong session data might
	 * hit us hard (SEGFAULT). We also have to check for expiry.
	 * When we enforce_peername, we may find an old session, that was
	 * saved when enforcement was not set. In this case the session will
	 * be removed and a fresh session will be negotiated.
	 */
	memcpy(&scache_info, data, sizeof(pfixtls_scache_info_t));
	if ((scache_info.scache_db_version != scache_db_version) ||
	    (scache_info.openssl_version != openssl_version) ||
	    (scache_info.timestamp + var_smtpd_tls_scache_timeout < time(NULL)))
	    dict_del(scache_db, idstring);
	else if (enforce_peername && (!scache_info.enforce_peername))
	    dict_del(scache_db, idstring);
	else {
	    sess_data = data + sizeof(pfixtls_scache_info_t);
	    session = d2i_SSL_SESSION(NULL, &sess_data,
				      hex_length / 2 - sizeof(time_t));
	    strncpy(SSL_SESSION_get_ex_data(session, TLSpeername_index),
		    idstring, id_maxlength + 1);
	    if (!session)
		pfixtls_print_errors();
	}
	free((char *)data);
    }

    if (session && (var_smtp_tls_loglevel >= 3))
        msg_info("Successfully reloaded session from disc");

    return (session);
}


static void create_client_lookup_id(char *idstring, char *hostname)
{
    int n, len, uselength;

    len = strlen(hostname);
    if (len > id_maxlength)
	uselength = id_maxlength;	/* Limit length of ID */
    else
	uselength = len;

    for (n = 0 ; n < uselength ; n++)
	idstring[n] = tolower(hostname[n]);
    idstring[uselength] = '\0';
}

/*
 * Save a new session to the external cache
 */
static int new_session_cb(SSL *ssl, SSL_SESSION *session)
{
  char idstring[2 * ID_MAXLENGTH + 1]; /* ALLOCA! */
    int n;
    int dsize;
    int len;
    unsigned char *data, *sess_data;
    pfixtls_scache_info_t scache_info;
    char *hexdata, *hostname;
    SmtpState *SS;

    if (tls_clientengine) {
        TLScontext = SSL_get_ex_data(ssl, TLScontext_index);
	hostname = SS->TLS.peername_save;
	create_client_lookup_id(idstring, hostname);
	strncpy(SSL_SESSION_get_ex_data(session, TLSpeername_index),
		hostname, id_maxlength + 1);
	/*
	 * Remember, whether peername matching was enforced when the session
	 * was created. If later enforce mode is enabled, we do not want to
	 * reuse a session that was not sufficiently checked.
	 */
	scache_info.enforce_peername =
		(SS->TLS.enforce_verify_errors && SS->TLS.enforce_CN);

	if (var_smtp_tls_loglevel >= 3)
	    msg_info(SS,"Trying to save session for hostID to disc: %s", idstring);

#if (OPENSSL_VERSION_NUMBER < 0x00906011L) || (OPENSSL_VERSION_NUMBER == 0x00907000L)
	    /*
	     * Ugly Hack: OpenSSL before 0.9.6a does not store the verify
	     * result in sessions for the client side.
	     * We modify the session directly which is version specific,
	     * but this bug is version specific, too.
	     *
	     * READ: 0-09-06-01-1 = 0-9-6-a-beta1: all versions before
	     * beta1 have this bug, it has been fixed during development
	     * of 0.9.6a. The development version of 0.9.7 can have this
	     * bug, too. It has been fixed on 2000/11/29.
	     */
	    session->verify_result = SSL_get_verify_result(SS->TLS.con);
#endif

    } else {
	create_server_lookup_id(idstring, session);
	if (var_smtpd_tls_loglevel >= 3)
	    msg_info(SS,"Trying to save Session to disc: %s", idstring);
    }


    /*
     * Get the session and convert it into some "database" useable form.
     * First, get the length of the session to allocate the memory.
     */
    dsize = i2d_SSL_SESSION(session, NULL);
    if (dsize < 0) {
	msg_info(SS,"Could not access session");
	return 0;
    }
    data = (unsigned char *)mymalloc(dsize + sizeof(pfixtls_scache_info_t));
    if (!data) {
	msg_info(SS,"could not allocate memory for SSL session");
	return 0;
    }

    /*
     * OpenSSL is not robust against wrong session data (might SEGFAULT),
     * so we secure it against version ids (session cache structure as well
     * as OpenSSL version).
     */
    scache_info.scache_db_version = scache_db_version;
    scache_info.openssl_version = openssl_version;

    /*
     * Put a timestamp, so that expiration can be checked without
     * analyzing the session data itself. (We would need OpenSSL funtions,
     * since the SSL_SESSION is a private structure.)
     */
    scache_info.timestamp = time(NULL);

    memcpy(data, &scache_info, sizeof(pfixtls_scache_info_t));
    sess_data = data + sizeof(pfixtls_scache_info_t);

    /*
     * Now, obtain the session. Unfortunately, it is binary and dict_update
     * cannot handle binary data (it could contain '\0' in it) directly.
     * To save memory we could use base64 encoding. To make handling easier,
     * we simply use hex format.
     */
    len = i2d_SSL_SESSION(session, &sess_data);
    len += sizeof(pfixtls_scache_info_t);

    hexdata = (char *)mymalloc(2 * len + 1);

    if (!hexdata) {
	msg_info(SS,"could not allocate memory for SSL session (HEX)");
	free((char *)data);
	return 0;
    }
    for (n = 0; n < len; n++) {
	hexdata[n * 2] = hexcodes[(data[n] & 0xf0) >> 4];
	hexdata[(n * 2) + 1] = hexcodes[(data[n] & 0x0f)];
    }
    hexdata[len * 2] = '\0';

    /*
     * The session id is a hex string, all uppercase. We are using SDBM as
     * compiled into Postfix with 8kB maximum entry size, so we set a limit
     * when caching. If the session is not cached, we have to renegotiate,
     * not more, not less. For a real session, this limit should never be
     * met
     */
    if (strlen(idstring) + strlen(hexdata) < 8000)
      dict_put(scache_db, idstring, hexdata);

    free(hexdata);
    free((char *)data);
    return (1);
}
#endif



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
  * This is the setup routine for the SSL client. As smtpd might be called
  * more than once, we only want to do the initialization one time.
  *
  * The skeleton of this function is taken from OpenSSL apps/s_client.c.
  */

int     tls_init_clientengine(SS, cfgpath)
     SmtpState *SS;
     char *cfgpath;
{
	int     off = 0;
	int     verify_flags = SSL_VERIFY_NONE;
	char	  buf[1024], *n, *a1;

	int	linenum = 0;
	FILE   *fp;
	unsigned char *s;

	const char   *CApath;
	const char   *CAfile;
	const char   *c_cert_file;
	const char   *c_key_file;
	const char   *c_dcert_file;
	const char   *c_dkey_file;


	vlog = SS->verboselog;

	if (tls_clientengine) return 0;		/* already running */

	if (SS->TLS.sslmode)
	  return (0);				/* already running */

	fp = fopen(cfgpath,"r");
	if (!fp) {
	  msg_info(SS, "Can't read TLS config file: '%s'",cfgpath);
	  return -1;
	}
	while (!feof(fp) && !ferror(fp)) {
	  if (!fgets(buf, sizeof(buf), fp))
	    break;
	  ++linenum;
	  s = (void*) strchr(buf, '\n');
	  if (s) *s = 0;
	  s = (void*) buf;
	  
#define SKIPSPACE(Y) while (*Y == ' ' || *Y == '\t' || *Y == '\n') ++Y
#define SKIPTEXT(Y ) while (*Y && !(*Y == ' ' || *Y == '\t' || *Y == '\n')) ++Y
	  
	  SKIPSPACE(s);
	  if (!*s || *s == '#' || *s == ';')
	    continue; /* First non-whitespace char is comment start (or EOL) */
	  
	  SKIPSPACE(s);
	  n = (char *)s;
	  SKIPTEXT(s);
	  if (*s) *s++ = 0;
	  
	  SKIPSPACE(s);
	  a1 = (char *)s;
	  SKIPTEXT(s);
	  if (*s) *s++ = 0;
	  

	  if        (strcasecmp(n, "tls-cert-file") == 0 && a1) {
	    tls_cert_file = strdup(a1);
	  } else if (strcasecmp(n, "tls-key-file") == 0  && a1) {
	    tls_key_file = strdup(a1);
	  } else if (strcasecmp(n, "tls-dcert-file") == 0 && a1) {
	    tls_dcert_file = strdup(a1);
	  } else if (strcasecmp(n, "tls-dkey-file") == 0  && a1) {
	    tls_dkey_file = strdup(a1);
	  } else if (strcasecmp(n, "tls-CAfile") == 0     && a1) {
	    tls_CAfile = strdup(a1);
	  } else if (strcasecmp(n, "tls-CApath") == 0     && a1) {
	    tls_CApath = strdup(a1);
	  } else if (strcasecmp(n, "tls-loglevel") == 0   && a1) {
	    tls_loglevel = atol(a1);
	    if (tls_loglevel < 0) tls_loglevel = 0;
	    if (tls_loglevel > 4) tls_loglevel = 4;
	  } else if (strcasecmp(n, "tls-strict-rfc2487") == 0) {
	    tls_protocol_tlsv1_only = 1;
	  } else if (strcasecmp(n, "tls-use-scache") == 0) {
	    tls_use_scache = 1;
	  } else if (strcasecmp(n, "tls-random-source") == 0 && a1) {
	    tls_random_source = strdup(a1);
	  } else if (strcasecmp(n, "tls-cipher-list") == 0 && a1) {
	    tls_cipherlist = strdup(a1);
	  } else if (strcasecmp(n, "tls-scache-timeout") == 0 && a1) {
	    tls_scache_timeout = atol(a1);
	    if (tls_loglevel < 0) tls_loglevel = 0;
	    if (tls_loglevel > 4) tls_loglevel = 4;
	  } else if (strcasecmp(n, "demand-tls-mode") == 0) {
	    demand_TLS_mode = 1;
	  } else if (strcasecmp(n, "no-tls-readahead") == 0) {
	    tls_use_read_ahead = 0;
	  } else {
	    sfprintf(sfstderr,"# TLS config file, line %d verb: '%s' unknown or missing parameters!\n",
		     linenum, n);
	  }
	}
	fclose(fp);


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

	/* Lets try to do RAND-pool initing.. */
	/* We don't loop, we bail-out from loop-contruction
	   enclosed alternate codes */


	/*
	 * Initialize the PRNG Pseudo Random Number Generator with some seed.
	 */
	tls_randseed.pid  = getpid();
	tls_randseed.ppid = getppid();
	gettimeofday(&tls_randseed.tv, NULL);
	RAND_seed(&tls_randseed, sizeof(tls_randseed));


	/*
	 * Access the external sources for random seed. We will only query
	 * them once, this should be sufficient and we will stir our entropy
	 * by using the prng-exchange file anyway.
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

	/*
	 * Some more seeding...
	 */
	tls_randseed.pid = getpid();
	tls_randseed.ppid = getppid();
	gettimeofday(&tls_randseed.tv, NULL);
	RAND_seed(&tls_randseed, sizeof(tls_randseed));


	if (tls_loglevel >= 2)
	  msg_info(SS, "starting TLS engine");

	/*
	 * The SSL/TLS speficications require the client to send
	 * a message in the oldest specification it understands with
	 * the highest level it understands in the message.
	 * RFC2487 is only specified for TLSv1, but we want to be
	 * as compatible as possible, so we will start off with
	 * a SSLv2 greeting allowing the best we can offer: TLSv1.
	 * We can restrict this with the options setting later, anyhow.
	 */

	if (tls_protocol_tlsv1_only)
	  SS->TLS.ctx = SSL_CTX_new(TLSv1_client_method());
	else
	  SS->TLS.ctx = SSL_CTX_new(SSLv23_client_method());

	if (! SS->TLS.ctx) {
	  tls_print_errors(SS);
	  return (-1);
	}

	/*
	 * Here we might set SSL_OP_NO_SSLv2, SSL_OP_NO_SSLv3, SSL_OP_NO_TLSv1.
	 * Of course, the last one would not make sense, since RFC2487 is only
	 * defined for TLS, but we don´t know what is out there. So leave 
	 * things completely open, as of today.
	 */
	off = SSL_OP_ALL;		/* Work around all known bugs */
	if (tls_protocol_tlsv1_only)
	  off |= (SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
	SSL_CTX_set_options(SS->TLS.ctx, off);

	/*
	 * Set the info_callback, that will print out messages during
	 * communication on demand.
	 */
	SSL_CTX_set_info_callback(SS->TLS.ctx, apps_ssl_info_callback);

	/*
	 * Set the list of ciphers, if explicitely given; otherwise the
	 * (reasonable) default list is kept.
	 */
	if (tls_cipherlist) {
	  if (SSL_CTX_set_cipher_list(SS->TLS.ctx, tls_cipherlist) == 0) {
	    tls_print_errors(SS);
	    return (-1);
	  }
	}

  
	/*
	 * Now we must add the necessary certificate stuff: A client key,
	 * a client certificate, and the CA certificates for both the client
	 * cert and the verification of server certificates.
	 * In fact, we do not need a client certificate,  so the certificates
	 * are only loaded (and checked), if supplied. A clever client would
	 * handle multiple client certificates and decide based on the list
	 * of acceptable CAs, sent by the server, which certificate to submit.
	 * OpenSSL does however not do this and also has no callback hoods to
	 * easily realize it.
	 *
	 * As provided by OpenSSL we support two types of CA certificate
	 * handling:  One possibility is to add all CA certificates to
	 * one large CAfile,  the other possibility is a directory pointed
	 * to by CApath, containing seperate files for each CA pointed on
	 * by softlinks named by the hash values of the certificate.
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

	if (CAfile || CApath)
	  if ((!SSL_CTX_load_verify_locations(SS->TLS.ctx, CAfile, CApath)) ||
	      (!SSL_CTX_set_default_verify_paths(SS->TLS.ctx))) {
	    msg_info(SS, "TLS engine: cannot load CA data");
	    tls_print_errors(SS);
	    return (-1);
	  }
	
	if (!tls_cert_file || *tls_cert_file == 0)
	  c_cert_file = NULL;
	else
	  c_cert_file = tls_cert_file;
	if (!tls_key_file || *tls_key_file == 0)
	  c_key_file = NULL;
	else
	  c_key_file = tls_key_file;

	if (c_cert_file || c_key_file) {
	  if (!set_cert_stuff(SS, c_cert_file, c_key_file)) {
	    msg_info(SS, "TLS engine: cannot load cert/key data");
	    tls_print_errors(SS);
	    return (-1);
	  }
	}

	if (!tls_dcert_file || *tls_dcert_file == 0)
	  c_dcert_file = NULL;
	else
	  c_dcert_file = tls_dcert_file;
	if (!tls_dkey_file || *tls_dkey_file == 0)
	  c_dkey_file = NULL;
	else
	  c_dkey_file = tls_dkey_file;

	if (c_dcert_file || c_dkey_file) {
	  if (!set_cert_stuff(SS, c_dcert_file, c_dkey_file)) {
	    msg_info(SS, "TLS engine: cannot load dcert/dkey data");
	    tls_print_errors(SS);
	    return (-1);
	  }
	}

	/*
	 * Sometimes a temporary RSA key might be needed by the OpenSSL
	 * library. The OpenSSL doc indicates, that this might happen when
	 * export ciphers are in use. We have to provide one, so well, we
	 * just do it.
	 */

	SSL_CTX_set_tmp_rsa_callback(SS->TLS.ctx, tmp_rsa_cb);

	/*
	 * Finally, the setup for the server certificate checking, done
	 * "by the book".
	 */

	SSL_CTX_set_verify(SS->TLS.ctx, verify_flags, verify_callback);

#if 0
	/*
	 * Initialize the session cache. We only want external caching to
	 * synchronize between server sessions, so we set it to a minimum value
	 * of 1. If the external cache is disabled, we won´t cache at all.
	 *
	 * In case of the client, there is no callback used in OpenSSL,
	 * so we must call the session cache functions manually during
	 * the process.
	 */
	SSL_CTX_sess_set_cache_size(SS->TLS.ctx, 1);
	SSL_CTX_set_timeout(SS->TLS.ctx, tls_scache_timeout);
#endif

#if 0
	/*
	 * The session cache is realized by an external database file, that
	 * must be opened before going to chroot jail. Since the session cache
	 * data can become quite large, "[n]dbm" cannot be used as it has a
	 * size limit that is by far to small.
	 */
	if (*var_smtp_tls_scache_db) {
	  /*
	   * Insert a test against other dbms here, otherwise while writing
	   * a session (content to large), we will receive a fatal error!
	   */
	  if (strncmp(var_smtp_tls_scache_db, "sdbm:", 5))
	    msg_warn("Only sdbm: type allowed for %s",
		     var_smtp_tls_scache_db);
	  else
	    scache_db = dict_open(var_smtp_tls_scache_db, O_RDWR,
				  ( DICT_FLAG_DUP_REPLACE | DICT_FLAG_LOCK |
				    DICT_FLAG_SYNC_UPDATE ));
	  if (!scache_db)
	    msg_warn("Could not open session cache %s",
		     var_smtp_tls_scache_db);
	  /*
	   * It is practical to have OpenSSL automatically save newly created
	   * sessions for us by callback. Therefore we have to enable the
	   * internal session cache for the client side. Disable automatic
	   * clearing, as smtp has limited lifetime anyway and we can call
	   * the cleanup routine at will.
	   */
	  SSL_CTX_set_session_cache_mode(ctx,
					 ( SSL_SESS_CACHE_CLIENT |
					   SSL_SESS_CACHE_NO_AUTO_CLEAR ));
	  SSL_CTX_sess_set_new_cb(ctx, new_session_cb);
	}
#endif

	/*
	 * Finally create the global index to access TLScontext information
	 * inside verify_callback.
	 */
	TLScontext_index = SSL_get_ex_new_index(0, "TLScontext ex_data index",
						NULL, NULL, NULL);
	TLSpeername_index = SSL_SESSION_get_ex_new_index(0,
							 "TLSpeername ex_data index",
							 new_peername_func,
							 dup_peername_func,
							 free_peername_func);

	tls_clientengine = 1;


	return (0);
}

 /*
  * This is the actual startup routine for the connection. We expect
  * that the buffers are flushed and the "220 Ready to start TLS" was
  * received by us, so that we can immediately can start the TLS
  * handshake process.
  */
int     tls_start_clienttls(SS, peername) /* XX: enforce-peername ? */
     SmtpState *SS;
     const char *peername;
{
    int     sts;
    SSL_SESSION *session, *old_session;
    SSL_CIPHER *cipher;
    X509   *peer;
    int     verify_flags;
    char cbuf[4000];

    vlog = SS->verboselog;	/* Grr.. global for BIO dump.	*/

    if (!tls_available) {	/* should never happen		*/
	msg_info(SS, "tls_engine not running");
	alarm(0);
	return (-1);
    }
    if (tls_loglevel >= 1)
	msg_info(SS, "setting up TLS connection");

    /*
     * If necessary, setup a new SSL structure for a connection.
     * We keep old ones on closure, so it might not be always
     * necessary. We however reset the old one, just in case.
     */

    if (SS->TLS.ssl != NULL) {
      SSL_clear(SS->TLS.ssl);
    } else {
      SS->TLS.ssl = SSL_new(SS->TLS.ctx);
      if (! SS->TLS.ssl) {
	msg_info(SS, "Could not allocate 'con' with SSL_new()");
	tls_print_errors(SS);
	alarm(0);
	return (-1);
      }
    }

    /*
     * Add the location of TLS-context to the SSL to later
     * retrieve the information inside the verify_callback().
     */

    if (!SSL_set_ex_data(SS->TLS.ssl, TLScontext_index, SS)) {
      msg_info(SS, "Could not set application data for 'SS->TLS.ssl'");
      tls_print_errors(SS);
      tls_stop_clienttls(SS, 1);
      return (-1);
    }



    old_session = NULL;	/* make sure no old info is kept */

    /*
     * Set the verification parameters to be checked in verify_callback().
     */
    if (tls_enforce_peername) {
      verify_flags = SSL_VERIFY_PEER;
      SS->TLS.enforce_verify_errors = 1;
      SS->TLS.enforce_CN = 1;
      SSL_set_verify(SS->TLS.ssl, verify_flags, verify_callback);
    } else {
      SS->TLS.enforce_verify_errors = 0;
      SS->TLS.enforce_CN = 0;
    }

    /*
     * Now, connect the filedescripter set earlier to the SSL connection
     * (this is for clean UNIX environment, for example windows "sockets"
     *  need somewhat different approach with customized BIO_METHODs.)
     */
    if (!SSL_set_fd(SS->TLS.ssl, sffileno(SS->smtpfp))) {
	msg_info(SS, "SSL_set_fd failed");
	tls_print_errors(SS);
	alarm(0);
	return (-1);
    }


    /*
     * Find out the hashed HostID for the client cache and try to
     * load the session from the cache.
     */
    SS->TLS.peername_save = strdup(peername);

#if 0 /* some day.. */
    if (scache_db) {
      old_session = load_clnt_session(peername, enforce_peername);
      if (old_session) {
	SSL_set_session(SS->TLS.con, old_session);
#if (OPENSSL_VERSION_NUMBER < 0x00906011L) || (OPENSSL_VERSION_NUMBER == 0x00907000L)
	/*
	 * Ugly Hack: OpenSSL before 0.9.6a does not store the verify
	 * result in sessions for the client side.
	 * We modify the session directly which is version specific,
	 * but this bug is version specific, too.
	 *
	 * READ: 0-09-06-01-1 = 0-9-6-a-beta1: all versions before
	 * beta1 have this bug, it has been fixed during development
	 * of 0.9.6a. The development version of 0.9.7 can have this
	 * bug, too. It has been fixed on 2000/11/29.
	 */
	SSL_set_verify_result(SS->TLS.con, old_session->verify_result);
#endif
	   
      }
    }
#endif

#if 0 /* Some day... */
    /*
     * Before really starting anything, try to seed the PRNG a little bit
     * more.
     */
    pfixtls_stir_seed();
    pfixtls_exchange_seed();
#endif

#if 0
    /*
     * Initialize the SSL connection to connect state. This should not be
     * necessary anymore since 0.9.3, but the call is still in the library
     * and maintaining compatibility never hurts.
     */
    SSL_set_connect_state(SS->TLS.ssl);
#endif

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

    /* Dump the negotiation for loglevels 3 and 4 */
    if (tls_loglevel >= 3)
	do_dump = 1;


    /*
     * Now we expect the negotiation to begin.
     * This whole process is like a black box for us.
     * We totally have to rely on the routines build
     * into the OpenSSL library.
     * The only thing we can do we already have done
     * by choosing our own callback certificate verification.
     *
     * Error handling:
     * If the SSL handhake fails, we print out an error message
     * and remove everything that might be there.
     * A session has to be removed anyway, because RFC2246 requires it. 
     */

    sts = do_tls_operation(SS, timeout_tcpw, SSL_connect, "connect");
    if (sts <= 0) {
      session = SSL_get_session(SS->TLS.ssl);
      if (session) {
	SSL_CTX_remove_session(SS->TLS.ctx, session);
	if (tls_loglevel >= 2)
	  msg_info(SS, "SSL session removed");
      }
      if (old_session && (!SSL_session_reused(SS->TLS.ssl)))
	SSL_SESSION_free(old_session); /* Must also be removed */
      
      tls_stop_clienttls(SS, 1);
      
      alarm(0);
    }

    if (!SSL_session_reused(SS->TLS.ssl)) {
      SSL_SESSION_free(old_session);	/* Remove unused session */
    } else if (tls_loglevel >= 3)
      msg_info(SS,"Reusing old session");


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

	cbuf[0] = 0;
	if (!X509_NAME_get_text_by_NID(X509_get_subject_name(peer),
				       NID_commonName,
				       cbuf, sizeof(cbuf))) {
	  msg_info(SS,"Could not parse server's subject CN");
	  tls_print_errors(SS);
	} else
	  SS->TLS.peer_CN = strdup(cbuf);

	cbuf[0] = 0;
	if (!X509_NAME_oneline(X509_get_subject_name(peer),
			       cbuf, sizeof(cbuf))) {
	  msg_info(SS,"Could not parse server's subject CN into oneline");
	  tls_print_errors(SS);
	} else
	  SS->TLS.peer_CN1 = strdup(cbuf);


	cbuf[0] = '\0';
	if (!X509_NAME_get_text_by_NID(X509_get_issuer_name(peer),
				       NID_commonName, cbuf, sizeof(cbuf))) {
	  msg_info(SS,"Could not parse server's issuer CN");
	  tls_print_errors(SS);
	}
	if (!cbuf[0]) {
	  /* No issuer CN field, use Organization instead */
	  if (!X509_NAME_get_text_by_NID(X509_get_issuer_name(peer),
					 NID_organizationName, 
					 cbuf, sizeof(cbuf))) {
	    msg_info(SS,"Could not parse server's issuer Organization");
	    tls_print_errors(SS);
	  }
	}
	if (cbuf[0])
	  SS->TLS.issuer_CN = strdup(cbuf);


	cbuf[0] = 0;
	if (!X509_NAME_oneline(X509_get_issuer_name(peer),
			       cbuf, sizeof(cbuf))) {
	  msg_info(SS,"Could not parse server's issuer CN into oneline");
	  tls_print_errors(SS);
	} else
	  SS->TLS.issuer_CN1 = strdup(cbuf);

	{
	  ASN1_TIME *tm1, *tm2;
	  tm1 = X509_get_notBefore(peer);
	  tm2 = X509_get_notAfter(peer);

	  SS->TLS.notBefore = zdupnstr(tm1->data, tm1->length);
	  SS->TLS.notAfter  = zdupnstr(tm2->data, tm2->length);
	}


	if (tls_loglevel >= 1) {
	    if (SS->TLS.peer_verified)
	      msg_info(SS,"Verified: subject_CN=%s, issuer=%s",
		       SS->TLS.peer_CN1 ? SS->TLS.peer_CN1 : "",
		       SS->TLS.issuer_CN1 ? SS->TLS.issuer_CN1 : "");
	    else
	      msg_info(SS,"Unverified: subject_CN=%s, issuer=%s",
		       SS->TLS.peer_CN1 ? SS->TLS.peer_CN1 : "",
		       SS->TLS.issuer_CN1 ? SS->TLS.issuer_CN1 : "");
	}
	X509_free(peer);
    }


    /*
     * Finally, collect information about protocol and cipher for logging
     */ 
    SS->TLS.protocol       = SSL_get_version(SS->TLS.ssl);
    cipher = SSL_get_current_cipher(SS->TLS.ssl);
    SS->TLS.cipher_name    = SSL_CIPHER_get_name(cipher);
    SS->TLS.cipher_usebits = SSL_CIPHER_get_bits(cipher,
						 &SS->TLS.cipher_algbits);

    msg_info(SS, "TLS connection established: %s with cipher %s (%d/%d bits)",
	     SS->TLS.protocol, SS->TLS.cipher_name,
	     SS->TLS.cipher_usebits, SS->TLS.cipher_algbits);

    if (tls_use_read_ahead)
      SSL_set_read_ahead(SS->TLS.ssl, 1); /* Improves performance */

    /* Mark the mode! */
    SS->TLS.sslmode = 1;

    return (0);
}

/*
 * Shut down the TLS connection, that does mean:
 * remove all the information and reset the flags!
 * This is needed if the actual running smtp is to
 * be restarted. We do not give back any value, as
 * there is nothing to be reported.
 * Since our session cache is external, we will remove
 * the session from memory in any case. The SSL_CTX_flush_sessions
 * might be redundant here, I however want to make sure nothing is left.
 * RFC2246 requires us to remove sessions if something went wrong, as
 * indicated by the "failure" value,so we remove it from the external
 * cache, too.
 */
int     tls_stop_clienttls(SS, failure)
     SmtpState *SS;
     int failure;
{
	SSL_SESSION *session;
	int retval;

	vlog = SS->verboselog;

	if (SS->TLS.sslmode) {

	  session = SSL_get_session(SS->TLS.ssl);

	  /*
	   * Perform SSL_shutdown() twice, as the first attempt may
	   * return too early: it will only send out the shutdown
	   * alert but it will not wait for the peer's shutdown alert.
	   * Therefore, when we are the first party to send the alert,
	   * we must call SSL_shutdown() again.
	   * On failure we don't want to resume the session, so we will
	   * not perform SSL_shutdown() and the session will be removed
	   * as being bad.
	   */
	  if (!failure) {
	    retval = do_tls_operation(SS, timeout_tcpw,
				      SSL_shutdown, "shutdown");
	    if (retval == 0)
	      retval = do_tls_operation(SS, timeout_tcpw,
					SSL_shutdown, "shutdown");
	  }

	  /*
	   * Free the SSL structure and the BIOs.
	   * Warning: the internal_bio is connected to
	   * the SSL structure and is automatically freed
	   * with it. Do not free it again (core dump)!!
	   * Only free the network_bio.
	   */

#if 0
	  pfixtls_stir_seed();
	  pfixtls_exchange_seed();
#endif

	  if (SS->TLS.ssl) SSL_free(SS->TLS.ssl);
	  SS->TLS.ssl = NULL;

	  SSL_CTX_flush_sessions(SS->TLS.ctx, time(NULL));

	  SS->TLS.peer_verified  = 0;
	  SS->TLS.protocol       = NULL;
	  SS->TLS.cipher_name    = NULL;
	  SS->TLS.cipher_usebits = 0;
	  SS->TLS.cipher_algbits = 0;

#define ZCONDFREE(var) if (var) free((void*)(var))

	  ZCONDFREE(SS->TLS.peername_save);
	  ZCONDFREE(SS->TLS.peer_subject); /* server only ??? */
	  ZCONDFREE(SS->TLS.peer_issuer);
	  ZCONDFREE(SS->TLS.peer_fingerprint);
	  ZCONDFREE(SS->TLS.peer_CN);
	  ZCONDFREE(SS->TLS.peer_CN1);
	  ZCONDFREE(SS->TLS.issuer_CN);
	  ZCONDFREE(SS->TLS.issuer_CN1);
	  ZCONDFREE(SS->TLS.notBefore);
	  ZCONDFREE(SS->TLS.notAfter);
	}

	return (0);
}
#endif /* - HAVE_OPENSSL */


/* About timeouts the RFC 1123 recommends:
     - Initial 220: 5 minutes
     - MAIL, RCPT : 5 minutes
     - DATA initialization (until "354.."): 2 minutes
     - While writing data, a block
       at the time: 3 minutes  (How large a block ?)
     - From "." to "250 OK": 10 minutes
       (We use 60 minutes here - sendmail's default)
 */

extern int timeout;  /* That is the global setting.. */


/*
 * We have moved buffered writes to Sfio_t discipline function
 * smtp_sfwrite(), and now we can do timeouting properly in it..
 *
 * The write socket is ALWAYS in non-blocking mode!
 */
ssize_t smtp_sfwrite(sfp, vp, len, discp)
     Sfio_t *sfp;
     const void * vp;
     size_t len;
     Sfdisc_t *discp;
{
	struct smtpdisc *sd = (struct smtpdisc *)discp;
	SmtpState *SS = (SmtpState *)sd->SS;

	const char * p = (const char *)vp;
	int r, rr, e, i;

	vlog = SS->verboselog;

	/* If we have an errno status on a socket, it is extremely
	   persistent!  Absolutely no writes are allowed from now
	   on into this socket, and all write attempts will yield
	   the same errno value. */

	if (SS->lasterrno != 0) {
	  errno = SS->lasterrno;
	  return -1;
	}

	rr = -1; /* No successfull write */
	e = errno; /* Whatever the previous one was.. */

#if 1 /* Remove after debug tests */
	if (SS->verboselog)
	  fprintf(SS->verboselog,
		  " smtp_sfwrite() to write %d bytes\n", (int)len);
#endif
	
	if (sferror(sfp)) {  /* Don't even consider writing,
				if the stream has error status..
				Oddly this means the upper layers
				of sfio have failed somehow, and
				it has not affected the  "lasterrno"
				on SmtpState .. */

	  SS->lasterrno = errno = EIO;
	  return -1;
	}

	if (sffileno(sfp) < 0) { 	/* Write-FD killed!
					   (a sanity thing)
					   (One of those things
					   that should never happen..) */

	  SS->lasterrno = errno = EBADF;
	  return -1;
	}

	/* If 'len' is zero, return zero.. */
	/* (I have a feeling such writes are sometimes asked for..) */
	errno = 0;
	if (len == 0) return 0;

	errno = e;

	while (len > 0 && !sferror(sfp) && sffileno(sfp) >= 0) {

#ifdef HAVE_OPENSSL
	  if (SS->TLS.sslmode) {
	    r = SSL_write(SS->TLS.ssl, p, len);
	    e = SSL_get_error(SS->TLS.ssl, r);
	    switch (e) {
	    case SSL_ERROR_WANT_READ:
	      SS->TLS.wantreadwrite = -1;
	      e = EAGAIN;
	      break;
	    case SSL_ERROR_WANT_WRITE:
	      SS->TLS.wantreadwrite = 1;
	      e = EAGAIN;
	      break;
	    default:
	      SS->TLS.wantreadwrite = 0;
	      break;
	    }
	  } else
#endif /* - HAVE_OPENSSL */
	    {
	      r = write(sffileno(sfp), p, len);
	      e = errno;
	    }

	  if (r >= 0) {
	    if (rr < 0) rr = 0;	/* something successfull. init this!   */
	    rr  += r;		/* Accumulate writeout accounting      */
	    p   += r;		/* move pointer			       */
	    len -= r;		/* count down the length to be written */
	    continue;
	  }

	  /* Hmm..  Write bounced for some reason */
	  switch (e) {
	  case EAGAIN:
#ifdef EWOULDBLOCK
#if EWOULDBLOCK != EAGAIN
	  case EWOULDBLOCK:
#endif
#endif
	    {
	      /* Write blocked, lets select (and sleep) for write.. */
	      struct timeval tv, t0;
	      fd_set wrset, rdset;

#if 1 /* Remove after debug tests */
	      if (SS->verboselog)
		gettimeofday(&t0, NULL);
#endif

	      i = sffileno(sfp);
	      _Z_FD_ZERO(wrset);
	      _Z_FD_ZERO(rdset);

#ifdef HAVE_OPENSSL
	      if (SS->TLS.sslmode) {
		if (SS->TLS.wantreadwrite < 0)
		  _Z_FD_SET(i, rdset); /* READ WANTED */
		else if (SS->TLS.wantreadwrite > 0)
		  _Z_FD_SET(i, wrset); /* WRITE WANTED */
		else
		  ; /* FIXME! What???  No reading, nor writing ??? */
	      } else
#endif /* - HAVE_OPENSSL */
		{
		  _Z_FD_SET(i, wrset);
		}

	      tv.tv_sec = timeout_tcpw;
	      tv.tv_usec = 0;

	      errno = 0;
	      r = select(i+1, &rdset, &wrset, NULL, &tv);
	      e = errno;

#if 1 /* Remove after debug tests */
	      if (SS->verboselog) {
		struct timeval t2;

		gettimeofday(&t2, NULL);

		t2.tv_usec -= t0.tv_usec;
		if (t2.tv_usec < 0) {
		  t2.tv_usec += 1000000;
		  t2.tv_sec  -= 1;
		}
		t2.tv_sec -= t0.tv_sec;
		fprintf(SS->verboselog,
			" smtp_sfwrite() did select; rc=%d errno=%d len=%d dt=%d.%06d\n",
			r, e, (int)len, (int)t2.tv_sec, (int)t2.tv_usec);
	      }
#endif

	      if (r > 0)
		/* Ready to write! */
		break;

	      if (r == 0) {
		/* TIMEOUT!  Uarrgh!! */
		gotalarm = 1; 
		sfp->flags |= SF_ERROR; /* Ensure the error treatment.. */

		/* Actually KILL the outbound stream here! */

		if (sffileno(SS->smtpfp) >= 0) {
		  /* Error on write stream, write is thus from now on
		     FORBIDDEN!  We do a write direction shutdown on
		     the socket, and only listen for replies from now on... */
#ifdef HAVE_OPENSSL
		  if (SS->TLS.sslmode) {
		    /* SSL mode on, kill it completely... */
		    close(sffileno(SS->smtpfp));
		  } else
#endif /* - HAVE_OPENSSL */
		    shutdown(sffileno(SS->smtpfp), 1);
		  /* Absolutely NO SFIO SYNC AT THIS POINT! */
		  zsfsetfd(SS->smtpfp, -1);
		  SS->writeclosed = 1;
		  if (SS->verboselog)
		    fprintf(SS->verboselog,
			    "   ...  TIMEOUT! Shut-down of write direction!\n");
		}

		e = ETIMEDOUT;


zsyslog((LOG_ERR,
	 "%s: ERROR: SMTP socket write timeout; leftover=%d; IP=[%s] mx=%d/%d\n",
	 SS->taspoolid, len, SS->ipaddress, SS->firstmx, SS->mxcount));

		break;
	      }

	      /* Khrm... */
	      /* Select error status is sent out */
	    }
	    break;
	  default:
	    /* Any other errno.. */
	    break;
	  }

	  /* If STILL a error, break out -- will retry EINTR at  Sfio  library. */
	  if (r < 0) break;

	} /* End of while(len > 0) loop */

	if (rr < 0) SS->lasterrno = e;
	errno = e;
	return rr;
}

/*
 *  Our callers are doing all timeout processing all by themselves.
 *  Indeed this call is always executed on a non-blocking socket!
 */
int smtp_nbread(SS, buf, spc)
     SmtpState *SS;
     void *buf;
     int spc;
{
	int r, e;
	int infd = SS->smtpfd;


#if 0
	/* Flush outputs just in case the remote is stuck waiting
	   for us.. */
	if (SS->smtpfp && sffileno(SS->smtpfp) >= 0) sfsync(SS->smtpfp);
#endif

	vlog = SS->verboselog;

#ifdef HAVE_OPENSSL
	if (SS->TLS.sslmode) {
	  r = SSL_read(SS->TLS.ssl, buf, spc);
	  e = SSL_get_error(SS->TLS.ssl, r);
	  switch (e) {
	  case SSL_ERROR_WANT_READ:
	    SS->TLS.wantreadwrite = -1;
	    e = EAGAIN;
	    break;
	  case SSL_ERROR_WANT_WRITE:
	    SS->TLS.wantreadwrite =  1;
	    e = EAGAIN;
	    break;
	  default:
	    SS->TLS.wantreadwrite =  0;
	    break;
	  }
	  if (tls_loglevel >= 3) {
	    msg_info(SS,"smtp_nbread() rc=%d errno=%d", r, e);
	    if (r > 0) tls_dump(SS, buf, r);
	  }
	} else
#endif /* - HAVE_OPENSSL */
	  {
	    /* Normal read(2) */
	    r = read(infd, buf, spc);
	    e = errno;
#if 0
	    msg_info(SS,"smtp_nbread() rc=%d errno=%d", r, e);
	    if (r > 0) tls_dump(SS, buf, r);
#endif
	  }
  
	errno = e;
	return r;
}

int zsfsetfd(fp, fd)
     Sfio_t *fp;
     int fd;
{
  /* This is *NOT* the SFIO's sfsetfd() -- we do no sfsync() at any point.. */
  fp->file = fd;
  return fd;
}
