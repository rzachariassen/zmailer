/* This is heavily bastardized TLS code for SMTP client (POSTFIX) bt:
 *	Lutz Jaenicke
 *	BTU Cottbus
 *	Allgemeine Elektrotechnik
 *	Universitaetsplatz 3-4
 *	D-03044 Cottbus, Germany
 *
 * Adaptation to ZMailer is by Matti Aarnio <mea@nic.funet.fi> (c) 1999
 */

#include "smtp.h"

#ifdef HAVE_OPENSSL

static const char MAIL_TLS_CLNT_CACHE[] = "TLSclntcache";
static const int id_maxlength = 32;	/* Max ID length in bytes */

static int verify_depth;
static int verify_error = X509_V_OK;
static int do_dump = 0;
/* static SSL_CTX *ctx = NULL; */
/* static SSL *con = NULL; */

int	tls_scache_timeout = 3600;	/* One hour */
int	tls_use_scache     = 0;

#define CCERT_BUFSIZ 256
static char peer_CN[CCERT_BUFSIZ];
static char issuer_CN[CCERT_BUFSIZ];

static unsigned char md[EVP_MAX_MD_SIZE];
static unsigned char peername_md5[MD5_DIGEST_LENGTH];

extern int demand_TLS_mode;

int	tls_peer_verified = 0;

char   *tls_CAfile = NULL;
char   *tls_CApath = NULL;
char   *tls_cert_file = NULL;
char   *tls_key_file  = NULL;

char   *tls_protocol = NULL;
const char   *tls_cipher_name = NULL;
int	tls_cipher_usebits = 0;
int	tls_cipher_algbits = 0;

int	tls_loglevel = 0;


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
msg_info(va_alist)
	va_dcl
#endif
{
	va_list	ap;
#ifdef HAVE_STDARG_H
	va_start(ap,fmt);
#else
	SmtpState *SS;
	char *fmt;
	va_start(ap);
	SS  = va_arg(ap, SmtpState *);
	fmt = va_arg(ap, char *);
#endif
	if (!logfp) return;


#ifdef	HAVE_VPRINTF
	vfprintf(logfp, fmt, ap);
#else	/* !HAVE_VPRINTF */
 ERROR:ERROR:ERROR:No 
#endif	/* HAVE_VPRINTF */

	va_end(ap);
}


void mail_queue_path(buf, subdir, filename)
     char *buf;
     char *subdir;
     char *filename;
{
  char *po = getzenv("POSTOFFICE");
  if (!po) po = POSTOFFICE;

  sprintf(buf, "%s/%s/%s", po, subdir, filename);
}


 /*
  * Wrapper routines around read/write and read_wait/write_wait.
  * If TLS is active, we must use the appropriate SSL function
  * instead of the direct one.
  *
  * We do live quite comfortable here, as smtp_stream can only handle
  * one connection at a time, so we also only take to care of one
  * filedescriptor, which is saved as "tls_fd".
  *
  * You may note, that tls_read_wait() and tls_write_wait()
  * seem to be of no real use here. The reason is, that there is no
  * equivalent to "select()" available for the SSL connection. But I
  * already have prepared the wrapper functions, so once this equivalent
  * is available, we can immediately use it.
  *
  * We explicitly leave out the select() calls in TLS mode, as there
  * is buffering included in the SSL_* routines and we don't want to
  * have it hanging! Consider that there are still bytes in the SSL buffer,
  * but no new bytes arrive at the interface, then select() on the read
  * channel would wait erronously.
  *
  * The SSL_read() and SSL_write() calls are blocking anyway, so we can
  * live without select() at this time.
  */

int     tls_read(SS, fd, buf, count)
     SmtpState *SS;
     int fd;
     void *buf;
     size_t count;
{
    int     i;
    int     ret;
    char    mybuf[40];
    char   *mybuf2;

    if (SS->sslmode) {
	ret = SSL_read(SS->ssl, buf, count);
	if (tls_loglevel >= 4) {
	    mybuf2 = (char *) buf;
	    if (ret > 0) {
		i = 0;
		while ((i < 39) && (i < ret) && (mybuf2[i] != 0)) {
		    mybuf[i] = mybuf2[i];
		    i++;
		}
		mybuf[i] = '\0';
		msg_info(SS, "Read %d chars: %s", ret, mybuf);
	    }
	}
	return (ret);
    } else
	return (read(fd, buf, count));
}

int     tls_write(SS, fd, buf, count)
     SmtpState *SS;
     int fd;
     void *buf;
     size_t count;
{
    int     i;
    char    mybuf[40];
    char   *mybuf2;

    if (SS->sslmode) {
      if (tls_loglevel >= 4) {
	mybuf2 = (char *) buf;
	if (count > 0) {
	  i = 0;
	  while ((i < 39) && (i < count) && (mybuf2[i] != 0)) {
	    mybuf[i] = mybuf2[i];
	    i++;
	  }
	  mybuf[i] = '\0';
	  msg_info(SS, "Write %d chars: %s", count, mybuf);
	}
      }
      return (SSL_write(SS->ssl, buf, count));
    } else
      return (write(fd, buf, count));
}

/* skeleton taken from OpenSSL crypto/err/err_prn.c */

static void tls_print_errors(void)
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
	    msg_info(NULL, "%lu:%s:%s:%d:%s:", es, ERR_error_string(l, buf),
		     file, line, data);
	else
	    msg_info(NULL, "%lu:%s:%s:%d:", es, ERR_error_string(l, buf),
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

static int set_cert_stuff(SSL_CTX * ctx, char *cert_file, char *key_file)
{
    if (cert_file != NULL) {
	if (SSL_CTX_use_certificate_file(ctx, cert_file,
					 SSL_FILETYPE_PEM) <= 0) {
	    msg_info(NULL, "unable to get certificate from '%s'", cert_file);
	    tls_print_errors();
	    return (0);
	}
	if (key_file == NULL)
	    key_file = cert_file;
	if (SSL_CTX_use_PrivateKey_file(ctx, key_file,
					SSL_FILETYPE_PEM) <= 0) {
	    msg_info(NULL, "unable to get private key from '%s'", key_file);
	    tls_print_errors();
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

/* taken from OpenSSL apps/s_cb.c */

static int verify_callback(int ok, X509_STORE_CTX * ctx)
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
	msg_info(NULL, "Peer cert verify depth=%d %s", depth, buf);
    if (!ok) {
	msg_info(NULL, "verify error:num=%d:%s", err,
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
	msg_info(NULL, "issuer= %s", buf);
	break;
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
	msg_info(NULL, "cert not yet valid");
	break;
    case X509_V_ERR_CERT_HAS_EXPIRED:
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
	msg_info(NULL, "cert has expired");
	break;
    }
    if (tls_loglevel >= 1)
	msg_info(NULL, "verify return:%d", ok);
    return (ok);
}

/* taken from OpenSSL apps/s_cb.c */

static void apps_ssl_info_callback(SSL * s, int where, int ret)
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
	    msg_info(NULL, "%s:%s", str, SSL_state_string_long(s));
    } else if (where & SSL_CB_ALERT) {
	str = (where & SSL_CB_READ) ? "read" : "write";
	if (tls_loglevel >= 2 ||
	    ((ret & 0xff) != SSL3_AD_CLOSE_NOTIFY))
	msg_info(NULL, "SSL3 alert %s:%s:%s", str,
		 SSL_alert_type_string_long(ret),
		 SSL_alert_desc_string_long(ret));
    } else if (where & SSL_CB_EXIT) {
	if (ret == 0)
	    msg_info(NULL, "%s:failed in %s",
		     str, SSL_state_string_long(s));
	else if (ret < 0) {
	    msg_info(NULL, "%s:error in %s",
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

static int tls_dump(const char *s, int len)
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
	msg_info(NULL, "%s", buf);
	ret += strlen(buf);
    }
#ifdef TRUNCATE
    if (trunc > 0) {
	sprintf(buf, "%04x - <SPACES/NULS>\n", len + trunc);
	msg_info(NULL, "%s", buf);
	ret += strlen(buf);
    }
#endif
    return (ret);
}



/* taken from OpenSSL apps/s_cb.c */

static long bio_dump_cb(BIO * bio, int cmd, const char *argp, int argi,
			long argl, long ret)
{
    if (!do_dump)
	return (ret);

    if (cmd == (BIO_CB_READ | BIO_CB_RETURN)) {
	msg_info(NULL, "read from %08X [%08lX] (%d bytes => %ld (0x%X))",
		 bio, argp, argi, ret, ret);
	tls_dump(argp, (int) ret);
	return (ret);
    } else if (cmd == (BIO_CB_WRITE | BIO_CB_RETURN)) {
	msg_info(NULL, "write to %08X [%08lX] (%d bytes => %ld (0x%X))",
		 bio, argp, argi, ret, ret);
	tls_dump(argp, (int) ret);
    }
    return (ret);
}


static SSL_SESSION *load_clnt_session(unsigned char *SessionID, int length,
				      int *verify_result)
{
    SSL_SESSION *session;
    char *buf;
    FILE *fp;
    struct stat st;
    char *idstring;
    int n;
    int uselength;

    if (length > id_maxlength)
	uselength = id_maxlength;	/* Limit length of ID */
    else
	uselength = length;

    idstring = (char *)malloc(2 * uselength + 1);
    if (!idstring) {
	msg_info(NULL, "could not allocate memory for IDstring");
	return (NULL);
    }

    for(n=0 ; n < uselength ; n++)
	sprintf(idstring+2*n, "%02X", SessionID[n]);
    if (tls_loglevel >= 3)
	msg_info(NULL, "Trying to reload Session from disc: %s", idstring);

    // FIXME: xxx
    buf = (char *)malloc(100 + 2 * uselength + 1);
    mail_queue_path(buf, MAIL_TLS_CLNT_CACHE, idstring);

    /*
     * Try to read the session from the file. If the file exists, but its
     * mtime is so old, that the session has already expired, we don´t
     * waste time anymore, we rather delete the session file immediately.
     *
     * There is a race condition included. If another process is putting
     * a new session file for the same HostID in the time during the
     * "stat()" and the REMOVE, we will delete this new session from the
     * disc cache. Well, then we have to negotiate a new one.
     */
    session = NULL;
    if (stat(buf, &st) == 0) {
	if (st.st_mtime + tls_scache_timeout < time(NULL))
            unlink(buf);
	else if ((fp = fopen(buf, "r")) != 0) {
	    if (fscanf(fp, "%d", verify_result) <= 0)
		*verify_result = X509_V_ERR_APPLICATION_VERIFICATION;
	    session = PEM_read_SSL_SESSION(fp, NULL, NULL, NULL);
	    fclose(fp);
	}
    }

    free(buf);
    free(idstring);

    if (session && (tls_loglevel >= 3))
        msg_info(NULL, "Successfully reloaded session from disc");

    return (session);
}


static void remove_clnt_session(unsigned char *SessionID, int length)
{
    char *buf;
    char *idstring;
    int n;
    int uselength;

    if (length > id_maxlength)
	uselength = id_maxlength;	/* Limit length of ID */
    else
	uselength = length;

    idstring = (char *)malloc(2 * uselength + 1);
    if (!idstring) {
	msg_info(NULL, "could not allocate memory for IDstring");
	return;
    }

    for(n=0 ; n < uselength ; n++)
	sprintf(idstring + 2 * n, "%02X", SessionID[n]);
    if (tls_loglevel >= 3)
	msg_info(NULL, "Trying to remove session from disc: %s", idstring);

    /*
     * The constant "100" is taken from mail_queue.c and also used there.
     * It must hold the name the postfix spool directory (if not chrooted)
     * and the hash directory forest.
     */
    buf = malloc(100 + 2 * uselength + 1);
    mail_queue_path(buf, MAIL_TLS_CLNT_CACHE, idstring);

    /*
     * Try to remove the session from the disc cache. Don´t care for return
     * values, as either the session file is already gone or there is nothing
     * we can do anyway.
     */
    unlink(buf);

    free(buf);
    free(idstring);
}


 /*
  * Save the new session to the external cache. As the HostID is given
  * by the contacted peer, we may have several negotiations going on at
  * the same time for the same peer. This is not purely hypothetical but
  * quite likely if several jobs to the same recipient host are in the queue
  * and a queue run is started. So we have to take care of race conditions.
  * As I consider the TLS-SessionID to be unique, we will first try to
  * create a file with the actual SessionID. Once the writing is finished,
  * the file is closed and moved to its final name. This way we should be
  * able to deal with race conditions, since rename should be atomic.
  * If the rename fails for some reason, we will just silently remove
  * the temporary file and forget about the session.
  */
static void save_clnt_session(SSL_SESSION *session, unsigned char *HostID,
			      int length, int verify_result)
{
    char *buf;
    char *temp;
    FILE *fp;
    char *myname = "save_clnt_session";
    char *idstring;
    int uselength;
    int n;
    int fd;
    int success;

    if (length > id_maxlength)
	uselength = id_maxlength;	/* Limit length of ID */
    else
	uselength = length;

    idstring = (char *)malloc(2 * id_maxlength + 1);
    if (!idstring) {
	msg_info(NULL, "could not allocate memory for IDstring");
    }

    for(n=0 ; n < uselength ; n++)
	sprintf(idstring + 2 * n, "%02X", HostID[n]);

    buf = malloc(100 + 2 * id_maxlength + 1);
    mail_queue_path(buf, MAIL_TLS_CLNT_CACHE, idstring);
    if (tls_loglevel >= 3)
	msg_info(NULL, "Trying to save session for hostID to disc: %s", idstring);

    if (session->session_id_length > id_maxlength)
	uselength = id_maxlength;	/* Limit length of ID */
    else
	uselength = session->session_id_length;

    for(n=0 ; n < uselength ; n++)
        sprintf(idstring + 2 * n, "%02X", session->session_id[n]);
    if (tls_loglevel >= 3)
	msg_info(NULL, "Session ID is %s", idstring);

    temp = malloc(100 + 2 * id_maxlength + 1);
    mail_queue_path(temp, MAIL_TLS_CLNT_CACHE, idstring);

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
    if ((fd = open(temp, O_WRONLY | O_CREAT | O_EXCL, 0600)) >= 0) {
      if ((fp = fdopen(fd, "w")) == 0) {
	msg_info(NULL,"%s: could not fdopen %s: %s", myname, temp,
		 strerror(errno));
	return;
      }
      fprintf(fp, "%d\n", verify_result);
      success = PEM_write_SSL_SESSION(fp, session);
      fclose(fp);
      if (success == 0)
	unlink(temp);
      else if (rename(temp, buf) != 0)
	unlink(temp);
      else if (tls_loglevel >= 3)
	msg_info(NULL, "Successfully saved session to disc");
    }

    free(temp);
    free(buf);
    free(idstring);
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
  char   *CApath;
  char   *CAfile;
  char   *c_cert_file;
  char   *c_key_file;
  int	  verifydepth = 0;
  FILE   *fp;
  char	  buf[1024], *s, *a1, *a2;

  if (SS->sslmode)
    return (0);				/* already running */

  fp = fopen(cfgpath,"r");
  if (!fp) {
    msg_info(SS, "Can't read TLS config file: '%s'\n",cfgpath);
    return -1;
  }
  while (!feof(fp) && !ferror(fp)) {
    if (!fgets(buf, sizeof(buf), fp))
      break;
    s = strchr(buf, '\n');
    if (s) *s = 0;
    s = buf;
    while (*s == ' ' || *s == '\t') ++s;
    if (!*s || *s == '#' || *s == ';')
      continue;
    a1 = strtok(s, " \t");
    a2 = strtok(a1, " \t");
    if        (strcasecmp(s, "tls-cert-file") == 0 && a1) {
      tls_cert_file = strdup(a1);
    } else if (strcasecmp(s, "tls-key-file") == 0  && a1) {
      tls_key_file = strdup(a1);
    } else if (strcasecmp(s, "tls-CAfile") == 0     && a1) {
      tls_CAfile = strdup(a1);
    } else if (strcasecmp(s, "tls-CApath") == 0     && a1) {
      tls_CApath = strdup(a1);
    } else if (strcasecmp(s, "tls-loglevel") == 0   && a1) {
      tls_loglevel = atol(a1);
      if (tls_loglevel < 0) tls_loglevel = 0;
      if (tls_loglevel > 4) tls_loglevel = 4;
    } else if (strcasecmp(s, "tls-use-scache") == 0) {
      tls_use_scache = 1;
    } else if (strcasecmp(s, "tls-scache-timeout") == 0 && a1) {
      tls_scache_timeout = atol(a1);
      if (tls_loglevel < 0) tls_loglevel = 0;
      if (tls_loglevel > 4) tls_loglevel = 4;
    } else if (strcasecmp(s, "demand-tls-mode") == 0) {
      demand_TLS_mode = 1;
    }
  }
  fclose(fp);

  if (tls_loglevel >= 2)
    msg_info(SS, "starting TLS engine");

  /*
   * Initialize the OpenSSL library by the book!
   * To start with, we must initialize the algorithms.
   * We want cleartext error messages instead of just error codes, so we
   * load the error_strings.
   */ 
  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();

  /*
   * The SSL/TLS speficications require the client to send a message in
   * the oldest specification it understands with the highest level it
   * understands in the message.
   * RFC2487 is only specified for TLSv1, but we want to be as compatible
   * as possible, so we will start off with a SSLv2 greeting allowing
   * the best we can offer: TLSv1.
   * We can restrict this with the options setting later, anyhow.
   */
  SS->ctx = SSL_CTX_new(SSLv23_client_method());
  if (SS->ctx == NULL) {
    tls_print_errors();
    return (-1);
  }

  /*
   * Here we might set SSL_OP_NO_SSLv2, SSL_OP_NO_SSLv3, SSL_OP_NO_TLSv1.
   * Of course, the last one would not make sense, since RFC2487 is only
   * defined for TLS, but we don´t know what is out there. So leave things
   * completely open, as of today.
   */
  off |= SSL_OP_ALL;		/* Work around all known bugs */
  SSL_CTX_set_options(SS->ctx, off);

  /*
   * Set the info_callback, that will print out messages during
   * communication on demand.
   */
  SSL_CTX_set_info_callback(SS->ctx, apps_ssl_info_callback);

  /*
   * Initialize the session cache. We only want external caching to
   * synchronize between server sessions, so we set it to a minimum value
   * of 1. If the external cache is disabled, we won´t cache at all.
   *
   * In case of the client, there is no callback used in OpenSSL, so
   * we must call the session cache functions manually during the process.
   */
  SSL_CTX_sess_set_cache_size(SS->ctx, 1);
  SSL_CTX_set_timeout(SS->ctx, tls_scache_timeout);
   
  /*
   * Now we must add the necessary certificate stuff: A client key, a
   * client certificate, and the CA certificates for both the client
   * cert and the verification of server certificates.
   * In fact, we do not need a client certificate,  so the certificates
   * are only loaded (and checked), if supplied. A clever client would
   * handle multiple client certificates and decide based on the list
   * of acceptable CAs, sent by the server, which certificate to submit.
   * OpenSSL does however not do this and also has no callback hoods to
   * easily realize it.
   *
   * As provided by OpenSSL we support two types of CA certificate handling:
   * One possibility is to add all CA certificates to one large CAfile,
   * the other possibility is a directory pointed to by CApath, containing
   * seperate files for each CA pointed on by softlinks named by the hash
   * values of the certificate.
   * The first alternative has the advantage, that the file is opened and
   * read at startup time, so that you don´t have the hassle to maintain
   * another copy of the CApath directory for chroot-jail. On the other
   * hand, the file is not really readable.
   */ 
  if (strlen(tls_CAfile) == 0)
    CAfile = NULL;
  else
    CAfile = tls_CAfile;
  if (strlen(tls_CApath) == 0)
    CApath = NULL;
  else
    CApath = tls_CApath;
  if (CAfile || CApath)
    if ((!SSL_CTX_load_verify_locations(SS->ctx, CAfile, CApath)) ||
	(!SSL_CTX_set_default_verify_paths(SS->ctx))) {
      msg_info(SS, "TLS engine: cannot load CA data");
      tls_print_errors();
      return (-1);
    }

  if (strlen(tls_cert_file) == 0)
    c_cert_file = NULL;
  else
    c_cert_file = tls_cert_file;
  if (strlen(tls_key_file) == 0)
    c_key_file = NULL;
  else
    c_key_file = tls_key_file;
  if (c_cert_file || c_key_file)
    if (!set_cert_stuff(SS->ctx, c_cert_file, c_key_file)) {
      msg_info(SS, "TLS engine: cannot load cert/key data");
      tls_print_errors();
      return (-1);
    }

  /*
   * Sometimes a temporary RSA key might be needed by the OpenSSL
   * library. The OpenSSL doc indicates, that this might happen when
   * export ciphers are in use. We have to provide one, so well, we
   * just do it.
   */
  SSL_CTX_set_tmp_rsa_callback(SS->ctx, tmp_rsa_cb);

  /*
   * Finally, the setup for the server certificate checking, done
   * "by the book".
   */
  verify_depth = verifydepth;
  SSL_CTX_set_verify(SS->ctx, verify_flags, verify_callback);


  SS->sslmode = 1;
  return (0);
}

 /*
  * This is the actual startup routine for the connection. We expect
  * that the buffers are flushed and the "220 Ready to start TLS" was
  * received by us, so that we can immediately can start the TLS
  * handshake process.
  */
int     tls_start_clienttls(SS,peername)
     SmtpState *SS;
     const char *peername;
{
    int     sts;
    int     j;
    unsigned int n;
    SSL_SESSION *session;
    SSL_CIPHER *cipher;
    X509   *peer;
    int     save_session;
    int	    length;
    int     verify_result;
    unsigned char *old_session_id;

    if (!SS->sslmode) {		/* should never happen */
	msg_info(SS, "tls_engine not running");
	return (-1);
    }
    if (tls_loglevel >= 1)
	msg_info(SS, "setting up TLS connection");

    /*
     * If necessary, setup a new SSL structure for a connection. We keep
     * old ones on closure, so it might not be always necessary. We however
     * reset the old one, just in case.
     */
    if (SS->ssl != NULL)
	SSL_clear(SS->ssl);
    else if ((SS->ssl = (SSL *) SSL_new(SS->ctx)) == NULL) {
	msg_info(SS, "Could not allocate 'con' with SSL_new()");
	tls_print_errors();
	return (-1);
    }
    old_session_id = NULL;	/* make sure no old info is kept */

    /*
     * Now, connect the filedescripter set earlier to the SSL connection
     */
    if (!SSL_set_fd(SS->ssl, sffileno(SS->smtpfp))) {
	msg_info(SS, "SSL_set_fd failed");
	tls_print_errors();
	return (-1);
    }

    /*
     * Find out the hashed HostID for the client cache and try to
     * load the session from the cache.
     * "old_session_id" holds the session ID of the reloaded session, so that
     * we can later check, whether it is really reused.
     */
    if (tls_use_scache) {
	MD5(peername, strlen(peername), peername_md5);
	session = load_clnt_session(peername_md5, MD5_DIGEST_LENGTH,
				    &verify_result);
	if (session) {
	   SSL_CTX_add_session(SS->ctx, session);
	   SSL_set_session(SS->ssl, session);
	   old_session_id = malloc(session->session_id_length);
	   if (old_session_id)
	     memcpy(old_session_id, session->session_id,
		    session->session_id_length);
	   
	}
    }

    /*
     * Initialize the SSL connection to connect state. This should not be
     * necessary anymore since 0.9.3, but the call is still in the library
     * and maintaining compatibility never hurts.
     */
    SSL_set_connect_state(SS->ssl);

    /*
     * If the debug level selected is high enough, all of the data is
     * dumped: 3 will dump the SSL negotiation, 4 will dump everything.
     *
     * We do have an SSL_set_fd() and now suddenly a BIO_ routine is called?
     * Well there is a BIO below the SSL routines that is automatically
     * created for us, so we can use it for debugging purposes.
     */
    if (tls_loglevel >= 3)
	BIO_set_callback(SSL_get_rbio(SS->ssl), bio_dump_cb);

    /* Dump the negotiation for loglevels 3 and 4 */
    if (tls_loglevel >= 3)
	do_dump = 1;

    /*
     * Now we expect the negotiation to begin. This whole process is like a
     * black box for us. We totally have to rely on the routines build into
     * the OpenSSL library. The only thing we can do we already have done
     * by choosing our own callback certificate verification.
     *
     * Error handling:
     * If the SSL handhake fails, we print out an error message and remove
     * everything that might be there. A session has to be removed anyway,
     * because RFC2246 requires it. 
     */
    if ((sts = SSL_connect(SS->ssl)) <= 0) {
	msg_info(SS, "SSL_connect error %d", sts);
	tls_print_errors();
	session = SSL_get_session(SS->ssl);
	if (session) {
	    remove_clnt_session(session->session_id,
			        session->session_id_length);
	    SSL_CTX_remove_session(SS->ctx, session);
	    msg_info(SS, "SSL session removed");
	}
	SSL_free(SS->ssl);
	SS->ssl = NULL;
	return (-1);
    }

    /*
     * Now we must save the new session to disk, if necessary. If we had
     * an old session, its ID was saved in "old_session_id" for comparison.
     */
    session = SSL_get_session(SS->ssl);
    if (tls_use_scache && session) {
	save_session = 1;
	if (old_session_id) {
	    if (memcmp(session->session_id, old_session_id,
		       session->session_id_length) == 0) {
		if (tls_loglevel >= 3)
		    msg_info(SS, "Reusing old session");
		save_session = 0;
		SSL_set_verify_result(SS->ssl, verify_result);
	    }
	    free(old_session_id);
	}
	if (save_session)
	    save_clnt_session(session, peername_md5, MD5_DIGEST_LENGTH,
			      SSL_get_verify_result(SS->ssl));
    }

    /* Only loglevel==4 dumps everything */
    if (tls_loglevel < 4)
	do_dump = 0;

    /*
     * Check the verification state of the peer certificate.
     */
    if (SSL_get_verify_result(SS->ssl) == X509_V_OK) {
	tls_peer_verified = 1;
    }

    /*
     * Lets see, whether a peer certificate is available and what is
     * the actual information. We want to save it for later use.
     */
    peer = SSL_get_peer_certificate(SS->ssl);
    if (peer != NULL) {
	X509_NAME_get_text_by_NID(X509_get_subject_name(peer),
				  NID_commonName, peer_CN, CCERT_BUFSIZ);
	X509_NAME_get_text_by_NID(X509_get_issuer_name(peer),
				  NID_commonName, issuer_CN, CCERT_BUFSIZ);
	if (tls_loglevel >= 3)
	    msg_info(SS, "subject_CN=%s, issuer_CN=%s", peer_CN, issuer_CN);
	X509_free(peer);
    }

    /*
     * Finally, collect information about protocol and cipher for logging
     */ 
    tls_protocol = SSL_get_version(SS->ssl);
    cipher = SSL_get_current_cipher(SS->ssl);
    tls_cipher_name = SSL_CIPHER_get_name(cipher);
    tls_cipher_usebits = SSL_CIPHER_get_bits(cipher, &tls_cipher_algbits);

    msg_info(SS, "TLS connection established: %s with cipher %s (%d/%d bits)",
	     tls_protocol, tls_cipher_name,
	     tls_cipher_usebits, tls_cipher_algbits);

    SSL_set_read_ahead(SS->ssl, 1); /* Improves performance */

    return (0);
}

 /*
  * Shut down the TLS connection, that does mean: remove all the information
  * and reset the flags! This is needed if the actual running smtp is to
  * be restarted. We do not give back any value, as there is nothing to
  * be reported.
  * Since our session cache is external, we will remove the session from
  * memory in any case. The SSL_CTX_flush_sessions might be redundant here,
  * I however want to make sure nothing is left.
  * RFC2246 requires us to remove sessions if something went wrong, as
  * indicated by the "failure" value,so we remove it from the external
  * cache, too.
  */
int     tls_stop_clienttls(SS, failure)
     SmtpState *SS;
     int failure;
{
    SSL_SESSION *session;

    if (SS->sslmode) {
	session = SSL_get_session(SS->ssl);
	SSL_shutdown(SS->ssl);
	if (session) {
	    if (failure) {
	      remove_clnt_session(peername_md5, MD5_DIGEST_LENGTH);
	      msg_info(SS, "SSL session removed");
	    }
	    SSL_CTX_remove_session(SS->ctx, session);
	    SSL_free(SS->ssl);
	    SS->ssl = NULL;
	}
	SSL_CTX_flush_sessions(SS->ctx,time(NULL));

	tls_peer_verified = 0;
	tls_protocol = NULL;
	tls_cipher_name = NULL;
	tls_cipher_usebits = 0;
	tls_cipher_algbits = 0;
    }

    return (0);
}
#endif /* - HAVE_OPENSSL */


ssize_t smtp_sfwrite(sfp, p, len, discp)
     Sfio_t *sfp;
     const void * p;
     size_t len;
     Sfdisc_t *discp;
{
#ifdef HAVE_OPENSSL
  /* FIXME: Must be changed for SSL/TLS streams! */

#if 0 /* Code in reserve for latter work... */
  struct smtpdisc *sd = (struct smtpdisc *)discp;
  SmtpState *SS = (SmtpState *)sd->SS;
#endif

#endif /* - HAVE_OPENSSL */

  return write(sffileno(sfp), p, len);
}


int smtp_nbread(SS, buf, spc, nonblocking)
     SmtpState *SS;
     void *buf;
     int spc, nonblocking;
{
  int r, flg, e;
  int infd = sffileno(SS->smtpfp);


  if (nonblocking) {
    flg = fd_nonblockingmode(infd);
#ifdef HAVE_OPENSSL
    if (SS->sslmode)
      r = SSL_read(SS->ssl, buf, spc);
    else
#endif /* - HAVE_OPENSSL */
      r = read(infd, buf, spc);
    e = errno;
    fcntl(infd, F_SETFL, flg);
    errno = e;
  } else {
#ifdef HAVE_OPENSSL
    if (SS->sslmode)
      r = SSL_read(SS->ssl, buf, spc);
    else
#endif /* - HAVE_OPENSSL */
      r = read(infd, buf, spc);
  }

  return r;
}
