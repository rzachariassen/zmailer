/*
 *  External module to do authentication at ZMAiler
 *  SMTP server against the SASLAUTHD.
 *
 *  With CMU Cyrus SASL v.2 libraries:
 *
 *     gcc -v -O -g  -o smtpauth-sasl smtpauth-sasl.c -lsasl2
 *
 *  For runtime: at file:  /opt/csasl2/lib/sasl2/smtpserver.conf 
 *
 *      pwcheck_method: saslauthd
 *
 */

#include <stdio.h>
#include <sasl/sasl.h>

int main(int argc, char *argv[])
{
  int rc;
  sasl_conn_t *conn;
  char buf[256];
  char *s;

  if (argc != 2) exit(64);
  if (argv[1][0] == 0) exit(64);

  rc = sasl_server_init(NULL, "smtpserver");
  if (rc != SASL_OK) exit(30);

  rc = sasl_server_new("smtpserver",NULL,"",
		       NULL, NULL, NULL,
		       0, &conn);
  if (rc != SASL_OK) exit(31);

  buf[sizeof(buf)-1] = 0;
  if (!fgets(buf, sizeof(buf)-1, stdin))
    exit(32); /* BAD read result! */

  s = strchr(buf, '\n'); /* Zap the newline... */
  if (s) *s = 0;

  rc = sasl_checkpass(conn,
		      argv[1], strlen(argv[1]),
		      buf, strlen(buf));
  if (rc < 0) rc = -rc;

  sasl_dispose(&conn);
  sasl_done();

  exit(rc);
}
