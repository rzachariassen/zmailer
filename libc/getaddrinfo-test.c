/*
 *	GETADDRINFO-TEST test-harness to verify that  getaddrinfo()
 *	has properly functioning 
 *
 *	Copyright 1991-2003 by Matti Aarnio <matti.aarnio@zmailer.org>
 */


#define	RFC974		/* If BIND, check that TCP SMTP service is enabled */

#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sysexits.h>
#include <string.h>

#include <sys/socket.h>
#include <netdb.h>
extern int h_errno;

int
getaddrinfo_test(host)
	const char *host;
{
	int n;
	struct addrinfo req, *ai;

	memset(&req, 0, sizeof(req));

	req.ai_socktype = SOCK_STREAM;
	req.ai_protocol = IPPROTO_TCP;
	req.ai_flags    = AI_CANONNAME;
	req.ai_family   = PF_INET;

	ai = NULL;
	n = 0;
	n = getaddrinfo(host, "0", &req, &ai);

	printf(" getaddrinfo('%s','0') (PF_INET) -> r=%d (%s), ai=%p\n",
	       host, n, gai_strerror(n), ai);

	switch (n) {
	case 0:
	  n = EX_OK;
	  break;
	case EAI_AGAIN:
	  n = EX_TEMPFAIL;
	  break;
	case EAI_NONAME:
	case EAI_FAIL:
	case EAI_NODATA:
	case EAI_SERVICE:
	  n = EX_UNAVAILABLE;
	  break;
	case EAI_MEMORY:
	default:
	  n = EX_OSERR;
	  break;
	}
	return n;
}


int
gethostbyname_test(host)
	const char *host;
{
	int n;
	struct hostent *hp;

	hp = gethostbyname(host);
	n = h_errno;

	printf(" gethostbyname('%s') (PF_INET) -> hp=%p, r=%d ",
	       host, hp, n);

	if (n == 0) {
	  printf("OK\n");
	  return EX_OK;
	}
	if (n == TRY_AGAIN) {
	  printf("TRY_AGAIN\n");
	  return EX_TEMPFAIL;
	}
	if (n == NO_RECOVERY) {
	  printf("NO_RECOVERY\n");
	  return EX_TEMPFAIL;
	}
	if (n == HOST_NOT_FOUND) {
	  printf("HOST_NOT_FOUND\n");
	  return EX_UNAVAILABLE;
	}
	if (n == NO_ADDRESS    ) {
	  printf("NO_ADDRESS\n");
	  return EX_UNAVAILABLE;
	}
	if (n == NO_DATA       ) {
	  printf("NO_DATA\n");
	  return EX_UNAVAILABLE;
	}
	
	printf("UNKNOWN h_errno CODE\n");
	return EX_OSERR;
}

static const char * str_exitstatus(const int rc)
{
	char *s;
	switch (rc) {
	case EX_OK:
	  s = "EX_OK";
	  break;
	case EX_USAGE:
	  s = "EX_USAGE";
	  break;
	case EX_DATAERR:
	  s = "EX_DATAERR";
	  break;
	case EX_NOINPUT:
	  s = "EX_NOINPUT";
	  break;
	case EX_NOUSER:
	  s = "EX_NOUSER";
	  break;
	case EX_NOHOST:
	  s = "EX_NOHOST";
	  break;
	case EX_UNAVAILABLE:
	  s = "EX_UNAVAILABLE";
	  break;
	case EX_SOFTWARE:
	  s = "EX_SOFTWARE";
	  break;
	case EX_OSERR:
	  s = "EX_OSERR";
	  break;
	case EX_OSFILE:
	  s = "EX_OSFILE";
	  break;
	case EX_CANTCREAT:
	  s = "EX_CANTCREAT";
	  break;
	case EX_IOERR:
	  s = "EX_IOERR";
	  break;
	case EX_TEMPFAIL:
	  s = "EX_TEMPFAIL";
	  break;
	case EX_PROTOCOL:
	  s = "EX_PROTOCOL";
	  break;
	case EX_NOPERM:
	  s = "EX_NOPERM";
	  break;
#ifdef EX_DEEFERALL
	case EX_DEFERALL:
	  s = "EX_DEFERALL";
	  break;
#endif
	default:
	  s = "UNKNOWN!";
	}
	return s;
}

int main(argc, argv)
     int argc;
     char *argv[];
{
	int rc;
	const char *s;

	if (argc != 1) {
	  printf("Usage: ./getaddrinfo-test\n");
	  printf("\n");
	  exit(EX_USAGE);
	}

	printf("ZMAILER GETADDRINFO() TEST HARNESS\n");

	printf("Looking up for  www.zmailer.org -- should yield OK!\n");
	rc = getaddrinfo_test("www.zmailer.org");
	s = str_exitstatus(rc);
	printf("  ... %s\n", s);

	printf("Looking up for  timeout-zone.zmailer.org -- should yield TEMPFAIL!\n");
	rc = getaddrinfo_test("timeout-zone.zmailer.org");
	s = str_exitstatus(rc);
	printf("  ... %s\n", s);


	printf("Looking up for  timeout-zone.zmailer.org -- should yield TEMPFAIL!\n");
	rc = gethostbyname_test("timeout-zone.zmailer.org");
	s = str_exitstatus(rc);
	printf("  ... %s\n", s);



	return 0;
}
