/*
 *  ZMailer smtpserver support daemon; "whosond" (who-is-on-daemon)
 *
 *  This is intended to help on a problem of roaming users who are
 *  using local POP/IMAP servers from which they retrieve their
 *  incoming email, but whom normal smtp policy will reject due to
 *  their connecting address.
 *
 */

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#ifdef HAVE_NETINET6_IN6_H
#include <netinet6/in6.h>
#endif
#ifdef HAVE_LINUX_IN6_H
#include <linux/in6.h>
#endif

#ifndef __Usockaddr__
typedef union {
    struct sockaddr_in v4;
#ifdef INET6
    struct sockaddr_in6 v6;
#endif
} Usockaddr;
#define __Usockaddr__
#endif


struct whosonreq {
  char          wh_user[8];		/* Client id */
  unsigned char wh_random[8];		/* Randomizing factor */
  unsigned char wh_authentic[16];	/* MD5 authenticator  */
  Usockaddr     wh_addr;		/* User's address */
  char		wh_uname[32];		/* Optional login username */
  unsigned char wh_cmd;			/* What ? */
  unsigned char wh_status;		/* ... exactly ? */
  unsigned char wh_seq;			/* Query id */
  unsigned char wh_age;			/* Age in minutes; top value: 255 */
};

#define WHCMD_QUERY	0
#define WHCMD_SET	1
#define WHSTAT_UNKNOWN  0
#define WHSTAT_LOGIN    1
#define WHSTAT_LOGOUT   2
