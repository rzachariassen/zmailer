#include "hostenv.h"
#ifdef HAVE_RESOLVER
#define USE_INET
#endif
#include <stdio.h>
#include "malloc.h"
#include <sys/types.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/file.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include "zmsignal.h"
#include <errno.h>
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>		/* If no  <stdarg.h>,  then presume <varargs.h> ... */
#endif

#include "whoson.h"
#include "libc.h"

#include "md5.h"

static int whoson_send_query(pktp)
     struct whosonreq *pktp;
{
  int sock;
  char *whosoncfg;

  /* Configuration in ZENV/ENV variable   WHOSONCFG,   with content
     like this:  serverip:serverport:username:whosonsecret(:more?) */

  whosoncfg = getzenv("WHOSONCFG");
  if (!whosoncfg)
    whosoncfg = getenv("WHOSONCFG");
  if (!whosoncfg)
    return -1;

  /* XX: pick configuration values, create UDP socket */
  /* XX: fill missing bits of the whoson request, compute
     the checksum. */
  /* XX: Send the packet, wait for a reply (1 sec?), retry
     up to a few times (5 ? 8 ?) */
  /* Receive reply packet into the same buffer (and size)
     as the query was, return 0 when got a reply (any reply ?) */
  return -1;
}

int whoson_register_addess(state,uname,addrp)
     void *addrp;
     char *uname;
     int state;
{
  struct whosonreq pkt;

  memset(&pkt,0,sizeof(pkt));
  memcpy(&pkt.wh_addr, addrp, sizeof(pkt.wh_addr));
  strncpy(pkt.wh_uname, uname, sizeof(pkt.wh_uname));
  pkt.wh_cmd = WHCMD_SET;
  pkt.wh_status = state;

  return whoson_send_query(&pkt);
}


/*
  == 0: Ok, exists
  != 0: Does not exist
*/
int whoson_query_address(addrp)
     void *addrp;
{
  struct whosonreq pkt;

  memset(&pkt,0,sizeof(pkt));
  memcpy(&pkt.wh_addr, addrp, sizeof(pkt.wh_addr));
  pkt.wh_cmd = WHCMD_QUERY;

  if (whoson_send_query(&pkt) != 0)
    return -1; /* No reply */

  if (pkt.wh_status != WHSTAT_UNKNOWN)
    return 0; /* Got reply, known */

  return 1; /* Got reply, not known */
}
