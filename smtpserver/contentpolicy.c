/*
 *  contentpolicy.c -- module for ZMailer's smtpserver
 *  By Matti Aarnio <mea@nic.funet.fi> 1998
 *
 *  This is the ugly one, we run SENSOR program on each
 *  accepted message -- if the sensor decrees the program
 *  unacceptable, we return policy-analysis result per
 *  analyzed file to the caller of this program.
 *
 */

#include "hostenv.h"
#include "mailer.h"

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <fcntl.h>
#ifdef HAVE_DB_H
#include <db.h>
#endif
#ifdef HAVE_NDBM_H
#define datum Ndatum
#include <ndbm.h>
#undef datum
#endif
#ifdef HAVE_GDBM_H
#define datum Gdatum
#include <gdbm.h>
#undef datum
#endif

#ifdef	HAVE_SYS_SOCKET_H
#include <sys/socket.h>

#include <netdb.h>

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

#endif

#include "libc.h"
#include "libz.h"

#define _POLICYTEST_INTERNAL_
#include "policytest.h"

extern int debug;


int
contentpolicy(rel, state, fname)
struct policytest *rel;
struct policystate *state;
const char *fname;
{

  if (state->always_reject)
    return -1;
  if (state->sender_reject)
    return -2;
  if (state->always_freeze)
    return 1;
  if (state->sender_freeze)
    return 1;
  if (state->always_accept)
    return 0;


  return 0; /* Until we have implementation */
}
