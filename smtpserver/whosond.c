/*
 *  ZMailer smtpserver support daemon; "whosond" (who-is-on-daemon)
 *
 *  This is intended to help on a problem of roaming users who are
 *  using local POP/IMAP servers from which they retrieve their
 *  incoming email, but whom normal smtp policy will reject due to
 *  their connecting address.
 *
 */


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
#include "libz.h"

#include "md5.h"

#include "splay.h"

#ifndef	MAXHOSTNAMELEN
#define	MAXHOSTNAMELEN 256
#endif				/* MAXHOSTNAMELEN */

#include "zsyslog.h"


int main(argc,argv)
     int argc;
     char *argv[];
{
  /*
    XX: Open up an UDP server socket
    XX: receive UDP datagrams of type  ``struct whosonreq''
    XX: Authenticate the query, if not authentic client, drop it..
    XX: Depending on action:
    XX: - Lookup for addresses from in-core database
    XX: - Store addresses + other data into in-core database
    XX: Reply to the querier about the data
    XX: Occasionally scrub old entries away... (?)
  */
}
