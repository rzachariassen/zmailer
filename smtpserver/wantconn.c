/*
 * NAME
 * 
 * wantconn - build tcpd access control into any TCP or UDP application
 * 
 * SYNOPSIS
 * 
 * extern int wantconn(int sock, char *progname)
 * 
 * extern int allow_severity;
 * 
 * extern int deny_severity;
 * 
 * DESCRIPTION
 * 
 * wantconn() returns a non-zero value when the client in sock is allowed to
 * talk to the daemon in progname. As a side effect of calling wantconn(),
 * the syslog severity levels in the global variables allow_severity and
 * deny_severity may be updated.
 * 
 * wantconn() is not "paranoid", i.e. it does not autmoatically refuse clients
 * whose host name is inconsistent with their address.
 * 
 * AUTHOR
 * 
 * Wietse Venema, Eindhoven University of Technology, The Netherlands
 */

/*
 *  Integration into ZMailer autoconfiguration environment by
 *  Matti Aarnio  <mea@nic.funet.fi>
 */

#include "hostenv.h"
#ifdef HAVE_TCPD_H		/* The hall-mark of having tcp-wrapper things around */

#include <syslog.h>

#ifdef __hpux
#define request_info tcpd_request_info
#endif

#ifndef ALLOW_SEVERITY
#define ALLOW_SEVERITY	LOG_INFO
#define DENY_SEVERITY	LOG_WARNING
#endif

#include "tcpd.h"

int allow_severity;		/* run-time adjustable */
int deny_severity;		/* ditto */

int wantconn(sock, progname)
int sock;
char *progname;
{
    struct request_info request;

    /*
     * Reset the logging level in case we are called from a program that
     * responds to multiple clients.
     */
    allow_severity = ALLOW_SEVERITY;
    deny_severity = DENY_SEVERITY;

    /*
     * The user will expect that this will work as if sendmail is run under
     * control of the tcpd program. For perfect emulation we must be prepared
     * to do our own username lookup and whatever else tcpd may want to do in
     * the future. The cost is a small hit in performance.
     */
    request_init(&request, RQ_FILE, sock, RQ_DAEMON, progname, 0);
    fromhost(&request);
    return (hosts_access(&request));
}

#else
static int dummy = 0;		/* Some compilers complain, if the source is void.. */
#endif
