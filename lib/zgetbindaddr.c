/*
 * int zgetbindaddr(char *bindspec, Usockaddr *sap)
 */

/*
    Parse first argument for the specification of IP v.4 or v.6
    address or network interface.  If NULL or empty, fallback to
    the value of 'BINDADDR' ZENV variable.  On success, return
    zero, otherwise non-zero.  That is, if the caller gets zero
    code, it should bind() to the address returned in *sap, else
    bind to INADDR_ANY.

    Possible specification formats are:
	any
	[0.0.0.0]
	any6
	[IPv6.0::0]
	iface:eth0:1
	iface:v4:eth0:1
	iface:v6:eth0:1

	FIXME: IPv6 address handling in iface: syntax is completely
	       broken!   SCOPING needs to be used when picking it!
	       Very least..


    Original copyright by Matti Aarnio <mea@nic.funet.fi> 1997,2000,2004,2005,
    modifications by Eugene Crosser <crosser@average.org> 2002
*/

#include "hostenv.h"
#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <sys/ioctl.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <netinet/in.h>
#ifdef HAVE_NETINET_IN6_H
# include <netinet/in6.h>
#endif
#ifdef HAVE_NETINET6_IN6_H
# include <netinet6/in6.h>
#endif
#ifdef HAVE_LINUX_IN6_H
# include <linux/in6.h>
#endif
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>

#include "libc.h"
#include "zmalloc.h"
#include "libz.h"

#include "hostenv.h"

#include <arpa/inet.h>
#include <net/if.h>

int
zgetbindaddr(bindspec, af, sap)
	char *bindspec;
	int af;
	Usockaddr *sap;
{
	int result = 0;

	if ((bindspec == NULL) || (*bindspec == '\0'))
	        bindspec = (char *)getzenv("BINDADDR"); /* we modify this..*/
	if ((bindspec == NULL) || (*bindspec == '\0'))
		return 1; /* not specified - bind to INADDR_ANY */

	memset(sap, 0, sizeof(*sap));

#if defined(AF_INET6) && defined(INET6)
	if (cistrcmp(bindspec, "any6") == 0 && (af == AF_INET6)) {
	  sap->v6.sin6_family = AF_INET6;
	  /* All other fields are zero.. */

	} else 	if ((af == AF_INET6) &&
		    (cistrncmp(bindspec, "[ipv6 ", 6) == 0 ||
		     cistrncmp(bindspec, "[ipv6:", 6) == 0 ||
		     cistrncmp(bindspec, "[ipv6.", 6) == 0)) {
		char *s = strchr(bindspec, ']');
		int c = s ? *s : 0;
		if (s) *s = 0;
		if (inet_pton
		    (AF_INET6, bindspec + 6, &sap->v6.sin6_addr) < 1) {
			/* False IPv6 number literal */
			/* ... then we don't set the IP address... */
			if (s) *s = c;
			result = 1;
		}
		if (s) *s = c;
		sap->v6.sin6_family = AF_INET6;
	} else
#endif
	if (cistrcmp(bindspec, "any") == 0 && (af == AF_INET)) {
	  sap->v4.sin_family = AF_INET;
	  /* All other fields are zero.. */

	} else if (*bindspec == '[' && (af == AF_INET)) {
	  char *s = strchr(bindspec, ']');
	  int c = s ? *s : 0;
	  if (s) *s = 0;
	  if (inet_pton(AF_INET, bindspec + 1, &sap->v4.sin_addr) < 1) {
	    /* False IP(v4) number literal */
	    /* ... then we don't set the IP address... */
	    if (s) *s = c;
	    result = 1;
	  }
	  if (s) *s = c;
	  sap->v4.sin_family = AF_INET;
	} else {
	  if (CISTREQN(bindspec, "iface:", 6)) {
	    bindspec += 6;
	    if (strncmp(bindspec,"v4:",3) == 0) {
	      af = AF_INET;
	      bindspec += 3;
	    }
#if defined(AF_INET6) && defined(INET6)
	    if (strncmp(bindspec,"v6:",3) == 0) {
	      af = AF_INET6;
	      bindspec += 3;
	    }
	    if (af == AF_INET6) {
	      sap->v6.sin6_family = AF_INET6;
	      if (zgetifaddress( AF_INET6, bindspec, sap )) {
		/* Didn't get IPv6 interface address of given name.. */
		if (zgetifaddress( AF_INET6, bindspec, sap )) {
		  /* No recognized interface! */
		  result = 1;
		}
	      }
	      return result;
	    }
#endif
	    if (af == 0 || af == AF_INET) {
	      if (zgetifaddress( AF_INET, bindspec, sap )) {
		/* No recognized interface! */
		result = 1;
	      }
	      return result;
	    }
	    
	  } else {
	    /* XXX: TODO: Try to see if this is an interface name,
	       and pick IPv4 and/or IPv6 addresses for that
	       interface. */
	    result = 1;
	  }
	}
	return result;
}
