/*
 *
 * Test harness for  zgetbindaddr()  function.
 *
 * Copyright by Matti Aarnio <mea@nic.funet.fi> 2006
 *
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

const char *progname;

int main(argc, argv)
     int argc;
     char **argv;
{

	int i;

	Usockaddr sa;

	if (argc < 2) exit(64);

	progname = argv[0];


	i = zgetbindaddr(argv[1], 0, &sa);
	i = zgetbindaddr(argv[1], 1, &sa);

}
