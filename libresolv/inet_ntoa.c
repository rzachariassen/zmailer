/*
 *	Copyright 1991 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *
 *	-- renamed for compability, and adjusted.. by Matti Aarnio
 *	   original was:  lib/dottedquad.c
 */

#include <sys/types.h>
#include <netinet/in.h>
#include "arpa/inet.h"

/*
 *  This is inet_ntoa() made for compability in case the SysVr4 features
 *  have mislaid the bit somewhere, like into -lnsl .. (libresolv needs this.)
 */

char *
inet_ntoa(ina)
	struct in_addr ina;
{
	static char buf[44];
	unsigned char *cp = (unsigned char *)&ina;

	sprintf(buf, "%d.%d.%d.%d", *(cp), *(cp+1), *(cp+2), *(cp+3));
	return buf;
}
