/*
 *	Copyright 1990 by Nicholas H. Briggs, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/* LINTLIBRARY */

#include "hostenv.h"

#ifdef	HAVE_YP
#include <rpc/rpc.h>
#include <netdb.h>
#include <sys/socket.h>
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/ypclnt.h>
#include <ctype.h>

#include "mailer.h"
#include "search.h"
#include "io.h"
#include "libz.h"
#include "libc.h"
#include "libsh.h"


/*
 * Query a Yellow Pages database
 */


conscell *
search_yp(sip)
	search_info *sip;
{
	int yperr;
	char *valptr;
	int vallen;
	conscell *tmp;
	char *ypdomainptr = NULL;
	char ypdomainname[YPMAXDOMAIN];

	/* use -f specification for default domain */
	if (sip->file != NULL) {
	  ypdomainptr = sip->file;
	  if (strlen(ypdomainptr) > YPMAXDOMAIN) {
	    fprintf(stderr, "search_yp: domain name `%.10s...' exceeds maximum length of %d\n",
		    ypdomainptr, YPMAXDOMAIN);
	    return NULL;
	  }
	}
	else {
	  ypdomainptr = ypdomainname;
	  if ((yperr = yp_get_default_domain(&ypdomainptr)) != 0) {
	    fprintf(stderr, "search_yp: %s.\n", yperr_string(yperr));
	    die(1, "yp_get_default_domain failure");
	  }
	}
	/* map name is specified as the subtype of the relation */

	if (sip->subtype == NULL || *(sip->subtype) == '\0') {
	  fprintf(stderr, "search_yp: missing map name for YP query!\n");
	  return NULL;
	} else if (strlen(sip->subtype) > YPMAXMAP) {
	  fprintf(stderr, "search_yp: map name `%.10s...' exceeds maximum length of %d\n",
		  sip->subtype, YPMAXMAP);
	  return NULL;
	}
	valptr = NULL;
	vallen = 0;
	yperr = yp_match(ypdomainptr, sip->subtype, sip->key,
			 strlen(sip->key), &valptr, &vallen);
decode_result:
	switch (yperr) {
	case 0:
	  /* trim leaning whitespace */
	  while (isspace(*valptr) && (vallen > 0)) {
	    valptr++; vallen--;
	  }
	  /* turn newline terminated values into null terminated values.
	   * the returned length of the value does not reflect the two extra
	   * bytes of memory allocated by NIS
	   */
	  if (valptr[vallen] == '\n') {
	    valptr[vallen] = '\0';
	  }
	  return newstring((u_char *) strnsave(valptr,vallen));
	case YPERR_KEY:
	  /* occasionally the terminating NULL is included in the key (lose!)
	     so if we failed for "key not found" then try again with the NULL
	   */
	  valptr = NULL;
	  vallen = 0;
	  yperr = yp_match(ypdomainptr, sip->subtype, sip->key,
			   strlen(sip->key)+1, &valptr, &vallen);
	  if (yperr != YPERR_KEY)
	    goto decode_result;
	  return NULL;
	default:
	  fprintf(stderr, "search_yp: %s\n", yperr_string(yperr));
	  return NULL;
	}
}

/*
 * Print the uid of the owner of the NIS map.  Since this information is
 * not actually available, and the maps are not particularly secure, we
 * claim that "nobody" owns the map.  nobody is defined in the library and
 * initialized by the "getnobody()" call in the router.
 */

int nobody;
void
owner_yp(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	fprintf(outfp, "%d\n", nobody);
	fflush(outfp);
}

void
print_yp(sip, outfp)
	search_info *sip;
	FILE *outfp;
{
	return;
}
#endif	/* HAVE_YP */
