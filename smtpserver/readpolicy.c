/*
 *  policy.h  -- ZMailer's smtpserver's runtime address acceptance
 *               policy database mechanisms.
 *
 *  By Matti Aarnio <mea@nic.funet.fi> after the model of
 *  Gabor Kiss's <kissg@sztaki.hu> first edition, which
 *  did require a router running in parallel to resolve
 *  each and all of the SMTP session's address processings.
 *  (Uhh... ... the load..)
 *
 */

#include "hostenv.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>		/* For AF_**** */
#include <stdio.h>

#include "policy.h"

static int parse_gen_policy();
static int parse_ip_policy();


/* These are subroutines for the policy compiler, these
   are NOT subroutines for the SMTPSERVER to use  */

/* XX:XX:XX! ASSUMPTION: 8 BITS PER CHAR! */


void mask_ip_bits(ipnum, width, maxwidth)
unsigned char *ipnum;
int width, maxwidth;
{
    int i, bytewidth, bytemaxwidth;

    bytemaxwidth = maxwidth >> 3;	/* multiple of 8 */
    bytewidth = (width + 7) >> 3;

    /* All full zero bytes... */
    for (i = bytewidth; i < bytemaxwidth; ++i)
	ipnum[i] = 0;

    /* Now the remaining byte */
    i = 8 - (width & 7);	/* Modulo 8 */

    bytewidth = width >> 3;
    if (i != 8) {
	/* Not exactly multiple-of-byte-width operand to be masked    */
	/* For 'width=31' we get now 'bytewidth=3', and 'i=1'         */
	/* For 'width=25' we get now 'bytewidth=3', and 'i=7'         */
	ipnum[bytewidth] &= (0xFF << i);
    }
}


static int parse_ip_policy(pbuf, str, wstr)
struct policy *pbuf;
char *str, *wstr;
{
    char *s;
    int width;
    struct policy_ipv4 *ip4 = (struct policy_ipv4 *) pbuf;
    struct policy_ipv6 *ip6 = (struct policy_ipv6 *) pbuf;

    if (*str == '[') {
	++str;
	s = strchr(str, ']');
	if (!s)
	    return -1;
	*s = 0;
	if (cistrncmp(str, "IPv6.", 5) == 0)
	    str += 5;
	if (cistrncmp(str, "IPv6:", 5) == 0)
	    str += 5;
	return parse_ip_policy(pbuf, str, wstr);
    }
    if (strchr(str, ':') != NULL) {	/* IPv6 */
#if defined(AF_INET6) && defined(INET6)
	if (inet_pton(AF_INET6, str, ip6->ipnum) <= 0)
	    return -2;
	width = atoi(wstr);
	if (width > 128 || width < 0)
	    return -3;
	ip6->width = width;
	mask_ip_bits(ip6->ipnum, ip6->width, 128);
	ip6->len = 19;
	ip6->type = P_K_IPv6;
	return 0;
#else
	return -1;
#endif
    }
    if (inet_pton(AF_INET, str, ip4->ipnum) <= 0)
	return -4;
    width = atoi(wstr);
    if (width > 32 || width < 0)
	return -5;
    ip4->width = width;
    mask_ip_bits(ip4->ipnum, ip4->width, 32);
    ip4->len = 7;
    ip4->type = P_K_IPv4;
    return 0;
}

static int parse_gen_policy(pbuf, str, type)
struct policy *pbuf;
char *str;
int type;
{
    int len = strlen(str) + 1;	/* Terminating \000 included! */

    memcpy(pbuf->data, str, len);
    pbuf->len = len + 2;
    pbuf->type = type;

    return 0;
}


/*
 * int parsepolicykey(struct policy *pbuf, char *inpstr)
 *
 * Return 0, when parse is successfull
 */
int parsepolicykey(pbuf, str)
struct policy *pbuf;
char *str;
{
    char *s = strchr(str, '/');

    if (s != NULL) {
	*s++ = 0;
	return parse_ip_policy(pbuf, str, s);
    }
    if (*str == '_')
	return parse_gen_policy(pbuf, str, P_K_TAG);
    if (strchr(str,'@') != NULL)
	return parse_gen_policy(pbuf, str, P_K_USER);

    return parse_gen_policy(pbuf, str, P_K_DOMAIN);
}

struct _tokenpair {
  char *name;
  int  key;
} attributes [] = {
  { "=",		P_A_ALIAS		},
  { "rejectnet",	P_A_REJECTNET		},
  { "freezenet",	P_A_FREEZENET		},
  { "rejectsource",	P_A_REJECTSOURCE	},
  { "freezesource",	P_A_FREEZESOURCE	},
  { "relaycustomer",	P_A_RELAYCUSTOMER	},
  { "relaycustnet",	P_A_RELAYCUSTNET	},
  { "relaytarget",	P_A_RELAYTARGET		},
  { "acceptifmx",	P_A_ACCEPTifMX		},
  { "acceptifdns",	P_A_ACCEPTifDNS		},
  { "senderokwithdns",	P_A_SENDERokWithDNS	},
  { "freeze",		P_A_ACCEPTbutFREEZE	},
  { "sendernorelay",	P_A_SENDERNoRelay	},
  { "message",		P_A_MESSAGE		},
  { "test-dns-rbl",	P_A_TestDnsRBL		},
  { "localdomain",	P_A_LocalDomain		},
  { "maxinsize",	P_A_InboundSizeLimit	},
  { "maxoutsize",	P_A_OutboundSizeLimit	},
  { NULL, 0 },
};


int parseattributepair(abuf, str1, str2)
struct attribute *abuf;
char *str1, *str2;
{
    struct _tokenpair *ap = attributes;

    abuf->len = 2 + strlen(str2) + 1;
    strcpy(abuf->data, str2);

    while (ap->name != NULL) {
      if (strcmp(ap->name, str1) == 0) {
	abuf->attrib = ap->key;
	return 0;
      }
      ++ap;
    }

    return -1;
}
