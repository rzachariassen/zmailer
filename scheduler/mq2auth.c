/*
 *	ZMailer 2.99.53+ Scheduler "mailq2" routines
 *
 *	Copyright Matti Aarnio <mea@nic.funet.fi> 1999-2000
 *
 */

#include "scheduler.h"
#include "prototypes.h"
#include <ctype.h>
#include <unistd.h>
#include "zsyslog.h"
#include <stdlib.h>
#include <errno.h>

#include "ta.h"
#include "libz.h"
#include "md5.h"

#include <arpa/inet.h>

/*
 *  MAILQv2 autentication database info content:
 *
 *  - username (search key)
 *  - cleartext password (for AUTH hash to work)
 *  - controlling attributes
 *  - IP ACL per tcp-wrapper (how?)
 *
 *
 *  Field separator classical double-colon (':'), meaning that
 *  the cleartext password shall *not* contain that character.
 */

struct mq2pw {
	char *user;
	char *plain;
	char *attrs;
	int auth;
};

struct mq2keys {
  long value;
  char *name;
};
static struct mq2keys keys[] =
{
  { 0,			"NONE"	},
  { MQ2MODE_SNMP,	"SNMP"	},
  { MQ2MODE_QQ,		"QQ"	},
  { MQ2MODE_FULL,	"TT"	},
  { MQ2MODE_ETRN,	"ETRN"	},
  { MQ2MODE_KILL,	"KILL"	},
  /* other modes ? */
  { 0x7fffffff,		"ALL"	},
  { 0, NULL },
};


static long mq2authtokens(s)
     char *s;
{
  char *p = s;
  long rc = 0;
  struct mq2keys *m;

  while (p && *p) {
    s = p;
    while (*p && *p != ' ') ++p;
    if (*p) *p = 0; else p = NULL;
    for (m = keys;m->name;++m) {
      if (strcmp(m->name,s)==0) {
	rc |= m->value;
	break;
      }
    }
    if (p) *p++ = ' ';
  }
  return rc;
}

static int parseaddrlit __((const char **, Usockaddr *));
static int
parseaddrlit(hostp, au)
	const char **hostp;
	Usockaddr *au;
{
	int rc = 0, err;
	const char *host = *hostp;
	char *hh = (void *) host;

	memset(au, 0, sizeof(*au));

	hh = strchr(hh, ']');
	if (hh) *hh = 0;

#if defined(AF_INET6) && defined(INET6)
	if (CISTREQN(host,"[IPv6:",6) ||
	    CISTREQN(host,"[IPv6.",6)) {
	  au->v6.sin6_family = AF_INET6;
	  err = inet_pton(AF_INET6, host+6, &au->v6.sin6_addr);
	  if (err > 0) rc = 128;
	} else
#endif
	  if (*host == '[') {
	    au->v4.sin_family = AF_INET;
	    err = inet_pton(AF_INET, host+1, &au->v4.sin_addr);
	    if (err > 0) rc = 32;
	  } else
	    err = -1;

	if (hh) *hh = ']';

	while (*host && *host != ']') ++host;
	if (*host == ']') ++host;

	if (*host == '/') {
	  ++host;
	  rc = -1;
	  while ('0' <= *host && *host <= '9') {
	    if (rc < 0) rc = 0;
	    rc = rc * 10 + (*host) - '0';
	    ++host;
	  }
	}

	*hostp = host;

	if (err < 0) rc = -1;
	return rc;
}

static void mask_ip_bits __((void *, int, int));
static void mask_ip_bits(ipnump, width, maxwidth)
     void *ipnump;
     int width, maxwidth;
{
    unsigned char *ipnum = ipnump;
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


static int mq2amaskcompare(mq, width, ua)
     struct mailq *mq;
     int width;
     Usockaddr *ua;
{
  Usockaddr qa = mq->qaddr;
  unsigned char ipbuf1[16], ipbuf2[16];

#ifdef INET6
  if (qa.v6.sin6_family == AF_INET6) {
    const u_char zv4mapprefix[16] = 
      { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0};

    if (memcmp((void *)&qa.v6.sin6_addr, zv4mapprefix, 12) == 0) {
      /* Is a IPv4 address mapped via IPv6 prefix. */
      qa.v4.sin_family = AF_INET;
      memcpy((void*)&qa.v4.sin_addr, 12+((char*)&qa.v6.sin6_addr), 4);
    }
  }
  if (qa.v6.sin6_family == AF_INET6) {
    if (ua->v6.sin6_family != AF_INET6) return 0; /* No match! */
    memcpy(ipbuf1, &qa.v6.sin6_addr, 16);
    memcpy(ipbuf2, &ua->v6.sin6_addr, 16);
    mask_ip_bits(ipbuf1, width, 128);
    mask_ip_bits(ipbuf2, width, 128);
    if (memcmp(ipbuf1, ipbuf2, 16) == 0)
      return 1; /* Match! */
    return 0; /* No match */

  } else
#endif
    if (qa.v4.sin_family == AF_INET) {
      if (ua->v4.sin_family != AF_INET) return 0; /* No match! */
      memcpy(ipbuf1, &qa.v4.sin_addr,  4);
      memcpy(ipbuf2, &ua->v4.sin_addr, 4);
      mask_ip_bits(ipbuf1, width, 32);
      mask_ip_bits(ipbuf2, width, 32);
      if (memcmp(ipbuf1, ipbuf2, 4) == 0)
	return 1; /* Match! */
      return 0; /* No match */

    } else {
      return 0; /* NO MATCH! */

    }
}

static int mq2amaskverify(mq, s)
     struct mailq *mq;
     const char *s;
{
  /* TO BE WRITTEN!
     Verify that  mq->qaddr  stored address is ok
     for this user/authenticator to use us.        */
  int rc;
  Usockaddr ua;
  int not = 0;

  while (*s == ' ') ++s;
  if (*s == 0) return 0; /* Empty -> Any OK */

  for ( ; *s; ++s) {
    if (*s == ',') { not = 0; continue; }
    if (*s == ' ') { not = 0; continue; }
    if (*s == '!') { not = 1; continue; }
    if (*s == '[') {
      rc = parseaddrlit( &s, &ua );
      if (rc >= 0 && mq2amaskcompare(mq, rc, &ua))
	return not;
    }
  }

  return -1;  /* Non-empty -> no match -> not ok */
}


static struct mq2pw * authuser(mq, user)
     struct mailq *mq;
     char *user;
{
  static char linebuf[2000];
  static struct mq2pw mpw;
  char *s;
  Sfio_t *fp;
  int ulen = strlen(user)+1;

  if (!mq2authfile) return NULL; /* D'uh! */

  fp = sfopen(NULL, mq2authfile, "r");
  if (!fp) return NULL; /* D'uh! */

  mpw.user = linebuf;
  while (csfgets(linebuf, sizeof(linebuf)-1, fp) >= 0) {
    if (*linebuf == '#' || *linebuf == '*' || *linebuf == '\n')
      continue;
    s = strchr(linebuf,'\n');
    if (s) *s = 0;
    s = strchr(linebuf,':');
    if (!s) continue; /* Bad syntax! */
    *s++ = '\000';
    if (memcmp(linebuf,user,ulen) == 0) {
      /* FOUND! */
      mpw.plain = s;
      s = strchr(s, ':');
      if (!s) continue; /* Bad syntax! */
      *s++ = '\000';
      mpw.attrs = s;

      s = strchr(s, ':');
      if (!s) continue; /* Bad syntax! */
      *s++ = '\000';
      if (mq2amaskverify(mq, s)) continue; /* BAD! */
      mpw.auth = mq2authtokens(mpw.attrs);
      sfclose(fp);
      return & mpw;
    }
  }

  sfclose(fp);
  return NULL; /* nothing found */
}



void mq2auth(mq,str)
     struct mailq *mq;
     char *str;
{
  char *p = str;
  struct mq2pw *pw;
  MD5_CTX CTX;
  unsigned char digest[16];
  char authbuf[32+1];
  int i;

  mq->auth = 0;

  while (*p && (*p != ' ') && (*p != '\t')) ++p;
  if (*p) *p++ = '\000';
  while (*p == ' ' || *p == '\t') ++p;

  /* Now 'str' points to username, and from 'p' onwards
     there is the HEX-encoded MD5 authenticator.. */

  pw = authuser(mq, str);

  if (!pw) {
    mq2_puts(mq,"-BAD USER OR AUTHENTICATOR OR CONTACT ADDRESS\n");
    return;
  }

  MD5Init(&CTX);
  MD5Update(&CTX, (const void *)(mq->challenge), strlen(mq->challenge));
  MD5Update(&CTX, (const void *)(pw->plain),     strlen(pw->plain));
  MD5Final(digest, &CTX);

  for (i = 0; i < 16; ++i)
    sprintf(authbuf+i+i, "%02x", digest[i]);

  if (strcmp(authbuf,p) != 0) {
    mq2_puts(mq,"-BAD USER OR PASSWORD");
#if 0 /* used to debug MD5 code... */
    mq2_puts(mq,"; real auth:");
    mq2_puts(mq,authbuf);
#endif
    mq2_puts(mq,"\n");
    return;
  }

  /* Right, authenticator is ok */
  mq->auth = pw->auth;

  mq2_puts(mq,"+OK\n");
}
