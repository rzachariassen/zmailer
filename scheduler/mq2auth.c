/*
 *	ZMailer 2.99.53+ Scheduler "mailq2" routines
 *
 *	Copyright Matti Aarnio <mea@nic.funet.fi> 1999
 *
 */

#include "scheduler.h"
#include "prototypes.h"
#include <ctype.h>
#include <unistd.h>
#include "zsyslog.h"
/* #include <stdlib.h> */
#include <errno.h>

#include "ta.h"
#include "md5.h"

/*
 *  MAILQv2 autentication database info content:
 *
 *  - username (search key)
 *  - cleartext password (for AUTH hash to work)
 *  - controlling attributes
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



static struct mq2pw * authuser(user)
     char *user;
{
  static char linebuf[2000];
  static struct mq2pw mpw;
  char *s;
  FILE *fp;
  int ulen = strlen(user)+1;

  if (!mq2authfile) return NULL; /* D'uh! */

  fp = fopen(mq2authfile,"r");
  if (!fp) return NULL; /* D'uh! */

  mpw.user = linebuf;
  while ((s = fgets(linebuf, sizeof(linebuf)-1, fp))) {
    if (*linebuf == '#' || *linebuf == '*')
      continue;
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

      mpw.auth = mq2authtokens(s);
      return & mpw;
    }
  }

  fclose(fp);
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

  pw = authuser(str);

  if (!pw) {
    mq2_puts(mq,"-BAD USER OR PASSWORD\n");
    return;
  }

  MD5Init(&CTX);
  MD5Update(&CTX, mq->challenge, strlen(mq->challenge));
  MD5Update(&CTX, pw->plain, strlen(pw->plain));
  MD5Final(digest, &CTX);

  for (i = 0; i < 16; ++i)
    sprintf(authbuf+i+i, "%02x", digest[i]);

  if (strcmp(authbuf,p) != 0) {
    mq2_puts(mq,"-BAD USER OR PASSWORD\n");
    return;
  }

  /* Right, authenticator is ok */
  mq->auth = pw->auth;

  mq2_puts(mq,"+OK\n");
}
