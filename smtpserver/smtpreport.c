/*
 *    Copyright 1988 by Rayan S. Zachariassen, all rights reserved.
 *      This will be free software, but only when it is finished.
 */
/*
 *    Several extensive changes by Matti Aarnio <mea@nic.funet.fi>
 *      Copyright 1991-2004.
 */
/*
 * Zmailer SMTP-server divided into bits
 *
 * This implements the  Z-REPORT  command.
 */

#include "smtpserver.h"

const char * reportauthfile;

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
  { 0x00000001,		"SMTPIP"},
  /* other modes ? */
  { 0x7fffffff,		"SMTPALL"},
  { 0, NULL },
};


/*** FIXME: Code copied from  scheduler/mq2auth.c !! LIBRARIZE ?? ***** */


static long mq2authtokens(keys,s)
     struct mq2keys *keys;
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
	  if (err != 1) rc = 128;
	} else
#endif
	  if (*host == '[') {
	    au->v4.sin_family = AF_INET;
	    err = inet_pton(AF_INET, host+1, &au->v4.sin_addr);
	    if (err != 1) rc = 32;
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


static int mq2amaskcompare(qa, width, ua)
     int width;
     Usockaddr *qa, *ua;
{
  unsigned char ipbuf1[16], ipbuf2[16];

#ifdef INET6
  if (qa->v6.sin6_family == AF_INET6) {
    const u_char zv4mapprefix[16] = 
      { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0};

    if (memcmp((void *)&qa->v6.sin6_addr, zv4mapprefix, 12) == 0) {
      /* Is a IPv4 address mapped via IPv6 prefix. */
      qa->v4.sin_family = AF_INET;
      memcpy((void*)&qa->v4.sin_addr, 12+((char*)&qa->v6.sin6_addr), 4);
    }
  }
  if (qa->v6.sin6_family == AF_INET6) {
    if (ua->v6.sin6_family != AF_INET6) return 0; /* No match! */
    memcpy(ipbuf1, &qa->v6.sin6_addr, 16);
    memcpy(ipbuf2, &ua->v6.sin6_addr, 16);
    mask_ip_bits(ipbuf1, width, 128);
    mask_ip_bits(ipbuf2, width, 128);
    if (memcmp(ipbuf1, ipbuf2, 16) == 0)
      return 1; /* Match! */
    return 0; /* No match */

  } else
#endif
    if (qa->v4.sin_family == AF_INET) {
      if (ua->v4.sin_family != AF_INET) return 0; /* No match! */
      memcpy(ipbuf1, &qa->v4.sin_addr,  4);
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

static int mq2amaskverify(qa, s)
     Usockaddr *qa;
     const char *s;
{
  /* Verify that  mq->qaddr  stored address is ok
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
      if (rc >= 0 && mq2amaskcompare(qa, rc, &ua))
	return not;
    }
  }

  return -1;  /* Non-empty -> no match -> not ok */
}


/* ---- Heavily mutated version of mq2_authuser() of scheduler.. --- */

static struct mq2pw * reportauthuser(qa, authfile, user, pass)
     Usockaddr *qa;
     const char *authfile;
     const char *user, *pass;
{
  static char linebuf[2000];
  static struct mq2pw mpw;
  char *s;
  FILE *fp;

  if (!authfile || !user || !pass) return NULL; /* D'uh! */

  fp = fopen(authfile, "r");
  if (!fp) return NULL; /* D'uh! */

  mpw.user = linebuf;
  while (fgets(linebuf, sizeof(linebuf)-1, fp) != NULL &&
	 !ferror(fp) && !feof(fp)) {
    if (*linebuf == '#' || *linebuf == '*' || *linebuf == '\n')
      continue;
    s = strchr(linebuf,'\n');
    if (s) *s = 0;

    /* type(NULL,0,NULL,"reportauthuser() inline='%s'",linebuf); */

    s = strchr(linebuf,':');
    if (!s) {
      /* type(NULL,0,NULL,"No ':' chars in line!"); */
      continue; /* Bad syntax! */
    }
    *s++ = '\000';
    if (STREQ(linebuf,user)) {
      /* FOUND! */
      /* type(NULL,0,NULL,"username matched"); */
      mpw.plain = s;
      s = strchr(s, ':');
      if (!s) {
	/* type(NULL,0,NULL,"Missing 2nd ':' char in line!"); */
	continue; /* Bad syntax! */
      }
      *s++ = '\000';
      if (! STREQ(mpw.plain,pass)) {
	/* type(NULL,0,NULL,"password non-match"); */
	continue; /* Keep scanning */
      }

      mpw.attrs = s;
      s = strchr(s, ':');
      if (!s) {
	/* type(NULL,0,NULL,"Missing 3rd ':' char in line!"); */
	continue; /* Bad syntax! */
      }
      *s++ = '\000';

      if (mq2amaskverify(qa, s)) {
	/* type(NULL,0,NULL,"amaskverify fail"); */
	continue; /* BAD! */
      }
      mpw.auth = mq2authtokens(keys, mpw.attrs);
      if (!mpw.auth) {
	/* type(NULL,0,NULL,"no authtokens"); */
	continue; /* NO ACL TOKENS! */
      }

      fclose(fp);
      return & mpw;
    }
  }

  fclose(fp);
  return NULL; /* nothing found */
}


/*
 * smtp_report() function
 *
 * SMTP protocol verb:  Z-REPORT
 * parameters:   user password queryparameter(s)
 *
 * Queryparameters: <cmd> (<params>)*
 *     <cmd>:    "IP"
 *        <params>:  1.2.3.4
 *        <params>:  1111:2222:3333::ffff
 */
int smtp_report(SS, buf, cp)
SmtpState *SS;
const char *buf;
char *cp;
{
    char user[32], pass[32], cmd[32], param1[200], *p;
    int l;

    MIBMtaEntry->ss.IncomingSMTP_REPORT ++;

    /* At entry the  cp  points right after the verb, skip LWSP.. */
    while (*cp == ' ') ++cp;

    p = cp;
    while (*cp && *cp != ' ') ++cp;
    l = cp - p;
    strncpy(user, p, sizeof(user));  user[sizeof(user)-1] = 0;
    if (l < sizeof(user)) user[l] = 0;

    while (*cp == ' ') ++cp;

    p = cp;
    while (*cp && *cp != ' ') ++cp;
    l = cp - p;
    strncpy(pass, p, sizeof(pass));  pass[sizeof(pass)-1] = 0;
    if (l < sizeof(pass)) pass[l] = 0;

    while (*cp == ' ') ++cp;

    p = cp;
    while (*cp && *cp != ' ') ++cp;
    l = cp - p;
    strncpy(cmd, p, sizeof(cmd));  cmd[sizeof(cmd)-1] = 0;
    if (l < sizeof(cmd)) cmd[l] = 0;

    while (*cp == ' ') ++cp;

    p = cp;
    while (*cp && *cp != ' ') ++cp;
    l = cp - p;
    strncpy(param1, p, sizeof(param1));  param1[sizeof(param1)-1] = 0;
    if (l < sizeof(param1)) param1[l] = 0;

    /* type(NULL,0,NULL,"user='%s', pass='%s', cmd='%s', param1='%s' reportauthfile=%s",
       user,pass,cmd,param1, reportauthfile ? reportauthfile : "<nil>"); */

    if (! *cmd || !reportauthfile) {
      return -1;
    }

    if (CISTREQ(cmd, "ip")) {
      struct mq2pw *pw = reportauthuser( & SS->raddr,
					 reportauthfile,
					 user, pass );
      if (pw) {
	return smtp_report_ip(SS, param1);
      }
    }
    if (CISTREQ(cmd, "dump")) {
      struct mq2pw *pw = reportauthuser( & SS->raddr,
					 reportauthfile,
					 user, pass );
      if (pw) {
	return smtp_report_dump(SS);
      }
    }
    return -1;
}
