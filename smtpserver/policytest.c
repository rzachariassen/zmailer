/*
 *  relaytest.c -- module for ZMailer's smtpserver
 *  By Matti Aarnio <mea@nic.funet.fi> 1997-1999
 *
 */

/*
 * TODO:
 *  - Attribute 'request' initializations for resolving
 *  - Addresses in form  <@foo:uu@dd>, <host!user>, <host!user@domain>
 *  - config-file stored messages.. when to pick next, and when not.
 *    (now will pick the first one, but there is no conditionality)
 */

#include "hostenv.h"
#include "mailer.h"

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <fcntl.h>
#ifdef HAVE_DB_H
#ifdef HAVE_DB_185_H
# include <db_185.h>
#else
# include <db.h>
#endif
#endif
#ifdef HAVE_NDBM_H
#define datum Ndatum
#include <ndbm.h>
#undef datum
#endif
#ifdef HAVE_GDBM_H
#define datum Gdatum
#include <gdbm.h>
#undef datum
#endif

#ifdef	HAVE_SYS_SOCKET_H
#include <sys/socket.h>

#include <netdb.h>

#include <netinet/in.h>
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#ifdef HAVE_NETINET6_IN6_H
#include <netinet6/in6.h>
#endif
#ifdef HAVE_LINUX_IN6_H
#include <linux/in6.h>
#endif
#include <arpa/inet.h>

#endif

#include "libc.h"
#include "libz.h"

#define _POLICYTEST_INTERNAL_
#include "policytest.h"

extern int debug;

static int resolveattributes __((struct policytest *, int, struct policystate *, const char *, int));
static int  check_domain __((struct policytest *, struct policystate *, const char *, int));
static int  check_user __((struct policytest *, struct policystate *, const char *, int));
static int  checkaddr  __((struct policytest *, struct policystate *, const char *));

#if defined(AF_INET6) && defined(INET6)
extern const struct in6_addr zv4mapprefix;
#endif

/* KK() and KA() macroes are at "policy.h" */

static char *showkey __((const char *key));
static char *showkey(key)
const char *key;
{
    static char buf[256];

    if (key[1] != P_K_IPv4 && key[1] != P_K_IPv6) {
	if (strlen(key+2) > (sizeof(buf) - 200))
	    sprintf(buf,"%d/%s/'%s'", key[0], KK(key[1]), "<too long name>");
	else
	    sprintf(buf,"%d/%s/'%s'", key[0], KK(key[1]), key+2);
    } else
      if (key[1] == P_K_IPv4)
	sprintf(buf,"%d/%s/%u.%u.%u.%u",
		key[0], KK(key[1]),
		key[2] & 0xff, key[3] & 0xff, key[4] & 0xff, key[5] & 0xff);
      else
	sprintf(buf,"%d/%s/%02x%02x:%02x%02x:...",
		key[0], KK(key[1]),
		key[2] & 0xff, key[3] & 0xff, key[4] & 0xff, key[5] & 0xff);
    return buf;
}

static char *showattr __((const char *key));
static char *showattr(key)
const char *key;
{
    static char buf[500];
    sprintf(buf,"%d/%s/'%s'", key[0], KA(key[1]), key+2);
    return buf;
}

static int valueeq __((const char *value, const char *str));
static int valueeq(value,str)
     const char *value, *str;
{
    if (!value) return 0;
    return (strcmp(value,str) == 0);
}

static char *showresults __((char *values[]));
static char *showresults(values)
char *values[];
{
    static char buf[2000];
    int i;

    buf[0] = '\0';
    for (i = P_A_FirstAttr; i <= P_A_LastAttr; ++i) {
	sprintf(buf+strlen(buf),"%s ",KA(i));
	sprintf(buf+strlen(buf),"%s ",values[i] ? values[i] : ".");
    }
    return buf;
}

static void printstate __((const struct policystate *state));
static void printstate (state)
const struct policystate *state;
{
	int i;

	printf("000- always_reject=%d\n",state->always_reject);
	printf("000- always_freeze=%d\n",state->always_freeze);
	printf("000- always_accept=%d\n",state->always_accept);
	printf("000- full_trust=%d\n",   state->full_trust);
	printf("000- trust_recipients=%d\n",state->trust_recipients);
	printf("000- sender_reject=%d\n",state->sender_reject);
	printf("000- sender_freeze=%d\n",state->sender_freeze);
	printf("000- sender_norelay=%d\n",state->sender_norelay);
	printf("000- relaycustnet=%d\n", state->relaycustnet);
	printf("000- rcpt_nocheck=%d\n", state->rcpt_nocheck);

	for ( i = P_A_FirstAttr; i <= P_A_LastAttr ; ++i) {
		printf("000- %s: %srequested, value=%s\n",
		       KA(i),
		       (state->origrequest & (1<<i)) ? "" : "not ",
		       state->values[i]?state->values[i]:".");
	}
}

static void mask_ip_bits __((unsigned char *, int, int));
static void mask_ip_bits(ipnum, width, maxwidth)
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


void policydefine(relp, dbtype, dbpath)
struct policytest **relp;
const char *dbtype, *dbpath;
{
    struct policytest *rel = (void *) emalloc(sizeof(*rel));
    *relp = rel;
    memset(rel, 0, sizeof(*rel));
    rel->dbtype = strdup(dbtype);
    rel->dbpath = strdup(dbpath);
    rel->dbt = _dbt_none;
}

/* Do the actual query - return pointer to the result record */
static void *dbquery __((struct policytest *, const void *, const int, int *));

static void *dbquery(rel, qptr, qlen, rlenp)
struct policytest *rel;
const void *qptr;
const int qlen;
int *rlenp;			/* result length ptr ! */
{
    char *buffer;
#ifdef HAVE_NDBM_H
    Ndatum Nkey, Nresult;
#endif
#ifdef HAVE_GDBM_H
    Gdatum Gkey, Gresult;
#endif
#ifdef HAVE_DB_H
    DBT Bkey, Bresult;
    int rc;
#endif


    switch (rel->dbt) {
#ifdef HAVE_NDBM_H
    case _dbt_ndbm:

	Nkey.dptr = (char *) qptr;
	Nkey.dsize = qlen;

	Nresult = dbm_fetch(rel->ndbm, Nkey);
	if (Nresult.dptr == NULL)
	    return NULL;

	buffer = (char *) emalloc(Nresult.dsize);
	memcpy(buffer, Nresult.dptr, Nresult.dsize);

	*rlenp = Nresult.dsize;
	return buffer;

	break; /* some compilers complain, some produce bad code
		  without this... */
#endif
#ifdef HAVE_GDBM_H
    case _dbt_gdbm:

	Gkey.dptr = (void *) qptr;
	Gkey.dsize = qlen;

	Gresult = gdbm_fetch(rel->gdbm, Gkey);

	/* gdbm_fetch allocates memory for return data: Gresult.dptr
	   Must be freed later. */

	*rlenp = Gresult.dsize;
	return Gresult.dptr;

	break; /* some compilers complain, some produce bad code
		  without this... */
#endif
#ifdef HAVE_DB_H
    case _dbt_btree:


	Bkey.data = (void *) qptr;
	Bkey.size = qlen;

	rc = (rel->btree->get) (rel->btree, &Bkey, &Bresult, 0);
	if (rc != 0)
	    return NULL;

	buffer = (char *) emalloc(Bresult.size);
	memcpy(buffer, Bresult.data, Bresult.size);

	*rlenp = Bresult.size;
	return buffer;

	break; /* some compilers complain, some produce bad code
		  without this... */

    case _dbt_bhash:

	Bkey.data = (void *) qptr;
	Bkey.size = qlen;

	rc = (rel->bhash->get) (rel->bhash, &Bkey, &Bresult, 0);
	if (rc != 0)
	    return NULL;

	buffer = (char *) emalloc(Bresult.size);
	memcpy(buffer, Bresult.data, Bresult.size);

	*rlenp = Bresult.size;
	return buffer;

	break; /* some compilers complain, some produce bad code
		  without this... */
#endif
    default:
	break;
    }
    return NULL;
}



/******************************************************************************
 * Function: resolveattributes()
 *
 *       recursions - Max recursive calls for parsing aliases.
 *    state.request - These bit flags say which attributes are checked.
 * state.values[]   - Attribute values are stored here. Both are indexed
 *                    according to the attribute constants. (P_A_...)
 *              key - Pointer to search record. Binary address, ascii alias or
 *                    ascii domain name.
 *             init - Init flag. Give value 1. Value 0 when called recursively
 *                    by itself.
 * -------------
 * Returns 0, when it has found something
 *****************************************************************************/

static int resolveattributes(rel, recursions, state, key, init)
struct policytest *rel;
int recursions;
struct policystate *state;
const char *key;
int init;
{
    char *str, *str_base, pbuf[256];
    int rlen, result, interest;

    if (init) {
	/* First call of this function. Not called recursively. */
	/* Zero return value array. */
	int i;
	for (i = 0; i <= P_A_LastAttr; ++i)
	  if (state->values[i]) free(state->values[i]);
	memset(state->values, 0, sizeof(state->values));

	state->origrequest = state->request;
    }
    --recursions;

    state->request |= (1 << P_A_MESSAGE);

    if (state->msgstr != NULL)
      free(state->msgstr);
    state->msgstr = NULL;


    if (debug)
       printf("000- Key: %s\n", showkey(key));
/*
    if (key[1] != P_K_IPv4 && key[1] != P_K_IPv6) {
	if (debug)
	  printf("000- Key: %d/%d/%s\n", key[0],key[1],key+2);
    } else
      if (debug)
	printf("000- Key: %u.%u.%u.%u\n", key[2] & 0xff, key[3] & 0xff, 
	       key[4] & 0xff, key[5] & 0xff);
*/

    str_base = str = (char *) dbquery(rel, &key[0], key[0], &rlen);

    /* str[0]    - attribute list lenght
       str[1]    - attribute numeric value
       str[2...] - attribute flag string    */

    if (str == NULL) {
      if (debug)
	printf("000-  query failed\n");
      return -1;
    }
    /* Scan trough attribute list. Call resolveattributes recursively
       if aliases is found */

    while (rlen > 3) {

	/* Alias */
	if (str[1] == P_A_ALIAS) {
	    /* Do not continue if max recursions reached. */
	    if (recursions < 0) {
	      if (debug)
		printf("000- Max recursions reached.\n");
	    } else {
	      if (debug)
		printf("000- Alias-recursion: %d\n", recursions);

	      strcpy(pbuf+2,str+2);
	      pbuf[0] = strlen(str+2) + 3;
	      pbuf[1] = P_K_TAG;
	      result = resolveattributes(rel, recursions, state, pbuf, 0);
	    }
	    rlen -= str[0];
	    str  += str[0];
	    continue;
	}

	/* Attribute */
	if (debug)
	  printf("000-   Attribute: %s\n", showattr(str));

	interest = 1 << str[1];	/* Convert attrib. num. value into flag bit */
	if ((interest & state->request) == 0) {
	    /* Not interested in this attribute, skip into next. */
	    if (debug)
	      printf("000-     not interested, skipped...\n");

	    goto nextattr;
	} else {
	    /* Mask it off. */
	    state->request &= ~interest;
	}

	if (str[1] == P_A_MESSAGE) {

	  if (state->msgstr == NULL)
	    state->msgstr = strdup(str+2);
	  goto nextattr;

	} else if (str[1] == P_A_InboundSizeLimit) {

	  sscanf(str+2,"%li", &state->maxinsize);
	  goto nextattr;

	} else if (str[1] == P_A_OutboundSizeLimit) {

	  sscanf(str+2,"%li", &state->maxoutsize);
	  goto nextattr;

	} else if ((str[2] != '+' && str[2] != '-') &&
		   !state->values[str[1] & 0xFF]) {

	  /* Supply suffix domain (set), e.g.:
	         RBL.MAPS.VIX.COM,DUL.MAPS.VIX.COM
	     whatever you want ... */

	  state->values[str[1] & 0xFF] = strdup(str + 2);

	} else if (str[2] != '+' && str[2] != '-') {

	  if (debug)
	    printf("000- Unknown flag: %s\n", &str[2]);
	  goto nextattr;
	}
	/* Store valid attribute.
	   str[1] is attributes id constant, str[2] attribute flag. */

	if (P_A_FirstAttr <= str[1] && str[1] <= P_A_LastAttr) {
	    if (!state->values[str[1] & 0xFF])
		state->values[str[1] & 0xFF] = strdup(str + 2);
	  if (debug)
	    printf("000-     accepted!\n");
	} else {
	  if (debug)
	    printf("000-   Unknown attribute, number: %d\n", str[1]);
	}

    nextattr:

	rlen -= str[0];
	str  += str[0];

	/* If all requests are done, exit. */
	if (!state->request) {
	  if (debug)
	    printf("000- Every request found. Finishing search.\n");
	  break;
	}
    }				/* End of while. */

    /* Free memory from attribute list. Allocated in dbquery. */
    if (str_base)
	free(str_base);

    return 0;
}


/* Return 0, when found something */
static int checkaddr(rel, state, pbuf)
struct policytest *rel;
struct policystate *state;
const char *pbuf;
{
    int result, count, countmax;
    int maxrecursions;


    maxrecursions = 5;

    if (pbuf[1] == P_K_DOMAIN) {
	if (debug)
	  printf("000- checkaddr(): domain of '%s'\n",pbuf+2);
	result = resolveattributes(rel, maxrecursions, state, pbuf, 1);
	if (debug) {
	  printf("000- Results: %s\n", showresults(state->values));
	}
	return (result);
    }
    if (pbuf[1] == P_K_USER) {
	if (debug)
	  printf("000- checkaddr(): user of '%s'\n",pbuf+2);
	result = resolveattributes(rel, maxrecursions, state, pbuf, 1);
	if (debug) {
	  printf("000- Results: %s\n", showresults(state->values));
	}
	return (result);
    } else if (pbuf[1] == P_K_IPv4)
	countmax = 32;
    else
	countmax = 128;

    result = 1;
    count = 0;

    while (result != 0 && count <= countmax) {

	count++;
	/* Search database */
	result = resolveattributes(rel, maxrecursions, state, pbuf, 1);
	if (result == 0)	/* Found. */
	    break;

	mask_ip_bits((u_char*)&pbuf[2], countmax - count, countmax);

	if (pbuf[1] == P_K_IPv4)
	    ((char*)pbuf)[6] = 32 - count;	/* Width */
#if defined(AF_INET6) && defined(INET6)
	else			/* AF_INET6 */
	  ((char*)pbuf)[18] = 128 - count;
#endif
    }

    
#if defined(AF_INET6) && defined(INET6)
    /* Umm.. looked for IPv6 address ?  And nothing found ?
       Try then to look for the wild-card [0.0.0.0]/0 entry. */
    if (result != 0 && pbuf[1] == P_K_IPv6) {
      memset((char*)pbuf,0,6);
      ((char*)pbuf)[0] = 7;
      ((char*)pbuf)[1] = P_K_IPv4;
      ((char*)pbuf)[6] = 0;
      /* Search database */
      result = resolveattributes(rel, maxrecursions, state, pbuf, 1);
    }
#endif

    if (result != 0) {
      if (debug)
	printf("000- Address not found.\n");
      return -1;
    } else
      if (debug) {
	printf("000-   %s\n", showresults(state->values));
      }
    return 0;
}


int policyinit(relp, state, whosonrc)
struct policytest **relp;
struct policystate *state;
int whosonrc;
{
    int openok;
    char *dbname;
    struct policytest *rel = *relp;

    if (rel == NULL)
      return 0;  /* Not defined! */

#ifdef HAVE_NDBM_H
    if (cistrcmp(rel->dbtype, "ndbm") == 0)
	rel->dbt = _dbt_ndbm;
#endif
#ifdef HAVE_GDBM_H
    if (cistrcmp(rel->dbtype, "gdbm") == 0)
	rel->dbt = _dbt_gdbm;
#endif
#ifdef HAVE_DB_H
    if (cistrcmp(rel->dbtype, "btree") == 0)
	rel->dbt = _dbt_btree;
    if (cistrcmp(rel->dbtype, "bhash") == 0)
	rel->dbt = _dbt_bhash;
#endif
    if (rel->dbt == _dbt_none) {
	/* XX: ERROR! Unknown/unsupported dbtype! */
      *relp = NULL;
	return 1;
    }
    openok = 0;
#ifdef HAVE_ALLOCA
    dbname = (char*)alloca(strlen(rel->dbpath) + 8);
#else
    dbname = (char*)emalloc(strlen(rel->dbpath) + 8);
#endif
    switch (rel->dbt) {
#ifdef HAVE_NDBM_H
    case _dbt_ndbm:
	/*
	   rel->ndbm = dbm_open((char*)rel->dbpath, O_RDWR|O_CREAT|O_TRUNC, 0644);
	 */
	rel->ndbm = dbm_open((char *) rel->dbpath, O_RDONLY, 0644);
	openok = (rel->ndbm != NULL);
	break;
#endif
#ifdef HAVE_GDBM_H
    case _dbt_gdbm:
	/* Append '.gdbm' to the name */
	sprintf(dbname, "%s.gdbm", rel->dbpath);
	rel->gdbm = gdbm_open(dbname, 0, GDBM_READER, 0644, NULL);
	openok = (rel->gdbm != NULL);
	break;
#endif
#ifdef HAVE_DB_H
    case _dbt_btree:
	/* Append '.db' to the name */
	sprintf(dbname, "%s.db", rel->dbpath);
	rel->btree = dbopen(dbname, O_RDONLY, 0644, DB_BTREE, NULL);
	openok = (rel->btree != NULL);
	break;

    case _dbt_bhash:
	rel->bhash = dbopen(rel->dbpath, O_RDONLY, 0644, DB_HASH, NULL);
	openok = (rel->bhash != NULL);
	break;
#endif
    default:
	break;
    }
#ifndef HAVE_ALLOCA
    free(dbname);
#endif
    if (!openok) {
	/* ERROR!  Could not open the database! */
      if (debug)
	printf("000- ERROR!  Could not open the database!\n");
      *relp = NULL;
      return 2;
    }

    memset(state, 0, sizeof(*state));
#ifdef HAVE_WHOSON_H
    state->whoson_result = whosonrc;
#endif
    return 0;
}


static int _addrtest_ __((struct policytest *rel, struct policystate *state, const char *pbuf, int sourceaddr));

static int _addrtest_(rel, state, pbuf, sourceaddr)
struct policytest *rel;
struct policystate *state;
const char *pbuf;
int sourceaddr;
{
    u_char ipaddr[16];
    int ipaf = pbuf[1];

    if (pbuf[1] == P_K_IPv4)
      memcpy(ipaddr, pbuf+2, 4);
    if (pbuf[1] == P_K_IPv6)
      memcpy(ipaddr, pbuf+2, 16);

    /* state->request initialization !! */

    state->request = ( 1 << P_A_REJECTNET         |
		       1 << P_A_FREEZENET         |
		       1 << P_A_RELAYCUSTNET      |
		       1 << P_A_TestDnsRBL        |
		       1 << P_A_RcptDnsRBL        |
		       1 << P_A_InboundSizeLimit  |
		       1 << P_A_OutboundSizeLimit |
		       1 << P_A_FullTrustNet	  |
		       1 << P_A_TrustRecipients   |
		       1 << P_A_TrustWhosOn        );

    state->maxinsize  = -1;
    state->maxoutsize = -1;

    if (checkaddr(rel, state, pbuf) != 0)
      return 0; /* Nothing found */

    if (!sourceaddr)
      goto just_rbl_checks;

#if 0
/* if (IP address of SMTP client has 'rejectnet +' attribute) then
    any further conversation refused
    [state->always_reject = 1; return -1;]
    ...
   if (IP address of SMTP client has 'freezenet +' attribute) then
    we present happy face, but always put the messages into a freezer..
    [state->always_freeze = 1; return -1;]
   if (IP address of SMTP client has 'relaycustnet +' attribute) then
    sender accepted, recipients not checked
    [state->always_accept = 1; return 0;]
    ...
   Except that:
   if (HELO-name of SMTP client has 'rejectnet +' attribute) then
    any further conversation refused
    [state->always_reject = 1; return -1;]
   else if (sender's domain has 'rejectsource +' attribute) then
    sender rejected, any further conversation refused
    [state->sender_reject = 1; return -1;]
 */
#endif

    if (state->message != NULL)
      free(state->message);
    state->message = state->msgstr;
    state->msgstr = NULL;

    if (valueeq(state->values[P_A_REJECTNET], "+")) {
      if (debug)
	printf("000- policytestaddr: 'rejectnet +' found\n");
      if (state->message == NULL)
	state->message = strdup("Your network address is blackholed in our static tables");
      state->always_reject = 1;
      return -1;
    }
    if (valueeq(state->values[P_A_FREEZENET], "+")) {
      if (debug)
	printf("000- policytestaddr: 'freezenet +' found\n");
      if (state->message == NULL)
	state->message = strdup("Your network address is blackholed in our static tables");
      state->always_freeze = 1;
      return  1;
    }
    if (valueeq(state->values[P_A_TrustRecipients], "+")) {
      if (debug)
	printf("000- policytestaddr: 'trustrecipients +' found\n");
      state->trust_recipients = 1;
    }
    if (valueeq(state->values[P_A_FullTrustNet], "+")) {
      if (debug)
	printf("000- policytestaddr: 'fulltrustnet +' found\n");
      state->full_trust = 1;
    }
#ifdef HAVE_WHOSON_H
    if (valueeq(state->values[P_A_TrustWhosOn], "+")) {
      if (debug)
	printf("000- policytestaddr: 'trust-whoson +' found, accept? = %d\n",
	       (state->whoson_result == 0));
      if (state->whoson_result == 0)
	state->always_accept = 1;
    }
#endif
    if (valueeq(state->values[P_A_RELAYCUSTNET], "+")) {
      if (debug)
	printf("000- policytestaddr: 'relaycustnet +' found\n");
      state->always_accept = 1;
    }
    if (state->trust_recipients || state->full_trust || state->always_accept)
      return 0;

    just_rbl_checks:;

    if (state->values[P_A_TestDnsRBL] &&
	!valueeq(state->values[P_A_TestDnsRBL], "-")) {
      int rc;
      if (debug)
	printf("000- policytestaddr: 'test-dns-rbl %s' found;\n",
	       state->values[P_A_TestDnsRBL]);
      rc = rbl_dns_test(ipaf, ipaddr, state->values[P_A_TestDnsRBL], &state->message);
      if (debug)
	printf("000-  rc=%d\n", rc);
      return rc;
    }
    if (state->values[P_A_RcptDnsRBL] &&
	!valueeq(state->values[P_A_RcptDnsRBL], "-")) {
      int rc;
      if (debug)
	printf("000- policytestaddr: 'rcpt-dns-rbl %s' found;\n",
	       state->values[P_A_RcptDnsRBL]);
      rc = rbl_dns_test(ipaf, ipaddr, state->values[P_A_RcptDnsRBL], &state->rblmsg);
      if (debug)
	printf("000-  rc=%d\n", rc);
      return rc;
    }
    return 0;
}

int policytestaddr(rel, state, what, raddr)
struct policytest *rel;
struct policystate *state;
PolicyTest what;
Usockaddr *raddr;
{
    char pbuf[64]; /* Not THAT much space needed.. */

    struct sockaddr_in *si4;
#if defined(AF_INET6) && defined(INET6)
    struct sockaddr_in6 *si6;
#endif


    if (what != POLICY_SOURCEADDR)
      abort();		/* Urgle..! Code mismatch! */

    if (rel == NULL)
      return 0;

    /* Find address match -- IPv4 mapped into IPv6 space too! */

    state->message = NULL; /* This is early initial clearing */

    if (raddr->v4.sin_family == 0){
      state->full_trust = 1;
      return 0; /* Interactive testing... */
    }

    if (raddr->v4.sin_family == AF_INET) {
      si4 = & (raddr->v4);
      pbuf[0] = 7;
      pbuf[1] = P_K_IPv4;
      memcpy(&pbuf[2], (char *) &si4->sin_addr.s_addr, 4);
      pbuf[6] = 32;		/* 32 bits */
    } else
#if defined(AF_INET6) && defined(INET6)
    if (raddr->v6.sin6_family == AF_INET6) {
      si6 = & (raddr->v6);
      if (memcmp((void *)&si6->sin6_addr, &zv4mapprefix, 12) == 0) {
	/* This is IPv4 address mapped into IPv6 */
	pbuf[0] = 7;
	pbuf[1] = P_K_IPv4;
	memcpy(pbuf+2, ((char *) &si6->sin6_addr) + 12, 4);
	pbuf[6] = 32;			/*  32 bits */
      } else {
	pbuf[0] = 19;
	pbuf[1] = P_K_IPv6;
	memcpy(pbuf+2, ((char *) &si6->sin6_addr), 16);
	pbuf[18] = 128;		/* 128 bits */
      }
    } else
#endif
    {
      printf("Unknown address format; sa_family = %d\n",
	     raddr->v4.sin_family);
      return -2;
    }

    return _addrtest_(rel, state, pbuf, 1);
}


static int check_domain(rel, state, input, inlen)
struct policytest *rel;
struct policystate *state;
const char *input;
int inlen;
{
    char *ptr, *ptr2, pbuf[256];
    int addr_len, i, plen, result;


#if 0
    /* Get address after @ */
    ptr = strchr(input, '@');
    if (ptr == NULL) {
	printf("Invalid address. @ not found!\n");
	exit(0);
    }
    ptr++;
    addr_len = inlen - (ptr - input);
#else
    ptr = (char*)input;
    addr_len = inlen;
#endif

    /* Convert to lower case. */
    if (addr_len > sizeof(pbuf)-3)
	addr_len = sizeof(pbuf)-3;
    strncpy(pbuf+2, ptr, addr_len);
    pbuf[2+addr_len] = 0;
    strlower(pbuf+2);

    if (pbuf[2] == '[') {
      /* IP address literal ??? */
      if (strncmp(pbuf+2+1,"ipv6",4)==0) {
#if defined(AF_INET6) && defined(INET6)
	char *s = strchr(pbuf+3,']');
	if (s) *s = 0;
	if (inet_pton(AF_INET6, pbuf+3+5, pbuf+2) < 1) {
	  /* XX: Duh ?  Our input is syntax checked, so
	     this ERROR should not happen.. */
	}
	pbuf[0] = 19;
	pbuf[1] = P_K_IPv6;
	pbuf[18] = 128;
#else
	/* XXX: Duh ??? IPv6 not supported, how to report errs ?? */
#endif
      } else {
	char *s = strchr(pbuf+3,']');
	if (s) *s = 0;
	if (inet_pton(AF_INET, pbuf+3, (u_char *)pbuf+2) < 1) {
	  /* XX: Duh ?  Our input is syntax checked, so
	     this ERROR should not happen.. */
	}

	pbuf[0] = 7;
	pbuf[1] = P_K_IPv4;
	pbuf[6] = 32;
      }
      return _addrtest_(rel,state,pbuf, 0);
    }

    plen = addr_len;
    /* '\0' not included in inlen... */
    plen += 1 + 2;

    pbuf[0] = plen;
    pbuf[1] = P_K_DOMAIN;

    result = 1;

    while (result != 0) {
	if (debug)
	  printf("000- DEBUG: %s\n", showkey(pbuf));
	result = checkaddr(rel, state, pbuf);

	if (result == 0) /* Found! */
	  return 0;

	if (pbuf[2] != '.') {
	    /* Put '.' in the beginning */
	    for (i = pbuf[0]; i >= 2; --i) {
		pbuf[i + 1] = pbuf[i];
	    }
	    pbuf[2] = '.';
	    pbuf[0] += 1;
	} else {
	    /* Test with shorter address. */
	    ptr = &pbuf[3];
	    while (*ptr != 0 && *ptr != '.')
		ptr++;
	    if (*ptr == '\0') {
		/* Quit the loop if everything is examined. */
		if (pbuf[2] == '.' && pbuf[3] == '\0')
		    break;
		pbuf[2] = '.';
		pbuf[3] = '\0';
	    } else {
		ptr++;
		ptr2 = &pbuf[3];
		while (*ptr != '\0') {
		    *ptr2++ = *ptr++;
		}
		*ptr2++ = *ptr++;
	    }
	    pbuf[0] = strlen(&pbuf[2]) + 1 + 2;
	}
    }
    return 0; /* Nothing found */
}

static const char * find_at __((const char *, int));
static const char *
find_at(input, inlen)
const char *input;
int inlen;
{
  int quote = 0;
  /* Find first unquoted '@' character, and return a pointer to it */
  for (; inlen > 0; --inlen,++input) {
    if (*input == '"')
      quote = !quote;
    if (*input == '\\') {
      --inlen; ++input;
      continue;
    }
    if (*input == '@' && !quote)
      return input;
  }
  return NULL;
}

/* Return 0, when found something */
static int check_user(rel, state, input, inlen)
struct policytest *rel;
struct policystate *state;
const char *input;
int inlen;
{
    char pbuf[512];
    const char *at;
    int result;

    if (inlen > (sizeof(pbuf) - 3))
      inlen = sizeof(pbuf) - 3;

    /* Store the MAIL FROM:<user@domain> into a temporary buffer, and
       lowercasify it   */
    strncpy(pbuf+2, input, inlen);
    pbuf[2+inlen] = 0;
    strlower(pbuf + 2);

    at = find_at(pbuf + 2, inlen);
    if (!at) return 0;

    pbuf[inlen + 2] = '\0';
    pbuf[0] = inlen + 1 + 2;
    pbuf[1] = P_K_USER;

    result = checkaddr(rel, state, pbuf);
    if (result == 0) /* Found! */
      return result;

    /* 'user@' */
    inlen = (at+1 - pbuf) - 2;
    pbuf[inlen + 2] = '\0';
    pbuf[0] = inlen + 1 + 2;
    pbuf[1] = P_K_USER;

    result = checkaddr(rel, state, pbuf);
    return result;
}


static int pt_heloname __((struct policytest *, struct policystate *, const char *, const int));

static int pt_mailfrom __((struct policytest *, struct policystate *, const char *, const int));

static int pt_rcptto __((struct policytest *, struct policystate *, const char *, const int));

static int pt_rcptpostmaster __((struct policytest *, struct policystate *, const char *, const int));

static int pt_heloname(rel, state, str, len)
struct policytest *rel;
struct policystate *state;
const char *str;
const int len;
{
    if (state->always_reject)
	return -1;
    if (state->always_freeze)
	return 1;
    if (state->always_accept)
	return 0;
    if (state->full_trust)
	return 0;

    /* state->request initialization !! */
    state->request = ( 1 << P_A_REJECTNET    |
		       1 << P_A_FREEZENET  );

    check_domain(rel, state, str, len);

/*
   # if (name of SMTP client has 'rejectnet +' attribute) then
   #    any further conversation refused
   #      [state->always_reject = 1; return -1;]
 */
    if (valueeq(state->values[P_A_REJECTNET], "+")) {
	state->always_reject = 1;
	return -1;
    }
    if (valueeq(state->values[P_A_FREEZENET], "+")) {
	state->always_freeze = 1;
	return  1;
    }
    return 0;
}

static int pt_sourcedomain(rel, state, str, len)
struct policytest *rel;
struct policystate *state;
const char *str;
const int len;
{
    if (state->always_reject)
	return -1;
    if (state->always_freeze)
	return 1;
    if (state->always_accept)
	return 0;
    if (state->full_trust)
	return 0;

    /* state->request initialization !! */
    state->request = ( 1 << P_A_REJECTNET    |
		       1 << P_A_FREEZENET    |
		       1 << P_A_RELAYCUSTNET |
		       1 << P_A_InboundSizeLimit  |
		       1 << P_A_OutboundSizeLimit   );

    check_domain(rel, state, str, len);

/*
   # if (name of SMTP client has 'rejectnet +' attribute) then
   #    any further conversation refused
   #      [state->always_reject = 1; return -1;]
 */
    if (valueeq(state->values[P_A_REJECTNET], "+")) {
	state->always_reject = 1;
	return -1;
    }
    if (valueeq(state->values[P_A_FREEZENET], "+")) {
	state->always_freeze = 1;
	return  1;
    }
    if (valueeq(state->values[P_A_RELAYCUSTNET], "+")) {
      if (debug)
	printf("000- pt_sourceaddr: 'relaycustnet +' found\n");
      state->always_accept = 1;
      return  0;
    }
    if (valueeq(state->values[P_A_FullTrustNet], "+")) {
      if (debug)
	printf("000- pt_sourceaddr: 'fulltrustnet +' found\n");
      state->full_trust = 1;
      return  0;
    }
    return 0;
}

static int pt_mailfrom(rel, state, str, len)
struct policytest *rel;
struct policystate *state;
const char *str;
const int len;
{
    const char *at;

    state->rcpt_nocheck  = 0;
    state->sender_reject = 0;
    state->sender_freeze = 0;
    state->sender_norelay = 0;

    if (state->always_reject)
	return -1;
    if (state->always_freeze)
	return 1;
    if (state->full_trust || state->authuser)
      return 0;

    if (len == 0) /* MAIL FROM:<> -- error message ? */
      return 0;   /* We accept it, sigh.. */

    /* state->request initialization !! */
    state->request = ( 1 << P_A_REJECTSOURCE |
		       1 << P_A_FREEZESOURCE   );

    /* XX: How about  <@foo:user@domain> ??? */
    /* XX: With IGNORING RFC-821-source-route "@foo:" we
           don't have problems here */

    /* Check source user */
    if (check_user(rel, state, str, len) == 0) {
      if (valueeq(state->values[P_A_FREEZESOURCE], "+")) {
	if (debug)
	  printf("000- mailfrom: 'freezesource +'\n");
	state->sender_freeze = 1;
	return 1;
      }
      if (valueeq(state->values[P_A_REJECTSOURCE], "+")) {
	if (debug)
	  printf("000- mailfrom: 'rejectsource +'\n");
	state->sender_reject = 1;
	return -1;
      }
    }

    state->request = ( 1 << P_A_REJECTSOURCE  |
		       1 << P_A_FREEZESOURCE  |
		       1 << P_A_RELAYCUSTOMER |
		       1 << P_A_SENDERNoRelay |
		       1 << P_A_SENDERokWithDNS );

    at = find_at(str, len);
    if (at != NULL) {
      /* @[1.2.3.4] ?? */
      if (check_domain(rel, state, at+1, len - (1 + at - str)) != 0)
	return -1;
    } else {
      /* Doh ??  Not  <user@domain> ??? */
      return -1;
    }

    if (valueeq(state->values[P_A_SENDERNoRelay], "+")) {
      if (debug)
	printf("000- mailfrom: 'sendernorelay +'\n");
      state->sender_norelay = 1;
    }
    if (state->values[P_A_SENDERokWithDNS]) {
      int rc = sender_dns_verify(state->values[P_A_SENDERokWithDNS][0],
				 at+1, len - (1 + at - str));
      if (debug)
	printf("000- ... returns: %d\n", rc);
      return rc;
    }

    if (valueeq(state->values[P_A_REJECTSOURCE], "+")) {
	if (debug)
	  printf("000- mailfrom: 'rejectsource +'\n");
	state->sender_reject = 1;
	return -1;
    }
    if (valueeq(state->values[P_A_FREEZESOURCE], "+")) {
	if (debug)
	  printf("000- mailfrom: 'freezesource +'\n");
	state->sender_freeze = 1;
	return -1;
    }

    if (state->always_accept) {
      int rc = sender_dns_verify('-', at+1, len - (1 + at - str));
      if (debug)
	printf("000- ... returns: %d\n", rc);
      return rc;
    }

    if (valueeq(state->values[P_A_RELAYCUSTOMER], "+")) {
	if (debug)
	  printf("000- mailfrom: 'relaycustomer +'\n");
	state->rcpt_nocheck = 1;
	return  0;
    }
    return 0;
}

static int pt_rcptto(rel, state, str, len)
struct policytest *rel;
struct policystate *state;
const char *str;
const int len;
{
    const char *at;

    if (state->always_reject) return -1;
    if (state->sender_reject) return -2;
    if (state->always_freeze) return  1;
    if (state->sender_freeze) return  1;
    if (state->full_trust)    return  0;
    if (state->authuser)      return  0;
    if (state->trust_recipients) return 0;

    /* rcptfreeze even for 'rcpt-nocheck' ? */

    /* state->request initialization !! */
    state->request = ( 1 << P_A_RELAYTARGET     |
		       1 << P_A_ACCEPTbutFREEZE );

    /* Test first the full address */
    if (check_user(rel, state, str, len) == 0) {
      if (valueeq(state->values[P_A_RELAYTARGET], "+")) {
	return  0;
      }
      if (valueeq(state->values[P_A_RELAYTARGET], "-")) {
	return -1;
      }
      if (valueeq(state->values[P_A_ACCEPTbutFREEZE], "+")) {
	state->sender_freeze = 1;
	return  1;
      }
    }

    /* state->request initialization !! */
    state->request = ( 1 << P_A_RELAYTARGET     |
		       1 << P_A_ACCEPTbutFREEZE |
		       1 << P_A_ACCEPTifMX      |
		       1 << P_A_ACCEPTifDNS     |
		       1 << P_A_TestRcptDnsRBL  );

    at = find_at(str, len);
    if (at != NULL) {
      if (check_domain(rel, state, at+1, len - (1 + at - str)) != 0)
	return -1;
    } else {
      if (state->rcpt_nocheck)
	return 0;

      /* Doh ??  Not  <user@domain> ??? */
      return -1;
    }

/*
   # else if (recipient's domain has 'relaytarget +' attribute) then
   #    recipient accepted
   #      [return  0;]
   # else if (recipient's domain has 'freeze +' attribute) then
   #    the MESSAGE is accepted into a freezer..
   #      [state->sender_freeze = 1; return -1;]
   # else
   #    this recipient refused
   #      [return -1;]
 */

    if (valueeq(state->values[P_A_RELAYTARGET], "+")) {
	return  0;
    }
    if (valueeq(state->values[P_A_ACCEPTbutFREEZE], "+")) {
	state->sender_freeze = 1;
	return  1;
    }

    if (state->rcpt_nocheck) {
      if (debug)
	printf("000- ... rcpt_nocheck is on!\n");
      return 0;
    }

    if (state->always_accept) {
      int rc, c = '-';
      if (state->values[P_A_ACCEPTifMX]) {
	c = state->values[P_A_ACCEPTifMX][0];
      }
      rc = client_dns_verify(c, at+1, len - (1 + at - str));
      /* XX: state->message setup! */
      if (debug)
	printf("000- ... returns: %d\n", rc);
      return rc;
    }

    if (valueeq(state->values[P_A_TestRcptDnsRBL], "+") &&
	state->rblmsg != NULL) {
      /* Now this is cute... the source address had RBL entry,
	 and the recipient domain had a request to honour the
	 RBL data. */
      if (state->message != NULL) free(state->message);
      state->message = strdup(state->rblmsg);
      if (debug)
	printf("000- ... TestRcptDnsRBL has a message: '%s'\n",
	       state->rblmsg);
      return -1;
    }

    if (state->values[P_A_ACCEPTifMX] || state->sender_norelay != 0) {
      int c = state->values[P_A_ACCEPTifMX] ? state->values[P_A_ACCEPTifMX][0] : '.';
      int rc = mx_client_verify(c, at+1, len - (1 + at - str)); 
      /* XX: state->message setup! */
      if (debug)
	printf("000- ...(mx_client_verify('%.*s')) returns: %d\n",
	       (int)(len - (1 + at - str)), at+1, rc);
      return rc;
    }
    if (state->values[P_A_ACCEPTifDNS]) {
      int rc = client_dns_verify(state->values[P_A_ACCEPTifDNS][0],
				 at+1, len - (1 + at - str));
      /* XX: state->message setup! */
      if (debug)
	printf("000- ... returns: %d\n", rc);
      return rc;
    }

    if (valueeq(state->values[P_A_RELAYTARGET], "-")) {
	return -1;
    }

    return 0;
}

static int pt_rcptpostmaster(rel, state, str, len)
struct policytest *rel;
struct policystate *state;
const char *str;
const int len;
{
    /* state->request initialization !! */
    state->request = ( 1 << P_A_RELAYTARGET );

    if (check_user(rel, state, str, len) == 0) {
      if (valueeq(state->values[P_A_RELAYTARGET], "+")) {
	return  0;
      }
    }
    return -1;
}


int policytest(rel, state, what, str, len, authuser)
struct policytest *rel;
struct policystate *state;
PolicyTest what;
const char *str, *authuser;
const int len;
{
    if (rel == NULL)
      return 0;

    if (state->authuser == NULL)
      state->authuser = (char*)authuser;

    if (debug) {
	printf("000- policytest what=%d\n", what);
	printstate(state);
    }

    if (state->message != NULL)
      free(state->message);
    state->message = NULL;

    if (what == POLICY_SOURCEDOMAIN)
	return pt_sourcedomain(rel, state, str, len);
    if (what == POLICY_HELONAME)
	return pt_heloname(rel, state, str, len);
    if (what == POLICY_MAILFROM)
	return pt_mailfrom(rel, state, str, len);
    if (what == POLICY_RCPTTO)
	return pt_rcptto(rel, state, str, len);
    if (what == POLICY_RCPTPOSTMASTER)
	return pt_rcptpostmaster(rel, state, str, len);

    abort();			/* Code error! Bad policy ! */
    return 9999; /* To silence most compilers.. */
}

char *
policymsg(rel, state)
struct policytest *rel;
struct policystate *state;
{
    return state->message;
}

long
policyinsizelimit(rel, state)
struct policytest *rel;
struct policystate *state;
{
    return state->maxinsize;
}
