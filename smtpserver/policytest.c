/*
 *  policytest.c -- module for ZMailer's smtpserver
 *  By Matti Aarnio <mea@nic.funet.fi> 1997-2004
 *
 */

/*
 * TODO:
 *  - Attribute 'request' initializations for resolving
 *  - Addresses in form  <@foo:uu@dd>, <host!user>
 */

#include "hostenv.h"

#include "sleepycatdb.h"

#ifdef HAVE_NDBM
#define datum Ndatum
#include <ndbm.h>
#undef datum
#endif
#ifdef HAVE_GDBM
#define datum Gdatum
#include <gdbm.h>
#undef datum
#endif

#define _POLICYTEST_INTERNAL_
#include "smtpserver.h"

#ifdef HAVE_SPF_ALT_SPF_H
#include <spf_alt/spf.h>
#include <spf_alt/spf_dns_resolv.h>
#endif

#define PICK_PA_MSG(attrib)	\
	if (state->message) free(state->message);	\
	state->message = state->messages[(attrib)];	\
	state->messages[(attrib)] = NULL

int use_spf;
int spf_received;
int spf_threshold;

static int resolveattributes __((struct policytest *, int, struct policystate *, const char *, int));
static int  check_domain __((struct policystate *, const char *, int));
static int  check_user __((struct policystate *, const char *, int));
static int  checkaddr  __((struct policystate *, const char *));

#if defined(AF_INET6) && defined(INET6)
extern const u_char zv4mapprefix[16];
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
	sprintf(buf,"%d/%s/%u.%u.%u.%u/%d",
		key[0], KK(key[1]),
		key[2] & 0xff, key[3] & 0xff, key[4] & 0xff, key[5] & 0xff,
		key[6] & 0xff);
      else
	sprintf(buf,"%d/%s/%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x/%d",
		key[0], KK(key[1]),
		key[2] & 0xff, key[3] & 0xff, key[4] & 0xff, key[5] & 0xff,
		key[6] & 0xff, key[7] & 0xff, key[8] & 0xff, key[9] & 0xff,
		key[10] & 0xff, key[11] & 0xff, key[12] & 0xff, key[13] & 0xff,
		key[14] & 0xff, key[15] & 0xff, key[16] & 0xff, key[17] & 0xff,
		key[18] & 0xff);
    return buf;
}

static char *showattr __((const unsigned char *key));
static char *showattr(key)
const unsigned char *key;
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

static char *showresults __((struct policystate *state));
static char *showresults(state)
struct policystate *state;
{
    static char buf[2000];
    int i;
    char **values=state->values;

    buf[0] = '\0';
    for (i = P_A_FirstAttr; i <= P_A_LastAttr; ++i) {
	sprintf(buf+strlen(buf),"%s ",KA(i));
	if (i == P_A_InboundSizeLimit )
	    sprintf(buf+strlen(buf),"%li ",state->maxinsize);
	else if (i == P_A_OutboundSizeLimit )
	    sprintf(buf+strlen(buf),"%li ",state->maxoutsize);
	else if (i == P_A_MaxSameIpSource )
	    sprintf(buf+strlen(buf),"%li ",state->maxsameiplimit);
	else
	    sprintf(buf+strlen(buf),"%s ",values[i] ? values[i] : ".");
    }
    return buf;
}

static void printstate __((const struct policystate *state));
static void printstate (state)
const struct policystate *state;
{
	int i;

	type(NULL,0,NULL," always_reject=%d",state->always_reject);
	type(NULL,0,NULL," always_freeze=%d",state->always_freeze);
	type(NULL,0,NULL," always_accept=%d",state->always_accept);
	type(NULL,0,NULL," full_trust=%d",   state->full_trust);
	type(NULL,0,NULL," trust_recipients=%d",state->trust_recipients);
	type(NULL,0,NULL," sender_reject=%d",state->sender_reject);
	type(NULL,0,NULL," sender_freeze=%d",state->sender_freeze);
	type(NULL,0,NULL," sender_norelay=%d",state->sender_norelay);
	type(NULL,0,NULL," relaycustnet=%d", state->relaycustnet);

	for ( i = P_A_FirstAttr; i <= P_A_LastAttr ; ++i) {
	    type(NULL,0,NULL," %s: %srequested, value=%s", KA(i),
		 (state->origrequest & (1<<i)) ? "" : "not ",
		 state->values[i]?state->values[i]:".");
	}

	type(NULL,0,NULL," maxinsize=%li", state->maxinsize);
	type(NULL,0,NULL," maxoutsize=%li", state->maxoutsize);
	type(NULL,0,NULL," maxsameiplimit=%li", state->maxsameiplimit);
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
    rel->dbt    = _dbt_none;
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
#ifdef HAVE_NDBM
    Ndatum Nkey, Nresult;
#endif
#ifdef HAVE_GDBM
    Gdatum Gkey, Gresult;
#endif
#ifdef HAVE_DB
    DBT Bkey, Bresult;
    int rc;
#endif


    switch (rel->dbt) {
#ifdef HAVE_NDBM
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
#ifdef HAVE_GDBM
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

#ifdef HAVE_DB
#ifdef DB_RPCCLIENT
    case _dbt_sleepyrpc:

	memset(&Bkey,    0, sizeof(Bkey));
	memset(&Bresult, 0, sizeof(Bresult));

	Bkey.data = (void *) qptr;
	Bkey.size = qlen;

#ifdef DB_INIT_TXN
	rc = (rel->sleepyrpc->get) (rel->sleepyrpc, NULL, &Bkey, &Bresult, 0);
#else
	rc = (rel->sleepyrpc->get) (rel->sleepyrpc, &Bkey, &Bresult, 0);
#endif
	if (rc != 0)
	    return NULL;

	buffer = (char *) emalloc(Bresult.size);
	memcpy(buffer, Bresult.data, Bresult.size);

	*rlenp = Bresult.size;
	return buffer;

	break; /* some compilers complain, some produce bad code
		  without this... */
#endif

    case _dbt_btree:

	memset(&Bkey,    0, sizeof(Bkey));
	memset(&Bresult, 0, sizeof(Bresult));

	Bkey.data = (void *) qptr;
	Bkey.size = qlen;

#ifdef DB_INIT_TXN
	rc = (rel->btree->get) (rel->btree, NULL, &Bkey, &Bresult, 0);
#else
	rc = (rel->btree->get) (rel->btree, &Bkey, &Bresult, 0);
#endif
	if (rc != 0)
	    return NULL;

	buffer = (char *) emalloc(Bresult.size);
	memcpy(buffer, Bresult.data, Bresult.size);

	*rlenp = Bresult.size;
	return buffer;

	break; /* some compilers complain, some produce bad code
		  without this... */

    case _dbt_bhash:

	memset(&Bkey,    0, sizeof(Bkey));
	memset(&Bresult, 0, sizeof(Bresult));

	Bkey.data = (void *) qptr;
	Bkey.size = qlen;

#ifdef DB_INIT_TXN
	rc = (rel->bhash->get) (rel->bhash, NULL, &Bkey, &Bresult, 0);
#else
	rc = (rel->bhash->get) (rel->bhash, &Bkey, &Bresult, 0);
#endif
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
    unsigned char *str, *str_base;
    int rlen, result, interest;
    char *msgstr = NULL;

    if (init) {
	/* First call of this function. Not called recursively. */
	/* Zero return value array. */
	int i;
	for (i = 0; i <= P_A_LastAttr; ++i) {
	  if (state->values[i])   free(state->values[i]);
	  if (state->messages[i]) free(state->messages[i]);
	}
	memset(state->values, 0, sizeof(state->values));
	memset(state->messages, 0, sizeof(state->messages));

	state->origrequest = state->request;
    }
    --recursions;

    if (debug)
       type(NULL,0,NULL," Key: %s", showkey(key));
/*
    if (key[1] != P_K_IPv4 && key[1] != P_K_IPv6) {
	if (debug)
	  type(NULL,0,NULL," Key: %d/%d/%s", key[0],key[1],key+2);
    } else
      if (debug)
	type(NULL,0,NULL," Key: %u.%u.%u.%u", key[2] & 0xff, key[3] & 0xff, 
	       key[4] & 0xff, key[5] & 0xff);
*/

    str_base = str = (unsigned char *) dbquery(rel, &key[0], key[0], &rlen);

    /* str[0]    - attribute list lenght
       str[1]    - attribute numeric value
       str[2...] - attribute flag string    */

    if (str == NULL) {
      if (debug)
	type(NULL,0,NULL,"  query failed");
      return -1;
    }
    /* Scan trough attribute list. Call resolveattributes recursively
       if aliases is found */

    while (rlen > 3) {

	if (str[0] < 3) {
	  if (debug)
	    type(NULL,0,NULL," Bad length of attrbute, under 3 bytes!  %d", str[0]);
	  break; /* BAD ATTRIBUTE! */
	}

	/* Attribute */
	if (debug)
	  type(NULL,0,NULL,"   Attribute: %s", showattr(str));

	/* Alias */
	if (str[1] == P_A_ALIAS) {
	    /* Do not continue if max recursions reached. */
	    if (recursions < 0) {
	      if (debug)
		type(NULL,0,NULL," Max recursions reached.");
	    } else {
	      char pbuf[256];

	      if (debug)
		type(NULL,0,NULL," Alias-recursion: %d", recursions);

	      strncpy(pbuf+2, (const char *) str+2, sizeof(pbuf)-3);
	      pbuf[ sizeof(pbuf)-1 ] = 0;

	      strlower(pbuf+2);
	      pbuf[0] = strlen((const char*) str+2) + 3;
	      pbuf[1] = P_K_TAG;
	      result = resolveattributes(rel, recursions, state, pbuf, 0);
	    }
	    rlen -= str[0];
	    str  += str[0];
	    continue;
	}

	if (str[1] == P_A_MESSAGE) {
	  if (msgstr) free(msgstr);
	  msgstr = strdup((const char *)str+2);
	  goto nextattr;
	}

	interest = 1 << str[1];	/* Convert attrib. num. value into flag bit */
	if ((interest & state->request) == 0) {
	    /* Not interested in this attribute, skip into next. */
	    if (debug)
	      type(NULL,0,NULL,"     not interested, skipped...");

	    goto nextattr;
	} else {
	    /* Mask it off. */
	    state->request &= ~interest;
	}

	if (P_A_FirstAttr <= str[1] && str[1] <= P_A_LastAttr) {
	  /* If a message was given in previous attribute, pick it! */
	  state->messages[0xFF & (str[1])] = msgstr;
	  msgstr = NULL;
	}

	if (str[1] == P_A_InboundSizeLimit) {

	  sscanf((char *)str+2,"%li", &state->maxinsize);
	  goto nextattr;

	} else if (str[1] == P_A_OutboundSizeLimit) {

	  sscanf((char *)str+2,"%li", &state->maxoutsize);
	  goto nextattr;

	} else if (str[1] == P_A_MaxSameIpSource) {

	  sscanf((char *)str+2,"%li", &state->maxsameiplimit);
	  goto nextattr;

	} else if ((str[2] != '+' && str[2] != '-') &&
		   !state->values[str[1] & 0xFF]) {

	  /* Supply suffix domain (set), e.g.:
	         RBL.MAPS.VIX.COM,DUL.MAPS.VIX.COM
	     whatever you want ... */

	  state->values[str[1] & 0xFF] = strdup((const char *)str + 2);

	} else if (str[2] != '+' && str[2] != '-') {

	  if (debug)
	    type(NULL,0,NULL," Unknown flag: %s", &str[2]);
	  goto nextattr;
	}
	/* Store valid attribute.
	   str[1] is attributes id constant, str[2] attribute flag. */

	if (P_A_FirstAttr <= str[1] && str[1] <= P_A_LastAttr) {
	    if (!state->values[str[1] & 0xFF])
		state->values[str[1] & 0xFF] = strdup((const char *)str + 2);
	  if (debug)
	    type(NULL,0,NULL,"     accepted!");
	} else {
	  if (debug)
	    type(NULL,0,NULL,"   Unknown attribute, number: %d", str[1]);
	}

    nextattr:

	/* If this wasn't the P_A_MESSAGE, we drop possibly
	   existing message here.. */
	if (str[1] != P_A_MESSAGE) {
	  if (msgstr) free(msgstr);
	  msgstr = NULL;
	}

	rlen -= str[0];
	str  += str[0];

	/* If all requests are done, exit. */
	if (!state->request) {
	  if (debug)
	    type(NULL,0,NULL," Every request found. Finishing search.");
	  break;
	}

    }				/* End of while. */

    /* Free memory from attribute list. Allocated in dbquery. */
    if (str_base)
	free(str_base);

    if (msgstr) free(msgstr);

    return 0;
}


/* Return 0, when found something */
static int checkaddr(state, pbuf)
     struct policystate *state;
     const char *pbuf;
{
    int result, count, countmax;
    int maxrecursions;
    struct policytest *rel = state->PT;

    maxrecursions = 5;

    if (pbuf[1] == P_K_DOMAIN) {
	if (debug)
	  type(NULL,0,NULL," checkaddr(): domain of '%s'",pbuf+2);
	result = resolveattributes(rel, maxrecursions, state, pbuf, 1);
	if (debug) {
	  type(NULL,0,NULL," Results: %s", showresults(state));
	}
	return (result);
    }
    if (pbuf[1] == P_K_USER) {
	if (debug)
	  type(NULL,0,NULL," checkaddr(): user of '%s'",pbuf+2);
	result = resolveattributes(rel, maxrecursions, state, pbuf, 1);
	if (debug) {
	  type(NULL,0,NULL," Results: %s", showresults(state));
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
	type(NULL,0,NULL," Address not found.");
      return -1;
    } else
      if (debug) {
	type(NULL,0,NULL," Results:  %s", showresults(state));
      }
    return 0;
}


int policyinit(state, rel, whosonrc)
     struct policystate *state;
     struct policytest  *rel;
     int whosonrc;
{
    int openok;
    char *dbname;

    if (rel == NULL)
      return -1;  /* Not defined! */

    memset(state, 0, sizeof(*state));

    state->PT = rel; /* Store the policytest dataset into state pointer.. */

#ifdef HAVE_NDBM
    if (cistrcmp(rel->dbtype, "ndbm") == 0)
	rel->dbt = _dbt_ndbm;
#endif
#ifdef HAVE_GDBM
    if (cistrcmp(rel->dbtype, "gdbm") == 0)
	rel->dbt = _dbt_gdbm;
#endif
#ifdef HAVE_DB
    if (cistrcmp(rel->dbtype, "btree") == 0)
	rel->dbt = _dbt_btree;
    if (cistrcmp(rel->dbtype, "bhash") == 0)
	rel->dbt = _dbt_bhash;
#if defined(DB_RPCCLIENT)
    if (cistrcmp(rel->dbtype, "sleepyrpc") == 0)
	rel->dbt = _dbt_sleepyrpc;
#endif
#endif
    if (rel->dbt == _dbt_none) {
	/* XX: ERROR! Unknown/unsupported dbtype! */
      state->PT = NULL;
      return 1;
    }
    openok = 0;
#ifdef HAVE_ALLOCA
    dbname = (char*)alloca(strlen(rel->dbpath) + 8);
#else
    dbname = (char*)emalloc(strlen(rel->dbpath) + 8);
#endif
    switch (rel->dbt) {
#ifdef HAVE_NDBM
    case _dbt_ndbm:
	/*
	   rel->ndbm = dbm_open((char*)rel->dbpath, O_RDWR|O_CREAT|O_TRUNC, 0644);
	 */
	strcpy(dbname, rel->dbpath);
	rel->ndbm = dbm_open(dbname, O_RDONLY, 0644);
	openok = (rel->ndbm != NULL);
	break;
#endif
#ifdef HAVE_GDBM
    case _dbt_gdbm:
	/* Append '.gdbm' to the name */
	sprintf(dbname, "%s.gdbm", rel->dbpath);
	rel->gdbm = gdbm_open(dbname, 0, GDBM_READER, 0644, NULL);
	openok = (rel->gdbm != NULL);
	break;
#endif
#ifdef HAVE_DB
#if defined(DB_RPCCLIENT)
    case _dbt_sleepyrpc:
      {
	DB_ENV *env;

	/* FIXME:FIXME:FIXME:
	   Treat supplied  rel->dbpath  as host into for
	   SleepyDB rpc server. Need also to have db name in there ??
	   Or more parameters by listing them in separate file that
	   is named in rel->dbpath  and parsed ?? 
	    - RPChost
	    - server timeout
	    - client timeout
	    - homedir in server
	    - database (file)name
	*/
	
        openok = db_env_create(& env, DB_RPCCLIENT);
	/* XX: 0 == ok */
	rel->db_._db_env = env;

	openok = env->set_rpc_server( env, NULL, rel->dbpath,
				      0 /* cl_timeout */, 0 /* sv_timeout */,
				      0 );
	/* XX: 0 == ok */

	openok = env->open(env, rel->dbpath, DB_JOINENV, 0); /* FIXME!FIXME! */
	/* XX: 0 == ok */

	openok = db_create(& rel->sleepyrpc, env, 0);
	/* XX: 0 == ok */


	/* Append '.db' to the name */
	sprintf(dbname, "%s.db", rel->dbpath);

	openok = rel->sleepyrpc->open(rel->sleepyrpc,
#if (DB_VERSION_MAJOR == 4) && (DB_VERSION_MINOR >= 1)
				      NULL, /* TXN id was added at SleepyDB 4.1 */
#endif
				      dbname, NULL,  DB_BTREE,
				      DB_RDONLY, 0);

	break;
      }
#endif

    case _dbt_btree:
	/* Append '.db' to the name */
	sprintf(dbname, "%s.db", rel->dbpath);

#if defined(HAVE_DB3) || defined(HAVE_DB4)

	rel->btree = NULL;
	openok = db_create(&rel->btree, NULL, 0);
	if (openok == 0)
	  openok = rel->btree->open(rel->btree,
#if (DB_VERSION_MAJOR == 4) && (DB_VERSION_MINOR >= 1)
				    NULL, /* TXN id was added at SleepyDB 4.1 */
#endif
				    dbname, NULL,  DB_BTREE,
				    DB_RDONLY, 0);
	if (debug && openok)
	  type(NULL,0,NULL," btree->open('%s',BTREE, RDONLY) ret=%d",dbname,openok);
	openok = !openok;

#else
#if defined(HAVE_DB2)

	rel->btree = NULL;
#ifndef DB_RDONLY
# define DB_RDONLY O_RDONLY
#endif
	openok = db_open(dbname, DB_BTREE, DB_RDONLY, 0644,
			 NULL, NULL, &rel->btree);
	openok = !openok;
#else /* HAVE_DB1 */
	rel->btree = dbopen(dbname, O_RDONLY, 0644, DB_BTREE, NULL);
	openok = (rel->btree != NULL);
#endif
#endif
	break;

    case _dbt_bhash:
	/* Append '.db' to the name */
	sprintf(dbname, "%s.dbh", rel->dbpath);

#if defined(HAVE_DB3) || defined(HAVE_DB4)

	rel->bhash = NULL;
	openok = db_create(&rel->bhash, NULL, 0);
	if (openok == 0)
	  openok = rel->bhash->open(rel->bhash,
#if (DB_VERSION_MAJOR == 4) && (DB_VERSION_MINOR >= 1)
				    NULL, /* TXN id was added at SleepyDB 4.1 */
#endif
				    dbname, NULL, DB_HASH,
				    DB_RDONLY, 0);
	if (debug && openok)
	  type(NULL,0,NULL," bhash->open('%s',BHASH, RDONLY) ret=%d",dbname,openok);
	openok = !openok;

#else
#if defined(HAVE_DB2)

	rel->bhash = NULL;
#ifndef DB_RDONLY
# define DB_RDONLY O_RDONLY
#endif
	openok = db_open(dbname, DB_HASH, DB_RDONLY, 0644,
			 NULL, NULL, &rel->bhash);
	openok = !openok;
#else /* HAVE_DB1 */
	rel->bhash = dbopen(rel->dbpath, O_RDONLY, 0644, DB_HASH, NULL);
	openok = (rel->bhash != NULL);
#endif
#endif
	break;
#endif
    default:
	break;
    }
    if (!openok) {
	/* ERROR!  Could not open the database! */
      if (debug) {
	type(NULL,0,NULL," ERROR!  Could not open the database file '%s'; errno=%d!",
	       dbname, errno);
	fflush(stdout);
      }
      state->PT = NULL;

#ifndef HAVE_ALLOCA
      free(dbname);
#endif
      return 2;
    }
#ifndef HAVE_ALLOCA
    free(dbname);
#endif

#ifdef HAVE_WHOSON_H
    if (debug) {
      type(NULL,0,NULL,"TEST: have-whoson found");
      type(NULL,0,NULL,"TEST: state-whoson=[%d] whosonrc=[%d]",
	   state->whoson_result, whosonrc);
    }
    state->whoson_result = whosonrc;
#endif
#ifdef HAVE_SPF_ALT_SPF_H
    state->check_spf=0;
#endif
    state->maxsameiplimit = -1;
    return 0;
}


static int _addrtest_ __((struct policystate *state, const char *pbuf, int sourceaddr));

static int _addrtest_(state, pbuf, sourceaddr)
     struct policystate *state;
     const char *pbuf;
     int sourceaddr;
{
    u_char ipaddr[16];
    int ipaf = pbuf[1];
    int myaddress, lcldom;
    Usockaddr saddr;

    /* Prepare for automatic match of the address */

    memset(&saddr, 0, sizeof(saddr));

    if (pbuf[1] == P_K_IPv4) {
      memcpy(ipaddr, pbuf+2, 4);
      memcpy(& saddr.v4.sin_addr, pbuf+2, 4);
      saddr.v4.sin_family = AF_INET;
    }
    if (pbuf[1] == P_K_IPv6) {
      memcpy(ipaddr, pbuf+2, 16);
#if defined(AF_INET6) && defined(INET6)
      memcpy(& saddr.v6.sin6_addr, pbuf+2, 4);
      saddr.v6.sin6_family = AF_INET6;
#endif
    }

    lcldom = (state->request & (1 << P_A_LocalDomain));
    myaddress = matchmyaddress(&saddr);

    if (debug)
      type(NULL,0,NULL," policytestaddr: lcldom/myaddress=%d/%d",lcldom,myaddress);

    /* state->request initialization !! */

    if (sourceaddr)
      state->request = ( 1 << P_A_REJECTNET         |
			 1 << P_A_FREEZENET         |
			 1 << P_A_RELAYCUSTNET      |
			 1 << P_A_InboundSizeLimit  |
			 1 << P_A_OutboundSizeLimit |
			 1 << P_A_FullTrustNet      |
			 1 << P_A_TrustRecipients   |
			 1 << P_A_TrustWhosOn       |
			 1 << P_A_Filtering         |
			 1 << P_A_RateLimitMsgs     |
			 1 << P_A_MaxSameIpSource    );
    if (!myaddress)
      state->request |= ( 1 << P_A_TestDnsRBL       |
			  1 << P_A_RcptDnsRBL       |
			  1 << P_A_CheckSPF          );

    state->maxinsize  = -1;
    state->maxoutsize = -1;

    if (checkaddr(state, pbuf) != 0)
      return 0; /* Nothing found */


    if (state->values[P_A_RateLimitMsgs]) {
      if (state->ratelimitmsgsvalue)	free (state->ratelimitmsgsvalue);
      state->ratelimitmsgsvalue = strdup(state->values[P_A_RateLimitMsgs]);
      PICK_PA_MSG(P_A_RateLimitMsgs);
    }

    if (myaddress && lcldom) {

      if (state->values[P_A_LocalDomain]) free(state->values[P_A_LocalDomain]);
      state->values[P_A_LocalDomain] = strdup("+");
      if (state->values[P_A_RELAYTARGET]) free(state->values[P_A_RELAYTARGET]);
      state->values[P_A_RELAYTARGET] = strdup("+");
      if (state->values[P_A_TestDnsRBL]) free(state->values[P_A_TestDnsRBL]);
      state->values[P_A_TestDnsRBL] = NULL;
      if (state->values[P_A_RcptDnsRBL]) free(state->values[P_A_RcptDnsRBL]);
      state->values[P_A_RcptDnsRBL] = NULL;

      if (state->values[P_A_Filtering]) {
	if (debug)
	  type(NULL,0,NULL," policytestaddr: 'filter %s' found",
		 state->values[P_A_Filtering]);
	if (valueeq(state->values[P_A_Filtering], "+")) {
	  state->content_filter = 1;
	} else {
	  state->content_filter = 0;
	}
      }

      if (debug)
	type(NULL,0,NULL," Results:  %s", showresults(state));

      return 0;
    }

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
    state->message = NULL;

    if (valueeq(state->values[P_A_REJECTNET], "+")) {
      if (debug)
	type(NULL,0,NULL," policytestaddr: 'rejectnet +' found");
      PICK_PA_MSG(P_A_REJECTNET);
      if (state->message == NULL)
	state->message = strdup("Your network address is blackholed in our static tables");
      state->always_reject = 1;
      return -1;
    }
    if (valueeq(state->values[P_A_FREEZENET], "+")) {
      if (debug)
	type(NULL,0,NULL," policytestaddr: 'freezenet +' found");
      PICK_PA_MSG(P_A_FREEZENET);
      if (state->message == NULL)
	state->message = strdup("Your network address is blackholed in our static tables");
      state->always_freeze = 1;
      return  1;
    }
    if (valueeq(state->values[P_A_TrustRecipients], "+")) {
      if (debug)
	type(NULL,0,NULL," policytestaddr: 'trustrecipients +' found");
      state->trust_recipients = 1;
      PICK_PA_MSG(P_A_TrustRecipients);
    }
    if (valueeq(state->values[P_A_FullTrustNet], "+")) {
      if (debug)
	type(NULL,0,NULL," policytestaddr: 'fulltrustnet +' found");
      state->full_trust = 1;
      PICK_PA_MSG(P_A_FullTrustNet);
    }
#ifdef HAVE_WHOSON_H
    if (valueeq(state->values[P_A_TrustWhosOn], "+")) {
      if (debug)
	type(NULL,0,NULL," policytestaddr: 'trust-whoson +' found, accept? = %d",
	       (state->whoson_result == 0));
      if (state->whoson_result == 0)
	state->always_accept = 1;
      PICK_PA_MSG(P_A_TrustWhosOn);
    }
#endif
    if (valueeq(state->values[P_A_RELAYCUSTNET], "+")) {
      if (debug)
	type(NULL,0,NULL," policytestaddr: 'relaycustnet +' found");
      state->always_accept = 1;
      PICK_PA_MSG(P_A_RELAYCUSTNET);
    }

    if (state->values[P_A_Filtering]) {
      if (debug)
	type(NULL,0,NULL," policytestaddr: 'filter %s' found",
	       state->values[P_A_Filtering]);
      if (valueeq(state->values[P_A_Filtering], "+")) {
	state->content_filter = 1;
      } else {
	state->content_filter = 0;
      }
    }

    if (state->trust_recipients || state->full_trust || state->always_accept)
      return 0;

 just_rbl_checks:;

    if (state->values[P_A_Filtering]) {
      if (debug)
	type(NULL,0,NULL," policytestaddr: 'filter %s' found",
	       state->values[P_A_Filtering]);
      if (valueeq(state->values[P_A_Filtering], "+")) {
	state->content_filter = 1;
      } else {
	state->content_filter = 0;
      }
    }

    if (valueeq(state->values[P_A_CheckSPF], "+")) {
#ifdef HAVE_SPF_ALT_SPF_H
      if (debug)
	type(NULL,0,NULL," policytestaddr: 'spf +' found");
      state->check_spf=1;
/* must be in the policystate destructor
      SPF_destroy_default_config();
*/
      if (state->spfcid) SPF_destroy_config(state->spfcid);
      if ((state->spfcid=SPF_create_config()) == NULL) {
	type(NULL,0,NULL," SPF_create_config() failed");
	state->check_spf=0;
      }
      if (state->spfdcid) SPF_dns_destroy_config_resolv(state->spfdcid);
      if ((state->spfdcid=SPF_dns_create_config_resolv(NULL, 0)) == NULL) {
	type(NULL,0,NULL," SPF_dns_create_config() failed");
	state->check_spf=0;
      }
      /* SPF_free_c_results(&state->local_policy); */
      SPF_init_c_results(&state->local_policy);
      if (SPF_compile_local_policy(state->spfcid,NULL,0,&state->local_policy)) {
	type(NULL,0,NULL," SPF_compile_local_policy() failed: %s",
						state->local_policy.err_msg);
	state->check_spf=0;
      }
#else
      type(NULL,0,NULL," compiled without SPF support, 'spf +' ignored");
#endif
    }

    if (state->values[P_A_TestDnsRBL] &&
	!valueeq(state->values[P_A_TestDnsRBL], "-")) {
      int rc;
      if (debug)
	type(NULL,0,NULL," policytestaddr: 'test-dns-rbl %s' found;",
	       state->values[P_A_TestDnsRBL]);
      rc = rbl_dns_test(state, ipaf, ipaddr, state->values[P_A_TestDnsRBL], &state->message);
      if (!state->message){ PICK_PA_MSG(P_A_TestDnsRBL); }

      if (debug)
	type(NULL,0,NULL,"  rc=%d; msg='%s'",
	     rc, state->message ? state->message : "<nil>");

      return rc;
    }

    /* bag = Andrey Blochintsev <bag@iptelecom.net.ua>  */
    /* bag + */
    if (state->values[P_A_RcptDnsRBL] &&
	state->values[P_A_RcptDnsRBL][0] == '_') {
      int rc = 1;
      if (debug)
	type(NULL,0,NULL," policytestaddr: 'rcpt-dns-rbl %s' found;",
	       state->values[P_A_RcptDnsRBL]);
      if (state->values[P_A_RcptDnsRBL][1] != '+') {
      	if (state->rblmsg != NULL)
	  free(state->rblmsg);
	state->rblmsg = strdup(state->values[P_A_RcptDnsRBL] + 1);
	rc = 0;
      }
      if (!state->message){ PICK_PA_MSG(P_A_RcptDnsRBL); }
      if (debug)
	type(NULL,0,NULL,"  rc=%d", rc);
      return 0; /* We report error LATER */

    }
    /* bag - */

    if (state->values[P_A_RcptDnsRBL] &&
	!valueeq(state->values[P_A_RcptDnsRBL], "-")) {
      int rc;
      if (debug)
	type(NULL,0,NULL," policytestaddr: 'rcpt-dns-rbl %s' found;",
	       state->values[P_A_RcptDnsRBL]);
      rc = rbl_dns_test(state, ipaf, ipaddr, state->values[P_A_RcptDnsRBL], &state->rblmsg);

      if (debug)
	type(NULL, 0, NULL, "rcpt-dns-rbl test yields: rc=%d rblmsg='%s'", rc,
	     state->rblmsg ? state->rblmsg : "<none>");

      if (!state->message){ PICK_PA_MSG(P_A_RcptDnsRBL); }
      if (debug)
	type(NULL,0,NULL,"  rc=%d", rc);
      return 0; /* We report error LATER */
    }
    return 0;
}

int policytestaddr(state, what, raddr)
     struct policystate *state;
     PolicyTest what;
     Usockaddr *raddr;
{
    char pbuf[64]; /* Not THAT much space needed.. */
    int rc;

    struct sockaddr_in *si4;
#if defined(AF_INET6) && defined(INET6)
    struct sockaddr_in6 *si6;
#endif


    if (what != POLICY_SOURCEADDR)
      abort();		/* Urgle..! Code mismatch! */

    if (state->PT == NULL)
      return 0;

    /* Find address match -- IPv4 mapped into IPv6 space too! */

    state->message = NULL; /* This is early initial clearing */

    if (raddr->v4.sin_family == 0) {
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
      if (memcmp((void *)&si6->sin6_addr, zv4mapprefix, 12) == 0) {
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
      type(NULL,0,NULL,"Unknown address format; sa_family = %d",
	   raddr->v4.sin_family);
      return -2;
    }

#if defined(AF_INET6) && defined(INET6)
    if (pbuf[1] == P_K_IPv6) {
      char *s;
      unsigned char *p;
      int i;

      strcpy(state->ratelabelbuf, "6:");
      p = pbuf+2;
      s = state->ratelabelbuf+2;
      for (i = 0; i < 16; ++i) {
	sprintf(s, "%02x", *p);
	s += 2; ++p;
      }
    } else
#endif
      {
	char *s;
	unsigned char *p;
	int i;

	strcpy(state->ratelabelbuf, "4:");
	p = (unsigned char *)(pbuf+2);
	s = state->ratelabelbuf+2;
	for (i = 0; i < 4; ++i) {
	  sprintf(s, "%02x", *p);
	  s += 2; ++p;
	}
      }

    state->request = 0;
    state->content_filter = -1;

    rc = _addrtest_(state, pbuf, 1);

#ifdef HAVE_SPF_ALT_SPF_H
    if (state->check_spf) {
      if (debug) {
	char aaa[32];
	inet_ntop(raddr->v4.sin_family,&raddr->v4.sin_addr,aaa,sizeof(aaa));
	if (debug) type(NULL,0,NULL,"doing SPF_set_ipv4(%s)",aaa);
      }
#if defined(AF_INET6) && defined(INET6)
      if (raddr->v6.sin6_family == AF_INET6) {
	if (SPF_set_ipv6(state->spfcid, raddr->v6.sin6_addr)) {
	  type(NULL,0,NULL,"SPF_set_ipv6() failed");
	  state->check_spf=0;
	}
      } else
#endif
      {
	if (SPF_set_ipv4(state->spfcid, raddr->v4.sin_addr)) {
	  type(NULL,0,NULL,"SPF_set_ipv4() failed");
	  state->check_spf=0;
	}
      }
    }
#endif /* HAVE_SPF_ALT_SPF_H */



    if (debug) fflush(stdout);
    return rc;
}

static int call_rate_counter(state, incr, what, countp)
     struct policystate *state;
     int incr, *countp;
     PolicyTest what;
{
    int rc;
    char pbuf[2000]; /* Not THAT much space needed.. */
    const char *cmd = "RATE";
    const char *whatp = "CONNECT";
    int count = 0;
    const char *limitp = state->ratelimitmsgsvalue;

    if (!limitp) limitp = "-1";

    if (debug)
      type(NULL,0,NULL,"call_rate_counter(incr=%d what=%d)",incr,what);


    /* How to see, that we will have interest in these rate entries
       in the future ?  E.g. there is no point in spending time
       for externally incoming email... */

    if (incr  &&  !state->did_query_rate)
      return 0; /* INCRed counters at DATA/BDAT, but hadn't
		   shown interest at MAIL for this... */


    state->did_query_rate = 1;

    switch (incr) {
    case 0:
      cmd   = "RATE";
      count = 0;
      break;
    case 1:
      cmd   = "MSGS";
      count = 1;
      break;
    case 2:
      cmd = "EXCESS";
      count = 1;
      break;
    default:
      break;
    }

    switch (what) {
    case POLICY_SOURCEADDR:
      break;
    case POLICY_MAILFROM:
      whatp = "MAIL";
      break;
    case POLICY_DATA:
    case POLICY_DATAOK:
      whatp = "DATA";
      count = 1;
      break;
    case POLICY_RCPTTO:
      whatp = "RCPT";
      cmd   = "RCPT";
      count = incr;
      break;
    default:
      whatp = "xxxx";
      break;
    }

    sprintf(pbuf, "%s %s %s %s %d",
	    cmd, state->ratelabelbuf, limitp, whatp, count);

    if (debug)
      type(NULL,0,NULL,"call_rate_counter: sending: '%s'",pbuf);

    rc = call_subdaemon_trk(&state->rate_state, pbuf, pbuf, sizeof(pbuf));

    if (debug)
      type(NULL,0,NULL,"call_rate_counter: got rc=%d, buf='%s'",rc, pbuf);

    if (rc < 0) return rc; 


    /* RATE all MAIL FROM lines, apply limits
     * INCR all accepted DATA/BDATs.
     */

    if (!countp) return 0; /* Don't actually care! */

    if (sscanf(pbuf, "%*s %d", countp) == 1)
      return 0;

    return -1;
}


static int check_domain(state, input, inlen)
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
      return _addrtest_(state,pbuf, 0);
    }

    plen = addr_len;
    /* '\0' not included in inlen... */
    plen += 1 + 2;

    pbuf[0] = plen;
    pbuf[1] = P_K_DOMAIN;

    result = 1;

    while (result != 0) {
	if (debug)
	  type(NULL,0,NULL," DEBUG: %s", showkey(pbuf));
	result = checkaddr(state, pbuf);

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

static const char * find_nonqchr __((const char *, int, int));
static const char *
find_nonqchr(input, chr, inlen)
     const char *input;
     int chr, inlen;
{
  int quote = 0;
  /* Find first unquoted ``chr'' character, and return a pointer to it */
  for (; inlen > 0; --inlen,++input) {
    if (*input == '"')
      quote = !quote;
    if (*input == '\\') {
      --inlen; ++input;
      continue;
    }
    if (*input == chr && !quote)
      return input;
  }
  return NULL;
}

/* Return 0, when found something */
static int check_user(state, input, inlen)
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

    at = find_nonqchr(pbuf + 2, '@', inlen);
    if (!at) return 0;

    pbuf[inlen + 2] = '\0';
    pbuf[0] = inlen + 1 + 2;
    pbuf[1] = P_K_USER;

    result = checkaddr(state, pbuf);
    if (result == 0) /* Found! */
      return result;

    /* 'user@' */
    inlen = (at+1 - pbuf) - 2;
    pbuf[inlen + 2] = '\0';
    pbuf[0] = inlen + 1 + 2;
    pbuf[1] = P_K_USER;

    result = checkaddr(state, pbuf);
    return result;
}


static int pt_heloname __((struct policystate *, const char *, const int));

static int pt_mailfrom __((struct policystate *, const char *, const int));

static int pt_rcptto __((struct policystate *, const char *, const int));

static int pt_rcptpostmaster __((struct policystate *, const char *, const int));

static int pt_heloname(state, str, len)
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
    if (state->full_trust || state->authuser)
	return 0;

    /*
     * This is somewhat controversial.
     * This exists solely to allow simplification of
     * smtpserver.conf  file by having the HELO/EHLO
     * strings to be rejected stored in the policy
     * database.
     *
     * In Sep-2001 it became apparent that very least
     * there is no point in analyzing '[...]' numeric
     * HELO parameter contained address data.
     *
     * Current code will only look for the input string
     * in the database (by domain lookup protocol), and
     * react on it by slamming the door shut (if any).
     *
     */

#ifdef HAVE_SPF_ALT_SPF_H
    if (state->check_spf) {
      if (debug) type(NULL,0,NULL,"doing SPF_set_helo_dom(\"%s\")",str);
      if (SPF_set_helo_dom(state->spfcid, str)) {
	  type(NULL,0,NULL,"SPF_set_helo_dom() failed");
	  state->check_spf=0;
      }
    }
#endif

    if (*str != '[') { /* Don't test address literals! */

      /* state->request initialization !! */
      state->request = ( 1 << P_A_REJECTNET    |
			 1 << P_A_FREEZENET  );

      check_domain(state, str, len);

/*
   # if (name of SMTP client has 'rejectnet +' attribute) then
   #    any further conversation refused
   #      [state->always_reject = 1; return -1;]
 */
      if (valueeq(state->values[P_A_REJECTNET], "+")) {
	state->always_reject = 1;
	PICK_PA_MSG(P_A_REJECTNET);
	return -1;
      }
      if (valueeq(state->values[P_A_FREEZENET], "+")) {
	state->always_freeze = 1;
	PICK_PA_MSG(P_A_FREEZENET);
	return  1;
      }

    }

    return 0;
}

static int pt_sourcedomain(state, str, len)
     struct policystate *state;
     const char *str;
     const int len;
{
    if (state->always_reject)
	return -1;
    if (state->always_freeze)
	return 1;
    if (state->full_trust || state->authuser)
	return 0;

    /* state->request initialization !! */
    state->request = ( 1 << P_A_REJECTNET    |
		       1 << P_A_FREEZENET    |
		       1 << P_A_RELAYCUSTNET |
		       1 << P_A_InboundSizeLimit  |
		       1 << P_A_OutboundSizeLimit  );
    state->request |= ( 1 << P_A_RcptDnsRBL );	/* bag */

    check_domain(state, str, len);

/*
   # if (name of SMTP client has 'rejectnet +' attribute) then
   #    any further conversation refused
   #      [state->always_reject = 1; return -1;]
 */
    if (valueeq(state->values[P_A_REJECTNET], "+")) {
	state->always_reject = 1;
	PICK_PA_MSG(P_A_REJECTNET);
	return -1;
    }
    if (valueeq(state->values[P_A_FREEZENET], "+")) {
	state->always_freeze = 1;
	PICK_PA_MSG(P_A_FREEZENET);
	return  1;
    }

    if (state->always_accept)
	return 0;

    if (valueeq(state->values[P_A_RELAYCUSTNET], "+")) {
      if (debug)
	type(NULL,0,NULL," pt_sourceaddr: 'relaycustnet +' found");
      state->always_accept = 1;
      PICK_PA_MSG(P_A_RELAYCUSTNET);
      return  0;
    }
    if (valueeq(state->values[P_A_FullTrustNet], "+")) {
      if (debug)
	type(NULL,0,NULL," pt_sourceaddr: 'fulltrustnet +' found");
      state->full_trust = 1;
      PICK_PA_MSG(P_A_FullTrustNet);
      return  0;
    }
    /* bag + */
    if (state->rblmsg == NULL &&	/* only if no rbl_message before (from lookup by net) */
	state->values[P_A_RcptDnsRBL] &&
	state->values[P_A_RcptDnsRBL][0] == '_') {
      if (debug)
	type(NULL,0,NULL," pt_sourceaddr: 'rcpt-dns-rbl %s' found;",
	       state->values[P_A_RcptDnsRBL]);
      if (state->values[P_A_RcptDnsRBL][1] != '+') {
	state->rblmsg = strdup(state->values[P_A_RcptDnsRBL] + 1);
      }
      free(state->values[P_A_RcptDnsRBL]);
      return 0; /* We report error LATER */

    }
    /* bag - */
    return 0;
}

static int pt_mailfrom(state, str, len)
     struct policystate *state;
     const char *str;
     const int len;
{
    const char *at;
    int requestmask = 0;
    int rc;

    state->sender_reject = 0;
    state->sender_freeze = 0;
    state->sender_norelay = 0;

#ifdef HAVE_SPF_ALT_SPF_H
    if (state->check_spf) {
      char *nstr=strdup(str);
      nstr[len]='\0';
      if (debug) type(NULL,0,NULL,"doing SPF_set_env_from(\"%s\")",nstr);
      if (SPF_set_env_from(state->spfcid, nstr)) {
	  type(NULL,0,NULL,"SPF_set_env_from(\"%s\") failed",nstr);
	  state->check_spf=0;
      }
      free(nstr);
    }
#endif

    if (state->always_reject)
	return -1;
    if (state->always_freeze)
	return 1;
    if (state->full_trust || state->authuser)
	return 0;


    if (len > 0) { /* Non-box address.. */

      /* state->request initialization !! */
      state->request = ( 1 << P_A_REJECTSOURCE |
			 1 << P_A_FREEZESOURCE   );

      /* XX: How about  <@foo:user@domain> ??? */
      /* XX: With IGNORING RFC-821-source-route "@foo:" we
	 don't have problems here */

      /* Check source user */
      if (check_user(state, str, len) == 0) {
	if (valueeq(state->values[P_A_FREEZESOURCE], "+")) {
	  if (debug)
	    type(NULL,0,NULL," mailfrom: 'freezesource +'");
	  state->sender_freeze = 1;
	  PICK_PA_MSG(P_A_FREEZESOURCE);
	  return 1;
	}
	if (state->values[P_A_FREEZESOURCE])
	  requestmask |= 1 << P_A_FREEZESOURCE;
	
	if (valueeq(state->values[P_A_REJECTSOURCE], "+")) {
	  if (debug)
	    type(NULL,0,NULL," mailfrom: 'rejectsource +'");
	  state->sender_reject = 1;
	  PICK_PA_MSG(P_A_REJECTSOURCE);
	  return -1;
	}
	if (state->values[P_A_REJECTSOURCE])
	  requestmask |= 1 << P_A_REJECTSOURCE;
      }

      state->request = ( 1 << P_A_REJECTSOURCE  |
			 1 << P_A_FREEZESOURCE  |
#if 0
			 1 << P_A_RELAYCUSTOMER |
#endif
			 1 << P_A_SENDERNoRelay |
			 1 << P_A_SENDERokWithDNS ) & (~ requestmask);

      at = find_nonqchr(str, '@', len);
      if (at != NULL) {
	/* @[1.2.3.4] ?? */
	if (check_domain(state, at+1, len - (1 + at - str)) != 0)
	  return -1;
      } else {
	/* Doh ??  Not  <user@domain> ??? */
	return -1;
      }

    } else { /* The case of: "MAIL FROM:<>" */

      state->request = ( 1 << P_A_REJECTSOURCE  |
			 1 << P_A_FREEZESOURCE  |
#if 0
			 1 << P_A_RELAYCUSTOMER |
#endif
			 1 << P_A_SENDERNoRelay |
			 1 << P_A_SENDERokWithDNS ) & (~ requestmask);

      if (check_domain(state, ".", 1) != 0)
	  return -1;
      at = str;
    }


    if ((len > 0) && valueeq(state->values[P_A_SENDERNoRelay], "+")) {
      if (debug)
	type(NULL,0,NULL," mailfrom: 'sendernorelay +'");
      state->sender_norelay = 1;
      PICK_PA_MSG(P_A_SENDERNoRelay);
    }

    if (debug)
      type(NULL,0,NULL,"mailfrom; always_accept=%d ratelimitmsgsvalue='%s'",
	   state->always_accept,
	   (state->ratelimitmsgsvalue ? state->ratelimitmsgsvalue : "<nil>"));

    if (state->always_accept && state->ratelimitmsgsvalue) {
      /* If we are in 'alwaysaccept' mode, which is true for IP-acl:s,
	 then we check to see rate-limits */

      int count;
      int limitval;

      if (debug)
	type(NULL,0,NULL,"Checking 'RateLimitMsgs %s' attribute",
	     state->ratelimitmsgsvalue);

      if (sscanf(state->ratelimitmsgsvalue, "%d", &limitval) == 1) {
	/* Valid numeric value had.. */

	int rc = call_rate_counter(state, 0, POLICY_MAILFROM,
				   &count);

	/* Non-zero value means that counter was not reachable, or
	   that there was no data. */

	if (rc == 0) {
	  /* Got some rate limit data back,  now USE IT ! */
	  if (limitval < 0 && count > -limitval) {
	    PICK_PA_MSG(P_A_RateLimitMsgs);
	    rc = -1;  /* Hard, e.g. 500-series */
	  } else if (limitval > 0 && count > limitval) {
	    PICK_PA_MSG(P_A_RateLimitMsgs);
	    rc = -100; /* Soft, e.g. 400-series */
	  }
	  if ((rc != 0)  && (! state->message))
	    state->message = strdup("You are sending too much mail per time interval.  Try again latter.");
	  if (rc != 0) {
	    /* register the excess! */
	    call_rate_counter(state, 2, POLICY_MAILFROM, &count);
	  }
	  return rc;
	}
      }
    }

    if (valueeq(state->values[P_A_REJECTSOURCE], "+")) {
	if (debug)
	  type(NULL,0,NULL," mailfrom: 'rejectsource +'");
	state->sender_reject = 1;
	PICK_PA_MSG(P_A_REJECTSOURCE);
	return -1;
    }

    if (valueeq(state->values[P_A_FREEZESOURCE], "+")) {
	if (debug)
	  type(NULL,0,NULL," mailfrom: 'freezesource +'");
	state->sender_freeze = 1;
	PICK_PA_MSG(P_A_FREEZESOURCE);
	return -1;
    }

    if ((len > 0)  && (at[1] != '[') && state->always_accept ) {
      /* Accept if found in DNS, and not an address literal! */
      int rc;
      rc = sender_dns_verify(state, '-', at+1, len - (1 + at - str));
      if (debug)
	type(NULL,0,NULL," ... returns: %d", rc);
      return rc;
    }

    if ((len > 0)  && (at[1] != '[') && state->values[P_A_SENDERokWithDNS]) {
      /* Accept if found in DNS, and not an address literal! */
      int test_c = state->values[P_A_SENDERokWithDNS][0];
      int rc = sender_dns_verify(state, test_c, at+1, len - (1 + at - str));
      if (debug)
	type(NULL,0,NULL," ... returns: %d", rc);
      PICK_PA_MSG(P_A_SENDERokWithDNS);
      return rc;
    }

#ifdef HAVE_WHOSON_H
    if (valueeq(state->values[P_A_TrustWhosOn], "+")) {
      if (debug)
	type(NULL,0,NULL," policytestaddr: 'trust-whoson +' found, accept? = %d",
	     (state->whoson_result == 0));
      if (state->whoson_result == 0)
	return 0; /* OK! */
    }
#endif

    rc=0;
#ifdef HAVE_SPF_ALT_SPF_H
    if (state->check_spf) {
      int spf_level;
      SPF_output_t spf_output = SPF_result(state->spfcid,state->spfdcid);
      if (debug) {
	type(NULL,0,NULL," SPF_result=%d (%s) reason=%d  (%s) error=%d",
	     spf_output.result,
	     SPF_strresult(spf_output.result),
	     spf_output.reason,
	     SPF_strreason(spf_output.reason),
	     spf_output.err);
	type(NULL,0,NULL,"%s",( spf_output.smtp_comment ?
				spf_output.smtp_comment : "<null>") );
      }
      if (state->spf_received_hdr != NULL)
	free(state->spf_received_hdr);
      state->spf_received_hdr=strdup(spf_output.received_spf);
      if (debug)
	type(NULL,0,NULL,"%s", (state->spf_received_hdr ?
				state->spf_received_hdr : "<null>") );

      switch (spf_output.result) {
      case SPF_RESULT_PASS:	spf_level=5; break;
      case SPF_RESULT_UNKNOWN:	spf_level=5; break;
      case SPF_RESULT_ERROR:	spf_level=5; break;
      case SPF_RESULT_NEUTRAL:	spf_level=4; break;
      case SPF_RESULT_NONE:	spf_level=3; break;
      case SPF_RESULT_SOFTFAIL:	spf_level=2; break;
      case SPF_RESULT_FAIL:	spf_level=1; break;
      default:			spf_level=5; break;
      }
      if (debug)
	type(NULL,0,NULL,
	     "rejecting if spf_level(%d) < spf_threshold(%d)",
	     spf_level,spf_threshold);

      if (spf_level < spf_threshold) {
	if (spf_output.smtp_comment) {
	  state->message=strdup(spf_output.smtp_comment);
	} else {
	  PICK_PA_MSG(P_A_CheckSPF);
	}
	rc=-1;
      }
      SPF_free_output(&spf_output);
    }
#endif
    return rc;
}

static int pt_rcptto(state, str, len)
     struct policystate *state;
     const char *str;
     const int len;
{
    const char *at;
    int localdom, relayable = 0;

    if (state->always_reject) return -1;
    if (state->sender_reject) return -2;
    if (state->always_freeze) return  1;
    if (state->sender_freeze) return  1;
    if (state->full_trust)    return  0;
    /* if (state->always_accept) return  0; */
    if (state->authuser)      return  0;
    if (state->trust_recipients) return 0;

#ifdef HAVE_WHOSON_H
    if (debug) {
      type(NULL,0,NULL,"TEST: 'have-whoson' found");
      type(NULL,0,NULL,"TEST: 'state-whoson=[%d] ",
	   state->values[P_A_TrustWhosOn]);
    }
#endif

    /* rcptfreeze even for 'rcpt-nocheck' ? */

    /* state->request initialization !! */
    state->request = ( 1 << P_A_RELAYTARGET     |
		       1 << P_A_ACCEPTbutFREEZE |
		       1 << P_A_TestRcptDnsRBL  |
		       1 << P_A_TrustWhosOn     |
		       1 << P_A_LocalDomain );

    /* Test first the full address */
    if (check_user(state, str, len) == 0) {
#ifdef HAVE_WHOSON_H
      if (valueeq(state->values[P_A_TrustWhosOn], "+")) {
	if (state->whoson_result == 0){
	  PICK_PA_MSG(P_A_TrustWhosOn);
	  return 0;
	}
      }
#endif
      if (valueeq(state->values[P_A_RELAYTARGET], "+")) {
	PICK_PA_MSG(P_A_RELAYTARGET);
	return  0;
      }
      if (valueeq(state->values[P_A_RELAYTARGET], "-")) {
	PICK_PA_MSG(P_A_RELAYTARGET);
	return -1;
      }
      if (valueeq(state->values[P_A_ACCEPTbutFREEZE], "+")) {
	state->sender_freeze = 1;
	PICK_PA_MSG(P_A_ACCEPTbutFREEZE);
	return  1;
      }
      if (valueeq(state->values[P_A_TestRcptDnsRBL], "+")) {

	type(NULL, 0, NULL, "test-rcpt-dns-rbl test; rblmsg='%s'",
	     state->rblmsg ? state->rblmsg : "<none>");

	if (state->rblmsg != NULL) {
	  /* Now this is cute... the source address had RBL entry,
	     and the recipient domain had a request to honour the
	     RBL data. */
	  if (state->message != NULL) free(state->message);
	  state->message = strdup(state->rblmsg);
	  if (debug)
	    type(NULL,0,NULL," ... TestRcptDnsRBL has a message: '%s'",
		   state->rblmsg);
	  return -1;
	}
      }
    }

    /* state->request initialization !! */
    state->request = ( 1 << P_A_RELAYTARGET     |
		       1 << P_A_ACCEPTbutFREEZE |
		       1 << P_A_ACCEPTifMX      |
		       1 << P_A_ACCEPTifDNS     |
		       1 << P_A_TestRcptDnsRBL  |
		       1 << P_A_TrustWhosOn     |
		       1 << P_A_LocalDomain );

    at = find_nonqchr(str, '@', len);
    if (at != NULL) {
      if (check_domain(state, at+1, len - (1 + at - str)) != 0) {
	type(NULL,0,NULL,"rcptto checkdomain fails; -1");
	return -1;
      }
    } else {
      if (state->always_accept) {
	return 0;
      }

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

    while (((localdom = valueeq(state->values[P_A_LocalDomain], "+")) ||
	    (relayable = valueeq(state->values[P_A_RELAYTARGET], "+"))) &&
	   (percent_accept < 0)) {

      /* Ok, local domain recognized, now see if it has
	 '%'-hack at the local-part.. */

      const char *phack, *phack2;
      int llen = (at - str);

      /* How about '!' ??? */
      phack = find_nonqchr(str, '!', llen);
      if (phack != NULL && percent_accept < 0) {
	/* Bang-path from left to right... */
	/* ... each component from str to phack-1 */
	/* state->request initialization !! */
	state->request = ( 1 << P_A_RELAYTARGET     |
			   1 << P_A_ACCEPTbutFREEZE |
			   1 << P_A_ACCEPTifMX      |
			   1 << P_A_ACCEPTifDNS     |
			   1 << P_A_TrustWhosOn     |
			   1 << P_A_TestRcptDnsRBL  |
			   1 << P_A_LocalDomain );

	llen = (phack - str);
	if (check_domain(state, str, llen) != 0)
	  return -1;
	
	str = phack+1;
	continue;
      }

      /* Find the LAST of unquoted '%' characters! */
      phack = find_nonqchr(str, '%', llen);
      phack2 = NULL;
      while (phack && !phack2) {
	int ll2 = at - phack -1;
	phack2 = find_nonqchr(phack+1, '%', ll2);
	if (phack2) {
	  phack = phack2;
	  phack2 = NULL;
	} else
	  break; /* Not found */
      }
      /* Now do test of the domain in there, is it ok
	 for relaying to ? */
      if (phack) {
	/* state->request initialization !! */
	state->request = ( 1 << P_A_RELAYTARGET     |
			   1 << P_A_ACCEPTbutFREEZE |
			   1 << P_A_ACCEPTifMX      |
			   1 << P_A_ACCEPTifDNS     |
			   1 << P_A_TrustWhosOn     |
			   1 << P_A_TestRcptDnsRBL  |
			   1 << P_A_LocalDomain );

	llen = (at - phack)-1;
	if (check_domain(state, phack+1, llen) != 0)
	  return -1;
	at = phack;
	*((int*)&len) = (1 + at - str) + llen;
	continue;
      }

      if (phack != NULL && percent_accept < 0) {
	return -2; /* Reject the percent kludge */
      }

      break; /* Ok, could be ok, but RBL may say differently ... */
    }


    /* Do target specific rejects early */

    if (valueeq(state->values[P_A_RELAYTARGET], "-")) {
      PICK_PA_MSG(P_A_RELAYTARGET);
      return -1;
    }

    if (valueeq(state->values[P_A_ACCEPTbutFREEZE], "+")) {
	state->sender_freeze = 1;
	PICK_PA_MSG(P_A_ACCEPTbutFREEZE);
	return  1;
    }

    if (valueeq(state->values[P_A_TestRcptDnsRBL], "+")) {

      type(NULL, 0, NULL, "test-rcpt-dns-rbl test; rblmsg='%s'",
	   state->rblmsg ? state->rblmsg : "<none>");

      if (state->rblmsg != NULL) {
	/* Now this is cute... the source address had RBL entry,
	   and the recipient domain had a request to honour the
	   RBL data. */
	if (state->message != NULL) free(state->message);
	state->message = strdup(state->rblmsg);
	if (debug)
	  type(NULL,0,NULL," ... TestRcptDnsRBL has a message: '%s'",
		 state->rblmsg);
	return -1;
      }
    }

    if (valueeq(state->values[P_A_RELAYTARGET], "+")) {
	PICK_PA_MSG(P_A_RELAYTARGET);
	return  0;
    }

    /* WHOSON processing sets 'always_accept' at connection setup..
       No need to ponder it here.. */

    if (state->always_accept) {
      int rc, c = '-';

      if (state->values[P_A_ACCEPTifMX]) {
	c = state->values[P_A_ACCEPTifMX][0];
      }
      rc = client_dns_verify(state, c, at+1, len - (1 + at - str));
      /* XX: state->message setup! */
      if (debug)
	type(NULL,0,NULL," ... returns: %d", rc);
      PICK_PA_MSG(P_A_ACCEPTifMX);
      return rc;
    }

    if (state->values[P_A_ACCEPTifMX] || state->sender_norelay != 0) {
      int c = state->values[P_A_ACCEPTifMX] ? state->values[P_A_ACCEPTifMX][0] : '.';
      int rc = mx_client_verify(state, c, at+1, len - (1 + at - str)); 
      /* XX: state->message setup! */
      if (debug)
	type(NULL,0,NULL," ...(mx_client_verify('%.*s')) returns: %d",
	       (int)(len - (1 + at - str)), at+1, rc);
      PICK_PA_MSG(P_A_ACCEPTifMX);
      return rc;
    }

    if (state->values[P_A_ACCEPTifDNS]) {
      int rc = client_dns_verify(state, state->values[P_A_ACCEPTifDNS][0],
				 at+1, len - (1 + at - str));
      /* XX: state->message setup! */
      if (debug)
	type(NULL,0,NULL," ... returns: %d", rc);
      PICK_PA_MSG(P_A_ACCEPTifDNS);
      return rc;
    }

    return 0;
}

static int pt_rcptpostmaster(state, str, len)
     struct policystate *state;
     const char *str;
     const int len;
{
    /* state->request initialization !! */
    state->request = ( 1 << P_A_RELAYTARGET );

    if (check_user(state, str, len) == 0) {
      if (valueeq(state->values[P_A_RELAYTARGET], "+")) {
	PICK_PA_MSG(P_A_RELAYTARGET);
	return  0;
      }
    }
    return -1;
}


int policytest(state, what, str, len, authuser)
     struct policystate *state;
     PolicyTest what;
     const char *str, *authuser;
     const int len;
{
    int rc;
    if (state == NULL || state->PT == NULL)
      return 0;

    if (state->authuser == NULL)
	state->authuser = (char*)authuser;

    if (debug) {
	type(NULL,0,NULL," policytest what=%d", what);
	printstate(state);
    }

    if (state->message != NULL)
	free(state->message);
    state->message = NULL;

    switch(what) {
    case POLICY_SOURCEDOMAIN:
	rc = pt_sourcedomain(state, str, len);
	break;
    case POLICY_HELONAME:
	rc = pt_heloname(state, str, len);
	break;
    case POLICY_MAILFROM:
	rc = pt_mailfrom(state, str, len);
	break;
    case POLICY_RCPTTO:
	rc = pt_rcptto(state, str, len);
	break;
    case POLICY_RCPTPOSTMASTER:
	rc = pt_rcptpostmaster(state, str, len);
	break;
    case POLICY_DATA:
    case POLICY_DATAOK:
	/* rc = call_rate_counter(state, 1, what, NULL); */
	rc = call_rate_counter(state, len, POLICY_RCPTTO, NULL);
	break;
    default:
	abort();		/* Code error! Bad policy !	*/
	return 9999;		/* To silence most compilers..	*/
    }
    if (debug) fflush(stdout);
    return rc;
}

char *
policymsg(state)
     struct policystate *state;
{
    return state->message;
}

#ifdef HAVE_SPF_ALT_SPF_H
char *
policyspfhdr(state)
     struct policystate *state;
{
    return state->spf_received_hdr;
}
#endif

long
policyinsizelimit(state)
     struct policystate *state;
{
    return state->maxinsize;
}

long
policysameiplimit(state)
     struct policystate *state;
{
    return state->maxsameiplimit;
}
