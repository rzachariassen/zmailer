/*
 *  ZMailer smtpserver, policy tests;
 *  Added for ZMailer 2.99.44 by Matti Aarnio on 16-Dec-1996;
 *  part of ZMailer.
 *
 *  by Matti Aarnio <mea@nic.funet.fi> 1996-1999
 */

/* Pre-included before including this:
   - all type-defining files
   - *DB* headers
 */

#include "policy.h"

struct policystate {		/* Part of SmtpState structure */
    /* States carried from one invocation to another */
    int always_reject;
    int always_freeze;
    int always_accept;
    int full_trust;
    int trust_recipients;
    int sender_reject;
    int sender_freeze;
    int relaycustnet;
    int rcpt_nocheck;
    int sender_norelay;
    int content_filter;
    char *authuser;

    /* This variable contains bitmapped flags of attributes to be checked. */
    /* For example: P_A_REJECTSOURCE ( == 3)
       Corresponding flag is 3rd bit (1 << 3) = 8.
       Flag P_A_ALIAS ( == 1) is ignored.            */
    int request;
    int origrequest;
    /* Attribute values are stored here. */
    char * values  [P_A_LastAttr+1];
    /* The message just before this attribute */
    char * messages[P_A_LastAttr+1];

    /* The lattest result message (line) */
    char *message;
    char *rblmsg;
    long maxinsize;
    long maxoutsize;
    int  islocaldomain;
#ifdef HAVE_WHOSON_H
    int whoson_result;
#endif
};


#ifndef __Usockaddr__  /* Match the same one in  smtpserver.h */
typedef union {
    struct sockaddr_in v4;
#ifdef INET6
    struct sockaddr_in6 v6;
#endif
} Usockaddr;
#define __Usockaddr__
#endif

#ifdef _POLICYTEST_INTERNAL_

typedef enum {
    _dbt_none, _dbt_btree, _dbt_bhash, _dbt_ndbm, _dbt_gdbm
} dbtypes;


struct policytest {
    char *dbtype;
    char *dbpath;
    dbtypes dbt;
    union {
#ifdef HAVE_NDBM
	DBM *_ndbm;
#endif
#ifdef HAVE_GDBM
	GDBM_FILE _gdbm;
#endif
#if defined(HAVE_DB1) || defined(HAVE_DB2) || defined(HAVE_DB3)
	DB *_db;
#endif
    } db_;
#define btree db_._db
#define bhash db_._db
#define gdbm  db_._gdbm
#define ndbm  db_._ndbm
};

#else				/* This is the external interface -- doesn't tell a thing ;-) */

struct policytest {
    void *dummy;
};

#endif

typedef enum {
    POLICY_HELONAME,
    POLICY_SOURCEADDR,
    POLICY_SOURCEDOMAIN,
    POLICY_MAILFROM,
    POLICY_RCPTTO,
    POLICY_RCPTPOSTMASTER
} PolicyTest;

/* Test return values:
   <0 : Always reject
   =0 : Accept
   >0 : Accept into freeze area...
 */

extern void policydefine __((struct policytest ** relp, const char *dbtype, const char *dbpath));
extern int policyinit __((struct policytest ** relp, struct policystate * ps, int whoson_result));
extern int policytest __((struct policytest * rel, struct policystate * ps, PolicyTest how, const char *str, const int len, const char *authuser));
extern int policytestaddr __((struct policytest * rel, struct policystate * ps, PolicyTest how, Usockaddr * raddr));
extern char *policymsg __((struct policytest *rel, struct policystate *ps));
extern long  policyinsizelimit __((struct policytest *rel, struct policystate *ps));

extern struct policytest *policydb;

/* contentpolicy.c */
extern int contentpolicy __((struct policytest *rel, struct policystate *ps, const char *fname));

extern int mx_client_verify  __((int, const char *, int));
extern int sender_dns_verify __((int, const char *, int));
extern int client_dns_verify __((int, const char *, int));
extern int rbl_dns_test __((const int, const u_char *, char *, char **));
