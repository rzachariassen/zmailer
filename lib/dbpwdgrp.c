/*
 * Module for ZMailer 3.0 by Matti Aarnio <mea@nic.funet.fi>
 *
 *  dbgetpwdgrp.c:  Use our own database for userid/group databases
 *		    Poor-mans NIS approach, where datas are stored
 *		    into a NDBM (or some such) database.
 *
 *  Essentially the datas are stored into keyed database that is
 *  indexed by an access key, and all else is stored as a string.
 *  Key is a NUL TERMINATED STRING (that is, string is: "XXXX\000")
 */

/* This is incomplete ! */

#include "hostenv.h"
#include <pwd.h>
#include <grp.h>

static int dbpwd_init = 0;
static int dbgrp_init = 0;
char *dbpwdnam_filename = NULL;
char *dbpwduid_filename = NULL;
char *dbgrpnam_filename = NULL;

#ifdef HAVE_NDBM
static DBM *db_pwdnam = NULL;
static DBM *db_pwduid = NULL;
static DBM *dn_grpnam = NULL;
#else
#ifdef HAVE_GDBM
static GDBM_FILE db_pwdnam = NULL;
static GDBM_FILE db_pwduid = NULL;
static GDBM_FILE dn_grpnam = NULL;
#else
 #error Need either GDBM, or NDBM...
#endif
#endif

static int password_chop __((struct passwd *pw, char *str));
static int password_chop(pw, str)
	struct passwd *pw;
	char *str;
{
	char *s;
	char *sname, *spwd, *suid, *sgid, *sgecos, *shome, *shell;

	sunam = str;
#define SPLITMAC(v1,v2) v2 = strchr(v1,':'); if (!v2) return -1; *(v2++)=0
	SPLITMAC(sname, spwd);
	SPLITMAC(spwd, suid);
	SPLITMAC(suid, sgid);
	SPLITMAC(sgid, sgecos);
	SPLITMAC(sgecos, shome);
	SPLITMAC(shome, shell);
	pw->pw_name    = sname;
	pw->pw_passwd  = spwd;
	if (sscanf(suid,"%d",&pw->pw_uid) != 1) return -1;
	if (sscanf(sgid,"%d",&pw->pw_gid) != 1) return -1;
	pw->pw_quota   = 0;
	pw->pw_comment = NULL;
	pw->pw_gecos   = sgecos;
	pw->pw_dir     = shome;
	pw->pw_shell   = shell;
	return 0;
}

static void init_dbpwd __((void));
static void init_dbpwd()
{
}

struct passwd *
dbgetpwnam(name)
	char *name;
{
	static struct passwd spw;
	static char *lastval = NULL;
	datum key, val;

	if (!dbpwd_init)
	  init_dbpwd();

	errno = 0;

	if (!db_pwdnam)
	  return getpwnam(name);

	key.dptr  = name;
	key.dsize = strlen(name)+1;

#ifdef HAVE_NDBM
	val = dbm_fetch(db_pwdnam, key);
#else
#ifdef HAVE_GDBM
	val = gdbm_fetch(db_pwdnam, key);
#endif
#endif
	if (val.dptr == NULL) {
	  /* Nothing.. */
	  return NULL;
	}
	if (lastval) free(lastval);
	lastval = emalloc(val.dsize+1);
	strncpy(lastval,val.dptr,val.dsize);
	lastval[val.dsize] = 0;
	if (password_chop(&spw,lastval) != 0)
	  return NULL;
	return &spw;
}

struct passwd *
dbgetpwuid(uid)
	int uid;
{
	static struct passwd spw;
	static char *lastval = NULL;
	datum key, val;
	char intbuf[20];

	if (!dbpwd_init)
	  init_dbpwd();

	if (!db_pwdnam)
	  return getpwuid(uid);

	sprintf(intbuf,"%d",uid);
	key.dptr  = intbuf;
	key.dsize = strlen(intbuf)+1;

#ifdef HAVE_NDBM
	val = dbm_fetch(db_pwdnam, key);
#else
#ifdef HAVE_GDBM
	val = gdbm_fetch(db_pwdnam, key);
#endif
#endif
	if (val.dptr == NULL) {
	  /* Nothing.. */
	  return NULL;
	}
	if (lastval) free(lastval);
	lastval = emalloc(val.dsize+1);
	strncpy(lastval,val.dptr,val.dsize);
	lastval[val.dsize] = 0;
	if (password_chop(&spw,lastval) != 0)
	  return NULL;
	return &spw;
}

