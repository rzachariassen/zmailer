/*
 * int readsleepycfg(char *cfgname, SleepyCfg* cfg)
 *
 * Common routines for SleepyCat DB interfacing in ZMailer
 *
 * by Matti Aarnio <mea@nic.funet.fi> 2002
 *
 */

#include "hostenv.h"
#include <sys/types.h>
#if (defined(__svr4__) || defined(__SVR4)) && defined(__sun)
# define BSD_COMP /* Damn Solaris, and its tricks... */
#endif
#include <sys/ioctl.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "sleepycatdb.h"

#include "zmalloc.h"
#include "libz.h"


ZSleepyEnvSet *ZSleepyEnvSetRoot = NULL;


/*
 * readsleepycfg
 */

/*
 *
 *  Config file syntax for SleepyCat DB 3.x/4.x:
 *
 *   envhome = /path/to/envhome/directory
 *   envflags = CDB, CREATE, RO
 *   envmode  = 0644
 *   tempdir  = /path/to/tmp/dir
 *
 *
 */



static int readsleepycfg(prv)
     ZSleepyPrivate* prv;
{
	FILE *cfgfp;
	char cfgline[250];
	ZSleepyEnvSet ZSE;
	int zseset = 0;

	memset(&ZSE, 0, sizeof(ZSE));

	if (!prv->cfgname) return -1;

	cfgfp = fopen(prv->cfgname,"r");
	if (!cfgfp) return -1;

	while (cfgfp && !ferror(cfgfp) && !feof(cfgfp)) {
	  char *cmd, *param, c;
	  char *s = fgets(cfgline, sizeof(cfgline)-1, cfgfp);
	  cfgline[sizeof(cfgline)-1] = 0;
	  if (!s) break;
	  /* Acceptable lines begin with letters */
	  c = *cfgline;
	  if (!(('a' <= c && c <= 'z')||('A' <= c && c <= 'Z'))) continue;
	  s = strchr(cfgline, '\n');
	  if (s) *s = 0; /* Zap ending LF */

	  cmd = cfgline;
	  s   = cfgline;
	  while (*s && *s != ' ' && *s != '\t' && *s != ':' && *s != '=') ++s;
	  if (*s) *s++ = 0;
	  while (*s && (*s == ' ' || *s == '\t' || *s == ':' || *s == '='))++s;
	  param = s;

	  if (CISTREQ(cmd,"envhome")) {
#if   defined(HAVE_DB3) || defined(HAVE_DB4)
	    if (ZSE.envhome) free((void*)ZSE.envhome);
	    ZSE.envhome  = strdup(param);
	    zseset = 1;
#endif
	    continue;
	  }
	  if (CISTREQ(cmd,"envflags")) {
	    /*   envflags = CDB, RO  */
	    long envflags2 = 0;
	    ZSE.envflags = 0;
	    while (param && *param != 0) {
	      char *p = param;

	      while (*p && !strchr(" \t,",*p)) ++p;
	      if (*p) *p++ = 0;
	      while (*p && strchr(" \t,",*p)) ++p;

	      if (CISTREQ(param, "cdb")) {
#if defined(DB_INIT_CDB) && defined(DB_INIT_MPOOL)
		ZSE.envflags = DB_INIT_CDB|DB_INIT_MPOOL;
		zseset = 1;
#endif
	      }
	      if (CISTREQ(param, "create")) {
#if defined(DB_INIT_CDB) && defined(DB_INIT_MPOOL)
		envflags2 |= DB_CREATE;
		zseset = 1;
#endif
	      }
	      if (CISTREQ(param, "ro")) {
		prv->roflag = 1;
	      }
	      param = p;

	    }
	    ZSE.envflags |= envflags2;
	    continue;
	  }
	  if (CISTREQ(cmd,"envmode")) {
#if   defined(HAVE_DB3) || defined(HAVE_DB4)
	    ZSE.envmode = 0600;
	    sscanf(param,"%o",&ZSE.envmode);
	    zseset = 1;
#endif
	    continue;
	  }
	  if (CISTREQ(cmd,"tmpdir")) {
#if   defined(HAVE_DB3) || defined(HAVE_DB4)
	    ZSE.tmpdir  = strdup(param);
	    if (ZSE.tmpdir) free((void*)ZSE.tmpdir);
	    zseset = 1;
#endif
	    continue;
	  }
	}

	fclose(cfgfp);


	if (zseset && ZSE.envhome) {

	  /* Ok, something usefull set, lets see if there exists a ZSE
	     set with alike values..  Well, alike ENVHOME value. */

	  ZSleepyEnvSet *zesp = ZSleepyEnvSetRoot;
	  ZSleepyEnvSet *zesp0 = zesp;

	  if (zesp) {
	    do {
	      if (strcmp(zesp->envhome,ZSE.envhome) == 0) {
		/* Alike value ! */
		prv->ZSE = zesp;
		zesp->refcount += 1;
		if (ZSE.envhome) free((void*)ZSE.envhome);
		if (ZSE.tmpdir)  free((void*)ZSE.tmpdir);
		return 0;
	      }
	      zesp = zesp->next;
	    } while (zesp != zesp0);
	  }
	  /* No environment found .. */
	  /* .. so we add it into the chain. */
	  zesp = malloc(sizeof(*zesp));
	  if (!zesp) return -1;
	  if (!ZSleepyEnvSetRoot) {
	    /* We are the new root! */
	    ZSleepyEnvSetRoot = zesp;
	    ZSE.next = zesp;
	    ZSE.prev = zesp;
	  } else {
	    /* We join the chain */
	    ZSE.next = zesp0->next;
	    ZSE.prev = zesp0;
	    zesp0->next    = zesp;
	    ZSE.next->prev = zesp;
	  }
	  *zesp = ZSE; /* Store the ready bundle.. */
	  prv->ZSE = zesp;
	  zesp->refcount = 1;

	}
	return 0;
}



ZSleepyPrivate *zsleepyprivateinit(filename, cfgname, dbtype)
     const char *filename;
     const char *cfgname;
     DBTYPE dbtype;
{
	ZSleepyPrivate *prv = malloc(sizeof(*prv));
	if (!prv) return NULL; /* GAWD!! */

	memset(prv, 0, sizeof(*prv));

	prv->dbtype   = dbtype;
	prv->filename = filename;
	prv->cfgname  = cfgname;

	readsleepycfg(prv);

	return prv;
}

void zsleepyprivatefree(prv)
     ZSleepyPrivate *prv;
{
	ZSleepyEnvSet *ZSE = prv->ZSE;
	if (ZSE && ZSE->refcount == 1) {
#if   defined(HAVE_DB3) || defined(HAVE_DB4)
	  ZSE->env->close(prv->ZSE->env, 0);
#endif
	  if (ZSE->envhome) free((void*)(ZSE->envhome));
	  if (ZSE->tmpdir)  free((void*)(ZSE->tmpdir));
	  /* Unlink from the chains */

	  if (ZSE->next != ZSE->prev) {
	    ZSE->next->prev = ZSE->next;
	    ZSE->prev->next = ZSE->prev;
	    /* Wether it was us, or not.. */
	    ZSleepyEnvSetRoot = ZSE->prev;
	  } else {
	    /* prev == next -- us alone.. */
	    ZSleepyEnvSetRoot = NULL;
	  }
	  free(ZSE);

	} else if (ZSE && ZSE->refcount > 1)
	  ZSE->refcount -= 1;

	free(prv);
}


int zsleepyprivateopen(prv, roflag, mode, comment)
     ZSleepyPrivate *prv;
     int roflag;
     int mode;
     char **comment;
{
	int err = 0;
	DB *db = NULL;

	if (prv->roflag && (roflag != O_RDONLY)) {
	  return -1;
	}

#if   defined(HAVE_DB3) || defined(HAVE_DB4)

	if (prv->ZSE && prv->ZSE->envhome && !prv->ZSE->env) {
	    if (comment) *comment = " environment of";

	    err = db_env_create(&prv->ZSE->env, 0);
	    if (err) return err; /* Uhh.. */

	    if (prv->ZSE->tmpdir)
	      err = prv->ZSE->env->set_tmp_dir(prv->ZSE->env,
					       prv->ZSE->tmpdir);

	    if (err) return err; /* Uhh.. */

	    err = prv->ZSE->env->open(prv->ZSE->env,
				 prv->ZSE->envhome,
				 prv->ZSE->envflags,
				 prv->ZSE->envmode);

	    if (err) return err; /* Uhh.. */
	}

	if (comment) *comment = " db_create()";
	err = db_create(&db, prv->ZSE ? prv->ZSE->env : NULL, 0);
	if (err == 0 && db != NULL) {
	    err = db->open( db, prv->filename, NULL, prv->dbtype,
			    ((roflag == O_RDONLY) ? DB_RDONLY:DB_CREATE),
			    mode );
	    if (comment) *comment = " database";
	}
	if (err != 0 && db != NULL) {
	  db->close(db, 0);
	  db = NULL;
	}
#else
#if defined(HAVE_DB2)

	err = db_open( prv->filename, prv->dbtype,
		       ((roflag == O_RDONLY) ? DB_RDONLY:DB_CREATE),
		       0644, NULL, NULL, &db );
	if (comment) *comment = " batabase";

#else

	db = dbopen( prv->filename, roflag, 0, prv->dbtype, NULL );
	if (!db)
	    err = errno;
	if (comment) *comment = " batabase";

#endif
#endif

	prv->db = db;
	prv->roflag = roflag;

	return err;
}
