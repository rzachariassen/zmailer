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


/*
 * readsleepycfg
 */

/*
 *
 *  Config file syntax for SleepyCat DB 3.x/4.x:
 *
 *   envhome = /path/to/envhome/directory
 *   envflags = CDB, RO
 *   envmode  = 0644
 *   tempdir  = /path/to/tmp/dir
 *
 *
 */



void readsleepycfg(prv)
     ZSleepyPrivate* prv;
{
	FILE *cfgfp;
	char cfgline[250];

#if   defined(HAVE_DB3) || defined(HAVE_DB4)
	prv->envhome  = NULL;
	prv->envflags = 0;
	prv->tmpdir   = NULL;
#endif
	if (!prv->cfgname) return;

	cfgfp = fopen(prv->cfgname,"r");
	if (!cfgfp) return;

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

	  cmd   = cfgline;
	  param = strtok(cfgline," \t:=");
	  strtok(NULL, " \t\n");

	  if (CISTREQ(cmd,"envhome")) {
#if   defined(HAVE_DB3) || defined(HAVE_DB4)
	    prv->envhome  = strdup(param);
#endif
	    continue;
	  }
	  if (CISTREQ(cmd,"envflags")) {
	    /*   envflags = CDB, RO  */
	    prv->envflags = 0;
	    while (param && *param != 0) {
	      char *p = param;
	      param = strtok(p," \t,");
	      if (CISTREQ(p, "cdb")) {
#if defined(DB_INIT_CDB) && defined(DB_INIT_MPOOL)
		prv->envflags = DB_INIT_CDB|DB_INIT_MPOOL;
#endif
	      }
	      if (CISTREQ(p, "ro")) {
		prv->roflag = 1;
	      }
	    }
	    continue;
	  }
	  if (CISTREQ(cmd,"envmode")) {
#if   defined(HAVE_DB3) || defined(HAVE_DB4)
	    prv->envmode = 0600;
	    sscanf(param,"%o",&prv->envmode);
#endif
	    continue;
	  }
	  if (CISTREQ(cmd,"tmpdir")) {
#if   defined(HAVE_DB3) || defined(HAVE_DB4)
	    prv->tmpdir  = strdup(param);
#endif
	    continue;
	  }
	}

	fclose(cfgfp);
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

	readsleepycfg(cfgname);

	return prv;
}

void zsleepyprivatefree(prv)
     ZSleepyPrivate *prv;
{
#if   defined(HAVE_DB3) || defined(HAVE_DB4)
	if (prv->env)
	  prv->env->close(prv->env, 0);
	if (prv->envhome) free((void*)(prv->envhome));
	if (prv->tmpdir)  free((void*)(prv->tmpdir));
#endif
	free(prv);
}


int zsleepyprivateopen(prv, roflag, mode)
     ZSleepyPrivate *prv;
     int roflag;
     int mode;
{
	int err = 0;
	DB *db = NULL;

	if (prv->roflag && (roflag != O_RDONLY)) {
	  return -1;
	}

#if   defined(HAVE_DB3) || defined(HAVE_DB4)

	if (prv->envhome) {
	    err = db_env_create(&prv->env, 0);
	    if (err) return err; /* Uhh.. */

	    if (prv->tmpdir)
	      err = prv->env->set_tmp_dir(prv->env, prv->tmpdir);

	    if (err) return err; /* Uhh.. */

	    err = prv->env->open(prv->env,
				 prv->envhome,
				 prv->envflags,
				 prv->envmode);

	    if (err) return err; /* Uhh.. */
	}

	err = db_create(&db, prv->env, 0);
	if (err == 0 && db != NULL)
	    err = db->open( db, prv->filename, NULL, prv->dbtype,
			    ((roflag == O_RDONLY) ? DB_RDONLY:DB_CREATE),
			    mode );

#else
#if defined(HAVE_DB2)

	err = db_open( prv->filename, prv->dbtype,
		       ((roflag == O_RDONLY) ? DB_RDONLY:DB_CREATE),
		       0644, NULL, NULL, &db );

#else

	db = dbopen( prv->filename, roflag, 0, prv->dbtype, NULL );
	if (!db)
	    err = errno;

#endif
#endif

	prv->db = db;
	prv->roflag = roflag;

	return err;
}
