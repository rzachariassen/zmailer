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


/*
 * readsleepycfg
 */

void readsleepycfg(cfg)
     ZSleepyPrivate* cfg;
{
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

#if   defined(HAVE_DB3) || defined(HAVE_DB4)

	/* FIXME: read the db (environment) config file! */

	prv->envhome  = NULL;
	prv->envflags = 0;
#endif

	return prv;
}

void zsleepyprivatefree(prv)
     ZSleepyPrivate *prv;
{
#if   defined(HAVE_DB3) || defined(HAVE_DB4)
	if (prv->env)
	  prv->env->close(prv->env, 0);
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

#if   defined(HAVE_DB3) || defined(HAVE_DB4)

	if (prv->envhome) {
	    err = db_env_create(&prv->env, 0);
	    if (err) return err; /* Uhh.. */

	    err = prv->env->open(prv->env, prv->envhome, prv->envflags, prv->envmode);
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
