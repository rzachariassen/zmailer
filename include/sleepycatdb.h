/*
 * Common routines for SleepyCat DB interfacing in ZMailer
 *
 * by Matti Aarnio <mea@nic.funet.fi> 2002
 *
 */

#if defined(HAVE_DB_H)     || defined(HAVE_DB1_DB_H) || \
    defined(HAVE_DB2_DB_H) || defined(HAVE_DB3_DB_H) || \
    defined(HAVE_DB4_DB_H)



#if defined(HAVE_DB_185_H) && !defined(HAVE_DB_OPEN2) && \
    !defined(HAVE_DB_CREATE)
# include <db_185.h>
#else
#if defined(HAVE_DB4_DB_H) && defined(HAVE_DB4)
# include <db4/db.h>
#else
#if defined(HAVE_DB3_DB_H) && defined(HAVE_DB3)
# include <db3/db.h>
#else
#if defined(HAVE_DB2_DB_H) && defined(HAVE_DB2)
# include <db2/db.h>
#else
#if defined(HAVE_DB_H)
# include <db.h>
#else
#if defined(HAVE_DB1_DB_H)
# include <db1/db.h>
#endif
#endif
#endif
#endif
#endif
#endif


#ifdef HAVE_DB_CLOSE2
# define SLEEPYCATDBCLOSE(db) (db->close)(db,0);
#else
# define SLEEPYCATDBCLOSE(db) (db->close)(db);
#endif

#if defined(HAVE_DB1) || defined(HAVE_DB2) || defined(HAVE_DB3) || \
    defined(HAVE_DB4)
# define HAVE_DB
#endif


typedef struct {
  const char *cfgname;
  const char *filename;

  DBTYPE      dbtype;
  DB         *db;

  time_t      mtime;
  int         roflag;

#if defined(HAVE_DB3) || defined(HAVE_DB4)

  /* This does not exist at DB1, I recall..
     .. and is different at DB2 ... */

  DB_ENV     *env;

  const char *envhome;
  long        envflags;
  int	      envmode;

#endif

} ZSleepyPrivate;



extern ZSleepyPrivate *zsleepyprivateinit __((const char *filename, const char *cfgname, DBTYPE dbtype));
extern void zsleepyprivatefree __((ZSleepyPrivate *prv));
extern int zsleepyprivateopen __((ZSleepyPrivate *prv, int roflag, int mode));


#endif /* no sleepycat in any form */
