/* Various prototypes for ROUTER of Zmailer */

#ifndef	__
# ifdef __STDC__
#  define __(x) x
# else
#  define __(x) ()
#  define const
#  define volatile
# endif
#endif

#include "libz.h"
#include "libsh.h"
#include "libc.h"

#ifdef  USE_SETUIDX	/* IBM AIXism */
# include <sys/id.h>
# ifdef USE_SETREUID
#  define  setreuid(x,y) setuidx(ID_REAL|ID_EFFECTIVE, y)
# else /* !USE_SETREUID */
#  define  setuid(y)     setuidx(ID_REAL|ID_EFFECTIVE, y)
# endif
#endif

/* various libraries, standard libc included.. */

extern const char * const gs_name;
extern const char * const monthname[];
extern char	*prio_list[];
#ifndef HAVE_STRERROR /* System has it, and propably has prototype too..
			 IRIX 6.2 */
extern char	*strerror __((const int errno));
#endif
extern int	D_hdr_rewrite;
extern int	D_router;
extern int	wanttabs;
extern void                init_header __((void));
extern struct headerinfo * find_header __((struct sptree *, const char *));
extern struct headerinfo envelope_hdrs[];
extern struct headerinfo mandatory_hdrs[];
#if	!defined(tolower) && !defined(sgi) /* XX: should use string.h or some such .. */
extern int	tolower __((const int));
#endif

/* File: conf.c */
extern int	 files_gid;
extern char	*cf_suffix;
extern const char *default_trusted[];
extern char	*err_prio_list[];
extern char	*files_group;
extern char	*logdir;
extern char	*prio_list[];
extern char	*trusted_group;
extern int	 filepriv_mask_reg;
extern int	 filepriv_mask_dir;
extern int	 maxReceived;
extern int	 real_stability;
extern int	 stability;
extern int	 wanttabs;
extern u_int	 sweepintvl;
extern struct sptree	*spt_databases, *spt_files, *spt_modcheck,
			*spt_goodguys, *spt_uidmap, *spt_loginmap,
			*spt_fullnamemap, *spt_incoredbs, *spt_headers,
			*spt_eheaders, *spt_builtins, *spt_funclist;
extern struct sptree_init splaytrees[];

/* File: dateparse.c */
extern long	dateParse __((struct tm *localtmptr, token822 *t));

/* File: db.c */
extern int	run_relation __((int argc, const char *argv[]));
extern struct sptree *icdbspltree __((const char *name));
extern int	run_db __((int argc, const char *argv[]));
extern conscell	  *db    __((const char *dbname, const char *key));
extern const char *dbfile __((const char *dbname));
extern void	   dbfree __((void));
extern const char *dbtype __((const char *dbname));

/* File: functions.c */
extern int	funclevel;

extern int	D_sequencer;
extern int	D_hdr_rewrite;
extern int	D_router;
extern int	D_functions;
extern int	D_compare;
extern int	D_matched;
extern int	D_assign;
extern int	D_final;
extern int	D_db;
extern int	D_alias;
extern int	D_bind;
extern int	D_resolv;
extern int	D_alloc;
extern int	D_regnarrate;

extern int run_trace __((int argc, const char *argv[]));
extern char *erraddrlog;
extern RETSIGTYPE sig_hup __((int));
extern int	run_daemon __((int argc, const char *argv[]));
extern int	gensym;
extern void	optsave __((int type, struct envelope *e));

/* File: rfc822.c */
extern char	*errors_to;

extern int	run_rfc822 __((int argc, const char *argv[]));
extern int	makeLetter __((struct envelope *e, int octothrp));
extern void	dumpInfo __((struct envelope *e));
extern void	dumpHeaders __((struct header *h));
extern void	dumpHeader __((struct header *h));
extern int	isSenderAddr;
extern int	isRecpntAddr;
extern void	squirrel __((struct envelope *e, const char *keyword, const char *text));
extern struct header	*erraddress __((struct envelope *e));
extern void	defer __((struct envelope *e, const char *why));
extern struct header	*mkSender __((struct envelope *e, const char *name, int flag));
extern struct header	*mkTrace __((struct envelope *e, struct header *rcvdhdr));
extern conscell	*pickaddress __((conscell *l));
extern int	thesender __((struct envelope *e, struct address *a));
extern conscell	*makequad __((void));
extern int	iserrmessage __((void));
extern int	sequencer __((struct envelope *e, const char *file));

/* File: rfc822hdrs.c */
extern union misc	 hdr_scanparse __((struct envelope *e, struct header *h, int commentflag, int no_line_crossing));
extern struct header	*makeHeader __((struct sptree *sb, const char *s, int len));
extern struct headerinfo *senderDesc __((void));
extern void   set_pname __((struct envelope *e, struct header *h, const char *s));
extern struct header	*copySender __((struct envelope *e));
extern struct header	*copyRecipient __((struct header *h));
extern struct header	*mkMessageId __((struct envelope *e, time_t unixtime));
extern struct header	*mkToHeader  __((struct envelope *e, const char *buf));
extern struct header	*mkDate __((int isresent, time_t unixtime));
extern void	hdr_print __((struct header *h, FILE *fp));
extern int	hdr_nilp __((struct header *h));
extern void	pureAddress __((FILE *fp, struct addr *pp));
extern int	pureAddressBuf __((char *buf, int len, struct addr *pp));
extern int	printAddress __((FILE *fp, struct addr *pp, int col));
extern int	printLAddress __((FILE *fp, struct addr *pp, int col, int foldcol, int nofold));
extern char    *saveAddress __((struct addr *pp));
extern void	errprint __((FILE *fp, struct addr *pp, int hdrlen));
extern HeaderStamp hdr_type __((struct header *h));
extern struct header	*hdr_warning __((struct header *h));
extern void	hdr_errprint __((struct envelope *e, struct header *h, FILE *fp, const char *msg));

/* File: rfc822walk.c */
extern struct address	*revaddress __((struct address *ap));
extern union misc	 parse822 __((HeaderSemantics entry, token822 **tlistp, struct tm *ltm, FILE *tfp));


/* File: router.c */
extern int deferuid;
extern const char *progname;
extern const char *mailshare;
extern const char *myhostname;
extern time_t now;
extern memtypes stickymem;
extern int   mustexit;
extern int   canexit;
extern int   deferit;
extern int   router_id;
extern int   savefile;
extern int   do_hdr_warning;

/* File: rtsyslog.c */
extern void rtsyslog __(( time_t msgmtime, long msgino, const char *from, const char *smtprelay, int size, int nrcpts, const char *msgid ));

extern int	main __((int argc, const char *argv[]));
extern int	login_to_uid __((const char *name));
extern const char *uidpwnam __((int uid));
extern int	isgoodguy __((int uid));
extern void	logmessage __((struct envelope *e));

/* File: shliase.c */
extern int	l_apply __((const char *fname, conscell *l));
extern int	s_apply __((int argc, const char *argv[]));
extern int	n_apply __((char **cpp, int argc, const char *argv[]));
extern struct header *hdr_rewrite __((const char *name, struct header *h));
extern void	setenvinfo __((struct envelope *e));
extern char     *build_gensym __((int uid, const char *type, const char *DSNstr, const char *errorsto, const char *sender));
extern conscell *router __((struct address *a, int uid, const char *type));
extern conscell *crossbar __((conscell *from, conscell *to));
extern char *newattribute_2 __((const char *, const char *, const char *));

extern int nobody;

extern void prversion __((const char *));
extern void setfreefd __((void));
