/* libsh/ -prototypes */

/* libsh/builtin.c */
extern int       sh_builtin __((int argc, const char *argv[]));
extern int       sh_include __((int argc, const char *argv[]));
extern conscell *sh_return  __((conscell *, conscell *, int *));
extern conscell *sh_returns __((conscell *, conscell *, int *));

/* libsh/execute.c */
#ifdef Z_SH_H
extern struct osCmd *globalcaller;
extern int execute __((struct osCmd *, struct osCmd *, int, const char *));
extern int   runio __((struct IOop **ioopp));
#endif
extern int smask;
extern int reapableTop;
extern void  sb_external __((int fd));
extern char *sb_retrieve __((int fd));

/* libsh/expand.c */
extern int        glob_match __((int *pattern, int *eopattern, const char *s));
extern char       globchars[];
extern void       glob_init __((void));
extern int        pathcmp __((const void *ap, const void *bp));
extern int        squish  __((conscell *d, char **bufp, int **ibufp, int doglob));
extern conscell * expand  __((conscell *d, int variant));

/* libsh/interpret.c */
extern int  magic_number;
extern long bin_magic;
#ifdef MAILER
extern int setfreefd __((void));
#endif
#ifdef TOKEN_NARGS /* Must have include "libsh/sh.h" for this */
extern void assign   __((conscell *, conscell *, struct osCmd *));
#endif
#ifdef SPTREE_H
extern int xundefun __((struct spblk *));
#endif
#ifdef TOKEN_NARGS /* Must have include "libsh/sh.h" for this */
extern void functype __((const char *, struct shCmd **, struct sslfuncdef **));
extern struct codedesc *interpret __((const void *, const void *, const void *,
				      struct osCmd *, int *, struct codedesc *));
#endif
extern int lapply __((const char *fname, conscell *l));
extern int  apply __((int argc, const char *argv[]));
extern int funcall __((const char *));

/* libsh/jobcontrol.c */
extern int lastbgpid;
extern void jc_report  __((int));
extern void jc_newproc __((int *pgrpp, int pid, int argc, const char *argv[]));

/* libsh/listutils.c */
extern conscell * s_last     __((conscell *));
extern int        s_equal1   __((conscell *, conscell *));
extern int        s_equal    __((conscell *, conscell *));
extern conscell * s_nth      __((conscell *list, int n));
extern void       s_grind    __((conscell *, FILE *));
extern void       _grind     __((conscell *));
extern conscell * s_catstring __((conscell *));
extern conscell * s_read      __((FILE *));
extern conscell * s_listify   __((int ac, const char *av[]));
extern conscell * s_pushstack __((conscell *, const char *));
extern conscell * s_popstack  __((conscell *));
#ifndef newcell
extern conscell * newcell     __((void));
#endif

/* libsh/mail.c */
extern void mail_check __((void));
extern void mail_flush __((void));
extern void mail_intvl __((void));

/* libsh/optimizer.c */
extern void * optimize __((int, void *, void **));

/* libsh/path.c */
extern char *prepath   __((char *pathspec, const char *name, char *buf,
			   unsigned int buflen));
extern char *path_hash __((const char *));
extern void path_flush __((void));
extern int  execvp __((const char *command, char *const *argv));
extern int  execv  __((const char *command, char *const *argv));

/* libsh/prompt.c */
extern void prompt_print  __((void));
extern void prompt_flush  __((void));
extern void prompt2_print __((void));
extern void prompt2_flush __((void));

/* libsh/sslwalker.c */
extern void	 ShInitIFS __((const char *));
extern void	 ShInit    __((void));
extern void	 ungetbuf  __((char *, int));
extern void	*SslWalker __((const char *, FILE*, void **));

/* libsh/strcspn.c */
/* extern int strcspn __((const char *, const char *)); */

/* libsh/test.c */
extern int sh_test __((int argc, const char *argv[]));

/* libsh/trap.c */
extern int  sprung;
extern int  interrupted;
extern const char * traps[];
extern RETSIGTYPE (*orig_handler[]) __((int));
extern void trapsnap __((void));
extern void trap_handler __((int));
extern int eval __((const char *script, const char *scriptname, const char *savefil, const struct stat *));
#ifdef S_IFMT
extern int loadeval __((int fcfd, const char *path, struct stat *srcstbufp));
extern int  leaux    __((int, const char*, struct stat *));
#endif
extern void trapped  __((void));
extern void trapexit __((int));
extern int  sh_trap  __((int argc, const char *argv[]));

/* libsh/tregexp.c: include "tregexp.h" */

/* libsh/variables.c */
#ifdef MAILER
extern void v_written __((conscell *));
extern void v_touched __((void));
#endif
extern conscell *envarlist;
extern void v_envinit __((void));
extern conscell *v_find __((const char *sname));
#ifdef Z_SH_H
extern conscell *v_expand __((const char *, struct osCmd *, int));
#endif
extern char *ifs;
extern void ifs_flush __((void));
extern void v_sync    __((const char *));
extern void v_set     __((const char *, const char *));
extern void v_setl    __((const char *, conscell *));
extern void v_export  __((const char *name));
extern void v_purge   __((const char *name));

/* libsh/version.c */
extern const char *Version;
extern const char *VersionNumb;
extern const char *CC_user;
extern const char *CC_pwd;

/* libsh/zmsh.c */
extern FILE     * runiofp;
extern conscell * commandline;
extern struct osCmd avcmd;
extern const char * progname;
extern int       zshtoplevel __((const char *));
extern void      zshprofile  __((const char *));
extern void      zshinit     __((int argc, const char *argv[]));
extern void      zshfree     __((void));
extern int       zshinput    __((int, char **, int *, char **, char **));


/* libsh/main.c */
extern conscell **return_valuep;
extern int funclevel;

/* Globals .... */

extern char *getenv __((const char *));
extern char *strerror __((int));
extern char *strsignal __((int));
extern int D_assign;
extern int D_compare;
extern int D_functions;
extern int D_matched;
extern int errno;
extern void *tmalloc __((const size_t n));
#ifdef SPTREE_H
extern void sp_null __((struct sptree *));
#endif
