/*	Prototypes of ZMailer Scheduler component routines	*/
/*
 *	Copyright Matti Aarnio <mea@nic.funet.fi> 1995
 */

#ifndef __
# ifdef __STDC__
#  define __(x) x
# else
#  define __(x) ()
# endif
#endif

#if 0
/* *** DEBUGGING STUFF! *** */

static void *__emalloc(size,fil,lin) size_t size; char *fil; int lin; { void *ptr = malloc(size); fprintf(stderr,"%s:%d:mal: siz=%d ptr=0x%p\n",fil,lin,size,ptr); return ptr; }
#define emalloc(size) __emalloc(size,__FILE__,__LINE__)
static void *__erealloc(ptr,size,fil,lin) void *ptr; size_t size; char*fil;int lin; {void *newptr = realloc(ptr,size);fprintf(stderr,"%s:%d:mal: realloc(0x%p,%d)->0x%p\n",fil,lin,ptr,size,newptr);return newptr; }
#define erealloc(ptr,size) __erealloc(ptr,size,__FILE__,__LINE__)
static char *__strsave(s,fil,lin) const char *s;char *fil; int lin; { char *s2 = __emalloc(strlen(s)+1,fil,lin); strcpy(s2,s); return s2;}
#define strsave(s) __strsave(s,__FILE__,__LINE__)
static char *__strnsave(s,len,fil,lin) const char *s; const size_t len; char *fil; int lin; { char *s2 = __emalloc(len+1,fil,lin); strncpy(s2,s,len); s2[len] = 0; return s2;}
#define strnsave(s,n) __strnsave(s,n,__FILE__,__LINE__)
static void __free(ptr,file,line) void *ptr; char*file;int line; { fprintf(stderr,"%s:%d:mal: free(0x%p)\n",file,line,ptr); free(ptr); }
#define free(ptr) __free(ptr,__FILE__,__LINE__)

#endif


#if 0
#ifndef strchr /* IBM AIX is a bit peculiar.. these are macroes! */
extern char *strcpy(), *strncpy(), *strcat();
extern char *strchr(), *strrchr();
#endif
#endif

/* lib/ranny.c */
extern u_int ranny __((u_int m));

/* agenda.c */
extern time_t qipcretry;
extern int doagenda __((void));
extern void turnme __((const char *));

/* conf.c */
extern char *qlogdir;
extern char *qcf_suffix;
extern char *qdefaultdir;
extern char *qoutputfile;
extern const char *replhost;
extern const char *replchannel;
extern int  nobody;
extern int  sweepinterval;

/* msgerror.c */
extern void msgerror __((struct vertex *vp, long offset, const char *message));
extern void reporterrs __((struct ctlfile *cfpi));

/* pipes.c */
extern int  pipes_create         __((int *tochild, int *fromchild));
extern void pipes_close_parent   __((int *tochild, int *fromchild));
extern void pipes_to_child_fds   __((int *tochild, int *fromchild));
extern void pipes_shutdown_child __((int fd)); /* At parent, shutdown channel towards child */

/* qprint.c */
extern void qprint __((int fd));

/* readconfig.c */
extern struct config_entry *rrcf_head;
extern struct config_entry *default_entry;
extern void   defaultconfigentry __((struct config_entry *ce, struct config_entry *defaults));
extern void   vtxprint __((struct vertex *vp));
extern struct config_entry *readconfig __((const char *file));
extern struct config_entry *rereadconfig __((struct config_entry *head, const char *file));

/* resources.c */
extern int  resources_query_nofiles  __((void));
extern void resources_maximize_nofiles __((void));
extern void resources_limit_nofiles __((int nfiles));
extern int  resources_query_pipesize __((int fildes));

/* scheduler.c */
extern int         transportmaxnofiles;
extern const char *progname;
extern const char *rendezvous;
extern const char *pidfile;
extern const char *mailshare;
extern const char *log;
extern int  hungry_childs;
extern int  global_maxkids;
extern int  verbose;
extern int  querysocket;
extern int  do_syslog;
extern struct ctlfile *slurp __((int fd, long ino));
extern void free_cfp_memory __((struct ctlfile *cfp));
extern int  vtxredo __((struct spblk *spl));
extern char *timestring __((void));
extern time_t now;
extern FILE *statuslog;
extern void resync_file __((struct procinfo *proc, const char *filename));
extern int thread_count_recipients __((void));
extern time_t mytime __((time_t *));
extern int dq_insert __((void*, long, const char*, int));
extern int in_dirscanqueue __((void *, long));
extern const char *cfpdirname __((int));

/* threads.c */
extern struct thread *thread_head, *thread_tail;
extern struct threadgroup *create_threadgroup __((struct config_entry *cep, struct web *wc, struct web *wh, int withhost, void (*ce_fillin)__((struct threadgroup *, struct config_entry *)) ));
extern void  delete_threadgroup __((struct threadgroup *thgp));
extern void  thread_linkin __((struct vertex *cp, struct config_entry *cep, int cfgid, void (*ce_fillin)__((struct threadgroup *, struct config_entry *)) ));
extern struct web *web_findcreate __((int flag, const char *s));
extern void        unweb __((int flag, struct web *wp));
extern int   thread_start __((struct thread *thr));
extern int   idle_cleanup __((void));
extern void  pick_next_vertex __((struct procinfo *proc, int ok, int justfree));
extern void  thread_report __((FILE *, int));
extern int   idleprocs;
extern void  web_disentangle __((struct vertex *vp, int ok));
extern void  reschedule __((struct vertex *vp, int factor, int index));
extern void  thread_reschedule __((struct thread *, time_t, int index));

/* transport.c */
extern struct procinfo *cpids;
extern int  numkids;
extern void feed_child      __((struct procinfo *cpidp));
extern int flush_child      __((struct procinfo *cpidp));
extern void idle_child      __((struct procinfo *cpidp));
extern int  start_child     __((struct vertex *vhead, struct web *channel, struct web *host));
extern void shutdown_kids   __(( void ));
extern RETSIGTYPE sig_chld __((int sig));
extern int mux __((time_t timeout));
extern void queryipccheck __((void));
extern void queryipcinit __((void));
#if defined(USE_BINMKDIR) || defined(USE_BINRMDIR)
extern int system __((char*));
#endif

/* update.c */
extern void update __((int, char *));
extern void unctlfile __((struct ctlfile *cfp, int no_unlink));
extern void unvertex __((struct vertex *, int justfree, int ok));
extern void deletemsg __((const char *, struct ctlfile *));
extern char *saytime __((long, char *, int));
extern void expire __((struct vertex *, int));

/* wantconn.c */
extern int wantconn __(( int sock, const char *prgname ));

extern int isalive __(( const char *pidfil, int *pidp, FILE **fpp ));
extern void docat __(( const char *file, int fd ));
extern void printaddrs __(( struct vertex *v ));
extern void checkrouter __(( void ));
extern void checkscheduler __(( void ));
extern void report __(( FILE *fp ));

/* Transport library */
/* extern int lockaddr __((int, char *, long, int, int)); */
