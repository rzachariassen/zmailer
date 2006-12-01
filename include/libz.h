/* **************************************************************** *
 *	ANSI-C (GCC) prototypes for Zmailer  libz.a -routines	    *
 *  Written by Matti Aarnio <mea@utu.fi> for Zmailer 2.2	    *
 * **************************************************************** */

#define _SYS_STREAM_H /* Block inclusion of Solaris 10 <sys/stream.h> */

#ifndef __
# ifdef __STDC__
#  define __(x) x
# else
#  define __(x) ()
# endif
#endif

#ifndef CISTREQ
#define  CISTREQ(x,y)	 (cistrcmp ((const char*)(x), (const char*)(y)  )==0)
#define  CISTREQN(x,y,n) (cistrncmp((const char*)(x), (const char*)(y),n)==0)
#define  STREQ(x,y)      (strcmp   ((const char*)(x), (const char*)(y)  )==0)
#define  STREQN(x,y,n)   (strncmp  ((const char*)(x), (const char*)(y),n)==0)
#endif

/* allocate.c */
#ifdef MEMTYPES
extern memtypes	 stickymem;
extern int       blockmen __((const memtypes memtype, univptr_t up));
extern univptr_t tmalloc  __((const size_t n));
extern univptr_t smalloc  __((const memtypes memtype, const size_t n));
extern void      memstats __((const memtypes memtype));
extern void      memcontents __((void));
extern void      tfree    __((const memtypes memtype));
extern univptr_t getlevel __((const memtypes memtype));
extern void      setlevel __((const memtypes memtype, const univptr_t s));
#endif
extern char *    strsave  __((const char *s));
extern char *    strnsave __((const char *s, const size_t n));

/* cfgets.c */
#ifdef _SFIO_H
extern int csfgets __((char *, int, Sfio_t *));
#endif

/* cleanenv.c */
extern const char * nukelist[];
extern void         cleanenv __((void));

/* detach.c */
extern void detach __((void));
extern int  countfds __((void));

/* die.c */
extern void die __((int status, const char *message));

/* dottedquad.c */
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef IN_CLASSA
extern char *dottedquad __((struct in_addr *inp));
#endif

/* esyslib.c */
extern int eopen __((const char *s, int f, int m));
extern int eread __((int fd, char *buf, int len));
extern int epipe __((int fdarr[2]));
extern void *emalloc  __((size_t len));
extern void *erealloc __((void *buf, size_t len));
#ifdef S_IFMT
extern int efstat __((int fd, struct stat *stbuf));
extern int estat  __((const char *path, struct stat *stbuf));
#endif
extern off_t elseek __((int fd, off_t pos, int action));
extern int elink    __((const char *file1, const char *file2));
extern int eunlink  __((const char *file, const char *tag));
extern int eclose   __((int fd));
extern int echdir   __((const char *file));
extern int emkdir   __((const char *file, int mode));
extern int ermdir   __((const char *file));
extern int erename  __((const char *from, const char *to));
extern int eqrename __((const char *from, const char *to));

#ifdef	HOST_NOT_FOUND	/* If we have  <netdb.h> included */
/* hostent.c */
extern void hp_init       __((struct hostent *hp));
extern void hp_setalist   __((struct hostent *hp, void **));
extern char **hp_getaddr  __((void));
extern char **hp_nextaddr __((void));
extern void hp_addr_randomize __((struct hostent *hp));
#endif

/* killprev.c */
extern int killprevious   __((int sig, const char *pidfil));
extern int killpidfile    __((const char *pidfil));

/* linebuffer.c */
extern char *zlinebuf;
extern void initzline      __((long blksize));
extern int  zgetline       __((FILE *fp));
extern void repos_zgetline __((FILE *fp, off_t pos));
extern int  zlinegetrest   __((void));
extern long zlineoffset    __((FILE *fp));

/* loginit.c */
extern /* RETSIGTYPE */ int loginit __((int));

/* nobody.c */
extern int getnobody __((void));

/* parseintv.c */
extern unsigned long parse_interval __((const char *str, const char **retp));

/* prversion.c */
extern void prversion __((const char *prgname));

/* pwdgrp.c */
extern struct Zpasswd	*zgetpwnam __((const char *name));
extern struct Zpasswd	*zgetpwuid __((const uid_t uid));
extern struct Zgroup	*zgetgrnam __((const char *name));

/* ranny.c */
extern u_int ranny __((u_int m));

/* rfc822date.c */
extern char *rfc822tz   __((time_t *, struct tm **ts, int prettyname));
extern char *rfc822date __((time_t *timep));

/* rfc822scan.c */
extern int  hdr_status __((const char *cp, const char *lbuf, int n, int octo));
#ifdef Z_TOKEN_H
extern token822 * scan822 __((const char **cpp, size_t n, int c1, int c2,
			      token822 **tlistp));
extern token822 * scan822utext __((const char **cpp, size_t n,
				   token822 **tlistp));
#endif

/* selfaddrs.c */

#ifndef __Usockaddr__
typedef union {
    struct sockaddr     sa;
    struct sockaddr_in  v4;
#ifdef INET6
    struct sockaddr_in6 v6;
#endif
} Usockaddr;
#define __Usockaddr__
#endif


struct sockaddr; /* a "forward" declaration */
struct addrinfo; /* a "forward" declaration */

extern void stashmyaddresses  __((const char *host));
#ifdef SOCK_STREAM

#ifdef TESTMODE
extern int  loadifaddresses   __((Usockaddr ***, void ***));
#else
extern int  loadifaddresses   __((Usockaddr ***));
#endif

extern int  matchmyaddress    __((Usockaddr *));
#endif
#ifdef EAI_AGAIN   /* have 'struct addrinfo' */
extern int  matchmyaddresses  __((struct addrinfo *));
#endif

/* zgetifaddress.c */
extern int zgetifaddress __((int af, const char *ifname, Usockaddr *));

/* zgetbindaddr.c */
extern int zgetbindaddr __((char *ifname, const int af, Usockaddr *));

/* splay.c */
/* .... much ... in  "splay.h" */

/* stringlib.c */
extern int cistrcmp   __((const char *a, const char *b));
extern int cistrncmp  __((const char *a, const char *b, int n));
extern int ci2strncmp __((const char *a, const char *b, int n));

/* strlower.c */
extern char * strlower __((char *));
/* strupper.c */
extern char * strupper __((char *));

/* strmatch.c */
extern int strmatch __((const char *pattern, const char *term));

/* symbol.c */
/* include "splay.h" ! */

/* taspoolid.c */ /* Minimum buffer size: 32 bytes ! */
extern void taspoolid __((char *buf, long inodenum, time_t mtime, long mtimens));

/* token.c */
#ifdef Z_TOKEN_H
extern token822 *makeToken __((const char *s, u_int n));
extern token822 *copyToken __((token822 *t));
extern const char *formatToken __((token822 *t));
extern int  printToken  __((char *buf, char *eob,
			    token822 *t, token822 *tend,
			    int quotespecials));
extern int  printdToken __((char **bufp, int *buflenp,
			    token822 *t, token822 *tend,
			    int quotespecials));
extern int  fprintToken __((FILE *fp, token822 *t, int col));
extern int  fprintFold  __((FILE *fp, token822 *t, int col, int foldcol));
extern void freeTokens __((token822 *t, int memtype));
#ifdef TOKENLEN /* Defined in  "mailer.h", like AddrComponent too.. */
extern const char *formatAddr __((AddrComponent d));
#endif
#endif

/* trusted.c */
extern void	settrusteduser	 __((void));
extern int	runastrusteduser __((void));
extern void	runasrootuser	 __((void));

/* any: version.c */
extern const char *Version;
extern const char *VersionNumb;
extern const char *CC_user;
extern const char *CC_pwd;

/* zshmmibattach.c */
extern int  Z_SHM_MIB_Attach      __((int rw));
extern int  Z_SHM_MIB_is_attached __((void)); /* True if we do have the segment */
extern void Z_SHM_MIB_Detach      __((void)); /* automatic atexit() handling */

extern struct MIB_MtaEntry *MIBMtaEntry; /* public MIB block pointer, either
					    private data before attach call,
					    or possibly shared data after the
					    call... */

/* fdstatfs.c */
extern int fd_statfs __((int fd, long *bavailp, long *busedp, long *iavailp, long *iusedp));

/* isterminal.c */
extern int z_isterminal __((const int fd));

/* pipes.c */
extern int  pipes_create         __((int *tochild, int *fromchild));
extern void pipes_close_parent   __((int *tochild, int *fromchild));
extern void pipes_to_child_fds   __((int *tochild, int *fromchild));
extern void pipes_shutdown_child __((int fd)); /* At parent, shutdown channel towards child */

/* fdpassing.c */
extern int  fdpass_create         __((int *tochild));
extern void fdpass_close_parent   __((int *tochild));
extern void fdpass_to_child_fds   __((int *tochild));
extern void fdpass_shutdown_child __((int fd)); /* At parent, shutdown channel towards child */
extern int  fdpass_receivefd      __((int fd, int *receivedfdp));
extern int  fdpass_sendfd         __((int fd, int passfd));

/* resources.c */
extern int  resources_query_nofiles  __((void));
extern void resources_maximize_nofiles __((void));
extern void resources_limit_nofiles __((int nfiles));
extern int  resources_query_pipesize __((int fildes));

/* crc32.c */
extern unsigned long crc32  __((const void *));
extern unsigned long crc32n __((const void *, int));

/* pjwhash32.c */
extern unsigned long pjwhash32 __((const char *));
extern unsigned long pjwhash32n __((const char *, int));

