/* **************************************************************** *
 *	ANSI-C (GCC) prototypes for Zmailer  libz.a -routines	    *
 *  Written by Matti Aarnio <mea@utu.fi> for Zmailer 2.2	    *
 * **************************************************************** */

#ifndef __
# ifdef __STDC__
#  define __(x) x
# else
#  define __(x) ()
# endif
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
extern int cfgets __((char *, int, FILE *));

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
extern univptr_t emalloc  __((size_t len));
extern univptr_t erealloc __((univptr_t buf, size_t len));
#ifdef S_IFMT
extern int efstat __((int fd, struct stat *stbuf));
extern int estat  __((const char *path, struct stat *stbuf));
#endif
extern off_t elseek __((int fd, off_t pos, int action));
extern int elink    __((const char *file1, const char *file2));
extern int eunlink  __((const char *file));
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
extern char *linebuf;
extern void initline      __((long blksize));
extern int  getline       __((FILE *fp));
extern void repos_getline __((FILE *fp, off_t pos));
extern int  linegetrest   __((void));
extern long lineoffset    __((FILE *fp));

/* loginit.c */
extern /* RETSIGTYPE */ int loginit __((int));

/* nobody.c */
extern int getnobody __((void));

/* prversion.c */
extern void prversion __((const char *prgname));

#ifdef USE_ZGETPWNAM
/* pwdgrp.c */
extern struct passwd	*zgetpwnam __((const char *name));
extern struct passwd	*zgetpwuid __((const char *uid));
extern struct group	*zgetgrnam __((const char *name));
#endif

/* ranny.c */
extern u_int ranny __((u_int m));

/* rfc822date.c */
extern char *rfc822tz   __((time_t *, struct tm **ts, int prettyname));
extern char *rfc822date __((time_t *timep));

/* rfc822scan.c */
extern int  hdr_status __((const char *cp, const char *lbuf, int n, int octo));
#ifdef Z_TOKEN_H
extern u_long _hdr_compound __((const char *cp, long n, int cstart, int cend,
				TokenType type, token822 *tp,
				token822 **tlist, token822 **tlistp));
extern const char *_unfold __((const char *start, const char *end, token822 *t));
extern token822 * scan822 __((const char **cpp, size_t n, int c1, int c2,
				  int allowcomments, token822 **tlistp));
#endif

/* selfaddrs.c */
extern void stashmyaddresses  __((const char *host));
#ifdef SOCK_STREAM
extern int  loadifaddresses   __((struct sockaddr ***));
extern int  matchmyaddress    __((struct sockaddr *));
#endif
#ifdef EAI_AGAIN   /* have 'struct addrinfo' */
extern int  matchmyaddresses  __((struct addrinfo *));
#endif

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

/* taspoolid.c */
extern void taspoolid __((char *buf, int len, time_t mtime, const char *fn));

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
extern int  fprintToken __((FILE *fp, token822 *t, int onlylength));
extern int  fprintFold  __((FILE *fp, token822 *t, int col));
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
