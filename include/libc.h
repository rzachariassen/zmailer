/*  ANSI-C prototypes for Zmailer  libc.a -library */

#ifndef __
# ifdef __STDC__
#  define __(x) x
# else
#  define __(x) ()
# endif
#endif

#define ZBUFSIZ 8192

/* fullname.c */
extern char *fullname __((const char *s, char buf[], int buflen, const char *up));

/* getopt.c */
extern int zgetopt __((int argc, char * const *argv, const char *optstring));
extern int zoptopt;
extern int zoptind;
extern int zopterr;
extern const char * zoptarg;

/* getdtblsize.c */
extern int getdtablesize __((void));

/* getzenv.c */
extern int         readzenv __((const char *file));
extern const char *getzenv  __((const char *variable));

/* mail.c */
extern const char *postoffice;
extern FILE *_mail_fopen  __((char **filenamep));
extern int    mail_link   __((const char *from, char **tonamep));
extern FILE * mail_open   __((const char *type));
extern int    mail_abort  __((FILE *fp));
extern int   _mail_close_ __((FILE *fp, long *, time_t *));
extern int    mail_close  __((FILE *fp));
extern int    mail_close_alternate __((FILE *fp, const char *where, const char *suffix));

/* mail_alloc.c */
extern void *mail_alloc   __((unsigned int nbytes));
extern void *mail_realloc __((void *ptr, unsigned int nbytes));
extern void  mail_free    __((void *s));

/* mail_host.c */
extern const char *mail_host __((void));

/* myhostname.c */
extern int getmyhostname __((char *namebuf, int len));

/* setreuid ?? SysV beastie.. */

/* setvbuf.c */
#ifndef HAVE_SETVBUF
extern int setvbuf __((FILE *fp, char *buf, int type, int size));
#endif

/* inet_ntop() & inet_pton() */
#ifndef HAVE_INET_NTOP
extern const char *inet_ntop __((int, const void *, char *, size_t));
#endif
#ifndef HAVE_INET_PTON
extern       int   inet_pton __((int, const char *, void *));
#endif
/* Must have included <netdb.h> and possibly <netdb6.h> before this .. */
#ifdef AI_PASSIVE
#ifdef HAVE__GETADDRINFO_
extern       int   _getaddrinfo_ __((const char *, const char *, const struct addrinfo *, struct addrinfo **, FILE *));
extern       int   getaddrinfo __((const char *, const char *, const struct addrinfo *, struct addrinfo **));
#endif
#ifndef HAVE_SOCKLEN_T
typedef unsigned int socklen_t;
#define HAVE_SOCKLEN_T 1
#endif
#ifndef HAVE_GETNAMEINFO
/* This is NASTY, GLIBC has changed the type after instroducing
   this function, Sol (2.)8 has 'int', of upcoming POSIX standard
   revision I don't know.. */

#ifndef GETNAMEINFOFLAGTYPE
# if defined(__GLIBC__) && defined(__GLIBC_MINOR__)
#  if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 2
	/* I am not sure that it was already 2.2(.0) that had
	   this change, but 2.2.2 has it... */
#   define GETNAMEINFOFLAGTYPE unsigned int
#  else
#   define GETNAMEINFOFLAGTYPE int
#  endif
# else
#  define GETNAMEINFOFLAGTYPE int
# endif
#endif

extern       int   getnameinfo __((const struct sockaddr *, socklen_t, char *, size_t, char *, size_t, GETNAMEINFOFLAGTYPE));
#endif
#ifndef HAVE_GETADDRINFO
extern       void  freeaddrinfo __((struct addrinfo *));
#endif
#ifndef HAVE_GAI_STRERROR
extern       char *gai_strerror __((int));
#endif
#endif /* ifdef AI_PASSIVE */

extern const char *progname;

/* whathost.c */
extern char *whathost __((const char *file));



#ifdef O_NONBLOCK /* POSIXy thing */

#define fd_nonblockingmode(fd)	/* void */	\
do {						\
	int __i, __i2;				\
	__i2 = __i = fcntl(fd, F_GETFL, 0);	\
	if (__i >= 0) {				\
	  /* set up non-blocking I/O */		\
	  __i |= O_NONBLOCK;			\
	  __i = fcntl(fd, F_SETFL, __i);	\
	}					\
} while(0)


#define ifd_nonblockingmode(fd)			\
do {						\
	int __i, __i2;				\
	__i2 = __i = fcntl(fd, F_GETFL, 0);	\
	if (__i >= 0) {				\
	  /* set up non-blocking I/O */		\
	  __i |= O_NONBLOCK;			\
	  __i = fcntl(fd, F_SETFL, __i);	\
	}					\
	__i2;					\
} while(0)

#define fd_blockingmode(fd)			\
do {						\
	int __i, __i2;				\
	__i2 = __i = fcntl(fd, F_GETFL, 0);	\
	if (__i >= 0) {				\
	  /* set up blocking I/O */		\
	  __i &= ~O_NONBLOCK;			\
	  __i = fcntl(fd, F_SETFL, __i);	\
	}					\
} while(0)

#define ifd_blockingmode(fd)			\
do {						\
	int __i, __i2;				\
	__i2 = __i = fcntl(fd, F_GETFL, 0);	\
	if (__i >= 0) {				\
	  /* set up blocking I/O */		\
	  __i &= ~O_NONBLOCK;			\
	  __i = fcntl(fd, F_SETFL, __i);	\
	}					\
	__i2;					\
} while(0)

#else
#ifdef	FNONBLOCK

#define fd_nonblockingmode(fd)			\
do {						\
	int __i, __i2;				\
	__i2 = __i = fcntl(fd, F_GETFL, 0);	\
	if (__i >= 0) {				\
	  /* set up non-blocking I/O */		\
	  __i |= FNONBLOCK;			\
	  __i = fcntl(fd, F_SETFL, __i);	\
	}					\
	__i2;					\
} while(0)

#define fd_blockingmode(fd)			\
do {						\
	int __i, __i2;				\
	__i2 = __i = fcntl(fd, F_GETFL, 0);	\
	if (__i >= 0) {				\
	  /* set up blocking I/O */		\
	  __i &= ~FNONBLOCK;			\
	  __i = fcntl(fd, F_SETFL, __i);	\
	}					\
	__i2;					\
} while(0)

#else

#define fd_nonblockingmode(fd)			\
do {						\
	int __i, __i2;				\
	__i2 = __i = fcntl(fd, F_GETFL, 0);	\
	if (__i >= 0) {				\
	  /* set up non-blocking I/O */		\
	  __i |= FNDELAY;			\
	  __i = fcntl(fd, F_SETFL, __i);	\
	}					\
	__i2;					\
} while(0)

#define fd_blockingmode(fd)			\
do {						\
	int __i, __i2;				\
	__i2 = __i = fcntl(fd, F_GETFL, 0);	\
	if (__i >= 0) {				\
	  /* set up blocking I/O */		\
	  __i &= ~FNDELAY;			\
	  __i = fcntl(fd, F_SETFL, __i);	\
	}					\
	__i2;					\
} while(0)
#endif
#endif

#define fd_restoremode(fd,mode) fcntl(fd, F_SETFL, mode)
