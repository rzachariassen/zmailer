/*  ANSI-C prototypes for Zmailer  libc.a -library */

#ifndef __
# ifdef __STDC__
#  define __(x) x
# else
#  define __(x) ()
# endif
#endif

/* fullname.c */
extern char *fullname __((const char *s, char buf[], int buflen, char *up));

#ifndef HAVE_STDLIB_H
/* getopt.c */
extern int getopt __((int argc, char * const *argv, const char *optstring));
#endif

/* getdtblsize.c */
extern int getdtablesize __((void));

/* getzenv.c */
extern int   readzenv __((const char *file));
extern char *getzenv  __((const char *variable));

/* mail.c */
extern const char *postoffice;
extern FILE *_mail_fopen  __((char **filenamep));
extern int    mail_link   __((const char *from, char **tonamep));
extern FILE * mail_open   __((const char *type));
extern int    mail_abort  __((FILE *fp));
extern int   _mail_close_ __((FILE *fp, int *, time_t *));
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
extern const char *inet_ntop __((int, const void *, char *, size_t));
extern       int   inet_pton __((int, const char *, void *));
/* Must have included <netdb.h> and possibly <netdb6.h> before this .. */
#ifdef AI_PASSIVE
extern       int   _getaddrinfo_ __((const char *, const char *, const struct addrinfo *, struct addrinfo **, FILE *));
extern       int   getaddrinfo __((const char *, const char *, const struct addrinfo *, struct addrinfo **));
extern       int   getnameinfo __((const struct sockaddr *, size_t, char *, size_t, char *, size_t, int));
extern       void  freeaddrinfo __((struct addrinfo *));
extern       char *gai_strerror __((int));
#endif

extern const char *progname;

/* whathost.c */
extern char *whathost __((const char *file));
