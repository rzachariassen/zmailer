#ifndef IDENTUSER_H
#define IDENTUSER_H

#ifndef __
# ifdef __STDC__
#  define __(args) args
# else
#  define __(args) ()
# endif
#endif

extern unsigned int ident_tcpport;
extern volatile const char *ident_tcpuser9 __((const int af, const int alen, const void *inlocal, const void *inremote, const int local, const int remote, const int timeout, char *buf, const int buflen));

#if 0
extern int ident_fd2 __((int fd, struct in_addr *inlocal, struct in_addr *inremote, unsigned short *local, unsigned short *remote));
extern int ident_tcpsock __((struct in_addr *inlocal, struct in_addr *inremote));
extern char *ident_sockuser2 __((int s, u_short local, u_short remote, char *buf, int buflen));
extern char *ident_tcpuser4 __((/* struct in_addr *inlocal, struct in_addr *inremote, unsigned short local, unsigned short remote, int timeout, char *buf, int buflen */));
extern char *ident_xline();
extern int ident_fd __((int fd, struct in_addr *in, unsigned short *local, unsigned short *remote));
/* extern char *ident_tcpuser(); */
extern char *ident_tcpuser2 __((/*struct in_addr *inlocal, struct in_addr *inremote, unsigned short local, unsigned short remote*/));
extern char *ident_tcpuser3 __((/*struct in_addr *inlocal, struct in_addr *inremote, unsigned short local, unsigned short remote, int timeout*/));
extern char *ident_sockuser __((/*int s, unsigned short local, unsigned short remote*/));
#endif
#endif
