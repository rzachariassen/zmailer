#ifndef _Z_DNSGETRR_H_
#define _Z_DNSGETRR_H_ 1

#ifndef MAXALIASES
#define	MAXALIASES	35
#define	MAXADDRS	35
#endif

struct dnsresult {
	struct hostent host;
	char           hostbuf[8*1024];
	char	      *host_aliases[MAXALIASES];
	char	      *h_addr_ptrs[MAXADDRS +1];
	u_char	       host_addr[16];
	int	       ttl;
};

/* dnsgetrr.c */
extern int	getrr     __((char *, int *, int, int, int, FILE *));
extern int	getrrtype __((char *, int *, int, int, int, FILE *));
extern struct hostent *gethostbyname2_rz __((const char *, int, struct dnsresult *));
extern struct hostent *gethostbyaddr_rz __((const char *, int, int, struct dnsresult *));

#endif /* _Z_DNSGETRR_H_ */

