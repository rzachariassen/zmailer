/*
 *  Various IP(v4/v6) multicast related functions for ZMailer
 *
 *  Part of ZMailer;  copyright Matti Aarnio <mea@nic.funet.fi> 2003
 *
 */

struct zmc_struct {
	int	pf;
	int	fd;
	int	port;

  /* - ACL ?
     - mc-group ?
     - UDP port number ?
  */
};

typedef struct zmc_struct ZMC;

extern int zmcast_set_loop __((ZMC *zmc, const int onoff));
extern int zmcast_set_ttl  __((ZMC *zmc, const int ttl));
extern int zmcast_set_if   __((ZMC *zmc, const Usockaddr *ifsa));
extern int zmcast_join     __((ZMC *zmc, const Usockaddr *sa, const Usockaddr *ifsa, const int ifindex));

extern ZMC *zmcast_new    __((const int pfamily, const Usockaddr *ifsa, const int port));
extern void zmcast_delete __((ZMC *zmc));
