/*
 *
 *  User mailbox filtering by SIEVE mechanisms
 *
 */


struct sieve {
	int			 state; /* 0: END */
	int			 uid;	 /* input */
	const struct passwd	*pw;	 /* input */
	const char		*username;  /* input */
	int			command;
	struct ctldesc		*dp;
	struct rcpt		*rp;
	int	pipeuid;
	char	pipecmdbuf[2048];
	void	*opaqueblock;
	int	keep_or_discard; /* <0: discard, ==0: not set, >0: keep */
};


extern int  sieve_start   __((struct sieve *svp));
extern void sieve_iterate __((struct sieve *svp));
extern void sieve_end     __((struct sieve *svp));
extern int  sieve_command __((struct sieve *svp));

#define SIEVE_NOOP      0
#define SIEVE_USERSTORE 1
#define SIEVE_RUNPIPE	2
#define SIEVE_DISCARD   3
