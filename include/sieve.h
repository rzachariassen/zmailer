/*
 *
 *  User mailbox filtering by SIEVE mechanisms
 *
 */


struct sieve {
	int		state; /* 0: END */
	int const		 uid;	 /* input */
	const struct passwd	*pw;	 /* input */
	const char		*username;  /* input */
	int	pipeuid;
	char	pipecmdbuf[2048];
};


extern int  sieve_start   __((struct sieve *svp));
extern void sieve_iterate __((struct sieve *svp));
extern void sieve_end     __((struct sieve *svp));
extern int  sieve_command __((struct sieve *svp));

#define SIEVE_USERSTORE 1
#define SIEVE_RUNPIPE	2
#define SIEVE_DISCARD   3
