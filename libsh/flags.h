/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#ifndef	Z_FLAGS_H
#define	Z_FLAGS_H

#ifndef	NBBY
#define	NBBY	8
#endif	/* NBBY */
#define	BITTEST(B,N)	(B[(N)/NBBY] & (1<<((N)%NBBY)))
#define	BITSET(B,N)	(B[(N)/NBBY] |= (1<<((N)%NBBY)))
#define	BITCLR(B,N)	(B[(N)/NBBY] &= ~(1<<((N)%NBBY)))

extern char shfl[];

#ifdef isset
/* sometimes isset() is defined in <sys/param.h> */
#undef isset
#endif	/* isset */
#define	isset(X)	BITTEST(shfl,((u_char)X))
#define setopt(X,TF)	(TF ? BITSET(shfl,((u_char)X)):BITCLR(shfl,((u_char)X)))

#endif	/* Z_FLAGS_H */
