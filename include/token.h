/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#ifndef	Z_TOKEN_H
#define	Z_TOKEN_H

typedef enum {
	Atom, Comment, DomainLiteral, Error, Fold,
	Line, String, Space, Special, Word, Empty
} TokenType;

/* #define token822 struct _token822 */

typedef struct _token822 {
	const char	*t_pname;		/* printable representation */
	u_long		 t_len;			/* length (0 if malloc'ed) */
	TokenType	 t_type;		/* information on token type */
	struct _token822 *t_next;
} token822;

#endif	/* Z_TOKEN_H */
