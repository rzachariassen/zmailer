/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#ifndef	Z_SIFT_H
#define	Z_SIFT_H
#include "listutils.h"
#include "token.h"
#include "tregexp.h"
#include "regex.h"

struct vaccess {	/* in a list of this structure */
	struct vaccess	*next;
	conscell	*l;		/* points at variable name in :env */
};
extern struct vaccess * v_accessed;

typedef struct regexp {
	regex_t		re;
	const char	*pattern;
	const char	**match;
} regexp;

struct si_retab {
	struct si_retab	*next;
	regexp		*rep;
	tregexp		*trep;
	const char	**match;
	token822	*startp[NSUBEXP];
	token822	*endp[NSUBEXP];
};

struct siftinfo {
	int		kind;		/* 0: StringSift, !0: TokenSift */
	token822	*tlist;		/* token list for tsift expression */
	const char	*str;		/* string for sift expression */
	struct vaccess	*accessed;	/* variables dependencies of expr. */
	int		label;		/* label to go to when reevaluating */
	regexp		*program;	/* compiled regular expression stack */
	tregexp		*tprogram;	/* compiled regular texpression stack*/
	struct si_retab	*subexps;	/* linked list of subexpressions */
};

#endif	/* Z_SIFT_H */
