/*
 * Definitions etc. for regexp(3) routines.
 *
 * Caveat:  this is V8 regexp(3) [actually, a reimplementation thereof],
 * not the System V one.
 */
#ifndef	Z_TREGEXP_H
#define	Z_TREGEXP_H
#include "token.h"

#define NSUBEXP  10
typedef struct tregexp {
#if 0
	token822 *startp[NSUBEXP];
	token822 *endp[NSUBEXP];
#else
	token822 **startp;
	token822 **endp;
#endif
	char regstart;		/* Internal use only. */
	char reganch;		/* Internal use only. */
	const char *regmust;	/* Internal use only. */
	int regmlen;		/* Internal use only. */
	const char *pattern;	/* Human version of the program */
	char program[1];	/* Unwarranted chumminess with compiler. */
} tregexp;

   tregexp *tregcomp  __((const char *));
       int  tregexec  __((tregexp *, token822 *));
const char *tregsub   __((tregexp *, int));
      void  tregerror __((const char *, tregexp *));
      void  tregdump  __((tregexp *));

/*
 * The first byte of the regexp internal "program" is actually this magic
 * number; the start node begins in the second byte.
 */
#define	MAGIC	0234
#endif	/* Z_REGEXP_H */
