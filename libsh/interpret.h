/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#ifndef	_INTERPRETER_H
#define	_INTERPRETER_H
#include "sh.h"

/*
 * Each command has associated with it a triple of lists of I/O operations
 * to be performed before fork(), between fork()/exec(), and after wait().
 * Each I/O operation is described by the following structure and a list of
 * these is executed by the runio() function.  The cmd is simply the S/SL
 * sh parser output token, the ioflags are set based on previous instructions
 * in the S/SL code (sIOsetIn/sIOsetOut/sIOsetInOut).  The two file descriptors
 * are used either by the command (e.g. dup(fd,fd2)) or are set earlier to
 * allow runio() to check that the command returned or set up the expected
 * file descriptor -- this is part of a descriptor-prediction scheme used to
 * keep track of what will happen during the various stages of command
 * execution.  The name can specify a file, fifo, or string buffer in-core.
 */

struct IOop {
	struct IOop	*next;
	const char 	*name;
	OutputTokens	cmd;		/* what does ``name'' mean? */
	short		ioflags;    /* if 0 then close() else open(,ioflags,) */
	short		opflags;	/* if 1, memory is malloc'ed */
	short		fd;		/* relevant file descriptor */
	short		fd2;		/* aux ditto, for dup() */
	struct osCmd	*command;	/* backpointer to the command */
};


/* There are two kinds of builtin functions:
 * - those that take a normal array of arguments (argc,argv) like any main()
 * - those that take a list as their only argument
 *
 * The first kind must return an integer exit code.
 * The second kind must return a list, their exit status is implicitly 0.
 * Furthermore, the second kind may not do any input or output, to make
 * their implementation cheap -- if they want stdin data then the flag field
 * is used to indicate that.
 */

struct shCmd {
	const char	*name;		/* name of function */
	int	  (*sptr) __((int, const char *av[]));	/* ptr to function taking argc,argv */
	conscell *(*lptr) __((conscell *, conscell *)); /* ptr to function taking list */
	conscell *(*rptr) __((conscell *, conscell *, int*)); /* ptr to function taking list and returning data */
	long		flag;		/* SH_* flags */
};

extern struct shCmd builtins[];

#define	SH_STDIN	1		/* this cmd wants data from stdin */
#define	SH_ARGV		2		/* this cmd gets data from arguments */
#define	SH_INTERNAL	3		/* this cmd is handled in interpreter */

#endif	/* _INTERPRETER_H */
