/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#ifndef	Z_SH_H
#define	Z_SH_H
#include "sh.sst.h"
#include <sys/types.h>
#ifdef	MAILER
#include "sift.h"
#endif	/* MAILER */
#include "listutils.h"
#include "interpret.h"

struct smallSymbol {
	InputTokens	name;		/* token for 1 char of this kind */
	InputTokens	name2;		/* token for 2 consecutive chars */
};

extern struct smallSymbol shsymbol[];

#define	WHITESPACE(C)	(shsymbol[(C) & 0377].name == tWhiteSpace || shsymbol[(C) & 0377].name == tNewLine)

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

struct cmddef {
	OutputTokens	opcode;
	const char	*name;
	int		nargs;		/* > 0 is char *, < 0 is int */
};

extern struct cmddef commands[];
extern int ncommands;

#define	TOKEN_NARGS(T)	commands[(int)(T)].nargs
#define	TOKEN_NAME(T)	commands[(int)(T)].name

struct sslfuncdef {
	const char	*name;		/* function name */
	const void	*pos;		/* code position */
	const void	*eot;		/* end of function code */
	struct codedesc	*tabledesc;	/* ptr to table containing its code */
	const char	*file;		/* file name defining function */
	struct sslfuncdef *next;
};

struct codedesc {
	const void	*table;
	const void	*eotable;
	struct sslfuncdef *functions;
#ifdef	MAILER
	/* Stringwise ...	*/
	regexp		**rearray;	/* array of regex's in this table */
	int		rearray_idx;	/* current index		*/
	int		rearray_size;	/* size of rearray in elements	*/
	/* ... and tokenized ..	*/
	tregexp		**trearray;	/* array of regexp's in this table */
	int		trearray_idx;	/* current index		*/
	int		trearray_size;	/* size of rearray in elements	*/
#endif	/* MAILER */
	short		oktofree;
};


typedef enum {
	ioNil,
	ioIntoBuffer,		/* this command's output goes into buffer */
	ioCarryBuffer,		/* don't null the buffer/bufferp in command */
	ioPipeOutput,		/* this builtin command pipes its output */
	ioPipeLater,		/* defer decision about how to handle pipe */
	ioOpenPipe		/* opening read side of pipe */
} IOFlag;

/*
 * Command specifications are constructed using the top element of a stack of
 * osCmd structures.  Each of these specifies the current argument list
 * for the command (in list format), a triple of lists of I/O operations to
 * perform before, during, and after command execution (see above), and a
 * list containing information about temporary variables (FOO=bar command)
 * that must be restored to their previous (non-)value after command execution.
 */

struct osCmd {
	conscell *argv;
	conscell *envold;	/* old values of cmd-line var assigns */
	conscell *rval;		/* rval from list-valued command */
	conscell *buffer;	/* string buffer to build up words */
	conscell **bufferp;	/* pointer to cdr() of last buffer */
	IOFlag	  iocmd;	/* flag, see above */
	int	  fdmask;	/* low bits indicate io taken care of */
	short	  reaperTop;	/* cur top of list of active children */
	short	  flag;		/* miscellaneous flag bits, see below */
	struct IOop	*doio;		/* list of I/O ops to do before cmd */
	struct IOop	*execio;	/* I/O ops to do between fork/exec */
	struct IOop	*undoio;	/* I/O ops to do in parent after cmd */
	void		*memlevel;	/* caddr_t used for MEM_SHCMD stack */
	struct shCmd	*shcmdp;	/* shell command pointer */
	struct sslfuncdef *sfdp;	/* S/SL function data pointer */
	struct osCmd	*prev;		/* previous command if known */
	struct osCmd	*next;		/* pointer to next command if known */
	int		pgrp;		/* process group leader if non-null */
	int		*pgrpp;		/* &pgrp, in background if non-null */
};

#define	OSCMD_BACKGROUND	01	/* inherited: put command in background */
#define	OSCMD_PGRPLEADER	02	/* command is process group leader */
#define	OSCMD_QUOTEOUTPUT	04	/* result of $() should be quoted */
#define	OSCMD_SKIPIT		010	/* there was a previous command */

#endif	/* Z_SH_H */
