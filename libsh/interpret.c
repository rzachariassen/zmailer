/*
 *	Copyright 1989 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * Runtime interpreter for the shell pseudo-code.
 */

#include "hostenv.h"
#include "listutils.h"
#ifdef	MAILER
#include "sift.h"	/* Include this BEFORE "mailer.h" ! */
#endif	/* MAILER */

#include "mailer.h"
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/file.h>

#include "zsyslog.h"

/* #define static
   #define register */
#define RUNIO(X)	(/*fprintf(runiofp, "runio(%s,%d)\n", __FILE__, __LINE__), */runio(&X))

#include "interpret.h"
#include "io.h"
#include "shconfig.h"
#include "libz.h"
#include "libsh.h"

extern struct sptree *spt_funclist;
extern int wait __((int *));
extern int v_record, v_changed;

int magic_number = 3;	/* check id for precompiled script files */
long bin_magic   = 1;	/* Another check-id -- exec file  st_ctime ? */

#if 0
#undef STATIC
#define STATIC /**/
#endif

STATIC int pipefd;		/* read side fd of a pipe, or -1 */

STATIC struct osCmd *ib_command[20];	/* max # nested $() in stack */
STATIC int ibt = -1;		/* top of ib_command stack, XXX reset somewh. */
STATIC const char *uBLANK = "";
/*
 * Because the structure of the interpreter is to build up a command descriptor
 * and then execute it, and the shell must remain relatively intact I/O-wise,
 * we have to predetermine which I/O actions should be taken to set up the
 * environment for a particular program or command.  To do this, we have to
 * know the effects of I/O-related system calls on the environment.  The only
 * possible effect is to create or destroy (or leave alone) one or more
 * file descriptors.  The algorithms used by the kernel to default file
 * descriptors (e.g. in an open() call) are well specified, so we can simulate
 * all that activity a-priori.  This in turn is necessary in order to know
 * how to undo these actions.  The simulation is aided by an array we maintain
 * of busy (i.e. in-use) file descriptors.
 */

STATIC short	fds[MAXNFILE];			/* could be a bitmap */
#define	FDBUSY(X)	((X) > (sizeof fds / sizeof fds[0]) ? abort(),0 : fds[X])

/*
 * This routine is used to model the effects of I/O operations on the
 * set of file descriptors.
 */

STATIC void freeio __((struct IOop *, int));
STATIC void
freeio(fioop, mark)
	register struct IOop *fioop;
	int mark;
{
	struct IOop *nfioop;
	int fd;

	for (; fioop != NULL; fioop = nfioop) {
		nfioop = fioop->next;
		if (1) {
			if (fioop->cmd == sIOdup)
				fd = fioop->fd2;
			else
				fd = fioop->fd;
			fds[fd] = (fioop->cmd != sIOclose);

			if (isset('R'))
				fprintf(stderr,
					"fds[%d] = %d\n",
					fd, (fioop->cmd != sIOclose));
		}
		if (fioop->opflags)
			free((void *)fioop);
	}
}


STATIC char *dequote __((const char *str, int len));
STATIC char *
dequote (str, len)
	const char *str;
	int   len;
{
	const char *sp, *ep;
	char *s, *s0;

/* fprintf(stderr,"dequote(\"%s\",%d) => ",str,len); */

	s0 = emalloc(len+1); /* All subsequent runs will be smaller,
				AND they fit running in-place! */

	do {

	  sp = str;
	  ep = str + len -1;

	  if (len > 1 && *sp == *ep && 
	      (*sp == '"' || *sp == '\'')) {
	    ++sp;
	    --ep;
	    len -= 2;

	    for (s = s0; len > 0; ++sp, --len, ++s) {
	      if (*sp == '\\' && sp[1] != 0) {
		*s = *++sp;
		--len;
	      } else
		*s = *sp;
	    }
	    *s = 0;
	  } else {
	    if (s0 != sp) /* Don't copy, if 'in-place' */
	      memcpy(s0, sp, len);
	    s = s0;
	    if (len > 0)
		s += len;
	    *s = 0;
	  }

	  ep = s-1;

	  str = s0;
	  len = strlen(str);

	} while (ep > s0 && *s0 == *ep && (*s0 == '"' || *s0 == '\''));

/* fprintf(stderr,"\"%s\"\n",s0); */

	return (s0);
}

extern void free_tregexp __((tregexp *prog));

STATIC void free_regexp __((regexp *prog));
STATIC void
free_regexp (prog)
	regexp *prog;
{
	if (prog != NULL) {
		regfree(&prog->re);
		free((void*)(prog->pattern));
		free(prog);
	}
}

STATIC const char * regsub __((regexp *, int));
STATIC const char *
regsub(prog, n)
	regexp *prog;
	int n;
{
	if (prog == NULL || n < 0 || n > prog->re.re_nsub)
		return (NULL);

	return (prog->match[n]);
}

STATIC regexp *reg_comp __((const char *str, int slen));
STATIC regexp *
reg_comp (str, slen)
	const char	*str;
	int		 slen;
{
	const char *reg_stat;
	regexp     *prog;
	char *s;

	prog = (regexp *) malloc(sizeof(regexp));
	if (prog == NULL) {
		fprintf(stderr, "%s: regexp %s: No space\n",
			progname, str);
		return (NULL);
	}
	memset((void*)prog, 0, sizeof(regexp));

	prog->pattern = s = emalloc(slen+1);
	memcpy(s, str, slen+1);
	s[slen] = 0; /* Just in case */

	reg_stat = re_compile_pattern(prog->pattern, slen, &prog->re);
	if (reg_stat != NULL) {
		fprintf(stderr,"%s: regexp %s: %s\n",progname,str,reg_stat);
		free((void*)(prog->pattern));
		free(prog);
		return (NULL);
	}

	return (prog);
}

STATIC int reg_exec __((regexp *, const char *));
STATIC int
reg_exec (prog, str)
	regexp	*prog;
	const char *str;
{
	int		i;
	int		re_stat;
	regmatch_t	*pmatch;

	if (prog == NULL) {
		fprintf(stderr, "%s: regexp: NULL program\n", progname);
		return (0);
	}

#define DEBUG /* allow traceing here as happens with tregexp.c ! */
#ifdef  DEBUG
	if (D_compare) {
		fprintf(stderr,
			"%*sscomparing '%s' and ", 4*funclevel, " ", prog->pattern);
		if (str != NULL)
			fprintf(stderr, "'%s'\n", str);
		else
			fprintf(stderr, "(nil)\n");
	}
#endif  /* DEBUG */

#ifndef USE_ALLOCA
	pmatch = (regmatch_t *)
			emalloc((prog->re.re_nsub+1)*sizeof(regmatch_t));
#else
	pmatch = (regmatch_t *)
			alloca((prog->re.re_nsub+1)*sizeof(regmatch_t));
#endif

	re_stat = regexec(&prog->re, str, prog->re.re_nsub+1, pmatch, 0);
	if (re_stat == REG_NOMATCH) {
#ifndef USE_ALLOCA
		free(pmatch);
#endif
		return 0;
	}

	for (i=0; i<=prog->re.re_nsub; i++)
	  prog->match[i] = strnsave(str + pmatch[i].rm_so,
				    pmatch[i].rm_eo - pmatch[i].rm_so);

#ifdef  DEBUG
	if (D_matched) {
		fprintf(stderr,
			"%*ssmatched '%s' and ", 4*funclevel, " ", prog->pattern);
		if (str != NULL)
			fprintf(stderr, "'%s'\n", str);
		else
			fprintf(stderr, "(nil)\n");
	}
#endif  /* DEBUG */

#ifndef USE_ALLOCA
	free(pmatch);
#endif

	return 1;
}


/*
 * Return the next available filedescriptor, simulating kernel lookup.
 */

STATIC int findfreefd __((void));
STATIC int
findfreefd()
{
        register int fd;

        for (fd = 0; fd <= (sizeof fds / sizeof fds[0]) ; ++fd)
                if (fds[fd] == 0) {
#ifdef  MAILER
                        /*
                         * This is supposed to compensate for random
                         * fopen's in the application, e.g. when caching
                         * file descriptors keeping a database open.
                         * This is a bit too expensive for my liking,
                         * and assumes these things are static as compared
                         * to shell code execution, so beware of subtle bugs.
                         */
                        if (fcntl(fd, F_GETFL,0) >= 0)
                                continue;
#endif  /* MAILER */
                        return fd;
                }
        fprintf(stderr, "%s: out of free filedescriptors (%d)!\n",
                        progname, fd);
        abort(); /* Out of free file-descriptors! */
        /* NOTREACHED */
	return 0;
}


#ifdef	MAILER

/*
 * The mailer should call this routine before toplevel entry to the
 * shell, and then be *VERY* careful about opening files in routines
 * that may be called from within shell execution or between apply calls.
 */

int
setfreefd()
{
	register int i;

#if 0
	register int fd;
	struct stat stbuf;
	
	for (fd = 0; fd <= (sizeof fds / sizeof fds[0]) ; ++fd)
		if (fstat(fd, &stbuf) == 0)
			fds[i = fd] = 1;
		else
			fds[fd] = 0;
#else
	i = -1;
#endif
	return i;
}
#endif	/* MAILER */

STATIC const char * ename __((OutputTokens));
STATIC const char *
ename(cmd)
	OutputTokens cmd;
{
	const char *s = NULL;

	switch (cmd) {
	case sBufferSet:	s = "sBufferSet"; break;
	case sBufferAppend:	s = "sBufferAppend"; break;
	case sBufferExpand:	s = "sBufferExpand"; break;
	case sBufferQuote:	s = "sBufferQuote"; break;
	case sBufferSetFromArgV: s = "sBufferSetFromArgV"; break;
	case sArgVpush:		s = "sArgVpush"; break;
	case sArgList:		s = "sArgList"; break;
	case sVariablePush:	s = "sVariablePush"; break;
	case sVariablePop:	s = "sVariablePop"; break;
	case sVariableCdr:	s = "sVariableCdr"; break;
	case sVariableBuffer:	s = "sVariableBuffer"; break;
	case sVariableAppend:	s = "sVariableAppend"; break;
	case sVariableLoopAttach: s = "sVariableLoopAttach"; break;
	case sCommandPush:	s = "sCommandPush"; break;
	case sCommandPop:	s = "sCommandPop"; break;
	case sCommandCarryBuffer: s = "sCommandCarryBuffer"; break;
	case sIOopen:		s = "sIOopen"; break;
	case sIOopenString:	s = "sIOopenString"; break;
	case sIOopenPortal:	s = "sIOopenPortal"; break;
	case sIOopenPipe:	s = "sIOopenPipe"; break;
	case sIOintoBuffer:	s = "sIOintoBuffer"; break;
	case sIOclose:		s = "sIOclose"; break;
	case sIOdup:		s = "sIOdup"; break;
	case sIOsetIn:		s = "sIOsetIn"; break;
	case sIOsetInOut:	s = "sIOsetInOut"; break;
	case sIOsetOut:		s = "sIOsetOut"; break;
	case sIOsetAppend:	s = "sIOsetAppend"; break;
	case sIOsetDesc:	s = "sIOsetDesc"; break;
	case sIObufIn:		s = "sIObufIn"; break;
	case sIObufOut:		s = "sIObufOut"; break;
	case sIObufFree:	s = "sIObufFree"; break;
	case sIObufString:	s = "sIObufString"; break;
	case sAssign:		s = "sAssign"; break;
	case sAssignTemporary:	s = "sAssignTemporary"; break;
	case sFunction:		s = "sFunction"; break;
	case sParameter:	s = "sParameter"; break;
	case sJump:		s = "sJump"; break;
	case sBranchOrigin:	s = "sBranchOrigin"; break;
	case sJumpFork:		s = "sJumpFork"; break;
	case sJumpIfFailure:	s = "sJumpIfFailure"; break;
	case sJumpIfSuccess:	s = "sJumpIfSuccess"; break;
	case sJumpIfNilVariable: s = "sJumpIfNilVariable"; break;
	case sJumpIfMatch:	s = "sJumpIfMatch"; break;
	case sJumpIfFindVarNil:	s = "sJumpIfFindVarNil"; break;
	case sJumpIfOrValueNil:	s = "sJumpIfOrValueNil"; break;
	case sJumpLoopBreak:	s = "sJumpLoopBreak"; break;
	case sJumpLoopContinue:	s = "sJumpLoopContinue"; break;
	case sLoopEnter:	s = "sLoopEnter"; break;
	case sLoopExit:		s = "sLoopExit"; break;
	case sLocalVariable:	s = "sLocalVariable"; break;
	case sScopePush:	s = "sScopePush"; break;
	case sScopePop:		s = "sScopePop"; break;
	case sDollarExpand:	s = "sDollarExpand"; break;
	case sNoOp:		s = "sNoOp"; break;
	case sPrintAndExit:	s = "sPrintAndExit"; break;
	case sBackground:	s = "sBackground"; break;
	case sSiftPush:		s = "sSiftPush"; break;
	case sSiftBody:		s = "sSiftBody"; break;
	case sSiftCompileRegexp: s = "sSiftCompileRegexp"; break;
	case sSiftReevaluate:	s = "sSiftReevaluate"; break;
	case sSiftPop:		s = "sSiftPop"; break;
	case sSiftBufferAppend:	s = "sSiftBufferAppend"; break;
	case sJumpIfRegmatch:	s = "sJumpIfRegmatch"; break;
	case sTSiftPush:	s = "sTSiftPush"; break;
	case sTSiftBody:	s = "sTSiftBody"; break;
	case sTSiftCompileRegexp: s = "sTSiftCompileRegexp"; break;
	case sTSiftReevaluate:	s = "sTSiftReevaluate"; break;
	case sTSiftPop:		s = "sTSiftPop"; break;
	/* case sTSiftBufferAppend: s = "sTSiftBufferAppend"; break; */
	case sTJumpIfRegmatch:	s = "sTJumpIfRegmatch"; break;
	default: break;
	}
	return s;
}

/*
 * Auxiliary routine (referenced by the INSERTIO macro) which links an
 * I/O action into a linked list of same (in reverse order of execution).
 * Since two of the parameters to the insertio() function are always the
 * same, and the list of arguments so long, we also define a macro invocation
 * for this function.
 */

#define	INSERTIO(X,C,Y,FD1,FD2,PERM)	insertio((X),(C),name,(Y),ioflags,(FD1),(FD2),(PERM))

STATIC struct IOop * insertio __((struct IOop **, struct osCmd *,
				  const char *, OutputTokens,
				  int, int, int, int));
STATIC struct IOop *
insertio(ioopp, command, name, cmd, ioflags, fd, fd2, opflags)
	struct IOop **ioopp;
	struct osCmd *command;
	const char *name;
	OutputTokens cmd;
	int ioflags, fd, fd2, opflags;
{
	register struct IOop *iotmp;

	if (isset('R'))
		fprintf(stderr,
			"insertio(%p): %s %d %d\n",ioopp, ename(cmd), fd, fd2);
	if (opflags)
		iotmp = (struct IOop *)emalloc(sizeof (struct IOop));
	else
		iotmp = (struct IOop *)tmalloc(sizeof (struct IOop));
	iotmp->command = command;
	if (name == NULL)
		iotmp->name = NULL;
	else
		iotmp->name = strsave(name);
	iotmp->cmd = cmd;
	iotmp->ioflags = ioflags;
	iotmp->opflags = opflags;
	iotmp->fd = fd;
	iotmp->fd2 = fd2;
	if (ioopp != NULL) {
		iotmp->next = *ioopp;
		*ioopp = iotmp;
	} else
		iotmp->next = NULL;
	return iotmp;
}

/*
 * When actions are executed in a particular order A,B,C, they sometimes
 * need to be undone in the reverse order: undo C, undo B, undo A.  To
 * aid that, the APPENDIO() macro will do the obvious thing, in contrast
 * with INSERTIO().  Due to the io op list reversal in runio, the APPENDIO's
 * have to be done in reverse natural order.  See below.
 */

#define	APPENDIO(X,C,Y,FD1,FD2)	appendio((X),(C),name,(Y),ioflags,(FD1),(FD2))

STATIC void appendio __((struct IOop **, struct osCmd *, const char *,
			 OutputTokens, int, int, int));
STATIC void
appendio(ioopp, command, name, cmd, ioflags, fd, fd2)
	struct IOop **ioopp;
	struct osCmd *command;
	const char *name;
	OutputTokens cmd;
	int ioflags, fd, fd2;
{
	register struct IOop *iotmp;

	if (isset('R'))
		fprintf(stderr,
			"appendio(%x): %s %d %d\n", ioopp, ename(cmd), fd, fd2);
	iotmp = *ioopp;
	if (iotmp != NULL) {
		for (; iotmp->next != NULL; iotmp = iotmp->next)
			continue;
		iotmp->next = insertio((struct IOop **)NULL, command, name,
				       cmd, ioflags, fd, fd2, 0);
	} else
		*ioopp = insertio((struct IOop **)NULL, command, name,
				       cmd, ioflags, fd, fd2, 0);
}


/*
 * This routine is the basic component for building up I/O descriptor
 * manipulation action lists (what a mouthful) that are later carried
 * out by RUNIO().  It models the effects of I/O system calls on the
 * set of available filedescriptors.
 */

STATIC void ioop __((OutputTokens, struct osCmd *, const char *,
		     int, int, const char *));
STATIC void
ioop(cmd, command, name, ioflags, defaultfd, arg1)
	OutputTokens cmd;
	struct osCmd *command;
	const char *name, *arg1;
	int ioflags, defaultfd;
{
	int	tofd, savefd, intobufflag;

	if (isset('R'))
		fprintf(stderr, "ioop(%x): %s\n", command, ename(cmd));
	intobufflag = 0;
	tofd = defaultfd;
	if (cmd == sIOdup) {
		defaultfd = atoi(arg1);
		if (!FDBUSY(defaultfd)) {
			fprintf(stderr, "%s: no fd %d!\n",
				progname, defaultfd);
			return;
		}
	}
	if (FDBUSY(tofd)) {
		/* save current to-fd somewhere else: save-fd */
		savefd = findfreefd();
		INSERTIO(&command->doio, command, sIOdup, tofd, savefd, 0);
		fds[savefd] = 1;
	} else
		savefd = 0;	/* shut up the compiler */
	if (cmd == sIOopenPipe && !(ioflags & O_CREAT)) {
		if ((defaultfd = pipefd) < 0) {
			fprintf(stderr, "%s: no pipe!\n", progname);
			abort(); /* No pipe on IOopenPipe when it should exist! */
		}
	} else {
		if (cmd == sIOintoBuffer) {
			cmd = sIOopenPipe;
			command->iocmd = ioIntoBuffer;
			intobufflag = 1;
		} else if (cmd == sIOopenPipe)
			command->iocmd = ioOpenPipe;
		INSERTIO(&command->doio, command, cmd, defaultfd, tofd, 0);
		defaultfd = findfreefd();
	}
	/* obey kernel semantics for fd return from open */
	if ((cmd == sIOopen || cmd == sIOopenPipe
	     || cmd == sIOopenPortal || cmd == sIOopenString)
	    && defaultfd != tofd) {
		/* this is always done for pipes, at least */
		/* set fd2 in prev. open for later checking */
		if (cmd == sIOopenPipe && (ioflags & O_CREAT)) {
			/* pipefd is read end of the pipe */
			pipefd = defaultfd;
			fds[pipefd] = 1;
			/* defaultfd is write end of pipe */
			defaultfd = findfreefd();
			command->doio->fd = defaultfd;
			command->doio->fd2 = pipefd;
			INSERTIO(&command->execio, command,sIOclose,pipefd,0,0);
		} else if (cmd == sIOopenPipe) {
			fds[pipefd] = 0;
			pipefd = -1;
		} else
			command->doio->fd = defaultfd;
		/* copy free fd to tofd */
		INSERTIO(&command->doio, command, sIOdup, defaultfd, tofd, 0);
		/* close free fd */
		INSERTIO(&command->doio, command, sIOclose, defaultfd, 0, 0);
	}
	if (FDBUSY(tofd)) {
		/* arrange to close save-fd inside fork/exec */
		INSERTIO(&command->execio, command, sIOclose, savefd, 0, 0);
		/*
		 * We need to restore original to-fd then close save-fd,
		 * but due to mechanics of these things we have to append
		 * them in reverse order here... don't get confused.
		 */
		/* in parent, need to close save-fd */
		APPENDIO(&command->undoio, command, sIOclose, savefd, 0);
		/* but first need to restore original to-fd */
		if (tofd <= 2
		    && (siofds[tofd] == NULL
				     || siofds[tofd]->_sb_refcnt == 0)) {
			APPENDIO(&command->undoio, command, sIObufFree, tofd,0);
		}
		APPENDIO(&command->undoio, command, sIOdup, savefd,tofd);
		if (tofd <= 2
		    && (siofds[tofd] == NULL
				     || siofds[tofd]->_sb_refcnt == 0)) {
			APPENDIO(&command->undoio, command, sIObufFree, tofd,0);
		}
	}
	fds[tofd] = (cmd != sIOclose);
	/* remember this command said something about tofd */
	if (tofd < ((sizeof command->fdmask) * 8))
		command->fdmask |= (1<<tofd);
	if (intobufflag) {
		cmd = sIOintoBuffer;
		intobufflag = 0;
		/*
		 * After forking the command we want to
		 * sit and wait on the output down in RUNIO.
		 */
		INSERTIO(&command->undoio, command, cmd, pipefd, 0, 0);
		/* and then we have to close it of course */
		INSERTIO(&command->undoio, command, sIOclose, pipefd, 0, 0);
		/*
		 * we can't release pipefd (and fds[pipefd])
		 * until after all the other doio's have been
		 * taken care of... but we don't know when
		 * that will be except for at next CommandPop.
		 */
	}
	if (isset('R'))
		fprintf(stderr, "end(%x)\n", command);
}

/*
 * The interpreter interface to the execute() routine.
 */

STATIC void runcommand __((struct osCmd *, struct osCmd *, int *, const char *));
STATIC void
runcommand(c, pc, retcodep, cmdname)
	struct osCmd *c, *pc;
	int *retcodep;
	const char *cmdname;
{
	int ioflags;
	GCVARS1;

	GCPRO1(c->argv);
	if (c->argv) {	/* from tconc into list */

		if (!LIST(c->argv)) *((int*)0) = 0; /* ZAP! */

		c->argv = copycell(car(c->argv));
		cdr(c->argv) = NULL;
	}
	c->buffer = NULL;
	c->bufferp = &(c->buffer);

	/* in a backquote and output hasn't been explicitly redirected */
	if (ibt >= 0 && c->argv != NULL && !(c->fdmask & (1<<1))) {
		/*
		 * If the current command isn't a builtin and stdout not
		 * yet assigned, set up stdout as a pipe and read it
		 * back at backquote commandpop.  This will work even if
		 * we're dealing with a sequence, e.g. `a | b ; c | d`
		 * and b is the current (non-builtin) command, because multiple
		 * calls to readstring() just append to the buffer.
		 * If any of b or d are builtins, the output will be
		 * that of the latter builtin.
		 */

		/* XX: is this necessary*/
		ib_command[ibt]->doio = ib_command[ibt]->execio = NULL;

		if (c->shcmdp != NULL || c->sfdp != NULL) {
			/* builtin function */
			const char *name = "<builtin cmd>";
			ioflags = 0;

			INSERTIO(&c->doio, c, sIObufOut, 1, 1, 0);
			INSERTIO(&ib_command[ibt]->undoio,
				 ib_command[ibt], sIObufIn, 0, 1, 1);
			INSERTIO(&ib_command[ibt]->undoio,
				 ib_command[ibt], sIObufString, 0, 0, 1);
			INSERTIO(&ib_command[ibt]->undoio,
				 ib_command[ibt], sIObufFree, 0, 0, 1);
		} else {
			/* ok, ok, create the silly pipe! */
			register struct IOop *iop;

			if (c->doio) {
				RUNIO(c->doio);
				freeio(c->doio, 1);
				c->doio = NULL;
			}
			ioop(sIOintoBuffer, ib_command[ibt], NULL,
			     O_CREAT|O_WRONLY|O_TRUNC, 1, NULL);
			/* Now copy doio and execio to current command */
			/* first doio */
#if 0
			for (iop = ib_command[ibt]->doio; iop != NULL; iop = iop->next)
				if (iop->next == NULL)
					break;
			if (iop != NULL) {
				iop->next = c->doio;
#endif
				c->doio = ib_command[ibt]->doio;
				ib_command[ibt]->doio = NULL;
#if 0
			}
#endif
			/* then execio */
			for (iop = ib_command[ibt]->execio; iop != NULL; iop = iop->next)
				if (iop->next == NULL)
					break;
			if (iop != NULL) {
				iop->next = c->execio;
				c->execio = ib_command[ibt]->execio;
				ib_command[ibt]->execio = NULL;
			}
		}
		--ibt;
	}

	/* run the command and undo any temporary variables */
	if (retcodep != NULL) {
		const char *name = "<builtin cmd>";
		if (c->shcmdp != NULL)
		  name = c->shcmdp->name;
		*retcodep = execute(c, pc, *retcodep, name);
		if (*retcodep != 0 && isset('e'))
			trapexit(*retcodep);
	}
	/* else we are ignoring execution of this command */

	/*
	 * We don't need to explicitly free the argv/envold/io
	 * lists since that is taken care of by the setlevel()
	 */
	if (c->doio)
		freeio(c->doio, 1);
	if (c->undoio)
		freeio(c->undoio, 1);
	if (c->execio)
		freeio(c->execio, 0);
	UNGCPRO1;
}

/*
 * Variable assignment routine.  This is used directly by the interpreter
 * and indirectly through v_set() by most everything else.  All new variables
 * are created in the global (but non-exported) scope unless variables are
 * automatically exported.  The prior value of a variable is sometimes stashed
 * away for later restoration.  This is only done when a command descriptor
 * is passed, since it is used to undo the effect of temporary variable
 * assignments on the command line.
 */

void
assign(sl_lhs, sl_rhs, command)
	conscell *sl_lhs, *sl_rhs;
	struct osCmd *command;
{
	conscell *s = NULL, *l = NULL;
	GCVARS4;

	GCPRO4(s, l, sl_lhs, sl_rhs);

	/*
	 * Add (lhs oldvalue) to a list "envold" kept in the command.
	 * Variable values are really (potentially) lists.
	 */
	s = v_find(sl_lhs->cstring);

	l = copycell(sl_rhs); /* Copy it just in case.. */
	/* that was: s_copy_tree(), but we don't need THAT! */
	if (l)
	  sl_rhs = l;

	if (s == NULL) {

	  /* We don't know this variable, we create it */

	  /* create the variable in the global but non-exported scope */
	  for (l = car(envarlist); cddr(l) != NULL; l = cdr(l))
	    continue; /* Scan scopes, stop at next to last */

	  /* l points at the next-to-last sublist of envarlist */
	  if (isset('a'))
	    l = cdr(l);	/* or the list of exports */

	  cdr(sl_rhs) = car(l);		/* the scope-list follows this value */
	  s = copycell(sl_lhs);		/* Variable name here */
	  cdr(s) = sl_rhs;		/* .. value follows varname */
	  car(l) = s;			/* .. and anchor varname into scope */
	  l = NIL; /* A NIL-cell for old value.. */

	} else {

	  /* The variable exists, we replace the data content */


	  cdr(sl_rhs) = cddr(s);	/* Glue the chain:
					   s -> new_value -> old_tail */
	  l = cdr(s);			/* Old value cell   */
	  cdr(l) = NULL;		/* ... disconnected */

	  cdr(s) = sl_rhs;		/* ... and place the new value in */

#ifdef	MAILER
	  if (v_accessed)
	    v_written(s);
#endif	/* MAILER */

	  if (isset('a'))		/* if "auto-export" set */
	    v_export(sl_lhs->cstring);	/* ick! */

	}
	/* stash old value */
	if (command != NULL) {
	  cdr(l) = command->envold; command->envold = l;
	  s      = copycell(sl_lhs);
	  cdr(s) = command->envold; command->envold = s;
	}
	UNGCPRO4;

	/* fvcache.namesymbol = 0; */
	v_sync(sl_lhs->cstring);

	if (isset('I')) {
	  fprintf(runiofp, "Assign %s = ", sl_lhs->cstring);
	  s_grind(sl_rhs, runiofp);
	  putc('\n', runiofp);
	}

#ifdef	MAILER
	if (D_assign) {
	  fprintf(stderr, "%*s%s=", 4*funclevel, " ", sl_lhs->cstring);
	  s_grind(sl_rhs, stderr);
	  fputc('\n', stderr);
	}
#endif	/* MAILER */

}

/*
 * Discard the definition of the function with the given name.  If this was
 * the last definition for the stored code table, free the table.
 */

STATIC void undefun __((const char *));
STATIC void
undefun(fname)
	const char *fname;
{
	struct spblk *spl;
	
	spl = sp_lookup(symbol(fname), spt_funclist);
	if (spl == NULL)
	  return;
	xundefun(spl);
}

/*
 * A version of undefun() we can call from inside sp_scan()
 */

int
xundefun(spl)
	struct spblk *spl;
{
	struct sslfuncdef *sfdp, **psfdp;
#ifdef	MAILER
	int idx;
	regexp **rep, **repstart;
	tregexp **trep, **trepstart;
#endif	/* MAILER */
	
	sfdp = (struct sslfuncdef *)spl->data;
	if (sfdp != NULL) {
	  psfdp = &(sfdp->tabledesc->functions);
	  for (sfdp = *psfdp; sfdp != NULL;
	       psfdp = &sfdp->next, sfdp = *psfdp) {
	    if (strcmp(sfdp->name,
		       ((struct sslfuncdef *)spl->data)->name) == 0) {
	      *psfdp = sfdp->next;
	      break;
	    }
	  }
	  if (sfdp->tabledesc->functions == NULL &&
	      sfdp->tabledesc->oktofree) {
#ifdef	MAILER
	    repstart = sfdp->tabledesc->rearray;
	    if (repstart != NULL) {
	      idx = sfdp->tabledesc->rearray_idx;
	      rep = repstart;
	      while (rep - repstart < idx && *rep != NULL)
		free_regexp(*rep++);
	      free((char *)sfdp->tabledesc->rearray);
	    }
	    trepstart = sfdp->tabledesc->trearray;
	    if (trepstart != NULL) {
	      idx = sfdp->tabledesc->trearray_idx;
	      trep = trepstart;
	      while (trep - trepstart < idx && *trep != NULL)
		free_tregexp(*trep++);
	      free((void *)sfdp->tabledesc->trearray);
	    }
#endif	/* MAILER */
	    free((void *)sfdp->tabledesc->table);
	    free((void *)sfdp->tabledesc);
	  }
	  free((void *)sfdp);
	  /*
	   * This should really be sp_delete, but if it is we won't
	   * be able to call undefun() inside an sp_scan...
	   */
	  spl->data = NULL;
	}
	return 0;
}

/*
 * Define an interpreted function.  Sets up mutual links between the function
 * descriptor and the code table descriptor.
 */

STATIC void defun __((struct codedesc *, const char *, const char *, const char *));
STATIC void
defun(cdp, fname, position, eofunc)
	struct codedesc *cdp;
	const char	*fname;
	const char	*position, *eofunc;
{
	struct sslfuncdef *sfdp;
	
	undefun(fname);
	sfdp = (struct sslfuncdef *)emalloc(sizeof (struct sslfuncdef));
	/*
	 * The function name string is known to be part of the function
	 * pseudo-code and will not disappear unless the data block containing
	 * the function definition goes bye-bye.
	 */
	sfdp->name = fname;
	sfdp->pos  = position;
	sfdp->eot  = eofunc;
	sfdp->tabledesc = cdp;	/* will be set properly at end of interpret() */
	sfdp->next = cdp->functions;
	cdp->functions = sfdp;
	sp_install(symbol(fname), (void *)sfdp, 0, spt_funclist);
}

/*
 * This routine determines possible internal definitions of a function.
 */

void
functype(fname, shcmdpp, sfdpp)
	register const char *fname;
	struct shCmd **shcmdpp;
	struct sslfuncdef **sfdpp;
{
	spkey_t symid;
	struct spblk *spl;

	symid = symbol_lookup(fname);
	/* is it a defined function? */
	spl = NULL;
	if (symid)
	  spl = sp_lookup(symid, spt_funclist);
	if (sfdpp) {
	  if (spl != NULL)
	    *sfdpp = (struct sslfuncdef *)spl->data;
	  else
	    *sfdpp = NULL;
	}

	/* behaviour in execute() requires we continue, not return */

	/* is it a builtin command? */
	spl = NULL;
	if (symid)
	  spl = sp_lookup(symid, spt_builtins);
	if (shcmdpp != NULL) {
	  if (spl != NULL)
	    *shcmdpp = (struct shCmd *)spl->data;
	  else
	    *shcmdpp = NULL;
	}
	/* it must be a unix program */
}


/*
 * Coalesces all the small buffers in command->buffer into a single buffer.
 */

STATIC void coalesce __((struct osCmd *));
STATIC void
coalesce(command)
	struct osCmd *command;
{
	conscell *s;

	if (command->buffer == NULL)
	  return;
	for (s = command->buffer; s != NULL; s = cdr(s))
	  if (LIST(s))
	    return;

	command->buffer->flags |= QUOTEDSTRING;	/* so result will be too */
	if (cdr(command->buffer) != NULL)
	  /* this is only done for LARGE intoBuffer outputs */
	  command->buffer = s_catstring(command->buffer);
	command->bufferp = &cdr(command->buffer);
}


/*
 * Chop off any leading and trailing whitespace.
 */

STATIC void flushwhite __((struct osCmd *));
STATIC void
flushwhite(command)
	struct osCmd *command;
{
	register conscell *s, *p;
	register char *cp;

	if (command->buffer == NULL)
	  return;
	if (ISELEMENT(command->buffer))
	  return;
	for (s = command->buffer; s != NULL; s = cdr(s))
	  if (LIST(s))
	    return;

#if 0
	/* strip leading whitespace */
	s = command->buffer;
	do {
	  for (cp = command->buffer->string;
	       *cp != '\0' && WHITESPACE(*cp); ++cp)
	    continue;
	} while ((*cp == '\0') && (command->buffer = cdr(command->buffer)));
	if (command->buffer == NULL) {
	  command->bufferp = &command->buffer;
	  return;
	}
	if (s->string != cp) {
	  command->buffer->string = strsave(cp);
	}
#endif

	/* strip trailing whitespace */
	p = NULL;
	do {
	  for (s = command->buffer; cdr(s) != p; s = cdr(s))
	    continue;
	  for (cp = s->string + s->slen - 1;
	       cp >= s->string; --cp)
	    if (*cp != '\n' /* !WHITESPACE(*cp) */)
	      break;
	  p = s;
	} while ((cp < s->string) && (s != command->buffer));
	if (cp < s->string) {
	  command->buffer = NULL;
	  command->bufferp = &command->buffer;
	} else {
	  *++cp = '\0';
	  s->slen  = cp - s->string;
	  cdr(s)   = NULL;
	  command->bufferp = &cdr(s);
	}
}

STATIC void tsetsubexps __((struct si_retab **, tregexp *));
STATIC void
tsetsubexps(sepp, tre)
	struct si_retab **sepp;
	tregexp *tre;
{
	register struct si_retab *sep, *psep;
	register unsigned int i;

	for (sep = *sepp, psep = NULL; sep != NULL;
	     psep = sep, sep = sep->next) {
	  if (sep->trep == tre)
	    break;
	}
	if (sep == NULL) {
	  sep = (struct si_retab *)tmalloc(sizeof (struct si_retab));
	  for (i = 0; i < (sizeof sep->startp)/(sizeof sep->startp[0]); ++i)
	    sep->startp[i] = sep->endp[i] = NULL;
	  memset((char *)sep, 0, sizeof (struct si_retab));
	  sep->trep = tre;
	  sep->next = *sepp;
	} else if (psep != NULL) {
	  psep->next = sep->next;
	  sep->next = *sepp;
	}
	*sepp = sep;
	tre->startp = sep->startp;
	tre->endp = sep->endp;
}


STATIC void setsubexps __((struct si_retab **, regexp *));
STATIC void
setsubexps(sepp, prog)
	struct si_retab **sepp;
	regexp *prog;
{
	register struct si_retab *sep, *psep;

	for (sep = *sepp, psep = NULL; sep != NULL;
	     psep = sep, sep = sep->next)
	  if (sep->rep == prog)
	    break;
	if (sep == NULL) {
	  sep = (struct si_retab *)tmalloc(sizeof (struct si_retab));
	  memset((char *)sep, 0, sizeof (struct si_retab));
	  if (prog != NULL)
	    sep->match = (const char **) tmalloc((prog->re.re_nsub+1) *
						 sizeof(char *));
	  else
	    sep->match = NULL;
	  sep->rep = prog;
	  sep->next = *sepp;
	} else if (psep != NULL) {
	  psep->next = sep->next;
	  sep->next = *sepp;
	}
	*sepp = sep;
	if (prog != NULL)
	  prog->match = sep->match;
}


#if 0
/*
 * This is a cache structure for v_find() which has appreciable locality.
 * Every time an assignment is made or a scope pushed/popped, this cache
 * is invalidated.
 */
struct {
	int	namesymbol;
	conscell *location;
} fvcache = { 0, NULL };
#endif

struct loopinfo {
	int	brk;		/* relative pc address if we want to break */
	int	cont;		/* relative pc address if we want to continue */
	short	cmdindex;	/* index of active command at this place */
	short	varindex;	/* index of active loop variable */
};

STATIC token822 *tscanstring __((const char *));
STATIC
token822 *
tscanstring(s)
	const char *s;
{
	const char *cp;
	int len;
	token822 *t;

	t = HDR_SCANNER(s);
	if (t != NULL && t->t_next == NULL && t->t_type == String) {
	  /* we need to de-quote the quoted-string */
	  char *bp;
	  const char *buf;
	  len = TOKENLEN(t);
	  buf = bp = (char *)tmalloc(len+1);
	  for (cp = t->t_pname; (cp - t->t_pname) < len ; ++cp) {
	    if ((*cp == '\\') && ((cp - t->t_pname) < len-1))
	      *bp++ = *++cp;
	    else
	      *bp++ = *cp;
	  }
	  *bp = '\0';
	  t = HDR_SCANNER(buf);
	}
	return t;
}

/* This is a last-line defence on utter stupidity -- doing recursive
 * evaluation on something without proper terminating condition does
 * quickly lead to awfull crash with a system whose stack is demolished,
 * and rather difficult to debug...   Trust me, I know -- Matti Aarnio */

STATIC int max_interpreter_recursions = 40;

/*
 * Interpret Shell pseudo-code generated from S/SL description.
 *
 * Memory allocation and freeing in this code is a bit funny.  To avoid
 * a complicated reference-count or other GC scheme, we maintain a stack
 * in memory (type MEM_SHCMD).  We unravel the stack as we pop commands.
 * That takes care of scratch allocations, which is everything except
 * variable names and values.  We have to be careful about freeing that
 * data (which is malloc()'ed) whenever we discard it.
 */

struct codedesc *
interpret(Vcode, Veocode, Ventry, caller, retcodep, cdp)
	const void *Vcode, *Veocode, *Ventry;
	struct osCmd *caller;
	int     *retcodep;
	struct codedesc *cdp;
{
	register const char *code = Vcode, *eocode = Veocode, *entry = Ventry;
	register const char  *pc;
	register OutputTokens cmd;
	register struct osCmd *command;
	register int commandIndex, variableIndex, i;
	const char *arg1 = NULL, *name, *cmdname;
	const char *origlevel;
	int	*iname;
	int	argi1 = 0, dye, childpid, dollar, ioflags;
	memtypes stickytmp, origstickymem;
	int	defaultfd, quote, quoted, nloop, ignore_level;
#define LOOPMAXDEPTH 30
	struct loopinfo loop[LOOPMAXDEPTH];	/* max # nested loops */
	conscell *variable = NULL, *l = NULL, *margin = NULL;
	conscell *d = NULL, *tmp = NULL;
	struct osCmd *prevcommand = NULL;
	struct osCmd *pcommand    = NULL;
#define COMMANDMAXDEPTH 30
	struct osCmd commandStack[COMMANDMAXDEPTH];
#define VARMAXDEPTH 30
	conscell *varmeter = NULL;
	conscell *varmchain = NULL;
#ifdef	MAILER
	struct siftinfo sift[30];
	int nsift = -1;
	regexp   *re = NULL;
	tregexp *tre = NULL;
#endif	/* MAILER */
	GCVARS6;


#ifdef	MAILER
	++funclevel;
	if (funclevel > max_interpreter_recursions) {
	  fprintf(stderr,"zmailer: interpret: recursed more than %d levels deep on invocation!  script termination condition error ?\n",max_interpreter_recursions);
	  zsyslog((LOG_EMERG,"zmailer: interpret: recursed more than %d levels deep on invocation!  script termination condition error ?\n",max_interpreter_recursions));
	  abort(); /* excessively deep recursion - *.cf -script termination condition error ? */
	}
#endif	/* MAILER */
	optind = 0;	/* for getopts */
	if (cdp == NULL) {
	  cdp = (struct codedesc *)emalloc(sizeof (struct codedesc));
	  cdp->table   = code;
	  cdp->eotable = eocode;
	  cdp->functions = NULL;
#ifdef	MAILER
	  cdp->rearray = NULL;
	  cdp->rearray_size = 0;
	  cdp->rearray_idx = -1;
	  cdp->trearray = NULL;
	  cdp->trearray_size = 0;
	  cdp->trearray_idx = -1;
#endif	/* MAILER */
	  cdp->oktofree = 0;
	}
	commandIndex  = -1;
	command = &commandStack[++commandIndex];
	command->buffer = NULL;
	command->bufferp = &command->buffer;
	command->flag = 0;
	command->rval = command->argv = command->envold = NULL;
	variableIndex = -1;
	variable = NULL;
	ioflags = 0;
	defaultfd = 0;
	dye = 0;
	dollar = 0;
	quote = 0;
	varmeter = NULL;
	fds[0] = fds[1] = fds[2] = 1;   /* XX: this isn't recursive, eh?? */
	if (entry == NULL)
		pipefd = -1;
	margin = car(envarlist);/* so we can be sure to pop scopes on exit */
#define	MAGIC_LARGE_IGNORE_LEVEL	123435	/* >> any valid ignore level */
	ignore_level = MAGIC_LARGE_IGNORE_LEVEL;
#define	MAGIC_LARGE_ADDRESS	9827432		/* >> any valid address */
	loop[0].brk = loop[0].cont = MAGIC_LARGE_ADDRESS;
	loop[0].varindex = -1;
	loop[0].cmdindex = 0;	/* this is important to unravel on "return" */
	nloop = 0;
	origstickymem = stickymem;
	origlevel = getlevel(MEM_SHCMD);
	stickymem = MEM_SHCMD;
	/* shut up the compiler */
	stickytmp = MEM_SHCMD;
	d = NULL;
	argi1 = 0;

  	GCPRO6(varmchain, variable, l, margin, d, tmp);

	/* Initialize syntax for regular expressions */
	(void) re_set_syntax(RE_CONTEXT_INDEP_ANCHORS |
			     RE_CONTEXT_INDEP_OPS |
			     RE_CONTEXT_INVALID_OPS |
			     RE_NO_BK_PARENS |
			     RE_NO_BK_VBAR |
			     RE_DOT_NOT_NULL);

#ifdef DEBUGxx
	fprintf(stderr,"%s:%d &command->buffer=%p\n",__FILE__,__LINE__,
		&command->buffer);
#endif
	GCPRO4STORE(command->,
		    command->argv, command->rval,
		    command->envold, command->buffer);

	/* funcall tracing could be done here */
	/* if (caller != NULL) grindef("ARGV = ", caller->argv); */
	if (isset('R'))
		fds[FILENO(stderr)] = 1;
	for (pc = (entry == NULL ? code : entry) ; pc < eocode; ++pc) {
		if (sprung) {
			trapped();
			if (interrupted)
				break;
		}
		cmd = (OutputTokens)(*pc & 0xFF);
		if (isset('I'))
			fprintf(runiofp, "'%d\t%s\n", pc - code,
				TOKEN_NAME(cmd));
		switch (TOKEN_NARGS(cmd)) {
		case 0:
			arg1  = NULL;
			argi1 = 0;
			break;
		case 1:
			argi1 = 0;
			arg1 = (const char*) ++pc;
			while (*pc != '\0')
				++pc;
			break;
		case -1:
			arg1   = NULL;
			argi1  = (*++pc) & 0xFF;
			argi1 <<= 8;
			argi1 |= (*++pc) & 0xFF;
			argi1 <<= 8;
			argi1 |= (*++pc) & 0xFF;
			argi1 <<= 8;
			argi1 |= (*++pc) & 0xFF;
			break;
		}

		switch (cmd) {
		case sBufferSetFromArgV:
			dollar = 1;
			quote = 1;
			arg1 = "@";
			/* this gives "$@" */
			/* FALL THROUGH */
		case sBufferSet:
			/* The buffer points at a linked list of strings */
			command->buffer  = NULL;
			command->bufferp = &command->buffer;
			/* FALL THROUGH */
		case sBufferAppend:
			if (dollar) {
				dollar = 0;
				d = v_expand(arg1, caller, *retcodep);
				if (d == NULL) {
					if (isset('u')) {
						fprintf(stderr,
						    "%s: parameter not set\n",
						    arg1);
						ignore_level = commandIndex;
					}
					d = conststring(uBLANK,0);
				} else {
					d = s_copy_tree(d);
				}
				if (!quote && STRING(d) && *(d->string) == '\0')
					break;
			} else if (*arg1 != '\0' || quote) {
				int slen = strlen(arg1);
#if 0
				d = newstring(dupnstr(arg1,slen),slen);
#else
				d = conststring(arg1,slen);
#endif
			} else
				break;	/* it is a null string! */
#ifdef DEBUGxx
fprintf(stderr,"%s:%d &command->buffer = %p\n",__FILE__,__LINE__,&command->buffer);
#endif
			*command->bufferp = d;
			for (tmp = d; cdr(tmp) != NULL; tmp = cdr(tmp))
				continue;
			command->bufferp = &cdr(tmp);
			if (quote) {
				while (d != NULL) {
					if (STRING(d) && !ISDONTQUOTE(d))
						d->flags |= QUOTEDSTRING;
					d = cdr(d);
				}
				quote = 0;
			}
			if (isset('I'))
				grindef("Buffer = ", command->buffer);
			break;
		case sBufferExpand:
			if (command->buffer == NULL)
				d = conststring(uBLANK,0);
			else if (cdr(command->buffer))
				d = s_catstring(command->buffer);
			else
				d = command->buffer;
			quoted = ISQUOTED(d);
			d = v_expand((const char*)d->string,caller,*retcodep);
			if (d == NULL) {
				if (isset('u')) {
					fprintf(stderr,
						"%s: parameter not set\n",
						arg1);
					ignore_level = commandIndex;
				}
				d = conststring(uBLANK,0);
			} else {
				d = s_copy_tree(d);
			}
			command->buffer = d;
			while (d != NULL) {
				if (quoted && STRING(d))
					d->flags |= QUOTEDSTRING;
				if (cdr(d) == NULL)
					break;
			}
			if (d == NULL)
				command->bufferp = &command->buffer;
			else {
				for (tmp = d; cdr(tmp) != NULL; tmp = cdr(tmp))
					continue;
				command->bufferp = &cdr(tmp);
			}
			if (isset('I'))
				grindef("Expanded Buffer = ", command->buffer);
		case sArgVpush:
			if (command->buffer == NULL)
				break;
			d = expand(command->buffer);
			if (command->argv == NULL && STRING(d)) {
				/* what kind of command is this? */
				functype(d->string,
					 &command->shcmdp, &command->sfdp);
				if (command->sfdp != NULL)
					command->shcmdp = NULL;
				if (prevcommand != NULL) {
					prevcommand->next = command;
					prevcommand->reaperTop = reapableTop;
					if (command->shcmdp == NULL
					    && command->sfdp == NULL) {
						/* create pipe for prev. cmd */
						ioop(sIOopenPipe, prevcommand,
						     NULL, O_CREAT, 1, NULL);
						/* --- */
						RUNIO(prevcommand->doio);
						freeio(prevcommand->doio, 1);
						prevcommand->doio = NULL;
						/* --- */
						/* add inpipe to this command */
						ioop(sIOopenPipe, command,
						     NULL, O_RDONLY, 0, NULL);
					} else if (command->sfdp != NULL  ||
						   (command->shcmdp != NULL &&
						    (command->shcmdp->sptr != NULL ||
						     prevcommand->shcmdp->sptr != NULL))){
						/* create stringbuffer */
						name = NULL;
						INSERTIO(&prevcommand->doio,
							 prevcommand,
							 sIObufOut, 1, 1, 0);
						/* --- */
						RUNIO(prevcommand->doio);
						freeio(prevcommand->doio, 1);
						prevcommand->doio = NULL;
						/* --- */
						INSERTIO(&command->doio,
							 command,
							 sIObufIn, 0, 1, 0);
#if 1
						if (nloop > 0 &&
						    loop[nloop].cmdindex == 
							commandIndex-1)
			    INSERTIO(&commandStack[commandIndex-2].undoio,
				     &commandStack[commandIndex-2],
				     sIObufFree, 0, 0, 0);
						else
#endif
						  INSERTIO(&command->undoio,
							   command,
							   sIObufFree,0,0,0);
					}
					/*
					 * ... else we're connecting two
					 * list-valued functions, which is ok.
					 */
					cmdname = NULL;
					if (prevcommand->sfdp)
					  cmdname = prevcommand->sfdp->name;
					if (prevcommand->shcmdp)
					  cmdname = prevcommand->shcmdp->name;
					runcommand(prevcommand, caller,
						   ignore_level>commandIndex ?
						   retcodep : NULL, cmdname);
					command->rval = prevcommand->rval;
					if (command->prev == prevcommand) {
						command->prev = NULL;
						command->flag |= OSCMD_SKIPIT;
					}
					free((char *)prevcommand);
					prevcommand = NULL;
					/* X:shouldn't prevcommand be stacked?*/
				}
			}

GCPLABPRINTis(command->gcpro4);
			if (command->argv == NULL) {
				command->argv = ncons(d);
				command->argv = ncons(command->argv);
			} else {
				cddar(command->argv) = d;
			}
			cdar(command->argv) = s_last(d);

			if (command->iocmd == ioPipeLater) {
				/* we saw an openPipe but it was too early...*/
				command->iocmd = ioNil;
				if (command->shcmdp != NULL
				    || command->sfdp != NULL) {
					/* set prevcommand in the CommandPop */
					command->iocmd = ioPipeOutput;
				} else {
					command->reaperTop = reapableTop;
					ioop(sIOopenPipe, command,
					     NULL, O_CREAT, 1, NULL);
				}
			}
			if (isset('I'))
				grindef("Argv = ", command->argv);
			break;
		case sArgList:
			/* take the remaining arguments in caller->argv
			   and stick them in the local variable "argv" in
			   the current scope */
			break;
		case sVariableCdr:
			if (variable != NULL)
				car(variable) = cdar(variable);
			if (varmeter) {
				if (variable && car(variable)) {
					car(varmeter) = caar(variable);
					varmeter->flags = car(variable)->flags;
					varmeter->slen  = car(variable)->slen;
				} else {
					car(varmeter) = NULL;
					varmeter->flags = 0;
				}
			}
			if (isset('I'))
				grindef("Variable = ", variable);
			break;
		case sVariablePush:
			if (variableIndex >= 0) {
			  tmp = ncons(varmeter);  cdr(tmp) = varmchain; varmchain = tmp;
			  tmp = ncons(variable);  cdr(tmp) = varmchain; varmchain = tmp;
			}

			++variableIndex;

			if (variableIndex >= VARMAXDEPTH) {
			  fprintf(stderr,"%s: interpret.c: varStack[] recursed once too many. Max depth: %d\n",
				  progname, VARMAXDEPTH);
			  abort(); /* varStack[] recursed too deep! */
			}

			if (command->buffer == NULL)
				variable = NULL;
			else {
				variable = expand(command->buffer);
				variable = ncons(variable);
			}

			varmeter = NULL;
			if (isset('I'))
				grindef("Variable = ", variable);
			break;
		case sVariablePop:
			--variableIndex;
			if (varmchain) {
				variable = car(varmchain);
				varmeter = cadr(varmchain);
				varmchain = cddr(varmchain);
				if (isset('I'))
					grindef("Variable = ", variable);
			}
			else
			  variable = varmeter = NULL;

			break;
		case sVariableBuffer:
			if (variable != NULL) {
				command->buffer = ncons(car(variable));
			} else
				command->buffer = NIL;
			if (isset('I'))
				grindef("Buffer = ", command->buffer);
			break;
		case sVariableAppend:
			if (command->buffer == NULL)
				break;
			d = expand(command->buffer);
			if (variable == NULL)
				variable = ncons(d);
			else if (car(variable) == NULL)
				car(variable) = d;
			else
				cdr(s_last(car(variable))) = d; /* XX */
			if (isset('I'))
				grindef("Variable = ", variable);
			break;
		case sVariableLoopAttach:
			varmeter = cdaar(envarlist);
			if (variable != NULL) {
				car(varmeter) = caar(variable);
				varmeter->flags = car(variable)->flags;
				varmeter->slen  = car(variable)->slen;
			}
			break;
		case sCommandPush:
			if (commandIndex > 0) {
				if (command->iocmd == ioPipeLater) {
					/* see above at end of ArgV */
					command->iocmd = ioNil;
					if (command->shcmdp != NULL
					    || command->sfdp != NULL)
						command->iocmd = ioPipeOutput;
					else {
						command->reaperTop =
							reapableTop;
						ioop(sIOopenPipe, command,
						     NULL, O_CREAT, 1, NULL);
					}
				}
				if (command->doio != NULL) {
					RUNIO(command->doio);
					freeio(command->doio, 1);
					command->doio = NULL;
					if (prevcommand != NULL) /* gross */
						prevcommand->doio = NULL;
				}
			}
			pcommand = command;
			command = &commandStack[++commandIndex];
			if (commandIndex >= COMMANDMAXDEPTH) {
			  fprintf(stderr,"%s: interpret.c: commandStack[] recursed once too many. Max depth: %d\n",
				  progname, COMMANDMAXDEPTH);
			  abort(); /* commandStack[] recursed too deep! */
			}

			memset(command, 0, sizeof(*command));
			command->bufferp = &command->buffer;
			/* command->argv = command->envold =
			   command->rval = command->buffer = NULL;
			   command->doio = command->undoio = 0;
			   command->execio = command->fdmask = 0;
			   command->pgrp = 0;
			   command->flag = 0;
			   command->shcmdp = NULL;
			   command->sfdp = NULL;
			   command->next = NULL;
			*/

			command->iocmd = ioNil;
#ifdef DEBUGxx
fprintf(stderr,"%s:%d &command->buffer=%p\n",__FILE__,__LINE__,
	&command->buffer);
#endif
			GCPRO4STORE(command->,
				    command->argv, command->rval,
				    command->envold, command->buffer);

			if (prevcommand != NULL) {	/* in pipe */
				command->memlevel = prevcommand->memlevel;
				command->pgrpp = prevcommand->pgrpp;
			} else {
				command->memlevel = getlevel(MEM_SHCMD);
				command->pgrpp = NULL;
			}
			command->prev = prevcommand;
			if (commandIndex > 1) {
				/*
				 * This value is inherited, NULL or not.  It
				 * is reset by a null return from list-valued
				 * function, or by any string-valued function.
				 */
				command->rval = pcommand->rval;

				command->pgrpp = pcommand->pgrpp;
				command->fdmask = pcommand->fdmask;

				/* mark child commands of `...` */
				if (pcommand->iocmd == ioIntoBuffer) {
					pcommand->reaperTop = reapableTop;
					command->reaperTop = reapableTop;
				} else if (pcommand->reaperTop > -1)
					command->reaperTop =
						pcommand->reaperTop;
				else
					command->reaperTop = -1;
			} else {
				command->reaperTop = -1;
				if (command->prev != NULL)
					command->rval = command->prev->rval;
				else
					command->rval = NULL;
			}
			break;
		case sCommandPop:
			if (pipefd >= 0)   /* IOintoBuffer relies on this */
				fds[pipefd] = 0;
			if (command->iocmd == ioPipeOutput) {
				/*
				 * This command pipes its output into
				 * another one.
				 */
				command->iocmd = ioNil;
				prevcommand =
				  (struct osCmd *)emalloc(sizeof(struct osCmd));
				*prevcommand = *command;
				command->flag |= OSCMD_SKIPIT;
				break;
			}
			argi1 = *retcodep;
			if (command->iocmd != ioCarryBuffer) {
				cmdname = NULL;
				if (command->sfdp)
				  cmdname = command->sfdp->name;
				if (command->shcmdp)
				  cmdname = command->shcmdp->name;
				runcommand(command, caller,
					   ignore_level > commandIndex ?
					   retcodep : NULL, cmdname);
				tmp = *(command->bufferp);
			}
			if (ignore_level == commandIndex)
				ignore_level = MAGIC_LARGE_IGNORE_LEVEL;
			if (command->shcmdp != NULL
			    && (command->shcmdp->flag == SH_INTERNAL ||
				(void*)command->shcmdp->rptr != NULL)) {
				/* this was break, continue, return or exit */
				/* any optional argument is now in *retcodep */
				if (*command->shcmdp->name == 'b' || /*break*/
				    *command->shcmdp->name == 'c') { /*cont'*/
					if (*retcodep > 0) {
						*retcodep -= 1;
						if (*retcodep <= nloop)
							nloop -= *retcodep;
					} else
						*retcodep = 0;
					if (nloop < 0)
						goto nobreak;
					if (*command->shcmdp->name == 'b')
					  pc = code + loop[nloop].brk;
					else
					  pc = code + loop[nloop].cont;
					--pc;
				} else if (*command->shcmdp->name == 'e') {
					if (cdar(command->argv))
						trapexit(*retcodep);
					else
						trapexit(argi1);
				}
#if 0
				else {
					std_printf("ix = %d\nrval = %x\n",
					       commandIndex, command->rval);
				}
#endif
				/* if not in a loop this is done for returns */
				while (commandIndex > loop[nloop].cmdindex) {
					pcommand = &commandStack[commandIndex];
					if (pcommand->undoio) {
						RUNIO(pcommand->undoio);
						freeio(pcommand->undoio, 1);
					}
					/* this is done after getout, below */
					/*setlevel(MEM_SHCMD, pcommand->memlevel);*/
#ifdef DEBUGxx
	fprintf(stderr,"%s:%d &command->buffer=%p\n",__FILE__,__LINE__,
		&command->buffer);
#endif
					UNGCPROSTORE4( pcommand-> );
					--commandIndex;
				}
				while (variableIndex > loop[nloop].varindex) {
					if (varmeter) {
						car(varmeter) = NULL;
						varmeter->flags = 0;
					}
					if (--variableIndex < 0)
					  break;
					if (varmchain) {
					  variable = car(varmchain);
					  varmeter = cadr(varmchain);
					  varmchain = cddr(varmchain);
					} else
					  variable = varmeter = NULL;
				}
				if (isset('I'))
					grindef("Variable = ", variable);

				if (*command->shcmdp->name == 'b'
				    && variableIndex >= 0
				    && varmeter != NULL) {
					car(varmeter) = NULL;
					varmeter->flags = 0;
					variableIndex--;
					if (varmchain)
					  varmchain = cddr(varmchain);
				}
				if (*command->shcmdp->name == 'r') { /* ``r''eturn */
#if 0
					std_printf("idx = %d\n", commandIndex);
					if (commandIndex >= 0)
						std_printf("rval %x\n",
							command->rval);
#endif
					goto getout;
				} else {
					command = &commandStack[commandIndex];
					break;
				}
			}
nobreak:
			if (command->prev != NULL
			    || (command->flag & OSCMD_SKIPIT)) {
			  UNGCPROSTORE4( commandStack[commandIndex]. );
				--commandIndex;
			}
			UNGCPROSTORE4( commandStack[commandIndex]. );
			--commandIndex;
#ifdef DEBUGxx
fprintf(stderr,"%s:%d commandIndex=%d\n",__FILE__,__LINE__,commandIndex);
#endif
			/*
			 * If we are returning data, we shouldn't free dtpr
			 * or do a setlevel(), since the value may be used in
			 * parent command.  Eventually a setlevel() will be
			 * done anyway to reclaim space... we hope.
XXX: HERE! Must copy the output to PREVIOUS memory level, then discard
	   the recursed one! <mea@utu.fi> ( command->rval )
			 */
			if (command->memlevel && command->rval == NULL
			    && command->buffer == NULL
			    && command->iocmd != ioIntoBuffer) {
				if (command->pgrp > 0)
					jc_report(command->pgrp);
			}
			if (commandIndex > 0) {
				pcommand = &commandStack[commandIndex];
				while (command->argv != NULL &&
				       pcommand->flag & OSCMD_SKIPIT) {
				  UNGCPROSTORE4( commandStack[commandIndex]. );
				  pcommand = &commandStack[--commandIndex];
				}
#ifdef DEBUGxx
	fprintf(stderr,"%s:%d &pcommand->buffer=%p\n",__FILE__,__LINE__,
		&pcommand->buffer);
#endif
				pcommand->rval = command->rval;
				if (command->buffer != NULL) {
				  GCVARS2;
				  GCPRO2(pcommand->buffer, command->buffer);
					if (command->flag & OSCMD_QUOTEOUTPUT)
						coalesce(command);
					else
						flushwhite(command);
					*(pcommand->bufferp) = command->buffer;
					pcommand->bufferp = command->bufferp;
				  UNGCPRO2;
				}
				command = pcommand;
				if (isset('I'))
					grindef("Command = ", command->argv);
			}
			break;
		case sCommandCarryBuffer:
			command->iocmd = ioCarryBuffer;
			break;
		case sIOopen:
		case sIOopenPortal:
		case sIOopenString:
			if (command->buffer == NULL)
				name = "";
			else if (cdr(command->buffer))
				name = (const char *) (s_catstring(command->buffer))->string;
			else if (command->buffer)
				/* always true, need else below */
				name = (const char *) command->buffer->string;
			else
			/* FALL THROUGH */
		case sIOopenPipe:
			if (cmd == sIOopenPipe) {
				if (ioflags & O_CREAT) {
					if (command->argv == NULL) {
						/* defer dealing with this */
						command->iocmd = ioPipeLater;
						break;
					} else if (command->shcmdp != NULL
						   || command->sfdp != NULL) {
						command->iocmd = ioPipeOutput;
						break;
					}
				} else if (prevcommand != NULL)
					break;
				name = NULL;
			} else		/* continuation of above fallthrough */
			/* FALL THROUGH */
		case sIOdup:
		case sIOclose:
				name = NULL;
			if (cmd == sIOclose)
				ioflags = 0;
			ioop(cmd, command, name, ioflags, defaultfd, arg1);
			break;
		case sIOintoBuffer:
			command->fdmask = 0;
			if (quote) {
				command->flag |= OSCMD_QUOTEOUTPUT;
				quote = 0;
			}
			ib_command[++ibt] = command;
			if (ibt > 20) {
			  fprintf(stderr,"interpret.c: Eccessive nested IOintoBuffer operations; over 20 of them in recursion!\n");
			  abort();
			}
			break;
		case sIOsetIn:
			defaultfd = 0;
			ioflags = O_RDONLY;
			break;
		case sIOsetInOut:
			defaultfd = 0;
			ioflags = O_CREAT|O_RDWR;
			break;
		case sIOsetOut:
			defaultfd = 1;
			ioflags = O_CREAT|O_WRONLY|O_TRUNC;
			break;
		case sIOsetAppend:
			defaultfd = 1;
			ioflags = O_CREAT|O_WRONLY|O_APPEND;
			break;
		case sIOsetDesc:
			defaultfd = atoi((const char *)arg1);
			break;
		case sParameter:
			if (caller != NULL && caller->argv != NULL) {
				int slen;
				l = car(caller->argv);
				if ((d = cdr(l)) != NULL) {
					cdr(l) = cddr(l);
					if (!LIST(d))
						name = (const char *)d->string;
				} else
					name = "";
				if (d != NULL && LIST(d)) {
				  d = copycell(d);
				  cdr(d) = NULL;
				} else {
				  slen = strlen(name);
				  d = newstring(dupnstr(name,slen),slen);
				}
				/* create the variable in the current scope */
				l = car(envarlist);
				cdr(d) = car(l);
				if (*arg1) {
				  slen = strlen(arg1);
#if 0
				  car(l) = newstring(dupnstr(arg1,slen),slen);
#else
				  car(l) = conststring(arg1,slen);
#endif
				} else
				  car(l) = conststring(uBLANK,0);
				cdar(l) = d;

				/* grindef("ARGV = ", caller->argv);
				   grindef("VARS = ", envarlist);
				   grindef("TMPO = ", l);  */
			} else {
				fprintf(stderr, "parameter without call\n");
				abort(); /* parameter without call! */
			}
			break;
		case sAssign:
		case sAssignTemporary:
			if (command->argv == NULL ||
			    cdar(command->argv) == NULL)
				break;
			for (d = caar(command->argv); cdr(d) != NULL; )
				d = cdr(d);
			coalesce(command);
			if (command->buffer == NULL)
			  command->buffer = conststring(uBLANK,0);
			if (nsift >= 0)
			  v_accessed = sift[nsift].accessed;
#if 0
			assign(d, command->buffer,
			       cmd==sAssign ? (struct osCmd *)NULL : command);
#else
			if (cmd == sAssign)
			  assign(d, command->buffer, NULL);
			else
			  assign(d, command->buffer, command);
#endif
			/* do NOT reset *retcodep here */
			command->bufferp = &command->buffer;
			command->argv    = NULL;
			command->shcmdp  = NULL;
			if (isset('I'))
				grindef("Argv = ", command->argv);
			break;
		case sFunction:
			if (isset('I'))
				fprintf(runiofp,
					"defining '%s', entry@ %d, exit@ %d cdp@ %p\n",
					command->buffer->string,
					pc + 1 - code, argi1, cdp);
			defun(cdp, command->buffer->string, pc+1,
			      code + argi1);
			/* FALL THROUGH */
		case sJump:
			pc = code + argi1 - 1;
			break;
		case sBranchOrigin:
			fprintf(stderr, "%s: unpatched branch at %d\n",
					progname, pc - code);
			break;
		case sJumpFork:
			if (command->doio != NULL) {
				RUNIO(command->doio);
				freeio(command->doio, 1);
				command->doio = NULL;
			}
			if ((childpid = fork()) == 0) {
				/* in child */
				dye = 1;
				eocode = code + argi1;
				if (command->execio != NULL) {
					RUNIO(command->execio);
					freeio(command->execio, 0);
					command->execio = NULL;
				}
				command->reaperTop = -1;
				--ibt;
			} else if (childpid > 0) {
				/* in parent */
				while (wait(NULL) != childpid)
					continue;
				pc = code + argi1 - 1;
			} else if (childpid < 0) {
				/* error */
			}
			break;
		case sJumpIfFailure:
			if (*retcodep > 0)
				pc = code + argi1 - 1;
			break;
		case sJumpIfSuccess:
			if (*retcodep == 0)
				pc = code + argi1 - 1;
			break;
		case sJumpIfNilVariable:
			if (variable == NULL || car(variable) == NULL)
				pc = code + argi1 - 1;
			break;
		case sJumpIfMatch:
			if (command->buffer == NULL)
				break;
			if (variable == NULL) {
				variable = conststring(uBLANK,0);
				variable = ncons(variable);
			} else if (car(variable)->string == NULL)
				break;
			globchars['|'] = 1;
			iname = NULL; name = NULL;
			switch (squish(command->buffer,(char**)&name,&iname)) {
			case -1:
				if (STRING(command->buffer)
				    && strcmp(command->buffer->string,
					      car(variable)->string) == 0)
					pc = code + argi1 - 1;
				break;
			case 0:
				if (strcmp(name, car(variable)->string) == 0)
					pc = code + argi1 - 1;
				break;
			case 1:
				i = 0;
				do {
					int fi = i;
					while (iname[i] != 0
					    && iname[i] != (u_int)'|')
						++i;
					if (glob_match(&iname[fi], &iname[i],
						      car(variable)->string)) {
						pc = code + argi1 - 1;
						break;
					}
				} while (iname[i++] != 0);
				break;
			}
			if (iname) free(iname);
			globchars['|'] = 0;
			break;
		case sJumpIfFindVarNil:
			if (command->buffer == NULL)
				d = conststring(uBLANK,0);
			else if (cdr(command->buffer))
				d = s_catstring(command->buffer);
			else
				d = command->buffer;
			d = v_expand(d->string, caller, *retcodep);
			if (d == NULL)
				pc = code + argi1 - 1;
			break;
		case sJumpIfOrValueNil:
			if (d == NULL
			    || (cdr(d) != NULL && (d = cdr(d)) == NULL)
			    || (STRING(d)
				&& (d->string == NULL || *d->string == '\0'))
			    || (LIST(d) && car(d) == NULL))
				pc = code + argi1 - 1;
			break;
		case sJumpLoopBreak:
			loop[nloop].brk = argi1;
			break;
		case sJumpLoopContinue:
			loop[nloop].cont = argi1;
			break;
		case sLoopEnter:
			++nloop;
			if (nloop >= LOOPMAXDEPTH) {
			  fprintf(stderr,"%s: interpret.c: sLoopEnter once too many times, max depth: %d\n",
				  progname, LOOPMAXDEPTH);
			  abort(); /* sLoopEnter too deep! */
			}
			loop[nloop].cont = 0;
			loop[nloop].brk = 0;
			loop[nloop].cmdindex = commandIndex;
			loop[nloop].varindex = variableIndex;
			if (prevcommand != NULL) {
				prevcommand->next = command;
				prevcommand->reaperTop = reapableTop;
				/* create stringbuffer */
				name = NULL;
				INSERTIO(&prevcommand->doio,
					 prevcommand,
					 sIObufOut, 1, 1, 0);
				/* --- */
				RUNIO(prevcommand->doio);
				freeio(prevcommand->doio, 1);
				prevcommand->doio = NULL;
				/* --- */
				INSERTIO(&command->doio,
					 command,
					 sIObufIn, 0, 1, 0);
				INSERTIO(&command->undoio,
					 command,
					 sIObufFree, 0, 0, 0);
				/*
				 * ... else we're connecting two
				 * list-valued functions, which is ok.
				 */
				cmdname = NULL;
				if (prevcommand->sfdp)
				  cmdname = prevcommand->sfdp->name;
				if (prevcommand->shcmdp)
				  cmdname = prevcommand->shcmdp->name;
				runcommand(prevcommand, caller,
					   ignore_level > commandIndex ?
					   retcodep : NULL, cmdname);
				command->rval = prevcommand->rval;
				if (command->prev == prevcommand)
					command->prev = NULL;
				free((char *)prevcommand);
				prevcommand = NULL;
				/* X:shouldn't prevcommand be stacked?*/
			}
			break;
		case sLoopExit:
			if (nloop >= 0)
				--nloop;
			break;
		case sLocalVariable:
			/* create the variable in the current scope */
			d = NIL;
			{
			  int slen = strlen(arg1);
#if 0
			  tmp = newstring(dupnstr(arg1,slen),slen); /* must allocate a fresh! */
#else
			  tmp = conststring(arg1, slen);
#endif
			}
			cdr(d) = caar(envarlist);
			cdr(tmp) = d;
			caar(envarlist) = tmp;
			if (isset('I'))
				grindef("Scopes = ", envarlist);
			break;
		case sScopePush:
			d = NIL;
			s_push(d, envarlist);
			/* fvcache.namesymbol = 0; */
			break;
		case sScopePop:
			d = car(envarlist);
			car(envarlist) = cdar(envarlist);
			cdr(d) = NULL;
			/*s_free_tree(d);*/
			/* fvcache.namesymbol = 0; */
			break;
		case sDollarExpand:
			dollar = 1;
			break;
		case sBufferQuote:
			quote = 1;
			break;
		case sBackground:
			/*
			 * 1. tell child and pipeline commands to background.
			 * 2. find place to stash pid of this command for pgrp.
			 * 3. call hook when this command finishes to print
			 *    pids of all commands and job number.
			 */
			command->pgrpp = &command->pgrp;
			break;
		case sPrintAndExit:
			if (command->buffer == NULL)
				d = conststring(uBLANK,0);
			else if (cdr(command->buffer))
				d = s_catstring(command->buffer);
			else
				d = command->buffer;
			fprintf(stderr, "%s: %s\n", progname,
					*(d->string) == '\0' ?
					"parameter null or not set"
					: d->string);
			if (!isset('i'))
				trapexit(1);
			break;
#ifdef	MAILER
/* String RegExpressions */

		case sSiftPush:
			v_record = 1;
			if (nsift >= 0)
				sift[nsift].program = re;
			if (++nsift >= (sizeof sift / sizeof sift[0])) {
				fprintf(stderr,"%s: sSiftPush more than %d times allowed by the interpret.c code\n",
					progname, nsift-1);
				abort(); /* Too deep SIFTs! */
			}
			sift[nsift].kind  = 0;
			sift[nsift].str = NULL;
			sift[nsift].label = pc+1 - code;
			sift[nsift].subexps = NULL;
			sift[nsift].count = 9999; /* Cut eternal loops */
			v_accessed = NULL;
			break;
		case sSiftBody:
			if (sift[nsift].str)
			       free((void*)sift[nsift].str);
			sift[nsift].str = NULL;
			if (command->buffer != NULL) {
				if (cdr(command->buffer))
					d = s_catstring(command->buffer);
				else
					d = command->buffer;
				if (STRING(d)) {
					sift[nsift].str = dequote(d->cstring, d->slen);
				}
			}
			sift[nsift].accessed = v_accessed;  /* nop 2nd time */
			if (v_record == 0)	/* we've been here before */
				pc = code + loop[nloop].cont - 1;
			else
				v_record = 0;
			v_changed = 0;
			break;
		case sSiftCompileRegexp:
			if (argi1) {
				re = cdp->rearray[argi1-1];
#if 0
std_printf("found %x at %d\n", re, argi1-1);
#endif
				break;
			}
			re = NULL;
			if (command->buffer != NULL) {
				if (cdr(command->buffer)) {
					/* stickytmp = stickymem;
					   stickymem = MEM_PERM; */
					d = s_catstring(command->buffer);
					/* stickymem = stickytmp; */
				} else
					d = command->buffer;
				if (STRING(d))
					re = reg_comp(d->string, d->slen);
			}
			if (re == NULL)
				break;
			if (cdp->rearray_size == 0) {
#define	RECLICK 25
				cdp->rearray_size = RECLICK;
				cdp->rearray = (regexp **)
					emalloc(RECLICK*sizeof(regexp *));
			} else if (cdp->rearray_idx >= cdp->rearray_size-2) {
				/* 1 spare */
				cdp->rearray_size *= 2;
				cdp->rearray =
					(regexp **)erealloc((char*)cdp->rearray,
							    cdp->rearray_size *
							    sizeof(regexp *));
			}
			cdp->rearray[++cdp->rearray_idx] = re;
#if 0
std_printf("set %x at %d\n", re, cdp->rearray_idx);
#endif

			/* NB! we are writing into the table */
			++cdp->rearray_idx;
			*(char*)(pc-3) = (cdp->rearray_idx >> 24) & 0xff;
			*(char*)(pc-2) = (cdp->rearray_idx >> 16) & 0xff;
			*(char*)(pc-1) = (cdp->rearray_idx >>  8) & 0xff;
			*(char*)(pc  ) =  cdp->rearray_idx        & 0xff;
			--cdp->rearray_idx;
			break;
		case sSiftReevaluate:
			if (v_changed)
				/* jump to sift expression evaluation
				   followed by sSiftBody */
				pc = sift[nsift].label - 1 + code;
			break;
		case sSiftPop:
			if (sift[nsift].str)
			       free((void*)sift[nsift].str);
			for (v_accessed = sift[nsift].accessed;
			     v_accessed != NULL;
			     v_accessed = sift[nsift].accessed) {
				sift[nsift].accessed = v_accessed->next;
				free((char *)v_accessed);
			}
			--nsift;
			if (nsift >= 0) {
				v_accessed = sift[nsift].accessed;
				re = sift[nsift].program;
			}
			break;
		case sSiftBufferAppend:
			if (sift[nsift].kind == 0) { /* StringSift.. */
			  if (arg1 == NULL || re == NULL ||
			      !isdigit((*arg1)&0xFF))
			    break;
			  if (nsift > 0 && sift[nsift].subexps == NULL)
			    setsubexps(&sift[nsift-1].subexps, re);
			  else
			    setsubexps(&sift[nsift].subexps, re);
			  arg1 = regsub(re, atoi(arg1));
			  if (arg1 != NULL) {
			    int slen = strlen(arg1);
#if 0
			    tmp = conststring(arg1,slen);
#else
			    tmp = newstring(dupnstr(arg1,slen),slen);
#endif
			    tmp->flags |= QUOTEDSTRING;
			    /* cdr(tmp) = command->buffer; */
			    *command->bufferp = tmp;
			    command->bufferp = &cdr(tmp);
			  }
			} else { /* TokenSift */
			  if (arg1 == NULL || tre == NULL ||
			      !isdigit((*arg1)&0xFF))
			    break;
			  if (nsift > 0 && sift[nsift].subexps == NULL)
			    tsetsubexps(&sift[nsift-1].subexps, tre);
			  else
			    tsetsubexps(&sift[nsift].subexps, tre);
			  arg1 = (const char *)tregsub(tre, atoi(arg1));
			  if (arg1 != NULL) {
			    int slen = strlen(arg1);
			    tmp = newstring(arg1,slen);
			    tmp->flags |= QUOTEDSTRING;
			    /* cdr(tmp) = command->buffer; */
			    *command->bufferp = tmp;
			    command->bufferp = &cdr(tmp);
			  }
			}
			break;
		case sJumpIfRegmatch:
			stickytmp = stickymem;
			stickymem = MEM_PERM;
			if (sift[nsift].str == NULL)
				sift[nsift].str = strsave("");
			stickymem = stickytmp;
			setsubexps(&sift[nsift].subexps, re);
			if ((sift[nsift].count >= 0) &&
			    !reg_exec(re, sift[nsift].str))
				pc = code + argi1 - 1;
			sift[nsift].count -= 1;
			break;

/* Token RegExpressions: */

		case sTSiftPush:
			v_record = 1;
			if (nsift >= 0)
				sift[nsift].program = (regexp *)tre;
			if (++nsift >= (sizeof sift / sizeof sift[0])) {
				fprintf(stderr,"%s: sTSiftPush more than %d times allowed by the interpret.c code\n",
					progname, nsift-1);
				abort(); /* Too deep TSIFT! */
			}
			sift[nsift].kind  = 1;
			sift[nsift].tlist = NULL;
			sift[nsift].label = pc+1 - code;
			sift[nsift].subexps = NULL;
			sift[nsift].count = 9999; /* Cut eternal loops */
			v_accessed = NULL;
			break;
		case sTSiftBody:
			/* we don't *need* to free tokens because they are
			   allocated off our MEM_SHCMD memory stack */
			if (sift[nsift].tlist)
				freeTokens(sift[nsift].tlist, MEM_SHCMD);
			sift[nsift].tlist = NULL;
			if (command->buffer != NULL) {
				if (cdr(command->buffer))
					d = s_catstring(command->buffer);
				else
					d = command->buffer;
				if (STRING(d)) {
					arg1 = (const char *) d->string;
					sift[nsift].tlist = tscanstring(arg1);
				}
			}
			sift[nsift].accessed = v_accessed;  /* nop 2nd time */
			if (v_record == 0)	/* we've been here before */
				pc = code + loop[nloop].cont - 1;
			else
				v_record = 0;
			v_changed = 0;
			break;
		case sTSiftCompileRegexp:
			if (argi1) {
			  tre = cdp->trearray[argi1-1];
#if 0
std_printf("found %x at %d\n", tre, argi1-1);
#endif
			  break;
			}
			tre = NULL;
			if (command->buffer != NULL) {
			  if (cdr(command->buffer)) {
			    d = s_catstring(command->buffer);
			  } else
			    d = command->buffer;
			  if (STRING(d))
			    tre = tregcomp(d->string);
			}
			if (tre == NULL)
			  break;
			if (cdp->trearray_size == 0) {
			  cdp->trearray_size = RECLICK;
			  cdp->trearray = (tregexp **)
			    emalloc(RECLICK*sizeof(tregexp *));
			} else if (cdp->trearray_idx >= cdp->trearray_size-2) {
			  /* 1 spare */
			  cdp->trearray_size *= 2;
			  cdp->trearray =
			    (tregexp **)erealloc((char*)cdp->trearray,
						 cdp->trearray_size *
						 sizeof(tregexp *));
			}
			cdp->trearray[++cdp->trearray_idx] = tre;
#if 0
std_printf("set %x at %d\n", tre, cdp->trearray_idx);
#endif

			/* NB! we are writing into the table */
			++cdp->trearray_idx;
			*(char*)(pc-3) = (cdp->trearray_idx >> 24) & 0xff;
			*(char*)(pc-2) = (cdp->trearray_idx >> 16) & 0xff;
			*(char*)(pc-1) = (cdp->trearray_idx >>  8) & 0xff;
			*(char*)(pc  ) =  cdp->trearray_idx        & 0xff;
			--cdp->trearray_idx;
			break;
		case sTSiftReevaluate:
			if (v_changed)
				/* jump to sift expression evaluation
				   followed by sTSiftBody */
				pc = sift[nsift].label-1 + code;
			break;
		case sTSiftPop:
			/* see comment above about freeing tokens */
			if (sift[nsift].tlist)
				freeTokens(sift[nsift].tlist, MEM_SHCMD);
			for (v_accessed = sift[nsift].accessed;
			     v_accessed != NULL;
			     v_accessed = sift[nsift].accessed) {
				sift[nsift].accessed = v_accessed->next;
				free((char *)v_accessed);
			}
			--nsift;
			if (nsift >= 0) {
				v_accessed = sift[nsift].accessed;
				tre = (tregexp *)sift[nsift].program;
			}
			break;
#if 0 /* wrong place.. */
		case sTSiftBufferAppend:
			if (arg1 == NULL || tre == NULL || !isdigit(*arg1))
				break;
			if (nsift > 0 && sift[nsift].subexps == NULL)
				tsetsubexps(&sift[nsift-1].subexps, tre);
			else
				tsetsubexps(&sift[nsift].subexps, tre);
			if ((arg1 = tregsub(tre,atoi(arg1))) != NULL) {
				int slen = strlen(arg1);
#if 0
				tmp = coststring(arg1, slen);
#else
				tmp = newstring(dupnstr(arg1,slen),slen);
#endif
				tmp->flags |= QUOTEDSTRING;
				/* cdr(tmp) = command->buffer; */
				*command->bufferp = tmp;
				command->bufferp = &cdr(tmp);
			}
			break;
#endif
		case sTJumpIfRegmatch:
			if (sift[nsift].tlist == NULL)
			  sift[nsift].tlist = makeToken(uBLANK, 0);
			tsetsubexps(&sift[nsift].subexps, tre);
			if ((sift[nsift].count >= 0) &&
			    !tregexec(tre, sift[nsift].tlist))
				pc = code + argi1 - 1;
			sift[nsift].count -= 1;
			break;

#endif	/* MAILER */
		default:
			fprintf(stderr,
				"Hey, you forgot to update the interpreter!\n");
			fprintf(stderr,
				"Illegal command token %d\n", (int)cmd);
			if (!isset('i'))
				exit(1);
			break;
		}
	}
getout:
	if (dye /* I know this is misspelled */)
		trapexit(0);
	if (isset('I'))
		grindef("Vars = ", envarlist);
	/* null any loop variable values so we can free scopes below */
	while (variableIndex > -1) {
		if (varmeter) {
			car(varmeter) = NULL;
			varmeter->flags = 0;
		}
		if (varmchain) {
		  variable = car(varmchain);
		  varmeter = cadr(varmchain);
		  varmchain = cddr(varmchain);
		} else
		  variable = varmeter = NULL;
		if (isset('I'))
		  grindef("Variable = ", variable);
		--variableIndex;
	}
	while (nsift >= 0) {
		for (v_accessed = sift[nsift].accessed;
		     v_accessed != NULL;
		     v_accessed = sift[nsift].accessed) {
			sift[nsift].accessed = v_accessed->next;
			free((char *)v_accessed);
		}
		--nsift;
	}
	while (commandIndex > 0) {
		pcommand = &commandStack[commandIndex];
		if (pcommand->undoio) {
			RUNIO(pcommand->undoio);
			freeio(pcommand->undoio, 1);
		}
		/* The setlevel is done below */

		/* XX: Now we free them in cases where the command
		   has no return value to be cared for ! */
		if (command->rval == NULL || caller == NULL)
		  setlevel(MEM_SHCMD, pcommand->memlevel);

		/* Can do without UNGCPROSTORE here, as we do
		   a larger scope UNGCPRO below.. */
		UNGCPROSTORE4( commandStack[commandIndex]. );
		--commandIndex;
	}

	setlevel(MEM_SHCMD, origlevel);

#ifdef	MAILER
	/*
	 * This is pretty dicey; we rely on setlevel() not changing the
	 * stuff that was just freed.  We need to do this to avoid
	 * malloc'ing stuff unnecessarily.  For example we usually just
	 * want to access the return value in the context of the caller.
	 */
	if (command->rval != NULL && caller != NULL) {
		caller->rval = command->rval;
	}
#endif

	while (margin != car(envarlist)) {
		d = car(envarlist);
		car(envarlist) = cdr(d);
		cdr(d) = NULL;
		/*s_free_tree(d);*/
	}
	stickymem = origstickymem;
#ifdef	MAILER
	--funclevel;
#endif	/* MAILER */

	commandIndex = 0; /* Should be already, in fact.. */
	UNGCPROSTORE4( commandStack[commandIndex]. );

	if (cdp->functions == NULL) {
		if (cdp->rearray != NULL) {
			while (cdp->rearray_idx >= 0)
				free_regexp(cdp->rearray[cdp->rearray_idx--]);
			free((char *)cdp->rearray);
		}
		if (cdp->trearray != NULL) {
			while (cdp->trearray_idx >= 0)
				free((void *)cdp->trearray[cdp->trearray_idx--]);
			free((void *)cdp->trearray);
		}
		free((void *)cdp->table);
		free((void *)cdp);
		UNGCPRO6;
		return NULL;
	}
	cdp->oktofree = 1;

	UNGCPRO6;

	return cdp;
}


/*
 * Doing an apply() outside the interpreter() is only a safe thing to do
 * when outside the interpreter (...), i.e. at interactive prompt level.
 * We want to call an arbitrary shell or builtin function with some number
 * of (string) arguments.
 */

STATIC int fapply __((struct shCmd *, conscell *));
STATIC int
fapply(shcmdp, l)
	struct shCmd *shcmdp;
	conscell *l;
{
	register conscell *ll;
	int argc = 0;
#define FARGCMAX 30
	const char *argv[FARGCMAX]; /* XX: argc never to exceed magic number */

	if (shcmdp->sptr != NULL) {
		argv[argc++] = shcmdp->name;
		for (ll = car(l); ll != NULL && argc < FARGCMAX-1; ll = cdr(ll)) {
			if (STRING(ll))
				argv[argc++] = ll->string;
		}
		argv[argc] = NULL;
		return (*(shcmdp->sptr))(argc, argv);
	}
	/* XX: we don't need to support this, yet */
	/* else if (shcmdp->lptr != NULL) {
		return -1;
	} */
	return -1;
}

int
lapply(fname, l)
	const char *fname;
	conscell *l;
{
	int retcode = -123456;
	struct sslfuncdef *sfdp;
	struct spblk *spl;
	struct osCmd avc;
	conscell *ll, *tmp;
	spkey_t spkey;
	GCVARS4;

#ifdef DEBUG
	if (D_functions) {
	  fprintf(stderr, "%*slapply('%s', (", 4*funclevel, " ", fname);
	  ll = l;
	  while (ll) {
	    fprintf(stderr,"'");
	    s_grind(ll, stderr);
	    ll = cdr(ll);
	    if (ll)
	      fprintf(stderr,"', ");
	    else
	      fprintf(stderr,"'");
	  }
	  fprintf(stderr, "))\n");
	  fflush(stderr);
	}
#endif

	spkey = symbol_lookup(fname);
	spl = NULL;
	if (!spkey)
	  return -1;
	spl = sp_lookup(spkey, spt_funclist);
	if (spl == NULL) {
		spl = sp_lookup(spkey, spt_builtins);
		if (spl == NULL)
			return -1;
		/* Non conscell input parameters to the target
		   function, no conscell creates while calling it. */
		return fapply((struct shCmd *)spl->data, l);
	}
	sfdp = (struct sslfuncdef *)spl->data;
	if (sfdp == NULL)
		return -1;
	avc = avcmd;
	ll = tmp = NULL;
	GCPRO4(ll, l, avc.argv, avc.rval);
	if (l != NULL) {
		int slen = strlen(fname);
		ll = newstring(dupnstr(fname,slen),slen);
		/* Sometimes could do without strdup(),
		   but often not... :-/ */
		cdr(ll) = car(l);
		car(l) = ll;
		avc.argv = l;
	}

	interpret(sfdp->tabledesc->table,
		  sfdp->eot, sfdp->pos,
		  &avc, &retcode, sfdp->tabledesc);
	UNGCPRO4;
	if (return_valuep != NULL) {
		*return_valuep = avc.rval;
	}
	avc.rval = NULL;
	return retcode;
}

int
apply(argc, argv)
	int argc;
	const char *argv[];
{
	conscell *args = NULL;
	int rc;
	GCVARS1;

	/* if argc == 0, don't change avc.argv even if there are arguments */
	if (argc > 1)
	  args = s_listify(argc-1, &argv[1]);
	GCPRO1(args);
	rc = lapply(argv[0], args);
	UNGCPRO1;
	return rc;
}


/*
 * A cheap way of calling (e.g.) prompt-generating functions without
 * having to set up argv lists and such.  Same restrictions as apply().
 */

int
funcall(fname)
	const char *fname;
{
	const char *av[1];

	av[0] = fname;
	return apply(0, &av[0]);
}
