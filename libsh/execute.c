/*
 *	Copyright 1989 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * Runtime execution and I/O control.
 */
#include "hostenv.h"
#ifdef	MAILER
#include "sift.h"	/* Include this BEFORE "mailer.h" ! */
#endif	/* MAILER */
#include <ctype.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "mailer.h"
#include "zmsignal.h"

#include "zsyslog.h"
extern int z_isterminal __((const int fd));

/* #define static
  #define register */
#define RUNIO(X)	(/*fprintf(runiofp, "runio(%s,%d)\n", __FILE__, __LINE__), */runio(&X))


#include "interpret.h"
#include "io.h"
#include "shconfig.h"

#include "libsh.h"


#ifdef  HAVE_WAITPID
# include <sys/wait.h>
#else
# ifdef HAVE_WAIT3
#  include <sys/wait.h> /* Has BSD wait3() */
# else
#  ifdef HAVE_SYS_WAIT_H /* POSIX.1 compatible */
#   include <sys/wait.h>
#  else /* Not POSIX.1 compatible, lets fake it.. */
extern int wait();
#  endif
# endif
#endif

#ifndef WEXITSTATUS
# define WEXITSTATUS(s) (((s) >> 8) & 0377)
#endif
#ifndef WSIGNALSTATUS
# define WSIGNALSTATUS(s) ((s) & 0177)
#endif

#ifndef	SIGCHLD
#define	SIGCHLD	SIGCLD
#endif	/* SIGCHLD */

/* The parent function of whatever is about to be executed, for $@ access */

struct osCmd *globalcaller = NULL;

/* Default file mode for open() (output redirection) */

int smask = DEFAULT_OPEN_MASK;

/*
 * When we need to run an independent process to feed data, we do a
 * double detach using the following macros.
 */

#define	BEGINGRANDCHILD(P)	if ((P = fork()) == 0) {	/* child */\
					/* detach completely from parent */\
					if ((P = fork()) == 0) {\
						/* grandchild */

#define	ENDGRANDCHILD(P)			_exit(0);\
					} else if (P < 0)\
						perror("fork");\
					_exit(0);\
				} else if (P > 0) { \
					int sTaTuS; /* reap the child */ \
					wait(&sTaTuS); \
				} else

typedef int status_t;

int reapableTop = 0;			/* top of stack of repable processes */
STATIC int reapable[MAXNPROC];		/* stack of reapable process ids */
STATIC status_t reapstatus;		/* status of last reaped process */

/*
 * SIGCHLD signal handler; it maintains the list of outstanding child
 * processes.  The reapstatus is only updated if the very last process
 * (sort of top of stack) returned.  This has to do with the requirement
 * for exit status of a pipeline.
 */

STATIC void reapchild __((int));
STATIC void
reapchild(sig)
int sig;
{
	status_t status;
	register int i, pid;

	pid = wait(&status);
	for (i = 0; i < reapableTop; ++i) {
		if (reapable[i] == pid) {
			--reapableTop;
			if (i == reapableTop) {
				reapstatus = status;
			} else {
				while (i < reapableTop) {
					reapable[i] = reapable[i+1];
					++i;
				}
			}
		}
	}
}

STATIC int bgsetup __((struct osCmd *));
STATIC int
bgsetup(c)
	struct osCmd *c;
{
	int fd;

	SIGNAL_IGNORE(SIGINT);			/* ignore interrupt	*/
	SIGNAL_IGNORE(SIGQUIT);			/* ignore quit		*/
	if (!(c->fdmask & 1)) {			/* /dev/null is default input */
		fd = open("/dev/null", O_RDONLY, 0);
		if (fd > 0) {
			dup2(fd, 0/* stdin */);
			close(fd);
		}
	}
	return 0;
}

/*
 * All function executions pass through here.  The environment is set up
 * and appropriate I/O manipulations controlled, and status code retrieved
 * and returned as the value of the execute() function.
 */

int
execute(c, caller, oretcode, name)
	struct osCmd	*c,		/* function we are about to execute */
			*caller;	/* the function we are currently in */
	int		oretcode;	/* default value for return code */
	const char	*name;		/* Redundant function name info */
{
	int ac = 0;			/* argument count in av[] */
	const char **av = NULL;		/* argument vector, with ac entries */
	struct sslfuncdef *sfdp;	/* defined function descriptor */
	int pid;			/* process id of child (unix program) */
	int retcode;			/* the new integer-valued return code */
	int nofork;			/* flag: don't fork shell before exec */
	status_t status;		/* return code from wait() */
	int n;
	RETSIGTYPE (*oquit_handler) __((int)),
	  (*oint_handler) __((int)),
	  (*oterm_handler) __((int));
	RETSIGTYPE (*ochld_handler) __((int));
	conscell *sl, *l, *tmp;

	GCVARS3;

	status = 0;

	sl = l = tmp = NULL;
	GCPRO3(sl, l, tmp); /* 'osCmd c' related conscells are caller
			       protected */

	ochld_handler = SIG_DFL;
	globalcaller = caller;
	ac = 0;
	nofork = 0;
	sfdp = NULL;
	if (c->shcmdp != NULL && c->shcmdp->sptr == sh_builtin) {
		car(c->argv) = cdar(c->argv);
		if (car(c->argv) == NULL || LIST(car(c->argv)))
			c->argv = NULL;
		else
			functype(car(c->argv)->cstring, &c->shcmdp, NULL);
	}
	if (c->argv && LIST(c->argv) && STRING(car(c->argv))) {
		/* there are string arguments */
		if (isset('I')||isset('J')) {
			grindef("Command = ", c->argv);
			fprintf(runiofp, "Run:");
		}
		if (c->shcmdp == NULL) {
			functype((car(c->argv))->cstring, NULL, &sfdp);
			if (sfdp == NULL)
				path_hash((car(c->argv))->string);
		}
		if ((c->shcmdp == NULL && sfdp == NULL)
		    || (c->shcmdp != NULL && c->shcmdp->sptr != NULL)) {
			/*
			 * It must be an external command, or an internal
			 * command that takes (argc, argv), so assemble
			 * the argv[] array now.
			 */
			/* first count how many arguments we got */
			ac = 1;		/* trailing NULL */
			for (sl = car(c->argv); sl != NULL; sl = cdr(sl))
				if (STRING(sl))
					ac++;
			/* allocate space */
			/* This lifetime seems to be longish, too early free
			   leads to "mysterious" crashes */
#ifdef USE_ALLOCA
			av = (const char **)alloca(ac * sizeof (char *));
#else
			av = (const char **)malloc(ac * sizeof (char *));
#endif
			/* set them up */
			ac = 0;
			for (sl = car(c->argv); sl != NULL; sl = cdr(sl)) {
			  if (STRING(sl))
			    av[ac++] = (char *)sl->string;
			}
			if (isset('I')) {
			  for (sl = car(c->argv); sl != NULL; sl = cdr(sl)) {
			    if (STRING(sl)) {
			      putc(' ', runiofp);
			      s_grind(sl, runiofp);
			    }
			  }
			}
			av[ac] = NULL;
			if (av[0][0] == 'e' && strcmp(av[0], "exec") == 0) {
				--ac, ++av;
				if (ac == 0 && c->doio)
					c->undoio = NULL;
				nofork = 1;
			}
		} else if (isset('I'))
			s_grind(c->argv, runiofp);
		if (isset('I'))
			putc('\n', runiofp);
	} else {
		/*
		 * There is no command, so the "temporary" environment
		 * variable settings should be kept.
		 */
		/* if (c->envold != NULL)
		   s_free_tree(c->envold); */
		c->envold = NULL;
		sfdp = NULL;
	}
	/*
	 * These are needed so builtins that write to stdout/err don't stomp
	 * on previous data.  Notice also the flushes below.
	 */
	fflush(stdout); fflush(stderr);

	sl = c->rval;
	c->rval = NULL;
#define	NO_RETCODE	-12345		/* anything < -128 or > 255 */
	retcode = NO_RETCODE;

	if (c->doio && RUNIO(c->doio))
		/*fprintf(stderr, "%s: runio(doio) failed\n", progname)*/;
	else if ((c->pgrpp != NULL && (c->shcmdp != NULL || sfdp != NULL)) &&
		 /* we have a builtin command that should be backgrounded */
		 ((pid = fork()) != 0	/* if in parent, do if stmt body */
		  || (setopt('t', 1), bgsetup(c)))) {
		 /* in parent, set up process group leader */
		 jc_newproc(c->pgrpp, pid, ac, av);
	} else if (c->shcmdp != NULL) {
		/*
		 * Builtin command
		 */
		if (c->shcmdp->lptr != NULL ||
		    c->shcmdp->rptr != NULL) {
			/*
			 * List-valued builtin
			 */
			*((int *)&status) = 0;
			if (c->prev == NULL || c->prev->shcmdp->sptr != NULL) {
				/* translate stdin into a list argument */
				if (c->shcmdp->flag & SH_STDIN)
					sl = s_read(stdin);
			}
			if (isset('x')) {
				fprintf(stderr,"+ %s ", c->shcmdp->name);
				s_grind(c->argv, stderr);
				putc(' ', stderr);
				s_grind(sl, stderr);
				putc('\n', stderr);
				fflush(stderr);
			}
#ifdef	MAILER
			if (D_functions) {
				fprintf(stderr, "%*s%s ", 4*funclevel, " ",
						c->shcmdp->name);
				s_grind(c->argv, stderr);
				fputc(' ', stderr);
				s_grind(sl, stderr);
				fputc('\n', stderr);
				fflush(stderr);
			}
#endif	/* MAILER */
			if (c->shcmdp->rptr != NULL)
			  c->rval = (c->shcmdp->rptr)(c->argv, sl, &retcode);
			else
			  c->rval = (c->shcmdp->lptr)(c->argv, sl);
			/* it's important that c->rval is NOT permanent mem. */
			if (retcode == NO_RETCODE)
				retcode = (c->rval == NULL);
			if (isset('t'))
				trapexit(retcode);
			if (c->flag & OSCMD_QUOTEOUTPUT) {
				for (tmp = c->rval; tmp != NULL; tmp = cdr(tmp))
					if (STRING(tmp))
						tmp->flags |= QUOTEDSTRING;
			}
			if (c->next != NULL &&
			    (c->next->shcmdp->lptr != NULL ||
			     c->next->shcmdp->rptr != NULL)  ) {
				;/* next command takes list input, keep mum! */
			} else if ((c->fdmask & (1<<1)) && _FILEIO(stdout)) {
				/* stdout is a pipe to another command */
				BEGINGRANDCHILD(pid)
				while (c->rval != NULL) {
					s_grind(c->rval, stdout);
					if ((c->rval = cdr(c->rval)))
						putchar(' ');
					else
						break;
				}
				putchar('\n');
				ENDGRANDCHILD(pid) {
					perror("fork");
				}
				c->rval = 0;
			} else if (1
#ifdef	MAILER
				&& return_valuep == NULL && c->rval != NULL
#endif	/* MAILER */
				) {
				/*
				 * There is a potential deadlock here if this
				 * code is executed instead of the detached
				 * write above, if we are sending data through
				 * a pipe to an internal function, e.g.
				 *	( builtincmd ) | builtincmd
				 * I don't think the general case (think about
				 * control flow) is solvable.
				 */
				tmp = c->rval;
				while (c->rval != NULL) {
					s_grind(c->rval, stdout);
					if ((c->rval = cdr(c->rval)))
						putchar(' ');
					else
						break;
				}
				putchar('\n');
				/* assert c->rval = 0; */
				c->rval = tmp;
			}
#if 0
			else if (c->rval != NULL) {
				fprintf(stderr, "rval = ");
				_grind(c->rval);
			}
#endif
		} else if (c->shcmdp->sptr != NULL) {
			/*
			 * Normal argc,argv builtin command
			 */
			if (isset('x')) {
				putc('+',stderr);
				for (n = 0; n < ac; ++n)
					fprintf(stderr," %s", av[n]);
				putc('\n',stderr);
				fflush(stderr);
			}
#ifdef	MAILER
			if (D_functions) {
				fprintf(stderr, "%*s%s", 4*funclevel, " ",
						av[0]);
				for (n = 1; n < ac; ++n)
					fprintf(stderr, " %s", av[n]);
				fputc('\n', stderr);
				fflush(stderr);
			}
#endif	/* MAILER */
			retcode = (c->shcmdp->sptr)(ac, av);
			fflush(stdout); fflush(stderr);
			if (isset('t'))
				trapexit(retcode);
		}
		if (interrupted)
			putchar('\n');
	} else if (sfdp != NULL) {
		/*
		 * Defined function
		 */
		if (isset('x')) {
			putc('+', stderr);
			for (tmp = car(c->argv); tmp != NULL; tmp = cdr(tmp))
				putc(' ', stderr), s_grind(tmp, stderr);
			putc('\n', stderr);
			fflush(stderr);
		}
#ifdef	MAILER
		if (D_functions) {
			fprintf(stderr, "%*s", 4*funclevel, " ");
			for (tmp = car(c->argv); tmp != NULL; tmp = cdr(tmp)) {
				if (tmp != car(c->argv))
					fputc(' ', stderr);
				s_grind(tmp, stderr);
			}
			fputc('\n', stderr);
			fflush(stderr);
		}
#endif	/* MAILER */
		interpret(sfdp->tabledesc->table,
			  sfdp->eot, sfdp->pos, c, &retcode,
			  sfdp->tabledesc);
		if (isset('t'))
			trapexit(retcode);
		if (interrupted)
			putchar('\n');
	} else if (ac == 0) {
		/*
		 * I/O side-effects are the raison d'etre
		 */
		retcode = oretcode;
		c->rval = sl;
		if (nofork && c->execio)
			RUNIO(c->execio);
	} else if (nofork || (pid = fork()) == 0) {
		/*
		 * Unix program (child of shell)
		 */
		if (isset('x')) {
			putc('+', stderr);
			for (n = 0; n < ac; ++n)
				fprintf(stderr," %s", av[n]);
			putc('\n',stderr);
			fflush(stderr);
		}
#ifdef	MAILER
		if (D_functions) {
			fprintf(stderr, "%*s%s", 4*funclevel, " ", av[0]);
			for (n = 1; n < ac; ++n)
				fprintf(stderr, " %s", av[n]);
			fputc('\n', stderr);
			fflush(stderr);
		}
#endif	/* MAILER */
		if (!nofork && c->execio && RUNIO(c->execio)) {
			if (c->undoio)
				RUNIO(c->undoio);
			fprintf(stderr, "%s: runio(execio) failed\n", progname);
			if (!nofork)
				_exit(1);
		}
		/*
		 * Any temporary variable assignments may have been done
		 * to non-exported variables, they must be exported to
		 * retain semantics of NAME=value program.
		 */
		for (sl = c->envold; sl != NULL; sl = cddr(sl))
			v_export(sl->string);

		if (c->pgrpp != NULL)
			bgsetup(c);
		/*
		 * We restore original signal handlers unless if we are
		 * explicitly ignoring the signal in question.
		 */
		SIGNAL_HANDLESAVE(SIGTERM,orig_handler[SIGTERM],oterm_handler);
		if (oterm_handler == SIG_IGN && orig_handler[SIGTERM]!=SIG_IGN)
			SIGNAL_IGNORE(SIGTERM);
		SIGNAL_HANDLESAVE(SIGINT,orig_handler[SIGINT],oint_handler);
		if (oint_handler == SIG_IGN && orig_handler[SIGINT] != SIG_IGN)
			SIGNAL_IGNORE(SIGINT);
		SIGNAL_HANDLESAVE(SIGQUIT,orig_handler[SIGQUIT],oquit_handler);
		if (oquit_handler == SIG_IGN && orig_handler[SIGQUIT]!=SIG_IGN)
			SIGNAL_IGNORE(SIGQUIT);
		/*
		 * Go fish
		 */
		execvp(av[0], (char *const*)av);

		if (!nofork && c->undoio)
			RUNIO(c->undoio);
		fprintf(stderr, "%s: %s\n", av[0], NOT_FOUND);
		if (!z_isterminal(0))
		  zsyslog((LOG_EMERG, "zmailer: interpreter: cmd not found: '%s'  ppid=%d", av[0], getppid()));
		if (!nofork)
			_exit(1);
		SIGNAL_HANDLE(SIGTERM, oterm_handler);
		SIGNAL_HANDLE(SIGINT, oint_handler);
		SIGNAL_HANDLE(SIGQUIT, oquit_handler);
	} else if (pid > 0) {
		/*
		 * In the shell, if the child is doing output to a pipe,
		 * the child *must* complete all its O before we wait on it
		 * here, since nothing is reading from the pipe.  Whence
		 * we need to do an asynchronous wait in some circumstances.
		 */
		if (c->pgrpp != NULL)
			jc_newproc(c->pgrpp, pid, ac, av);
		else if (c->reaperTop < 0) {
			while ((n = wait(&status)) != pid && n > 0)
				continue;
		} else {	/* asynchronous wait */
			reapable[reapableTop++] = pid;
			SIGNAL_HANDLESAVE(SIGCHLD, reapchild, ochld_handler);
		}
	} else {	/* fork failed */
		retcode = 0200;
		fprintf(stderr, "%s: %s\n", progname, CANNOT_FORK);
	}

#ifndef USE_ALLOCA
	if (av) free(av);
#endif

#ifdef	MAILER
	if (D_functions && retcode != 0 && retcode != NO_RETCODE)
		fprintf(stderr, "?=%d\n", retcode);
#endif	/* MAILER */

	/*
	 * Undo the I/O manipulations needed for child setup.
	 */
	if (c->undoio) {
		RUNIO(c->undoio);
		if (c->iocmd == ioIntoBuffer) {
			SIGNAL_HANDLE(SIGCHLD, ochld_handler);
			while (c->reaperTop >= 0 && reapableTop > c->reaperTop)
				reapchild(0);
			/* one way or another it has been reaped */
			status = reapstatus;
		}
	}

	/*
	 * Undo any temporary variable values
	 */
	for (sl = c->envold; sl != NULL; sl = cddr(sl)) {
		if (cadr(sl) == NULL) {
			if (isset('I'))
				fprintf(runiofp, "purge(%s)\n", sl->string);
			v_purge(sl->string);
		} else {
			if (isset('I'))
				fprintf(runiofp, "revert(%s)\n", sl->string);
			l = v_find(sl->string);
			/* if (ISNEW(cdr(l)))
			   free((char *)cdr(l)->string);
			   else
			   s_free_tree(cadr(l));
			*/
			cadr(l) = cadr(sl);
#ifdef	MAILER
			if (v_accessed)
				v_written(l);
#endif	/* MAILER */
		}
		/* be sure to update internal dependencies */
		v_sync(sl->string);
	}
	if (c->envold != NULL) {
		if (isset('I'))
			grindef("Freeing = ", c->envold);
		/* s_free_tree(c->envold); */
		c->envold = NULL;
	}
	if (retcode != NO_RETCODE) {
		if (isset('t'))
			trapexit(retcode);
		goto out_exit;
	}
	if (WSIGNALSTATUS(status) != 0) {
		if (WSIGNALSTATUS(status) != SIGINT) {
			fprintf(stderr, "%s", strsignal(WSIGNALSTATUS(status)));
			if (status&0200)
				fprintf(stderr, CORE_DUMPED);
		}
		fprintf(stderr, "\n");
		retcode = 0200 + WSIGNALSTATUS(status);
	} else
		retcode = WEXITSTATUS(status);
	if (isset('t'))
		trapexit(retcode);
 out_exit:;
	UNGCPRO3;
	return retcode;
}

static int addbuffer __((char *, int, int, struct osCmd *));
static int
addbuffer(buf, len, state, command)
	char *buf;
	register int	len, state;
	struct osCmd *command;
{
	register char *ncp, *cp;
	conscell *tmp;

	ncp = cp = buf;
	for (cp = buf; --len >= 0; ++cp) {
		int c = (*cp) & 0xFF;
		if (!isascii(c))
			*ncp++ = c, state = 1;
		else if (state) {	/* break on whitespace */
			if (isspace(c)) {
				*ncp++ = (c == '\n') ? c : ' ';
				state = 0;
			} else
				*ncp++ = c;
		} else if (!isspace(c)) /* ignoring whitespace */
			*ncp++ = c, state = 1;
	}
	/* wrap up the stuff we got so far into a string buffer */
	if (ncp > buf) {
		int c = ncp[-1] & 0xFF;
		if (isascii(c) && isspace(c))
			--ncp;
		if (ncp > buf) {
			int slen = ncp-buf;
			tmp = newstring(dupnstr(buf, slen), slen);

			if (isset('I') || isset('R'))
				fprintf(stderr,
					"readstring: '%s'\n", ncp);
			*command->bufferp =  tmp;
			command->bufferp = &cdr(tmp);
		}
	}
	return state;
}


/*
 * Read a byte-stream from fd into a linked list of buffers in command->buffer.
 */

STATIC void readstring __((int, struct osCmd *));
STATIC void
readstring(fd, command)
	int fd;
	struct osCmd *command;
{
	int n, state;
	char buf[BUFSIZ];	/* read this size chunk at a time */
	GCVARS1;

	state = 0;
	GCPRO1(command->buffer); /* Should not need ... */
	while ((n = read(fd, &buf[0], sizeof(buf))) > 0)
		state = addbuffer(&buf[0], n, state, command);
	UNGCPRO1;
}


/*
 * String Buffer routines (for lack of a better name).
 * We want a stack on each fd, with the TOS marking whether I/O should
 * happen to something internal or to a real fd.  An siobuf with a flag
 * of -1 (and a null stack) indicate I/O to fd.
 *
 * In order to deal with dup()s, we must share a single siobuf between
 * the source and destination fd.  That happens when we sb_push(destination,
 * source), essentially.
 */

STATIC void sb_push __((struct siobuf **, struct siobuf *));
STATIC void
sb_push(siopp, sioptop)
	struct siobuf **siopp, *sioptop;
{
	struct siobuf *siop;

	siop = (struct siobuf *)emalloc(sizeof (struct siobuf));
/*std_printf("sb_push(%x)\n", siop);*/
	siop->_sb_data = siop;
	siop->sb_cnt = -1;
	siop->sb_ptr = NULL;
	siop->sb_base = NULL;
	siop->sb_bufsiz = -1;
	siop->sb_refcnt = 0;
	siop->sb_flag = (short)-1;	/* magic value */
	if (sioptop != NULL) {
		while (sioptop != NULL && sioptop != sioptop->_sb_data)
			sioptop = sioptop->_sb_data;
		siop->_sb_data = sioptop;
		siop->sb_refcnt += 1;
	}
	siop->sb_next = *siopp;
	*siopp = siop;
/*sb_pr();*/
}

/* read from string buffer by replacing new read buffer with old write buffer */

STATIC int sb_in __((int, int));
STATIC int
sb_in(n, outfd)
	int n, outfd;
{
	struct siobuf *siop;

	/*
	 * XX: keep this in sync with _FILEIO, which we cant use because
	 * it uses a global...
	 */
	if (siofds[outfd] == NULL || siofds[outfd]->sb_flag < 0) {
		fprintf(stderr, "%s: no siofds to read!\n",
				progname);
		return 1;
	}
	siop = siofds[n];
	siofds[n] = siofds[outfd];
	siofds[outfd] = siofds[outfd]->sb_next;
	siofds[n]->sb_next = siop;
	siop = siofds[n];
	siop->sb_cnt = siop->sb_bufsiz - (siop->sb_ptr - siop->sb_base);
	siop->sb_ptr = siop->sb_base;
	siop->sb_flag = O_RDONLY|(siop->sb_flag & O_CREAT);
/*std_printf("POP(%d) = %x (in)\n", outfd, siofds[outfd]);*/
/*std_printf("PUSH(%d) = %x (in)\n", n, siofds[n]);*/
/*sb_pr();*/
	return 0;
}

/* allocate a string buffer to write to */

STATIC void sb_out __((int));
STATIC void
sb_out(n)
	int n;
{
	struct siobuf *siop;

	siop = siofds[n];
	siofds[n] = (struct siobuf *)emalloc(sizeof (struct siobuf));
	siofds[n]->_sb_data = siofds[n];
	siofds[n]->sb_next = siop;
	siop = siofds[n];
	siop->sb_cnt = 0;
	siop->sb_ptr = siop->sb_base = NULL;
	siop->sb_bufsiz = 0;
	siop->sb_flag = O_WRONLY|O_APPEND;
	siop->sb_refcnt = 0;
/*std_printf("PUSH(%d) = %x (out)\n", n, siofds[n]);*/
/*sb_pr();*/
}

/* free a string buffer */

STATIC void sb_free __((int));
STATIC void
sb_free(n)
	int n;
{
	struct siobuf *siop;
	int flag, i;

/*std_printf("FREE(%d) = %x\n", n, siofds[n]);*/
	siop = siofds[n];
	if (siop == NULL) {
		fprintf(stderr, "%s: no siofds to free (fd=%d)\n",
				progname, n);
		return;
	}
	siofds[n] = siop->sb_next;
	flag = siop->_sb_data != siop;

	siop->sb_refcnt -= 1;
	if (siop->sb_refcnt >= 0) {
/*std_printf("sb_free: refcnt = %d, flag = %d\n", siop->sb_refcnt, flag);*/
		if (flag) {
			free((char *)siop);
			return;
		}
/*std_printf("sb_free: sb_flag = %d\n", siop->sb_flag);*/
		if (siop->sb_flag != (short)-1)
			return;
		for (i = 0; i < MAXNFILE ; ++i) {	/* XX: inefficient! */
/*if (siofds[i] != NULL) std_printf("sb_free: siofds[%d] = %x\n", i, siofds[i]);*/
			if (i == n || siofds[i] == NULL)
				continue;
#if 1
			if (siofds[i]->_sb_flag == (short)-1)
			  if (siofds[i]->_sb_refcnt == (short)0)
			    continue;
#endif
/*std_printf( "sb_free: siofds[%d]->_sb_data == siop: %d\n", siofds[i]->_sb_data == siop);*/
			if (siofds[i]->_sb_data == siop)
				sb_free(i);
		}
/*std_printf( "sb_free: returning\n");*/
		return;
	}
	/* we want to free whatever we're pointing to, perhaps us */
	if (siop->sb_base)
	  if (siop->sb_flag & O_CREAT)
	    /* data is malloc'ed */
	    free((char *)siop->sb_base);
	if (flag)	/* we're pointing at another siobuf */
	  free((char *)siop->_sb_data);
/*fprintf(runiofp, "sb_free: done\n");*/
	free((char *)siop);/* can do this because nothing refers to us */
}

void
sb_external(n)
	int n;
{
	sb_out(n);
	if (stickymem == MEM_SHCMD)
		abort(); /* must be either MEM_TEMP or MEM_PERM */
	siomore(siofds[n]);
	/* we now have a safe buffer in siop->sb_base */
}

char *
sb_retrieve(n)
	int n;
{
	struct siobuf *siop;
	char *cp;

	siop = siofds[n];
	if (siop->sb_flag & O_CREAT) {	/* turn malloc'ed data to MEM_TEMP */
		if (stickymem == MEM_SHCMD)
			abort(); /* must be either MEM_TEMP or MEM_PERM */
		cp = strnsave((char *)siop->sb_base,
			      siop->sb_ptr - siop->sb_base);
	} else
		cp = (char *)siop->sb_base;
	sb_free(n);
	return cp;
}

/*
sb_pr()
{
	int i;
	struct siobuf *siop;

	std_printf("\n");
	for (i = 0; i < MAXNFILE; ++i) {
		if (siofds[i] == NULL)
			continue;
		std_printf("%2d:", i);
		for (siop = siofds[i]; siop != NULL; siop = siop->sb_next) {
			std_printf(" %x", siop);
			if (siop->_sb_data != siop)
				std_printf("(%x)", siop->_sb_data);
		}
		std_printf("\n");
	}
}
*/

/*
 * Data-driven I/O manipulations.  This routine is called to set up or undo
 * the file descriptors as specified by the user and as required to make
 * stdin/out/err point at the right thing.  Sometimes file descriptors are
 * faked for the benefit of internally run functions (builtins or defined
 * functions) by using a growable string buffer mechanism.  This is how one
 * can (e.g.) pipe output from one builtin to the input of another without
 * doing any syscalls or forking.
 */

int
runio(ioopp)
	struct IOop **ioopp;
{
	struct IOop *ioprev, *ionext, *ioop;
	int errflag, fd = 0, pid, p[2];
	struct stat stbuf;
	struct siobuf *siop = NULL;
	GCVARS1;

	/*
	 * The list of actions is stored in reverse order.  Since each such
	 * list is only ever executed once, we can do inline reversal before
	 * interpreting the list.
	 */
	ioop = *ioopp;
	for (ioprev = NULL; ioop != NULL; ioop = ionext) {
		ionext = ioop->next;
		ioop->next = ioprev;
		ioprev = ioop;
	}
	errflag = 0;
	for (ioop = ioprev, ionext = NULL; ioop != NULL; ioop = ioop->next) {

#ifdef DEBUG_xxx
fprintf(stderr,"runio(@%p) ioop=%p &ioop->command->buffer=%p\n",
	__builtin_return_address(0), ioop, &ioop->command->buffer);
#endif
		switch (ioop->cmd) {
#ifdef	S_IFIFO
		case sIOopenPortal:	/* open named pipe */
			if (ioop->ioflags & O_CREAT) {
				if (stat(ioop->name, &stbuf) == 0
					&& !(stbuf.st_mode & S_IFIFO)) {
					fprintf(stderr, "%s: %d %s\n",
						progname, ioop->name,
						EXISTS_BUT_NOT_FIFO);
					++errflag;
					break;
				}
				unlink(ioop->name);
				/* if the pipe already exists, don't bother */
				if (mknod(ioop->name, S_IFIFO, 0) < 0) {
					fprintf(stderr, "%s: %s %s\n", progname,
							CANNOT_MKNOD,
							ioop->name);
					++errflag;
					break;
				}
			}
			/* FALL THROUGH */
#endif	/* S_IFIFO */
		case sIOopen:		/* open file */
			fd = open(ioop->name, ioop->ioflags, smask);
			if (fd < 0) {
				fprintf(stderr, "%s: %s %s\n", progname,
						CANNOT_OPEN, ioop->name);
				++errflag;
			} else if (fd != ioop->fd
				&& (dup2(fd, ioop->fd) < 0 || close(fd) < 0)) {
				fprintf(stderr,
					"%s: prediction error: got %d not %d\n",
					progname, fd, ioop->fd);
				++errflag;
			}
			sb_push(&siofds[ioop->fd], (struct siobuf *)NULL);
/*std_printf( "PUSH(%d) = %x (%d)\n", ioop->fd, siofds[ioop->fd], __LINE__);*/
			if (isset('R'))
				fprintf(stderr,
					"open(%s, %x, %o) = %d\n",
					ioop->name, ioop->ioflags,
					smask, fd);
			break;
		case sIOopenString:
			/* fork off a process to feed other proc in pipe */
			if (pipe(p) < 0) {
				fprintf(stderr, "%s: %s: %s\n",
						progname, PIPE,
						strerror(errno));
				++errflag;
			} else if (p[0] != ioop->fd) {
				if (p[1] == ioop->fd)
					fd = dup(p[1]);
				else
					fd = p[1];
				dup2(p[0], ioop->fd);
				close(p[0]);
			} else
				fd = p[1];
			if (!errflag) {
				BEGINGRANDCHILD(pid)
					write(fd, ioop->name,
					      strlen(ioop->name));
				ENDGRANDCHILD(pid) {		/* error */
					fprintf(stderr, "%s: %s\n",
							progname, CANNOT_FORK);
					++errflag;
				}
			}
			close(fd);
			if (isset('R'))
				fprintf(stderr,
					"write(%d, '%.40s', %d)\n",
					ioop->fd, ioop->name,
					strlen(ioop->name));
			break;
		case sIOopenPipe:
			if (pipe(p) < 0) {
				fprintf(stderr, "%s: %s: %s\n",
					progname, PIPE,
					strerror(errno));
				++errflag;
			} else if (p[1] != ioop->fd || p[0] != ioop->fd2) {
				fprintf(stderr, "%s: pipe prediction wrong: got %d|%d not %d|%d\n",
					progname, p[1], p[0],
					ioop->fd, ioop->fd2);
				++errflag;
				close(p[1]);
				close(p[0]);
			}
			sb_push(&siofds[p[0]], (struct siobuf *)NULL);
/*std_printf( "PUSH(%d) = %x (%d)\n", p[0], siofds[p[0]], __LINE__);*/
			sb_push(&siofds[p[1]], (struct siobuf *)NULL);
/*std_printf( "PUSH(%d) = %x (%d)\n", p[1], siofds[p[1]], __LINE__);*/
			if (isset('R'))
				fprintf(stderr, "pipe(%d|%d)\n", p[1], p[0]);
			break;
		case sIOintoBuffer:
			GCPRO1(ioop->command->buffer);
			readstring(ioop->fd, ioop->command);
			UNGCPRO1;
			if (isset('R'))
				fprintf(stderr, "intoBuffer '%s'\n",
					ioop->command->buffer ?
					ioop->command->buffer->string : "");
			break;
		case sIOdup:
/*putc('\n', runiofp);*/
			fd = dup2(ioop->fd, ioop->fd2);
			if (siofds[ioop->fd2] != NULL)
			  if (siofds[ioop->fd2]->sb_refcnt == 0)
			    sb_free(ioop->fd2)/*, sb_pr()*/;
			sb_push(&siofds[ioop->fd2], siofds[ioop->fd]);
/*std_printf( "PUSH(%d) = %x %x (%d)\n", ioop->fd2, siofds[ioop->fd2], siofds[ioop->fd], __LINE__);*/
			if (isset('R'))
				fprintf(stderr, "dup2(%d,%d) = %d\n",
					ioop->fd, ioop->fd2, fd);
			break;
		case sIOclose:
/*putc('\n', runiofp);*/
			fd = close(ioop->fd);
			if (siofds[ioop->fd])
				sb_free(ioop->fd)/*, sb_pr()*/;
			if (isset('R'))
				fprintf(stderr, "close(%d) = %d\n",
						 ioop->fd, fd);
			break;
		case sIObufIn:
			errflag += sb_in(ioop->fd, ioop->fd2);
			if (isset('R'))
				fprintf(stderr, "sb_in(%d,%d) err=%d\n",
						 ioop->fd, ioop->fd2, errflag);
			break;
		case sIObufOut:
			/* allocate a string buffer to write to */
			sb_out(ioop->fd);
			if (isset('R'))
				fprintf(stderr, "sb_out(%d)\n", ioop->fd);
			break;
		case sIObufFree:
			/* free a string buffer */
			sb_free(ioop->fd)/*, sb_pr()*/;
			if (isset('R'))
				fprintf(stderr, "sb_free(%d)\n", ioop->fd);
			break;
		case sIObufString:
			/* move string buffer contents to command->buffer */
			if (ioop->command->rval != NULL) {
				/* if rval exists, use it in preference */
				*(ioop->command->bufferp) = ioop->command->rval;
				ioop->command->bufferp = &cdr(*ioop->command->bufferp);
				ioop->command->rval = NULL;
			} else if ((siop = siofds[ioop->fd]) == NULL
				   || siop->sb_base == NULL) {
				break;
			} else {
				siop = siofds[ioop->fd];
				*(siop->sb_base + siop->sb_bufsiz
						- siop->sb_cnt) = '\0';
#if 0 /* Bad input excercised this code (and SEGVed in glibc-2.x),
	 no other has ever hit it.  KILL IT! */
				if (*siop->sb_base == '(') {
					FILE f;
					/*
					 * The FILE stuff in s_read() will
					 * get info from the string buffer
					 */
#ifdef _HPUX_SOURCE
					f.__fileL = ioop->fd % 256;
					f.__fileH = ioop->fd / 256;
#else /* Other non-portable.. */
#if defined(__GNU_LIBRARY__) || defined(__GLIBC__)
					/* GNU LIBC systems */
					f._fileno = ioop->fd;
#else
					/* classic SysIII derived systems */
					f._file = ioop->fd;/* XX: nonportable */

#endif
#endif
					GCPRO1(ioop->command->buffer);
					*(ioop->command->bufferp) = s_read(&f);
					UNGCPRO1;
					ioop->command->bufferp = &cdr(*ioop->command->bufferp);
				} else
#endif
				  {
					GCPRO1(ioop->command->buffer);
					addbuffer(siop->sb_base, siop->sb_bufsiz - siop->sb_cnt, 0, ioop->command);
					UNGCPRO1;
				}
			}
			break;
		default:
			break;
		}
	}
	*ioopp = ioprev;
	return errflag;
}
