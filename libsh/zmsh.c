/*
 *	Copyright 1989 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * ZShell main and input routines.
 */

#include "hostenv.h"
#ifdef	MAILER
#include "sift.h"
#endif	/* MAILER */
#include "mailer.h"
#include <sys/file.h>
#include <fcntl.h>
#include <errno.h>
#include "zmsignal.h"
#include "flags.h"
#include "interpret.h"
#include "shconfig.h"
#include "splay.h"
#include "sh.h"

#include "libsh.h"

struct cmddef commands[] = {
#include "sh-out.i"
};

int ncommands = sizeof commands / sizeof commands[0];

struct sptree *spt_funclist = NULL;
struct sptree *spt_builtins = NULL;
struct sptree *spt_searchpath;

int saweof;
FILE *runiofp = NULL;
conscell *commandline = NULL;	/* argument to -c option */
const char *progname;
struct osCmd avcmd = { 0, };

char shfl[CHARSETSIZE/NBBY];

int
zshtoplevel(errname)
	const char *errname;
{
	void *table, *eotable;
	int status = 0;
	memtypes oval;

	setfreefd();
	oval = stickymem;
	stickymem = MEM_PERM;
	saweof = 0;
	while (1) {
		table = SslWalker(errname, stdout, &eotable);
		if (saweof)
			break;
		if (table == NULL) {
			if (isset('i')) {
				status = 1;	/* syntax error status */
				continue;
			} else
				break;
		}
		if (isset('n')) {
			free((char *)table);
			continue;
		}
		if (isset('W'))
			table = optimize(1, table, &eotable);
		if (isset('O')) {
			table = optimize(0, table, &eotable);
			if (isset('V'))
				table = optimize(1, table, &eotable);
		}
		interpret(table, eotable, NULL, &avcmd, &status,
			  (struct codedesc *)NULL);
	}

	stickymem = oval;
	return status;
}

void
zshprofile(command)
	const char *command;
{
	memtypes oval = stickymem;

	stickymem = MEM_PERM;
	commandline = s_pushstack(commandline, command);
	stickymem = oval;
}

/* things to do once only, the first time zsh is called */

void
zshinit(argc, argv)
	int argc;
	const char **argv;
{
	int c, errflag, io, uid, loadit;
	register struct shCmd *shcmdp;
	memtypes oval;

	runiofp = stdout;

	oval = stickymem;
	stickymem = MEM_PERM;

	/* check for funny business */
	uid = geteuid();
	if (uid != getuid()) {
		fprintf(stderr, "%s: ruid != euid\n", argv[0]);
		exit(1);
	}

	/* take and stash a snapshot of inherited signal handlers */
	trapsnap();

	if (spt_funclist == NULL)
		spt_funclist = sp_init();
	spt_searchpath = sp_init();

	/* The Router will initialize this on its own if it needs to */
	if (spt_builtins == NULL)
		spt_builtins = sp_init();

	for (shcmdp = &builtins[0]; shcmdp->name != NULL; ++shcmdp)
	  sp_install(symbol(shcmdp->name), (void *)shcmdp, 0L, spt_builtins);

	TOKEN_NARGS(sBufferSet) = 1;
	TOKEN_NARGS(sBufferAppend) = 1;
	TOKEN_NARGS(sIOdup) = 1;
	TOKEN_NARGS(sIOsetDesc) = 1;
	TOKEN_NARGS(sLocalVariable) = 1;
	TOKEN_NARGS(sParameter) = 1;
#ifdef	MAILER
	TOKEN_NARGS(sSiftBufferAppend) = 1;
#endif	/* MAILER */

	TOKEN_NARGS(sFunction) = -1;
	TOKEN_NARGS(sJump) = -1;
	TOKEN_NARGS(sJumpFork) = -1;
	TOKEN_NARGS(sJumpIfFailure) = -1;
	TOKEN_NARGS(sJumpIfSuccess) = -1;
	TOKEN_NARGS(sJumpIfNilVariable) = -1;
	TOKEN_NARGS(sJumpIfMatch) = -1;
	TOKEN_NARGS(sJumpIfFindVarNil) = -1;
	TOKEN_NARGS(sJumpIfOrValueNil) = -1;
	TOKEN_NARGS(sJumpLoopBreak) = -1;
	TOKEN_NARGS(sJumpLoopContinue) = -1;
#ifdef	MAILER
	TOKEN_NARGS(sSiftCompileRegexp) = -1;
	TOKEN_NARGS(sJumpIfRegmatch) = -1;
	TOKEN_NARGS(sTSiftCompileRegexp) = -1;
	TOKEN_NARGS(sTJumpIfRegmatch) = -1;
#endif	/* MAILER */

	setopt('h', 1);

	/* argument processing */
	progname = argv[0];
	if (*progname == '-') {
		setopt('c', 1);
		zshprofile(LOGIN_SCRIPT);
	}
	loadit = errflag = 0;
	optind = 1;	/* not to be influenced by previous getopt()'s */
	while (1) {
		c = getopt(argc, (char**)argv, "CILMOPRSYc:l:isaefhkntuvx");
		if (c == EOF)
		  break;
		switch (c) {
		case 'O':	/* optimize */
			if (isset(c))
				setopt('V', 1);	/* print optimizer output */
			setopt(c, 1);
			break;
		case 'C':	/* coder (what the S/SL emits) */
			if (isset(c)) {
				setopt('W', 1);	/* print optimizer output */
				setopt(c, 0);	/* turn off ugly output */
			} else
				setopt(c, 1);
			break;
		case 'R':	/* runtime I/O */
		case 'I':	/* interpreter (runtime interpretation) */
		case 'Y':	/* just open the runiofp stream */
			setopt(c, 1);
			if (runiofp == stdout) {
				io = open("/dev/tty", O_WRONLY, 0);
				dup2(io, 19);
				close(io);
				runiofp = fdopen(19 /* out of the way */, "w");
			}
			break;
		/* these are the normal shell-external flags */
		case 'c':	/* run the command given as an argument */
			if (isset(c)) {
				fprintf(stderr,
					"%s: illegal duplicate option '%c'\n",
					progname, c);
				++errflag;
				break;
			}
			setopt(c, 1);
			zshprofile(optarg);
			break;
		case 'l':	/* load the precompiled script, ignore optarg */
		case 'i':	/* interactive shell */
		case 's':	/* read commands from stdin */
		/* these are the shell-internal flags */
		case 'a':	/* automatically export new/changed variables */
		case 'e':	/* exit on error exit status of any command */
		case 'f':	/* disable filename generation (no globbing) */
		case 'h':	/* hash program locations */
		case 'k':	/* place all keyword arguments in environment */
		case 'n':	/* read commands but do not execute them */
		case 't':	/* read and execute one command only */
		case 'u':	/* unset variables are error on substitution */
		case 'v':	/* print shell input lines as they are read */
		case 'x':	/* print commands as they are executed */
		/* these are the miscellaneous debugging flags we're fond of */
		case 'L':	/* lexer (char-by-char input) */
		case 'M':	/* memory statistics */
		case 'P':	/* parser (S/SL tracing) */
		case 'S':	/* scanner (assembling tokens) */
			setopt(c, 1);
			break;
		default:
			++errflag;
		}
	}
	if (errflag) {
		fprintf(stderr, USAGE, argv[0]);
		exit(1);
	}
	if (!isset('s')) {
		if (optind == argc) {
			/* read commands from stdin */
			setopt('s', 1);
		} else if ((io = open(argv[optind], O_RDONLY, 0)) < 0) {

			fprintf(stderr, "%s: open(\"%s\"): %s\n",
				progname, argv[optind],
				strerror(errno));
			exit(1);
		} else if (io != 0) {
			dup2(io, 0);
			close(io);
		}
	}

	if (!isset('i') && isatty(0) && isatty(2))
		setopt('i', 1);
	if (isset('i')) {
		SIGNAL_IGNORE(SIGTERM);
		SIGNAL_HANDLE(SIGINT, trap_handler);
	}

	avcmd.argv = NULL;

	staticprot(& avcmd.argv);  /* LispGC */
	staticprot(& commandline); /* LispGC */
	staticprot(& envarlist);   /* LispGC */

	avcmd.argv = s_listify(argc-optind, &argv[optind]);

	if (isset('s')) {
		conscell *d = NULL;
		GCVARS1;
		GCPRO1(d);
		d = conststring(progname);
		s_push(d, avcmd.argv);
		UNGCPRO1;
	}

	v_envinit();
	v_set(PS2, DEFAULT_PS2);
	if (uid == 0) {
		v_set(PS1, DEFAULT_ROOT_PS1);
	} else {
		v_set(PS1, DEFAULT_PS1);
	}
	path_flush();
	mail_flush();
	mail_intvl();

	glob_init();
	/* we don't inherit IFS, enforced in envinit() */
	v_set(IFS, DEFAULT_IFS);

	if (isset('l') && argv[optind] != NULL)
	  exit(leaux(-1, argv[optind], (struct stat *)NULL));

	stickymem = oval;
}

/* cleanup function, only called if pedantic about freeing allocated memory */

void
zshfree()
{
	sp_scan(xundefun, (struct spblk *)NULL, spt_funclist);
	sp_null(spt_funclist);
	/* s_free_tree(envarlist); */
	envarlist = NULL;
}

/* return no. of characters left to read from *cpp */

int
zshinput(contd, cpp, moredata, bobufp, eobufp)
	int	contd;		/* 0 for PS1, 1 for PS2 */
	char	**cpp;		/* will point at input characters */
	int	*moredata;	/* set to indicate if there is more to read */
	char	**bobufp, **eobufp;	/* range of valid data for error msgs */
{
	int n;
	char *cp;
	static char buf[BUFSIZ];

	if (sprung)
		trapped();
	if (isset('c') && commandline == NULL) {
		++saweof;
		return 0;
	}
	if (commandline) {
		*bobufp = (char *)commandline->string;
		*eobufp = (char *)commandline->string
				+ strlen((char *)commandline->string);
		cp = tmalloc(*eobufp - *bobufp + 1);
		memcpy(cp, *bobufp, *eobufp - *bobufp + 1);
		*eobufp = cp + (*eobufp - *bobufp);
		*bobufp = *cpp = cp;

		commandline = s_popstack(commandline);
		*moredata = (commandline != NULL);
		if (isset('v'))
			fwrite(*bobufp, 1, *eobufp - *bobufp, stdout);
		return *eobufp - *bobufp;
	}
	*moredata = 0;
	if (interrupted)
		interrupted = 0;
again:
	if (isset('i')) {
		if (contd) prompt2_print();
		else {
			mail_check();
			prompt_print();
		}
		fflush(stdout);
	}
	if ((n = read(0, buf, sizeof buf)) <= 0) {
		if (n == -1 && errno == EINTR) {
			putchar('\n');
			if (!contd) {
				interrupted = 0;
				if (sprung)
					trapped();
				goto again;
			} else
				return 0;
		}
		++saweof;
		return 0;
	}
	*bobufp = *cpp = buf;
	*eobufp = buf + n;
	if (n == sizeof buf)
		*moredata = 1;
	if (isset('v'))
		fwrite(*bobufp, 1, n, stdout);
	return n;
}
