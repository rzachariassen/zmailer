/*
 *	Copyright 1989 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * Trap script and signal management, and the builtin "trap" command.
 */

#include "hostenv.h"
#include <stdio.h>
#include <ctype.h>
#include <sys/stat.h>
#include "zmsignal.h"
#include "flags.h"
#include "malloc.h"
/* #include "listutils.h" */
#include "sh.h"
#include "io.h"			/* redefines stdio routines */
#include "shconfig.h"
#include "libsh.h"

extern const char *VersionNumb;

#ifndef SIGCHLD
#define SIGCHLD SIGCLD
#endif  /* SIGCHLD */

/*
 * The script to execute for a particular trap is stored as a string in
 * malloc()'ed storage, with a pointer to it in the traps[] array.
 */

const char *traps[NSIG];

/*
 * The effect of a signal is to increment a count of seen but unprocessed
 * (as in the trap script hasn't been run) signals in the spring[] array,
 * one counter per signal.  They had better start out as 0.
 */

STATIC int spring[NSIG];	/* pending trap counts */

/*
 * As a cheap way of testing if there are pending unprocessed signals, the
 * sprung variable is used as a flag to that effect.  It is a cheap test
 * elsewhere in the shell (in interpreter loop and input function).
 */

int sprung;			/* there are pending traps */

/*
 * In order to interrupt builtin function execution (as opposed to builtin
 * functions), set a flag whenever we see an interrupt that doesn't have
 * a trap handler.  This flag should be tested in the interpreter loop, and
 * anywhere else the shell might be spending a lot of time (e.g. the filename
 * expansion routines).
 */

int interrupted;		/* XX: we saw an interrupt */

/*
 * To maintain sh semantics, we need to know what the original signal handler
 * values are.  These are retrieved once at startup time (from main) and
 * stored in the orig_handler[] array.
 */

RETSIGTYPE (*orig_handler[NSIG]) __((int));

/*
 * Indeed, that is what the trapsnap() function does.
 */

void
trapsnap()
{
	int i;

	for (i = 1; i < NSIG; ++i)
		SIGNAL_HANDLESAVE(i, SIG_DFL, orig_handler[i]);
	/* is there a vulnerability here due to SIG_DFL instead of SIG_IGN ? */
	for (i = 1; i < NSIG; ++i)
		if (orig_handler[i] != SIG_DFL && i != SIGCHLD)
			SIGNAL_HANDLE(i, orig_handler[i]);
}

/*
 * This is the generic signal handler that is set whenever a trap is laid.
 */

void
trap_handler(sig)
	int sig;
{
	if (sig > 0 && sig < NSIG) {
		SIGNAL_HANDLE(sig, trap_handler);
		spring[sig] += 1;
		sprung = 1;
	}
	if (sig == SIGINT && traps[sig] == NULL)
		interrupted = 1;
}

/*
 * Evaluate the contents of the buffer and invoke the interpreter.
 * This function really should not be here!
 */

#define CFSUFFIX	".cf"
#define FCSUFFIX	".fc"
#define FCSUBDIR	"fc"

STATIC char * makefc __((const char *, char *));
STATIC char *
makefc(path, buf)
	const char *path;
	char *buf;
{
	register char *cp;
	struct stat stbuf;

	u_int plen = strlen(path);

	if (plen <= sizeof CFSUFFIX)
		return NULL;
	if (strcmp(path+plen-(sizeof FCSUFFIX - 1), FCSUFFIX) == 0) {
		strcpy(buf, path);
		return buf;
	}
	if (strcmp(path+plen-(sizeof CFSUFFIX - 1), CFSUFFIX) != 0)
		return NULL;

	strcpy(buf, path);
	if ((cp = strrchr(buf, '/')) != NULL)
		++cp;
	else
		cp = buf;
	strcpy(cp, FCSUBDIR);
	if (stat(buf, &stbuf) == 0 && (stbuf.st_mode & S_IFDIR)) {
		sprintf(buf + strlen(buf), "/%s", path+(cp-buf));
		strcpy(buf + strlen(buf) - (sizeof CFSUFFIX - 1), FCSUFFIX);
	} else {
		strcpy(buf, path);
		strcpy(buf+plen-(sizeof CFSUFFIX - 1), FCSUFFIX);
	}
	return buf;
}


int
eval(script, scriptname, savefile, srcstbufp)
	const char *script, *scriptname, *savefile;
	const struct stat *srcstbufp;
{
	int status;
	void *table, *eotable;
	FILE *fp;
	char *fcfile;
	char *buf = NULL;
#ifdef	USE_ALLOCA
	if (savefile != NULL)
	  buf = alloca(strlen(savefile)+9);
#else
	if (savefile != NULL)
	  buf = emalloc(strlen(savefile)+9);
#endif

	commandline = s_pushstack(commandline, script);
	table = SslWalker(scriptname, stdout, &eotable);
	status = 0;
	if (table != NULL) {
		if (isset('n')) {
			free((char *)table);
			return 0;
		}
		fcfile = NULL;
		if (isset('O')) {
extern void *optimize __((int, void *, void **));
			table = optimize(0, table, &eotable);
			if (isset('V'))
				table = optimize(1, table, &eotable);
			if (savefile != NULL &&
			    (fcfile = makefc(savefile,buf)) != NULL &&
			    (fp = fopen(fcfile, "w")) != NULL) {
				/* magic1, magic2, st_dev, st_ino,
				   st_size, st_mtime, st_ctime */
				fprintf(fp,"#!zmsh -l%s,%d,%ld,%ld,%ld,%ld,%d,%d\n",
					VersionNumb,
					magic_number, (long)bin_magic,
					(long)srcstbufp->st_dev,
					(long)srcstbufp->st_ino,
					(long)srcstbufp->st_size,
					(int)srcstbufp->st_mtime,
					(int)srcstbufp->st_ctime);

				std_fwrite(table, 1,
					   (char*)eotable - (char*)table, fp);
				if (fclose(fp) == EOF) {
					fprintf(stderr,
						"%s: write to %s failed\n",
						progname, fcfile);
					unlink(fcfile);
				}
			}
		}
		interpret(table, eotable, (u_char *)NULL,
			  globalcaller == NULL ? &avcmd : globalcaller,
			  &status, (struct codedesc *)NULL);
	}
#ifndef	USE_ALLOCA
	free(buf);
#endif
	return status;
}

int
loadeval(fcfd, path, srcstbufp)
	int fcfd;
	const char *path;
	struct stat *srcstbufp;
{
	int status;
	char *fcfile;
#ifdef	USE_ALLOCA
	char *buf = alloca(strlen(path)+9);
#else
	char *buf = emalloc(strlen(path)+9);
#endif

	fcfile = makefc(path,buf);
	if (fcfile == NULL) {
#ifndef	USE_ALLOCA
		free(buf);
#endif
		return -1;
	}
	status = leaux(fcfd, fcfile, srcstbufp);
#ifndef	USE_ALLOCA
	free(buf);
#endif
	return status;
}

int
leaux(fcfd, path, srcstbufp)
	int fcfd;
	const char *path;
	struct stat *srcstbufp;
{
	FILE *fp;
	int status, len;
	void *table;
	struct stat objstbuf;
	char buf[200];
	char sbuf[200];

	/* magic1, magic2, st_dev, st_ino, st_size, st_mtime, st_ctime */
	sprintf(sbuf,"#!zmsh -l%s,%d,%ld,%ld,%ld,%ld,%d,%d\n",
		VersionNumb,
		magic_number, (long)bin_magic,
		(long)srcstbufp->st_dev,
		(long)srcstbufp->st_ino,
		(long)srcstbufp->st_size,
		(int)srcstbufp->st_mtime,
		(int)srcstbufp->st_ctime);

	fp = fopen(path, "r");
	if (fp == NULL)
		return -1;
	if (std_fgets(buf, sizeof buf, fp) == NULL) {
		fclose(fp);
		fprintf(stderr, "%s: cannot get first line of %s\n",
			progname, path);
		return -1;
	}

	if (fstat(FILENO(fp), &objstbuf) < 0) {
		fclose(fp);
		fprintf(stderr, "%s: fstat failed on %s\n",
				progname, path);
		return -1;
	}
	if (strcmp(buf,sbuf) != 0) {
		fclose(fp);
		unlink(path);
		return -1;
	}
	if (srcstbufp != NULL && srcstbufp->st_mtime > objstbuf.st_mtime) {
		fclose(fp);
		unlink(path);
		return -1;
	}
	len = (int)(objstbuf.st_size - ftell(fp));
	table = (void *)emalloc(len);
	if (std_fread(table, 1, len, fp) != len) {
		fclose(fp);
		fprintf(stderr, "%s: read of %d failed on %s\n",
			progname, len, path);
		return -1;
	}
	fclose(fp);
	if (fcfd >= 0)
	  close(fcfd);
	status = 0;
	interpret(table, (char*)table + len, NULL,
		  globalcaller == NULL ? &avcmd : globalcaller,
		  &status, (struct codedesc *)NULL);
	return status;
}

/*
 * If unprocessed signals are pending (and the sprung flag set), we call
 * this function to do the processing.  It will deal with pending signals
 * in numerical as opposed to chronological order.
 */

void
trapped()
{
	int i;
	static int intrap = 0;

	if (!sprung)
	  return;
	/*
	 * We must reset the sprung flag before calling aval(), or we will
	 * almost certainly get a recursive invocation of this routine from
	 * the interpreter.
	 */
	sprung = 0;

	/*
	 * What about this scenario: interpreter calls trapped.  trapped calls
	 * eval which calls interpreter.  a signal is delivered and sprung
	 * gets set.  the interpreter calls trapped again.  some traps will
	 * then maybe get run twice.  Ergo we need some semaphore here.
	 */
	if (intrap) {
	  /* more signals have arrived, be sure not to miss them */
	  ++intrap;
	  return;
	}
	for (++intrap; intrap > 0; --intrap) {
	  for (i = 1; i < NSIG; ++i)
	    while (spring[i] > 0) {
	      if (traps[i] != NULL)
		eval(traps[i], "trap", NULL, NULL);
	      --spring[i];
	    }
	}
}


/*
 * This is the exit routine used when one wants a "trap 0" to be honoured.
 */

void
trapexit(n)
	int n;
{
	if (traps[0] != NULL) {
	  const char *cmd = traps[0];
	  traps[0] = NULL;
	  eval(cmd, "exit trap", NULL, NULL);
	}

	/* Lets clean these up, malloc tracers complain less.. */
	s_free_tree(envarlist);

#ifdef	MALLOC_TRACE
	mal_dumpleaktrace(stderr);
	/* mal_heapdump(&_iob[2]); */
#endif	/* MALLOC_TRACE */

	exit(n);
	/* NOTREACHED */
}

/*
 * The builtin "trap" function is implemented here.
 */

int
sh_trap(argc, argv)
	int argc;
	const char *argv[];
{
	int i;
	const char *av0, *script;
	
	if (argc == 1) {
		/* just print the known traps */
		for (i = 0; i < NSIG; ++i) {
			if (traps[i] != NULL)
				printf("%d: %s\n", i, traps[i]);
		}
		return 0;
	}
	av0 = argv[0];
	--argc, ++argv;
	if (**argv == '\0') {
		/* ignore the specified signals */
		script = *argv;
		--argc, ++argv;
	} else if (isascii(**argv) && isdigit(**argv)) {
		/* reset the signal handlers to original value */
		script = NULL;
	} else {
		/* stash the script away for later execution by a trap */
		script = *argv;
		--argc, ++argv;
		/* don't bother guarding argc > 0, sh doesn't */
	}
	while (argc-- > 0) {
		if (!isascii(**argv) || !isdigit(**argv)) {
			fprintf(stderr, "%s: bad number: '%s'\n", av0, *argv);
			++argv;
			continue;
		}
		i = atoi(*argv++);
		if (i < 0 || i >= NSIG) {
			fprintf(stderr, "%s: %s: %s\n",
				av0, BAD_TRAP, *(argv-1));
			continue;
		}
		if (traps[i] != NULL)
			free((void*)traps[i]);
		if (script != NULL && *script != '\0') {
			char *tp = (char *)emalloc(strlen(script)+1);
			strcpy(tp, script);
			traps[i] = tp;
			/* enable that signal */
			if (i > 0 && orig_handler[i] != SIG_IGN)
				SIGNAL_HANDLE(i, trap_handler);
		} else if (script != NULL) {
			traps[i] = NULL;
			/* disable that signal */
			if (i > 0)
				SIGNAL_IGNORE(i);
		} else {
			traps[i] = NULL;
			if (i > 0)
				SIGNAL_HANDLE(i, orig_handler[i]);
		}
	}
	return 0;
}
