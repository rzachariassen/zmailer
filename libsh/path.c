/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include "hostenv.h" /* Usage of 'mailer.h' here is dangerous, because
			'sh.h' includes 'regex.h', which barfs at the
			definition of 'string' ... */

#include <stdio.h>
#ifndef FILE /* Some systems don't have this as a MACRO.. */
# define FILE FILE
#endif
/* #include <sfio.h> */

#if HAVE_STRING_H || STDC_HEADERS
# include <string.h>
#else
# include <strings.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include "sh.h"
#include "shconfig.h"
#include "flags.h"
#include "io.h"		/* redefines stdio routines */
#include "splay.h"

#include "libz.h"
#include "libsh.h"

extern struct sptree *spt_searchpath;

/*
 * Take a path specification, e.g. ":/bin:/usr/bin" and iterate through it
 * composing "./name" "/bin/name" and "/usr/bin/name" in the path buffer.
 * State is maintained by returning the next position pointer in near-proper
 * co-routine fashion.
 */

char *
prepath(pathspec, name, buf, buflen)
	register char *pathspec;
	register const char *name;
	char *buf;
	register unsigned int buflen;
{
	register char *cp;

	if (pathspec == NULL || *pathspec == '\0')
		return NULL;
	cp = buf;
	while (buflen > 2 && *pathspec != '\0' && *pathspec != ':')
		*cp++ = *pathspec++, --buflen;
	if (cp == buf)
		*cp++ = '.', --buflen;
	if (name != NULL) {	/* name == 0 means we're dealing with files */
		*cp++ = '/', --buflen;
		while (buflen > 1 && *name != '\0')
			*cp++ = *name++, --buflen;
		if (*name != '\0') {
			fprintf(stderr, "prepath: path too long\n");
			return NULL;
		}
	}
	*cp = '\0';
	if (*pathspec == '\0')
		return NULL;
	return ++pathspec;
}

/*
 * Maintain a quick index to the 'first place' to look for a unix command.
 * The method is to keep a pointer into the PATH string value, namely to
 * the directory the command seems to be in.  This pointer is then returned
 * to the caller who uses it instead of the PATH string value itself, to
 * feed to a prepath()-based iteration.  That way even if the command isn't
 * found in the indicated directory, the directories afterwards will still
 * be searched.  If that fails, the caller should use the PATH string value
 * until prepend() returns the same pointer that hashpath() did.  Because
 * the stuff hashpath() stashes away is invalidated by resetting path,
 * it is a good idea to call path_flush() to reset the hash tables when this
 * happens.
 */

char *
path_hash(command)
	const char *command;
{
	char *dir, *odir, *path;
	spkey_t n;
	conscell *d;
	struct spblk *spl;
	int pathlen;

	if (!isset('h'))
		return NULL;
	if (command == NULL || *command == '\0')
		return NULL;
	if (strchr(command, '/') != NULL)
		return NULL;
	n = symbol(command);
	if ((spl = sp_lookup(n, spt_searchpath)) != NULL
	    && (dir = (char *)spl->data) != NULL)
		return dir;
	d = v_find("PATH");
	if (d == NULL || cdr(d) == NULL || LIST(cdr(d)))
		return NULL;	/* try doing a real execvp() */
	dir = (char *)cdr(d)->string;
	pathlen = strlen(dir)+strlen(command)+1+1;
#ifdef	xxUSE_ALLOCA
	path = alloca(pathlen);
#else
	path = emalloc(pathlen);
#endif
	while (dir != NULL) {
		odir = dir;
		dir = prepath(dir, command, path, pathlen);
#ifndef	X_OK
#define	X_OK	1
#endif
		if (access(path, X_OK) == 0) {
			sp_install(n, (u_char *)odir, 0, spt_searchpath);
#ifndef	xxUSE_ALLOCA
			free(path);
#endif
			return odir;
		}
	}
#ifndef	xxUSE_ALLOCA
	free(path);
#endif
	return NULL;	/* can't find the thing! use errno for details */
}

/* flush all the cached command locations */

void
path_flush()
{
	if (isset('h'))
		sp_null(spt_searchpath);
}

int
execvp(command, argv)
	const char *command;
	char *const *argv;
{
	char *dir, *odir, *path;
	conscell *d;
	struct spblk *spl;
	u_int pathlen;

	if (command == NULL || *command == '\0') {
		errno = EINVAL;
		return -1;
	} else if (strchr(command, '/') != NULL) {
		return execv(command, argv);
	} else if (!isset('h')) {
		dir = odir = NULL;
	} else if ((dir = path_hash(command)) == NULL) {
		dir = getenv("ZSHPATH");
		odir = NULL;
	} else {
		/* printf("found hash: '%s'\n", dir); */
		odir = dir;
	}
	if (dir != NULL) {
		pathlen = strlen(dir)+strlen(command)+1+1;
#ifdef	xxUSE_ALLOCA
		path = alloca(pathlen);
#else
		path = emalloc(pathlen);
#endif
		while (dir != NULL) {
		  dir = prepath(dir, command, path, pathlen);
		  /* printf("execv '%s'\n", path); */
		  execv(path, argv);
		}
#ifndef	xxUSE_ALLOCA
		free(path);
#endif
	}
	if ((d = v_find("PATH")) != NULL && cdr(d) != NULL && STRING(cdr(d))) {
		if (odir != NULL) {
			/* Hmm, wasn't in the hashed location, clear that out */
			spl = sp_lookup(symbol(command), spt_searchpath);
			if (spl != NULL)
				sp_delete(spl, spt_searchpath);
			/*
			 * We shouldn't rehash right now or we might get
			 * into loops trying to use the result.
			 */
		}
		dir = (char *)cdr(d)->string;
		pathlen = strlen(dir)+strlen(command)+1+1;
#ifdef	xxUSE_ALLOCA
		path = alloca(pathlen);
#else
		path = emalloc(pathlen);
#endif
		while (dir != NULL && dir != odir) {
		  dir = prepath(dir, command, path, pathlen);
		  /* printf("reexecv '%s'\n", path); */
		  execv(path, argv);
		}
#ifndef	xxUSE_ALLOCA
		free(path);
#endif
	}
	/* oh well... */
	return -1;
}

int
execv(command, argv)
	const char *command;
	char *const *argv;
{
	register conscell *scope, *l;
	register int n, len;
	register char **envp, *buf;

	if (envarlist == NULL)
		abort(); /* Empty envarlist for execv() ! */
	for (scope = car(envarlist); cdr(scope) != NULL; scope = cdr(scope))
		continue;
	for (n = 1, len = 0, l = car(scope); l != NULL; l = cdr(l))
		if (STRING(l))
			++n, len += l->slen;
	envp = (char **)tmalloc((n/2 + 1) * sizeof (char *));
	buf  = (char *)tmalloc(len + n /* terminating NUL */ + n /* = */);
	for (n = 0, l = car(scope); l != NULL; l = cddr(l)) {
		if (!(STRING(l) && cdr(l) != NULL && STRING(cdr(l))))
			continue;
		envp[n++] = buf;
		memcpy(buf, l->cstring, l->slen);
		buf    += l->slen;
		*buf++  = '=';
		memcpy(buf, cdr(l)->cstring, cdr(l)->slen);
		buf    += cdr(l)->slen;
		*buf++  = '\0';
	}
	qsort(envp, n, sizeof envp[0], pathcmp);
	envp[n] = NULL;

	n = execve(command, argv, envp);

	if (errno == ENOEXEC) {	/* maybe the kernel doesn't understand #! */
		int nargs;
		const char **av;

		for (nargs = 0; argv[nargs] != NULL; ++nargs)
			continue;
		av = (const char **)tmalloc((nargs + 2) * sizeof argv[0]);
		av[0] = "sh";
		for (nargs = 0; argv[nargs] != NULL; ++nargs)
			av[nargs+1] = argv[nargs];
		av[nargs+1] = NULL;
		execve("/bin/sh", (char*const*)av, envp);
		errno = ENOEXEC;
	}
	return n;
}
