/*
 *	Copyright 1989 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * Shell Variable maintenance routines.
 */

#include "hostenv.h"
#ifdef	MAILER
#include "sift.h"	/* Include this BEFORE "mailer.h" ! */
#endif	/* MAILER */

#include "mailer.h"
#include "sh.h"
#include "flags.h"
#include "shconfig.h"

#include "libsh.h"

#ifdef	MAILER

int v_record = 0;	/* record variable accesses */
int v_changed = 0;	/* a variable in v_accessed was changed */
struct vaccess *v_accessed = NULL;

extern char **environ; /* Should be declated in  <stdlib.h>, but isn't.. */

void
v_written(l)
	register conscell *l;
{
	register struct vaccess *va;

	for (va = v_accessed; va != NULL; va = va->next)
		if (va->l == l) {
			++v_changed;
			return;
		}
}

void
v_touched()
{
	if (v_accessed)
		++v_changed;
}
#endif	/* MAILER */


/*
 * Shell variables and their values are stored in p-lists (property lists),
 * one property list per scope.  The envarlist variable is a list of these
 * property lists, the local scope at the car of the value.  There are usually
 * two scopes, the global scope and the exported scope (super-global, if you
 * will).  So envarlist looks something like
 *	(closest-localscope-plist ... global-plist export-plist)
 * Each property list has the standard format, i.e. alternating name value
 * pairs in a flat structure.  The envarlist itself is stored in the global
 * scope under the ENVIRONMENT name, I can't recall why except the pleasing
 * nature of the recursion (well, it might be useful some day).
 * Any variables in the export-plist will be in the environment of programs
 * started by the shell.
 */

conscell *envarlist = NULL;

/*
 * Certain mechanisms inside the shell need very frequent access to specific
 * variable values.  Instead of doing a relatively expensive lookup every
 * time, we keep a list of variables that should cause a function call whenever
 * they change (aka metered variables).  This concept should perhaps be
 * extended later to be able to call defined functions.
 */

STATIC struct vsync {
	const char	*v_name;		/* variable name */
	int	v_hash;			/* computed hash value of name */
	void	(*v_flush) __((void));	/* function to call on change */
} vcheck[] = {
{	PATH,		0,		path_flush		},
{	PS1,		0,		prompt_flush		},
{	PS2,		0,		prompt2_flush		},
{	MAIL,		0,		mail_flush		},
{	MAILPATH,	0,		mail_flush		},
{	MAILCHECK,	0,		mail_intvl		},
{	IFS,		0,		ifs_flush		},
};


/*
 * The ifs_flush() routine is defined below, it maintains this global value:
 */

char *ifs;		/* input file separator characters */

/*
 * Find the value of a named variable by looking through the scoped p-lists.
 */

conscell *
v_find(name)
	const char * name;
{
	register conscell *l, *pl, *scope;
	int nlen = strlen(name);

	if (name == NULL) return NULL; /* No input name, no output var.. */

	/* if (fvcache.namesymbol > 0 && fvcache.namesymbol == symbol(name))
		return fvcache.location; */

	pl = NULL;
	for (scope = car(envarlist); scope != NULL; scope = cdr(scope)) {
		for (l = car(scope); l != NULL; pl = cdr(l), l = cddr(l)) {
			if (l->slen == nlen &&
			    memcmp(name, l->cstring, nlen) == 0){
				if (l != car(scope)) {
					/* move it to start of scope plist */
					cdr(pl) = cddr(l);
					cddr(l) = car(scope);
					car(scope) = l;
				}
				/* fvcache.namesymbol = symbol(name);
				fvcache.location = l; */
#ifdef	MAILER
				if (v_record) {
					struct vaccess *v;

					v = (struct vaccess *)
					    emalloc(sizeof (struct vaccess));
					v->l = l;
					v->next = v_accessed;
					v_accessed = v;
				}
#endif	/* MAILER */
				return l;
			}
		}
	}
	return NULL;
}

/*
 * Variable expansion, handles all the special symbols in addition to the
 * normal variable names.  The value returned is always a copy of the
 * actual stored variable value, so destructive manipulation of the return
 * value is okay.
 */


conscell *
v_expand(s, caller, retcode)
	const char *s;			/* variable name */
	struct osCmd *caller;		/* caller, for $@ */
	int retcode;			/* last return code, for $? */
{
	conscell *d = NULL, *l = NULL, *tmp = NULL;
	register int n;
	register char *cp;
	char np[CHARSETSIZE+1]; /* each possible option, plus last NUL */

	GCVARS3;
	GCPRO3(d,l,tmp);

	/* fprintf(stderr,"v_expand('%s',...,retcode=%d)\n",s,retcode); */

	/*
	 * We only need to test the first character since the parser
	 * is supposed to enforce variable name syntax (so to speak).
	 */
	switch (*s) {
	case '@':
	case '*':
		if (caller == NULL || cdar(caller->argv) == NULL) {
			goto end_v_expand;
		}
		d = s_copy_tree(cdar(caller->argv));
		for (l = d; l != NULL && cdr(l) != NULL ; l = cdr(l)) {
			tmp = conststring(" ",1);
			cdr(tmp) = cdr(l);
			l = cdr(l) = tmp;
			if (*s == '@')
				tmp->flags |= NOQUOTEIFQUOTED;
		}
		/* grindef("ARGW = ", ncons(d)); */
		goto end_v_expand;

	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
		if (caller == NULL) {
			d = NULL;
			goto end_v_expand;
		}
		if ((d = s_nth(caller->argv, atoi(s))) == NULL) {
			goto end_v_expand;
		}
		d = copycell(d);
		cdr(d) = NULL;
		/* d = s_copy_tree(d); */ /* XXX: Needed ? */
		goto end_v_expand;

	case '#':
		if (*++s == '\0')
			d = car(caller->argv), n = -1;
		else if ((d = v_find(s)) == NULL || !LIST(cdr(d))) {
			UNGCPRO3;
			return NULL;
		} else
			d = cadr(d), n = 0;
		while (d != NULL)
			d = cdr(d), ++n;
		/* print n into a string */
		sprintf(np, "%d", n);
		n = strlen(np);
		d = newstring(dupnstr(np,n),n);
		goto end_v_expand;

	case '$':
		sprintf(np, "%d", (int)getpid());
		n = strlen(np);
		d = newstring(dupnstr(np,n),n);
		goto end_v_expand;

	case '?':
		if (retcode == -123456) {
			fprintf(stderr,
				"%s: BAD magic retcode on $? expansion!\n",
				progname);
			abort(); /* Bad magic retcode on $? expansion! */
		}
		sprintf(np, "%d", retcode);
		n = strlen(np);
		d = newstring(dupnstr(np,n),n);
		goto end_v_expand;

	case '!':
		sprintf(np, "%d", lastbgpid);
		n = strlen(np);
		d = newstring(dupnstr(np,n),n);
		goto end_v_expand;

	case '-':
		cp = np;
		for (n = 0; n < 256; ++n)
			if (isset(n))
				*cp++ = (char)n;
		if (cp == np)
			*cp++ = '-';
		*cp = '\0';
		n = strlen(np);
		d = newstring(dupnstr(np,n),n);
		goto end_v_expand;

	default:
		break;
	}

	if ((d = v_find(s)) != NULL) {
		d = copycell(cdr(d));
		cdr(d) = NULL;
	}
 end_v_expand:

	/* grindef("  d = ", d); */

	UNGCPRO3;

	return d;
}


/*
 * Maintain the ifs value and scanner syntax table whenever IFS changes.
 */

void
ifs_flush()
{
	conscell *d;

	d = v_find(IFS);
	if (d == NULL || cdr(d) == NULL || LIST(cdr(d)))
		return;
	ifs = cdr(d)->string;
	ShInitIFS(ifs);
}

/*
 * This routine is called on any variable assignment, to ensure that program
 * state is kept synchronized whenever relevant shell variables change.  There
 * is a comment about that at the top of this file.  Since this function is
 * called quite frequently and the list of variables to keep an eye on might
 * be quite long, we need a fast lookup method.  The hash values will be
 * unique for all variable names smaller than N characters long, where
 * N ~= # bits in int - # bits in CHARSETSIZE.  This is usually 24 on 32-bit
 * machines, which means the strcmp will almost always succeed.
 */

void
v_sync(name)
	const char *name;
{
	register unsigned int i;
	register int hash, j;
	register const char *cp;

	if (name == NULL)
		return;
	if (vcheck[0].v_hash == 0) {	/* just once */
		for (i = 0; i < sizeof vcheck / sizeof vcheck[0]; ++i) {
			cp = vcheck[i].v_name;
			hash = 0;
			for (j = CHARSETSIZE; *cp != '\0'; ++cp, j *= 2)
				hash += (*cp + j);
			vcheck[i].v_hash = hash;
		}
	}
	for (cp = name, j = CHARSETSIZE, hash = 0; *cp != '\0'; ++cp, j *= 2)
		hash += (*cp + j);
	for (i = 0; i < sizeof vcheck / sizeof vcheck[0]; ++i) {
		if (vcheck[i].v_hash == hash &&
		    strcmp(name, vcheck[i].v_name) == 0) {
			(vcheck[i].v_flush)();
			return;
		}
	}
}

/*
 * Easy interface to the assign() routine.
 */

void
v_setl(variable, value)
	const char *variable;
	conscell *value;
{
	int slen = strlen(variable);
	conscell *lhs = newstring(dupnstr(variable,slen),slen);
	GCVARS1;
	GCPRO1(lhs);
	assign(lhs, value, (struct osCmd *)NULL);
	UNGCPRO1;
}

/*
 * Easy interface to the assign() routine.
 */

void
v_set(variable, value)
	const char *variable, *value;
{
	conscell *rhs;
	GCVARS1;
	int slen = strlen(value);

	rhs = newstring(dupnstr(value,slen),slen);
	GCPRO1(rhs);
	v_setl(variable, rhs);
	UNGCPRO1;
}

/*
 * This function is called once at startup to initialize the shell variables
 * and the scope p-lists and such.
 */

void
v_envinit()
{
	conscell *s = NULL, *e = NULL;
	register char	**cpp, *cp;
	int gotpath, slen;
	memtypes oval;
	GCVARS2;

	GCPRO2(s, e);

	oval = stickymem;
	stickymem = MEM_MALLOC;
	envarlist = NIL;
	staticprot(&envarlist); /* Register this pointer to *all*
				   variables in use! */
	gotpath = 0;
	for (cpp = environ; cpp != NULL && *cpp != NULL; ++cpp) {

		cp = strchr(*cpp, '=');
		if (cp == NULL)
			continue;
		*cp++ = '\0';
		if (strcmp(*cpp, PATH) == 0)
			++gotpath;
		else if (strcmp(*cpp, IFS) == 0)
			continue;	/* don't inherit IFS */
		slen = strlen(*cpp);
		s = newstring(dupnstr(*cpp,slen),slen);
		nconc(envarlist, s);
		slen = strlen(cp);
		s = newstring(dupnstr(cp,slen),slen);
		nconc(envarlist, s);
		*--cp = '=';
	}
	if (!gotpath) {
		s = conststring(PATH,strlen(PATH));
		nconc(envarlist, s);
		s = conststring(DEFAULT_PATH,strlen(DEFAULT_PATH));
		nconc(envarlist, s);
	}
	/* now make it into a list of plists */
	e = s_copy_tree(car(envarlist));
	envarlist = ncons(envarlist);	/* ((env)) */
	/* ... and prepend the normal scope */
	/* ... and put it in the list of pre-defined non-env. variables */
	s = conststring(ENVIRONMENT,strlen(ENVIRONMENT));
	cdr(s) = envarlist;	/* must only use s_push with envarlist now */
	cdr(s_last(e)) = s;	/* (envcopy ENVIRONMENT (env))		*/
	s = ncons(e);		/* s = (envcopy ENVIRONMENT (env))	*/
	s_push(s, envarlist);	/* ((envcopy ENVIRONMENT (env)) (env))	*/
	s = NULL;

	stickymem = oval;
	UNGCPRO2;
}


/*
 * Ensure that a specific variable is going to be exported to programs.
 */

void
v_export(name)
	register const char	*name;
{
	conscell *l, *pl, *scope, *value;

	value = NULL;
	pl = NULL;
	/* find the first value of this variable that isn't exported */
	for (scope = car(envarlist); cdr(scope) != NULL; scope = cdr(scope)) {
		for (l = car(scope); l != NULL; pl = cdr(l), l = cddr(l)) {
			if (*name == *(l->string)
			    && name[1] == l->string[1]
			    && (name[1] == '\0'
				|| strcmp(name, l->string) == 0)) {
				if (l == car(scope))
					car(scope) = cddr(l);
				else
					cdr(pl) = cddr(l);
				cddr(l) = NULL;
				if (value == NULL)
					value = l;
				/* else
				   s_free_tree(l); */ /* GC work.. */
			}
		}
	}
	/* now search for the already-exported value */
	for (l = car(scope); l != NULL; pl = cdr(l), l = cddr(l)) {
		if (*name == *(l->string) && name[1] == l->string[1]
		    && (name[1] == '\0' || strcmp(name, l->string) == 0)) {
			/* it is already being exported */
			if (value == NULL)
				return;
			if (l == car(scope))
				car(scope) = value;
			else
				cdr(pl) = value;
			cddr(value) = cddr(l);
			cddr(l) = NULL;
			/* s_free_tree(l); */
			return;
		}
	}
	/* it isn't being exported */
	if (value == NULL) {
		GCVARS1;
		int slen = strlen(name);
		value = newstring(dupnstr(name,slen),slen);
		GCPRO1(value);
		cdr(value) = conststring("",0);
		UNGCPRO1;
	}
	cddr(value) = car(scope);
	car(scope) = value;
}

/*
 * Purge the dynamically closest instance of a variable.  This is intended
 * for undoing the effect of temporary variable assignments when the
 * variable didn't exist in advance.
 */

void
v_purge(name)
	const char * name;
{
	register conscell *l, *pl, *scope;

	pl = NULL;
	for (scope = car(envarlist); scope != NULL; scope = cdr(scope)) {
		for (l = car(scope); l != NULL; pl = cdr(l), l = cddr(l)) {
			if (strcmp(name, l->string) == 0) {
				if (l == car(scope))
					car(scope) = cddr(l);
				else
					cdr(pl) = cddr(l);
                                /* free it ... by dissociating the tail,
                                   GC does freeup.. */
                                cddr(l) = NULL;
				return;
			}
		}
	}
}
