/*
 *	Copyright 1989 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * List manipulation utility functions.
 */

#include "hostenv.h"
#include "listutils.h"
#ifdef	MAILER
#include "sift.h"
#endif	/* MAILER */
#include "mailer.h"
#include <ctype.h>
#include "sh.h"
#include "io.h"
#include "shconfig.h"

#include "libz.h"
#include "libsh.h"

/*
 * Cdr down a linked list to retrieve its last element.  This is not
 * quite identical to (last l), which would be s_last(car(l)) due to
 * our representation of lists.
 */

conscell *
s_last(list)
	register conscell *list;
{
	if (list == NULL)
		return NULL;
	while (cdr(list) != NULL)
		list = cdr(list);
	return list;
}

int
s_equal1(l1, l2)
	register conscell *l1, *l2;
{
	if (l1 == NULL)
		return (l2 == NULL);
	if (l2 == NULL)
		return 0;

	/* assert l1 != NULL && l2 != NULL */
	if (STRING(l1) && STRING(l2))
		return CISTREQ(l1->string, l2->string);
	return 0;
}

int
s_equal(l1, l2)
	register conscell *l1, *l2;
{
	if (l1 == NULL)
		return l2 == NULL;
	else if (l2 == NULL)
		return 0;

	/* assert l1 != NULL && l2 != NULL */
	if (STRING(l1) && STRING(l2) && CISTREQ(l1->string, l2->string))
		return s_equal(cdr(l1), cdr(l2));
	else if (LIST(l1) && LIST(l2) && s_equal(car(l1), car(l2)))
		return s_equal(cdr(l1), cdr(l2));
	return 0;

#if 0
	if (l1->next == NULL) {
		if (l2->next == NULL) {
			if (STRING(l1)) {
				if (STRING(l2))
					return CISTREQ(l1->string, l2->string);
				else
					return 0;
			} else {
				if (STRING(l2))
					return 0;
				else
					return s_equal(car(l1), car(l2));
			}
		} else
			return 0;
	} else if (l2->next == NULL)
		return 0;
	else
		return s_equal(cdr(l1), cdr(l2));
#endif
}

/*
 * The N'th element of a list.
 */

conscell *
s_nth(list, n)
	register conscell *list;
	register int n;
{
	if (list == NULL || STRING(list))
		return NULL;
	for (list = car(list); list != NULL && n-- > 0; list = cdr(list))
		continue;
	if (list == NULL)
		return NULL;
	return list;
}


#ifdef CONSCELL_PREV
/*
 * Set the back-pointers (->prev) for the passed structure.
 * This is used by the setf facility to figure out where stuff is stashed.
 */

void
s_set_prev(prev, list)
	register conscell *prev, *list;
{
	while (list != NULL) {
		list->prev = prev;
		if (LIST(list))
			s_set_prev(list, car(list));
		prev = list;
		list = cdr(list);
		if (list == envarlist)
			return;
		else if (list)
			list->pflags = 1;
	}
}
#endif

/*
 * Does a string contain any metacharacters that might be misinterpreted
 * if the string was read in as is?
 */

STATIC int s_isname __((const char *s));
STATIC int
s_isname(s)
	register const char *s;
{
	while (*s != '\0') {
	  int c = (*s) & 0xFF;
	  if (!isascii(c) || !isprint(c) || c == '\\' || c  ==  ' ' ||
	      c == '\''   || c == '"'  || *s == '`') {
			return 0;
		} else
			++s;
	}
	return 1;
}

/*
 * Print a string in quoted form.
 */

STATIC void s_pname __((const char *s, FILE *fp));
STATIC void
s_pname(s, fp)
	register const char *s;
	FILE *fp;
{
	const char *base = s;

	if (*s != '\'')
		putc('\'', fp);
	while (*s != '\0') {
		if (*s == '\'') {
			if (s > base)
				putc('\'', fp);	/* end previous string */
			putc('\\', fp); /* backslash */
			putc('\'', fp); /* quote */
			if (*(s+1) == '\0')
				return;
			/* putc('\'', fp); */	/* start new string */
		}
		putc(*s, fp);
		++s;
	}
	putc('\'', fp);
}

/*
 * Print a list.
 */

void
s_grind(list, fp)
	conscell *list;
	FILE *fp;
{
	if (list == NULL) {
		fputs("<0>", fp);
		return;
	} else if (STRING(list)) {
		if (list->string != NULL) {
		  if (list->string[0] && s_isname(list->string))
		    fputs(list->string, fp);
		  else
		    s_pname(list->string, fp);
		} else
		  fputs("\\000", fp);
	} else if ((list = car(list))) {
		putc('(', fp);
		while (list != NULL) {
			if (list == envarlist)
				fputs(ENVIRONMENT, fp);
			else
				s_grind(list, fp);
			if ((list = cdr(list)))
				putc(' ', fp);
		}
		putc(')', fp);
	} else
		fputs("nil", fp);
}

/*
 * Print a list to stdout.
 */

void
_grind(list)
	conscell *list;
{
	s_grind(list, stderr);
	putc('\n', stderr);
}

/*
 * Squish a linked list of buffers into a single buffer.
 */

conscell *
s_catstring(s)
	conscell *s;
{
	char *cp, *buf;
	conscell *sp, *tmp;
	int len, quoted;

	if (cdr(s) == NULL)
		return s;
	len = 0;
	for (sp = s; sp != NULL; sp = cdr(sp))
		if (sp->string)
			len += strlen(sp->string);
	quoted = 0;
	cp = buf = (char *)tmalloc(len+1);
	for (sp = s; sp != NULL; sp = cdr(sp)) {
		if (sp->string) {
			strcpy(cp, sp->string);
			cp += strlen(cp);
			quoted += ISQUOTED(sp);
		}
	}
	*cp++ = '\0';
	sp = newstring(buf);
	if (quoted)
		sp->flags |= QUOTEDSTRING;
	return sp;
}

/*
 * Construct a list structure representing the data on the input file pointer.
 */

conscell *
s_read(fp)
	FILE *fp;
{
	register int ch;
	register char *bp;
	register conscell **listp;
	char	ech, buf[8096];
	conscell *list;

	if (feof(fp))
		return NULL;
	while ((ch = getc(fp)) != EOF)
		if (!(isascii(ch) && isspace(ch)))
			break;
	bp = buf;
	list = NULL;	/* lint */
	switch (ch) {
	case '(':
		list = newcell();
		list->flags = 0;
		cdr(list) = NULL;
#ifdef CONSCELL_PREV
		list->prev = 0;
		list->pflags = 0;
#endif
		listp = &car(list);
		do {
			if ((*listp = s_read(fp)) == NULL)
				break;
			if ((cdr(*listp) = s_read(fp)))
				listp = &cddr(*listp);
			else
				break;
		} while (1);
		break;
	case ')':
	case EOF:
		return NULL;
	case '"':	/* quoted symbol */
	case '\'':
		ech = ch;
		list = newcell();
		cdr(list) = NULL;
		list->flags = NEWSTRING;	/* string */
#ifdef CONSCELL_PREV
		list->prev = 0;
		list->pflags = 0;
#endif
		while ((ch = getc(fp)) != EOF && ch != ech) {
			if (ch == '\\')
				if ((ch = getc(fp)) == EOF)
					break;
			*bp++ = ch;
		}
		*bp = '\0';
		list->string = strnsave(buf, bp - buf);
		break;
	default:	/* normal symbol */
		list = newcell();
		cdr(list) = NULL;
		list->flags = NEWSTRING;	/* string */
#ifdef CONSCELL_PREV
		list->prev = 0;
		list->pflags = 0;
#endif
		*bp++ = ch;
		while ((ch = getc(fp)) != EOF && isascii(ch) &&
		       !isspace(ch) && ch != '(' && ch != ')') {
			if (ch == '\\')
				if ((ch = getc(fp)) == EOF)
					break;
			*bp++ = ch;
		}
		if (ch != EOF)
			ungetc(ch, fp);
		*bp = '\0';
		list->string = strnsave(buf, bp - buf);
		break;
	}
	/* putc('>', runiofp);s_grind(list, runiofp); putc('\n', runiofp); */
	return list;
}

/*
 * Turn an argc,argv type parameter spec into a list of the argv's.
 */

conscell *
s_listify(ac, av)
	register int ac;
	register const char *av[];
{
	register conscell **pl, *tmp;
	conscell *l;

	for (l = NIL, pl = &car(l); ac-- > 0 && *av != NULL; pl = &cdr(*pl))
		*pl = conststring(*av++);
	*pl = NULL;
	return l;
}

/* push a command string onto the input stack */

conscell *
s_pushstack(l, s)
	conscell *l;
	const char *s;
{
	conscell *d, *tmp;
	memtypes oval = stickymem;

	stickymem = MEM_MALLOC;
	d = newstring(strsave(s));
	cdr(d) = conststring(" \n");
	cddr(d) = l;
	stickymem = oval;
	return d;
}

conscell *
s_popstack(l)
	conscell *l;
{
	conscell *d;

	d = l;
	l = cdr(l);
	cdr(d) = NULL;
	s_free_tree(d);
	return l;
}

conscell *
newcell()
{
	return (conscell*)tmalloc(sizeof(conscell));
}
