/*
 *	Copyright 1989 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *
 *	Fully LISPis memory allocation scheme with garbage collection
 *	by   Matti Aarnio <mea@nic.funet.fi> 1996
 */

#include "malloc.h"
#ifndef	_LISTUTILS_H
#define	_LISTUTILS_H

/*
 * A LIST is a conscell with flags 0, the list is kept under dtpr.
 * A STRING is a conscell with flags !0, the string is kept under string.
 * The value of a LIST is a linked list of (conscell) of either type.
 * The value of a C variable must not be assumed to be either a LIST of STRING.
 * NIL is a LIST with null dtpr.
 */

typedef struct _conscell {
	struct _conscell *next;
	union {
		struct _conscell *u_dtpr;
		char		 *u_string;
		const char	 *cu_string;
	} u;
#if 1 /* use this branch when you don't have setf(),
	 and friends in use anymore... */
	int		flags;
#else
#define CONSCELL_PREV
#ifdef __alpha	/* Alpha doesn't take nicely stores into too small objects.
		   The hardware has store support only for 32/64/128-bit
		   objects. (Well, newer EV5/EV56/EV6 processors have byte
		   and short store/read operations too..) */
	int		flags;	/* if 0 is a list, otherwise a string */
	int		pflags;	/* if 1 x->prev->cdr == x */
#else
	short		flags;	/* if 0 is a list, otherwise a string */
	short		pflags;	/* if 1 x->prev->cdr == x */
#endif
	struct _conscell *prev;	/* points to whichever dtpr points to here */
#endif
} conscell;

#define	NEWSTRING	0001	/* newly allocated string (free() when GC) */
#define	CONSTSTRING	0002	/* constant, mutually exclusive with above */
#define	QUOTEDSTRING	0004	/* quoted, don't apply IFS after expansion */
#define	NOQUOTEIFQUOTED	0010	/* if to be quoted, don't quote (for "$@") */
#define ELEMENT		0020	/* result of element expansion */
#define DSW_MARKER	0040	/* for garbage collection run.. */
#define DSW_BACKPTR	0100	/* ... this too (DSW == Deutch-Schorr-Waite) */

#define LIST(C)		((C)->flags == 0)
#define STRING(C)	((C)->flags != 0)
#define	ISCONST(C)	((C)->flags & CONSTSTRING)
#define	ISNEW(C)	((C)->flags & NEWSTRING)
#define	ISQUOTED(C)	((C)->flags & QUOTEDSTRING)
#define	ISDONTQUOTE(C)	((C)->flags & NOQUOTEIFQUOTED)
#define	ISELEMENT(C)	((C)->flags & ELEMENT)

#define	dtpr		u.u_dtpr
#define	string		u.u_string
#define	cstring		u.cu_string


#define	car(X)		(X)->dtpr
#define	cdr(X)		(X)->next
#define	caar(X)		car(car(X))
#define cadr(X)		car(cdr(X))
#define	cdar(X)		cdr(car(X))
#define	cddr(X)		cdr(cdr(X))
#define	caaar(X)	car(car(car(X)))
#define	cdaar(X)	cdr(car(car(X)))
#define	cadar(X)	car(cdr(car(X)))
#define	cddar(X)	cdr(cdr(car(X)))

#define grindef(T,L)	(fprintf(runiofp, T), s_grind(L,runiofp), putc('\n', runiofp))

/*
 * These macros make it easier to maintain the illusion of dealing with lists.
 */

/* YOU MUST BE VERY CAREFUL ABOUT CALLING MACROS FROM WITHIN MACROS!!! */
/* BE VERY CAREFUL ABOUT USING EXPRESSIONS WITH SIDEEFFECTS INSIDE MACRO ARGS */
/* #define newcell()	(conscell *)tmalloc(sizeof (conscell)) */

#ifndef newcell
extern conscell * newcell __((void));
#endif
#define copycell(X)	(tmp = newcell(), *tmp = *(X), tmp)
/* nconc(list, list) -> old (,@list ,@list) */
#define nconc(X,Y)	(car(X) != 0 ? cdr(s_last(car(X))) = (Y) \
			       : (car(X) = (Y), (X)))
/* ncons(s-expr) -> new (s-expr) */
#ifdef CONSCELL_PREV
#define ncons(X)	(tmp = newcell(), car(tmp) = (X), \
	 tmp->flags = 0, cdr(tmp) = 0, tmp->prev = 0, tmp->pflags = 0, tmp)
/* cons(s-expr, list) -> new (s-expr ,@list) */
#else
#define ncons(X)	(tmp = newcell(), car(tmp) = (X), \
			 tmp->flags = 0, cdr(tmp) = 0, tmp)
/* cons(s-expr, list) -> new (s-expr ,@list) */
#endif
#define cons(X,Y)	(tmp = ncons(X), cdar(tmp) = (Y), tmp)
/* s_push(s-expr, list) -> old (s-expr ,@list) */
#define s_push(X,Y)	(cdr(X) = car(Y), car(Y) = (X), (Y))
#ifdef CONSCELL_PREV
#define newstring(X)	(tmp = newcell(), tmp->string = (X), \
    tmp->flags = NEWSTRING, cdr(tmp) = 0, tmp->prev = 0, tmp->pflags = 0, tmp)
#define conststring(X)	(tmp = newcell(), tmp->cstring = (X), \
    tmp->flags = CONSTSTRING, cdr(tmp) = 0, tmp->prev = 0, tmp->pflags = 0, tmp)
#else
#define newstring(X)	(tmp = newcell(), tmp->string = (X), \
			 tmp->flags = NEWSTRING, cdr(tmp) = 0, tmp)
#define conststring(X)	(tmp = newcell(), tmp->cstring = (X), \
			 tmp->flags = CONSTSTRING, cdr(tmp) = 0, tmp)
#endif
#define NIL		ncons(0)

/* listutils.c */
#ifdef	MALLOC_TRACE
#ifndef	s_copy_tree
extern conscell *__s_copy_tree __((conscell *, const char *, const char *));
extern void __s_free_tree __((conscell *, const char *, const char *));
#define s_copy_tree(l)		__s_copy_tree((l), __FILE__, __LINE__)
#define s_free_tree(l)		__s_free_tree((l), __FILE__, __LINE__)
#endif	/* !s_copy_tree */
#else	/* !MALLOC_TRACE */
extern conscell *s_copy_tree __((conscell *));
extern void      s_free_tree __((conscell *));
#endif	/* MALLOC_TRACE */

/* LISPic memory allocator, and other stuff.. */
extern int cons_garbage_collect __((void));
extern int consvar_register __(( const conscell* ));
extern void *consvar_mark __(( void ));
extern void consvar_release __(( void* ));

#endif	/* _LISTUTILS_H */
