/*
 *	Copyright 1989 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *
 *	LISPish memory allocation scheme with garbage collection by
 *	Matti Aarnio <mea@nic.funet.fi> 1996, 1999  containing ideas
 *	(and possible bits of code) from GNU Emacs, (C) FSF.
 */

/* #define CELLDEBUG */

#include "zmalloc.h"
#ifndef	_LISTUTILS_H
#define	_LISTUTILS_H

extern char *dupnstr __((const char *str, const int len));
extern char *mallocstr __((const int len));
extern void  freestr __((const char *str, const int slen));

/*
 * A LIST is a conscell with flags 0, the list is kept under dtpr.
 * A STRING is a conscell with flags !0, the string is kept under string.
 * The value of a LIST is a linked list of (conscell) of either type.
 * The value of a C variable must not be assumed to be either a LIST of STRING.
 * NIL is a LIST with null dtpr.
 */

typedef struct _conscell {
#if SIZEOF_VOID_P == 8 /* Presuming ALPHA with distaste to shorts.. */
	struct _conscell *next;
	union {
		struct _conscell *u_dtpr;
		char		 *u_string;
		const char	 *cu_string;
	} u;
	unsigned int		  flags;
	unsigned int		  slen;
#else /* presuming 32 bit machines */
	struct _conscell *next;
	union {
		struct _conscell *u_dtpr;
		char		 *u_string;
		const char	 *cu_string;
	} u;
	unsigned short		  flags;
	unsigned short		  slen;
#endif
} conscell;

#define	NEWSTRING	0x001	/* newly allocated string (free() when GC) */
#define	CONSTSTRING	0x002	/* constant, mutually exclusive with above */
#define	QUOTEDSTRING	0x004	/* quoted, don't apply IFS after expansion */
#define	NOQUOTEIFQUOTED	0x008	/* if to be quoted, don't quote (for "$@") */
#define ELEMENT		0x010	/* result of element expansion */
#define DSW_MARKER	0x020	/* for garbage collection run.. */
#define DSW_FREEMARK	0x040	/* for gc tracking, marks already free cell */
#define _DSW_MASK	0x060

#define	dtpr		u.u_dtpr
#define	string		u.u_string
#define	cstring		u.cu_string

#if defined(__GNUC__) && !defined(PROFILING) && defined(__OPTIMIZE__)

#ifndef EXTINLINE
#define EXTINLINE extern __inline__
#endif

EXTINLINE int LIST(conscell *C)   { return ((~(_DSW_MASK|ELEMENT) & (C)->flags) == 0); }
EXTINLINE int STRING(conscell *C) { return ((~(_DSW_MASK|ELEMENT) & (C)->flags) != 0); }
EXTINLINE int ISCONST(conscell *C) { return ((C)->flags & CONSTSTRING); }
EXTINLINE int ISNEW(conscell *C) { return ((C)->flags & NEWSTRING); }
EXTINLINE int ISQUOTED(conscell *C) { return ((C)->flags & QUOTEDSTRING); }
EXTINLINE int ISDONTQUOTE(conscell *C) {return ((C)->flags & NOQUOTEIFQUOTED);}
EXTINLINE int ISELEMENT(conscell *C) { return ((C)->flags & ELEMENT); }

#else /* ----- not profiling ----- */

#define LIST(C)		((~(_DSW_MASK|ELEMENT) & (C)->flags) == 0)
#define STRING(C)	((~(_DSW_MASK|ELEMENT) & (C)->flags) != 0)
#define	ISCONST(C)	((C)->flags & CONSTSTRING)
#define	ISNEW(C)	((C)->flags & NEWSTRING)
#define	ISQUOTED(C)	((C)->flags & QUOTEDSTRING)
#define	ISDONTQUOTE(C)	((C)->flags & NOQUOTEIFQUOTED)
#define	ISELEMENT(C)	((C)->flags & ELEMENT)

#endif /* .... not profiling .... */

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

#define grindef(T,L)	(fprintf(stderr, T), s_grind(L,stderr), putc('\n', stderr))

/*
 * These macros make it easier to maintain the illusion of dealing with lists.
 */

/* YOU MUST BE VERY CAREFUL ABOUT CALLING MACROS FROM WITHIN MACROS!!! */
/* BE VERY CAREFUL ABOUT USING EXPRESSIONS WITH SIDEEFFECTS INSIDE MACRO ARGS */
/* #define newcell()	(conscell *)tmalloc(sizeof (conscell)) */

#ifndef newcell
extern conscell * newcell __((void));
#endif

extern conscell *s_last __((conscell *));

#if !defined(__GNUC__)

extern conscell * copycell    __((conscell*X));
extern conscell * nconc       __((conscell *X, conscell *Y));
extern conscell * ncons       __((conscell *X));
extern conscell * cons        __((conscell *X, conscell *Y));
extern conscell * s_push      __((conscell *X, conscell *Y));
extern conscell * newstring   __((char *s, const int slen));
extern conscell * conststring __((const char *s, const int slen));

#else /* ---- not profiling ---- */

#if defined(__GNUC__) && !defined(PROFILING) && defined(__OPTIMIZE__)

EXTINLINE conscell *copycell(conscell *X) {
  conscell *tmp = newcell();
  *tmp = *X;
  if (STRING(tmp)) {
    tmp->string = dupnstr(tmp->cstring,tmp->slen);
    /* Copycell does *NOT* preserve other string flags,
       caller must do that! */
    tmp->flags = NEWSTRING;
  }
  return tmp;
}

/*
#define nconc(X,Y)	(car(X) != 0 ? cdr(s_last(car(X))) = (Y) \
			       : (car(X) = (Y), (X)))
*/

/* nconc(list, list) -> old (,@list ,@list) */
EXTINLINE conscell * nconc(conscell *X, conscell *Y)
{
  if (car(X)) {
    cdr(s_last(car(X))) = Y;
    return Y;
  } else {
    car(X) = Y;
    return X;
  }
}

/* ncons(s-expr) -> new (s-expr) */
EXTINLINE conscell * ncons(conscell *X)
{
  conscell *tmp = newcell();
  car(tmp) = X;
  tmp->slen = tmp->flags = 0;
  cdr(tmp) = NULL;
  return tmp;
}

/* cons(s-expr, list) -> new (s-expr ,@list) */
EXTINLINE conscell *cons(conscell *X, conscell *Y)
{
  conscell *tmp = ncons(X);
  cdar(tmp) = Y;
  return tmp;
}

/* s_push(s-expr, list) -> old (s-expr ,@list) */
EXTINLINE conscell * s_push(conscell *X, conscell *Y)
{
  cdr(X) = car(Y);
  car(Y) = X;
  return Y;
}

EXTINLINE conscell * newstring(char *s, const int slen)
{
  conscell *tmp = newcell();
  tmp->string = s;
  tmp->flags  = NEWSTRING;
  tmp->slen   = slen;
  cdr(tmp) = NULL;
  return tmp;
}

EXTINLINE conscell * conststring(const char *cs, const int slen)
{
  conscell *tmp = newcell();
  tmp->cstring = cs;
  tmp->flags   = CONSTSTRING;
  tmp->slen    = slen;
  cdr(tmp) = NULL;
  return tmp;
}

#else /* Not optimizing; no inlines.. */

#define copycell(X)					\
({conscell *_tmp = newcell(); *_tmp = *(X);		\
 if (STRING(_tmp)) {					\
   _tmp->string = dupnstr(_tmp->cstring,_tmp->slen);	\
    /* Copycell does *NOT* preserve other string flags, \
       caller must do that! */				\
   _tmp->flags = NEWSTRING;				\
 } _tmp;})

/* nconc(list, list) -> old (,@list ,@list) */
#if 1
#define nconc(X,Y)	(car(X) != 0 ? cdr(s_last(car(X))) = (Y) \
			       : (car(X) = (Y), (X)))
#else
#define nconc(X,Y)	\
	({conscell *_tmpX = (X), *_tmpY = (Y);		\
	  (car(_tmpX) != NULL ? cdr(s_last(car(_tmpX))) = _tmpY : \
	   (car(_tmpX) = _tmpY, _tmpX)); })
#endif

/* ncons(s-expr) -> new (s-expr) */
#define ncons(X)	\
	({conscell *_tmp = newcell(); car(_tmp) = (X); \
	 _tmp->slen = _tmp->flags = 0; cdr(_tmp) = NULL;  _tmp;})

/* cons(s-expr, list) -> new (s-expr ,@list) */
#define cons(X,Y)	\
	({conscell *_tmp = ncons(X); cdar(_tmp) = (Y); _tmp;})

/* s_push(s-expr, list) -> old (s-expr ,@list) */
#define s_push(X,Y)	\
	({conscell *_tmpX = (X); conscell *_tmpY = (Y);	  \
	  cdr(_tmpX) = car(_tmpY); car(_tmpY) = _tmpX; _tmpY;})

#define newstring(X,SLEN)	\
	({conscell *_tmp = newcell(); _tmp->string = (X); \
	  _tmp->flags = NEWSTRING; _tmp->slen = (SLEN);   \
	  cdr(_tmp) = NULL; _tmp;})

#define conststring(X,SLEN)	\
	({conscell *_tmp = newcell(); _tmp->cstring = (X); \
	  _tmp->flags = CONSTSTRING; _tmp->slen = (SLEN);  \
	  cdr(_tmp) = NULL; _tmp;})

#endif
#endif /* .... not profiling .... */

#define NIL		ncons(NULL)

/* listutils.c */
#ifdef	MALLOC_TRACE
#ifndef	s_copy_tree
extern conscell *__s_copy_tree __((conscell *, const char *, const char *));
#define s_copy_tree(l)		__s_copy_tree((l), __FILE__, __LINE__)
extern conscell *__s_copy_chain __((conscell *, const char *, const char *));
#define s_copy_chain(l)		__s_copy_chain((l), __FILE__, __LINE__)
#endif	/* !s_copy_tree */
#else	/* !MALLOC_TRACE */
extern conscell *s_copy_tree __((conscell *));
extern conscell *s_copy_chain __((conscell *));
#endif	/* MALLOC_TRACE */

/* LISPic memory allocator, and other stuff.. */
extern int cons_garbage_collect __(( void ));
extern int consvar_register __(( conscell ** ));
extern void *consvar_mark __(( void ));
extern void consvar_release __(( void * ));

/***** A bunch of neat things pulled in from GNU Emacs LISP interpreter *****/

/* Structure for recording stack slots that need marking.  */

/* This is a chain of structures, each of which points at
   a Lisp_Object variable whose value should be marked in
   garbage collection.  Normally every link of the chain is
   an automatic variable of a function, and its `val' points
   to some argument or local variable of the function.
   On exit to the function, the chain is set back to the value
   it had on entry.  This way, no link remains in the chain
   when the stack frame containing the link disappears.

   Every function that can call Feval must protect in this fashion
   all Lisp_Object variables whose contents will be used again.  */

struct gcpro {	/* ZMailer way -- to store a bit more info in one block */
  struct gcpro *next;
  int nvars;		/* Number of consecutive protected variables */
  conscell **var[6];	/* Address of first protected variable       */
  void *labeladdr;	/* Debug stuff... */
};

extern struct gcpro *gcprolist;

#ifdef CELLDEBUG /* while testing */
#define GCPLABPRINT(var) {fprintf(stderr,"%s:%d %s() GCPROx(" #var "= %p )\n", \
	__FILE__, __LINE__, __FUNCTION__, &var);}
#define GCPLABPRINTis(var) {fprintf(stderr,"%s:%d %s() GCPROis(" #var "= %p )\n", \
	__FILE__, __LINE__, __FUNCTION__, &var);}
#define GCULABPRINT(var) {fprintf(stderr,"%s:%d %s() UNGCPROx(" #var "= %p )\n", \
	__FILE__, __LINE__, __FUNCTION__, &var);}

#define UNGCASSERT(var) {GCULABPRINT(var); \
	if(gcprolist != &(var)) {	\
	  fprintf(stderr, "%s:%d %s UNGCASSERT FAIL; labeladdr = %p\n", \
	  __FILE__, __LINE__, __FUNCTION__ /* GCCism? */, \
	  (var).labeladdr), \
	*(long*)0 = 0; /* ZAP! */}}

#else

#define GCPLABPRINT(var) /*nothing*/
#define GCPLABPRINTis(var) /*nothing*/
#define GCULABPRINT(var) /*nothing*/

#define UNGCASSERT(var) /*no assert*/

#endif

#ifdef __GNUC__
#define LABELME(varname) ({__label__ _gc_; _gc_:; varname ## .labeladdr = &&_gc_;})
#else
#define LABELME(varname)
#endif
#define GCVARS1 struct gcpro gcpro1
#define GCPRO1(varname) \
 {LABELME(gcpro1);GCPLABPRINT(gcpro1);	\
  gcpro1.next = gcprolist; gcpro1.var[0] = &varname; gcpro1.nvars = 1; \
  gcprolist = &gcpro1; }
#define UNGCPRO1 {UNGCASSERT(gcpro1); gcprolist = gcpro1.next;}
#define GCPRO1STORE(storage,varname)	\
 {LABELME(storage gcpro1);GCPLABPRINT(storage gcpro1);	\
  storage gcpro1.next = gcprolist;	\
  storage gcpro1.var[0] = &varname;	\
  storage gcpro1.nvars = 1;		\
  gcprolist = &storage gcpro1; }
#define UNGCPROSTORE1(storage) \
 { UNGCASSERT(storage gcpro1); gcprolist = storage gcpro1.next; }

#define GCVARS2 struct gcpro gcpro2
#define GCPRO2(varname1, varname2) 	\
 {LABELME(gcpro2);GCPLABPRINT(gcpro2);				\
  gcpro2.var[0] = &varname1; gcpro2.var[1] = &varname2;		\
  gcpro2.next = gcprolist; gcpro2.nvars = 2;			\
  gcprolist = &gcpro2; }
#define UNGCPRO2 {UNGCASSERT(gcpro2);gcprolist = gcpro2.next;}
#define GCPRO2STORE(storage, varname1, varname2) \
 {LABELME(storage gcpro2);GCPLABPRINT(storage gcpro2);			\
  storage gcpro2.var[0] = &varname1; storage gcpro2.bar[1] = &varname2; \
  storage gcpro2.next = gcprolist; storage gcpro2.nvars = 2;		\
  gcprolist = &storage gcpro2; }
#define UNGCPROSTORE2(storage) \
 { UNGCASSERT(storage gcpro2);gcprolist = storage gcpro2.next; }

#define GCVARS3 struct gcpro gcpro3
#define GCPRO3(varname1, varname2, varname3) \
 {LABELME(gcpro3);GCPLABPRINT(gcpro3);				\
  gcpro3.var[0] = &varname1; gcpro3.var[1] = &varname2;		\
  gcpro3.var[2] = &varname3;					\
  gcpro3.next = gcprolist; gcpro3.nvars = 3;			\
  gcprolist = &gcpro3; }
#define UNGCPRO3 {UNGCASSERT(gcpro3);gcprolist = gcpro3.next;}
#define GCPRO3STORE(storage, varname1, varname2, varname3) \
 {LABELME(storage gcpro3);GCPLABPRINT(storage gcpro3);			\
  storage gcpro3.var[0] = &varname1; storage gcpro3.bar[1] = &varname2; \
  storage gcpro3.var[2] = &varname3;				\
  storage gcpro3.next = gcprolist; storage gcpro3.nvars = 3;	\
  gcprolist = &storage gcpro3; }
#define UNGCPROSTORE3(storage) \
 {UNGCASSERT(storage gcpro3);gcprolist = storage gcpro3.next; }

#define GCVARS4 struct gcpro gcpro4
#define GCPRO4(varname1, varname2, varname3, varname4) \
 {LABELME(gcpro4);GCPLABPRINT(gcpro4);				\
  gcpro4.var[0] = &varname1; gcpro4.var[1] = &varname2;		\
  gcpro4.var[2] = &varname3; gcpro4.var[3] = &varname4;		\
  gcpro4.next = gcprolist; gcpro4.nvars = 4;			\
  gcprolist = &gcpro4; }
#define UNGCPRO4 {UNGCASSERT(gcpro4);gcprolist = gcpro4.next;}
#define GCPRO4STORE(storage, varname1, varname2, varname3, varname4) \
 {LABELME(storage gcpro4);GCPLABPRINT(storage gcpro4);			\
  storage gcpro4.var[0] = &varname1; storage gcpro4.var[1] = &varname2; \
  storage gcpro4.var[2] = &varname3; storage gcpro4.var[3] = &varname4;	\
  storage gcpro4.next = gcprolist; storage gcpro4.nvars = 4;	\
  gcprolist = &storage gcpro4; }
#define UNGCPROSTORE4(storage) \
 {UNGCASSERT(storage gcpro4);gcprolist = storage gcpro4.next; }

#define GCVARS5 struct gcpro gcpro5
#define GCPRO5(varname1, varname2, varname3, varname4, varname5) \
 {LABELME(gcpro5);GCPLABPRINT(gcpro5);				\
  gcpro5.var[0] = &varname1; gcpro5.var[1] = &varname2;		\
  gcpro5.var[2] = &varname3; gcpro5.var[3] = &varname4;		\
  gcpro5.var[4] = &varname5;					\
  gcpro5.next = gcprolist; gcpro5.nvars = 5;			\
  gcprolist = &gcpro5; }
#define UNGCPRO5 {UNGCASSERT(gcpro5);gcprolist = gcpro5.next;}
#define GCPRO5STORE(storage, varname1, varname2, varname3, varname4, varname5) \
 {LABELME(storage gcpro5);GCPLABPRINT(storage gcpro5);			\
  storage gcpro5.var[0] = &varname1; storage gcpro5.var[1] = &varname2; \
  storage gcpro5.var[2] = &varname3; storage gcpro5.var[3] = &varname4;	\
  storage gcpro5.var[4] = &varname5;				\
  storage gcpro5.next = gcprolist; storage gcpro5.nvars = 5;	\
  gcprolist = &storage gcpro5; }
#define UNGCPROSTORE5(storage) \
 {UNGCASSERT(storage gcpro5);gcprolist = storage gcpro5.next;}

#define GCVARS6 struct gcpro gcpro6
#define GCPRO6(varname1, varname2, varname3, varname4, varname5, varname6) \
 {LABELME(gcpro6);GCPLABPRINT(gcpro6);				\
  gcpro6.var[0] = &varname1; gcpro6.var[1] = &varname2;		\
  gcpro6.var[2] = &varname3; gcpro6.var[3] = &varname4;		\
  gcpro6.var[4] = &varname5; gcpro6.var[5] = &varname6;		\
  gcpro6.next = gcprolist; gcpro6.nvars = 6;			\
  gcprolist = &gcpro6; }
#define UNGCPRO6 {UNGCASSERT(gcpro6);gcprolist = gcpro6.next;}
#define GCPRO6STORE(storage, varname1, varname2, varname3, varname4, varname5, varname6) \
 {LABELME(storage gcpro6);GCPLABPRINT(storage gcpro6);			\
  storage gcpro6.var[0] = &varname1; storage gcpro6.var[1] = &varname2; \
  storage gcpro6.var[2] = &varname3; storage gcpro6.var[3] = &varname4;	\
  storage gcpro6.var[4] = &varname5; storage gcpro6.var[5] = &varname6; \
  storage gcpro6.next = gcprolist; storage gcpro6.nvars = 6;	\
  gcprolist = &storage gcpro6; }
#define UNGCPROSTORE6(storage) \
 {UNGCASSERT(storage gcpro6);gcprolist = storage gcpro6.next;}



/* Call staticprot (&var) to protect static variable `var'.  */
extern void staticprot __((conscell **));
/* Register a function yielding conscells by calling function given as param */
extern void functionprot __((void (*)(conscell *)));

#endif	/* _LISTUTILS_H */
