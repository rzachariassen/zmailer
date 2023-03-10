/*  Author: Mark Moraes <moraes@csri.toronto.edu> */
/* $Id: malloc.h,v 1.2 1999/12/29 19:37:35 mea Exp $ */
#ifndef __XMALLOC_H__
#define __XMALLOC_H__

#if defined(ANSI_TYPES) || defined(__STDC__)
#define univptr_t		void *
#else	/* ! ANSI_TYPES */
#define univptr_t		char *
#if !defined(HAVE_CONFIG_H)
#define	size_t		unsigned int
#endif
#endif	/* ANSI_TYPES */

#if defined(ANSI_TYPES) && !defined(__STDC__) && !defined(HAVE_CONFIG_H)
#define size_t		unsigned long
#endif

#if defined(__STDC__)
#define __proto(x)	x
#else
#define __proto(x)	()
#endif

/*
 *  defined so users of new features of this malloc can #ifdef
 *  invocations of those features.
 */
#define CSRIMALLOC

#ifdef MALLOC_TRACE
/* Tracing malloc definitions - helps find leaks */

extern univptr_t __malloc __proto((size_t, const char *, int));
extern univptr_t __calloc __proto((size_t, size_t, const char *, int));
extern univptr_t __realloc __proto((univptr_t, size_t, const char *, int));
extern univptr_t __valloc __proto((size_t, const char *, int));
extern univptr_t __memalign __proto((size_t, size_t, const char *, int));
extern univptr_t __emalloc __proto((size_t, const char *, int));
extern univptr_t __ecalloc __proto((size_t, size_t, const char *, int));
extern univptr_t __erealloc __proto((univptr_t, size_t, const char *, int));
extern char *___strdup __proto((const char *, const char *, int));
extern char *__strsave __proto((const char *, const char *, int));
extern void __free __proto((univptr_t, const char *, int));
extern void __cfree __proto((univptr_t, const char *, int));

#define malloc(x)		__malloc((x), __FILE__, __LINE__)
#define calloc(x, n)		__calloc((x), (n), __FILE__, __LINE__)
#define realloc(p, x)		__realloc((p), (x), __FILE__, __LINE__)
#define memalign(x, n)		__memalign((x), (n), __FILE__, __LINE__)
#define valloc(x)		__valloc((x), __FILE__, __LINE__)
#define emalloc(x)		__emalloc((x), __FILE__, __LINE__)
#define ecalloc(x, n)		__ecalloc((x), (n), __FILE__, __LINE__)
#define erealloc(p, x)		__erealloc((p), (x), __FILE__, __LINE__)
#define strdup(p)		___strdup((p), __FILE__, __LINE__)
#define strsave(p)		__strsave((p), __FILE__, __LINE__)
/* cfree and free are identical */
#define cfree(p)		__free((p), __FILE__, __LINE__)
#define free(p)			__free((p), __FILE__, __LINE__)

#else /* MALLOC_TRACE */

extern univptr_t malloc __proto((size_t));
extern univptr_t calloc __proto((size_t, size_t));
extern univptr_t realloc __proto((univptr_t, size_t));
extern univptr_t valloc __proto((size_t));
extern univptr_t memalign __proto((size_t, size_t));
extern univptr_t emalloc __proto((size_t));
extern univptr_t ecalloc __proto((size_t, size_t));
extern univptr_t erealloc __proto((univptr_t, size_t));
extern char *strdup __proto((const char *));
extern char *strsave __proto((const char *));
extern void free __proto((univptr_t));
extern void cfree __proto((univptr_t));

#endif /* MALLOC_TRACE */

extern void mal_debug __proto((int));
extern void mal_dumpleaktrace __proto((FILE *));
extern void mal_heapdump __proto((FILE *));
extern void mal_leaktrace __proto((int));
extern void mal_sbrkset __proto((int));
extern void mal_slopset __proto((int));
extern void mal_statsdump __proto(());
extern void mal_setstatsfile __proto((FILE *));
extern void mal_trace __proto((int));
extern int mal_verify __proto((int));
extern void mal_mmap __proto((char *));


/*
 *  You may or may not want this - In gcc version 1.30, on Sun3s running
 *  SunOS3.5, this works fine.
 */
#ifdef __GNUC__
#define alloca(n) __builtin_alloca(n)
#endif /* __GNUC__ */
#ifdef sparc
#define alloca(n) __builtin_alloca(n)
#endif /* sparc */

#ifdef ANSI_TYPES
#undef univptr_t
#else	/* ! ANSI_TYPES */
#undef univptr_t
#undef size_t
#endif	/* ANSI_TYPES */

/* Just in case you want an ANSI malloc without an ANSI compiler */
#if defined(ANSI_TYPES) && !defined(__STDC__)
#undef size_t
#endif

#undef __proto

#endif /* __XMALLOC_H__ */ /* Do not add anything after this line */
