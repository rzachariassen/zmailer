/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * Fake I/O that *must* be used by all internal builtin functions.
 *
 * To use, include <stdio.h> then this file.
 */

#ifndef	Z_IO_H
#define	Z_IO_H

#ifndef __
# ifdef __STDC__
#  define __(x) x
# else
#  define __(x) ()
# endif
#endif

struct	siobuf {
	struct siobuf	*_sb_data;	/* usually self pointer unless dup'ed */
	int		_sb_cnt;	/* no. of bytes left in buffer */
	char		*_sb_ptr;	/* current position in buffer */
	char		*_sb_base;	/* base of buffer */
	int		_sb_bufsiz;	/* size of buffer */
	short		_sb_flag;	/* open flags, O_CREAT == malloc'ed */
	short		_sb_refcnt;	/* reference count */
	struct siobuf	*sb_next;	/* linked list of these things */
};

#define sb_cnt		_sb_data->_sb_cnt
#define	sb_ptr		_sb_data->_sb_ptr
#define sb_base		_sb_data->_sb_base
#define sb_bufsiz	_sb_data->_sb_bufsiz
#define sb_flag		_sb_data->_sb_flag
#define sb_refcnt	_sb_data->_sb_refcnt

extern struct siobuf *siofds[];		/* array of linked lists of siobufs */

extern struct siobuf *sIOp;

#define	_FILEIO(p)  (((sIOp = siofds[FILENO(p)]) == NULL) || sIOp->sb_flag < 0)

#ifndef	REALSTDIO

#ifdef	putc
#undef	putc
#endif	/* putc */
#define putc(x, p)	(_FILEIO(p) ? std_putc(x, p): \
			 ((--sIOp->sb_cnt <= 0 ? siomore(sIOp) : 0), \
			  (int)(*sIOp->sb_ptr++ = (u_char)(x))))

#ifdef	getc
#undef	getc
#endif	/* getc */
#define	getc(p)		(_FILEIO(p) ? std_getc(p) : \
			 (--sIOp->sb_cnt >= 0 ? (int)*sIOp->sb_ptr++ : EOF))

#ifdef	putchar
#undef	putchar
#endif	/* putchar */
#define putchar(x)      putc((x),stdout)

#ifdef	getchar
#undef	getchar
#endif	/* getchar */
#define getchar()       getc(stdin)

#ifdef	ungetc
#undef	ungetc
#endif	/* ungetc */
#define	ungetc(c,p)	(_FILEIO(p) ? std_ungetc(c,p) : \
			 (sIOp->sb_ptr > sIOp->sb_base ? \
			     ++sIOp->sb_cnt, (int)(*--sIOp->sb_ptr = c) : EOF))

#ifdef	feof
#undef	feof
#define	feof(p)		(_FILEIO(p) ? std_feof(p) : \
			 sIOp->sb_ptr == sIOp->sb_base + sIOp->sb_bufsiz)
#endif	/* feof */

#define	ftell(p)	(_FILEIO(p) ? std_ftell(p) : \
			 (long)(sIOp->sb_ptr - sIOp->sb_base))

#define	fgets(s,n,p)	(_FILEIO(p) ? std_fgets(s,n,p) : siofgets(s,n,p))
#define	gets(s)		(_FILEIO(stdin) ? std_gets(s) : siogets(s))
#define	fputs(s,p)	(_FILEIO(p) ? std_fputs(s,p) : siofputs(s,p))
#define	puts(s)		(_FILEIO(stdout) ? std_puts(s) : sioputs(s))
#define	fread(b,s,n,p)	(_FILEIO(p) ? std_fread(b,s,n,p) : siofread(b,s,n,p))
#define	fwrite(b,s,n,p)	(_FILEIO(p) ? std_fwrite(b,s,n,p) : siofwrite(b,s,n,p))

#define	printf		(_FILEIO(stdout) ? std_printf : sioprintf)
#define	fprintf		siofprintf
/* #define fscanf siofscanf */

#endif	/* REALSTDIO */

extern char	*std_gets  __((char *));
extern char	*std_fgets __((char *, u_int, FILE *));
extern char	*siogets  __((char *));
extern char	*siofgets __((char *, u_int, FILE *));
extern int	std_puts  __((const char *));
extern int	std_fputs __((const char *, FILE *));
extern int	sioputs   __((const char *));
extern int	siofputs  __((const char *, FILE *));
extern int	siofread  __((char *, u_int, u_int, FILE *));
extern int	siofwrite __((const char *, u_int, u_int, FILE *));

extern int	std_putc __((int, FILE *));
extern int	std_getc __((FILE *));
extern int	std_ungetc __((int, FILE *));
extern int	std_feof   __((FILE *));
extern int	std_fread  __((char *, u_int, u_int, FILE *));
extern int	std_fwrite __((const char *, u_int, u_int, FILE *));
extern long	std_ftell  __((FILE *));
#ifdef HAVE_STDARG_H
extern int	(*std_printf) __((const char *fmt, ...));
extern int	sioprintf  __((const char *fmt, ...));
extern int	siofprintf __((FILE *fp, const char *fmt, ...));
#else
extern int	(*std_printf) __((const char *fmt, ...));
extern int	sioprintf  __((const char *fmt, ...));
extern int	siofprintf __((FILE *fp, const char *fmt, ...));
#endif
/* extern int siofscanf __(()); */
extern int	siomore   __((struct siobuf *));
#endif	/* Z_IO_H */
