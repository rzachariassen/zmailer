/*
 *	Copyright 1989 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * This file contains support routines for our (hopefully) portable version
 * of string-stream stdio.  Much or most of this stuff would be superfluous
 * if stdio allowed you to open strings.  Sigh.
 */

#include "hostenv.h"
#include <stdio.h>
#ifdef HAVE_STDARG_H
# include <stdarg.h>
#else
# include <varargs.h>
#endif
#include <fcntl.h>
#include <sys/file.h>
#include "shconfig.h"

#define REALSTDIO
#include "io.h"

STATIC int vsiodoprnt __((struct siobuf *, const char *, va_list));

#define NO_FLOAT_CONVERSION
#ifndef NO_FLOAT_CONVERSION
extern int cvt();
extern double modf();
extern char *exponent(), *round();
#endif
#if !defined(__STDC__) && !defined(_AIX)
 extern int printf();
#endif

struct siobuf *siofds[MAXNFILE];	/* string buffers */

struct siobuf *sIOp;	/* generic scratch pointer */

/* wrapper routines for selecting the standard stdio functions/macros */

int std_putc(ch, fp) int ch; FILE *fp; { return putc(ch, fp); }

int std_getc(fp) FILE *fp; { return getc(fp); }

int std_ungetc(ch, fp) int ch; FILE *fp; { return ungetc(ch, fp); }

int std_feof(fp) FILE *fp; { return feof(fp); }

long std_ftell(fp) FILE *fp; { return ftell(fp); }

#if 0
char *std_gets(s) char *s; { return gets(s); }
#endif

int std_fgetc(fp) FILE *fp; { return fgetc(fp); }
char *std_fgets(s, n, fp) char *s; u_int n; FILE *fp; { return fgets(s, n, fp); }

int std_puts(s) const char *s; { return puts(s); }

int std_fputs(s, fp) const char *s; FILE *fp; { return fputs(s, fp); }

#ifdef HAVE_STDARG_H
#if (defined(__GNUC__) && defined(sun) && !defined(__svr4__))
extern int printf(); /* Sun 4.1.x with old GCC */
#endif
int (*std_printf) __((const char *fmt, ...)) = (int(*)__((const char *, ...)))printf;
#else
#if (defined(__GNUC__) && defined(sun) && !defined(__svr4__))
extern int printf __((const char *fmt, ...));
#endif
int (*std_printf) __((const char *fmt, ...)) = (int (*) __((const char *fmt, ...)))printf;
#endif

int std_fread(b,s,n,fp) char *b; u_int s, n; FILE *fp;{ return fread(b,s,n,fp); }

int std_fwrite(b,s,n,fp) const char *b; u_int s, n; FILE *fp;{ return fwrite(b,s,n,fp); }

/* functionally equivalent (to stdio) routines to deal with string buffers */

#if 0
char *
siogets(s)
	register char *s;
{
	register struct siobuf *siop = siofds[FILENO(stdin)];
	register int ch;
	char *os = s;

	/* assert siop != NULL */
	while (siop->sb_ptr + siop->sb_cnt < siop->sb_base + siop->sb_bufsiz) {
	  if ((ch = (int)*siop->sb_ptr++) == '\0' || ch == '\n')
	    break;
	  *s++ = ch;
	}
	*s = '\0';
	return (s == os) ? NULL : os;
}
#endif

int
siofgetc(fp)
	FILE *fp;
{
	register struct siobuf *siop = siofds[FILENO(fp)];

	/* assert siop != NULL */
	if (siop->sb_ptr + siop->sb_cnt < siop->sb_base + siop->sb_bufsiz) {
	  register int ch = (int)*siop->sb_ptr++;
	  if (ch == '\0')  return EOF;
	  return ch;
	}
	return EOF;
}

char *
siofgets(s, n, fp)
	register char *s;
	register u_int n;
	FILE *fp;
{
	register struct siobuf *siop = siofds[FILENO(fp)];
	register int ch;
	char *os = s;

	/* assert siop != NULL */
	while (--n > 0 &&
	       siop->sb_ptr + siop->sb_cnt < siop->sb_base + siop->sb_bufsiz) {
	  ch = (int)*siop->sb_ptr++;
	  if (ch == '\0')
	    break;
	  *s++ = ch;
	  if (ch == '\n')
	    break;
	}
	*s = '\0';
	return (s == os) ? NULL : os;
}

int
sioputs(s)
	register const char *s;
{
	register struct siobuf *siop = siofds[FILENO(stdout)];

	if (!s)
		return EOF;
	siofputs(s, stdout);
	if ((--siop->sb_cnt) <= 0)
	  siomore(siop);
	*siop->sb_ptr = '\n';
	siop->sb_ptr++;
	return 0;
}

int
siofputs(s, fp)
	register const char *s;
	FILE *fp;
{
	register struct siobuf *siop = siofds[FILENO(fp)];

	if (!s)
		return EOF;
	while (*s != '\0') {
	  if ((--siop->sb_cnt) <= 0)
	    siomore(siop);
	  *siop->sb_ptr++ = *s++;
	}
	return 0;
}

#ifndef	HAVE_VPRINTF
/* This is done in desperation... */
int
vfprintf(fp, fmt, ap)
	FILE *fp;
	char *fmt;
	va_list ap;
{
        register int count;

        if (!(fp->_flag & _IOWRT)) {
	  /* if no write flag */
	  if (fp->_flag & _IORW) {
	    /* if ok, cause read-write */
	    fp->_flag |= _IOWRT;
	  } else {
	    /* else error */
	    return EOF;
	  }
        }
        count = _doprnt(fmt, ap, fp);
        return(ferror(fp)? EOF: count);
}
#endif	/* !HAVE_VPRINTF */

int
#ifdef HAVE_STDARG_H
#ifdef __STDC__
siofprintf(FILE *fp, const char *fmt, ...)
#else /* Non ANSI-C */
siofprintf(fp, fmt)
	FILE *fp;
	const char *fmt;
#endif
#else
siofprintf(va_alist)
	va_dcl
#endif
{
	va_list ap;
	int r;
#ifdef HAVE_STDARG_H
	va_start(ap,fmt);
#else
	FILE *fp;
	char *fmt;

	va_start(ap);
	fp = va_arg(ap, FILE *);
	fmt = va_arg(ap, char *);
#endif
	if (_FILEIO(fp))
	  r = vfprintf(fp, fmt, ap);
	else
	  r = vsiodoprnt(sIOp, fmt, ap);
	va_end(ap);
	return r;
}

int
#ifdef HAVE_STDARG_H
#ifdef __STDC__
sioprintf(const char *fmt, ...)
#else /* Non ANSI-C */
sioprintf(fmt)
	const char *fmt;
#endif
#else
sioprintf(va_alist)
	va_dcl
#endif
{
	va_list ap;
	int r;
#ifdef HAVE_STDARG_H
	va_start(ap, fmt);
#else
	const char *fmt;

	va_start(ap);
	fmt = va_arg(ap, char *);
#endif
	if (_FILEIO(stdout))
	  r = vfprintf(stdout, fmt, ap);
	else
	  r = vsiodoprnt(sIOp, fmt, ap);
	va_end(ap);
	return r;
}

int
siofread(b, s, n, fp)
	char *b;
	u_int s, n;
	FILE *fp;
{
	struct siobuf *siop = siofds[FILENO(fp)];

	s *= n;
	n = s;
	/* assert siop != NULL */
	while ((s > 0) &&
	       ((siop->sb_ptr + siop->sb_cnt) < (siop->sb_base + siop->sb_bufsiz)))
	  --s, *b++ = *siop->sb_ptr++;
	return n-s;
}

int
siofwrite(b, s, n, fp)
	register const char *b;
	register u_int s, n;
	FILE *fp;
{
	register struct siobuf *siop = siofds[FILENO(fp)];

	if (!b)
		return EOF;
	s *= n;
	n = s;
	while (s-- > 0) {
	  if ((--siop->sb_cnt) <= 0)
	    siomore(siop);
	  *siop->sb_ptr++ = *b++;
	}
	return n;
}


#define	CLICK	120		/* this should cover most addresses/lists */

int
siomore(siop)
	struct siobuf *siop;
{
	char *prevbase;

	if (siop->sb_base == NULL) {
	  /* first time around, we allocate off scratch memory */
	  siop->sb_bufsiz = CLICK;
	  /* note: base needn't be aligned */
	  siop->sb_base = (char *)emalloc(siop->sb_bufsiz);
	  siop->sb_flag |= O_CREAT;
	  siop->sb_ptr = siop->sb_base;
	  siop->sb_cnt = siop->sb_bufsiz;
	} else {
	  /*
	   * if we overran scratch memory allocation, this buffer
	   * might get real big, so do malloc/realloc instead.
	   */
	  prevbase = siop->sb_base;
	  siop->sb_cnt += siop->sb_bufsiz;
	  siop->sb_bufsiz *= 2;
	  if (siop->sb_flag & O_CREAT) {
	    /* ahh, it already is a malloc'ed buffer */
	    siop->sb_base = (char *)erealloc(siop->sb_base,
					     siop->sb_bufsiz);
	  } else {
	    /* copy existing buffer into malloc'ed ditto */
	    siop->sb_base = (char *)emalloc(siop->sb_bufsiz);
	    memcpy(siop->sb_base, prevbase, siop->sb_ptr - prevbase);
	    siop->sb_flag |= O_CREAT;
	  }
	  siop->sb_ptr += siop->sb_base - prevbase;
	}
	return siop->sb_cnt;
}

/*
 * Everything from here on down is derived from libc/gen/stdio/doprnt.c on
 * the 4.3tahoe tape, and is therefore:
 */
/*
 * Copyright (c) 1988 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
STATIC char sccsid[] = "@(#)doprnt.c	5.35 (Berkeley) 6/27/88";
#endif /* LIBC_SCCS and not lint */

#include <ctype.h>

/* 11-bit exponent (VAX G floating point) is 308 decimal digits */
#define	MAXEXP		308
/* 128 bit fraction takes up 39 decimal digits; max reasonable precision */
#define	MAXFRACT	39

#define	DEFPREC		6

#define	BUF		(MAXEXP+MAXFRACT+1)	/* + decimal point */

#if 1
static void sio_PUTC __((int ch, struct siobuf *siop));

static void sio_PUTC(ch,siop)
register int ch;
register struct siobuf *siop;
{
	if ((--siop->sb_cnt) <= 0)
	  siomore(siop);
	*(siop->sb_ptr++) = ch;
}
#define PUTC(ch) sio_PUTC(ch,siop)
#else
#define	PUTC(ch)	(void) ((((--siop->sb_cnt) <= 0) ? siomore(siop) : 0), \
				(int)(*(siop->sb_ptr++) = (ch)))
#endif
#define	ARG() \
	_ulong = flags&LONGINT ? va_arg(argp, long) : \
	    flags&SHORTINT ? (short)va_arg(argp, int) : va_arg(argp, int);

#define	todigit(c)	((c) - '0')
#define	tochar(n)	((n) + '0')

/* have to deal with the negative buffer count kludge */
#define	NEGATIVE_COUNT_KLUDGE

#define	LONGINT		0x01		/* long integer */
#define	LONGDBL		0x02		/* long double; unimplemented */
#define	SHORTINT	0x04		/* short integer */
#define	ALT		0x08		/* alternate form */
#define	LADJUST		0x10		/* left adjustment */
#define	ZEROPAD		0x20		/* zero (as opposed to blank) pad */
#define	HEXPREFIX	0x40		/* add 0x or 0X prefix */

#ifndef HAVE_MEMCHR

static const char *mymemchr __((const char *s, int, int));
static const char *
mymemchr(s, c, n)
	register const char *s;
	register int c, n;
{
	while (n > 0 && *s != c)
		--n, ++s;
	if (n > 0 && *s == c)
		return s;
	return NULL;
}

#else

#define mymemchr memchr

#endif


STATIC int
vsiodoprnt(siop, fmt0, argp)
	register struct siobuf *siop;
	const char *fmt0;
	va_list argp;
{
	register const char *fmt; /* format string */
	register int ch;	/* character from fmt */
	register int cnt;	/* return value accumulator */
	register int n;		/* random handy integer */
	register const char *t;	/* buffer pointer */
	double _double;		/* double precision arguments %[eEfgG] */
	u_long _ulong;		/* integer arguments %[diouxX] */
	int base;		/* base for [diouxX] conversion */
	int dprec;		/* decimal precision in [diouxX] */
	int fieldsz;		/* field size expanded by sign, etc */
	int flags;		/* flags as above */
	int fpprec;		/* `extra' floating precision in [eEfgG] */
	int prec;		/* precision from format (%.3d), or -1 */
	int realsz;		/* field size expanded by decimal precision */
	int size;		/* size of converted field or string */
	int width;		/* width from format (%8d), or 0 */
	char sign;		/* sign prefix (' ', '+', '-', or \0) */
#ifndef NO_FLOAT_CONVERSION
	char softsign;		/* temporary negative sign for floats */
#endif
	const char *digs;	/* digits for [diouxX] conversion */
	char buf[BUF];		/* space for %c, %[diouxX], %[eEfgG] */

	if ((siop->sb_flag & O_WRONLY) == 0)
		return (EOF);

	fmt = fmt0;
	digs = "0123456789abcdef";
	for (cnt = 0;; ++fmt) {
		for (; (ch = *fmt) && ch != '%'; ++cnt, ++fmt)
			PUTC(ch);
		if (!ch)
			return (cnt);

		flags = 0; dprec = 0; fpprec = 0; width = 0;
		prec = -1;
		sign = '\0';

rflag:		switch (*++fmt) {
		case ' ':
			/*
			 * ``If the space and + flags both appear, the space
			 * flag will be ignored.''
			 *	-- ANSI X3J11
			 */
			if (!sign)
				sign = ' ';
			goto rflag;
		case '#':
			flags |= ALT;
			goto rflag;
		case '*':
			/*
			 * ``A negative field width argument is taken as a
			 * - flag followed by a  positive field width.''
			 *	-- ANSI X3J11
			 * They don't exclude field widths read from args.
			 */
			if ((width = va_arg(argp, int)) >= 0)
				goto rflag;
			width = -width;
			/* FALLTHROUGH */
		case '-':
			flags |= LADJUST;
			goto rflag;
		case '+':
			sign = '+';
			goto rflag;
		case '.':
			if (*++fmt == '*')
				n = va_arg(argp, int);
			else {
				n = 0;
				while (isascii((255 & *fmt)) && isdigit((255 & *fmt)))
					n = 10 * n + todigit(*fmt++);
				--fmt;
			}
			prec = n < 0 ? -1 : n;
			goto rflag;
		case '0':
			/*
			 * ``Note that 0 is taken as a flag, not as the
			 * beginning of a field width.''
			 *	-- ANSI X3J11
			 */
			flags |= ZEROPAD;
			goto rflag;
		case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			n = 0;
			do {
				n = 10 * n + todigit(*fmt);
			} while (isascii((255 & *++fmt)) && isdigit((255 & *fmt)));
			width = n;
			--fmt;
			goto rflag;
		case 'L':
			flags |= LONGDBL;
			goto rflag;
		case 'h':
			flags |= SHORTINT;
			goto rflag;
		case 'l':
			flags |= LONGINT;
			goto rflag;
		case 'c':
			*buf = va_arg(argp, int);
			t = buf;
			size = 1;
			sign = '\0';
			goto pforw;
		case 'D':
			flags |= LONGINT;
			/*FALLTHROUGH*/
		case 'd':
		case 'i':
			ARG();
			if ((long)_ulong < 0) {
				_ulong = -_ulong;
				sign = '-';
			}
			base = 10;
			goto number;
#ifdef NO_FLOAT_CONVERSION
		case 'e':
		case 'E':
		case 'f':
		case 'g':
		case 'G':
			_double = va_arg(argp, double);
			break;
#else
		case 'e':
		case 'E':
		case 'f':
		case 'g':
		case 'G':
			_double = va_arg(argp, double);
			/*
			 * don't do unrealistic precision; just pad it with
			 * zeroes later, so buffer size stays rational.
			 */
			if (prec > MAXFRACT) {
				if (*fmt != 'g' && (*fmt != 'G' || (flags&ALT)))
					fpprec = prec - MAXFRACT;
				prec = MAXFRACT;
			}
			else if (prec == -1)
				prec = DEFPREC;
			/*
			 * softsign avoids negative 0 if _double is < 0 and
			 * no significant digits will be shown
			 */
			if (_double < 0) {
				softsign = '-';
				_double = -_double;
			}
			else
				softsign = 0;
			/*
			 * cvt may have to round up past the "start" of the
			 * buffer, i.e. ``intf("%.2f", (double)9.999);'';
			 * if the first char isn't NULL, it did.
			 */
			*buf = '\0';
			size = cvt(_double, prec, flags, &softsign, *fmt, buf,
			    buf + sizeof(buf));
			if (softsign)
				sign = '-';
			t = *buf ? buf : buf + 1;
			goto pforw;
#endif
		case 'n':
			if (flags & LONGINT)
				*va_arg(argp, long *) = cnt;
			else if (flags & SHORTINT)
				*va_arg(argp, short *) = cnt;
			else
				*va_arg(argp, int *) = cnt;
			break;
		case 'O':
			flags |= LONGINT;
			/*FALLTHROUGH*/
		case 'o':
			ARG();
			base = 8;
			goto nosign;
		case 'p':
			/*
			 * ``The argument shall be a pointer to void.  The
			 * value of the pointer is converted to a sequence
			 * of printable characters, in an implementation-
			 * defined manner.''
			 *	-- ANSI X3J11
			 */
			/* NOSTRICT */
			_ulong = (u_long)va_arg(argp, void *);
			base = 16;
			goto nosign;
		case 's':
			t = va_arg(argp, char *);
			if (t == NULL)
				t = "(null)";
			if (prec >= 0) {
				/*
				 * can't use strlen; can only look for the
				 * NUL in the first `prec' characters, and
				 * strlen() will go further.
				 */
				const char *p;

				p = mymemchr(t, 0, prec);
				if (p != NULL) {
					size = p - t;
					if (size > prec)
						size = prec;
				} else
					size = prec;
			} else
				size = strlen(t);
			sign = '\0';
			goto pforw;
		case 'U':
			flags |= LONGINT;
			/*FALLTHROUGH*/
		case 'u':
			ARG();
			base = 10;
			goto nosign;
		case 'X':
			digs = "0123456789ABCDEF";
			/* FALLTHROUGH */
		case 'x':
			ARG();
			base = 16;
			/* leading 0x/X only if non-zero */
			if (flags & ALT && _ulong != 0)
				flags |= HEXPREFIX;

			/* unsigned conversions */
nosign:			sign = '\0';
			/*
			 * ``... diouXx conversions ... if a precision is
			 * specified, the 0 flag will be ignored.''
			 *	-- ANSI X3J11
			 */
number:			if ((dprec = prec) >= 0)
				flags &= ~ZEROPAD;

			/*
			 * ``The result of converting a zero value with an
			 * explicit precision of zero is no characters.''
			 *	-- ANSI X3J11
			 */
			t = buf + BUF;
			if (_ulong != 0 || prec != 0) {
				char *tt = buf + BUF;
				do {
					*(--tt) = digs[_ulong % base];
					_ulong /= base;
				} while (_ulong);
				digs = "0123456789abcdef";
				if (flags & ALT && base == 8 && *tt != '0')
					*(--tt) = '0'; /* octal leading 0 */
				t = tt;
			}
			size = buf + BUF - t;

pforw:
			/*
			 * All reasonable formats wind up here.  At this point,
			 * `t' points to a string which (if not flags&LADJUST)
			 * should be padded out to `width' places.  If
			 * flags&ZEROPAD, it should first be prefixed by any
			 * sign or other prefix; otherwise, it should be blank
			 * padded before the prefix is emitted.  After any
			 * left-hand padding and prefixing, emit zeroes
			 * required by a decimal [diouxX] precision, then print
			 * the string proper, then emit zeroes required by any
			 * leftover floating precision; finally, if LADJUST,
			 * pad with blanks.
			 */

			/*
			 * compute actual size, so we know how much to pad
			 * fieldsz excludes decimal prec; realsz includes it
			 */
			fieldsz = size + fpprec;
			if (sign)
				fieldsz++;
			if (flags & HEXPREFIX)
				fieldsz += 2;
			realsz = dprec > fieldsz ? dprec : fieldsz;

			/* right-adjusting blank padding */
			if ((flags & (LADJUST|ZEROPAD)) == 0 && width)
				for (n = realsz; n < width; n++)
					PUTC(' ');
			/* prefix */
			if (sign)
				PUTC(sign);
			if (flags & HEXPREFIX) {
				PUTC('0');
				PUTC(*fmt);
			}
			/* right-adjusting zero padding */
			if ((flags & (LADJUST|ZEROPAD)) == ZEROPAD)
				for (n = realsz; n < width; n++)
					PUTC('0');
			/* leading zeroes from decimal precision */
			for (n = fieldsz; n < dprec; n++)
				PUTC('0');

			/* the string or number proper */
			if (siop->sb_cnt - (n = size) > 0) {
				siop->sb_cnt -= n;
				memcpy(siop->sb_ptr, t, n);
				siop->sb_ptr += n;
			} else
				while (--n >= 0)
					PUTC(*t++);
			/* trailing f.p. zeroes */
			while (--fpprec >= 0)
				PUTC('0');
			/* left-adjusting padding (always blank) */
			if (flags & LADJUST)
				for (n = realsz; n < width; n++)
					PUTC(' ');
			/* finally, adjust cnt */
			cnt += width > realsz ? width : realsz;
			break;
		case '\0':	/* "%?" prints ?, unless ? is NULL */
			return (cnt);
		default:
			PUTC(*fmt);
			cnt++;
		}
	}
	/* NOTREACHED */
}

#ifndef NO_FLOAT_CONVERSION
int
cvt(number, prec, flags, signp, fmtch, startp, endp)
	double number;
	register int prec;
	int flags;
	char fmtch;
	char *signp, *startp, *endp;
{
	register char *p, *t;
	register double fract;
	int dotrim, expcnt, gformat;
	double integer, tmp;

	dotrim = expcnt = gformat = 0;
	fract = modf(number, &integer);

	/* get an extra slot for rounding. */
	t = ++startp;

	/*
	 * get integer portion of number; put into the end of the buffer; the
	 * .01 is added for modf(356.0 / 10, &integer) returning .59999999...
	 */
	for (p = endp - 1; integer; ++expcnt) {
		tmp = modf(integer / 10, &integer);
		*p-- = tochar((int)((tmp + .01) * 10));
	}
	switch(fmtch) {
	case 'f':
		/* reverse integer into beginning of buffer */
		if (expcnt)
			for (; ++p < endp; *t++ = *p);
		else
			*t++ = '0';
		/*
		 * if precision required or alternate flag set, add in a
		 * decimal point.
		 */
		if (prec || flags&ALT)
			*t++ = '.';
		/* if requires more precision and some fraction left */
		if (fract) {
			if (prec)
				do {
					fract = modf(fract * 10, &tmp);
					*t++ = tochar((int)tmp);
				} while (--prec && fract);
			if (fract)
				startp = round(fract, (int *)NULL, startp,
					       t - 1, 0, signp);
		}
		for (; prec--; *t++ = '0');
		break;
	case 'e':
	case 'E':
eformat:	if (expcnt) {
			*t++ = *++p;
			if (prec || flags&ALT)
				*t++ = '.';
			/* if requires more precision and some integer left */
			for (; prec && ++p < endp; --prec)
				*t++ = *p;
			/*
			 * if done precision and more of the integer component,
			 * round using it; adjust fract so we don't re-round
			 * later.
			 */
			if (!prec && ++p < endp) {
				fract = 0;
				startp = round((double)0, &expcnt, startp,
				    t - 1, *p, signp);
			}
			/* adjust expcnt for digit in front of decimal */
			--expcnt;
		}
		/* until first fractional digit, decrement exponent */
		else if (fract) {
			/* adjust expcnt for digit in front of decimal */
			for (expcnt = -1;; --expcnt) {
				fract = modf(fract * 10, &tmp);
				if (tmp)
					break;
			}
			*t++ = tochar((int)tmp);
			if (prec || flags&ALT)
				*t++ = '.';
		}
		else {
			*t++ = '0';
			if (prec || flags&ALT)
				*t++ = '.';
		}
		/* if requires more precision and some fraction left */
		if (fract) {
			if (prec)
				do {
					fract = modf(fract * 10, &tmp);
					*t++ = tochar((int)tmp);
				} while (--prec && fract);
			if (fract)
				startp = round(fract, &expcnt, startp,
					       t - 1, 0, signp);
		}
		/* if requires more precision */
		for (; prec--; *t++ = '0');

		/* unless alternate flag, trim any g/G format trailing 0's */
		if (gformat && !(flags&ALT)) {
			while (t > startp && *--t == '0');
			if (*t == '.')
				--t;
			++t;
		}
		t = exponent(t, expcnt, fmtch);
		break;
	case 'g':
	case 'G':
		/* a precision of 0 is treated as a precision of 1. */
		if (!prec)
			++prec;
		/*
		 * ``The style used depends on the value converted; style e
		 * will be used only if the exponent resulting from the
		 * conversion is less than -4 or greater than the precision.''
		 *	-- ANSI X3J11
		 */
		if (expcnt > prec || (!expcnt && fract && fract < .0001)) {
			/*
			 * g/G format counts "significant digits, not digits of
			 * precision; for the e/E format, this just causes an
			 * off-by-one problem, i.e. g/G considers the digit
			 * before the decimal point significant and e/E doesn't
			 * count it as precision.
			 */
			--prec;
			fmtch -= 2;		/* G->E, g->e */
			gformat = 1;
			goto eformat;
		}
		/*
		 * reverse integer into beginning of buffer,
		 * note, decrement precision
		 */
		if (expcnt)
			for (; ++p < endp; *t++ = *p, --prec);
		else
			*t++ = '0';
		/*
		 * if precision required or alternate flag set, add in a
		 * decimal point.  If no digits yet, add in leading 0.
		 */
		if (prec || flags&ALT) {
			dotrim = 1;
			*t++ = '.';
		}
		else
			dotrim = 0;
		/* if requires more precision and some fraction left */
		if (fract) {
			if (prec) {
				do {
					fract = modf(fract * 10, &tmp);
					*t++ = tochar((int)tmp);
				} while(!tmp);
				while (--prec && fract) {
					fract = modf(fract * 10, &tmp);
					*t++ = tochar((int)tmp);
				}
			}
			if (fract)
				startp = round(fract, (int *)NULL, startp,
					       t - 1, 0, signp);
		}
		/* alternate format, adds 0's for precision, else trim 0's */
		if (flags&ALT)
			for (; prec--; *t++ = '0');
		else if (dotrim) {
			while (t > startp && *--t == '0');
			if (*t != '.')
				++t;
		}
	}
	return(t - startp);
}

char *
round(fract, exp, start, end, ch, signp)
	double fract;
	int *exp;
	register char *start, *end;
	char ch, *signp;
{
	double tmp;

	if (fract)
		modf(fract * 10, &tmp);
	else
		tmp = todigit(ch);
	if (tmp > 4)
		for (;; --end) {
			if (*end == '.')
				--end;
			if (++*end <= '9')
				break;
			*end = '0';
			if (end == start) {
				if (exp) {	/* e/E; increment exponent */
					*end = '1';
					++*exp;
				}
				else {		/* f; add extra digit */
					*--end = '1';
					--start;
				}
				break;
			}
		}
	/* ``"%.3f", (double)-0.0004'' gives you a negative 0. */
	else if (*signp == '-')
		for (;; --end) {
			if (*end == '.')
				--end;
			if (*end != '0')
				break;
			if (end == start)
				*signp = 0;
		}
	return(start);
}

char *
exponent(p, exp, fmtch)
	register char *p;
	register int exp;
	char fmtch;
{
	register char *t;
	char expbuf[MAXEXP];

	*p++ = fmtch;
	if (exp < 0) {
		exp = -exp;
		*p++ = '-';
	}
	else
		*p++ = '+';
	t = expbuf + MAXEXP;
	if (exp > 9) {
		do {
			*--t = tochar(exp % 10);
		} while ((exp /= 10) > 9);
		*--t = tochar(exp);
		for (; t < expbuf + MAXEXP; *p++ = *t++);
	}
	else {
		*p++ = '0';
		*p++ = tochar(exp);
	}
	return(p);
}
#endif
