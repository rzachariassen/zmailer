/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *
 *	Fixes done by Matti Aarnio <mea@nic.funet.fi>, and at least
 *	Zack at <zack@bitmover.com>.
 */

#include "hostenv.h"
#include "mailer.h"
#include "libz.h"

/* Start of the scanner */

/* scanner tables: definition of character classes according to RFC822 */

#define _h	  01	/* header field */
#define _w	  02	/* linear white-space character (space / htab) */
#define _d	  04	/* digit */
#define _c	 010	/* control */
#define _a	 020	/* alphabetic */
#define _l	 040	/* line feed */
#define _r	0100	/* carriage return */
#define _s	0200	/* specials */
#define _8      0400	/* 8th bit on -- illegal on Headers! */

/* ISO Latin 1 (8859) */

#if defined(__alpha)||defined(__alpha__)
/* On Alpha the short is slow to access! (this array is modified!) */
int
#else
/* All other systems are assumed to contain short-load/store instructions */
short
#endif
	rfc_ctype[256] = {					/* octalcode */
_c,	_c,	_c,	_c,	_c,	_c,	_c,	_c,	/*   0 -   7 */
_c,	_c|_w,	_l|_c,	_c,	_c,	_r|_c,	_c,	_c,	/*  10 -  17 */
_c,	_c,	_c,	_c,	_c,	_c,	_c,	_c,	/*  20 -  27 */
_c,	_c,	_c,	_c,	_c,	_c,	_c,	_c,	/*  30 -  37 */
_w,	_h,	_s|_h,	_h,	_h,	_h,	_h,	_h,	/*  40 -  47 */
_s|_h,	_s|_h,	_h,	_h,	_s|_h,	_h,	_s|_h,	_h,	/*  50 -  57 */
_d|_h,	_d|_h,	_d|_h,	_d|_h,	_d|_h,	_d|_h,	_d|_h,	_d|_h,	/* '0' - '7' */
_d|_h,	_d|_h,	_s,	_s|_h,	_s|_h,	_h,	_s|_h,	_h,	/* '8' -  77 */
_s|_h,	_a|_h,	_a|_h,	_a|_h,	_a|_h,	_a|_h,	_a|_h,	_a|_h,	/* '@' - 'G' */
_a|_h,	_a|_h,	_a|_h,	_a|_h,	_a|_h,	_a|_h,	_a|_h,	_a|_h,	/* 'H' - 'O' */
_a|_h,	_a|_h,	_a|_h,	_a|_h,	_a|_h,	_a|_h,	_a|_h,	_a|_h,	/* 'P' - 'X' */
_a|_h,	_a|_h,	_a|_h,	_s|_h,	_s|_h,	_s|_h,	_h,	_h,	/* 'Y' - 137 */
_h,	_a|_h,	_a|_h,	_a|_h,	_a|_h,	_a|_h,	_a|_h,	_a|_h,	/* '`' - 'g' */
_a|_h,	_a|_h,	_a|_h,	_a|_h,	_a|_h,	_a|_h,	_a|_h,	_a|_h,	/* 'h' - 'o' */
_a|_h,	_a|_h,	_a|_h,	_a|_h,	_a|_h,	_a|_h,	_a|_h,	_a|_h,	/* 'p' - 'x' */
_a|_h,	_a|_h,	_a|_h,	_h,	_h,	_h,	_h,	_c,	/* 'y' - 177 */
	/* The class assignments of the second half are all ILLEGAL */
_8,	_8,	_8,	_8,	_8,	_8,	_8,	_8,	/* 200 - 207 */
_8,	_8,	_8,	_8,	_8,	_8,	_8,	_8,	/* 210 - 217 */
_8,	_8,	_8,	_8,	_8,	_8,	_8,	_8,	/* 220 - 227 */
_8,	_8,	_8,	_8,	_8,	_8,	_8,	_8,	/* 230 - 237 */
_8,	_8,	_8,	_8,	_8,	_8,	_8,	_8,	/* 240 - 247 */
_8,	_8,	_8,	_8,	_8,	_8,	_8,	_8,	/* 250 - 257 */
_8,	_8,	_8,	_8,	_8,	_8,	_8,	_8,	/* 260 - 267 */
_8,	_8,	_8,	_8,	_8,	_8,	_8,	_8,	/* 270 - 277 */
_8,	_8,	_8,	_8,	_8,	_8,	_8,	_8,	/* 300 - 307 */
_8,	_8,	_8,	_8,	_8,	_8,	_8,	_8,	/* 310 - 317 */
_8,	_8,	_8,	_8,	_8,	_8,	_8,	_8,	/* 320 - 327 */
_8,	_8,	_8,	_8,	_8,	_8,	_8,	_8,	/* 330 - 337 */
_8,	_8,	_8,	_8,	_8,	_8,	_8,	_8,	/* 340 - 347 */
_8,	_8,	_8,	_8,	_8,	_8,	_8,	_8,	/* 350 - 357 */
_8,	_8,	_8,	_8,	_8,	_8,	_8,	_8,	/* 360 - 367 */
_8,	_8,	_8,	_8,	_8,	_8,	_8,	_8	/* 370 - 377 */
};


/*
 * Tell whether we are looking at a new header line, a continuation line,
 * or if we are done with the header. Return the number of characters in
 * the name of the header, or 0 if a continuation, or < 0 if end of header.
 * If non-0, the cardinality of the number returned is the length of the
 * header field name.
 */

int
hdr_status(cp, lbuf, n, octo)
	register const char *cp, *lbuf;
	int	n, octo;
{
	if (*cp == ' ' || *cp == '\t') {
	  while ((cp < lbuf + n) && (rfc_ctype[(*cp) & 0xFF] & (_w|_l)))
	    ++cp;
	  if (cp == lbuf + n)
	    /* a line containing only whitespace is EOH */
	    return -1;
	  /* a continuation line (folded header) */
	  return 0;
	}
	if (!octo) {
	  while ((cp < lbuf + n) && (rfc_ctype[(*cp) & 0xFF] & _h))
	    ++cp;
	  if ((cp < lbuf + n) &&
	      (*cp == ':') /*&& (cp > cpin)*/)	/* header line */
	    return cp - lbuf;
	  /* if we get to here, we have a malformed header line */
	  /* if (*cp == ':' && cp == cpin) return -1; */
	  return lbuf - cp;
	} else {
	  /* complex calling relations -- we are parsing alias database,
	     and we want to have spaces allowed in the left-hand side.. */
	  char quote = 0;
	  while (cp < lbuf + n) {
	    char c = *cp;
	    if (c == '\\') {
	      ++cp;
	      if (cp >= (lbuf + n))
		break;
	    }
	    if (c == quote)
	      quote = 0;
	    else if (c == '"')
	      quote = '"';
	    else if (!quote && !(rfc_ctype[c & 0xFF] & _h))
	      break;
	    ++cp;
	  }
	  if (cp < lbuf + n && *cp == ':')
	    return cp - lbuf;
	  return lbuf - cp;
	}
}

#if 0
#define MKERROR(msg,prevp)	tn = makeToken((msg), strlen(msg)); \
				tn->t_type = Error; \
				tn->t_next = *(prevp); \
				*(prevp) = tn;
#else
static void
MKERROR(msg, prevp)
     const char *msg;
     token822 **prevp;
{
  token822 *tn = makeToken((msg), strlen(msg));
  tn->t_type = Error;
  tn->t_next = *(prevp);
  *(prevp) = tn;
}
#endif

/*
 * Recognize a compound token, or rather, a token which is defined by
 * matching start and end delimiters. A comment or quoted string is
 * the typical example. Comments may be recursive.
 */

static u_long _hdr_compound __((const char *cp, int *np,
				int cstart, int cend,
				const char **cpp,
				TokenType type, token822 *tp,
				token822 **tlist, token822 **tlistp));

static u_long
_hdr_compound(cp, np, cstart, cend, cpp, type, tp, tlist, tlistp)
	register const char *cp;
	int	*np;
	int	cstart, cend;
	const char	**cpp;
	TokenType	type;
	token822	*tp, **tlist, **tlistp;
{
	int nest = 1;
	int len = 1;
	int n = *np;

	if (*cp != cstart)
		abort(); /* Sanity check!  Call fault! */
	++cp, --n;

nextline:
	for (; n > 0; ++cp, --n, ++len) {
		if (*cp == cend) {
			if (--nest <= 0) {
			    break;
			}
		} else if (*cp == cstart) {
			if (type == Comment)
				++nest;
			else {
				MKERROR("illegal char in compound", tlist);
			}
		} else if (*cp == '\\') {
			if (n == 1) {
				MKERROR("missing character after backslash",
					tlist);
				/* Continue with next line, if existing! */
				n = 0;
				break;
			}
			++cp;
			--n;
			++len;
		} else if (*cp == '\r') {
			/* type = Error; */
			MKERROR("illegal CR in token", tlist);
		}
	}
	/* we either found cend, or ran off the end, either may be within
	   a recursion */
	if (n == 0) { /* we ran off the end */
		char msgbuf[50];

		if (tlistp != NULL && *tlistp != NULL
		    && (*tlistp)->t_next != NULL) {
			/* compound token is continued on next line */
			*tlistp = (*tlistp)->t_next;
			n = TOKENLEN(*tlistp);
			cp = (*tlistp)->t_pname;
			++len;
			goto nextline;
		}
		/* type=Error; */	/* hey, no reason to refuse a message*/
		sprintf(msgbuf, "missing closing '%c' in token", cend);
		MKERROR(msgbuf, tlist);
		tp->t_pname = NULL;	/* ugly way of signalling scanner */
	} else if (*cp == cend) {	/* we found matching terminator */
		++len;
		--n;			/* move past terminator */
	} else {	/* there was an error */
	  abort() ; /* ??? some sort of sanity check ? */
	}
	tp->t_type = type;
	tp->t_len = len;
	*np = n;
	*cpp = (char*)cp;
	return len;
}

/* Unfold (see RFC822) the contents of a compound token */

static const char * _unfold __((int, const char *, const char **, token822*));
static const char *
_unfold(len, start, cpp, t)
	int len; /* Total length to unfold */
	const char *start;
	const char **cpp;
	token822 *t;
{
	char *s, *cp;
	const char *cpe = *cpp;

	/* Start and End may be at different tmalloc()ed objects! */

	s = cp = (char *)tmalloc(len +1);
	while (len > 0 && start != cpe) {
		if (*start == 0) {
		  t = t->t_next;
if (t == NULL) {
  fprintf(stderr,"_unfold() did meet EndOfTokenchain; len=%d\n",len);
  break;
}
		  start = t->t_pname;
		  --len;
#if 0 /* zero: unfold.. */
		  *s++ = '\n';
#else
		  /* Skip all folding white-space */
		  while (len > 0 && start != cpe &&
			 (*start == ' '  || *start == '\t' ||
			  *start == '\n' || *start == '\r')) {
		    ++start;
		    --len;
		  }
		  /* And replace it with *one* space */
		  *s++ = ' ';
#endif
		}
		if (*start == '\n') {
			++start;
			--len;
			continue;
		}
		if (start == cpe)
		  break;
		--len;
		*s++ = *start++;
	}
	*s = '\0';
	*cpp = start +1;
	return cp;
}

/*
 * The Scanner.
 *
 * cpp		- pointer to pointer to string.
 * n		- number of characters left in string.
 * c1, c2	- if non-NUL, these characters should be considered Special.
 *
 * The scanner will return a token list corresponding to the n next characters
 * in the string. Originally only a single token was returned per call, but
 * for efficiency this was changed to avoid function call overhead. The tokens
 * returned are classified by type (TokenType enum class).
 */
token822 * scan822(cpp, nn, c1, c2, allowcomments, tlistp)
	const char **cpp;		/* pointer to pointer to text */
	size_t	nn;			/* number of characters to scan */
	int	c1, c2;			/* temporary specials */
	int allowcomments;		/* #prefix tokens are comments to EOT */
	token822 **tlistp;		/* continuation line tokens if any */
{
	register const char *cp;
	static token822  t;
	token822	*tlist, *tp, *tn, *ot;
	char	msgbuf[50];
	short	ct, sc1, sc2;
	int n = (int) nn;

	if (n == 0)
		return NULL;
	sc1 = sc2 = '\0';
	if (c1 != '\0') {
		sc1 = rfc_ctype[c1 & 0xFF];
		rfc_ctype[c1] |= _s;
	}
	if (c2 != '\0') {
		sc2 = rfc_ctype[c2 & 0xFF];
		rfc_ctype[c2 & 0xFF] |= _s;
	}
	tlist = NULL;
	do {
		cp = *cpp;
		ct = rfc_ctype[(*cp) & 0xFF];
		t.t_len = n;
		t.t_pname = cp;
		if (ct & _w) {		/* LWSP without the CR LF part */
			while (--n > 0 && (rfc_ctype[(*++cp) & 0xFF] & _w))
			  continue;
			t.t_type = Space;
		} else if (ct & _r) {	/* >= 1 CR followed by LFs is a fold */
			while (--n > 0 && (rfc_ctype[(*++cp) & 0xFF] & _r))
			  continue;
			if (n == 0 || !(rfc_ctype[(*cp) & 0xFF] & _l)) {
			  strcpy(msgbuf, "CR without LF (newline)");
			  MKERROR(msgbuf, &tlist);
			} else if (n > 1 && (rfc_ctype[(*cp) & 0xFF] & _l)) {
			  while (--n > 0 && (rfc_ctype[(*++cp) & 0xFF] & _l))
			    continue;
			  strcpy(msgbuf,"too many newlines (LFs) in field[1]");
			  MKERROR(msgbuf, &tlist);
			}
			t.t_type = Fold;
		} else if (ct & _l) {	/* >= 1 LFs without CR is a fold too */
			while (--n > 0 && (rfc_ctype[(*++cp) & 0xFF] & _l))
			  continue;
			strcpy(msgbuf,"too many newlines (LFs) in field[2]");
			MKERROR(msgbuf, &tlist);
			t.t_type = Fold;
		} else if ((ct & _s) && (*cp=='(' || *cp=='"' || *cp=='[')) {
			TokenType	type;
			char	cend;
			int len;

			if (*cp == '"') {
			  cend = '"';
			  type = String;
			} else if (*cp == '[') {
			  cend = ']';
			  type = DomainLiteral;
			} else {
			  cend = ')';
			  type = Comment;
			}
			ot = (tlistp == NULL ? NULL : *tlistp);
			len = _hdr_compound(cp, &n, *cp, cend, cpp,
					    type, &t, &tlist, tlistp);
			if (ot != NULL && tlistp != NULL && ot != *tlistp) {

			  /* a compound token crossed line boundary */
			  /* copy from ++cp for len chars */
			  t.t_pname = _unfold(len-1, ++cp, cpp, ot);
			  t.t_len   = strlen(t.t_pname);
			} else {
			  if (t.t_pname != NULL)
			    /* magic sign; NULL: no ending char */
			    --t.t_len, ++(*cpp);
				/* past first bracketing char */
			  --t.t_len;  /* ++(*cpp); */
			  t.t_pname = ++cp;
			}

			/* compensate for calculations below */
			(*cpp)  -= t.t_len;
			t.t_len += n;

		} else if (ct & _s) {		/* specials */
			/* Double-colons as with DECNET */
			if (n > 1 && *cp == ':' && cp[1] == ':')
				--n;
			/* Backslash + special:  \@ \! \: ... */
			if (n > 1 && *cp == '\\' && cp[1] != 0 &&
			    (rfc_ctype[cp[1] & 0xFF] & _s))
				--n;
			--n;
			t.t_type = Special;
		} else if (!(ct & (_c|_8))) {	/* atom */
			while (--n > 0 &&
			       !(rfc_ctype[(*++cp) & 0xFF]&(_w|_s|_c|_l|_r)))
				continue;
			t.t_type = Atom;
		} else {
			int bit8 = 0;
			while (--n > 0 &&
			       (rfc_ctype[(*++cp) & 0xFF] & (_c|_8)))
				if (rfc_ctype[(*cp) & 0xFF] & _8) {
					bit8 = 1;
					break;
				}
			if (bit8)
				strcpy(msgbuf, "illegal 8-bit/control character");
			else
				strcpy(msgbuf, "illegal control character");
			if (t.t_len > n+1)
				strcat(msgbuf, "s");
			MKERROR(msgbuf, &tlist);
			t.t_type = Atom;
		}
		t.t_len -= n;
		/* return two values */
		*cpp += t.t_len;
		if (allowcomments && t.t_len >= 1 && t.t_pname[0] == '#') {
			*cpp += n;
			break;
		}
		t.t_next = tlist;
		if (t.t_len > 0)
			tlist = copyToken(&t);
		else {
			t.t_pname = "";
			t.t_len   = 0;
			tlist = copyToken(&t);
		}
	} while (n > 0);

	/* Reverse the token822 chain */
	tp = tn = NULL;
	for (tp = NULL; tlist != NULL; tlist = tn) {
		tn = tlist->t_next;
		tlist->t_next = tp;
		tp = tlist;
	}
	if (c1 != '\0') rfc_ctype[c1 & 0xFF] = sc1;
	if (c2 != '\0') rfc_ctype[c2 & 0xFF] = sc2;
	return tp;
}
