#include "hostenv.h"
#include "mailer.h"
#include <ctype.h>
#include "tregexp.h"
#include "shconfig.h"
#include "io.h"
#ifdef	MAILER
#define DEBUG

#ifndef strchr
extern char *strchr();
#endif

#include "libz.h"

/*
 * tregcomp, tregexec, and tregsub -- regerror is in errors.c
 *
 *	Copyright (c) 1986 by University of Toronto.
 *	Written by Henry Spencer.  Not derived from licensed software.
 *
 *	Permission is granted to anyone to use this software for any
 *	purpose on any computer system, and to redistribute it freely,
 *	subject to the following restrictions:
 *
 *	1. The author is not responsible for the consequences of use of
 *		this software, no matter how awful, even if they arise
 *		from defects in it.
 *
 *	2. The origin of this software must not be misrepresented, either
 *		by explicit claim or by omission.
 *
 *	3. Altered versions must be plainly marked as such, and must not
 *		be misrepresented as being the original software.
 *
 * Beware that some of this code is subtly aware of the way operator
 * precedence is structured in regular expressions.  Serious changes in
 * regular-expression syntax might require a total rethink.
 */
/*
 * This code has been altered to deal with token sequences instead of
 * character strings. The modifications can mostly be identified by the
 * appearance of token822 * variables. In addition, the character
 * class stuff has been removed (perhaps it should be revised instead).
 * Any errors in these changes are of course not to be attributed to the
 * original author of this regular expression code, whom I thank for
 * making the code available. The modifications to the original code
 * are rather trivial, but to avoid problems let me say this:
 * Modifications are Copyright 1988 by Rayan Zachariassen.
 */

/*
 * The "internal use only" fields in regexp.h are present to pass info from
 * compile to execute that permits the execute phase to run lots faster on
 * simple cases.  They are:
 *
 * regstart	char that must begin a match; '\0' if none obvious
 * reganch	is the match anchored (at beginning-of-line only)?
 * regmust	string (pointer into program) that match must include, or NULL
 * regmlen	length of regmust string
 *
 * Regstart and reganch permit very fast decisions on suitable starting points
 * for a match, cutting down the work a lot.  Regmust permits fast rejection
 * of lines that cannot possibly match.  The regmust tests are costly enough
 * that regcomp() supplies a regmust only if the r.e. contains something
 * potentially expensive (at present, the only such thing detected is * or +
 * at the start of the r.e., which can involve a lot of backup).  Regmlen is
 * supplied because the test in regexec() needs it and regcomp() is computing
 * it anyway.
 */

/*
 * Structure for regexp "program".  This is essentially a linear encoding
 * of a nondeterministic finite-state machine (aka syntax charts or
 * "railroad normal form" in parsing technology).  Each node is an opcode
 * plus a "next" pointer, possibly plus an operand.  "Next" pointers of
 * all nodes except BRANCH implement concatenation; a "next" pointer with
 * a BRANCH on both ends of it is connecting two alternatives.  (Here we
 * have one of the subtle syntax dependencies:  an individual BRANCH (as
 * opposed to a collection of them) is never concatenated with anything
 * because of operator precedence.)  The operand of some types of node is
 * a literal tstring; for others, it is a node leading into a sub-FSM.  In
 * particular, the operand of a BRANCH node is the first node of the branch.
 * (NB this is *not* a tree structure:  the tail of the branch connects
 * to the thing following the set of BRANCHes.)  The opcodes are:
 */

/* definition	number	opnd?	meaning */
#define	END	0	/* no	End of program. */
#define	BOL	1	/* no	Match "" at beginning of line. */
#define	EOL	2	/* no	Match "" at end of line. */
#define	ANY	3	/* no	Match any one character. */
#define	ANYOF	4	/* str	Match any character in this string. */
#define	ANYBUT	5	/* str	Match any character not in this string. */
#define	BRANCH	6	/* node	Match this alternative, or the next... */
#define	BACK	7	/* no	Match "", "next" ptr points backward. */
#define	EXACTLY	8	/* str	Match this string. */
#define	NOTHING	9	/* no	Match empty string. */
#define	STAR	10	/* node	Match this (simple) thing 0 or more times. */
#define	PLUS	11	/* node	Match this (simple) thing 1 or more times. */
#define	OPEN	20	/* no	Mark this point in input as start of #n. */
			/*	OPEN+1 is number 1, etc. */
#define	CLOSE	30	/* no	Analogous to OPEN. */

/*
 * Opcode notes:
 *
 * BRANCH	The set of branches constituting a single choice are hooked
 *		together with their "next" pointers, since precedence prevents
 *		anything being concatenated to any individual branch.  The
 *		"next" pointer of the last BRANCH in a choice points to the
 *		thing following the whole choice.  This is also where the
 *		final "next" pointer of each individual branch points; each
 *		branch starts with the operand node of a BRANCH node.
 *
 * BACK		Normal "next" pointers all implicitly point forward; BACK
 *		exists to make loop structures possible.
 *
 * STAR,PLUS	'?', and complex '*' and '+', are implemented as circular
 *		BRANCH structures using BACK.  Simple cases (one character
 *		per match) are implemented with STAR and PLUS for speed
 *		and to minimize recursive plunges.
 *
 * OPEN,CLOSE	...are numbered at compile time.
 */

/*
 * A node is one char of opcode followed by two chars of "next" pointer.
 * "Next" pointers are stored as two 8-bit pieces, high order first.  The
 * value is a positive offset from the opcode of the node containing it.
 * An operand, if any, simply follows the node.  (Note that much of the
 * code generation knows about this implicit relationship.)
 *
 * Using two bytes for the "next" pointer is vast overkill for most things,
 * but allows patterns to get big without disasters.
 */
#define	OP(p)	(*(p))
#define	NEXT(p)	(((*((p)+1)&0377)<<8) + (*((p)+2)&0377))
#define	OPERAND(p)	((p) + 3)

/*
 * See regmagic.h for one further detail of program structure.
 */


/*
 * Utility definitions.
 */
#ifndef CHARBITS
#define	UCHARAT(p)	((*(p)) & 0xFF)
#else
#define	UCHARAT(p)	((*(p)) & CHARBITS)
#endif

#define	FAIL(m)  { tregerror(m, regprog); return NULL; }
#define	FAIL0(m) { tregerror(m, regprog); return 0; }
#define	ISMULT(c)	((c) == '*' || (c) == '+' || (c) == '?')
#define	META	"^$.[()|?+*\\"

#define	CICHEQ(a,b) (((isascii(UCHARAT(a)) && isupper(UCHARAT(a))) ? tolower(UCHARAT(a)) : UCHARAT(a)) \
		  == ((isascii(UCHARAT(b)) && isupper(UCHARAT(b))) ? tolower(UCHARAT(b)) : UCHARAT(b)))

/*
 * Flags to be passed up and down.
 */
#define	HASWIDTH	01	/* Known never to match null string. */
#define	SIMPLE		02	/* Simple enough to be STAR/PLUS operand. */
#define	SPSTART		04	/* Starts with * or +. */
#define	WORST		0	/* Worst case. */

/*
 * Global work variables for tregcomp().
 */
STATIC const char *regparse;	/* Input-scan pointer. */
STATIC int regnpar;		/* () count. */
STATIC char regdummy;
STATIC char *regcode;		/* Code-emit pointer; &regdummy = don't. */
STATIC long regsize;		/* Code size. */
STATIC tregexp *regprog;

/*
 * Forward declarations for tregcomp()'s friends.
 */
STATIC const char *reg       __((int, int *));
STATIC const char *regatom   __((int *));
STATIC const char *regbranch __((int *));
STATIC       char *regnode   __((int));
STATIC const char *regpiece  __((int *));
STATIC       int   regmatch  __((const char *));
STATIC       int   regrepeat __((const char *));
STATIC       int   regtoken  __((token822 **, const char *, int));
STATIC       int   regtry    __((tregexp *, token822 *));
STATIC       void  regc      __((int));
STATIC       void  reginsert __((int, const char *));
STATIC       void  regoptail __((const char *, const char *));
STATIC       void  regtail   __((const char *, const char *));
STATIC const char *regnext   __((const char *));


extern int funclevel;
extern char *progname;

#ifdef DEBUG
extern int D_regnarrate, D_compare, D_matched;
void tregdump __((tregexp *));
STATIC char *regprop __((const char *));
char *progp;
#endif

/*
 - tregcomp - compile a regular expression into internal code
 *
 * We can't allocate space until we know how big the compiled form will be,
 * but we can't compile it (and thus know how big it is) until we've got a
 * place to put the code.  So we cheat:  we compile it twice, once with code
 * generation turned off and size counting turned on, and once "for real".
 * This also means that we don't allocate space until we are sure that the
 * thing really will compile successfully, and we never have to move the
 * code and thus invalidate pointers into it.  (Note that it has to be in
 * one piece because free() must be able to free it all.)
 *
 * Beware that the optimization-preparation code in here knows about some
 * of the structure of the compiled tregexp.
 */
tregexp *
tregcomp(exp)
const char *exp;
{
	register tregexp *prog;
	register const char *scan;
	register const char *longest;
	register int len;
	int flags;

	regprog = NULL;
	if (exp == NULL)
		FAIL("NULL argument");

	/* First pass: determine size, legality. */
	regparse = exp;
	regnpar = 1;
	regsize = 0L;
	regcode = &regdummy;
	regc(MAGIC);
	if (reg(0, &flags) == NULL)
		return NULL;

	/* Small enough for pointer-storage convention? */
	if (regsize >= 32767L)		/* Probably could be 65535L. */
		FAIL("tregexp too big");

	/* Allocate space. */
	prog = (tregexp *)emalloc(sizeof (tregexp) + (unsigned int) regsize);
/* printf("tregexp %x: %s\n", prog, exp); */
	if (prog == NULL)
		FAIL("out of space");
	prog->pattern = exp;
	regprog = prog;

	/* Second pass: emit code. */
	regparse = exp;
	regnpar = 1;
	regcode = prog->program;
	regc(MAGIC);
	/* if (reg(0, &flags, prog) == NULL) ... */
	if (reg(0, &flags) == NULL) {
		free((char *)prog);
		return NULL;
	}

	/* Dig out information for optimizations. */
	prog->regstart = '\0';	/* Worst-case defaults. */
	prog->reganch = 0;
	prog->regmust = NULL;
	prog->regmlen = 0;
	scan = prog->program+1;			/* First BRANCH. */
	if (OP(regnext(scan)) == END) {		/* Only one top-level choice. */
		scan = OPERAND(scan);

		/* Starting-point info. */
		if (OP(scan) == EXACTLY)
			prog->regstart = *OPERAND(scan);
		else if (OP(scan) == BOL)
			prog->reganch++;

		/*
		 * If there's something expensive in the r.e., find the
		 * longest literal string that must appear and make it the
		 * regmust.  Resolve ties in favor of later strings, since
		 * the regstart check works with the beginning of the r.e.
		 * and avoiding duplication strengthens checking.  Not a
		 * strong reason, but sufficient in the absence of others.
		 */
		if (flags&SPSTART) {
			longest = NULL;
			len = 0;
			for (; scan != NULL; scan = regnext(scan))
				if (OP(scan) == EXACTLY && strlen(OPERAND(scan)) >= len) {
					longest = OPERAND(scan);
					len = strlen(OPERAND(scan));
				}
			prog->regmust = longest;
			prog->regmlen = len;
		}
	}
#ifdef	DEBUG
	if (D_regnarrate)
		tregdump(prog);
#endif	/* DEBUG */
	return(prog);
}

/*
 - reg - regular expression, i.e. main body or parenthesized thing
 *
 * Caller must absorb opening parenthesis.
 *
 * Combining parenthesis handling with the base level of regular expression
 * is a trifle forced, but the need to tie the tails of the branches to what
 * follows makes it hard to avoid.
 */
STATIC const char *
reg(paren, flagp)
	int paren;			/* Parenthesized? */
	int *flagp;
{
	register const char *ret;
	register const char *br;
	register const char *ender;
	register int parno = 0;
	int flags;

	*flagp = HASWIDTH;	/* Tentatively. */

	/* Make an OPEN node, if parenthesized. */
	if (paren > 0) {
		if (regnpar >= NSUBEXP)
			FAIL("too many ()");
		parno = regnpar;
		regnpar++;
		ret = regnode(OPEN+parno);
	} else
		ret = NULL;

	/* Pick up the branches, linking them together. */
	br = regbranch(&flags);
	if (br == NULL)
		return(NULL);
	if (ret != NULL)
		regtail(ret, br);	/* OPEN -> first. */
	else
		ret = br;
	if (!(flags&HASWIDTH))
		*flagp &= ~HASWIDTH;
	*flagp |= flags&SPSTART;
	while (*regparse == '|') {
		regparse++;
		br = regbranch(&flags);
		if (br == NULL)
			return(NULL);
		regtail(ret, br);	/* BRANCH -> BRANCH. */
		if (!(flags&HASWIDTH))
			*flagp &= ~HASWIDTH;
		*flagp |= flags&SPSTART;
	}

	/* Make a closing node, and hook it on the end. */
	if (paren >= 0)
		ender = regnode((paren) ? CLOSE+parno : END);	
	else
		ender = regcode;
	regtail(ret, ender);

	/* Hook the tails of the branches to the closing node. */
	for (br = ret; br != NULL; br = regnext(br)) {
		if (paren < 0 && br >= ender)
			break;
		regoptail(br, ender);
	}

	/* Check for proper termination. */
	if (paren > 0 && *regparse++ != ')') {
		FAIL("unmatched ()");
	} else if (paren <= 0 && *regparse != '\0') {
		if (*regparse == ')') {
			FAIL("unmatched ()");
		} else
			FAIL("junk on end");	/* "Can't happen". */
		/* NOTREACHED */
	}

	return(ret);
}

/*
 - regbranch - one alternative of an | operator
 *
 * Implements the concatenation operator.
 */
STATIC const char *
regbranch(flagp)
int *flagp;
{
	register const char *ret;
	register const char *chain;
	register const char *latest;
	int flags;

	*flagp = WORST;		/* Tentatively. */

	ret = regnode(BRANCH);
	chain = NULL;
	while (*regparse != '\0' && *regparse != '|' && *regparse != ')') {
		latest = regpiece(&flags);
		if (latest == NULL)
			return(NULL);
		*flagp |= flags&HASWIDTH;
		if (chain == NULL)	/* First piece. */
			*flagp |= flags&SPSTART;
		else
			regtail(chain, latest);
		chain = latest;
	}
	if (chain == NULL)	/* Loop ran zero times. */
		regnode(NOTHING);

	return(ret);
}

/*
 - regpiece - something followed by possible [*+?]
 *
 * Note that the branching code sequences used for ? and the general cases
 * of * and + are somewhat optimized:  they use the same NOTHING node as
 * both the endmarker for their branch list and the body of the last branch.
 * It might seem that this node could be dispensed with entirely, but the
 * endmarker role is not redundant.
 */
STATIC const char *
regpiece(flagp)
int *flagp;
{
	register const char *ret;
	register       char op;
	register const char *next;
	int flags;

	ret = regatom(&flags);
	if (ret == NULL)
		return(NULL);

	op = *regparse;
	if (!ISMULT(op)) {
		*flagp = flags;
		return(ret);
	}

	if (!(flags&HASWIDTH) && op != '?')
		FAIL("*+ operand could be empty");
	*flagp = (op != '+') ? (WORST|SPSTART) : (WORST|HASWIDTH);

	if (op == '*' && (flags&SIMPLE))
		reginsert(STAR, ret);
	else if (op == '*') {
		/* Emit x* as (x&|), where & means "self". */
		reginsert(BRANCH, ret);			/* Either x */
		regoptail(ret, regnode(BACK));		/* and loop */
		regoptail(ret, ret);			/* back     */
		regtail(ret, regnode(BRANCH));		/* or       */
		regtail(ret, regnode(NOTHING));		/* null.    */
	} else if (op == '+' && (flags&SIMPLE))
		reginsert(PLUS, ret);
	else if (op == '+') {
		/* Emit x+ as x(&|), where & means "self". */
		next = regnode(BRANCH);			/* Either    */
		regtail(ret, next);
		regtail(regnode(BACK), ret);		/* loop back */
		regtail(next, regnode(BRANCH));		/* or        */
		regtail(ret, regnode(NOTHING));		/* null.     */
	} else if (op == '?') {
		/* Emit x? as (x|) */
		reginsert(BRANCH, ret);			/* Either x  */
		regtail(ret, regnode(BRANCH));		/* or        */
		next = regnode(NOTHING);		/* null.     */
		regtail(ret, next);
		regoptail(ret, next);
	}
	regparse++;
	if (ISMULT(*regparse))
		FAIL("nested *?+");

	return(ret);
}

/*
 - regatom - the lowest level
 *
 * Optimization:  gobbles an entire sequence of ordinary characters so that
 * it can turn them into a single node, which is smaller to store and
 * faster to run.  Backslashed characters are exceptions, each becoming a
 * separate node; the code is simpler that way and it's not worth fixing.
 */
STATIC const char *
regatom(flagp)
	int *flagp;
{
	register const char *ret;
	int flags;

	*flagp = WORST;		/* Tentatively. */

	switch (*regparse++) {
	case '^':
		ret = regnode(BOL);
		break;
	case '$':
		if (*regparse == '\0')
			ret = regnode(EOL);
		else {
			ret = regnode(EXACTLY);
			regc('$');
			regc('\0');
			*flagp |= HASWIDTH;
		}
		break;
	case '.':
		ret = regnode(ANY);
		*flagp |= HASWIDTH|SIMPLE;
		break;
	case '[': {
			register int class;
			register int classend;

			if (*regparse == '^') {	/* Complement of range. */
				ret = regnode(ANYBUT);
				regparse++;
			} else
				ret = regnode(ANYOF);
			if (*regparse == ']' || *regparse == '-')
				regc(*regparse++);
			while (*regparse != '\0' && *regparse != ']') {
				if (*regparse == '-') {
					regparse++;
					if (*regparse == ']' || *regparse == '\0')
						regc('-');
					else {
						class = UCHARAT(regparse-2)+1;
						classend = UCHARAT(regparse);
						if (class > classend+1)
							FAIL("invalid [] range");
						for (; class <= classend; class++)
							regc(class);
						regparse++;
					}
				} else
					regc(*regparse++);
			}
			regc('\0');
			if (*regparse != ']')
				FAIL("unmatched []");
			regparse++;
			*flagp |= HASWIDTH|SIMPLE;
		}
		break;
	case '(':
		ret = reg(1, &flags);
		if (ret == NULL)
			return(NULL);
		*flagp |= flags&(HASWIDTH|SPSTART);
		break;
	case '\0':
	case '|':
	case ')':
		FAIL("internal urp");	/* Supposed to be caught earlier. */
	case '?':
	case '+':
	case '*':
		FAIL("?+* follows nothing");
	case '\\':
		if (*regparse == '\0')
			FAIL("trailing \\");
		ret = regnode(EXACTLY);
		regc(*regparse++);
		regc('\0');
		*flagp |= HASWIDTH|SIMPLE;
		break;
	default: {
			register int len;
			register char ender;

			regparse--;
			len = strcspn(regparse, META);
			if (len <= 0)
				FAIL("internal disaster");
			ender = *(regparse+len);
			if (len > 1 && ISMULT(ender))
				len--;		/* Back off clear of ?+* operand. */
			*flagp |= HASWIDTH;
			if (len == 1)
				*flagp |= SIMPLE;
			ret = regnode(EXACTLY);
			while (len > 0) {
				regc(*regparse++);
				len--;
			}
			regc('\0');
		}
		break;
	}

	return(ret);
}

/*
 - regnode - emit a node
 */
STATIC char *			/* Location. */
regnode(op)
	int op;
{
	register char *ret;
	register char *ptr;

	ret = regcode;
	if (ret == &regdummy) {
		regsize += 3;
		return(ret);
	}

	 ptr    = ret;
	*ptr++  = op;
	*ptr++  = '\0';		/* Null "next" pointer. */
	*ptr++  = '\0';
	regcode = ptr;

	return (ret);
}

/*
 - regc - emit (if appropriate) a byte of code
 */
STATIC void
regc(b)
	int b;
{
	if (regcode != &regdummy)
		*regcode++ = b;
	else
		regsize++;
}

/*
 - reginsert - insert an operator in front of already-emitted operand
 *
 * Means relocating the operand.
 */
STATIC void
reginsert(op, opnd)
	int         op;
	const char *opnd;
{
	register  char * src;
	register  char * dst;
	register  char * place;

	if (regcode == &regdummy) {
		regsize += 3;
		return;
	}

	src = regcode;
	regcode += 3;
	dst = regcode;
	while (src > opnd)
		*--dst = *--src;

	/* Yeah, we WRITE here! */
	place   = (char*)opnd;	/* Op node, where operand used to be. */
	*place++ = op;
	*place++ = '\0';
	*place++ = '\0';
}

/*
 - regtail - set the next-pointer at the end of a node chain
 */
STATIC void
regtail(p, val)
	const char *p;
	const char *val;
{
	const char * scan;
	char * wp;
	int offset;

	if (p == &regdummy)
		return;

	/* Find last node. */
	scan = p;
	for (;;) {
		register const char * temp;
		temp = regnext(scan);
		if (temp == NULL)
			break;
		scan = temp;
	}

	if (OP(scan) == BACK)
		offset = scan - val;
	else
		offset = val - scan;
	/* Ok, we DO modify this.. */
	wp = (char*)scan;
	*(wp+1) = (offset >> 8) & 0xFF;
	*(wp+2) =  offset       & 0xFF;
}

/*
 - regoptail - regtail on operand of first argument; nop if operandless
 */
STATIC void
regoptail(p, val)
	const char *p;
	const char *val;
{
	/* "Operandless" and "op != BRANCH" are synonymous in practice. */
	if (p == NULL || p == &regdummy || OP(p) != BRANCH)
		return;
	regtail(OPERAND(p), val);
}

/*
 * tregexec and friends
 */

/*
 * Global work variables for tregexec().
 */
STATIC token822 *reginput;		/* String-input pointer. */
STATIC token822 *previnput;		/* Previous string-input pointer. */
STATIC token822 *regbol;		/* Beginning of input, for ^ check. */
STATIC token822 **regstartp;	/* Pointer to startp array. */
STATIC token822 **regendp;		/* Ditto for endp. */
STATIC short regatomize[10] = { 0 };	/* if on turn DomainLiteral->Atom */

/*
 - tregexec - match a tregexp against a string
 */
int
tregexec(prog, tstring)
	register tregexp *prog;
	register token822 *tstring;
{
	register token822 *s;

	regprog = prog;
	/* Be paranoid... */
	if (prog == NULL)
		FAIL0("NULL program");

	/* Check validity of program. */
	if (UCHARAT(prog->program) != MAGIC)
		FAIL0("corrupted program");

#ifdef	DEBUG
	if (D_compare) {
		fprintf(stderr,
			"%*stcomparing '%s' and ", 4*funclevel, "", prog->pattern);
		if (tstring != NULL) {
			putc('\'', stderr);
			for (s = tstring; s != NULL ; s = s->t_next)
				fprintToken(stderr, s, 0);
			putc('\'', stderr);
		} else
			fprintf(stderr, "(nil)");
		putc('\n', stderr);
	}
#endif	/* DEBUG */

	if (tstring == NULL)
		FAIL0("NULL tstring");

	/* If there is a "must appear" string, look for it. */
	if (prog->regmust != NULL) {
		int rmlen, len;
		token822 *t;

		for (s = tstring; s != NULL; s = s->t_next) {
			const char *cp;
			rmlen = prog->regmlen;
			for (t = s, cp = prog->regmust; t != NULL && rmlen > 0;
			     cp += len) {
				len = regtoken(&t, cp, rmlen);
				if (len == 0)
					break;
				rmlen -= len;
			}
			if (rmlen == 0)
				break;
		}
		if (s == NULL)	/* Not present. */
			return(0);
	}

	/* Mark beginning of line for ^ . */
	regbol = tstring;

	/* Simplest case:  anchored match need be tried only once. */
	if (prog->reganch) {
		if (regtry(prog, tstring))
			goto success;
		return 0;
	}

	/* Messy cases:  unanchored match. */
	for (s = tstring; s != NULL; s = s->t_next) {
		if (prog->regstart != '\0') {
			/* We know what char it must start with. */
			/* TODO: case independent stuff */
			if (CICHEQ(s->t_pname, &(prog->regstart))
			    && regtry(prog, s))
				goto success;
		} else if (regtry(prog, s)) /* We don't -- general case. */
			goto success;
	}
	/* Failure. */
	return(0);
success:
#ifdef	DEBUG
	if (D_matched) {
		fprintf(stderr,
			"%*stmatched '%s' and '", 4*funclevel, "", prog->pattern);
		for (s = tstring; s != NULL ; s = s->t_next)
			fprintToken(stderr, s, 0);
		fprintf(stderr, "'\n");
	}
#endif	/* DEBUG */
	return 1;
}

/*
 * General function to match a token with the start of a string.
 * This function is part of ZMailer.
 */

STATIC int
regtoken(tp, s, maxlen)
	token822 **tp;		/* the token to match with */
	const char *s;			/* the string to match with */
	int maxlen;			/* how long the string is */
{
	register int	len, endbytes;

	if (*s == '[' && (*tp)->t_type == DomainLiteral) {
		/* endbytes = 2, ++s; */
		return 1;
	} else if (*s == ']'
		 && previnput != NULL && previnput->t_type == DomainLiteral) {
		/* if we see \[(.)\] want to make literal into atom */
		previnput->t_type = Atom;
		return 1;
	} else if (CICHEQ((*tp)->t_pname, s))
		endbytes = 0;
	else
		return 0;

	len = TOKENLEN(*tp);
	if ((len + endbytes) > maxlen)
		return 0;
	if (endbytes && *(s+len) != ']')
		return 0;
	if (ci2strncmp((*tp)->t_pname, s, len) == 0) {
		*tp = (*tp)->t_next;
		return len + endbytes;
	}
	return 0;
}

/*
 - regtry - try match at specific point
 */
STATIC int			/* 0 failure, 1 success */
regtry(prog, tstring)
	tregexp *prog;
	token822 *tstring;
{
	register int i;
	token822 **sp;
	token822 **ep;

	previnput = NULL;
	reginput = tstring;
	regstartp = prog->startp;
	regendp = prog->endp;

	sp = prog->startp;
	ep = prog->endp;
	for (i = NSUBEXP; i > 0; i--) {
		*sp++ = NULL;
		*ep++ = NULL;
	}
	progp = prog->program;
	if (regmatch(prog->program + 1)) {
		prog->startp[0] = tstring;
		prog->endp[0]   = reginput;
		return(1);
	} else
		return(0);
}

/*
 - regmatch - main matching routine
 *
 * Conceptually the strategy is simple:  check to see whether the current
 * node matches, call self recursively to see whether the rest matches,
 * and then act accordingly.  In practice we make some effort to avoid
 * recursion, in particular by going through "ordinary" nodes (that don't
 * need to know whether the rest of the match failed) by a loop instead of
 * by recursion.
 */
STATIC int			/* 0 failure, 1 success */
regmatch(prog)
	const char *prog;
{
	register const char *scan;	/* Current node. */
	const char *next;		/* Next node.    */

	scan = prog;
#ifdef DEBUG
	if (scan != NULL && D_regnarrate)
		fprintf(stderr, "%d%s(\n", scan - progp, regprop(scan));
#endif
	while (scan != NULL) {
#ifdef DEBUG
		if (D_regnarrate) {
			fprintf(stderr, "%d%s...'",
					scan - progp, regprop(scan));
			if (reginput != NULL)
				fprintToken(stderr, reginput, 0);
			else
				fprintf(stderr, "<EOL>");
			fprintf(stderr, "'\n");
		}
#endif
		next = regnext(scan);

		switch (OP(scan)) {
		case BOL:
			if (reginput != regbol)
				return(0);
			break;
		case EOL:
			if (reginput != NULL)
				return(0);
			break;
		case ANY:
			if (reginput == NULL)
				return(0);
			previnput = reginput, reginput = reginput->t_next;
			break;
		case EXACTLY: {
				token822 *t;
				register int len, toklen;
				register const char *opnd;

				opnd = OPERAND(scan);
				if (*opnd == ']' && previnput != NULL
				    && previnput->t_type == DomainLiteral)
					break;
				if (reginput == NULL)
					return 0;
				/* Inline the first character, for speed. */
				if (reginput->t_type != DomainLiteral
				    && !CICHEQ(opnd, reginput->t_pname))
					return 0;
				len = strlen(opnd);
				/* NOTE!! The end of the EXACTLY string
				 * *must* coincide with the end of a token.
				 * XX: handle simple case of len==1
				 */
				for (t = reginput; t != NULL && len > 0;
				     opnd += toklen) {
					if (*opnd == '[' && OP(next) >= OPEN
					    && OP(next) <= OPEN+9)
						regatomize[OP(next)-OPEN] = 1;
					toklen = regtoken(&t, opnd, len);
					if (toklen == 0)
						return 0;
					len -= toklen;
				}
				if (len == 0)
					previnput = reginput, reginput = t;
				else
					return 0;
			}
			break;
#ifndef	notdef
		case ANYOF: /* these shouldn't really happen.... right? */
			if (reginput == NULL
			    || strchr(OPERAND(scan),
					(char)(reginput->t_pname[0])) == NULL)
				return(0);
			previnput = reginput, reginput = reginput->t_next;
			break;
		case ANYBUT:
			if (reginput == NULL
			    || strchr(OPERAND(scan),
					(char)(reginput->t_pname[0])) != NULL)
				return(0);
			previnput = reginput, reginput = reginput->t_next;
			break;
#endif
		case NOTHING:
			break;
		case BACK:
			break;
		case OPEN+1:
		case OPEN+2:
		case OPEN+3:
		case OPEN+4:
		case OPEN+5:
		case OPEN+6:
		case OPEN+7:
		case OPEN+8:
		case OPEN+9: {
				register int no;
				register token822 *save;

				no = OP(scan) - OPEN;
				save = reginput;

				if (regmatch(next)) {
					/*
					 * Don't set startp if some later
					 * invocation of the same parentheses
					 * already has.
					 */
					if (regstartp[no] == NULL) {
						regstartp[no] = save;
						if (regatomize[no]) {
						    if (save->t_type
							    == DomainLiteral)
							save->t_type = Atom;
						    regatomize[no] = 0;
						}
					}
					return(1);
				}
			}
			return(0);
		case CLOSE+1:
		case CLOSE+2:
		case CLOSE+3:
		case CLOSE+4:
		case CLOSE+5:
		case CLOSE+6:
		case CLOSE+7:
		case CLOSE+8:
		case CLOSE+9: {
				register int no;
				register token822 *save;

				no = OP(scan) - CLOSE;
				save = reginput;

				if (regmatch(next)) {
					/*
					 * Don't set endp if some later
					 * invocation of the same parentheses
					 * already has.
					 */
					if (regendp[no] == NULL)
						regendp[no] = save;
					return(1);
				}
			}
			return(0);
		case BRANCH: {
				register token822 *save, *saveprev;

				if (OP(next) != BRANCH)		/* No choice. */
					next = OPERAND(scan);	/* Avoid recursion. */
				else {
					do {
						save = reginput;
						saveprev = previnput;
						if (regmatch(OPERAND(scan)))
							return(1);
						previnput = saveprev;
						reginput = save;
						scan = regnext(scan);
					} while (scan != NULL && OP(scan) == BRANCH);
					return(0);
					/* NOTREACHED */
				}
			}
			break;
		case STAR:
		case PLUS: {
				register const char *nextch;
				register int no, i;
				register token822 *save, *saveprev;
				register int min;

				/*
				 * Lookahead to avoid useless match attempts
				 * when we know what character comes next.
				 */
				nextch = NULL;
				if (OP(next) == EXACTLY)
					nextch = OPERAND(next);
				min = (OP(scan) == STAR) ? 0 : 1;
				save = reginput;
				saveprev = previnput;
				no = regrepeat(OPERAND(scan));
				while (no >= min) {
					/* If it could work, try it. */
					if (nextch == NULL ||
					    (reginput != NULL &&
					     CICHEQ(reginput->t_pname, nextch)))
						if (regmatch(next))
							return(1);
					/* Couldn't or didn't -- back up. */
					no--;
					reginput = save;
					previnput = saveprev;
					for (i = 0; i < no; ++i) {
						previnput = reginput;
						reginput = reginput->t_next;
					}
				}
			}
			return(0);
		case END:
			return(1);	/* Success! */
		default:
			FAIL0("memory corruption");
		}

		scan = next;
	}

	/*
	 * We get here only if there's trouble -- normally "case END" is
	 * the terminating point.
	 */
	FAIL0("corrupted pointers");
}

/*
 - regrepeat - repeatedly match something simple, report how many
 */
STATIC int
regrepeat(p)
	const char *p;
{
	register int    count = 0;
	register token822 *scan;
	register const  char  *opnd;

	scan = reginput;
	opnd = OPERAND(p);
	switch (OP(p)) {
	case ANY:
		for (; scan != NULL; scan = scan->t_next)
			if (!(scan->t_len == 0 && scan->t_pname[0] == '\0'))
				++count;
		break;
	case EXACTLY:
		/* TODO case independent compare */
		while (scan != NULL
		       && TOKENLEN(scan) == 1 && CICHEQ(opnd, scan->t_pname))
			++count, scan = scan->t_next;
		break;
#ifndef	notdef
	case ANYOF:
		while (scan != NULL && TOKENLEN(scan) == 1
		       && strchr(opnd, (char)(scan->t_pname[0])) != NULL)
			++count, scan = scan->t_next;
		break;
	case ANYBUT:
		while (scan != NULL && (TOKENLEN(scan) > 1
		       || strchr(opnd, (char)(scan->t_pname[0])) == NULL))
			++count, scan = scan->t_next;
		break;
#endif
	default:		/* Oh dear.  Called inappropriately. */
		tregerror("internal foulup", regprog);
		count = 0;	/* Best compromise. */
		break;
	}
	previnput = reginput;
	reginput = scan;

	return(count);
}

/*
 - regnext - dig the "next" pointer out of a node
 */
STATIC const char *
regnext(p)
	register const char *p;
{
	register int offset;

	if (p == &regdummy)
		return(NULL);

	offset = NEXT(p);
	if (offset == 0)
		return(NULL);

	if (OP(p) == BACK)
		return(p-offset);
	else
		return(p+offset);
}

#ifdef DEBUG


/*
 - tregdump - dump a tregexp onto stderr in vaguely comprehensible form
 */
void
tregdump(r)
	tregexp *r;
{
	register const char *s;
	register       char op = EXACTLY;  /* Arbitrary non-END op. */
	register const char *next;

	fprintf(stderr, "Compilation of %s:\n", r->pattern);
	s = r->program + 1;
	while (op != END) {	/* While that wasn't END last time... */
		op = OP(s);
		fprintf(stderr,
			"%2d%s", s - r->program, regprop(s));/* Where, what. */
		next = regnext(s);
		if (next == NULL)		/* Next ptr. */
			fprintf(stderr, "(0)");
		else 
			fprintf(stderr, "(%d)", (s-r->program)+(next-s));
		s += 3;
#ifndef	notdef
		if (op == ANYOF || op == ANYBUT || op == EXACTLY) {
#else
		if (op == EXACTLY) {
#endif
			/* Literal string, where present. */
			while (*s != '\0') {
				putc(*s,stderr);
				s++;
			}
			s++;
		}
		putc('\n',stderr);
	}

	/* Header fields of interest. */
	if (r->regstart != '\0')
		fprintf(stderr, "start `%c' ", r->regstart);
	if (r->reganch)
		fprintf(stderr, "anchored ");
	if (r->regmust != NULL)
		fprintf(stderr, "must have \"%s\"", r->regmust);
	fprintf(stderr, "\n");
}

/*
 - regprop - printable representation of opcode
 */
STATIC char *
regprop(op)
	const char *op;
{
	register const char *p = NULL;
	static char buf[50];

	strcpy(buf, ":");

	switch (OP(op)) {
	case BOL:
		p = "BOL";
		break;
	case EOL:
		p = "EOL";
		break;
	case ANY:
		p = "ANY";
		break;
#ifndef	notdef
	case ANYOF:
		p = "ANYOF";
		break;
	case ANYBUT:
		p = "ANYBUT";
		break;
#endif
	case BRANCH:
		p = "BRANCH";
		break;
	case EXACTLY:
		p = "EXACTLY";
		break;
	case NOTHING:
		p = "NOTHING";
		break;
	case BACK:
		p = "BACK";
		break;
	case END:
		p = "END";
		break;
	case OPEN+1:
	case OPEN+2:
	case OPEN+3:
	case OPEN+4:
	case OPEN+5:
	case OPEN+6:
	case OPEN+7:
	case OPEN+8:
	case OPEN+9:
		sprintf(buf+strlen(buf), "OPEN%d", OP(op)-OPEN);
		p = NULL;
		break;
	case CLOSE+1:
	case CLOSE+2:
	case CLOSE+3:
	case CLOSE+4:
	case CLOSE+5:
	case CLOSE+6:
	case CLOSE+7:
	case CLOSE+8:
	case CLOSE+9:
		sprintf(buf+strlen(buf), "CLOSE%d", OP(op)-CLOSE);
		p = NULL;
		break;
	case STAR:
		p = "STAR";
		break;
	case PLUS:
		p = "PLUS";
		break;
	default:
		tregerror("corrupted opcode", regprog);
		break;
	}
	if (p != NULL)
		strcat(buf, p);
	return(buf);
}
#endif

void
tregerror(s, prog)
	const char *s;
	tregexp *prog;
{
	if (prog != NULL && prog->pattern != NULL)
		fprintf(stderr, "%s: tregexp %s: %s\n", progname,
				prog->pattern, s);
	else
		fprintf(stderr, "%s: tregexp: %s\n", progname, s);
}


/*
 - tregsub - perform substitutions after a tregexp match
 *
 * prog may be NULL, in which case we only handle $ substitution.
 * $ returns the number of characters in dest, or 0 if no expansion
 * took place.
 */
const char *
tregsub(prog, n)
	tregexp *prog;
	int n;
{
	register token822 *ts, *te;
	char *cp;
	int len;
	int buflen;
	char *buf;

	regprog = prog;
	if (prog != NULL && UCHARAT(prog->program) != MAGIC)
		FAIL("damaged tregexp fed to tregsub");

	if (n < 0 || n > 9)
		FAIL("invalid substitution parameter requested");

	ts = prog->startp[n];
	te = prog->endp  [n];

	if (ts == NULL)
		/*FAIL("null substitution expansion");*/
		return NULL;

	ts = prog->startp[n];

	/* Must use malloc()ed buffer -- May resize while processing */
	buflen = 4000;
	buf = (char*)malloc(buflen);
	len = printdToken(&buf, &buflen, ts, te, 0);
	buf[len] = '\0';

	cp = (char*) tmalloc(len+1);
	memcpy(cp,buf,len+1);
	free(buf);

	return cp;
}
#endif	/* MAILER */
