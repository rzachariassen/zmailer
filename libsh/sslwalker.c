/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

#include "hostenv.h"
#include <stdio.h>
#include <ctype.h>
#include <sys/stat.h>
#include "listutils.h"
#include "sh.h"
#include "shconfig.h"

static		/* This will apply to the array in the .sst file */
#include "sh.sst.c"
#include "sh.entry"

#include "libsh.h"

STATIC const char * InputTokenName __((int));
STATIC char	*base, *nbase, *out;
STATIC u_int	outlen, outsize;
#define PATCH(Y)	*out++ = (Y)
#define	OUTPUT(X)	((outlen <= 0 ? \
			    (outsize *= 2, \
			     nbase = (char *)erealloc(base, outsize),\
			     out += (nbase - base), base = nbase, \
			     outlen = outsize/2 - 1) \
			  : --outlen), \
			 PATCH(X))

#define	INCPOS(c,v)	(c == '\t' ? v = (v|07)+1 : ++v)
#define	DECPOS(c,v)	(c == '\t' ? v &= ~07 : --v)

struct smallSymbol shsymbol[CHARSETSIZE];

struct kwdefn {
	const char *name;
	Keyword	    kw;
} kwlist[] = {	/* most used first order */
{	"in",		kIn		},
#ifdef	MAILER
{	"ssift",	kSSift		}, /* String SIFT */
{	"tfiss",	kTfisS		},
{	"tsift",	kTSift		}, /* Token SIFT */
{	"tfist",	kTfisT		},
{	"sift",		kSift		}, /* Obsolete Token SIFT */
{	"tfis",		kTfis		},
#endif	/* MAILER */
{	"case",		kCase		},
{	"esac",		kEsac		},
{	"if",		kIf		},
{	"then",		kThen		},
{	"fi",		kFi		},
{	"else",		kElse		},
{	"do",		kDo		},
{	"for",		kFor		},
{	"done",		kDone		},
{	"while",	kWhile		},
{	"elif",		kElif		},
{	"until",	kUntil		},
{	"localvar",	kLocalVariable	},
{	"local",	kLocalVariable	},
{	0,		kNull		}
};

/* Table Walker State */
STATIC int	processing;		/* are we running the table walker? */
STATIC int	sslPointer;		/* index into S/SL table */
STATIC int	commandLevel;		/* nesting level of Command structure */
STATIC int	flagindex, flags[100];	/* flags flags and more flags */
STATIC int	counter[10];		/* integer counters (++,--,==0?) */

/* Input State */
STATIC int	inlen;			/* number of characters before EOF */
STATIC char	*inptr;			/* next character to be read */
STATIC int	more;			/* is there more data ready to read? */
STATIC char	*bs, *be;		/* points to valid input data block */

/* Tracing Control */
STATIC FILE	*tracefp = NULL;	/* if non-null, trace output here */

/* Abort flag */
STATIC int	aborted;


/* S/SL System Failure Codes */

typedef enum {
	fSemanticChoiceFailed,			/* 0 */
	fChoiceRuleFailed			/* 1 */
} FailureCodes;				/* S/SL System Failure Code Type */


/* Input Interface */
STATIC FILE	*infp;
STATIC InputTokens	nextInputToken;
STATIC InputTokens	savedToken;
STATIC char inputTokenBuffer[3], acceptedTokenText[3];
STATIC char *inputCharStack = NULL;
STATIC u_int inputCharStackSize = 0;
STATIC int   charStackIndex = -1;

/* Line Counters */

STATIC int	nextLineNumber, nextLineChar;
STATIC int	lineNumber, lineChar;

/* Output Interface */
STATIC int	outputPosition;		/* current offset in output stream */

/* Variables Used in Syntax Error Recovery */
STATIC int	newInputLine = 0;

/* Initial "old" values of whitespace symbols, in case reset by IFS */
STATIC struct smallSymbol ws_symbols[] = {
{	tLetter,	tSyntaxError	},		/* space */
{	tLetter,	tSyntaxError	}		/* tab */
};

STATIC const char ws_chars[] = " \t";

void
ShInitIFS(uIFS)
	const char *uIFS;
{
	register const char *cp;
	int count;
	static const char *saveifs = ws_chars;
	char *saveifs_w;
	static struct smallSymbol *savesymbol = ws_symbols;

	if (savesymbol != NULL) {
		for (cp = saveifs, count = 0; *cp != '\0'; ++cp)
		  if (*cp != '\n') {
		    shsymbol[(*cp) & 0xFF].name  = savesymbol[count].name;
		    shsymbol[(*cp) & 0xFF].name2 = savesymbol[count].name2;
		    ++count;
		  }
		if (saveifs != ws_chars) {
			free((void *)savesymbol);
			free((void *)saveifs);
		}
	}
	if (*uIFS == '\0')
		uIFS = ws_chars;
	for (cp = uIFS, count = 0; *cp != '\0'; ++cp)
		if (*cp != '\n')
			++count;
	savesymbol = (struct smallSymbol *)emalloc(count *
						   sizeof (struct smallSymbol));
	for (cp = uIFS, count = 0; *cp != '\0'; ++cp)
		if (*cp != '\n') {
			savesymbol[count].name  = shsymbol[(*cp) & 0xFF].name;
			savesymbol[count].name2 = shsymbol[(*cp) & 0xFF].name2;
			shsymbol[(*cp) & 0xFF].name = tWhiteSpace;
			shsymbol[(*cp) & 0xFF].name2 = tSyntaxError;
			++count;
		}
	/* Using strsave() has hidden dangers due to  stickymem  value! */
	saveifs_w = (char *)emalloc(strlen(uIFS)+1);
	strcpy(saveifs_w, uIFS);
	saveifs = saveifs_w;
}

void
ShInit()
{
	register u_int i;
	register const u_char *cp;

	for (i = 0; i < (sizeof shsymbol/sizeof shsymbol[0]); ++i) {
		shsymbol[i].name  = tLetter;
		shsymbol[i].name2 = tSyntaxError;
	}
	for (cp = (const u_char *)"0123456789"; *cp != '\0'; ++cp)
		shsymbol[*cp].name = tDigit;
#if 0
	for (cp = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; *cp != '\0'; ++cp)
		shsymbol[*cp].name = tLetter;
	for (cp = "abcdefghijklmnopqrstuvwxyz"; *cp != '\0'; ++cp)
		shsymbol[*cp].name = tLetter;
#endif
	shsymbol['\t'].name = tWhiteSpace;
	shsymbol['\n'].name = tNewLine;
	shsymbol[' '].name = tWhiteSpace;
	shsymbol['!'].name = tExclamation;
	shsymbol['"'].name = tDoubleQuote;
	shsymbol['#'].name = tSharp;
	shsymbol['$'].name = tDollar;
	shsymbol['%'].name = tPercent;
	shsymbol['&'].name = tAmpersand;
	shsymbol['&'].name2 = tAnd;
	shsymbol['\''].name = tSingleQuote;
	shsymbol['('].name = tParenLeft;
	shsymbol[')'].name = tParenRight;
	shsymbol['*'].name = tStar;
	shsymbol['+'].name = tPlus;
	shsymbol[','].name = tComma;
	shsymbol['-'].name = tDash;
	shsymbol['.'].name = tPeriod;
	shsymbol['/'].name = tSlash;
	shsymbol[':'].name = tColon;
	shsymbol[';'].name = tSemicolon;
	shsymbol[';'].name2 = tLabelEnd;
	shsymbol['<'].name = tAngleLeft;
	shsymbol['<'].name2 = tAppendLeft;
	shsymbol['='].name = tEqual;
	shsymbol['>'].name = tAngleRight;
	shsymbol['>'].name2 = tAppendRight;
	shsymbol['?'].name = tQuestionMark;
	shsymbol['@'].name = tAt;
	shsymbol['['].name = tSquareLeft;
	shsymbol['\\'].name = tBackSlash;
	shsymbol[']'].name = tSquareRight;
	shsymbol['^'].name = tCaret;
	shsymbol['_'].name = tUnderscore;
	shsymbol['`'].name = tBackQuote;
	shsymbol['{'].name = tBraceLeft;
	shsymbol['|'].name = tPipe;
	shsymbol['|'].name2 = tOr;
	shsymbol['}'].name = tBraceRight;
	shsymbol['~'].name = tTilde;
}

/* This procedure emits the error message associated with errCode */

STATIC struct errmsgs {
	ErrorCodes	e;
	const char	*m;
} emsglist[] = {
{ eSyntaxError,			"syntax error"				},
{ ePrematureEndOfFile,		"unexpected end of file"		},
{ eExtraneousProgramText,	"extraneous program text"		},
{ eSslStackOverflow,		"nesting too deep"			},
{ eIllegalArgumentSeparator,	"illegal argument separator"		},
{ eMissingDo,			"missing 'do' keyword"			},
{ eMissingDoOrIn,		"missing 'do' or 'in' keyword to start loop"  },
{ eMissingDone,			"missing 'done' keyword to terminate loop"    },
{ eMissingEndOfPattern,		"missing '|' or ')' to continue or end label" },
{ eMissingEsac,			"missing 'esac' to end case statement"	},
{ eMissingFi,			"missing 'fi' to end if statement"	},
{ eMissingIOopTarget,		"missing I/O operation (dup/close) target"    },
{ eMissingKeywordIn,		"missing 'in' after case statement expression"},
{ eMissingThen,			"missing 'then' after conditional expression" },
{ eMissingRightBrace,		"missing '}' to end parameter substitution" },
{ eUnknownDollarOperand,	"unknown operand of $"			},
{ eUnmatchedEndOfGroup,		"saw unmatched group terminator ('}' or ')')" },
{ eIllegalLeftParen,		"illegal position for unquoted left parenthesis"},
{ eIllegalConnector,		"illegal connector after backgrounding"	},
{ eIllegalTokenUnbalancedList,	"illegal token within list"		},
{ eObsoleteSift,		"'sift' is obsolete form of 'tsift'" },
{ eObsoleteTfis,		"'tfis' is obsolete form of 'tfist'" },
{ eTfissMisparity,		"had 'tfiss', expected 'tfist'" },
{ eTfistMisparity,		"had 'tfist', expected 'tfiss'" },
};

STATIC const char *errfilename;   /* set from inputname in SslWalker */

STATIC void sslw_error __((ErrorCodes));
STATIC void
sslw_error(errCode)
	ErrorCodes errCode;
{
	u_int i;
	char *cp, *bos;
	const char *msg = "unknown error";

	if (errCode == eNoError)
		abort();

	for (i = 0; i < (sizeof emsglist / sizeof emsglist[0]); ++i)
		if (emsglist[i].e == errCode) {
			msg = emsglist[i].m;
			break;
		}
	if (errfilename)
		printf("\"%s\", line %d, column %d: %s\n",
			    errfilename, lineNumber, lineChar+1, msg);
	else
		printf("stdin, line %d, column %d: %s\n",
			    lineNumber, lineChar+1, msg);
	for (cp = inptr-1; cp > bs ; --cp) {
		if (*cp == '\n') {
			++cp;
			break;
		}
	}
	bos = cp;
	while (cp < be && *cp != '\n' && *cp != '\0')
		++cp;
	putchar('\t');
	for (i = 0; i < lineChar; ++i)
		putchar(' ');
	putchar('v');
	putchar('\n');
	printf("\t%*.*s\n", (int)(cp - bos), (int)(cp - bos), bos);

	/* all errors are fatal because its almost impossible to recover well */
	processing = 0;
	aborted = 1;
}

#define	NEXTCHAR(FLAG)	\
	if (charStackIndex >= 0) {	\
		c = inputCharStack[charStackIndex--], INCPOS(c,nextLineChar); \
		if (isset('L')) \
			printf("ate '%c' from charstack, left %d\n", \
				    c, charStackIndex); \
	} else if (inlen == 0 \
		   && (!(FLAG) || \
		       (inlen = zshinput(1, &inptr, &more, &bs, &be)) == 0)) { \
		nextInputToken = tEndOfFile; \
		goto traceit; \
	} else \
		inlen--, c = *inptr++, INCPOS(c,nextLineChar); \
	if (isset('L')) \
		printf("read '%c' (%d)\n", c, inlen);

#define	PUSHCHAR(C)	\
	if (inputCharStackSize < charStackIndex + 1) { \
		inputCharStackSize *= 2; \
		inputCharStack = erealloc(inputCharStack, inputCharStackSize); \
	} \
	inputCharStack[++charStackIndex] = (C);	\
	DECPOS(c,nextLineChar);	\
	if (isset('L'))	\
		printf("unread '%c', left %d\n", (C), charStackIndex);

void
ungetbuf(buf, len)
	char *buf;
	int len;
{
	int i;

	while (inputCharStackSize < charStackIndex + 2 + len + 1) {
		inputCharStackSize *= 2;
		inputCharStack = erealloc(inputCharStack, inputCharStackSize);
	}
	if (inputTokenBuffer[1] != '\0') {
		inputCharStack[++charStackIndex] = inputTokenBuffer[1];
		DECPOS(inputTokenBuffer[1],nextLineChar);
	}
	inputCharStack[++charStackIndex] = inputTokenBuffer[0];
	if (shsymbol[inputTokenBuffer[0] & 0xFF].name == tNewLine)
		--nextLineNumber;
	/* push buffer */
	for (i = 0; i < len; ++i) {
		inputCharStack[++charStackIndex] = *(buf+len-i-1);
		DECPOS(*(buf+len-i-1),nextLineChar);
	}
	/* get rid of the byte we put in inputTokenBuffer */

if (charStackIndex < 0) /* Make sure it is above zero.. */
  abort();

	inputCharStack[charStackIndex--] = '\0';
	if (len > 0) {
		inputTokenBuffer[0] = *buf;
		inputTokenBuffer[1] = '\0';
	}
	lineChar = nextLineChar-1; /* the -1 is empirical... */
	if (isset('S'))
		printf("ungot keyword '%s', inputCharStack<%d> is '%s%c'\n",
			buf,charStackIndex,inputCharStack,*buf);
}

/*
 * This procedure provides the interface to the previous pass.
 * It is reponsible for handling all input including line number
 * indicators and the values and text associated with input tokens.  
 */

STATIC void AcceptInputToken __((int));
STATIC void
AcceptInputToken(flag)
	register int	flag;
{
	register int	c;
	InputTokens	acceptedToken;
	/* max no. backslashes in a row inside backquotes */
	char		*cp, backbuf[256];
	int i;

	if (!flag) {
		if (nextInputToken == tEndOfFile)
			abort();

		/* Accept Token */
		acceptedToken = nextInputToken;
		acceptedTokenText[0] = inputTokenBuffer[0];
		acceptedTokenText[1] = inputTokenBuffer[1];
		acceptedTokenText[2] = inputTokenBuffer[2];
	} else	/* random assignment to shut up compilers */
		acceptedToken = nextInputToken;

	/* Update Line Number */
	lineNumber = nextLineNumber;
	lineChar = nextLineChar;

	/* Read Next Input Token */
	newInputLine = 0;
	NEXTCHAR(flag);
	inputTokenBuffer[0] = c;
	inputTokenBuffer[1] = '\0';
	nextInputToken = shsymbol[c & 0xFF].name;
	if (nextInputToken == tNewLine) {
		/* Update Line Counter and Set Flag */
		newInputLine = 1;
		nextLineChar = 0;
		++nextLineNumber;
	} else if (shsymbol[c & 0xFF].name2 != tSyntaxError) {
		/* A two-character symbol */
		NEXTCHAR(1);
		if (c == inputTokenBuffer[0]) {
			nextInputToken = shsymbol[c & 0xFF].name2;
			inputTokenBuffer[1] = c;
			inputTokenBuffer[2] = '\0';
		} else {
			PUSHCHAR(c);
		}
	} else if (counter[(int)countBackQuoteNestingLevel] > 0
		   && shsymbol[c & 0xFF].name == tBackSlash) {
		cp = backbuf;
		for (i = 0; i < counter[(int)countBackQuoteNestingLevel]; ++i) {
			if (shsymbol[c & 0xFF].name != tBackSlash)
				break;
			NEXTCHAR(flag);
			*cp++ = c;	/* onto slash stack */
		}
		if (shsymbol[c & 0xFF].name == tBackQuote) {
			/* ignore the stuff we pushed - that's easy */
			inputTokenBuffer[0] = c;
			inputTokenBuffer[1] = '\0';
			if (i == counter[(int)countBackQuoteNestingLevel])
				nextInputToken = tBackQuoteLeft;
			else
				nextInputToken = tBackQuote;
		} else {
			/* restore the stuff we pushed */
			while (cp > backbuf) {
				--cp;
				PUSHCHAR(*cp);;
			}
			/* the original tBackSlash was fine */
		}
	}

	/* Trace Input */
traceit:
	if (!flag && tracefp)
	    printf("Input token accepted %s (%d)  Line %d  Next input token %s (%d)\n",
			InputTokenName((int)acceptedToken), acceptedToken,
			lineNumber,
			InputTokenName((int)nextInputToken), nextInputToken);
}

/* Emit an output token to the output stream */

STATIC void EmitOutputToken __(( OutputTokens ));
STATIC void
EmitOutputToken(emittedToken) 
	register OutputTokens	emittedToken;
{
	if (emittedToken == sCommandPush)
		++commandLevel;
	else if (emittedToken == sCommandPop)
		--commandLevel;
	/* Trace Output */
	/* if (tracefp == NULL)
		return; */
	if (isset('C'))
		printf("%d:\t%s (%d)\n", outputPosition,
				TOKEN_NAME(emittedToken), emittedToken);
	else
		OUTPUT(emittedToken);
	++outputPosition;
	if (emittedToken == sBranchOrigin) {
		outputPosition += 3;
		if (!isset('C')) {
			OUTPUT(emittedToken);
			OUTPUT(emittedToken);
			OUTPUT(emittedToken);
		}
	}
}


/*
 * The constants, variables, types, modules and procedures used in
 * implementing the Semantic Mechanisms of the pass go here.  These
 * implement the facilities used in the semantic operations.
 */

/*
 * This procedure handles syntax errors in the input to the Parser pass,
 * for Semantic passes this procedure will simply assert false since a
 * syntax error in input would indicate an error in the previous pass.
 *
 * Syntax error recovery:
 * When a mismatch occurs between the the next input token and the syntax
 * table, the following recovery is employed.
 *
 * If the expected token is tNewLine then if there has been no previous
 * syntax error on the line, ignore the error.  (A missing logical new line
 * is not a real error.)
 *
 * If the expected token is tNewLine or tSemicolon and a syntax error has
 * already been detected on the current logical line (Flagged by nextToken ==
 * tSyntaxError), then flush the input exit when a new line or end of file
 * is found.
 *
 * Otherwise, if this is the first syntax error detected on the line
 * (flagged by nextToken != tSyntaxError), then if the input token is
 * tEndOfFile then emit the ePrematureEndOfFile error code and terminate
 * execution.  Otherwise, emit the eSyntaxError error code and set the
 * nextToken to tSyntaxError to prevent further input exit when the expected
 * input is tSemicolon or tNewLine.
 *
 * If the expected token is not tSemicolon nor tNewLine and a syntax error
 * has already been detected on the current line (flagged by nextToken ==
 * tSyntaxError), then do nothing and continue as if the expected token had
 * been matched.
 */

STATIC void SslSyntaxError __((TableOperation));
STATIC void
SslSyntaxError(opcode)
	TableOperation opcode;
{
	if (opcode != oInput && opcode != oInputAny)
		abort();

	if (nextInputToken == tSyntaxError) {
		/* Currently recovering from syntax error */
		if (sslTable[sslPointer] == (int)(tNewLine)
		    || sslTable[sslPointer] == (int)(tSemicolon)) {
			/* Complete recovery by synchronizing
			   input to a new line */
			nextInputToken = savedToken;
			newInputLine = 0;
			while (nextInputToken != tSemicolon
			       && nextInputToken != tEndOfFile && !newInputLine)
				AcceptInputToken(0);
		}
	} else {
		/* First syntax error on the line */
		if (sslTable[sslPointer] == (int)(tNewLine)) {
			/* Ignore missing logical newlines */
		} else if (nextInputToken == tEndOfFile) {
			/* Flag error and terminate processing */
			sslw_error(ePrematureEndOfFile);
			processing = 0;
		} else {
			sslw_error(eSyntaxError);
			savedToken = nextInputToken;
			nextInputToken = tSyntaxError;
			lineNumber = nextLineNumber;
		}
	}
}

STATIC const char *
InputTokenName(in)
	int in;
{
	switch ((InputTokens)in) {
#include "sh-in.i"
	default:
		break;
	}
	return "unknown input token";
}

STATIC const char * TableOperationName __((TableOperation));
STATIC const char *
TableOperationName(op)
	TableOperation	op;
{
	static char buf[40];

	switch (op) {
	case oCall:		return "oCall";
	case oReturn:		return "oReturn";
	case oRuleEnd:		return "oRuleEnd";
	case oJump:		return "oJump";
	case oInput:		return "oInput";
	case oInputAny:		return "oInputAny";
	case oInputChoice:	return "oInputChoice";
	case oEmit:		return "oEmit";
	case oError:		return "oError";
	case oChoice:		return "oChoice";
	case oChoiceEnd:	return "oChoiceEnd";
	case oSetParameter:	return "oSetParameter";
	case oSetResult:	return "oSetResult";
	case oSetResultFromInput:	return "oSetResultFromInput";
	/* case oString:		return "oString"; */
	case oIdentWord:	return "oIdentWord";
	case oIdentifyKeyword:	return "oIdentifyKeyword";
	case oUngetKeyword:	return "oUngetKeyword";
	case oBufferClear:	return "oBufferClear";
	case oBufferAppend:	return "oBufferAppend";
	case oBufferAppendCaret:	return "oBufferAppendCaret";
	case oBufferAppendDollar:	return "oBufferAppendDollar";
	case oBufferEmit:	return "oBufferEmit";
	case oBufferTerminate:	return "oBufferTerminate";
	case oBufferUsed:	return "oBufferUsed";
	case oBranchPushOrigin:	return "oBranchPushOrigin";
	case oBranchPatch:	return "oBranchPatch";
	case oBranchPatchBack:	return "oBranchPatchBack";
	case oBranchPopOrigin:	return "oBranchPopOrigin";
	case oBranchSwapTop:	return "oBranchSwapTop";
	case oEmitBranchOrigin:	return "oEmitBranchOrigin";
	case oHereSaveStop:	return "oHereSaveStop";
	case oHereCompareStop:	return "oHereCompareStop";
	case oHereCutBuffer:	return "oHereCutBuffer";
	case oFlagsPush:	return "oFlagsPush";
	case oFlagsPop:		return "oFlagsPop";
	case oFlagsSet:		return "oFlagsSet";
	case oFlagsTest:	return "oFlagsTest";
	case oCounterClear:	return "oCounterClear";
	default:	break;
	}
	sprintf(buf, "unknown op %d", op);
	return buf;
}

STATIC int level = 0;

STATIC void SslTrace __((TableOperation));
STATIC void
SslTrace(opcode)
	TableOperation opcode;
{
	int i;

	for (i = 0; i < level; ++i) {
		putchar(' '); putchar(' '); putchar(' '); putchar(' ');
	}
	printf("%4d: %s ", sslPointer-1, TableOperationName(opcode));
	if (opcode == oCall) {
		switch (sslTable[sslPointer]) {
#include "sh-procs.i"
		default:	printf("%d", sslTable[sslPointer]);
		}
		putchar('\n');
		++level;
	} else
		printf("(%d)\n", sslTable[sslPointer]);
	if (opcode == oReturn)
		--level;
}


STATIC void SslFailure __((FailureCodes, TableOperation));

STATIC void
SslFailure(failCode, opcode)
	FailureCodes failCode;
	TableOperation opcode;
{
	printf("### S/SL program failure:  ");

	switch (failCode) {
	case fSemanticChoiceFailed:
		printf("Semantic choice failed\n");
		break;
	case fChoiceRuleFailed:
		printf("Choice rule returned without a value\n");
		break;
	}

	printf("while processing line %d\n", lineNumber);

	SslTrace(opcode);
	abort();
}


/*
 * This procedure performs both input and semantic choices.  It sequentially
 * tests each alternative value against the tag value, and when a match is
 * found, performs a branch to the corresponding alternative path.  If none
 * of the alternative values matches the tag value, sslTable interpretation
 * proceeds to the operation immediately following the list of alternatives
 * (normally the otherwise path).  The flag choiceTagMatched is set to true
 * if a match is found and false otherwise.
 */

STATIC int SslChoice __((int));

STATIC int
SslChoice(choiceTag)
	register int choiceTag;
{
	register int	numberOfChoices, choicePointer;

	choicePointer = sslTable[sslPointer];

	if (choiceTag == (int)tEndOfFile
	    && (more || commandLevel != 0
		|| (flagindex >= 0
		    && (flags[flagindex] & (1 << (int)bitHereData))))) {
		/* printf("need continuation\n"); */
		AcceptInputToken(1);
		choiceTag = (int)nextInputToken;
	}
	for (numberOfChoices = sslTable[choicePointer++];
	     numberOfChoices > 0;
	     choicePointer += 2, --numberOfChoices) {
		if (tracefp) {
			int i;
			for (i = -1; i < level; ++i) {
				putchar(' '); putchar(' ');
				putchar(' '); putchar(' ');
			}
			printf("? %s (%d) == %s (%d) ?\n",
				InputTokenName(choiceTag), choiceTag,
				InputTokenName(sslTable[choicePointer]),
				sslTable[choicePointer]);
		}
		if (sslTable[choicePointer] == choiceTag) {
			sslPointer = sslTable[choicePointer+1];
			return 1;
		}
	}
	sslPointer = choicePointer;
	return 0;
}


void *
SslWalker(inputname, tfp, eotp)
	const char *inputname;	/* string used for error messages */
	FILE *tfp;
	void **eotp;
{
	static int	inited = 0;
	struct kwdefn	*kwp;
	register int	i, bufferIndex;
	TableOperation	opcode;	/* the current operation */
	int		branchOriginTop, branchOrigin[127];
	char		*cp, *herebuf, *buffer;
	int		bufferSize;

	/*
	 * These are used to hold the decoded parameter value to a parameterized
	 * semantic operation and the result value returned by a choice semantic
	 * operation or rule respectively.
	 */

	int	parameterValue = 0;	/* Parameter for Semantic Operation */
	int	resultValue = 0;	/* Result from Semantic Operation */

	/*
	 * The Rule Call Stack implements Syntax/Semantic Language rule call and
	 * return.  Each time an oCall operation is executed, the table return
	 * address is pushed onto the Rule Call Stack.  When an oReturn is
	 * executed, the return address is popped from the stack.  An oReturn
	 * executed when the Rule Call Stack is empty terminates table
	 * execution.
	 */
	int	sslStack[127];		/* The S/SL Rule Call Stack */
#define	sslStackSize	(sizeof sslStack/sizeof sslStack[0])
	int	sslTop = 0;


	if (!inited) {
		ShInit();
		inited = 1;
	}

/*setopt('L',1);*//*setopt('C',1);setopt('P',1);setopt('S',1);*/

	/*
	 * Grab input before initializations in case a trap causes
	 * recursive invocation of the SslWalker().
	 */
	inlen = zshinput(0, &inptr, &more, &bs, &be);

	/* initialize state */
	buffer = NULL;
	bufferIndex = 0;
	bufferSize = 0;
	charStackIndex = -1;
	inputCharStackSize = 128-24;
	inputCharStack = emalloc(inputCharStackSize); /* External buffer */
	flagindex = -1;
	infp = stdin;
	if (isset('P'))
		tracefp = tfp;
	else
		tracefp = NULL;
	branchOriginTop = -1;
	processing = 1;
	sslPointer = 0;
	commandLevel = 0;
	errfilename = inputname;
	aborted = 0;
	herebuf = NULL;

	/* Initialize Input/Output */
	outlen = outsize = (1<<8)-8; /* Smallish start size */
	out = base = (char *)emalloc(outsize); /* External buffer */
	nextInputToken = tNewLine;
	nextLineNumber = lineNumber = 1;
	nextLineChar = lineChar = 0;
	outputPosition = 0;
	AcceptInputToken(0);

	/* Walk the S/SL Table */

	while (processing && !interrupted) {
		opcode = (TableOperation)(sslTable[sslPointer++]);

		/* Trace Execution */
		if (tracefp)
			SslTrace(opcode);

		switch (opcode) {
		case oCall:
			if (sslTop < sslStackSize) {
				sslStack[++sslTop] = sslPointer + 1;
				sslPointer = sslTable[sslPointer];
			} else {
				sslw_error(eSslStackOverflow);
				processing = 0;
			}
			break;
		case oReturn:
			if (sslTop == 0)
				/* Return from main S/SL procedure */
				processing = 0;
			else
				sslPointer = sslStack[sslTop--];
			break;
		case oRuleEnd:
			SslFailure(fChoiceRuleFailed, opcode);
			break;
		case oJump:
			sslPointer = sslTable[sslPointer];
			break;
		case oInput:
			if (sslTable[sslPointer] == (int)(nextInputToken))
				AcceptInputToken(0);
			else
				/* Syntax error in input */
				SslSyntaxError(opcode);
			++sslPointer;
			break;
		case oInputAny:
			if (nextInputToken != tEndOfFile)
				AcceptInputToken(0);
			else
				/* Premature end of file */
				SslSyntaxError(opcode);
			break;
		case oInputChoice:
			if (SslChoice((int)nextInputToken))
				AcceptInputToken(0);
			break;
		case oEmit:
			EmitOutputToken((OutputTokens)sslTable[sslPointer]);
			++sslPointer;
			break;
		case oError:
			sslw_error((ErrorCodes)sslTable[sslPointer]);
			++sslPointer;
			break;
		case oChoice:
			SslChoice(resultValue);
			break;
		case oChoiceEnd:
			SslFailure(fSemanticChoiceFailed, opcode);
			break;
		case oSetParameter:
			parameterValue = sslTable[sslPointer++];
			break;
		case oSetResult:
			resultValue = sslTable[sslPointer++];
			break;
		case oSetResultFromInput:
			resultValue = (int)nextInputToken;
			break;

		/* Identify mechanism */
		case oIdentWord:
			/*
			 * Determine if the buffer contains a Name or a Word.
			 */
			if (buffer == NULL || bufferSize == 0
			    || !isascii(buffer[0]) || !isalnum(buffer[0])
			    || (buffer[0] == 'r'
				&& strncmp(buffer, "return", 6) == 0)) {
				resultValue = (int)sWord;
				break;
			}
			resultValue = (int)sName;
			for (i = 1; i < bufferIndex; ++i) {
				if (!isascii(buffer[0])) {
					resultValue = (int)sWord;
					break;
				}
				if (!(isalnum(buffer[i]) || buffer[i] == '_')) {
					resultValue = (int)sWord;
					break;
				}
			}
			break;
		case oIdentifyKeyword:
			/*
			 * If the buffer contains a keyword, set resultValue
			 * to a value indicating which keyword
			 */
			resultValue = (int)kNull;
			if (buffer == NULL)
				break;
			if (isset('S'))
				printf("identifying '%s'\n", buffer);
			for (kwp = &kwlist[0]; kwp->name != NULL; ++kwp) {
				if (strcmp(kwp->name, buffer) == 0) {
					resultValue = (int)(kwp->kw);
					break;
				}
			}
			break;

		/* Backup mechanism */
		case oUngetKeyword:
			/* push pending stuff on input stack */
			if (buffer == NULL || buffer[0] == '\0')
				break;
			ungetbuf(buffer, bufferIndex);
			nextInputToken = shsymbol[buffer[0] & 0xFF].name;
			break;

		/* Buffer mechanism */
		case oBufferClear:
			bufferIndex = 0;
			break;
		case oBufferAppendCaret:
		case oBufferAppendDollar:
			if (opcode == oBufferAppendCaret)
				acceptedTokenText[0] = '^';
			else
				acceptedTokenText[0] = '$';
			acceptedTokenText[1] = '\0';
			/* fall through */
		case oBufferAppend:
			if (isset('S'))
				printf("append '%c'\n",
						      acceptedTokenText[0]);
			if (bufferIndex + 1
			    + (acceptedTokenText[1] != '\0') >= bufferSize) {
				if (buffer == NULL) {
					bufferSize = 128-24;
					buffer = emalloc(bufferSize);
				} else {
					bufferSize *= 2;
					buffer = erealloc(buffer, bufferSize);
				}
			}
			buffer[bufferIndex++] = acceptedTokenText[0];
			if (acceptedTokenText[1] != '\0')
				buffer[bufferIndex++] = acceptedTokenText[1];
			break;
		case oBufferEmitPattern:
			if (!isset('C'))
				OUTPUT('^');
			++outputPosition;
			/* FALLTHROUGH */
		case oBufferEmit:
			if (isset('C'))
				printf("buffer '%s'\n", buffer);
			else if (buffer != NULL) {
				for (cp = buffer; *cp != '\0'; ++cp)
					OUTPUT(*cp);
				outputPosition += strlen(buffer);
			}
			if (opcode == oBufferEmitPattern) {
				if (!isset('C'))
					OUTPUT('$');
				++outputPosition;
			}
			if (!isset('C'))
				OUTPUT(0);
			++outputPosition;
			break;
		case oBufferTerminate:
			if (buffer == NULL)
				break;
			buffer[bufferIndex] = '\0';
			if (isset('S'))
				printf("buffer: '%s'\n", buffer);
			break;
		case oBufferUsed:
			resultValue = (int)(bufferIndex == 0 ? empty : used);
			break;
		    
		/* BranchStack mechanism */
		case oBranchPushNullOrigin:
			branchOrigin[++branchOriginTop] = 0;
			break;
		case oBranchPushOrigin:
			branchOrigin[++branchOriginTop] = outputPosition;
/* XXX */		if (branchOriginTop > 100) {
				setopt('P', 1);
				tracefp = stdout;
				printf("---%d\n", branchOriginTop);
			}
			break;
		case oBranchPatchBack:
			if (branchOriginTop)
				i = branchOrigin[branchOriginTop-1];
			else
				i = outputPosition;
			if (isset('C'))
				printf("patching %d to be %d\n",
					 branchOrigin[branchOriginTop], i);
			else {
				out = base + branchOrigin[branchOriginTop];
				PATCH((i>>24)&0xff);
				PATCH((i>>16)&0xff);
				PATCH((i>>8)&0xff);
				PATCH(i&0xff);
				out = base + outputPosition;
			}
			break;
		case oBranchPatch:
			i = outputPosition;
			if (isset('C'))
				printf("patching %d to be %d\n",
					 branchOrigin[branchOriginTop], i);
			else {
				out = base + branchOrigin[branchOriginTop];
				PATCH((i>>24)&0xff);
				PATCH((i>>16)&0xff);
				PATCH((i>>8)&0xff);
				PATCH(i&0xff);
				out = base + outputPosition;
			}
			break;
		case oBranchPopOrigin:
			if (branchOriginTop < 0)
				abort();
			--branchOriginTop;
			break;
		case oBranchSwapTop:
			if (branchOriginTop < 1)
				abort();
			i = branchOrigin[branchOriginTop];
			branchOrigin[branchOriginTop] =
				branchOrigin[branchOriginTop-1];
			branchOrigin[branchOriginTop-1] = i;
			break;

		/* Emit mechanism */
		case oEmitBranchOrigin:
			if (isset('C'))
				printf("position %d\n", branchOrigin[branchOriginTop]);
			else {
				i = branchOrigin[branchOriginTop];
				OUTPUT((i>>24)&0xff);
				OUTPUT((i>>16)&0xff);
				OUTPUT((i>>8)&0xff);
				OUTPUT(i&0xff);
			}
			outputPosition += 4;
			break;

		/* Here Documents mechanism */
		case oHereSaveStop:
			/* Save stuff in the buffer into separate storage */
			if (herebuf != NULL)
				free(herebuf);
			herebuf = emalloc(bufferSize);
			strcpy(herebuf, buffer);
			break;
		case oHereCompareStop:
			/* Compare last line in the buffer with herebuf */
			buffer[bufferIndex] = '\0';
			for (i = bufferIndex; i >= 0; --i) {
				if (buffer[i] == '\n') {
					++i;
					break;
				}
			}
			if (i < 0)
				i = 0;
			if (isset('S'))
				printf("comparing '%s' and '%s'\n",
						  &buffer[i], herebuf);
			if (strcmp(&buffer[i], herebuf) == 0)
				resultValue = (int)same;
			else
				resultValue = (int)different;
			break;
		case oHereCutBuffer:
			/* Get rid of last line in the buffer */
			for (i = bufferIndex; i >= 0; --i) {
				if (buffer[i] == '\n') {
					bufferIndex = ++i;
					buffer[bufferIndex] = '\0';
					if (isset('S'))
					    printf("buffer: '%s'\n",buffer);
					break;
				}
			}
			if (i < 0) {
				bufferIndex = 0;
				buffer[0] = '\0';
			}
			break;

		/* Flags Mechanism */
		case oFlagsPush:
			if (flagindex+1 >= (sizeof flags / sizeof flags[0]))
				abort();
			flags[++flagindex] = 0;
			break;

		case oFlagsPop:
			if (flagindex < 0)
				abort();
			--flagindex;
			break;

		case oFlagsSet:
			flags[flagindex] |= (1<<parameterValue);
			break;

		case oFlagsTest:
			if (flagindex >= 0
			    && (flags[flagindex] & (1<<parameterValue)))
				resultValue = (int) on;
			else
				resultValue = (int) off;
			break;

		case oCounterClear:
			if (parameterValue >=(sizeof counter/sizeof counter[0]))
				abort();
			counter[parameterValue] = 0;
			break;

		case oCounterIncrement:
			if (parameterValue >=(sizeof counter/sizeof counter[0]))
				abort();
			++counter[parameterValue];
			break;

		case oCounterDecrement:
			if (parameterValue >=(sizeof counter/sizeof counter[0]))
				abort();
			--counter[parameterValue];
			break;

		case oCounterTest:
			if (parameterValue >=(sizeof counter/sizeof counter[0]))
				abort();
			if (counter[parameterValue] > 0)
				resultValue = (int) on;
			else
				resultValue = (int) off;
			break;

		default:
			printf("Unknown operation %d\n", opcode);
			abort();
		}
	}

	if (isset('L'))
	  printf("inputCharStackSize=%d (initial was: %d)\n",
		 inputCharStackSize,128-24);
	free(inputCharStack);
	inputCharStack = NULL;
	if (herebuf != NULL)
		free(herebuf);
	if (buffer != NULL)
		free(buffer);
	if (aborted || interrupted || out == base) {
		free((char *)base);
		return NULL;
	} else if (nextInputToken != tEndOfFile && !aborted) {
		sslw_error(eExtraneousProgramText);
		free((char *)base);
		return NULL;
	}

	*eotp = out;
	return base;
}
