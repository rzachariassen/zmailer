/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *
 *      Copyright Matti Aarnio <mea@nic.funet.fi> 1992-2000
 */

/* DO NOT USE  #include "router.h" */
#include "hostenv.h"
#include "mailer.h"
#include "libz.h"
#include "prototypes.h"


#undef STATIC
#define STATIC	static
#undef ATHACK	/* 'user at host' == 'user@host' */

#include "rfc822.sst.h"
STATIC		/* This will apply to the array in the .sst file */
#include "rfc822.sst.c"

extern void	EmitToken __((token822 *t, ComponentClass ac, struct address *ap));
STATIC const char * Input822TokenName __((int));

/* private semantics mechanism variables: */
STATIC ComponentClass currentTokenType;
STATIC token822 *ptrNextInputToken, *ptrAcceptedToken;
STATIC token822 *headPending, **pending;
STATIC token822 *headDeferred, **deferred;

/* Table Walker State */
STATIC int	processing;		/* are we running the table walker? */
STATIC int	inAddress;		/* are we collecting an address? */
STATIC int	sslPointer;		/* index into S/SL table */
STATIC TableOperation	operation;	/* the current operation */

/* convenience */
STATIC struct address nullAddr = { NULL, NULL, newAddress, 0, NULL, NULL };
#ifdef ATHACK
STATIC token822 atsigntoken = { "@", 1, Special, NULL };
#endif

/* Tracing Control */
STATIC FILE	*tracefp;		/* if non-null, trace output here */

/* Abort flag */
STATIC int	aborted;

/*
 * The Rule Call Stack implements Syntax/Semantic Language rule call and return.
 * Each time an oCall operation is executed, the table return address is pushed
 * onto the Rule Call Stack.  When an oReturn is executed, the return address
 * is popped from the stack.  An oReturn executed when the Rule Call Stack is
 * empty terminates table execution.
 */

STATIC int	sslStack[127];		/* The S/SL Rule Call Stack */
#define	sslStackSize	(sizeof sslStack/sizeof sslStack[0])
STATIC int	sslTop;

/*
 * Set by the Choice Handler to indicate whether a match was made or the
 * otherwise path was taken.  Set to true if a match was made and false
 * otherwise.  This flag is used in input choices to indicate whether the
 * choice input token should be accepted or not.
 */

STATIC int	choiceTagMatched;	/* Choice Match Flag */

/*
 * These are used to hold the decoded parameter value to a parameterized
 * semantic operation and the result value returned by a choice semantic
 * operation or rule respectively.					 
 */

STATIC int	parameterValue;		/* Parameter for Semantic Operation */
STATIC int	resultValue;		/* Result from Semantic Operation */

/* S/SL System Failure Codes */

typedef enum {
	fSemanticChoiceFailed,			/* 0 */
	fChoiceRuleFailed			/* 1 */
} FailureCodes;				/* S/SL System Failure Code Type */


#define	maxErrors	20
STATIC int	noErrors;		/* Error Counter */
STATIC ErrorCodes	firstFatalErrorCode = eSslStackOverflow;  /* fix */

/* Input Interface */
STATIC InputTokens	nextInputToken = tNewLine;
STATIC InputTokens	acceptedToken;

struct receivedtag {
	const char	*name;
	int		 len;
	InputTokens	 value;
};

STATIC struct receivedtag rt[] = {
	{	"from",		4,	tFrom		},
	{	"by",		2,	tBy		},
	{	"id",		2,	tId		},
	{	"with",		4,	tWith		},
	{	"via",		3,	tVia		},
	{	"for",		3,	tFor		},
	{	"convert",	7,	tConvert	},
	{	0,		0,	tSyntaxError	}
};

/* Variables Used in Syntax Error Recovery */
STATIC InputTokens	savedInputToken;
STATIC int		RunningSslRecovery = 0;

STATIC struct {
	ErrorCodes ec;
	const char *msg;
} ear[] = {
{ eSyntaxError,			"Syntax error"				},
{ ePrematureEndOfFile,		"Unexpected end of file"		},
{ eExtraneousProgramText,	"Extraneous program text"		},
{ eSslStackOverflow,		"Nesting too deep"			},
{ eExtraneousTokensInAddress,	"extraneous tokens in address"		},
{ eExtraneousTokensInMailbox,	"extraneous tokens in mailbox"		},
{ eMissingSemicolonToEndGroup,	"missing semicolon to end mail group"	},
{ eMissingSemicolonInReceived,	"missing semicolon before timestamp"	},
{ eMissingEndOfAddress,		"missing end of address"		},
{ eMissingEndOfMailbox,		"missing end of mailbox"		},
{ eIllegalWordInPhrase,		"illegal word in phrase"		},
{ eIllegalSpecialInPhrase,	"illegal special character in phrase"	},
{ eIllegalPeriodInPhrase,	"illegal period in phrase"		},
{ eIllegalPhraseMustBeQuoted,	"phrases containing '.' must be quoted"	},
{ eIllegalSubdomainInDomain,	"illegal subdomain in domain, probably extra '.' at the end of the address"	},
{ eIllegalTokenInRoute,		"illegal token in route"		},
{ eIllegalWordInLocalPart,	"illegal word in localpart, probably extra '.' at the end of the address"	},
{ eIllegalStartOfMessageId,	"illegal start of message identification"},
{ eIllegalEndOfMessageId,	"illegal end of message identification"	},
{ eIllegalEncryptionIdentifier,	"illegal encryption Identifier"		},
{ eIllegalAddressSeparator,	"illegal address separator"		},
{ eIllegalMailboxSeparator,	"illegal mailbox separator"		},
{ eIllegalMessageIDSeparator,	"illegal message-id separator"		},
{ eExpectedWord,		"expected word"				},
{ eIllegalStartOfRouteAddress,	"illegal start of route address"	},
{ eIllegalEndOfRouteAddress,	"illegal end of route address"		},
{ eIllegalSpecialInValue,	"illegal special in value"		},
{ eIllegalReferencesSeparator,	"illegal reference separator"		},
};

/* This procedure emits the error message associated with errCode */

STATIC void SslError __((ErrorCodes, struct address *));
STATIC void
SslError(errCode, ap)
	ErrorCodes errCode;
	struct address *ap;
{
	token822 *t;
	int i;

	if (errCode == eNoError)
	  abort();

	for (t = NULL, i = 0; i < (sizeof ear/sizeof ear[0]); ++i) {
	  if (ear[i].ec == errCode) {
	    t = makeToken(ear[i].msg, strlen(ear[i].msg));
	    break;
	  }
	}
	if (t == NULL)
	  t = makeToken("Unknown", sizeof("Unknown")-1);
	t->t_type = Error;
	EmitToken(t, cError, ap);

	++noErrors;

	if ((int)(errCode) >= (int)(firstFatalErrorCode)
	    || noErrors == maxErrors) {
	  aborted = 1;
	  processing = 0;
	}
}

/*
 * This procedure provides the interface to the previous pass.
 * It is reponsible for handling all input including line number
 * indicators and the values and text associated with input tokens.  
 */

STATIC void AcceptInputToken __((token822 **, struct address *));
STATIC void
AcceptInputToken(tlistp, ap)
	token822 **tlistp;
	struct address *ap;
{

	if (acceptedToken == tEndOfHeader && nextInputToken == tEndOfHeader)
	  abort();

	if (nextInputToken == tSyntaxError) {
	  acceptedToken = tSyntaxError;
	  /* ptrAcceptedToken = NULL; */
	  nextInputToken = savedInputToken;
	  goto ok;
	} else {
	  /* Accept Token */
	  acceptedToken = nextInputToken;
	  ptrAcceptedToken = ptrNextInputToken;
	}

	/* Read Next Input Token */
	do {
	next:
	  if (*tlistp == NULL) {
	    nextInputToken = tEndOfHeader;
	    ptrNextInputToken = NULL;
	  } else {
	    ptrNextInputToken = *tlistp;
	    switch ((*tlistp)->t_type) {
	    case Error:
	    case Comment:
	      if (ptrAcceptedToken == NULL && ap != NULL) {
		EmitToken(*tlistp,
			  (*tlistp)->t_type == Error ?
			  cError : cComment, ap);
	      } else {
		(*pending) = copyToken(*tlistp);
		pending = &((*pending)->t_next);
	      }
	      (*tlistp) = (*tlistp)->t_next;
	      goto next;
	    case Space:
#if 0
# if 0
	      if (RunningSslRecovery) {
		/* Copy it only during SslRecovery */
		if (ptrAcceptedToken == NULL && ap != NULL) {
		  EmitToken(*tlistp, cSpace, ap);
		} else {
		  (*pending) = copyToken(*tlistp);
		  pending = &((*pending)->t_next);
		}
	      }
# else
	      nextInputToken = tSpace;
	      (*tlistp) = (*tlistp)->t_next;
	      break;
# endif
#endif
	      /* fall through */
	    case Fold:
	      (*tlistp) = (*tlistp)->t_next;
	      goto next;
	    case Special:
	      switch ((*tlistp)->t_pname[0]) {
	      case ';':
		nextInputToken = tSemicolon;
		break;
	      case ',':
		nextInputToken = tComma;
		break;
	      case '.':
		nextInputToken = tPeriod;
		break;
	      case ':':
		if ((*tlistp)->t_pname[1] == ':')
		  nextInputToken = tDoubleColon;
		else
		  nextInputToken = tColon;
		break;
	      case '<':
		nextInputToken = tLeftAngle;
		break;
	      case '>':
		nextInputToken = tRightAngle;
		break;
	      case '@':
		nextInputToken = tAtSign;
		break;
	      default:
		nextInputToken = tOtherSpecial;
		break;
	      }
	      *tlistp = (*tlistp)->t_next;
	      break;
	    case String:
	      nextInputToken = tQuotedString;
	      *tlistp = (*tlistp)->t_next;
	      break;
	    case Atom:
	      nextInputToken = tAtom;
	      *tlistp = (*tlistp)->t_next;
	      break;
	    case DomainLiteral:
	      nextInputToken = tDomainLiteral;
	      *tlistp = (*tlistp)->t_next;
	      break;
	    case Word:
	    case Empty:
	      abort();
	    default:
	      break;
	    }
	  }
	} while (nextInputToken == tNewLine);

ok:
	/* Trace Input */
	if (tracefp)
	  printf("Input token accepted %s (%d)  Next input token %s (%d)\n",
		 Input822TokenName((int)acceptedToken), acceptedToken,
		 Input822TokenName((int)nextInputToken), nextInputToken);
}

/*
 * The constants, variables, types, modules and procedures used in
 * implementing the Semantic Mechanisms of the pass go here.  These
 * implement the facilities used in the semantic operations.
 */

/* Syntax Error Handling */

/*
 * This procedure handles syntax errors in the input to the Parser pass,
 *
 * Syntax error recovery:
 * When a mismatch occurs between the the next input token and the syntax
 * table, the following recovery is employed.
 *
 * If the expected token is tEndOfHeader then if there has been no previous
 * syntax error on the line, ignore the error.  (A missing logical end of
 * header is not a real error.)
 *
 * If the expected token is tComma or tSemicolon or tEndOfHeader and a syntax
 * error has already been detected in the current logical address (flagged
 * by nextInputToken == tSyntaxError), then flush the input and exit when
 * any of these tokens are found.
 *
 * Otherwise, if this is the first syntax error detected on the line
 * (flagged by nextInputToken != tSyntaxError), then if the input token is
 * tEndOfHeader then emit the ePrematureEndOfFile error code and terminate
 * execution.  Otherwise, emit the eSyntaxError error code and set the
 * nextInputToken to tSyntaxError to prevent further input, and exit when the
 * expected ( ?? ) input is tSemicolon or tNewLine.
 *
 * If the expected token is not tSemicolon nor tNewLine and a syntax error
 * has already been detected on the current line (flagged by nextInputToken ==
 * tSyntaxError), then do nothing and continue as if the expected token had
 * been matched.
 */

STATIC void SslSyntaxError __((token822 **, struct address *));
STATIC void
SslSyntaxError(tlistp, ap)
	token822 **tlistp;
	struct address *ap;
{
	if (operation != oInput && operation != oInputAny)
		abort();

	if (nextInputToken == tSyntaxError) {
	  /* Currently recovering from syntax error */
	  /* Complete recovery by synchronizing input to a new address */
	  nextInputToken = savedInputToken;
	  RunningSslRecovery = 1;
	  while (nextInputToken != tSemicolon
		 && nextInputToken != tComma
		 && nextInputToken != tEndOfHeader) {
	    AcceptInputToken(tlistp, ap);
	    EmitToken(ptrAcceptedToken, cResync, ap);
	  }
	  RunningSslRecovery = 0;
	  if (sslTop == 0)
	    /* Return from main S/SL procedure */
	    processing = 0;
	  else
	    sslPointer = sslStack[sslTop--];
	} else {
	  /* First syntax error on the line */
	  if (sslTable[sslPointer] == (int)(tEndOfHeader)) {
	    /* Ignore missing logical newlines */
	  } else {
	    /* mark syntax error, gobble tokens, jump to resync */
	    savedInputToken = nextInputToken;
	    nextInputToken = tSyntaxError;
	  }
	}
}

STATIC const char *
Input822TokenName(in)
	int in;
{
	switch ((InputTokens)in) {
	case tSyntaxError:	return "tSyntaxError";
	case tIdent:		return "tIdent";
	case tString:		return "tString";
	case tInteger:		return "tInteger";
	case tSemicolon:	return "tSemicolon";
	case tComma:		return "tComma";
	case tPeriod:		return "tPeriod";
	case tDoubleColon:	return "tDoubleColon";
	case tColon:		return "tColon";
	case tLeftAngle:	return "tLeftAngle";
	case tRightAngle:	return "tRightAngle";
	case tAtSign:		return "tAtSign";
	case tOtherSpecial:	return "tOtherSpecial";
	case tAtom:		return "tAtom";
	case tBy:		return "tBy";
	case tDomainLiteral:	return "tDomainLiteral";
	case tFor:		return "tFor";
	case tFrom:		return "tFrom";
	case tId:		return "tId";
	case tQuotedString:	return "tQuotedString";
	case tVia:		return "tVia";
	case tWith:		return "tWith";
	case tNewLine:		return "tNewLine";
	case tEndOfHeader:	return "tEndOfHeader";
	default: break;
	}
	return "unknown input token";
}

STATIC const char * TableOperationName __((TableOperation));
STATIC const char *
TableOperationName(op)
	TableOperation	op;
{
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
	case oSetComponentType:	return "oSetComponentType";
	case oEmitToken:	return "oEmitToken";
	case oEmitTokenCurType:	return "oEmitTokenCurType";
	case oOpenAddress:	return "oOpenAddress";
	case oAppendAddress:	return "oAppendAddress";
	case oCloseAddress:	return "oCloseAddress";
	case oDateTime:		return "oDateTime";
	case oEnterReceived:	return "oEnterReceived";
	case oExitReceived:	return "oExitReceived";
	case oSetReturnType:	return "oSetReturnType";
	case oRewind:		return "oRewind";
	default: break;
	}
	return "unknown operation";
}

STATIC void SslTrace __((void));
STATIC void
SslTrace()
{
	printf("Table index %d  Operation %d (%s) Argument %d\n",
	       sslPointer-1, operation, TableOperationName(operation),
	       sslTable[sslPointer]);
}

STATIC void SslFailure __((FailureCodes));
STATIC void
SslFailure(failCode)
	FailureCodes failCode;
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

	SslTrace();
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

STATIC void SslChoice __((int));
STATIC void
SslChoice(choiceTag)
	int choiceTag;
{
	int	numberOfChoices, choicePointer;

	choicePointer = sslTable[sslPointer];
	choiceTagMatched = 0;

	for (numberOfChoices = sslTable[choicePointer++];
	     numberOfChoices > 0;
	     choicePointer += 2, --numberOfChoices) {
	  if (tracefp)
	    printf("Matching %s (%d) with %s (%d)\n",
		   Input822TokenName(choiceTag), choiceTag,
		   Input822TokenName(sslTable[choicePointer]),
		   sslTable[choicePointer]);
	  if (sslTable[choicePointer] == choiceTag
#ifdef	ATHACK
	      || (choiceTag == (int)tAtom
		  && sslTable[choicePointer] == (int)tAtSign
		  && ptrNextInputToken != NULL
		  && ptrNextInputToken->t_len == 2
		  && (ptrNextInputToken->t_pname[0] == 'a'
		      || ptrNextInputToken->t_pname[0] == 'A')
		  && (ptrNextInputToken->t_pname[1] == 't'
		      || ptrNextInputToken->t_pname[1] == 'T')
		  && (ptrNextInputToken = &atsigntoken))
#endif	/* ATHACK */
	      ) {
	    sslPointer = sslTable[choicePointer+1];
	    choiceTagMatched = 1;
	    if (tracefp)
	      printf("Matched!\n");
	    return;
	  }
	}
	if (tracefp)
	  printf("No match!\n");
	sslPointer = choicePointer;
}

void
EmitToken(t, ac, ap)
	token822 *t;
	ComponentClass ac;
	struct address *ap;
{
	token822 *nt, **ptp;
	struct addr *na;
	AddrComponent type;

	if (deferred != NULL) {
	  if (ac == cError)  {	/* prepend errors to deferred tokens */
	    nt = copyToken(t);
	    ptp = &headDeferred;
	    for(t = headDeferred; t ; ptp = &t->t_next, t = *ptp)
	      if (t->t_type != Error)
		break;
	    nt->t_next = *ptp;
	    *ptp = nt;
	    if (deferred == &headDeferred)
	      deferred = &nt->t_next;
	  } else {
	    (*deferred) = copyToken(t);
	    deferred = &((*deferred)->t_next);
	  }
	  if (headPending) {
	    /* printf("append pending\n"); */
	    (*deferred) = headPending;
	    deferred = pending;
	    (*pending) = NULL;
	    pending = &headPending;
	    headPending = 0;
	  }
	  return;
	}
	switch (ac) {
	case cPhrase:	type = aPhrase; break;
	case cComment:	type = aComment; break;
	case cSpecial:	type = aSpecial; break;
	case cGroup:	type = aGroup; break;
	case cAddress:	type = anAddress; break;
	case cDomain:	type = aDomain; break;
	case cWord:	type = aWord; break;
#if 0
	case cSpace:	type = aSpace; break;
#endif
	case cResync:	type = reSync; ap->a_stamp = BadAddress; break;
	case cError:
	default:	type = anError; ap->a_stamp = BadAddress; break;
	}
	/*
	 * For efficiency, we just keep prepending tokens. The
	 * reverseComponent() function will eventually do the reversal.
	 */
	if (ap->a_tokens != NULL && ap->a_tokens->p_type == type) {
	  /* prepend now -- reverse later */
	  nt = copyToken(t);
	  nt->t_next = ap->a_tokens->p_tokens;
	  ap->a_tokens->p_tokens = nt;
	} else {
	  na = (struct addr *)tmalloc(sizeof (struct addr));
	  /* prepend now -- reverse later */
	  nt = copyToken(t);
	  nt->t_next = NULL;
	  na->p_tokens = nt;
	  na->p_next = ap->a_tokens;
	  na->p_type = type;
	  ap->a_tokens = na;
	}
	if (headPending) {
	  (*pending) = NULL;
	  for (t = headPending, headPending = NULL;
	       t != NULL; t = t->t_next)
	    EmitToken(t, t->t_type==Error ? cError : cComment, ap);
	  pending = &headPending;
	}
}

struct address *
revaddress(ap)
	struct address *ap;
{
	register token822	*rprev, *rnext, *r;
	register struct addr	*pprev, *pnext, *p;

	/* reverse order of address components and tokens */
	if (ap == NULL)
	  return NULL;
	/* reverse the various linked lists */
	pprev = NULL;
	for (p = ap->a_tokens; p != NULL; p = pnext) {
	  pnext = p->p_next;
	  p->p_next = pprev;
	  pprev = p;
	  rprev = NULL;
	  for (r = p->p_tokens; r != NULL; r = rnext) {
	    rnext = r->t_next;
	    r->t_next = rprev;
	    rprev = r;
	  }
	  p->p_tokens = rprev;
	}
	ap->a_tokens = pprev;
	return ap;
}

STATIC void revappend __((token822 **, struct address *));
STATIC void
revappend(tprev,ap)
token822 **tprev;
struct address *ap;
{
	struct addr *p;
	token822 *t;

	ap = revaddress(ap);
	/* append all the tokens together */
	if (ap == NULL || ap->a_tokens == NULL
	    || ap->a_stamp == BadAddress)
	  return;
	for (p = ap->a_tokens; p ; p = p->p_next) {
	  *tprev = p->p_tokens;
	  for (t = p->p_tokens; t ; t = t->t_next)
	    tprev = &(t->t_next);
	}
	*tprev = NULL;
}

/*
 * The Parser.
 *
 * entry	- where in the S/SL table to start executing.
 * tlistp	- pointer to raw token list as returned by the scanner.
 * tfp		- trace file pointer (for debugging output)
 *
 * The parser can return any of the union misc type values, however the
 * usual case is when trying to recognize an address or mailbox of some kind.
 * In this case, the parser can return a list of address structures, each
 * of which describes an address or mailbox as appropriate. This description
 * consists of a categorization of which scanner tokens correspond to which
 * RFC822 tokens. Certain non-terminals in the RFC822 grammar can correspond
 * to simple word lists, for example phrases or comments. These appear as
 * token classes (the AddrComponent enum type) alongside Atoms and Specials
 * in what the parser returns.
 */

union misc
parse822(entry, tlistp, ltmp, tfp)
	HeaderSemantics	entry;
	token822 **tlistp;
	struct tm *ltmp;
	FILE *tfp;
{
	int		inReceived, i;
	token822	*t, *torig;
	struct address	*ap, *na, *pap;
	struct received	rcvd;
	union misc	retval;
	ReturnValue	returnType;

	tracefp = tfp;
	torig = *tlistp;
	pending = &headPending;
	deferred = NULL;
	inReceived = 0;
	inAddress = 0;
	ap = NULL;
	processing = 1;
	aborted = 0;
	sslTop = 0;
	noErrors = 0;
	nextInputToken = tNewLine;
	acceptedToken = tNewLine;
	returnType = rAddress;
	currentTokenType = cAddress;

	if (tracefp) {
	  sslPointer = ((int)entry) + 1;
	  operation = (TableOperation)-1; /* Invalid value! */
	  SslTrace();
	}

	/* Initialize Input/Output */
	AcceptInputToken(tlistp, ap);
	if (nextInputToken == tEndOfHeader) {
	  retval.a = NULL;
	  return retval;
	}

	/* Walk the S/SL Table */

	sslPointer = (int)entry;
	while (processing || inAddress) {
	  if (processing)
	    operation = (TableOperation)(sslTable[sslPointer++]);
	  else
	    operation = oCloseAddress;

	  /* Trace Execution */
	  if (tracefp)
	    SslTrace();

	  switch (operation) {
	  case oCall:
	    if (sslTop < sslStackSize) {
	      sslStack[++sslTop] = sslPointer + 1;
	      sslPointer = sslTable[sslPointer];
	    } else {
	      if (ap == NULL) {
		ap = (struct address *)
		  tmalloc(sizeof (struct address));
		*ap = nullAddr;
		inAddress = 1;
	      }
	      SslError(eSslStackOverflow, ap);
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
	    SslFailure(fChoiceRuleFailed);
	    break;
	  case oJump:
	    sslPointer = sslTable[sslPointer];
	    break;
	  case oInput:
	    if (sslTable[sslPointer] == (int)(nextInputToken)
#ifdef	ATHACK
		|| (nextInputToken == tAtom
		    && sslTable[sslPointer] == (int)tAtSign
		    && ptrNextInputToken != NULL
		    && ptrNextInputToken->t_len == 2
		    && (ptrNextInputToken->t_pname[0] == 'a'
			|| ptrNextInputToken->t_pname[0] == 'A')
		    && (ptrNextInputToken->t_pname[1] == 't'
			|| ptrNextInputToken->t_pname[1] == 'T')
		    && (ptrNextInputToken = &atsigntoken))
#endif	/* ATHACK */
		) {
	      AcceptInputToken(tlistp, ap);
	      ++sslPointer;
	    } else {
	      ++sslPointer;
	      /* Syntax error in input */
	      if (ap == NULL) {
		ap = (struct address *)
		  tmalloc(sizeof (struct address));
		*ap = nullAddr;
		inAddress = 1;
	      }
	      SslSyntaxError(tlistp, ap);
	    }
	    break;
	  case oInputAny:
	    if (nextInputToken != tEndOfHeader)
	      AcceptInputToken(tlistp, ap);
	    else {
	      /* Premature end of file */
	      if (ap == NULL) {
		ap = (struct address *)
		  tmalloc(sizeof (struct address));
		*ap = nullAddr;
		inAddress = 1;
	      }
	      SslSyntaxError(tlistp, ap);
	    }
	    break;
	  case oInputChoice:
	    if (inReceived && nextInputToken == tAtom) {
	      t = ptrNextInputToken;
	      for (i = 0; rt[i].name != NULL; ++i) {
		if (TOKENLEN(t) == strlen(rt[i].name)
		    && CISTREQN(t->t_pname,
				rt[i].name, rt[i].len)) {
		  nextInputToken = rt[i].value;
		  break;
		}
	      }
	    }
	    SslChoice((int)nextInputToken);

	    if (choiceTagMatched)
	      AcceptInputToken(tlistp, ap);
	    break;
	  case oEmit:
	    ++sslPointer;
	    break;
	  case oError:
	    ++sslPointer;
	    if (ap == NULL) {
	      ap = (struct address *)
		tmalloc(sizeof (struct address));
	      *ap = nullAddr;
	      inAddress = 1;
	    }
	    SslError((ErrorCodes)sslTable[sslPointer-1], ap);
	    break;
	  case oChoice:
	    if (inReceived && resultValue == (int)tAtom) {
	      t = ptrNextInputToken;
	      for (i = 0; rt[i].name != NULL; ++i) {
		if (TOKENLEN(t) == strlen(rt[i].name)
		    && CISTREQN(t->t_pname,
				rt[i].name, rt[i].len)) {
		  resultValue = (int)rt[i].value;
		  break;
		}
	      }
	    }
	    SslChoice(resultValue);
	    break;
	  case oChoiceEnd:
	    SslFailure(fSemanticChoiceFailed);
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

	    /* The Following Are Pass Dependent Semantic Mechanisms */

	  case oSetComponentType:
	    currentTokenType = (ComponentClass)parameterValue;
	    break;
	  case oEmitTokenCurType:
	    parameterValue = (int)currentTokenType;
	    /* fall through */
	  case oEmitToken:
	    if (ap == NULL) {
	      ap = (struct address *)
		tmalloc(sizeof (struct address));
	      *ap = nullAddr;
	      inAddress = 1;
	    }
	    EmitToken(ptrAcceptedToken,
		      (ComponentClass)parameterValue, ap);
	    break;
	  case oDeferEmitToken:
	    if (deferred != NULL)
	      abort();
	    deferred = &headDeferred;
	    if (headPending) {
	      if (ap == NULL) {
		ap = (struct address *)
		  tmalloc(sizeof (struct address));
		*ap = nullAddr;
		inAddress = 1;
	      }
	      (*pending) = NULL;
	      for (t = headPending, headPending = NULL;
		   t != NULL; t = t->t_next)
		EmitToken(t, t->t_type == Error ?
			  cError : cComment, ap);
	      pending = &headPending;
	    }
	    break;
	  case oReleaseEmitToken:	/* comments... */
	    if (ap == NULL) {
	      ap = (struct address *)
		tmalloc(sizeof (struct address));
	      *ap = nullAddr;
	      inAddress = 1;
	    }
	    t = headDeferred;
	    headDeferred = NULL;
	    (*deferred) = NULL;
	    deferred = NULL;
	    for (; t != NULL; t = t->t_next)
	      if (t->t_type == Comment)
		EmitToken(t, cComment, ap);
	      else if (t->t_type == Error)
		EmitToken(t, cError, ap);
	      else
		EmitToken(t,
			  (ComponentClass)parameterValue,
			  ap);
	    break;
	  case oOpenAddress:
	    if (inAddress)
	      break;
	    na = (struct address *)tmalloc(sizeof (struct address));
	    *na = nullAddr;
	    na->a_next = ap;
	    ap = na;
	    inAddress = 1;
	    break;
	  case oAppendAddress:
	    if (inAddress)
	      break;
	    ap = revaddress(ap);
	    inAddress = 1;
	    break;
	  case oCloseAddress:
	    if (!inAddress)
	      break;
	    ap = revaddress(ap);
	    inAddress = 0;
	    break;
	  case oDateTime:
	    if (ptrNextInputToken != NULL) {
	      retval.d = dateParse(ltmp, ptrNextInputToken);
	    } else
	      retval.d = 0;
	    break;
	  case oEnterReceived:
	    inReceived = 1;
	    rcvd.r_from = rcvd.r_by = rcvd.r_id = rcvd.r_for = NULL;
	    rcvd.r_via = rcvd.r_with = rcvd.r_convert = NULL;
	    rcvd.r_time = 0L;
	    break;
	  case oExitReceived:
	    inReceived = 0;
	    break;
	  case oSaveReceivedComponent:
	    switch ((ReceivedComponent)parameterValue) {
	    case rcFrom:
	      rcvd.r_from = revaddress(ap);
	      break;
	    case rcBy:
	      rcvd.r_by = revaddress(ap);
	      break;
	    case rcVia:
	      /* grab a single token */
	      if (ap != NULL
		  && ap->a_stamp != BadAddress
		  && ap->a_tokens != NULL
		  && ap->a_tokens->p_tokens != NULL) {
		rcvd.r_via = ap->a_tokens->p_tokens;
		rcvd.r_via->t_next = NULL; /* in case */
	      }
	      break;
	    case rcWith:
	      revappend(&rcvd.r_with,ap);
	      break;
	    case rcConvert:
	      revappend(&rcvd.r_convert,ap);
	      break;
	    case rcId:
	      rcvd.r_id = revaddress(ap);
	      break;
	    case rcFor:
	      rcvd.r_for = revaddress(ap);
	      break;
	    case rcDate:
	      rcvd.r_time = retval.d;
	      break;
	    default:
	      break;
	    }
	    ap = NULL;
	    break;
	  case oSetReturnType:
	    returnType = (ReturnValue)parameterValue;
	    break;
	  case oRewind:
	    if (ap == NULL
		|| (ap->a_tokens == NULL && ap->a_next == NULL)) {
	      *tlistp = torig;
	      pending = &headPending;
	      deferred = NULL;
	      nextInputToken = tNewLine;
	      acceptedToken = tNewLine;
	      AcceptInputToken(tlistp, ap);
	      resultValue = (int)Success;
	    } else
	      resultValue = (int)Failure;
	    break;
		    
	  default:
	    printf("Unknown operation %d\n", (int)operation);
	    abort();
	  }
	}

	if (returnType == rAddress) {
	  if (nextInputToken != tEndOfHeader && !aborted && ap != NULL)
	    SslError(eExtraneousProgramText, ap);
	  /* reverse order of addresses */
	  for (na = NULL; ap != NULL; na = ap, ap = pap) {
	    pap = ap->a_next;
	    ap->a_next = na;
	  }
	  retval.a = na;
	} else if (returnType == rReceived) {
	  retval.r = (struct received *)tmalloc(sizeof (struct received));
	  *(retval.r) = rcvd;
	}
	return retval;
}
