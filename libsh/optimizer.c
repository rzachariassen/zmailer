/*
 *	Copyright 1989 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 */

/*
 * This is an almost-standalone optimizer for the Shell pseudo-code.
 * It usually improves execution time and code space by 20-40%.
 */

#include "hostenv.h"
#include <stdio.h>
#include <sys/stat.h>
#include "listutils.h"
#include "sh.h"
#include "shconfig.h"
#include "libsh.h"

#ifdef DEBUG
#define ASSERT_INRANGE(val,low,high) ({if (val < low || val > high) abort();})
#else
#define ASSERT_INRANGE(val,low,high)
#endif

#define	LNEXT(x)		(*((x)+1) & 0xFF)
#define	LNEXTl(x)		 *((x)+1)
#define	NEXT(x)			(OutputTokens)LNEXT(x)
#define	LNEXTNEXT(x)		(*((x)+2) & 0xFF)
#define	LNEXTNEXTl(x)		 *((x)+2)
#define	NEXTNEXT(x)		(OutputTokens)LNEXTNEXT(x)
		/* NEXTNEXT only makes sense if nargs of NEXT(pc) is 0 */
#define	LNEXTNEXTNEXT(x)	(*((x)+3) & 0xFF)
#define	LNEXTNEXTNEXTl(x)	 *((x)+3)
#define	NEXTNEXTNEXT(x)		(OutputTokens)LNEXTNEXTNEXT(x)
		/* NEXTNEXTNEXT only makes sense if (as above) */
#define	CODE(x)			(OutputTokens)(code[(x)] & 0xFF)
#define	JUMPADDRESS(x)	((code[(x)+1] & 0xFF) << 24 | \
			 (code[(x)+2] & 0xFF) << 16 | \
			 (code[(x)+3] & 0xFF) <<  8 | \
			 (code[(x)+4] & 0xFF))

/*
 * Shell pseudo-code optimizer.
 */

void *
optimize(print, Vcode, eocodep)
	int	print;
	void	*Vcode, **eocodep;
{
	char	*code = Vcode;
	char	*arg1, *bitmap;
	char	*pc, *spc;
	char	*eocode = (char*) *eocodep;
	char	*npc, *nspc, *ncode;
	int	*addrmap;
	int	coderange = (eocode - code)+1;
	int	cmd, argi1, i, j, k, scopetop = -1, commandtop = -1, quotenext;
	short	scope[MAXNSCOPES], command[MAXNCOMMANDS];
	char	*scopeaddr[MAXNSCOPES], *commandaddr[MAXNCOMMANDS];

	quotenext = 0;
	/* The  ncode[]  array may REPLACE the  code[]  array, thus it
	   MUST be  malloc()ed buffer.. */
	ncode = (char *)malloc(coderange);
	if (ncode == NULL) {
	  fprintf(stderr, "%s: can't malloc %d bytes\n",
		  progname, (int)((char *)*eocodep - code));
	  return code;
	}
#ifdef	USE_ALLOCA
	if ((addrmap = (int *)alloca((coderange) * sizeof(int))) == NULL ||
	    (bitmap = (char *)alloca((coderange)/8+1)) == NULL) {
		fprintf(stderr, "%s: can't alloca %d bytes\n",
			progname, (int)((char *)*eocodep - code));
		return code;
	}
	memset(bitmap, 0, (coderange)/8+1);
#else /* Not  USE_ALLOCA */
	if ((addrmap = (int *)malloc((coderange) * sizeof(int))) == NULL ||
	    (bitmap = (char *)calloc((coderange)/8+1, 1)) == NULL) {
		fprintf(stderr, "%s: can't malloc %d bytes\n",
			progname, coderange);
		if (addrmap) free(addrmap);
		if (bitmap)  free(bitmap);
		/* If those previous ones succeeded, it was ncode that
		   failed.. no need to test and free it.. */
		return code;
	}
#endif

	/* shut up compilers */
	arg1 = NULL; spc = NULL; argi1 = 0;

again:
	for (pc = code, npc = ncode; pc < eocode; ++pc) {
		if ((*pc & 0xFF) >= ncommands) {
			fprintf(stderr, "%s: unknown opcode %d at %d\n",
				progname, (*pc & 0xFF), (int)(pc - code));
			fprintf(stderr, "%s: previous opcode was %d\n",
				progname, *(pc-1) & 0xFF);
			break;
		}
		cmd = (*pc) & 0xFF;
		if (print)
			printf("%d:\t%s", (int)(pc-code), TOKEN_NAME(cmd));
		spc = pc;
		switch (TOKEN_NARGS(cmd)) {
		case 1:
			arg1 = (char *)++pc;
			while (*pc != '\0')
				++pc;
			if (print)
				printf("(%s)", arg1);
			break;
		case -1:
			argi1  = (*++pc) & 0xFF;
			argi1 <<= 8;
			argi1 |= (*++pc) & 0xFF;
			argi1 <<= 8;
			argi1 |= (*++pc) & 0xFF;
			argi1 <<= 8;
			argi1 |= (*++pc) & 0xFF;
if (argi1 < 0 || argi1 > coderange-1)
printf("argi1 @%d outside coderange! %d (%d..%d)\n",
       (int)(pc-code),argi1,0,coderange-1);
			if (print)
				printf("(%d)", argi1);
			break;
		}
		nspc = npc;
ASSERT_INRANGE(spc-code,0,coderange-1);
		addrmap[spc-code] = npc-ncode;
		while (spc <= pc)
			*npc++ = *spc++;
		if (print) {
			putchar('\n');
			continue;
		}
		if (commandtop >= 0)
			++command[commandtop];
		switch ((OutputTokens)cmd) {
		case sBufferSet:
			if (quotenext == 0 && *arg1 == '\0') {
				if (NEXT(pc) == sBufferAppend) {
					npc = nspc;
					LNEXTl(pc) = sBufferSet;
				} else if (NEXT(pc) == sBufferSet) {
					npc = nspc;
				} else if ((NEXT(pc) == sDollarExpand
					    || NEXT(pc) == sBufferQuote)
					   && NEXTNEXT(pc) == sBufferAppend) {
					npc = nspc;
					LNEXTNEXTl(pc) = sBufferSet;
				} else if (NEXT(pc) == sDollarExpand
					&& NEXTNEXT(pc) == sBufferQuote
					&& NEXTNEXTNEXT(pc) == sBufferAppend) {
					npc = nspc;
					LNEXTNEXTNEXTl(pc) = sBufferSet;
				}
			} else if (NEXT(pc) == sVariablePop
				   || NEXT(pc) == sBufferSet
				   || (NEXT(pc) == sIOsetOut
				       && NEXTNEXT(pc) == sBufferSet))
				npc = nspc;
			break;
		case sBufferQuote:
			quotenext = 1;
			continue;
		case sBufferAppend:
		case sBufferExpand:
		case sBufferSetFromArgV:
		case sArgVpush:
		case sArgList:
		case sVariableCdr:
		case sVariablePush:
		case sVariablePop:
		case sVariableBuffer:
		case sVariableAppend:
		case sVariableLoopAttach:
			break;
		case sCommandPush:
			if (NEXT(pc) == sCommandPop) {
				npc = nspc;	/* skip the CommandPush */
				++pc;		/* skip the CommandPop */
			} else {
				if (commandtop >= 0)
					--command[commandtop];
				command[++commandtop] = 0;
				commandaddr[commandtop] = nspc;
			}
			break;
		case sCommandPop:
			--command[commandtop];
			if (command[commandtop] == 0) {
				/* this command push/pop pair is superfluous */
				*commandaddr[commandtop] = (u_char)sNoOp;
				npc = nspc;	/* superfluous commandPop */
			}
			--commandtop;
			break;
		case sCommandCarryBuffer:
		case sIOopen:
		case sIOopenString:
		case sIOopenPortal:
		case sIOintoBuffer:
		case sIOclose:
		case sIOdup:
			break;
		case sIOsetIn:
		case sIOsetInOut:
		case sIOsetOut:
		case sIOsetAppend:
			if (NEXT(pc) == sIOdup)
				npc = nspc;	/* skip the sIOset{In,Out} */
			break;
		case sIOsetDesc:
		case sAssign:
		case sAssignTemporary:
			break;
		case sFunction:
		case sJump:
			while (CODE(argi1) == sJump)
				argi1 = JUMPADDRESS(argi1);
			if (argi1 == pc-code+1)
				npc = nspc;	/* superfluous Jump */
			else {
				*(npc-1) =  argi1        & 0xff;
				*(npc-2) = (argi1 >>  8) & 0xff;
				*(npc-3) = (argi1 >> 16) & 0xff;
				*(npc-4) = (argi1 >> 24) & 0xff;
			}
			if (npc != nspc /* jump wasn't superfluous */
				&& NEXT(pc) == sJump) {
				/* superfluous jump because it is cascaded */
ASSERT_INRANGE(pc-code+1,0,coderange-1);
				addrmap[pc-code+1] = npc-ncode;
				pc += 5;	/* skip next Jump command */
			}
			if (npc != nspc) {
				if (argi1 < pc-code) {
ASSERT_INRANGE(argi1,0,coderange-1);
					i = addrmap[argi1];
				} else {
ASSERT_INRANGE(npc-4-ncode,0,coderange-1);
					i = -argi1, BITSET(bitmap,npc-4-ncode);
				}
				*(npc-1) =  i        & 0xff;
				*(npc-2) = (i >>  8) & 0xff;
				*(npc-3) = (i >> 16) & 0xff;
				*(npc-4) = (i >> 24) & 0xff;
			}
			break;
		case sBranchOrigin:
			fprintf(stderr, "%s: unpatched branch at %d\n",
					progname, (int)(pc-code));
			break;
		case sJumpFork:
			while (CODE(argi1) == sJump)
				argi1 = JUMPADDRESS(argi1);
			if (argi1 < pc-code) {
ASSERT_INRANGE(argi1,0,coderange-1);
				i = addrmap[argi1];
			} else {
ASSERT_INRANGE(npc-4-ncode,0,coderange-1);
				i = -argi1, BITSET(bitmap,npc-4-ncode);
			}
			*(npc-1) =  i       & 0xff;
			*(npc-2) = (i >> 8) & 0xff;
			*(npc-3) = (i >>16) & 0xff;
			*(npc-4) = (i >>24) & 0xff;
			break;
		case sJumpIfFailure:
			while (argi1 < (eocode - code)
			       && (CODE(argi1) == sJump
				   || CODE(argi1) == sJumpIfFailure)) {
				argi1 = JUMPADDRESS(argi1);
			}
			if (argi1 < pc-code) {
ASSERT_INRANGE(argi1,0,coderange-1);
				i = addrmap[argi1];
			} else {
ASSERT_INRANGE(npc-4-ncode,0,coderange-1);
				i = -argi1;
				BITSET(bitmap, npc-4-ncode);
			}
			*(npc-1) =  i        & 0xff;
			*(npc-2) = (i >>  8) & 0xff;
			*(npc-3) = (i >> 16) & 0xff;
			*(npc-4) = (i >> 24) & 0xff;
			break;
#ifdef	MAILER
		case sSiftPush:
		case sSiftBody:
		case sSiftCompileRegexp:
		case sSiftReevaluate:
		case sSiftPop:
		case sSiftBufferAppend:

		case sTSiftPush:
		case sTSiftBody:
		case sTSiftCompileRegexp:
		case sTSiftReevaluate:
		case sTSiftPop:
		/* case sTSiftBufferAppend: */
			break;
		case sJumpIfRegmatch:
		case sTJumpIfRegmatch:
#endif	/* MAILER */
		case sJumpIfSuccess:
		case sJumpIfNilVariable:
		case sJumpIfFindVarNil:
		case sJumpIfOrValueNil:
		case sJumpLoopBreak:
		case sJumpLoopContinue:
			if (argi1 < pc-code) {
ASSERT_INRANGE(argi1,0,coderange-1);
				i = addrmap[argi1];
			} else {
ASSERT_INRANGE(npc-4-ncode,0,coderange-1);
				i = -argi1, BITSET(bitmap,npc-4-ncode);
			}
			*(npc-1) =  i        & 0xff;
			*(npc-2) = (i >>  8) & 0xff;
			*(npc-3) = (i >> 16) & 0xff;
			*(npc-4) = (i >> 24) & 0xff;
			break;
		case sJumpIfMatch:
			while (CODE(argi1) == sJumpIfMatch
			       || CODE(argi1) == sJump)
				argi1 = JUMPADDRESS(argi1);
			if (argi1 < pc-code) {
ASSERT_INRANGE(argi1,0,coderange-1);
				i = addrmap[argi1];
			} else {
ASSERT_INRANGE(npc-4-ncode,0,coderange-1);
				i = -argi1, BITSET(bitmap,npc-4-ncode);
			}
			*(npc-1) =  i        & 0xff;
			*(npc-2) = (i >>  8) & 0xff;
			*(npc-3) = (i >> 16) & 0xff;
			*(npc-4) = (i >> 24) & 0xff;
			break;
		case sLocalVariable:
			--command[commandtop];
			/* FALL THROUGH */
		case sParameter:
			scope[scopetop] = 1;
			break;
		case sScopePush:
			scope[++scopetop] = 0;
			scopeaddr[scopetop] = nspc;
			if (commandtop >= 0)
				--command[commandtop];
			break;
		case sScopePop:
			if (scope[scopetop] == 0
			    /*
			     * WARNING!!! the following optimization is on
			     * the assumption that two ScopePop's in a row
			     * will only occur for local variables in a
			     * function, which is usually a benign assumption.
			     * IT MAY BECOME THE SOURCE OF STRANGE BEHAVIOUR!
			     */
			    || NEXT(pc) == sScopePop) {
				/* this scope push/pop pair is superfluous */
				*scopeaddr[scopetop] = (u_char)sNoOp;
				npc = nspc;	/* superfluous scopePop */
			}
			--scopetop;
			if (commandtop >= 0)
				--command[commandtop];
		case sDollarExpand:
		case sPrintAndExit:
		case sLoopEnter:
		case sLoopExit:
		case sBackground:
			break;
		case sNoOp:
			npc = nspc;	/* superfluous command */
			if (commandtop >= 0)
				--command[commandtop];
			break;
		default:
			break;
		}
		quotenext = 0;
	}
	if (print)
		goto done;
ASSERT_INRANGE(spc-code,0,coderange-1);
	addrmap[spc-code] = npc-ncode;	/* in case we jump to after eocode */
	for (i = 0; i <= npc-ncode; i += 8) {	/* yes, the <= is on purpose */
ASSERT_INRANGE(i,0,coderange-1);
		if (bitmap[i/8]) {
			for (j = 0; j < 8; ++j) {
				if (BITTEST(bitmap,i+j)) {
					k  = ncode[i+j  ] & 0xFF;
					k <<= 8;
					k |= ncode[i+j+1] & 0xFF;
					k <<= 8;
					k |= ncode[i+j+2] & 0xFF;
					k <<= 8;
					k |= ncode[i+j+3] & 0xFF;
ASSERT_INRANGE(-k,0,coderange-1);
					k = addrmap[-k];
					ncode[i+j  ] = (k >>24) & 0xff;
					ncode[i+j+1] = (k >>16) & 0xff;
					ncode[i+j+2] = (k >> 8) & 0xff;
					ncode[i+j+3] =  k       & 0xff;
				}
			}
			bitmap[i/8] = 0;	/* so we can reuse the bitmap */
		}
	}
	if (npc-ncode < pc-code) {
		*eocodep = eocode = ncode + (npc-ncode);
		spc = ncode;
		ncode = code;
		code = spc;
		goto again;
	}
done:
#ifndef USE_ALLOCA
	free((char *)addrmap);
	free(bitmap);
#endif
	free(ncode);
	return code;
}
