/* Small pieces for scanning forward on a buffer of RFC-821/822 compliant
   addresses */

/* (c) Matti Aarnio 1993-1997 <mea@nic.funet.fi> */

/* All these routines scan over the lexical elements they are after, and
   if successfull, return pointer just AFTER such element.
   If they fail, they return their input -- thus no scan forward.. */

#ifndef __STDC__
#define const
#endif

#include <string.h>

const char *rfc821_error = 0;	/* Error text */
const char *rfc821_error_ptr = 0;	/* scan position of the error */

extern char *rfc821_domain();	/* Entry point */
extern char *rfc821_path();	/* Entry point */
extern char *rfc821_path2();	/* Entry point */
extern char *rfc821_adl();	/* Entry point */

static char *rfc821_localpart();	/* static forward definition */
static char *rfc821_dotnum();	/* static forward definition */

static const char *premature_end = "Premature end of input";
static const char *no_input = "No input";

/* ================================================================ */


#define CHAR_ALPHA  0x0001
#define CHAR_ALNUM  0x0002
#define CHAR_SPECL  0x0004
#define CHAR_DIGIT  0x0008
#define CHAR_C      0x0010
#define CHAR_X	    0x0020
#define CHAR_Q	    0x0040
#define CHAR_XDIGIT 0x0080
#define CHAR_822ATM 0x0100
#define CHAR_XCHAR  0x0200

#define CHR_ENT(a,b,c,d,e,f,g,h,i,j)				 \
	(a?CHAR_ALPHA:0)|(b?CHAR_ALNUM:0)|(c?CHAR_SPECL:0)|	 \
	(d?CHAR_DIGIT:0)|(e?CHAR_C:0)|(f?CHAR_X:0)|(g?CHAR_Q:0)| \
	(h?CHAR_XDIGIT:0)|(i?CHAR_822ATM:0)|(j?CHAR_XCHAR:0)

/* Could use 'unsigned short' here, but the Alpha machines dislike
   anything smaller than int (32 bit) */
static
#if defined(__alpha)||defined(__alpha__)
 int
#else
 short
#endif
 char_array[] =
{
		       /* /------------------------------ CHAR_ALPHA
			  |  /--------------------------- CHAR_ALNUM
			  |  |  /------------------------ CHAR_SPECL
			  |  |  |  /--------------------- CHAR_DIGIT
			  |  |  |  |  /------------------ CHAR_C
			  |  |  |  |  |  /--------------- CHAR_X
			  |  |  |  |  |  |  /------------ CHAR_Q
			  |  |  |  |  |  |  |  /--------- CHAR_XDIGIT
			  |  |  |  |  |  |  |  |  /------ CHAR_822ATM
			  |  |  |  |  |  |  |  |  |  /--- CHAR_XCHAR
			  |  |  |  |  |  |  |  |  |  |                  */
/*   0: `^@'   */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/*   1: `^A'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*   2: `^B'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*   3: `^C'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*   4: `^D'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*   5: `^E'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*   6: `^F'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*   7: `^G'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*   8: `^H'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*   9: `^I'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*  10: `^J'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 0, 0, 0, 0),
/*  11: `^K'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*  12: `^L'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*  13: `^M'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 0, 0, 0, 0),
/*  14: `^N'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*  15: `^O'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*  16: `^P'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*  17: `^Q'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*  18: `^R'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*  19: `^S'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*  20: `^T'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*  21: `^U'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*  22: `^V'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*  23: `^W'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*  24: `^X'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*  25: `^Y'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*  26: `^Z'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*  27: `^['   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*  28: `^\'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*  29: `^]'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*  30: `^^'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*  31: `^_'   */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 0),
/*  32: ` '    */ CHR_ENT(0, 0, 0, 0, 0, 1, 1, 0, 0, 0),
/*  33: `!'    */ CHR_ENT(0, 0, 0, 0, 0, 1, 1, 0, 1, 1),
/*  34: `"'    */ CHR_ENT(0, 0, 1, 0, 0, 1, 0, 0, 1, 1),
/*  35: `#'    */ CHR_ENT(0, 0, 0, 0, 1, 1, 1, 0, 1, 1),
/*  36: `$'    */ CHR_ENT(0, 0, 0, 0, 1, 1, 1, 0, 1, 1),
/*  37: `%'    */ CHR_ENT(0, 0, 0, 0, 0, 1, 1, 0, 1, 1),
/*  38: `&'    */ CHR_ENT(0, 0, 0, 0, 1, 1, 1, 0, 1, 1),
/*  39: `''    */ CHR_ENT(0, 0, 0, 0, 1, 1, 1, 0, 1, 1),
/*  40: `('    */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 1),
/*  41: `)'    */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 1),
/*  42: `*'    */ CHR_ENT(0, 0, 0, 0, 1, 1, 1, 0, 1, 1),
/*  43: `+'    */ CHR_ENT(0, 0, 0, 0, 1, 1, 1, 0, 1, 0),
/*  44: `,'    */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 1),
/*  45: `-'    */ CHR_ENT(0, 0, 0, 0, 1, 1, 1, 0, 1, 1),
/*  46: `.'    */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 1, 1),
/*  47: `/'    */ CHR_ENT(0, 0, 0, 0, 1, 1, 1, 0, 1, 1),
/*  48: `0'    */ CHR_ENT(0, 1, 0, 1, 1, 1, 1, 1, 1, 1),
/*  49: `1'    */ CHR_ENT(0, 1, 0, 1, 1, 1, 1, 1, 1, 1),
/*  50: `2'    */ CHR_ENT(0, 1, 0, 1, 1, 1, 1, 1, 1, 1),
/*  51: `3'    */ CHR_ENT(0, 1, 0, 1, 1, 1, 1, 1, 1, 1),
/*  52: `4'    */ CHR_ENT(0, 1, 0, 1, 1, 1, 1, 1, 1, 1),
/*  53: `5'    */ CHR_ENT(0, 1, 0, 1, 1, 1, 1, 1, 1, 1),
/*  54: `6'    */ CHR_ENT(0, 1, 0, 1, 1, 1, 1, 1, 1, 1),
/*  55: `7'    */ CHR_ENT(0, 1, 0, 1, 1, 1, 1, 1, 1, 1),
/*  56: `8'    */ CHR_ENT(0, 1, 0, 1, 1, 1, 1, 1, 1, 1),
/*  57: `9'    */ CHR_ENT(0, 1, 0, 1, 1, 1, 1, 1, 1, 1),
/*  58: `:'    */ CHR_ENT(0, 0, 0, 0, 0, 1, 1, 0, 0, 1),
/*  59: `;'    */ CHR_ENT(0, 0, 0, 0, 0, 1, 1, 0, 0, 1),
/*  60: `<'    */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 1),
/*  61: `='    */ CHR_ENT(0, 0, 0, 0, 1, 1, 1, 0, 1, 0),
/*  62: `>'    */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 1),
/*  63: `?'    */ CHR_ENT(0, 0, 0, 0, 1, 1, 1, 0, 1, 1),
/*  64: `@'    */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 1, 1),
/*  65: `A'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 1, 1, 1),
/*  66: `B'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 1, 1, 1),
/*  67: `C'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 1, 1, 1),
/*  68: `D'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 1, 1, 1),
/*  69: `E'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 1, 1, 1),
/*  70: `F'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 1, 1, 1),
/*  71: `G'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/*  72: `H'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/*  73: `I'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/*  74: `J'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/*  75: `K'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/*  76: `L'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/*  77: `M'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/*  78: `N'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/*  79: `O'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/*  80: `P'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/*  81: `Q'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/*  82: `R'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/*  83: `S'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/*  84: `T'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/*  85: `U'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/*  86: `V'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/*  87: `W'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/*  88: `X'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/*  89: `Y'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/*  90: `Z'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/*  91: `['    */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 1),
/*  92: `\'    */ CHR_ENT(0, 0, 1, 0, 0, 1, 0, 0, 0, 1),
/*  93: `]'    */ CHR_ENT(0, 0, 1, 0, 0, 1, 1, 0, 0, 1),
/*  94: `^'    */ CHR_ENT(0, 0, 0, 0, 1, 1, 1, 0, 1, 1),
/*  95: `_'    */ CHR_ENT(0, 0, 0, 0, 1, 1, 1, 0, 1, 1),
/*  96: ``'    */ CHR_ENT(0, 0, 0, 0, 1, 1, 1, 0, 1, 1),
/*  97: `a'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 1, 1, 1),
/*  98: `b'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 1, 1, 1),
/*  99: `c'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 1, 1, 1),
/* 100: `d'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 1, 1, 1),
/* 101: `e'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 1, 1, 1),
/* 102: `f'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 1, 1, 1),
/* 103: `g'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/* 104: `h'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/* 105: `i'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/* 106: `j'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/* 107: `k'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/* 108: `l'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/* 109: `m'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/* 110: `n'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/* 111: `o'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/* 112: `p'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/* 113: `q'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/* 114: `r'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/* 115: `s'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/* 116: `t'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/* 117: `u'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/* 118: `v'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/* 119: `w'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/* 120: `x'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/* 121: `y'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/* 122: `z'    */ CHR_ENT(1, 1, 0, 0, 1, 1, 1, 0, 1, 1),
/* 123: `{'    */ CHR_ENT(0, 0, 0, 0, 1, 1, 1, 0, 1, 1),
/* 124: `|'    */ CHR_ENT(0, 0, 0, 0, 1, 1, 1, 0, 1, 1),
/* 125: `}'    */ CHR_ENT(0, 0, 0, 0, 1, 1, 1, 0, 1, 1),
/* 126: `~'    */ CHR_ENT(0, 0, 0, 0, 1, 1, 1, 0, 1, 1),
/* 127: `DEL'  */ CHR_ENT(0, 0, 0, 0, 0, 1, 1, 0, 0, 0),
/* 128: `\200' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 129: `\201' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 130: `\202' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 131: `\203' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 132: `\204' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 133: `\205' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 134: `\206' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 135: `\207' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 136: `\210' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 137: `\211' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 138: `\212' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 139: `\213' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 140: `\214' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 141: `\215' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 142: `\216' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 143: `\217' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 144: `\220' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 145: `\221' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 146: `\222' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 147: `\223' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 148: `\224' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 149: `\225' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 150: `\226' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 151: `\227' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 152: `\230' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 153: `\231' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 154: `\232' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 155: `\233' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 156: `\234' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 157: `\235' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 158: `\236' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 159: `\237' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 160: `\240' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 161: `\241' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 162: `\242' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 163: `\243' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 164: `\244' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 165: `\245' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 166: `\246' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 167: `\247' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 168: `\250' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 169: `\251' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 170: `\252' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 171: `\253' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 172: `\254' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 173: `\255' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 174: `\256' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 175: `\257' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 176: `\260' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 177: `\261' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 178: `\262' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 179: `\263' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 180: `\264' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 181: `\265' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 182: `\266' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 183: `\267' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 184: `\270' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 185: `\271' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 186: `\272' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 187: `\273' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 188: `\274' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 189: `\275' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 190: `\276' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 191: `\277' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 192: `\300' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 193: `\301' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 194: `\302' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 195: `\303' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 196: `\304' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 197: `\305' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 198: `\306' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 199: `\307' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 200: `\310' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 201: `\311' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 202: `\312' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 203: `\313' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 204: `\314' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 205: `\315' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 206: `\316' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 207: `\317' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 208: `\320' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 209: `\321' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 210: `\322' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 211: `\323' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 212: `\324' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 213: `\325' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 214: `\326' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 215: `\327' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 216: `\330' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 217: `\331' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 218: `\332' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 219: `\333' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 220: `\334' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 221: `\335' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 222: `\336' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 223: `\337' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 224: `\340' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 225: `\341' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 226: `\342' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 227: `\343' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 228: `\344' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 229: `\345' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 230: `\346' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 231: `\347' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 232: `\350' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 233: `\351' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 234: `\352' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 235: `\353' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 236: `\354' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 237: `\355' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 238: `\356' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 239: `\357' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 240: `\360' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 241: `\361' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 242: `\362' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 243: `\363' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 244: `\364' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 245: `\365' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 246: `\366' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 247: `\367' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 248: `\370' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 249: `\371' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 250: `\372' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 251: `\373' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 252: `\374' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 253: `\375' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 254: `\376' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
/* 255: `\377' */ CHR_ENT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
};

#ifdef __GNUC__
#define __MY_INLINE__ static __inline__
#else
#define __MY_INLINE__ static
#endif

__MY_INLINE__ int is_821_alpha(chr)
unsigned int chr;
{
    return (char_array[chr] & CHAR_ALPHA);
}

__MY_INLINE__ int is_821_alnum(chr)
unsigned int chr;
{
    return (char_array[chr] & CHAR_ALNUM);
}

__MY_INLINE__ int is_821_specl(chr)
unsigned int chr;
{
    return (char_array[chr] & CHAR_SPECL);
}

__MY_INLINE__ int is_821_digit(chr)
unsigned int chr;
{
    return (char_array[chr] & CHAR_DIGIT);
}

__MY_INLINE__ int is_821_xdigit(chr)
unsigned int chr;
{
    return (char_array[chr] & CHAR_XDIGIT);
}

__MY_INLINE__ int is_821_C(chr)
unsigned int chr;
{
    return (char_array[chr] & CHAR_C);
}

__MY_INLINE__ int is_821_X(chr)
unsigned int chr;
{
    return (char_array[chr] & CHAR_X);
}

__MY_INLINE__ int is_821_Q(chr)
unsigned int chr;
{
    return (char_array[chr] & CHAR_Q);
}

__MY_INLINE__ int is_822_atomchar(chr)
unsigned int chr;
{
    return (char_array[chr] & CHAR_822ATM);
}

/* ================================================================ */


char *rfc822atom(str)
char *str;
{
    char *str0 = str;
    while (*str != 0) {
	if (!is_822_atomchar(*(unsigned char *) str)) {
	    if (str > str0)	/* Stop on ';', for example */
		return str;
	    goto err;
	}
	++str;
    }
    if (str == str0) {
      err:
	rfc821_error_ptr = str;
	rfc821_error = "Invalid RFC822 atom";
	return str0;
    }
    return str;
}

char *xtext_string(str)
char *str;
{
    /* Verify that the input is valid RFC 1981 XTEXT string! */
    char *str0 = str;

    while (*str) {
	unsigned char c = *str;

	if (c == ' ' || c == '\t')
	    break;

	if (char_array[c] & CHAR_XCHAR)
	    /* ('!' <= c && c <= '~' && c != '+' && c != '=') */
	    ;			/* is ok! */
	else if (c == '+') {
	    c = *++str;
	    if (!(('0' <= c && c <= '9') || ('A' <= c && c <= 'F'))) {
		goto err;
	    }
	    c = *++str;
	    if (!(('0' <= c && c <= '9') || ('A' <= c && c <= 'F'))) {
		goto err;
	    }
	} else {
	    goto err;
	}
	++str;
    }
    if (str == str0) {
      err:
	rfc821_error_ptr = str;
	rfc821_error = "Invalid character in XTEXT string";
	return str0;
    }
    return str;
}


static
char *rfc821_at_domain(s, strict)	/* "@" <domain> */
char *s;
int strict;
{
    char *p;

    if (!s || !*s)
	return s;		/* Pathological termination */

    if (*s != '@') {
	rfc821_error = "<at-domain> missing initial \"@\"";
	rfc821_error_ptr = s;
	return s;
    }
    p = rfc821_domain(s + 1, strict);
    if (!p || p == s + 1) {
	rfc821_error_ptr = s + 1;
	rfc821_error = "missing domain entry";
	return s;
    }
    return p;

}

char *rfc821_adl(s, strict)	/* <at-domain> | <at-domain> "," <a-d-l> */
char *s;
int strict;
{
    char *p = s, *q;

    if (!s || !*s)
	return s;		/* Pathological termination */
    while ((q = rfc821_at_domain(p, strict)) && (q > p)) {
	/* Scanned over an "@"+<domain> */
	p = q;
	if (*p != ',')
	    return p;
	++p;
    }
    return s;
}


static
char *rfc821_v6dotnum(s, strict)
char *s;
int strict;
{
    /* rfc821_v6dotnum() -- rather heavily mutated from BIND 4.9.4 inet_pton6()
     *                      routine by Matti Aarnio <mea@nic.funet.fi>, 1997 */
    /* int
     * inet_pton6(src, dst)
     *    convert presentation level address to network order binary form.
     * return:
     *    1 if `src' is a valid [RFC1884 2.2] address, else 0.
     * notice:
     *    (1) does not touch `dst' unless it's returning 1.
     *    (2) :: in a full address is silently ignored.
     * credit:
     *    inspired by Mark Andrews.
     * author:
     *    Paul Vixie, 1996.
     */

#ifndef IN6ADDRSZ		/* Propably these all set at the same time.. */
#define IN6ADDRSZ 16
#define INADDRSZ   4
#define INT16SZ    2
#endif

    const char *curtok;
    int ch, saw_xdigit;
    int tpcnt, colonidx;
    unsigned int val;
    char *src = s;

    tpcnt = 0;
    colonidx = -1;
    /* Leading :: requires some special handling. */
    if (*src == ':')
	if (*++src != ':') {
	    rfc821_error_ptr = s;
	    rfc821_error = "Leading double-colon must have a pair in <v6dotnum>";
	    return (s);
	}
    curtok = src;
    saw_xdigit = 0;
    val = 0;

    for ( ;((ch = *src) != '\0' && ch != ']'); ++src) {

	if (is_821_xdigit(ch)) {
	    val <<= 4;
	    if (ch >= 'a')
		ch -= ('a' - 'A');
	    if (ch >= 'A')
		ch -= ('A' + 1 - '9');
	    val |= (ch - '0');
	    if (val > 0xffff) {
		rfc821_error_ptr = src - 1;
		rfc821_error = "Too big value for <v6dotnum> element";
		return (s);
	    }
	    saw_xdigit = 1;
	    continue;
	}
	if (ch == ':') {
	    curtok = src;
	    if (!saw_xdigit) {
		if (colonidx >= 0) {
		    rfc821_error_ptr = src - 2;
		    rfc821_error = "Illegal intermediate double-colon in <v6dotnum>";
		    return (s);
		}
		colonidx = tpcnt;
		continue;
	    }
	    if (tpcnt + INT16SZ > IN6ADDRSZ) {
		rfc821_error_ptr = src - 1;
		rfc821_error = "Too many colon-separated components in <v6dotnum>";
		return (s);
	    }
	    tpcnt += 2;
	    saw_xdigit = 0;
	    val = 0;
	    continue;
	}
	if (ch == '.' && ((tpcnt + INADDRSZ) <= IN6ADDRSZ)) {
	    src = rfc821_dotnum(curtok, strict);
	    if (src == curtok) {
		/* The plain dotnum reported its own errors.. */
		return (s);
	    }
	    tpcnt += INADDRSZ;
	    saw_xdigit = 0;
	    break;		/* '\0' was seen by inet_pton4(). */
	}
	rfc821_error_ptr = src - 1;
	rfc821_error = "<v6dotnum> error ?";
	return (s);
    }
    if (saw_xdigit) {
	if (tpcnt + INT16SZ > IN6ADDRSZ) {
	    rfc821_error_ptr = src - 1;
	    rfc821_error = "Too many colon-separated components in <v6dotnum>";
	    return (s);
	}
	tpcnt += 2;
    }
    if (colonidx >= 0) {
	tpcnt = IN6ADDRSZ;
    }
    if (tpcnt != IN6ADDRSZ) {
	rfc821_error_ptr = src - 1;	/* XX: Really this diagnostics ? */
	rfc821_error = "Too few colon-separated components in <v6dotnum>";
	return (s);
    }
    return (src);
}

static
char *rfc821_dotnum(s, strict)	/* <snum> "." <snum> "." <snum> "." <snum> */
char *s;
int strict;
{
    int i, val, cnt;
    char *p = s - 1;

    if (*s == 'i' || *s == 'I') {
	/* Wow! Possibly IPv6 prefix! */
	if (strncasecmp(s, "IPv6:", 5) == 0 /* ||
	    strncasecmp(s, "IPv6.", 5) == 0  */  ) {
	    p = rfc821_v6dotnum(s + 5, strict);
	    if (p == s + 5)
		return s;
	    return p;
	} else {
	    rfc821_error_ptr = s;
	    rfc821_error = "Bad syntax of <dotnum/v6dotnum> value";
	    return s;
	}
    }
    for (i = 0; i < 4; ++i) {
	val = cnt = 0;
	++p;
	while (*p && is_821_digit(*p)) {
	    val *= 10;
	    val += (*p - '0');
	    ++cnt;
	    ++p;
	}
	if (val > 255 || cnt < 1 || cnt > 3) {
	    rfc821_error_ptr = p;
	    rfc821_error = "Bad syntax of <dotnum> value";
	    return s;
	}
	if (i < 3 && (!*p || *p != '.')) {
	    rfc821_error_ptr = p;
	    rfc821_error = "Bad syntax of <dotnum>, missing '.'";
	    return s;
	}
    }
    return p;
}

static
char *rfc821_name(s, strict, allnump)
char *s;
int strict;
int *allnump;			/* Return a flag about all-numeric field.. */
{
    char c;
    char *p = s;
    char *bad_name = "RFC821 <name> bad syntax";
    int has_alpha = 0;

    if (!s || !*s)
	return s;		/* Pathological termination */

    /* The first test should be  is_821_alpha(), as per RFC821
       we should accept only A-Z,a-Z in the begining, but
       3COM spoiled that... Grumble...                      */
    /* So now we allow chars:  0-9, A-Z, a-z, and '-'  for valid at
       the domain name segment -- but '-' is not ok at the begin.   */
    /* To note futher; the underscore is not allowed at the DNS,
       and thus it should not be allowed at email addresses either. */
    /* Our caller will do deeper analysis, wether or not ALL of the
       input was numeric:  foo@12.34.56.78   If yes, special error
       message is reported. For that purpose we count '-' as an alpha */

    c = *p;
    if (!is_821_alnum(c)) {
	rfc821_error_ptr = p;
	rfc821_error = bad_name;
	return s;		/* Don't advance, leave! */
    }
    while (is_821_alnum(c) || (c == '-')) {
	has_alpha |= (is_821_alpha(c) || c == '-');
	c = *(++p);
    }

    *allnump &= !has_alpha;

    return p;			/* Name ok, return advanced pointer */
}

char *rfc821_domain(s, strict)	/* "#" <number> | "[" <dotnum> "]" | <name> | <name> "." <domain> */
char *s;
int strict;
{
    char *p = s, *q;
    int allnum;			/* If all fields are numeric, it isn't domain.. */

    if (!s || !*s) {
	rfc821_error = "RFC821: No input";
	return s;		/* Pathological termination */
    }
    if (*p == '[') {
	q = rfc821_dotnum(p + 1, strict);
#if 0
 printf("    dotnum: p='%s', q='%s'\n",p,q); 
#endif
	if (q == p + 1)
	    return s;
	if (*q != ']') {
	    rfc821_error_ptr = q - 1;
	    rfc821_error = "RFC821 <dotnum> element missing terminating \"]\"";
	    return s;
	}
	return q + 1;
    }
    if (*p == '#') {
	/* Deprecated  "#1234234324" -format */
	++p;
	while (is_821_digit(*p))
	    ++p;
	if (p > s + 1)
	    return p;
	rfc821_error_ptr = s;
	rfc821_error = "RFC821 Domain \"#numbers\" has inadequate count of numbers";
	return s;	/* Failure, don't advance */
    }
    allnum = 1;		/* Collect info about all fields being numeric..
			   To accept  "1302.watstar.waterloo.edu" et.al.
			   but not something which looks like all numbers.. */

    if (*p == '.') {
      rfc821_error = "A domain-name does not start with a dot (.)";
      rfc821_error_ptr = p;
      return s;
    }

    q = rfc821_name(p, strict, &allnum);

    while (p && q > p && *q == '.') {
	p = q + 1;
	if (*p == 0 || *p == '>') {
	    rfc821_error = "Spurious dot (.) at the end of the domain name";
	    rfc821_error_ptr = q;
	    return s;
	}
	q = rfc821_name(p, strict, &allnum);
    }
    if (allnum) {
	rfc821_error = "Should this be of <dotnum> format ? ( [nn.nn.nn.nn] )";
	return s;
    }
    if (!rfc821_error)
	rfc821_error = "bad syntax on domain";
    if (!q || p == q)
	return s;		/* Report whatever  <name>  reports */
    return q;			/* Ok */
}

static
char *rfc821_mailbox(s, strict)	/* <local-part> "@" <domain> */
char *s;			/* Report error */
int strict;
{
    char *p = s, *q;

    if (!s || !*s) {
	/* rfc821_error_ptr = s;
	   rfc821_error = no_input; */
	return s;		/* Pathological termination */
    }
    p = rfc821_localpart(p, strict);
    if (p == s) {
	/*rfc821_error_ptr = s; */
	/*rfc821_error = "No mailbox definition"; */
	return s;
    }
    if (!strict) {
	if (*p == 0 || *p == '>')	/* If it terminates here, it is
					   only the <local-part> */
	    return p;
    }
    if (*p == ':') {
	rfc821_error_ptr = p;
	rfc821_error = "Perhaps this should have been a dot (.) instead of colon (:) ?";
	return s;
    }
    if (*p != '@') {
	rfc821_error_ptr = p;
	rfc821_error = "Missing \"@\" from mailbox definition";
	return s;
    }
    ++p;
    q = rfc821_domain(p, strict);
    if (q == p) {
	/* Error report from domain.. */
	return s;
    }
    return q;
}

static
char *rfc821_char(s)
char *s;
{
    if (!s || !*s)
	return s;
    if (*s == '\\') {
	if (!is_821_X(*(s + 1)))
	    return s;
	return s + 2;
    }
    if (is_821_C(*s))
	return s + 1;
    return s;
}

static
char *rfc821_string(s, strict)
char *s;
int strict;
{
    char *p = s, *q;

    if (!s || !*s)
	return s;
    while ((q = rfc821_char(p)) && (q > p)) {
	p = q;
    }
    if (*(unsigned char *) q > 127) {
	rfc821_error_ptr = q;
	rfc821_error = "Improper 8-bit character in string";
	return s;
    }
    if (q == s) {
	rfc821_error_ptr = s;
	rfc821_error = "Had characters unsuitable for an rfc821-string";
    }
    return q;			/* Advanced or not.. */
}

static
char *rfc821_dot_string(s, strict)
char *s;
int strict;
{
    char *p = s, *q;

    if (!s || !*s)
	return s;		/* Pathological termination */

    q = rfc821_string(p, strict);
    if (q == p)
	return s;		/* Missing string */
    while (*q == '.') {		/* Well, intermediate dot.. */
	p = q + 1;
#if 0
	if (!is_821_alnum(*p)) {
	  rfc821_error_ptr = q;
	  rfc821_error = "After a dot, something which is not alphanumeric";
	  return s;
	}
#endif
	q = rfc821_string(p, strict);
	if (q == p) {
	  if (*q == '@') {
	    rfc821_error = "Localpart must not end with unquoted dot!";
	  }
	  return s;		/* Missing string */
	}
	
    }
    return q;
}

static
char *rfc821_qtext(s, strict)
char *s;
int strict;
{
    char *p = s;
    int fail = 0;

    if (!s || !*s)
	return s;

    while (*p && !fail) {
	if (*p == '\\') {
	    ++p;
	    if (is_821_X(*p))
		++p;
	    else
		fail = 1;
	} else if (is_821_Q(*p))
	    ++p;
	else
	    break;
    }
    if ((unsigned char) *p > 127) {
	rfc821_error_ptr = p;
	rfc821_error = "Improper 8-bit character in qtext";
	return s;
    }
    if (fail || p == s) {
	rfc821_error_ptr = p;
	rfc821_error = "RFC821 qtext data failure";
	return s;
    }
    return p;
}

static
char *rfc821_quoted_string(s, strict)
char *s;
int strict;
{
    char *p = s, *q;

    if (!s || !*s)
	return s;		/* Pathological termination */
    if (*p != '"') {
	rfc821_error_ptr = p;
	rfc821_error = "Quoted string w/o initial quote (\")";
	return s;
    }
    ++p;
    q = rfc821_qtext(p, strict);
    if (p == q) {
	/* rfc821_error_ptr = q;
	   rfc821_error     = "Quoted string of 0 length :-("; */
	return s;
    }
    if (*q != '"') {
	rfc821_error_ptr = q;
	rfc821_error = "Quoted string w/o final quote (\")";
	return s;
    }
    return q + 1;
}

static
char *rfc821_localpart(s, strict)	/* <dot-string> | <quoted-string> */
char *s;			/* Stretched RFC821 a bit here.. !%-hacks */
int strict;
{
    char *p = s, *q;
    int _ok = 0;

    if (!s || !*s)
	return s;		/* Pathological termination */
    while (*p) {
	if (*p == '"') {
	    q = rfc821_quoted_string(p, strict);
	    if (q == p)
		return s;	/* Uh... */
	    if (*q == '%' || *q == '!') {
		p = q + 1;
		_ok = (*q == '!' && *p == '_');
		if (!is_821_alnum(*p) && !_ok && *p != '"') {
		  rfc821_error_ptr = q;
		  if (*q == '%') {
		    rfc821_error = "After a '%', a non alphanumeric element";
		  } else {
		    rfc821_error = "After a '!', a non alphanumeric element";
		  }
		  return s;
		}
		continue;
	    }
	    return q;
	}
	q = rfc821_dot_string(p, strict);
	if (q == p)
	    return s;		/* Uh... */
	if (*q == '%' || *q == '!') {
	    p = q + 1;
	    _ok = (*q == '!' && *p == '_');
	    if (!is_821_alnum(*p) && !_ok && *p != '"') {
	      rfc821_error_ptr = q;
	      if (*q == '%') {
		rfc821_error = "After a '%', a non alphanumeric element";
	      } else {
		rfc821_error = "After a '!', a non alphanumeric element";
	      }
	      return s;
	    }
	    continue;
	}
	return q;
    }
    return p;			/* Run to end of string.. */
}

char *rfc821_path2(s, strict)	/*  [ <a-d-l> ":" ] <mailbox>  */
char *s;
int strict;
{
    char *p = s, *q;

    if (!s || !*s) {
	rfc821_error_ptr = s;
	rfc821_error = no_input;
	return s;		/* Pathological termination */
    }
    if (*p == '@' && (q = rfc821_adl(p, strict)) && (q > p)) {
	p = q;
	if (*p == '>' || *p == ' ') {
	    rfc821_error_ptr = p;
	    rfc821_error = "No local part before leading @-character ?";
	    return s;
	}
	if (*p != ':') {
	    rfc821_error_ptr = p;
	    rfc821_error = "Missing colon (:) from <@xxx:yyy@zzz>";
	    return s;
	}
	++p;
    }
    q = rfc821_mailbox(p, strict);
    if (q == p) {
	/* Report whatever mailbox() reports as an error */
	return s;
    }
    return q;
}


char *rfc821_path(s, strict)	/*  "<" [ <a-d-l> ":" ] <mailbox> ">"  */
char *s;
int strict;
{
    char *p = s, *q;

    if (!s || !*s) {
	rfc821_error_ptr = s;
	rfc821_error = no_input;
	return s;		/* Pathological termination */
    }
    if (*p != '<') {
	rfc821_error = "Missing \"<\" from begining";
	rfc821_error_ptr = p;
	return s;
    }
    ++p;
    if (!*p) {
	rfc821_error = premature_end;
	rfc821_error_ptr = p;
	return s;
    }
    if (*p == '>') {
	return p + 1;		/* Termination ok */
    }
    q = rfc821_path2(p, strict);
    if (q == p) {
	/* Report whatever path2() reports as an error */
	return s;
    }
    if (*q == ' ' || *q == '\t') {
	/* Sometimes sending systems have:  <foo@foo   >, painfull.. */
	p = q;
	while (*p == ' ' || *p == '\t') ++p;
	/* Ok, copy down the rest of the input, and thus save the day..
	   Purist would just report an error, but lets be lenient, when
	   it is fairly easy, and painless to do.. */
	if (p > q)
	    strcpy(q, p);
    }
    if (*q != '>') {
	rfc821_error = "Missing \">\" at end";
	if (*q)
	    rfc821_error = "Extra garbage before terminating \">\"";
	rfc821_error_ptr = q;
	return s;
    }
    return q + 1;
}
