/* MD5C.C - RSA Data Security, Inc., MD5 message-digest algorithm
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

/*
** The following macro re-definitions added to work around a problem on
** Solaris where the original MD5 routines are already in /lib/libnsl.a.
** This causes dynamic linking of the module to fail.
**
** Thanks to Ken Pizzini (ken@spry.com) for finally nailing this one!
*/

#ifdef solaris
#define MD5Init		MD5Init_perl
#define MD5Update	MD5Update_perl
#define MD5Final	MD5Final_perl
#endif

#include "md5-global.h"
#include "md5.h"

/* Constants for MD5Transform routine.
 */

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

static void MD5Transform PROTO_LIST ((UINT4 [4], unsigned char [64]));
static void Encode PROTO_LIST
  ((unsigned char *, UINT4 *, unsigned long));
static void Decode PROTO_LIST
  ((UINT4 *, unsigned char *, unsigned long));
static void MD5_memcpy PROTO_LIST ((POINTER, POINTER, unsigned long));
static void MD5_memset PROTO_LIST ((POINTER, int, unsigned long));

static unsigned char PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) TO32((((x) & (y)) | ((~x) & (z))))
#define G(x, y, z) TO32((((x) & (z)) | ((y) & (~z))))
#define H(x, y, z) TO32(((x) ^ (y) ^ (z)))
#define I(x, y, z) TO32(((y) ^ ((x) | (~z))))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) TO32((((x) << (n)) | (TO32((x)) >> (32-(n)))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
Rotation is separate from addition to prevent recomputation.
 */
#ifdef __GNUC__
extern __inline__ UINT4 FF(register UINT4 a, register UINT4 b, register UINT4 c, register UINT4 d, register UINT4 x, register UINT4 s, register UINT4 ac)
{
  a += F (b,c,d) + x + ac;
  a = ROTATE_LEFT(a,s);
  a += b;
  return a;
}

extern __inline__ UINT4 GG(register UINT4 a, register UINT4 b, register UINT4 c, register UINT4 d, register UINT4 x, register UINT4 s, register UINT4 ac)
{
  a += G (b,c,d) + x + ac;
  a = ROTATE_LEFT(a,s);
  a += b;
  return a;
}

extern __inline__ UINT4 HH(register UINT4 a, register UINT4 b, register UINT4 c, register UINT4 d, register UINT4 x, register UINT4 s, register UINT4 ac)
{
  a += H (b, c, d) + x + ac;
  a = ROTATE_LEFT (a, s);
  a += b;
  return a;
}

extern __inline__ UINT4 II(register UINT4 a, register UINT4 b, register UINT4 c, register UINT4 d, register UINT4 x, register UINT4 s, register UINT4 ac)
{
  a += I (b, c, d) + x + ac;
  a = ROTATE_LEFT (a, s);
  a += b;
  return a;
}

#else
#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
 TO32((a)); \
  }
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
 TO32((a)); \
  }
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
 TO32((a)); \
  }
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
 TO32((a)); \
  }
#endif

/* MD5 initialization. Begins an MD5 operation, writing a new context.
 */
void MD5Init (context)
MD5_CTX *context;                                        /* context */
{
  context->count[0] = context->count[1] = 0;
  /* Load magic initialization constants.
*/
  context->state[0] = 0x67452301U;
  context->state[1] = 0xefcdab89U;
  context->state[2] = 0x98badcfeU;
  context->state[3] = 0x10325476U;
}

/* MD5 block update operation. Continues an MD5 message-digest
  operation, processing another message block, and updating the
  context.
 */
void MD5Update (context, input, inputLen)
MD5_CTX *context;                                        /* context */
const unsigned char *input;                          /* input block */
const unsigned int inputLen;               /* length of input block */
{
  unsigned long i, index, partLen;

  /* Compute number of bytes mod 64 */
  index = (unsigned long)((context->count[0] >> 3) & 0x3F);

  /* Update number of bits */
  if (TO32(context->count[0] += (inputLen << 3))
      < TO32(inputLen << 3))
    context->count[1]++;
  context->count[1] += (inputLen >> 29);

  partLen = 64 - index;

  /* Transform as many times as possible. */

  if (inputLen >= partLen) {
    MD5_memcpy
      ((POINTER)&context->buffer[index], (POINTER)input, partLen);
    MD5Transform (context->state, context->buffer);

    for (i = partLen; i + 63 < inputLen; i += 64)
      MD5Transform (context->state, &input[i]);

    index = 0;
  }
  else
    i = 0;

  /* Buffer remaining input */
  MD5_memcpy((POINTER)&context->buffer[index],
	     (POINTER)&input[i],
	     inputLen-i);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
  the message digest and zeroizing the context.
 */
void MD5Final (digest, context)
unsigned char digest[16];                         /* message digest */
MD5_CTX *context;                                       /* context */
{
  unsigned char bits[8];
  unsigned long index, padLen;

  /* Save number of bits */
  Encode (bits, context->count, 8);

  /* Pad out to 56 mod 64. */

  index = (unsigned long)((context->count[0] >> 3) & 0x3f);
  padLen = (index < 56) ? (56 - index) : (120 - index);
  MD5Update (context, PADDING, padLen);

  /* Append length (before padding) */
  MD5Update (context, bits, 8);

  /* Store state in digest */
  Encode (digest, context->state, 16);

  /* Zeroize sensitive information. */
  MD5_memset ((POINTER)context, 0, sizeof (*context));
}

/* MD5 basic transformation. Transforms state based on block.
 */
static void MD5Transform (state, block)
UINT4 state[4];
unsigned char block[64];
{
  UINT4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];

  Decode (x, block, 64);

  /* Round 1 */
  a = FF (a, b, c, d, x[ 0], S11, 0xd76aa478U); /* 1 */
  d = FF (d, a, b, c, x[ 1], S12, 0xe8c7b756U); /* 2 */
  c = FF (c, d, a, b, x[ 2], S13, 0x242070dbU); /* 3 */
  b = FF (b, c, d, a, x[ 3], S14, 0xc1bdceeeU); /* 4 */
  a = FF (a, b, c, d, x[ 4], S11, 0xf57c0fafU); /* 5 */
  d = FF (d, a, b, c, x[ 5], S12, 0x4787c62aU); /* 6 */
  c = FF (c, d, a, b, x[ 6], S13, 0xa8304613U); /* 7 */
  b = FF (b, c, d, a, x[ 7], S14, 0xfd469501U); /* 8 */
  a = FF (a, b, c, d, x[ 8], S11, 0x698098d8U); /* 9 */
  d = FF (d, a, b, c, x[ 9], S12, 0x8b44f7afU); /* 10 */
  c = FF (c, d, a, b, x[10], S13, 0xffff5bb1U); /* 11 */
  b = FF (b, c, d, a, x[11], S14, 0x895cd7beU); /* 12 */
  a = FF (a, b, c, d, x[12], S11, 0x6b901122U); /* 13 */
  d = FF (d, a, b, c, x[13], S12, 0xfd987193U); /* 14 */
  c = FF (c, d, a, b, x[14], S13, 0xa679438eU); /* 15 */
  b = FF (b, c, d, a, x[15], S14, 0x49b40821U); /* 16 */

 /* Round 2 */
  a = GG (a, b, c, d, x[ 1], S21, 0xf61e2562U); /* 17 */
  d = GG (d, a, b, c, x[ 6], S22, 0xc040b340U); /* 18 */
  c = GG (c, d, a, b, x[11], S23, 0x265e5a51U); /* 19 */
  b = GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aaU); /* 20 */
  a = GG (a, b, c, d, x[ 5], S21, 0xd62f105dU); /* 21 */
  d = GG (d, a, b, c, x[10], S22,  0x2441453U); /* 22 */
  c = GG (c, d, a, b, x[15], S23, 0xd8a1e681U); /* 23 */
  b = GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8U); /* 24 */
  a = GG (a, b, c, d, x[ 9], S21, 0x21e1cde6U); /* 25 */
  d = GG (d, a, b, c, x[14], S22, 0xc33707d6U); /* 26 */
  c = GG (c, d, a, b, x[ 3], S23, 0xf4d50d87U); /* 27 */
  b = GG (b, c, d, a, x[ 8], S24, 0x455a14edU); /* 28 */
  a = GG (a, b, c, d, x[13], S21, 0xa9e3e905U); /* 29 */
  d = GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8U); /* 30 */
  c = GG (c, d, a, b, x[ 7], S23, 0x676f02d9U); /* 31 */
  b = GG (b, c, d, a, x[12], S24, 0x8d2a4c8aU); /* 32 */

  /* Round 3 */
  a = HH (a, b, c, d, x[ 5], S31, 0xfffa3942U); /* 33 */
  d = HH (d, a, b, c, x[ 8], S32, 0x8771f681U); /* 34 */
  c = HH (c, d, a, b, x[11], S33, 0x6d9d6122U); /* 35 */
  b = HH (b, c, d, a, x[14], S34, 0xfde5380cU); /* 36 */
  a = HH (a, b, c, d, x[ 1], S31, 0xa4beea44U); /* 37 */
  d = HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9U); /* 38 */
  c = HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60U); /* 39 */
  b = HH (b, c, d, a, x[10], S34, 0xbebfbc70U); /* 40 */
  a = HH (a, b, c, d, x[13], S31, 0x289b7ec6U); /* 41 */
  d = HH (d, a, b, c, x[ 0], S32, 0xeaa127faU); /* 42 */
  c = HH (c, d, a, b, x[ 3], S33, 0xd4ef3085U); /* 43 */
  b = HH (b, c, d, a, x[ 6], S34,  0x4881d05U); /* 44 */
  a = HH (a, b, c, d, x[ 9], S31, 0xd9d4d039U); /* 45 */
  d = HH (d, a, b, c, x[12], S32, 0xe6db99e5U); /* 46 */
  c = HH (c, d, a, b, x[15], S33, 0x1fa27cf8U); /* 47 */
  b = HH (b, c, d, a, x[ 2], S34, 0xc4ac5665U); /* 48 */

  /* Round 4 */
  a = II (a, b, c, d, x[ 0], S41, 0xf4292244U); /* 49 */
  d = II (d, a, b, c, x[ 7], S42, 0x432aff97U); /* 50 */
  c = II (c, d, a, b, x[14], S43, 0xab9423a7U); /* 51 */
  b = II (b, c, d, a, x[ 5], S44, 0xfc93a039U); /* 52 */
  a = II (a, b, c, d, x[12], S41, 0x655b59c3U); /* 53 */
  d = II (d, a, b, c, x[ 3], S42, 0x8f0ccc92U); /* 54 */
  c = II (c, d, a, b, x[10], S43, 0xffeff47dU); /* 55 */
  b = II (b, c, d, a, x[ 1], S44, 0x85845dd1U); /* 56 */
  a = II (a, b, c, d, x[ 8], S41, 0x6fa87e4fU); /* 57 */
  d = II (d, a, b, c, x[15], S42, 0xfe2ce6e0U); /* 58 */
  c = II (c, d, a, b, x[ 6], S43, 0xa3014314U); /* 59 */
  b = II (b, c, d, a, x[13], S44, 0x4e0811a1U); /* 60 */
  a = II (a, b, c, d, x[ 4], S41, 0xf7537e82U); /* 61 */
  d = II (d, a, b, c, x[11], S42, 0xbd3af235U); /* 62 */
  c = II (c, d, a, b, x[ 2], S43, 0x2ad7d2bbU); /* 63 */
  b = II (b, c, d, a, x[ 9], S44, 0xeb86d391U); /* 64 */

  state[0] += a; TO32(state[0]);
  state[1] += b; TO32(state[1]);
  state[2] += c; TO32(state[2]);
  state[3] += d; TO32(state[3]);

  /* Zeroize sensitive information.
   */
  MD5_memset ((POINTER)x, 0, sizeof (x));
}

/* Encodes input (UINT4) into output (unsigned char). Assumes len is
  a multiple of 4.
 */
static void Encode (output, input, len)
unsigned char *output;
UINT4 *input;
unsigned long len;
{
  unsigned long i, j;

  for (i = 0, j = 0; j < len; i++, j += 4) {
 output[j] = (unsigned char)(input[i] & 0xff);
 output[j+1] = (unsigned char)((input[i] >> 8) & 0xff);
 output[j+2] = (unsigned char)((input[i] >> 16) & 0xff);
 output[j+3] = (unsigned char)((input[i] >> 24) & 0xff);
  }
}

/* Decodes input (unsigned char) into output (UINT4). Assumes len is
  a multiple of 4.
 */
static void Decode (output, input, len)
UINT4 *output;
unsigned char *input;
unsigned long len;
{
  unsigned long i, j;

  for (i = 0, j = 0; j < len; i++, j += 4)
 output[i] = ((UINT4)input[j]) | (((UINT4)input[j+1]) << 8) |
   (((UINT4)input[j+2]) << 16) | (((UINT4)input[j+3]) << 24);
}

/* Note: Replace "for loop" with standard memcpy if possible.
 */

static void MD5_memcpy (output, input, len)
POINTER output;
POINTER input;
unsigned long len;
{
  unsigned long i;

  for (i = 0; i < len; i++)
 output[i] = input[i];
}

/* Note: Replace "for loop" with standard memset if possible.
 */
static void MD5_memset (output, value, len)
POINTER output;
int value;
unsigned long len;
{
  unsigned long i;

  for (i = 0; i < len; i++)
 ((char *)output)[i] = (char)value;
}
