#ifndef __EC_VLONG_H
#define __EC_VLONG_H

#include <stdio.h>

#if defined( INC_ALL ) || defined( INC_CHILD )
  #include "ec_param.h"
#else
  #include "crypt/ec_param.h"
#endif /* Compiler-specific includes */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef USUAL_TYPES
#define USUAL_TYPES
	typedef unsigned char	byte;
	typedef unsigned short	word16;
#ifdef __alpha
	typedef unsigned int	word32;
#else  /* !__alpha */
	typedef unsigned long	word32;
#endif /* ?__alpha */
#endif /* ?USUAL_TYPES */

#define VL_UNITS ((GF_M + 15)/16 + 1) /* must be large enough to hold a (packed) curve point (plus one element: the length) */

typedef word16 order_t[VL_UNITS + 2];

#ifdef USE_BNLIB

#include <assert.h>
#include <stdlib.h>

#if defined( INC_ALL )
  #include "bn.h"
#elif defined( INC_CHILD )
  #include "../bnlib/bn.h"
#else
  #include "bnlib/bn.h"
#endif /* Compiler-specific includes */

typedef struct BigNum *vlPoint;

#define vlBegin(p) \
{ \
	(p) = (vlPoint) malloc (sizeof (struct BigNum)); \
	assert (p != NULL); \
	bnBegin (p); \
} /* vlBegin */

#define vlEnd(p) \
{ \
	bnEnd (p); \
	free (p); \
	p = NULL; \
} /* vlEnd */

#define vlClear			bnEnd
#define vlCopy			bnCopy
#define vlCompare		bnCmp
#define vlShortCompare	bnCmpQ
#define vlNumBits		bnBits
#define vlTakeBit		bnReadBit
#define vlLSWord		bnLSWord
#define vlAdd			bnAdd
#define vlShortAdd		bnAddQ
#define vlSub			bnSub
#define vlShortSub		bnSubQ
#define vlShortLshift	bnLShift
#define vlShortRshift	bnRShift
#define vlShortMultiply	bnMulQ

#define vlRemainder(p,q) \
{ \
	bnMod ((p), (p), (q)); \
} /* vlRemainder */

#define vlMulMod(u,v,w,m) \
{ \
	bnMul ((u), (v), (w)); \
	bnMod ((u), (u), (m)); \
} /* vlMulMod */

#define vlLoadOrder(ord,val) \
{ \
	bnInsertLittleBytes ((ord), (byte *) &(val)[1], 0, (val)[0] * sizeof (word16)); \
} /* vlLoadOrder */

#else  /* !USE_BNLIB */

typedef word16 vlPoint [VL_UNITS + 2];

#define vlBegin(p) {}

#define vlEnd(p) \
{ \
	vlClear (p); \
} /* vlEnd */

void vlClear (vlPoint p);
	/* sets p := 0, clearing entirely the content of p */

void vlCopy (vlPoint p, const vlPoint q);
	/* sets p := q */

unsigned vlExtractLittleBytes (const vlPoint k, byte a[]);
    /* dumps the contents of k into a[] in little-endian order; */
    /* evaluates to the number of bytes written to a[] */

int  vlCompare (const vlPoint p, const vlPoint q);
	/* evaluates to -1 if p < q, +1 if p > q, and 0 if p == q */

int  vlShortCompare (const vlPoint p, unsigned u);
	/* evaluates to -1 if p < (vlPoint)u, +1 if p > (vlPoint)u, and 0 if p == (vlPoint)u */

unsigned vlNumBits (const vlPoint p);
	/* evaluates to the number of bits of p (index of most significant bit, plus one) */

unsigned vlTakeBit (const vlPoint p, unsigned i);
	/* evaluates to the i-th bit of p */

unsigned vlLSWord (const vlPoint p);
	/* evaluates to the least significant 16-bit word of p */

void vlAdd (vlPoint p, const vlPoint q);
	/* sets p := p + q */

void vlShortAdd (vlPoint p, unsigned u);
	/* sets p := p + (vlPoint)u */

void vlSub (vlPoint p, const vlPoint q);
	/* sets p := p - q */

void vlShortSub (vlPoint p, unsigned u);
	/* sets p := p - (vlPoint)u */

void vlShortLshift (vlPoint p, unsigned n);
	/* sets p := p << n (n must be in range 0...16) */

void vlShortRshift (vlPoint p, unsigned n);
	/* sets p := p >> n (n must be in range 0...16) */

void vlShortMultiply (vlPoint p, const vlPoint q, unsigned d);
	/* sets p = q * d, where d is a single digit */

void vlRemainder (vlPoint p, const vlPoint m);
	/* sets p := p mod m */

void vlMulMod (vlPoint p, const vlPoint u, const vlPoint v, const vlPoint m);
	/* sets p := (u * v) mod m */

void vlLoadOrder (vlPoint ord, const order_t prime_order);

#endif /* ?USE_BNLIB */


#ifdef SELF_TESTING

void vlPrint (FILE *out, const char *tag, const vlPoint k);
	/* printf prefix tag and the contents of k to file out */

void vlRandom (vlPoint p);
	/* sets p := <random very long integer value> */

int  vlSelfTest (int test_count);
	/* executes several tests to check implementation correctness */

#endif /* ?SELF_TESTING */

#ifdef __cplusplus
};
#endif

#endif /* __EC_VLONG_H */
