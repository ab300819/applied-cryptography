#ifndef __EC_FIELD_H
#define __EC_FIELD_H

#include <stdio.h>

/* !6-bit systems need all sorts of kludges to work properly for the 
   larger field sizes, the following checks define symbols which are
   used to adjust the code on 16-bit systems */

#if ( defined( _Windows ) || defined( _WINDOWS ) ) && \
	!( defined( __WIN32__ ) || defined( WIN32 ) || defined( _WIN32 ) )
  #define __WIN16__
#endif /* Windows 3.x */

#if defined( __MSDOS__ ) && !defined( __MSDOS32__ )
  #define __MSDOS16__
#endif /* __MSDOS__ && !__MSDOS32__ */

#if defined( INC_ALL ) || defined( INC_CHILD )
  #include "ec_param.h"
  #include "ec_vlong.h"
#else
  #include "crypt/ec_param.h"
  #include "crypt/ec_vlong.h"
#endif /* Compiler-specific includes */

#ifndef USUAL_TYPES
#define USUAL_TYPES
	typedef unsigned char	byte;	/*  8 bit */
	typedef unsigned short	word16;	/* 16 bit */
#ifdef __alpha
	typedef unsigned int	word32;	/* 32 bit */
#else  /* !__alpha */
	typedef unsigned long	word32;	/* 32 bit */
#endif /* ?__alpha */
#endif /* ?USUAL_TYPES */

#define GF_POINT_UNITS	(2*(GF_K+1))

#if GF_L < 8 || GF_L > 16
	#error "this implementation assumes 8 <= GF_L <= 16"
#endif

#if GF_L ==  8
	#define BITS_PER_LUNIT 8
	typedef byte	lunit;
#else
	#define BITS_PER_LUNIT 16
	typedef word16	lunit;
#endif

#if GF_L == 16
	typedef word32	ltemp;
#else
	typedef word16	ltemp;
#endif

typedef lunit gfPoint [GF_POINT_UNITS];

/* interface functions: */

int  gfInit (void);
	/* initialize the library ---> MUST be called before any other gf-function */

void gfQuit (void);
	/* perform housekeeping for library termination */

int  gfEqual (const gfPoint p, const gfPoint q);
	/* evaluates to 1 if p == q, otherwise 0 (or an error code) */

void gfClear (gfPoint p);
	/* sets p := 0, clearing entirely the content of p */

void gfCopy (gfPoint p, const gfPoint q);
	/* sets p := q */

void gfAdd (gfPoint p, const gfPoint q, const gfPoint r);
	/* sets p := q + r */

void gfMultiply (gfPoint r, const gfPoint p, const gfPoint q);
	/* sets r := p * q mod (x^GF_K + x^GF_T + 1) */

void gfSmallDiv (gfPoint p, lunit b);
	/* sets p := (b^(-1))*p mod (x^GF_K + x^GF_T + 1) for b != 0 (of course...) */

void gfSquare (gfPoint p, const gfPoint q);
	/* sets p := q^2 mod (x^GF_K + x^GF_T + 1) */

int  gfInvert (gfPoint p, const gfPoint q);
	/* sets p := q^(-1) mod (x^GF_K + x^GF_T + 1) */
	/* warning: p and q must not overlap! */

void gfSquareRoot (gfPoint p, lunit b);
	/* sets p := sqrt(b) = b^(2^(GF_M-1)) */

int  gfTrace (const gfPoint p);
	/* quickly evaluates to the trace of p (or an error code) */

int  gfQuadSolve (gfPoint p, const gfPoint q);
	/* sets p to a solution of p^2 + p = q */

unsigned gfYbit (const gfPoint p);
	/* evaluates to the rightmost (least significant) bit of p (or an error code) */

void gfPack (const gfPoint p, vlPoint k);
	/* packs a field point into a vlPoint */

void gfUnpack (gfPoint p, const vlPoint k);
	/* unpacks a vlPoint into a field point */

#ifdef SELF_TESTING

void gfPrint (FILE *out, const char *tag, const gfPoint p);
	/* printf prefix tag and the contents of p to file out */

void gfRandom (gfPoint p);
	/* sets p := <random field element> */

int  gfSlowTrace (const gfPoint p);
	/* slowly evaluates to the trace of p */

int  gfSelfTest (int test_count);
	/* perform test_count self tests */

#endif /* ?SELF_TESTING */

#endif /* __EC_FIELD_H */

