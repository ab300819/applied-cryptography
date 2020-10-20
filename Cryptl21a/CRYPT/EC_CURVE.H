#ifndef __EC_CURVE_H
#define __EC_CURVE_H

#include <stddef.h>

#if defined( INC_ALL ) || defined( INC_CHILD )
  #include "ec_field.h"
  #include "ec_vlong.h"
#else
  #include "crypt/ec_field.h"
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

typedef struct {
	gfPoint x, y;
} ecPoint;


void ecCopy (ecPoint *p, const ecPoint *q);
	/* sets p := q */

int  ecCalcY (ecPoint *p, unsigned ybit);
	/* given the x coordinate of p and a suitable bit ybit of the corresponding */
	/* y coordinate, evaluate the full y value such that y^2 + x*y = x^3 + EC_B */
	/* returning 1 if successful and 0 if there is no solution */

void ecAdd (ecPoint *p, const ecPoint *r);
	/* sets p := p + r */

void ecSub (ecPoint *p, const ecPoint *r);
	/* sets p := p - r */

void ecDouble (ecPoint *p);
	/* sets p := 2*p */

void ecMultiply (ecPoint *p, const vlPoint k);
	/* sets p := k*p */

unsigned ecYbit (const ecPoint *p);
	/* evaluates to 0 if p->x == 0, otherwise to gfYbit (p->y / p->x) */

void ecPack (const ecPoint *p, vlPoint k);
	/* packs a curve point into a vlPoint */

void ecUnpack (ecPoint *p, const vlPoint k);
	/* unpacks a vlPoint into a curve point */

#ifdef SELF_TESTING

void ecPrint (FILE *out, const char *tag, const ecPoint *p);
	/* printf prefix tag and the contents of p to file out */

int  ecCheck (const ecPoint *p);
	/* confirm that y^2 + x*y = x^3 + EC_B for point p */

int  ecEqual (const ecPoint *p, const ecPoint *q);
	/* evaluates to 1 if p == q, otherwise 0 (or an error code) */

void ecRandom (ecPoint *p);
	/* sets p to a random point of the elliptic curve defined by y^2 + x*y = x^3 + EC_B */

void ecClear (ecPoint *p);
	/* sets p to the point at infinity O, clearing entirely the content of p */

void ecNegate (ecPoint *p);
	/* sets p := -p */

int  ecSelfTest (int test_count);
	/* perform test_count self tests */

#endif /* ?SELF_TESTING */

#endif /* __EC_CURVE_H */
