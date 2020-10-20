#ifndef __EC_CRYPT_H
#define __EC_CRYPT_H

#if defined( INC_ALL ) || defined( INC_CHILD )
  #include "ec_curve.h"
  #include "ec_vlong.h"
#else
  #include "crypt/ec_curve.h"
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
	vlPoint r, s;
} cpPair;


void cpPairBegin (cpPair *pair);
void cpPairEnd (cpPair *pair);
void cpMakePublicKey (vlPoint vlPublicKey, const vlPoint vlPrivateKey);
void cpEncodeSecret (const vlPoint vlPublicKey, vlPoint vlMessage, vlPoint vlSecret);
void cpDecodeSecret (const vlPoint vlPrivateKey, const vlPoint vlMessage, vlPoint d);
void cpSign (const vlPoint vlPrivateKey, const vlPoint vlSecret, const vlPoint vlMac, cpPair *cpSig);
int  cpVerify (const vlPoint vlPublicKey, const vlPoint vlMac, cpPair *cpSig);

#endif /* __EC_CRYPT_H */
