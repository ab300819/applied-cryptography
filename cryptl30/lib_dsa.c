/****************************************************************************
*																			*
*						cryptlib DSA Encryption Routines					*
*						Copyright Peter Gutmann 1995-1998					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#include "cryptctx.h"

/* Prototypes for functions in asn1keys.c */

int encodeDLValues( BYTE *buffer, BIGNUM *value1, BIGNUM *value2 );
int decodeDLValues( BYTE *buffer, BIGNUM **value1, BIGNUM **value2 );

/****************************************************************************
*																			*
*						Predefined DSA p, q, and g Parameters				*
*																			*
****************************************************************************/

/* We never use shared DSA parameters because they allow forgery of
   signatures on certificates.  This works as follows: Suppose that the
   certificate contains a copy of the certificate signers DSA parameters, and
   the verifier of the certificate has a copy of the signers public key but
   not the signers DSA parameters (which are shared with other keys).  If the
   verifier uses the DSA parameters from the certificate along with the
   signers public key to verify the signature on the certificate, then an
   attacker can create bogus certificates by choosing a random u and finding
   its inverse v modulo q (uv is congruent to 1 modulo q).  Then take the
   certificate signer's public key g^x and compute g' = (g^x)^u.  Then
   g'^v = g^x.  Using the DSA parameters p, q, g', the signers public key
   corresponds to the private key v, which the attacker knows.  The attacker
   can then create a bogus certificate, puts parameters (p, q, g') in it, and
   signs it with the DSA private key v to create an apparently valid
   certificate.  This works with the DSA OID which makes p, q, and g
   unauthenticated public parameters and y the public key, but not the one
   which makes p, q, g, and y the public key */

#if 0

/* DSA public values, generated by Colin Plumb for PGP 5.  These values were
   chosen as representative well-known public values to allay fears of
   possible trapdoors in self-generated values.  Note that the p values are
   identical to the DH primes except for the last ~160 bits (see the code
   used to generate them for the details).  Also, once we move p over 1024
   bits we need to correspondingly increase q above 160 bits to provide
   protection from small-exponent attacks (a 4096-bit p isn't any good if q
   remains at 160 bits) */

static const BYTE prime1024p[] = {
	0xF4, 0x88, 0xFD, 0x58, 0x4E, 0x49, 0xDB, 0xCD,
	0x20, 0xB4, 0x9D, 0xE4, 0x91, 0x07, 0x36, 0x6B,
	0x33, 0x6C, 0x38, 0x0D, 0x45, 0x1D, 0x0F, 0x7C,
	0x88, 0xB3, 0x1C, 0x7C, 0x5B, 0x2D, 0x8E, 0xF6,
	0xF3, 0xC9, 0x23, 0xC0, 0x43, 0xF0, 0xA5, 0x5B,
	0x18, 0x8D, 0x8E, 0xBB, 0x55, 0x8C, 0xB8, 0x5D,
	0x38, 0xD3, 0x34, 0xFD, 0x7C, 0x17, 0x57, 0x43,
	0xA3, 0x1D, 0x18, 0x6C, 0xDE, 0x33, 0x21, 0x2C,
	0xB5, 0x2A, 0xFF, 0x3C, 0xE1, 0xB1, 0x29, 0x40,
	0x18, 0x11, 0x8D, 0x7C, 0x84, 0xA7, 0x0A, 0x72,
	0xD6, 0x86, 0xC4, 0x03, 0x19, 0xC8, 0x07, 0x29,
	0x7A, 0xCA, 0x95, 0x0C, 0xD9, 0x96, 0x9F, 0xAB,
	0xD0, 0x0A, 0x50, 0x9B, 0x02, 0x46, 0xD3, 0x08,
	0x3D, 0x66, 0xA4, 0xB0, 0xB6, 0x51, 0xE2, 0xBA,
	0xE5, 0x4E, 0x44, 0x39, 0x7C, 0x9F, 0x2A, 0x5E,
	0x31, 0x2F, 0xF6, 0xDB, 0x5C, 0x75, 0xAE, 0x81
	};
static const BYTE prime1024q[] = {
	0xFF, 0x9F, 0x9C, 0x7C, 0xBD, 0x89, 0x4B, 0x22,
	0x19, 0x26, 0xBA, 0xAB, 0xA2, 0x5E, 0xC3, 0x55,
	0xE9, 0x27, 0xC2, 0xB1
	};

static const BYTE prime1536p[] = {
	0xF8, 0xF5, 0x59, 0x5F, 0xDC, 0x76, 0x52, 0x4F,
	0x3D, 0x3D, 0x8D, 0xDB, 0xCE, 0x99, 0xE1, 0x57,
	0x92, 0x59, 0xCD, 0xFD, 0xB8, 0xAE, 0x74, 0x4F,
	0xC5, 0xFC, 0x76, 0xBC, 0x83, 0xC5, 0x47, 0x30,
	0x61, 0xCE, 0x7C, 0xC9, 0x66, 0xFF, 0x15, 0xF9,
	0xBB, 0xFD, 0x91, 0x5E, 0xC7, 0x01, 0xAA, 0xD3,
	0x5B, 0x9E, 0x8D, 0xA0, 0xA5, 0x72, 0x3A, 0xD4,
	0x1A, 0xF0, 0xBF, 0x46, 0x00, 0x58, 0x2B, 0xE5,
	0xF4, 0x88, 0xFD, 0x58, 0x4E, 0x49, 0xDB, 0xCD,
	0x20, 0xB4, 0x9D, 0xE4, 0x91, 0x07, 0x36, 0x6B,
	0x33, 0x6C, 0x38, 0x0D, 0x45, 0x1D, 0x0F, 0x7C,
	0x88, 0xB3, 0x1C, 0x7C, 0x5B, 0x2D, 0x8E, 0xF6,
	0xF3, 0xC9, 0x23, 0xC0, 0x43, 0xF0, 0xA5, 0x5B,
	0x18, 0x8D, 0x8E, 0xBB, 0x55, 0x8C, 0xB8, 0x5D,
	0x38, 0xD3, 0x34, 0xFD, 0x7C, 0x17, 0x57, 0x43,
	0xA3, 0x1D, 0x18, 0x6C, 0xDE, 0x33, 0x21, 0x2C,
	0xB5, 0x2A, 0xFF, 0x3C, 0xE1, 0xB1, 0x29, 0x40,
	0x18, 0x11, 0x8D, 0x7C,	0x84, 0xA7, 0x0A, 0x72,
	0xD6, 0x86, 0xC4, 0x03, 0x19, 0xC8, 0x07, 0x29,
	0x7A, 0xCA, 0x95, 0x0C, 0xD9, 0x96, 0x9F, 0xAB,
	0xD0, 0x0A, 0x50, 0x9B, 0x02, 0x47, 0x2C, 0xCB,
	0xA6, 0x82, 0xA5, 0xEB, 0xA2, 0x84, 0x3E, 0xE3,
	0x3D, 0x56, 0xE7, 0xA9, 0xF3, 0xE1, 0xC4, 0x3D,
	0x22, 0x98, 0x80, 0xF3, 0xC3, 0x08, 0x49, 0x8F
	};
static const BYTE prime1536q[] = {
	0x3F, 0xFD, 0x66, 0xA4, 0x5D, 0x41, 0x9F, 0x9C,
	0x7C, 0xBD, 0x89, 0x4B, 0x22, 0x19, 0x26, 0xBA,
	0xAB, 0xA2, 0x5E, 0xC3, 0x55, 0xE9, 0x27, 0xC2,
	0x43
	};

static const BYTE prime2048p[] = {
	0xF6, 0x42, 0x57, 0xB7, 0x08, 0x7F, 0x08, 0x17,
	0x72, 0xA2, 0xBA, 0xD6, 0xA9, 0x42, 0xF3, 0x05,
	0xE8, 0xF9, 0x53, 0x11, 0x39, 0x4F, 0xB6, 0xF1,
	0x6E, 0xB9, 0x4B, 0x38, 0x20, 0xDA, 0x01, 0xA7,
	0x56, 0xA3, 0x14, 0xE9, 0x8F, 0x40, 0x55, 0xF3,
	0xD0, 0x07, 0xC6, 0xCB, 0x43, 0xA9, 0x94, 0xAD,
	0xF7, 0x4C, 0x64, 0x86, 0x49, 0xF8, 0x0C, 0x83,
	0xBD, 0x65, 0xE9, 0x17, 0xD4, 0xA1, 0xD3, 0x50,
	0xF8, 0xF5, 0x59, 0x5F, 0xDC, 0x76, 0x52, 0x4F,
	0x3D, 0x3D, 0x8D, 0xDB, 0xCE, 0x99, 0xE1, 0x57,
	0x92, 0x59, 0xCD, 0xFD, 0xB8, 0xAE, 0x74, 0x4F,
	0xC5, 0xFC, 0x76, 0xBC, 0x83, 0xC5, 0x47, 0x30,
	0x61, 0xCE, 0x7C, 0xC9, 0x66, 0xFF, 0x15, 0xF9,
	0xBB, 0xFD, 0x91, 0x5E, 0xC7, 0x01, 0xAA, 0xD3,
	0x5B, 0x9E, 0x8D, 0xA0, 0xA5, 0x72, 0x3A, 0xD4,
	0x1A, 0xF0, 0xBF, 0x46, 0x00, 0x58, 0x2B, 0xE5,
	0xF4, 0x88, 0xFD, 0x58, 0x4E, 0x49, 0xDB, 0xCD,
	0x20, 0xB4, 0x9D, 0xE4, 0x91, 0x07, 0x36, 0x6B,
	0x33, 0x6C, 0x38, 0x0D, 0x45, 0x1D, 0x0F, 0x7C,
	0x88, 0xB3, 0x1C, 0x7C, 0x5B, 0x2D, 0x8E, 0xF6,
	0xF3, 0xC9, 0x23, 0xC0, 0x43, 0xF0, 0xA5, 0x5B,
	0x18, 0x8D, 0x8E, 0xBB, 0x55, 0x8C, 0xB8, 0x5D,
	0x38, 0xD3, 0x34, 0xFD, 0x7C, 0x17, 0x57, 0x43,
	0xA3, 0x1D, 0x18, 0x6C, 0xDE, 0x33, 0x21, 0x2C,
	0xB5, 0x2A, 0xFF, 0x3C, 0xE1, 0xB1, 0x29, 0x40,
	0x18, 0x11, 0x8D, 0x7C, 0x84, 0xA7, 0x0A, 0x72,
	0xD6, 0x86, 0xC4, 0x03, 0x19, 0xC8, 0x07, 0x29,
	0x7A, 0xCA, 0x95, 0x0C, 0xD9, 0x96, 0x9F, 0xAB,
	0xD0, 0x0A, 0x51, 0xB8, 0x4F, 0xCF, 0x7E, 0xC9,
	0x6A, 0x96, 0xFA, 0x9E, 0x4E, 0xDC, 0x9F, 0x93,
	0x37, 0x21, 0x13, 0x1D, 0xE3, 0xDD, 0x3D, 0xE0,
	0x7D, 0x1D, 0x6B, 0xCE, 0x09, 0x83, 0x11, 0xB5
	};
static const BYTE prime2048q[] = {
	0x01, 0xFE, 0x46, 0xD3, 0x08, 0x3D, 0x66, 0xA4,
	0x5D, 0x41, 0x9F, 0x9C, 0x7C, 0xBD, 0x89, 0x4B,
	0x22, 0x19, 0x26, 0xBA, 0xAB, 0xA2, 0x5E, 0xC3,
	0x55, 0xE9, 0x27, 0xC2, 0xCF
	};

static const BYTE prime3072p[] = {
	0xCC, 0x1D, 0x77, 0x57, 0x24, 0x38, 0x4A, 0xE2,
	0xC4, 0xF0, 0xE8, 0x8E, 0x13, 0x67, 0x97, 0x4E,
	0x92, 0x13, 0x61, 0xF6, 0xDB, 0xEB, 0x25, 0x0E,
	0x17, 0xFD, 0xF6, 0x98, 0xF7, 0xC8, 0x7C, 0x79,
	0xB0, 0x72, 0x1D, 0x38, 0x75, 0xFB, 0xF6, 0xC1,
	0x73, 0xC4, 0x83, 0x11, 0x26, 0x2B, 0x43, 0x60,
	0xC3, 0xE3, 0xE8, 0xD6, 0x0A, 0xFD, 0xA1, 0x28,
	0x26, 0x0B, 0xAE, 0xA9, 0xAE, 0xB3, 0x65, 0x0F,
	0xA2, 0x00, 0x53, 0x01, 0xA0, 0x7C, 0xD6, 0xAB,
	0xA3, 0x12, 0x1E, 0xFA, 0x0F, 0x2A, 0xCE, 0x1F,
	0x74, 0x84, 0x4F, 0xCA, 0xF3, 0x17, 0xF3, 0xA4,
	0x40, 0xE9, 0xD7, 0xD2, 0x77, 0xB6, 0x42, 0x2D,
	0x02, 0x36, 0xC1, 0x26, 0xCB, 0x68, 0x5E, 0x9D,
	0x7C, 0x98, 0x09, 0x0A, 0x8D, 0x7E, 0x2D, 0xED,
	0xE4, 0x5D, 0x79, 0xF5, 0xD4, 0x92, 0x4F, 0x9B,
	0x18, 0x8E, 0xFC, 0x2A, 0xA7, 0x4B, 0x7C, 0x32,
	0xF6, 0x42, 0x57, 0xB7, 0x08, 0x7F, 0x08, 0x17,
	0x72, 0xA2, 0xBA, 0xD6, 0xA9, 0x42, 0xF3, 0x05,
	0xE8, 0xF9, 0x53, 0x11, 0x39, 0x4F, 0xB6, 0xF1,
	0x6E, 0xB9, 0x4B, 0x38, 0x20, 0xDA, 0x01, 0xA7,
	0x56, 0xA3, 0x14, 0xE9, 0x8F, 0x40, 0x55, 0xF3,
	0xD0, 0x07, 0xC6, 0xCB, 0x43, 0xA9, 0x94, 0xAD,
	0xF7, 0x4C, 0x64, 0x86, 0x49, 0xF8, 0x0C, 0x83,
	0xBD, 0x65, 0xE9, 0x17, 0xD4, 0xA1, 0xD3, 0x50,
	0xF8, 0xF5, 0x59, 0x5F, 0xDC, 0x76, 0x52, 0x4F,
	0x3D, 0x3D, 0x8D, 0xDB, 0xCE, 0x99, 0xE1, 0x57,
	0x92, 0x59, 0xCD, 0xFD, 0xB8, 0xAE, 0x74, 0x4F,
	0xC5, 0xFC, 0x76, 0xBC, 0x83, 0xC5, 0x47, 0x30,
	0x61, 0xCE, 0x7C, 0xC9, 0x66, 0xFF, 0x15, 0xF9,
	0xBB, 0xFD, 0x91, 0x5E, 0xC7, 0x01, 0xAA, 0xD3,
	0x5B, 0x9E, 0x8D, 0xA0, 0xA5, 0x72, 0x3A, 0xD4,
	0x1A, 0xF0, 0xBF, 0x46, 0x00, 0x58, 0x2B, 0xE5,
	0xF4, 0x88, 0xFD, 0x58, 0x4E, 0x49, 0xDB, 0xCD,
	0x20, 0xB4, 0x9D, 0xE4, 0x91, 0x07, 0x36, 0x6B,
	0x33, 0x6C, 0x38, 0x0D, 0x45, 0x1D, 0x0F, 0x7C,
	0x88, 0xB3, 0x1C, 0x7C, 0x5B, 0x2D, 0x8E, 0xF6,
	0xF3, 0xC9, 0x23, 0xC0, 0x43, 0xF0, 0xA5, 0x5B,
	0x18, 0x8D, 0x8E, 0xBB,	0x55, 0x8C, 0xB8, 0x5D,
	0x38, 0xD3, 0x34, 0xFD, 0x7C, 0x17, 0x57, 0x43,
	0xA3, 0x1D, 0x18, 0x6C, 0xDE, 0x33, 0x21, 0x2C,
	0xB5, 0x2A, 0xFF, 0x3C, 0xE1, 0xB1, 0x29, 0x40,
	0x18, 0x11, 0x8D, 0x7C, 0x84, 0xA7, 0x0A, 0x72,
	0xD6, 0x86, 0xC4, 0x03, 0x19, 0xC8, 0x07, 0x29,
	0x7A, 0xCA, 0x95, 0x0C, 0xDB, 0x13, 0xD8, 0xA2,
	0x1A, 0x8F, 0x32, 0x6B, 0x11, 0xEB, 0xA3, 0xF2,
	0x71, 0x5E, 0xF5, 0xC5, 0x43, 0x6D, 0x84, 0x4B,
	0xF6, 0xFE, 0x52, 0xB9, 0x60, 0x5A, 0x8E, 0x09,
	0xCE, 0xCB, 0xFE, 0x94, 0xBC, 0xEF, 0x23, 0x5B
	};
static const BYTE prime3072q[] = {
	0x3F, 0xEB, 0xD0, 0x0A, 0x50, 0x9B, 0x02, 0x46,
	0xD3, 0x08, 0x3D, 0x66, 0xA4, 0x5D, 0x41, 0x9F,
	0x9C, 0x7C, 0xBD, 0x89, 0x4B, 0x22, 0x19, 0x26,
	0xBA, 0xAB, 0xA2, 0x5E, 0xC3, 0x55, 0xE9, 0x27,
	0xC3, 0x1D
	};

static const BYTE prime4096p[] = {
	0xF9, 0x18, 0xA0, 0x7E, 0x5A, 0x06, 0x61, 0x7A,
	0x43, 0x90, 0x95, 0xDC, 0x05, 0x6C, 0x87, 0x86,
	0xEC, 0x61, 0xEC, 0xCD, 0x45, 0x1F, 0x0E, 0xD8,
	0xE0, 0xA3, 0x79, 0xC6, 0xC9, 0xDC, 0x7A, 0x0B,
	0xAC, 0xE4, 0x3F, 0xE3, 0x46, 0x94, 0xB6, 0x30,
	0x4A, 0x53, 0xD7, 0x7C, 0x02, 0x16, 0x48, 0x80,
	0xB5, 0x15, 0xE5, 0x29, 0x99, 0xA9, 0x9F, 0x07,
	0x74, 0xD3, 0xFF, 0xE3, 0xA1, 0xC5, 0x96, 0x20,
	0x4E, 0x98, 0x65, 0xB8, 0xD8, 0x0D, 0xEE, 0x10,
	0x5D, 0xAB, 0xB6, 0x17, 0x1C, 0x51, 0xD8, 0x50,
	0xCA, 0x22, 0x57, 0x43, 0x29, 0xBE, 0x95, 0xE8,
	0x56, 0x2B, 0x38, 0x78, 0x5C, 0x0B, 0xDB, 0xF8,
	0x4C, 0x4D, 0xD5, 0xE3, 0xAA, 0x46, 0xCC, 0xFB,
	0xCE, 0x17, 0xE8, 0x2A, 0x9D, 0x14, 0x61, 0xE3,
	0x84, 0xA9, 0x4F, 0xD1, 0x83, 0x84, 0xA8, 0x79,
	0xB6, 0xEF, 0x8F, 0xA7, 0x43, 0x46, 0x08, 0xC6,
	0xCC, 0x1D, 0x77, 0x57, 0x24, 0x38, 0x4A, 0xE2,
	0xC4, 0xF0, 0xE8, 0x8E, 0x13, 0x67, 0x97, 0x4E,
	0x92, 0x13, 0x61, 0xF6, 0xDB, 0xEB, 0x25, 0x0E,
	0x17, 0xFD, 0xF6, 0x98, 0xF7, 0xC8, 0x7C, 0x79,
	0xB0, 0x72, 0x1D, 0x38, 0x75, 0xFB, 0xF6, 0xC1,
	0x73, 0xC4, 0x83, 0x11, 0x26, 0x2B, 0x43, 0x60,
	0xC3, 0xE3, 0xE8, 0xD6, 0x0A, 0xFD, 0xA1, 0x28,
	0x26, 0x0B, 0xAE, 0xA9, 0xAE, 0xB3, 0x65, 0x0F,
	0xA2, 0x00, 0x53, 0x01, 0xA0, 0x7C, 0xD6, 0xAB,
	0xA3, 0x12, 0x1E, 0xFA, 0x0F, 0x2A, 0xCE, 0x1F,
	0x74, 0x84, 0x4F, 0xCA, 0xF3, 0x17, 0xF3, 0xA4,
	0x40, 0xE9, 0xD7, 0xD2, 0x77, 0xB6, 0x42, 0x2D,
	0x02, 0x36, 0xC1, 0x26, 0xCB, 0x68, 0x5E, 0x9D,
	0x7C, 0x98, 0x09, 0x0A, 0x8D, 0x7E, 0x2D, 0xED,
	0xE4, 0x5D, 0x79, 0xF5, 0xD4, 0x92, 0x4F, 0x9B,
	0x18, 0x8E, 0xFC, 0x2A, 0xA7, 0x4B, 0x7C, 0x32,
	0xF6, 0x42, 0x57, 0xB7, 0x08, 0x7F, 0x08, 0x17,
	0x72, 0xA2, 0xBA, 0xD6, 0xA9, 0x42, 0xF3, 0x05,
	0xE8, 0xF9, 0x53, 0x11, 0x39, 0x4F, 0xB6, 0xF1,
	0x6E, 0xB9, 0x4B, 0x38, 0x20, 0xDA, 0x01, 0xA7,
	0x56, 0xA3, 0x14, 0xE9, 0x8F, 0x40, 0x55, 0xF3,
	0xD0, 0x07, 0xC6, 0xCB, 0x43, 0xA9, 0x94, 0xAD,
	0xF7, 0x4C, 0x64, 0x86, 0x49, 0xF8, 0x0C, 0x83,
	0xBD, 0x65, 0xE9, 0x17, 0xD4, 0xA1, 0xD3, 0x50,
	0xF8, 0xF5, 0x59, 0x5F, 0xDC, 0x76, 0x52, 0x4F,
	0x3D, 0x3D, 0x8D, 0xDB, 0xCE, 0x99, 0xE1, 0x57,
	0x92, 0x59, 0xCD, 0xFD, 0xB8, 0xAE, 0x74, 0x4F,
	0xC5, 0xFC, 0x76, 0xBC, 0x83, 0xC5, 0x47, 0x30,
	0x61, 0xCE, 0x7C, 0xC9, 0x66, 0xFF, 0x15, 0xF9,
	0xBB, 0xFD, 0x91, 0x5E, 0xC7, 0x01, 0xAA, 0xD3,
	0x5B, 0x9E, 0x8D, 0xA0, 0xA5, 0x72, 0x3A, 0xD4,
	0x1A, 0xF0, 0xBF, 0x46, 0x00, 0x58, 0x2B, 0xE5,
	0xF4, 0x88, 0xFD, 0x58, 0x4E, 0x49, 0xDB, 0xCD,
	0x20, 0xB4, 0x9D, 0xE4, 0x91, 0x07, 0x36, 0x6B,
	0x33, 0x6C, 0x38, 0x0D, 0x45, 0x1D, 0x0F, 0x7C,
	0x88, 0xB3, 0x1C, 0x7C, 0x5B, 0x2D, 0x8E, 0xF6,
	0xF3, 0xC9, 0x23, 0xC0, 0x43, 0xF0, 0xA5, 0x5B,
	0x18, 0x8D, 0x8E, 0xBB, 0x55, 0x8C, 0xB8, 0x5D,
	0x38, 0xD3, 0x34, 0xFD, 0x7C, 0x17, 0x57, 0x43,
	0xA3, 0x1D, 0x18, 0x6C, 0xDE, 0x33, 0x21, 0x2C,
	0xB5, 0x2A, 0xFF, 0x3C, 0xE1, 0xB1, 0x29, 0x40,
	0x18, 0x11, 0x8D, 0x7C, 0x84, 0xA7, 0x0A, 0x72,
	0xD6, 0x86, 0xC4, 0x03, 0x19, 0xC8, 0x07, 0x29,
	0x88, 0x50, 0x05, 0x4B, 0xFE, 0x24, 0x36, 0x96,
	0x47, 0xAB, 0x40, 0x4A, 0xA2, 0xE5, 0xB3, 0xCB,
	0x0E, 0x0F, 0x2A, 0x1C, 0x45, 0x17, 0x3D, 0xD9,
	0x5D, 0xED, 0x9F, 0x0D, 0x33, 0xDA, 0x04, 0xC9,
	0x19, 0xA9, 0x9D, 0x3F, 0x40, 0xF3, 0xF4, 0x2D
	};
static const BYTE prime4096q[] = {
	0x01, 0xFF, 0x0C, 0xD9, 0x96, 0x9F, 0xAB, 0xD0,
	0x0A, 0x50, 0x9B, 0x02, 0x46, 0xD3, 0x08, 0x3D,
	0x66, 0xA4, 0x5D, 0x41, 0x9F, 0x9C, 0x7C, 0xBD,
	0x89, 0x4B, 0x22, 0x19, 0x26, 0xBA, 0xAB, 0xA2,
	0x5E, 0xC3, 0x55, 0xE9, 0x27, 0xC2, 0x65
	};

/* The structure for storing the DSA public values */

typedef struct {
	const int baseLen; const BYTE base[ 1 ];
	const int primePLen; const BYTE *primeP;
	const int primeQLen; const BYTE *primeQ;
	} DSA_PUBLIC_VALUES;

static const DSA_PUBLIC_VALUES dsaPublicValues[] = {
	{ 1, { 0x02 }, 1024, prime1024p, 160, prime1024q },
	{ 1, { 0x02 }, 1536, prime1536p, 200, prime1536q },
	{ 1, { 0x02 }, 2048, prime2048p, 232, prime2048q },
	{ 1, { 0x02 }, 3072, prime3072p, 272, prime3072q },
	{ 1, { 0x02 }, 4096, prime4096p, 312, prime4096q },
	{ 0, { 0 }, 0, NULL }
	};
#endif /* 0 */

/****************************************************************************
*																			*
*							DSA Self-test Routines							*
*																			*
****************************************************************************/

/* Test the DSA implementation using the sample key and hash from FIPS 186.
   Because a lot of the high-level encryption routines don't exist yet, we
   cheat a bit and set up a dummy encryption context with just enough
   information for the following code to work */

typedef struct {
	int pLen; BYTE p[ 64 ];
	int qLen; BYTE q[ 20 ];
	int gLen; BYTE g[ 64 ];
	int xLen; BYTE x[ 20 ];
	int yLen; BYTE y[ 64 ];
	} DLP_PRIVKEY;

static const DLP_PRIVKEY dlpTestKey = {
	/* p */
	512,
	{ 0x8D, 0xF2, 0xA4, 0x94, 0x49, 0x22, 0x76, 0xAA,
	  0x3D, 0x25, 0x75, 0x9B, 0xB0, 0x68, 0x69, 0xCB,
	  0xEA, 0xC0, 0xD8, 0x3A, 0xFB, 0x8D, 0x0C, 0xF7,
	  0xCB, 0xB8, 0x32, 0x4F, 0x0D, 0x78, 0x82, 0xE5,
	  0xD0, 0x76, 0x2F, 0xC5, 0xB7, 0x21, 0x0E, 0xAF,
	  0xC2, 0xE9, 0xAD, 0xAC, 0x32, 0xAB, 0x7A, 0xAC,
	  0x49, 0x69, 0x3D, 0xFB, 0xF8, 0x37, 0x24, 0xC2,
	  0xEC, 0x07, 0x36, 0xEE, 0x31, 0xC8, 0x02, 0x91 },
	/* q */
	160,
	{ 0xC7, 0x73, 0x21, 0x8C, 0x73, 0x7E, 0xC8, 0xEE,
	  0x99, 0x3B, 0x4F, 0x2D, 0xED, 0x30, 0xF4, 0x8E,
	  0xDA, 0xCE, 0x91, 0x5F },
	/* g */
	512,
	{ 0x62, 0x6D, 0x02, 0x78, 0x39, 0xEA, 0x0A, 0x13,
	  0x41, 0x31, 0x63, 0xA5, 0x5B, 0x4C, 0xB5, 0x00,
	  0x29, 0x9D, 0x55, 0x22, 0x95, 0x6C, 0xEF, 0xCB,
	  0x3B, 0xFF, 0x10, 0xF3, 0x99, 0xCE, 0x2C, 0x2E,
	  0x71, 0xCB, 0x9D, 0xE5, 0xFA, 0x24, 0xBA, 0xBF,
	  0x58, 0xE5, 0xB7, 0x95, 0x21, 0x92, 0x5C, 0x9C,
	  0xC4, 0x2E, 0x9F, 0x6F, 0x46, 0x4B, 0x08, 0x8C,
	  0xC5, 0x72, 0xAF, 0x53, 0xE6, 0xD7, 0x88, 0x02 },
	/* y */
	160,
	{ 0x20, 0x70, 0xB3, 0x22, 0x3D, 0xBA, 0x37, 0x2F,
	  0xDE, 0x1C, 0x0F, 0xFC, 0x7B, 0x2E, 0x3B, 0x49,
	  0x8B, 0x26, 0x06, 0x14 },
	/* x */
	512,
	{ 0x19, 0x13, 0x18, 0x71, 0xD7, 0x5B, 0x16, 0x12,
	  0xA8, 0x19, 0xF2, 0x9D, 0x78, 0xD1, 0xB0, 0xD7,
	  0x34, 0x6F, 0x7A, 0xA7, 0x7B, 0xB6, 0x2A, 0x85,
	  0x9B, 0xFD, 0x6C, 0x56, 0x75, 0xDA, 0x9D, 0x21,
	  0x2D, 0x3A, 0x36, 0xEF, 0x16, 0x72, 0xEF, 0x66,
	  0x0B, 0x8C, 0x7C, 0x25, 0x5C, 0xC0, 0xEC, 0x74,
	  0x85, 0x8F, 0xBA, 0x33, 0xF4, 0x4C, 0x06, 0x69,
	  0x96, 0x30, 0xA7, 0x6B, 0x03, 0x0E, 0xE3, 0x33 }
	};

static const BYTE shaM[] = {
	0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A,
	0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C,
	0x9C, 0xD0, 0xD8, 0x9D
	};

/* If we're doing a self-test using the FIPS 186 values we use the following
   fixed k data rather than a randomly-generated value */

static const BYTE kVal[] = {
	0x35, 0x8D, 0xAD, 0x57, 0x14, 0x62, 0x71, 0x0F,
	0x50, 0xE2, 0x54, 0xCF, 0x1A, 0x37, 0x6B, 0x2B,
	0xDE, 0xAA, 0xDF, 0xBF
	};

int dsaInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int dsaSign( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes );
int dsaSigCheck( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes );

int dsaSelfTest( void )
	{
	CRYPT_INFO cryptInfo;
	CRYPT_PKCINFO_DLP *dsaKey;
	static const CAPABILITY_INFO capabilityInfo = { CRYPT_ALGO_DSA, 0, NULL, 
													64, 128, 512, 0 };
	BYTE buffer[ 128 ];
	int status;

	/* Set up the key components */
	if( ( dsaKey = ( CRYPT_PKCINFO_DLP * ) malloc( sizeof( CRYPT_PKCINFO_DLP ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	cryptInitComponents( dsaKey, CRYPT_KEYTYPE_PRIVATE );
	cryptSetComponent( dsaKey->p, dlpTestKey.p, dlpTestKey.pLen );
	cryptSetComponent( dsaKey->q, dlpTestKey.q, dlpTestKey.qLen );
	cryptSetComponent( dsaKey->g, dlpTestKey.g, dlpTestKey.gLen );
	cryptSetComponent( dsaKey->y, dlpTestKey.y, dlpTestKey.yLen );
	cryptSetComponent( dsaKey->x, dlpTestKey.x, dlpTestKey.xLen );

	/* Initialise the BigNum information and components */
	memset( &cryptInfo, 0, sizeof( CRYPT_INFO ) );
	cryptInfo.ctxPKC.param1 = BN_new();
	cryptInfo.ctxPKC.param2 = BN_new();
	cryptInfo.ctxPKC.param3 = BN_new();
	cryptInfo.ctxPKC.param4 = BN_new();
	cryptInfo.ctxPKC.param5 = BN_new();
	cryptInfo.capabilityInfo = &capabilityInfo;

	/* Perform the test en/decryption (actualy a sig generation/check) of a
	   block of data */
	memcpy( buffer, shaM, 20 );
	dsaInitKey( &cryptInfo, dsaKey, CRYPT_UNUSED );
	status = dsaSign( &cryptInfo, buffer, -1 );
	if( !cryptStatusError( status ) )
		{
		memmove( buffer + 20, buffer, status );
		memcpy( buffer, shaM, 20 );
		status = dsaSigCheck( &cryptInfo, buffer, 20 + status );
		}
	if( cryptStatusError( status ) )
		status = CRYPT_ERROR;

	/* Clean up */
	cryptDestroyComponents( dsaKey );
	BN_clear_free( cryptInfo.ctxPKC.param1 );
	BN_clear_free( cryptInfo.ctxPKC.param2 );
	BN_clear_free( cryptInfo.ctxPKC.param3 );
	BN_clear_free( cryptInfo.ctxPKC.param4 );
	BN_clear_free( cryptInfo.ctxPKC.param5 );
	zeroise( &cryptInfo, sizeof( CRYPT_INFO ) );
	free( dsaKey );

	return( status );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* Not needed for the DSA routines */

/****************************************************************************
*																			*
*							DSA En/Decryption Routines						*
*																			*
****************************************************************************/

/* Since DSA signature generation produces two values and the cryptEncrypt()
   model only provides for passing a byte string in and out (or, more
   specifically, the internal bignum data can't be exported to the outside
   world), we need to encode the resulting data into a flat format.  This is
   done by encoding the output as an X9.31 Dss-Sig record:

	Dss-Sig ::= SEQUENCE {
		r	INTEGER,
		s	INTEGER
		}

   The input is the 160-bit hash, usually SHA but possibly also RIPEMD-160.

   Signature checking is even uglier, since we need to pass in the hash as
   well as the composite signature (in effect we need to do what
   cryptCheckSignature() does).  We do this by appending the 160-bit hash to
   the composite signature when we call cryptDecrypt() */

/* The size of each DSA signature component - 160 bits */

#define DSA_SIGPART_SIZE	20

/* Sign a single block of data  */

int dsaSign( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BN_CTX *bnCTX;
	BIGNUM *p = cryptInfo->ctxPKC.dlpParam_p;
	BIGNUM *q = cryptInfo->ctxPKC.dlpParam_q;
	BIGNUM *g = cryptInfo->ctxPKC.dlpParam_g;
	BIGNUM *x = cryptInfo->ctxPKC.dlpParam_x;
	BIGNUM *hash, *k, *r, *s, *kInv;
	int length, status = CRYPT_OK;

	assert( noBytes == DSA_SIGPART_SIZE || noBytes == -1 );

	if( ( bnCTX = BN_CTX_new() ) == NULL )
		return( CRYPT_ERROR_MEMORY );

	/* Generate the secret random value k.  During the initial self-test
	   the random data pool may not exist yet, and may in fact never exist in
	   a satisfactory condition if there isn't enough randomness present in
	   the system to generate cryptographically strong random numbers.  To
	   bypass this problem, if the caller passes in a noBytes value which
	   can't be passed in via a call to cryptEncrypt() we know it's an
	   internal self-test call and use a fixed bit pattern for k which avoids
	   having to call generateBignum() (this also means we can use the FIPS
	   186 self-test value for k).  This is a somewhat ugly use of 'magic
	   numbers', but it's safe because cryptEncrypt() won't allow any such
	   value for noBytes so there's no way an external caller can pass in a 
	   value like this */
	k = BN_new();
	if( noBytes == -1 )
		BN_bin2bn( ( BYTE * ) kVal, DSA_SIGPART_SIZE, k );
	else
		{
		status = generateBignum( k, bytesToBits( DSA_SIGPART_SIZE ), 0x80, 0 );
		if( cryptStatusError( status ) )
			{
			BN_clear_free( k );
			BN_CTX_free( bnCTX );
			return( status );
			}
		}
	BN_mod( k, k, q, bnCTX );	/* Reduce k to the correct range */

	/* Initialise the bignums */
	hash = BN_new();
	r = BN_new();
	s = BN_new();

	/* Move the data from the buffer into a bignum */
	BN_bin2bn( buffer, DSA_SIGPART_SIZE, hash );

	/* r = ( g ^ k mod p ) mod q */
	BN_mod_exp( r, g, k, p, bnCTX );
	BN_mod( r, r, q, bnCTX );

	/* s = k^-1 * ( hash + x * r ) mod q */
	kInv = BN_mod_inverse( k, q, bnCTX );	/* temp = k^-1 mod q */
/*	BN_mul( s, x, r );					// s = x * r */
	BN_mod_mul( s, x, r, q, bnCTX );	/* s = ( x * r ) mod q */
	BN_add( s, s, hash );				/* s = s + hash */
	if( BN_cmp( s, q ) > 0 )			/* if s > q */
		BN_sub( s, s, q );				/*   s = s - q (fast mod) */
	BN_mod_mul( s, s, kInv, q, bnCTX );	/* s = k^-1 * ( hash + x * r ) mod q */

	/* Encode the result as a DL data block */
	length = encodeDLValues( buffer, r, s );

	/* Destroy sensitive data */
	BN_clear_free( kInv );
	BN_clear_free( s );
	BN_clear_free( r );
	BN_clear_free( k );
	BN_clear_free( hash );

	BN_CTX_free( bnCTX );

	return( ( status == -1 ) ? CRYPT_ERROR_FAILED : length );
	}

/* Signature check a single block of data */

int dsaSigCheck( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BN_CTX *bnCTX;
	BIGNUM *p = cryptInfo->ctxPKC.dlpParam_p;
	BIGNUM *q = cryptInfo->ctxPKC.dlpParam_q;
	BIGNUM *g = cryptInfo->ctxPKC.dlpParam_g;
	BIGNUM *y = cryptInfo->ctxPKC.dlpParam_y;
	BIGNUM *r, *s;
	int status;

	UNUSED( noBytes );

	if( ( bnCTX = BN_CTX_new() ) == NULL )
		return( CRYPT_ERROR_MEMORY );

	/* Decode the values from a DL data block and make sure r and s are
	   valid */
	status = decodeDLValues( buffer + DSA_SIGPART_SIZE, &r, &s );
	if( cryptStatusError( status ) )
		{
		BN_CTX_free( bnCTX );
		return( status );
		}
	if( BN_cmp( r, q ) >= 0 || BN_cmp( s, q ) >= 0 )
		status = CRYPT_ERROR_BADDATA;
	else
		{
		BIGNUM *u1, *v;

		u1 = BN_new();

		BN_bin2bn( buffer, DSA_SIGPART_SIZE, u1 );

#if 0
		v = BN_new();

		/* w = s^-1 mod q */
		s = BN_mod_inverse( s, q, bnCTX );	/* w = s^-1 mod q */

		/* u1 = ( hash * w ) mod q */
		BN_mod_mul( u1, u1, s, q, bnCTX );	/* u1 = ( hash * w ) mod q */

		/* u2 = ( r * w ) mod q */
		BN_mod_mul( s, r, s, q, bnCTX );	/* u2 = ( r * w ) mod q */

		/* v = ( ( ( g^u1 ) * ( y^u2 ) ) mod p ) mod q.  We need to use
		   an extra temp variable here because BN_mod_exp() params 1 and
		   3 must differ, and BN_mod() params 1 and 2 must differ */
		BN_mod_exp( v, g, u1, p, bnCTX );	/* u1' = ( g ^ u1 ) mod p */
		BN_mod_exp( u1, y, s, p, bnCTX );	/* u2' = ( y ^ u2 ) mod p */
		BN_mod_mul( v, v, u1, p, bnCTX );	/* v = ( u1' * u2' ) mod p */
		BN_mod( s, v, q, bnCTX );			/* v = v mod q */

		/* if r == v signature is good */
		if( BN_cmp( r, s ) && cryptStatusOK( status ) )
#else
		/* w = s^-1 mod q */
		v = BN_mod_inverse( s, q, bnCTX );	/* w = s^-1 mod q */

		/* u1 = ( hash * w ) mod q */
		BN_mod_mul( u1, u1, v, q, bnCTX );	/* u1 = ( hash * w ) mod q */

		/* u2 = ( r * w ) mod q */
		BN_mod_mul( v, r, v, q, bnCTX );	/* u2 = ( r * w ) mod q */

		/* v = ( ( ( g^u1 ) * ( y^u2 ) ) mod p ) mod q.  We need to use
		   an extra temp variable here because BN_mod_exp() params 1 and
		   3 must differ, and BN_mod() params 1 and 2 must differ */
		BN_mod_exp( s, g, u1, p, bnCTX );	/* u1' = ( g ^ u1 ) mod p */
		BN_mod_exp( u1, y, v, p, bnCTX );	/* u2' = ( y ^ u2 ) mod p */
		BN_mod_mul( s, s, u1, p, bnCTX );	/* v = ( u1' * u2' ) mod p */
		BN_mod( v, s, q, bnCTX );			/* v = v mod q */

		/* if r == v signature is good */
		if( BN_cmp( r, v ) && cryptStatusOK( status ) )
#endif
			status = CRYPT_ERROR_SIGNATURE;

		BN_clear_free( v );
		BN_clear_free( u1 );
		}

	/* Destroy sensitive data */
	BN_clear_free( s );
	BN_clear_free( r );

	BN_CTX_free( bnCTX );

	return( ( status == -1 ) ? CRYPT_ERROR_FAILED : status );
	}

/****************************************************************************
*																			*
*							DSA Key Management Routines						*
*																			*
****************************************************************************/

/* Load DSA public/private key components into an encryption context */

int dsaInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength )
	{
	CRYPT_PKCINFO_DLP *dsaKey = ( CRYPT_PKCINFO_DLP * ) key;
	BOOLEAN calculateY = FALSE;
	int status;

	/* Load the key component from the external representation into the
	   internal BigNums unless we're doing an internal load */
	if( keyLength != sizeof( PKCINFO_LOADINTERNAL ) )
		{
		cryptInfo->ctxPKC.isPublicKey = dsaKey->isPublicKey;

		BN_bin2bn( dsaKey->p, bitsToBytes( dsaKey->pLen ),
				   cryptInfo->ctxPKC.dlpParam_p );
		BN_bin2bn( dsaKey->q, bitsToBytes( dsaKey->qLen ),
				   cryptInfo->ctxPKC.dlpParam_q );
		BN_bin2bn( dsaKey->g, bitsToBytes( dsaKey->gLen ),
				   cryptInfo->ctxPKC.dlpParam_g );
		if( dsaKey->yLen == 0 && !dsaKey->isPublicKey )
			/* No y available, generate it ourselves */
			calculateY = TRUE;
		else
			BN_bin2bn( dsaKey->y, bitsToBytes( dsaKey->yLen ),
					   cryptInfo->ctxPKC.dlpParam_y );
		if( !dsaKey->isPublicKey )
			BN_bin2bn( dsaKey->x, bitsToBytes( dsaKey->xLen ),
				   cryptInfo->ctxPKC.dlpParam_x );
		}

	/* Some sources (specifically PKCS #11) don't make y available for 
	   private keys, so if the caller is trying to load a private key with a 
	   zero y value, we calculate it for them */
	if( calculateY )
		{
		BN_CTX *bnCTX;

		if( BN_is_zero( cryptInfo->ctxPKC.dlpParam_p ) || \
			BN_is_zero( cryptInfo->ctxPKC.dlpParam_q ) || \
			BN_is_zero( cryptInfo->ctxPKC.dlpParam_g ) )
			/* We have to perform this redundant check now because we can't 
			   safely calculate y without it */
			return( CRYPT_ARGERROR_STR1 );
		if( ( bnCTX = BN_CTX_new() ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		BN_mod_exp( cryptInfo->ctxPKC.dlpParam_y, cryptInfo->ctxPKC.dlpParam_g,
					cryptInfo->ctxPKC.dlpParam_x, cryptInfo->ctxPKC.dlpParam_p, bnCTX );
		BN_CTX_free( bnCTX );
		}

	/* Check the parameters and calculate the key ID */
	status = checkDLParams( cryptInfo );
	if( cryptStatusError( status ) )
		return( status );
	cryptInfo->ctxPKC.keySizeBits = BN_num_bits( cryptInfo->ctxPKC.dlpParam_p );
	return( calculateKeyID( cryptInfo ) );
	}

/* Generate a DSA key into an encryption context */

int dsaGenerateKey( CRYPT_INFO *cryptInfo, const int keySizeBits )
	{
	int status;

	status = generateDLPKey( cryptInfo, ( keySizeBits / 64 ) * 64, 160 );
	if( cryptStatusError( status ) )
		return( status );
	return( calculateKeyID( cryptInfo ) );
	}
