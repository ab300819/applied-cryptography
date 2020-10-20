/****************************************************************************
*																			*
*								cryptlib Test Code							*
*						Copyright Peter Gutmann 1995-1999					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _MSC_VER
  #include "../capi.h"
  #include "../test/test.h"
#else
  #include "capi.h"
  #include "test/test.h"
#endif /* Braindamaged VC++ include handling */

/* Define the following to enable/disable various blocks of tests */

#if 0
#define TEST_LOWLEVEL		/* Test low-level functions */
#define TEST_RANDOM			/* Test randomness functions */
#define TEST_CONFIG			/* Test configuration functions */
#define TEST_DEVICE			/* Test crypto device functions */
#define TEST_MIDLEVEL		/* Test high-level encr/sig.functions */
#endif /* 0 */
#define TEST_DEVICE	/*!!!!!!!!!!!*/
#if 1
#define TEST_CERT			/* Test certificate management functions */
#define TEST_KEYSET			/* Test keyset read functions */
#define TEST_CERTPROCESS	/* Test certificate handling process */
#define TEST_HIGHLEVEL		/* Test high-level encr/sig.functions */
#endif /* 0 */
#if 1
#define TEST_ENVELOPE		/* Test enveloping functions */
#endif /* 0 */

/* When the keyset test is enabled, one of the keysets it writes to is
   the smart card keyset.  Since this can be rather slow, you can define
   the following to enable/disable this test */

/*#define TEST_KEYSET_SMARTCARD	/**/

/* The size of the test buffers */

#define TESTBUFFER_SIZE		256

/* Prototypes for functions in testhl.c */

int testDeriveKey( void );
int testRandomRoutines( void );
int testConventionalExportImport( void );
int testKeyExportImport( void );
int testSignData( void );
int testKeyExchange( void );
int testKeygen( void );
int testKeygenAsync( void );
int testKeyExportImportCMS( void );
int testSignDataCMS( void );
int testDevices( void );

/* Prototypes for functions in testkey.c */

int testGetPGPPublicKey( void );
int testGetPGPPrivateKey( void );
int testReadWriteFileKey( void );
int testReadFilePublicKey( void );
int testUpdateFileKeyCert( void );
int testUpdateFileKeyCertChain( void );
int testReadFileCert( void );
int testReadFileCertChain( void );
int testWriteCardKey( void );
int testReadCardKey( void );
int testWriteCert( void );
int testReadCert( void );
int testKeysetQuery( void );
int testWriteCertLDAP( void );
int testReadCertLDAP( void );
int testReadCertHTTP( void );

/* Prototypes for functions in testenv.c.  Data and SessionCrypt and both
   CMS and cryptlib, the remainder are either cryptlib or CMS */

int testEnvelopeData( void );
int testEnvelopeSessionCrypt( void );
int testEnvelopeCrypt( void );
int testEnvelopePKCCrypt( void );
int testEnvelopeSign( void );
int testCMSEnvelopePKCCrypt( void );
int testCMSEnvelopeSign( void );
int testCMSEnvelopeDetachedSig( void );
int testCMSImportSignedData( void );
int testCMSImportEnvelopedData( void );

/* Prototypes for functions in testcert.c */

int testCert( void );
int testCACert( void );
int testComplexCert( void );
int testSETCert( void );
int testAttributeCert( void );
int testCRL( void );
int testComplexCRL( void );
int testCertChain( void );
int testCertRequest( void );
int testComplexCertRequest( void );
int testCMSAttributes( void );
int testCertImport( void );
int testCertReqImport( void );
int testCRLImport( void );
int testCertChainImport( void );
int testSPKACImport( void );
int testCertProcess( void );

/* Prototypes for functions in testsess.c */

int testSessionSSH( void );
int testSessionSSL( void );

/* Whether the PKC read in testhl.c worked - used later to test other
   routines.  We initially set it to TRUE in case the keyset read tests are
   never called, so we can still trying reading the keys in other tests */

int keyReadOK = TRUE;

/* The keys for testing the RSA, DSA, and Elgamal implementations. These are
   the same 512-bit keys as the one used for the lib_xxx.c self-tests.  For
   RSA we also include a 768-bit key which is needed for SSH.

   It would be nicer if we had a fixed encoded public key which we read in
   via the keyset routines rather than using this messy indirect-loading,
   but that would defeat the purpose of the self-test somewhat since it could
   fail in the (rather complex) keyset access routines rather than in the
   PKC code which is what we're really trying to test */

typedef struct {
	const int nLen; const BYTE n[ 96 ];
	const int eLen; const BYTE e[ 3 ];
	const int dLen; const BYTE d[ 96 ];
	const int pLen; const BYTE p[ 48 ];
	const int qLen; const BYTE q[ 48 ];
	const int uLen; const BYTE u[ 48 ];
	const int e1Len; const BYTE e1[ 48 ];
	const int e2Len; const BYTE e2[ 48 ];
	} RSA_KEY;

static const RSA_KEY rsa512TestKey = {
	/* n */
	512,
	{ 0xE1, 0x95, 0x41, 0x17, 0xB4, 0xCB, 0xDC, 0xD0,
	  0xCB, 0x9B, 0x11, 0x19, 0x9C, 0xED, 0x04, 0x6F,
	  0xBD, 0x70, 0x2D, 0x5C, 0x8A, 0x32, 0xFF, 0x16,
	  0x22, 0x57, 0x30, 0x3B, 0xD4, 0x59, 0x9C, 0x01,
	  0xF0, 0xA3, 0x70, 0xA1, 0x6C, 0x16, 0xAC, 0xCC,
	  0x8C, 0xAD, 0xB0, 0xA0, 0xAF, 0xC7, 0xCC, 0x49,
	  0x4F, 0xD9, 0x5D, 0x32, 0x1C, 0x2A, 0xE8, 0x4E,
	  0x15, 0xE1, 0x26, 0x6C, 0xC4, 0xB8, 0x94, 0xE1 },
	/* e */
	5,
	{ 0x11 },
	/* d */
	509,
	{ 0x13, 0xE7, 0x85, 0xBE, 0x53, 0xB7, 0xA2, 0x8A,
	  0xE4, 0xC9, 0xEA, 0xEB, 0xAB, 0xF6, 0xCB, 0xAF,
	  0x81, 0xA8, 0x04, 0x00, 0xA2, 0xC8, 0x43, 0xAF,
	  0x21, 0x25, 0xCF, 0x8C, 0xCE, 0xF8, 0xD9, 0x0F,
	  0x10, 0x78, 0x4C, 0x1A, 0x26, 0x5D, 0x90, 0x18,
	  0x79, 0x90, 0x42, 0x83, 0x6E, 0xAE, 0x3E, 0x20,
	  0x0B, 0x0C, 0x5B, 0x6B, 0x8E, 0x31, 0xE5, 0xCF,
	  0xD6, 0xE0, 0xBB, 0x41, 0xC1, 0xB8, 0x2E, 0x17 },
	/* p */
	256,
	{ 0xED, 0xE4, 0x02, 0x90, 0xA4, 0xA4, 0x98, 0x0D,
	  0x45, 0xA2, 0xF3, 0x96, 0x09, 0xED, 0x7B, 0x40,
	  0xCD, 0xF6, 0x21, 0xCC, 0xC0, 0x1F, 0x83, 0x09,
	  0x56, 0x37, 0x97, 0xFB, 0x05, 0x5B, 0x87, 0xB7 },
	/* q */
	256,
	{ 0xF2, 0xC1, 0x64, 0xE8, 0x69, 0xF8, 0x5E, 0x54,
	  0x8F, 0xFD, 0x20, 0x8E, 0x6A, 0x23, 0x90, 0xF2,
	  0xAF, 0x57, 0x2F, 0x4D, 0x10, 0x80, 0x8E, 0x11,
	  0x3C, 0x61, 0x44, 0x33, 0x2B, 0xE0, 0x58, 0x27 },
	/* u */
	255,
	{ 0x68, 0x45, 0x00, 0x64, 0x32, 0x9D, 0x09, 0x6E,
	  0x0A, 0xD3, 0xF3, 0x8A, 0xFE, 0x15, 0x8C, 0x79,
	  0xAD, 0x84, 0x35, 0x05, 0x19, 0x2C, 0x19, 0x51,
	  0xAB, 0x83, 0xC7, 0xE8, 0x5C, 0xAC, 0xAD, 0x7A },
	/* exponent1 */
	256,
	{ 0x99, 0xED, 0xE3, 0x8A, 0xC4, 0xE2, 0xF8, 0xF9,
	  0x87, 0x69, 0x70, 0x70, 0x24, 0x8A, 0x9B, 0x0B,
	  0xD0, 0x90, 0x33, 0xFC, 0xF4, 0xC9, 0x18, 0x8D,
	  0x92, 0x23, 0xF8, 0xED, 0xB8, 0x2C, 0x2A, 0xA3 },
	/* exponent2 */
	256,
	{ 0xB9, 0xA2, 0xF2, 0xCF, 0xD8, 0x90, 0xC0, 0x9B,
	  0x04, 0xB2, 0x82, 0x4E, 0xC9, 0xA2, 0xBA, 0x22,
	  0xFE, 0x8D, 0xF6, 0xFE, 0xB2, 0x44, 0x30, 0x67,
	  0x88, 0x86, 0x9D, 0x90, 0x8A, 0xF6, 0xD9, 0xFF }
	};

static const RSA_KEY rsa768TestKey = {
	/* n */
	768,
	{ 0xE6, 0xAB, 0x1A, 0xF4, 0x5B, 0xD8, 0x1E, 0x8F,
	  0x8D, 0x33, 0x18, 0x3C, 0x21, 0xDB, 0x96, 0x85,
	  0xFA, 0xA1, 0xFB, 0x5B, 0x7B, 0x5C, 0x5B, 0x85,
	  0x2B, 0xDD, 0x09, 0x83, 0x79, 0x17, 0x70, 0x35,
	  0x96, 0x01, 0x2F, 0x6A, 0xEC, 0x2D, 0x2D, 0xAB,
	  0xBB, 0x58, 0x22, 0x3F, 0x3D, 0x3B, 0xCA, 0x5E,
	  0xA7, 0xDF, 0x72, 0x3D, 0x67, 0x9D, 0x45, 0xEB,
	  0x26, 0x38, 0x4D, 0xE2, 0x5B, 0x41, 0x6D, 0x6A,
	  0x65, 0xE3, 0x73, 0x15, 0x23, 0x63, 0xF6, 0xD7,
	  0x0E, 0x09, 0x4F, 0x4B, 0x09, 0x6C, 0xE5, 0x80,
	  0xEC, 0x8F, 0x36, 0xB3, 0x51, 0xF8, 0xE5, 0xEA,
	  0x68, 0xF0, 0x22, 0xB7, 0xB7, 0x28, 0x61, 0x9B },
	/* e */
	17,
	{ 0x01, 0x00, 0x01 },
	/* d */
	768,
	{ 0x9B, 0x38, 0x87, 0x01, 0xEA, 0x90, 0x0B, 0x38,
	  0xA4, 0x56, 0xBE, 0xB7, 0x30, 0x3D, 0x79, 0x14,
	  0x1D, 0x6D, 0x45, 0x1C, 0xF1, 0x6D, 0x5B, 0xF4,
	  0xC8, 0x68, 0x8C, 0x8F, 0x59, 0x3C, 0x09, 0x79,
	  0x35, 0xC1, 0x04, 0x6C, 0x9A, 0x13, 0x68, 0xC9,
	  0x48, 0x5F, 0x6D, 0x64, 0x4A, 0xCB, 0x62, 0x48,
	  0x7A, 0xCB, 0x5F, 0xA9, 0x68, 0xA0, 0xB3, 0xD5,
	  0x80, 0x68, 0x0B, 0xAA, 0x84, 0xDE, 0xD7, 0xE9,
	  0xDB, 0xC0, 0x94, 0x0B, 0x69, 0xE7, 0xE7, 0x0B,
	  0x6D, 0xD7, 0xA2, 0xC2, 0x69, 0x84, 0x12, 0xEE,
	  0x5B, 0x86, 0xB9, 0x1B, 0x2F, 0xD4, 0xDF, 0xE9,
	  0xE7, 0x21, 0xE5, 0x8D, 0xF5, 0x83, 0xDF, 0x29 },
	/* p */
	384,
	{ 0xFB, 0x1B, 0x4D, 0x3A, 0x6A, 0xC8, 0x8D, 0xE2,
	  0xFF, 0xEC, 0x24, 0xC3, 0x2C, 0x01, 0xEA, 0x4D,
	  0xD2, 0x3F, 0x92, 0x44, 0xE4, 0xEC, 0xC3, 0x0D,
	  0xDF, 0xC7, 0x1A, 0xCA, 0xEB, 0xC3, 0x47, 0xF9,
	  0x92, 0xFB, 0xB3, 0x22, 0xD6, 0xDE, 0xE2, 0xDD,
	  0x86, 0xB4, 0x1C, 0x82, 0x01, 0x87, 0x9E, 0xED },
	/* q */
	384,
	{ 0xEB, 0x29, 0xD7, 0xD0, 0x6B, 0x7A, 0x06, 0xE3,
	  0xBE, 0xF6, 0x49, 0xF9, 0x59, 0xE7, 0xE8, 0x10,
	  0xCC, 0xF4, 0x6B, 0xF7, 0xB0, 0x34, 0x44, 0x4A,
	  0xFE, 0xD0, 0xAD, 0x0E, 0x31, 0xA6, 0xD3, 0x90,
	  0x49, 0x67, 0x46, 0xF9, 0x4B, 0x31, 0x9A, 0xB5,
	  0x95, 0x8F, 0x2C, 0xC2, 0xBC, 0xF2, 0xE9, 0xA7 },
	/* u */
	384,
	{ 0xC7, 0x71, 0x07, 0xF5, 0x6A, 0xA2, 0x2A, 0x1A,
	  0x50, 0xC0, 0xCF, 0xF0, 0xC0, 0xAA, 0x71, 0xB7,
	  0xAA, 0x66, 0xF3, 0x5E, 0x12, 0x93, 0xBF, 0xD7,
	  0x41, 0x31, 0xC1, 0xC5, 0xF1, 0x77, 0x26, 0xD6,
	  0xDC, 0x86, 0x5C, 0xD4, 0x84, 0xEB, 0x0D, 0x0E,
	  0xCB, 0x71, 0x64, 0xC6, 0x8F, 0xD9, 0x02, 0x9D },
	/* exponent1 */
	384,
	{ 0xE5, 0xB0, 0x3C, 0x7D, 0x21, 0xEE, 0x1F, 0x73,
	  0x33, 0x9B, 0xA2, 0xA8, 0xF0, 0x59, 0x34, 0x24,
	  0x49, 0x1C, 0x23, 0x44, 0x67, 0x8E, 0x76, 0x80,
	  0xFB, 0x5F, 0x99, 0x8F, 0x62, 0x06, 0xB7, 0x90,
	  0x7F, 0xB5, 0x42, 0x4F, 0xAC, 0xF2, 0x25, 0xDC,
	  0x72, 0x79, 0xCF, 0xD5, 0xCF, 0x66, 0x69, 0xA5 },
	/* exponent2 */
	384,
	{ 0xAC, 0x62, 0x22, 0xE2, 0x94, 0x36, 0x82, 0x60,
	  0x66, 0x76, 0x92, 0x29, 0x68, 0x1F, 0x58, 0x7D,
	  0x20, 0x50, 0xB7, 0xE8, 0x7C, 0x51, 0x04, 0x12,
	  0xD9, 0x91, 0xCC, 0x99, 0xD0, 0x09, 0xD3, 0xA2,
	  0x3C, 0x3C, 0xA9, 0xC9, 0x4A, 0xB6, 0x95, 0x0B,
	  0x31, 0x14, 0x20, 0x22, 0xAC, 0x71, 0x80, 0x97 }
	};

typedef struct {
	const int pLen; const BYTE p[ 64 ];
	const int qLen; const BYTE q[ 20 ];
	const int gLen; const BYTE g[ 64 ];
	const int xLen; const BYTE x[ 20 ];
	const int yLen; const BYTE y[ 64 ];
	} DSA_PRIVKEY;

static const DSA_PRIVKEY dsaTestKey = {
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
	/* x */
	160,
	{ 0x20, 0x70, 0xB3, 0x22, 0x3D, 0xBA, 0x37, 0x2F,
	  0xDE, 0x1C, 0x0F, 0xFC, 0x7B, 0x2E, 0x3B, 0x49,
	  0x8B, 0x26, 0x06, 0x14 },
	/* y */
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

typedef struct {
	const int pLen; const BYTE p[ 64 ];
	const int gLen; const BYTE g[ 1 ];
	const int yLen; const BYTE y[ 64 ];
	const int xLen; const BYTE x[ 64 ];
	} ELGAMAL_PRIVKEY;

static const ELGAMAL_PRIVKEY elgamalTestKey = {
	/* p */
	512,
	{ 0xF5, 0x2A, 0xFF, 0x3C, 0xE1, 0xB1, 0x29, 0x40,
	  0x18, 0x11, 0x8D, 0x7C, 0x84, 0xA7, 0x0A, 0x72,
	  0xD6, 0x86, 0xC4, 0x03, 0x19, 0xC8, 0x07, 0x29,
	  0x7A, 0xCA, 0x95, 0x0C, 0xD9, 0x96, 0x9F, 0xAB,
	  0xD0, 0x0A, 0x50, 0x9B, 0x02, 0x46, 0xD3, 0x08,
	  0x3D, 0x66, 0xA4, 0x5D, 0x41, 0x9F, 0x9C, 0x7C,
	  0xBD, 0x89, 0x4B, 0x22, 0x19, 0x26, 0xBA, 0xAB,
	  0xA2, 0x5E, 0xC3, 0x55, 0xE9, 0x2A, 0x05, 0x5F },
	/* g */
	2,
	{ 0x03 },
	/* y */
	512,
	{ 0x26, 0x26, 0x98, 0x3C, 0x25, 0xD5, 0x80, 0xDA,
	  0x84, 0xA8, 0xA7, 0xFA, 0xF1, 0x68, 0x62, 0xB0,
	  0x01, 0x90, 0x82, 0xBC, 0x3C, 0xDC, 0x78, 0x57,
	  0x62, 0x2C, 0x52, 0x8D, 0x74, 0x08, 0xA4, 0x4C,
	  0xAA, 0x01, 0xF2, 0x89, 0x23, 0xAA, 0xF6, 0x44,
	  0x67, 0xF1, 0x76, 0x54, 0x84, 0xE5, 0xC6, 0xA7,
	  0x01, 0xE7, 0x78, 0x01, 0xFD, 0x5F, 0x10, 0x2B,
	  0xB1, 0x06, 0x2E, 0x9C, 0x63, 0x0B, 0x2B, 0x21 },
	/* x */
	512,
	{ 0xCD, 0x27, 0x3A, 0x8F, 0x3D, 0x8E, 0x14, 0x54,
	  0xFF, 0xB9, 0x3A, 0xB1, 0x11, 0x3C, 0xDF, 0xBD,
	  0x50, 0x78, 0xC4, 0x55, 0x24, 0x5C, 0xAC, 0xF2,
	  0x45, 0x06, 0xE7, 0xBE, 0xAC, 0x7E, 0xD7, 0xCC,
	  0x76, 0x14, 0x9C, 0x84, 0xF4, 0xD6, 0x0C, 0xF7,
	  0x14, 0x40, 0xE5, 0x56, 0xFA, 0xE7, 0xA7, 0x42,
	  0x54, 0x64, 0xDF, 0xE4, 0xD1, 0x92, 0x83, 0x01,
	  0x54, 0x36, 0x37, 0x22, 0xF5, 0x1B, 0xB9, 0x36 }
	};

#ifdef TEST_CONFIG

/* The names of the configuration options we check for */

static struct {
	const CRYPT_OPTION_TYPE option;		/* Option */
	const char *name;					/* Option name */
	const BOOLEAN isNumeric;			/* Whether it's a numeric option */
	} configOption[] = {
	{ CRYPT_OPTION_INFO_DESCRIPTION, "CRYPT_OPTION_INFO_DESCRIPTION", FALSE },
	{ CRYPT_OPTION_INFO_COPYRIGHT, "CRYPT_OPTION_INFO_COPYRIGHT", FALSE },
	{ CRYPT_OPTION_INFO_MAJORVERSION, "CRYPT_OPTION_INFO_MAJORVERSION", TRUE },
	{ CRYPT_OPTION_INFO_MINORVERSION, "CRYPT_OPTION_INFO_MINORVERSION", TRUE },

	{ CRYPT_OPTION_ENCR_ALGO, "CRYPT_OPTION_ENCR_ALGO", TRUE },
	{ CRYPT_OPTION_ENCR_MODE, "CRYPT_OPTION_ENCR_MODE", TRUE },
	{ CRYPT_OPTION_ENCR_HASH, "CRYPT_OPTION_ENCR_HASH", TRUE },

	{ CRYPT_OPTION_PKC_ALGO, "CRYPT_OPTION_PKC_ALGO", TRUE },
	{ CRYPT_OPTION_PKC_KEYSIZE, "CRYPT_OPTION_PKC_KEYSIZE", TRUE },

	{ CRYPT_OPTION_SIG_ALGO, "CRYPT_OPTION_SIG_ALGO", TRUE },
	{ CRYPT_OPTION_SIG_KEYSIZE, "CRYPT_OPTION_SIG_KEYSIZE", TRUE },

	{ CRYPT_OPTION_KEYING_ALGO, "CRYPT_OPTION_KEYING_ALGO", TRUE },
	{ CRYPT_OPTION_KEYING_ITERATIONS, "CRYPT_OPTION_KEYING_ITERATIONS", TRUE },

	{ CRYPT_OPTION_CERT_CREATEV3CERT, "CRYPT_OPTION_CERT_CREATEV3CERT", TRUE },
	{ CRYPT_OPTION_CERT_PKCS10ALT, "CRYPT_OPTION_CERT_PKCS10ALT", TRUE },
	{ CRYPT_OPTION_CERT_CHECKENCODING, "CRYPT_OPTION_CERT_CHECKENCODING", TRUE },
	{ CRYPT_OPTION_CERT_FIXSTRINGS, "CRYPT_OPTION_CERT_FIXSTRINGS", TRUE },
	{ CRYPT_OPTION_CERT_FIXEMAILADDRESS, "CRYPT_OPTION_CERT_FIXEMAILADDRESS", TRUE },
	{ CRYPT_OPTION_CERT_ISSUERNAMEBLOB, "CRYPT_OPTION_CERT_ISSUERNAMEBLOB", TRUE },
	{ CRYPT_OPTION_CERT_KEYIDBLOB, "CRYPT_OPTION_CERT_KEYIDBLOB", TRUE },
	{ CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES, "CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES", TRUE },
	{ CRYPT_OPTION_CERT_TRUSTCHAINROOT, "CRYPT_OPTION_CERT_TRUSTCHAINROOT", TRUE },
	{ CRYPT_OPTION_CERT_VALIDITY, "CRYPT_OPTION_CERT_VALIDITY", TRUE },
	{ CRYPT_OPTION_CERT_UPDATEINTERVAL, "CRYPT_OPTION_CERT_UPDATEINTERVAL", TRUE },
	{ CRYPT_OPTION_CERT_ENCODE_VALIDITYNESTING, "CRYPT_OPTION_CERT_ENCODE_VALIDITYNESTING", TRUE },
	{ CRYPT_OPTION_CERT_DECODE_VALIDITYNESTING, "CRYPT_OPTION_CERT_DECODE_VALIDITYNESTING", TRUE },
	{ CRYPT_OPTION_CERT_ENCODE_CRITICAL, "CRYPT_OPTION_CERT_ENCODE_CRITICAL", TRUE },
	{ CRYPT_OPTION_CERT_DECODE_CRITICAL, "CRYPT_OPTION_CERT_DECODE_CRITICAL", TRUE },

	{ CRYPT_OPTION_KEYS_PUBLIC, "CRYPT_OPTION_KEYS_PUBLIC", TRUE },
	{ CRYPT_OPTION_KEYS_PRIVATE, "CRYPT_OPTION_KEYS_PRIVATE", TRUE },
	{ CRYPT_OPTION_KEYS_SIGCHECK, "CRYPT_OPTION_KEYS_SIGCHECK", TRUE },
	{ CRYPT_OPTION_KEYS_SIGNATURE, "CRYPT_OPTION_KEYS_SIGNATURE", TRUE },

	{ CRYPT_OPTION_KEYS_FILE_PRIVATE, "CRYPT_OPTION_KEYS_FILE_PRIVATE", FALSE },
	{ CRYPT_OPTION_KEYS_FILE_SIGNATURE, "CRYPT_OPTION_KEYS_FILE_SIGNATURE", FALSE },

	{ CRYPT_OPTION_KEYS_PGP_PUBLIC, "CRYPT_OPTION_KEYS_PGP_PUBLIC", FALSE },
	{ CRYPT_OPTION_KEYS_PGP_PRIVATE, "CRYPT_OPTION_KEYS_PGP_PRIVATE", FALSE },
	{ CRYPT_OPTION_KEYS_PGP_SIGCHECK, "CRYPT_OPTION_KEYS_PGP_SIGCHECK", FALSE },
	{ CRYPT_OPTION_KEYS_PGP_SIGNATURE, "CRYPT_OPTION_KEYS_PGP_SIGNATURE", FALSE },

	{ CRYPT_OPTION_KEYS_DBMS_NAMETABLE, "CRYPT_OPTION_KEYS_DBMS_NAMETABLE", FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAME_C, "CRYPT_OPTION_KEYS_DBMS_NAME_C", FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAME_SP, "CRYPT_OPTION_KEYS_DBMS_NAME_SP", FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAME_L, "CRYPT_OPTION_KEYS_DBMS_NAME_L", FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAME_O, "CRYPT_OPTION_KEYS_DBMS_NAME_O", FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAME_OU, "CRYPT_OPTION_KEYS_DBMS_NAME_OU", FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAME_CN, "CRYPT_OPTION_KEYS_DBMS_NAME_CN", FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAMEEMAIL, "CRYPT_OPTION_KEYS_DBMS_NAMEEMAIL", FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAMEDATE, "CRYPT_OPTION_KEYS_DBMS_NAMEDATE", FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAMENAMEID, "CRYPT_OPTION_KEYS_DBMS_NAMENAMEID", FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAMEISSUERID, "CRYPT_OPTION_KEYS_DBMS_NAMEISSUERID", FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAMEKEYID, "CRYPT_OPTION_KEYS_DBMS_NAMEKEYID", FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAMEKEYDATA, "CRYPT_OPTION_KEYS_DBMS_NAMEKEYDATA", FALSE },

	{ CRYPT_OPTION_KEYS_HTTP_PROXY, "CRYPT_OPTION_KEYS_HTTP_PROXY", FALSE },
	{ CRYPT_OPTION_KEYS_HTTP_TIMEOUT, "CRYPT_OPTION_KEYS_HTTP_TIMEOUT", TRUE },

	{ CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS, "CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_CACERTNAME, "CRYPT_OPTION_KEYS_LDAP_CACERTNAME", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_CERTNAME, "CRYPT_OPTION_KEYS_LDAP_CERTNAME", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_CRLNAME, "CRYPT_OPTION_KEYS_LDAP_CRLNAME", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_EMAILNAME, "CRYPT_OPTION_KEYS_LDAP_EMAILNAME", FALSE },

	{ CRYPT_OPTION_DEVICE_PKCS11_DVR01, "CRYPT_OPTION_DEVICE_PKCS11_DVR01", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR02, "CRYPT_OPTION_DEVICE_PKCS11_DVR02", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR03, "CRYPT_OPTION_DEVICE_PKCS11_DVR03", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR04, "CRYPT_OPTION_DEVICE_PKCS11_DVR04", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR05, "CRYPT_OPTION_DEVICE_PKCS11_DVR05", FALSE },
	{ CRYPT_OPTION_DEVICE_SERIALRNG, "CRYPT_OPTION_DEVICE_SERIALRNG", FALSE },
	{ CRYPT_OPTION_DEVICE_SERIALRNG_PARAMS, "CRYPT_OPTION_DEVICE_SERIALPARAMS", FALSE },
	{ CRYPT_OPTION_DEVICE_SERIALRNG_ONLY, "CRYPT_OPTION_DEVICE_SERIALRNG_ONLY", TRUE },

	{ CRYPT_OPTION_CMS_DEFAULTATTRIBUTES, "CRYPT_OPTION_CMS_DEFAULTATTRIBUTES", TRUE },

	{ CRYPT_OPTION_MISC_FORCELOCK, "CRYPT_OPTION_MISC_FORCELOCK", TRUE },
	{ CRYPT_OPTION_MISC_ASYNCINIT, "CRYPT_OPTION_MISC_ASYNCINIT", TRUE },
	{ CRYPT_OPTION_NONE, NULL, 0 }
	};
#endif /* TEST_CONFIG */

/* There are some sizeable (for DOS) data structures used, so we increase the
   stack size to allow for them */

#if defined( __MSDOS16__ ) && defined( __TURBOC__ )
  extern unsigned _stklen = 16384;

/* We also fake out a few unnecessary/unused functions */

void gfInit( void ) {}
void gfQuit( void ) {}
void deflateInit_( void ) {}
void deflateInit2_( void ) {}
void deflate( void ) {}
void deflateEnd( void ) {}

int pgpProcessPreamble( void ) { return( CRYPT_ERROR ); }
int pgpProcessPostamble( void ) { return( CRYPT_ERROR ); }

#ifdef __BORLANDC__x

/* BC++ 3.x doesn't have mbstowcs() in the default library, and also defines
   wchar_t as char (!!) so we fake it here */

size_t mbstowcs( char *pwcs, const char *s, size_t n )
	{
	memcpy( pwcs, s, n );
	return( n );
	}
#endif /* __BORLANDC__ */

#endif /* __MSDOS16__ && __TURBOC__ */

/* Some algorithms can be disabled to eliminate patent problems or reduce the
   size of the code.  The following functions are used to select generally
   equivalent alternatives if the required algorithm isn't available.  These
   selections make certain assumptions (that the given algorithms are always
   available, which is virtually guaranteed, and that they have the same
   general properties as the algorithms they're replacing, which is also
   usually the case - Blowfish for IDEA, RC2, or RC5, and MD5 for MD4) */

CRYPT_ALGO selectCipher( const CRYPT_ALGO algorithm )
	{
	if( cryptStatusOK( cryptQueryCapability( algorithm, CRYPT_UNUSED, NULL ) ) )
		return( algorithm );
	return( CRYPT_ALGO_BLOWFISH );
	}

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Report information on the encryption algorithm */

void reportAlgorithmInformation( const CRYPT_QUERY_INFO *cryptQueryInfo )
	{
	printf( "algorithm %s/%s\n",
			cryptQueryInfo->algoName, cryptQueryInfo->modeName );
	printf(	"  is available with name `%s', block size %d bits",
			cryptQueryInfo->algoName,
			bytesToBits( cryptQueryInfo->blockSize ) );
	if( cryptQueryInfo->cryptAlgo < CRYPT_ALGO_FIRST_HASH || \
		cryptQueryInfo->cryptAlgo > CRYPT_ALGO_LAST_HASH )
		{
		printf( ",\n"
				"  min keysize %d bits, recommended keysize %d bits, "
					"max keysize %d bits",
				bytesToBits( cryptQueryInfo->minKeySize ),
				bytesToBits( cryptQueryInfo->keySize ),
				bytesToBits( cryptQueryInfo->maxKeySize ) );
		if( cryptQueryInfo->cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
			cryptQueryInfo->cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL )
			printf( ",\n"
					"  min IV size %d bits, recommended IV size %d bits, "
						"max IV size %d bits",
					bytesToBits( cryptQueryInfo->minIVsize ),
					bytesToBits( cryptQueryInfo->ivSize ),
					bytesToBits( cryptQueryInfo->maxIVsize ) );
		}
	printf( ".\n" );
	}

#if defined( TEST_LOWLEVEL ) || defined( TEST_DEVICE )

/* Work routines: Set a pair of encrypt/decrypt buffers to a known state,
   and make sure they're still in that known state */

static void initTestBuffers( BYTE *buffer1, BYTE *buffer2 )
	{
	/* Set the buffers to a known state */
	memset( buffer1, '*', TESTBUFFER_SIZE );
	memcpy( buffer1, "12345678", 8 );		/* For endianness check */
	memcpy( buffer2, buffer1, TESTBUFFER_SIZE );
	}

static void checkTestBuffers( BYTE *buffer1, BYTE *buffer2 )
	{
	/* Make sure everything went OK */
	if( memcmp( buffer1, buffer2, TESTBUFFER_SIZE ) )
		{
		puts( "Error: Decrypted data != original plaintext." );

		/* Try and guess at block chaining problems */
		if( !memcmp( buffer1, "12345678****", 12 ) )
			puts( "\t\bIt looks like there's a problem with block chaining." );
		else
			/* Try and guess at endianness problems - we want "1234" */
			if( !memcmp( buffer1, "4321", 4 ) )
				puts( "\t\bIt looks like the 32-bit word endianness is "
					  "reversed." );
			else
				if( !memcmp( buffer1, "2143", 4 ) )
					puts( "\t\bIt looks like the 16-bit word endianness is "
						  "reversed." );
			else
				if( buffer1[ 0 ] >= '1' && buffer1[ 0 ] <= '9' )
					puts( "\t\bIt looks like there's some sort of endianness "
						  "problem which is\n\t more complex than just a "
						  "reversal." );
				else
					puts( "\t\bIt's probably more than just an endianness "
						  "problem." );
		}
	}

/* Check for an algorithm/mode */

static BOOLEAN checkLowlevelInfo( const CRYPT_DEVICE cryptDevice,
								  const CRYPT_ALGO cryptAlgo,
								  const CRYPT_MODE cryptMode )
	{
	CRYPT_QUERY_INFO cryptQueryInfo;
	const BOOLEAN isDevice = ( cryptDevice != CRYPT_UNUSED ) ? TRUE : FALSE;
	int status;

	if( isDevice )
		status = cryptDeviceQueryCapability( cryptDevice, cryptAlgo,
											 cryptMode, &cryptQueryInfo );
	else
		status = cryptQueryCapability( cryptAlgo, cryptMode, &cryptQueryInfo );
	if( cryptStatusError( status ) )
		{
		printf( "crypt%sQueryCapability() reports algorithm %d, mode %d is "
				"not available: Code %d.\n", isDevice ? "Device" : "",
				cryptAlgo, cryptMode, status );
		return( FALSE );
		}
	printf( "cryptQueryCapability() reports " );
	reportAlgorithmInformation( &cryptQueryInfo );

	return( TRUE );
	}

/* Load the encryption contexts */

static BOOLEAN loadContexts( CRYPT_CONTEXT *cryptContext, CRYPT_CONTEXT *decryptContext,
							 const CRYPT_DEVICE cryptDevice,
							 const CRYPT_ALGO cryptAlgo,
							 const CRYPT_MODE cryptMode,
							 const BYTE *key, const int length )
	{
	const BOOLEAN isDevice = ( cryptDevice != CRYPT_UNUSED ) ? TRUE : FALSE;
	const BOOLEAN hasKey = ( cryptMode != CRYPT_MODE_NONE || \
					   ( cryptAlgo >= CRYPT_ALGO_FIRST_MAC && \
						 cryptAlgo <= CRYPT_ALGO_LAST_MAC ) ) ? TRUE : FALSE;
	int status;

	/* Create the encryption context */
	if( isDevice )
		status = cryptDeviceCreateContext( cryptDevice, cryptContext,
										   cryptAlgo, cryptMode );
	else
		status = cryptCreateContext( cryptContext, cryptAlgo, cryptMode );
	if( cryptStatusError( status ) )
		{
		printf( "crypt%sCreateContext() failed with error code %d.\n",
				isDevice ? "Device" : "", status );
		return( FALSE );
		}
	if( hasKey )
		{
		status = cryptLoadKey( *cryptContext, key, length );
		if( cryptStatusError( status ) )
			{
			printf( "cryptLoadKey() failed with error code %d.\n", status );
			return( FALSE );
			}
		}
	if( decryptContext == NULL )
		return( TRUE );

	/* Create the decryption context */
	if( cryptDevice == CRYPT_UNUSED )
		status = cryptCreateContext( decryptContext, cryptAlgo, cryptMode );
	else
		status = cryptDeviceCreateContext( cryptDevice, decryptContext,
										   cryptAlgo, cryptMode );
	if( cryptStatusError( status ) )
		{
		printf( "crypt%sCreateContext() failed with error code %d.\n",
				( cryptDevice != CRYPT_UNUSED ) ? "Device" : "", status );
		return( FALSE );
		}
	if( hasKey )
		{
		status = cryptLoadKey( *decryptContext, key, length );
		if( cryptStatusError( status ) )
			{
			printf( "cryptLoadKey() failed with error code %d.\n", status );
			return( FALSE );
			}
		}

	return( TRUE );
	}
#endif /* TEST_LOWLEVEL || TEST_DEVICE */

/* Load RSA, DSA, and Elgamal PKC encrytion contexts */

BOOLEAN loadRSAContexts( const CRYPT_DEVICE cryptDevice,
						 CRYPT_CONTEXT *cryptContext,
						 CRYPT_CONTEXT *decryptContext )
	{
	CRYPT_PKCINFO_RSA *rsaKey;
	const BOOLEAN isDevice = ( cryptDevice != CRYPT_UNUSED ) ? TRUE : FALSE;
	int status;

	/* Allocate room for the public-key components */
	if( ( rsaKey = ( CRYPT_PKCINFO_RSA * ) malloc( sizeof( CRYPT_PKCINFO_RSA ) ) ) == NULL )
		return( CRYPT_NOMEM );

	/* Create the encryption context */
	if( cryptContext != NULL )
		{
		if( isDevice )
			status = cryptDeviceCreateContext( cryptDevice, cryptContext,
											   CRYPT_ALGO_RSA, CRYPT_MODE_PKC );
		else
			status = cryptCreateContext( cryptContext, CRYPT_ALGO_RSA,
										 CRYPT_MODE_PKC );
		if( cryptStatusError( status ) )
			{
			free( rsaKey );
			printf( "crypt%sCreateContext() failed with error code %d.\n",
					isDevice ? "Device" : "", status );
			return( FALSE );
			}
		cryptInitComponents( rsaKey, CRYPT_COMPONENTS_BIGENDIAN,
							 CRYPT_KEYTYPE_PUBLIC );
		cryptSetComponent( rsaKey->n, rsa512TestKey.n, rsa512TestKey.nLen );
		cryptSetComponent( rsaKey->e, rsa512TestKey.e, rsa512TestKey.eLen );
		status = cryptLoadKey( *cryptContext, rsaKey, CRYPT_UNUSED );
		cryptDestroyComponents( rsaKey );
		if( cryptStatusError( status ) )
			{
			free( rsaKey );
			cryptDestroyContext( *cryptContext );
				printf( "cryptLoadKey() failed with error code %d.\n", status );
			return( FALSE );
			}
		if( decryptContext == NULL )
			{
			free( rsaKey );
			return( TRUE );
			}
		}

	/* Create the decryption context */
	if( isDevice )
		status = cryptDeviceCreateContext( cryptDevice, decryptContext,
										   CRYPT_ALGO_RSA, CRYPT_MODE_PKC );
	else
		status = cryptCreateContext( decryptContext, CRYPT_ALGO_RSA,
									 CRYPT_MODE_PKC );
	if( cryptStatusError( status ) )
		{
		free( rsaKey );
		if( cryptContext != NULL )
			cryptDestroyContext( *cryptContext );
		printf( "crypt%sCreateContext() failed with error code %d.\n",
				isDevice ? "Device" : "", status );
		return( FALSE );
		}
	cryptInitComponents( rsaKey, CRYPT_COMPONENTS_BIGENDIAN,
						 CRYPT_KEYTYPE_PRIVATE );
	cryptSetComponent( rsaKey->n, rsa512TestKey.n, rsa512TestKey.nLen );
	cryptSetComponent( rsaKey->e, rsa512TestKey.e, rsa512TestKey.eLen );
	cryptSetComponent( rsaKey->d, rsa512TestKey.d, rsa512TestKey.dLen );
	cryptSetComponent( rsaKey->p, rsa512TestKey.p, rsa512TestKey.pLen );
	cryptSetComponent( rsaKey->q, rsa512TestKey.q, rsa512TestKey.qLen );
	cryptSetComponent( rsaKey->u, rsa512TestKey.u, rsa512TestKey.uLen );
	cryptSetComponent( rsaKey->e1, rsa512TestKey.e1, rsa512TestKey.e1Len );
	cryptSetComponent( rsaKey->e2, rsa512TestKey.e2, rsa512TestKey.e2Len );
	status = cryptLoadKey( *decryptContext, rsaKey, CRYPT_UNUSED );
	cryptDestroyComponents( rsaKey );
	free( rsaKey );
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( *cryptContext );
		cryptDestroyContext( *decryptContext );
		printf( "cryptLoadKey() failed with error code %d.\n", status );
		return( FALSE );
		}

	return( TRUE );
	}

BOOLEAN loadRSALargeContext( CRYPT_CONTEXT *cryptContext )
	{
	CRYPT_PKCINFO_RSA *rsaKey;
	int status;

	/* Allocate room for the key components */
	if( ( rsaKey = ( CRYPT_PKCINFO_RSA * ) malloc( sizeof( CRYPT_PKCINFO_RSA ) ) ) == NULL )
		return( CRYPT_NOMEM );

	/* Create the private-key context */
	status = cryptCreateContext( cryptContext, CRYPT_ALGO_RSA, CRYPT_MODE_PKC );
	if( cryptStatusError( status ) )
		{
		free( rsaKey );
		printf( "cryptCreateContext() failed with error code %d.\n", status );
		return( FALSE );
		}
	cryptInitComponents( rsaKey, CRYPT_COMPONENTS_BIGENDIAN,
						 CRYPT_KEYTYPE_PRIVATE );
	cryptSetComponent( rsaKey->n, rsa768TestKey.n, rsa768TestKey.nLen );
	cryptSetComponent( rsaKey->e, rsa768TestKey.e, rsa768TestKey.eLen );
	cryptSetComponent( rsaKey->d, rsa768TestKey.d, rsa768TestKey.dLen );
	cryptSetComponent( rsaKey->p, rsa768TestKey.p, rsa768TestKey.pLen );
	cryptSetComponent( rsaKey->q, rsa768TestKey.q, rsa768TestKey.qLen );
	cryptSetComponent( rsaKey->u, rsa768TestKey.u, rsa768TestKey.uLen );
	cryptSetComponent( rsaKey->e1, rsa768TestKey.e1, rsa768TestKey.e1Len );
	cryptSetComponent( rsaKey->e2, rsa768TestKey.e2, rsa768TestKey.e2Len );
	status = cryptLoadKey( *cryptContext, rsaKey, CRYPT_UNUSED );
	cryptDestroyComponents( rsaKey );
	free( rsaKey );
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( *cryptContext );
		printf( "cryptLoadKey() failed with error code %d.\n", status );
		return( FALSE );
		}

	return( TRUE );
	}

BOOLEAN loadDSAContexts( CRYPT_CONTEXT *signContext,
						 CRYPT_CONTEXT *sigCheckContext )
	{
	CRYPT_PKCINFO_DSA *dsaKey;
	int status;

	/* Allocate room for the public-key components */
	if( ( dsaKey = ( CRYPT_PKCINFO_DSA * ) malloc( sizeof( CRYPT_PKCINFO_DSA ) ) ) == NULL )
		return( CRYPT_NOMEM );

	/* Create the encryption context */
	if( signContext != NULL )
		{
		status = cryptCreateContext( signContext, CRYPT_ALGO_DSA,
									 CRYPT_MODE_PKC );
		if( cryptStatusError( status ) )
			{
			free( dsaKey );
			printf( "cryptCreateContext() failed with error code %d.\n",
					status );
			return( FALSE );
			}
		cryptInitComponents( dsaKey, CRYPT_COMPONENTS_BIGENDIAN,
							 CRYPT_KEYTYPE_PRIVATE );
		cryptSetComponent( dsaKey->p, dsaTestKey.p, dsaTestKey.pLen );
		cryptSetComponent( dsaKey->q, dsaTestKey.q, dsaTestKey.qLen );
		cryptSetComponent( dsaKey->g, dsaTestKey.g, dsaTestKey.gLen );
		cryptSetComponent( dsaKey->x, dsaTestKey.x, dsaTestKey.xLen );
		cryptSetComponent( dsaKey->y, dsaTestKey.y, dsaTestKey.yLen );
		status = cryptLoadKey( *signContext, dsaKey, CRYPT_UNUSED );
		cryptDestroyComponents( dsaKey );
		if( cryptStatusError( status ) )
			{
			free( dsaKey );
			cryptDestroyContext( *signContext );
			printf( "cryptLoadKey() failed with error code %d.\n", status );
			return( FALSE );
			}
		if( sigCheckContext == NULL )
			{
			free( dsaKey );
			return( TRUE );
			}
		}

	/* Create the decryption context */
	status = cryptCreateContext( sigCheckContext, CRYPT_ALGO_DSA, CRYPT_MODE_PKC );
	if( cryptStatusError( status ) )
		{
		free( dsaKey );
		cryptDestroyContext( *sigCheckContext );
		printf( "cryptCreateContext() failed with error code %d.\n", status );
		return( FALSE );
		}
	cryptInitComponents( dsaKey, CRYPT_COMPONENTS_BIGENDIAN,
						 CRYPT_KEYTYPE_PUBLIC );
	cryptSetComponent( dsaKey->p, dsaTestKey.p, dsaTestKey.pLen );
	cryptSetComponent( dsaKey->q, dsaTestKey.q, dsaTestKey.qLen );
	cryptSetComponent( dsaKey->g, dsaTestKey.g, dsaTestKey.gLen );
	cryptSetComponent( dsaKey->y, dsaTestKey.y, dsaTestKey.yLen );
	status = cryptLoadKey( *sigCheckContext, dsaKey, CRYPT_UNUSED );
	cryptDestroyComponents( dsaKey );
	free( dsaKey );
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( *signContext );
		cryptDestroyContext( *sigCheckContext );
		printf( "cryptLoadKey() failed with error code %d.\n", status );
		return( FALSE );
		}

	return( TRUE );
	}

BOOLEAN loadElgamalContexts( CRYPT_CONTEXT *cryptContext,
							 CRYPT_CONTEXT *decryptContext )
	{
	CRYPT_PKCINFO_ELGAMAL *elgamalKey;
	int status;

	/* Allocate room for the public-key components */
	if( ( elgamalKey = ( CRYPT_PKCINFO_ELGAMAL * ) malloc( sizeof( CRYPT_PKCINFO_ELGAMAL ) ) ) == NULL )
		return( CRYPT_NOMEM );

	/* Create the encryption context */
	status = cryptCreateContext( cryptContext, CRYPT_ALGO_ELGAMAL, CRYPT_MODE_PKC );
	if( cryptStatusError( status ) )
		{
		free( elgamalKey );
		printf( "cryptCreateContext() failed with error code %d.\n", status );
		return( FALSE );
		}
	cryptInitComponents( elgamalKey, CRYPT_COMPONENTS_BIGENDIAN,
						 CRYPT_KEYTYPE_PUBLIC );
	cryptSetComponent( elgamalKey->p, elgamalTestKey.p, elgamalTestKey.pLen );
	cryptSetComponent( elgamalKey->g, elgamalTestKey.g, elgamalTestKey.gLen );
	cryptSetComponent( elgamalKey->y, elgamalTestKey.y, elgamalTestKey.yLen );
	status = cryptLoadKey( *cryptContext, elgamalKey, CRYPT_UNUSED );
	cryptDestroyComponents( elgamalKey );
	if( cryptStatusError( status ) )
		{
		free( elgamalKey );
		cryptDestroyContext( *cryptContext );
		printf( "cryptLoadKey() failed with error code %d.\n", status );
		return( FALSE );
		}
	if( decryptContext == NULL )
		{
		free( elgamalKey );
		return( TRUE );
		}

	/* Create the decryption context */
	status = cryptCreateContext( decryptContext, CRYPT_ALGO_ELGAMAL, CRYPT_MODE_PKC );
	if( cryptStatusError( status ) )
		{
		free( elgamalKey );
		cryptDestroyContext( *cryptContext );
		printf( "cryptCreateContext() failed with error code %d.\n", status );
		return( FALSE );
		}
	cryptInitComponents( elgamalKey, CRYPT_COMPONENTS_BIGENDIAN,
						 CRYPT_KEYTYPE_PRIVATE );
	cryptSetComponent( elgamalKey->p, elgamalTestKey.p, elgamalTestKey.pLen );
	cryptSetComponent( elgamalKey->g, elgamalTestKey.g, elgamalTestKey.gLen );
	cryptSetComponent( elgamalKey->y, elgamalTestKey.y, elgamalTestKey.yLen );
	cryptSetComponent( elgamalKey->x, elgamalTestKey.x, elgamalTestKey.xLen );
	status = cryptLoadKey( *decryptContext, elgamalKey, CRYPT_UNUSED );
	cryptDestroyComponents( elgamalKey );
	free( elgamalKey );
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( *cryptContext );
		cryptDestroyContext( *decryptContext );
		printf( "cryptLoadKey() failed with error code %d.\n", status );
		return( FALSE );
		}

	return( TRUE );
	}

/* Load Diffie-Hellman encrytion contexts */

BOOLEAN loadDHContexts( CRYPT_CONTEXT *cryptContext1,
						CRYPT_CONTEXT *cryptContext2, int keySize )
	{
	CRYPT_PKCINFO_DH *dhKey;
	int status;

	/* Allocate room for the public-key components */
	if( ( dhKey = ( CRYPT_PKCINFO_DH * ) malloc( sizeof( CRYPT_PKCINFO_DH ) ) ) == NULL )
		return( CRYPT_NOMEM );

	/* Create the first encryption context */
	status = cryptCreateContext( cryptContext1, CRYPT_ALGO_DH, CRYPT_MODE_PKC );
	if( cryptStatusError( status ) )
		{
		free( dhKey );
		printf( "cryptCreateContext() failed with error code %d.\n", status );
		return( FALSE );
		}
	cryptInitComponents( dhKey, keySize, CRYPT_UNUSED );
	status = cryptLoadKey( *cryptContext1, dhKey, CRYPT_UNUSED );
	cryptDestroyComponents( dhKey );
	if( cryptStatusError( status ) )
		{
		free( dhKey );
		printf( "cryptLoadKey() failed with error code %d.\n", status );
		return( FALSE );
		}
	if( cryptContext2 == NULL )
		{
		free( dhKey );
		return( TRUE );
		}

	/* Create the second encryption context */
	status = cryptCreateContext( cryptContext2, CRYPT_ALGO_DH, CRYPT_MODE_PKC );
	if( cryptStatusError( status ) )
		{
		free( dhKey );
		printf( "cryptCreateContext() failed with error code %d.\n", status );
		return( FALSE );
		}
	cryptInitComponents( dhKey, keySize, CRYPT_UNUSED );
	status = cryptLoadKey( *cryptContext2, dhKey, CRYPT_UNUSED );
	cryptDestroyComponents( dhKey );
	free( dhKey );
	if( cryptStatusError( status ) )
		{
		printf( "cryptLoadKey() failed with error code %d.\n", status );
		return( FALSE );
		}

	return( TRUE );
	}

/* Destroy the encryption contexts */

void destroyContexts( CRYPT_CONTEXT cryptContext, CRYPT_CONTEXT decryptContext )
	{
	int status;

	status = cryptDestroyContext( cryptContext );
	if( cryptStatusError( status ) )
		printf( "cryptDestroyContext() failed with error code %d.\n", status );
	status = cryptDestroyContext( decryptContext );
	if( cryptStatusError( status ) )
		printf( "cryptDestroyContext() failed with error code %d.\n", status );
	}

/****************************************************************************
*																			*
*							Low-level Routines Test							*
*																			*
****************************************************************************/

#if defined( TEST_LOWLEVEL ) || defined( TEST_DEVICE )

/* Perform a test en/decryption */

static void testCrypt( CRYPT_CONTEXT cryptContext, CRYPT_CONTEXT decryptContext,
					   BYTE *buffer )
	{
	CRYPT_QUERY_INFO cryptQueryInfo;
	BYTE iv[ CRYPT_MAX_IVSIZE ];
	int status;

	/* Find out about the algorithm we're using */
	cryptQueryContext( cryptContext, &cryptQueryInfo );
	if( cryptQueryInfo.cryptMode == CRYPT_MODE_CFB ||
		cryptQueryInfo.cryptMode == CRYPT_MODE_OFB ||
		cryptQueryInfo.cryptMode == CRYPT_MODE_STREAM )
		{
		/* Encrypt the buffer in two odd-sized chunks */
		status = cryptEncrypt( cryptContext, buffer, 79 );
		if( cryptStatusError( status ) )
			printf( "Couldn't encrypt data: Code %d.\n", status );
		status = cryptEncrypt( cryptContext, buffer + 79, TESTBUFFER_SIZE - 79 );
		if( cryptStatusError( status ) )
			printf( "Couldn't encrypt data: Code %d.\n", status );

		/* Copy the IV from the encryption to the decryption context if
		   necessary */
		if( cryptQueryInfo.cryptMode != CRYPT_MODE_STREAM )
			{
			status = cryptRetrieveIV( cryptContext, iv );
			if( cryptStatusError( status ) )
				printf( "Couldn't retrieve IV after encryption: Code %d.\n",
						status );
			status = cryptLoadIV( decryptContext, iv, cryptQueryInfo.ivSize );
			if( cryptStatusError( status ) )
				printf( "Couldn't load IV for decryption: Code %d.\n", status );
			}

		/* Decrypt the buffer in different odd-size chunks */
		status = cryptDecrypt( decryptContext, buffer, 125 );
		if( cryptStatusError( status ) )
			printf( "Couldn't decrypt data: Code %d.\n", status );
		status = cryptDecrypt( decryptContext, buffer + 125, TESTBUFFER_SIZE - 125 );
		if( cryptStatusError( status ) )
			printf( "Couldn't decrypt data: Code %d.\n", status );

		return;
		}
	if( cryptQueryInfo.cryptMode == CRYPT_MODE_ECB ||
		cryptQueryInfo.cryptMode == CRYPT_MODE_CBC )
		{
		/* Encrypt the buffer in two odd-sized chunks */
		status = cryptEncrypt( cryptContext, buffer, 80 );
		if( cryptStatusError( status ) )
			printf( "Couldn't encrypt data: Code %d.\n", status );
		status = cryptEncrypt( cryptContext, buffer + 80, TESTBUFFER_SIZE - 80 );
		if( cryptStatusError( status ) )
			printf( "Couldn't encrypt data: Code %d.\n", status );
		status = cryptEncrypt( cryptContext, buffer + TESTBUFFER_SIZE, 0 );

		/* Copy the IV from the encryption to the decryption context if
		   necessary */
		if( cryptQueryInfo.cryptMode != CRYPT_MODE_ECB )
			{
			status = cryptRetrieveIV( cryptContext, iv );
			if( cryptStatusError( status ) )
				printf( "Couldn't retrieve IV after encryption: Code %d.\n",
						status );
			status = cryptLoadIV( decryptContext, iv, cryptQueryInfo.ivSize );
			if( cryptStatusError( status ) )
				printf( "Couldn't load IV for decryption: Code %d.\n", status );
			status = cryptEncrypt( cryptContext, buffer + TESTBUFFER_SIZE, 0 );
			}

		/* Decrypt the buffer in different odd-size chunks */
		status = cryptDecrypt( decryptContext, buffer, 128 );
		if( cryptStatusError( status ) )
			printf( "Couldn't decrypt data: Code %d.\n", status );
		status = cryptDecrypt( decryptContext, buffer + 128, TESTBUFFER_SIZE - 128 );
		if( cryptStatusError( status ) )
			printf( "Couldn't decrypt data: Code %d.\n", status );
		status = cryptDecrypt( decryptContext, buffer + TESTBUFFER_SIZE, 0 );

		return;
		}
	if( cryptQueryInfo.cryptMode == CRYPT_MODE_PKC )
		{
		/* To ensure that the magnitude of the integer corresponding to the
		   data to be encrypted is less than the modulus (in the case of
		   RSA), we set the first byte of the buffer to 1.  This is only
		   required for this test code which uses a set data pattern and
		   isn't necessary for the usual mid-level calls like
		   cryptExportKey() */
		int ch = buffer[ 0 ];

		/* Since the PKC algorithms only handle a single block, we only
		   perform a single encrypt and decrypt operation */
		buffer[ 0 ] = 1;
		status = cryptEncrypt( cryptContext, buffer, CRYPT_USE_DEFAULT );
		if( cryptStatusError( status ) )
			printf( "Couldn't encrypt data: Code %d.\n", status );
		status = cryptDecrypt( decryptContext, buffer, CRYPT_USE_DEFAULT );
		if( cryptStatusError( status ) )
			printf( "Couldn't decrypt data: Code %d.\n", status );
		buffer[ 0 ] = ch;
		return;
		}
	if( cryptQueryInfo.cryptMode == CRYPT_MODE_NONE )
		{
		/* Hash the buffer in two odd-sized chunks */
		status = cryptEncrypt( cryptContext, buffer, 80 );
		if( cryptStatusError( status ) )
			printf( "Couldn't hash data: Code %d.\n", status );
		status = cryptEncrypt( cryptContext, buffer + 80, TESTBUFFER_SIZE - 80 );
		if( cryptStatusError( status ) )
			printf( "Couldn't hash data: Code %d.\n", status );
		status = cryptEncrypt( cryptContext, buffer + TESTBUFFER_SIZE, 0 );

		/* Hash the buffer in different odd-size chunks */
		status = cryptEncrypt( decryptContext, buffer, 128 );
		if( cryptStatusError( status ) )
			printf( "Couldn't hash data: Code %d.\n", status );
		status = cryptEncrypt( decryptContext, buffer + 128, TESTBUFFER_SIZE - 128 );
		if( cryptStatusError( status ) )
			printf( "Couldn't hash data: Code %d.\n", status );
		status = cryptEncrypt( decryptContext, buffer + TESTBUFFER_SIZE, 0 );

		return;
		}

	puts( "Unknown encryption mode found in test code." );
	}

/* Sample code to test an algorithm/mode implementation */

int testLowlevel( const CRYPT_DEVICE cryptDevice, const CRYPT_ALGO cryptAlgo,
				  const CRYPT_MODE cryptMode )
	{
	BYTE buffer[ TESTBUFFER_SIZE ], testBuffer[ TESTBUFFER_SIZE ];
	CRYPT_CONTEXT cryptContext, decryptContext;
	CRYPT_QUERY_INFO cryptQueryInfo, decryptQueryInfo;
	int status;

	/* Initialise the test buffers */
	initTestBuffers( buffer, testBuffer );

	/* Check the capabilities of the library */
	if( !checkLowlevelInfo( cryptDevice, cryptAlgo, cryptMode ) )
		return( FALSE );

	/* Since DH only performs a key agreement rather than a true key
	   exchange, we can't test its encryption capabilities */
	if( cryptAlgo == CRYPT_ALGO_DH )
		return( TRUE );

	/* Set up an encryption context, load a user key into it, and perform a
	   key setup */
	switch( cryptAlgo )
		{
		case CRYPT_ALGO_DES:
			if( !loadContexts( &cryptContext, &decryptContext, cryptDevice,
							   cryptAlgo, cryptMode, ( BYTE * ) "12345678", 8 ) )
				return( FALSE );
			break;

		case CRYPT_ALGO_SKIPJACK:
			if( !loadContexts( &cryptContext, &decryptContext, cryptDevice,
							   cryptAlgo, cryptMode, ( BYTE * ) "1234567890", 10 ) )
				return( FALSE );
			break;

		case CRYPT_ALGO_CAST:
		case CRYPT_ALGO_IDEA:
		case CRYPT_ALGO_SAFER:
			if( !loadContexts( &cryptContext, &decryptContext, cryptDevice,
							   cryptAlgo, cryptMode, ( BYTE * ) "1234567887654321", 16 ) )
				return( FALSE );
			break;

		case CRYPT_ALGO_3DES:
			if( !loadContexts( &cryptContext, &decryptContext, cryptDevice,
							   cryptAlgo, cryptMode, ( BYTE * ) "123456788765432112345678", 24 ) )
				return( FALSE );
			break;

		case CRYPT_ALGO_RC2:
		case CRYPT_ALGO_RC4:
		case CRYPT_ALGO_RC5:
		case CRYPT_ALGO_BLOWFISH:
		case CRYPT_ALGO_HMAC_MD5:
		case CRYPT_ALGO_HMAC_SHA:
		case CRYPT_ALGO_HMAC_RIPEMD160:
			if( !loadContexts( &cryptContext, &decryptContext, cryptDevice,
							   cryptAlgo, cryptMode,
							   ( BYTE * ) "1234567890098765432112345678900987654321", 40 ) )
				return( FALSE );
			break;

		case CRYPT_ALGO_MD2:
		case CRYPT_ALGO_MD4:
		case CRYPT_ALGO_MD5:
		case CRYPT_ALGO_SHA:
		case CRYPT_ALGO_RIPEMD160:
		case CRYPT_ALGO_MDC2:
			if( !loadContexts( &cryptContext, &decryptContext, cryptDevice,
							   cryptAlgo, cryptMode, ( BYTE * ) "", 0 ) )
				return( FALSE );
			break;

		case CRYPT_ALGO_RSA:
			if( !loadRSAContexts( cryptDevice, &cryptContext, &decryptContext ) )
				return( FALSE );
			break;

		case CRYPT_ALGO_DSA:
			if( !loadDSAContexts( &cryptContext, &decryptContext ) )
				return( FALSE );
			break;

		case CRYPT_ALGO_ELGAMAL:
			if( !loadElgamalContexts( &cryptContext, &decryptContext ) )
				return( FALSE );
			break;

		default:
			printf( "Unknown encryption algorithm ID %d, cannot perform "
					"encryption test\n", cryptAlgo );
			return( FALSE );
		}

	/* Some "encryption" algorithms are a bit odd and can't be tested in the
	   same way as most other algorithms, so we test them seperately */
	if( cryptAlgo != CRYPT_ALGO_DSA )
		{
		/* Perform a test en/decryption */
		testCrypt( cryptContext, decryptContext, buffer );

		/* Make sure everything went OK */
		if( ( status = cryptQueryContext( cryptContext, &cryptQueryInfo ) ) == CRYPT_OK )
			status = cryptQueryContext( decryptContext, &decryptQueryInfo );
		if( cryptQueryInfo.cryptMode == CRYPT_MODE_NONE )
			{
			if( cryptStatusError( status ) )
				printf( "Couldn't get hash information: Code %d\n", status );
			else
				if( memcmp( cryptQueryInfo.hashValue, decryptQueryInfo.hashValue, \
							cryptQueryInfo.blockSize ) )
					puts( "Error: Hash value of identical buffers differs." );
			}
		else
			checkTestBuffers( buffer, testBuffer );
		}
	else
		{
		/* DSA works in a somewhat odd manner and isn't really meant to be
		   called from user code */
		memcpy( buffer, "01234567890123456789", 20 );
		status = cryptEncrypt( cryptContext, buffer, CRYPT_USE_DEFAULT );
		if( cryptStatusError( status ) )
			{
			/* Use of DSA requires that the randomness-gathering code is
			   functional, if we fail at this point with a CRYPT_NORANDOM
			   then it isn't really a problem in the DSA code */
			if( status == CRYPT_NORANDOM )
				puts( "  The DSA sign operation failed because no random "
					  "data is available (the\n  randomness self-test will "
					  "give more information on this problem)." );
			else
				printf( "Couldn't sign data: Code %d.\n", status );
			}
		else
			{
			/* Move the signature up in the buffer to make room for the hash
			   (this is a kludge for code which isn't normally called by the
			   user) */
			memmove( buffer + 20, buffer, 64 );
			memcpy( buffer, "01234567890123456789", 20 );
			status = cryptDecrypt( decryptContext, buffer, CRYPT_USE_DEFAULT );
			if( cryptStatusError( status ) )
				printf( "Couldn't verify signature on data: Code %d.\n",
						status );
			}
		}

	/* Clean up */
	destroyContexts( cryptContext, decryptContext );
	return( TRUE );
	}
#endif /* TEST_LOWLEVEL || TEST_DEVICE */

/****************************************************************************
*																			*
*								Misc.Kludges								*
*																			*
****************************************************************************/

#if 0	/* Kludge to check file hash */
{
CRYPT_CONTEXT cryptContext;
CRYPT_QUERY_INFO cryptQueryInfo;
FILE *filePtr = fopen( "g:test.dat", "rb" );
BYTE buffer[ 512 ];
long LENGTH = 0x123E0L;
long count = 0;
int status;

/*
{
const int delta = 0;

LENGTH -= delta;
fseek( filePtr, delta, SEEK_SET );
}
*/
status = cryptCreateContext( &cryptContext, CRYPT_ALGO_MD5, CRYPT_MODE_NONE );
/*
{
const int STARTSIZE = 0x120;
const int PREHOLE = 0x118;
const int HOLESIZE = STARTSIZE - PREHOLE;

fread( buffer, 1, PREHOLE, filePtr );
cryptEncrypt( cryptContext, buffer, PREHOLE );
fseek( filePtr, HOLESIZE, SEEK_CUR );
count += STARTSIZE;
}
*/
while( count < LENGTH )
	{
	int readCount = ( LENGTH - count ) > 512 ? 512 : ( int )( LENGTH - count );

if( readCount < 512 )
	{ readCount <<= 1; readCount /= 2; }

	fread( buffer, 1, readCount, filePtr );
	status = cryptEncrypt( cryptContext, buffer, readCount );
	count += readCount;
	}
fclose( filePtr );
status = cryptEncrypt( cryptContext, "", 0 );
status = cryptQueryContext( cryptContext, &cryptQueryInfo );
status = cryptDestroyContext( cryptContext );
if( status );
}
#endif

/****************************************************************************
*																			*
*								Main Test Code								*
*																			*
****************************************************************************/

#if defined( _WINDOWS ) || defined( WIN32 ) || defined( _WIN32 )
  #define __WINDOWS__
  #define INC_CHILD
#endif /* _WINDOWS || WIN32 || _WIN32 */

/* Exercise various aspects of cryptlib */

int main( int argc, char **argv )
	{
#ifdef TEST_LOWLEVEL
	CRYPT_ALGO cryptAlgo;
#endif /* TEST_LOWLEVEL */
#ifdef TEST_CONFIG
	int i;
#endif /* TEST_CONFIG */
	int status;
	void testSystemSpecific( void );

	/* Get rid of compiler warnings */
	if( argc || argv );

	/* Make sure various system-specific features are set right */
	testSystemSpecific();

	/* VisualAge C++ doesn't set the TZ correctly */
#if defined( __IBMC__ ) || defined( __IBMCPP__ )
	tzset();
#endif /* VisualAge C++ */

	/* Initialise cryptlib.  To speed up the startup time, we only call
	   cryptInitEx() if the low-level functions are being tested,
	   presumably once these have been tested exhaustively the code isn't
	   going to break itself */
#if defined( TEST_LOWLEVEL )
	status = cryptInitEx();
#else
	status = cryptInit();
#endif /* TEST_LOWLEVEL */
	if( cryptStatusError( status ) )
		{
		printf( "cryptInit() failed with error code %d.\n", status );
		exit( EXIT_FAILURE );
		}

#ifndef TEST_RANDOM
	/* In order to avoid having to do a randomness poll for every test run,
	   we bypass the randomness-handling by adding some junk - it doesn't
	   matter here because we're not worried about security, but should never
	   be done in production code */
	cryptAddRandom( "a", 1 );
#endif /* TEST_RANDOM */

/*!!!!!!!!!!!!!!!!!!!!!!!!*/
#if 0
{
/*status = testSessionSSH();*/
/*status = testSessionSSL();*/
}
#endif /* 0 */
/*!!!!!!!!!!!!!!!!!!!!!!!!*/

#ifdef TEST_LOWLEVEL
	/* Test the conventional encryption routines */
	for( cryptAlgo = CRYPT_ALGO_FIRST_CONVENTIONAL;
		 cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL; cryptAlgo++ )
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, CRYPT_UNUSED, NULL ) ) )
			{
			CRYPT_MODE cryptMode;

			for( cryptMode = CRYPT_MODE_FIRST_CONVENTIONAL;
				 cryptMode <= CRYPT_MODE_LAST_CONVENTIONAL; cryptMode++ )
				if( cryptStatusOK( cryptQueryCapability( cryptAlgo, cryptMode, NULL ) ) && \
					!testLowlevel( CRYPT_UNUSED, cryptAlgo, cryptMode ) )
					goto errorExit;
			}

	/* Test the public-key encryption routines */
	for( cryptAlgo = CRYPT_ALGO_FIRST_PKC;
		 cryptAlgo <= CRYPT_ALGO_LAST_PKC; cryptAlgo++ )
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, CRYPT_UNUSED, NULL ) ) && \
			!testLowlevel( CRYPT_UNUSED, cryptAlgo, CRYPT_MODE_PKC ) )
				goto errorExit;

	/* Test the hash routines */
	for( cryptAlgo = CRYPT_ALGO_FIRST_HASH;
		 cryptAlgo <= CRYPT_ALGO_LAST_HASH; cryptAlgo++ )
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, CRYPT_UNUSED, NULL ) ) && \
			!testLowlevel( CRYPT_UNUSED, cryptAlgo, CRYPT_MODE_NONE ) )
			goto errorExit;

	/* Test the MAC routines */
	for( cryptAlgo = CRYPT_ALGO_FIRST_MAC;
		 cryptAlgo <= CRYPT_ALGO_LAST_MAC; cryptAlgo++ )
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, CRYPT_UNUSED, NULL ) ) && \
			!testLowlevel( CRYPT_UNUSED, cryptAlgo, CRYPT_MODE_NONE ) )
			goto errorExit;

	putchar( '\n' );
#else
	puts( "Skipping test of low-level encryption routines...\n" );
#endif /* TEST_LOWLEVEL */

	/* Test the randomness-gathering routines */
#ifdef TEST_RANDOM
	if( !testRandomRoutines() )
		{
		puts( "The self-test will proceed without using a strong random "
			  "number source.\n" );

		/* Kludge the randomness routines so we can continue the self-tests */
		cryptAddRandom( "a", 1 );
		}
#else
	puts( "Skipping test of randomness routines...\n" );
#endif /* TEST_RANDOM */

	/* Test the configuration options routines */
#ifdef TEST_CONFIG
	for( i = 0; configOption[ i ].option != CRYPT_OPTION_NONE; i++ )
		{
		if( configOption[ i ].isNumeric )
			{
			int value;

			cryptGetOptionNumeric( configOption[ i ].option, &value );
			printf( "%s = %d.\n", configOption[ i ].name, value );
			}
		else
			{
			char buffer[ 256 ];
			int length;

			cryptGetOptionString( configOption[ i ].option, buffer, &length );
			printf( "%s = %s.\n", configOption[ i ].name, buffer );
			}
		}

	putchar( '\n' );
#else
	puts( "Skipping display of config options...\n" );
#endif /* TEST_CONFIG */

	/* Test the crypto device routines */
#ifdef TEST_DEVICE
	status = testDevices();
	if( status == CRYPT_ERROR )
		puts( "Handling for crypto devices doesn't appear to be enabled in "
			  "this build of\ncryptlib.\n" );
	else
		if( !status )
			goto errorExit;
#else
	puts( "Skipping test of crypto device routines...\n" );
#endif /* TEST_DEVICE */

	/* Test the mid-level routines.  This is implemented as a series of
	   separate function calls rather than a monolithic
	   if( a || b || c || ... ) block to make testing easier */
#ifdef TEST_MIDLEVEL
	if( !testDeriveKey() )
		goto errorExit;
	if( !testConventionalExportImport() )
		goto errorExit;
	if( !testKeyExportImport() )
		goto errorExit;
	if( !testSignData() )
		goto errorExit;
	if( !testKeyExchange() )
		goto errorExit;
	if( !testKeygen() )
		goto errorExit;
	if( !testKeygenAsync() )
		goto errorExit;
	/* No need for putchar, mid-level functions leave a blank line at end */
#else
	puts( "Skipping test of mid-level encryption routines...\n" );
#endif /* TEST_MIDLEVEL */

	/* Test the certificate management routines */
#ifdef TEST_CERT
	if( !testCert() )
		goto errorExit;
	if( !testCACert() )
		goto errorExit;
	if( !testComplexCert() )
		goto errorExit;
	if( !testSETCert() )
		goto errorExit;
	if( !testAttributeCert() )
		goto errorExit;
	if( !testCertRequest() )
		goto errorExit;
	if( !testComplexCertRequest() )
		goto errorExit;
	if( !testCRL() )
		goto errorExit;
	if( !testComplexCRL() )
		goto errorExit;
	if( !testCertChain() )
		goto errorExit;
	if( !testCMSAttributes() )
		goto errorExit;
	if( !testCertImport() )
		goto errorExit;
	if( !testCertReqImport() )
		goto errorExit;
	if( !testCRLImport() )
		goto errorExit;
	if( !testCertChainImport() )
		goto errorExit;
	if( !testSPKACImport() )
		goto errorExit;
#else
	puts( "Skipping test of certificate managment routines...\n" );
#endif /* TEST_CERT */

	/* Test the keyset read routines */
#ifdef TEST_KEYSET
	status = testGetPGPPublicKey();
	if( status == CRYPT_ERROR )
		puts( "Couldn't find key files, skipping test of\nPGP keyset read "
			  "routines...\n" );
	else
		{
		if( !status )
			goto errorExit;
		if( !testGetPGPPrivateKey() )
			goto errorExit;
		}
	if( !testReadWriteFileKey() )
		goto errorExit;
	if( !testReadFilePublicKey() )
		goto errorExit;
	if( !testUpdateFileKeyCert() )
		goto errorExit;
	if( !testReadFileCert() )
		goto errorExit;
	if( !testUpdateFileKeyCertChain() )
		goto errorExit;
	if( !testReadFileCertChain() )
		goto errorExit;
#ifdef TEST_KEYSET_SMARTCARD
	/* The following test is rather slow so we provide the ability to
	   disable this one separately */
	status = testWriteCardKey();
	if( status == CRYPT_ERROR )
		puts( "Couldn't access smart card reader, skipping test of\ncard key "
			  "read routines.\n" );
	else
		{
		if( !status )
			goto errorExit;
		if( !testReadCardKey() )
			goto errorExit;
		}
#endif /* TEST_KEYSET_SMARTCARD */
	status = testWriteCert();
	if( status == CRYPT_ERROR )
		puts( "Handling for certificate databases doesn't appear to be "
			  "enabled in this\nbuild of cryptlib, skipping the test of "
			  "the certificate database routines.\n" );
	else
		{
		if( !status )
			goto errorExit;
		if( !testReadCert() )
			goto errorExit;
		if( !testKeysetQuery() )
			goto errorExit;
		}
	status = testWriteCertLDAP();
	if( status == CRYPT_ERROR )
		puts( "Handling for LDAP certificate directories doesn't appear to "
			  "be enabled in\nthis build of cryptlib, skipping the test of "
			  "the certificate directory\nroutines.\n" );
	else
		/* LDAP access can fail if the directory doesn't use the standard
		   du jour, so we don't treat a failure as a fatal error */
		if( status )
			{
			if( !testReadCertLDAP() )
				goto errorExit;
			}
	status = testReadCertHTTP();
	if( status == CRYPT_ERROR )
		puts( "Handling for fetching certificates from web pages doesn't "
			  "appear to be\nenabled in this build of cryptlib, skipping "
			  "the test of the HTTP routines.\n" );
#else
	puts( "Skipping test of keyset read routines...\n" );
#endif /* TEST_KEYSET */

	/* Test the certificate processing functionality */
#ifdef TEST_CERTPROCESS
	if( !testCertProcess() )
		goto errorExit;
#else
	puts( "Skipping test of certificate handling process...\n" );
#endif /* TEST_CERTPROCESS */

	/* Test the high-level routines (these are similar to the mid-level
	   routines but rely on things like certificate management to work) */
#ifdef TEST_HIGHLEVEL
	if( !testKeyExportImportCMS() )
		goto errorExit;
	if( !testSignDataCMS() )
		goto errorExit;
#endif /* TEST_HIGHLEVEL */

	/* Test the enveloping routines */
#ifdef TEST_ENVELOPE
/*	if( !testEnvelopeData() )
		goto errorExit;
	if( !testEnvelopeSessionCrypt() )
		goto errorExit;
	if( !testEnvelopeCrypt() )
		goto errorExit;
	if( !testEnvelopePKCCrypt() )
		goto errorExit;
	if( !testEnvelopeSign() )
		goto errorExit;
*/	if( !testEnvelopePKCCrypt() )
		goto errorExit;
	if( !testCMSEnvelopePKCCrypt() )
		goto errorExit;
	if( !testCMSEnvelopeSign() )
		goto errorExit;
	if( !testCMSEnvelopeDetachedSig() )
		goto errorExit;
	if( !testCMSImportSignedData() )
		goto errorExit;
/*	if( testCMSImportEnvelopedData() )
		goto errorExit; */
#else
	puts( "Skipping test of enveloping routines...\n" );
#endif /* TEST_ENVELOPE */

	/* Shut down the library */
	status = cryptEnd();
	if( cryptStatusError( status ) )
		{
		printf( "cryptEnd() failed with error code %d.\n", status );
		exit( EXIT_FAILURE );
		}

	puts( "All tests concluded successfully." );
	return( EXIT_SUCCESS );

	/* All errors end up here */
#if defined( TEST_LOWLEVEL ) || defined( TEST_MIDLEVEL ) || \
	defined( TEST_DEVICE ) || defined( TEST_CERT ) || \
	defined( TEST_KEYSET ) || defined( TEST_CERTPROCESS ) || \
	defined( TEST_HIGHLEVEL ) || defined( TEST_ENVELOPE )
errorExit:
	cryptEnd();
	puts( "Tests aborted due to encryption library error." );
#ifdef __WINDOWS__
	/* The pseudo-CLI VC++ output windows are closed when the program exits
	   so we need to explicitly wait to allow the user to read them */
	puts( "Hit a key..." );
	getchar();
#endif /* __WINDOWS__ */
	return( EXIT_FAILURE );
#endif /* Test functions which require an error exit facility */
	}

/* Test the system-specific defines in crypt.h.  This is the last function in
   the file because we want to avoid any definitions in crypt.h messing with
   the rest of the test.c code.

   The following include is needed only so we can check whether the defines
   are set right.  crypt.h should never be included in a program which uses
   cryptlib */

#undef __WINDOWS__
#undef __WIN16__
#undef __WIN32__
#undef BOOLEAN
#undef BYTE
#undef FALSE
#undef TRUE
#ifdef _MSC_VER
  #include "../crypt.h"
#else
  #include "crypt.h"
#endif /* Braindamaged MSC include handling */

void testSystemSpecific( void )
	{
	int bigEndian;

	/* Make sure we've got the endianness set right.  If the machine is
	   big-endian (up to 64 bits) the following value will be signed,
	   otherwise it will be unsigned.  Unfortunately we can't test for
	   things like middle-endianness without knowing the size of the data
	   types */
	bigEndian = ( *( long * ) "\x80\x00\x00\x00\x00\x00\x00\x00" < 0 );
#ifdef DATA_LITTLEENDIAN
	if( bigEndian )
		{
		puts( "The CPU endianness define is set wrong in crypt.h, this "
			  "machine appears to be\nbig-endian, not little-endian.  Edit "
			  "the file and rebuild cryptlib." );
		exit( EXIT_FAILURE );
		}
#else
	if( !bigEndian )
		{
		puts( "The CPU endianness define is set wrong in crypt.h, this "
			  "machine appears to be\nlittle-endian, not big-endian.  Edit "
			  "the file and rebuild cryptlib." );
		exit( EXIT_FAILURE );
		}
#endif /* DATA_LITTLEENDIAN */

	/* If we're compiling under Windows or OS/2, make sure the LONG type is
	   correct */
#if defined( __WINDOWS__ ) || defined( __OS2__ )
	{
	LONG test = 0x80000000L;

	if( test < 0 )
		{
		puts( "typeof( LONG ) is incorrect.  It evaluates to a signed 32-bit "
			  "value rather\nthan an unsigned 32-bit value.  You need to edit "
			  "crypt.h and recompile \ncryptlib." );
		exit( EXIT_FAILURE );
		}
	}
#endif /* __WINDOWS__ || __OS2__ */
	}
