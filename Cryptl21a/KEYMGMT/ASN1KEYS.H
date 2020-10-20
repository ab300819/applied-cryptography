/****************************************************************************
*																			*
*				ASN.1 Key Management Structures and Prototypes 				*
*						Copyright Peter Gutmann 1992-1998					*
*																			*
****************************************************************************/

#ifndef _ASN1KEYS_DEFINED

#define _ASN1KEYS_DEFINED

#ifndef _STREAM_DEFINED
  #if defined( INC_ALL ) || defined( INC_CHILD )
	#include "stream.h"
  #else
	#include "keymgmt/stream.h"
  #endif /* Compiler-specific includes */
#endif /* _STREAM_DEFINED */

/* Generate a key ID for a public key */

int generateKeyID( const CRYPT_ALGO cryptAlgo, void *pkcInfo, BYTE *keyID );

/****************************************************************************
*																			*
*						Key Encode/Decode, Read/Write Routines				*
*																			*
****************************************************************************/

/* Read and write public keys in the X.509 SubjectPublicKeyInfo format and
   private keys in the cryptlib format.  The sizeof/write functions come in
   two variants, one which works with a context and one with the algorithm-
   specific key information structure (eg CRYPT_PKCINFO_DH).  The read
   functions can only read the data into this structure because the read may
   need to be performed in two parts, first to get the public portion of a
   key record and then the private portion, and we can't do a context load in
   two stages */

int sizeofPublicKey( const CRYPT_CONTEXT iCryptContext );
int readPublicKey( STREAM *stream, CRYPT_CONTEXT *iCryptContext );
int writePublicKey( STREAM *stream, const CRYPT_CONTEXT iCryptContext );
int readPrivateKey( STREAM *stream, CRYPT_CONTEXT *iCryptContext );
int writePrivateKey( STREAM *stream, const CRYPT_CONTEXT iCryptContext );

/* The following routines work with PKC_INFO structures which are only
   available to some modules.  Because of this, we only provide prototypes
   for these if we're being included into a module which has the PKC_INFO
   structure available */

#ifdef _CRYPTCTX_DEFINED

int sizeofPublicKeyInfo( const CRYPT_ALGO cryptAlgo, const PKC_INFO *pkcInfo );
int writePublicKeyInfo( STREAM *stream, const CRYPT_ALGO cryptAlgo,
						const PKC_INFO *pkcInfo );

#endif /* _CRYPTCTX_DEFINED */

/* Flat-file key conversion routines */

int readPrivateKeyBuffer( const BYTE *buffer, const char *password,
						  CRYPT_CONTEXT *iCryptContextPtr, BYTE *keyID,
						  const BOOLEAN publicComponentsOnly );
int writePrivateKeyBuffer( void **buffer, int *bufSize,
						   const CRYPT_CONTEXT cryptContext,
						   const char *password );
int convertPrivateKeyBuffer( void **buffer, int *bufSize,
							 const CRYPT_CERTIFICATE cryptCert,
							 const void *keyData );

/* External key format read functions */

int getKeysetType( STREAM *stream );
int pgpGetKey( STREAM *stream, const CRYPT_KEYID_TYPE keyIDtype,
			   const void *keyID, const char *password, void *keyData,
			   CRYPT_CONTEXT *iCryptContext, char *userID,
			   const BOOLEAN readPublicKey );
int x509GetKey( STREAM *stream, const CRYPT_KEYID_TYPE keyIDtype,
				const void *keyID, CRYPT_CONTEXT *iCryptContext,
				char *userID );
int netscapeGetKey( STREAM *stream, const char *password,
					CRYPT_CONTEXT *iCryptContext, char *userID );

#endif /* _ASN1KEYS_DEFINED */
