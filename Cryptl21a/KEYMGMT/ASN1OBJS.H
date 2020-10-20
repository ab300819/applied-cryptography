/****************************************************************************
*																			*
*				ASN.1 Object Management Structures and Prototypes 			*
*						Copyright Peter Gutmann 1992-1999					*
*																			*
****************************************************************************/

#ifndef _ASN1OBJS_DEFINED

#define _ASN1OBJS_DEFINED

#ifndef _STREAM_DEFINED
  #if defined( INC_ALL ) ||  defined( INC_CHILD )
	#include "stream.h"
  #else
	#include "keymgmt/stream.h"
  #endif /* Compiler-specific includes */
#endif /* _STREAM_DEFINED */

/* The default value for tagged types.  If this value is given the basic
   type is used, otherwise the value is used as a context-specific tag */

#ifndef DEFAULT_TAG
  #define DEFAULT_TAG			-1
#endif /* DEFAULT_TAG */

/* The ASN.1 MessageDigest type.  The isSHA1 algorithm-specific information
   field is a kludge which works for now since SHA-1 is the only algorithm
   with optional parameters */

typedef struct {
	CRYPT_ALGO type;				/* Message digest algorithm */
	BOOLEAN isSHA;					/* Set to TRUE for SHA rather than SHA1
									   if type is CRYPT_ALGO_SHA */
	BYTE data[ CRYPT_MAX_HASHSIZE ];/* Message digest */
	int length;						/* Length of MD data */
	} MESSAGE_DIGEST;

/****************************************************************************
*																			*
*						General ASN.1 Object Types Routines					*
*																			*
****************************************************************************/

/* Routines for handling message digests */

int newMessageDigest( MESSAGE_DIGEST *messageDigest, const CRYPT_ALGO mdAlgo,
					  const BYTE *md, const int length );
int deleteMessageDigest( MESSAGE_DIGEST *messageDigest );
int sizeofMessageDigest( const MESSAGE_DIGEST *messageDigest );
int writeMessageDigest( STREAM *stream, const MESSAGE_DIGEST *messageDigest,
						const int tag );
int readMessageDigest( STREAM *stream, MESSAGE_DIGEST *messageDigest );

/* Get information on a cryptlib object */

int queryObject( STREAM *stream, OBJECT_INFO *cryptObjectInfo );

/****************************************************************************
*																			*
*					Encryption-related ASN.1 Object Types Routines			*
*																			*
****************************************************************************/

/* The following routines work with CRYPT_INFO structures, which are only
   available to some modules.  Because of this, we only provide prototypes
   for these if we're being included into a module which has the CRYPT_INFO
   structure available */

#ifdef _CRYPTCTX_DEFINED

/* Routines for reading and writing session key information for
   encapsulation inside a RecipientInfo data block.  The first function
   writes only the header information (but not the key itself) for use in
   various locations which need to process encryption key information
   formatted in a standardised manner) */

int writeKeyInfoHeader( STREAM *stream, const CRYPT_INFO *cryptInfoPtr,
						const int keyLength, const int extraLength );
int sizeofKeyInfo( const CRYPT_INFO *cryptInfo, const BOOLEAN addPadding,
				   const RECIPIENT_TYPE recipientType );
int writeKeyInfo( STREAM *stream, const CRYPT_INFO *cryptInfoPtr,
				  int *keyOffset, const BOOLEAN addPadding,
				  const RECIPIENT_TYPE recipientType );
int readKeyInfo( STREAM *stream, CRYPT_CONTEXT *iCryptContext );

/* Routines for reading and writing various RecipientInfo records */

int writeKeyTransInfo( STREAM *stream, const CRYPT_INFO *cryptInfoPtr,
					   const BYTE *buffer, const int length,
					   const void *auxInfo, const int auxInfoLength,
					   const RECIPIENT_TYPE recipientType );
int readKeyTransInfo( STREAM *stream, OBJECT_INFO *cryptObjectInfo );
int writeKeyAgreeInfo( STREAM *stream, const CRYPT_INFO *cryptInfoPtr,
					   const CRYPT_INFO *sessionKeyInfo );
int readKeyAgreeInfo( STREAM *stream, OBJECT_INFO *cryptObjectInfo,
					  CRYPT_CONTEXT *iKeyAgreeContext,
					  CRYPT_CONTEXT *iSessionKeyContext );
int writeKEKInfo( STREAM *stream, const CRYPT_INFO *cryptInfoPtr,
				  const BYTE *buffer, const int length,
				  const RECIPIENT_TYPE recipientType );
int readKEKInfo( STREAM *stream, OBJECT_INFO *cryptObjectInfo, void *iv,
				 int *ivSize );

/* Routines for reading and writing signatures */

int writeSignature( STREAM *stream, const CRYPT_INFO *pkcInfo,
					const CRYPT_ALGO hashAlgo, const BYTE *buffer,
					const int length, const SIGNATURE_TYPE signatureType );
int readSignature( STREAM *stream, OBJECT_INFO *cryptObjectInfo,
				   const SIGNATURE_TYPE signatureType );

#endif /* _CRYPTCTX_DEFINED */

#endif /* _ASN1OBJS_DEFINED */
