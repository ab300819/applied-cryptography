/****************************************************************************
*																			*
*				ASN.1 Object Identifier Structures and Prototypes 			*
*						Copyright Peter Gutmann 1992-1999					*
*																			*
****************************************************************************/

#ifndef _ASN1OID_DEFINED

#define _ASN1OID_DEFINED

#ifndef _STREAM_DEFINED
  #if defined( INC_ALL ) ||  defined( INC_CHILD )
	#include "stream.h"
  #else
	#include "keymgmt/stream.h"
  #endif /* Compiler-specific includes */
#endif /* _STREAM_DEFINED */

/* The maximum (encoded) object identifier size */

#define MAX_OID_SIZE		20

/* A macro to make make declaring OID's simpler */

#define MKOID( value )	( ( BYTE * ) value )

/* Data-type OIDs which are used in various places */

#define OID_CMS_DATA			MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x01" )
#define OID_CMS_SIGNEDDATA		MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x02" )
#define OID_CMS_ENVELOPEDDATA	MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x03" )
#define OID_CMS_DIGESTEDDATA	MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x05" )
#define OID_CMS_ENCRYPTEDDATA	MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x06" )
#define OID_NS_CERTSEQ			MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x02\x05" )
#define OID_CRYPTLIB_ENVELOPE	MKOID( "\x06\x09\x2B\x06\x01\x04\x01\x97\x55\x20\x01" )
#define OID_CRYPTLIB_PRIVATEKEY	MKOID( "\x06\x09\x2B\x06\x01\x04\x01\x97\x55\x20\x02" )
#define OID_CRYPTLIB_KEYWRAP	MKOID( "\x06\x09\x2B\x06\x01\x04\x01\x97\x55\x20\x03" )

/* The structure which is used to look up OIDs when reading a CMS header.  We
   step through an array of these checking each OID in turn, when we find a
   match we return the selection value */

typedef struct {
	const BYTE *oid;		/* OID */
	const int minVersion;	/* Minimum version number for content type */
	const int maxVersion;	/* Maximum version number for content type */
	const int selection;	/* Value to return for this OID */
	} OID_SELECTION;

/* AlgorithmIdentifier routines */

int sizeofAlgorithmIdentifier( const CRYPT_ALGO algorithm,
							   const CRYPT_ALGO subAlgorithm,
							   const int parameter, const int extraLength );
int writeAlgorithmIdentifier( STREAM *stream, const CRYPT_ALGO algorithm,
							  const CRYPT_ALGO subAlgorithm,
							  const int parameter, const int extraLength );
int readAlgorithmIdentifier( STREAM *stream, CRYPT_ALGO *cryptAlgo,
							 CRYPT_ALGO *cryptSubAlgo, int *parameter,
							 int *extraLength );

/* Alternative versions which read/write basic algorithm ID's from
   encryption contexts */

int sizeofContextAlgorithmIdentifier( const CRYPT_CONTEXT iCryptContext,
									  const CRYPT_ALGO subAlgorithm );
int writeContextAlgorithmIdentifier( STREAM *stream,
									 const CRYPT_CONTEXT iCryptContext,
									 const CRYPT_ALGO subAlgorithm );
int readContextAlgorithmIdentifier( STREAM *stream,
									CRYPT_CONTEXT *iCryptContext,
									CRYPT_ALGO *subAlgorithm );

/* Read/write general-purpose OIDs */

int readOID( STREAM *stream, const BYTE *oid );

/* Read/write CMS headers */

int readCMSheader( STREAM *stream, const OID_SELECTION *oidSelection,
				   long *dataSize );
void writeCMSheader( STREAM *stream, const BYTE *oid, const long dataSize );
int sizeofCMSencrHeader( const BYTE *contentOID, const long dataSize,
						 const CRYPT_CONTEXT iCryptContext );
int readCMSencrHeader( STREAM *stream, const OID_SELECTION *oidSelection,
					   long *dataSize, CRYPT_ALGO *algorithm,
					   CRYPT_MODE *mode, BYTE *iv, int *ivSize );
int writeCMSencrHeader( STREAM *stream, const BYTE *contentOID,
						const long dataSize,
						const CRYPT_CONTEXT iCryptContext );

#endif /* _ASN1OID_DEFINED */
