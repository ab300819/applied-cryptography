/****************************************************************************
*																			*
*					  Cryptographic Message Syntax Routines					*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "asn1.h"
  #include "asn1objs.h"
  #include "asn1oid.h"
  #include "cert.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1objs.h"
  #include "keymgmt/asn1oid.h"
  #include "keymgmt/cert.h"
#endif /* Compiler-specific includes */

/* The CMS version number */

#define CMS_VERSION		1

/****************************************************************************
*																			*
*							Read/Write RecipientInfo						*
*																			*
****************************************************************************/

/****************************************************************************
*																			*
*								Read/Write SignerInfo						*
*																			*
****************************************************************************/

/* Read signed attributes */

int readCMSAttributes( STREAM *stream, CERT_INFO *attributeInfoPtr )
	{
	/* CMS attributes are straight attribute objects so we just pass the call
	   through */
	return( readAttributes( stream, &attributeInfoPtr->attributes,
							CRYPT_CERTTYPE_CMS_ATTRIBUTES,
							&attributeInfoPtr->errorLocus,
							&attributeInfoPtr->errorType ) );
	}

/* Read the information in a SignerInfo record */

int readSignerInfo( STREAM *stream, CRYPT_ALGO *hashAlgorithm,
					void **iAndSStart, void **attributes, int *attributeSize,
					void **signature )
	{
	OBJECT_INFO cryptObjectInfo;
	int status;

	*hashAlgorithm = CRYPT_ERROR;
	*attributes = *signature = NULL;
	*attributeSize = 0;

	/* Obtain the hash algorithm and issuer ID using the standard query
	   function */
	status = queryObject( stream, &cryptObjectInfo );
	if( cryptObjectInfo.formatType != CRYPT_FORMAT_CMS )
		status = CRYPT_BADDATA;
	if( cryptStatusError( status ) )
		return( status );
	*iAndSStart = cryptObjectInfo.iAndSStart;
	*hashAlgorithm = cryptObjectInfo.hashAlgo;

	/* Remember where the attributes and signature start.  Since
	   queryObject() resets the stream, we seek to the start of the payload
	   before we try to process anything */
	sseek( stream, ( BYTE * ) cryptObjectInfo.dataStart - sMemBufPtr( stream ) );
	if( peekTag( stream ) == MAKE_CTAG( 0 ) )
		{
		long length;

		*attributes = sMemBufPtr( stream );
		readTag( stream );
		readLength( stream, &length );
		*attributeSize = ( int ) sizeofObject( length );
		sSkip( stream, length );
		}
	*signature = sMemBufPtr( stream );
	zeroise( &cryptObjectInfo, sizeof( OBJECT_INFO ) );

	return( CRYPT_OK );
	}

/* Write signed attributes */

int writeCMSAttributes( STREAM *stream, CERT_INFO *attributeInfoPtr )
	{
	const BOOLEAN addDefaultAttributes = \
					getOptionNumeric( CRYPT_OPTION_CMS_DEFAULTATTRIBUTES );
	ATTRIBUTE_LIST *attributeListPtr;
	int attributeSize, status;

	/* Make sure there's a hash and content type present */
	if( findAttributeField( attributeInfoPtr->attributes,
							CRYPT_CERTINFO_CMS_MESSAGEDIGEST,
							CRYPT_CERTINFO_NONE ) == NULL )
		{
		setCertError( attributeInfoPtr, CRYPT_CERTINFO_CMS_MESSAGEDIGEST,
					  CRYPT_CERTERROR_ABSENT );
		return( CRYPT_INVALID );
		}
	attributeListPtr = findAttribute( attributeInfoPtr->attributes,
									  CRYPT_CERTINFO_CMS_CONTENTTYPE );
	if( attributeListPtr == NULL )
		{
		const int value = CRYPT_CONTENT_DATA;

		/* If there's no content type and we're not adding it automatically,
		   complain */
		if( !addDefaultAttributes )
			{
			setCertError( attributeInfoPtr, CRYPT_CERTINFO_CMS_CONTENTTYPE,
						  CRYPT_CERTERROR_ABSENT );
			return( CRYPT_INVALID );
			}

		/* There's no content type present, treat it as straight data (which
		   means this is signedData) */
		status = addCertComponent( attributeInfoPtr, CRYPT_CERTINFO_CMS_CONTENTTYPE,
								   &value, CRYPT_UNUSED );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If there's no signing time attribute present and we're adding the
	   default attributes, add it now */
	if( addDefaultAttributes && \
		( attributeListPtr = findAttribute( attributeInfoPtr->attributes,
							CRYPT_CERTINFO_CMS_SIGNINGTIME ) ) == NULL )
		{
		const time_t currentTime = time( NULL );

		status = addCertComponent( attributeInfoPtr, CRYPT_CERTINFO_CMS_SIGNINGTIME,
								   &currentTime, sizeof( time_t ) );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Check that the attributes are in order and determine how big the whole
	   mess will be */
	status = checkAttributes( ATTRIBUTE_CMS, attributeInfoPtr->attributes,
							  &attributeInfoPtr->errorLocus,
							  &attributeInfoPtr->errorType );
	if( cryptStatusError( status ) )
		return( status );
	attributeSize = sizeofAttributes( attributeInfoPtr->attributes );

	/* Write the attributes */
	return( writeAttributes( stream, attributeInfoPtr->attributes,
							 CRYPT_CERTTYPE_CMS_ATTRIBUTES, attributeSize ) );
	}

/* Write signer information:

	SignerInfo ::= SEQUENCE {
		version					INTEGER (1),
		issuerAndSerialNumber	IssuerAndSerialNumber,
		digestAlgorithm			AlgorithmIdentifier,
		signedAttrs		  [ 0 ]	IMPLICIT SET OF Attribute OPTIONAL,
		signatureAlgorithm		AlgorithmIdentifier,
		signature				OCTET STRING
		} */

int writeSignerInfo( STREAM *stream, CRYPT_CERTIFICATE certificate,
					 const CRYPT_ALGO hashAlgorithm,
					 const void *attributes, const int attributeSize,
					 const void *signature, const int signatureSize )
	{
	CERT_INFO *signerInfoPtr;
	int length;

	getCheckInternalResource( certificate, signerInfoPtr,
							  RESOURCE_TYPE_CERTIFICATE );

	/* Determine the size of the signerInfo information */
	length = sizeofShortInteger( CMS_VERSION ) +
			 sizeofIssuerAndSerialNumber( signerInfoPtr->issuerName,
				signerInfoPtr->serialNumber, signerInfoPtr->serialNumberLength ) +
			 sizeofAlgorithmIdentifier( hashAlgorithm, CRYPT_ALGO_NONE, 0, 0 ) +
			 attributeSize + signatureSize;

	/* Write the outer SEQUENCE wrapper and version number */
	writeSequence( stream, length );
	writeShortInteger( stream, CMS_VERSION, DEFAULT_TAG );

	/* Write the issuer name and serial number, and digest algorithm
	   identifier */
	writeIssuerAndSerialNumber( stream, signerInfoPtr->issuerName,
			signerInfoPtr->serialNumber, signerInfoPtr->serialNumberLength );
	writeAlgorithmIdentifier( stream, hashAlgorithm, CRYPT_ALGO_NONE, 0, 0 );

	/* Write the attributes and signature */
	swrite( stream, attributes, attributeSize );
	swrite( stream, signature, signatureSize );

	unlockResourceExit( signerInfoPtr, sGetStatus( stream ) );
	}
