/****************************************************************************
*																			*
*						 ASN.1 Object Management Routines					*
*						Copyright Peter Gutmann 1992-1999					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "cryptctx.h"
  #include "asn1.h"
  #include "asn1keys.h"
  #include "asn1objs.h"
  #include "asn1oid.h"
#elif defined( INC_CHILD )
  #include "../cryptctx.h"
  #include "asn1.h"
  #include "asn1keys.h"
  #include "asn1objs.h"
  #include "asn1oid.h"
#else
  #include "cryptctx.h"
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1keys.h"
  #include "keymgmt/asn1objs.h"
  #include "keymgmt/asn1oid.h"
#endif /* Compiler-specific includes */

/* Context-specific tags for the conventional-encrypted key record */

enum { CTAG_CK_DERIVATIONINFO, CTAG_CK_IV };

/* Context-specific tags for the KeyTrans record */

enum { CTAG_KT_SKI };

/* Context-specific tags for the RecipientInfo record.  KeyTrans has no tag
   (actually it has an implied 0 tag because of CMS misdesign, so the other
   tags start at 1) */

enum { CTAG_RI_KEYAGREE = 1, CTAG_RI_KEK };

/* Context-specific tags for the SignerInfo record */

enum { CTAG_SI_SKI };

/* CMS version numbers for various objects */

#define KEYTRANS_VERSION		0
#define KEYTRANS_EX_VERSION		2
#define KEK_VERSION				4
#define SIGNATURE_VERSION		1
#define SIGNATURE_EX_VERSION	3

/****************************************************************************
*																			*
*							Algorithm Parameter Routines					*
*																			*
****************************************************************************/

/* Evaluate the size of the algorithm information */

static int sizeofParameters( const CRYPT_INFO *cryptInfo )
	{
#if !( defined( NO_RC5 ) && defined( NO_SAFER ) )
	BOOLEAN boolean;
	long integer;

	/* If we're using parameterised algorithms with the default parameters,
	   nothing is encoded */
	if( !cryptInfo->ctxConv.nonDefaultValues )
		return( 0 );

	/* Determine the size of the optional parameters */
	switch( cryptInfo->capabilityInfo->cryptAlgo )
		{
#ifndef NO_RC5
		case CRYPT_ALGO_RC5:
			integer = getRC5info( cryptInfo );
			return( ( int ) sizeofObject( sizeofShortInteger( integer ) ) );
#endif /* NO_RC5 */

#ifndef NO_SAFER
		case CRYPT_ALGO_SAFER:
			integer = getSaferInfo( cryptInfo, &boolean );
			return( ( int ) sizeofObject( sizeofBoolean() +
										  sizeofShortInteger( integer ) ) );
#endif /* NO_SAFER */
		}
#else
	UNUSED( cryptInfo );
#endif /* !( NO_RC5 || NO_SAFER ) */

	return( 0 );
	}

static int sizeofAlgorithmInfo( const CRYPT_INFO *cryptInfo )
	{
	return( ( int ) sizeofObject( \
				sizeofEnumerated( cryptInfo->capabilityInfo->cryptAlgo ) +
				sizeofEnumerated( cryptInfo->capabilityInfo->cryptMode ) +
				sizeofParameters( cryptInfo ) ) );
	}

/* Write the algorithm information */

static void writeAlgorithmInfo( STREAM *stream,
								const CRYPT_INFO *cryptInfo )
	{
	const CAPABILITY_INFO *capabilityInfo = cryptInfo->capabilityInfo;

	/* First, write the header and algorithm ID fields */
	writeSequence( stream, sizeofEnumerated( capabilityInfo->cryptAlgo ) +
				   sizeofEnumerated( capabilityInfo->cryptMode ) +
				   sizeofParameters( cryptInfo ) );
	writeEnumerated( stream, capabilityInfo->cryptAlgo, DEFAULT_TAG );
	writeEnumerated( stream, capabilityInfo->cryptMode, DEFAULT_TAG );

#if !( defined( NO_RC5 ) && defined( NO_SAFER ) )
	/* Now write any algorithm-specific fields.  We've already checked
	   previously for unknown algorithms so we don't need to include a
	   default case for this here */
	if( cryptInfo->ctxConv.nonDefaultValues )
		{
		BOOLEAN boolean;
		long integer;

		switch( capabilityInfo->cryptAlgo )
			{
#ifndef NO_RC5
			case CRYPT_ALGO_RC5:
				integer = getRC5info( cryptInfo );
				writeSequence( stream, sizeofShortInteger( integer ) );
				writeShortInteger( stream, integer, DEFAULT_TAG );
				break;
#endif /* NO_RC5 */

#ifndef NO_SAFER
			case CRYPT_ALGO_SAFER:
				integer = getSaferInfo( cryptInfo, &boolean );
				writeSequence( stream, sizeofBoolean() +
							   sizeofShortInteger( integer ) );
				writeBoolean( stream, boolean, DEFAULT_TAG );
				writeShortInteger( stream, integer, DEFAULT_TAG );
				break;
#endif /* NO_SAFER */
			}
		}
#endif /* !( NO_RC5 || NO_SAFER ) */
	}

/* Read the algorithm information and either read it into an OBJECT_INFO
   structure or create an internal encryption context to hold it */

static int readAlgorithmInfo( STREAM *stream, CRYPT_CONTEXT *iCryptContext,
							  OBJECT_INFO *cryptObjectInfo )
	{
	CRYPT_ALGO cryptAlgo;
	CRYPT_MODE cryptMode;
	int length, status, temp;

	/* Clear the return value */
	if( iCryptContext != NULL )
		*iCryptContext = CRYPT_ERROR;

	/* Read header and algorithm ID and make sure we know what to do with
	   it */
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	length -= readEnumerated( stream, &temp );
	cryptAlgo = temp;	/* Kludge for IBM OS/2 compiler */
	length -= readEnumerated( stream, &temp );
	cryptMode = temp;	/* Kludge for IBM OS/2 compiler */
	if( cryptObjectInfo != NULL )
		{
		cryptObjectInfo->cryptAlgo = cryptAlgo;
		cryptObjectInfo->cryptMode = cryptMode;
		}
	if( sGetStatus( stream ) != CRYPT_OK )
		/* If there's an error with the stream, make sure we don't return a
		   badparam error in the next call due to misread data */
		return( sGetStatus( stream ) );
	if( cryptStatusError( status = cryptQueryCapability( cryptAlgo,
														 cryptMode, NULL ) ) )
		return( status );

	/* Create an encryption context to hold the encrypted data information if
	   required */
	if( iCryptContext != NULL )
		{
		if( cryptStatusError( status = iCryptCreateContext( iCryptContext,
												cryptAlgo, cryptMode ) ) )
			return( status );
		}

	/* Read the algorithm-specific parameters if necessary */
	if( length > 0 )
		{
#if !( defined( NO_RC5 ) && defined( NO_SAFER ) )
		CRYPT_INFO *cryptInfo;
		BOOLEAN boolean;
		long integer;
		void *cPtr;

		/* Lock the resource for use if necessary.  Note that the use of
		   getCheckInternalResource() (which returns if the resource can't be
		   located) is perfectly safe here since it will only return if the
		   resource doesn't exist, so there's no need to call
		   cryptDestroyContext() */
		if( iCryptContext != NULL )
			getCheckInternalResource( *iCryptContext, cryptInfo, RESOURCE_TYPE_CRYPT );

		/* Set up a pointer to the extended parameters area if necessary (we
		   can reuse the keyID memory because it's only used for PKC's) */
		if( cryptObjectInfo != NULL )
			{
			cryptObjectInfo->cryptContextExInfo = cryptObjectInfo->keyID;
			cPtr = cryptObjectInfo->cryptContextExInfo;
			}

		readSequence( stream, &length );
		switch( cryptAlgo )
			{
#ifndef NO_RC5
			case CRYPT_ALGO_RC5:
				readShortInteger( stream, &integer );
				if( iCryptContext == NULL )
					( ( CRYPT_INFO_RC5 * ) cPtr )->rounds = ( int ) integer;
				else
					setRC5info( cryptInfo, ( int ) integer );
				break;
#endif /* NO_RC5 */

#ifndef NO_SAFER
			case CRYPT_ALGO_SAFER:
				readBoolean( stream, &boolean );
				readShortInteger( stream, &integer );
				if( iCryptContext == NULL )
					{
					( ( CRYPT_INFO_SAFER * ) cPtr )->useSaferSK = boolean;
					( ( CRYPT_INFO_SAFER * ) cPtr )->rounds = ( int ) integer;
					}
				else
					setSaferInfo( cryptInfo, boolean, ( int ) integer );
				break;
#endif /* NO_SAFER */

			default:
				if( iCryptContext != NULL )
					{
					unlockResource( cryptInfo );
					iCryptDestroyObject( *iCryptContext );
					*iCryptContext = CRYPT_ERROR;
					}
				return( CRYPT_NOALGO );
			}

		/* Remember that we're using non-default algorithm parameters */
		if( iCryptContext != NULL )
			cryptInfo->ctxConv.nonDefaultValues = TRUE;
#else
		if( iCryptContext != NULL )
			{
			iCryptDestroyObject( *iCryptContext );
			*iCryptContext = CRYPT_ERROR;
			}
		return( CRYPT_NOALGO );
#endif /* !( NO_RC5 || NO_SAFER ) */
		}
	else
		/* No algorithm-specific parameters, use default settings */
		if( cryptObjectInfo != NULL )
			cryptObjectInfo->cryptContextExInfo = NULL;

	/* Clean up */
	if( sGetStatus( stream ) != CRYPT_OK && iCryptContext != NULL )
		{
		iCryptDestroyObject( *iCryptContext );
		*iCryptContext = CRYPT_ERROR;
		}
	return( sGetStatus( stream ) );
	}

/****************************************************************************
*																			*
*							Key Check Value Routines						*
*																			*
****************************************************************************/

/* Calculate a key check value */

int calculateKeyCheckValue( const CRYPT_INFO *cryptInfo, BYTE *checkValue )
	{
	STREAM stream;
	BYTE *buffer;
	const void *userKey;
	int dataLength, userKeyLength, status = CRYPT_OK;

	/* Extract the user key information */
	if( cryptInfo->type == CONTEXT_CONV )
		{
		userKey = cryptInfo->ctxConv.userKey;
		userKeyLength = cryptInfo->ctxConv.userKeyLength;
		}
	else
		{
		userKey = cryptInfo->ctxMAC.userKey;
		userKeyLength = cryptInfo->ctxMAC.userKeyLength;
		}

	/* Allocate a buffer for the DER-encoded key parameters and write
	   everything but the key to it */
	if( ( buffer = ( BYTE * ) malloc( CRYPT_MAX_PKCSIZE ) ) == NULL )
		return( CRYPT_NOMEM );
	sMemOpen( &stream, buffer, CRYPT_MAX_PKCSIZE );
	status = writeKeyInfoHeader( &stream, cryptInfo, userKeyLength, 0 );
	dataLength = sMemSize( &stream );
	if( cryptStatusOK( status ) )
		{
		CRYPT_CONTEXT iCryptContext;

		/* Hash the algorithm parameters and key and copy the first
		   KEY_CHECKVALUE_SIZE bytes to the check value.  Since we're dealing
		   with sensitive keying material here, we need to use the external
		   hash API rather than the internal one to make sure the memory
		   containing the key is protected */
		status = iCryptCreateContext( &iCryptContext, CRYPT_ALGO_SHA, 
									  CRYPT_MODE_NONE );
		if( cryptStatusOK( status ) )
			{
			ICRYPT_QUERY_INFO iCryptQueryInfo;

			iCryptEncrypt( iCryptContext, buffer, dataLength );
			iCryptEncrypt( iCryptContext, ( void * ) userKey, userKeyLength );
			iCryptEncrypt( iCryptContext, buffer, 0 );
			iCryptQueryContext( iCryptContext, &iCryptQueryInfo );
			iCryptDestroyObject( iCryptContext );
			memcpy( checkValue, iCryptQueryInfo.hashValue, KEY_CHECKVALUE_SIZE );
			zeroise( &iCryptQueryInfo, sizeof( ICRYPT_QUERY_INFO ) );
			}
		}

	/* Clean up */
	sMemClose( &stream );
	free( buffer );
	return( status );
	}

/* Make sure a check value matches the key check value for a context */

static int checkKeyCheckValue( const CRYPT_CONTEXT cryptContext,
							   const BYTE *checkValue )
	{
	CRYPT_INFO *cryptInfoPtr;
	BYTE cryptCheckValue[ KEY_CHECKVALUE_SIZE ];
	int status = CRYPT_OK;

	getCheckInternalResource( cryptContext, cryptInfoPtr, RESOURCE_TYPE_CRYPT );
	calculateKeyCheckValue( cryptInfoPtr, cryptCheckValue );
	if( memcmp( cryptCheckValue, checkValue, KEY_CHECKVALUE_SIZE ) )
		status = CRYPT_WRONGKEY;
	unlockResourceExit( cryptInfoPtr, status );
	}

/****************************************************************************
*																			*
*							Message Digest Routines							*
*																			*
****************************************************************************/

/* Initialise a message digest to a given value, and destroy it afterwards */

int newMessageDigest( MESSAGE_DIGEST *messageDigest, const CRYPT_ALGO mdAlgo,
					  const BYTE *md, const int length )
	{
	/* Set up MD information */
	memset( messageDigest, 0, sizeof( MESSAGE_DIGEST ) );
	messageDigest->type = mdAlgo;
	messageDigest->length = length;
	if( length )
		memcpy( messageDigest->data, md, length );

	return( CRYPT_OK );
	}

int deleteMessageDigest( MESSAGE_DIGEST *messageDigest )
	{
	/* Zero the message digest fields */
	return( newMessageDigest( messageDigest, CRYPT_ALGO_NONE, NULL, 0 ) );
	}

/* Determine the encoded size of a message digest value */

int sizeofMessageDigest( const MESSAGE_DIGEST *messageDigest )
	{
	int parameter = 0, size;

	/* Handle any algorithm-specific parameters */
	if( messageDigest->isSHA )
		parameter = TRUE;

	/* It's a composite type.  Evaluate the size of the algorithm parameters
	   and the octet string needed to encode the MD itself */
	size = sizeofAlgorithmIdentifier( messageDigest->type, CRYPT_ALGO_NONE,
			parameter, 0 ) + ( int ) sizeofObject( messageDigest->length );
	return( sizeof( BYTE ) + calculateLengthSize( size ) + size );
	}

/* Write a message digest value */

int writeMessageDigest( STREAM *stream, const MESSAGE_DIGEST *messageDigest,
						const int tag )
	{
	int parameter = 0;

	/* Handle any algorithm-specific parameters */
	if( messageDigest->isSHA )
		parameter = TRUE;

	/* Write the identifier and length fields */
	if( tag == DEFAULT_TAG )
		writeTag( stream, BER_SEQUENCE );
	else
		writeCtag( stream, tag );
	writeLength( stream, sizeofAlgorithmIdentifier( messageDigest->type,
				 CRYPT_ALGO_NONE, parameter, 0 ) +
				 sizeofObject( messageDigest->length ) );

	/* Write the algorithm identifier and digest */
	writeAlgorithmIdentifier( stream, messageDigest->type, CRYPT_ALGO_NONE,
							  parameter, 0 );
	writeOctetString( stream, messageDigest->data, messageDigest->length,
					  DEFAULT_TAG );

	return( sGetStatus( stream ) );
	}

/* Read a message digest value */

int readMessageDigest( STREAM *stream, MESSAGE_DIGEST *messageDigest )
	{
	int readDataLength = 0, parameter, status;
	long dummy;

	/* Read the identifier field */
	if( readTag( stream ) != BER_SEQUENCE )
		{
		sSetError( stream, CRYPT_BADDATA );
		return( CRYPT_BADDATA );
		}
	readDataLength = readLength( stream, &dummy ) + 1;

	/* Read the algorithm identifier and the digest itself */
	status = readAlgorithmIdentifier( stream, &messageDigest->type, NULL,
									  &parameter, NULL );
	if( parameter )
		{
		/* Handle an algorithm-specific parameters */
		switch( messageDigest->type )
			{
			case CRYPT_ALGO_SHA:
				messageDigest->isSHA = parameter;
				break;

			default:
				return( CRYPT_NOALGO );
			}
		}
	if( cryptStatusError( status ) )
		return( status );
	readDataLength += readOctetString( stream, messageDigest->data,
						&messageDigest->length, CRYPT_MAX_HASHSIZE ) + status;

	if( sGetStatus( stream ) != CRYPT_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}

/****************************************************************************
*																			*
*							Key Information Routines						*
*																			*
****************************************************************************/

/* Determine the encoded size of a key information record */

int sizeofKeyInfo( const CRYPT_INFO *cryptInfo, const BOOLEAN addPadding,
				   const RECIPIENT_TYPE recipientType )
	{
	const int userKeyLength = ( cryptInfo->type == CONTEXT_CONV ) ? \
			cryptInfo->ctxConv.userKeyLength : cryptInfo->ctxMAC.userKeyLength;
	int size;

	if( recipientType != RECIPIENT_CRYPTLIB )
		return( CRYPT_ERROR );

	/* Determine the total encoded size.  If we're padding the length, we
	   just return the nearest KEYINFO_PADSIZE-byte value above this,
	   otherwise we return the real size */
	size = ( int ) sizeofObject( sizeofAlgorithmInfo( cryptInfo ) +
						( int ) sizeofObject( userKeyLength ) +
						( int ) sizeofObject( KEY_CHECKVALUE_SIZE ) );
	if( addPadding && ( size & ( KEYINFO_PADSIZE - 1 ) ) )
		/* We only need to pad if it's not a multiple of KEYINFO_PADSIZE
		   bytes long.  The three bytes added to the calculation are for the
		   minimum-length octet string possible for the padding.  Note that
		   we don't have to worry about the outer sequence length-of-length
		   changing over the 128-byte boundary because 126 bytes of data
		   will be encoded as 128 bytes while 127 bytes will be rounded up to
		   192 bytes, so the 1-byte length-of-length change is lost in the
		   padding */
		return( ( size + 3 + ( KEYINFO_PADSIZE - 1 ) ) & ~( KEYINFO_PADSIZE - 1 ) );
	return( size );
	}

/* Write the key information.  The first function writes only the header
   information (but not the key itself) for use in various locations which
   need to process encryption key information formatted in a standardised
   manner */

int writeKeyInfoHeader( STREAM *stream, const CRYPT_INFO *cryptInfo,
						const int keyLength, const int extraLength )
	{
	/* Write the header and algorithm parameters */
	writeTag( stream, BER_SEQUENCE );
	writeLength( stream, sizeofAlgorithmInfo( cryptInfo ) +
				 ( int ) sizeofObject( keyLength ) + extraLength );
	writeAlgorithmInfo( stream, cryptInfo );

	/* Write the start of the octetString which contains the key */
	writeTag( stream, BER_OCTETSTRING );
	writeLength( stream, keyLength );

	return( sGetStatus( stream ) );
	}

int writeKeyInfo( STREAM *stream, const CRYPT_INFO *cryptInfo,
				  int *keyOffset, const BOOLEAN addPadding,
				  const RECIPIENT_TYPE recipientType )
	{
	BYTE dummy[ CRYPT_MAX_KEYSIZE ], checkValue[ KEY_CHECKVALUE_SIZE ];
	STREAM nullStream;
	const int sizeofCheckValue = ( int ) sizeofObject( KEY_CHECKVALUE_SIZE );
	const int userKeyLength = ( cryptInfo->type == CONTEXT_CONV ) ? \
			cryptInfo->ctxConv.userKeyLength : cryptInfo->ctxMAC.userKeyLength;
	int length, padSize = 0, status;

	if( recipientType != RECIPIENT_CRYPTLIB )
		return( CRYPT_ERROR );

	/* Calculate the key check value */
	status = calculateKeyCheckValue( cryptInfo, checkValue );
	if( cryptStatusError( status ) )
		return( status );

	/* If there's no padding to be added, just write the data and exit */
	if( !addPadding )
		{
		/* Write the start of the KeyInformation record */
		writeKeyInfoHeader( stream, cryptInfo, userKeyLength,
							sizeofCheckValue );
		*keyOffset = sMemSize( stream );

		/* Insert the dummy key and follow it with the key check value */
		swrite( stream, dummy, userKeyLength );
		writeOctetString( stream, checkValue, KEY_CHECKVALUE_SIZE,
						  DEFAULT_TAG );

		return( sGetStatus( stream ) );
		}

	/* We need to pad the data to a multiple of KEYINFO_PADSIZE bytes.
	   First, determine how long the unpadded and padded KeyInfo record will
	   be */
	sMemOpen( &nullStream, NULL, 0 );
	writeKeyInfoHeader( &nullStream, cryptInfo, userKeyLength,
						sizeofCheckValue );
	length = sMemSize( &nullStream ) + userKeyLength + sizeofCheckValue;
	sMemClose( &nullStream );

	/* If the output is not a multiple of KEYINFO_PADSIZE bytes long,
	   determine how much padding we need to add to make it the right
	   length */
	if( length & ( KEYINFO_PADSIZE - 1 ) )
		{
		int totalLength = sizeofKeyInfo( cryptInfo, TRUE, RECIPIENT_CRYPTLIB );

		padSize = totalLength - length;

		/* If the padded vs unpadded length crosses the length-encoding
		   boundary at 128 bytes, the outer sequence length-of-length
		   encoding will be 2 bytes rather than 1, so we need to shrink the
		   padding size by 1 byte.  Note that we use a > comparison rather
		   than >= because a total length of 128 bytes will still only have
		   a data length of 126 bytes */
		if( length < 128 && totalLength > 128 )
			padSize--;
		}

	/* Write the start of the KeyInformation record */
	writeKeyInfoHeader( stream, cryptInfo, userKeyLength,
						sizeofCheckValue + padSize );
	*keyOffset = sMemSize( stream );

	/* Insert the dummy key and follow it with the key check value */
	swrite( stream, dummy, userKeyLength );
	writeOctetString( stream, checkValue, KEY_CHECKVALUE_SIZE, DEFAULT_TAG );

	/* Insert the padding if necessary */
	if( padSize )
		{
		BYTE padding[ KEYINFO_PADSIZE ];

		/* Adjust the padding string for the size of the header to
		   make sure we get exactly the number of bytes required */
		padSize -= ( padSize >= 128 ) ? 3 : 2;

		/* Write the octet string with the padding.  It doesn't have to
		   be cryptographically strong, or even random for that matter,
		   although writing a constant string is inadvisable */
		getNonce( padding, padSize );	/* Insert subliminal channel here */
		writeOctetString( stream, padding, padSize, DEFAULT_TAG );
		}

	return( sGetStatus( stream ) );
	}

/* Read the key information.  Since this is only ever read from a memory
   stream prior to being loaded into an encryption context, there's no need
   to specify whether we'll read the tag type.  Note that this function
   returns CRYPT_BADDATA if it encounters unexpected data, the caller should
   convert this to CRYPT_WRONGKEY where appropriate */

int readKeyInfo( STREAM *stream, CRYPT_CONTEXT *iCryptContext )
	{
	BYTE keyCheckValue[ KEY_CHECKVALUE_SIZE ];
	int checkValueLength, status;
	long length;

	/* Read the identifier and length fields */
	if( readTag( stream ) != BER_SEQUENCE )
		{
		sSetError( stream, CRYPT_BADDATA );
		return( CRYPT_BADDATA );
		}
	readLength( stream, &length );

	/* Read the encryption algorithm information and create an encryption
	   context from it */
	status = readAlgorithmInfo( stream, iCryptContext, NULL );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the encryption key and load it into the encryption context.  Like
	   the equivalent code in writeEncryptedDataInfo(), we never actually
	   read the data into an octet string but load it directly into the
	   encryption context, so we need to duplicate most of readOctetString()
	   here */
	if( readTag( stream ) != BER_OCTETSTRING || \
		cryptStatusError( status = readLength( stream, &length ) ) || \
		length < 5 || length > CRYPT_MAX_KEYSIZE )
		{
		iCryptDestroyObject( *iCryptContext );
		sSetError( stream, CRYPT_BADDATA );
		return( CRYPT_BADDATA );
		}
	status = iCryptLoadKey( *iCryptContext, stream->buffer + stream->bufPos,
							( int ) length );
	if( cryptStatusError( status ) )
		{
		iCryptDestroyObject( *iCryptContext );
		return( status );
		}
	sSkip( stream, ( size_t ) length );	/* Move past the key */

	/* Finally, read the key check value and make sure it matches the
	   calculated check value */
	status = readOctetString( stream, keyCheckValue, &checkValueLength,
							  KEY_CHECKVALUE_SIZE );
	if( cryptStatusError( status ) || \
		checkKeyCheckValue( *iCryptContext, keyCheckValue ) != CRYPT_OK )
		{
		iCryptDestroyObject( *iCryptContext );
		return( CRYPT_BADDATA );
		}

	/* There could be padding after the key, but we don't need to do anything
	   with it so we can exit now */
	return( sGetStatus( stream ) );
	}

/****************************************************************************
*																			*
*						Conventionally-Encrypted Key Routines				*
*																			*
****************************************************************************/

/* The OID for the PKCS #5 v2.0 key derivation function */

#define OID_PBKDF2	MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x05\x09" )

/* Write a key derivation record */

int writeKeyDerivationInfo( STREAM *stream, const CRYPT_INFO *cryptInfoPtr )
	{
	const int derivationInfoSize = \
			( int ) sizeofObject( cryptInfoPtr->ctxConv.saltLength ) + \
			sizeofShortInteger( ( long ) cryptInfoPtr->ctxConv.keySetupIterations );

	/* Write the PBKDF2 information */
	writeSequence( stream, sizeofOID( OID_PBKDF2 ) +
				   ( int ) sizeofObject( derivationInfoSize ) );
	writeOID( stream, OID_PBKDF2 );
	writeSequence( stream, derivationInfoSize );
	writeOctetString( stream, cryptInfoPtr->ctxConv.salt,
					  cryptInfoPtr->ctxConv.saltLength, DEFAULT_TAG );
	writeShortInteger( stream, cryptInfoPtr->ctxConv.keySetupIterations,
					   DEFAULT_TAG );

	return( sGetStatus( stream ) );
	}

/* Read a key derivation record */

int readKeyDerivationInfo( STREAM *stream, CRYPT_INFO *cryptInfoPtr )
	{
	long integer;
	int length, status;

	/* Read the outer wrapper and key derivation algorithm OID */
	readSequence( stream, &length );
	status = readOID( stream, OID_PBKDF2 );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the PBKDF2 parameters, limiting the salt and iteration count to
	   sane values */
	readSequence( stream, &length );
	status = readOctetString( stream, cryptInfoPtr->ctxConv.salt,
							  &cryptInfoPtr->ctxConv.saltLength,
							  CRYPT_MAX_HASHSIZE );
	if( cryptStatusError( status ) )
		return( status );
	length -= status;
	status = readShortInteger( stream, &integer );
	if( cryptStatusError( status ) )
		return( status );
	if( integer > 20000 )
		return( CRYPT_BADDATA );
	length -= status;
	if( length > 0 )
		sSkip( stream, length );
	cryptInfoPtr->ctxConv.keySetupIterations = ( int ) integer;

	return( sGetStatus( stream ) );
	}

/* Write a KEKRecipientInfo record */

int writeKEKInfo( STREAM *stream, const CRYPT_INFO *cryptInfoPtr,
				  const BYTE *buffer, const int length,
				  const RECIPIENT_TYPE recipientType )
	{
	const CAPABILITY_INFO *capabilityInfo = cryptInfoPtr->capabilityInfo;
	int ivSize = 0, derivationInfoSize = 0, parameterSize;

	/* CMS wrapping isn't handled yet because it changes with every draft */
	if( recipientType == RECIPIENT_CMS )
		return( CRYPT_ERROR );

	/* Determine the size of any optional parameters */
	if( cryptInfoPtr->type == CONTEXT_CONV && \
		cryptInfoPtr->ctxConv.keySetupAlgorithm != CRYPT_ALGO_NONE )
		{
		/* The constant 2 is the size of the tag and length fields.  We can
		   safely pass a zero parameter because the cryptDeriveKey() API
		   doesn't allow the specification of subtypes such as SHA (rather
		   than SHA-1), so the algorithm will always be the base type */
		derivationInfoSize = 2 + sizeofAlgorithmIdentifier( \
					cryptInfoPtr->ctxConv.keySetupAlgorithm, CRYPT_ALGO_NONE, 0, 0 ) + \
					sizeofShortInteger( ( long ) cryptInfoPtr->ctxConv.keySetupIterations );
		}
	if( needsIV( capabilityInfo->cryptMode ) )
		ivSize = ( int ) sizeofObject( cryptInfoPtr->ctxConv.ivLength );
	parameterSize = sizeofOID( OID_CRYPTLIB_KEYWRAP ) +
					( int ) sizeofObject( sizeofAlgorithmInfo( cryptInfoPtr ) +
										  derivationInfoSize + ivSize );

	/* Write the header and start of the AlgorithmIdentifier */
	writeCtag( stream, CTAG_RI_KEK );
	writeLength( stream, sizeofShortInteger( KEK_VERSION ) +
				 sizeofObject( parameterSize + ( int ) sizeofObject( length ) ) );
	writeShortInteger( stream, KEK_VERSION, DEFAULT_TAG );
	writeSequence( stream, parameterSize );
	writeOID( stream, OID_CRYPTLIB_KEYWRAP );
	writeSequence( stream, sizeofAlgorithmInfo( cryptInfoPtr ) +
				   derivationInfoSize + ivSize );
	writeAlgorithmInfo( stream, cryptInfoPtr );

	/* Write the key derivation info if necessary.  We can always pass a zero
	   parameter because the cryptDeriveKey() API doesn't allow the
	   specification of subtypes such as SHA (rather than SHA-1), so the
	   algorithm will always be the base type */
	if( derivationInfoSize )
		{
		writeCtag( stream, CTAG_CK_DERIVATIONINFO );
		writeLength( stream, derivationInfoSize - 2 );
		writeAlgorithmIdentifier( stream, cryptInfoPtr->ctxConv.keySetupAlgorithm,
								  CRYPT_ALGO_NONE, 0, 0 );
		writeShortInteger( stream, cryptInfoPtr->ctxConv.keySetupIterations,
						   DEFAULT_TAG );
		}

	/* Write the encryted key */
	if( needsIV( capabilityInfo->cryptMode ) )
		writeOctetString( stream, cryptInfoPtr->ctxConv.iv,
						  cryptInfoPtr->ctxConv.ivLength, CTAG_CK_IV );
	writeOctetString( stream, buffer, length, DEFAULT_TAG );

	return( sGetStatus( stream ) );
	}

/* Read a conventionally encrypted key */

int readKEKInfo( STREAM *stream, OBJECT_INFO *cryptObjectInfo, void *iv,
				 int *ivSize )
	{
	long value;
	int dummy, status;

	/* Clear return value */
	memset( cryptObjectInfo, 0, sizeof( OBJECT_INFO ) );

	/* Read the header and start of the AlgorithmIdentifier */
	if( !checkReadCtag( stream, CTAG_RI_KEK, TRUE ) )
		sSetError( stream, CRYPT_BADDATA );
	readLength( stream, &value );
	status = readShortInteger( stream, &value );
	if( !cryptStatusError( status ) && value != KEK_VERSION )
		sSetError( stream, CRYPT_BADDATA );
	readSequence( stream, &dummy );
	status = readOID( stream, OID_CRYPTLIB_KEYWRAP );
	readSequence( stream, &dummy );
	if( !cryptStatusError( status ) )
		status = readAlgorithmInfo( stream, NULL, cryptObjectInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the key derivation information if necessary */
	status = checkReadCtag( stream, CTAG_CK_DERIVATIONINFO, TRUE );
	if( status )
		{
		long integer;

		readLength( stream, &value );
		readAlgorithmIdentifier( stream, &cryptObjectInfo->keySetupAlgo,
								 NULL, NULL, NULL );
		readShortInteger( stream, &integer );
		cryptObjectInfo->keySetupIterations = ( int ) integer;
		}
	else
		{
		/* If no parameters are given, record the fact that the key used
		   wasn't a derived key */
		cryptObjectInfo->keySetupAlgo = CRYPT_ERROR;
		cryptObjectInfo->keySetupIterations = CRYPT_ERROR;
		}

	/* Read the IV if necessary.  Strictly speaking we don't need to look for
	   the context-specific tag for the IV since we can tell whether it'll be
	   present based on the encryption mode */
	status = checkReadCtag( stream, CTAG_CK_IV, FALSE );
	if( status )
		readOctetStringData( stream, iv, ivSize, CRYPT_MAX_IVSIZE );

	/* Finally, read the start of the encrypted key.  We never read the data
	   itself since it's passed directly to the decrypt function */
	if( readTag( stream ) != BER_OCTETSTRING )
		sSetError( stream, CRYPT_BADDATA );
	readLength( stream, &value );
	cryptObjectInfo->dataStart = sMemBufPtr( stream );
	cryptObjectInfo->dataLength = ( int ) value;

	return( sGetStatus( stream ) );
	}

/****************************************************************************
*																			*
*						Public-key Encrypted Key Routines					*
*																			*
****************************************************************************/

/* Write a KeyTransRecipientInfo record */

int writeKeyTransInfo( STREAM *stream, const CRYPT_INFO *cryptInfoPtr,
					   const BYTE *buffer, const int length,
					   const void *auxInfo, const int auxInfoLength,
					   const RECIPIENT_TYPE recipientType )
	{
	const CRYPT_ALGO cryptAlgo = cryptInfoPtr->capabilityInfo->cryptAlgo;
	const int dataLength = sizeofAlgorithmIdentifier( cryptAlgo, CRYPT_ALGO_NONE, 0, 0 ) +
						   ( int ) sizeofObject( length );

	if( recipientType == RECIPIENT_CRYPTLIB )
		{
		writeSequence( stream, sizeofShortInteger( KEYTRANS_EX_VERSION ) +
					   ( int ) sizeofObject( KEYID_SIZE ) + dataLength );
		writeShortInteger( stream, KEYTRANS_EX_VERSION, DEFAULT_TAG );
		writeOctetString( stream, cryptInfoPtr->ctxPKC.keyID, KEYID_SIZE, CTAG_KT_SKI );
		}
	else
		{
		writeSequence( stream, sizeofShortInteger( KEYTRANS_VERSION ) +
					   auxInfoLength + dataLength );
		writeShortInteger( stream, KEYTRANS_VERSION, DEFAULT_TAG );
		swrite( stream, auxInfo, auxInfoLength );
		}
	writeAlgorithmIdentifier( stream, cryptAlgo, CRYPT_ALGO_NONE, 0, 0 );
	writeOctetString( stream, buffer, length, DEFAULT_TAG );

	return( sGetStatus( stream ) );
	}

/* Read a KeyTransRecipientInfo record */

int readKeyTransInfo( STREAM *stream, OBJECT_INFO *cryptObjectInfo )
	{
	int temp, status;
	long value;

	/* Clear return value */
	memset( cryptObjectInfo, 0, sizeof( OBJECT_INFO ) );
	cryptObjectInfo->formatType = CRYPT_FORMAT_CRYPTLIB;

	/* Read the header and version number */
	status = readSequence( stream, &temp );
	if( cryptStatusError( status ) )
		return( status );
	status = readShortInteger( stream, &value );
	if( !cryptStatusError( status ) && \
		( value < 0 || value > KEYTRANS_EX_VERSION ) )
		{
		sSetError( stream, CRYPT_BADDATA );
		status = CRYPT_BADDATA;
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Read the key ID and PKC algorithm information */
	if( value != KEYTRANS_EX_VERSION )
		{
		cryptObjectInfo->formatType = CRYPT_FORMAT_CMS;
		cryptObjectInfo->iAndSStart = sMemBufPtr( stream );
		if( readTag( stream ) != BER_SEQUENCE )
			status = CRYPT_BADDATA;
		else
			{
			/* Read the IssuerAndSerialNumber length.  We do it this way
			   instead of using readSequence() so that we can easily
			   determine the overall length */
			readLength( stream, &value );
			cryptObjectInfo->iAndSLength = ( int ) value + 1;
			sSkip( stream, value );
			}
		}
	else
		status = readOctetStringTag( stream, cryptObjectInfo->keyID, &temp,
							KEYID_SIZE, MAKE_CTAG_PRIMITIVE( CTAG_KT_SKI ) );
	if( !cryptStatusError( status ) )
		status = readAlgorithmIdentifier( stream, &cryptObjectInfo->cryptAlgo,
										  NULL, NULL, NULL );
	if( cryptStatusError( status ) )
		return( status );
	cryptObjectInfo->cryptMode = CRYPT_MODE_PKC;

	/* Finally, read the start of the encrypted key.  We never read the data
	   itself since it's passed directly to the PKC decrypt function */
	if( readTag( stream ) != BER_OCTETSTRING )
		sSetError( stream, CRYPT_BADDATA );
	readLength( stream, &value );
	cryptObjectInfo->dataStart = sMemBufPtr( stream );
	cryptObjectInfo->dataLength = ( int ) value;

	return( sGetStatus( stream ) );
	}

/****************************************************************************
*																			*
*								Key Agreement Routines						*
*																			*
****************************************************************************/

/* Write a key agreement record.  Because this part of CMS is still
   fluctuating wildly, this doesn't quite correspond to the version du
   jour */

int writeKeyAgreeInfo( STREAM *stream, const CRYPT_INFO *cryptInfoPtr,
					   const CRYPT_INFO *sessionKeyInfo )
	{
	const CRYPT_ALGO cryptAlgo = cryptInfoPtr->capabilityInfo->cryptAlgo;

	/* Write the header, public key information, and conventional algorithm
	   parameters */
	writeCtag( stream, CTAG_RI_KEYAGREE );
	writeLength( stream, sizeofShortInteger( 3 ) +
				 sizeofPublicKeyInfo( cryptAlgo, &cryptInfoPtr->ctxPKC ) +
				 sizeofAlgorithmInfo( sessionKeyInfo ) );
	writeShortInteger( stream, 3, DEFAULT_TAG );
	writePublicKeyInfo( stream, cryptAlgo, &cryptInfoPtr->ctxPKC );
	writeAlgorithmInfo( stream, sessionKeyInfo );

	return( sGetStatus( stream ) );
	}

/* Read a key agreement record */

int readKeyAgreeInfo( STREAM *stream, OBJECT_INFO *cryptObjectInfo,
					  CRYPT_CONTEXT *iKeyAgreeContext,
					  CRYPT_CONTEXT *iSessionKeyContext )
	{
	CRYPT_CONTEXT iLocalKeyAgreeContext;
	long value;
	int status;

	/* Clear return values */
	memset( cryptObjectInfo, 0, sizeof( OBJECT_INFO ) );
	if( iKeyAgreeContext != NULL )
		*iKeyAgreeContext = CRYPT_ERROR;
	if( iSessionKeyContext != NULL )
		*iSessionKeyContext = CRYPT_ERROR;

	/* Read the header and version number */
	if( !checkReadCtag( stream, CTAG_RI_KEYAGREE, TRUE ) || \
		cryptStatusError( readLength( stream, &value ) ) || \
		cryptStatusError( readShortInteger( stream, &value ) ) || value != 3 )
		{
		sSetError( stream, CRYPT_BADDATA );
		return( CRYPT_BADDATA );
		}

	/* Read the public key information and encryption algorithm information */
	status = readPublicKey( stream, &iLocalKeyAgreeContext );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're doing a query we're not interested in the key agreement
	   context so we just copy out the information we need and destroy it */
	if( iKeyAgreeContext == NULL )
		{
		ICRYPT_QUERY_INFO iCryptQueryInfo;

		status = iCryptQueryContext( iLocalKeyAgreeContext, &iCryptQueryInfo );
		iCryptDestroyObject( iLocalKeyAgreeContext );
		if( cryptStatusError( status ) )
			return( status );
		cryptObjectInfo->cryptAlgo = iCryptQueryInfo.cryptAlgo;
		cryptObjectInfo->cryptMode = iCryptQueryInfo.cryptMode;
		memcpy( cryptObjectInfo->keyID, iCryptQueryInfo.keyID, KEYID_SIZE );
		zeroise( &iCryptQueryInfo, sizeof( ICRYPT_QUERY_INFO ) );
		}
	else
		/* Make the key agreement context externally visible */
		*iKeyAgreeContext = iLocalKeyAgreeContext;

	return( readAlgorithmInfo( stream, iSessionKeyContext, cryptObjectInfo ) );
	}

/****************************************************************************
*																			*
*								Signature Routines							*
*																			*
****************************************************************************/

/* Write a signature */

int writeSignature( STREAM *stream, const CRYPT_INFO *cryptInfo,
					const CRYPT_ALGO hashAlgo, const BYTE *buffer,
					const int length, const SIGNATURE_TYPE signatureType )
	{
	const CRYPT_ALGO pkcAlgo = cryptInfo->capabilityInfo->cryptAlgo;

	/* Write the appropriate identification information for the signature
	   type */
	if( signatureType == SIGNATURE_CRYPTLIB )
		{
		/* Write the identifier and length fields */
		writeTag( stream, BER_SEQUENCE );
		writeLength( stream, sizeofShortInteger( SIGNATURE_EX_VERSION ) +
					 sizeofObject( KEYID_SIZE ) +
					 sizeofAlgorithmIdentifier( pkcAlgo, CRYPT_ALGO_NONE, 0, 0 ) +
					 sizeofAlgorithmIdentifier( hashAlgo, CRYPT_ALGO_NONE, 0, 0 ) +
					 sizeofObject( length ) );

		/* Write the version, key ID and algorithm identifier */
		writeShortInteger( stream, SIGNATURE_EX_VERSION, DEFAULT_TAG );
		writeOctetString( stream, cryptInfo->ctxPKC.keyID, KEYID_SIZE,
						  CTAG_SI_SKI );
		writeAlgorithmIdentifier( stream, hashAlgo, CRYPT_ALGO_NONE, 0, 0 );
		writeAlgorithmIdentifier( stream, pkcAlgo, CRYPT_ALGO_NONE, 0, 0 );
		}
	if( signatureType == SIGNATURE_X509 )
		/* Write the hash+signature algorithm identifier */
		writeAlgorithmIdentifier( stream, pkcAlgo, hashAlgo, 0, 0 );
	if( signatureType == SIGNATURE_CMS )
		/* Write the signature algorithm identifier */
		writeAlgorithmIdentifier( stream, pkcAlgo, CRYPT_ALGO_NONE, 0, 0 );

	/* Write the signature encapsulated in an OCTET STRING (CMS and cryptlib)
	   or BIT STRING (X.509) */
	if( signatureType == SIGNATURE_X509 )
		{
		writeTag( stream, BER_BITSTRING );
		writeLength( stream, length + 1 );
		sputc( stream, 0 );		/* Write bit remainder octet */
		}
	else
		{
		writeTag( stream, BER_OCTETSTRING );
		writeLength( stream, length );
		}
	writeRawObject( stream, buffer, length );

	return( sGetStatus( stream ) );
	}

/* Read a signature */

int readSignature( STREAM *stream, OBJECT_INFO *cryptObjectInfo,
				   const SIGNATURE_TYPE signatureType )
	{
	int status;
	long length;

	/* If it's an X.509 signature, it's just a signature+hash algorithm ID */
	if( signatureType == SIGNATURE_X509 )
		{
		/* Read the signature and hash algorithm information and start of the
		   signature */
		status = readAlgorithmIdentifier( stream, &cryptObjectInfo->cryptAlgo,
									&cryptObjectInfo->hashAlgo, NULL, NULL );
		if( cryptStatusOK( status ) && readTag( stream ) != BER_BITSTRING )
			sSetError( stream, CRYPT_BADDATA );
		readLength( stream, &length );
		sgetc( stream );		/* Read bit remainder octet */
		cryptObjectInfo->dataStart = sMemBufPtr( stream );
		cryptObjectInfo->dataLength = ( int ) length;
		return( sGetStatus( stream ) );
		}

	/* If it's CMS signer information, read the issuer ID and hash algorithm
	   identifier */
	if( signatureType == SIGNATURE_CMS_SIGNATUREINFO )
		{
		long value;

		/* Read the identifier and length fields */
		if( readTag( stream ) != BER_SEQUENCE )
			{
			sSetError( stream, CRYPT_BADDATA );
			return( CRYPT_BADDATA );
			}
		readLength( stream, &length );
		status = readShortInteger( stream, &value );
		if( !cryptStatusError( status ) && value != SIGNATURE_VERSION )
			sSetError( stream, CRYPT_BADDATA );

		/* Read the issuer and serial number and hash algorithm ID */
		cryptObjectInfo->iAndSStart = sMemBufPtr( stream );
		if( readTag( stream ) != BER_SEQUENCE )
			status = CRYPT_BADDATA;
		else
			{
			/* Read the IssuerAndSerialNumber length.  We do it this way
			   instead of using readSequence() so that we can easily
			   determine the overall length */
			readLength( stream, &value );
			cryptObjectInfo->iAndSLength = ( int ) value + 1;
			sSkip( stream, value );
			}
		if( !cryptStatusError( status ) )
			status = readAlgorithmIdentifier( stream,
							&cryptObjectInfo->hashAlgo, NULL, NULL, NULL );
		cryptObjectInfo->dataStart = sMemBufPtr( stream );
		return( status );
		}

	/* If it's a cryptlib signature, there's a key ID at the start */
	if( signatureType == SIGNATURE_CRYPTLIB )
		{
		long value;
		int dummy;

		/* Read the identifier and length fields */
		if( readTag( stream ) != BER_SEQUENCE )
			{
			sSetError( stream, CRYPT_BADDATA );
			return( CRYPT_BADDATA );
			}
		readLength( stream, &length );
		status = readShortInteger( stream, &value );
		if( !cryptStatusError( status ) && value != SIGNATURE_EX_VERSION )
			sSetError( stream, CRYPT_BADDATA );

		/* Read the key ID and hash algorithm identifier */
		status = readOctetStringTag( stream, cryptObjectInfo->keyID, &dummy,
									 KEYID_SIZE, MAKE_CTAG_PRIMITIVE( CTAG_SI_SKI ) );
		if( !cryptStatusError( status ) )
			status = readAlgorithmIdentifier( stream,
							&cryptObjectInfo->hashAlgo, NULL, NULL, NULL );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Read the CMS/cryptlib signature algorithm and start of the signature */
	status = readAlgorithmIdentifier( stream, &cryptObjectInfo->cryptAlgo,
									  NULL, NULL, NULL );
	if( cryptStatusOK( status ) && readTag( stream ) != BER_OCTETSTRING )
		sSetError( stream, CRYPT_BADDATA );
	readLength( stream, &length );
	cryptObjectInfo->dataStart = sMemBufPtr( stream );
	cryptObjectInfo->dataLength = ( int ) length;
	return( sGetStatus( stream ) );
	}

/****************************************************************************
*																			*
*								Object Query Routines						*
*																			*
****************************************************************************/

/* Read the type and start of a cryptlib object */

static int readObjectType( STREAM *stream, CRYPT_OBJECT_TYPE *objectType,
						   long *length, CRYPT_FORMAT_TYPE *formatType )
	{
	const long streamPos = stell( stream );
	int readDataLength, tag;

	*formatType = CRYPT_FORMAT_CRYPTLIB;
	tag = readTag( stream );
	readDataLength = readLength( stream, length ) + 1;
	*length += readDataLength;	/* Include size of tag in total length */
	if( tag == BER_SEQUENCE )
		{
		long value;

		/* This could be a signature or a PKC-encrypted key.  Read the
		   length and see what follows */
		readShortInteger( stream, &value );
		if( value == KEYTRANS_VERSION || value == KEYTRANS_EX_VERSION )
			*objectType = CRYPT_OBJECT_PKCENCRYPTED_KEY;
		else
			if( value == SIGNATURE_VERSION || value == SIGNATURE_EX_VERSION )
				*objectType = CRYPT_OBJECT_SIGNATURE;
			else
				{
				*objectType = CRYPT_OBJECT_NONE;
				sSetError( stream, CRYPT_BADDATA );
				}
		if( value == KEYTRANS_VERSION || value == SIGNATURE_VERSION )
			*formatType = CRYPT_FORMAT_CMS;
		}
	else
		{
		switch( tag )
			{
			case MAKE_CTAG( CTAG_RI_KEYAGREE ):
				*objectType = CRYPT_OBJECT_KEYAGREEMENT;
				break;

			case MAKE_CTAG( CTAG_RI_KEK ):
				*objectType = CRYPT_OBJECT_ENCRYPTED_KEY;
				break;

			default:
				*objectType = CRYPT_OBJECT_NONE;
				sSetError( stream, CRYPT_BADDATA );
			}
		}
	sseek( stream, streamPos );

	return( sGetStatus( stream ) );
	}

/* Low-level object query function.  This is used by a number of library
   routines to get information on objects at a lower level than that provided
   by cryptQueryObject() (for example the enveloping functions use it to
   determine whether there is enough data available to allow a full
   cryptQueryObject()).  At this level the stream error code (which is
   independant of the crypt error code returned by the ASN.1 routines) is
   available to provide more information via sGetError().

   Note that this function doens't perform a full check of all the fields in
   an object, all it does is extract enough information from the start to
   satisfy the query, and confirm that there's enough data in the stream to
   contain the rest of the non-payload portion of the object.  The
   appropriate import function checks the validity of the entire object, but
   has side-effects such as creating encryption contexts and/or performing
   signature checks as part of the import function.  It's not really possible
   to check the validity of the octet or bit string which makes up an
   encrypted session key or signature without actually performing the import,
   so once we've read the rest of the header we just make sure the final
   octet or bit string is complete without checking its validity */

int queryObject( STREAM *stream, OBJECT_INFO *cryptObjectInfo )
	{
	CRYPT_FORMAT_TYPE formatType;
	CRYPT_OBJECT_TYPE objectType;
	BYTE dummyIV[ CRYPT_MAX_IVSIZE ];
	long length;
	int startPos = sMemSize( stream ), dummy, status;

	/* Clear the return value and determine the object type */
	memset( cryptObjectInfo, 0, sizeof( OBJECT_INFO ) );
	status = readObjectType( stream, &objectType, &length, &formatType );
	if( cryptStatusError( status ) )
		return( status );

	/* Call the appropriate routine to find out more about the object */
	switch( objectType )
		{
		case CRYPT_OBJECT_ENCRYPTED_KEY:
			status = readKEKInfo( stream, cryptObjectInfo, dummyIV, &dummy );
			break;

		case CRYPT_OBJECT_PKCENCRYPTED_KEY:
			status = readKeyTransInfo( stream, cryptObjectInfo );
			break;

		case CRYPT_OBJECT_KEYAGREEMENT:
			status = readKeyAgreeInfo( stream, cryptObjectInfo, NULL, NULL );
			break;

		case CRYPT_OBJECT_SIGNATURE:
			status = readSignature( stream, cryptObjectInfo,
						( formatType == CRYPT_FORMAT_CRYPTLIB ) ? \
						SIGNATURE_CRYPTLIB : SIGNATURE_CMS_SIGNATUREINFO );
			break;

		default:
			status = CRYPT_ERROR;	/* Internal error, should never happen */
		}
	if( !cryptStatusError( status ) )
		{
		cryptObjectInfo->formatType = formatType;
		cryptObjectInfo->type = objectType;
		cryptObjectInfo->size = length;
		status = CRYPT_OK;	/* The readXXX() fns.return a byte count */
		}

	/* Sometimes there's extra information (such as an encrypted key or
	   signature) which we don't read since it's passed directly to the
	   decrypt function, so if there's any unread data left in the header we
	   seek over it to make sure everything we need is in the buffer.  Since
	   a length-limited stream is used by the enveloping routines, we return
	   an underflow error if the object isn't entirely present */
	if( cryptStatusOK( status ) && \
		length > sMemSize( stream ) - startPos && \
		sSkip( stream, length - ( sMemSize( stream ) - startPos ) ) != CRYPT_OK )
		status = CRYPT_UNDERFLOW;

	/* Return to the start of the object in case the caller wants to read it
	   from the stream following the query */
	sseek( stream, startPos );

	return( status );
	}
