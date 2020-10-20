/****************************************************************************
*																			*
*						ASN.1 Key Encode/Decode Routines					*
*						Copyright Peter Gutmann 1992-1998					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
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

/****************************************************************************
*																			*
*						Key Component Read/Write Routines					*
*																			*
****************************************************************************/

/* The non-RSA algorithms splits the key components over the information in
   the AlgorithmIdentifier and the actual public/private key components.  The
   split is as follows:

	DH = SEQ {					key = y INTEGER		-- g^x mod p
		p INTEGER,
		g INTEGER,
		q INTEGER,			-- X9.42 only
		j INTEGER OPTIONAL	-- X9.42 only
		}

	DSA = SEQ {					key = y INTEGER
		p INTEGER,
		q INTEGER,
		g INTEGER
		}

	Elgamal = SEQ {				key = y INTEGER
		p INTEGER,
		q INTEGER
		}

   For these algorithms there are separate functions to write the key
   parameters (which are included in the AlgorithmIdentifier) and the key
   components (which make up the per-user unique key).  In addition when
   writing the private key components we can write them using the generally
   accepted form, which includes the public components, and therefore a huge
   amount of known plaintext, with each private key, or the cryptlib form,
   which only encodes the private components */

/* When we're writing bignums we can't use the standard ASN.1 sizeof()
   routines, the following macro works out the encoded size */

#define sizeofEncodedBignum( value ) \
	( ( int ) sizeofObject( bitsToBytes( BN_num_bits( value ) ) + \
							BN_high_bit( value ) ) )

/* Read/write a bignum */

static int writeBignum( STREAM *stream, const BIGNUM *value )
	{
	BYTE buffer[ CRYPT_MAX_PKCSIZE ];
	int length, status;

	length = BN_bn2bin( ( BIGNUM * ) value, buffer );
	status = writeStaticInteger( stream, buffer, length, DEFAULT_TAG );
	zeroise( buffer, CRYPT_MAX_PKCSIZE );

	return( status );
	}

static int readBignum( STREAM *stream, BIGNUM *value )
	{
	BYTE buffer[ CRYPT_MAX_PKCSIZE ];
	int length, status;

	/* Read the value into a fixed buffer */
	status = readStaticInteger( stream, buffer, &length, CRYPT_MAX_PKCSIZE );
	if( cryptStatusError( status ) )
		return( status );
	BN_bin2bn( buffer, length, value );
	zeroise( buffer, CRYPT_MAX_PKCSIZE );

	return( CRYPT_OK );
	}

/* Read and write the DH public key parameters and components */

static int readDHparameters( STREAM *stream, PKC_INFO *dhKey )
	{
	int length;

	/* Read the header and key components */
	readSequence( stream, &length );
	readBignum( stream, dhKey->dhParam_p );
	readBignum( stream, dhKey->dhParam_g );

	return( sGetStatus( stream ) );
	}

static void writeDHparameters( STREAM *stream, const PKC_INFO *dhKey )
	{
	/* Write the identifier and length fields */
	writeTag( stream, BER_SEQUENCE );
	writeLength( stream, sizeofEncodedBignum( dhKey->dhParam_p ) +
				 sizeofEncodedBignum( dhKey->dhParam_g ) );

	/* Write the the parameter fields */
	writeBignum( stream, dhKey->dhParam_p );
	writeBignum( stream, dhKey->dhParam_g );
	}

static int readDHcomponents( STREAM *stream, PKC_INFO *dhKey,
							 const BOOLEAN isPublicKey,
							 const BOOLEAN cryptlibComponents )
	{
	if( isPublicKey || cryptlibComponents );	/* Get rid of compiler warning */

	/* The isPublicKey flag usage is somewhat different for DH than it is for
	   general PKC's, so we set this to the correct value */
	dhKey->isPublicKey = CRYPT_UNUSED;

	/* DH has two y values, the one we generate using the parameters in the 
	   context, and the one the other party generates.  When we import the
	   other parties values, we read their y value into the yPrime variable,
	   our own y value is stored in the y variable */
	readBignum( stream, dhKey->dhParam_yPrime );
	return( sGetStatus( stream ) );
	}

static void writeDHcomponents( STREAM *stream, const PKC_INFO *dhKey,
							   const BOOLEAN isPublicKey,
							   const BOOLEAN cryptlibComponents )
	{
	if( isPublicKey || cryptlibComponents );	/* Get rid of compiler warning */

	/* DH only has a single INTEGER component */
	writeBignum( stream, dhKey->dhParam_y );
	}

/* Read and write the RSA public or private key components */

static int readRSAcomponents( STREAM *stream, PKC_INFO *rsaKey,
							  const BOOLEAN isPublicKey,
							  const BOOLEAN cryptlibComponents )
	{
	int length;
	long dummy;

	/* Set up the general information fields */
	rsaKey->isPublicKey = isPublicKey;

	/* Read the header and key components */
	readSequence( stream, &length );
	if( !isPublicKey && !cryptlibComponents )
		/* Ignored, present for PKCS compatibility only */
		readShortInteger( stream, &dummy );
	if( isPublicKey || !cryptlibComponents )
		{
		readBignum( stream, rsaKey->rsaParam_n );
		readBignum( stream, rsaKey->rsaParam_e );
		}
	if( !isPublicKey )
		{
		readBignum( stream, rsaKey->rsaParam_d );
		readBignum( stream, rsaKey->rsaParam_p );
		readBignum( stream, rsaKey->rsaParam_q );
		readBignum( stream, rsaKey->rsaParam_exponent1 );
		readBignum( stream, rsaKey->rsaParam_exponent2 );
		readBignum( stream, rsaKey->rsaParam_u );
		}

	return( sGetStatus( stream ) );
	}

static void writeRSAcomponents( STREAM *stream, const PKC_INFO *rsaKey,
								const BOOLEAN isPublicKey,
								const BOOLEAN cryptlibComponents )
	{
	long size = 0;

	/* Determine the size of the public and private fields */
	if( !cryptlibComponents )
		size += sizeofEncodedBignum( rsaKey->rsaParam_n ) +
				sizeofEncodedBignum( rsaKey->rsaParam_e );
	if( !isPublicKey )
		{
		if( !cryptlibComponents )
			size += sizeofEnumerated( 0 );	/* Extra PKCS field */
		size += sizeofEncodedBignum( rsaKey->rsaParam_d ) +
				sizeofEncodedBignum( rsaKey->rsaParam_p ) +
				sizeofEncodedBignum( rsaKey->rsaParam_q ) +
				sizeofEncodedBignum( rsaKey->rsaParam_exponent1 ) +
				sizeofEncodedBignum( rsaKey->rsaParam_exponent2 ) +
				sizeofEncodedBignum( rsaKey->rsaParam_u );
		}

	/* Write the identifier and length fields */
	writeTag( stream, BER_SEQUENCE );
	writeLength( stream, size );

	/* Write the the PKC fields */
	if( !cryptlibComponents )
		{
		if( !isPublicKey )
			writeEnumerated( stream, 0, DEFAULT_TAG );	/* For PKCS compatibility */
		writeBignum( stream, rsaKey->rsaParam_n );
		writeBignum( stream, rsaKey->rsaParam_e );
		}
	if( !isPublicKey )
		{
		writeBignum( stream, rsaKey->rsaParam_d );
		writeBignum( stream, rsaKey->rsaParam_p );
		writeBignum( stream, rsaKey->rsaParam_q );
		writeBignum( stream, rsaKey->rsaParam_exponent1 );
		writeBignum( stream, rsaKey->rsaParam_exponent2 );
		writeBignum( stream, rsaKey->rsaParam_u );
		}
	}

/* Read and write the DSA public or private key parameters and components */

static int readDSAparameters( STREAM *stream, PKC_INFO *dsaKey )
	{
	int length;

	/* Read the header and key parameters */
	readSequence( stream, &length );
	readBignum( stream, dsaKey->dsaParam_p );
	readBignum( stream, dsaKey->dsaParam_q );
	readBignum( stream, dsaKey->dsaParam_g );

	return( sGetStatus( stream ) );
	}

static void writeDSAparameters( STREAM *stream, const PKC_INFO *dsaKey )
	{
	/* Write the identifier and length fields */
	writeTag( stream, BER_SEQUENCE );
	writeLength( stream, sizeofEncodedBignum( dsaKey->dsaParam_p ) +
				 sizeofEncodedBignum( dsaKey->dsaParam_q ) +
				 sizeofEncodedBignum( dsaKey->dsaParam_g ) );

	/* Write the parameter fields */
	writeBignum( stream, dsaKey->dsaParam_p );
	writeBignum( stream, dsaKey->dsaParam_q );
	writeBignum( stream, dsaKey->dsaParam_g );
	}

static int readDSAcomponents( STREAM *stream, PKC_INFO *dsaKey,
							  const BOOLEAN isPublicKey,
							  const BOOLEAN cryptlibComponents )
	{
	int length;

	/* Set up the general information fields */
	dsaKey->isPublicKey = isPublicKey;

	/* If it's a public key there's a single INTEGER component */
	if( isPublicKey )
		{
		readBignum( stream, dsaKey->dsaParam_y );
		return( sGetStatus( stream ) );
		}

	/* Read the header and key components */
	readSequence( stream, &length );
	if( !cryptlibComponents )
		{
		readEnumerated( stream, &length );
		readBignum( stream, dsaKey->dsaParam_y );
		}
	readBignum( stream, dsaKey->dsaParam_x );

	return( sGetStatus( stream ) );
	}

static void writeDSAcomponents( STREAM *stream, const PKC_INFO *dsaKey,
								const BOOLEAN isPublicKey,
								const BOOLEAN cryptlibComponents )
	{
	/* If it's a public key there's a single INTEGER component */
	if( isPublicKey )
		{
		writeBignum( stream, dsaKey->dsaParam_y );
		return;
		}

	/* Write the identifier and length fields */
	writeTag( stream, BER_SEQUENCE );
	if( !cryptlibComponents )
		writeLength( stream, sizeofEnumerated( 0 ) +
					 sizeofEncodedBignum( dsaKey->dsaParam_y ) +
					 sizeofEncodedBignum( dsaKey->dsaParam_x ) );
	else
		writeLength( stream, sizeofEncodedBignum( dsaKey->dsaParam_x ) );

	/* Write the the PKC fields */
	if( !cryptlibComponents )
		{
		writeEnumerated( stream, 0, DEFAULT_TAG );	/* For PKCS compatibility */
		writeBignum( stream, dsaKey->dsaParam_y );
		}
	writeBignum( stream, dsaKey->dsaParam_x );
	}

/* Write the ElGamal public or private key parameters and components */

static int readElGamalParameters( STREAM *stream, PKC_INFO *elGamalKey )
	{
	int length;

	/* Read the header and key parameters */
	readSequence( stream, &length );
	readBignum( stream, elGamalKey->egParam_p );
	readBignum( stream, elGamalKey->egParam_g );

	return( sGetStatus( stream ) );
	}

static void writeElGamalParameters( STREAM *stream, const PKC_INFO *elgamalKey )
	{
	/* Write the identifier and length fields */
	writeTag( stream, BER_SEQUENCE );
	writeLength( stream, sizeofEncodedBignum( elgamalKey->egParam_p ) +
				 sizeofEncodedBignum( elgamalKey->egParam_g ) );

	/* Write the parameter fields */
	writeBignum( stream, elgamalKey->egParam_p );
	writeBignum( stream, elgamalKey->egParam_g );
	}

static int readElGamalComponents( STREAM *stream, PKC_INFO *elGamalKey,
								  const BOOLEAN isPublicKey,
								  const BOOLEAN cryptlibComponents )
	{
	int length;

	/* Set up the general information fields */
	elGamalKey->isPublicKey = isPublicKey;

	/* If it's a public key there's a single INTEGER component */
	if( isPublicKey )
		{
		readBignum( stream, elGamalKey->egParam_y );
		return( sGetStatus( stream ) );
		}

	/* Read the header and key components */
	readSequence( stream, &length );
	if( !cryptlibComponents )
		{
		readEnumerated( stream, &length );
		readBignum( stream, elGamalKey->egParam_y );
		}
	readBignum( stream, elGamalKey->egParam_x );

	return( sGetStatus( stream ) );
	}

static void writeElGamalComponents( STREAM *stream, const PKC_INFO *elgamalKey,
									const BOOLEAN isPublicKey,
									const BOOLEAN cryptlibComponents  )
	{
	/* If it's a public key there's a single INTEGER component */
	if( isPublicKey )
		{
		writeBignum( stream, elgamalKey->egParam_y );
		return;
		}

	/* Write the identifier and length fields */
	writeTag( stream, BER_SEQUENCE );
	if( !cryptlibComponents )
		writeLength( stream, sizeofEnumerated( 0 ) +
					 sizeofEncodedBignum( elgamalKey->egParam_y ) +
					 sizeofEncodedBignum( elgamalKey->egParam_x ) );
	else
		writeLength( stream, sizeofEncodedBignum( elgamalKey->egParam_x ) );

	/* Write the the PKC fields */
	if( !cryptlibComponents )
		{
		writeEnumerated( stream, 0, DEFAULT_TAG );	/* For PKCS compatibility */
		writeBignum( stream, elgamalKey->egParam_y );
		}
	writeBignum( stream, elgamalKey->egParam_x );
	}

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Generate a key ID, which is the SHA-1 hash of the SubjectPublicKeyInfo.
   There are about half a dozen incompatible ways of generating X.509
   keyIdentifiers, the following is conformant with the PKIX specification
   ("use whatever you like as long as it's unique"), but differs slightly
   from one common method which hashes the SubjectPublicKey without the
   BIT STRING encapsulation.  The problem with this is that a number of DLP-
   based algorithms use a single integer as the SubjectPublicKey, leading to
   key ID clashes */

int calculateKeyID( const CRYPT_ALGO algorithm, const PKC_INFO *pkcInfo,
					BYTE *keyID )
	{
	STREAM stream;
	HASHFUNCTION hashFunction;
	BYTE buffer[ ( CRYPT_MAX_PKCSIZE * 2 ) + 50 ];
	int hashInfoSize, hashInputSize, hashOutputSize;
	int status;

	/* Get the hash algorithm information */
	if( !getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashInputSize,
							&hashOutputSize, &hashInfoSize ) )
		return( CRYPT_ERROR );	/* API error, should never occur */

	/* Write the public key fields to a buffer and hash them to get the key
	   ID */
	sMemOpen( &stream, buffer, ( CRYPT_MAX_PKCSIZE * 2 ) + 50 );
	status = writePublicKeyInfo( &stream, algorithm, pkcInfo );
	hashFunction( NULL, keyID, buffer, sMemSize( &stream ), HASH_ALL );
	sMemClose( &stream );

	return( status );
	}

/****************************************************************************
*																			*
*						sizeof() methods for ASN.1 Types					*
*																			*
****************************************************************************/

/* Determine the size of the DH public key parameters and components */

static int sizeofDHparameters( const PKC_INFO *dhKey )
	{
	/* PKCS #3 also allows for an optional length of the private value x as a
	   third parameter but there's no real use for it and we never encode
	   it */
	return( ( int ) sizeofObject( \
			sizeofEncodedBignum( dhKey->dhParam_p ) +
			sizeofEncodedBignum( dhKey->dhParam_g ) ) );
	}

static int sizeofDHcomponents( const PKC_INFO *dhKey,
							   const BOOLEAN isPublicKey,
							   const BOOLEAN cryptlibComponents )
	{
	if( isPublicKey || cryptlibComponents );	/* Get rid of compiler warning */

	return( sizeofEncodedBignum( dhKey->dhParam_y ) );
	}

/* Determine the size of the RSA public or private key components */

static int sizeofRSAcomponents( const PKC_INFO *rsaKey,
								const BOOLEAN isPublicKey,
								const BOOLEAN cryptlibComponents  )
	{
	long size = 0;

	if( !cryptlibComponents )
		size = sizeofEncodedBignum( rsaKey->rsaParam_n ) +
			   sizeofEncodedBignum( rsaKey->rsaParam_e );
	if( !isPublicKey )
		{
		if( !cryptlibComponents )
			size += sizeofEnumerated( 0 );
		size += sizeofEncodedBignum( rsaKey->rsaParam_d ) +
				sizeofEncodedBignum( rsaKey->rsaParam_p ) +
				sizeofEncodedBignum( rsaKey->rsaParam_q ) +
				sizeofEncodedBignum( rsaKey->rsaParam_exponent1 ) +
				sizeofEncodedBignum( rsaKey->rsaParam_exponent2 ) +
				sizeofEncodedBignum( rsaKey->rsaParam_u );
		}

	return( ( int ) sizeofObject( size ) );
	}

/* Determine the size of the DSA public or private key parameters and
   components */

static int sizeofDSAparameters( const PKC_INFO *dsaKey )
	{
	return( ( int ) sizeofObject( \
			sizeofEncodedBignum( dsaKey->dsaParam_p ) +
			sizeofEncodedBignum( dsaKey->dsaParam_q ) +
			sizeofEncodedBignum( dsaKey->dsaParam_g ) ) );
	}

static int sizeofDSAcomponents( const PKC_INFO *dsaKey,
								const BOOLEAN isPublicKey,
								const BOOLEAN cryptlibComponents )
	{
	long size = 0;

	/* If it's a public key there's a single INTEGER component */
	if( isPublicKey )
		return( sizeofEncodedBignum( dsaKey->dsaParam_y ) );

	if( !cryptlibComponents )
		{
		size = sizeofEnumerated( 0 );
		size += sizeofEncodedBignum( dsaKey->dsaParam_y );
		}
	size += sizeofEncodedBignum( dsaKey->dsaParam_x );

	return( ( int ) sizeofObject( size ) );
	}

/* Determine the size of the ElGamal public or private key parameters and
   components */

static int sizeofElGamalParameters( const PKC_INFO *elGamalKey )
	{
	return( ( int ) sizeofObject( \
			sizeofEncodedBignum( elGamalKey->egParam_p ) +
			sizeofEncodedBignum( elGamalKey->egParam_g ) ) );
	}

static int sizeofElGamalComponents( const PKC_INFO *elGamalKey,
									const BOOLEAN isPublicKey,
									const BOOLEAN cryptlibComponents )
	{
	long size = 0;

	/* If it's a public key there's a single INTEGER component */
	if( isPublicKey )
		return( sizeofEncodedBignum( elGamalKey->egParam_y ) );

	if( !cryptlibComponents )
		{
		size = sizeofEnumerated( 0 );
		size += sizeofEncodedBignum( elGamalKey->egParam_y );
		}
	size += sizeofEncodedBignum( elGamalKey->egParam_x );

	return( ( int ) sizeofObject( size ) );
	}

/* Determine the size of the data payload of an X.509 SubjectPublicKeyInfo
   record (not including the SEQUENCE encapsulation) or a private key
   record */

static int sizeofPublicParameters( const CRYPT_ALGO cryptAlgo,
								   const PKC_INFO *pkcInfo )
	{
	/* Determine the size of the PKC parameters */
	switch( cryptAlgo )
		{
		case CRYPT_ALGO_DH:
			return( sizeofDHparameters( pkcInfo ) );

		case CRYPT_ALGO_DSA:
			return( sizeofDSAparameters( pkcInfo ) );

		case CRYPT_ALGO_ELGAMAL:
			return( sizeofElGamalParameters( pkcInfo ) );
		}

	return( 0 );
	}

static int sizeofPublicComponents( const CRYPT_ALGO cryptAlgo,
								   const PKC_INFO *pkcInfo )
	{
	/* Determine the size of the PKC components */
	switch( cryptAlgo )
		{
		case CRYPT_ALGO_DH:
			return( sizeofDHcomponents( pkcInfo, TRUE, FALSE ) );

		case CRYPT_ALGO_RSA:
			return( sizeofRSAcomponents( pkcInfo, TRUE, FALSE ) );

		case CRYPT_ALGO_DSA:
			return( sizeofDSAcomponents( pkcInfo, TRUE, FALSE ) );

		case CRYPT_ALGO_ELGAMAL:
			return( sizeofElGamalComponents( pkcInfo, TRUE, FALSE ) );
		}

	return( 0 );
	}

#if 0	/* Currently unused, needed only for PKCS #8-type routines */

static int sizeofPrivateComponents( const CRYPT_ALGO cryptAlgo,
									const PKC_INFO *pkcInfo,
									const BOOLEAN cryptlibComponents )
	{
	/* Determine the size of the PKC components */
	switch( cryptAlgo )
		{
		case CRYPT_ALGO_RSA:
			return( sizeofRSAcomponents( pkcInfo, FALSE, cryptlibComponents ) );

		case CRYPT_ALGO_DSA:
			return( sizeofDSAcomponents( pkcInfo, FALSE, cryptlibComponents ) );

		case CRYPT_ALGO_ELGAMAL:
			return( sizeofElGamalComponents( pkcInfo, FALSE, cryptlibComponents ) );
		}

	return( 0 );
	}
#endif /* 0 */

/****************************************************************************
*																			*
*							Read/Write X.509 Key Records					*
*																			*
****************************************************************************/

/* Determine the size of the encoded public key components */

int sizeofPublicKeyInfo( const CRYPT_ALGO cryptAlgo, const PKC_INFO *pkcInfo )
	{
	const int parameterSize = sizeofPublicParameters( cryptAlgo, pkcInfo );
	const int componentSize = sizeofPublicComponents( cryptAlgo, pkcInfo );
	int totalSize;

	/* Determine the size of the AlgorithmIdentifier record and the
	   BITSTRING-encapsulated public-key data (the +1 is for the bitstring) */
	totalSize = sizeofAlgorithmIdentifier( cryptAlgo, CRYPT_ALGO_NONE, 0,
					parameterSize ) + ( int ) sizeofObject( componentSize + 1 );

	return( ( int ) sizeofObject( totalSize ) );
	}

int sizeofPublicKey( const CRYPT_CONTEXT iCryptContext )
	{
	CRYPT_INFO *cryptInfoPtr;
	int size;

	/* Make sure that we've been given a PKC context with a key loaded (this
	   has already been checked at a higher level, but we perform a sanity
	   check here to be sage) */
	getCheckInternalResource( iCryptContext, cryptInfoPtr, RESOURCE_TYPE_CRYPT );
	if( cryptInfoPtr->type != CONTEXT_PKC || !cryptInfoPtr->ctxPKC.keySet )
		unlockResourceExit( cryptInfoPtr, CRYPT_BADPARM2 );

	/* Determine the size of the public key information */
	size = sizeofPublicKeyInfo( cryptInfoPtr->capabilityInfo->cryptAlgo,
								&cryptInfoPtr->ctxPKC );

	unlockResourceExit( cryptInfoPtr, size );
	}

/* Read a public key from an X.509 SubjectPublicKeyInfo record */

int readPublicKey( STREAM *stream, CRYPT_CONTEXT *iCryptContext )
	{
	CRYPT_CONTEXT iContext;
	CRYPT_ALGO cryptAlgo;
	CRYPT_INFO *cryptInfoPtr;
	int extraLength, status;
	long length;

	/* Clear the return value */
	*iCryptContext = CRYPT_ERROR;

	/* Read the SubjectPublicKeyInfo header field and create a context to
	   read the public key information into */
	if( readTag( stream ) != BER_SEQUENCE )
		return( CRYPT_BADDATA );
	readLength( stream, &length );
	status = readAlgorithmIdentifier( stream, &cryptAlgo, NULL, NULL,
									  &extraLength );
	if( cryptStatusOK( status ) )
		status = iCryptCreateContext( &iContext, cryptAlgo, CRYPT_MODE_PKC );
	if( cryptStatusError( status ) )
		return( status );
	getCheckInternalResource( iContext, cryptInfoPtr, RESOURCE_TYPE_CRYPT );

	/* If there's parameter data present, read it now */
	if( extraLength )
		{
		switch( cryptAlgo )
			{
			case CRYPT_ALGO_DH:
				status = readDHparameters( stream, &cryptInfoPtr->ctxPKC );
			break;

			case CRYPT_ALGO_DSA:
				status = readDSAparameters( stream, &cryptInfoPtr->ctxPKC );
				break;

			case CRYPT_ALGO_ELGAMAL:
				status = readElGamalParameters( stream, &cryptInfoPtr->ctxPKC );
				break;

			default:
				status = CRYPT_ERROR;	/* Internal error, should never happen */
			}
		}

	/* Read the BITSTRING encapsulation of the public key fields */
	if( !cryptStatusError( status ) && readTag( stream ) != BER_BITSTRING )
		status = CRYPT_BADDATA;
	readLength( stream, &length );
	sgetc( stream );	/* Skip extra bit count in bitfield */
	if( cryptStatusError( status ) )
		{
		unlockResource( cryptInfoPtr );
		iCryptDestroyObject( iContext );
		return( status );
		}

	/* Finally, read the PKC information */
	switch( cryptAlgo )
		{
		case CRYPT_ALGO_DH:
			status = readDHcomponents( stream, &cryptInfoPtr->ctxPKC, TRUE,
									   TRUE );
			break;

		case CRYPT_ALGO_RSA:
			status = readRSAcomponents( stream, &cryptInfoPtr->ctxPKC, TRUE,
										TRUE );
			break;

		case CRYPT_ALGO_DSA:
			status = readDSAcomponents( stream, &cryptInfoPtr->ctxPKC, TRUE,
										TRUE );
			break;

		case CRYPT_ALGO_ELGAMAL:
			status = readElGamalComponents( stream, &cryptInfoPtr->ctxPKC,
											TRUE, TRUE );
			break;

		default:
			status = CRYPT_ERROR;	/* Internal error, should never happen */
		}
	unlockResource( cryptInfoPtr );
	if( cryptStatusOK( status ) )
		{
		/* If everything went OK, perform an internal load which uses the
		   values already present in the context */
		status = iCryptLoadKey( iContext, NULL, LOAD_INTERNAL_PUBLIC );
		if( status == CRYPT_BADPARM2 )
			status = CRYPT_BADDATA;		/* Map to a more appropriate code */
		}
	if( cryptStatusError( status ) )
		iCryptDestroyObject( iContext );
	else
		*iCryptContext = iContext;

	return( status );
	}

/* Write a public key to an X.509 SubjectPublicKeyInfo record */

static int writeSubjectPublicKey( STREAM *stream, const CRYPT_ALGO cryptAlgo,
								  const PKC_INFO *pkcInfo )
	{
	/* Write the PKC information */
	switch( cryptAlgo )
		{
		case CRYPT_ALGO_DH:
			writeDHcomponents( stream, pkcInfo, TRUE, FALSE );
			break;

		case CRYPT_ALGO_RSA:
			writeRSAcomponents( stream, pkcInfo, TRUE, FALSE );
			break;

		case CRYPT_ALGO_DSA:
			writeDSAcomponents( stream, pkcInfo, TRUE, FALSE );
			break;

		case CRYPT_ALGO_ELGAMAL:
			writeElGamalComponents( stream, pkcInfo, TRUE, FALSE );
			break;

		default:
			return( CRYPT_ERROR );	/* Internal error, should never happen */
		}

	return( sGetStatus( stream ) );
	}

int writePublicKeyInfo( STREAM *stream, const CRYPT_ALGO cryptAlgo,
						const PKC_INFO *pkcInfo )
	{
	const int parameterSize = sizeofPublicParameters( cryptAlgo, pkcInfo );
	const int componentSize = sizeofPublicComponents( cryptAlgo, pkcInfo );
	int totalSize;

	/* Determine the size of the AlgorithmIdentifier record and the
	   BITSTRING-encapsulated public-key data (the +1 is for the bitstring) */
	totalSize = sizeofAlgorithmIdentifier( cryptAlgo, CRYPT_ALGO_NONE, 0,
					parameterSize ) + ( int ) sizeofObject( componentSize + 1 );

	/* Write the SubjectPublicKeyInfo header field */
	writeTag( stream, BER_SEQUENCE );
	writeLength( stream, totalSize );
	writeAlgorithmIdentifier( stream, cryptAlgo, CRYPT_ALGO_NONE, 0,
							  parameterSize );

	/* Write the parameter data if necessary */
	if( parameterSize )
		{
		switch( cryptAlgo )
			{
			case CRYPT_ALGO_DH:
				writeDHparameters( stream, pkcInfo );
				break;

			case CRYPT_ALGO_DSA:
				writeDSAparameters( stream, pkcInfo );
				break;

			case CRYPT_ALGO_ELGAMAL:
				writeElGamalParameters( stream, pkcInfo );
				break;

			default:
				return( CRYPT_ERROR );	/* Internal error, should never happen */
			}
		}

	/* Write the BITSTRING wrapper and the PKC information */
	writeTag( stream, BER_BITSTRING );
	writeLength( stream, componentSize + 1 );	/* +1 for bitstring */
	sputc( stream, 0 );
	return( writeSubjectPublicKey( stream, cryptAlgo, pkcInfo ) );
	}

int writePublicKey( STREAM *stream, const CRYPT_CONTEXT iCryptContext )
	{
	CRYPT_INFO *cryptInfoPtr;
	int status;

	/* Make sure that we've been given a PKC context with a key loaded (this
	   has already been checked at a higher level, but we perform a sanity
	   check here to be sage) */
	getCheckInternalResource( iCryptContext, cryptInfoPtr, RESOURCE_TYPE_CRYPT );
	if( cryptInfoPtr->type != CONTEXT_PKC || !cryptInfoPtr->ctxPKC.keySet )
		unlockResourceExit( cryptInfoPtr, CRYPT_BADPARM2 );

	/* Write the public components to the stream */
	status = writePublicKeyInfo( stream, cryptInfoPtr->capabilityInfo->cryptAlgo,
								 &cryptInfoPtr->ctxPKC );

	unlockResourceExit( cryptInfoPtr, status );
	}

/****************************************************************************
*																			*
*							Read/Write Private Key Records					*
*																			*
****************************************************************************/

/* Read private key components.  This function assumes that the public
   portion of the context has already been set up */

int readPrivateKey( STREAM *stream, CRYPT_CONTEXT *iCryptContext )
	{
	CRYPT_INFO *cryptInfoPtr;
	int status;

	getCheckInternalResource( *iCryptContext, cryptInfoPtr, RESOURCE_TYPE_CRYPT );

	/* Read the private key information */
	switch( cryptInfoPtr->capabilityInfo->cryptAlgo )
		{
		case CRYPT_ALGO_RSA:
			status = readRSAcomponents( stream, &cryptInfoPtr->ctxPKC, FALSE,
										TRUE );
			break;

		case CRYPT_ALGO_DSA:
			status = readDSAcomponents( stream, &cryptInfoPtr->ctxPKC, FALSE,
										TRUE );
			break;

		case CRYPT_ALGO_ELGAMAL:
			status = readElGamalComponents( stream, &cryptInfoPtr->ctxPKC,
											FALSE, TRUE );
			break;

		default:
			return( CRYPT_ERROR );	/* Internal error, should never happen */
		}
	unlockResource( cryptInfoPtr );
	if( cryptStatusOK( status ) )
		{
		/* If everything went OK, perform an internal load which uses the
		   values already present in the context */
		status = iCryptLoadKey( *iCryptContext, NULL, LOAD_INTERNAL_PRIVATE );
		if( status == CRYPT_BADPARM2 )
			status = CRYPT_BADDATA;		/* Map to a more appropriate code */
		}
	if( cryptStatusError( status ) )
		iCryptDestroyObject( *iCryptContext );

	return( status );	/* Either a length or an error code */
	}

/* Write private key components.  This is just a wrapper for the various
   writeXXXcomponents() functions */

int writePrivateKey( STREAM *stream, const CRYPT_CONTEXT iCryptContext )
	{
	CRYPT_INFO *cryptInfoPtr;
	int status;

	/* Make sure that we've been given a PKC context with a private key
	   loaded (this has already been checked at a higher level, but we
	   perform a sanity check here to be sage) */
	getCheckInternalResource( iCryptContext, cryptInfoPtr, RESOURCE_TYPE_CRYPT );
	if( cryptInfoPtr->type != CONTEXT_PKC || !cryptInfoPtr->ctxPKC.keySet || \
		cryptInfoPtr->ctxPKC.isPublicKey )
		unlockResourceExit( cryptInfoPtr, CRYPT_BADPARM2 );

	/* Write the private key information */
	switch( cryptInfoPtr->capabilityInfo->cryptAlgo )
		{
		case CRYPT_ALGO_RSA:
			writeRSAcomponents( stream, &cryptInfoPtr->ctxPKC, FALSE, TRUE );
			break;

		case CRYPT_ALGO_DSA:
			writeDSAcomponents( stream, &cryptInfoPtr->ctxPKC, FALSE, TRUE );
			break;

		case CRYPT_ALGO_ELGAMAL:
			writeElGamalComponents( stream, &cryptInfoPtr->ctxPKC, FALSE, TRUE );
			break;

		default:
			return( CRYPT_ERROR );	/* Internal error, should never happen */
		}

	status = sGetStatus( stream );
	unlockResourceExit( cryptInfoPtr, status );
	}

/****************************************************************************
*																			*
*							Read/Write DL Value Record						*
*																			*
****************************************************************************/

/* Unlike the simpler RSA PKC, DL-based PKC's produce a pair of values which
   need to be encoded as ASN.1 records.  The following two functions perform
   this en/decoding */

int encodeDLValues( BYTE *buffer, BIGNUM *value1, BIGNUM *value2 )
	{
	STREAM stream;
	BYTE dataBuffer[ CRYPT_MAX_PKCSIZE ];
	int length, status;

	sMemConnect( &stream, buffer, STREAMSIZE_UNKNOWN );

	/* Write the identifier and length fields */
	writeTag( &stream, BER_SEQUENCE );
	writeLength( &stream, sizeofEncodedBignum( value1 ) +
				 sizeofEncodedBignum( value2 ) );

	/* Write the values */
	length = BN_bn2bin( value1, dataBuffer );
	writeStaticInteger( &stream, dataBuffer, length, DEFAULT_TAG );
	length = BN_bn2bin( value2, dataBuffer );
	writeStaticInteger( &stream, dataBuffer, length, DEFAULT_TAG );

	/* Clean up */
	status = sMemSize( &stream );
	sMemDisconnect( &stream );
	zeroise( dataBuffer, CRYPT_MAX_PKCSIZE );
	return( status );
	}

int decodeDLValues( BYTE *buffer, BIGNUM **value1, BIGNUM **value2 )
	{
	STREAM stream;
	BYTE dataBuffer[ CRYPT_MAX_PKCSIZE ];
	int length, status;
	long dummy;

	sMemConnect( &stream, buffer, STREAMSIZE_UNKNOWN );

	/* Read start of parameter sequence fields */
	if( readTag( &stream ) != BER_SEQUENCE )
		{
		sMemDisconnect( &stream );
		return( CRYPT_BADDATA );
		}
	readLength( &stream, &dummy );	/* Skip SEQ len.*/

	/* Read the DL components from the buffer */
	status = readStaticInteger( &stream, dataBuffer, &length, CRYPT_MAX_PKCSIZE );
	if( cryptStatusError( status ) )
		return( CRYPT_BADDATA );
	*value1 = BN_new();
	BN_bin2bn( dataBuffer, length, *value1 );
	status = readStaticInteger( &stream, dataBuffer, &length, CRYPT_MAX_PKCSIZE );
	if( cryptStatusError( status ) )
		{
		BN_clear_free( *value1 );
		return( CRYPT_BADDATA );
		}
	*value2 = BN_new();
	BN_bin2bn( dataBuffer, length, *value2 );

	/* Clean up */
	sMemDisconnect( &stream );
	zeroise( dataBuffer, length );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Read/Write Ad Hoc-format Key Records				*
*																			*
****************************************************************************/

/* Determine the length of an SSH-format bignum, a signed bignum value with
   the length expressed in bits */

#define sshBignumLength( value ) \
	( BN_num_bits( value ) + bytesToBits( BN_high_bit( value ) ) )

/* Read a public key from one of a number of ad hoc formats */

static int readSshPublicKey( const void *data, PKC_INFO *rsaKey )
	{
	BYTE *dataPtr = ( BYTE * ) data;
	int length;

	rsaKey->isPublicKey = TRUE;
	length = ( int ) mgetBLong( dataPtr );
	if( length < 2 || length > 256 )
		return( CRYPT_BADDATA );
	length = bitsToBytes( length );
	BN_bin2bn( dataPtr, length, rsaKey->rsaParam_e );
	dataPtr += length;
	length = ( int ) mgetBLong( dataPtr );
	if( length < 512 || length > bytesToBits( CRYPT_MAX_PKCSIZE ) )
		return( CRYPT_BADDATA );
	length = bitsToBytes( length );
	BN_bin2bn( dataPtr, length, rsaKey->rsaParam_n );
	dataPtr += length;

	return( ( int ) ( dataPtr - ( BYTE * ) data ) );
	}

int readAdhocPublicKey( const void *data, CRYPT_CONTEXT *iCryptContext )
	{
	CRYPT_CONTEXT iContext;
	CRYPT_INFO *cryptInfoPtr;
	int readDataLength, status;

	/* Clear the return value */
	*iCryptContext = CRYPT_ERROR;

	/* Create the context to hold the key */
	status = iCryptCreateContext( &iContext, CRYPT_ALGO_RSA, CRYPT_MODE_PKC );
	getCheckInternalResource( iContext, cryptInfoPtr, RESOURCE_TYPE_CRYPT );

	/* Read the PKC information */
	status = readDataLength = readSshPublicKey( data, &cryptInfoPtr->ctxPKC );
	unlockResource( cryptInfoPtr );
	if( !cryptStatusError( status ) )
		{
		/* If everything went OK, perform an internal load which uses the
		   values already present in the context */
		status = iCryptLoadKey( iContext, NULL, LOAD_INTERNAL_PUBLIC );
		if( status == CRYPT_BADPARM2 )
			status = CRYPT_BADDATA;		/* Map to a more appropriate code */
		}
	if( cryptStatusError( status ) )
		iCryptDestroyObject( iContext );
	else
		*iCryptContext = iContext;

	return( cryptStatusOK( status ) ? readDataLength : status );
	}

/* Write a public key in one of a number of ad hoc formats */

static int writeSshPublicKey( void *data, const PKC_INFO *rsaKey )
	{
	BYTE *dataPtr = data;
	long length;
	int bnLength;

	length = sshBignumLength( rsaKey->rsaParam_e );
	mputBLong( dataPtr, length );
	if( BN_high_bit( rsaKey->rsaParam_e ) )
		*dataPtr++ = 0;
	bnLength = BN_bn2bin( rsaKey->rsaParam_e, dataPtr );
	dataPtr += bnLength;
	length = sshBignumLength( rsaKey->rsaParam_n );
	mputBLong( dataPtr, length );
	if( BN_high_bit( rsaKey->rsaParam_n ) )
		*dataPtr++ = 0;
	bnLength = BN_bn2bin( rsaKey->rsaParam_n, dataPtr );
	dataPtr += bnLength;

	return( ( int ) ( dataPtr - ( BYTE * ) data ) );
	}

int writeAdhocPublicKey( void *data, const CRYPT_CONTEXT iCryptContext )
	{
	CRYPT_INFO *cryptInfoPtr;
	int status;

	/* Make sure that we've been given a PKC context with a key loaded (this
	   has already been checked at a higher level, but we perform a sanity
	   check here to be sage) */
	getCheckInternalResource( iCryptContext, cryptInfoPtr, RESOURCE_TYPE_CRYPT );
	if( cryptInfoPtr->type != CONTEXT_PKC || !cryptInfoPtr->ctxPKC.keySet )
		unlockResourceExit( cryptInfoPtr, CRYPT_BADPARM2 );

	/* The ad hoc formats all require an RSA PKC */
	if( cryptInfoPtr->capabilityInfo->cryptAlgo != CRYPT_ALGO_RSA )
		unlockResourceExit( cryptInfoPtr, CRYPT_BADPARM2 );

	/* Write the key in SSH format */
	status = writeSshPublicKey( data, &cryptInfoPtr->ctxPKC );

	unlockResourceExit( cryptInfoPtr, status );
	}
