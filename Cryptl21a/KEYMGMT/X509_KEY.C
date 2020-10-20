/****************************************************************************
*																			*
*							  X.509 Key Read Routines						*
*						Copyright Peter Gutmann 1996-1997					*
*																			*
*	This code has been fairly well obsoleted by the certificate management	*
*				routines and will probably be removed at some point.		*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "asn1.h"
  #include "asn1keys.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1keys.h"
#endif /* Compiler-specific includes */

/* The minimum and maximum X.509 certificate format we recognise */

#define MIN_X509_VERSION		0	/* X.509v1 */
#define MAX_X509_VERSION		2	/* X.509v3 */

/* Context-specific tags for the X.509 certificate */

enum { CTAG_XC_VERSION, CTAG_XC_ISSUERID, CTAG_XC_SUBJECTID,
	   CTAG_XC_EXTENSIONS };

/* Prototypes for functions in cryptapi.c */

BOOLEAN matchSubstring( const char *subString, const char *string );

/****************************************************************************
*																			*
*						Object Identifier Handling Routines					*
*																			*
****************************************************************************/

/* The maximum (encoded) object identifier size */

#define MAX_OID_SIZE		20

/* A macro to make make declaring OID's simpler */

#define MKOID( value )	( ( BYTE * ) value )

/* Various object identifiers.  We take advantage of the fact that object
   identifiers were designed to be handled in the encoded form (without any
   need for decoding) and compare expected OID's with the raw encoded form */

#define OID_PKCS1			MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x01\x01" )
	/* pkcs-1				(1 2 840 113549 1 1) */
#define OID_RC4				MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x04" )
	/* rc4					(1 2 840 113549 3 4) */
#define OID_COMMONNAME		MKOID( "\x06\x03\x55\x04\x03" )
	/* commonName			(2 5 4 3) */

/* Get the length of an encoded object identifier (OBJECT_IDENTIFIER +
   length + value */

#define sizeofOID( oid )	( 1 + 1 + ( int ) oid[ 1 ] )

/* Read a SEQUENCE { OBJECT IDENTIFIER, ... } object and compare it with an
   expected value.  This routine doesn't compare the passed-in object ID
   length with the read length since sometimes all we need is a match down
   one arc of the graph and not a complete match.

   This function returns information in a complex and screwball manner:

	CRYPT_BADDATA if an object identifier in the correct format wasn't
	found

	0 and skips the associated attribute data, storing the total number of
	bytes read in remainingData if an object identifier was found by didn't
	match the required one,

	The number of bytes read and the associated attribute data ready to read
	if a match was found */

#define checkOID( stream, oid, remainingData ) \
		_checkOID( stream, oid, remainingData, TRUE )
#define checkOIDdata( stream, oid, remainingData ) \
		_checkOID( stream, oid, remainingData, FALSE )

static int _checkOID( STREAM *stream, const BYTE *oid, int *remainingData,
					  const BOOLEAN readIdent )
	{
	BYTE buffer[ MAX_OID_SIZE ];
	long totalLength;
	const int oidLength = sizeofOID( oid );
	int readDataLength, bufferLength;

	/* Perform a quick sanity check */
	if( oidLength > MAX_OID_SIZE )
		return( CRYPT_ERROR );

	/* Read the identifier and length fields */
	if( readIdent )
		{
		if( readTag( stream ) != BER_SEQUENCE )
			return( CRYPT_BADDATA );
		}
	readDataLength = readLength( stream, &totalLength ) + 1;

	/* Read the raw object identifier data and compare it to the expected
	   OID */
	readDataLength += readRawObject( stream, buffer, &bufferLength,
									 MAX_OID_SIZE, BER_OBJECT_IDENTIFIER );
	if( bufferLength < oidLength )
		return( CRYPT_BADDATA );
	totalLength -= bufferLength;
	if( memcmp( buffer, oid, oidLength ) )
		{
		/* It's not what we want, skip any associated attribute data */
		if( totalLength )
			readDataLength += readUniversal( stream );
		*remainingData = 0;
		return( 0 );
		}

	/* Remember the length of any optional attribute fields */
	*remainingData = ( int ) totalLength;

	return( readDataLength );
	}

/* Check an OID and skip any associated attribute data */

static int checkReadOID( STREAM *stream, BYTE *oid )
	{
	int remainingData, status;

	status = checkOID( stream, oid, &remainingData );
	if( !cryptStatusError( status ) && remainingData > 0 )
		readUniversal( stream );

	return( status );
	}

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Find a Common Name (CN) in a Name record */

static int readName( STREAM *stream, char *commonName )
	{
	int readDataLength;
	long totalLength;

	/* Read the identifier field */
	if( readTag( stream ) != BER_SEQUENCE )
		return( CRYPT_BADDATA );
	readDataLength = readLength( stream, &totalLength ) + 1;
	readDataLength += ( int ) totalLength;

	/* Walk through the SEQUENCE OF RelativeDistinguishedNames looking
	   for the common name */
	while( totalLength > 0 )
		{
		long setLength;

		/* Read the identifier field */
		if( readTag( stream ) != BER_SET )
			return( CRYPT_BADDATA );
		totalLength -= readLength( stream, &setLength ) + 1;
		totalLength -= setLength;

		/* Walk through the SET OF AttributeValueAssertions looking for the
		   first common name */
		while( setLength > 0 )
			{
			int remainingData, status;

			/* Check for a commonName */
			status = checkOID( stream, OID_COMMONNAME, &remainingData );
			if( cryptStatusError( status ) )
				return( status );
			if( status )
				{
				int commonNameLength;

				/* Read in the common name */
				status += readOctetStringTag( stream, ( BYTE * ) commonName,
							&commonNameLength, CRYPT_MAX_TEXTSIZE,
							BER_STRING_PRINTABLE ) + 1;
				commonName[ commonNameLength ] = '\0';

				/* Subtract the number of bytes read from the set length */
				setLength -= status;
				}
			else
				/* We've read the OID/attribute sequence as part of
				   checkOID(), subtract it from the set length */
				setLength -= remainingData;
			}
		if( setLength < 0 )
			return( CRYPT_BADDATA );
		}
	if( totalLength < 0 )
		return( CRYPT_BADDATA );

	return( readDataLength );
	}

/****************************************************************************
*																			*
*							Read an X.509/SET Public Key					*
*																			*
****************************************************************************/

/* Read an X.509/SET key */

static int readX509key( STREAM *stream, CRYPT_CONTEXT *iCryptContext,
						const CRYPT_KEYID_TYPE keyIDtype,
						const void *keyID, char *name )
	{
	long length, integer;
	time_t time;
	int status;

	/* Read the identifier field */
	if( readTag( stream ) != BER_SEQUENCE )
		return( CRYPT_BADDATA );
	readLength( stream, &length );

	/* Read the version number and certificate serial number */
	if( checkReadCtag( stream, CTAG_XC_VERSION, TRUE ) )
		{
		readLength( stream, &length );
		readShortInteger( stream, &integer );
		if( integer < MIN_X509_VERSION || integer > MAX_X509_VERSION )
			return( CRYPT_BADDATA );
		}
	if( readTag( stream ) != BER_INTEGER )
		return( CRYPT_BADDATA );
	readUniversalData( stream );

	/* Read the signature algorithm type */
	status = checkReadOID( stream, OID_PKCS1 );
	if( status <= 0 )
		return( CRYPT_BADDATA );

	/* Read the certificate issuer name */
	if( readTag( stream ) != BER_SEQUENCE )
		return( CRYPT_BADDATA );
	readUniversalData( stream );

	/* Read the certificate validity period */
	if( readTag( stream ) != BER_SEQUENCE )
		return( CRYPT_BADDATA );
	readLength( stream, &length );
	readUTCTime( stream, &time );
	readUTCTime( stream, &time );

	/* Read the subject name if we're looking for a match by name, otherwise
	   skip this field */
	if( keyIDtype != CRYPT_KEYID_OBJECT )
		{
		char nameBuffer[ CRYPT_MAX_TEXTSIZE + 1 ];

		readName( stream, nameBuffer );
		if( name != NULL )
			strcpy( name, nameBuffer );
		if( !matchSubstring( keyID, nameBuffer ) )
			return( CRYPT_DATA_NOTFOUND );
		}
	else
		{
		if( readTag( stream ) != BER_SEQUENCE )
			return( CRYPT_BADDATA );
		readUniversalData( stream );
		}

	/* Read the SubjectPublicKeyInfo field */
	return( readPublicKey( stream, iCryptContext ) );
	}

/* Read an X.509/SET public key certificate */

static int readX509certificate( STREAM *stream, CRYPT_CONTEXT *iCryptContext,
								const CRYPT_KEYID_TYPE keyIDtype,
								const void *keyID, char *name )
	{
	long length;
	int status;

	/* Read the identifier field */
	if( readTag( stream ) != BER_SEQUENCE )
		{
		sSetError( stream, CRYPT_BADDATA );
		return( CRYPT_BADDATA );
		}
	readLength( stream, &length );

	status = readX509key( stream, iCryptContext, keyIDtype, keyID, name );
	return( status );
	}

/****************************************************************************
*																			*
*							Read a Netscape Private Key						*
*																			*
****************************************************************************/

/* Read a PKCS #8 private key */

static int readPKCS8PrivateKey( BYTE *buffer, int bufferLength,
								CRYPT_CONTEXT *iCryptContext )
	{
	STREAM stream;
	long integer, length;
	int status = CRYPT_WRONGKEY;

	/* Connect the memory buffer to an I/O stream */
	sMemConnect( &stream, buffer, bufferLength );

	/* Read the start of the private-key encapsulation as a check that the
	   correct decryption key was used.  We check that we've got a SEQUENCE,
	   that the size of the object is > 128 bytes (which is about the
	   minimum a 256-bit key can be encoded in, and also catches any cases
	   of the BER short length encoding), that the size of the object is
	   < 8192 bytes (which is a suspiciously large key of about 8K+ bits),
	   and that the version number is 0 */
	if( readTag( &stream ) != BER_SEQUENCE )
		{
		sMemClose( &stream );
		return( CRYPT_WRONGKEY );
		}
	readLength( &stream, &length );
	readShortInteger( &stream, &integer );
	if( length < 128 || length > 8192 || integer )
		{
		sMemClose( &stream );
		return( CRYPT_WRONGKEY );
		}
	sMemDisconnect( &stream );

	/* Now that we're reasonably sure we've used the correct decryption key,
	   reconnect the stream and read the private key fields */
	sMemConnect( &stream, buffer, bufferLength );
/*	status = readRSAcomponents( &stream, iCryptContext, FALSE ); */
	if( iCryptContext );	/* Get rid of compiler warning */
	status = CRYPT_ERROR;
	if( !cryptStatusError( status ) )
		status = CRYPT_OK;	/* readXXX() functions return a byte count */

	/* Clean up */
	sMemClose( &stream );
	return( status );
	}

/* Read a Netscape private key, which contains Netscapes encapsulation of the
   PKCS #8 RSA private key fields.  The format is:

	SEQUENCE {
		OCTET STRING 'private-key',
		SEQUENCE {
			SEQUENCE {
				OBJECT IDENTIFIER '1 2 840 113549 3 4' (rc4),
				NULL
				}
			OCTET STRING encrypted-private-key
			}
		}

	The OCTET STRING decrypts to a standard PKCS #8 private key object */

static int readNetscapeKey( STREAM *stream, CRYPT_CONTEXT *iCryptContextPtr,
							const char *password )
	{
	CRYPT_CONTEXT iCryptContext;
	BYTE *buffer, hashResult[ CRYPT_MAX_HASHSIZE ], dataType[ 11 ];
	int hashInfoSize, hashInputSize, hashOutputSize;
	HASHFUNCTION hashFunction;
	long length;
	int dataTypeLength, status;

	/* Read the identifier field */
	if( readTag( stream ) != BER_SEQUENCE )
		return( CRYPT_BADDATA );
	readLength( stream, &length );

	/* Read the data type field */
	if( cryptStatusError( readOctetString( stream, dataType,
										   &dataTypeLength, 11 ) ) || \
		dataTypeLength != 11 || memcmp( dataType, "private-key", 11 ) )
		return( CRYPT_BADDATA );

	/* Read the inner SEQUENCE field */
	if( readTag( stream ) != BER_SEQUENCE )
		return( CRYPT_BADDATA );
	readLength( stream, &length );

	/* Read the encryption algorithm type */
	status = checkReadOID( stream, OID_RC4 );
	if( status <= 0 )
		return( CRYPT_BADDATA );

	/* Read the OCTET STRING containing the encrypted RSA key */
	if( readTag( stream ) != BER_OCTETSTRING )
		return( CRYPT_BADDATA );
	readLength( stream, &length );
	if( length > 8192 )
		return( CRYPT_BADDATA );

	/* Read the encrypted data into an in-memory buffer */
	if( ( buffer = ( BYTE * ) malloc( ( size_t ) length ) ) == NULL )
		return( CRYPT_NOMEM );
	sread( stream, buffer, ( int ) length );
	if( ( status = sGetStatus( stream ) ) == CRYPT_UNDERFLOW ||
		status == CRYPT_DATA_READ )
		{
		zeroise( buffer, ( int ) length );
		free( buffer );
		return( CRYPT_BADDATA );
		}

	/* Hash the passphrase with MD5 */
	if( !getHashParameters( CRYPT_ALGO_MD5, &hashFunction, &hashInputSize,
							&hashOutputSize, &hashInfoSize ) )
		{
		zeroise( buffer, ( int ) length );
		free( buffer );
		return( CRYPT_ERROR );	/* API error, should never occur */
		}
	hashFunction( NULL, hashResult, ( void * ) password, strlen( password ),
				  HASH_ALL );

	/* Load the hashed passphrase into an encryption context.  Since it's an
	   internal key load, this clears the hashed key */
	status = iCryptCreateContext( &iCryptContext, CRYPT_ALGO_RC4,
								  CRYPT_MODE_STREAM );
	if( !cryptStatusError( status ) )
		status = iCryptLoadKey( iCryptContext, hashResult, hashOutputSize );
	if( cryptStatusError( status ) )
		{
		zeroise( buffer, ( int ) length );
		free( buffer );
		return( status );
		}

	/* Decrypt the private key components */
	iCryptDecrypt( iCryptContext, buffer, ( int ) length );
	iCryptDestroyObject( iCryptContext );

	/* Read the private key fields */
	status = readPKCS8PrivateKey( buffer, ( int ) length, iCryptContextPtr );

	/* Clean up (the buffer has already been wiped in readPKCS8PrivateKey() */
	free( buffer );
	return( status );
	}

/* Get an X.509/Netscape key */

int x509GetKey( STREAM *stream, const CRYPT_KEYID_TYPE keyIDtype,
				const void *keyID, CRYPT_CONTEXT *iCryptContext,
				char *userID )
	{
	return( readX509certificate( stream, iCryptContext, keyIDtype, keyID,
								 userID ) );
	}

int netscapeGetKey( STREAM *stream, const char *password,
					CRYPT_CONTEXT *iCryptContext, char *userID )
	{
	int status;

	/* Read the private key */
	status = readNetscapeKey( stream, iCryptContext, password );
	if( userID != NULL )
		strcpy( userID, "Netscape private key file" );
	return( status );
	}
