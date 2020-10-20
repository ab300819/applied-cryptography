/****************************************************************************
*																			*
*						  cryptlib Key Stream Routines						*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

/* The format used to protect the private key components is a standard
   cryptlib envelope, however for various reasons the required enveloping
   functionality is duplicated here:

	1. It's somewhat inelegant to use the heavyweight enveloping routines to
	   wrap up 100 bytes of data.
	2. The enveloping code is enormous and complex, especially when extra
	   sections like zlib and PGP and S/MIME support are factored in.  This
	   makes it difficult to compile a stripped-down version of cryptlib,
	   since private key storage will require all the enveloping code to be
	   included.
	3. Since the enveloping code is general-purpose, it doesn't allow very
	   precise control over the data being processed.  Specifically, it's
	   necessary to write the private key components to a buffer which is
	   then copied to the envelope, leaving two copies in unprotected memory
	   for some amount of time.  In contrast if we do the buffer management
	   ourselves we can write the data to a buffer and immediately encrypt
	   it.

   For these reasons this module includes the code to process minimal
   (password-encrypted data) envelopes */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "dbms.h"
  #include "asn1.h"
  #include "asn1objs.h"
  #include "asn1oid.h"
  #include "asn1keys.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "dbms.h"
  #include "../keymgmt/asn1.h"
  #include "../keymgmt/asn1objs.h"
  #include "../keymgmt/asn1oid.h"
  #include "../keymgmt/asn1keys.h"
#else
  #include "crypt.h"
  #include "misc/dbms.h"
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1objs.h"
  #include "keymgmt/asn1oid.h"
  #include "keymgmt/asn1keys.h"
#endif /* Compiler-specific includes */

/* Context-specific tags for the PublicKeyInfo record */

enum { CTAG_PK_CERTREQUEST, CTAG_PK_CERTIFICATE, CTAG_PK_CERTCHAIN };

/* Context-specific tag for the EncryptedData record (this is normally
   defined in env_asn1.c) */

#define CTAG_CI_ENCRYPTED	1

/****************************************************************************
*																			*
*								Read a Private Key							*
*																			*
****************************************************************************/

/* The size of the buffer for the decrypted private key data.  Anything below
   this size (up to 2K RSA keys and any size non-RSA keys) is held in the
   stack buffer, anything over this size is stored on the heap.  This is
   helpful for memory-starved 16-bit environments */

#define KEYBUF_SIZE		1024

/* OID information used to read a private key file */

static const OID_SELECTION keyFileOIDselection[] = {
	{ OID_CRYPTLIB_PRIVATEKEY, 0, 0, CRYPT_OK },
	{ NULL, 0, 0, 0 }
	};

static const OID_SELECTION privKeyDataOIDselection[] = {
	{ OID_CMS_ENVELOPEDDATA, 0, 2, TRUE },				/* Encr.priv.key */
	{ OID_CMS_DATA, CRYPT_UNUSED, CRYPT_UNUSED, FALSE },/* Non-encr priv.key */
	{ NULL, 0, 0, 0 }
	};

static const OID_SELECTION dataOIDselection[] = {
	{ OID_CMS_DATA, CRYPT_UNUSED, CRYPT_UNUSED, CRYPT_OK },
	{ NULL, 0, 0, 0 }
	};

/* Read the public components of the key data.  This returns information as
   follows:

				|		iCryptContextPtr
		Data	|	NULL				Non-null
	------------+-------------------------------------
	Raw pub.key | Handle = context		Handle = -
				|						Context = public-key context
				|
		Cert	| Handle = cert			Handle = data-only cert
				|						Context = public-key context */

static int readPublicComponents( STREAM *stream,
								 CRYPT_HANDLE *iCryptHandlePtr,
								 CRYPT_CONTEXT *iCryptContextPtr )
	{
	long length;
	int tag, status;

	/* Clear return values */
	*iCryptHandlePtr = CRYPT_ERROR;
	if( iCryptContextPtr != NULL )
		*iCryptContextPtr = CRYPT_ERROR;

	/* If it's a straight public key, read the key components into a
	   context */
	if( peekTag( stream ) == BER_SEQUENCE )
		{
		status = readPublicKey( stream, ( iCryptContextPtr == NULL ) ? \
								iCryptHandlePtr: iCryptContextPtr );
		return( status );
		}

	/* It should be some sort of certificate object.  We ignore the exact
	   tagging since the cert import code will sort the object type out for
	   us */
	tag = readTag( stream );
	if( ( tag != MAKE_CTAG( CTAG_PK_CERTREQUEST ) && \
		  tag != MAKE_CTAG( CTAG_PK_CERTIFICATE ) && \
		  tag != MAKE_CTAG( CTAG_PK_CERTCHAIN ) ) || \
		cryptStatusError( readLength( stream, &length ) ) )
		return( CRYPT_BADDATA );

	/* Read the cert object into the cryptlib object, either as a data-only
	   cert object if it'll be attached to a context later, or as a standard
	   cert object */
	status = iCryptImportCert( sMemBufPtr( stream ), iCryptHandlePtr,
							   iCryptContextPtr );
	if( !cryptStatusError( status ) )
		{
		sSkip( stream, status );
		status = CRYPT_OK;			/* iCryptImport returns a length */
		}

	return( status );
	}

/* Read the decryption information for the encrypted private key, decrypt the
   key components, and read them into the existing public-key context */

static int readEncryptedKey( STREAM *stream, CRYPT_CONTEXT *iPrivKeyContextPtr,
							 const char *password )
	{
	CRYPT_CONTEXT iCryptContext, iSessionKeyContext;
	CRYPT_ALGO cryptAlgo;
	CRYPT_MODE cryptMode;
	OBJECT_INFO cryptObjectInfo;
	BYTE iv[ CRYPT_MAX_IVSIZE ];
	void *buffer;
	long length;
	int ivSize, status, dummy;

	/* Read the header for the SET OF EncryptionInfo */
	if( cryptStatusError( readSet( stream, &dummy ) ) )
		return( CRYPT_BADDATA );

	/* Query the exported key information to determine the parameters
	   required to reconstruct the decryption key */
	status = queryObject( stream, &cryptObjectInfo );
	if( cryptStatusError( status ) )
		return( status );
	if( cryptObjectInfo.type != CRYPT_OBJECT_ENCRYPTED_KEY )
		return( CRYPT_BADDATA );

	/* Create an encryption context and derive the user password into it
	   using the given parameters, and import the session key.  If there's an
	   error in the paramters stored with the exported key, these functions
	   will return a generic CRYPT_BADPARM, so we translate it into an error
	   code which is appropriate for the situation (algorithm and mode
	   checking is already perform by queryObject(), so any problems which
	   make it into the create/derive functions are likely to be rather
	   obscure) */
	status = iCryptCreateContextEx( &iCryptContext, cryptObjectInfo.cryptAlgo,
									cryptObjectInfo.cryptMode,
									cryptObjectInfo.cryptContextExInfo );
	if( cryptStatusOK( status ) )
		{
		status = iCryptDeriveKeyEx( iCryptContext, password,
							strlen( password ), cryptObjectInfo.keySetupAlgo,
							cryptObjectInfo.keySetupIterations );
		if( cryptStatusOK( status ) )
			status = iCryptImportKeyEx( sMemBufPtr( stream ), iCryptContext,
										&iSessionKeyContext );
		iCryptDestroyObject( iCryptContext );
		}
	memset( &cryptObjectInfo, 0, sizeof( OBJECT_INFO ) );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_BADPARM ) ? CRYPT_BADDATA : status );
	readUniversal( stream );	/* Skip the exported key */

	/* Read the IV and load it into the session key context.  We don't
	   bother checking the algorithm parameters since they're already given
	   by the imported session key, if they differ we'll get a CRYPT_BADDATA
	   later on anyway */
	status = readCMSencrHeader( stream, dataOIDselection, &length,
								&cryptAlgo, &cryptMode, iv, &ivSize );
	if( cryptStatusOK( status ) )
		status = iCryptLoadIV( iSessionKeyContext, iv, ivSize );

	/* Make sure the data has a sane length and is a multiple of 8 bytes
	   (since we force the use of the CBC mode we know it has to have this
	   property) */
	if( cryptStatusOK( status ) && \
		( length >= MAX_PRIVATE_KEYSIZE || length & 7 ) )
		status = CRYPT_BADDATA;

	/* Decrypt the data and read it into a context */
	if( cryptStatusOK( status ) && \
		( status = krnlMemalloc( &buffer, MAX_PRIVATE_KEYSIZE ) ) == CRYPT_OK )
		{
		STREAM privKeyStream;

		/* Copy the encrypted private key data to a temporary buffer, decrypt
		   it, and read it into a context */
		sread( stream, buffer, ( int ) length );
		sMemConnect( &privKeyStream, buffer, ( int ) length );
		status = iCryptDecrypt( iSessionKeyContext, buffer, ( int ) length );
		if( cryptStatusOK( status ) )
			status = readPrivateKey( &privKeyStream, iPrivKeyContextPtr );
		sMemClose( &privKeyStream );
		krnlMemfree( &buffer );
		}
	iCryptDestroyObject( iSessionKeyContext );

	return( status );
	}

/* Read a private key from a memory buffer into an internal encryption
   context.  This can be called in several variants:

	Handle = NULL: Generate a key ID only (used for cached updates)
	PubOnly = TRUE: Read publikc-key context or cert
	PubOnly = FALSE: Read private-key context with optional data-only cert
					 attached */

int readPrivateKeyBuffer( const BYTE *buffer, const char *password,
						  CRYPT_CONTEXT *iCryptHandlePtr, BYTE *keyID,
						  const BOOLEAN publicComponentsOnly )
	{
	CRYPT_CERTIFICATE iDataCert = CRYPT_ERROR;
	CRYPT_CONTEXT iCryptContext;
	ICRYPT_QUERY_INFO iCryptQueryInfo;
	STREAM stream;
	BOOLEAN isEncrypted;
	int status;

	sMemConnect( &stream, buffer, STREAMSIZE_UNKNOWN );

	/* Clear the return values */
	if( iCryptHandlePtr != NULL )
		*iCryptHandlePtr = CRYPT_ERROR;
	memset( keyID, 0, KEYID_SIZE );

	/* Read the header fields */
	status = readCMSheader( &stream, keyFileOIDselection, NULL );
	if( cryptStatusError( status ) )
		{
		/* Turn the error code into a general CRYPT_BADDATA, since the low-
		   level routines can return other codes which won't mean much to the
		   caller */
		sMemDisconnect( &stream );
		return( CRYPT_BADDATA );
		}

	/* If we're only interested in the public components, read whatever's
	   there and exit */
	if( publicComponentsOnly )
		{
		status = readPublicComponents( &stream, iCryptHandlePtr, NULL );
		sMemDisconnect( &stream );
		return( status );
		}

	/* Read the public components into a public-key context and optional
	   data-only cert if there's cert information present, and export the
	   key ID */
	status = readPublicComponents( &stream, &iDataCert, &iCryptContext );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	iCryptQueryContext( iCryptContext, &iCryptQueryInfo );
	memcpy( keyID, iCryptQueryInfo.keyID, KEYID_SIZE );
	zeroise( &iCryptQueryInfo, sizeof( ICRYPT_QUERY_INFO ) );

	/* If we're only doing a key ID check, clean up and exit */
	if( iCryptHandlePtr == NULL )
		{
		sMemDisconnect( &stream );
		iCryptDestroyObject( iCryptContext );
		if( iDataCert != CRYPT_ERROR )
			iCryptDestroyObject( iDataCert );
		return( status );
		}

	/* Read the start of the private key header fields */
	isEncrypted = readCMSheader( &stream, privKeyDataOIDselection, NULL );
	if( cryptStatusError( isEncrypted ) )
		status = isEncrypted;	/* Remember what went wrong */
	else
		/* If the key is encrypted, the user must supply a password */
		if( isEncrypted && password == NULL )
			status = CRYPT_WRONGKEY;
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		iCryptDestroyObject( iCryptContext );
		if( iDataCert != CRYPT_ERROR )
			iCryptDestroyObject( iDataCert );
		return( status );
		}

	/* If the data is encrypted, decrypt it and read the data */
	if( isEncrypted )
		status = readEncryptedKey( &stream, &iCryptContext, password );
	else
		/* It's an unencrypted key (ouch!), read it straight from the
		   stream */
		status = readPrivateKey( &stream, &iCryptContext );
	sMemDisconnect( &stream );

	/* Connect the data-only certificate object to the context and export
	   it */
	if( cryptStatusOK( status ) )
		{
		krnlSendMessage( iCryptContext, RESOURCE_IMESSAGE_SETDATA, &iDataCert,
						 RESOURCE_MESSAGE_DATA_CERTIFICATE, 0 );
		*iCryptHandlePtr = iCryptContext;
		}
	else
		{
		iCryptDestroyObject( iCryptContext );
		if( iDataCert != CRYPT_ERROR )
			iCryptDestroyObject( iDataCert );
		}

	return( status );
	}

/****************************************************************************
*																			*
*								Write a Private Key							*
*																			*
****************************************************************************/

/* Generate a session key and write the encryption information in the form
   SET OF {	[ 0 ] (EncryptedKey) } */

static int writeEncryptionInformation( STREAM *stream,
									   CRYPT_CONTEXT *iSessionKeyContextPtr,
									   const char *password )
	{
	CRYPT_CONTEXT iCryptContext, iSessionKeyContext;
	CRYPT_ALGO cryptAlgo;
	int iterations, exportedKeySize, status;

	/* Clear the return value */
	*iSessionKeyContextPtr = CRYPT_ERROR;

	/* In the interests of luser-proofing, we're really paranoid and force
	   the use of non-weak algorithms and modes of operation.  In addition
	   since OIDs are only defined for a limited subset of algorithms, we
	   also default to a guaranteed available algorithm if no OID is defined
	   for the one requested */
	cryptAlgo = getOptionNumeric( CRYPT_OPTION_ENCR_ALGO );
	if( isWeakCryptAlgo( cryptAlgo ) ||
		cryptStatusError( sizeofAlgorithmIdentifier( cryptAlgo,
													 CRYPT_MODE_CBC, 0, 0 ) ) )
		cryptAlgo = CRYPT_ALGO_3DES;
	iterations = getOptionNumeric( CRYPT_OPTION_KEYING_ITERATIONS );
	if( iterations < 500 )
		iterations = 500;

	/* Create an encryption context and derive the user password into it */
	status = iCryptCreateContext( &iCryptContext, cryptAlgo, CRYPT_MODE_CBC );
	if( cryptStatusError( status ) )
		return( status );
	status = iCryptDeriveKeyEx( iCryptContext, password, strlen( password ),
								getOptionNumeric( CRYPT_OPTION_KEYING_ALGO ),
								iterations );
	if( cryptStatusError( status ) )
		{
		iCryptDestroyObject( iCryptContext );
		return( status );
		}

	/* Create a session key context and generate a key and IV into it.  The IV
	   would be generated automatically later on when we encrypt data for the
	   first time, but we do it explicitly here to catch any possible errors
	   at a point where recovery is easier */
	status = iCryptCreateContext( &iSessionKeyContext, cryptAlgo, CRYPT_MODE_CBC );
	if( cryptStatusError( status ) )
		{
		iCryptDestroyObject( iCryptContext );
		return( status );
		}
	status = krnlSendMessage( iSessionKeyContext,
							  RESOURCE_IMESSAGE_CTX_GENKEY, NULL,
							  CRYPT_USE_DEFAULT, 0 );
	if( cryptStatusOK( status ) )
		status = iCryptLoadIV( iSessionKeyContext, NULL, 0 );

	/* Determine the size of the exported key and write the encrypted data
	   content field */
	if( cryptStatusOK( status ) )
		status = iCryptExportKeyEx( NULL, &exportedKeySize, CRYPT_FORMAT_CRYPTLIB,
									iCryptContext, iSessionKeyContext );
	if( cryptStatusOK( status ) )
		{
		writeSet( stream, exportedKeySize );
		status = iCryptExportKeyEx( stream->buffer + stream->bufPos,
									&exportedKeySize, CRYPT_FORMAT_CRYPTLIB,
									iCryptContext, iSessionKeyContext );
		sSkip( stream, exportedKeySize );
		}

	/* Clean up */
	iCryptDestroyObject( iCryptContext );
	if( cryptStatusError( status ) )
		iCryptDestroyObject( iSessionKeyContext );
	else
		*iSessionKeyContextPtr = iSessionKeyContext;
	return( cryptStatusError( status ) ? \
			status : ( int ) sizeofObject( exportedKeySize ) );
	}

/* Write a private key to a memory buffer from an encryption context */

int writePrivateKeyBuffer( void **buffer, int *bufSize,
						   const CRYPT_CONTEXT cryptContext,
						   const char *password )
	{
	CRYPT_CONTEXT iSessionKeyContext;
	STREAM stream, nullStream;
	BYTE *bufPtr, *privateKeyDataStart;
	int publicKeyInfoSize, privateKeyInfoSize, privateKeyDataSize;
	int padSize = 0, bufferSize, status;

	/* Clear the return values */
	*buffer = NULL;
	*bufSize = 0;

	/* Check and reserve the context for our use until we've written the key
	   components to the buffer */
	status = krnlSendMessage( cryptContext, RESOURCE_MESSAGE_CHECK, NULL,
							  RESOURCE_MESSAGE_CHECK_PKC_PRIVATE, CRYPT_BADPARM3 );
	if( cryptStatusOK( status ) )
		status = krnlSendNotifier( cryptContext, RESOURCE_MESSAGE_LOCK );
	if( cryptStatusError( status ) )
		return( status );

	/* Find out how large the encoded public and private key information will
	   be and allocate the buffer to contain the data */
	publicKeyInfoSize = sizeofPublicKey( cryptContext );
	if( !cryptStatusError( publicKeyInfoSize ) )
		{
		sMemOpen( &nullStream, NULL, 0 );
		status = writePrivateKey( &nullStream, cryptContext );
		privateKeyInfoSize = sMemSize( &nullStream );
		sMemClose( &nullStream );
		}
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_BADPARM2 )
			status = CRYPT_BADPARM3;	/* Map error to correct parameter */
		krnlSendNotifier( cryptContext, RESOURCE_MESSAGE_UNLOCK );
		return( status );
		}
	bufferSize = publicKeyInfoSize + privateKeyInfoSize + 512;
	if( ( *buffer = malloc( bufferSize ) ) == NULL )
		{
		krnlSendNotifier( cryptContext, RESOURCE_MESSAGE_UNLOCK );
		return( CRYPT_NOMEM );
		}
	sMemOpen( &stream, *buffer, bufferSize );

	/* Since we can't write the outer header and public key until we write
	   the inner, encrypted private key, we leave enough space at the start
	   to contain this information and write the private key after that */
	sSkip( &stream, publicKeyInfoSize + 100 );
	privateKeyDataStart = sMemBufPtr( &stream );

	/* Write the envelope header if the private components are to be
	   encrypted */
	if( password != NULL )
		{
		const BYTE *streamStartPtr = sMemBufPtr( &stream );
		const int streamStart = ( int ) stell( &stream );
		int cmsEncrHeaderLength, encrKeyInfoLength;

		/* Determine the amount of expansion in the encrypted key due to block
		   padding */
		padSize = 8 - ( privateKeyInfoSize & 7 );

		/* Write the encryption information with a gap at the start for the
		   CMS header */
		sSkip( &stream, 32 );
		encrKeyInfoLength = writeEncryptionInformation( &stream,
											&iSessionKeyContext, password );
		if( cryptStatusError( encrKeyInfoLength ) )
			{
			krnlSendNotifier( cryptContext, RESOURCE_MESSAGE_UNLOCK );
			sMemClose( &stream );
			free( *buffer );
			return( encrKeyInfoLength );
			}
		cmsEncrHeaderLength = sizeofCMSencrHeader( OID_CMS_DATA,
											privateKeyInfoSize + padSize,
											iSessionKeyContext );

		/* Move back and add the CMS header for the cryptlib envelope.  This
		   writes the outer envelope header and version, the encrypted key,
		   and the inner encrypted data header.  Since we're using
		   KEKRecipientInfo, we use a version of 2 rather than 0 */
		sseek( &stream, streamStart );
		writeCMSheader( &stream, OID_CMS_ENVELOPEDDATA, \
						sizeofShortInteger( 2 ) + encrKeyInfoLength + \
						cmsEncrHeaderLength + privateKeyInfoSize + padSize );
		writeShortInteger( &stream, 2, DEFAULT_TAG );
		memmove( sMemBufPtr( &stream ), streamStartPtr + 32, encrKeyInfoLength );
		sSkip( &stream, encrKeyInfoLength );
		writeCMSencrHeader( &stream, OID_CMS_DATA,
							privateKeyInfoSize + padSize,
							iSessionKeyContext );
		}
	else
		/* Key is written as raw data */
		writeCMSheader( &stream, OID_CMS_DATA, privateKeyInfoSize );

	/* Write the private key data, PKCS #5-padded and encrypted if
	   necessary */
	bufPtr = sMemBufPtr( &stream );
	status = writePrivateKey( &stream, cryptContext );
	if( password != NULL )
		{
		int i;

		for( i = 0; i < padSize; i++ )
			sputc( &stream, padSize );
		if( cryptStatusOK( status ) )
			status = iCryptEncrypt( iSessionKeyContext, bufPtr,
									privateKeyInfoSize + padSize );
		iCryptDestroyObject( iSessionKeyContext );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( cryptContext, RESOURCE_MESSAGE_UNLOCK );
		sMemClose( &stream );
		free( *buffer );
		return( status );
		}
	writeEndIndef( &stream );
	privateKeyDataSize = sMemSize( &stream ) - ( publicKeyInfoSize + 100 );

	/* Now that we've written the private key data and know how long it is,
	   move back to the start and write the public key data.  First we write
	   the CMS outer header */
	sseek( &stream, 0 );
	writeCMSheader( &stream, OID_CRYPTLIB_PRIVATEKEY,
					sizeofShortInteger( 0 ) + publicKeyInfoSize +
					privateKeyDataSize );
	writeShortInteger( &stream, 0, DEFAULT_TAG );

	/* Write the public key field.  We can unlock the context as soon as
	   we've written this since we no longer need it */
	status = writePublicKey( &stream, cryptContext );
	krnlSendNotifier( cryptContext, RESOURCE_MESSAGE_UNLOCK );
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_BADPARM2 )
			status = CRYPT_BADPARM3;	/* Map error to correct parameter */
		sMemClose( &stream );
		free( *buffer );
		return( status );
		}

	/* Finally, move the private key data down to the end of the public key
	   data */
	memmove( sMemBufPtr( &stream ), privateKeyDataStart, privateKeyDataSize );
	*bufSize = sMemSize( &stream ) + privateKeyDataSize;

	/* Clean up */
	sMemDisconnect( &stream );
	return( CRYPT_OK );
	}

/* Take an existing complete private key record, extract only the encrypted
   key, and rewrite it as a new private key record with an exported cert as
   the public key components */

int convertPrivateKeyBuffer( void **buffer, int *bufSize,
							 const CRYPT_CERTIFICATE cryptCert,
							 const void *keyData )
	{
	STREAM stream;
	void *privateDataPtr;
	int privateDataSize, publicDataSize, bufferSize, certType, status;

	/* Clear the return values */
	*buffer = NULL;
	*bufSize = 0;

	/* Determine the type of the certificate */
	status = cryptGetCertComponentNumeric( cryptCert, CRYPT_CERTINFO_CERTTYPE,
										   &certType );
	if( cryptStatusError( status ) || \
		( certType != CRYPT_CERTTYPE_CERTREQUEST && \
		  certType != CRYPT_CERTTYPE_CERTIFICATE && \
		  certType != CRYPT_CERTTYPE_CERTCHAIN ) )
		return( CRYPT_BADPARM3 );

	/* Skip the header fields and public key field and determine the position
	   and size of the private key field */
	sMemConnect( &stream, keyData, STREAMSIZE_UNKNOWN );
	status = readCMSheader( &stream, keyFileOIDselection, NULL );
	readUniversal( &stream );	/* Public key fields */
	privateDataPtr = sMemBufPtr( &stream );
	if( !cryptStatusError( status ) )
		status = readSequence( &stream, &privateDataSize );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	privateDataSize = ( int ) sizeofObject( privateDataSize ); /* Include tag+len */

	/* Determine how big the exported public key information will be and
	   allocate a buffer for the combined public and private key data */
	status = iCryptExportCert( NULL, &publicDataSize, cryptCert );
	if( cryptStatusError( status ) )
		return( status );
	bufferSize = publicDataSize + privateDataSize + 64;
	if( ( *buffer = malloc( bufferSize ) ) == NULL )
		return( CRYPT_NOMEM );

	/* Write the public and private key data to the buffer */
	sMemOpen( &stream, *buffer, bufferSize );
	writeCMSheader( &stream, OID_CRYPTLIB_PRIVATEKEY, \
		sizeofShortInteger( 0 ) + ( int ) sizeofObject( publicDataSize ) + \
		privateDataSize );
	writeShortInteger( &stream, 0, DEFAULT_TAG );
	writeCtag( &stream, ( certType == CRYPT_CERTTYPE_CERTREQUEST ) ? \
		CTAG_PK_CERTREQUEST : ( certType == CRYPT_CERTTYPE_CERTIFICATE ) ? \
		CTAG_PK_CERTIFICATE : CTAG_PK_CERTCHAIN );
	writeLength( &stream, publicDataSize );
	status = iCryptExportCert( sMemBufPtr( &stream ), &publicDataSize,
							   cryptCert );
	if( cryptStatusOK( status ) )
		{
		sSkip( &stream, publicDataSize );
		swrite( &stream, privateDataPtr, privateDataSize );
		*bufSize = sMemSize( &stream );
		sMemDisconnect( &stream );
		}
	else
		{
		sMemClose( &stream );
		free( *buffer );
		}

	return( status );
	}

/****************************************************************************
*																			*
*						Key File Identification Routines					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "pgp.h"
#elif defined( INC_CHILD )
  #include "../envelope/pgp.h"
#else
  #include "envelope/pgp.h"
#endif /* Compiler-specific includes */

/* Identify a flat-file keyset without changing the stream position.  We have
   to return the keyset type as an int rather than a KEYSET_SUBTYPE because
   of complex header file nesting issues */

int getKeysetType( STREAM *stream )
	{
	KEYSET_SUBTYPE type = KEYSET_SUBTYPE_ERROR;
	BOOLEAN isPGP = FALSE;
	long objectLength, position = stell( stream );
	int length, value;

	/* Try and guess the basic type */
	value = sgetc( stream );
	if( value != BER_SEQUENCE )
		if( getCTB( value ) != PGP_CTB_PUBKEY && \
			getCTB( value ) != PGP_CTB_SECKEY )
			{
			sseek( stream, position );
			return( KEYSET_SUBTYPE_ERROR );
			}
		else
			isPGP = TRUE;

	/* If it looks like a PGP keyring, make sure the start of the file looks
	   OK */
	if( isPGP )
		{
		/* Try and establish the file type based on the initial CTB */
		if( getCTB( value ) == PGP_CTB_PUBKEY )
			type = KEYSET_SUBTYPE_PGP_PUBLIC;
		if( getCTB( value ) == PGP_CTB_SECKEY )
			type = KEYSET_SUBTYPE_PGP_PRIVATE;

		/* Perform a sanity check to make sure the rest looks like a PGP
		   keyring */
		length = ( int ) pgpGetLength( stream, value );
		if( type == KEYSET_SUBTYPE_PGP_PUBLIC )
			{
			if( length < 64 || length > 1024  )
				type = KEYSET_SUBTYPE_ERROR;
			}
		else
			if( length < 200 || length > 4096 )
				type = KEYSET_SUBTYPE_ERROR;
		value = sgetc( stream );
		if( value != PGP_VERSION_2 && value != PGP_VERSION_3 )
			type = KEYSET_SUBTYPE_ERROR;
		sseek( stream, position );
		return( type );
		}

	/* Read the length of the object.  This should be encoded with the DER
	   and be no longer than 16K */
	if( readLength( stream, &objectLength ) > 3 || objectLength > 16384 )
		{
		sseek( stream, position );
		return( KEYSET_SUBTYPE_ERROR );
		}

	/* Check for a SEQUENCE identifier field */
	if( peekTag( stream ) == BER_SEQUENCE )
		/* See the comment in the cryptlib envelope check for why we only do
		   a rather superficial check */
		type = KEYSET_SUBTYPE_X509;
	else
		{
		STREAM memStream;
		BYTE data[ 16 ];
		int dataLength, status;

		/* Read enough information to enable us to identify the object into a
		   memory stream */
		memset( data, 0, 16 );
		sread( stream, data, 16 );
		sMemConnect( &memStream, data, 16 );

		/* Check for a cryptlib private key file */
		status = readOID( &memStream, OID_CRYPTLIB_PRIVATEKEY );
		if( !cryptStatusError( status ) )
			type = KEYSET_SUBTYPE_CRYPTLIB;
		else
			{
			/* Check for a Netscape private key file */
			sseek( &memStream, 0 );
			if( !cryptStatusError( readOctetString( stream, data,
													&dataLength, 11 ) ) && \
				dataLength == 11 && !memcmp( data, "private-key", 11 ) )
				type = KEYSET_SUBTYPE_NETSCAPE;
			}

		sMemClose( &memStream );
		}

	sseek( stream, position );
	return( type );
	}
