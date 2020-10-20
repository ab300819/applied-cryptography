/****************************************************************************
*																			*
*					  Certificate Trust Management Routines					*
*						Copyright Peter Gutmann 1998-1999					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "asn1.h"
  #include "asn1keys.h"
  #include "cert.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1keys.h"
  #include "keymgmt/cert.h"
#endif /* Compiler-specific includes */

/* The ASN.1 object used to store trust information is as follows:

	TrustInfo ::= SEQUENCE {
		sCheck			INTEGER,				-- Fletcher chk.of subjName
		sHash			OCTET STRING SIZE(20),	-- Hash of subjectName
		publicKey		SubjectPublicKeyInfo	-- Trusted key
		} */

typedef struct TI {
	/* Identification information */
	int sCheck;
	BYTE sHash[ 20 ];			/* Checksum and hash of subjectName */

	/* The trusted key.  When we read trust info from a config file, the key
	   is stored as the encoded public key information from the cert to save
	   creating contexts which will never be used, when it's needed the
	   context is created on the fly from the pubkeyInfo.  When we get the
	   trust info from the user setting it, the context already exists and
	   the pubKey isn't used */
	void *pubKey;					/* Encoded public key */
	int pubKeySize;
	CRYPT_CONTEXT iCryptContext;	/* Public key context */

	/* Pointer to the next entry */
	struct TI *next;				/* Next trustInfo record in the chain */
	} TRUST_INFO;

/****************************************************************************
*																			*
*						Trust Information Management Routines				*
*																			*
****************************************************************************/

/* Locking variables used to serialise access to the trust information.  All
   functions declared static assume the trustInfo mutex is held by the
   calling function */

DECLARE_LOCKING_VARS( trustInfo )

/* The table of trust information */

static TRUST_INFO *trustInfoIndex[ 256 ];

/* Checksum and hash a DN */

static int checksumName( const BYTE *name, const int nameLength )
	{
	int sum1 = 0, sum2 = 0, i;

	/* Calculate an 8-bit Fletcher checksum of the name */
	for( i = 0; i < nameLength; i++ )
		{
		sum1 += name[ i ];
		sum2 += sum1;
		}

	return( sum2 & 0xFF );
	}

static void hashName( BYTE *hash, const BYTE *name, const int nameLength )
	{
	static HASHFUNCTION hashFunction = NULL;
	int hashInfoSize, hashInputSize, hashOutputSize;

	/* Get the hash algorithm information if necessary */
	if( hashFunction == NULL )
		getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashInputSize,
						   &hashOutputSize, &hashInfoSize );

	/* Hash the DN */
	hashFunction( NULL, hash, ( BYTE * ) name, nameLength, HASH_ALL );
	}

/* Add and delete a trust entry */

static int addTrustEntry( const int sCheck, const BYTE *sHash,
						  const CRYPT_CONTEXT iCryptContext,
						  const void *pubKey, const int pubKeySize )
	{
	TRUST_INFO *newElement;

	/* Allocate memory for the new element and copy the information across */
	if( ( newElement  = ( TRUST_INFO * ) malloc( sizeof( TRUST_INFO ) ) ) == NULL )
		return( CRYPT_NOMEM );
	memset( newElement, 0, sizeof( TRUST_INFO ) );
	if( pubKey != NULL )
		{
		/* The trusted key is being read from config data, remember it for
		   later use */
		if( ( newElement->pubKey = malloc( pubKeySize ) ) == NULL )
			{
			free( newElement );
			return( CRYPT_NOMEM );
			}
		memcpy( newElement->pubKey, pubKey, pubKeySize );
		newElement->pubKeySize = pubKeySize;
		newElement->iCryptContext = CRYPT_ERROR;
		}
	else
		{
		/* The trusted key exists as a context, remember it for later */
		krnlSendNotifier( iCryptContext, RESOURCE_IMESSAGE_INCREFCOUNT );
		newElement->iCryptContext = iCryptContext;
		}
	newElement->sCheck = sCheck;
	memcpy( newElement->sHash, sHash, 20 );

	/* Add it to the list */
	if( trustInfoIndex[ sCheck ] == NULL )
		trustInfoIndex[ sCheck ] = newElement;
	else
		{
		TRUST_INFO *trustInfoPtr;

		/* Add the new element to the end of the list */
		for( trustInfoPtr = trustInfoIndex[ sCheck ];
			 trustInfoPtr->next != NULL; trustInfoPtr = trustInfoPtr->next );
		trustInfoPtr->next = newElement;
		}

	return( CRYPT_OK );
	}

static void deleteTrustEntry( TRUST_INFO *trustInfoPtr )
	{
	if( trustInfoPtr->iCryptContext != CRYPT_ERROR )
		krnlSendNotifier( trustInfoPtr->iCryptContext,
						  RESOURCE_IMESSAGE_DECREFCOUNT );
	if( trustInfoPtr->pubKey != NULL )
		{
		zeroise( trustInfoPtr->pubKey, trustInfoPtr->pubKeySize );
		free( trustInfoPtr->pubKey );
		}
	memset( trustInfoPtr, 0, sizeof( TRUST_INFO ) );
	free( trustInfoPtr );
	}

/* Find the trust info entry for a given DN */

static TRUST_INFO *findTrustEntry( const void *name, const int nameLength )
	{
	const int trustInfoPos = checksumName( name, nameLength );
	TRUST_INFO *trustInfoPtr = trustInfoIndex[ trustInfoPos ];

	/* Check to see whether something with the issuers DN is present.  We
	   initially do a quick check using a checksum of the name to weed out
	   most entries, and only if this matches do we check the full hash */
	if( trustInfoPtr != NULL )
		{
		BYTE sHash[ 20 ];

		hashName( sHash, name, nameLength );
		while( trustInfoPtr != NULL )
			{
			if( !memcmp( trustInfoPtr->sHash, sHash, 20 ) )
				break;
			trustInfoPtr = trustInfoPtr->next;
			}
		}

	return( trustInfoPtr );
	}

/* Initialise and shut down the trust information */

int initTrustInfo( void )
	{
	/* Create any required thread synchronization variables and the trust
	   information table */
	initGlobalResourceLock( trustInfo );
	memset( trustInfoIndex, 0, sizeof( trustInfoIndex ) );

	return( CRYPT_OK );
	}

void endTrustInfo( void )
	{
	int i;

	lockGlobalResource( trustInfo );

	/* Destroy the chain of items at each table position */
	for( i = 0; i < 256; i++ )
		{
		TRUST_INFO *trustInfoPtr = trustInfoIndex[ i ];

		/* Destroy any items in the list */
		while( trustInfoPtr != NULL )
			{
			TRUST_INFO *itemToFree = trustInfoPtr;

			trustInfoPtr = trustInfoPtr->next;
			deleteTrustEntry( itemToFree );
			}
		}
	memset( trustInfoIndex, 0, sizeof( trustInfoIndex ) );

	unlockGlobalResource( trustInfo );
	deleteGlobalResourceLock( trustInfo );
	}

/* Check whether we have trust information present for the issuer of this
   cert.  If there's an entry, return the associated public key context if
   required */

CRYPT_CONTEXT findTrustInfo( const void *dn, const int dnSize,
							 const BOOLEAN instantiateContext )
	{
	TRUST_INFO *trustInfoPtr;
	CRYPT_CONTEXT iCryptContext = CRYPT_UNUSED;

	lockGlobalResource( trustInfo );

	/* If there's no entry present, return an error */
	if( ( trustInfoPtr = findTrustEntry( dn, dnSize ) ) == NULL )
		iCryptContext = CRYPT_ERROR;
	else
		/* If there's no need to return a context (this is just a yes/no
		   check), we're done */
		if( !instantiateContext )
			iCryptContext = CRYPT_OK;
	if( iCryptContext != CRYPT_UNUSED )
		{
		unlockGlobalResource( trustInfo );
		return( iCryptContext );
		}

	/* There's an entry present, if the public key context hasn't already
	   been instantiated, do it now */
	if( trustInfoPtr->iCryptContext == CRYPT_ERROR )
		{
		STREAM stream;
		int status;

		sMemConnect( &stream, trustInfoPtr->pubKey, trustInfoPtr->pubKeySize );
		status = readPublicKey( &stream, &trustInfoPtr->iCryptContext );
		sMemDisconnect( &stream );

		/* If the context was successfully instantiated, free the encoded key */
		if( !cryptStatusError( status ) )
			{
			zeroise( trustInfoPtr->pubKey, trustInfoPtr->pubKeySize );
			free( trustInfoPtr->pubKey );
			trustInfoPtr->pubKey = NULL;
			trustInfoPtr->pubKeySize = 0;
			}
		else
			trustInfoPtr->iCryptContext = CRYPT_ERROR;
		}
	iCryptContext = trustInfoPtr->iCryptContext;

	unlockGlobalResource( trustInfo );
	return( iCryptContext );
	}

/* Add trust information for a cert */

int addTrustInfo( const CERT_INFO *certInfoPtr )
	{
	int status = CRYPT_OK;

	lockGlobalResource( trustInfo );

	/* Make sure that trust information for this cert isn't already present */
	if( findTrustEntry( certInfoPtr->subjectDNptr,
						certInfoPtr->subjectDNsize ) == NULL )
		{
		BYTE sHash[ 20 ];
		int sCheck;

		/* Generate the checksum and hash of the certs subject name */
		sCheck = checksumName( certInfoPtr->subjectDNptr,
							   certInfoPtr->subjectDNsize );
		hashName( sHash, certInfoPtr->subjectDNptr, certInfoPtr->subjectDNsize );

		status = addTrustEntry( sCheck, sHash, certInfoPtr->iCryptContext,
								NULL, 0 );
		}
	else
		status = CRYPT_INITED;

	unlockGlobalResource( trustInfo );
	return( status );
	}

/* Delete trust information for a cert */

int deleteTrustInfo( const CERT_INFO *certInfoPtr )
	{
	TRUST_INFO *entryToDelete;
	int status = CRYPT_OK;

	lockGlobalResource( trustInfo );

	/* Find the entry to delete */
	entryToDelete = findTrustEntry( certInfoPtr->subjectDNptr,
									certInfoPtr->subjectDNsize );
	if( entryToDelete != NULL )
		{
		TRUST_INFO *trustInfoPtr, *nextEntry;
		const int trustInfoPos = checksumName( certInfoPtr->subjectDNptr,
											   certInfoPtr->subjectDNsize );
		/* Delete the entry from the list */
		trustInfoPtr = trustInfoIndex[ trustInfoPos ];
		nextEntry = entryToDelete->next;
		if( entryToDelete == trustInfoPtr )
			{
			/* Special case for the start of the list */
			deleteTrustEntry( entryToDelete );
			trustInfoIndex[ trustInfoPos ] = nextEntry;
			}
		else
			{
			/* Find the previous entry in the list and link it to the one
			   which follows the deleted entry */
			while( trustInfoPtr->next != entryToDelete )
				   trustInfoPtr = trustInfoPtr->next;
			deleteTrustEntry( entryToDelete );
			trustInfoPtr->next = nextEntry;
			}
		}
	else
		status = CRYPT_DATA_NOTFOUND;

	unlockGlobalResource( trustInfo );
	return( status );
	}

/****************************************************************************
*																			*
*								Read/Write TrustInfo						*
*																			*
****************************************************************************/

/* Read/write a trust item */

static int readTrustItem( STREAM *stream, int *sCheck, BYTE *sHash,
						  void **pubKeyPtr, int *pubKeySize )
	{
	long value;
	int totalLength, dummy, status;

	/* Read the primitive fields at the start of the trust info */
	readSequence( stream, &totalLength );
	readShortInteger( stream, &value );
	*sCheck = ( int ) value;
	status = readOctetString( stream, sHash, &dummy, 20 );
	if( cryptStatusError( status ) )
		return( status );
		
	/* Decode the information on the public key data */
	*pubKeyPtr = sMemBufPtr( stream );
	status = getObjectLength( *pubKeyPtr, totalLength - \
			( int ) ( sizeofShortInteger( value ) + sizeofObject( 20 ) ) );
	if( cryptStatusError( status ) )
		return( status );
	*pubKeySize = status;

	return( CRYPT_OK );
	}

static int writeTrustItem( STREAM *stream, const TRUST_INFO *trustInfoPtr )
	{
	int pubKeySize = trustInfoPtr->pubKeySize;

	if( trustInfoPtr->iCryptContext != CRYPT_ERROR )
		{
		pubKeySize = sizeofPublicKey( trustInfoPtr->iCryptContext );
		if( cryptStatusError( pubKeySize ) )
			return( 0 );	/* Context was signalled, skip this entry */
		}

	writeSequence( stream, \
				   sizeofShortInteger( ( long ) trustInfoPtr->sCheck ) + \
				   ( int ) sizeofObject( 20 ) + pubKeySize );
	writeShortInteger( stream, trustInfoPtr->sCheck, DEFAULT_TAG );
	writeOctetString( stream, trustInfoPtr->sHash, 20, DEFAULT_TAG );
	if( trustInfoPtr->iCryptContext != CRYPT_ERROR )
		writePublicKey( stream, trustInfoPtr->iCryptContext );
	else
		swrite( stream, trustInfoPtr->pubKey, trustInfoPtr->pubKeySize );

	return( sMemSize( stream ) );
	}

/* Add a trust item in encoded form */

int setTrustItem( void *itemBuffer, const int itemLength,
				  const BOOLEAN isEncoded )
	{
	BYTE buffer[ CRYPT_MAX_PKCSIZE * 2 ], sHash[ 20 ];
	STREAM stream;
	void *pubKeyPtr;
	int sCheck, length = itemLength, pubKeySize, status;

	/* Decode the data if necessary */
	if( isEncoded )
		{
		length = base64decode( buffer, itemBuffer, itemLength,
							   CRYPT_CERTFORMAT_NONE );
		if( !length )
			return( CRYPT_BADDATA );
		}

	/* Read the trust information */
	sMemConnect( &stream, isEncoded ? buffer : itemBuffer, length );
	status = readTrustItem( &stream, &sCheck, sHash, &pubKeyPtr, &pubKeySize );
	sMemDisconnect( &stream );
	if( cryptStatusOK( status ) )
		{
		lockGlobalResource( trustInfo );
		status = addTrustEntry( sCheck, sHash, CRYPT_ERROR, pubKeyPtr,
								pubKeySize );
		unlockGlobalResource( trustInfo );
		}

	return( status );
	}

/* Return the next trust item in encoded form */

int getTrustItem( void **statePtr, int *stateIndex, void *itemBuffer,
				  int *itemLength, const BOOLEAN encodeData )
	{
	TRUST_INFO *trustInfoPtr = ( TRUST_INFO * ) *statePtr;
	BOOLEAN gotTrustItem = FALSE;
	int trustInfoPos = *stateIndex, length;

	lockGlobalResource( trustInfo );

	do
		{
		/* If there's nothing left in the current chain of entries, move on
		   to the next chain */
		if( trustInfoPtr == NULL && trustInfoPos < 255 )
			trustInfoPtr = trustInfoIndex[ ++trustInfoPos ];

		/* If there's an entry present, return it to the caller */
		if( trustInfoPtr != NULL )
			{
			BYTE buffer[ CRYPT_MAX_PKCSIZE * 2 ];
			STREAM stream;

			/* Write the trust information to the output buffer, encoding it
			   if necessary */
			sMemConnect( &stream, encodeData ? buffer : itemBuffer,
						 STREAMSIZE_UNKNOWN );
			length = writeTrustItem( &stream, trustInfoPtr );
			sMemDisconnect( &stream );
			if( !length )
				{
				/* The write may have failed because the context was
				   signalled, skip this trust item and continue */
				trustInfoPtr = trustInfoPtr->next;
				continue;
				}
			if( encodeData )
				length = base64encode( itemBuffer, buffer, length,
									   CRYPT_CERTTYPE_NONE,
									   CRYPT_CERTFORMAT_NONE );
			if( itemLength != NULL )
				*itemLength = length;

			/* Update the state and exit */
			*statePtr = trustInfoPtr->next;
			*stateIndex = trustInfoPos;
			gotTrustItem = TRUE;
			break;
			}
		}
	while( trustInfoPos < 255 );

	unlockGlobalResource( trustInfo );
	return( gotTrustItem );
	}
