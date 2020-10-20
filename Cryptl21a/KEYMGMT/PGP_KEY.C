/****************************************************************************
*																			*
*							  PGP Key Read Routines							*
*						Copyright Peter Gutmann 1992-1998					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "pgp.h"
  #include "asn1keys.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../envelope/pgp.h"
  #include "asn1keys.h"
#else
  #include "crypt.h"
  #include "envelope/pgp.h"
  #include "keymgmt/asn1keys.h"
#endif /* Compiler-specific includes */

/* Since the key components can consume a sizeable amount of memory, we
   allocate storage for them dynamically.  This also keeps them in one place
   for easy sanitization */

typedef struct {
	/* Key components (in PGP format) */
	BYTE n[ PGP_MAX_MPISIZE ], e[ PGP_MAX_MPISIZE ], d[ PGP_MAX_MPISIZE ];
	BYTE p[ PGP_MAX_MPISIZE ], q[ PGP_MAX_MPISIZE ], u[ PGP_MAX_MPISIZE ];
	int nLen, eLen, dLen, pLen, qLen, uLen;

	/* Key components (in cryptlib format) */
	CRYPT_PKCINFO_RSA rsaKey;

	/* userID for this key */
	char userID[ PGP_MAX_USERIDSIZE ];
	} PGP_INFO;

/* Prototypes for functions in cryptapi.c */

BOOLEAN matchSubstring( const char *subString, const char *string );

/****************************************************************************
*																			*
*								Read Byte/Word/Long 						*
*																			*
****************************************************************************/

/* Routines to read BYTE, WORD, LONG */

static BYTE fgetByte( STREAM *stream )
	{
	return( ( BYTE ) sgetc( stream ) );
	}

static WORD fgetWord( STREAM *stream )
	{
	WORD value;

	value = ( ( WORD ) sgetc( stream ) ) << 8;
	value |= ( WORD ) sgetc( stream );
	return( value );
	}

static LONG fgetLong( STREAM *stream )
	{
	LONG value;

	value = ( ( LONG ) sgetc( stream ) ) << 24;
	value |= ( ( LONG ) sgetc( stream ) ) << 16;
	value |= ( ( LONG ) sgetc( stream ) ) << 8;
	value |= ( LONG ) sgetc( stream );
	return( value );
	}

/****************************************************************************
*																			*
*							PGP Keyring Read Routines						*
*																			*
****************************************************************************/

/* Skip to the start of the next key packet */

static void skipToKeyPacket( STREAM *stream )
	{
	int ctb;

	/* Skip any following non-key packets */
	while( ctb = fgetByte( stream ), sGetStatus( stream ) == CRYPT_OK && \
		   getCTB( ctb ) != PGP_CTB_PUBKEY && getCTB( ctb ) != PGP_CTB_SECKEY )
		{
		int length = ( int ) pgpGetLength( stream, ctb );

		/* If we get an impossibly large packet, assume we're in trouble and
		   set the EOF status */
		if( length > 5000 )
			sSetError( stream, CRYPT_UNDERFLOW );
		else
			/* Skip the current packet */
			sSkip( stream, length );
		}

	/* Finally, put back the last CTB we read unless we've reached the end
	   of the file */
	if( sGetStatus( stream ) == CRYPT_OK )
		sungetc( stream );
	}

/* Generate a cryptlib-style key ID for the PGP key and check it against the
   given key ID.  This will really suck with large public keyrings since it
   requires creating a context for each key we check, but there's no easy
   way around this */

static BOOLEAN matchKeyID( PGP_INFO *pgpInfo, const BYTE *requiredID )
	{
	CRYPT_CONTEXT iCryptContext;
	CRYPT_PKCINFO_RSA *rsaKeyPtr = &pgpInfo->rsaKey;
	BYTE keyID[ KEYID_SIZE ];
	int status;

	/* Generate the key ID */
	status = iCryptCreateContext( &iCryptContext, CRYPT_ALGO_RSA,
								  CRYPT_MODE_PKC );
	if( cryptStatusError( status ) )
		return( FALSE );
	cryptInitComponents( rsaKeyPtr, CRYPT_COMPONENTS_BIGENDIAN,
						 CRYPT_KEYTYPE_PUBLIC );
	cryptSetComponent( rsaKeyPtr->n, pgpInfo->n, pgpInfo->nLen );
	cryptSetComponent( rsaKeyPtr->e, pgpInfo->e, pgpInfo->eLen );
	status = iCryptLoadKey( iCryptContext, rsaKeyPtr, CRYPT_UNUSED );
	if( cryptStatusOK( status ) )
		{
		ICRYPT_QUERY_INFO iCryptQueryInfo;

		status = iCryptQueryContext( iCryptContext, &iCryptQueryInfo );
		memcpy( keyID, iCryptQueryInfo.keyID, KEYID_SIZE );
		}
	cryptDestroyComponents( rsaKeyPtr );
	iCryptDestroyObject( iCryptContext );
	if( cryptStatusError( status ) )
		return( FALSE );

	/* Check if it's the same as the key ID we're looking for */
	return( !memcmp( requiredID, keyID, KEYID_SIZE ) ? TRUE : FALSE );
	}

/* Read a key and check whether it matches the required user ID */

static int readKey( PGP_INFO *pgpInfo, STREAM *stream,
					const CRYPT_KEYID_TYPE keyIDtype, const void *keyID,
					const char *password, void *keyData,
					const BOOLEAN readPublicKey )
	{
	STREAM keyStream;
	BOOLEAN isEncrypted, gotUserID = FALSE, foundKey = FALSE;
	BOOLEAN isPublicKey = TRUE;
	WORD checkSum, packetChecksum;
	BYTE keyIV[ PGP_IDEA_IVSIZE ];
	int ctb, length, i, status = CRYPT_OK;

	/* If we're reading a full key packet, read the keyring headers */
	if( stream != NULL )
		{
		/* Skip CTB, packet length, and version byte */
		ctb = sgetc( stream );
		if( getCTB( ctb ) == PGP_CTB_SECKEY )
			isPublicKey = FALSE;
		else
			if( getCTB( ctb ) != PGP_CTB_PUBKEY )
				return( sGetStatus( stream ) != CRYPT_OK ? \
						CRYPT_DATA_NOTFOUND : CRYPT_BADDATA );
		length = ( int ) pgpGetLength( stream, ctb );
		if( ( i = fgetByte( stream ) ) != PGP_VERSION_2 && i != PGP_VERSION_3 )
			{
			/* Unknown version number, skip this packet */
			sungetc( stream );
			skipToKeyPacket( stream );
			return( -1000 );
			}

		/* Read the timestamp and validity period and make sure what's left
		   will fit into the buffer */
		fgetLong( stream );
		fgetWord( stream );
		length -= PGP_SIZE_BYTE + PGP_SIZE_LONG + PGP_SIZE_WORD;
		if( length > MAX_PRIVATE_KEYSIZE )
			return( CRYPT_BADDATA );

		/* Read the rest of the record into the memory buffer */
		if( sread( stream, keyData, length ) != CRYPT_OK )
			return( sGetStatus( stream ) );
		}
	else
		/* If we're rereading a cached key from a memory stream it'll be a
		   private key */
		isPublicKey = FALSE;

	/* Read the public key components */
	sMemConnect( &keyStream, keyData, STREAMSIZE_UNKNOWN );
	if( ( i = fgetByte( &keyStream ) ) != PGP_ALGO_RSA )
		{
		/* Unknown PKE algorithm type, skip this packet */
		skipToKeyPacket( stream );
		return( -1000 );
		}
	if( ( pgpInfo->nLen = pgpReadMPI( &keyStream, pgpInfo->n ) ) == CRYPT_ERROR || \
		( pgpInfo->eLen = pgpReadMPI( &keyStream, pgpInfo->e ) ) == CRYPT_ERROR )
		{
		skipToKeyPacket( stream );
		return( -1000 );
		}

	/* If it's a private keyring, read in the private key components */
	if( !isPublicKey )
		{
		/* Handle decryption info for secret components if necessary */
		isEncrypted = ( ctb = fgetByte( &keyStream ) ) == PGP_ALGO_IDEA;
		if( isEncrypted )
			for( i = 0; i < PGP_IDEA_IVSIZE; i++ )
				keyIV[ i ] = sgetc( &keyStream );

		/* Read in private key components and checksum */
		if( ( pgpInfo->dLen = pgpReadMPI( &keyStream, pgpInfo->d ) ) == CRYPT_ERROR || \
			( pgpInfo->pLen = pgpReadMPI( &keyStream, pgpInfo->p ) ) == CRYPT_ERROR || \
			( pgpInfo->qLen = pgpReadMPI( &keyStream, pgpInfo->q ) ) == CRYPT_ERROR || \
			( pgpInfo->uLen = pgpReadMPI( &keyStream, pgpInfo->u ) ) == CRYPT_ERROR )
			{
			skipToKeyPacket( stream );
			return( -1000 );
			}
		packetChecksum = fgetWord( &keyStream );
		}
	sMemDisconnect( &keyStream );

	/* If it's a full keyring stream, check for a keyID/userID match */
	if( stream != NULL )
		{
		/* If we're searching by key ID, check whether this is the packet we
		   want */
		if( keyIDtype == CRYPT_KEYID_OBJECT )
			if( matchKeyID( pgpInfo, keyID ) )
				foundKey = TRUE;
			else
				{
				/* These aren't the keys you're looking for... you may go
				   about your business... move along, move along */
				skipToKeyPacket( stream );
				return( -1000 );
				}

		/* Read the userID packet(s).  We also make sure we get at least one
		   userID if we've already got a match based on a key ID */
		while( !foundKey || !gotUserID )
			{
			/* Skip keyring trust and signature packets */
			ctb = fgetByte( stream );
			while( getCTB( ctb ) == PGP_CTB_TRUST || \
				   getCTB( ctb ) == PGP_CTB_SIGNATURE )
				{
				/* Skip the packet */
				length = ( int ) pgpGetLength( stream, ctb );
				sSkip( stream, length );
				ctb = fgetByte( stream );
				}

			/* Check if we've got a userID packet now */
			if( getCTB( ctb ) != PGP_CTB_USERID )
				{
				sungetc( stream );

				/* If we saw at least one userID, everything was OK.  Before
				   we exit we move to the next key packet so we can continue
				   looking for keys if required */
				if( gotUserID )
					{
					skipToKeyPacket( stream );
					return( foundKey ? CRYPT_OK : -1000 );
					}

				/* We still don't have a userID CTB, complain */
				skipToKeyPacket( stream );
				return( -1000 );
				}
			length = ( int ) pgpGetLength( stream, ctb );
			for( i = 0; i < length && i < PGP_MAX_USERIDSIZE; i++ )
				pgpInfo->userID[ i ] = fgetByte( stream );
			pgpInfo->userID[ i ] = '\0';
			if( i > length )
				sSkip( stream, i - length );/* Skip excessively long userID */
			gotUserID = TRUE;

			/* Check if it's the one we want */
			if( keyIDtype != CRYPT_KEYID_OBJECT && \
				( keyID == CRYPT_KEYSET_GETFIRST || \
				  keyID == CRYPT_KEYSET_GETNEXT || \
				  matchSubstring( ( char * ) keyID, pgpInfo->userID ) ) )
				foundKey = TRUE;
			}
		}

	/* Process the secret-key fields if necessary */
	if( !readPublicKey )
		{
		/* Decrypt the secret-key fields if necessary */
		if( isEncrypted )
			{
			CRYPT_CONTEXT iCryptContext;

			/* If no password is supplied, let the caller know they need a
			   password */
			if( password == NULL )
				{
				if( stream != NULL )
					skipToKeyPacket( stream );
				return( CRYPT_WRONGKEY );
				}

			/* Convert the user password into an IDEA encryption context */
			status = iCryptCreateContext( &iCryptContext, CRYPT_ALGO_IDEA,
										  CRYPT_MODE_CFB );
			if( cryptStatusOK( status ) )
				status = pgpPasswordToKey( iCryptContext, password );
			if( cryptStatusOK( status ) )
				status = iCryptLoadIV( iCryptContext, keyIV, 8 );
			if( cryptStatusError( status ) )
				return( status );

			/* Decrypt the secret-key fields */
			iCryptDecrypt( iCryptContext, pgpInfo->d, bitsToBytes( pgpInfo->dLen ) );
			iCryptDecrypt( iCryptContext, pgpInfo->p, bitsToBytes( pgpInfo->pLen ) );
			iCryptDecrypt( iCryptContext, pgpInfo->q, bitsToBytes( pgpInfo->qLen ) );
			iCryptDecrypt( iCryptContext, pgpInfo->u, bitsToBytes( pgpInfo->uLen ) );
			iCryptDestroyObject( iCryptContext );
			}

		/* Make sure all was OK */
		checkSum = pgpChecksumMPI( pgpInfo->d, pgpInfo->dLen );
		checkSum += pgpChecksumMPI( pgpInfo->p, pgpInfo->pLen );
		checkSum += pgpChecksumMPI( pgpInfo->q, pgpInfo->qLen );
		checkSum += pgpChecksumMPI( pgpInfo->u, pgpInfo->uLen );
		if( checkSum != packetChecksum )
			status = isEncrypted ? CRYPT_WRONGKEY : CRYPT_BADDATA;
		}

	/* If it's a full keyring stream, move on to the next key packet so we
	   can continue looking for keys if required */
	if( stream != NULL )
		skipToKeyPacket( stream );
	return( status );
	}

/* Create an encryption context from the PGP key info */

static int createKey( CRYPT_CONTEXT *iCryptContext, PGP_INFO *pgpInfo,
					  const BOOLEAN isPublicKey )
	{
	CRYPT_PKCINFO_RSA *rsaKey;
	int status;

	/* Load the key into the encryption context */
	status = iCryptCreateContext( iCryptContext, CRYPT_ALGO_RSA, CRYPT_MODE_PKC );
	if( cryptStatusError( status ) )
		return( status );
	rsaKey = &pgpInfo->rsaKey;
	if( isPublicKey )
		{
		/* Set up the RSA public-key fields */
		cryptInitComponents( rsaKey, CRYPT_COMPONENTS_BIGENDIAN,
							 CRYPT_KEYTYPE_PUBLIC );
		cryptSetComponent( rsaKey->n, pgpInfo->n, pgpInfo->nLen );
		cryptSetComponent( rsaKey->e, pgpInfo->e, pgpInfo->eLen );
		}
	else
		{
		/* Set up the RSA private-key fields */
		cryptInitComponents( rsaKey, CRYPT_COMPONENTS_BIGENDIAN,
							 CRYPT_KEYTYPE_PRIVATE );
		cryptSetComponent( rsaKey->n, pgpInfo->n, pgpInfo->nLen );
		cryptSetComponent( rsaKey->e, pgpInfo->e, pgpInfo->eLen );
		cryptSetComponent( rsaKey->d, pgpInfo->d, pgpInfo->dLen );
		cryptSetComponent( rsaKey->p, pgpInfo->p, pgpInfo->pLen );
		cryptSetComponent( rsaKey->q, pgpInfo->q, pgpInfo->qLen );
		cryptSetComponent( rsaKey->u, pgpInfo->u, pgpInfo->uLen );
		}
	status = iCryptLoadKey( *iCryptContext, rsaKey, CRYPT_UNUSED );
	cryptDestroyComponents( rsaKey );
	if( cryptStatusError( status ) )
		{
		iCryptDestroyObject( *iCryptContext );
		return( status );
		}

	return( CRYPT_OK );
	}

/* Get a public or private key from a file or memory buffer and return it in
   an encryption context */

int pgpGetKey( STREAM *stream, const CRYPT_KEYID_TYPE keyIDtype,
			   const void *keyID, const char *password, void *keyData,
			   CRYPT_CONTEXT *iCryptContext, char *userID,
			   const BOOLEAN readPublicKey )
	{
	PGP_INFO *pgpInfo;
	int status = CRYPT_OK;

	/* Allocate memory for the PGP key info.  This is somewhat messy
	   security-wise for private keys because we first read the PGP key
	   components into the pgpInfo structure, decrypt and unmangle them, and
	   then move them into the rsaInfo structure in preparation for loading
	   them into an encryption context, but there's no real way around this.
	   The memory is sanitised immediately after the transfer, so the
	   critical information is only held in one of the two structures at any
	   one time */
	if( ( pgpInfo = malloc( sizeof( PGP_INFO ) ) ) == NULL )
		return( CRYPT_NOMEM );
	memset( pgpInfo, 0, sizeof( PGP_INFO ) );

	/* Try and find the required key in the file */
	do
		status = readKey( pgpInfo, stream, keyIDtype, keyID, password,
						  keyData, readPublicKey );
	while( stream != NULL && status == -1000 );
	if( stream != NULL && userID != NULL && \
		( status == CRYPT_OK || status == CRYPT_WRONGKEY ) )
		{
		int length = min( strlen( pgpInfo->userID ), CRYPT_MAX_TEXTSIZE - 1 );

		/* Remember the userID (even if the private-key decrypt failed) so we
		   can report who the key belongs to to the caller */
		strncpy( userID, pgpInfo->userID, length );
		userID[ length ] = '\0';
		}
	if( cryptStatusOK( status ) )
		status = createKey( iCryptContext, pgpInfo, readPublicKey );

	/* Clean up */
	zeroise( pgpInfo, sizeof( PGP_INFO ) );
	free( pgpInfo );

	return( status );
	}
