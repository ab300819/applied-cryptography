/****************************************************************************
*																			*
*						cryptlib Enveloping Test Routines					*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _MSC_VER
  #include "../capi.h"
  #include "../test/test.h"
#else
  #include "capi.h"
  #include "test/test.h"
#endif /* Braindamaged MSC include handling */

/* Generic I/O buffer size.  This has to be of a reasonable size so we can
   handle S/MIME signatures chains */

#if defined( __MSDOS__ ) && defined( __TURBOC__ )
  #define BUFFER_SIZE		/*6144/**/3072/**/
#else
  #define BUFFER_SIZE		8192
#endif /* __MSDOS__ && __TURBOC__ */

/* Test data to use for the self-test */

#define ENVELOPE_TESTDATA		( ( BYTE * ) "Some test data" )
#define ENVELOPE_TESTDATA_SIZE	15

/* External flag which indicates that the key read routines work OK.  This is
   set by earlier self-test code, if it isn't set some of the enveloping
   tests are disabled */

extern int keyReadOK;

/****************************************************************************
*																			*
*								Utility Routines 							*
*																			*
****************************************************************************/

BYTE FAR_BSS buffer[ BUFFER_SIZE ];

/* Common routines to create an envelope, add enveloping information, push
   data, pop data, and destroy an envelope */

static int createEnvelope( CRYPT_ENVELOPE *envelope, const BOOLEAN isCMS )
	{
	int status;

	/* Create the envelope */
	if( isCMS )
		status = cryptCreateEnvelopeEx( envelope, CRYPT_FORMAT_CMS,
										CRYPT_USE_DEFAULT );
	else
		status = cryptCreateEnvelope( envelope );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateEnvelope() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

static int createDeenvelope( CRYPT_ENVELOPE *envelope )
	{
	int status;

	/* Create the envelope */
	status = cryptCreateDeenvelope( envelope );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateDeevelope() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

static int addEnvInfoString( const CRYPT_ENVELOPE envelope,
							 const CRYPT_ENVINFO_TYPE type,
							 const void *envInfo, const int envInfoLen )
	{
	int status;

	status = cryptAddEnvComponentString( envelope, type, envInfo, envInfoLen );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddEnvelopeInfoString() failed with error code %d, "
				"line %d\n", status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

static int addEnvInfoNumeric( const CRYPT_ENVELOPE envelope,
							  const CRYPT_ENVINFO_TYPE type,
							  const int envInfo )
	{
	int status;

	status = cryptAddEnvComponentNumeric( envelope, type, envInfo );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddEnvelopeInfoNumeric() failed with error code %d, "
				"line %d\n", status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

static int pushData( const CRYPT_ENVELOPE envelope, const BYTE *buffer,
					 const int length, const void *stringEnvInfo,
					 const int numericEnvInfo )
	{
	int status, bytesIn;

	/* Push in the data */
	status = cryptPushData( envelope, buffer, length, &bytesIn );
	if( status == CRYPT_ENVELOPE_RESOURCE )
		{
		int cryptEnvInfo;

		/* Print the envelope information types we need to continue */
		cryptAddEnvComponentNumeric( envelope,
					CRYPT_ENVINFO_CURRENT_COMPONENT, CRYPT_CURSOR_FIRST );
		status = cryptGetEnvComponentNumeric( envelope,
					CRYPT_ENVINFO_CURRENT_COMPONENT, &cryptEnvInfo );
		if( cryptStatusError( status ) )
			{
			printf( "cryptGetEnvComponentNumeric() failed with error code "
					"%d, line %d\n", status, __LINE__ );
			return( CRYPT_ERROR );
			}

		/* Add the appropriate enveloping information */
		do
			{
			char nameBuffer[ CRYPT_MAX_TEXTSIZE + 1 ];

			switch( cryptEnvInfo )
				{
				case CRYPT_ENVINFO_PRIVATEKEY:
					puts( "Need private key." );
					status = cryptGetResourceOwnerName( envelope, nameBuffer );
					if( status == CRYPT_OK )
						break;	/* Key present, not encrypted */
					if( status == CRYPT_DATA_NOTFOUND )
						break;	/* Private key for this user not present */

					/* Private key is present, need password to decrypt */
					printf( "Need password to decrypt private key for '%s'.\n",
							nameBuffer );
					if( !addEnvInfoString( envelope, CRYPT_ENVINFO_PASSWORD,
								stringEnvInfo, strlen( stringEnvInfo ) ) )
						return( CRYPT_ERROR );
					break;

				case CRYPT_ENVINFO_PASSWORD:
					puts( "Need user password." );
					if( !addEnvInfoString( envelope, CRYPT_ENVINFO_PASSWORD,
								stringEnvInfo, strlen( stringEnvInfo ) ) )
						return( CRYPT_ERROR );
					break;

				case CRYPT_ENVINFO_SESSIONKEY:
					puts( "Need session key." );
					if( !addEnvInfoNumeric( envelope, CRYPT_ENVINFO_SESSIONKEY,
											numericEnvInfo ) )
						return( CRYPT_ERROR );
					break;

				case CRYPT_ENVINFO_KEY:
					puts( "Need conventional encryption key." );
					break;

				case CRYPT_ENVINFO_SIGNATURE:
					/* If we've processed the entire data block in one go,
					   we may end up with only signature information
					   available, in which case we defer processing them
					   until after we've finished with the deenveloped data */
					break;

				default:
					printf( "Need unknown enveloping information type %d.\n",
							cryptEnvInfo );
					return( CRYPT_ERROR );
				}
			}
		while( cryptAddEnvComponentNumeric( envelope,
			CRYPT_ENVINFO_CURRENT_COMPONENT, CRYPT_CURSOR_NEXT ) == CRYPT_OK );
		}
	else
		if( cryptStatusError( status ) )
			{
			printf( "cryptPushData() failed with error code %d, line %d\n",
					status, __LINE__ );
			return( CRYPT_ERROR );
			}
	if( bytesIn != length )
		{
		printf( "cryptPushData() only copied %d of %d bytes, line %d\n",
				bytesIn, length, __LINE__ );
		return( CRYPT_ERROR );
		}

	/* Flush the data */
	status = cryptPushData( envelope, NULL, 0, NULL );
	if( cryptStatusError( status ) && status != CRYPT_COMPLETE )
		{
		printf( "cryptPushData() (flush) failed with error code %d, line "
				"%d\n", status, __LINE__ );
		return( CRYPT_ERROR );
		}

	return( bytesIn );
	}

static int popData( CRYPT_ENVELOPE envelope, BYTE *buffer, int bufferSize )
	{
	int status, bytesOut;

	status = cryptPopData( envelope, buffer, bufferSize, &bytesOut );
	if( cryptStatusError( status ) )
		{
		printf( "cryptPopData() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( CRYPT_ERROR );
		}

	return( bytesOut );
	}

static int destroyEnvelope( CRYPT_ENVELOPE envelope )
	{
	int status;

	/* Destroy the envelope */
	status = cryptDestroyEnvelope( envelope );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyEnvelope() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

/****************************************************************************
*																			*
*							Enveloping Test Routines 						*
*																			*
****************************************************************************/

/* Test various parts of the enveloping code */

static int envelopeData( const BOOLEAN useDatasize )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	int count;

	if( useDatasize )
		puts( "Testing plain data enveloping with datasize hint..." );
	else
		puts( "Testing plain data enveloping..." );

	/* Create the envelope, push in the data, pop the enveloped result, and
	   destroy the envelope */
	if( !createEnvelope( &cryptEnvelope, FALSE ) )
		return( FALSE );
	if( useDatasize )
		cryptAddEnvComponentNumeric( cryptEnvelope, CRYPT_ENVINFO_DATASIZE,
									 ENVELOPE_TESTDATA_SIZE );
	count = pushData( cryptEnvelope, ENVELOPE_TESTDATA,
					  ENVELOPE_TESTDATA_SIZE, NULL, 0 );
	if( count == CRYPT_ERROR )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( count == CRYPT_ERROR )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "Enveloped data has size %d bytes.\n", count );
	debugDump( ( useDatasize ) ? "env_dat" : "env_datn", buffer, count );

	/* Create the envelope, push in the data, pop the de-enveloped result,
	   and destroy the envelope */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	count = pushData( cryptEnvelope, buffer, count, NULL, 0 );
	if( count == CRYPT_ERROR )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( count == CRYPT_ERROR )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Make sure the result matches what we pushed */
	if( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( buffer, ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}

	/* Clean up */
	puts( "Enveloping of plain data succeeded.\n" );
	return( TRUE );
	}

int testEnvelopeData( void )
	{
	if( !envelopeData( FALSE ) )
		return( FALSE );
	return( envelopeData( TRUE ) );
	}

static int envelopeSessionCrypt( const BOOLEAN useDatasize )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_CONTEXT cryptContext;
	CRYPT_ALGO cryptAlgo = selectCipher( CRYPT_ALGO_CAST );
	int count;

	if( useDatasize )
		puts( "Testing raw-session-key encrypted enveloping with datasize hint..." );
	else
		puts( "Testing raw-session-key encrypted enveloping..." );

	/* If this version has been built without support for CAST-128, the self-
	   test will fall back to the (always available) Blowfish, however this
	   doesn't have an OID defined so we need to convert the choice to 3DES */
	if( cryptAlgo == CRYPT_ALGO_BLOWFISH )
		cryptAlgo = CRYPT_ALGO_3DES;

	/* Create the session key context.  We don't check for errors here since
	   this code will already have been tested earlier */
	cryptCreateContext( &cryptContext, cryptAlgo, CRYPT_MODE_CBC );
	cryptLoadKey( cryptContext, "0123456789ABCDEF", 16 );

	/* Create the envelope, push in a password and the data, pop the
	   enveloped result, and destroy the envelope */
	if( !createEnvelope( &cryptEnvelope, FALSE ) || \
		!addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_SESSIONKEY,
							cryptContext ) )
		return( FALSE );
	if( useDatasize )
		cryptAddEnvComponentNumeric( cryptEnvelope, CRYPT_ENVINFO_DATASIZE,
									 ENVELOPE_TESTDATA_SIZE );
	count = pushData( cryptEnvelope, ENVELOPE_TESTDATA,
					  ENVELOPE_TESTDATA_SIZE, NULL, 0 );
	if( count == CRYPT_ERROR )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( count == CRYPT_ERROR )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "Enveloped data has size %d bytes.\n", count );
	debugDump( ( useDatasize ) ? "env_ses" : "env_sesn", buffer, count );

	/* Create the envelope, push in the data, pop the de-enveloped result,
	   and destroy the envelope */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	count = pushData( cryptEnvelope, buffer, count, NULL, cryptContext );
	if( count == CRYPT_ERROR )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( count == CRYPT_ERROR )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Make sure the result matches what we pushed */
	if( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( buffer, ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyContext( cryptContext );
	puts( "Enveloping of raw-session-key-encrypted data succeeded.\n" );
	return( TRUE );
	}

int testEnvelopeSessionCrypt( void )
	{
	if( !envelopeSessionCrypt( FALSE ) )
		return( FALSE );
	return( envelopeSessionCrypt( TRUE ) );
	}

static int envelopeCrypt( const BOOLEAN useDatasize )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	int count;

	if( useDatasize )
		puts( "Testing password-encrypted enveloping with datasize hint..." );
	else
		puts( "Testing password-encrypted enveloping..." );

	/* Create the envelope, push in a password and the data, pop the
	   enveloped result, and destroy the envelope */
	if( !createEnvelope( &cryptEnvelope, FALSE ) || \
		!addEnvInfoString( cryptEnvelope, CRYPT_ENVINFO_PASSWORD, "Password", 8 ) )
		return( FALSE );
	if( useDatasize )
		cryptAddEnvComponentNumeric( cryptEnvelope, CRYPT_ENVINFO_DATASIZE,
									 ENVELOPE_TESTDATA_SIZE );
	count = pushData( cryptEnvelope, ENVELOPE_TESTDATA,
					  ENVELOPE_TESTDATA_SIZE, NULL, 0 );
	if( count == CRYPT_ERROR )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( count == CRYPT_ERROR )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "Enveloped data has size %d bytes.\n", count );
	debugDump( ( useDatasize ) ? "env_pas" : "env_pasn", buffer, count );

	/* Create the envelope, push in the data, pop the de-enveloped result,
	   and destroy the envelope */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	count = pushData( cryptEnvelope, buffer, count, "Password", 8 );
	if( count == CRYPT_ERROR )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( count == CRYPT_ERROR )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Make sure the result matches what we pushed */
	if( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( buffer, ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}

	/* Clean up */
	puts( "Enveloping of password-encrypted data succeeded.\n" );
	return( TRUE );
	}

int testEnvelopeCrypt( void )
	{
	if( !envelopeCrypt( FALSE ) )
		return( FALSE );
	return( envelopeCrypt( TRUE ) );
	}

static int envelopePKCCrypt( const BOOLEAN useDatasize,
							 const BOOLEAN useRawKey )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_KEYSET cryptKeyset;
	CRYPT_HANDLE cryptKey;
	int count, status;

	if( !keyReadOK )
		{
		puts( "Couldn't find key files, skipping test of public-key "
			  "encrypted enveloping..." );
		return( TRUE );
		}
	printf( "Testing public-key encrypted enveloping" );
	if( useDatasize )
		printf( " with datasize hint" );
	printf( ( useRawKey ) ? " using raw public key" : " using X.509 cert" );
	puts( "..." );

	/* Get the public key.  We do it the hard way rather than just adding the
	   recipient info to make sure this version works */
	if( useRawKey )
		{
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
								  PGP_PUBKEY_FILE, CRYPT_KEYOPT_READONLY );
		if( cryptStatusOK( status ) )
			status = cryptGetPublicKey( cryptKeyset, &cryptKey,
										CRYPT_KEYID_NAME, "test" );
		}
	else
		{
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
								  USER_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
		if( cryptStatusOK( status ) )
			status = cryptGetPublicKey( cryptKeyset, &cryptKey,
										CRYPT_KEYID_NONE, NULL );
		}
	if( cryptStatusOK( status ) )
		status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		puts( "Read of public key from key file failed, cannot test "
			  "enveloping." );
		return( FALSE );
		}

	/* Create the envelope, push in the public key and data, pop the
	   enveloped result, and destroy the envelope */
	if( !createEnvelope( &cryptEnvelope, FALSE ) || \
		!addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_PUBLICKEY,
							cryptKey ) )
		return( FALSE );
	cryptDestroyObject( cryptKey );
	if( useDatasize )
		cryptAddEnvComponentNumeric( cryptEnvelope, CRYPT_ENVINFO_DATASIZE,
									 ENVELOPE_TESTDATA_SIZE );
	count = pushData( cryptEnvelope, ENVELOPE_TESTDATA,
					  ENVELOPE_TESTDATA_SIZE, NULL, 0 );
	if( count == CRYPT_ERROR )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( count == CRYPT_ERROR )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "Enveloped data has size %d bytes.\n", count );
	debugDump( ( useDatasize ) ? ( ( useRawKey ) ? "env_pkc" : "env_crt" ) : \
			   ( ( useRawKey ) ? "env_pkcn" : "env_crtn" ), buffer, count );

	/* Create the envelope and push in the decryption keyset */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	if( useRawKey )
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
								  PGP_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	else
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
								  USER_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		status = addEnvInfoNumeric( cryptEnvelope,
								CRYPT_ENVINFO_KEYSET_DECRYPT, cryptKeyset );
	cryptKeysetClose( cryptKeyset );
	if( !status )
		return( FALSE );

	/* Push in the data */
	count = pushData( cryptEnvelope, buffer, count, useRawKey ? \
					  "test10" : USER_PRIVKEY_PASSWORD, 0 );
	if( count == CRYPT_ERROR )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( count == CRYPT_ERROR )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Make sure the result matches what we pushed */
	if( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( buffer, ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}

	/* Clean up */
	puts( "Enveloping of public-key encrypted data succeeded.\n" );
	return( TRUE );
	}

int testEnvelopePKCCrypt( void )
	{
	if( cryptQueryCapability( CRYPT_ALGO_IDEA, CRYPT_UNUSED, NULL ) == CRYPT_NOALGO )
		puts( "Skipping raw public-key based enveloping, which requires the "
			  "IDEA cipher to\nbe enabled.\n" );
	else
		{
		if( !envelopePKCCrypt( FALSE, TRUE ) )
			return( FALSE );
		if( !envelopePKCCrypt( TRUE, TRUE ) )
			return( FALSE );
		}
	if( !envelopePKCCrypt( FALSE, FALSE ) )
		return( FALSE );
	return( envelopePKCCrypt( TRUE, FALSE ) );
	}

static int envelopeSign( const BOOLEAN useDatasize, const BOOLEAN useRawKey )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int value, count, status;

	if( !keyReadOK )
		{
		puts( "Couldn't find key files, skipping test of signed "
			  "enveloping..." );
		return( TRUE );
		}
	printf( "Testing signed enveloping" );
	if( useDatasize )
		printf( " with datasize hint" );
	printf( ( useRawKey ) ? " using raw public key" : " using X.509 cert" );
	puts( "..." );

	/* Get the private key */
	if( useRawKey )
		{
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
								  PGP_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
		if( cryptStatusOK( status ) )
			{
			status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
										CRYPT_KEYID_NAME, "test", "test10" );
			cryptKeysetClose( cryptKeyset );
			}
		}
	else
		status = getPrivateKey( &cryptContext, USER_PRIVKEY_FILE,
								USER_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		puts( "Read of private key from key file failed, cannot test "
			  "enveloping." );
		return( FALSE );
		}

	/* Create the envelope, push in the signing key and data, pop the
	   enveloped result, and destroy the envelope */
	if( !createEnvelope( &cryptEnvelope, FALSE ) || \
		!addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_SIGNATURE,
							cryptContext ) )
		return( FALSE );
	cryptDestroyContext( cryptContext );
	if( useDatasize )
		cryptAddEnvComponentNumeric( cryptEnvelope, CRYPT_ENVINFO_DATASIZE,
									 ENVELOPE_TESTDATA_SIZE );
	count = pushData( cryptEnvelope, ENVELOPE_TESTDATA,
					  ENVELOPE_TESTDATA_SIZE, NULL, 0 );
	if( count == CRYPT_ERROR )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( count == CRYPT_ERROR )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "Enveloped data has size %d bytes.\n", count );
	debugDump( ( useDatasize ) ? ( ( useRawKey ) ? "env_sig" : "env_csg" ) : \
			   ( ( useRawKey ) ? "env_sign" : "env_csgn" ), buffer, count );

	/* Create the envelope and push in the sig.check keyset */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	if( useRawKey )
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
								  PGP_PUBKEY_FILE, CRYPT_KEYOPT_READONLY );
	else
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
								  USER_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		status = addEnvInfoNumeric( cryptEnvelope,
							CRYPT_ENVINFO_KEYSET_SIGCHECK, cryptKeyset );
	cryptKeysetClose( cryptKeyset );
	if( !status )
		return( FALSE );

	/* Push in the data */
	count = pushData( cryptEnvelope, buffer, count, NULL, 0 );
	if( count == CRYPT_ERROR )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( count == CRYPT_ERROR )
		return( FALSE );

	/* Determine the result of the signature check */
	cryptGetEnvComponentNumeric( cryptEnvelope,
								 CRYPT_ENVINFO_CURRENT_COMPONENT, &value );
	if( value != CRYPT_ENVINFO_SIGNATURE )
		{
		printf( "Envelope requires unexpected enveloping information type "
				"%d.\n", value );
		return( FALSE );
		}
	status = cryptGetEnvComponentNumeric( cryptEnvelope,
								CRYPT_ENVINFO_SIGNATURE_RESULT, &value );
	switch( value )
		{
		case CRYPT_OK:
			puts( "Signature is valid." );
			break;

		case CRYPT_DATA_NOTFOUND:
			puts( "Cannot find key to check signature." );
			break;

		case CRYPT_BADSIG:
			puts( "Signature is invalid." );
			break;

		default:
			printf( "Signature check returned status %d.\n", status );
		}
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Make sure the result matches what we pushed */
	if( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( buffer, ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}

	/* Clean up */
	puts( "Enveloping of signed data succeeded.\n" );
	return( TRUE );
	}

int testEnvelopeSign( void )
	{
	if( cryptQueryCapability( CRYPT_ALGO_IDEA, CRYPT_UNUSED, NULL ) == CRYPT_NOALGO )
		puts( "Skipping raw public-key based signing, which requires the "
			  "IDEA cipher to\nbe enabled.\n" );
	else
		{
		if( !envelopeSign( FALSE, TRUE ) )
			return( FALSE );
		if( !envelopeSign( TRUE, TRUE ) )
			return( FALSE );
		}
	if( !envelopeSign( FALSE, FALSE ) )
		return( FALSE );
	return( envelopeSign( TRUE, FALSE ) );
	}

/****************************************************************************
*																			*
*							CMS Enveloping Test Routines 					*
*																			*
****************************************************************************/

/* Test CMS signature generation/checking */

static int cmsEnvelopeSigCheck( const void *signedData,
								const int signedDataLength,
								const BOOLEAN detachedSig,
								const BOOLEAN checkData )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_CERTIFICATE signerInfo;
	BOOLEAN sigStatus = FALSE;
	int value, count, status;

	/* Create the envelope and push in the data.  Since this is a CMS
	   signature which carries its certs with it, there's no need to push in
	   a sig.check keyset.  If it has a detached sig, we need to push two
	   lots of data, first the signature to set the envelope state, then the
	   data.  In addition if it's a detached sig, there's nothing to be
	   unwrapped so we don't pop any data */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	count = pushData( cryptEnvelope, signedData, signedDataLength, NULL, 0 );
	if( count != CRYPT_ERROR )
		if( detachedSig )
			count = pushData( cryptEnvelope, ENVELOPE_TESTDATA,
						  ENVELOPE_TESTDATA_SIZE, NULL, 0 );
		else
			count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( count == CRYPT_ERROR )
		return( FALSE );

	/* Determine the result of the signature check */
	cryptGetEnvComponentNumeric( cryptEnvelope,
								 CRYPT_ENVINFO_CURRENT_COMPONENT, &value );
	if( value != CRYPT_ENVINFO_SIGNATURE )
		{
		printf( "Envelope requires unexpected enveloping information type "
				"%d.\n", value );
		return( FALSE );
		}
	status = cryptGetEnvComponentNumeric( cryptEnvelope,
								CRYPT_ENVINFO_SIGNATURE_RESULT, &value );
	switch( value )
		{
		case CRYPT_OK:
			puts( "Signature is valid." );
			sigStatus = TRUE;
			break;

		case CRYPT_DATA_NOTFOUND:
			puts( "Cannot find key to check signature." );
			break;

		case CRYPT_BADSIG:
			puts( "Signature is invalid." );
			break;

		default:
			printf( "Signature check returned status %d.\n", status );
		}

	/* Report on the signer and signature info.  We continue even if the sig
	   status is bad since we can still try and display signing info even if
	   the check fails */
	status = cryptGetEnvComponentNumeric( cryptEnvelope,
							CRYPT_ENVINFO_SIGNATURE, &signerInfo );
	if( cryptStatusError( status ) && sigStatus )
		{
		printf( "Cannot retrieve signer information from CMS signature, "
				"status = %d.\n", status );
		return( FALSE );
		}
	if( cryptStatusOK( status ) )
		{
		puts( "Signer information is:" );
		printCertInfo( signerInfo );
		cryptDestroyCert( signerInfo );
		}
	status = cryptGetEnvComponentNumeric( cryptEnvelope,
							CRYPT_ENVINFO_SIGNATURE_EXTRADATA, &signerInfo );
	if( cryptStatusError( status ) && sigStatus )
		{
		printf( "Cannot retrieve signature information from CMS signature, "
				"status = %d.\n", status );
		return( FALSE );
		}
	if( cryptStatusOK( status ) )
		{
		puts( "Signature information is:" );
		printCertInfo( signerInfo );
		cryptDestroyCert( signerInfo );
		}

	/* Make sure the result matches what we pushed */
	if( !detachedSig && checkData && ( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( buffer, ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE ) ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}

	/* Clean up */
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );
	return( sigStatus );
	}

static int cmsEnvelopeSign( const BOOLEAN useDatasize,
							const BOOLEAN useExtAttributes,
							const BOOLEAN detachedSig )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_CONTEXT cryptContext;
	int count, status;

	if( !keyReadOK )
		{
		puts( "Couldn't find key files, skipping test of CMS signed "
			  "enveloping..." );
		return( TRUE );
		}
	printf( "Testing CMS %s%s", ( useExtAttributes ) ? "extended " : "",
			( detachedSig ) ? "detached signature" : "signed enveloping" );
	if( useDatasize )
		printf( " with datasize hint" );
	puts( "..." );

	/* Get the private key */
	status = getPrivateKey( &cryptContext, USER_PRIVKEY_FILE,
							USER_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		puts( "Read of private key from key file failed, cannot test "
			  "CMS enveloping." );
		return( FALSE );
		}

	/* Create the CMS envelope, push in the signing key and data, pop the
	   enveloped result, and destroy the envelope */
	if( !createEnvelope( &cryptEnvelope, TRUE ) || \
		!addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_SIGNATURE,
							cryptContext ) )
		return( FALSE );
	cryptDestroyContext( cryptContext );
#if 0	/* Test non-data content type w.automatic attribute handling */
	cryptAddEnvComponentNumeric( cryptEnvelope, CRYPT_ENVINFO_CONTENTTYPE,
								 CRYPT_CONTENT_SIGNEDDATA );
#endif /* 1 */
	if( useDatasize )
		cryptAddEnvComponentNumeric( cryptEnvelope, CRYPT_ENVINFO_DATASIZE,
									 ENVELOPE_TESTDATA_SIZE );
	if( useExtAttributes )
		{
		CRYPT_CERTIFICATE cmsAttributes;

		/* Add an ESS security label as signing attributes */
		cryptCreateCert( &cmsAttributes, CRYPT_CERTTYPE_CMS_ATTRIBUTES );
		cryptAddCertComponentString( cmsAttributes,
						CRYPT_CERTINFO_CMS_SECLABEL_POLICY,
						"1 3 6 1 4 1 9999 1", 18 );
		cryptAddCertComponentNumeric( cmsAttributes,
						CRYPT_CERTINFO_CMS_SECLABEL_CLASSIFICATION,
						CRYPT_CLASSIFICATION_SECRET );
		status = cryptAddEnvComponentNumeric( cryptEnvelope,
						CRYPT_ENVINFO_SIGNATURE_EXTRADATA, cmsAttributes );
		cryptDestroyCert( cmsAttributes );
		if( cryptStatusError( status ) )
			{
			printf( "cryptAddEnvComponentNumeric() failed with error code "
					"%d, line %d\n", status, __LINE__ );
			return( FALSE );
			}
		}
	if( detachedSig )
		cryptAddEnvComponentNumeric( cryptEnvelope,
									 CRYPT_ENVINFO_DETACHEDSIGNATURE, TRUE );
	count = pushData( cryptEnvelope, ENVELOPE_TESTDATA,
					  ENVELOPE_TESTDATA_SIZE, NULL, 0 );
	if( count == CRYPT_ERROR )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( count == CRYPT_ERROR )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "CMS %s has size %d bytes.\n", ( detachedSig ) ? \
			"detached signature" : "signed data", count );
	debugDump( ( detachedSig ) ? "smi_dsig" : ( useExtAttributes ) ? \
			   ( useDatasize ) ? "smi_esg" : "smi_esgn" : \
			   ( useDatasize ) ? "smi_sig" : "smi_sign", buffer, count );

	/* Make sure the signature is valid */
	status = cmsEnvelopeSigCheck( buffer, count, detachedSig, TRUE );
	if( !status )
		return( FALSE );

	if( detachedSig )
		printf( "Creation of CMS %sdetached signature succeeded.\n\n",
				( useExtAttributes ) ? "extended " : "" );
	else
		printf( "Enveloping of CMS %ssigned data succeeded.\n\n",
				( useExtAttributes ) ? "extended " : "" );
	return( TRUE );
	}

int testCMSEnvelopeSign( void )
	{
	if( !cmsEnvelopeSign( FALSE, FALSE, FALSE ) )
		return( FALSE );
	if( !cmsEnvelopeSign( TRUE, FALSE, FALSE ) )
		return( FALSE );
	if( !cmsEnvelopeSign( FALSE, TRUE, FALSE ) )
		return( FALSE );
	return( cmsEnvelopeSign( TRUE, TRUE, FALSE ) );
	}

int testCMSEnvelopeDetachedSig( void )
	{
	return( cmsEnvelopeSign( FALSE, FALSE, TRUE ) );
	}

int testCMSImportSignedData( void )
	{
	FILE *filePtr;
	int count;

#if 1
	if( ( filePtr = fopen( SMIME_SIGNED_FILE, "rb" ) ) == NULL )
#else
	puts( "Kludging read" );
	if( ( filePtr = fopen( "f:smimesic.der", "rb" ) ) == NULL )
#endif
		{
		puts( "Couldn't find S/MIME SignedData file, skipping test of "
			  "SignedData import..." );
		return( TRUE );
		}
	puts( "Testing S/MIME SignedData import..." );
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	if( count == BUFFER_SIZE )
		{
		puts( "The data buffer size is too small for the signed data.  To "
			  "fix this,\nincrease the BUFFER_SIZE value in " __FILE__
			  " and recompile the code." );
		return( TRUE );		/* Skip this test and continue */
		}
	printf( "SignedData has size %d bytes.\n", count );

	/* Check the signature on the data */
	if( !cmsEnvelopeSigCheck( buffer, count, FALSE, FALSE ) )
		return( FALSE );

	/* Clean up */
	puts( "Import of S/MIME SignedData succeeded.\n" );
	return( TRUE );
	}

/* Test CMS enveloping/de-enveloping */

static int cmsEnvelopeDecrypt( const void *envelopedData,
							   const int envelopedDataLength )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_KEYSET cryptKeyset;
	int count, status;

	/* Create the envelope and push in the decryption keyset */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  USER_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		status = addEnvInfoNumeric( cryptEnvelope,
								CRYPT_ENVINFO_KEYSET_DECRYPT, cryptKeyset );
	cryptKeysetClose( cryptKeyset );
	if( !status )
		return( FALSE );

	/* Push in the data */
	count = pushData( cryptEnvelope, envelopedData, envelopedDataLength,
					  USER_PRIVKEY_PASSWORD, 0 );
	if( count == CRYPT_ERROR )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( count == CRYPT_ERROR )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Make sure the result matches what we pushed */
	if( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( buffer, ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}

	return( TRUE );
	}

static int cmsEnvelopeCrypt( const BOOLEAN useDatasize )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_KEYSET cryptKeyset;
	CRYPT_HANDLE cryptKey;
	int count, status;

	if( !keyReadOK )
		{
		puts( "Couldn't find key files, skipping test of CMS encrypted "
			  "enveloping..." );
		return( TRUE );
		}
	printf( "Testing CMS public-key encrypted enveloping" );
	if( useDatasize )
		printf( " with datasize hint" );
	puts( "..." );

	/* Get the public key.  We do it the hard way rather than just adding the
	   recipient info to make sure this version works */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  USER_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		status = cryptGetPublicKey( cryptKeyset, &cryptKey,
									CRYPT_KEYID_NONE, NULL );
	if( cryptStatusOK( status ) )
		status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		puts( "Read of public key from key file failed, cannot test "
			  "CMS enveloping." );
		return( FALSE );
		}

	/* Create the envelope, push in the public key and data, pop the
	   enveloped result, and destroy the envelope */
	if( !createEnvelope( &cryptEnvelope, TRUE ) || \
		!addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_PUBLICKEY,
							cryptKey ) )
		return( FALSE );
	cryptDestroyObject( cryptKey );
	if( useDatasize )
		cryptAddEnvComponentNumeric( cryptEnvelope, CRYPT_ENVINFO_DATASIZE,
									 ENVELOPE_TESTDATA_SIZE );
	count = pushData( cryptEnvelope, ENVELOPE_TESTDATA,
					  ENVELOPE_TESTDATA_SIZE, NULL, 0 );
	if( count == CRYPT_ERROR )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( count == CRYPT_ERROR )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "Enveloped data has size %d bytes.\n", count );
	debugDump( ( useDatasize ) ? "smi_pkc" : "smi_pkcn", buffer, count );

	/* Make sure the enveloped data is valid */
	status = cmsEnvelopeDecrypt( buffer, count );
	if( !status )
		return( FALSE );

	/* Clean up */
	puts( "Enveloping of CMS public-key encrypted data succeeded.\n" );
	return( TRUE );
	}

int testCMSEnvelopePKCCrypt( void )
	{
	if( !cmsEnvelopeCrypt( FALSE ) )
		return( FALSE );
	return( cmsEnvelopeCrypt( TRUE ) );
	}

#if 0	/* This function doesn't currently serve any purpose since there's no
		   third-party enveloped data present to test */

int testCMSImportEnvelopedData( void )
	{
	FILE *filePtr;
	int count;

	if( ( filePtr = fopen( SMIME_ENVELOPED_FILE, "rb" ) ) == NULL )
		{
		puts( "Couldn't find S/MIME EnvelopedData file, skipping test of "
			  "EnvelopedData import..." );
		return( TRUE );
		}
	puts( "Testing S/MIME EnvelopedData import..." );
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	if( count == BUFFER_SIZE )
		{
		puts( "The data buffer size is too small for the enveloped data.  To "
			  "fix this,\nincrease the BUFFER_SIZE value in " __FILE__
			  " and recompile the code." );
		return( TRUE );		/* Skip this test and continue */
		}
	printf( "EnvelopedData has size %d bytes.\n", count );

	/* Decrypt the data */
	if( !cmsEnvelopeDecrypt( buffer, count ) )
		return( FALSE );

	/* Clean up */
	puts( "Import of S/MIME EnvelopedData succeeded.\n" );
	return( TRUE );
	}
#endif /* 0 */
