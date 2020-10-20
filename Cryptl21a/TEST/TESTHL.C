/****************************************************************************
*																			*
*					cryptlib Mid and High-Level Test Routines				*
*						Copyright Peter Gutmann 1995-1999					*
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

/* The key size to use for the PKC routines */

#define PKC_KEYSIZE			512

/* Generic I/O buffer size.  This has to be of a reasonable size so we can
   handle signatures with large keys and sizeable test certificates */

#define BUFFER_SIZE			1024

/* Prototypes for functions in testlib.c */

int testLowlevel( const CRYPT_DEVICE cryptDevice, const CRYPT_ALGO cryptAlgo,
				  const CRYPT_MODE cryptMode );

/****************************************************************************
*																			*
*							Mid-level Routines Test							*
*																			*
****************************************************************************/

/* Test whether two session keys are identical */

static int compareSessionKeys( const CRYPT_CONTEXT cryptContext1,
							   const CRYPT_CONTEXT cryptContext2 )
	{
	BYTE buffer[ 8 ];
	int status;

	cryptLoadIV( cryptContext1, "\x00\x00\x00\x00", 4 );
	cryptLoadIV( cryptContext2, "\x00\x00\x00\x00", 4 );
	memcpy( buffer, "12345678", 8 );
	status = cryptEncrypt( cryptContext1, buffer, 8 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptEncrypt() with first key failed with error "
				"code %d, line %d\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptDecrypt( cryptContext2, buffer, 8 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDecrypt() with second key failed with error "
				"code %d, line %d\n", status, __LINE__ );
		return( FALSE );
		}
	if( memcmp( buffer, "12345678", 8 ) )
		{
		puts( "Data decrypted with key2 != plaintext encrypted with key1." );
		return( FALSE );
		}
	return( TRUE );
	}

/* Test the randomness gathering routines */

int testRandomRoutines( void )
	{
	CRYPT_CONTEXT cryptContext;
	int status;

	puts( "Testing randomness routines.  This may take a few seconds..." );

	/* Create an encryption context to generate a key into */
	cryptCreateContext( &cryptContext, CRYPT_ALGO_DES, CRYPT_MODE_ECB );
	status = cryptGenerateKey( cryptContext );
	cryptDestroyContext( cryptContext );

	/* Check whether we got enough randomness */
	if( status == CRYPT_NORANDOM )
		{
		puts( "The randomness-gathering routines in the library can't acquire enough" );
		puts( "random information to allow key generation and public-key encryption to" );
		puts( "function.  You will need to change lib_rand.c or reconfigure your system" );
		puts( "to allow the randomness-gathering routines to function.  The code to" );
		puts( "change can be found in misc/rndXXXX.c\n" );
		return( FALSE );
		}

	puts( "Randomness-gathering self-test succeeded.\n" );
	return( TRUE );
	}

/* Test the code to derive a fixed-length encryption key from a variable-
   length user key */

int testDeriveKey( void )
	{
	CRYPT_CONTEXT cryptContext, decryptContext;
	BYTE *userKey = ( BYTE * ) "This is a long user key for cryptDeriveKey()";
	int userKeyLength = strlen( ( char * ) userKey ), status;

	puts( "Testing key derivation..." );

	/* Create IDEA/CBC encryption and decryption contexts */
	cryptCreateContext( &cryptContext, selectCipher( CRYPT_ALGO_IDEA ), 
						CRYPT_MODE_CBC );
	cryptCreateContext( &decryptContext, selectCipher( CRYPT_ALGO_IDEA ), 
						CRYPT_MODE_CBC );

	/* Load an IDEA key derived from a user key into both contexts */
	status = cryptDeriveKey( cryptContext, userKey, userKeyLength );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDeriveKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptDeriveKey( decryptContext, userKey, userKeyLength );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDeriveKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure the two derived keys match */
	if( !compareSessionKeys( cryptContext, decryptContext ) )
		return( FALSE );

	/* Clean up */
	destroyContexts( cryptContext, decryptContext );
	puts( "Generation of key via cryptDeriveKey() succeeded.\n" );
	return( TRUE );
	}

/* Test the code to export/import an encrypted key via conventional
   encryption.  This demonstrates the ability to use one context type to
   export another - we export a triple DES key using Blowfish.  We're not as
   picky with error-checking here since most of the functions have just
   executed successfully */

int testConventionalExportImport( void )
	{
	CRYPT_OBJECT_INFO cryptObjectInfo;
	CRYPT_CONTEXT cryptContext, decryptContext;
	CRYPT_CONTEXT sessionKeyContext1, sessionKeyContext2;
	BYTE *userKey = ( BYTE * ) "This is a long user key for cryptDeriveKey()";
	BYTE *buffer;
	int userKeyLength = strlen( ( char * ) userKey );
	int status, length;

	puts( "Testing conventional key export/import..." );

	/* Create a triple-DES encryption context for the session key */
	cryptCreateContext( &sessionKeyContext1, CRYPT_ALGO_3DES, CRYPT_MODE_CFB );
	cryptGenerateKey( sessionKeyContext1 );

	/* Create a Blowfish encryption context to export the session key */
	cryptCreateContext( &cryptContext, CRYPT_ALGO_BLOWFISH, CRYPT_MODE_CFB );
	cryptDeriveKey( cryptContext, userKey, userKeyLength );

	/* Find out how big the exported key will be */
	status = cryptExportKey( NULL, &length, cryptContext, sessionKeyContext1 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "cryptExportKey() reports exported key object will be %d bytes "
			"long\n", length );
	if( ( buffer = malloc( length ) ) == NULL )
		return( FALSE );

	/* Export the session information */
	status = cryptExportKey( buffer, &length, cryptContext, sessionKeyContext1 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}

	/* Query the encrypted key object */
	status = cryptQueryObject( buffer, &cryptObjectInfo );
	if( cryptStatusError( status ) )
		{
		printf( "cryptQueryObject() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}
	printf( "cryptQueryObject() reports object type %d, size %d bytes,\n"
			"\talgorithm %d, mode %d, key derivation done with %d iterations of\n"
			"\talgorithm %d.\n", cryptObjectInfo.objectType,
			cryptObjectInfo.objectSize, cryptObjectInfo.cryptAlgo,
			cryptObjectInfo.cryptMode, cryptObjectInfo.keySetupIterations,
			cryptObjectInfo.keySetupAlgo );
	debugDump( "kek", buffer, length );

	/* Recreate the session key by importing the encrypted key */
	status = cryptCreateContextEx( &decryptContext,
								   cryptObjectInfo.cryptAlgo,
								   cryptObjectInfo.cryptMode,
								   cryptObjectInfo.cryptContextExInfo );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateContext() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}
	cryptDeriveKeyEx( decryptContext, userKey, userKeyLength,
					  cryptObjectInfo.keySetupAlgo,
					  cryptObjectInfo.keySetupIterations );
	memset( &cryptObjectInfo, 0, sizeof( CRYPT_OBJECT_INFO ) );

	status = cryptImportKey( buffer, decryptContext, &sessionKeyContext2 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}

	/* Make sure the two keys match */
	if( !compareSessionKeys( sessionKeyContext1, sessionKeyContext2 ) )
		return( FALSE );

	/* Clean up */
	destroyContexts( sessionKeyContext1, sessionKeyContext2 );
	destroyContexts( cryptContext, decryptContext );
	printf( "Export/import of Blowfish key via user-key-based triple DES "
			"conventional\n  encryption succeeded.\n\n" );
	free( buffer );
	return( TRUE );
	}

/* Test the code to export/import an encrypted key.  We're not as picky with
   error-checking here since most of the functions have just executed
   successfully */

int testKeyExportImport( void )
	{
	CRYPT_OBJECT_INFO cryptObjectInfo;
	CRYPT_CONTEXT cryptContext, decryptContext;
	CRYPT_CONTEXT sessionKeyContext1, sessionKeyContext2;
	BYTE *buffer;
	int status, length;

	puts( "Testing public-key export/import..." );

	/* Create an RC2 encryption context for the session key */
	cryptCreateContext( &sessionKeyContext1, selectCipher( CRYPT_ALGO_RC2 ),
						CRYPT_MODE_OFB );
	cryptGenerateKey( sessionKeyContext1 );

	/* Create the RSA en/decryption contexts */
	if( !loadRSAContexts( CRYPT_UNUSED, &cryptContext, &decryptContext ) )
		return( FALSE );

	/* Find out how big the exported key will be */
	status = cryptExportKey( NULL, &length, cryptContext, sessionKeyContext1 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "cryptExportKey() reports exported key object will be %d bytes "
			"long\n", length );
	if( ( buffer = malloc( length ) ) == NULL )
		return( FALSE );

	/* Export the session key */
	status = cryptExportKey( buffer, &length, cryptContext, sessionKeyContext1 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}

	/* Query the encrypted key object */
	status = cryptQueryObject( buffer, &cryptObjectInfo );
	if( cryptStatusError( status ) )
		{
		printf( "cryptQueryObject() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}
	printf( "cryptQueryObject() reports object type %d, size %d bytes,\n"
			"\talgorithm %d, mode %d.\n", cryptObjectInfo.objectType,
			cryptObjectInfo.objectSize, cryptObjectInfo.cryptAlgo,
			cryptObjectInfo.cryptMode );
	memset( &cryptObjectInfo, 0, sizeof( CRYPT_OBJECT_INFO ) );
	debugDump( "keytrans", buffer, length );

	/* Recreate the session key by importing the encrypted key */
	status = cryptImportKey( buffer, decryptContext, &sessionKeyContext2 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}

	/* Make sure the two keys match */
	if( !compareSessionKeys( sessionKeyContext1, sessionKeyContext2 ) )
		return( FALSE );

	/* Clean up */
	destroyContexts( sessionKeyContext1, sessionKeyContext2 );
	destroyContexts( cryptContext, decryptContext );
	printf( "Export/import of session key via %d-bit RSA-encrypted data "
			"block succeeded.\n\n", PKC_KEYSIZE );
	free( buffer );
	return( TRUE );
	}

/* Test the code to sign data.  We're not as picky with error-checking here
   since most of the functions have just executed successfully.  We check two
   algorithm types since there are different code paths for DLP and non-DLP
   based PKC's */

static int testSign( const char *algoName, const CRYPT_ALGO algorithm )
	{
	CRYPT_OBJECT_INFO cryptObjectInfo;
	CRYPT_CONTEXT signContext, checkContext;
	CRYPT_CONTEXT hashContext;
	BYTE *buffer, hashBuffer[] = "abcdefghijklmnopqrstuvwxyz";
	int status, length;

	printf( "Testing %s digital signature...\n", algoName );

	/* Create an SHA hash context and hash the test buffer */
	cryptCreateContext( &hashContext, CRYPT_ALGO_SHA, CRYPT_MODE_NONE );
	cryptEncrypt( hashContext, hashBuffer, 26 );
	cryptEncrypt( hashContext, hashBuffer, 0 );

	/* Create the appropriate en/decryption contexts */
	if( algorithm == CRYPT_ALGO_DSA )
		status = loadDSAContexts( &signContext, &checkContext );
	else
		status = loadRSAContexts( CRYPT_UNUSED, &checkContext, &signContext );
	if( !status )
		return( FALSE );

	/* Find out how big the signature will be */
	status = cryptCreateSignature( NULL, &length, signContext, hashContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSignature() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "cryptCreateSignature() reports signature object will be %d "
			"bytes long\n", length );
	if( ( buffer = malloc( length ) ) == NULL )
		return( FALSE );

	/* Sign the hashed data */
	status = cryptCreateSignature( buffer, &length, signContext, hashContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSignature() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}

	/* Query the signed object */
	status = cryptQueryObject( buffer, &cryptObjectInfo );
	if( cryptStatusError( status ) )
		{
		printf( "cryptQueryObject() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}
	printf( "cryptQueryObject() reports object type %d, size %d bytes,\n"
			"\talgorithm %d, mode %d.\n", cryptObjectInfo.objectType,
			cryptObjectInfo.objectSize, cryptObjectInfo.cryptAlgo,
			cryptObjectInfo.cryptMode );
	memset( &cryptObjectInfo, 0, sizeof( CRYPT_OBJECT_INFO ) );
	debugDump( "signature", buffer, length );

	/* Check the signature on the hash */
	status = cryptCheckSignature( buffer, checkContext, hashContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCheckSignature() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyContext( hashContext );
	destroyContexts( checkContext, signContext );
	printf( "Generation and checking of %s digital signature via %d-bit "
			"data block\n  succeeded.\n", algoName, PKC_KEYSIZE );
	free( buffer );
	return( TRUE );
	}

int testSignData( void )
	{
	int status;

	status = testSign( "RSA", CRYPT_ALGO_RSA );
	if( status == TRUE )
		status = testSign( "DSA", CRYPT_ALGO_DSA );
	putchar( '\n' );
	return( status );
	}

/* Test the code to exchange a session key via Diffie-Hellman.  We're not as
   picky with error-checking here since most of the functions have just
   executed successfully */

int testKeyExchange( void )
	{
	CRYPT_OBJECT_INFO cryptObjectInfo;
	CRYPT_CONTEXT cryptContext1, cryptContext2;
	CRYPT_CONTEXT sessionKeyContext1, sessionKeyContext2;
	BYTE *buffer;
	int length, status;

	puts( "Testing key agreement..." );

	/* Create the DH encryption contexts, one with a key loaded and the
	   other as a blank template for the import from the first one */
	if( !loadDHContexts( &cryptContext1, NULL, PKC_KEYSIZE ) )
		return( FALSE );
	cryptCreateContext( &cryptContext2, CRYPT_ALGO_DH, CRYPT_MODE_PKC );

	/* Create the session key template */
	cryptCreateContext( &sessionKeyContext1, selectCipher( CRYPT_ALGO_RC5 ),
						CRYPT_MODE_CFB );

	/* Find out how big the exported key will be */
	status = cryptExportKey( NULL, &length, cryptContext1, sessionKeyContext1 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "cryptExportKey() reports exported key object will be %d bytes "
			"long\n", length );
	if( ( buffer = malloc( length ) ) == NULL )
		return( FALSE );

	/* Perform phase 1 of the exchange */
	status = cryptExportKey( buffer, &length, cryptContext1, sessionKeyContext1 );
	cryptDestroyContext( sessionKeyContext1 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKey() #1 failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}
	status = cryptImportKey( buffer, cryptContext2, &sessionKeyContext2 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportKey() #1 failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}

	/* Query the encrypted key object */
	status = cryptQueryObject( buffer, &cryptObjectInfo );
	if( cryptStatusError( status ) )
		{
		printf( "cryptQueryObject() failed with error code %d, line %d\n",
				status );
		free( buffer );
		return( FALSE );
		}
	printf( "cryptQueryObject() reports object type %d, size %d bytes,\n"
			"\talgorithm %d, mode %d.\n", cryptObjectInfo.objectType,
			cryptObjectInfo.objectSize, cryptObjectInfo.cryptAlgo,
			cryptObjectInfo.cryptMode );
	memset( &cryptObjectInfo, 0, sizeof( CRYPT_OBJECT_INFO ) );
	debugDump( "keyagree", buffer, length );

	/* Perform phase 2 of the exchange */
	status = cryptExportKey( buffer, &length, cryptContext2, sessionKeyContext2 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKey() #2 failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}
	status = cryptImportKey( buffer, cryptContext1, &sessionKeyContext1 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportKey() #2 failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}

	/* Make sure the two keys match */
	if( !compareSessionKeys( sessionKeyContext1, sessionKeyContext2 ) )
		return( FALSE );

	/* Clean up */
	destroyContexts( sessionKeyContext1, sessionKeyContext2 );
	destroyContexts( cryptContext1, cryptContext2 );
	printf( "Exchange of session key via %d-bit Diffie-Hellman succeeded.\n\n",
			PKC_KEYSIZE );
	free( buffer );
	return( TRUE );
	}

/* Test normal and asynchronous public-key generation */

static int keygen( const CRYPT_ALGO cryptAlgo, const char *algoName )
	{
	CRYPT_CONTEXT cryptContext;
	BYTE buffer[ BUFFER_SIZE ];
	int length, status;

	printf( "Testing %s key generation...\n", algoName );

	/* Create an encryption context and generate a (short) key into it.
	   Generating a minimal-length 512 bit key is faster than the default
	   1-2K bit keys */
	cryptCreateContext( &cryptContext, cryptAlgo, CRYPT_MODE_PKC );
	status = cryptGenerateKeyEx( cryptContext, 64 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGenerateKey() failed with error code %d, line %d\n",
				status );
		return( FALSE );
		}

	/* Perform a test operation to check the new key */
	if( cryptAlgo == CRYPT_ALGO_RSA || cryptAlgo == CRYPT_ALGO_DSA )
		{
		CRYPT_CONTEXT hashContext;
		BYTE hashBuffer[] = "abcdefghijklmnopqrstuvwxyz";

		/* Create an SHA hash context and hash the test buffer */
		cryptCreateContext( &hashContext, CRYPT_ALGO_SHA, CRYPT_MODE_NONE );
		cryptEncrypt( hashContext, hashBuffer, 26 );
		cryptEncrypt( hashContext, hashBuffer, 0 );

		/* Sign the hashed data and check the signature */
		status = cryptCreateSignature( buffer, &length, cryptContext, hashContext );
		if( cryptStatusOK( status ) )
			status = cryptCheckSignature( buffer, cryptContext, hashContext );

		/* Clean up */
		cryptDestroyContext( hashContext );
		cryptDestroyContext( cryptContext );
		if( cryptStatusError( status ) )
			{
			printf( "Sign/signature check with generated key failed with "
					"error code %d, line %d\n", status, __LINE__ );
			return( FALSE );
			}
		}
	else
		{
		CRYPT_CONTEXT dhContext;
		CRYPT_CONTEXT sessionKeyContext1, sessionKeyContext2;

		/* Test the key exchange */
		cryptCreateContext( &sessionKeyContext1, CRYPT_ALGO_DES, CRYPT_MODE_CBC );
		cryptCreateContext( &dhContext, CRYPT_ALGO_DH, CRYPT_MODE_PKC );
		status = cryptExportKey( buffer, &length, cryptContext,
								  sessionKeyContext1 );
		cryptDestroyContext( sessionKeyContext1 );
		if( cryptStatusOK( status ) )
			status = cryptImportKey( buffer, dhContext,
									 &sessionKeyContext2 );
		if( cryptStatusOK( status ) )
			status = cryptExportKey( buffer, &length, dhContext,
									 sessionKeyContext2 );
		if( cryptStatusOK( status ) )
			status = cryptImportKey( buffer, cryptContext,
									 &sessionKeyContext1 );
		cryptDestroyContext( cryptContext );
		cryptDestroyContext( dhContext );
		if( cryptStatusError( status ) )
			{
			destroyContexts( sessionKeyContext1, sessionKeyContext2 );
			printf( "Key exchange with generated key failed with error code "
					"%d, line %d\n", status, __LINE__ );
			return( FALSE );
			}

		/* Make sure the two keys match */
		if( !compareSessionKeys( sessionKeyContext1, sessionKeyContext2 ) )
			return( FALSE );

		/* Clean up */
		destroyContexts( sessionKeyContext1, sessionKeyContext2 );
		}

	printf( "%s key generation succeeded.\n\n", algoName );
	return( TRUE );
	}


int testKeygen( void )
	{
	if( !keygen( CRYPT_ALGO_RSA, "RSA" ) )
		return( FALSE );
	if( !keygen( CRYPT_ALGO_DSA, "DSA" ) )
		return( FALSE );
	return( keygen( CRYPT_ALGO_DH, "DH" ) );
	}

int testKeygenAsync( void )
	{
	/* Async keygen requires threading support which is currently only
	   handled under Win32 or OS/2 (actually it's present under many versions
	   of Unix as well but it's a bit tricky to determine automatically
	   without the cryptlib-internal configuration tricks which ones support
	   it */
#if !defined( WIN32 ) && !defined( _WIN32 ) && !defined( __IBMC__ ) && \
	!defined( __IBMCPP__ )
	return( TRUE );
#else
	CRYPT_CONTEXT cryptContext;
	int status;

	puts( "Testing asynchronous key generation..." );

	/* Create an encryption context and generate a longish (2K bit) key
	   into it (this ensures that we can see the async operation in
	   action) */
	cryptCreateContext( &cryptContext, CRYPT_ALGO_RSA, CRYPT_MODE_PKC );
	status = cryptGenerateKeyAsyncEx( cryptContext, 256 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGenerateKeyAsync() failed with error code %d, line "
				"%d\n", status );
		return( FALSE );
		}

	/* Hang around a bit to allow things to start.  This value is a bit of a
	   difficult quantity to get right since VC++ can spend longer than the
	   startup time thrashing the drive doing nothing (so it has to be high),
	   but on faster PC's even a 2K bit key can be generated in a few
	   seconds, so it can't be too high or the keygen will have finished.
	   The following value is safe for a 400MHz PII, presumably the next step
	   will be to move to 3K bit keys (3072 bits, 384 in the above keygen
	   call) but this may cause problems with some external implementations
	   which cap the keysize at 2K bits */
	printf( "Delaying 2s to allow keygen to start..." );
	Sleep( 2000 );
	puts( "done." );

	/* Check that the async keygen is still in progress */
	status = cryptAsyncQuery( cryptContext );
	if( status == CRYPT_BUSY )
		puts( "Async keygen in progress." );
	else
		{
		/* If the machine's really fast, the keygen could have completed
		   already */
		if( status == CRYPT_OK )
			{
			printf( "The async keygen has completed before the rest of the "
					"test code could run.\nTo fix this, either decrease "
					"the startup delay on line %d\nof " __FILE__ " or "
					"increase the size of the key being generated to slow\n"
					"down the generation process.\n\n", __LINE__ - 15 );
			cryptDestroyContext( cryptContext );

			return( TRUE );
			}

		printf( "Async keygen failed with error code %d, line %d\n", status,
				__LINE__ );
		return( FALSE );
		}

	/* Cancel the async keygen */
	status = cryptAsyncCancel( cryptContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAsyncCancel() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "Cancelling async operation..." );
	while( cryptAsyncQuery( cryptContext ) == CRYPT_BUSY )
		Sleep( 1000 );	/* Wait for the cancel to take effect */
	puts( "done." );

	/* Clean up */
	cryptDestroyContext( cryptContext );
	puts( "Asynchronous key generation succeeded.\n" );
	return( TRUE );
#endif /* Win32 */
	}

/****************************************************************************
*																			*
*							Crypto Device Routines Test						*
*																			*
****************************************************************************/

/* Test a crypto device */

static int testCryptoDevice( const CRYPT_DEVICE_TYPE deviceType,
							 const char *deviceName,
							 const char *deviceDescription )
	{
	CRYPT_DEVICE cryptDevice;
	CRYPT_ALGO cryptAlgo;
	BOOLEAN testResult;
	int status;

	printf( "Testing %s...\n", deviceDescription );

	/* Open a connection to the device */
	status = cryptDeviceOpen( &cryptDevice, deviceType, deviceName );
	if( status == CRYPT_BADPARM2 )
		return( CRYPT_ERROR );		/* Device access not available */
	if( cryptStatusError( status ) )
		{
		printf( "cryptDeviceOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		if( status == CRYPT_DATA_OPEN )
			printf( "This may be because you haven't plugged in or enabled "
					"the\n%s.\n", deviceDescription );
		return( FALSE );
		}

	/* Report what the device can do */
	printf( "Checking %s capabilities...\n", deviceDescription );
	for( cryptAlgo = CRYPT_ALGO_FIRST_CONVENTIONAL;
		 cryptAlgo <= CRYPT_ALGO_LAST; cryptAlgo++ )
		if( cryptStatusOK( cryptDeviceQueryCapability( cryptDevice,
										cryptAlgo, CRYPT_UNUSED, NULL ) ) )
			{
			CRYPT_MODE cryptMode;

			for( cryptMode = CRYPT_MODE_FIRST_CONVENTIONAL;
				 cryptMode <= CRYPT_MODE_LAST; cryptMode++ )
				if( cryptStatusOK( cryptDeviceQueryCapability( cryptDevice,
								   cryptAlgo, cryptMode, NULL ) ) )
				{
				testResult = testLowlevel( cryptDevice, cryptAlgo, cryptMode );
				if( !testResult )
					break;
				}
			}

	/* Clean up */
	status = cryptDeviceClose( cryptDevice );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDeviceClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	if( !testResult )
		return( FALSE );
	printf( "%s tests succeeded.\n\n", deviceDescription );
	return( TRUE );
	}

int testDevices( void )
	{
	int status;

	status = testCryptoDevice( CRYPT_DEVICE_CEI, NULL,
							   "CE Infosys DES/3DES accelerator" );
	if( cryptStatusError( status ) && status != CRYPT_ERROR )
		return( status );
	status = testCryptoDevice( CRYPT_DEVICE_FORTEZZA, NULL,
							   "Fortezza PCMCIA card" );
	if( cryptStatusError( status ) && status != CRYPT_ERROR )
		return( status );
	status = testCryptoDevice( CRYPT_DEVICE_PKCS11, "GemSAFE",
							   "PKCS #11 crypto token" );
	if( cryptStatusError( status ) )
		return( status );
	return( TRUE );
	}

/****************************************************************************
*																			*
*							High-level Routines Test						*
*																			*
****************************************************************************/

/* Test the code to export/import a CMS key */

int testKeyExportImportCMS( void )
	{
	CRYPT_OBJECT_INFO cryptObjectInfo;
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	CRYPT_CONTEXT sessionKeyContext1, sessionKeyContext2;
	BYTE *buffer;
	int status, length;

	puts( "Testing CMS public-key export/import..." );

	/* Get a private key with a cert chain attached */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  USER_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
							CRYPT_KEYID_NONE, NULL, USER_PRIVKEY_PASSWORD );
		cryptKeysetClose( cryptKeyset );
		}
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't read private key, status %d, line %d.\n", status,
				__LINE__ );
		return( FALSE );
		}

	/* Create triple-DES encryption contexts for the exported and imported
	   session keys */
	cryptCreateContext( &sessionKeyContext1, CRYPT_ALGO_3DES, CRYPT_MODE_CFB );
	cryptGenerateKey( sessionKeyContext1 );
	cryptCreateContext( &sessionKeyContext2, CRYPT_ALGO_3DES, CRYPT_MODE_CFB );

	/* Find out how big the exported key will be */
	status = cryptExportKeyEx( NULL, &length, CRYPT_FORMAT_SMIME,
							   cryptContext, sessionKeyContext1 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKeyEx() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "cryptExportKeyEx() reports CMS exported key will be %d bytes "
			"long\n", length );
	if( ( buffer = malloc( length ) ) == NULL )
		return( FALSE );

	/* Export the key */
	status = cryptExportKeyEx( buffer, &length, CRYPT_FORMAT_SMIME,
							   cryptContext, sessionKeyContext1 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKeyEx() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}

	/* Query the encrypted key object */
	status = cryptQueryObject( buffer, &cryptObjectInfo );
	if( cryptStatusError( status ) )
		{
		printf( "cryptQueryObject() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}
	printf( "cryptQueryObject() reports object type %d, size %d bytes,\n"
			"\talgorithm %d, mode %d.\n", cryptObjectInfo.objectType,
			cryptObjectInfo.objectSize, cryptObjectInfo.cryptAlgo,
			cryptObjectInfo.cryptMode );
	memset( &cryptObjectInfo, 0, sizeof( CRYPT_OBJECT_INFO ) );
	debugDump( "cms_ri", buffer, length );

	/* Import the encrypted key and load it into the session key context */
	status = cryptImportKeyEx( buffer, cryptContext, &sessionKeyContext2 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportKeyEx() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}

	/* Make sure the two keys match */
	if( !compareSessionKeys( sessionKeyContext1, sessionKeyContext2 ) )
		return( FALSE );

	/* Clean up */
	destroyContexts( sessionKeyContext1, sessionKeyContext2 );
	cryptDestroyContext( cryptContext );
	puts( "Export/import of CMS session key succeeded.\n" );
	free( buffer );
	return( TRUE );
	}

/* Test the code to create an CMS signature */

static const CERT_DATA cmsAttributeData[] = {
	/* Content type and signing time */
	{ CRYPT_CERTINFO_CMS_CONTENTTYPE, IS_NUMERIC, CRYPT_CONTENT_SPCINDIRECTDATACONTEXT },
	{ CRYPT_CERTINFO_CMS_SIGNINGTIME, IS_TIME, 0, NULL, 0x34000000L },

	/* Odds and ends */
	{ CRYPT_CERTINFO_CMS_SPCOPUSINFO, IS_NUMERIC, CRYPT_UNUSED },
	{ CRYPT_CERTINFO_CMS_SPCSTMT_COMMERCIALCODESIGNING, IS_NUMERIC, CRYPT_UNUSED },

	{ CRYPT_CERTINFO_NONE, IS_VOID }
	};

static int signDataCMS( const char *description,
						const CRYPT_CERTIFICATE signingAttributes )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cmsAttributes = signingAttributes;
	CRYPT_CONTEXT signContext, hashContext;
	BYTE *buffer, hashBuffer[] = "abcdefghijklmnopqrstuvwxyz";
	int status, length;

	printf( "Testing %s...\n", description );

	/* Create an SHA hash context and hash the test buffer */
	cryptCreateContext( &hashContext, CRYPT_ALGO_SHA, CRYPT_MODE_NONE );
	cryptEncrypt( hashContext, hashBuffer, 26 );
	cryptEncrypt( hashContext, hashBuffer, 0 );

	/* Get a private key with a cert chain attached */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  USER_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetPrivateKey( cryptKeyset, &signContext,
							CRYPT_KEYID_NONE, NULL, USER_PRIVKEY_PASSWORD );
		cryptKeysetClose( cryptKeyset );
		}
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't read private key, status %d, line %d.\n", status,
				__LINE__ );
		return( FALSE );
		}

	/* Find out how big the signature will be */
	status = cryptCreateSignatureEx( NULL, &length, CRYPT_FORMAT_SMIME,
									 signContext, hashContext, cmsAttributes );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSignatureEx() failed with error code %d, line "
				"%d\n", status, __LINE__ );
		return( FALSE );
		}
	printf( "cryptCreateSignatureEx() reports CMS signature will be %d "
			"bytes long\n", length );
	if( ( buffer = malloc( length ) ) == NULL )
		return( FALSE );

	/* Sign the hashed data */
	status = cryptCreateSignatureEx( buffer, &length, CRYPT_FORMAT_SMIME,
									 signContext, hashContext, cmsAttributes );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSignatureEx() failed with error code %d, line "
				"%d\n", status, __LINE__ );
		free( buffer );
		return( FALSE );
		}
	debugDump( ( signingAttributes == CRYPT_USE_DEFAULT ) ? \
			   "cms_sigd" : "cms_sig", buffer, length );

	/* Check the signature on the hash */
	status = cryptCheckSignatureEx( buffer, signContext, hashContext,
			( cmsAttributes == CRYPT_USE_DEFAULT ) ? NULL : &cmsAttributes );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCheckSignatureEx() failed with error code %d, line "
				"%d\n", status, __LINE__ );
		free( buffer );
		return( FALSE );
		}
	
	/* Display the signing attributes */
	printCertInfo( cmsAttributes );

	/* Clean up */
	cryptDestroyContext( hashContext );
	cryptDestroyContext( signContext );
	cryptDestroyCert( cmsAttributes );
	printf( "Generation and checking of %s succeeded.\n\n", description );
	free( buffer );
	return( TRUE );
	}

int testSignDataCMS( void )
	{
	CRYPT_CERTIFICATE cmsAttributes;
	int status;

	/* First test the basic CMS signature with default attributes (content
	   type, signing time, and message digest) */
	if( !signDataCMS( "CMS signature", CRYPT_USE_DEFAULT ) )
		return( FALSE );

	/* Create some CMS attributes and sign the data with the user-defined
	   attributes */
	status = cryptCreateCert( &cmsAttributes, CRYPT_CERTTYPE_CMS_ATTRIBUTES );
	if( cryptStatusOK( status ) && \
		!addCertFields( cmsAttributes, cmsAttributeData ) )
		status = CRYPT_ERROR;
	if( cryptStatusError( status ) )
		return( FALSE );
	status = signDataCMS( "complex CMS signature", cmsAttributes );
	cryptDestroyCert( cmsAttributes );

	return( status );
	}
