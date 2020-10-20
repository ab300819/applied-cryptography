/****************************************************************************
*																			*
*					  Envelope-based File Processing Program				*
*						Copyright Peter Gutmann 1997-1998					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _MSC_VER
  #include "../capi.h"
#else
  #include "capi.h"
#endif /* Braindamaged MSC include handling */

/* The following program isn't generally kept in sync with beta releases
   since the code changes too much.  Don't expect it to work with anything
   except final releases */

/* Define the following to run the program in test mode (no real randomness,
   hardcoded test keys and passwords) */

/*#define TEST_MODE	/**/

/* There are a few OS's broken enough not to define the standard exit codes
   (SunOS springs to mind) so we define some sort of equivalent here just
   in case */

#ifndef EXIT_SUCCESS
  #define EXIT_SUCCESS	0
  #define EXIT_FAILURE	!EXIT_SUCCESS
#endif /* EXIT_SUCCESS */

/* Under Win32 the certain things (mainly paths) are somewhat different
   because of the way Visual C does things */

#if defined( _WIN32 ) || defined( WIN32 )
  #define __WIN32__
#endif /* _WIN32 || WIN32 */

/* If we're using a DOS compiler but not a 32-bit one, record this */

#if defined( __MSDOS__ ) && !defined( __MSDOS32__ )
  #define __MSDOS16__
#endif /* __MSDOS__ && !__MSDOS32__ */

/* The names of the test external public and private key files */

#ifdef TEST_MODE
  #if defined( __WIN32__ )
	#define PGP_PUBKEY_FILE		"../../test/pubring.pgp"
	#define PGP_PRIVKEY_FILE	"../../test/secring.pgp"
  #elif defined( __WIN16__ )
	#define PGP_PUBKEY_FILE		"../test/pubring.pgp"
	#define PGP_PRIVKEY_FILE	"../test/secring.pgp"
  #else
	#define PGP_PUBKEY_FILE		"test/pubring.pgp"
	#define PGP_PRIVKEY_FILE	"test/secring.pgp"
  #endif /* __WIN32__ */
#else
  #define PGP_PUBKEY_FILE		"pubring.pgp"
  #define PGP_PRIVKEY_FILE		"secring.pgp"
#endif /* TEST_MODE */

/* Various useful types and defines */

typedef unsigned char	BYTE;
#ifndef __WIN32__
  typedef int			BOOLEAN;
#endif /* __WIN32__ */

#ifndef TRUE
  #define FALSE			0
  #define TRUE			!FALSE
#endif /* TRUE */

/* The size of the file I/O buffer */

#if defined( __MSDOS16__ ) || \
	( defined( _WINDOWS ) && !( defined( WIN32 ) || defined( _WIN32 ) ) )
  #define IO_BUFFERSIZE	16384
#else
  #define IO_BUFFERSIZE	32768
#endif /* OS-specific buffer size defines */

/* The encryption routines need to be careful about cleaning up allocated
   memory which contains sensitive information.  Ideally we would throw an
   exception which takes care of this, but we can't really do this without
   assuming a C++ compiler.  As a tradeoff the following macro, which just
   evaluates to a goto, is used to indicate that we'd do something nicer
   here if we could */

#define THROW( x )	goto x

/****************************************************************************
*																			*
*							Key Acquisition Routines						*
*																			*
****************************************************************************/

/* Get a password from the user */

static void getPassword( const char *prompt, char *password )
	{
#ifdef TEST_MODE
	puts( "Using hardcoded test password..." );
//	strcpy( password, ( *prompt == 'p' ) ? "test10" : "1234" );
	strcpy( password, ( *prompt == 'p' ) ? "test10" : "test10" );
	if( password ) return;
#endif /* TEST_MODE */
	printf( "Please enter %s: ", prompt );
	fflush( stdout );
	fgets( password, 200, stdin );
	password[ strlen( password ) - 1 ] = '\0';
	}

/* Get a public key from a keyring */

static int getPublicKey( CRYPT_CONTEXT *cryptContext, const char *keyring,
						 const char *userID )
	{
	CRYPT_KEYSET cryptKeyset;
	int status;

	/* Open the external key collection and try to read the required key */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE, keyring,
							  CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't open public key file %s, error code %d.\n",
				keyring, status );
		return( status );
		}
	status = cryptGetPublicKey( cryptKeyset, cryptContext, CRYPT_KEYID_NAME,
								userID );
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't get public key for %s, error code %d\n",
				userID, status );
		return( status );
		}
	cryptKeysetClose( cryptKeyset );

	return( CRYPT_OK );
	}

/* Get a (possibly encrypted) private key from a keyring */

static int getPrivateKey( CRYPT_CONTEXT *cryptContext, const char *keyring,
						  const char *prompt, const char *userID,
						  const char *password )
	{
	CRYPT_KEYSET cryptKeyset;
	const char *passwordPtr = password;
	int status;

	/* Open the external key collection and try to read the required key */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE, keyring,
							  CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't open private key file %s, error code %d.\n",
				keyring, status );
		return( status );
		}
	status = cryptGetPrivateKey( cryptKeyset, cryptContext, CRYPT_KEYID_NAME,
								 userID, NULL );
	if( status == CRYPT_WRONGKEY )
		{
		char passwordBuffer[ 200 ];

		/* We need a password for this private key, get it from the user and
		   get the key again */
		if( passwordPtr == NULL )
			{
			passwordPtr = passwordBuffer;
			getPassword( prompt, passwordBuffer );
			}
		status = cryptGetPrivateKey( cryptKeyset, cryptContext, CRYPT_KEYID_NAME,
									 userID, passwordPtr );
		memset( passwordBuffer, 0, 200 );
		}
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't get private key for %s, error code %d\n", userID,
				status );
		return( status );
		}
	cryptKeysetClose( cryptKeyset );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Resource Management Routines					*
*																			*
****************************************************************************/

/* Add a resource to an envelope.  Note that we wouldn't normally encounter
   session key or conventional key resources from the test application */

static int addResource( CRYPT_ENVELOPE cryptEnvelope,
						const CRYPT_RESOURCE_TYPE resource,
						const char *userID, const char *password,
						const BOOLEAN isDeenvelope )
	{
	CRYPT_CONTEXT cryptContext = CRYPT_ERROR;
	const char *passwordPtr = password;
	char passwordBuffer[ 200 ];
	int status;

	/* If the user hasn't specified a password, use our internal buffer to
	   get one from them */
	if( passwordPtr == NULL )
		passwordPtr = passwordBuffer;

	/* Figure out what it is we need */
	switch( resource )
		{
		case CRYPT_RESOURCE_SIGNATURE:
			/* Add a signature verification resource */
			if( isDeenvelope )
				status = getPublicKey( &cryptContext, PGP_PUBKEY_FILE, userID );
			else
				status = getPrivateKey( &cryptContext, PGP_PRIVKEY_FILE,
										"signature key password", userID,
										password );
			break;

		case CRYPT_RESOURCE_PASSWORD:
			if( password == NULL )
				getPassword( ( isDeenvelope ) ? "decryption password" : \
							 "encryption password", passwordBuffer );
			status = cryptAddResource( cryptEnvelope, CRYPT_RESOURCE_PASSWORD,
									   passwordPtr );
			memset( passwordBuffer, 0, 200 );
			break;

		case CRYPT_RESOURCE_PRIVATEKEY:
			/* Add a public-key decryption resource */
			status = getPrivateKey( &cryptContext, PGP_PRIVKEY_FILE,
									"decryption key password", userID,
									password );
			break;

		case CRYPT_RESOURCE_PUBLICKEY:
			/* Add a public-key encryption resource */
			status = getPublicKey( &cryptContext, PGP_PUBKEY_FILE, userID );
			break;

		case CRYPT_RESOURCE_SESSIONKEY:
			puts( "A session key encryption context is needed to process "
				  "this file.  This\ntype of processing isn't supported by "
				  "this program." );
			return( CRYPT_ERROR );

		case CRYPT_RESOURCE_KEY:
			puts( "A conventional encryption context is needed to process "
				  "this file.  This\ntype of processing isn't supported by "
				  "this program." );
			return( CRYPT_ERROR );

		default:
			/* We shouldn't get anything else */
			printf( "An unknown resource of type %d is needed to process "
					"this file.\n", resource );
			return( CRYPT_ERROR );
		}

	/* Add the resource to the envelope */
	if( resource != CRYPT_RESOURCE_PASSWORD )
		{
		if( cryptStatusOK( status ) )
			status = cryptAddResource( cryptEnvelope, resource,
									   ( void * ) cryptContext );
		cryptDestroyContext( cryptContext );
		}

	return( status );
	}

/****************************************************************************
*																			*
*						Stream Data Processing Routines						*
*																			*
****************************************************************************/

/* Process the data in an I/O stream */

static int processStream( FILE *inFile, FILE *outFile,
						  CRYPT_ENVELOPE cryptEnvelope )
	{
	BYTE *inBuffer, *outBuffer;
	int status;

	/* Allocate the I/O buffer */
	if( ( inBuffer = malloc( IO_BUFFERSIZE ) ) == NULL )
		return( CRYPT_NOMEM );
	if( ( outBuffer = malloc( IO_BUFFERSIZE ) ) == NULL )
		{
		free( inBuffer );
		return( CRYPT_NOMEM );
		}

	/* Process the entire stream */
	while( !feof( inFile ) )
		{
		int length = IO_BUFFERSIZE, offset = 0;

		length = fread( inBuffer, 1, length, inFile );
		while( length )
			{
			int bytesIn;

			/* Push as much as we can into the envelope */
			status = cryptPushData( cryptEnvelope, inBuffer + offset, length,
									&bytesIn );
			if( cryptStatusError( status ) )
				THROW( exception );
			length -= bytesIn;

			/* If we couldn't push everything, the envelope is full, so we
			   empty a buffers worth out */
			if( length )
				{
				int bytesOut;

				status = cryptPopData( cryptEnvelope, outBuffer,
									   IO_BUFFERSIZE, &bytesOut );
				if( cryptStatusError( status ) )
					THROW( exception );
				fwrite( outBuffer, 1, bytesOut, outFile );
				}
			offset += bytesIn;
			}
		}

	/* Flush out any remaining data */
	while( TRUE )
		{
		int bytesOut;

		status = cryptPushData( cryptEnvelope, NULL, 0, NULL );	/* Flush */
		if( cryptStatusOK( status ) || status == CRYPT_COMPLETE )
			status = cryptPopData( cryptEnvelope, outBuffer, IO_BUFFERSIZE,
								   &bytesOut );
		if( cryptStatusError( status ) || bytesOut == 0 )
			break;
		fwrite( outBuffer, 1, bytesOut, outFile );
		}

	/* Exception/exit handlers */
exception:
	memset( inBuffer, 0, IO_BUFFERSIZE );
	free( inBuffer );
	memset( outBuffer, 0, IO_BUFFERSIZE );
	free( outBuffer );
	return( status );
	}

/****************************************************************************
*																			*
*								Enveloping Routines							*
*																			*
****************************************************************************/

/* Envelope an I/O stream */

static int envelopeStream( FILE *inFile, FILE *outFile,
						   BOOLEAN doConventionalEncrypt, char *encryptID,
						   char *signID, const char *password )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	int status;

	/* Create the envelope */
	status = cryptCreateEnvelope( &cryptEnvelope );
	if( cryptStatusError( status ) )
		return( status );

	/* Add the required resources */
	if( doConventionalEncrypt )
		{
		status = addResource( cryptEnvelope, CRYPT_RESOURCE_PASSWORD, NULL,
							  password, FALSE );
		if( cryptStatusError( status ) )
			THROW( exception );
		}
	if( encryptID != NULL )
		{
		status = addResource( cryptEnvelope, CRYPT_RESOURCE_PUBLICKEY,
							  encryptID, NULL, FALSE );
		if( cryptStatusError( status ) )
			THROW( exception );
		}
	if( signID != NULL )
		{
		status = addResource( cryptEnvelope, CRYPT_RESOURCE_SIGNATURE,
							  signID, password, FALSE );
		if( cryptStatusError( status ) )
			THROW( exception );
		}

	/* Envelope the data */
	status = processStream( inFile, outFile, cryptEnvelope );

	/* Exception/exit handlers */
exception:
	if( cryptEnvelope != CRYPT_ERROR )
		cryptDestroyEnvelope( cryptEnvelope );
	return( status );
	}

/* De-envelope an I/O stream */

static int deenvelopeStream( FILE *inFile, FILE *outFile,
							 const char *password )
	{
	CRYPT_KEYSET decryptKeyset = CRYPT_ERROR, sigCheckKeyset = CRYPT_ERROR;
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_RESOURCE_TYPE cryptResource;
	CRYPT_FORMAT_TYPE formatType;
	const char *passwordPtr = password;
	void *ioBuffer = NULL;
	int length, status;

	/* Try and figure out what we're deenveloping.  This is fairly crude,
	   normally we'd know what sort of data we've got from the file type or
	   extension or MIME content type or whatever, but since this is meant
	   to be a general-purpose program we kludge it by looking at the start
	   of the data and taking a guess */
	status = getc( inFile );
	ungetc( status, inFile );
	if( status == 0x30 )
		formatType = CRYPT_FORMAT_CRYPTLIB;
	else
		if( ( status & 0xC0 ) == 0x80 )
			formatType = CRYPT_FORMAT_PGP;
		else
			return( CRYPT_BADDATA );

	/* Allocate the I/O buffer */
	if( ( ioBuffer = malloc( IO_BUFFERSIZE ) ) == NULL )
		return( CRYPT_NOMEM );

	/* Create the envelope */
	if( formatType == CRYPT_FORMAT_CRYPTLIB )
		status = cryptCreateDeenvelope( &cryptEnvelope );
	else
		status = cryptCreateDeenvelopeEx( &cryptEnvelope, formatType,
										  CRYPT_USE_DEFAULT );
	if( cryptStatusError( status ) )
		return( status );

	/* Add the keysets required to perform the deenveloping.  If they aren't
	   found, we continue anyway since they may not be needed */
	status = cryptKeysetOpen( &sigCheckKeyset, CRYPT_KEYSET_FILE,
							  PGP_PUBKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		{
		status = cryptAddKeyset( cryptEnvelope, sigCheckKeyset,
								 CRYPT_KEYFUNCTION_SIGCHECK );
		cryptKeysetClose( sigCheckKeyset );
		}
	if( cryptStatusError( status ) && status != CRYPT_DATA_NOTFOUND )
		THROW( exception );
	status = cryptKeysetOpen( &decryptKeyset, CRYPT_KEYSET_FILE,
							  PGP_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		{
		status = cryptAddKeyset( cryptEnvelope, decryptKeyset,
								 CRYPT_KEYFUNCTION_DECRYPT );
		cryptKeysetClose( sigCheckKeyset );
		}
	if( cryptStatusError( status ) && status != CRYPT_DATA_NOTFOUND )
		THROW( exception );

	/* Push in as much initial data as we can.  We should get a resource
	   error after we've pushed the data to tell us that we need to add
	   resources before we can continue with the deenveloping */
	if( ( length = fread( ioBuffer, 1, IO_BUFFERSIZE, inFile ) ) == 0 )
		{
		status = CRYPT_ERROR;
		THROW( exception );
		}
	status = cryptPushData( cryptEnvelope, ioBuffer, length, &length );
	if( cryptStatusError( status ) && status != CRYPT_ENVELOPE_RESOURCE )
		THROW( exception );
	free( ioBuffer );
	ioBuffer = NULL;

	/* If there's more data in the file, set the file pointer so that
	   processStream() will continue from where we left off */
	if( length == IO_BUFFERSIZE )
		fseek( inFile, ( long ) length, SEEK_SET );

	/* Print the resource types we need to continue */
	if( cryptGetFirstResource( cryptEnvelope, &cryptResource ) == CRYPT_OK )
		do
			{
			/* If we've processed the entire data block in one go, we may end
			   up with only signature resources required, in which case we
			   defer processing them until after we've written the
			   deenveloped data to disk */
			if( cryptResource == CRYPT_RESOURCE_SIGNATURE )
				break;

			/* If it's public-key encrypted, perform the necessary steps to
			   get the private key to the enveloping code */
			if( cryptResource == CRYPT_RESOURCE_PRIVATEKEY )
				{
				char nameBuffer[ CRYPT_MAX_TEXTSIZE ], passwordBuffer[ 200 ];

				puts( "A private key is needed to decrypt this file." );
				status = cryptGetResourceOwnerName( cryptEnvelope, nameBuffer );
				if( status == CRYPT_OK )
					break;	/* Key present, not encrypted */
				if( status == CRYPT_DATA_NOTFOUND )
					break;	/* Private key for this user not present */

				/* Private key is present and we need a password to decrypt
				   it.  The enveloping code knows that it needs a password
				   for this, so we can resolve things by adding a password
				   resource */
				if( passwordPtr == NULL )
					{
					passwordPtr = passwordBuffer;
					getPassword( "private key decryption password",
								 passwordBuffer );
					}
				status = cryptAddResource( cryptEnvelope, CRYPT_RESOURCE_PASSWORD,
										   passwordPtr );
				memset( passwordBuffer, 0, 200 );
				break;
				}

			/* It's something else, feed it to the general-purpose resource-
			   handling routine */
			status = addResource( cryptEnvelope, cryptResource, NULL,
								  password, TRUE );
			if( cryptStatusError( status ) )
				THROW( exception );
			}
		while( cryptGetNextResource( cryptEnvelope, &cryptResource ) == CRYPT_OK );

	/* De-envelope the data */
	status = processStream( inFile, outFile, cryptEnvelope );
	if( cryptStatusError( status ) )
		THROW( exception );

	/* Check if there are signature resources present */
	if( cryptGetFirstResource( cryptEnvelope, &cryptResource ) == CRYPT_OK )
		do
			{
			char nameBuffer[ CRYPT_MAX_TEXTSIZE ];

			/* Make sure it's a signature resource */
			if( cryptResource != CRYPT_RESOURCE_SIGNATURE )
				{
				printf( "An unknown resource type %d was encountered.\n",
						cryptResource );
				break;
				}

			/* Check the signature */
			status = cryptGetResourceOwnerName( cryptEnvelope, nameBuffer );
			switch( status )
				{
				case CRYPT_OK:
					printf( "The file has a valid signature from %s.\n",
							nameBuffer );
					break;
				case CRYPT_DATA_NOTFOUND:
					puts( "Cannot find the public key needed to check the "
						  "signature." );
					break;
				case CRYPT_BADSIG:
					printf( "The file has an invalid signature from %s.\n",
							nameBuffer );
					break;
				default:
					printf( "The attempt to check the signature check failed "
							"with a status of %d.\n", status );
				}
			}
		while( cryptGetNextResource( cryptEnvelope, &cryptResource ) == CRYPT_OK );

	/* Exception/exit handlers */
exception:
	if( decryptKeyset != CRYPT_ERROR )
		cryptKeysetClose( decryptKeyset );
	if( sigCheckKeyset != CRYPT_ERROR )
		cryptKeysetClose( sigCheckKeyset );
	if( cryptEnvelope != CRYPT_ERROR )
		cryptDestroyEnvelope( cryptEnvelope );
	if( ioBuffer != NULL )
		free( ioBuffer );
	return( status );
	}

/****************************************************************************
*																			*
*									Main Program							*
*																			*
****************************************************************************/

/* Error codes.  cryptlib return codes are converted to a positive value
   (some OS's don't like negative status codes), application-specific codes
   unrelated to cryptlib are given below */

#define ERROR_BADARG		500		/* Bad argument */
#define ERROR_FILE_EXISTS	501		/* Output file already exists */
#define ERROR_FILE_INPUT	502		/* Error opening input file */
#define ERROR_FILE_OUTPUT	503		/* Error opening/creating output file */

/* The main program */

int main( int argc, char **argv )
	{
	FILE *inFile, *outFile;
	BOOLEAN doEnvelope = FALSE, doConventionalEncrypt = FALSE;
	BOOLEAN doOverwriteOutfile = FALSE;
	char *encryptID = NULL, *signID = NULL, *password = NULL;
	int status;

	/* Process the input parameters */
	if( argc < 3 )
		{
		puts( "Usage: testapp [-co -e<recipient> -p<password> -s<owner>] <infile> <outfile>" );
		puts( "       -c = conventional encrypt" );
		puts( "       -e = encrypt with key for <recipient>" );
		puts( "       -o = overwrite output file" );
		puts( "       -p = use <password> to encrypt/decrypt file or private key" );
		puts( "       -s = sign with key belonging to <owner>" );
		puts( "" );
		puts( "       Example: testapp -c infile outfile" );
		puts( "                - Conventionally encrypt infile, write result to outfile." );
		puts( "       Example: testapp -smykey infile outfile" );
		puts( "                - Sign infile, write result to outfile." );
		puts( "       Example: testapp infile outfile" );
		puts( "                - Decrypt or sig check infile, write result to outfile." );
		return( ERROR_BADARG );
		}

	/* VisualAge C++ doesn't set the TZ correctly */
#if defined( __IBMC__ ) || defined( __IBMCPP__ )
	tzset();
#endif /* VisualAge C++ */

	/* Initialise the library */
	status = cryptInit();
	if( cryptStatusError( status ) )
		{
		printf( "Encryption initialisation failed with error code %d.\n",
				status );
		return( -status );
		}

	/* Check for arguments */
	while( *argv[ 1 ] == '-' )
		{
		char *argPtr = argv[ 1 ] + 1;

		while( *argPtr )
			{
			switch( toupper( *argPtr ) )
				{
				case 'C':
					/* Perform basic error checking */
					if( encryptID != NULL )
						{
						puts( "You can't use both conventional and public-"
							  "key encryption for the same file." );
						return( ERROR_BADARG );
						}
					doConventionalEncrypt = doEnvelope = TRUE;
					argPtr++;
					break;

				case 'E':
					/* Perform basic error checking */
					if( doConventionalEncrypt )
						{
						puts( "You can't use both conventional and public-"
							  "key encryption for the same file." );
						return( ERROR_BADARG );
						}
					encryptID = argPtr + 1;
					if( !strlen( encryptID ) )
						{
						puts( "You must specify a recipient to encrypt the "
							  "file for." );
						return( ERROR_BADARG );
						}
					doEnvelope = TRUE;
                    argPtr += strlen( argPtr );
					break;

				case 'O':
					doOverwriteOutfile = TRUE;
					argPtr++;
					break;

				case 'P':
					/* Perform basic error checking */
					if( password != NULL )
						break;
					password = argPtr + 1;
					if( !strlen( password ) )
						{
						puts( "You must specify a password to "
							  "encrypt/decrypt." );
						return( ERROR_BADARG );
						}
					argPtr += strlen( argPtr );
					break;

				case 'S':
					/* Perform basic error checking */
					if( signID != NULL )
						break;
					signID = argPtr + 1;
					if( !strlen( signID ) )
						{
						puts( "You must specify a key owner to sign the "
							  "file with." );
						return( ERROR_BADARG );
						}
					doEnvelope = TRUE;
					argPtr += strlen( argPtr );
					break;

				default:
					printf( "Unknown option '%c'.\n", *argPtr );
					return( ERROR_BADARG );
				}
			}

		argv++;
		}

#ifdef TEST_MODE
	/* In order to avoid having to do a randomness poll for every test run,
	   we bypass the randomness-handling by adding some junk - it doesn't
	   matter here because we're not worried about security, but should never
	   be done in production code */
	cryptAddRandom( "a", 1 );
#endif /* TEST_MODE */

	/* At the moment we can't both encrypt and sign in one pass because the
	   low-level ASN.1 encoding routines can't handle this yet */
	if( encryptID != NULL && signID != NULL )
		{
		puts( "This version of cryptlib cannot both sign and encrypt data in "
			  "the same\noperation." );
		return( ERROR_BADARG );
		}

	/* Make sure the output file doesn't already exist */
	if( ( outFile = fopen( argv[ 2 ], "rb" ) ) != NULL )
		{
		fclose( outFile );
		if( !doOverwriteOutfile )
			{
			printf( "Output file %s already exists.\n", argv[ 2 ] );
			return( ERROR_FILE_EXISTS );
			}
		}

	/* Open the input and output files */
	if( ( inFile = fopen( argv[ 1 ], "rb" ) ) == NULL )
		{
		perror( argv[ 1 ] );
		return( ERROR_FILE_INPUT );
		}
	if( ( outFile = fopen( argv[ 2 ], "wb" ) ) == NULL )
		{
		fclose( inFile );
		perror( argv[ 2 ] );
		return( ERROR_FILE_OUTPUT );
		}

	/* Envelope or deenvelope the data */
	if( doEnvelope )
		status = envelopeStream( inFile, outFile, doConventionalEncrypt,
								 encryptID, signID, password );
	else
		status = deenvelopeStream( inFile, outFile, password );

	/* Clean up */
	fclose( inFile );
	fclose( outFile );
	if( cryptStatusError( status ) )
		{
		printf( "Data %senveloping failed with error code %d\n",
				( doEnvelope ) ? "" : "de-", status );
		return( -status );
		}

	/* Clean up */
	status = cryptEnd();
	if( cryptStatusError( status ) )
		{
		printf( "Encryption shutdown failed with error code %d.\n", status );
		return( -status );
		}
	if( doEnvelope )
		{
		if( signID )
			printf( "The has been signed by %s.\n", signID );
		if( encryptID )
			printf( "The file has been encrypted for %s.\n", encryptID );
		if( doConventionalEncrypt )
			puts( "The file has been conventionally encrypted." );
		if( !signID && !encryptID && !doConventionalEncrypt )
			puts( "The file has been encapsulated as raw data." );
		}
	else
		printf( "File processing succeeded.\n" );
	return( EXIT_SUCCESS );
	}
