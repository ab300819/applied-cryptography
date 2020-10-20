/****************************************************************************
*																			*
*						  cryptlib Fortezza Routines						*
*						Copyright Peter Gutmann 1998						*
*																			*
****************************************************************************/

/* This file contains its own version of the various Fortezza definitions and
   values to avoid potential copyright problems with redistributing the
   Fortezza interface library header files */

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "cryptctx.h"
  #include "asn1.h"
  #include "device.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../cryptctx.h"
  #include "../keymgmt/asn1.h"
  #include "device.h"
#else
  #include "crypt.h"
  #include "cryptctx.h"
  #include "keymgmt/asn1.h"
  #include "misc/device.h"
#endif /* Compiler-specific includes */

/* Return codes */

#define CI_OK			0			/* OK */
#define CI_FAIL			1			/* Generic failure */
#define CI_EXEC_FAIL	10			/* Command execution failed */
#define CI_NO_KEY		11			/* No key loaded */
#define CI_NO_IV		12			/* No IV loaded */
#define CI_NO_X			13			/* No DSA x value loaded */
#define CI_NO_CARD		-20			/* Card not present */
#define CI_BAD_CARD		-30			/* Invalid or malfunctioning card */

/* Constants */

#define CI_NULL_FLAG	0			/* No operation */

#define CI_PIN_SIZE		12			/* Maximum size of PIN */

#define CI_SSO_PIN		37			/* SSO PIN */
#define CI_USER_PIN		42			/* User PIN */

#define CI_KEA_TYPE		5			/* KEA algorithm */
#define CI_DSA_TYPE		10			/* DSA algorithm */
#define CI_DSA_KEA_TYPE	15			/* DSA+KEA algorithm */

#define CI_ENCRYPT_TYPE	0			/* Cipher mode = encryption */
#define CI_DECRYPT_TYPE	1			/* Cipher mode = decryption */

#define CI_ECB64_MODE	0			/* Skipjack/ECB */
#define CI_CBC64_MODE	1			/* Skipjack/CBC */
#define CI_OFB64_MODE	2			/* Skipjack/OFB */
#define CI_CFB64_MODE	3			/* Skipjack/CFB */

/* Data types */

typedef BYTE *CI_DATA;				/* Pointer to plaintext/ciphertext */
typedef BYTE CI_IV[ 24 ];			/* LEAF + IV */
typedef BYTE CI_G[ 128 ];			/* DSA g paramter */
typedef BYTE CI_HASHVALUE[ 20 ];	/* SHA-1 hash value */
typedef BYTE CI_P[ 128 ];			/* DSA p parameter */
typedef BYTE CI_PIN[ CI_PIN_SIZE + 4];	/* Longword-padded PIN */
typedef BYTE CI_Q[ 20 ];			/* DSA q parameter */
typedef BYTE CI_SIGNATURE[ 40 ];	/* DSA signature value */
typedef BYTE CI_Y[ 128 ];			/* Signature Y value */
typedef unsigned int *CI_STATE_PTR;	/* Pointer to device state */

/* Various constants not defined in the Fortezza driver code */

#define FORTEZZA_SOCKET		1			/* Default card socket */
#define FORTEZZA_IVSIZE		24			/* Size of LEAF+IV */

/****************************************************************************
*																			*
*						 		Init/Shutdown Routines						*
*																			*
****************************************************************************/

/* Global function pointers.  These are necessary because the functions need
   to be dynamically linked since not all systems contain the necessary
   DLL's.  Explicitly linking to them will make cryptlib unloadable on most
   systems */

#define NULL_HINSTANCE	( HINSTANCE ) NULL

static HINSTANCE hFortezza = NULL_HINSTANCE;

typedef int ( *CI_CHANGEPIN )( int PINType, CI_PIN pOldPIN, CI_PIN pNewPIN );
typedef int ( *CI_CHECKPIN )( int PINType, CI_PIN pPIN );
typedef int ( *CI_CLOSE )( unsigned int Flags, int SocketIndex );
typedef int ( *CI_DECRYPT )( unsigned int CipherSize, CI_DATA pCipher,
							 CI_DATA pPlain );
typedef int ( *CI_ENCRYPT )( unsigned int PlainSize, CI_DATA pPlain,
							 CI_DATA pCipher );
typedef int ( *CI_GENERATEIV )( CI_IV pIV );
typedef int ( *CI_GENERATEX )( int CertificateIndex, int AlgorithmType,
							   unsigned int PAndGSize, unsigned int QSize,
							   CI_P pP, CI_Q pQ, CI_G pG, unsigned int YSize,
							   CI_Y pY );
typedef int ( *CI_GETHASH )( unsigned int DataSize, CI_DATA pData,
							 CI_HASHVALUE pHashValue );
typedef int ( *CI_GETSTATE )( CI_STATE_PTR pState );
typedef int ( *CI_HASH )( unsigned int DataSize, CI_DATA pData );
typedef int ( *CI_INITIALIZE )( int *SocketCount );
typedef int ( *CI_INITIALIZEHASH )( void );
typedef int ( *CI_LOADIV )( CI_IV pIV );
typedef int ( *CI_LOCK )( int Flags );
typedef int ( *CI_OPEN )( unsigned int *Flags, int SocketIndex );
typedef int ( *CI_SETMODE )( int CryptoType, int CryptoMode );
typedef int ( *CI_SIGN )( CI_HASHVALUE pHashValue, CI_SIGNATURE pSignature );
typedef int ( *CI_TERMINATE )( void );
typedef int ( *CI_UNLOCK )( void );
typedef int ( *CI_VERIFYSIGNATURE )( CI_HASHVALUE pHashValue, unsigned int YSize,
									 CI_Y pY, CI_SIGNATURE pSignature );
typedef int ( *CI_ZEROIZE )( void );
static CI_CHANGEPIN pCI_ChangePIN = NULL;
static CI_CHECKPIN pCI_CheckPIN = NULL;
static CI_CLOSE pCI_Close = NULL;
static CI_DECRYPT pCI_Decrypt = NULL;
static CI_ENCRYPT pCI_Encrypt = NULL;
static CI_GENERATEIV pCI_GenerateIV = NULL;
static CI_GENERATEX pCI_GenerateX = NULL;
static CI_GETHASH pCI_GetHash = NULL;
static CI_GETSTATE pCI_GetState = NULL;
static CI_HASH pCI_Hash = NULL;
static CI_INITIALIZE pCI_Initialize = NULL;
static CI_INITIALIZEHASH pCI_InitializeHash = NULL;
static CI_LOADIV pCI_LoadIV = NULL;
static CI_LOCK pCI_Lock = NULL;
static CI_OPEN pCI_Open = NULL;
static CI_SETMODE pCI_SetMode = NULL;
static CI_SIGN pCI_Sign = NULL;
static CI_TERMINATE pCI_Terminate = NULL;
static CI_UNLOCK pCI_Unlock = NULL;
static CI_VERIFYSIGNATURE pCI_VerifySignature = NULL;
static CI_ZEROIZE pCI_Zeroize = NULL;

/* Depending on whether we're running under Win16 or Win32 we load the device
   driver under a different name */

#ifdef __WIN16__
  #define FORTEZZA_LIBNAME	"FTZA16.DLL"
#else
  #define FORTEZZA_LIBNAME	"FORTEZZA.DLL"
#endif /* __WIN16__ */

/* Dynamically load and unload any necessary card drivers */

void deviceInitFortezza( void )
	{
#ifdef __WIN16__
	UINT errorMode;
#endif /* __WIN16__ */
	static BOOLEAN initCalled = FALSE;
	int dummy;

	/* If we've previously tried to init the drivers, don't try it again */
	if( initCalled )
		return;
	initCalled = TRUE;

	/* Obtain a handle to the device driver module */
#ifdef __WIN16__
	errorMode = SetErrorMode( SEM_NOOPENFILEERRORBOX );
	hFortezza = LoadLibrary( FORTEZZA_LIBNAME );
	SetErrorMode( errorMode );
	if( hFortezza < HINSTANCE_ERROR )
		{
		hFortezza = NULL_HINSTANCE;
		return;
		}
#else
	if( ( hFortezza = LoadLibrary( FORTEZZA_LIBNAME ) ) == NULL_HINSTANCE )
		return;
#endif /* __WIN32__ */

	/* Now get pointers to the functions */
	pCI_ChangePIN = ( CI_CHANGEPIN ) GetProcAddress( hFortezza, "CI_ChangePIN" );
	pCI_CheckPIN = ( CI_CHECKPIN ) GetProcAddress( hFortezza, "CI_CheckPIN" );
	pCI_Close = ( CI_CLOSE ) GetProcAddress( hFortezza, "CI_Close" );
	pCI_Decrypt = ( CI_DECRYPT ) GetProcAddress( hFortezza, "CI_Decrypt" );
	pCI_Encrypt = ( CI_ENCRYPT ) GetProcAddress( hFortezza, "CI_Encrypt" );
	pCI_GenerateIV = ( CI_GENERATEIV ) GetProcAddress( hFortezza, "CI_GenerateIV" );
	pCI_GenerateX = ( CI_GENERATEX ) GetProcAddress( hFortezza, "CI_GenerateX" );
	pCI_GetHash = ( CI_GETHASH ) GetProcAddress( hFortezza, "CI_GetHash" );
	pCI_GetState = ( CI_GETSTATE ) GetProcAddress( hFortezza, "CI_GetState" );
	pCI_Hash = ( CI_HASH ) GetProcAddress( hFortezza, "CI_Hash" );
	pCI_Initialize = ( CI_INITIALIZE ) GetProcAddress( hFortezza, "CI_Initialize" );
	pCI_InitializeHash = ( CI_INITIALIZEHASH ) GetProcAddress( hFortezza, "CI_InitializeHash" );
	pCI_LoadIV = ( CI_LOADIV ) GetProcAddress( hFortezza, "CI_LoadIV" );
	pCI_Lock = ( CI_LOCK ) GetProcAddress( hFortezza, "CI_Lock" );
	pCI_Open = ( CI_OPEN ) GetProcAddress( hFortezza, "CI_Open" );
	pCI_SetMode = ( CI_SETMODE ) GetProcAddress( hFortezza, "CI_SetMode" );
	pCI_Sign = ( CI_SIGN ) GetProcAddress( hFortezza, "CI_Sign" );
	pCI_Terminate = ( CI_TERMINATE ) GetProcAddress( hFortezza, "CI_Terminate" );
	pCI_Unlock = ( CI_UNLOCK ) GetProcAddress( hFortezza, "CI_Unlock" );
	pCI_VerifySignature = ( CI_VERIFYSIGNATURE ) GetProcAddress( hFortezza, "CI_VerifySignature" );
	pCI_Zeroize = ( CI_ZEROIZE ) GetProcAddress( hFortezza, "CI_Zeroize" );

	/* Make sure we got valid pointers for every device function */
	if( pCI_ChangePIN == NULL || pCI_CheckPIN == NULL || pCI_Close == NULL ||
		pCI_Decrypt == NULL || pCI_Encrypt == NULL ||
		pCI_GenerateIV == NULL || pCI_GenerateX == NULL ||
		pCI_GetHash == NULL || pCI_GetState == NULL || pCI_Hash == NULL ||
		pCI_Initialize == NULL || pCI_InitializeHash == NULL ||
		pCI_LoadIV == NULL || pCI_Lock == NULL || pCI_Open == NULL ||
		pCI_SetMode == NULL || pCI_Sign == NULL || pCI_Terminate == NULL ||
		pCI_Unlock == NULL || pCI_VerifySignature == NULL ||
		pCI_Zeroize == NULL )
		{
		/* Free the library reference and reset the handle */
		FreeLibrary( hFortezza );
		hFortezza = NULL_HINSTANCE;
		}

	/* Initialise the Fortezza library */
	if( pCI_Initialize( &dummy ) != CI_OK )
		{
		/* Free the library reference and reset the handle */
		FreeLibrary( hFortezza );
		hFortezza = NULL_HINSTANCE;
		}
	}

void deviceEndFortezza( void )
	{
	if( hFortezza != NULL_HINSTANCE )
		{
		pCI_Terminate();
		FreeLibrary( hFortezza );
		}
	hFortezza = NULL_HINSTANCE;
	}

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* Map a Fortezza-specific error to a cryptlib error */

static int mapError( const int errorCode )
	{
	switch( errorCode )
		{
		case CI_OK:
			return( CRYPT_OK );
		case CI_NO_KEY:
			return( CRYPT_NOKEY );
		case CI_NO_IV:
			return( CRYPT_NOIV );
		case CI_NO_CARD:
		case CI_BAD_CARD:
			return( CRYPT_SIGNALLED );
		}

	return( CRYPT_ERROR );
	}

/****************************************************************************
*																			*
*					Device Init/Shutdown/Device Control Routines			*
*																			*
****************************************************************************/

/* Close a previously-opened session with the device.  We have to have this
   before the init function since it may be called by it if the init process
   fails */

static void shutdownDeviceFunction( DEVICE_INFO *deviceInfo )
	{
	UNUSED( deviceInfo );

	/* Unlock the socket and close the session with the device */
	pCI_Unlock();
	pCI_Close( CI_NULL_FLAG, FORTEZZA_SOCKET );
	}

/* Open a session with the device */

static int initDeviceFunction( DEVICE_INFO *deviceInfo )
	{
	unsigned int deviceState;
	int status;

	/* The Fortezza open is a bit problematic since the open will succeed
	   even if there's no device in the socket, so after we perform the
	   open we check the card state to make sure we're not just rhapsodising
	   into the void */
	status = pCI_Open( CI_NULL_FLAG, FORTEZZA_SOCKET );
	if( status == CI_OK )
		{
		status = pCI_GetState( &deviceState );
		if( status != CI_OK )
			pCI_Close( CI_NULL_FLAG, FORTEZZA_SOCKET );
		}
	if( status != CI_OK )
		{
		deviceInfo->errorCode = status;
		return( CRYPT_DATA_OPEN );
		}

	/* Lock the device for our exclusive use */
	status = pCI_Lock( CI_NULL_FLAG );
	if( status != CI_OK )
		{
		deviceInfo->errorCode = status;
		return( CRYPT_DATA_OPEN );
		}

	/* Set up device-specific information */
	deviceInfo->minPinSize = 1;
	deviceInfo->maxPinSize = CI_PIN_SIZE;

	return( CRYPT_OK );
	}

/* Handle device control functions */

static int controlFunction( DEVICE_INFO *deviceInfo,
							const CRYPT_DEVICECONTROL_TYPE type,
							const void *data1, const int data1Length,
							const void *data2, const int data2Length )
	{
	int status;

	UNUSED( deviceInfo );

	/* Handle user authorisation */
	if( type == CRYPT_DEVICECONTROL_AUTH_USER || \
		type == CRYPT_DEVICECONTROL_AUTH_SUPERVISOR )
		{
		BYTE pin[ CI_PIN_SIZE + 1 ];

		memcpy( pin, data1, data1Length );
		pin[ data1Length ] = '\0';	/* Ensure PIN is null-terminated */
		status = pCI_CheckPIN( ( type == CRYPT_DEVICECONTROL_AUTH_USER ) ? \
							   CI_USER_PIN : CI_SSO_PIN, pin );
		return( ( status == CI_FAIL ) ? CRYPT_WRONGKEY : mapError( status ) );
		}

	/* Handle authorisation value change */
	if( type == CRYPT_DEVICECONTROL_SET_AUTH_USER || \
		type == CRYPT_DEVICECONTROL_SET_AUTH_SUPERVISOR )
		{
		BYTE oldPIN[ CI_PIN_SIZE + 1 ], newPIN[ CI_PIN_SIZE + 1 ];

		memcpy( oldPIN, data1, data1Length );
		oldPIN[ data1Length ] = '\0';	/* Ensure PIN is null-terminated */
		memcpy( newPIN, data2, data2Length );
		newPIN[ data1Length ] = '\0';	/* Ensure PIN is null-terminated */
		status = pCI_ChangePIN( ( type == CRYPT_DEVICECONTROL_AUTH_USER ) ? \
								CI_USER_PIN : CI_SSO_PIN, oldPIN, newPIN );
		return( ( status == CI_FAIL ) ? CRYPT_WRONGKEY : mapError( status ) );
		}

	/* Handle zeroisation */
	if( type == CRYPT_DEVICECONTROL_ZEROISE )
		return( mapError( pCI_Zeroize() ) );

	/* Anything else isn't handled */
	return( CRYPT_BADPARM2 );
	}

/****************************************************************************
*																			*
*						 	Capability Interface Routines					*
*																			*
****************************************************************************/

/* Initialise the encryption */

static int initFunction( CRYPT_INFO *cryptInfoPtr, const void *cryptInfoEx )
	{
	const CRYPT_MODE cryptMode = cryptInfoPtr->capabilityInfo->cryptMode;
	int cryptoMode, status;

	UNUSED( cryptInfoEx );

	/* If we're hashing data, intialise the hashing */
	if( cryptMode == CRYPT_MODE_NONE )
		return( mapError( pCI_InitializeHash() ) );

	/* We're encrypting data, set the appropriate mode for future
	   en/decryption */
	switch( cryptMode )
		{
		case CRYPT_MODE_ECB:
			cryptoMode = CI_ECB64_MODE;
			break;

		case CRYPT_MODE_CBC:
			cryptoMode = CI_CBC64_MODE;
			break;

		case CRYPT_MODE_CFB:
			cryptoMode = CI_CFB64_MODE;
			break;

		case CRYPT_MODE_OFB:
			cryptoMode = CI_OFB64_MODE;
			break;
		}
	status = pCI_SetMode( CI_DECRYPT_TYPE, cryptoMode );
	if( status == CI_OK )
		status = pCI_SetMode( CI_ENCRYPT_TYPE, cryptoMode );
	return( mapError( status ) );
	}

/* Load an IV */

static int initIVFunction( CRYPT_INFO *cryptInfoPtr, const void *iv,
						   const int ivLength )
	{
	BYTE ivBuffer[ FORTEZZA_IVSIZE ];
	int status;

	if( ivLength );	/* Get rid of compiler warning */

	/* If the user has supplied an IV, load it into the device */
	if( iv != NULL )
		{
		status = pCI_LoadIV( ( BYTE * ) iv );
		return( mapError( status ) );
		}

	/* Generate a new IV in the device and store a copy in the context */
	status = pCI_GenerateIV( ivBuffer );
	if( status != CI_OK )
		return( mapError( status ) );
	cryptInfoPtr->ctxConv.ivLength = FORTEZZA_IVSIZE;
	memset( cryptInfoPtr->ctxConv.iv, 0, CRYPT_MAX_IVSIZE );
	memcpy( cryptInfoPtr->ctxConv.iv, ivBuffer, FORTEZZA_IVSIZE );
	cryptInfoPtr->ctxConv.ivSet = TRUE;

	return( CRYPT_OK );
	}

/* Load a key */

static int initKeyFunction( CRYPT_INFO *cryptInfoPtr, const void *key,
							const int keyLength )
	{
	UNUSED( cryptInfoPtr );

/*	pCI_DeleteKey, p.18 */
/*	pCI_SetKey, p.62 / pCI_SetPersonality, p.64 */
/*	pCI_GenerateMEK, p.25 = session key */

	return( CRYPT_ERROR );
	}

/* Generate a key */

static int generateKeyFunction( CRYPT_INFO *cryptInfoPtr,
								const int keySizeBits )
	{
	int status;

	UNUSED( cryptInfoPtr );

	status = pCI_GenerateX( 1, CI_DSA_TYPE, bitsToBytes( keySizeBits ), 20,
							NULL, NULL, NULL, 0, NULL );
	return( ( status == CI_EXEC_FAIL ) ? CRYPT_PKCCRYPT : mapError( status ) );
	}

/* Encrypt/decrypt/hash data */

static int encryptFunction( CRYPT_INFO *cryptInfoPtr, void *buffer, int length )
	{
	UNUSED( cryptInfoPtr );

	return( mapError( pCI_Encrypt( length, buffer, buffer ) ) );
	}

static int decryptFunction( CRYPT_INFO *cryptInfoPtr, void *buffer, int length )
	{
	UNUSED( cryptInfoPtr );

	return( mapError( pCI_Decrypt( length, buffer, buffer ) ) );
	}

static int hashFunction( CRYPT_INFO *cryptInfoPtr, void *buffer, int length )
	{
	/* The Fortezza implementation can only hash data in lots of 64 bytes.
	   In theory we could do our own buffering, but it's easier to complain
	   about it, in practice it's better if the caller uses the built-in
	   implementation which is much faster */
	if( length % 64 )
		return( CRYPT_BADPARM3 );

	/* Either continue the hashing or wrap up the hashing if this was the
	   last block */
	if( !length )
		return( mapError( pCI_GetHash( length, buffer,
									   cryptInfoPtr->ctxHash.hash ) ) );
	return( mapError( pCI_Hash( length, buffer ) ) );
	}

/* Sign/sig check data */

static int signFunction( CRYPT_INFO *cryptInfoPtr, void *buffer, int length )
	{
	CI_SIGNATURE signature;
	STREAM stream;
	int status;

	UNUSED( cryptInfoPtr );
	UNUSED( length );

	/* Sign the hash */
	status = pCI_Sign( buffer, signature );
	if( status != CI_OK )
		return( ( status == CI_EXEC_FAIL || status == CI_NO_X ) ?
				CRYPT_PKCCRYPT : mapError( status ) );

	/* Reformat the signature into the form expected by cryptlib */
	sMemConnect( &stream, buffer, STREAMSIZE_UNKNOWN );
	writeTag( &stream, BER_SEQUENCE );
	writeLength( &stream, sizeofStaticInteger( signature, 20 ) +
				 sizeofStaticInteger( signature + 20, 20 ) );
	writeStaticInteger( &stream, signature, 20, DEFAULT_TAG );
	writeStaticInteger( &stream, signature + 20, 20, DEFAULT_TAG );
	status = sMemSize( &stream );
	sMemDisconnect( &stream );

	return( status );
	}

static int readFixedValue( STREAM *stream, BYTE *buffer )
	{
	int length, status;

	/* Read an integer value and pad it out to a fixed length if necessary */
	status = readStaticInteger( stream, buffer, &length, 20 );
	if( cryptStatusError( status ) )
		return( status );
	if( length < 20 )
		{
		const int delta = 20 - length;

		memmove( buffer, buffer + delta, length );
		memset( buffer, 0, delta );
		}

	return( CRYPT_OK );
	}

static int sigCheckFunction( CRYPT_INFO *cryptInfoPtr, void *buffer, int length )
	{
	CI_SIGNATURE signature;
	STREAM stream;
	long dummy;
	int status;

	UNUSED( cryptInfoPtr );
	UNUSED( length );

	/* Decode the signature from the cryptlib format */
	sMemConnect( &stream, ( BYTE * ) buffer + 20, STREAMSIZE_UNKNOWN );
	if( readTag( &stream ) != BER_SEQUENCE )
		{
		sMemDisconnect( &stream );
		return( CRYPT_BADDATA );
		}
	readLength( &stream, &dummy );	/* Skip SEQ len.*/
	status = readFixedValue( &stream, signature );
	if( !cryptStatusError( status ) )
		status = readFixedValue( &stream, signature + 20 );
	if( cryptStatusError( status ) )
		return( CRYPT_BADDATA );
	sMemDisconnect( &stream );

	/* Verify the signature */
	status = pCI_VerifySignature( buffer, 0, NULL, signature );
	return( ( status == CI_EXEC_FAIL ) ? CRYPT_PKCCRYPT : mapError( status ) );
	}

/****************************************************************************
*																			*
*						 	Device Capability Routines						*
*																			*
****************************************************************************/

/* The capability information for this device */

#define bits(x)	bitsToBytes(x)

static const CAPABILITY_INFO FAR_BSS capabilities[] = {
	/* The Skipjack capabilities.  The bizarre IV is the LEAF+IV */
	{ CRYPT_ALGO_SKIPJACK, CRYPT_MODE_ECB, bits( 64 ), "Skipjack", "ECB",
		bits( 80 ), bits( 80 ), bits( 80 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		NULL, initFunction, NULL, NULL, initKeyFunction,
		NULL, NULL, encryptFunction, decryptFunction, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_SKIPJACK, CRYPT_MODE_CBC, bits( 64 ), "Skipjack", "CBC",
		bits( 80 ), bits( 80 ), bits( 80 ),
		bits( 192 ), bits( 192 ), bits( 192 ),
		NULL, initFunction, NULL, initIVFunction, initKeyFunction,
		NULL, NULL, encryptFunction, decryptFunction, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_SKIPJACK, CRYPT_MODE_CFB, bits( 8 ), "Skipjack", "CFB",
		bits( 80 ), bits( 80 ), bits( 80 ),
		bits( 192 ), bits( 192 ), bits( 192 ),
		NULL, initFunction, NULL, initIVFunction, initKeyFunction,
		NULL, NULL, encryptFunction, decryptFunction, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_SKIPJACK, CRYPT_MODE_OFB, bits( 8 ), "Skipjack", "OFB",
		bits( 80 ), bits( 80 ), bits( 80 ),
		bits( 192 ), bits( 192 ), bits( 192 ),
		NULL, initFunction, NULL, initIVFunction, initKeyFunction,
		NULL, NULL, encryptFunction, decryptFunction, NULL, NULL,
		CRYPT_ERROR },

	/* The SHA capabilities */
	{ CRYPT_ALGO_SHA, CRYPT_MODE_NONE, bits( 160 ), "SHA", "Hash algorithm",
		bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ),
		NULL, initFunction, NULL, NULL,
		NULL, NULL, NULL, hashFunction, hashFunction, NULL, NULL,
		CRYPT_ERROR },

	/* The DSA capabilities */
	{ CRYPT_ALGO_DSA, CRYPT_MODE_PKC, bits( 0 ), "DSA",
		"Public-key algorithm",
		bits( 512 ), bits( 1024 ), bits( 1024 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		NULL, NULL, NULL, NULL, initKeyFunction,
		generateKeyFunction, NULL, NULL, NULL, signFunction, sigCheckFunction,
		CRYPT_ERROR },

	/* The end-of-list marker */
	{ CRYPT_ALGO_NONE, CRYPT_MODE_NONE, CRYPT_ERROR, "", "",
		0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, CRYPT_ERROR }
	};

/* Get the capability information for a given algorithm and mode */

static int findCapabilityFunction( DEVICE_INFO *deviceInfo,
								   const void FAR_BSS **capabilityInfoPtr,
								   const CRYPT_ALGO cryptAlgo,
								   const CRYPT_MODE cryptMode )
	{
	int index, status = CRYPT_NOALGO;

	UNUSED( deviceInfo );

	/* Find the capability corresponding to the requested algorithm/mode */
	for( index = 0; capabilities[ index + 1 ].blockSize != CRYPT_ERROR; index++ )
		if( capabilities[ index ].cryptAlgo == cryptAlgo )
			{
			status = CRYPT_NOMODE;
			if( capabilities[ index ].cryptMode == cryptMode || \
				cryptMode == CRYPT_UNUSED )
				{
				*capabilityInfoPtr = &capabilities[ index ];
				status = CRYPT_OK;
				break;
				}
			}
	return( status );
	}

/* Create a context using the capabilities of the device */

static int createContextFunction( DEVICE_INFO *deviceInfo,
								  CRYPT_CONTEXT *cryptContext,
								  const CRYPT_ALGO cryptAlgo,
								  const CRYPT_MODE cryptMode )
	{
	const CAPABILITY_INFO *capabilityInfoPtr;
	int status;

	UNUSED( deviceInfo );

	/* Find the capability corresponding to the requested algorithm/mode */
	status = findCapabilityFunction( deviceInfo,
				( const void ** ) &capabilityInfoPtr, cryptAlgo, cryptMode );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the context */
	return( createContext( cryptContext, capabilityInfoPtr, NULL, 0 ) );
	}

/****************************************************************************
*																			*
*						 	Device Access Routines							*
*																			*
****************************************************************************/

/* Set up the function pointers to the device methods */

int setDeviceFortezza( DEVICE_INFO *deviceInfo )
	{
	/* Load the Fortezza driver DLL's if they aren't already loaded */
	if( hFortezza == NULL_HINSTANCE )
		{
		deviceInitFortezza();
		if( hFortezza == NULL_HINSTANCE )
			return( CRYPT_DATA_OPEN );
		}

	deviceInfo->initDeviceFunction = initDeviceFunction;
	deviceInfo->shutdownDeviceFunction = shutdownDeviceFunction;
	deviceInfo->controlFunction = controlFunction;
	deviceInfo->findCapabilityFunction = findCapabilityFunction;
	deviceInfo->createContextFunction = createContextFunction;

	return( CRYPT_OK );
	}
