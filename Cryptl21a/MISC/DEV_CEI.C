/****************************************************************************
*																			*
*				cryptlib CE Infosys DES Accelerator Routines				*
*						Copyright Peter Gutmann 1995-1998					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "cryptctx.h"
  #include "device.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../cryptctx.h"
  #include "device.h"
#else
  #include "crypt.h"
  #include "cryptctx.h"
  #include "misc/device.h"
#endif /* Compiler-specific includes */

/* Encryption modes */

#define CEI_MODE_ECB		0		/* DES-ECB */
#define CEI_MODE_CBC		1		/* DES-CBC */
#define CEI_MODE_CFB		2		/* DES-CFB */
#define CEI_MODE_OFB		3		/* DES-OFB */
#define CEI_MODE_KSG		4		/* DES-KSG (counter mode, not used) */

/* Values returned by the MiniCrypt driver */

#define CEI_STATUS_OK			0	/* OK */
#define CEI_STATUS_BADCMD		-1	/* Invalid driver command */
#define CEI_STATUS_NOCARD		-2	/* Card not found */
#define CEI_STATUS_INITERR		-3	/* Card initialisation error */
#define CEI_STATUS_NOKEYS		-4	/* No key slots available */
#define CEI_STATUS_KEYLOADERR	-5	/* Key load error */
#define CEI_STATUS_KEYUNAVAIL	-6	/* Key unavailable for this type of opn */
#define CEI_STATUS_ENCERR		-7	/* Encrypt error */
#define CEI_STATUS_DECERR		-8	/* Decrypt error */

/* Create a triple DES key from three single keys */

#define make3DesKey(key1,key2,key3)	\
	( ( ( key3 ) << 8 ) | ( ( key2 ) << 4 ) | ( key1 ) )

/* The loadIV() function is shared among all the built-in capabilities */

int loadIV( CRYPT_INFO *cryptInfoPtr, const void *iv, const int ivLength );

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

static HINSTANCE hCEI = NULL_HINSTANCE;

typedef int ( *CEIINIT )( void );
typedef int ( *CEICLEAR )( void );
typedef int ( *CEILOADKEY )( const int keyNo, const BYTE *key );
typedef int ( *CEIDELETEKEY )( const int keyNo );
typedef int ( *CEIENCRYPT )( const int keyNo, const int mode, BYTE *iv,
							 BYTE *data, const int count );
typedef int ( *CEIDECRYPT )( const int keyNo, const int mode, BYTE *iv,
							 BYTE *data, const int count );
static CEIINIT pSuperCryptInit = NULL;
static CEICLEAR pSuperCryptClear = NULL;
static CEILOADKEY pSuperCryptLoadKey = NULL;
static CEIDELETEKEY pSuperCryptDeleteKey = NULL;
static CEIENCRYPT pSuperCryptEncrypt = NULL;
static CEIDECRYPT pSuperCryptDecrypt = NULL;

/* Depending on whether we're running under Win16 or Win32 we load the device
   driver under a different name */

#ifdef __WIN16__
  #define CEI_LIBNAME	"MINICRYP.DLL"
#else
  #define CEI_LIBNAME	"MiniCrypt.DLL"
#endif /* __WIN16__ */

/* Dynamically load and unload any necessary card drivers */

void deviceInitCEI( void )
	{
#ifdef __WIN16__
	UINT errorMode;
#endif /* __WIN16__ */
	static BOOLEAN initCalled = FALSE;

	/* If we've previously tried to init the drivers, don't try it again */
	if( initCalled )
		return;
	initCalled = TRUE;

	/* Obtain a handle to the device driver module */
#ifdef __WIN16__
	errorMode = SetErrorMode( SEM_NOOPENFILEERRORBOX );
	hCEI = LoadLibrary( CEI_LIBNAME );
	SetErrorMode( errorMode );
	if( hCEI < HINSTANCE_ERROR )
		{
		hCEI = NULL_HINSTANCE;
		return;
		}
#else
	if( ( hCEI = LoadLibrary( CEI_LIBNAME ) ) == NULL_HINSTANCE )
		return;
#endif /* __WIN32__ */

	/* Now get pointers to the functions */
	pSuperCryptInit = ( CEIINIT ) GetProcAddress( hCEI, "ceiInit" );
	pSuperCryptClear = ( CEICLEAR ) GetProcAddress( hCEI, "ceiClear" );
	pSuperCryptLoadKey = ( CEILOADKEY ) GetProcAddress( hCEI, "ceiLoadKey" );
	pSuperCryptDeleteKey = ( CEIDELETEKEY ) GetProcAddress( hCEI, "ceiDeleteKey" );
	pSuperCryptEncrypt = ( CEIENCRYPT ) GetProcAddress( hCEI, "ceiEncrypt" );
	pSuperCryptDecrypt = ( CEIDECRYPT ) GetProcAddress( hCEI, "ceiDecrypt" );

	/* Make sure we got valid pointers for every device function */
	if( pSuperCryptInit == NULL || pSuperCryptClear == NULL || 
		pSuperCryptLoadKey == NULL || pSuperCryptDeleteKey == NULL || 
		pSuperCryptEncrypt == NULL || pSuperCryptDecrypt == NULL )
		{
		/* Free the library reference and reset the handle */
		FreeLibrary( hCEI );
		hCEI = NULL_HINSTANCE;
		}

	/* Initialise the CEI library */
	if( pSuperCryptInit() != CEI_STATUS_OK )
		{
		/* Free the library reference and reset the handle */
		FreeLibrary( hCEI );
		hCEI = NULL_HINSTANCE;
		}
	}

void deviceEndCEI( void )
	{
	if( hCEI != NULL_HINSTANCE )
		{
		pSuperCryptClear();
		FreeLibrary( hCEI );
		}
	hCEI = NULL_HINSTANCE;
	}

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* Map a Minicrypt-specific error to a cryptlib error */

static int mapError( const int errorCode )
	{
	switch( errorCode )
		{
		case CEI_STATUS_OK:
			return( CRYPT_OK );
		case CEI_STATUS_INITERR:
			return( CRYPT_NOTINITED );
		case CEI_STATUS_NOKEYS:
		case CEI_STATUS_KEYLOADERR:
			return( CRYPT_NOKEY );
		case CEI_STATUS_KEYUNAVAIL:
			return( CRYPT_NOTAVAIL );
		case CEI_STATUS_NOCARD:
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

	/* Zeroize the device */
	pSuperCryptClear();
	}

/* Open a session with the device */

static int initDeviceFunction( DEVICE_INFO *deviceInfo )
	{
	UNUSED( deviceInfo );

	/* The card is just a dumb crypto accelerator, there's nothing to do
	   until we try to use it */
	return( CRYPT_OK );
	}

/* Handle device control functions */

static int controlFunction( DEVICE_INFO *deviceInfo,
							const CRYPT_DEVICECONTROL_TYPE type,
							const void *data1, const int data1Length,
							const void *data2, const int data2Length )
	{
	UNUSED( deviceInfo );
	if( data1 || data1Length || data2 || data2Length );	/* Get rid of compiler warning */

	/* Handle zeroisation */
	if( type == CRYPT_DEVICECONTROL_ZEROISE )
		return( mapError( pSuperCryptClear() ) );

	/* Anything else isn't handled */
	return( CRYPT_BADPARM2 );
	}

/****************************************************************************
*																			*
*						 	Capability Interface Routines					*
*																			*
****************************************************************************/

/* Load a key */

static int initKeyFunction( CRYPT_INFO *cryptInfoPtr, const void *key,
							const int keyLength )
	{
	int status;

	UNUSED( cryptInfoPtr );

	/* Load the first DES key into the first register */
	status = pSuperCryptLoadKey( 0, key );
	if( status != CEI_STATUS_OK || keyLength <= 8 )
		return( mapError( status ) );

	/* We're doing 3DES, load keys into subsequent registers to give either
	   EDE-3DES or 3-key 3DES */
	pSuperCryptLoadKey( 1, ( ( BYTE * ) key ) + 8 );
	if( keyLength > 16 )
		status = pSuperCryptLoadKey( 2, ( ( BYTE * ) key ) + 16 );
	else
		status = pSuperCryptLoadKey( 2, ( ( BYTE * ) key ) + 8 );

	return( mapError( status ) );
	}

/* Encrypt/decrypt data */

static int encryptFunction( CRYPT_INFO *cryptInfoPtr, void *buffer, int length )
	{
	const CRYPT_ALGO cryptAlgo = cryptInfoPtr->capabilityInfo->cryptAlgo;
	const CRYPT_MODE cryptMode = cryptInfoPtr->capabilityInfo->cryptMode;

	return( mapError( pSuperCryptEncrypt( ( cryptAlgo == CRYPT_ALGO_DES ) ? \
				0 : make3DesKey( 0, 1, 2 ), \
				( cryptMode == CRYPT_MODE_ECB ) ? CEI_MODE_ECB : \
				( cryptMode == CRYPT_MODE_CBC ) ? CEI_MODE_CBC : \
				( cryptMode == CRYPT_MODE_CFB ) ? CEI_MODE_CFB : CEI_MODE_OFB,
				cryptInfoPtr->ctxConv.currentIV, buffer, length ) ) );
	}

static int decryptFunction( CRYPT_INFO *cryptInfoPtr, void *buffer, int length )
	{
	const CRYPT_ALGO cryptAlgo = cryptInfoPtr->capabilityInfo->cryptAlgo;
	const CRYPT_MODE cryptMode = cryptInfoPtr->capabilityInfo->cryptMode;

	return( mapError( pSuperCryptDecrypt( ( cryptAlgo == CRYPT_ALGO_DES ) ? \
				0 : make3DesKey( 0, 1, 2 ), \
				( cryptMode == CRYPT_MODE_ECB ) ? CEI_MODE_ECB : \
				( cryptMode == CRYPT_MODE_CBC ) ? CEI_MODE_CBC : \
				( cryptMode == CRYPT_MODE_CFB ) ? CEI_MODE_CFB : CEI_MODE_OFB,
				cryptInfoPtr->ctxConv.currentIV, buffer, length ) ) );
	}

/****************************************************************************
*																			*
*						 	Device Capability Routines						*
*																			*
****************************************************************************/

/* The capability information for this device */

#define bits(x)	bitsToBytes(x)

static const CAPABILITY_INFO FAR_BSS capabilities[] = {
	/* The DES capabilities */
	{ CRYPT_ALGO_DES, CRYPT_MODE_ECB, bits( 64 ), "DES", "ECB",
		bits( 40 ), bits( 64 ), bits( 64 ),
		bits( 0 ), bits( 0 ), bits( 0  ),
		NULL, NULL, NULL, NULL, initKeyFunction, NULL,
		NULL, encryptFunction, decryptFunction, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_DES, CRYPT_MODE_CBC, bits( 64 ), "DES", "CBC",
		bits( 40 ), bits( 64 ), bits( 64 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		NULL, NULL, NULL, loadIV, initKeyFunction, NULL,
		NULL, encryptFunction, decryptFunction, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_DES, CRYPT_MODE_CFB, bits( 8 ), "DES", "CFB",
		bits( 40 ), bits( 64 ), bits( 64 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		NULL, NULL, NULL, loadIV, initKeyFunction, NULL,
		NULL, encryptFunction, decryptFunction, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_DES, CRYPT_MODE_OFB, bits( 8 ), "DES", "OFB",
		bits( 40 ), bits( 64 ), bits( 64 ),
		bits( 64 ), bits( 64 ), bits( 64 ),
		NULL, NULL, NULL, loadIV, initKeyFunction, NULL,
		NULL, encryptFunction, decryptFunction, NULL, NULL,
		CRYPT_ERROR },

	/* The triple DES capabilities.  Unlike the other algorithms, the minimum
	   key size here is 64 + 8 bits (nominally 56 + 1 bits) because using a
	   key any shorter is (a) no better than single DES, and (b) will result
	   in a key load error since the second key will be an all-zero weak
	   key */
	{ CRYPT_ALGO_3DES, CRYPT_MODE_ECB, bits( 64 ), "3DES", "ECB",
		bits( 64 + 8 ), bits( 128 ), bits( 192 ),
		bits( 0 ), bits( 0 ), bits( 0  ),
		NULL, NULL, NULL, NULL, initKeyFunction, NULL,
		NULL, encryptFunction, decryptFunction, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_3DES, CRYPT_MODE_CBC, bits( 64 ), "3DES", "CBC",
		bits( 64 + 8 ), bits( 128 ), bits( 192 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		NULL, NULL, NULL, loadIV, initKeyFunction, NULL,
		NULL, encryptFunction, decryptFunction, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_3DES, CRYPT_MODE_CFB, bits( 8 ), "3DES", "CFB",
		bits( 64 + 8 ), bits( 128 ), bits( 192 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		NULL, NULL, NULL, loadIV, initKeyFunction, NULL,
		NULL, encryptFunction, decryptFunction, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_3DES, CRYPT_MODE_OFB, bits( 8 ), "3DES", "OFB",
		bits( 64 + 8 ), bits( 128 ), bits( 192 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		NULL, NULL, NULL, loadIV, initKeyFunction, NULL,
		NULL, encryptFunction, decryptFunction, NULL, NULL,
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

int setDeviceCEI( DEVICE_INFO *deviceInfo )
	{
	/* Load the MiniCrypt driver DLL's if they aren't already loaded */
	if( hCEI == NULL_HINSTANCE )
		{
		deviceInitCEI();
		if( hCEI == NULL_HINSTANCE )
			return( CRYPT_DATA_OPEN );
		}

	deviceInfo->initDeviceFunction = initDeviceFunction;
	deviceInfo->shutdownDeviceFunction = shutdownDeviceFunction;
	deviceInfo->controlFunction = controlFunction;
	deviceInfo->findCapabilityFunction = findCapabilityFunction;
	deviceInfo->createContextFunction = createContextFunction;

	return( CRYPT_OK );
	}
