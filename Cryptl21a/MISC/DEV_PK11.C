/****************************************************************************
*																			*
*							cryptlib PKCS #11 Routines						*
*						Copyright Peter Gutmann 1998-1999					*
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

/* Before we can include the PKCS #11 headers we need to define a few OS-
   specific things which are required by the headers */

#ifdef __WINDOWS__
  #ifdef __WIN16__
	#pragma pack( 1 )					/* Struct packing */
	#define CK_PTR	far *				/* Pointer type */
	#define CK_DEFINE_FUNCTION( returnType, name ) \
								returnType __export _far _pascal name
	#define CK_DECLARE_FUNCTION( returnType, name ) \
								 returnType __export _far _pascal name
	#define CK_DECLARE_FUNCTION_POINTER( returnType, name ) \
								returnType __export _far _pascal (* name)
	#define CK_CALLBACK_FUNCTION( returnType, name ) \
								  returnType (_far _pascal * name)
  #else
	#pragma pack( push, cryptoki, 1 )	/* Struct packing */
	#define CK_PTR	*					/* Pointer type */
	#define CK_DEFINE_FUNCTION( returnType, name ) \
								returnType __declspec( dllexport ) name
	#define CK_DECLARE_FUNCTION( returnType, name ) \
								 returnType __declspec( dllimport ) name
	#define CK_DECLARE_FUNCTION_POINTER( returnType, name ) \
								returnType __declspec( dllimport ) (* name)
	#define CK_CALLBACK_FUNCTION( returnType, name ) \
								  returnType (* name)
  #endif /* Win16 vs Win32 */
#else
  #define CK_PTR	*					/* Pointer type */
  #define CK_DEFINE_FUNCTION( returnType, name ) \
							  returnType name
  #define CK_DECLARE_FUNCTION( returnType, name ) \
							   returnType name
  #define CK_DECLARE_FUNCTION_POINTER( returnType, name ) \
									   returnType (* name)
  #define CK_CALLBACK_FUNCTION( returnType, name ) \
								returnType (* name)
#endif /* __WINDOWS__ */
#ifndef NULL_PTR
  #define NULL_PTR	NULL
#endif /* NULL_PTR */

#if defined( INC_ALL ) || defined( INC_CHILD )
  #include "pkcs11.h"
#else
  #include "misc/pkcs11.h"
#endif /* Compiler-specific includes */

/* The max. number of drivers we can work with and the max.number of slots
   per driver */

#define MAX_PKCS11_DRIVERS		5
#define MAX_PKCS11_SLOTS		16

/* Occasionally we need to read things into host memory from a device, the
   following value defines the maximum size of the on-stack buffer, if the
   data is larger than this we dynamically allocate the buffer (this almost
   never occurs) */

#define MAX_BUFFER_SIZE			1024

/****************************************************************************
*																			*
*						 		Init/Shutdown Routines						*
*																			*
****************************************************************************/

#ifdef __WINDOWS__

/* Global function pointers.  These are necessary because the functions need
   to be dynamically linked since not all systems contain the necessary
   DLL's.  Explicitly linking to them will make cryptlib unloadable on most
   systems */

#define NULL_HINSTANCE	( HINSTANCE ) NULL

/* Since we can be using multiple PKCS #11 drivers, we define an array of
   them and access the appropriate one by its name */

typedef struct {
	char name[ 32 + 1 ];			/* Name of device */
	HINSTANCE hPKCS11;				/* Handle to driver */
	CK_C_CloseSession pC_CloseSession;	/* Interface function pointers */
	CK_C_CreateObject pC_CreateObject;
	CK_C_Decrypt pC_Decrypt;
	CK_C_DecryptInit pC_DecryptInit;
	CK_C_DestroyObject pC_DestroyObject;
	CK_C_Encrypt pC_Encrypt;
	CK_C_EncryptInit pC_EncryptInit;
	CK_C_Finalize pC_Finalize;
	CK_C_FindObjects pC_FindObjects;
	CK_C_FindObjectsFinal pC_FindObjectsFinal;
	CK_C_FindObjectsInit pC_FindObjectsInit;
	CK_C_GenerateKeyPair pC_GenerateKeyPair;
	CK_C_GenerateRandom pC_GenerateRandom;
	CK_C_GetAttributeValue pC_GetAttributeValue;
	CK_C_GetMechanismInfo pC_GetMechanismInfo;
	CK_C_GetSlotList pC_GetSlotList;
	CK_C_GetTokenInfo pC_GetTokenInfo;
	CK_C_InitToken pC_InitToken;
	CK_C_Login pC_Login;
	CK_C_Logout pC_Logout;
	CK_C_OpenSession pC_OpenSession;
	CK_C_SetPIN pC_SetPIN;
	CK_C_Sign pC_Sign;
	CK_C_SignInit pC_SignInit;
	CK_C_Verify pC_Verify;
	CK_C_VerifyInit pC_VerifyInit;
	} PKCS11_INFO;

static PKCS11_INFO pkcs11InfoTbl[ MAX_PKCS11_DRIVERS ];
static BOOLEAN pkcs11Initialised = FALSE;

/* The use of dynamically bound function pointers vs statically linked
   functions requires a bit of sleight of hand since we can't give the
   pointers the same names as prototyped functions.  To get around this we
   redefine the actual function names to the names of the pointers */

#define C_CloseSession		pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_CloseSession
#define C_CreateObject		pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_CreateObject
#define C_Decrypt			pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_Decrypt
#define C_DecryptInit		pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_DecryptInit
#define C_DestroyObject		pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_DestroyObject
#define C_Encrypt			pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_Encrypt
#define C_EncryptInit		pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_EncryptInit
#define C_Finalize			pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_Finalize
#define C_FindObjects		pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_FindObjects
#define C_FindObjectsFinal	pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_FindObjectsFinal
#define C_FindObjectsInit	pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_FindObjectsInit
#define C_GenerateKeyPair	pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_GenerateKeyPair
#define C_GenerateRandom	pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_GenerateRandom
#define C_GetAttributeValue	pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_GetAttributeValue
#define C_GetMechanismInfo	pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_GetMechanismInfo
#define C_GetSlotList		pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_GetSlotList
#define C_GetTokenInfo		pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_GetTokenInfo
#define C_Initialize		pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_Initialize
#define C_InitToken			pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_InitToken
#define C_Login				pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_Login
#define C_Logout			pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_Logout
#define C_OpenSession		pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_OpenSession
#define C_SetPIN			pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_SetPIN
#define C_Sign				pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_Sign
#define C_SignInit			pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_SignInit
#define C_Verify			pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_Verify
#define C_VerifyInit		pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_VerifyInit

/* Dynamically load and unload any necessary PKCS #11 drivers */

static int loadPKCS11driver( PKCS11_INFO *pkcs11Info,
							 const char *driverName )
	{
	CK_C_GetInfo pC_GetInfo;
	CK_C_Initialize pC_Initialize;
	CK_INFO info;
#ifdef __WIN16__
	UINT errorMode;
#endif /* __WIN16__ */

	/* Obtain a handle to the device driver module */
#ifdef __WIN16__
	errorMode = SetErrorMode( SEM_NOOPENFILEERRORBOX );
	pkcs11Info->hPKCS11 = LoadLibrary( driverName );
	SetErrorMode( errorMode );
	if( pkcs11Info->hPKCS11 < HINSTANCE_ERROR )
		{
		pkcs11Info->hPKCS11 = NULL_HINSTANCE;
		return( CRYPT_ERROR );
		}
#else
	if( ( pkcs11Info->hPKCS11 = LoadLibrary( driverName ) ) == NULL_HINSTANCE )
		return( CRYPT_ERROR );
#endif /* __WIN32__ */

	/* Now get pointers to the functions */
	pC_GetInfo = ( CK_C_GetInfo ) GetProcAddress( pkcs11Info->hPKCS11, "C_GetInfo" );
	pC_Initialize = ( CK_C_Initialize ) GetProcAddress( pkcs11Info->hPKCS11, "C_Initialize" );
	pkcs11Info->pC_CloseSession = ( CK_C_CloseSession ) GetProcAddress( pkcs11Info->hPKCS11, "C_CloseSession" );
	pkcs11Info->pC_CreateObject = ( CK_C_CreateObject ) GetProcAddress( pkcs11Info->hPKCS11, "C_CreateObject" );
	pkcs11Info->pC_Decrypt = ( CK_C_Decrypt ) GetProcAddress( pkcs11Info->hPKCS11, "C_Decrypt" );
	pkcs11Info->pC_DecryptInit = ( CK_C_DecryptInit ) GetProcAddress( pkcs11Info->hPKCS11, "C_DecryptInit" );
	pkcs11Info->pC_DestroyObject = ( CK_C_DestroyObject ) GetProcAddress( pkcs11Info->hPKCS11, "C_DestroyObject" );
	pkcs11Info->pC_Encrypt = ( CK_C_Encrypt ) GetProcAddress( pkcs11Info->hPKCS11, "C_Encrypt" );
	pkcs11Info->pC_EncryptInit = ( CK_C_EncryptInit ) GetProcAddress( pkcs11Info->hPKCS11, "C_EncryptInit" );
	pkcs11Info->pC_Finalize = ( CK_C_Finalize ) GetProcAddress( pkcs11Info->hPKCS11, "C_Finalize" );
	pkcs11Info->pC_FindObjects = ( CK_C_FindObjects ) GetProcAddress( pkcs11Info->hPKCS11, "C_FindObjects" );
	pkcs11Info->pC_FindObjectsFinal = ( CK_C_FindObjectsFinal ) GetProcAddress( pkcs11Info->hPKCS11, "C_FindObjectsFinal" );
	pkcs11Info->pC_FindObjectsInit = ( CK_C_FindObjectsInit ) GetProcAddress( pkcs11Info->hPKCS11, "C_FindObjectsInit" );
	pkcs11Info->pC_GenerateKeyPair = ( CK_C_GenerateKeyPair ) GetProcAddress( pkcs11Info->hPKCS11, "C_GenerateKeyPair" );
	pkcs11Info->pC_GenerateRandom = ( CK_C_GenerateRandom ) GetProcAddress( pkcs11Info->hPKCS11, "C_GenerateRandom" );
	pkcs11Info->pC_GetAttributeValue = ( CK_C_GetAttributeValue ) GetProcAddress( pkcs11Info->hPKCS11, "C_GetAttributeValue" );
	pkcs11Info->pC_GetMechanismInfo = ( CK_C_GetMechanismInfo ) GetProcAddress( pkcs11Info->hPKCS11, "C_GetMechanismInfo" );
	pkcs11Info->pC_GetSlotList = ( CK_C_GetSlotList ) GetProcAddress( pkcs11Info->hPKCS11, "C_GetSlotList" );
	pkcs11Info->pC_GetTokenInfo = ( CK_C_GetTokenInfo ) GetProcAddress( pkcs11Info->hPKCS11, "C_GetTokenInfo" );
	pkcs11Info->pC_InitToken = ( CK_C_InitToken ) GetProcAddress( pkcs11Info->hPKCS11, "C_InitToken" );
	pkcs11Info->pC_Login = ( CK_C_Login ) GetProcAddress( pkcs11Info->hPKCS11, "C_Login" );
	pkcs11Info->pC_Logout = ( CK_C_Logout ) GetProcAddress( pkcs11Info->hPKCS11, "C_Logout" );
	pkcs11Info->pC_OpenSession = ( CK_C_OpenSession ) GetProcAddress( pkcs11Info->hPKCS11, "C_OpenSession" );
	pkcs11Info->pC_SetPIN = ( CK_C_SetPIN ) GetProcAddress( pkcs11Info->hPKCS11, "C_SetPIN" );
	pkcs11Info->pC_Sign = ( CK_C_Sign ) GetProcAddress( pkcs11Info->hPKCS11, "C_Sign" );
	pkcs11Info->pC_SignInit = ( CK_C_SignInit ) GetProcAddress( pkcs11Info->hPKCS11, "C_SignInit" );
	pkcs11Info->pC_Verify = ( CK_C_Verify ) GetProcAddress( pkcs11Info->hPKCS11, "C_Verify" );
	pkcs11Info->pC_VerifyInit = ( CK_C_VerifyInit ) GetProcAddress( pkcs11Info->hPKCS11, "C_VerifyInit" );

	/* Make sure we got valid pointers for every device function */
	if( pC_GetInfo == NULL || pC_Initialize == NULL ||
		pkcs11Info->pC_CloseSession == NULL ||
		pkcs11Info->pC_CreateObject == NULL ||
		pkcs11Info->pC_Decrypt == NULL ||
		pkcs11Info->pC_DecryptInit == NULL ||
		pkcs11Info->pC_DestroyObject == NULL ||
		pkcs11Info->pC_Encrypt == NULL ||
		pkcs11Info->pC_EncryptInit == NULL ||
		pkcs11Info->pC_Finalize == NULL ||
		pkcs11Info->pC_FindObjects == NULL ||
		pkcs11Info->pC_FindObjectsFinal == NULL ||
		pkcs11Info->pC_FindObjectsInit == NULL ||
		pkcs11Info->pC_GenerateRandom == NULL ||
		pkcs11Info->pC_GenerateKeyPair == NULL ||
		pkcs11Info->pC_GetAttributeValue == NULL ||
		pkcs11Info->pC_GetMechanismInfo == NULL ||
		pkcs11Info->pC_GetSlotList == NULL ||
		pkcs11Info->pC_GetTokenInfo == NULL ||
		pkcs11Info->pC_InitToken == NULL || pkcs11Info->pC_Login == NULL ||
		pkcs11Info->pC_Logout == NULL || pkcs11Info->pC_OpenSession == NULL ||
		pkcs11Info->pC_SetPIN == NULL || pkcs11Info->pC_Sign == NULL ||
		pkcs11Info->pC_SignInit == NULL || pkcs11Info->pC_Verify == NULL ||
		pkcs11Info->pC_VerifyInit == NULL )
		{
		/* Free the library reference and clear the info */
		FreeLibrary( pkcs11Info->hPKCS11 );
		memset( pkcs11Info, 0, sizeof( PKCS11_INFO ) );
		return( CRYPT_ERROR );
		}

	/* Initialise the PKCS #11 library */
	if( pC_Initialize( NULL_PTR ) != CKR_OK )
		{
		/* Free the library reference and clear the info */
		FreeLibrary( pkcs11Info->hPKCS11 );
		memset( pkcs11Info, 0, sizeof( PKCS11_INFO ) );
		return( CRYPT_ERROR );
		}

	/* Get info on the device */
	if( pC_GetInfo( &info ) == CKR_OK )
		{
		int i = 32;

		/* Copy out the device drivers name so the user can access it by
		   name */
		memcpy( pkcs11Info->name, info.libraryDescription, 32 );
		while( pkcs11Info->name[ i ] == ' ' )
			i--;
		pkcs11Info->name[ i ] = '\0';
		}

	return( CRYPT_OK );
	}

void deviceInitPKCS11( void )
	{
	CRYPT_OPTION_TYPE option = CRYPT_OPTION_DEVICE_PKCS11_DVR01;
	int tblIndex = 0, optionIndex;

	/* If we've previously tried to init the drivers, don't try it again */
	if( pkcs11Initialised )
		return;
	memset( pkcs11InfoTbl, 0, sizeof( pkcs11InfoTbl ) );

	/* Try and link in each driver specified in the config options */
	for( optionIndex = 0; optionIndex < MAX_PKCS11_DRIVERS; optionIndex++ )
		{
		const char *deviceDriverName = getOptionString( option + optionIndex );

		if( deviceDriverName != NULL && \
			cryptStatusOK( loadPKCS11driver( &pkcs11InfoTbl[ tblIndex++ ], 
											 deviceDriverName ) ) )
			pkcs11Initialised = TRUE;
		}
	}

void deviceEndPKCS11( void )
	{
	int i;

	for( i = 0; i < MAX_PKCS11_DRIVERS; i++ )
		{
		if( pkcs11InfoTbl[ i ].hPKCS11 != NULL_HINSTANCE )
			{
			pkcs11InfoTbl[ i ].pC_Finalize( NULL_PTR );
			FreeLibrary( pkcs11InfoTbl[ i ].hPKCS11 );
			}
		pkcs11InfoTbl[ i ].hPKCS11 = NULL_HINSTANCE;
		}
	}
#endif /* __WINDOWS__ */

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* Map a PKCS #11-specific error to a cryptlib error */

static int mapError( DEVICE_INFO *deviceInfo, const CK_RV errorCode,
					 const int defaultError )
	{
	deviceInfo->errorCode = ( int ) errorCode;
	switch( ( int ) errorCode )
		{
		case CKR_OK:
			return( CRYPT_OK );
		case CKR_HOST_MEMORY:
		case CKR_DEVICE_MEMORY:
			return( CRYPT_NOMEM );
		case CKR_DEVICE_ERROR:
		case CKR_DEVICE_REMOVED:
			return( CRYPT_SIGNALLED );
		case CKR_PIN_INCORRECT:
		case CKR_PIN_INVALID:
		case CKR_PIN_LEN_RANGE:
			return( CRYPT_WRONGKEY );
		case CKR_SIGNATURE_INVALID:
			return( CRYPT_BADSIG );
		}

	return( defaultError );
	}

/****************************************************************************
*																			*
*					Device Init/Shutdown/Device Control Routines			*
*																			*
****************************************************************************/

/* Prototypes for functions to get and free device capability information */

static void freeCapabilities( DEVICE_INFO *deviceInfo );
static int getCapabilities( DEVICE_INFO *deviceInfo );
static int findCapabilityFunction( DEVICE_INFO *deviceInfo,
								   const void FAR_BSS **capabilityInfoPtrPtr,
								   const CRYPT_ALGO cryptAlgo,
								   const CRYPT_MODE cryptMode );

/* Prototypes for device-specific functions */

static int getRandomFunction( DEVICE_INFO *deviceInfo, void *buffer,
							  const int length );

/* Close a previously-opened session with the device.  We have to have this
   before the init function since it may be called by it if the init process
   fails */

static void shutdownDeviceFunction( DEVICE_INFO *deviceInfo )
	{
	/* Log out and close the session with the device */
	if( deviceInfo->loggedIn )
		{
		C_Logout( deviceInfo->deviceHandle );
		deviceInfo->loggedIn = FALSE;
		}
	C_CloseSession( deviceInfo->deviceHandle );
	deviceInfo->deviceHandle = CRYPT_ERROR;

	/* Free the device capability information */
	freeCapabilities( deviceInfo );
	}

/* Open a session with the device */

static int initDeviceFunction( DEVICE_INFO *deviceInfo )
	{
	CK_SESSION_HANDLE hSession;
	CK_SLOT_ID slotList[ MAX_PKCS11_SLOTS ];
	CK_ULONG slotCount = MAX_PKCS11_SLOTS;
	CK_TOKEN_INFO tokenInfo;
	CK_RV status;
	int cryptStatus;

	/* Get ID of the slot we're interacting with (for now we always use the
	   first slot we find) */
	status = C_GetSlotList( FALSE, slotList, &slotCount );
	if( status != CKR_OK )
		return( mapError( deviceInfo, status, CRYPT_DATA_OPEN ) );
	deviceInfo->slotHandle = slotList[ 0 ];

	/* Open a session with the device in the first slot */
	status = C_OpenSession( slotList[ 0 ], CKF_RW_SESSION | CKF_SERIAL_SESSION,
							NULL_PTR, NULL_PTR, &hSession );
	if( status != CKR_OK )
		return( mapError( deviceInfo, status, CRYPT_DATA_OPEN ) );
	deviceInfo->deviceHandle = hSession;

	/* Set up any device-specific capabilities */
	status = C_GetTokenInfo( deviceInfo->slotHandle, &tokenInfo );
	if( status != CKR_OK )
		{
		shutdownDeviceFunction( deviceInfo );
		return( mapError( deviceInfo, status, CRYPT_DATA_OPEN ) );
		}
	if( tokenInfo.flags & CKF_RNG )
		/* The device has an onboard RNG we can use */
		deviceInfo->getRandomFunction = getRandomFunction;
	if( tokenInfo.flags & CKF_WRITE_PROTECTED )
		/* The device can't have data on it changed */
		deviceInfo->readOnly = TRUE;
	deviceInfo->minPinSize = ( int ) tokenInfo.ulMinPinLen;
	deviceInfo->maxPinSize = ( int ) tokenInfo.ulMaxPinLen;

	/* Set up the capability information for this device */
	cryptStatus = getCapabilities( deviceInfo );
	if( cryptStatusError( cryptStatus ) )
		{
		shutdownDeviceFunction( deviceInfo );
		return( ( cryptStatus == CRYPT_ERROR ) ? \
				CRYPT_DATA_OPEN : ( int ) cryptStatus );
		}

	return( CRYPT_OK );
	}

/* Handle device control functions */

static int controlFunction( DEVICE_INFO *deviceInfo,
							const CRYPT_DEVICECONTROL_TYPE type,
							const void *data1, const int data1Length,
							const void *data2, const int data2Length )
	{
	CK_RV status;

	/* Handle user authorisation */
	if( type == CRYPT_DEVICECONTROL_AUTH_USER || \
		type == CRYPT_DEVICECONTROL_AUTH_SUPERVISOR )
		{
		/* If the user is already logged in, log them out before we try
		   logging in with a new authentication value */
		if( deviceInfo->loggedIn )
			{
			C_Logout( deviceInfo->deviceHandle );
			deviceInfo->loggedIn = FALSE;
			}

		/* Authenticate the user to the device */
		status = C_Login( deviceInfo->deviceHandle,
						  ( type == CRYPT_DEVICECONTROL_AUTH_USER ) ? \
						  CKU_USER : CKU_SO, ( CK_CHAR_PTR ) data1,
						  ( CK_ULONG ) data1Length );
		if( status == CKR_OK )
			deviceInfo->loggedIn = TRUE;
		return( mapError( deviceInfo, status, CRYPT_ERROR ) );
		}

	/* Handle authorisation value change */
	if( type == CRYPT_DEVICECONTROL_SET_AUTH_USER || \
		type == CRYPT_DEVICECONTROL_SET_AUTH_SUPERVISOR )
		{
		status = C_SetPIN( deviceInfo->deviceHandle, ( CK_CHAR_PTR ) data1,
						   ( CK_ULONG ) data1Length, ( CK_CHAR_PTR ) data2,
						   ( CK_ULONG ) data2Length );
		return( mapError( deviceInfo, status, CRYPT_ERROR ) );
		}

	/* Handle initialisation and zeroisation */
	if( type == CRYPT_DEVICECONTROL_INITIALISE || \
		type == CRYPT_DEVICECONTROL_ZEROISE )
		{
		CK_SESSION_HANDLE hSession;
		CK_CHAR label[ 32 ];

		/* If there's a session active with the device, log out and terminate
		   the session, since the token init will reset this */
		C_Logout( deviceInfo->deviceHandle );
		C_CloseSession( deviceInfo->deviceHandle );
		deviceInfo->deviceHandle = CRYPT_ERROR;

		/* Initialise/clear the device */
		memset( label, ' ', 32 );
		status = C_InitToken( 0, ( CK_CHAR_PTR ) data1,
							  ( CK_ULONG ) data1Length, label );
		if( status != CKR_OK )
			return( mapError( deviceInfo, status, CRYPT_ERROR ) );

		/* Reopen the session with the device */
		status = C_OpenSession( deviceInfo->slotHandle,
								CKF_RW_SESSION | CKF_SERIAL_SESSION,
								NULL_PTR, NULL_PTR, &hSession );
		if( status != CKR_OK )
			return( mapError( deviceInfo, status, CRYPT_DATA_OPEN ) );
		deviceInfo->deviceHandle = hSession;

		/* If it's a straight zeroise, we're done */
		if( type == CRYPT_DEVICECONTROL_ZEROISE )
			return( CRYPT_OK );

		/* If we're initialising it, log in as supervisor */
		status = C_Login( deviceInfo->deviceHandle, CKU_SO,
						  ( CK_CHAR_PTR ) data1, ( CK_ULONG ) data1Length );
		if( status == CKR_OK )
			deviceInfo->loggedIn = TRUE;
		return( mapError( deviceInfo, status, CRYPT_ERROR ) );
		}

	/* Anything else isn't handled */
	return( CRYPT_BADPARM2 );
	}

/****************************************************************************
*																			*
*						 	Misc.Device Interface Routines					*
*																			*
****************************************************************************/

/* Get random data from the device */

static int getRandomFunction( DEVICE_INFO *deviceInfo, void *buffer,
							  const int length )
	{
	CK_RV status;

	status = C_GenerateRandom( deviceInfo->deviceHandle, buffer, length );
	return( mapError( deviceInfo, status, CRYPT_ERROR ) );
	}

/* Instantiate an object by name.  This works like the create context
   function but instantiates a cryptlib object using data already contained
   in the device (for example a stored private key or certificate).  If the
   value being read is a public key and there's a certificate attached, the
   instantiated object is a native cryptlib object rather than a device
   object with a native certificate object attached, the reason for this is
   that there doesn't appear to be any good reason to create the public-key
   object in the device, and for most devices the cryptlib native object will
   be faster anyway */

static int findObject( DEVICE_INFO *deviceInfo, CK_OBJECT_HANDLE *hObject,
					   const CK_ATTRIBUTE *template,
					   const CK_ULONG templateCount )
	{
	CK_ULONG ulObjectCount;
	CK_RV status;

	status = C_FindObjectsInit( deviceInfo->deviceHandle,
								( CK_ATTRIBUTE_PTR ) template,
								templateCount );
	if( status == CKR_OK )
		{
		status = C_FindObjects( deviceInfo->deviceHandle, hObject, 1,
								&ulObjectCount );
		C_FindObjectsFinal( deviceInfo->deviceHandle );
		}
	if( status != CKR_OK )
		return( mapError( deviceInfo, status, CRYPT_DATA_NOTFOUND ) );
	if( !ulObjectCount )
		return( CRYPT_DATA_NOTFOUND );

	return( CRYPT_OK );
	}

static int findCertificate( DEVICE_INFO *deviceInfo,
							CRYPT_CERTIFICATE *iCryptCert,
							const CK_OBJECT_HANDLE hObject )
	{
	static const CK_OBJECT_CLASS class = CKO_CERTIFICATE;
	static const CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_ATTRIBUTE certTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &class, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_CERTIFICATE_TYPE, ( CK_VOID_PTR ) &certType, sizeof( CK_CERTIFICATE_TYPE ) },
		{ CKA_ID, NULL, 0 }
		};
	CK_ATTRIBUTE idTemplate[] = {
		{ CKA_ID, NULL_PTR, 0 }
		};
	CK_ATTRIBUTE dataTemplate[] = {
		{ CKA_VALUE, NULL_PTR, 0 }
		};
	CK_OBJECT_HANDLE hCertificate;
	CK_RV status;
	BYTE buffer[ MAX_BUFFER_SIZE ], *bufPtr = buffer;
	int cryptStatus;

	/* Read the key ID from the device */
	status = C_GetAttributeValue( deviceInfo->deviceHandle, hObject,
								  idTemplate, 1 );
	if( status == CKR_OK )
		{
		if( idTemplate[ 0 ].ulValueLen > MAX_BUFFER_SIZE && \
			( bufPtr = malloc( ( size_t ) ( idTemplate[ 0 ].ulValueLen ) ) ) == NULL )
			return( CRYPT_NOMEM );
		idTemplate[ 0 ].pValue = bufPtr;
		status = C_GetAttributeValue( deviceInfo->deviceHandle, hObject,
									  idTemplate, 1 );
		}
	if( status != CKR_OK )
		{
		if( bufPtr != buffer )
			free( bufPtr );
		return( mapError( deviceInfo, status, CRYPT_DATA_NOTFOUND ) );
		}

	/* Look for a certificate with the same ID as the key */
	certTemplate[ 2 ].pValue = bufPtr;
	certTemplate[ 2 ].ulValueLen = idTemplate[ 0 ].ulValueLen;
	cryptStatus = findObject( deviceInfo, &hCertificate, certTemplate, 3 );
	if( bufPtr != buffer )
		free( bufPtr );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );

	/* We found a matching cert, fetch it into local memory */
	status = C_GetAttributeValue( deviceInfo->deviceHandle, hObject,
								  dataTemplate, 1 );
	if( status == CKR_OK )
		{
		if( dataTemplate[ 0 ].ulValueLen > MAX_BUFFER_SIZE && \
			( bufPtr = malloc( ( size_t ) ( dataTemplate[ 0 ].ulValueLen ) ) ) == NULL )
			return( CRYPT_NOMEM );
		dataTemplate[ 0 ].pValue = bufPtr;
		status = C_GetAttributeValue( deviceInfo->deviceHandle, hObject,
									  dataTemplate, 1 );
		}
	if( status != CKR_OK )
		{
		if( bufPtr != buffer )
			free( bufPtr );
		return( mapError( deviceInfo, status, CRYPT_DATA_NOTFOUND ) );
		}

	/* Import the cert as a cryptlib object */
	cryptStatus = iCryptImportCert( buffer, iCryptCert, NULL );
	if( bufPtr != buffer )
		free( bufPtr );

	return( cryptStatus );
	}

static int instantiateNamedObjectFunction( DEVICE_INFO *deviceInfo,
										   CRYPT_CONTEXT *cryptContext,
										   const char *name,
										   const BOOLEAN isPublicKey )
	{
	static const CK_OBJECT_CLASS pubkeyClass = CKO_PUBLIC_KEY;
	static const CK_OBJECT_CLASS privkeyClass = CKO_PRIVATE_KEY;
	const CAPABILITY_INFO *capabilityInfoPtr;
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, NULL, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_LABEL, NULL, 0 },
		};
	CK_ATTRIBUTE keyTypeTemplate[] = {
		{ CKA_KEY_TYPE, NULL, sizeof( CK_KEY_TYPE ) }
		};
	CK_OBJECT_HANDLE hObject;
	CK_KEY_TYPE keyType;
	CRYPT_ALGO cryptAlgo;
	const int templateCount = ( name == NULL ) ? 1 : 2;
	int status;

	/* Try and find the object with the given ID, or the first object of the
	   given class if no ID is given */
	keyTemplate[ 0 ].pValue = ( CK_VOID_PTR ) ( isPublicKey ? \
							  &pubkeyClass : &privkeyClass );
	if( name != NULL )
		{
		keyTemplate[ 1 ].pValue = ( CK_VOID_PTR ) name;
		keyTemplate[ 1 ].ulValueLen = strlen( name );
		}
	status = findObject( deviceInfo, &hObject, keyTemplate, templateCount );
	if( cryptStatusError( status ) )
		return( status );

	/* We found something, map the key type to a cryptlib algorithm ID and
	   find its capabilities */
	keyTypeTemplate[ 0 ].pValue = &keyType;
	C_GetAttributeValue( deviceInfo->deviceHandle, hObject, keyTypeTemplate, 1 );
	switch( ( int ) keyType )
		{
		case CKK_RSA:
			cryptAlgo = CRYPT_ALGO_RSA;
			break;
		case CKK_DSA:
			cryptAlgo = CRYPT_ALGO_DSA;
			break;
		case CKK_DH:
			cryptAlgo = CRYPT_ALGO_DH;
			break;
		default:
			return( CRYPT_NOALGO );
		}
	status = findCapabilityFunction( deviceInfo,
				( const void ** ) &capabilityInfoPtr, cryptAlgo, CRYPT_MODE_PKC );
	if( cryptStatusError( status ) )
		return( status );

	/* Quick hack to get rid of unused functions/params warning */
	status = findCertificate( deviceInfo, cryptContext, hObject );

#if 0
	if pub key
		if cert
			create native cert (+key) object
		else
			create device pubkey object, mark as "key loaded"
	else
		create device privkey object, mark as "key loaded"
		if cert
			create native data-only cert object (this will require some
												 changes in the cert code)
			attach cert object to key

	/* Create the context and remember the device it's contained in */
	status = createContext( cryptContext, capabilityInfoPtr, NULL, 0 );
	if( cryptStatusError( status ) )
		return( status );
	krnlSendMessage( *cryptContext, RESOURCE_MESSAGE_SETDATA,
					 &deviceInfo->objectHandle, RESOURCE_MESSAGE_DATA_DEVICE,
					 0 );
#endif
	return( status );
	}

/****************************************************************************
*																			*
*						 	Capability Interface Routines					*
*																			*
****************************************************************************/

/* Sign data, check a signature */

static int genericSign( DEVICE_INFO *deviceInfo, CRYPT_INFO *cryptInfo,
						const CK_MECHANISM *pMechanism, void *buffer,
						const int length )
	{
	CK_ULONG resultLen;
	CK_RV status;

	status = C_SignInit( deviceInfo->deviceHandle,
						 ( CK_MECHANISM_PTR ) pMechanism,
						 cryptInfo->iCryptDeviceHandle );
	if( status == CKR_OK )
		status = C_Sign( deviceInfo->deviceHandle, buffer, length,
						 buffer, &resultLen );
	if( status != CKR_OK )
		return( mapError( deviceInfo, status, CRYPT_PKCCRYPT ) );

	return( ( int ) resultLen );
	}

static int genericVerify( DEVICE_INFO *deviceInfo, CRYPT_INFO *cryptInfo,
						  const CK_MECHANISM *pMechanism, void *buffer,
						  const int length )
	{
	CK_RV status;

	status = C_VerifyInit( deviceInfo->deviceHandle,
						   ( CK_MECHANISM_PTR ) pMechanism,
						   cryptInfo->iCryptDeviceHandle );
	if( status == CKR_OK )
		status = C_Verify( deviceInfo->deviceHandle, buffer, length,
						   buffer, length );
	if( status != CKR_OK )
		return( mapError( deviceInfo, status, CRYPT_PKCCRYPT ) );

	return( CRYPT_OK );
	}

/* Public-key encrypt, decrypt */

static int genericEncrypt( DEVICE_INFO *deviceInfo, CRYPT_INFO *cryptInfo,
						   const CK_MECHANISM *pMechanism, void *buffer,
						   const int length )
	{
	CK_ULONG resultLen;
	CK_RV status;

	status = C_EncryptInit( deviceInfo->deviceHandle,
							( CK_MECHANISM_PTR ) pMechanism,
							cryptInfo->iCryptDeviceHandle );
	if( status == CKR_OK )
		status = C_Encrypt( deviceInfo->deviceHandle, buffer, length,
							buffer, &resultLen );
	if( status != CKR_OK )
		return( mapError( deviceInfo, status, CRYPT_PKCCRYPT ) );

	return( ( int ) resultLen );
	}

static int genericDecrypt( DEVICE_INFO *deviceInfo, CRYPT_INFO *cryptInfo,
						   const CK_MECHANISM *pMechanism, void *buffer,
						   const int length )
	{
	CK_ULONG resultLen;
	CK_RV status;

	status = C_DecryptInit( deviceInfo->deviceHandle,
							( CK_MECHANISM_PTR ) pMechanism,
							cryptInfo->iCryptDeviceHandle );
	if( status == CKR_OK )
		status = C_Decrypt( deviceInfo->deviceHandle, buffer, length,
							buffer, &resultLen );
	if( status != CKR_OK )
		return( mapError( deviceInfo, status, CRYPT_PKCCRYPT ) );

	return( ( int ) resultLen );
	}

/* Clean up the object associated with a context */

static int genericEndFunction( CRYPT_INFO *cryptInfoPtr )
	{
	DEVICE_INFO *deviceInfo;

	/* For now we always destroy the created object to allow the storage to
	   be recycled, in reality we should only destroy ephemeral objects */
	getCheckInternalResource( cryptInfoPtr->iCryptDevice, deviceInfo,
							  RESOURCE_TYPE_DEVICE );
	C_DestroyObject( deviceInfo->deviceHandle,
					 cryptInfoPtr->iCryptDeviceHandle );
	unlockResourceExit( deviceInfo, CRYPT_OK );
	}

/* RSA algorithm-specific mapping functions.  We always use the X.509 (raw)
   mechanism for the encrypt/decrypt/sign/verify functions since cryptlib
   does its own padding, and it means we can support any new padding method
   regardless of what the underlying implementation supports */

static int rsaInitKey( CRYPT_INFO *cryptInfoPtr, const void *key, const int keyLength )
	{
	static const CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
	static const CK_KEY_TYPE type = CKK_RSA;
	static const CK_BBOOL bTrue = TRUE;
	CK_ATTRIBUTE template[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &class, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_KEY_TYPE, ( CK_VOID_PTR ) &type, sizeof( CK_KEY_TYPE ) },
		{ CKA_TOKEN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_PRIVATE, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_SIGN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_MODULUS, NULL, 0 },
		{ CKA_PUBLIC_EXPONENT, NULL, 0 },
		{ CKA_PRIVATE_EXPONENT, NULL, 0 },
		{ CKA_PRIME_1, NULL, 0 },
		{ CKA_PRIME_2, NULL, 0 },
		{ CKA_EXPONENT_1, NULL, 0 },
		{ CKA_EXPONENT_2, NULL, 0 },
		{ CKA_COEFFICIENT, NULL, 0 },
		};
	CRYPT_PKCINFO_RSA *rsaKey = ( CRYPT_PKCINFO_RSA * ) key;
	DEVICE_INFO *deviceInfo;
	CK_OBJECT_HANDLE hObject;
	CK_RV status;
	int cryptStatus;

	if( keyLength );	/* Get rid of compiler warning */

	getCheckInternalResource( cryptInfoPtr->iCryptDevice, deviceInfo,
							  RESOURCE_TYPE_DEVICE );
	if( deviceInfo->readOnly )
		unlockResourceExit( deviceInfo, CRYPT_NOPERM );

	/* Set up the key values */
	template[ 5 ].pValue = rsaKey->n;
	template[ 5 ].ulValueLen = bitsToBytes( rsaKey->nLen );
	template[ 6 ].pValue = rsaKey->e;
	template[ 6 ].ulValueLen = bitsToBytes( rsaKey->eLen );
	template[ 7 ].pValue = rsaKey->d;
	template[ 7 ].ulValueLen = bitsToBytes( rsaKey->dLen );
	template[ 8 ].pValue = rsaKey->p;
	template[ 8 ].ulValueLen = bitsToBytes( rsaKey->pLen );
	template[ 9 ].pValue = rsaKey->q;
	template[ 9 ].ulValueLen = bitsToBytes( rsaKey->qLen );
	template[ 10 ].pValue = rsaKey->e1;
	template[ 10 ].ulValueLen = bitsToBytes( rsaKey->e1Len );
	template[ 11 ].pValue = rsaKey->e2;
	template[ 11 ].ulValueLen = bitsToBytes( rsaKey->e2Len );
	template[ 12 ].pValue = rsaKey->u;
	template[ 12 ].ulValueLen = bitsToBytes( rsaKey->uLen );

	/* Load the key into the token */
	status = C_CreateObject( deviceInfo->deviceHandle,
							 ( CK_ATTRIBUTE_PTR ) template, 12, &hObject );
	cryptStatus = mapError( deviceInfo, status, CRYPT_PKCCRYPT );
	if( cryptStatusOK( status ) )
		cryptInfoPtr->iCryptDeviceHandle = hObject;
	zeroise( template, sizeof( CK_ATTRIBUTE ) * 12 );

	unlockResourceExit( deviceInfo, cryptStatus );
	}

static int rsaGenerateKey( CRYPT_INFO *cryptInfoPtr, const int keysizeBits )
	{
	static const CK_BBOOL bTrue = TRUE;
	static const CK_ATTRIBUTE privateKeyTemplate[] = {
		{ CKA_TOKEN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_PRIVATE, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_SENSITIVE, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_DECRYPT, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_SIGN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_UNWRAP, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) }
		};
	static const CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
	const CK_ULONG modulusBits = keysizeBits;
	CK_ATTRIBUTE publicKeyTemplate[] = {
		{ CKA_TOKEN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_ENCRYPT, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_VERIFY, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_WRAP, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_MODULUS_BITS, NULL, sizeof( CK_ULONG ) }
		};
	CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
	DEVICE_INFO *deviceInfo;
	CK_RV status;
	int cryptStatus;

	getCheckInternalResource( cryptInfoPtr->iCryptDevice, deviceInfo,
							  RESOURCE_TYPE_DEVICE );
	if( deviceInfo->readOnly )
		unlockResourceExit( deviceInfo, CRYPT_NOPERM );

	/* Patch in the key size and generate the keys */
	publicKeyTemplate[ 5 ].pValue = ( CK_VOID_PTR ) &modulusBits;
	status = C_GenerateKeyPair( deviceInfo->deviceHandle,
								( CK_MECHANISM_PTR ) &mechanism,
								( CK_ATTRIBUTE_PTR ) publicKeyTemplate, 5,
								( CK_ATTRIBUTE_PTR ) privateKeyTemplate, 6,
								&hPublicKey, &hPrivateKey );
	cryptStatus = mapError( deviceInfo, status, CRYPT_PKCCRYPT );
	if( cryptStatusOK( status ) )
		cryptInfoPtr->iCryptDeviceHandle = hPrivateKey;

	unlockResourceExit( deviceInfo, cryptStatus );
	}

static int rsaSign( CRYPT_INFO *cryptInfo, void *buffer, int length )
	{
	static const CK_MECHANISM mechanism = { CKM_RSA_X_509, NULL_PTR, 0 };
	DEVICE_INFO *deviceInfo;
	int status;

	getCheckInternalResource( cryptInfo->iCryptDevice, deviceInfo,
							  RESOURCE_TYPE_DEVICE );
	status = genericSign( deviceInfo, cryptInfo, &mechanism, buffer, length );
	unlockResourceExit( deviceInfo, status );
	}

static int rsaVerify( CRYPT_INFO *cryptInfo, void *buffer, int length )
	{
	static const CK_MECHANISM mechanism = { CKM_RSA_X_509, NULL_PTR, 0 };
	DEVICE_INFO *deviceInfo;
	int status;

	getCheckInternalResource( cryptInfo->iCryptDevice, deviceInfo,
							  RESOURCE_TYPE_DEVICE );
	status = genericVerify( deviceInfo, cryptInfo, &mechanism, buffer,
							length );
	unlockResourceExit( deviceInfo, status );
	}

static int rsaEncrypt( CRYPT_INFO *cryptInfo, void *buffer, int length )
	{
	static const CK_MECHANISM mechanism = { CKM_RSA_X_509, NULL_PTR, 0 };
	DEVICE_INFO *deviceInfo;
	int status;

	getCheckInternalResource( cryptInfo->iCryptDevice, deviceInfo,
							  RESOURCE_TYPE_DEVICE );
	status = genericEncrypt( deviceInfo, cryptInfo, &mechanism, buffer,
							 length );
	unlockResourceExit( deviceInfo, status );
	}

static int rsaDecrypt( CRYPT_INFO *cryptInfo, void *buffer, int length )
	{
	static const CK_MECHANISM mechanism = { CKM_RSA_X_509, NULL_PTR, 0 };
	DEVICE_INFO *deviceInfo;
	int status;

	getCheckInternalResource( cryptInfo->iCryptDevice, deviceInfo,
							  RESOURCE_TYPE_DEVICE );
	status = genericDecrypt( deviceInfo, cryptInfo, &mechanism, buffer,
							 length );
	unlockResourceExit( deviceInfo, status );
	}

/****************************************************************************
*																			*
*						 	Device Capability Routines						*
*																			*
****************************************************************************/

/* The reported key size for PKCS #11 implementations is rather inconsistent,
   most are reported in bits, a number don't return a useful value, and a few
   are reported in bytes.  The following macros sort out which algorithms
   have valid key size info and which report the length in bytes */

#define keysizeValid( algo ) \
	( ( algo ) == CRYPT_ALGO_RSA || ( algo ) == CRYPT_ALGO_RC2 || \
	  ( algo ) == CRYPT_ALGO_RC4 || ( algo ) == CRYPT_ALGO_RC5 )
#define keysizeBytes( algo ) \
	( ( algo ) == CRYPT_ALGO_RC2 )

/* Since cryptlib's CAPABILITY_INFO is fixed, all the fields are declared
   const so they'll probably be allocated in the code segment.  This doesn't
   quite work for PKCS #11 devices since things like the available key
   lengths can vary depending on the device which is plugged in, so we
   declare an equivalent structure here which makes the variable fields non-
   const.  Once the fields are set up, the result is copied into a
   dynamically-allocated CAPABILITY_INFO block at which point the fields are
   treated as const by the code */

typedef struct {
	const CRYPT_ALGO cryptAlgo;
	const CRYPT_MODE cryptMode;
	const int blockSize;
	const char *algoName;
	const char *modeName;
	int minKeySize;					/* Non-const */
	int keySize;					/* Non-const */
	int maxKeySize;					/* Non-const */
	const int minIVsize;
	const int ivSize;
	const int maxIVsize;
	int ( *selfTestFunction )( void );
	int ( *initFunction )( struct CI *cryptInfoPtr, const void *cryptInfoEx );
	int ( *endFunction )( struct CI *cryptInfoPtr );
	int ( *initIVFunction )( struct CI *cryptInfoPtr, const void *iv, const int ivLength );
	int ( *initKeyFunction )( struct CI *cryptInfoPtr, const void *key, const int keyLength );
	int ( *generateKeyFunction )( struct CI *cryptInfoPtr, const int keySizeBits );
	int ( *getKeysizeFunction )( struct CI *cryptInfoPtr );
	int ( *encryptFunction )( struct CI *cryptInfoPtr, void *buffer, int length );
	int ( *decryptFunction )( struct CI *cryptInfoPtr, void *buffer, int length );
	int ( *signFunction )( struct CI *cryptInfoPtr, void *buffer, int length );
	int ( *sigCheckFunction )( struct CI *cryptInfoPtr, void *buffer, int length );
	int selfTestStatus;
	struct CA *next;
	} VARIABLE_CAPABILITY_INFO;

/* Templates for the various capabilities.  These only contain the basic
   information, the remaining fields are filled in when the capability is set
   up */

#define bits(x)	bitsToBytes(x)

static CAPABILITY_INFO FAR_BSS capabilityTemplates[] = {
	/* Encryption capabilities */
	{ CRYPT_ALGO_DES, CRYPT_MODE_ECB, bits( 64 ), "DES", "ECB",
		bits( 40 ), bits( 64 ), bits( 64 ),
		bits( 0 ), bits( 0 ), bits( 0  ) },
	{ CRYPT_ALGO_DES, CRYPT_MODE_CBC, bits( 64 ), "DES", "CBC",
		bits( 40 ), bits( 64 ), bits( 64 ),
		bits( 32 ), bits( 64 ), bits( 64 ) },
	{ CRYPT_ALGO_3DES, CRYPT_MODE_ECB, bits( 64 ), "3DES", "ECB",
		bits( 64 + 8 ), bits( 128 ), bits( 192 ),
		bits( 0 ), bits( 0 ), bits( 0  ) },
	{ CRYPT_ALGO_3DES, CRYPT_MODE_CBC, bits( 64 ), "3DES", "CBC",
		bits( 64 + 8 ), bits( 128 ), bits( 192 ),
		bits( 32 ), bits( 64 ), bits( 64 ) },
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_ECB, bits( 64 ), "IDEA", "ECB",
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 0 ), bits( 0 ), bits( 0 ) },
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_CBC, bits( 64 ), "IDEA", "CBC",
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 32 ), bits( 64 ), bits( 64 ) },
	{ CRYPT_ALGO_CAST, CRYPT_MODE_ECB, bits( 64 ), "CAST-128", "ECB",
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 0 ), bits( 0 ), bits( 0 ) },
	{ CRYPT_ALGO_CAST, CRYPT_MODE_CBC, bits( 64 ), "CAST-128", "CBC",
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 32 ), bits( 64 ), bits( 64 ) },
	{ CRYPT_ALGO_RC2, CRYPT_MODE_ECB, bits( 64 ), "RC2", "ECB",
		bits( 40 ), bits( 128 ), bits( 1024 ),
		bits( 0 ), bits( 0 ), bits( 0 ) },
	{ CRYPT_ALGO_RC2, CRYPT_MODE_CBC, bits( 64 ), "RC2", "CBC",
		bits( 40 ), bits( 128 ), bits( 1024 ),
		bits( 32 ), bits( 64 ), bits( 64 ) },
	{ CRYPT_ALGO_RC4, CRYPT_MODE_STREAM, bits( 8 ), "RC4", "Stream",
		bits( 40 ), bits( 128 ), 256,
		bits( 0 ), bits( 0 ), bits( 0 ) },
	{ CRYPT_ALGO_RC5, CRYPT_MODE_ECB, bits( 64 ), "RC5", "ECB",
		bits( 40 ), bits( 128 ), bits( 832 ),
		bits( 0 ), bits( 0 ), bits( 0 ) },
	{ CRYPT_ALGO_RC5, CRYPT_MODE_CBC, bits( 64 ), "RC5", "CBC",
		bits( 40 ), bits( 128 ), bits( 832 ),
		bits( 32 ), bits( 64 ), bits( 64 ) },
	{ CRYPT_ALGO_SKIPJACK, CRYPT_MODE_ECB, bits( 64 ), "Skipjack", "ECB",
		bits( 80 ), bits( 80 ), bits( 80 ),
		bits( 0 ), bits( 0 ), bits( 0 ) },
	{ CRYPT_ALGO_SKIPJACK, CRYPT_MODE_CBC, bits( 64 ), "Skipjack", "CBC",
		bits( 80 ), bits( 80 ), bits( 80 ),
		bits( 32 ), bits( 64 ), bits( 64 ) },
	{ CRYPT_ALGO_SKIPJACK, CRYPT_MODE_CFB, bits( 8 ), "Skipjack", "CFB",
		bits( 80 ), bits( 80 ), bits( 80 ),
		bits( 32 ), bits( 64 ), bits( 64 ) },
	{ CRYPT_ALGO_SKIPJACK, CRYPT_MODE_OFB, bits( 8 ), "Skipjack", "OFB",
		bits( 80 ), bits( 80 ), bits( 80 ),
		bits( 32 ), bits( 64 ), bits( 64 ) },

	/* Hash capabilities */
	{ CRYPT_ALGO_MD2, CRYPT_MODE_NONE, bits( 128 ), "MD2", "Hash algorithm",
		bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ) },
	{ CRYPT_ALGO_MD5, CRYPT_MODE_NONE, bits( 128 ), "MD5", "Hash algorithm",
		bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ) },
	{ CRYPT_ALGO_SHA, CRYPT_MODE_NONE, bits( 160 ), "SHA", "Hash algorithm",
		bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ) },

	/* Public-key capabilities */
	{ CRYPT_ALGO_RSA, CRYPT_MODE_PKC, bits( 0 ), "RSA",
		"Public-key algorithm",
		bits( 512 ), bits( 1024 ), CRYPT_MAX_PKCSIZE,
		bits( 0 ), bits( 0 ), bits( 0 ) },
	{ CRYPT_ALGO_DSA, CRYPT_MODE_PKC, bits( 0 ), "DSA",
		"Public-key algorithm",
		bits( 512 ), bits( 1024 ), CRYPT_MAX_PKCSIZE,
		bits( 0 ), bits( 0 ), bits( 0 ) }
	};

/* Mapping of PKCS #11 device capabilities to cryptlib capabilities */

typedef struct {
	/* Mapping information */
	CK_MECHANISM_TYPE mechanism;	/* PKCS #11 mechanism type */
	CRYPT_ALGO cryptAlgo;			/* cryptlib algo and mode */
	CRYPT_MODE cryptMode;

	/* Function pointers */
	int ( *initKeyFunction )( CRYPT_INFO *cryptInfoPtr, const void *key, const int keyLength );
	int ( *generateKeyFunction )( CRYPT_INFO *cryptInfoPtr, const int keySizeBits );
	int ( *encryptFunction )( CRYPT_INFO *cryptInfoPtr, void *buffer, int length );
	int ( *decryptFunction )( CRYPT_INFO *cryptInfoPtr, void *buffer, int length );
	int ( *signFunction )( CRYPT_INFO *cryptInfoPtr, void *buffer, int length );
	int ( *sigCheckFunction )( CRYPT_INFO *cryptInfoPtr, void *buffer, int length );
	} MECHANISM_INFO;

static const MECHANISM_INFO mechanismInfo[] = {
	{ CKM_RSA_PKCS, CRYPT_ALGO_RSA, CRYPT_MODE_PKC,
	  rsaInitKey, rsaGenerateKey, rsaEncrypt, rsaDecrypt, rsaSign, rsaVerify },
	{ CKM_DES_ECB, CRYPT_ALGO_DES, CRYPT_MODE_ECB, NULL, NULL, NULL, NULL },
	{ CKM_DES_CBC, CRYPT_ALGO_DES, CRYPT_MODE_CBC, NULL, NULL, NULL, NULL },
	{ CKM_DES3_ECB, CRYPT_ALGO_3DES, CRYPT_MODE_ECB, NULL, NULL, NULL, NULL },
	{ CKM_DES3_CBC, CRYPT_ALGO_3DES, CRYPT_MODE_CBC, NULL, NULL, NULL, NULL },
	{ CKM_IDEA_ECB, CRYPT_ALGO_IDEA, CRYPT_MODE_ECB, NULL, NULL, NULL, NULL },
	{ CKM_IDEA_CBC, CRYPT_ALGO_IDEA, CRYPT_MODE_CBC, NULL, NULL, NULL, NULL },
	{ CKM_CAST5_ECB, CRYPT_ALGO_CAST, CRYPT_MODE_ECB, NULL, NULL, NULL, NULL },
	{ CKM_CAST5_CBC, CRYPT_ALGO_CAST, CRYPT_MODE_CBC, NULL, NULL, NULL, NULL },
	{ CKM_RC2_ECB, CRYPT_ALGO_RC2, CRYPT_MODE_ECB, NULL, NULL, NULL, NULL },
	{ CKM_RC2_CBC, CRYPT_ALGO_RC2, CRYPT_MODE_CBC, NULL, NULL, NULL, NULL },
	{ CKM_RC4, CRYPT_ALGO_RC4, CRYPT_MODE_STREAM, NULL, NULL, NULL, NULL },
	{ CKM_RC5_ECB, CRYPT_ALGO_RC5, CRYPT_MODE_ECB, NULL, NULL, NULL, NULL },
	{ CKM_RC5_CBC, CRYPT_ALGO_RC5, CRYPT_MODE_CBC, NULL, NULL, NULL, NULL },
	{ CKM_SKIPJACK_ECB64, CRYPT_ALGO_SKIPJACK, CRYPT_MODE_ECB, NULL, NULL, NULL, NULL },
	{ CKM_SKIPJACK_CBC64, CRYPT_ALGO_SKIPJACK, CRYPT_MODE_CBC, NULL, NULL, NULL, NULL },
	{ CKM_SKIPJACK_CFB64, CRYPT_ALGO_SKIPJACK, CRYPT_MODE_CFB, NULL, NULL, NULL, NULL },
	{ CKM_SKIPJACK_OFB64, CRYPT_ALGO_SKIPJACK, CRYPT_MODE_OFB, NULL, NULL, NULL, NULL },
	{ CRYPT_ERROR, CRYPT_ALGO_NONE, CRYPT_MODE_NONE, NULL, NULL, NULL, NULL }
	};

/* Query a given capability for a device and fill out a capability info
   record for it if present */

static CAPABILITY_INFO *getCapability( const DEVICE_INFO *deviceInfo,
									   const MECHANISM_INFO *mechanismInfoPtr )
	{
	VARIABLE_CAPABILITY_INFO *capabilityInfo;
	CK_MECHANISM_INFO mechanismInfo;
	CK_RV status;
	int i;

	/* Get the information for this mechanism */
	status = C_GetMechanismInfo( deviceInfo->slotHandle, 
								 mechanismInfoPtr->mechanism,
								 &mechanismInfo );
	if( status != CKR_OK )
		return( NULL );

	/* Copy across the template for this capability */
	if( ( capabilityInfo = malloc( sizeof( CAPABILITY_INFO ) ) ) == NULL )
		return( NULL );
	for( i = 0; \
		 capabilityTemplates[ i ].cryptAlgo != mechanismInfoPtr->cryptAlgo && \
		 capabilityTemplates[ i ].cryptMode != mechanismInfoPtr->cryptMode; \
		 i++ );
	memcpy( capabilityInfo, &capabilityTemplates[ i ],
			sizeof( CAPABILITY_INFO ) );

	/* Set up the keysize information if there's anything useful available */
	if( keysizeValid( mechanismInfoPtr->cryptAlgo ) )
		{
		int minKeySize = ( int ) mechanismInfo.ulMinKeySize;
		int maxKeySize = ( int ) mechanismInfo.ulMaxKeySize;

		if( !keysizeBytes( mechanismInfoPtr->cryptAlgo ) )
			{
			minKeySize = bitsToBytes( minKeySize );
			maxKeySize = bitsToBytes( maxKeySize );
			}
		capabilityInfo->minKeySize = minKeySize;
		if( capabilityInfo->keySize < capabilityInfo->minKeySize )
			capabilityInfo->keySize = capabilityInfo->minKeySize;
		capabilityInfo->maxKeySize = ( int ) mechanismInfo.ulMaxKeySize;
		if( capabilityInfo->keySize > capabilityInfo->maxKeySize )
			capabilityInfo->keySize = capabilityInfo->maxKeySize;
		capabilityInfo->endFunction = genericEndFunction;
		}

	/* Set up the device-specific handlers */
	capabilityInfo->initKeyFunction = mechanismInfoPtr->initKeyFunction;
	if( mechanismInfo.flags & CKF_GENERATE_KEY_PAIR )
		capabilityInfo->generateKeyFunction = mechanismInfoPtr->generateKeyFunction;
	if( mechanismInfo.flags & CKF_SIGN )
		capabilityInfo->signFunction = mechanismInfoPtr->signFunction;
	if( mechanismInfo.flags & CKF_VERIFY )
		capabilityInfo->sigCheckFunction = mechanismInfoPtr->sigCheckFunction;
	if( mechanismInfo.flags & CKF_ENCRYPT )
		capabilityInfo->encryptFunction = mechanismInfoPtr->encryptFunction;
	if( mechanismInfo.flags & CKF_DECRYPT )
		capabilityInfo->decryptFunction = mechanismInfoPtr->decryptFunction;

	return( ( CAPABILITY_INFO * ) capabilityInfo );
	}

/* Set the capability information based on device capabilities.  Since
   PKCS #11 devices can have assorted capabilities (and can vary depending
   on what's plugged in), we have to build this up on the fly rather than
   using a fixed table like the built-in capabilities */

static void freeCapabilities( DEVICE_INFO *deviceInfo )
	{
	CAPABILITY_INFO *capabilityInfoPtr = deviceInfo->capabilityInfoPtr;

	/* If the list was empty, return now */
	if( capabilityInfoPtr == NULL )
		return;
	deviceInfo->capabilityInfoPtr = NULL;

	while( capabilityInfoPtr != NULL )
		{
		CAPABILITY_INFO *itemToFree = capabilityInfoPtr;

		capabilityInfoPtr = capabilityInfoPtr->next;
		zeroise( itemToFree, sizeof( CAPABILITY_INFO ) );
		free( itemToFree );
		}
	}

static int getCapabilities( DEVICE_INFO *deviceInfo )
	{
	CAPABILITY_INFO *capabilityListTail = deviceInfo->capabilityInfoPtr;
	int i;

	/* Add capability information for each recognised mechanism type */
	for( i = 0; mechanismInfo[ i ].mechanism != CRYPT_ERROR; i++ )
		{
		CAPABILITY_INFO *newCapability;

		newCapability = getCapability( deviceInfo, &mechanismInfo[ i ] );
		if( newCapability == NULL )
			continue;
		if( deviceInfo->capabilityInfoPtr == NULL )
			deviceInfo->capabilityInfoPtr = newCapability;
		else
			capabilityListTail->next = newCapability;
		capabilityListTail = newCapability;
		}

	return( ( deviceInfo->capabilityInfoPtr == NULL ) ? \
			CRYPT_ERROR : CRYPT_OK );
	}

/* Get the capability information for a given algorithm and mode */

static int findCapabilityFunction( DEVICE_INFO *deviceInfo,
								   const void FAR_BSS **capabilityInfoPtrPtr,
								   const CRYPT_ALGO cryptAlgo,
								   const CRYPT_MODE cryptMode )
	{
	CAPABILITY_INFO *capabilityInfoPtr;
	int status = CRYPT_NOALGO;

	UNUSED( deviceInfo );

	/* Find the capability corresponding to the requested algorithm/mode */
	for( capabilityInfoPtr = deviceInfo->capabilityInfoPtr;
		 capabilityInfoPtr != NULL;
		 capabilityInfoPtr = capabilityInfoPtr->next )
		if( capabilityInfoPtr->cryptAlgo == cryptAlgo )
			{
			status = CRYPT_NOMODE;
			if( capabilityInfoPtr->cryptMode == cryptMode || \
				cryptMode == CRYPT_UNUSED )
				{
				*capabilityInfoPtrPtr = capabilityInfoPtr;
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

	/* Find the capability corresponding to the requested algorithm/mode */
	status = findCapabilityFunction( deviceInfo,
				( const void ** ) &capabilityInfoPtr, cryptAlgo, cryptMode );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the context and remember the device it's contained in */
	status = createContext( cryptContext, capabilityInfoPtr, NULL, 0 );
	if( cryptStatusError( status ) )
		return( status );
	krnlSendMessage( *cryptContext, RESOURCE_MESSAGE_SETDATA,
					 &deviceInfo->objectHandle, RESOURCE_MESSAGE_DATA_DEVICE,
					 0 );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Device Access Routines							*
*																			*
****************************************************************************/

/* Set up the function pointers to the device methods */

int setDevicePKCS11( DEVICE_INFO *deviceInfo, const char *name )
	{
#ifdef __WINDOWS__
	int i;

	/* Make sure the PKCS #11 driver DLL's are loaded */
	if( !pkcs11Initialised )
		return( CRYPT_DATA_OPEN );

	/* Try and find the driver based on its name */
	for( i = 0; i < MAX_PKCS11_DRIVERS; i++ )
		if( !stricmp( pkcs11InfoTbl[ i ].name, name ) )
			break;
	if( i == MAX_PKCS11_DRIVERS )
		return( CRYPT_BADPARM2 );
	deviceInfo->deviceNo = i;
#else
	UNUSED( name );

	/* Initialise the PKCS #11 library.  Since this is statically linked
	   there's no need to give a driver name */
	if( C_Initialize( NULL_PTR ) != CKR_OK )
		return( CRYPT_DATA_OPEN );
#endif /* __WINDOWS__ */

	deviceInfo->initDeviceFunction = initDeviceFunction;
	deviceInfo->shutdownDeviceFunction = shutdownDeviceFunction;
	deviceInfo->controlFunction = controlFunction;
	deviceInfo->findCapabilityFunction = findCapabilityFunction;
	deviceInfo->createContextFunction = createContextFunction;
	deviceInfo->instantiateNamedObjectFunction = instantiateNamedObjectFunction;
	deviceInfo->getRandomFunction = getRandomFunction;

	return( CRYPT_OK );
	}
