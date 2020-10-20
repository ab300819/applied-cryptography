/****************************************************************************
*																			*
*					cryptlib Towitoko Smart Card Reader Routines			*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "scard.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "scard.h"
#else
  #include "crypt.h"
  #include "misc/scard.h"
#endif /* Compiler-specific includes */

/* Reader LED colour settings */

#define SCARD_LED_OFF		0
#define SCARD_LED_RED		1
#define SCARD_LED_GREEN		2
#define SCARD_LED_YELLOW	3

#ifdef __WINDOWS__
  #ifdef __WIN16__
	#define SCARD_API	FAR PASCAL _export
  #else
	#define SCARD_API	__stdcall
  #endif /* Windows version-specific entry types */
#else
  #define SCARD_API
#endif /* OS-specific entry types */

/* Function prototypes */

WORD SCARD_API TDevAppCard( WORD devID, BYTE ASel, BYTE ACSel, void *data );
WORD SCARD_API TDevCard( WORD devID, char *card);
WORD SCARD_API TDevCardChange( WORD devID, char *cardChange );
WORD SCARD_API TDevCardSTATUS( WORD devID, char *cardStatus );
WORD SCARD_API TDevCreateCDX10( WORD port, WORD id );
WORD SCARD_API TDevCreateCDI10( WORD port, WORD id );
WORD SCARD_API TDevCreateCDD10( WORD port, WORD id );
WORD SCARD_API TDevCreateKTZ10( WORD port, WORD id );
WORD SCARD_API TDevEjectCard( WORD devID );
WORD SCARD_API TDevErrCode( void );
WORD SCARD_API TDevError( char *error );
WORD SCARD_API TDevFree( WORD devID );
WORD SCARD_API TDevISOATR( WORD devID );
/*WORD SCARD_API TDevISOATRData( WORD devID, struct TIsoAtr* Data );*/
WORD SCARD_API TDevLed( WORD devID, BYTE color );
WORD SCARD_API TDevMemCard( WORD devID, BYTE CSel, BYTE CCSel, WORD *CCSI,
							WORD *CCDI, void *buffer );
WORD SCARD_API TDevRequestCard( WORD devID, WORD *prtMode );
WORD SCARD_API TDevSyncMode( WORD devID, BYTE Mode );
WORD SCARD_API TDevT0COMRX( WORD devID, BYTE CLA, BYTE INS, BYTE P1,
							BYTE P2, BYTE P3, BYTE *Data, WORD DataSize,
							WORD Cwt, WORD *SW );
WORD SCARD_API TDevT0COMTX( WORD devID, BYTE CLA, BYTE INS, BYTE P1,
							BYTE P2, BYTE P3, BYTE *data, WORD dataSize,
							WORD Cwt, WORD *SW );
WORD SCARD_API TDevT1COM( WORD devID, WORD TxLen, WORD *RxLen, WORD *SW,
						  BYTE *TxD, WORD TxDSize, BYTE *RxD, WORD RxDSize );
WORD SCARD_API TDevT1Init( WORD devID, WORD Bwt, WORD Cwt, WORD IFSD,
						   WORD IFSC, char InitIfs );
WORD SCARD_API TDevT1Node( WORD devID, BYTE Sad, BYTE Dad );

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

static HINSTANCE hScard = NULL_HINSTANCE;

typedef WORD ( SCARD_API *TDEVAPPCARD )( WORD devID, BYTE ASel, BYTE ACSel,
			   void *data );
typedef WORD ( SCARD_API *TDEVCARD )( WORD devID, char *card);
typedef WORD ( SCARD_API *TDEVCARDCHANGE )( WORD devID, char *cardChange );
typedef WORD ( SCARD_API *TDEVCARDSTATUS )( WORD devID, char *cardStatus );
typedef WORD ( SCARD_API *TDEVCREATECDX10 )( WORD port, WORD id );
typedef WORD ( SCARD_API *TDEVCREATECDI10 )( WORD port, WORD id );
typedef WORD ( SCARD_API *TDEVCREATECDD10 )( WORD port, WORD id );
typedef WORD ( SCARD_API *TDEVCREATEKTZ10 )( WORD port, WORD id );
typedef WORD ( SCARD_API *TDEVEJECTCARD )( WORD devID );
typedef WORD ( SCARD_API *TDEVERRCODE )( void );
typedef WORD ( SCARD_API *TDEVERROR )( char *error );
typedef WORD ( SCARD_API *TDEVFREE )( WORD devID );
typedef WORD ( SCARD_API *TDEVISOATR )( WORD devID );
typedef WORD ( SCARD_API *TDEVISOATRDATA )( WORD devID, struct TIsoAtr* Data );
typedef WORD ( SCARD_API *TDEVLED )( WORD devID, BYTE color );
typedef WORD ( SCARD_API *TDEVMEMCARD )( WORD devID, BYTE CSel, BYTE CCSel,
			   WORD *CCSI, WORD *CCDI, void *buffer );
typedef WORD ( SCARD_API *TDEVREQUESTCARD )( WORD devID, WORD *prtMode );
typedef WORD ( SCARD_API *TDEVSYNCMODE )( WORD devID, BYTE Mode );
typedef WORD ( SCARD_API *TDEVT0COMRX )( WORD devID, BYTE CLA, BYTE INS,
			   BYTE P1, BYTE P2, BYTE P3, BYTE *Data, WORD DataSize,
			   WORD Cwt, WORD *SW );
typedef WORD ( SCARD_API *TDEVT0COMTX )( WORD devID, BYTE CLA, BYTE INS,
			   BYTE P1, BYTE P2, BYTE P3, BYTE *data, WORD dataSize,
			   WORD Cwt, WORD *SW );
typedef WORD ( SCARD_API *TDEVT1COM )( WORD devID, WORD TxLen, WORD *RxLen,
			   WORD *SW, BYTE *TxD, WORD TxDSize, BYTE *RxD, WORD RxDSize );
typedef WORD ( SCARD_API *TDEVT1INIT )( WORD devID, WORD Bwt, WORD Cwt,
			   WORD IFSD, WORD IFSC, char InitIfs );
typedef WORD ( SCARD_API *TDEVT1NODE )( WORD devID, BYTE Sad, BYTE Dad );
static TDEVCREATECDX10 pTDevCreateCDX10 = NULL;
static TDEVCREATECDI10 pTDevCreateCDI10 = NULL;
static TDEVCREATECDD10 pTDevCreateCDD10 = NULL;
static TDEVCREATEKTZ10 pTDevCreateKTZ10 = NULL;
static TDEVERRCODE pTDevErrCode = NULL;
static TDEVERROR pTDevError = NULL;
static TDEVFREE pTDevFree = NULL;
static TDEVLED pTDevLed = NULL;

/* The use of dynamically bound function pointers vs statically linked
   functions requires a bit of sleight of hand since we can't give the
   pointers the same names as prototyped functions.  To get around this we
   redefine the actual function names to the names of the pointers */

#define TDevCreateCDX10		pTDevCreateCDX10
#define TDevCreateCDI10		pTDevCreateCDI10
#define TDevCreateCDD10		pTDevCreateCDD10
#define TDevCreateKTZ10		pTDevCreateKTZ10
#define TDevErrCode			pTDevErrCode
#define TDevError			pTDevError
#define TDevFree			pTDevFree
#define TDevLed				pTDevLed

/* Depending on whether we're running under Win16 or Win32 we load the card
   driver under a different name */

#ifdef __WIN16__
  #define SCARD_LIBNAME	"TDEV.DLL"
#else
  #define SCARD_LIBNAME	"TDEV32.DLL"
#endif /* __WIN16__ */

/* Dynamically load and unload any necessary smart card drivers */

void scardInitTowitoko( void )
	{
#ifdef __WIN16__
	UINT errorMode;
#endif /* __WIN16__ */
	static BOOLEAN initCalled = FALSE;

	/* If we've previously tried to init the drivers, don't try it again */
	if( initCalled )
		return;
	initCalled = TRUE;

	/* Obtain a handle to the smart card driver module */
#ifdef __WIN16__
	errorMode = SetErrorMode( SEM_NOOPENFILEERRORBOX );
	hScard = LoadLibrary( SCARD_LIBNAME );
	SetErrorMode( errorMode );
	if( hScard == NULL_HINSTANCE )
		return;
#else
	if( ( hScard = LoadLibrary( SCARD_LIBNAME ) ) == NULL_HINSTANCE )
		return;
#endif /* __WIN32__ */

	/* Now get pointers to the functions */
	pTDevCreateCDX10 = ( TDEVCREATECDX10 ) GetProcAddress( hScard, "TDevCreateCDX10" );
	pTDevCreateCDI10 = ( TDEVCREATECDI10 ) GetProcAddress( hScard, "TDevCreateCDI10" );
	pTDevCreateCDD10 = ( TDEVCREATECDD10 ) GetProcAddress( hScard, "TDevCreateCDD10" );
	pTDevCreateKTZ10 = ( TDEVCREATEKTZ10 ) GetProcAddress( hScard, "TDevCreateKTZ10" );
	pTDevErrCode = ( TDEVERRCODE ) GetProcAddress( hScard, "TDevErroCode" );
	pTDevError = ( TDEVERROR ) GetProcAddress( hScard, "TDevError" );
	pTDevFree = ( TDEVFREE ) GetProcAddress( hScard, "TDevFree" );
	pTDevLed = ( TDEVLED ) GetProcAddress( hScard, "TDevLed" );

	/* Make sure we got valid pointers for every card function */
	if( pTDevCreateCDX10 == NULL || pTDevCreateCDI10 == NULL || \
		pTDevCreateCDD10 == NULL || pTDevCreateKTZ10 == NULL || \
		pTDevErrCode == NULL || pTDevError == NULL || \
		pTDevFree == NULL || pTDevLed == NULL )
		{
		/* Free the library reference and reset the handle */
		FreeLibrary( hScard );
		hScard = NULL_HINSTANCE;
		}
	}

void scardEndTowitoko( void )
	{
	if( hScard != NULL_HINSTANCE )
		FreeLibrary( hScard );
	hScard = NULL_HINSTANCE;
	}
#endif /* __WINDOWS__ */

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* Get information on a card reader error */

static void getErrorInfo( SCARD_INFO *scardInfo )
	{
	*scardInfo->errorCode = TDevErrCode();
	TDevError( scardInfo->errorMessage );
	}

/****************************************************************************
*																			*
*						 	Reader Init/Shutdown Routines					*
*																			*
****************************************************************************/

/* Close a previously-opened session with the reader.  We have to have this
   before initReader() since it may be called by initReader() if the init
   process fails */

static void shutdownReader( SCARD_INFO *scardInfo )
	{
	/* We're closing down, turn the reader LED off to indicate we're not
	   using it any more */
	TDevLed( ( WORD ) scardInfo->readerHandle, SCARD_LED_OFF );

	/* Clean up */
	TDevFree( ( WORD ) scardInfo->readerHandle );
	scardInfo->readerHandle = 0;
	}

/* Open a session with a reader */

static int initReader( SCARD_INFO *scardInfo, const char *readerName,
					   const char *cardName, const COMM_PARAMS *commParams )
	{
	UNUSED( cardName );
	UNUSED( commParams );

	/* Determine which function we need to call based on the reader type */
	if( stricmp( readerName, "CHIPDRIVE extern" ) )
		scardInfo->readerHandle = TDevCreateCDX10( 1, 0 );
	else
	if( stricmp( readerName, "CHIPDRIVE intern" ) )
		scardInfo->readerHandle = TDevCreateCDI10( 1, 0 );
	else
	if( stricmp( readerName, "CHIPDRIVE extern II" ) )
		scardInfo->readerHandle = TDevCreateCDD10( 1, 0 );
	else
	if( stricmp( readerName, "KartenZwerg" ) )
		scardInfo->readerHandle = TDevCreateKTZ10( 1, 0 );
	else
		/* Unknown reader type */
		return( CRYPT_BADPARM );
	if( scardInfo->readerHandle < 0 )
		{
		getErrorInfo( scardInfo );
		return( CRYPT_DATA_OPEN );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Card Access Routines							*
*																			*
****************************************************************************/

/* Set up the function pointers to the access methods */

int setAccessMethodTowitoko( SCARD_INFO *scardInfo )
	{
#ifdef __WINDOWS__
	/* Load the Towitoko driver DLL if it isn't already loaded */
	if( hScard == NULL_HINSTANCE )
		{
		scardInitTowitoko();
		if( hScard == NULL_HINSTANCE )
			return( CRYPT_DATA_OPEN );
		}
#endif /* __WINDOWS__ */

	scardInfo->initReader = initReader;
	scardInfo->shutdownReader = shutdownReader;

	return( CRYPT_OK );
	}
