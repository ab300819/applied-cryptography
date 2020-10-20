/****************************************************************************
*																			*
*						 cryptlib HTTP Mapping Routines						*
*						Copyright Peter Gutmann 1998-1999					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <time.h>
#include "../crypt.h"
#include "dbms.h"
#ifdef DBX_HTTP
  #if defined( INC_ALL ) || defined( INC_CHILD )
	#include "tcp4u.h"
	#include "http4u.h"
  #else
	#include "misc/tcp4u.h"
	#include "misc/http4u.h"
  #endif /* Compiler-specific includes */
#endif /* DBX_HTTP */

/* The default size of the HTTP read buffer.  This is a bit of a difficult
   quantity to get right, for cert's it's way too big, for cert chains it's
   a bit too big, and for CRL's it could be much too small (1/4MB CRL's
   have been seen in the wild).  We try to allocate an appropriate-sized
   buffer if we can, otherwise we grow it in HTTP_BUFFER_STEP chunks */

#define HTTP_BUFFER_SIZE	8192
#define HTTP_BUFFER_STEP	16384

#ifdef DBX_HTTP

/****************************************************************************
*																			*
*						 		Init/Shutdown Routines						*
*																			*
****************************************************************************/

#ifdef __WINDOWS__

/* Global function pointers.  These are necessary because the functions need
   to be dynamically linked since not all systems contain the necessary
   DLL's.  Explicitly linking to them will make cryptlib unloadable on some
   systems */

#define NULL_HINSTANCE	( HINSTANCE ) NULL

static HINSTANCE hHTTP = NULL_HINSTANCE;

typedef int ( API4U *TCP4UCLEANUP )( void );
typedef LPSTR ( API4U *TCP4UERRORSTRING )( int Rc );
typedef int ( API4U *TCP4UINIT )( void );
typedef int ( API4U *HTTP4UGETFILEEX )( LPCSTR szURL, LPCSTR szProxyURl,
										LPCSTR szLocalFile, LPCSTR szHeaderFile,
										HTTP4U_CALLBACK CbkTransmit,
										long luserValue, LPSTR szResponse,
										int nResponseSize, LPSTR szHeaders,
										int nHeadersSize );
typedef int ( API4U *HTTP4USETTIMEOUT )( unsigned int uTimeout );
static TCP4UCLEANUP pTcp4uCleanup = NULL;
static TCP4UERRORSTRING pTcp4uErrorString = NULL;
static TCP4UINIT pTcp4uInit = NULL;
static HTTP4UGETFILEEX pHttp4uGetFileEx = NULL;
static HTTP4USETTIMEOUT pHttp4uSetTimeout = NULL;

/* Depending on whether we're running under Win16 or Win32 we load the HTTP
   driver under a different name */

#ifdef __WIN16__
  #define HTTP_LIBNAME	"TCP4W.DLL"
#else
  #define HTTP_LIBNAME	"TCP4W32.DLL"
#endif /* __WIN16__ */

/* The use of dynamically bound function pointers vs statically linked
   functions requires a bit of sleight of hand since we can't give the
   pointers the same names as prototyped functions.  To get around this we
   redefine the actual function names to the names of the pointers */

#define Tcp4uCleanup		pTcp4uCleanup
#define Tcp4uErrorString	pTcp4uErrorString
#define Tcp4uInit			pTcp4uInit
#define Http4uGetFileEx		pHttp4uGetFileEx
#define Http4uSetTimeout	pHttp4uSetTimeout

/* Dynamically load and unload any necessary HTTP libraries */

void dbxInitHTTP( void )
	{
#ifdef __WIN16__
	UINT errorMode;
#endif /* __WIN16__ */

	/* If the HTTP module is already linked in, don't do anything */
	if( hHTTP != NULL_HINSTANCE )
		return;

	/* Obtain a handle to the module containing the HTTP functions */
#ifdef __WIN16__
	errorMode = SetErrorMode( SEM_NOOPENFILEERRORBOX );
	hHTTP = LoadLibrary( HTTP_LIBNAME );
	SetErrorMode( errorMode );
	if( hHTTP < HINSTANCE_ERROR )
		{
		hHTTP = NULL_HINSTANCE;
		return;
		}
#else
	if( ( hHTTP = LoadLibrary( HTTP_LIBNAME ) ) == NULL_HINSTANCE )
		return;
#endif /* __WIN32__ */

	/* Now get pointers to the functions */
	pTcp4uCleanup = ( TCP4UCLEANUP ) GetProcAddress( hHTTP, "Tcp4uCleanup" );
	pTcp4uErrorString = ( TCP4UERRORSTRING ) GetProcAddress( hHTTP, "Tcp4uErrorString" );
	pTcp4uInit = ( TCP4UINIT ) GetProcAddress( hHTTP, "Tcp4uInit" );
	pHttp4uGetFileEx = ( HTTP4UGETFILEEX ) GetProcAddress( hHTTP, "Http4uGetFileEx" );
	if( pHttp4uGetFileEx == NULL )
		/* The version without the 4u is possibly a typo which may be fixed 
		   in future versions so we check for both */
		pHttp4uGetFileEx = ( HTTP4UGETFILEEX ) GetProcAddress( hHTTP, "HttpGetFileEx" );
	pHttp4uSetTimeout = ( HTTP4USETTIMEOUT ) GetProcAddress( hHTTP, "Http4uSetTimeout" );

	/* Make sure we got valid pointers for every HTTP function */
	if( pTcp4uCleanup == NULL || pTcp4uErrorString == NULL || \
		pTcp4uInit == NULL || pHttp4uGetFileEx == NULL || \
		pHttp4uSetTimeout == NULL )
		{
		/* Free the library reference and reset the handle */
		FreeLibrary( hHTTP );
		hHTTP = NULL_HINSTANCE;
		return;
		}

	/* Initialise the Winsock code */
	if( Tcp4uInit() != TCP4U_SUCCESS )
		{
		/* Free the library reference and reset the handle */
		FreeLibrary( hHTTP );
		hHTTP = NULL_HINSTANCE;
		}
	}

void dbxEndHTTP( void )
	{
	if( hHTTP != NULL_HINSTANCE )
		{
		Tcp4uCleanup();
		FreeLibrary( hHTTP );
		}
	hHTTP = NULL_HINSTANCE;
	}
#else

void dbxInitHTTP( void )
	{
	Tcp4uInit();
	}

void dbxEndHTTP( void )
	{
	Tcp4uCleanup();
	}
#endif /* __WINDOWS__ */

/****************************************************************************
*																			*
*						 		Keyset Access Routines						*
*																			*
****************************************************************************/

/* Map a Tcp4u status to a cryptlib one */

static int mapError( KEYSET_INFO *keysetInfoPtr, int status )
	{
	/* Remember the error code and message */
	keysetInfoPtr->errorCode = status;
	strncpy( keysetInfoPtr->errorMessage, Tcp4uErrorString( status ),
			 MAX_ERRMSG_SIZE - 1 );
	keysetInfoPtr->errorMessage[ MAX_ERRMSG_SIZE - 1 ] = '\0';

	switch( status )
		{
		case HTTP4U_SUCCESS:
			return( CRYPT_OK );

		case HTTP4U_CANCELLED:
		case HTTP4U_INSMEMORY:
			return( CRYPT_NOMEM );

		case HTTP4U_BAD_URL:
		case HTTP4U_HOST_UNKNOWN:
		case HTTP4U_TCP_CONNECT:
		case HTTP4U_TCP_FAILED:
			return( CRYPT_DATA_OPEN );

		case HTTP4U_BAD_REQUEST:
		case HTTP4U_FORBIDDEN:
		case HTTP4U_MOVED:
		case HTTP4U_NO_CONTENT:
		case HTTP4U_NOT_FOUND:
		case HTTP4U_PROTOCOL_ERROR:
			return( CRYPT_DATA_READ );

		case HTTP4U_OVERFLOW:
			return( CRYPT_OVERFLOW );
		}
	return( CRYPT_ERROR );
	}

/* The callback used to handle data read from a socket */

BOOL CALLBACK httpCallback( long lBytesTransferred, long lTotalBytes,
							long lUserValue, LPCSTR data, int dataLength )
	{
	KEYSET_INFO *keysetInfoPtr = ( KEYSET_INFO * ) lUserValue;
	const int bufSize = keysetInfoPtr->keysetHTTP.bufSize;

	/* If nothing has been transferred yet, just return (we always get this
	   at least once when only the headers have been transferred) */
	if( !dataLength )
		{
		/* If we know how big the file will be and it's bigger than the
		   allocated buffer, allocate room for it.  We don't use realloc()
		   because there's no need to preserve any existing data */
		if( lTotalBytes > bufSize )
			{
			free( keysetInfoPtr->keysetHTTP.buffer );
			if( ( keysetInfoPtr->keysetHTTP.buffer = malloc( lTotalBytes + 512 ) ) == NULL )
				return( FALSE );
			keysetInfoPtr->keysetHTTP.bufSize = lTotalBytes + 512;
			}

		return( TRUE );
		}

	/* Copy the transferred data in, expanding the buffer if necessary */
	if( keysetInfoPtr->keysetHTTP.bufPos + dataLength > bufSize )
		{
		const int newSize = max( bufSize + HTTP_BUFFER_STEP, lTotalBytes );
		void *newBuffer = realloc( keysetInfoPtr->keysetHTTP.buffer, newSize );

		if( newBuffer == NULL )
			return( FALSE );
		keysetInfoPtr->keysetHTTP.buffer = newBuffer;
		keysetInfoPtr->keysetHTTP.bufSize = newSize;
		}
	memcpy( keysetInfoPtr->keysetHTTP.buffer + keysetInfoPtr->keysetHTTP.bufPos,
			data, dataLength );
	keysetInfoPtr->keysetHTTP.bufPos += dataLength;

	return( TRUE );
	}

/* Fetch data from a URL */

int httpGetKey( KEYSET_INFO *keysetInfoPtr, const char *url )
	{
	char *proxy = getOptionString( CRYPT_OPTION_KEYS_HTTP_PROXY );
	int status;

#ifdef __WINDOWS__
	/* Make sure the HTTP interface has been initialised */
	if( hHTTP == NULL_HINSTANCE )
		return( CRYPT_DATA_READ );
#endif /* __WINDOWS__ */

	/* If we haven't allocated a buffer for the data yet, do so now */
	if( keysetInfoPtr->keysetHTTP.buffer == NULL )
		{
		if( ( keysetInfoPtr->keysetHTTP.buffer = malloc( HTTP_BUFFER_SIZE ) ) == NULL )
			return( CRYPT_NOMEM );
		keysetInfoPtr->keysetHTTP.bufSize = HTTP_BUFFER_SIZE;
		}
	keysetInfoPtr->keysetHTTP.bufPos = 0;

	/* Read the data into the buffer */
	Http4uSetTimeout( getOptionNumeric( CRYPT_OPTION_KEYS_HTTP_TIMEOUT ) );
	status = Http4uGetFileEx( url, *proxy ? proxy : NULL, NULL, NULL,
							  httpCallback, ( long ) keysetInfoPtr, NULL, 
							  0, NULL, 0 );
	return( mapError( keysetInfoPtr, status ) );
	}
#endif /* DBX_HTTP */
