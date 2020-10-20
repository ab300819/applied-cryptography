/****************************************************************************
*																			*
*					cryptlib Generic Smart Card Reader Routines				*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "scard.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../keymgmt/asn1.h"
  #include "scard.h"
#else
  #include "crypt.h"
  #include "keymgmt/asn1.h"
  #include "misc/scard.h"
#endif /* Compiler-specific includes */

#if defined( __MSDOS16__ ) && defined( __TURBOC__ ) && ( __TURBOC__ <= 0x200 )
  #undef getCommParams
#endif /* Kludge for TC 2.0 */

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* The default comms settings */

#ifdef __WINDOWS__
  #define DEFAULT_PORT			2
  #define DEFAULT_PORTNAME		"COM2"
#else
  #define DEFAULT_PORT			1
  #define DEFAULT_PORTNAME		"/dev/ttyS1"
#endif /* OS-specific comm port name */

static const COMM_PARAMS defaultParams = { DEFAULT_PORT, DEFAULT_PORTNAME,
										   9600, 8, COMM_PARITY_NONE, 1 };

/* Decode a string contains comms parameters into a COMM_PARAMS structure */

#define skipWhitespace( string )	while( isspace( *string ) ) string++

int getCommParams( COMM_PARAMS *commParams, const char *commParamStr,
				   const BOOLEAN longFormOK )
	{
	char *strPtr = ( char * ) commParamStr;
	long longVal;
	int value;

	/* Set up the default parameters */
	memcpy( commParams, &defaultParams, sizeof( COMM_PARAMS ) );
	if( commParamStr == NULL )
		return( CRYPT_OK );

	/* Decode the comms port.  This should always be present */
#if defined( __WINDOWS__ )
	if( strnicmp( strPtr, "COM", 3 ) )
		return( CRYPT_BADPARM );
	value = atoi( strPtr + 3 );
	if( value < 1 || value > 4 )
		return( CRYPT_BADPARM );
	commParams->port = value - 1;
	strPtr += 4;
#elif defined( __UNIX__ )
	while( *strPtr && *strPtr != ',' )
		*strPtr++;	/* Skip the serial device name */
#endif /* OS-dependant comm port processing */
	value = ( int ) ( strPtr - ( char * ) commParamStr );
	if( value > CRYPT_MAX_TEXTSIZE - 1 )
		return( CRYPT_BADPARM );
	strncpy( commParams->portName, commParamStr, value );
	commParams->portName[ value ] = '\0';

	/* Check whether this is the short form of the parameter string */
	skipWhitespace( strPtr );
	if( !*strPtr )
		return( CRYPT_OK );
	if( !longFormOK || *strPtr++ != ',' )
		return( CRYPT_BADPARM );
	skipWhitespace( strPtr );

	/* Decode the comms device parameters */
	longVal = atol( strPtr );
	if( longVal != 9600 && longVal != 19200 && longVal != 38400L )
		return( CRYPT_BADPARM );
	commParams->baudRate = longVal;
	while( isdigit( *strPtr ) )
		strPtr++;	/* Skip baud rate */
	skipWhitespace( strPtr );
	if( *strPtr++ != ',' )
		return( CRYPT_BADPARM );
	skipWhitespace( strPtr );
	value = atoi( strPtr );
	if( value < 7 || value > 8 )
		return( CRYPT_BADPARM );
	commParams->dataBits = value;
	strPtr++;	/* Skip data bits value */
	skipWhitespace( strPtr );
	if( *strPtr++ != ',' )
		return( CRYPT_BADPARM );
	skipWhitespace( strPtr );
	value = toupper( *strPtr );
	strPtr++;		/* toupper() has side-effects on some systems */
	value = ( value == 'N' ) ? COMM_PARITY_NONE : \
			( value == 'E' ) ? COMM_PARITY_EVEN : \
			( value == 'O' ) ? COMM_PARITY_ODD : CRYPT_ERROR;
	if( value == CRYPT_ERROR )
		return( CRYPT_BADPARM );
	commParams->parity = value;
	skipWhitespace( strPtr );
	if( *strPtr++ != ',' )
		return( CRYPT_BADPARM );
	skipWhitespace( strPtr );
	value = atoi( strPtr );
	if( value < 0 || value > 2 )
		return( CRYPT_BADPARM );
	commParams->stopBits = value;
	strPtr++;	/* Skip stop bits value */
	skipWhitespace( strPtr );
	if( *strPtr )
		return( CRYPT_BADPARM );

	return( CRYPT_OK );
	}

/* ATR values for various cards */

typedef struct {
	const BYTE *atr;				/* ATR for card */
	const BYTE *atrMask;			/* Mask for bytes to ignore */
	const int atrLength;			/* Length of ATR */
	const SCARD_TYPE type;			/* Card type */
	} ATR_VALUE;

static const ATR_VALUE atrTable[] = {
	{ ( const BYTE * ) "\x03\x19\x5B\xFF\x7B\xFB\xFF",
		NULL, 7, SCARD_TB1000 },
	{ ( const BYTE * ) "\x03\x59\x58\xFF\x2B\x6F",
		NULL, 6, SCARD_TB98S },
	{ ( const BYTE * ) "\x3B\x02\x14\x50",
		NULL, 4, SCARD_MULTIFLEX },
	{ ( const BYTE * ) "\x3B\x23\x00\x35\x11\x80",
		NULL, 6, SCARD_PAYFLEX1K },
	{ ( const BYTE * ) "\x3B\x24\x00\x80\x72\x94",
		NULL, 6, SCARD_MPCOS_3DES },
	{ ( const BYTE * ) "\x3B\x27\x00\x80\x65\xA2",
		NULL, 6, SCARD_GPK2000 },
	{ ( const BYTE * ) "\x3B\x32\x15\x00\x06\x80",
		NULL, 6, SCARD_MULTIFLEX },	/* MultiFlex3K-G3, 8K */
	{ ( const BYTE * ) "\x3B\x85\x40\x64\xCA\xFE\x01\x90\x00",
		NULL, 9, SCARD_CAFE },
	{ ( const BYTE * ) "\x3B\x88\x01\x50\x43\x31\x36\x54\x34\x7F\xFF\x46",
		NULL, 12, SCARD_RG200 },
	{ ( const BYTE * ) "\x3B\x8B\x81\x31\x40\x34\x53\x4D\x41\x52\x54\x53\x43\x4F\x50\x45\x31\x6D",
		NULL, 18, SCARD_SMARTSCOPE1 },
	{ ( const BYTE * ) "\x3B\x8B\x81\x31\x40\x34\x53\x4D\x41\x52\x54\x53\x43\x4F\x50\x45\x33\x6F",
		NULL, 18, SCARD_SMARTSCOPE3 },
	{ ( const BYTE * ) "\x3B\xB0\x11\x00\x81\31",
		NULL, 6, SCARD_SIGNASURE },
	{ ( const BYTE * ) "\x3B\xBE\x11\x00\x00",
		NULL, 5, SCARD_ACOS1 },
	{ ( const BYTE * ) "\x3B\xBE\x18\x00\x81\x31\x20\x53\x50\x4B\x20\x32",
		NULL, 12, SCARD_STARCOS },
	{ ( const BYTE * ) "\x3B\xE2\x00\x00\x40\x20\x49\x03",
		NULL, 8, SCARD_CRYPTOFLEX },
	{ ( const BYTE * ) "\x3B\xEB\x00\x00\x81\x31\x42\x45\x4E\x4C\x43\x68\x69\x70\x70\x65\x72\x30\x31\x0A",
		NULL, 20, SCARD_CHIPPER },
	{ ( const BYTE * ) "\x3B\xFA\x11\x00\x02\x40\x20\x41\xC0\x03\xF8\x03\x03\x00\x00\x90\x00",
	  ( const BYTE * ) "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x00\x01\x01\x01\x01",
		17, SCARD_DX },
	{ ( const BYTE * ) "\x3B\xEF\x00\xFF\x81\x31\x50\x45\x65\x63\x08\x04\x13\xFF\xFF\xFF\xFF\x01\x50\x02\x01\x01\x31\xCE",
		NULL, 24, SCARD_GELDKARTE },
	{ ( const BYTE * ) "\x3F\x05\xDC\x20\xFC\x00\x01",
		NULL, 7, SCARD_DIGICASH },
	{ ( const BYTE * ) "\x3F\x67\x25\x00\x2A\x20\x00\x40\x68\x9F\x00",
		NULL, 11, SCARD_CHIPKNIP1 },
	{ ( const BYTE * ) "\x3F\x67\x25\x00\x2A\x20\x00\x41\x68\x90\x00",
		NULL, 11, SCARD_CHIPKNIP2_CC60 },
	{ ( const BYTE * ) "\x3F\x67\x25\x00\x2A\x20\x00\x6F\x68\x90\x00",
		NULL, 11, SCARD_CHIPKNIP2_CC1000 },
	{ ( const BYTE * ) "\x3F\x67\x2F\x00\x11\x14\x00\x03\x68\x90\x00",
		NULL, 11, SCARD_WAFERCARD },
	{ ( const BYTE * ) "\x3F\x6C\x00\x00\x24\xA0\x30\x00\xFF\x00\x00\x01\x00\x04\x90\x00",
		NULL, 16, SCARD_COS },
	{ NULL, NULL, 0 }
	};

/* Determine the card type based on the ATR */

int getCardType( const BYTE *atr, const int atrLength )
	{
	int i;

	for( i = 0; atrTable[ i ].atr != NULL; i++ )
		{
		const BYTE *atrMask = atrTable[ i ].atrMask;
		int length = atrTable[ i ].atrLength;

		if( length != atrLength )
			continue;	/* Quick check for length match */
		if( atrMask == NULL && !memcmp( atr, atrTable[ i ].atr, length ) )
			return( atrTable[ i ].type );
		else
			{
			int j;

			/* There's a mask for the ATR, compare only the bytes which
			   aren't masked out */
			for( j = 0; j < length; j++ )
				if( atrTable[ i ].atrMask && \
					atrTable[ i ].atr[ j ] != atr[ j ] )
					break;
			if( j == length )
				return( atrTable[ i ].type );
			}
		}

	return( CRYPT_ERROR );
	}

/* Map a text string to a reader-specific magic number */

int stringToValue( const STRINGMAP_INFO *stringmapInfo, const char *string )
	{
	int i;

	for( i = 0; stringmapInfo[ i ].string != NULL; i++ )
		if( !stricmp( stringmapInfo[ i ].string, string ) )
			return( stringmapInfo[ i ].value );

	return( CRYPT_ERROR );
	}

/****************************************************************************
*																			*
*						 	Memory Smart Card Simulator						*
*																			*
****************************************************************************/

int createDF( const BYTE *path, const int size );
int createEF( const BYTE *path, const int size );
int readEF( const BYTE *path, BYTE *buffer, int *length );
int writeEF( const BYTE *path, const BYTE *buffer, const int length );

/* This code provides a software-only simulation of an ISO 7816-4 memory card
   with no crypto capabilities.  The virtual card represents an amalgamation
   of several widely-used cards, and has the following properties and
   limitations:

	- CARD_MEMSIZE memory
	- CARD_FILES files
	- Once created, files can't be resized or deleted (effectively, it's a
	  WORM) */

#define CARD_MEMSIZE	8192
#define CARD_FILES		16

typedef struct {
	BYTE path[ MAX_EF_PATHLEN ];	/* Path to the file */
	int pathLen;					/* Length of path */
	int offset, length;				/* Offset and size within card */
	} SC_FILEINFO;

static BYTE cardMemory[ CARD_MEMSIZE ];
static SC_FILEINFO cardDirectory[ CARD_FILES ];
static int cardMemoryAllocEnd, cardDirectoryLastEntry;

/* Find a directory entry for a given path */

static SC_FILEINFO *findPath( const BYTE *path )
	{
	int length = 0, i;

	while( path[ length ] && length < MAX_EF_PATHLEN )
		length += 2;
	for( i = 0; i < CARD_FILES; i++ )
		if( cardDirectory[ i ].pathLen == length && \
			!memcmp( cardDirectory[ i ].path, path, length ) )
			return( &cardDirectory[ i ] );

	return( NULL );
	}

/* Create a DF or EF of a given size */

int createDF( const BYTE *path, const int size )
	{
	SC_FILEINFO *fileInfo = findPath( path );

	/* Make sure it's a new dirctory and that there's room for it */
	if( fileInfo != NULL )
		return( CRYPT_DATA_DUPLICATE );
	if( CARD_MEMSIZE - cardMemoryAllocEnd < size )
		return( CRYPT_NOMEM );

	/* We ignore anything else to do with directories */
	if( size );		/* Get rid of compiler warning */

	return( CRYPT_OK );
	}

int createEF( const BYTE *path, const int size )
	{
	SC_FILEINFO *fileInfo = findPath( path );
	int i;

	/* Make sure it's a new dirctory and that there's room for it */
	if( fileInfo != NULL )
		return( CRYPT_DATA_DUPLICATE );
	if( CARD_MEMSIZE - cardMemoryAllocEnd < size )
		return( CRYPT_NOMEM );

	/* Add the new entry */
	fileInfo = &cardDirectory[ cardDirectoryLastEntry++ ];
	for( i = 0; path[ i ]; i += 2 )
		{
		fileInfo->path[ i ] = path[ i ];
		fileInfo->path[ i + 1 ] = path[ i + 1 ];
		}
	fileInfo->path[ i ] = '\0';		/* Add der terminador */
	fileInfo->pathLen = i;
	fileInfo->offset = cardMemoryAllocEnd;
	fileInfo->length = size;
	cardMemoryAllocEnd += size;

	return( CRYPT_OK );
	}

/* Read/write an EF */

int readEF( const BYTE *path, BYTE *buffer, int *length )
	{
	SC_FILEINFO *fileInfo = findPath( path );

	if( fileInfo == NULL )
		return( CRYPT_DATA_NOTFOUND );
	memcpy( buffer, cardMemory + fileInfo->offset, fileInfo->length );
	*length = fileInfo->length;
	return( CRYPT_OK );
	}

int writeEF( const BYTE *path, const BYTE *buffer, const int length )
	{
	SC_FILEINFO *fileInfo = findPath( path );

	if( fileInfo == NULL )
		return( CRYPT_DATA_NOTFOUND );
	if( fileInfo->length < length )
		return( CRYPT_OVERFLOW );
	memcpy( cardMemory + fileInfo->offset, buffer, length );
	return( CRYPT_OK );
	}

/* Initialise the emulator */

void init( void )
	{
	memset( cardMemory, 0, CARD_MEMSIZE );
	memset( cardDirectory, 0, sizeof( SC_FILEINFO ) * CARD_FILES );
	cardMemoryAllocEnd = cardDirectoryLastEntry = 0;
	}

/* Debugging function: Dump all EF's.  Assumes a Unix-like FS */

void dumpEFs( const char *filePath )
	{
	char fileName[ 128 ];
	int numberOffset, i;

	/* Build the path to the output files */
	if( strlen( filePath ) > 120 )
		return;
	strcpy( fileName, filePath );
	strcat( fileName, "/file" );
	numberOffset = strlen( fileName );

	/* Dump each EF to an output file */
	for( i = 0; i < cardDirectoryLastEntry; i++ )
		{
		FILE *filePtr;

		sprintf( fileName + numberOffset, "%d.der", i );
		if( ( filePtr = fopen( fileName, "wb" ) ) == NULL )
			continue;
		fwrite( cardMemory + cardDirectory[ i ].offset, 1,
				cardDirectory[ i ].length, filePtr );
		fclose( filePtr );
		}
	}

/****************************************************************************
*																			*
*						 PKCS #15 Object Read/Write Routines				*
*																			*
****************************************************************************/

/* This code is currently highly incomplete because PKCS #15 is still
   changing radically between releases */

/* Determine the length of a path */

static int pathLength( const BYTE *path )
	{
	int length = 0;

	while( path[ length ] && length < MAX_EF_PATHLEN )
		length += 2;
	return( length );
	}

/* Read/write a path to an EF */

static void writePath( STREAM *stream, const BYTE *path, const int tag )
	{
	BYTE *pathPtr = ( BYTE * ) path;
	int length = 0;

	/* Determine how long the path is */
	while( pathPtr[ length ] )
		length += 2;
	if( !length )
		return;		/* Nothing to write */

	/* Write the path.  Since the object is so short, we can cheat a bit in
	   the encoding of the lengths */
	writeCtag( stream, tag );
	writeLength( stream, length + 6 );
	writeCtag( stream, 0 );
	writeLength( stream, length + 4 );
	writeSequence( stream, length + 2 );
	writeTag( stream, BER_APPLICATION | 17 );
	writeLength( stream, length );
	while( *pathPtr )
		{
		swrite( stream, pathPtr, 2 );
		pathPtr += 2;
		}
	}

static void readPath( STREAM *stream, BYTE *path, const int tag )
	{
	long pathLen, dummy;
	int length;

	/* If this component isn't present, exit */
	if( !checkReadCtag( stream, tag, TRUE ) )
		return;

	/* Read the multiple layers of wrapping until we get to the actual path */
	readLength( stream, &dummy );
	if( !checkReadCtag( stream, 0, FALSE ) )
		{
		sSetError( stream, CRYPT_BADDATA );
		return;
		}
	readLength( stream, &dummy );
	readSequence( stream, &length );
	if( readTag( stream ) != ( BER_APPLICATION | 17 ) )
		{
		sSetError( stream, CRYPT_BADDATA );
		return;
		}
	readLength( stream, &pathLen );
	length -= 2 + ( int ) pathLen;
	if( pathLen > MAX_EF_PATHLEN )
		{
		sSetError( stream, CRYPT_BADDATA );
		return;
		}

	/* Read the path and skip the offset+length fields if they're present */
	if( pathLen )
		sread( stream, path, ( int ) pathLen );
	if( length > 0 )
		sSkip( stream, length );
	}

/* Read/write an ODF */

int readODF( const void *data, ODF_INFO *odfInfo )
	{
	STREAM stream;
	int status;

	memset( odfInfo, 0, sizeof( ODF_INFO ) );

	/* Read the header */
	sMemConnect( &stream, data, STREAMSIZE_UNKNOWN );
	readPath( &stream, odfInfo->prKDF, 0 );
	readPath( &stream, odfInfo->puKDF, 1 );
	readPath( &stream, odfInfo->sKDF, 2 );
	readPath( &stream, odfInfo->cDF, 3 );
	readPath( &stream, odfInfo->dODF, 4 );
	readPath( &stream, odfInfo->authDF, 5 );
	status = sGetStatus( &stream );
	sMemDisconnect( &stream );

	return( status );
	}

int writeODF( void *data, const ODF_INFO *odfInfo )
	{
	STREAM stream;

	/* Write the header */
	sMemConnect( &stream, data, STREAMSIZE_UNKNOWN );
	writePath( &stream, odfInfo->prKDF, 0 );
	writePath( &stream, odfInfo->puKDF, 1 );
	writePath( &stream, odfInfo->sKDF, 2 );
	writePath( &stream, odfInfo->cDF, 3 );
	writePath( &stream, odfInfo->dODF, 4 );
	writePath( &stream, odfInfo->authDF, 5 );
	sMemDisconnect( &stream );

	return( CRYPT_OK );
	}

/* Read/write an PrKDF */

int readPrKDF( const void *data, PRKDF_INFO *prKDFInfo )
	{
	STREAM stream;
	int status;

	memset( prKDFInfo, 0, sizeof( prKDFInfo ) );

	sMemConnect( &stream, data, STREAMSIZE_UNKNOWN );
	status = sGetStatus( &stream );
	sMemDisconnect( &stream );

	return( status );
	}

int writePrKDF( void *data, const PRKDF_INFO *prKDFInfo )
	{
	STREAM stream;

	UNUSED( prKDFInfo );

	sMemConnect( &stream, data, STREAMSIZE_UNKNOWN );
	sMemDisconnect( &stream );

	return( CRYPT_OK );
	}

/* Read/write a PINInfo EF */

int readPINInfo( const void *data )
	{
	STREAM stream;
	int length;

	/* Read the header */
	sMemConnect( &stream, data, STREAMSIZE_UNKNOWN );
	if( cryptStatusError( readSequence( &stream, &length ) ) || \
		cryptStatusError( readSequence( &stream, &length ) ) )
		{
		sMemDisconnect( &stream );
		return( CRYPT_BADDATA );
		}
	sMemDisconnect( &stream );

	return( CRYPT_OK );
	}

int writePINInfo( void *data )
	{
	STREAM stream;

	/* Write the header */
	sMemConnect( &stream, data, STREAMSIZE_UNKNOWN );
	writeSequence( &stream, ( int ) sizeofObject( 0 ) );
	writeSequence( &stream, 0 );
	sMemDisconnect( &stream );

	return( CRYPT_OK );
	}

/* Read/write a TokenInfo EF */

int readTokenInfo( const void *data )
	{
	STREAM stream;
	int length, status;

	/* Read the header */
	sMemConnect( &stream, data, STREAMSIZE_UNKNOWN );
	status = readSequence( &stream, &length );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	sMemDisconnect( &stream );

	return( CRYPT_OK );
	}

int writeTokenInfo( void *data )
	{
	STREAM stream;

	/* Write the header */
	sMemConnect( &stream, data, STREAMSIZE_UNKNOWN );
	writeSequence( &stream, 0 );
	sMemDisconnect( &stream );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 PKCS #15 File Manipulation Routines				*
*																			*
****************************************************************************/

/* Paths to DF's and EF's.  The DF, ODF, and TokenInfo paths are predefined,
   the others are left to implementors but simply following on from the
   existing ones seems logical */

#define PKCS15_PATH_DF			( BYTE * ) "\x3F\x00\x50\x15"
#define PKCS15_PATH_ODF			( BYTE * ) "\x3F\x00\x50\x15\x50\x31"
#define PKCS15_PATH_TOKENINFO	( BYTE * ) "\x3F\x00\x50\x15\x50\x32"
#define PKCS15_PATH_PRKDF		( BYTE * ) "\x3F\x00\x50\x15\x50\x33"
#define PKCS15_PATH_PUKDF		( BYTE * ) "\x3F\x00\x50\x15\x50\x34"
#define PKCS15_PATH_SKDF		( BYTE * ) "\x3F\x00\x50\x15\x50\x35"
#define PKCS15_PATH_CDF			( BYTE * ) "\x3F\x00\x50\x15\x50\x36"
#define PKCS15_PATH_DODF		( BYTE * ) "\x3F\x00\x50\x15\x50\x37"
#define PKCS15_PATH_AUTHDF		( BYTE * ) "\x3F\x00\x50\x15\x50\x38"

/*
read ODF

if( no PrKDF in ODF )
  {
  if( no ODF )
    ODF = new;
  add PrKDF to ODF;
  ODF = dirty;
  }
else
  read PrKDF

if( no PrKDF entry )
  {
  if( no PrKDF )
    PrKDF = new;
  add entry to PrKDF;
  PrKDF = dirty;
  }

if( no key file )
  keyfile = new;

if( ODF new )
  create ODF;
if( ODF dirty )
  write ODF;
if( PrKDF new )
  create PrKDF;
if( PrKDF dirty )
  write PrKDF;
if( PrKDF update failed && ODF new )
  delete PrKDF entry in ODF;
*/

int pkcs15Init( SCARD_INFO *scardInfo )
	{
	BYTE buffer[ 256 ];
	int length, status;

	memset( &scardInfo->odfInfo, 0, sizeof( ODF_INFO ) );

	/* Try and read the ODF */
	status = readEF( PKCS15_PATH_ODF, buffer, &length );
	if( cryptStatusOK( status ) )
		{
		/* There's an ODF present, decode the information */
		status = readODF( buffer, &scardInfo->odfInfo );
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		/* There's no ODF there, create a new one */
		if( status == CRYPT_DATA_NOTFOUND )
			scardInfo->odfInfo.new = TRUE;
		else
			return( status );

	/* If there's a PrKDF there, read it and decode it */
	if( scardInfo->odfInfo.prKDF[ 0 ] )
		{
		status = readEF( scardInfo->odfInfo.prKDF, buffer, &length );
		if( cryptStatusError( status ) )
			return( status );
		status = readPrKDF( buffer, &scardInfo->prKDFInfo );
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		{
		/* There's no PrKDF, create an entry in the ODF for it */
		scardInfo->odfInfo.dirty = TRUE;
		memcpy( scardInfo->odfInfo.prKDF, PKCS15_PATH_PRKDF,
				pathLength( PKCS15_PATH_PRKDF ) );
		}

	return( CRYPT_OK );
	}
