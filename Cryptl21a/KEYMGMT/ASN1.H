/****************************************************************************
*																			*
*						  ASN.1 Constants and Structures					*
*						Copyright Peter Gutmann 1992-1998					*
*																			*
****************************************************************************/

#ifndef _ASN1_DEFINED

#define _ASN1_DEFINED

#include <time.h>
#if defined( INC_CHILD )|| defined( INC_ALL )
  #include "stream.h"
  #include "ber.h"
#else
  #include "keymgmt/stream.h"
  #include "keymgmt/ber.h"
#endif /* Compiler-specific includes */

/* The following routines are an optimised subset of the original, very
   general ASN.1 library which began as a general-purpose ASN.1 class library
   but slowly mutated towards one which contained mostly special-purpose
   routines optimised for use with cryptlib.  This is about half the size and
   twice as fast as the original, and doesn't need to use or instatiate a new
   ASN.1 object every time you you call a function.

   The only thing worth noting is that the read() calls have two variants,
   the read() form which reads the basic ASN.1 object type and checks the
   tag, and the more general readData() form which only reads the data
   contained in the ASN.1 object but doesn't read the tag.

   A few (very minor) fragments of the original code remain, these are
   disabled when the following define is commented out */

/* #define STRICT_ASN1 */

/****************************************************************************
*																			*
*							Universal ASN.1 Structures						*
*																			*
****************************************************************************/

/* The default value for tagged types.  If this value is given the basic
   type is used, otherwise the value is used as a context-specific tag */

#define DEFAULT_TAG			-1

/* A non-tag.  If this value is given, processing of the tag is skipped */

#define NO_TAG				-2

/* When specifying a tag, we can use either the default tag for the object
   (given with DEFAULT_TAG) or a special-case tag.  The following macro
   selects the correct value */

#define selectTag( tag, default )	\
		( ( ( tag ) == DEFAULT_TAG ) ? ( default ) : ( tag ) )

/****************************************************************************
*																			*
*							ASN.1 Function Prototypes						*
*																			*
****************************************************************************/

/* Routines to read and write the identifier information for an ASN.1 value.
   These are occasionally needed by higher-level routines to handle a stream
   of complex ASN.1 structures involving constructed and choice types */

int readLength( STREAM *stream, long *length );
void writeLength( STREAM *stream, long length );

/* Generalized ASN.1 type manipulation routines */

int readUniversalData( STREAM *stream );
int readUniversal( STREAM *stream );

/* Routines for handling OBJECT IDENTIFIERS.  This determines the length of
   an encoded object identifier as tag + length + value.  Read/write OID
   routines equivalent to the ones for other ASN.1 types don't exist since
   OIDs are always read and written as a blob with sread()/swrite() */

#define sizeofOID( oid )	( 1 + 1 + ( int ) oid[ 1 ] )
#define writeOID( stream, oid ) \
							swrite( ( stream ), ( oid ), sizeofOID( oid ) )

/* Routines for handling bignum integers.  When we're writing these we can't
   use sizeofObject() directly because the internal representation is
   unsigned whereas the encoded form is signed.  The following macro performs
   the appropriate conversion on the data length before passing it on to
   sizeofObject() */

#define sizeofStaticInteger( value, valueLength ) \
		( int ) sizeofObject( ( valueLength ) + \
							  ( ( *( BYTE * )( value ) & 0x80 ) ? 1 : 0 ) )
int readStaticInteger( STREAM *stream, BYTE *integer, int *integerLength,
					   const int maxLength );
int writeStaticInteger( STREAM *stream, const BYTE *integer,
						const int integerLength, const int tag );

/* Generally most integers will be non-bignum values, so we also define
   routines to handle values which will fit into a machine word */

#define sizeofShortInteger( value )	\
	( ( ( value ) < 128 ) ? 3 : ( ( value ) < 32768L ) ? 4 : \
		( ( value ) < 8388608L ) ? 5 : ( ( value ) < 2147483648UL ) ? 6 : 7 )
int writeShortInteger( STREAM *stream, const long value, const int tag );
int readShortIntegerTag( STREAM *stream, long *value, const int tag );

#define readShortIntegerData( stream, integer )	\
		readShortIntegerTag( stream, integer, NO_TAG )
#define readShortInteger( stream, integer )	\
		readShortIntegerTag( stream, integer, DEFAULT_TAG )

/* Routines for handling enumerations */

#define sizeofEnumerated( value )	( ( ( value ) < 128 ) ? 3 : 4 )
int writeEnumerated( STREAM *stream, const int enumerated, const int tag );
int readEnumeratedTag( STREAM *stream, int *enumeration, const int tag );

#define readEnumeratedData( stream, enumeration ) \
		readEnumeratedTag( stream, enumeration, NO_TAG )
#define readEnumerated( stream, enumeration ) \
		readEnumeratedTag( stream, enumeration, DEFAULT_TAG )

/* Routines for handling booleans */

#define sizeofBoolean()	( sizeof( BYTE ) + sizeof( BYTE ) + sizeof( BYTE ) )
int writeBoolean( STREAM *stream, const BOOLEAN boolean, const int tag );
int readBooleanTag( STREAM *stream, BOOLEAN *boolean, const int tag );

#define readBooleanData( stream, boolean ) \
		readBooleanTag( stream, boolean, NO_TAG )
#define readBoolean( stream, boolean ) \
		readBooleanTag( stream, boolean, DEFAULT_TAG )

/* Routines for handling null values */

#define sizeofNull()	( sizeof( BYTE ) + sizeof( BYTE ) )
int writeNull( STREAM *stream, const int tag );
int readNullTag( STREAM *stream, const int tag );

#define readNullData( stream )	readNullTag( stream, NO_TAG )
#define readNull( stream )		readNullTag( stream, DEFAULT_TAG )

/* Routines for handling octet strings */

int writeOctetString( STREAM *stream, const BYTE *string, const int length, \
					  const int tag );
int readOctetStringTag( STREAM *stream, BYTE *string, int *stringLength,
						const int maxLength, const int tag );

#define readOctetStringData( stream, string, stringLength, maxLength ) \
		readOctetStringTag( stream, string, stringLength, maxLength, NO_TAG )
#define readOctetString( stream, string, stringLength, maxLength ) \
		readOctetStringTag( stream, string, stringLength, maxLength, DEFAULT_TAG )

/* Routines for handling character strings.  There are a number of oddball
   character string types which are all handled through the same functions -
   it's not worth having a seperate function to handle each of the half-dozen
   types.

   There's no equivalent readCharacterString function since the plethora of
   string types means the higher-level routines which read them invariably
   have to sort out the valid tag types themselves, after which the string
   itself can be read with readOctetStringData() */

int writeCharacterString( STREAM *stream, const BYTE *string,
						  const int length, const int tag );

/* Routines for handling bit strings.  The sizeof() values are 3 bytes for
   the tag, length, and surplus-bits value, and the data itself */

#define sizeofBitString( value )	\
	( 3 + ( ( ( value ) > 65535L ) ? 3 : ( ( value ) > 256 ) ? 2 : 1 ) )
int writeBitString( STREAM *stream, const int bitString, const int tag );
int readBitStringTag( STREAM *stream, int *bitString, const int tag );

#define readBitStringData( stream, bitString ) \
		readBitStringTag( stream, bitString, NO_TAG )
#define readBitString( stream, bitString ) \
		readBitStringTag( stream, bitString, DEFAULT_TAG )

/* Routines for handling UTC and Generalized time */

#define sizeofUTCTime()			( 1 + 1 + 13 )
int writeUTCTime( STREAM *stream, const time_t time, const int tag );
int readUTCTimeTag( STREAM *stream, time_t *time, const int tag );

#define readUTCTimeData( stream, time )	readUTCTimeTag( stream, time, NO_TAG )
#define readUTCTime( stream, time )		readUTCTimeTag( stream, time, DEFAULT_TAG )

#define sizeofGeneralizedTime()	( 1 + 1 + 15 )
int writeGeneralizedTime( STREAM *stream, const time_t time, const int tag );
int readGeneralizedTimeTag( STREAM *stream, time_t *time, const int tag );

#define readGeneralizedTimeData( stream, time )	\
		readGeneralizedTimeTag( stream, time, NO_TAG )
#define readGeneralizedTime( stream, time )	\
		readGeneralizedTimeTag( stream, time, DEFAULT_TAG )

/* Utilitity routines for reading and writing constructed objects */

int readSequence( STREAM *stream, int *length );
int readSet( STREAM *stream, int *length );
int writeSequence( STREAM *stream, const int length );
int writeSet( STREAM *stream, const int length );

/* Determine the length of an ASN.1-encoded object.  This just reads the
   outer length if present, but will burrow down into the object if necessary
   if the length is indefinite */

int getObjectLength( const void *certObjectPtr, const int length );

#endif /* !_ASN1_DEFINED */
