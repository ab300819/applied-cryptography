/****************************************************************************
*																			*
*						 Certificate String/DN Routines						*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "asn1.h"
  #include "asn1objs.h"
  #include "cert.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1objs.h"
  #include "keymgmt/cert.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*						Character Set Management Functions					*
*																			*
****************************************************************************/

/* Most systems now include some sort of support for various wide char
   functions.  We require wchar_t (not supported older DOS compilers and
   legacy Unixen), mbstowcs() (usually supported, but with varying degrees of
   success), and towlower() (everything from unsupported to token support to
   relatively good support).  In addition since wchar_t can be anything from
   8 bits (Borland C++ under DOS) to 64 bits (RISC Unixen), we define a
   bmpchar_t (short for Unicode/BMPString char) which is always 16 bits as
   required for BMPStrings.  The conversion to and from a BMPString and
   wchar_t may require narrowing or widening of characters, and possibly
   endianness conversion as well */

typedef unsigned short int bmpchar_t;		/* Unicode data type */
#if defined( __MSDOS16__ ) && !defined( __BORLANDC__ )
  typedef unsigned short int wchar_t;		/* Widechar data type */
#endif /* OS's which don't support wide chars */
#if defined( __BORLANDC__ ) && ( __BORLANDC__ == 0x410 )
  #define wchar_t unsigned short int	/* BC++ 3.1 has an 8-bit wchar_t */
#endif /* BC++ 3.1 */
#ifdef __UNIX__
  #if defined( __hpux ) || defined( _AIX )
	#include <wchar.h>
	#define HAS_TOWLOWER
  /* The following check tries to include the wcXXX stuff by default,
     which should work for most recent Unixen */
  #elif !( defined( __linux ) || ( defined( sun ) && OSVERSION < 5 ) || \
		   defined( __bsdi__ ) )
	#include <wctype.h>
	#define HAS_TOWLOWER
  #endif /* OS's which support towlower() */
#endif /* __UNIX__ */
#ifdef __WIN32__
  /* Win95 doesn't have Unicode support so we can't use CompareString()
	 since it compares ANSI rather than Unicode strings.  However there is
	 support for towlower() via the C library, so we can use the general
	 wchar_t comparison routines */
  #include <wchar.h>
  #define HAS_TOWLOWER
#endif /* __WIN32__ */

/* The CSTR_EQUAL define doesn't appear unless the October'97 MSDN stealth
   upgrade is installed, so we define it here if it's not already defined */

#if defined( __WIN32__ ) && !defined( CSTR_EQUAL )
  #define CSTR_EQUAL	2
#endif /* __WIN32__ && !CSTR_EQUAL */

/* Useful defines to help with scaling offsets and lengths for wchar_t and
   bmpchar_t strings */

#define WCSIZE	( sizeof( wchar_t ) )
#define UCSIZE	2

/* Because of the bizarre (and mostly useless) collection of ASN.1 character
   types, we need to be very careful about what we allow in a string.  The
   following table is used to determine whether a character is valid within
   certain string types.

   Although IA5String and VisibleString/ISO646String are technically
   different, the only real difference is that IA5String allows the full
   range of control characters, which isn't notably useful.  For this reason
   we treat both as ISO646String */

#define P	1						/* PrintableString */
#define I	2						/* IA5String/VisibleString/ISO646String */
#define PI	( P | I )				/* PrintableString and IA5String */

static const int charFlags[] = {
	/* 00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F */
		0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,
	/* 10  11  12  13  14  15  16  17  18  19  1A  1B  1C  1D  1E  1F */
		0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,
	/*		!	"	#	$	%	&	'	(	)	*	+	,	-	.	/ */
	   PI,	I,	I,	I,	I,	I,	I, PI, PI, PI,	I, PI, PI, PI, PI, PI,
	/*	0	1	2	3	4	5	6	7	8	9	:	;	<	=	>	? */
	   PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI,	I,	I, PI,	I, PI,
	/*	@	A	B	C	D	E	F	G	H	I	J	K	L	M	N	O */
		I, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI,
	/*	P	Q	R	S	T	U	V	W	X	Y	Z	[	\	]	^	_ */
	   PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI,	I,	I,	I,	I,	I,
	/*	`	a	b	c	d	e	f	g	h	i	j	k	l	m	n	o */
		I, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI,
	/*	p	q	r	s	t	u	v	w	x	y	z	{	|	}	~  DL */
	   PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI,	I,	I,	I,	I,	0
	};

/* Try and guess whether a byte string is a widechar or BMPString */

static BOOLEAN isWidecharString( const BYTE *string, const int length )
	{
	wchar_t *wcString = ( wchar_t * ) string;
	int i;

	/* Check for a Unicode BOM at the start of the string */
	if( *wcString == 0xFFFE || *wcString == 0xFEFF )
		return( TRUE );		/* Definitely Unicode with a BOM */

#if !defined( __MSDOS16__ ) && !defined( __WIN16__ )
	/* If wchar_t is > 16 bits and the bits above 16 are set or all zero,
	   it's either definitely not Unicode or Unicode */
	if( WCSIZE > 2 )
		return( ( *wcString > 0x0FFFF ) ? FALSE : TRUE );
#endif /* > 16-bit machines */

	/* wchar_t is 16 bits, check whether it's in the form 00 xx 00 xx.  The
	   code used is safe because to get to this point the string has to be
	   some multiple of 2 bytes long.  Note that if someone passes in a
	   1-byte string and mistakenly includes the terminator in the length
	   it'll be identified as a 16-bit widechar string, but this doesn't
	   really matter since it'll get "converted" into a non-widechar string
	   later */
	for( i = 0; i < length; i += 2 )
		{
		if( *wcString > 0xFF )
			return( FALSE );	/* Probably 8-bit chars */
		wcString++;
		}

	return( TRUE );				/* Probably 16-bit chars */
	}

static BOOLEAN isBMPString( const BYTE *string, const int length )
	{
	int i;

	/* This one is rather tricky, it's necessary because some broken
	   implementations will stuff anything which isn't an ASCII string
	   (including Unicode) into a T61String.  The easiest check to weed
	   these things out is to check whether the entire string looks like a
	   generic T61String, if it does we treat the string as a T61String,
	   otherwise it's Unicode */
	for( i = 0; i < length; i++ )
		{
		BYTE ch = string[ i ];

		if( !( charFlags[ ch & 0x7F ] & I ) )
			return( TRUE );		/* Probably non-T61String chars */
		}

	return( FALSE );			/* Probably T61String chars */
	}

/* Try and figure out the ASN.1 string type for a string.  This detects (or
   at least tries to detect) not only the basic string type, but also basic
   string types encoded as widechar strings, and BMPStrings encoded as basic
   string types */

static ASN1_STRINGTYPE getStringType( const BYTE *string, int length,
									  const BOOLEAN isASN1string )
	{
	BOOLEAN notPrintable = FALSE, notIA5 = FALSE;

	/* Check for bad input values */
	if( string == NULL || length < 1 )
		return( STRINGTYPE_NONE );

	/* Try and figure out whether it's a widechar or BMPString.  The non-
	   Win32 version uses all sorts of ad-hockery to try and guess whether a
	   string is a widechar/BMPString one or not.  This usually works, but
	   probably mainly because we rarely encounter widechar/BMPString
	   strings */
#ifdef __WIN32__
	if( !isWin95 )
		{
		/* Try and guess whether the thing is Unicode.  This only works under
		   NT, the function is present under Win95 but doesn't do anything */
		if( IsTextUnicode( ( CONST LPVOID ) string, length, NULL ) )
			return( STRINGTYPE_UNICODE );
		}
	else
#endif /* __WIN32__ */
	if( !isASN1string )
		{
		/* If it a multiple of wchar_t or bmpchar_t in size, check whether it's
		   a widechar string.  If it's a widechar string it may actually be
		   something else which has been bloated out into widechars, so we
		   check for this as well */
		if( !( length % WCSIZE ) && isWidecharString( string, length ) )
			{
			wchar_t *wcString = ( wchar_t * ) string;

			/* Make sure we don't include the BOM in the test */
			if( *wcString == 0xFFFE || *wcString == 0xFEFF )
				{ wcString++; length -= WCSIZE; }

			while( length > 0 )
				{
				wchar_t ch = *wcString;

				/* If the high bit is set, it's not an ASCII subset */
				if( ch >= 128 )
					{
					notPrintable = notIA5 = TRUE;
					if( !charFlags[ ch & 0x7F ] )
						/* It's not 8859-1 either */
						return( STRINGTYPE_UNICODE );
					}
				else
					/* Check whether it's a PrintableString */
					if( !( charFlags[ ch ] & P ) )
						notPrintable = TRUE;

				wcString++;
				length -= WCSIZE;
				}

			return( notIA5 ? STRINGTYPE_UNICODE_T61 : notPrintable ? \
					STRINGTYPE_UNICODE_IA5 : STRINGTYPE_UNICODE_PRINTABLE );
			}
		}
	else
		/* If it's a multiple of bmpchar_t in size, check whether it's a
		   BMPString stuffed into a T61String or an 8-bit string encoded as
		   a BMPString */
		if( !( length % UCSIZE ) )
			{
			bmpchar_t *bmpString = ( bmpchar_t * ) string;
			int stringLength = length;

			if( isBMPString( string, length ) )
				return( STRINGTYPE_UNICODE );

			/* If the first character is a null, it's an 8-bit string stuffed
			   into a BMPString */
			if( !*string )
				{
				while( stringLength > 0 )
					{
					bmpchar_t ch = *bmpString;

					/* If the high bit is set, it's not an ASCII subset */
					if( ch >= 128 )
						{
						notPrintable = notIA5 = TRUE;
						if( !charFlags[ ch & 0x7F ] )
							/* It's not 8859-1 either */
							return( STRINGTYPE_UNICODE );
						}
					else
						/* Check whether it's a PrintableString */
						if( !( charFlags[ ch ] & P ) )
							notPrintable = TRUE;

					bmpString++;
					stringLength -= UCSIZE;
					}

				return( notIA5 ? STRINGTYPE_UNICODE_T61 : notPrintable ? \
						STRINGTYPE_UNICODE_IA5 : STRINGTYPE_UNICODE_PRINTABLE );
				}
			}

	/* Walk down the string checking each character */
	while( length-- )
		{
		BYTE ch = *string;

		/* If the high bit is set, it's not an ASCII subset */
		if( ch >= 128 )
			{
			notPrintable = notIA5 = TRUE;
			if( !charFlags[ ch & 0x7F ] )
				/* It's not 8859-1 either, probably some odd widechar type */
				return( STRINGTYPE_NONE );
			}
		else
			{
			/* Check whether it's a PrintableString */
			if( !( charFlags[ ch ] & P ) )
				notPrintable = TRUE;

			/* Check whether it's something peculiar */
			if( !charFlags[ ch ] )
				return( STRINGTYPE_NONE );
			}

		string++;
		}

	return( notIA5 ? STRINGTYPE_T61 : notPrintable ? STRINGTYPE_IA5 : \
			STRINGTYPE_PRINTABLE );
	}

/* The SET string type is much more sensible, we map the ASN.1 string types
   to the subset used by SET */

static ASN1_STRINGTYPE getSETStringType( const BYTE *string, const int length,
										 const BOOLEAN isASN1string )
	{
	ASN1_STRINGTYPE type = getStringType( string, length, isASN1string );

	/* If it can be translated directly to a SETString type, use that */
	if( type == STRINGTYPE_IA5 || type == STRINGTYPE_PRINTABLE )
		return( STRINGTYPE_VISIBLE );
	if( type == STRINGTYPE_UNICODE || type == STRINGTYPE_UNICODE_T61 )
		return( STRINGTYPE_UNICODE );
	if( type == STRINGTYPE_UNICODE_IA5 || type == STRINGTYPE_UNICODE_PRINTABLE )
		return( STRINGTYPE_UNICODE_VISIBLE );

	/* It can't be directly translated, we need to convert it to Unicode */
	return( STRINGTYPE_T61_UNICODE );
	}

/* Convert a character string into a format in which it can be used in a
   certificate.  This copies the string across unchanged if it'll fit into
   the allowed 8-bit string type, or converts it to Unicode if it won't (see
   the "X.509 Style Guide" for the rationale behind this).  The Unicode
   conversion is rather OS-dependant, under Windows NT we can Do It Right,
   under environments which support mbstowc() we can Do It As Right As The
   Implementation Gets It, but in other environments we just assume ISO
   8859-1 and do a brute-force conversion (this is actually equivalent to
   what a lot of mbstowc() implementations do) */

ASN1_STRINGTYPE copyConvertString( const void *source, const int sourceLen,
								   void *dest, int *destLen, const int maxLen,
								   const BOOLEAN isSETString,
								   const BOOLEAN isASN1string )
	{
	ASN1_STRINGTYPE stringType;

	/* Set default return values */
	*destLen = 0;

	/* Determine the string type */
	if( isSETString )
		stringType = getSETStringType( source, sourceLen, isASN1string );
	else
		stringType = getStringType( source, sourceLen, isASN1string );

	/* If it's Unicode or something masquerading as Unicode, convert it to
	   the appropriate format.  Note that STRINGTYPE_UNICODE_VISIBLE is
	   already covered by STRINGTYPE_UNICODE_IA5, so we don't need to check
	   for this seperately */
	if( stringType == STRINGTYPE_UNICODE || \
		stringType == STRINGTYPE_UNICODE_PRINTABLE || \
		stringType == STRINGTYPE_UNICODE_IA5 || \
		stringType == STRINGTYPE_UNICODE_T61 )
		{
		wchar_t *srcPtr = ( wchar_t * ) source;
		int length = sourceLen;
		BYTE *destPtr;

		/* If it's from an ASN.1 source (ie it's a BMPString) and contains
		   an intrinsically narrower character type, copy it across to the
		   narrower string type */
		if( isASN1string && stringType != STRINGTYPE_UNICODE )
			{
			bmpchar_t *bmpSrcPtr = ( bmpchar_t * ) source;
			int i;

			if( length / UCSIZE > maxLen )
				return( STRINGTYPE_NONE );
			destPtr = dest;
			for( i = 0; i < length; i += UCSIZE )
				{
#ifdef DATA_LITTLEENDIAN
				*destPtr++ = ( BYTE ) ( *bmpSrcPtr++ >> 8 );
#else
				*destPtr++ = *bmpSrcPtr++;
#endif /* DATA_LITTLEENDIAN */
				}
			*destLen = length / UCSIZE;

			/* Return the converted string type */
			return( stringType - 1 );
			}

		/* If the first character is a BOM, skip it */
		if( *srcPtr == 0xFFFE || *srcPtr == 0xFEFF )
			{
			srcPtr++;
			length -= WCSIZE;
			}

		/* If it's a pure Unicode string, copy it across, converting from
		   wchar_t to bmpchar_t as we go.  Since the internal/encoded form of
		   a Unicode string is a BMPString, if we're running on a little-
		   endian system we also convert it to big-endian */
		if( stringType == STRINGTYPE_UNICODE )
			{
			bmpchar_t *bmpDestPtr = ( bmpchar_t * ) dest;
			int newSize = ( length / WCSIZE ) * UCSIZE, i;

			if( newSize > maxLen )
				return( STRINGTYPE_NONE );
			for( i = 0; i < length; i += WCSIZE )
				{
				wchar_t ch = *srcPtr++;
#ifdef DATA_LITTLEENDIAN
				ch = ( ( ch & 0xFF ) << 8 ) | ( ch >> 8 );
#endif /* DATA_LITTLEENDIAN */
				*bmpDestPtr++ = ch;
				}
			*destLen = newSize;

			return( STRINGTYPE_UNICODE );
			}

		/* It's some 8-bit string type masquerading as a Unicode string,
		   convert the characters to the 8-bit string type */
		if( ( int ) ( length / WCSIZE ) > maxLen )
			return( STRINGTYPE_NONE );
		destPtr = dest;
		while( *srcPtr )
			*destPtr++ = ( BYTE ) *srcPtr++;
		*destLen = length / WCSIZE;

		/* Return the converted string type */
		return( stringType - 1 );
		}

	/* If it's a non-Unicode string which needs to be recoded as Unicode,
	   convert it to Unicode */
	if( stringType == STRINGTYPE_T61_UNICODE )
		{
#ifdef DATA_LITTLEENDIAN
		bmpchar_t *bmpStrPtr;
		int destChars, i;
#endif /* LITTLE_ENDIA */

		if( sourceLen * UCSIZE > maxLen )
			return( STRINGTYPE_NONE );
#ifdef __WIN32__
		/* It's some non-Unicode string, convert it to Unicode */
		*destLen = MultiByteToWideChar( GetACP(), 0, source, -1, dest,
										sourceLen ) * UCSIZE;
#else
  #ifndef NO_WIDECHAR
	#if defined( __MSDOS16__ ) || defined( __WIN16__ )
		/* If the widechar set is Unicode, convert it directly */
		*destLen = mbstowcs( dest, source, sourceLen ) * UCSIZE;
	#else
	if( WCSIZE == UCSIZE )
		/* If the widechar set is Unicode, convert it directly */
		*destLen = mbstowcs( dest, source, sourceLen ) * UCSIZE;
	else
		{
		/* It's a character set in the native word size, convert it up to
		   this and then back down to a BMPString */
		wchar_t wcTemp[ CRYPT_MAX_TEXTSIZE + 1 ], *wcTmpPtr = wcTemp;
		bmpchar_t *bmpDestPtr = dest;
		int length, i;

		length = mbstowcs( wcTemp, source, sourceLen );
		for( i = 0; i < length; i++ )
			*bmpDestPtr++ = ( bmpchar_t ) *wcTmpPtr++;
		*destLen = length * WCSIZE;
		}
	#endif /* 16-bit machines */
  #else
		/* No wide char support, do a brute-force conversion of 8-bit char to
		   BMPString */
		BYTE sourcePtr = ( BYTE * ) source;
		bmpchar_t *bmpDestPtr = dest;

		while( *sourcePtr )
			*bmpDestPtr++ = *sourcePtr++;
		*destLen = sourceLen * UCSIZE;	/* Unicode = RAM vendor conspiracy */
  #endif /* NO_WIDECHAR */
#endif /* OS-specific Unicode processing */
#ifdef DATA_LITTLEENDIAN
		/* BMPString characters are always big-endian, so we need to convert
		   them if the string was generated on a little-endian system */
		bmpStrPtr = dest;
		destChars = *destLen / UCSIZE;
		for( i = 0; i < destChars; i++ )
			bmpStrPtr[ i ] = ( ( bmpStrPtr[ i ] & 0xFF ) << 8 ) | \
							   ( bmpStrPtr[ i ] >> 8 );
#endif /* DATA_LITTLEENDIAN */

		/* Now it's a BMPString */
		return( STRINGTYPE_UNICODE );
		}

	/* It's not Unicode, just copy it across */
	if( sourceLen > maxLen )
		return( STRINGTYPE_NONE );
	memcpy( dest, source, sourceLen );
	*destLen = sourceLen;

	return( stringType );
	}

/* Convert a UTF-8 string to ASCII, 8859-1, or Unicode */

static const int utf8bytesTbl[] = {
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6
	};

#define utf8bytes( value )	( ( value <= 192 ) ? 1 : \
							  ( value <= 224 ) ? 2 : \
							  utf8bytesTbl[ ( value ) - 224 ] )

ASN1_STRINGTYPE convertFromUTF8( BYTE *destPtr, int *destLen,
								 const BYTE *srcPtr, const int srcLen )
	{
	static const LONG offsetFromUTF8[] = {
		0x00000000UL, 0x00003080UL, 0x000E2080UL,
		0x03C82080UL, 0xFA082080UL, 0x82082080UL
		};
	ASN1_STRINGTYPE stringType = STRINGTYPE_PRINTABLE;
	int i = 0;

	/* Clear the return value */
	*destLen = 0;

	/* Scan the string to determine the widest character type in it */
	while( i < srcLen )
		{
		LONG ch = 0;
		int count = utf8bytes( *srcPtr ), j;

		/* Parse one character from the string */
		i += count;
		if( i > srcLen )
			return( STRINGTYPE_NONE );
		for( j = 0; j < count; j++ )
			{
			ch <<= 6;
			ch += *srcPtr++;
			}
		ch -= offsetFromUTF8[ count - 1 ];

		/* Check which range it fits into */
		if( !( charFlags[ ( int ) ch ] & P ) )
			{
			/* If it's not a PrintableString char, mark it as T61 if it's
			   within range and we haven't already hit a Unicode char */
			if( ch < 0xFF && ( charFlags[ ( int ) ch & 0x7F ] & I ) && \
				stringType != STRINGTYPE_UNICODE )
				stringType = STRINGTYPE_T61;
			else
				stringType = STRINGTYPE_UNICODE;
			}
		}

	/* Perform a second pass copying the string over */
	i = 0;
	while( i < srcLen )
		{
		LONG ch = 0;
		int count = utf8bytes( *srcPtr ), j;

		/* Parse one character from the string */
		i += count;
		if( i > srcLen )
			return( STRINGTYPE_NONE );
		for( j = 0; j < count; j++ )
			{
			ch <<= 6;
			ch += *srcPtr++;
			}
		ch -= offsetFromUTF8[ count - 1 ];

		/* If the result won't fit into a Unicode character, replace it with
		   a kanitvustan */
		if( ch > 0xFFFF )
			ch = 0xFFFD;

		/* Copy the result as a Unicode or ASCII/8859-1 character */
		if( stringType == STRINGTYPE_UNICODE )
			{
			*destPtr++ = ( BYTE ) ( ch >> 8 );
			( *destLen )++;
			}
		*destPtr++ = ( BYTE ) ch;
		( *destLen )++;
		}

	return( stringType );
	}

/* Strip leading, trailing, and repeated internal spaces from an ASN.1
   string.  This gets somewhat complicated because there are many ways of
   encoding a space.  The best we can do is to assume that either 0x20 or
   0xA0 are spaces */

#ifdef DATA_BIGENDIAN
  #define ASCII_SPC		0x0020
  #define ASCII_NBS		0x00A0
#else
  #define ASCII_SPC		0x2000
  #define ASCII_NBS		0xA000
#endif /* Endianness-dependant ASCII-in-Unicode values */

static int stripASN1spaces( void **string, int length, BOOLEAN isUnicode )
	{
	BYTE *strptr = *string;
	int i = 2;

	if( isUnicode )
		{
		bmpchar_t *bmpStrptr = *string;

		/* Convert the length value from bytes to Unicode characters */
		length /= UCSIZE;

		/* Strip leading and trailing spaces */
		while( length && ( *bmpStrptr == ASCII_SPC || *bmpStrptr == ASCII_NBS ) )
			{ bmpStrptr++; length --; }
		while( length && ( bmpStrptr[ length - 1 ] == ASCII_SPC || \
						   bmpStrptr[ length - 1 ] == ASCII_NBS ) )
			length--;

		/* Strip internal spaces */
		while( i <= length - 2 )
			{
			if( ( bmpStrptr[ i - 1 ] == ASCII_SPC || bmpStrptr[ i - 1 ] == ASCII_NBS ) && \
				( bmpStrptr[ i ] == ASCII_SPC || bmpStrptr[ i ] == ASCII_NBS ) )
				{
				memmove( bmpStrptr + i, bmpStrptr + i + 1, \
						 ( length - ( i + 1 ) ) * UCSIZE );
				length--;
				}
			else
				i++;
			}

		return( length * UCSIZE );
		}

	/* Strip leading and trailing spaces */
	while( length && ( *strptr == 0x20 || *strptr == 0xA0 ) )
		{ strptr++; length--; }
	while( length && ( strptr[ length - 1 ] == 0x20 || \
					   strptr[ length - 1 ] == 0xA0 ) )
		length--;

	/* Strip internal spaces */
	while( i <= length - 2 )
		{
		if( ( strptr[ i - 1 ] == 0x20 || strptr[ i - 1 ] == 0xA0 ) && \
			( strptr[ i ] == 0x20 || strptr[ i ] == 0xA0 ) )
			{
			memmove( strptr + i, strptr + i + 1, length - ( i + 1 ) );
			length--;
			}
		else
			i++;
		}

	return( length );
	}

/* Compare two ASN.1 strings in a case-insensitive manner.  This is only
   guaranteed to work for straight ASCII strings, for everything else it
   ranges from pure guesswork (most systems) to bare bones support (8859-1
   only under Solaris, PHUX, AIX) to vague support (Unicode under Win95,
   OSF/1) to reasonable support (Windows NT) */

BOOLEAN compareASN1string( const void *string1, const int string1len,
						   const void *string2, const int string2len )
	{
	BYTE str1[ ( CRYPT_MAX_TEXTSIZE + 1 ) * 2 ], *str1ptr = str1;
	BYTE str2[ ( CRYPT_MAX_TEXTSIZE + 1 ) * 2 ], *str2ptr = str2;
	BOOLEAN str1unicode = FALSE, str2unicode = FALSE;
	int str1len, str2len;

#if defined( __BORLANDC__ ) && ( __BORLANDC__ == 0x410 )
	/* Borland C++ 3.1 has an 8-bit wchar_t which causes problems with the
	   conversion code above which assumes wchar_t is at least as wide as a
	   BMPString char, so we set the whole array to zero before converting
	   the string which means any extraneous positions will have identical
	   values */
	memset( str1, 0, ( ( CRYPT_MAX_TEXTSIZE + 1 ) * 2 ) );
	memset( str2, 0, ( ( CRYPT_MAX_TEXTSIZE + 1 ) * 2 ) );
#endif /* BC++ 3.1 */

	/* First we convert the strings into canonical form, either ASCII or
	   Unicode.  We can't rely on the encoded type because some
	   implementations will stuff almost anything (including Unicode) into a
	   T61String, so we try and guess the exact type ourselves and then
	   convert it to a type we can work with.  By forcing a conversion to a
	   SETString we end up with either ASCII or Unicode */
	if( copyConvertString( string1, string1len, str1, &str1len,
						   CRYPT_MAX_TEXTSIZE, TRUE, TRUE ) == STRINGTYPE_UNICODE )
		str1unicode = TRUE;
	if( copyConvertString( string2, string2len, str2, &str2len,
						   CRYPT_MAX_TEXTSIZE, TRUE, TRUE ) == STRINGTYPE_UNICODE )
		str2unicode = TRUE;

	/* If one can only be represented in Unicode and the other is fine as
	   ASCII, they're definitely different.  After this test, they're either
	   both ASCII or both Unicode */
	if( ( str1unicode && !str2unicode ) || ( !str1unicode && str2unicode ) )
		return( FALSE );

	/* Now we have to strip leading, trailing, and internal spaces.  This
	   gets somewhat complicated because there are many ways of encoding a
	   space.  If the stripped strings differ in length after they've been
	   stripped, they're different */
	str1len = stripASN1spaces( ( void ** ) &str1ptr, str1len, str1unicode );
	str2len = stripASN1spaces( ( void ** ) &str2ptr, str2len, str2unicode );
	if( str1len != str2len )
		return( FALSE );

#ifdef __WIN32__
	/* Compare the string using the Win32 native string compare function.
	   Under NT this compares Unicode strings, under Win95 it only compares
	   ANSI strings so we can only use it under NT.  When making the
	   comparison, we ignore the string case, there are other options as
	   well but these probably aren't useful */
	if( !isWin95 )
		return( ( CompareString( LOCALE_USER_DEFAULT, NORM_IGNORECASE, str1ptr,
					str1len / UCSIZE, str2ptr, str2len / UCSIZE ) == CSTR_EQUAL ) ? \
				TRUE : FALSE );
#else
	/* If it's a Unicode string, we try to perform the comparison in a case-
	   insensitive manner.  This is almost impossible to do, the few systems
	   which support towlower() only include fairly patchy support for the
	   full Unicode character range (many only support 8859-1), or handle
	   things in a locale-specific manner (for example if the current locale
	   supports the given Unicode characters, the conversion works, otherwise
	   the character is returned unchanged) */
	if( str1unicode )
		{
		while( str1len )
			{
			wchar_t ch1, ch2;

			/* Extract the next two characters from the string */
			ch1 = mgetBWord( str1ptr );
			ch2 = mgetBWord( str2ptr );

  #ifdef HAS_TOWLOWER
			if( towlower( ch1 ) != towlower( ch2 ) )
				break;
  #else
			/* If there's no support for towlower(), the best we can do is
			   try to convert single-octet characters as if they were ASCII/
			   8859-1, and compare the rest unchanged.  Note that we go for
			   the full 8-bit range in tolower() for the systems which do
			   support 8859-1 for this function, the worst that can happen is
			   that the value will be returned unchanged */
			if( ch1 <= 0xFF && ch2 <= 0xFF )
				{
				if( tolower( ch1 ) != tolower( ch2 ) )
					break;
				}
			else
				if( ch1 != ch2 )
					break;
  #endif /* HAS_TOWLOWER */
			str1len -= UCSIZE;
			}

		return( str1len ? FALSE : TRUE );
		}

	/* It's an ASCII string, do a straight case-insensitive comparison */
	return( !strnicmp( ( char * ) str1ptr, ( char * ) str2ptr, str1len ) ? \
			TRUE : FALSE );
#endif /* __WIN32__ */
	}

/****************************************************************************
*																			*
*						Distinguished Name Management Functions				*
*																			*
****************************************************************************/

/* Short form names for DN attributes:

	BC		Business Category
	C		Country
	CN		Common Name
	D		Description
	EMAIL	email address (PKCS #9)
	L		Locality
	O		Organisation
	OU		Organisational Unit
	S		Surname
	SN		Serial Number
	SP		State or Province
	ST		Street Address
	T		Title
	DC		Domain component (weird kludge for DNS names in a DN) */

/* The sort order for DN components */

static int dnSortTable[] = {
	0,								/* countryName */
	1,								/* stateOrProvinceName */
	2,								/* locationName */
	3,								/* organizationName */
	4,								/* organizationalUnitName */
	5								/* commonName */
	};

#define dnSortOrder( value )	\
		dnSortTable[ ( value ) - CRYPT_CERTINFO_COUNTRYNAME ]

/* A macro to make make declaring DN OID's simpler */

#define MKDNOID( value )	( ( const BYTE * ) "\x06\x03" value )

/* Type information for DN components */

typedef struct {
	const CRYPT_CERTINFO_TYPE type;	/* cryptlib type */
	const BYTE *oid;				/* OID for this type */
	const BOOLEAN IA5OK;			/* Whether IA5 is allowed for this comp.*/
	} DN_COMPONENT_INFO;

static const DN_COMPONENT_INFO certInfoOIDs[] = {
	/* Useful components */
	{ CRYPT_CERTINFO_COMMONNAME, MKDNOID( "\x55\x04\x03" ), FALSE },
	{ CRYPT_CERTINFO_COUNTRYNAME, MKDNOID( "\x55\x04\x06" ), FALSE },
	{ CRYPT_CERTINFO_LOCALITYNAME, MKDNOID( "\x55\x04\x07" ), FALSE },
	{ CRYPT_CERTINFO_STATEORPROVINCENAME, MKDNOID( "\x55\x04\x08" ), FALSE },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, MKDNOID( "\x55\x04\x0A" ), FALSE },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, MKDNOID( "\x55\x04\x0B" ), FALSE },

	/* Non-useful components */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x01" ), FALSE },	/* aliasObjectName (2 5 4 1) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x02" ), FALSE },	/* knowledgeInformation (2 5 4 2) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x04" ), FALSE },	/* surname (2 5 4 4) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x05" ), FALSE },	/* serialNumber (2 5 4 5) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x09" ), FALSE },	/* streetAddress (2 5 4 9) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x0C" ), FALSE },	/* title (2 5 4 12) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x0D" ), FALSE },	/* description (2 5 4 13) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x0E" ), FALSE },	/* searchGuide (2 5 4 14) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x0F" ), FALSE },	/* businessCategory (2 5 4 15) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x10" ), FALSE },	/* postalAddress (2 5 4 16) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x11" ), FALSE },	/* postalCode (2 5 4 17) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x12" ), FALSE },	/* postOfficeBox (2 5 4 18) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x13" ), FALSE },	/* physicalDeliveryOfficeName (2 5 4 19) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x14" ), FALSE },	/* telephoneNumber (2 5 4 20) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x15" ), FALSE },	/* telexNumber (2 5 4 21) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x16" ), FALSE },	/* teletexTerminalIdentifier (2 5 4 22) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x17" ), FALSE },	/* facsimileTelephoneNumber (2 5 4 23) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x18" ), FALSE },	/* x121Address (2 5 4 24) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x19" ), FALSE },	/* internationalISDNNumber (2 5 4 25) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x1A" ), FALSE },	/* registeredAddress (2 5 4 26) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x1B" ), FALSE },	/* destinationIndicator (2 5 4 27) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x1C" ), FALSE },	/* preferredDeliveryMehtod (2 5 4 28) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x1D" ), FALSE },	/* presentationAddress (2 5 4 29) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x1E" ), FALSE },	/* supportedApplicationContext (2 5 4 30) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x1F" ), FALSE },	/* member (2 5 4 31) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x20" ), FALSE },	/* owner (2 5 4 32) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x21" ), FALSE },	/* roleOccupant (2 5 4 33) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x22" ), FALSE },	/* seeAlso (2 5 4 34) */
																/* 0x23-0x28 are certs/CRLs */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x29" ), FALSE },	/* name (2 5 4 41) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x2A" ), FALSE },	/* givenName (2 5 4 42) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x2B" ), FALSE },	/* initials (2 5 4 43) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x2C" ), FALSE },	/* generationQualifier (2 5 4 44) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x2D" ), FALSE },	/* uniqueIdentifier (2 5 4 45) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x2E" ), FALSE },	/* dnQualifier (2 5 4 46) */
																/* 0x2F-0x30 are directory components */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x31" ), FALSE },	/* distinguishedName (2 5 4 49) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x32" ), FALSE },	/* uniqueMember (2 5 4 50) */
	{ CRYPT_CERTINFO_NONE, MKDNOID( "\x55\x04\x33" ), FALSE },	/* houseIdentifier (2 5 4 51) */
																/* 0x34-0x3A are more certs */
	{ CRYPT_CERTINFO_NONE, ( const BYTE * ) "\x06\x09\x09\x92\x26\x89\x93\xF2\x2C\x01\x03", TRUE },
							/* rfc822Mailbox (0 9 2342 19200300 1 3) */
	{ CRYPT_CERTINFO_NONE, ( const BYTE * ) "\x06\x0A\x09\x92\x26\x89\x93\xF2\x2C\x64\x01\x01", TRUE },
							/* domainComponent (0 9 2342 19200300 100 1 25) */
	{ CRYPT_CERTINFO_NONE, ( const BYTE * ) "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x01", TRUE },
							/* emailAddress (1 2 840 113549 1 9 1) */

	{ CRYPT_CERTINFO_NONE, NULL }
	} ;

/* The size of DN OID - these are always 5 bytes long */

#define DN_OID_SIZE		5

/* If the OID doesn't correspond to a valid cryptlib component (ie it's one
   of the 1,001 other odd things which can be crammed into a DN), we can't
   directly identify it with a type but instead return the index in the OID
   info table, offset by a suitable amount */

#define DN_OID_OFFSET	1000

/* Check that a country code is valid */

static BOOLEAN checkCountryCode( const char *countryCode )
	{
	const static char *countryCodes[] = {
		"AD", "AE", "AF", "AG", "AI", "AL", "AM", "AN", "AO", "AQ",
		"AR", "AS", "AT", "AU", "AW", "AZ", "BA", "BB", "BD", "BE",
		"BF", "BG", "BH", "BI", "BJ", "BM", "BN", "BO", "BR", "BS",
		"BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CF", "CG", "CH",
		"CI", "CK", "CL", "CM", "CN", "CO", "CR", "CU", "CV", "CX",
		"CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE",
		"EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO",
		"FR", "FX", "GA", "GB", "GD", "GE", "GF", "GH", "GI", "GL",
		"GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY",
		"HK", "HM", "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IN",
		"IO", "IQ", "IR", "IS", "IT", "JM", "JO", "JP", "KE", "KG",
		"KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA",
		"LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY",
		"MA", "MC", "MD", "MG", "MH", "MK", "ML", "MM", "MN", "MO",
		"MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY",
		"MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP",
		"NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK",
		"PL", "PM", "PN", "PR", "PT", "PW", "PY", "QA", "RE", "RO",
		"RU", "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI",
		"SJ", "SK", "SL", "SM", "SN", "SO", "SR", "ST", "SV", "SY",
		"SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TM", "TN",
		"TO", "TP", "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM",
		"US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI", "VN", "VU",
		"WF", "WS", "YE", "YT", "YU", "ZA", "ZM", "ZR", "ZW", NULL
		};
	int i;

	/* Check that the country code is present in the table of known codes */
	for( i = 0; countryCodes[ i ] != NULL; i++ )
		if( !strcmp( countryCode, countryCodes[ i ] ) )
			return( TRUE );
	return( FALSE );
	}

/* Find a DN component in a DN component list by type and by OID */

DN_COMPONENT *findDNComponent( const DN_COMPONENT *listHead,
							   const CRYPT_CERTINFO_TYPE type,
							   const void *value, const int valueLength )
	{
	DN_COMPONENT *listPtr;

	/* Find the position of this component in the list */
	if( listHead == NULL )
		return( NULL );
	for( listPtr = ( DN_COMPONENT * ) listHead; listPtr != NULL;
		 listPtr = listPtr->next )
		if( listPtr->type == type && \
			( ( value == NULL ) || \
			  ( listPtr->valueLength == valueLength && \
				!memcmp( listPtr->value, value, valueLength ) ) ) )
			break;

	return( listPtr );
	}

static DN_COMPONENT *findDNComponentByOID( const DN_COMPONENT *listHead,
										   const BYTE *oid )
	{
	DN_COMPONENT *listPtr;
	const int oidLen = sizeofOID( oid );

	/* Find the position of this component in the list */
	if( listHead == NULL )
		return( NULL );
	for( listPtr = ( DN_COMPONENT * ) listHead; listPtr != NULL;
		 listPtr = listPtr->next )
		{
		const DN_COMPONENT_INFO *dnComponentInfo = listPtr->typeInfo;

		if( !memcmp( dnComponentInfo->oid, oid, oidLen ) )
			break;
		}

	return( listPtr );
	}

/* Insert a DN component into a list.  If the type is zero then it's an
   unrecognised component type, and if it's negative it's a recognised
   component type being read from a cert produced by a non-cryptlib
   application.  In this case we don't try to sort the component into the
   correct position */

static void insertListElement( DN_COMPONENT **listHeadPtr,
							   DN_COMPONENT *insertPoint,
							   DN_COMPONENT *newElement )
	{
	/* If it's an empty list, make this the new list */
	if( *listHeadPtr == NULL )
		{
		*listHeadPtr = newElement;
		return;
		}

	/* If we're inserting at the start of the list, make this the new first
	   element */
	if( insertPoint == NULL )
		{
		/* Insert the element at the start of the list */
		newElement->next = *listHeadPtr;
		( *listHeadPtr )->prev = newElement;
		*listHeadPtr = newElement;
		return;
		}

	/* Insert the element in the middle or end of the list.  Update the links
	   for the next element */
	newElement->next = insertPoint->next;
	if( insertPoint->next != NULL )
		insertPoint->next->prev = newElement;

	/* Update the links for the previous element */
	insertPoint->next = newElement;
	newElement->prev = insertPoint;
	}

int insertDNComponent( DN_COMPONENT **listHead,
					   const CRYPT_CERTINFO_TYPE componentType,
					   const void *value, const int valueLength,
					   const ASN1_STRINGTYPE stringType,
					   const BOOLEAN isContinued,
					   CRYPT_CERTERROR_TYPE *errorType )
	{
	const CRYPT_CERTINFO_TYPE type = abs( componentType );
	const DN_COMPONENT_INFO *dnComponentInfo;
	DN_COMPONENT *newElement, *insertPoint;

	/* Make sure the length is valid */
	if( ( valueLength > ( ( stringType == STRINGTYPE_UNICODE ) ? \
						  CRYPT_MAX_TEXTSIZE * 2 : CRYPT_MAX_TEXTSIZE ) ) || \
		( type == CRYPT_CERTINFO_COUNTRYNAME && valueLength != 2 ) )
		{
		if( errorType != NULL )
			*errorType = CRYPT_CERTERROR_SIZE;
		return( CRYPT_BADPARM );
		}

	/* Find the type information for this component if it's a recognised
	   type */
	if( type < DN_OID_OFFSET )
		{
		int i;

		/* It's a handled component, get the pointer to the OID */
		for( i = 0; certInfoOIDs[ i ].type != CRYPT_CERTINFO_NONE; i++ )
			if( certInfoOIDs[ i ].type == type )
				{
				dnComponentInfo = &certInfoOIDs[ i ];
				break;
				}
		if( certInfoOIDs[ i ].type == CRYPT_CERTINFO_NONE )
			return( CRYPT_ERROR );	/* Internal error, should never happen */
		}
	else
		/* It's a non-handled component, the type is an index into the
		   component table.  At this point we run into a GCC 2.7.x compiler
		   bug (detect with '#if defined( __GNUC__ ) && ( __GNUC__ == 2 )').
		   If we use the expression '&certInfoOIDs[ type - DN_OID_OFFSET ]'
		   what we should get is:
				leal -1000(%ebp,%ebp,2),%eax
				movl certInfoOIDs(,%eax,4),%eax
		   but what we actually get is:
				leal -3000(%ebp,%ebp,2),%eax
				movl certInfoOIDs(,%eax,4),%eax
		   To fix this we need to insert some form of dummy evaluation in a
		   form which ensures that it can't be optimised away (which is
		   actually quite difficult with gcc because it optimises any simple
		   code way.  To work around this we insert a dummy expression to
		   keep the value live */
		{
#if defined( __GNUC__ ) && ( __GNUC__ == 2 )
		int i = type - DN_OID_OFFSET;
		dnComponentInfo = &certInfoOIDs[ i ];
		if( dnComponentInfo < 0 )	/* Dummy code to keep i live */
			newElement = ( i + type ) ? NULL : ( void * ) value;
#else
		dnComponentInfo = &certInfoOIDs[ type - DN_OID_OFFSET ];
#endif /* gcc 2.7.x bug workaround */
		}

	/* Find the correct place in the list to insert the new element */
	if( *listHead != NULL )
		{
		DN_COMPONENT *prevElement = NULL;

		/* If it's being read from an external cert item, just append it to
		   the end of the list */
		if( componentType <= CRYPT_CERTINFO_NONE )
			for( insertPoint = *listHead; insertPoint->next != NULL;
				 insertPoint = insertPoint->next );
		else
			{
			for( insertPoint = *listHead; insertPoint != NULL && \
				 dnSortOrder( type ) >= dnSortOrder( insertPoint->type );
				 insertPoint = insertPoint->next )
				{
				/* Make sure this component isn't already present.  For now
				   we only allow a single DN component of any type to keep
				   things simple for the user, if it's necessary to allow
				   multiple components of the same type we need to check the
				   value and valueLength as well */
				if( insertPoint->type == type )
					{
					if( errorType != NULL )
						*errorType = CRYPT_CERTERROR_PRESENT;
					return( CRYPT_INITED );
					}

				prevElement = insertPoint;
				}
			insertPoint = prevElement;
			}
		}

	/* Allocate memory for the new element and copy over the information */
	if( ( newElement  = ( DN_COMPONENT * ) malloc( sizeof( DN_COMPONENT ) ) ) == NULL )
		return( CRYPT_NOMEM );
	memset( newElement, 0, sizeof( DN_COMPONENT ) );
	newElement->type = type;
	newElement->stringType = stringType;
	newElement->typeInfo = dnComponentInfo;
	memcpy( newElement->value, value, valueLength );
	newElement->valueLength = valueLength;
	newElement->isContinued = isContinued;

	/* If it's a country code and it's not coming from an external source,
	   force it to uppercase as per ISO 3166 */
	if( componentType > CRYPT_CERTINFO_NONE && \
		type == CRYPT_CERTINFO_COUNTRYNAME )
		{
		newElement->value[ 0 ] = toupper( newElement->value[ 0 ] );
		newElement->value[ 1 ] = toupper( newElement->value[ 1 ] );
		if( !checkCountryCode( ( char * ) newElement->value ) )
			{
			free( newElement );
			if( errorType != NULL )
				*errorType = CRYPT_CERTERROR_VALUE;
			return( CRYPT_INVALID );
			}
		}

	/* Link it into the list */
	insertListElement( listHead, insertPoint, newElement );

	return( CRYPT_OK );
	}

/* Delete a DN component from a list */

static int deleteComponent( DN_COMPONENT **listHead,
							DN_COMPONENT *theElement )
	{
	DN_COMPONENT *listPrevPtr, *listNextPtr;

	if( theElement == NULL )
		return( CRYPT_DATA_NOTFOUND );
	listPrevPtr = theElement->prev;
	listNextPtr = theElement->next;

	/* Remove the item from the list */
	if( theElement == *listHead )
		*listHead = listNextPtr;			/* Delete from start */
	else
		listPrevPtr->next = listNextPtr;	/* Delete from middle or end */
	if( listNextPtr != NULL )
		listNextPtr->prev = listPrevPtr;

	/* Clear all data in the list item and free the memory */
	zeroise( theElement, sizeof( DN_COMPONENT ) );
	free( theElement );

	return( CRYPT_OK );
	}

int deleteDNComponent( DN_COMPONENT **listHead,
					   const CRYPT_CERTINFO_TYPE type, const void *value,
					   const int valueLength )
	{
	/* Find the component in the list and delete it */
	return( deleteComponent( listHead, findDNComponent( *listHead, type,
													value, valueLength ) ) );
	}

/* Delete a DN component list */

void deleteDN( DN_COMPONENT **listHead )
	{
	DN_COMPONENT *listPtr = *listHead;

	/* Mark the list as being empty */
	*listHead = NULL;

	/* If the list was empty, return now */
	if( listPtr == NULL )
		return;

	/* Destroy any remaining list items */
	while( listPtr != NULL )
		{
		DN_COMPONENT *itemToFree = listPtr;

		listPtr = listPtr->next;
		zeroise( itemToFree, sizeof( DN_COMPONENT ) );
		free( itemToFree );
		}
	}

/* Compare two DN's.  Since this is used for constraint comparisons as well
   as just strict equality checks, we provide a flag which, if set, returns
   a match if the first DN is a proper substring of the second DN */

BOOLEAN compareDN( const DN_COMPONENT *dnComponentListHead1,
				   const DN_COMPONENT *dnComponentListHead2,
				   const BOOLEAN dn1substring )
	{
	DN_COMPONENT *dn1ptr = ( DN_COMPONENT * ) dnComponentListHead1;
	DN_COMPONENT *dn2ptr = ( DN_COMPONENT * ) dnComponentListHead2;

	/* Check each DN component for equality */
	while( dn1ptr != NULL && dn2ptr != NULL )
		{
		/* If the RDN types differ, the DN's don't match */
		if( dn1ptr->type != dn2ptr->type )
			return( FALSE );

		/* Compare the current RDN's */
		if( !compareASN1string( dn1ptr->value, dn1ptr->valueLength,
								dn2ptr->value, dn2ptr->valueLength ) )
			return( FALSE );

		/* Move on to the next component */
		dn1ptr = dn1ptr->next;
		dn2ptr = dn2ptr->next;
		}

	/* If we've reached the end of both DN's or we're looking for a substring
	   match, the two match */
	return( ( ( dn1ptr == NULL && dn2ptr == NULL ) || dn1substring ) ? \
			TRUE : FALSE );
	}

/* Copy a DN */

int copyDN( DN_COMPONENT **dest, const DN_COMPONENT *src )
	{
	DN_COMPONENT *destPtr = NULL;

	for( *dest = NULL; src != NULL; src = src->next )
		{
		DN_COMPONENT *newElement;

		/* Allocate memory for the new element and copy over the information */
		if( ( newElement  = ( DN_COMPONENT * ) malloc( sizeof( DN_COMPONENT ) ) ) == NULL )
			{
			deleteDN( dest );
			return( CRYPT_NOMEM );
			}
		memcpy( newElement, src, sizeof( DN_COMPONENT ) );

		/* Link it into the list */
		if( destPtr == NULL )
			{
			*dest = destPtr = newElement;
			newElement->prev = newElement->next = NULL;
			}
		else
			{
			newElement->prev = destPtr;
			newElement->next = NULL;
			destPtr->next = newElement;
			destPtr = newElement;
			}
		}

	return( CRYPT_OK );
	}

/* Check the validity of a DN.  The check for the bottom of the DN (common
   name) and top (country) are made configurable, DN's which act as filters
   (eg path constraints) may not have the lower DN parts present, and cert
   requests submitted to CA's which set the country themselves may not have
   the country present */

int checkDN( const DN_COMPONENT *dnComponentListHead,
			 const BOOLEAN checkCN, const BOOLEAN checkC,
			 CRYPT_CERTINFO_TYPE *errorLocus,
			 CRYPT_CERTERROR_TYPE *errorType )
	{
	DN_COMPONENT *dnComponentListPtr;
	BOOLEAN hasCountry = TRUE, hasCommonName = FALSE;

	/* Clear the return values */
	*errorType = CRYPT_CERTERROR_NONE;
	*errorLocus = CRYPT_CERTINFO_NONE;

	/* Make sure that certain critical components are present */
	for( dnComponentListPtr = ( DN_COMPONENT * ) dnComponentListHead;
		 dnComponentListPtr != NULL;
		 dnComponentListPtr = dnComponentListPtr->next )
		{
		if( dnComponentListPtr->type == CRYPT_CERTINFO_COUNTRYNAME )
			{
			if( !checkCountryCode( ( char * ) dnComponentListPtr->value ) )
				{
				*errorType = CRYPT_CERTERROR_VALUE;
				*errorLocus = CRYPT_CERTINFO_COUNTRYNAME;
				return( CRYPT_INVALID );
				}
			hasCountry = TRUE;
			}
		if( dnComponentListPtr->type == CRYPT_CERTINFO_COMMONNAME )
			hasCommonName = TRUE;
		}
	if( ( checkC && !hasCountry ) || ( checkCN && !hasCommonName ) )
		{
		*errorType = CRYPT_CERTERROR_ABSENT;
		*errorLocus = ( hasCountry ) ? CRYPT_CERTINFO_COMMONNAME : \
									   CRYPT_CERTINFO_COUNTRYNAME;
		return( CRYPT_NOTINITED );
		}

	return( CRYPT_OK );
	}

/* Convert a DN component containing a PKCS #9 emailAddress or an (????)
   rfc822Mailbox into an rfc822Name */

static int convertEmail( CERT_INFO *certInfoPtr, DN_COMPONENT **listHead,
						 const CRYPT_CERTINFO_TYPE altNameType )
	{
	DN_COMPONENT *emailComponent = findDNComponentByOID( *listHead,
			( const BYTE * ) "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x01" );
	SELECTION_STATE selectionState;
	const int dummy = CRYPT_UNUSED;
	int status;

	/* If there's no PKCS #9 email address present, try for a (????) one.  If
	   that's not present either, exit */
	if( emailComponent == NULL )
		{
		emailComponent = findDNComponentByOID( *listHead,
			( const BYTE * ) "\x06\x09\x09\x92\x26\x89\x93\xF2\x2C\x01\x03" );
		if( emailComponent == NULL )
			return( CRYPT_OK );
		}

	/* Try and add the email address component as an rfc822Name.  Since this
	   changes the current GeneralName selection, we have to be careful about
	   saving and restoring the state */
	saveSelectionState( selectionState, certInfoPtr );
	addCertComponent( certInfoPtr, altNameType, &dummy, 0 );
	status = addCertComponent( certInfoPtr, CRYPT_CERTINFO_RFC822NAME,
							   emailComponent->value,
							   emailComponent->valueLength );
	if( status == CRYPT_INITED )
		/* If it's already present (which is somewhat odd since the presence
		   of an email address in the DN implies that the implementation
		   doesn't know about rfc822Name) we can't do anything about it */
		status = CRYPT_OK;
	else
		/* It was successfully copied over, delete the copy in the DN */
		deleteComponent( listHead, emailComponent );
	restoreSelectionState( selectionState, certInfoPtr );

	return( status );
	}

int convertEmailAddress( CERT_INFO *certInfoPtr )
	{
	int status;

	status = convertEmail( certInfoPtr, &certInfoPtr->subjectName,
						   CRYPT_CERTINFO_SUBJECTALTNAME );
	if( cryptStatusOK( status ) )
		status = convertEmail( certInfoPtr, &certInfoPtr->issuerName,
							   CRYPT_CERTINFO_ISSUERALTNAME );
	return( status );
	}

/* Perform the pre-encoding processing for a DN */

static int preEncodeDN( const DN_COMPONENT *dnComponentListHead )
	{
	DN_COMPONENT *dnComponentPtr = ( DN_COMPONENT * ) dnComponentListHead;
	int size = 0;

	while( dnComponentPtr != NULL )
		{
		DN_COMPONENT *rdnStartPtr = dnComponentPtr;
		BOOLEAN isContinued;

		/* Calculate the size of every AVA in this RDN */
		do
			{
			const DN_COMPONENT_INFO *dnComponentInfo = dnComponentPtr->typeInfo;

			dnComponentPtr->encodedAVAdataSize = \
						sizeofOID( dnComponentInfo->oid ) + \
						( int ) sizeofObject( dnComponentPtr->valueLength );
			dnComponentPtr->encodedRDNdataSize = 0;
			rdnStartPtr->encodedRDNdataSize += ( int ) \
						sizeofObject( dnComponentPtr->encodedAVAdataSize );
			isContinued = dnComponentPtr->isContinued;
			dnComponentPtr = dnComponentPtr->next;
			}
		while( isContinued && dnComponentPtr != NULL );

		/* Calculate the overall size of the RDN */
		size += ( int ) sizeofObject( rdnStartPtr->encodedRDNdataSize );
		}

	return( size );
	}

int sizeofDN( const DN_COMPONENT *dnComponentListHead )
	{
	const int size = preEncodeDN( dnComponentListHead );

	return( sizeof( BYTE ) + calculateLengthSize( size ) + size );
	}

/* Write a DN */

int writeDN( STREAM *stream, const DN_COMPONENT *dnComponentListHead,
			 const int tag )
	{
	DN_COMPONENT *dnComponentPtr;
	const int size = preEncodeDN( dnComponentListHead );

	/* Write the DN */
	writeTag( stream, ( tag == DEFAULT_TAG ) ? \
			  BER_SEQUENCE : MAKE_CTAG( tag ) );
	writeLength( stream, size );

	for( dnComponentPtr = ( DN_COMPONENT * ) dnComponentListHead;
		 dnComponentPtr != NULL; dnComponentPtr = dnComponentPtr->next )
		{
		const DN_COMPONENT_INFO *dnComponentInfo = dnComponentPtr->typeInfo;
		int tag;

		if( dnComponentPtr->encodedRDNdataSize )
			/* If it's the start of an RDN, write the RDN header */
			writeSet( stream, dnComponentPtr->encodedRDNdataSize );
		writeSequence( stream, dnComponentPtr->encodedAVAdataSize );
		swrite( stream, dnComponentInfo->oid, \
				sizeofOID( dnComponentInfo->oid ) );
		switch( dnComponentPtr->stringType )
			{
			case STRINGTYPE_UNICODE:
				tag = BER_STRING_BMP;
				break;

			case STRINGTYPE_PRINTABLE:
				tag = BER_STRING_PRINTABLE;
				break;

			case STRINGTYPE_IA5:
				tag = dnComponentInfo->IA5OK ? BER_STRING_IA5 : BER_STRING_T61;
				break;

			case STRINGTYPE_T61:
				tag = BER_STRING_T61;
				break;

			default:
				return( CRYPT_ERROR );	/* Internal error, should never happen */
			}
		writeCharacterString( stream, dnComponentPtr->value,
							  dnComponentPtr->valueLength, tag );
		}

	return( sGetStatus( stream ) );
	}

/* Parse an AVA.   This determines the AVA type and leaves the stream pointer
   at the start of the data value */

static int readAVA( STREAM *stream, CRYPT_CERTINFO_TYPE *type,
					int *valueLength, ASN1_STRINGTYPE *stringType )
	{
	BYTE buffer[ 32 ];
	long length;
	int bufferLength, tag, i;

	/* Clear return values */
	*type = CRYPT_CERTINFO_NONE;
	*valueLength = 0;
	*stringType = STRINGTYPE_NONE;

	/* Read the start of the AVA and determine the type from the AttributeType
	   field.  If we find something which cryptlib doesn't recognise, we
	   indicate it as a non-component type which can be read or written but
	   not directly accessed by the user (although it can be accessed using
	   the cursor functions) */
	if( cryptStatusError( cryptStatusError( readSequence( stream, &i ) ) ) || \
		cryptStatusError( readRawObject( stream, buffer, &bufferLength, 32,
										 BER_OBJECT_IDENTIFIER ) ) )
		return( CRYPT_BADDATA );
	for( i = 0; certInfoOIDs[ i ].oid != NULL; i++ )
		if( !memcmp( certInfoOIDs[ i ].oid, buffer, bufferLength ) )
			{
			*type = ( certInfoOIDs[ i ].type != CRYPT_CERTINFO_NONE ) ?
					certInfoOIDs[ i ].type : i + DN_OID_OFFSET;
			break;
			}
	if( *type == CRYPT_CERTINFO_NONE )
		/* If we don't recognise the component type, return a bad data error -
		   this isn't perfect, but chances are any OID that peculiar is an
		   error */
		return( CRYPT_BADDATA );

	/* We've reached the data value, make sure it's in order */
	tag = readTag( stream );
	switch( tag )
		{
		case BER_STRING_BMP:
			*stringType = STRINGTYPE_UNICODE;
			break;

		case BER_STRING_IA5:
			*stringType = STRINGTYPE_IA5;
			break;

		case BER_STRING_PRINTABLE:
			*stringType = STRINGTYPE_PRINTABLE;
			break;

		case BER_STRING_T61:
			*stringType = STRINGTYPE_T61;
			break;

		case BER_STRING_UTF8:
			/* This type will have its characters converted to something
			   useful later */
			*stringType = STRINGTYPE_UTF8;
			break;

		default:
			return( CRYPT_BADDATA );
		}
	if( cryptStatusError( readLength( stream, &length ) ) )
		return( CRYPT_BADDATA );
	*valueLength = ( int ) length;

	return( CRYPT_OK );
	}

/* Read an RDN component */

static int readRDNcomponent( STREAM *stream, DN_COMPONENT **dnComponentListHead,
							 const int rdnDataLeft )
	{
	CRYPT_CERTINFO_TYPE type;
	ASN1_STRINGTYPE stringType;
	BYTE stringBuffer[ CRYPT_MAX_TEXTSIZE ], *value;
	BOOLEAN isContinued = FALSE;
	const int rdnStart = sMemSize( stream );
	int valueLength, status;

	/* Read the type information for this AVA */
	if( cryptStatusError( readAVA( stream, &type, &valueLength, &stringType ) ) )
		return( CRYPT_BADDATA );
	value = sMemBufPtr( stream );

	/* If there's room for another AVA, mark this one as being continued.  The
	   +10 is the minimum length for an AVA: SEQ{ OID, value }.  We don't do
	   a simple =/!= check to get around incorrectly encoded lengths */
	if( rdnDataLeft >= ( sMemSize( stream ) - rdnStart ) + valueLength + 10 )
		isContinued = TRUE;

	/* If it's a UTF-8 string, convert it into a useful character set */
	if( stringType == STRINGTYPE_UTF8 )
		{
		stringType = convertFromUTF8( stringBuffer, &valueLength, value,
									  valueLength );
		if( stringType == STRINGTYPE_NONE )
			return( CRYPT_BADDATA );
		value = stringBuffer;
		}
	else
		/* Take the opportunity to fix up the string type if necessary.  Some
		   broken implementations will check to see that they receive back the
		   same broken encoding which they produce, so we make this a user-
		   configurable option */
		if( getOptionNumeric( CRYPT_OPTION_CERT_FIXSTRINGS ) )
			{
			ASN1_STRINGTYPE actualStringType = getStringType( value, valueLength, TRUE );
			BOOLEAN IA5OK = ( type < DN_OID_OFFSET ) ? FALSE : \
							certInfoOIDs[ type - DN_OID_OFFSET ].IA5OK;

			/* If it's an IA5 or PrintableString encoded as Unicode, convert
			   it down to the correct type */
			if( actualStringType == STRINGTYPE_UNICODE_T61 || \
				actualStringType == STRINGTYPE_UNICODE_IA5 || \
				actualStringType == STRINGTYPE_UNICODE_PRINTABLE )
				{
				stringType = copyConvertString( value, valueLength,
												stringBuffer, &valueLength,
												CRYPT_MAX_TEXTSIZE, FALSE, TRUE );
				if( stringType == STRINGTYPE_NONE )
					return( CRYPT_BADDATA );
				value = stringBuffer;
				}

			/* If it's IA5 and it isn't allowed in this situation, make it
			   T61 */
			if( actualStringType == STRINGTYPE_IA5 && !IA5OK )
				stringType = STRINGTYPE_T61;

			/* If it's a country code, force it to uppercase as per ISO 3166 */
			if( type == CRYPT_CERTINFO_COUNTRYNAME )
				{
				value[ 0 ] = toupper( value[ 0 ] );
				value[ 1 ] = toupper( value[ 1 ] );
				}
			}

	/* Add the DN component to the DN.  If we hit a non-memory related error
	   we turn it into a generic CRYPT_BADDATA error, since the other codes
	   are somewhat too specific for this case (eg CRYPT_INITED on a cert
	   import isn't too useful for the caller) */
	status = insertDNComponent( dnComponentListHead, -type, value,
								valueLength, stringType, isContinued, NULL );
	if( cryptStatusError( status ) && status != CRYPT_NOMEM )
		return( CRYPT_BADDATA );
	sSkip( stream, valueLength );

	return( status );
	}

/* Read a DN */

int readDNTag( STREAM *stream, DN_COMPONENT **dnComponentListHead,
			   const int tag )
	{
	long length;
	int tagValue = BER_SEQUENCE;

	/* Read the start of the DN */
	if( tag != NO_TAG )
		{
		if( tag != DEFAULT_TAG )
			tagValue = MAKE_CTAG( tag );
		if( readTag( stream ) != tagValue )
			return( CRYPT_BADDATA );
		}
	if( cryptStatusError( readLength( stream, &length ) ) )
		return( CRYPT_BADDATA );
	while( length > 0 )
		{
		const int startPos = sMemSize( stream );
		int rdnLength;

		/* Read the start of the RDN */
		if( cryptStatusError( readSet( stream, &rdnLength ) ) )
			return( CRYPT_BADDATA );

		/* Read each RDN component */
		while( rdnLength > 0 )
			{
			const int rdnStart = sMemSize( stream );
			int status;

			status = readRDNcomponent( stream, dnComponentListHead,
									   rdnLength );
			if( cryptStatusError( status ) )
				return( status );

			rdnLength -= sMemSize( stream ) - rdnStart;
			}
		if( rdnLength < 0 )
			return( CRYPT_BADDATA );

		length -= sMemSize( stream ) - startPos;
		}
	if( length < 0 )
		return( CRYPT_BADDATA );

	return( sGetStatus( stream ) );
	}
