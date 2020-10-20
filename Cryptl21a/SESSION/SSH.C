/****************************************************************************
*																			*
*						cryptlib SSH v1 Session Management					*
*						Copyright Peter Gutmann 1998-1999					*
*																			*
****************************************************************************/

/* Implementation comments:

	- At the moment we never advertise 3DES since this uses inner-CBC which
	  is both nonstandard and has known (although not serious) weaknesses.
	  If we wanted to implement it in a portable manner (ie usable with
	  external drivers and devices) we'd have to synthesize it using three
	  lots of DES-CBC since nothing implements the variant which SSH uses.
	  This leads to problems with cryptEncrypt() because it's based on a
	  single object, not three of them.
	- We always advertise no MAC since there's no easy way to both encrypt
	  and MAC using cryptEncrypt(), and in any case it's unlikely that the
	  MAC is adding much except unnecessary overhead */

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "session.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../session/session.h"
#else
  #include "crypt.h"
  #include "session/session.h"
#endif /* Compiler-specific includes */

/* Prototypes for functions in lib_rand.c */

int getRandomData( BYTE *buffer, const int length );

/* Various SSH constants */

#define SSH_COOKIE_SIZE			8	/* Size of anti-spoofing cookie */
#define SSH_HEADER_SIZE			5	/* Size of the SSH packet header */
#define SSH_SECRET_SIZE			32	/* Size of SSH shared secret */

/* SSH v1 packet types */

#define SSH_SMSG_PUBLIC_KEY		2	/* Server public key */
#define SSH_CMSG_SESSION_KEY	3	/* Encrypted session key */

/* SSH v1 cipher types */

#define SSH_CIPHER_NONE			0	/* No encryption */
#define SSH_CIPHER_IDEA			1	/* IDEA/CFB */
#define SSH_CIPHER_DES			2	/* DES/CBC */
#define SSH_CIPHER_3DES			3	/* 3DES/inner-CBC */
#define SSH_CIPHER_TSS			4	/* Deprecated */
#define SSH_CIPHER_RC4			5	/* RC4 */

/* The DH values used in SSH v2.  p is equal to
   2^1024 - 2^960 - 1 + 2^64 * floor( 2^894 Pi + 129093 ) */

typedef struct {
	const int baseLen; const BYTE base[ 1 ];
	const int primeLen; const BYTE FAR_BSS prime[ 128 ];
	} DH_VALUE;

static const DH_VALUE FAR_BSS sshDHvalue[] = {
	/* g */
	2,
	{ 0x02 },
	/* p */
	1024,
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	  0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
	  0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
	  0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
	  0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
	  0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
	  0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
	  0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
	  0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
	  0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
	  0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
	  0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
	  0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
	  0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
	  0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
	  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Calculate the CRC32 for a data block.  This uses the slightly nonstandard
   variant from SSH which calculates the UART-style reflected value and
   doesn't pre-set the value to all ones (done to to catch leading zero
   bytes, which happens quite a bit with SSH because of the 32-bit length at
   the start) or XOR it with all ones before returning it.  This means that
   the resulting CRC is not the same as the one in Ethernet, Pkzip, and most
   other implementations */

static const LONG crc32table[] = {
	0x00000000UL, 0x77073096UL, 0xEE0E612CUL, 0x990951BAUL,
	0x076DC419UL, 0x706AF48FUL, 0xE963A535UL, 0x9E6495A3UL,
	0x0EDB8832UL, 0x79DCB8A4UL, 0xE0D5E91EUL, 0x97D2D988UL,
	0x09B64C2BUL, 0x7EB17CBDUL, 0xE7B82D07UL, 0x90BF1D91UL,
	0x1DB71064UL, 0x6AB020F2UL, 0xF3B97148UL, 0x84BE41DEUL,
	0x1ADAD47DUL, 0x6DDDE4EBUL, 0xF4D4B551UL, 0x83D385C7UL,
	0x136C9856UL, 0x646BA8C0UL, 0xFD62F97AUL, 0x8A65C9ECUL,
	0x14015C4FUL, 0x63066CD9UL, 0xFA0F3D63UL, 0x8D080DF5UL,
	0x3B6E20C8UL, 0x4C69105EUL, 0xD56041E4UL, 0xA2677172UL,
	0x3C03E4D1UL, 0x4B04D447UL, 0xD20D85FDUL, 0xA50AB56BUL,
	0x35B5A8FAUL, 0x42B2986CUL, 0xDBBBC9D6UL, 0xACBCF940UL,
	0x32D86CE3UL, 0x45DF5C75UL, 0xDCD60DCFUL, 0xABD13D59UL,
	0x26D930ACUL, 0x51DE003AUL, 0xC8D75180UL, 0xBFD06116UL,
	0x21B4F4B5UL, 0x56B3C423UL, 0xCFBA9599UL, 0xB8BDA50FUL,
	0x2802B89EUL, 0x5F058808UL, 0xC60CD9B2UL, 0xB10BE924UL,
	0x2F6F7C87UL, 0x58684C11UL, 0xC1611DABUL, 0xB6662D3DUL,
	0x76DC4190UL, 0x01DB7106UL, 0x98D220BCUL, 0xEFD5102AUL,
	0x71B18589UL, 0x06B6B51FUL, 0x9FBFE4A5UL, 0xE8B8D433UL,
	0x7807C9A2UL, 0x0F00F934UL, 0x9609A88EUL, 0xE10E9818UL,
	0x7F6A0DBBUL, 0x086D3D2DUL, 0x91646C97UL, 0xE6635C01UL,
	0x6B6B51F4UL, 0x1C6C6162UL, 0x856530D8UL, 0xF262004EUL,
	0x6C0695EDUL, 0x1B01A57BUL, 0x8208F4C1UL, 0xF50FC457UL,
	0x65B0D9C6UL, 0x12B7E950UL, 0x8BBEB8EAUL, 0xFCB9887CUL,
	0x62DD1DDFUL, 0x15DA2D49UL, 0x8CD37CF3UL, 0xFBD44C65UL,
	0x4DB26158UL, 0x3AB551CEUL, 0xA3BC0074UL, 0xD4BB30E2UL,
	0x4ADFA541UL, 0x3DD895D7UL, 0xA4D1C46DUL, 0xD3D6F4FBUL,
	0x4369E96AUL, 0x346ED9FCUL, 0xAD678846UL, 0xDA60B8D0UL,
	0x44042D73UL, 0x33031DE5UL, 0xAA0A4C5FUL, 0xDD0D7CC9UL,
	0x5005713CUL, 0x270241AAUL, 0xBE0B1010UL, 0xC90C2086UL,
	0x5768B525UL, 0x206F85B3UL, 0xB966D409UL, 0xCE61E49FUL,
	0x5EDEF90EUL, 0x29D9C998UL, 0xB0D09822UL, 0xC7D7A8B4UL,
	0x59B33D17UL, 0x2EB40D81UL, 0xB7BD5C3BUL, 0xC0BA6CADUL,
	0xEDB88320UL, 0x9ABFB3B6UL, 0x03B6E20CUL, 0x74B1D29AUL,
	0xEAD54739UL, 0x9DD277AFUL, 0x04DB2615UL, 0x73DC1683UL,
	0xE3630B12UL, 0x94643B84UL, 0x0D6D6A3EUL, 0x7A6A5AA8UL,
	0xE40ECF0BUL, 0x9309FF9DUL, 0x0A00AE27UL, 0x7D079EB1UL,
	0xF00F9344UL, 0x8708A3D2UL, 0x1E01F268UL, 0x6906C2FEUL,
	0xF762575DUL, 0x806567CBUL, 0x196C3671UL, 0x6E6B06E7UL,
	0xFED41B76UL, 0x89D32BE0UL, 0x10DA7A5AUL, 0x67DD4ACCUL,
	0xF9B9DF6FUL, 0x8EBEEFF9UL, 0x17B7BE43UL, 0x60B08ED5UL,
	0xD6D6A3E8UL, 0xA1D1937EUL, 0x38D8C2C4UL, 0x4FDFF252UL,
	0xD1BB67F1UL, 0xA6BC5767UL, 0x3FB506DDUL, 0x48B2364BUL,
	0xD80D2BDAUL, 0xAF0A1B4CUL, 0x36034AF6UL, 0x41047A60UL,
	0xDF60EFC3UL, 0xA867DF55UL, 0x316E8EEFUL, 0x4669BE79UL,
	0xCB61B38CUL, 0xBC66831AUL, 0x256FD2A0UL, 0x5268E236UL,
	0xCC0C7795UL, 0xBB0B4703UL, 0x220216B9UL, 0x5505262FUL,
	0xC5BA3BBEUL, 0xB2BD0B28UL, 0x2BB45A92UL, 0x5CB36A04UL,
	0xC2D7FFA7UL, 0xB5D0CF31UL, 0x2CD99E8BUL, 0x5BDEAE1DUL,
	0x9B64C2B0UL, 0xEC63F226UL, 0x756AA39CUL, 0x026D930AUL,
	0x9C0906A9UL, 0xEB0E363FUL, 0x72076785UL, 0x05005713UL,
	0x95BF4A82UL, 0xE2B87A14UL, 0x7BB12BAEUL, 0x0CB61B38UL,
	0x92D28E9BUL, 0xE5D5BE0DUL, 0x7CDCEFB7UL, 0x0BDBDF21UL,
	0x86D3D2D4UL, 0xF1D4E242UL, 0x68DDB3F8UL, 0x1FDA836EUL,
	0x81BE16CDUL, 0xF6B9265BUL, 0x6FB077E1UL, 0x18B74777UL,
	0x88085AE6UL, 0xFF0F6A70UL, 0x66063BCAUL, 0x11010B5CUL,
	0x8F659EFFUL, 0xF862AE69UL, 0x616BFFD3UL, 0x166CCF45UL,
	0xA00AE278UL, 0xD70DD2EEUL, 0x4E048354UL, 0x3903B3C2UL,
	0xA7672661UL, 0xD06016F7UL, 0x4969474DUL, 0x3E6E77DBUL,
	0xAED16A4AUL, 0xD9D65ADCUL, 0x40DF0B66UL, 0x37D83BF0UL,
	0xA9BCAE53UL, 0xDEBB9EC5UL, 0x47B2CF7FUL, 0x30B5FFE9UL,
	0xBDBDF21CUL, 0xCABAC28AUL, 0x53B39330UL, 0x24B4A3A6UL,
	0xBAD03605UL, 0xCDD70693UL, 0x54DE5729UL, 0x23D967BFUL,
	0xB3667A2EUL, 0xC4614AB8UL, 0x5D681B02UL, 0x2A6F2B94UL,
	0xB40BBE37UL, 0xC30C8EA1UL, 0x5A05DF1BUL, 0x2D02EF8DUL
	};

static LONG calculateCRC( const BYTE *data, const int dataLength )
	{
	LONG crc32 = 0;
	int i;

	for( i = 0; i < dataLength; i++ )
		crc32 = crc32table[ ( int ) ( crc32 ^ data[ i ] ) & 0xFF ] ^ ( crc32 >> 8 );

	return( crc32 );
	}

/* Generate an SSH session ID */

static int generateSessionID( SESSION_INFO *sessionInfoPtr )
	{
	HASHFUNCTION hashFunction;
	BYTE buffer[ CRYPT_MAX_PKCSIZE ], hashInfo[ MAX_HASHINFO_SIZE ], *dataPtr;
	int hashInfoSize, hashInputSize, hashOutputSize, length, status;

	/* Get the hash algorithm information and hash the host key modulus,
	   server key modulus, and cookie */
	if( !getHashParameters( CRYPT_ALGO_MD5, &hashFunction, &hashInputSize,
							&hashOutputSize, &hashInfoSize ) )
		return( CRYPT_ERROR );	/* API error, should never occur */
	status = writeAdhocPublicKey( buffer,
								  sessionInfoPtr->iKeyexCryptContext );
	if( cryptStatusError( status ) )
		return( status );
	dataPtr = buffer;
	length = ( int ) mgetBLong( dataPtr );
	hashFunction( hashInfo, NULL, dataPtr, bitsToBytes( length ), HASH_START );
	status = writeAdhocPublicKey( buffer,
								  sessionInfoPtr->iKeyexAuthContext );
	if( cryptStatusError( status ) )
		return( status );
	dataPtr = buffer;
	length = ( int ) mgetBLong( dataPtr );
	hashFunction( hashInfo, NULL, dataPtr, bitsToBytes( length ), HASH_CONTINUE );
	hashFunction( hashInfo, sessionInfoPtr->sessionID,
				  sessionInfoPtr->cookie, SSH_COOKIE_SIZE, HASH_END );

	return( CRYPT_OK );
	}

/* Convert an SSH algorithm ID to a cryptlib ID in preferred-algorithm order */

static CRYPT_ALGO convertAlgoID( const int value )
	{
	if( value & ( 1 << SSH_CIPHER_3DES ) )
		return( CRYPT_ALGO_3DES );
	if( ( value & ( 1 << SSH_CIPHER_IDEA ) ) && \
		cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_IDEA,
											 CRYPT_MODE_CFB, NULL ) ) )
		return( CRYPT_ALGO_IDEA );
	if( ( value & ( 1 << SSH_CIPHER_RC4 ) ) && \
		cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_RC4,
											 CRYPT_MODE_STREAM, NULL ) ) )
		return( CRYPT_ALGO_RC4 );
	if( value & ( 1 << SSH_CIPHER_DES ) )
		return( CRYPT_ALGO_DES );

	return( CRYPT_ALGO_NONE );
	}

/* Set up the incoming and outgoing encryption contexts based on the
   negotiated algorithm and key */

static CRYPT_CONTEXT initContext( const CRYPT_ALGO cryptAlgo,
								  const CRYPT_MODE cryptMode,
								  const void *key, const int keyLength )
	{
	CRYPT_CONTEXT iCryptContext;
	int status;

	status = iCryptCreateContext( &iCryptContext, cryptAlgo, cryptMode );
	if( cryptStatusError( status ) )
		return( status );
	status = iCryptLoadKey( iCryptContext, key, keyLength );
	if( cryptStatusOK( status ) )
		status = iCryptLoadIV( iCryptContext,
							   "\x00\x00\x00\x00\x00\x00\x00\x00", 8 );
	if( cryptStatusError( status ) )
		{
		iCryptDestroyObject( iCryptContext );
		return( status );
		}

	return( iCryptContext );
	}

static int initEncryption( SESSION_INFO *sessionInfoPtr )
	{
	const CRYPT_ALGO cryptAlgo = sessionInfoPtr->cryptAlgo;
	const CRYPT_MODE cryptMode = ( cryptAlgo == CRYPT_ALGO_IDEA ) ? CRYPT_MODE_CFB : \
		( cryptAlgo == CRYPT_ALGO_RC4 ) ? CRYPT_MODE_STREAM : CRYPT_MODE_CBC;
	const int keySize = ( cryptAlgo == CRYPT_ALGO_DES ) ? 8 : \
						( cryptAlgo == CRYPT_ALGO_3DES ) ? 24 : 16;
	CRYPT_CONTEXT iCryptContext;

	iCryptContext = initContext( cryptAlgo, cryptMode,
								 sessionInfoPtr->secureState, keySize );
	if( cryptStatusError( iCryptContext ) )
		return( iCryptContext );
	sessionInfoPtr->iCryptInContext = iCryptContext;
	iCryptContext = initContext( cryptAlgo, cryptMode,
								 sessionInfoPtr->secureState, keySize );
	if( cryptStatusError( iCryptContext ) )
		{
		iCryptDestroyObject( sessionInfoPtr->iCryptInContext );
		sessionInfoPtr->iCryptInContext = CRYPT_ERROR;
		return( iCryptContext );
		}
	sessionInfoPtr->iCryptOutContext = iCryptContext;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Control Information Management Functions			*
*																			*
****************************************************************************/

/* Get the key size for a context */

static int getContextKeySize( const CRYPT_CONTEXT iCryptContext )
	{
	ICRYPT_QUERY_INFO iCryptQueryInfo;
	int status;

	status = iCryptQueryContext( iCryptContext, &iCryptQueryInfo );
	if( cryptStatusError( status ) )
		return( status );
	status = iCryptQueryInfo.keySize;
	memset( &iCryptQueryInfo, 0, sizeof( ICRYPT_QUERY_INFO ) );

	return( status );
	}

/* Add control information to a session object */

int sshAddInfo( SESSION_INFO *sessionInfoPtr,
				const CRYPT_SESSINFO_TYPE sessionInfo, const void *value,
				const int valueLength )
	{
	CRYPT_HANDLE cryptHandle = *( ( CRYPT_HANDLE * ) value );
	int status;

	if( valueLength );		/* Get rid of compiler warning */

	/* If it's a context used to establish the session, remember it and exit */
	if( sessionInfo == CRYPT_SESSINFO_KEY_ENCRYPTION )
		{
		/* If there's a host key present, make sure it's larger than the
		   server key by at least 128 bits */
		if( sessionInfoPtr->iKeyexAuthContext != CRYPT_ERROR )
			{
			const int hostKeySize = \
				getContextKeySize( sessionInfoPtr->iKeyexAuthContext );
			const int serverKeySize = getContextKeySize( cryptHandle );

			if( cryptStatusError( hostKeySize ) )
				return( hostKeySize );
			if( cryptStatusError( serverKeySize ) )
				return( serverKeySize );
			if( hostKeySize < serverKeySize + 16 )
				return( CRYPT_OVERFLOW );	/* Server key is too big */
			}

		status = krnlSendNotifier( cryptHandle, RESOURCE_MESSAGE_INCREFCOUNT );
		if( cryptStatusOK( status ) )
			sessionInfoPtr->iKeyexCryptContext = cryptHandle;
		return( status );
		}
	if( sessionInfo == CRYPT_SESSINFO_KEY_AUTHENTICATION )
		{
		/* If there's a server key present, make sure it's smaller than the
		   host key by at least 128 bits */
		if( sessionInfoPtr->iKeyexCryptContext != CRYPT_ERROR )
			{
			const int serverKeySize = \
				getContextKeySize( sessionInfoPtr->iKeyexCryptContext );
			const int hostKeySize = getContextKeySize( cryptHandle );

			if( cryptStatusError( serverKeySize ) )
				return( serverKeySize );
			if( cryptStatusError( hostKeySize ) )
				return( hostKeySize );
			if( serverKeySize > hostKeySize - 16 )
				return( CRYPT_UNDERFLOW );	/* Host key is too small */
			}
		status = krnlSendNotifier( cryptHandle, RESOURCE_MESSAGE_INCREFCOUNT );
		if( cryptStatusOK( status ) )
			sessionInfoPtr->iKeyexAuthContext = cryptHandle;
		return( status );
		}

	/* The information isn't valid for this session type */
	return( CRYPT_BADPARM2 );
	}

/****************************************************************************
*																			*
*							Data Packet Get/Add Functions					*
*																			*
****************************************************************************/

/* Wrap/unwrap data in an SSH packet:

	uint32		length
	byte		packet_type
	byte[]		data
	uint32		crc32				- Calculated over packet_type and data

   This takes as input a data packet with a 5-byte gap at the start for the
   header and wraps it up as appropriate in the SSH packet encapsulation */

static int wrapSshPacket( void *data, const int length, const int packetType )
	{
	BYTE *dataPtr = data;
	LONG crc32;

	/* Add the length and type at the start */
	mputBLong( dataPtr, ( long ) length );
	*dataPtr = ( BYTE ) packetType;

	/* Calculate the CRC-32 over the type and data */
	crc32 = calculateCRC( dataPtr, length + 1 );
	dataPtr += length + 1;
	mputBLong( dataPtr, crc32 );

	return( SSH_HEADER_SIZE + length + 4 );
	}

static int unwrapSshPacket( const void *data, int *packetType )
	{
	BYTE *dataPtr = ( BYTE * ) data;
	LONG crc32, storedCrc32;
	long length;
	int type;

	*packetType = 0;

	/* Read the packet header */
	length = mgetBLong( dataPtr );
	if( length <= SSH_HEADER_SIZE || length > 32767L )
		return( CRYPT_BADDATA );
	type = *dataPtr;
	if( ( type != SSH_SMSG_PUBLIC_KEY ) && ( type != SSH_CMSG_SESSION_KEY ) )
		return( CRYPT_BADDATA );
	*packetType = type;

	/* Calculate the CRC-32 over the type and data and make sure it matches
	   the transmitted value */
	crc32 = calculateCRC( dataPtr, ( int ) length + 1 );
	dataPtr += ( int ) length + 1;
	storedCrc32 = mgetBLong( dataPtr );
	if( crc32 != storedCrc32 )
		return( CRYPT_BADDATA );

	return( ( int ) length - SSH_HEADER_SIZE );
	}

/* Get/add the server public key packet:

	byte[8]		cookie
	uint32		keysize_bits		- Usually 768 bits
	mpint		serverkey_exponent
	mpint		serverkey_modulus
	uint32		keysize_bits		- Usually 1024 bits
	mpint		hostkey_exponent
	mpint		hostkey_modulus
	uint32		protocol_flags		- Always 0
	uint32		offered_ciphers
	uint32		offered_authent */

static int getServerPubkeyPacket( SESSION_INFO *sessionInfoPtr, void *data )
	{
	BYTE *dataPtr = ( BYTE * ) data + SSH_HEADER_SIZE;
	long flags;
	int value, status;

	/* Generate the session cookie */
	getNonce( sessionInfoPtr->cookie, SSH_COOKIE_SIZE );
	memcpy( dataPtr, sessionInfoPtr->cookie, SSH_COOKIE_SIZE );
	dataPtr += SSH_COOKIE_SIZE;

	/* Write the server key */
	value = getContextKeySize( sessionInfoPtr->iKeyexAuthContext );
	if( cryptStatusError( value ) )
		return( value );
	value = bytesToBits( value );
	mputBLong( dataPtr, value );
	status = writeAdhocPublicKey( dataPtr,
								  sessionInfoPtr->iKeyexAuthContext );
	if( cryptStatusError( status ) )
		return( status );
	dataPtr += status;

	/* Write the host key */
	value = getContextKeySize( sessionInfoPtr->iKeyexCryptContext );
	if( cryptStatusError( value ) )
		return( value );
	value = bytesToBits( value );
	mputBLong( dataPtr, value );
	status = writeAdhocPublicKey( dataPtr,
								  sessionInfoPtr->iKeyexCryptContext );
	if( cryptStatusError( status ) )
		return( status );
	dataPtr += status;

	/* Write the various flags */
	mputBLong( dataPtr, 0 );		/* Protocol flags */
	flags = ( 1 << SSH_CIPHER_DES )/* | ( 1 << SSH_CIPHER_3DES )*/;
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_IDEA, CRYPT_MODE_CFB,
											 NULL ) ) )
		flags |= ( 1 << SSH_CIPHER_IDEA );
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_RC4, CRYPT_MODE_STREAM,
											 NULL ) ) )
		flags |= ( 1 << SSH_CIPHER_RC4 );
	mputBLong( dataPtr, flags );	/* Encryption flags */
	flags = 0;
	mputBLong( dataPtr, flags );	/* Authentication flags */

	return( wrapSshPacket( data, ( int ) ( dataPtr - data ),
						   SSH_SMSG_PUBLIC_KEY ) );
	}

static int addServerPubkeyPacket( SESSION_INFO *sessionInfoPtr,
								  const void *data )
	{
	const BYTE *dataPtr = data;
	long value;
	int status;

	/* Read the session cookie */
	memcpy( sessionInfoPtr->cookie, dataPtr, SSH_COOKIE_SIZE );
	dataPtr += SSH_COOKIE_SIZE;

	/* Read the server key */
	value = mgetBLong( dataPtr );
	if( value < 512 || value > bytesToBits( CRYPT_MAX_PKCSIZE ) )
		return( CRYPT_BADDATA );
	status = readAdhocPublicKey( dataPtr,
								 &sessionInfoPtr->iKeyexAuthContext );
	if( cryptStatusError( status ) )
		return( status );
	dataPtr += status;

	/* Read the host key */
	value = mgetBLong( dataPtr );
	if( value < 512 || value > bytesToBits( CRYPT_MAX_PKCSIZE ) )
		return( CRYPT_BADDATA );
	status = readAdhocPublicKey( dataPtr,
								 &sessionInfoPtr->iKeyexCryptContext );
	if( cryptStatusError( status ) )
		return( status );
	dataPtr += status;

	/* Read the various flags */
	dataPtr += 4;					/* Protocol flags */
	value = mgetBLong( dataPtr );	/* Encryption flags */
	sessionInfoPtr->cryptAlgo = convertAlgoID( ( int ) value );
	if( sessionInfoPtr->cryptAlgo == CRYPT_ALGO_NONE )
		return( CRYPT_NOALGO );
	value = mgetBLong( dataPtr );	/* Authentication flags */

	return( CRYPT_OK );
	}

/* Get/add the session key packet:

	byte		cipher_type
	byte[8]		cookie
	mpint		double_enc_sessionkey
	uint32		protocol_flags */

static int getSessionKeyPacket( SESSION_INFO *sessionInfoPtr, void *data )
	{
	BYTE buffer[ CRYPT_MAX_PKCSIZE ];
	BYTE *dataPtr = ( BYTE * ) data + SSH_HEADER_SIZE;
	int length, value, i, status;

	/* Generate the session ID */
	status = generateSessionID( sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* Output the cipher type */
	switch( sessionInfoPtr->cryptAlgo )
		{
		case CRYPT_ALGO_3DES:
			value = SSH_CIPHER_3DES;
			break;
		case CRYPT_ALGO_DES:
			value = SSH_CIPHER_DES;
			break;
		case CRYPT_ALGO_IDEA:
			value = SSH_CIPHER_IDEA;
			break;
		case CRYPT_ALGO_RC4:
			value = SSH_CIPHER_RC4;
			break;
		default:
			return( CRYPT_ERROR );		/* Internal error, should never happen */
		}
	*dataPtr++ = value;

	/* Output the session cookie */
	memcpy( dataPtr, sessionInfoPtr->cookie, SSH_COOKIE_SIZE );
	dataPtr += SSH_COOKIE_SIZE;

	/* Generate the secure state information and XOR it with the session ID */
	status = getRandomData( sessionInfoPtr->secureState, SSH_SECRET_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	for( i = 0; i < 16; i++ )
		( ( BYTE * ) sessionInfoPtr->secureState )[ i ] ^= sessionInfoPtr->sessionID[ i ];

	/* Export the secure state information in double-encrypted form */
	status = exportEncryptedSecret( buffer, &value,
							sessionInfoPtr->iKeyexCryptContext,
							sessionInfoPtr->secureState, SSH_SECRET_SIZE );
	if( cryptStatusOK( status ) )
		status = exportEncryptedSecret( dataPtr + 4, &value,
							sessionInfoPtr->iKeyexAuthContext, buffer,
							value );
	if( cryptStatusError( status ) )
		{
		zeroise( sessionInfoPtr->secureState, SSH_SECRET_SIZE );
		return( status );
		}
	length = bytesToBits( value );
	mputBLong( dataPtr, length );
	dataPtr += value;

	/* XOR the state with the session ID to recover the actual state */
	for( i = 0; i < 16; i++ )
		( ( BYTE * ) sessionInfoPtr->secureState )[ i ] ^= sessionInfoPtr->sessionID[ i ];

	/* Write the various flags */
	mputBLong( dataPtr, 0 );		/* Protocol flags */

	return( wrapSshPacket( data, ( int ) ( dataPtr - data ),
						   SSH_CMSG_SESSION_KEY ) );
	}

static int addSessionKeyPacket( SESSION_INFO *sessionInfoPtr,
								const void *data )
	{
	BYTE buffer[ CRYPT_MAX_PKCSIZE ];
	const BYTE *dataPtr = data;
	int length, value, i, status;

	/* Make sure the encryption algorithm is what we asked for */
	value = *dataPtr++;
	if( sessionInfoPtr->cryptAlgo != convertAlgoID( value ) )
		return( CRYPT_NOALGO );

	/* Generate the session ID */
	status = generateSessionID( sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* Check that the session cookie matches the returned one */
	if( memcmp( sessionInfoPtr->cookie, dataPtr, SSH_COOKIE_SIZE ) )
		return( CRYPT_BADDATA );
	dataPtr += SSH_COOKIE_SIZE;

	/* Import the double-encrypted secure state information */
	length = ( int ) mgetBLong( dataPtr );
	if( length < 512 || length > bytesToBits( CRYPT_MAX_PKCSIZE ) )
		return( CRYPT_BADDATA );
	length = bitsToBytes( length );
	status = importEncryptedSecret( dataPtr, length,
							sessionInfoPtr->iKeyexAuthContext, buffer );
	if( cryptStatusOK( status ) )
		status = importEncryptedSecret( buffer, 0,
										sessionInfoPtr->iKeyexCryptContext,
										sessionInfoPtr->secureState );

	/* XOR the state with the session ID to recover the actual state */
	for( i = 0; i < 16; i++ )
		( ( BYTE * ) sessionInfoPtr->secureState )[ i ] ^= sessionInfoPtr->sessionID[ i ];

	return( status );
	}

/* Get an SSH data packet from a session object */

int sshGetData( SESSION_INFO *sessionInfoPtr,
				const CRYPT_SESSIONDATA_TYPE type, void *data, int *length )
	{
	int status = CRYPT_BADPARM2;

	if( type == CRYPT_SESSIONDATA_HELLO )
		{
		/* Make sure that both the key exchange keys we require are set up */
		if( sessionInfoPtr->iKeyexCryptContext == CRYPT_ERROR || \
			sessionInfoPtr->iKeyexAuthContext == CRYPT_ERROR )
			return( CRYPT_NOTINITED );

		status = getServerPubkeyPacket( sessionInfoPtr, data );
		}
	if( type == CRYPT_SESSIONDATA_KEYEXCHANGE )
		{
		/* Make sure the session encryption keys aren't already set up */
		if( sessionInfoPtr->iCryptInContext != CRYPT_ERROR )
			return( CRYPT_INITED );

		status = getSessionKeyPacket( sessionInfoPtr, data );
		if( cryptStatusOK( status ) )
			status = initEncryption( sessionInfoPtr );
		}
	if( cryptStatusError( status ) )
		return( status );
	*length = status;
	return( CRYPT_OK );
	}

int sshAddData( SESSION_INFO *sessionInfoPtr, const void *data )
	{
	const BYTE *dataPtr = ( BYTE * ) data + SSH_HEADER_SIZE;
	int packetType, status;

	/* Unwrap the SSH wrapping */
	status = unwrapSshPacket( data, &packetType );
	if( cryptStatusError( status ) )
		return( status );
	if( packetType == SSH_CMSG_SESSION_KEY )
		{
		/* Make sure the session encryption keys aren't already set up */
		if( sessionInfoPtr->iCryptInContext != CRYPT_ERROR )
			return( CRYPT_INITED );

		status = addSessionKeyPacket( sessionInfoPtr, dataPtr );
		}
	else
		if( packetType == SSH_SMSG_PUBLIC_KEY )
			{
			/* Make sure the key exchange keys aren't already set up */
			if( sessionInfoPtr->iKeyexCryptContext != CRYPT_ERROR || \
				sessionInfoPtr->iKeyexAuthContext != CRYPT_ERROR )
				return( CRYPT_INITED );

			status = addServerPubkeyPacket( sessionInfoPtr, dataPtr );
			if( cryptStatusOK( status ) )
				status = initEncryption( sessionInfoPtr );
			}
		else
			status = CRYPT_BADDATA;

	return( status );
	}
