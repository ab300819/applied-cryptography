/****************************************************************************
*																			*
*					cryptlib Smart Card Interface Header File 				*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

#ifndef _SCARD_DEFINED

#define _SCARD_DEFINED

/* The data structure for storing comms parameters for serial-port based
   devices.  The port number is encoded in an OS-specific manner, under
   Windows it's the number of the COM port - 1 (so COM1 is 0), under Unix
   it's the encoded form of the serial device */

typedef enum { COMM_PARITY_NONE, COMM_PARITY_EVEN, COMM_PARITY_ODD } COMM_PARITY_TYPE;

typedef struct {
	int port;						/* Port name and number (OS-specific) */
	char portName[ CRYPT_MAX_TEXTSIZE ];
	long baudRate;					/* Baud rate */
	int dataBits;					/* Data bits */
	COMM_PARITY_TYPE parity;		/* Parity */
	int stopBits;					/* Stop bits */
	} COMM_PARAMS;

/* Structure used to map user-supplied strings to reader-specific magic
   numbers */

typedef struct {
	const char *string;				/* Text string */
	const int value;				/* Corresponding magic number */
	} STRINGMAP_INFO;

/* The different smart card types which we recognise */

typedef enum { SCARD_CRYPTOFLEX, SCARD_PAYFLEX1K, SCARD_DX, SCARD_COS,
			   SCARD_RG200, SCARD_CHIPKNIP1, SCARD_CHIPKNIP2_CC60,
			   SCARD_CHIPKNIP2_CC1000, SCARD_SMARTSCOPE1, SCARD_SMARTSCOPE3,
			   SCARD_DIGICASH, SCARD_CAFE, SCARD_CHIPPER, SCARD_WAFERCARD,
			   SCARD_ACOS1, SCARD_MULTIFLEX, SCARD_MPCOS_3DES, SCARD_GPK2000,
			   SCARD_STARCOS, SCARD_SIGNASURE, SCARD_TB1000, SCARD_TB98S,
			   SCARD_GELDKARTE
			   } SCARD_TYPE;

/* PKCS #15 ODF and PrKDF information */

#define MAX_EF_PATHLEN	16		/* Maximum length of a path in the ODF */

typedef struct {
	/* General information on the item */
	BOOLEAN new, dirty;			/* Whether ODF is new or needs updating */

	/* Directory information */
	BYTE prKDF[ MAX_EF_PATHLEN + 1 ];	/* Path to private key EF */
	BYTE puKDF[ MAX_EF_PATHLEN + 1 ];	/* Path to public key EF */
	BYTE sKDF[ MAX_EF_PATHLEN + 1 ];	/* Path to secret key EF */
	BYTE cDF[ MAX_EF_PATHLEN + 1 ];		/* Path to cert EF */
	BYTE dODF[ MAX_EF_PATHLEN + 1 ];	/* Path to data object EF */
	BYTE authDF[ MAX_EF_PATHLEN + 1 ];	/* Path to authent.object EF */
	} ODF_INFO;

typedef struct {
	/* General information on the item */
	BOOLEAN new, dirty;			/* Whether ODF is new or needs updating */
	} PRKDF_INFO;

/* Information on a card reader and card.  This is used by higher-level
   objects like keysets and device objects */

typedef struct SC {
	/* The card type which we're working with */
	SCARD_TYPE type;

	/* A handle to the smart card reader and optional session to the card,
	   the type of card which is present in the reader (this is a reader-
	   specific type which doesn't correspond to an SCARD_TYPE and is usually
	   used to denote the protocol required to talk to the card), and a
	   pointer to card reader and card-specific information.  The
	   interpretation of these values depends on the reader type and driver
	   software */
	int readerHandle;				/* Handle to reader */
	int cardHandle;					/* Optional handle to card in reader */
	int cardType;					/* Reader-specific card type */
	void *cardInfo;					/* Reader-specific extra info */

	/* PKCS #15 information */
	ODF_INFO odfInfo;				/* ODF for card */
	PRKDF_INFO prKDFInfo;			/* PrKDF for card */

	/* Error information.  These values point back to the actual storage in
	   the encapsulating object */
	int *errorCode;
	char *errorMessage;

	/* Pointers to the access methods */
	int ( *initReader )( struct SC *scardInfo, const char *readerName,
						 const char *cardName, const COMM_PARAMS *commParams );
	void ( *shutdownReader )( struct SC *scardInfo );
	int ( *readData )( struct SC *scardInfo, BYTE *data );
	int ( *writeData )( struct SC *scardInfo, const BYTE *data,
						const int length );
	} SCARD_INFO;

/* Get and check user-supplied comm params, get card type in reader, map a
   text string to a reader-specific magic number */

int getCommParams( COMM_PARAMS *commParams, const char *commParamStr,
				   const BOOLEAN longFormOK );
int getCardType( const BYTE *atr, const int atrLength );
int stringToValue( const STRINGMAP_INFO *stringmapInfo, const char *string );

/* Prototypes for smart card reader mapping functions */

int setAccessMethodASE( SCARD_INFO *scardInfo );
int setAccessMethodAuto( SCARD_INFO *scardInfo );
int setAccessMethodTowitoko( SCARD_INFO *scardInfo );
int setAccessMethodGemplus( SCARD_INFO *scardInfo );

/* Some card reader types aren't supported on some platforms, so we replace a
   call to the mapping functions with an error code */

#ifndef __WIN32__
  #define setAccessMethodASE( x )		CRYPT_ERROR
#endif /* __WIN32__ */
#ifndef __WINDOWS__
  #define setAccessMethodTowitoko( x )	CRYPT_ERROR
  #define setAccessMethodGemplus( x )	CRYPT_ERROR
#endif /* !__WINDOWS__ */
#if !( defined( __UNIX__ ) || defined( __WIN32__ ) )
  #define setAccessMethodAuto( x )		CRYPT_ERROR
#endif /* !( __UNIX__ || __WIN32__ ) */
#if !( defined( __UNIX__ ) || defined( __WINDOWS__ ) )
  #define getCommParams( x, y, z )		CRYPT_ERROR
#endif /* !( __UNIX__ || __WINDOWS__ ) */

#endif /* SCARD_DEFINED */
