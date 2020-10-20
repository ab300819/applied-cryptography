/****************************************************************************
*																			*
*						Secure Session Routines Header File					*
*						 Copyright Peter Gutmann 1998-1999					*
*																			*
****************************************************************************/

#ifndef _SES_DEFINED

#define _SES_DEFINED

/* The size of the secure state information for various session types */

#define STATE_SIZE_SSH		32		/* 256 bytes */

/* The structure which stores the information on a session */

typedef struct SI {
	/* Control and status information */
	CRYPT_FORMAT_TYPE type;			/* Session type */
	BOOLEAN isHost;					/* Whether object is host or client */
	CRYPT_ALGO cryptAlgo;			/* Negotiated encryption algo */
	CRYPT_ALGO integrityAlgo;		/* Negotiated integrity protection algo */

	/* Storage for general session state information */
	BYTE cookie[ CRYPT_MAX_HASHSIZE ];	/* Session cookie */
	BYTE sessionID[ CRYPT_MAX_HASHSIZE ];	/* Session ID */

	/* Secure storage for session state information (eg the SSL master
	   secret or the SSH 256-bit secret value) */
	void *secureState;				/* Crypto-related state information */

	/* The session generally has various contexts associated with it, some
	   short-term (eg public-key contexts used to establish the session) and
	   some long-term (eg encryption contexts used to perform bulk data
	   encryption).  The following values store these contexts */
	CRYPT_CONTEXT iKeyexCryptContext;	/* Key exchange encryption */
	CRYPT_CONTEXT iKeyexAuthContext;/* Key exchange authentication */
	CRYPT_CONTEXT iCryptInContext, iCryptOutContext;
									/* In/outgoing data encryption */
	CRYPT_CONTEXT iAuthInContext, iAuthOutContext;
									/* In/outgoing authentication */

	/* Pointers to the enveloping/deenveloping functions */
	int ( *addInfo )( struct SI *sessionInfoPtr,
					  const CRYPT_SESSINFO_TYPE sessionInfo,
					  const void *value, const int valueLength );
	int ( *getData )( struct SI *sessionInfoPtr,
					  const CRYPT_SESSIONDATA_TYPE type, void *data,
					  int *length );
	int ( *addData )( struct SI *sessionInfoPtr, const void *data );

	/* When we clone an object, there are certain per-instance fields which
	   don't get cloned.  These fields are located after the following
	   member, and must be initialised by the cloning function */
	int _sharedEnd;					/* Dummy used for end of shared fields */

	/* The reference count for this object.  If this drops below zero, the
	   object is destroyed */
	int refCount;					/* Reference count for object */

	/* In multithreaded environments we need to protect the information from
	   access by other threads while we use it.  The following macro declares
	   the actual variables required to handle the resource locking (the
	   actual values are defined in cryptos.h) */
	DECLARE_RESOURCE_LOCKING_VARS
	} SESSION_INFO;

/* Prototypes for functions in keymgmt/asn1keys.c */

int writeAdhocPublicKey( void *data, const CRYPT_CONTEXT iCryptContext );
int readAdhocPublicKey( const void *data, CRYPT_CONTEXT *iCryptContext );

#endif /* _SES_DEFINED */
