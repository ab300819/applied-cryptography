/****************************************************************************
*																			*
*					  cryptlib Device Interface Header File 				*
*						Copyright Peter Gutmann 1998-1999					*
*																			*
****************************************************************************/

#ifndef _DEVICE_DEFINED

#define _DEVICE_DEFINED

#if defined( INC_ALL )
  #include "scard.h"
#elif defined( INC_CHILD )
  #include "../misc/scard.h"
#else
  #include "misc/scard.h"
#endif /* Compiler-specific includes */

/* The maximum length of error message we can store */

#define MAX_ERRMSG_SIZE		512

/* The structure which stores information on a device */

typedef struct DI {
	/* General device information.  Alongside various handles used to access
	   the device we also record whether the user has authenticated
	   themselves to the device since some devices have multiple user-access
	   states and the user needs to be logged out of one state before they
	   can log in to another state */
	CRYPT_DEVICE_TYPE type;			/* Device type */
	long deviceHandle;				/* Handle to the device */
	long slotHandle;				/* Handle to slot for multi-device */
	BOOLEAN loggedIn;				/* Whether user is logged into device */
	BOOLEAN readOnly;				/* Whether device can't be written to */

	/* Plug-in devices can provide various capabilities, so we maintain a
	   per-device capability list rather than the fixed table for the built-
	   in capabilities */
	void *capabilityInfoPtr;

	/* Some devices have minimum and maximum PIN/password lengths, if these
	   are known we record them when the device is initialised */
	int minPinSize, maxPinSize;		/* Minimum, maximum PIN lengths */

	/* Last-error information.  To help developers in debugging, we store
	   the error code and error text (if available) */
	int errorCode;
	char errorMessage[ MAX_ERRMSG_SIZE ];

	/* Pointers to device access methods */
	int ( *initDeviceFunction )( struct DI *deviceInfo );
	void ( *shutdownDeviceFunction )( struct DI *deviceInfo );
	int ( *controlFunction )( struct DI *deviceInfo,
							  const CRYPT_DEVICECONTROL_TYPE type,
							  const void *data1, const int data1Length,
							  const void *data2, const int data2Length );
	int ( *findCapabilityFunction )( struct DI *deviceInfo,
									 const void FAR_BSS **capabilityInfoPtr,
									 const CRYPT_ALGO cryptAlgo,
									 const CRYPT_MODE cryptMode );
	int ( *createContextFunction )( struct DI *deviceInfo,
									CRYPT_CONTEXT *cryptContext,
									const CRYPT_ALGO cryptAlgo,
									const CRYPT_MODE cryptMode );
	int ( *instantiateNamedObjectFunction )( struct DI *deviceInfo,
											 CRYPT_CONTEXT *cryptContext,
											 const char *name,
											 const BOOLEAN isPublicKey );
	int ( *getRandomFunction)( struct DI *deviceInfo, void *buffer,
							   const int length );

	/* Device information for smart card devices */
	SCARD_INFO deviceScard;

	/* Information for PKCS #11 devices */
	int deviceNo;					/* Index into PKCS #11 token table */

	/* When we clone an object, there are certain per-instance fields which
	   don't get cloned.  These fields are located after the following
	   member, and must be initialised by the cloning function */
	int _sharedEnd;					/* Dummy used for end of shared fields */

	/* The object handle, used when sending messages to the object from
	   functions when only the DEVICE_INFO data is available */
	CRYPT_DEVICE objectHandle;

	/* The reference count for this object.  If this drops below zero, the
	   object is destroyed */
	int refCount;					/* Reference count for object */

	/* In multithreaded environments we need to protect the information from
	   access by other threads while we use it.  The following macro declares
	   the actual variables required to handle the resource locking (the
	   actual values are defined in cryptos.h) */
	DECLARE_RESOURCE_LOCKING_VARS
	} DEVICE_INFO;

/* Prototypes for the low-level capability checking and context-creation
   functions used when creating a context in a device.  We only provide
   prototypes for these functions when they're being included into a module
   which has the CAPABILITY_INFO structure available */

#if defined( _CRYPTCTX_DEFINED )

int checkCapability( const CAPABILITY_INFO *capabilityInfoPtr );
int createContext( CRYPT_CONTEXT *cryptContext,
				   const CAPABILITY_INFO *capabilityInfoPtr,
				   const void *cryptInfoEx, const int objectFlags );

#endif /* _CRYPTCTX_DEFINED */

/* Prototypes for device mapping functions */

int setDeviceFortezza( DEVICE_INFO *deviceInfo );
int setDeviceCEI( DEVICE_INFO *deviceInfo );
int setDevicePKCS11( DEVICE_INFO *deviceInfo, const char *name );

#endif /* _DEVICE_DEFINED */
