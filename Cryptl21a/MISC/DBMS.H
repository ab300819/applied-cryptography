/****************************************************************************
*																			*
*					  cryptlib Database Interface Header File 				*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

#ifndef _DBMS_DEFINED

#define _DBMS_DEFINED

/* Various include files needed by the DBMS libraries.  To enable the code
   for a particular database interface, define DBX_<database-type> (multiple
   database types can be defined, the required interface is selected at
   runtime).  Currently supported database types and operating systems are:

	DBX_ODBC		Windows - generic ODBC (always enabled under Windows)
	DBX_BSQL		Unix - Beagle SQL
	DBX_MSQL		Unix/Windows - mSQL
	DBX_MYSQL		Unix - MySQL
	DBX_ORACLE		Unix - Oracle
	DBX_POSTGRES	Unix - Postgres
	DBX_RAIMA		Unix/Windows - Raima Velocis
	DBX_SOLID		Unix/Windows - Solid
	DBX_LDAP		Unix/Windows - LDAP
	DBX_HTTP		Unix/Windows - HTTP

   The interface is probably portable to OS's other than the ones listed
   above provided they use the same API for the database libraries, but has
   only been tested with the given OS's */

#include <time.h>
#ifdef __WINDOWS__
  /* As part of the ever-changing way of identifying Win32, Microsoft changed
	 the predefined constant from WIN32 to _WIN32 in VC++ 2.1.  However the
	 ODBC header files still expect to find WIN32, and if this isn't defined
	 will use the default (ie C) calling convention instead of the Pascal
	 convention which is actually used by the ODBC functions.  This means
	 that both the caller and the callee clean up the stack, so that for each
	 ODBC call the stack creeps upwards by a few bytes until eventually the
	 local variables and/or return address get trashed.  This problem is
	 usually hidden by the fact that something else defines WIN32 so
	 everything works OK, but the October 1997 development platform upgrade
	 changes this so compiling the code after this update is installed breaks
	 things.

	 To avoid this problem, we define WIN32 if it isn't defined, which
	 ensures that the ODBC header files work properly */
  #if defined( __WIN32__ ) && !defined( WIN32 )
	#define WIN32
  #endif /* __WIN32__ && !WIN32 */
  #include <sql.h>
  #include <sqlext.h>
#endif /* __WINDOWS__ */
#ifdef DBX_BSQL
  #include "bsql.h"
#endif /* DBX_BSQL */
#ifdef DBX_MSQL
  #include "msql.h"
#endif /* DBX_MSQL */
#ifdef DBX_MYSQL
  #include <mysql.h>
#endif /* DBX_MYSQL */
#ifdef DBX_ORACLE
  #include "oratypes.h"
  #include "ocidfn.h"
  #include "ociapr.h"
#endif /* DBX_ORACLE */
#ifdef DBX_POSTGRES
  #include "libpq-fe.h"
#endif /* DBX_POSTGRES */
#if defined( DBX_RAIMA ) || defined( DBX_SOLID )
  #include "sql.h"
  #include "sqlext.h"
#endif /* DBX_RAIMA || DBX_SOLID */
#if ( defined( __WINDOWS__ ) || defined( __UNIX__ ) ) && defined( DBX_LDAP )
  /* These should really be taken from the system include directory but
     this leads to too many complaints from people who don't read the
	 LDAP installation section of the manual */
  #if defined( INC_ALL ) || defined( INC_CHILD )
	#include "lber.h"
	#include "ldap.h"
  #else
	#include "misc/lber.h"
	#include "misc/ldap.h"
  #endif /* Compiler-specific includes */
#endif /* ( __WINDOWS__ || __UNIX__ ) && DBX_LDAP */
#ifndef _STREAM_DEFINED
  #if defined( INC_ALL )
	#include "stream.h"
  #elif defined( INC_CHILD )
	#include "../keymgmt/stream.h"
  #else
	#include "keymgmt/stream.h"
  #endif /* Compiler-specific includes */
#endif /* _STREAM_DEFINED */
#if defined( INC_ALL )
  #include "scard.h"
#elif defined( INC_CHILD )
  #include "../misc/scard.h"
#else
  #include "misc/scard.h"
#endif /* Compiler-specific includes */

/* Whether we need to include support for DBMS access.  This define is
   enabled if the OS *might* support a DBMS, not if it definitely supports
   it, since the DBMS mapping layer is always compiled in on these OS's */

#if defined( __WINDOWS__ ) || defined( __UNIX__ )
  #define HAS_RDBMS
#endif /* Checks for RDBMS support */

/* The size of various fields, or the maximum size if the exact size is of
   variable length.  The keyID size is based on the size of an SHA-1 hash
   with or without base64 encoding (the base64 encoding adds up to 2 bytes of
   padding and a byte of null terminator, we strip the padding after encoding
   so the given encoded size is slightly shorter than normal).  The field
   size value is encoded into the SQL strings and is also given in text form
   for this purpose (without the terminator being included).  The SQL query
   size is the size of the DN and other components, the key ID's, and the key
   itself */

#define MAX_ENCODED_KEYID_SIZE		28		/* 49 for DigestInfo */
#define TEXT_KEYID_SIZE				"27"	/* "48" for DigestInfo */

#define MAX_KEYDATA_SIZE			1536
#define MAX_ENCODED_KEYDATA_SIZE	2048
#define TEXT_MAX_ENCODED_KEYDATA_SIZE	"2047"
#define MAX_SQL_QUERY_SIZE			( ( 7 * CRYPT_MAX_TEXTSIZE ) + \
									  ( 3 * MAX_ENCODED_KEYID_SIZE ) + \
									  MAX_ENCODED_KEYDATA_SIZE + 128 )

/* Some older compilers don't yet have the ANSI FILENAME_MAX define so we
   define a reasonable value here (the length is checked when we open the
   keyset so there's no chance it'll overflow even if the OS path limit is
   higher than what's defined here) */

#ifndef FILENAME_MAX
  #if defined( __MSDOS16__ )
	#define FILENAME_MAX	80
  #elif defined( __hpux )
	#include <sys/param.h>	/* HPUX's stdio.h defines this to be 14 (!!) */
	#define FILENAME_MAX	MAXPATHLEN
  #else
	#define FILENAME_MAX	256
  #endif /* __MSDOS16__ */
#endif /* FILENAME_MAX */

/* The maximum length of error message we can store */

#define MAX_ERRMSG_SIZE		512

/* The precise type of the key file we're working with.  This is used for
   type checking to make sure we don't try to find private keys in a
   collection of public-key certificates or whatever */

typedef enum {
	KEYSET_SUBTYPE_NONE,			/* Unknown */
	KEYSET_SUBTYPE_ERROR,			/* Bad keyset format */
	KEYSET_SUBTYPE_PGP_PUBLIC,		/* PGP public keyring */
	KEYSET_SUBTYPE_PGP_PRIVATE,		/* PGP private keyring */
	KEYSET_SUBTYPE_X509,			/* X.509 (public) key */
	KEYSET_SUBTYPE_NETSCAPE,		/* Netscape (private) key */
	KEYSET_SUBTYPE_CRYPTLIB			/* cryptlib (private) key */
	} KEYSET_SUBTYPE;

/* The state of a bulk update operation, used to store large amounts of
   data to a keyset at once */

typedef enum {
	BULKUPDATE_NONE,				/* No bulk update */
	BULKUPDATE_START,				/* Start of bulk update */
	BULKUPDATE_UPDATE,				/* Update in progress */
	BULKUPDATE_FINISH				/* End of bulk update */
	} BULKUPDATE_STATE;

/* The state of a database keyset query operation, used to retrive multiple
   keys from a keyset */

typedef enum {
	QUERY_NONE,						/* No query in progress */
	QUERY_INPROGRESS,				/* Query in progress */
	QUERY_COMPLETE					/* Query completed */
	} QUERY_STATE;

/* The internal fields in a keyset which hold data for the various keyset
   types.   These are implemented as a union to allow keyset-type-specific
   information to be passed to lower-level routines without having to have
   an entire keyset record present, and as a convenient side-effect to
   conserve memory with some of the more data-intensive types such as
   database keysets.  In addition the structures provide a convenient way to
   group the context-type-specific parameters */

typedef enum { KEYSET_NONE, KEYSET_FILE, KEYSET_DBMS, KEYSET_SMARTCARD,
			   KEYSET_LDAP } KEYSET_TYPE;

struct KI;	/* Forward declaration for argument to function pointers */

typedef struct {
	/* The I/O stream and file name, and whether the stream is currently
	   open */
	STREAM stream;					/* I/O stream for key file */
	char fileName[ FILENAME_MAX ];	/* Name of key file */
	BOOLEAN streamOpen;				/* Whether stream is open */
	} FILE_INFO;

typedef struct {
	/* DBMS status information */
	BOOLEAN needsUpdate;			/* Whether key DBX needs to be committed */
	BOOLEAN databaseOpen;			/* Whether connection to DBMS is open */
	BOOLEAN hasBinaryBlobs;			/* Whether DBMS supports binary blobs */
	BULKUPDATE_STATE bulkUpdateState;	/* State of DBMS bulk update */
	QUERY_STATE queryState;			/* State of DBMS query */

	/* The names of various database fields.  These are stored as part of
	   the keyset context since they may be user-defined or the library-wide
	   definition may change over time */
	char nameTable[ CRYPT_MAX_TEXTSIZE + 1 ];	/* Name of key collection table */
	char nameCRLTable[ CRYPT_MAX_TEXTSIZE + 1 ];/* Name of CRL table */
	char nameC[ CRYPT_MAX_TEXTSIZE + 1 ];		/* Name of C column */
	char nameSP[ CRYPT_MAX_TEXTSIZE + 1 ];		/* Name of SP column */
	char nameL[ CRYPT_MAX_TEXTSIZE + 1 ];		/* Name of L column */
	char nameO[ CRYPT_MAX_TEXTSIZE + 1 ];		/* Name of O column */
	char nameOU[ CRYPT_MAX_TEXTSIZE + 1 ];		/* Name of OU column */
	char nameCN[ CRYPT_MAX_TEXTSIZE + 1 ];		/* Name of CN column */
	char nameEmail[ CRYPT_MAX_TEXTSIZE + 1 ];	/* Name of email address col.*/
	char nameDate[ CRYPT_MAX_TEXTSIZE + 1 ];	/* Name of expiry date col.*/
	char nameNameID[ CRYPT_MAX_TEXTSIZE + 1 ];	/* Name of name ID column */
	char nameIssuerID[ CRYPT_MAX_TEXTSIZE + 1 ];/* Name of issuer ID column */
	char nameKeyID[ CRYPT_MAX_TEXTSIZE + 1 ];	/* Name of key ID column */
	char nameKeyData[ CRYPT_MAX_TEXTSIZE + 1 ];	/* Name of key data column */

	/* The maximum lenth of a table and column name (some legacy databases
	   only allow rather short names) */
	int maxColumnNameLen;			/* Max.column name length */
	int maxTableNameLen;			/* Max.table name length */

	/* For some database types or access methods, we need to bind the
	   locations of variables and use placeholders in the SQL text rather
	   than passing the data as part of the SQL.  The following variables are
	   the storage which is bound.  If the database supports blobs, we also
	   have to record the length of the key blob.  In addition we record the
	   name of the blob data type (set when we open the database) in case
	   this is needed */
  #ifdef __WINDOWS__
	TIMESTAMP_STRUCT boundDate;
  #endif /* __WINDOWS__ */
	char boundNameID[ MAX_ENCODED_KEYID_SIZE ];
	char boundIssuerID[ MAX_ENCODED_KEYID_SIZE ];
	char boundKeyID[ MAX_ENCODED_KEYID_SIZE ];
	char boundKeyData[ MAX_ENCODED_KEYDATA_SIZE ];
	int boundKeyDataLen;
	char blobName[ 64 ];

	/* When we're binding the information we perform an update which doesn't
	   actually send any data to the database backend.  The following flag
	   records whether we're performing a data update on the database or
	   not */
	BOOLEAN isDataUpdate;			/* Whether an update is sending data */

	/* Database-specific information */
  #ifdef __WINDOWS__
	/* ODBC access information */
	HENV hEnv;						/* Environment handle */
	HDBC hDbc;						/* Connection handle */
	HSTMT hStmt;					/* Statement handle */
	SWORD blobType;					/* SQL type of blob data type */
	SDWORD cbBlobLength;			/* Length of key (blob) data */
  #endif /* __WINDOWS__ */
  #ifdef DBX_BSQL
	int socket;						/* Connection handle */
	struct bresult result;			/* Query result */
  #endif /* DBX_BSQL */
  #ifdef DBX_MSQL
	int sock;						/* Connection handle */
  #endif /* DBX_MSQL */
  #ifdef DBX_MYSQL
	MYSQL *connection;				/* Connection handle */
  #endif /* DBX_MYSQL */
  #ifdef DBX_ORACLE
	Lda_Def lda;					/* Logon data area */
	ub1 hda[ 256 ];					/* Host data area */
	Cda_Def cda;					/* Cursor data area */
  #endif /* DBX_ORACLE */
  #ifdef DBX_POSTGRES
	PGconn *pgConnection;			/* Connection handle */
	PGresult *pgResult;				/* Query result handle */
  #endif /* DBX_POSTGRES */
  #if defined( DBX_RAIMA ) || defined( DBX_SOLID )
	/* ODBC-like interface access information */
	HENV hEnv;						/* Environment handle */
	HDBC hDbc;						/* Connection handle */
	HSTMT hStmt;					/* Statement handle */
	SWORD blobType;					/* SQL type of blob data type */
	SDWORD cbBlobLength;			/* Length of key (blob) data */
  #endif /* DBX_RAIMA || DBX_SOLID */

	/* When storing a cert we need the certificate DN, email address,
	   and cert expiry date */
	char C[ CRYPT_MAX_TEXTSIZE + 1 ], SP[ CRYPT_MAX_TEXTSIZE + 1 ],
		L[ CRYPT_MAX_TEXTSIZE + 1 ], O[ CRYPT_MAX_TEXTSIZE + 1 ],
		OU[ CRYPT_MAX_TEXTSIZE + 1 ], CN[ CRYPT_MAX_TEXTSIZE + 1 ];
	char email[ CRYPT_MAX_TEXTSIZE + 1 ];
	time_t date;

	/* Pointers to open/close methods */
	int ( *openDatabase )( struct KI *keysetInfo, const char *name,
						   const char *server, const char *user,
						   const char *password );
	void ( *closeDatabase )( struct KI *keysetInfo );

	/* Pointers to the access methods */
	int ( *performUpdate )( struct KI *keysetInfo, const char *command );
	int ( *performBulkUpdate )( struct KI *keysetInfo, const char *command );
	int ( *performCheck )( struct KI *keysetInfo, const char *command );
	int ( *performQuery )( struct KI *keysetInfo, const char *command,
						   char *data, int *dataLength, const int maxLength );
	} DBMS_INFO;

typedef struct {
	/* An HTTP fetch differs from the other types of read in that it can
	   return data in multiple chunks depending on how much comes over the
	   net at once, and it can return large files (eg long CRL's).  Because
	   of this we need to track what's come in, and also allocate more
	   buffer space on demand if required */
	BYTE *buffer;					/* Data buffer */
	int bufSize;					/* Allocated buffer size */
	int bufPos;						/* Current position in buffer */
	} HTTP_INFO;

typedef struct {
	/* LDAP status information */
	BOOLEAN directoryOpen;			/* Whether connection to LDAP directory open */
	QUERY_STATE queryState;			/* State of directory query */

#ifdef DBX_LDAP
	/* LDAP access information */
	LDAP *ld;						/* LDAP connection information */
	void *result;					/* State information for ongoing queries */
#endif /* DBX_LDAP */

	/* The names of the object class and various attributes.  These are
	   stored as part of the keyset context since they may be user-defined or
	   the library-wide definition may change over time */
	char nameObjectClass[ CRYPT_MAX_TEXTSIZE + 1 ];	/* Name of object class */
	char nameCACert[ CRYPT_MAX_TEXTSIZE + 1 ];	/* Name of CA cert attribute */
	char nameCert[ CRYPT_MAX_TEXTSIZE + 1 ];	/* Name of cert attribute */
	char nameCRL[ CRYPT_MAX_TEXTSIZE + 1 ];		/* Name of CRL attribute */
	char nameEmail[ CRYPT_MAX_TEXTSIZE + 1 ];	/* Name of email addr.attribute */

	/* When storing a cert we need the certificate DN, email address,
	   and cert expiry date */
	char C[ CRYPT_MAX_TEXTSIZE + 1 ], SP[ CRYPT_MAX_TEXTSIZE + 1 ],
		L[ CRYPT_MAX_TEXTSIZE + 1 ], O[ CRYPT_MAX_TEXTSIZE + 1 ],
		OU[ CRYPT_MAX_TEXTSIZE + 1 ], CN[ CRYPT_MAX_TEXTSIZE + 1 ];
	char email[ CRYPT_MAX_TEXTSIZE + 1 ];
	time_t date;

	/* Pointers to open/close methods */
	int ( *openDatabase )( struct KI *keysetInfo, const char *name,
						   const char *server, const char *user,
						   const char *password );
	void ( *closeDatabase )( struct KI *keysetInfo );
	} LDAP_INFO;

/* Defines to make access to the union fields less messy */

#define keysetFile		keysetInfo.fileInfo
#define keysetDBMS		keysetInfo.dbmsInfo
#define keysetScard		keysetInfo.scardInfo
#define keysetHTTP		keysetInfo.httpInfo
#define keysetLDAP		keysetInfo.ldapInfo

/* The structure which stores information on a keyset */

typedef struct KI {
	/* General keyset information */
	CRYPT_KEYSET_TYPE type;			/* Keyset type (native, PGP, X.509, etc) */
	KEYSET_SUBTYPE subType;			/* Keyset subtype (public, private, etc) */
	CRYPT_KEYOPT_TYPE options;		/* Keyset option flags */
	BOOLEAN keysetEmpty;			/* Whether keyset is empty */
	BOOLEAN isDatabaseKeyset;		/* Whether it's a database keyset */

	/* The keyset-type-specific information */
	union {
		FILE_INFO fileInfo;
		DBMS_INFO dbmsInfo;
		SCARD_INFO scardInfo;
		HTTP_INFO httpInfo;
		LDAP_INFO ldapInfo;
		} keysetInfo;				/* Keyset-specific information */

	/* Last-error information.  To help developers in debugging, we store
	   the error code and error text (if available) */
	int errorCode;
	char errorMessage[ MAX_ERRMSG_SIZE ];

	/* Information required when "cloning" a keyset context.  Unlike
	   encryption contexts, we can't easily clone a keyset because the
	   information may be expensive to clone (database connections), unique
	   (card readers), or impossible to access (file stream information held
	   by the OS).  One way to get around this is to utilise the approach
	   used in multi-tier ODBC drivers where a single lower (tier 1) level of
	   driver interfaces to the underlying keyset and a multitude of higher
	   (tier 2) level of drivers interface to the tier 1 driver and maintain
	   state information.

	   However this approach leads to all sorts of complications, as
	   evidenced by the complexity and bugginess of many ODBC drivers, and
	   the fact that the majority of them still don't implement this type of
	   functionality (very few ODBC drivers are thread-safe).  This is a good
	   indication of how difficult it is to implement this.  For this reason
	   we use a slightly different approach which almost always looks like
	   real cloning to the caller but doesn't require the complexity of the
	   multi-tier driver approach.

	   Every time a keyset context is cloned, its reference count is
	   increased by one.  A call to cryptKeysetClose() decrements the
	   reference count and makes the object inaccessible from outside
	   cryptlib, but doesn't actually delete the object until the reference
	   count goes back to zero.  This means the caller can open a keyset,
	   push it into an envelope, and close it again and the object will
	   still be available from the envelope (since the call to access the
	   keyset is coming from within cryptlib, it isn't blocked).

	   To ensure consistency, public-key keysets are made read-only (if
	   they're not already read-only) once they're cloned (for keysets used
	   in enveloping it's extremely unlikely that they'll be opened in
	   anything other than read-only mode).  Private-key keysets are a bit
	   more complex since they perform key cacheing, so they're made
	   inaccessible to the caller while the envelope is active (any attempt
	   to access the keyset will return CRYPT_BUSY).  Thus access attempts on
	   a cloned keyset will function as follows:

				| Private 		| Public
		--------+---------------+---------
		Read	| CRYPT_BUSY	| OK
		Write	| CRYPT_NOPERM	| CRYPT_NOPERM
		Close	| OK			| OK

	   A slight variant of this scheme is to disallow cloning unless the
	   keyset is opened with CRYPT_KEYOPT_READONLY, however this requires
	   that the user reads the documentation whereas the above scheme almost
	   always works without the user even knowing it's happening.

	   To keep track of the information needed for this pseudocloning, we
	   keep a copy of the keyset options before the keyset was made read-only
	   by the pseudocloning process */
	CRYPT_KEYOPT_TYPE savedOptions;	/* Saved copy of original options */

	/* The keyset may have a service routine associated with it to handle
	   callback-type functions such as connection status checks.  The
	   following information records service routine-related data */
	int serviceID;

	/* A copy of the ID used to identify the key for private-key reads.  This
	   is used to identify repeated reads of the same key (for example if an
	   incorrect password is used), which allows the cached key to be
	   reused */
	BYTE cachedKeyTag[ CRYPT_MAX_TEXTSIZE ];

	/* The key ID for the currently cached key and the cached key, and a flag
	   to indicate whether a cached key is present.  The key ID is used when
	   updating a private key keyset to make sure the certificate being added
	   matches the private key in the keyset */
	BYTE cachedKeyID[ KEYID_SIZE ];
	BYTE cachedKey[ MAX_PRIVATE_KEYSIZE ];
	BOOLEAN cachedKeyPresent;

	/* When we attach a certificate to the key in a private key keyset, we do
	   it by reading the encoded private key into the key cache and adding
	   the certificate.  The fact that we're performing this special kind of
	   update (in which a public key can be added to a private key) is
	   recorded by the following flag.  Since having this flag set affects
	   the nature of the keyset object, we only set it if the cached private
	   key read works, and reset it either once the cert has been added or if
	   any other type of operation is performed */
	BOOLEAN cachedUpdate;			/* Whether this is update of cached key */

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
	} KEYSET_INFO;

/* Prototypes for DBMS mapping functions */

int setAccessMethodODBC( KEYSET_INFO *keysetInfo );
int setAccessMethodBSQL( KEYSET_INFO *keysetInfo );
int setAccessMethodMSQL( KEYSET_INFO *keysetInfo );
int setAccessMethodMySQL( KEYSET_INFO *keysetInfo );
int setAccessMethodOracle( KEYSET_INFO *keysetInfo );
int setAccessMethodPostgres( KEYSET_INFO *keysetInfo );
int setAccessMethodRaima( KEYSET_INFO *keysetInfo );
int setAccessMethodSolid( KEYSET_INFO *keysetInfo );

/* Prototypes for LDAP mapping functions */

int setAccessMethodLDAP( KEYSET_INFO *keysetInfo );

#endif /* DBMS_DEFINED */
