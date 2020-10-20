/****************************************************************************
*																			*
*						cryptlib Test Routines Header File					*
*						Copyright Peter Gutmann 1995-1999					*
*																			*
****************************************************************************/

#include <time.h>

/* Various useful types */

#define BOOLEAN	int
#define BYTE	unsigned char
#ifndef TRUE
  #define FALSE	0
  #define TRUE	!FALSE
#endif /* TRUE */

/* There are a few OS's broken enough not to define the standard exit codes
   (SunOS springs to mind) so we define some sort of equivalent here just
   in case */

#ifndef EXIT_SUCCESS
  #define EXIT_SUCCESS	0
  #define EXIT_FAILURE	!EXIT_SUCCESS
#endif /* EXIT_SUCCESS */

/* If we're using a DOS compiler but not a 32-bit one, record this */

#if defined( __MSDOS__ ) && !defined( __MSDOS32__ )
  #define __MSDOS16__
#endif /* __MSDOS__ && !__MSDOS32__ */

/* In certain memory-starved environments we have to kludge things to help
   the compiler along.  The following define tells the compiler to move BSS
   data outside the default data segment */

#if defined( _MSC_VER ) && ( _MSC_VER <= 800 )
  #define FAR_BSS			far
#else
  #define FAR_BSS
#endif /* Win16 */

/* The key size to use for the PKC routines.  This is the minimum allowed by
   cryptlib, it speeds up the various tests but shouldn't be used in
   practice */

#define PKC_KEYSIZE			512

/* The names of the test key and certificate files.  DSA/RSA_PRIVKEY_FILE is
   the test private key file which is created and modified during the testing
   process. CA_PRIVKEY_FILE and USER_PRIVKEY_FILE are the CA private key +
   cert and user private key + cert chain */

#ifdef _MSC_VER
  #define DSA_PRIVKEY_FILE		"../test/privkeyd.der"
  #define RSA_PRIVKEY_FILE		"../test/privkeyr.der"
  #define CA_PRIVKEY_FILE		"../test/ca_key.der"
  #define USER_PRIVKEY_FILE		"../test/user_key.der"
  #define PGP_PUBKEY_FILE		"../test/pubring.pgp"
  #define PGP_PRIVKEY_FILE		"../test/secring.pgp"

  #define CERT_FILE				"../test/cert.der"
  #define CERTREQ_FILE			"../test/cert_req.der"
  #define CRL_FILE				"../test/cert_crl.der"
  #define CERTCHAIN_FILE		"../test/cert_chn.der"
  #define SPKAC_FILE			"../test/cert_spk.der"
  #define CRLCERT1_FILE			"../test/crlcert1.der"
  #define CRLCERT2_FILE			"../test/crlcert2.der"

  #define SMIME_SIGNED_FILE		"../test/smime.p7s"
  #define SMIME_ENVELOPED_FILE	"../test/smime.p7m"
#else
  #define DSA_PRIVKEY_FILE		"test/privkeyd.der"
  #define RSA_PRIVKEY_FILE		"test/privkeyr.der"
  #define CA_PRIVKEY_FILE		"test/ca_key.der"
  #define USER_PRIVKEY_FILE		"test/user_key.der"
  #define PGP_PUBKEY_FILE		"test/pubring.pgp"
  #define PGP_PRIVKEY_FILE		"test/secring.pgp"

  #define CERT_FILE				"test/cert.der"
  #define CERTREQ_FILE			"test/cert_req.der"
  #define CRL_FILE				"test/cert_crl.der"
  #define CERTCHAIN_FILE		"test/cert_chn.der"
  #define SPKAC_FILE			"test/cert_spk.der"
  #define CRLCERT1_FILE			"test/crlcert1.der"
  #define CRLCERT2_FILE			"test/crlcert2.der"

  #define SMIME_SIGNED_FILE		"test/smime.p7s"
  #define SMIME_ENVELOPED_FILE	"test/smime.p7m"
#endif /* More MSC braindamage */

/* The password for the private key keysets */

#define CA_PRIVKEY_PASSWORD		"test"
#define USER_PRIVKEY_PASSWORD	"test"

/* The database keyset type and name.  Under Windoze we use ODBC, for
   anything else we use the first database which is enabled by a preprocessor
   define, defaulting to mSQL (which doesn't have to be available, if it's
   not present we continue after printing a warning) */

#if defined( _MSC_VER )
  #define DATABASE_KEYSET_TYPE	CRYPT_KEYSET_ODBC
#elif defined( DBX_BSQL )
  #define DATABASE_KEYSET_TYPE	CRYPT_KEYSET_BSQL
#elif defined( DBX_MSQL )
  #define DATABASE_KEYSET_TYPE	CRYPT_KEYSET_MSQL
#elif defined( DBX_MYSQL )
  #define DATABASE_KEYSET_TYPE	CRYPT_KEYSET_MYSQL
#elif defined( DBX_ORACLE )
  #define DATABASE_KEYSET_TYPE	CRYPT_KEYSET_ORACLE
#elif defined( DBX_POSTGRES )
  #define DATABASE_KEYSET_TYPE	CRYPT_KEYSET_POSTGRES
#elif defined( DBX_RAIMA )
  #define DATABASE_KEYSET_TYPE	CRYPT_KEYSET_RAIMA
#elif defined( DBX_SOLID )
  #define DATABASE_KEYSET_TYPE	CRYPT_KEYSET_SOLID
#else
  #define DATABASE_KEYSET_TYPE	CRYPT_KEYSET_MSQL
#endif /* Various database backends */
#define DATABASE_KEYSET_NAME	"testkeys"

/* The LDAP keyset name (hey, it's local for me).  There's a list of more
   LDAP servers at http://www.dante.net/np/pdi.html, none of these are known
   to contain certificates */

#define LDAP_KEYSET_NAME		"ldap.mcs.vuw.ac.nz"

/* The HTTP keyset name (actually a URL for a page containing a cert) */

#define HTTP_KEYSET_NAME		"www.thawte.com/persfree.crt"

/* A structure which allows us to specify a collection of extension
   components.  This is used when adding a collection of extensions to a
   cert */

typedef enum { IS_VOID, IS_NUMERIC, IS_STRING, IS_TIME } COMPONENT_TYPE;

typedef struct {
	const CRYPT_CERTINFO_TYPE type;	/* Extension component ID */
	const COMPONENT_TYPE componentType;	/* Component type */
	const int numericValue;			/* Value if numeric */
	const char *stringValue;		/* Value if string */
	const time_t timeValue;			/* Value if time */
	} CERT_DATA;

/* Prototypes for functions in certutil.c */

void printCertErrorInfo( const CRYPT_CERTIFICATE certificate );
void printCertInfo( const CRYPT_CERTIFICATE certificate );
int importCertFile( CRYPT_CERTIFICATE *cryptCert, const char *fileName );
int addCertFields( const CRYPT_CERTIFICATE certificate,
				   const CERT_DATA *certData );
int getPrivateKey( CRYPT_CONTEXT *cryptContext, const char *keysetName,
				   const char *password );
void debugDump( const char *fileName, const void *data,
				const int dataLength );

/* Prototypes for functions in testlib.c */

BOOLEAN loadRSAContexts( const CRYPT_DEVICE cryptDevice,
						 CRYPT_CONTEXT *cryptContext,
						 CRYPT_CONTEXT *decryptContext );
BOOLEAN loadRSALargeContext( CRYPT_CONTEXT *cryptContext );
BOOLEAN loadDSAContexts( CRYPT_CONTEXT *signContext,
						 CRYPT_CONTEXT *sigCheckContext );
BOOLEAN loadDHContexts( CRYPT_CONTEXT *cryptContext1,
						CRYPT_CONTEXT *cryptContext2, int keySize );
void destroyContexts( CRYPT_CONTEXT cryptContext, CRYPT_CONTEXT decryptContext );
CRYPT_ALGO selectCipher( const CRYPT_ALGO algorithm );
