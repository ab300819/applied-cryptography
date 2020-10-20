/****************************************************************************
*																			*
*						  cryptlib Keyset Test Routines						*
*						Copyright Peter Gutmann 1995-1999					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _MSC_VER
  #include "../capi.h"
  #include "../test/test.h"
#else
  #include "capi.h"
  #include "test/test.h"
#endif /* Braindamaged MSC include handling */

/* External flag which indicates that the key read routines work OK.  This is
   set by earlier self-test code, if it isn't set some of the enveloping
   tests are disabled */

extern int keyReadOK;

/****************************************************************************
*																			*
*							Keyset Access Routines Test						*
*																			*
****************************************************************************/

/* Get a public key from a PGP keyring */

int testGetPGPPublicKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	FILE *filePtr;
	int status;

	/* Check that the file actually exists so we can return an appropriate
	   error message */
	if( ( filePtr = fopen( PGP_PUBKEY_FILE, "rb" ) ) == NULL )
		return( CRYPT_ERROR );
	fclose( filePtr );
	keyReadOK = FALSE;

	puts( "Testing PGP public key read..." );

	/* Try and open the keyset and try to read the required key */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  PGP_PUBKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Get the key */
	status = cryptGetPublicKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
								"test" );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetPublicKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( "Read of public key from PGP keyring succeeded.\n" );
	return( TRUE );
	}

/* Get a private key from a PGP keyring */

int testGetPGPPrivateKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	FILE *filePtr;
	int status;

	/* Check that the file actually exists so we can return an appropriate
	   error message */
	if( ( filePtr = fopen( PGP_PRIVKEY_FILE, "rb" ) ) == NULL )
		return( CRYPT_ERROR );
	fclose( filePtr );

	puts( "Testing PGP private key read..." );

	/* Try and open the keyset and try to read the required key */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  PGP_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Get the key.  First we try it without a password, if that fails we
	   retry it with the password - this tests a lot of the private-key get
	   functionality including things like key cacheing */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
 								 "test10", NULL );
	if( status == CRYPT_WRONGKEY )
		{
		/* We need a password for this private key, get it from the user and
		   get the key again */
		status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
									 CRYPT_KEYID_NAME, "test10", "test10" );
		}
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetPrivateKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Both key reads worked, remember this for later */
	keyReadOK = TRUE;

	puts( "Read of private key from PGP keyring succeeded.\n" );
	return( TRUE );
	}

/* Read/write a private key from a file */

static int readFileKey( const BOOLEAN useRSA )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int status;

	printf( "Testing %s private key file read...\n", useRSA ? "RSA" : "DSA" );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  useRSA ? RSA_PRIVKEY_FILE : DSA_PRIVKEY_FILE,
							  CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Read the key from the file.  Since it only contains one key, there's
	   no need to give a key ID */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
								 CRYPT_KEYID_NONE, NULL, "test" );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetPrivateKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	cryptDestroyContext( cryptContext );

	printf( "Read of %s private key from key file succeeded.\n\n",
			useRSA ? "RSA" : "DSA" );
	return( TRUE );
	}

static int writeFileKey( const BOOLEAN useRSA )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT privateKeyContext;
	int status;

	printf( "Testing %s private key file write...\n", useRSA ? "RSA" : "DSA" );

	/* Create the private key context */
	if( useRSA )
		{
		if( !loadRSAContexts( CRYPT_UNUSED, NULL, &privateKeyContext ) )
			return( FALSE );
		}
	else
		if( !loadDSAContexts( &privateKeyContext, NULL ) )
			return( FALSE );

	/* Create the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  useRSA ? RSA_PRIVKEY_FILE : DSA_PRIVKEY_FILE,
							  CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Write the key to the file */
	status = cryptAddPrivateKey( cryptKeyset, privateKeyContext, "test" );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddPrivateKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyContext( privateKeyContext );
	printf( "Write of %s private key to key file succeeded.\n\n",
			useRSA ? "RSA" : "DSA" );
	return( TRUE );
	}

int testReadWriteFileKey( void )
	{
	int status;

	status = writeFileKey( TRUE );
	if( status )
		status = readFileKey( TRUE );
	if( status )
		status = writeFileKey( FALSE );
	if( status )
		status = readFileKey( FALSE );
	return( status );
	}

/* Read only the public key/cert/cert chain portion of a private key keyset */

int testReadFilePublicKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	CRYPT_QUERY_INFO cryptQueryInfo;
	int status;

	puts( "Testing public key read from private key file..." );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  RSA_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Read the public key from the file and make sure it really is a public-
	   key context */
	status = cryptGetPublicKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NONE,
								NULL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetPublicKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptQueryContext( cryptContext, &cryptQueryInfo );
	if( cryptStatusError( status ) || \
		cryptQueryInfo.cryptMode != CRYPT_MODE_PKC )
		{
		puts( "Returned object isn't a public-key context." );
		return( FALSE );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	cryptDestroyContext( cryptContext );

	puts( "Read of public key from private key file succeeded.\n" );
	return( TRUE );
	}

static int readCert( const char *certTypeName,
					 const CRYPT_CERTTYPE_TYPE certType )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCert;
	int value, status;

	printf( "Testing %s read from private key file...\n", certTypeName );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  RSA_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Read the certificate from the file and make sure it really is a cert */
	status = cryptGetPublicKey( cryptKeyset, &cryptCert, CRYPT_KEYID_NONE,
								NULL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetPublicKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptGetCertComponentNumeric( cryptCert, CRYPT_CERTINFO_CERTTYPE,
										   &value );
	if( cryptStatusError( status ) || value != certType )
		{
		printf( "Returned object isn't a %s.\n", certTypeName );
		return( FALSE );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	cryptDestroyCert( cryptCert );

	printf( "Read of %s from private key file succeeded.\n\n", certTypeName );
	return( TRUE );
	}

int testReadFileCert( void )
	{
	return( readCert( "certificate", CRYPT_CERTTYPE_CERTIFICATE ) );
	}
int testReadFileCertChain( void )
	{
	return( readCert( "cert chain", CRYPT_CERTTYPE_CERTCHAIN ) );
	}

/* Update a private key keyset to contain a certificate */

static const CERT_DATA cACertData[] = {
	/* Identification information.  Note the non-heirarchical order of the
	   components to test the automatic arranging of the DN */
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers and CA" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave Himself" },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "Certification Division" },
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },

	/* Self-signed X.509v3 certificate */
	{ CRYPT_CERTINFO_SELFSIGNED, IS_NUMERIC, TRUE },

	/* CA extensions.  Policies are very much CA-specific and currently
	   undefined, so we use a dummy OID for a nonexistant private org for
	   now */
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC,
	  CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN },
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },

	{ CRYPT_CERTINFO_NONE, IS_VOID }
	};

int testUpdateFileKeyCert( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT publicKeyContext, privateKeyContext;
	int status;

	puts( "Testing private key file certificate update..." );

	/* Create a self-signed CA certificate using the in-memory key (which is
	   the same as the one in the keyset) */
	if( !loadRSAContexts( CRYPT_UNUSED, &publicKeyContext, &privateKeyContext ) )
		return( FALSE );
	status = cryptCreateCert( &cryptCert, CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d.\n", status );
		return( FALSE );
		}
	status = cryptAddCertComponentNumeric( cryptCert,
						CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, publicKeyContext );
	if( cryptStatusOK( status ) && !addCertFields( cryptCert, cACertData ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCert, privateKeyContext );
	destroyContexts( publicKeyContext, privateKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "Certificate creation failed with error code %d.\n", status );
		cryptDestroyCert( status );
		return( FALSE );
		}

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  RSA_PRIVKEY_FILE, CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Read the private key data into the keyset object */
	status = cryptGetPrivateKey( cryptKeyset, NULL, CRYPT_KEYID_NONE, NULL,
								 NULL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetPrivateKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Update the file with the certificate.  This is the only instance in
	   which you can add a public key object to a private key keyset */
	status = cryptAddPrivateKey( cryptKeyset, cryptCert, NULL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddPrivateKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	cryptDestroyCert( cryptCert );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( "Private key file certificate update succeeded.\n" );
	return( TRUE );
	}

/* Update a private key keyset to contain a cert chain */

static const CERT_DATA certRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers" },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "Procurement" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave Smith" },

	{ CRYPT_CERTINFO_NONE, 0, 0, NULL }
	};

int testUpdateFileKeyCertChain( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCertRequest, cryptCertChain;
	CRYPT_CONTEXT cryptCAKey, pubKeyContext, privKeyContext;
	int status;

	puts( "Testing private key file cert chain update..." );

	/* Get the CA's key and open the private key keyset in preparation for
	   updating it */
	status = getPrivateKey( &cryptCAKey, CA_PRIVKEY_FILE,
							CA_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "CA private key read failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  RSA_PRIVKEY_FILE, CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Create a cert chain using the in-memory key, which is the same as the
	   one in the keyset.  This is done so we can overwrite the existing CA
	   cert with an end entity cert chain containing a different cert.   If
	   we didn't use this trick we've have to create a completely new private
	   key file from scratch for the end entity.  Obviously in real life this
	   wouldn't happen (well, not unless your CA has a really strange cert
	   issuing policy).

	   First we create a new cert request to act as the end entity cert */
	if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, &privKeyContext ) )
		return( FALSE );
	status = cryptCreateCert( &cryptCertRequest, CRYPT_CERTTYPE_CERTREQUEST );
	if( cryptStatusOK( status ) )
		status = cryptAddCertComponentNumeric( cryptCertRequest,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusOK( status ) )
		if( !addCertFields( cryptCertRequest, certRequestData ) )
			status = CRYPT_ERROR;
	destroyContexts( pubKeyContext, privKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "Certificate creation failed with error code %d, line %d\n",
				status, __LINE__ );
		printCertErrorInfo( cryptCertRequest );
		return( FALSE );
		}

	/* Add the cert request to the chain and sign it with the CA cert */
	status = cryptCreateCert( &cryptCertChain, CRYPT_CERTTYPE_CERTCHAIN );
	if( cryptStatusOK( status ) )
		status = cryptAddCertComponentNumeric( cryptCertChain,
					CRYPT_CERTINFO_CERTREQUEST, cryptCertRequest );
	cryptDestroyCert( cryptCertRequest );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCertChain, cryptCAKey );
	cryptDestroyContext( cryptCAKey );
	if( cryptStatusError( status ) )
		{
		printf( "Cert chain creation failed with error code %d, line %d\n",
				status, __LINE__ );
		printCertErrorInfo( cryptCertChain );
		return( FALSE );
		}

	/* Read the private key data into the keyset object and update the file
	   with the cert chain */
	status = cryptGetPrivateKey( cryptKeyset, NULL, CRYPT_KEYID_NONE, NULL,
								 NULL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetPrivateKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPrivateKey( cryptKeyset, cryptCertChain, NULL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddPrivateKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	cryptDestroyCert( cryptCertChain );
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( "Private key file cert chain update succeeded.\n" );
	return( TRUE );
	}

/* Read/write a private key from a smart card */

int testReadCardKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int status;

	puts( "Testing smart card key read..." );

	/* Open the smart card keyset, with a check to make sure this access
	   method exists so we can return an appropriate error message */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_SMARTCARD,
							  "Gemplus", CRYPT_KEYOPT_READONLY );
	if( status == CRYPT_BADPARM2 )	/* Smart card access not available */
		return( CRYPT_ERROR );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Read the key from the file.  Since it only contains one key, there's
	   no need to give a key ID */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
								 CRYPT_KEYID_NONE, NULL, "test" );
	if( cryptStatusError( status ) )
		printf( "cryptGetPrivateKey() failed with error code %d, line %d\n",
				status, __LINE__ );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );

	cryptDestroyContext( cryptContext );

	puts( "Key read from smart card succeeded.\n" );
	return( TRUE );
	}

int testWriteCardKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext, decryptContext;
	int status;

	puts( "Testing smart card key write..." );

	/* Create the RSA encryption context */
	if( !loadRSAContexts( CRYPT_UNUSED, &cryptContext, &decryptContext ) )
		return( FALSE );

	/* Create the smart card keyset, with a check to make sure this access
	   method exists so we can return an appropriate error message */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_SMARTCARD,
							  "Gemplus", CRYPT_KEYOPT_CREATE );
	if( status == CRYPT_BADPARM2 )	/* Smart card access not available */
		return( CRYPT_ERROR );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Write the key to the card */
	status = cryptAddPrivateKey( cryptKeyset, cryptContext, "test" );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddPrivateKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	destroyContexts( cryptContext, decryptContext );

	puts( "Key write to smart card succeeded.\n" );
	return( TRUE );
	}

/* Read/write a certificate from a database keyset.  Returns CRYPT_ERROR if
   this keyset type isn't available from this cryptlib build, CRYPT_NOTAVAIL
   if the keyset/data source isn't available */

static int testKeysetRead( const CRYPT_KEYSET_TYPE keysetType,
						   const char *keysetName,
						   const char *keyName )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCert;
	int status;

	/* Open the database keyset with a check to make sure this access
	   method exists so we can return an appropriate error message */
	status = cryptKeysetOpen( &cryptKeyset, keysetType, keysetName,
							  CRYPT_KEYOPT_READONLY );
	if( status == CRYPT_BADPARM2 )	/* Database keyset access not available */
		return( CRYPT_ERROR );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( CRYPT_NOTAVAIL );
		}

	/* Read the certificate from the database */
	puts( "Reading certificate." );
	status = cryptGetPublicKey( cryptKeyset, &cryptCert, CRYPT_KEYID_NAME,
								keyName );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetPublicKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Check the cert against the CRL.  Any kind of error is a failure since
	   the cert isn't in the CRL */
	if( keysetType != CRYPT_KEYSET_LDAP && \
		keysetType != CRYPT_KEYSET_HTTP )
		{
		puts( "Checking certificate against CRL." );
		status = cryptCheckCert( cryptCert, cryptKeyset );
		if( cryptStatusError( status ) )
			{
			printf( "cryptCheckCert() (for CRL in keyset) failed with error "
					"code %d, line %d\n", status, __LINE__ );
			return( FALSE );
			}
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	cryptDestroyCert( cryptCert );
	return( TRUE );
	}

#if 0
int testKludge( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCert;
	int status;

	/* Import the certificate from a file - this is easier than creating one
	   from scratch */
	status = importCertFile( &cryptCert, "e:\\spool\\testcrt1.der" );
	if( cryptStatusError( status ) )
		{
		puts( "Couldn't read certificate from file, skipping test of keyset "
			  "write..." );
		return( TRUE );
		}

	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_ODBC, "PublicKeys",
							  CRYPT_KEYOPT_CREATE );
	if( status == CRYPT_DATA_DUPLICATE )
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_ODBC, "PublicKeys", 0 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		if( status == CRYPT_DATA_OPEN )
			return( CRYPT_NOTAVAIL );
		return( FALSE );
		}

	/* Write the key to the database */
	status = cryptAddPublicKey( cryptKeyset, cryptCert );
	if( status == CRYPT_DATA_DUPLICATE )
		{
		/* The key is already present, delete it and retry the write */
		status = cryptDeleteKey( cryptKeyset, CRYPT_KEYID_NAME,
								 "John Doe" );
		if( cryptStatusError( status ) )
			{
			printf( "cryptDeleteKey() failed with error code %d, line %d\n",
					status, __LINE__ );
			return( FALSE );
			}
		status = cryptAddPublicKey( cryptKeyset, cryptCert );
		}
	if( cryptStatusError( status ) )
		{
		char errorMessage[ 512 ];
		int errorCode, errorMessageLength;

		printf( "cryptAddPublicKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		status = cryptGetErrorInfo( cryptKeyset, &errorCode, errorMessage,
									&errorMessageLength );
		if( cryptStatusError( status ) )
			printf( "cryptGetErrorInfo() failed with error code %d, line %d\n",
					status, __LINE__ );
		else
			{
			errorMessage[ errorMessageLength ] = '\0';
			printf( "Extended error code = %d, error message = %s.\n", errorCode,
					errorMessage );
			}

		/* LDAP writes can fail due to the chosen directory not supporting the
		   schema du jour, so we're a bit more careful about cleaning up since
		   we'll skip the error and continue processing */
		cryptDestroyCert( cryptCert );
		cryptKeysetClose( cryptKeyset );
		return( FALSE );
		}
	cryptDestroyCert( cryptCert );

	status = cryptGetPublicKey( cryptKeyset, &cryptCert, CRYPT_KEYID_NAME,
								"John Doe" );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetPublicKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );

	return( TRUE );
	}
#endif

static int testKeysetWrite( const CRYPT_KEYSET_TYPE keysetType,
							const char *keysetName )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCert;
	int status;

	/* Import the certificate from a file - this is easier than creating one
	   from scratch */
	status = importCertFile( &cryptCert, CERT_FILE );
	if( cryptStatusError( status ) )
		{
		puts( "Couldn't read certificate from file, skipping test of keyset "
			  "write..." );
		return( TRUE );
		}

	/* Create the database keyset with a check to make sure this access
	   method exists so we can return an appropriate error message.  If the
	   database table already exists, this will return a duplicate data
	   error so we retry the open with no flags to open the existing database
	   keyset for write access */
	status = cryptKeysetOpen( &cryptKeyset, keysetType, keysetName,
							  CRYPT_KEYOPT_CREATE );
	if( status == CRYPT_BADPARM2 )
		{
		/* This type of keyset access isn't available, return a special error
		   code to indicate that the test wasn't performed, but that this
		   isn't a reason to abort processing */
		cryptDestroyCert( cryptCert );
		return( CRYPT_ERROR );
		}
	if( status == CRYPT_DATA_DUPLICATE )
		status = cryptKeysetOpen( &cryptKeyset, keysetType, keysetName, 0 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		if( status == CRYPT_DATA_OPEN )
			return( CRYPT_NOTAVAIL );
		return( FALSE );
		}

	/* Write the key to the database */
	puts( "Adding certificate." );
	status = cryptAddPublicKey( cryptKeyset, cryptCert );
	if( status == CRYPT_DATA_DUPLICATE )
		{
		/* The key is already present, delete it and retry the write */
		status = cryptDeleteKey( cryptKeyset, CRYPT_KEYID_NAME,
						"Class 1 Public Primary Certification Authority" );
		if( cryptStatusError( status ) )
			{
			printf( "cryptDeleteKey() failed with error code %d, line %d\n",
					status, __LINE__ );
			return( FALSE );
			}
		status = cryptAddPublicKey( cryptKeyset, cryptCert );
		}
	if( cryptStatusError( status ) )
		{
		char errorMessage[ 512 ];
		int errorCode, errorMessageLength;

		printf( "cryptAddPublicKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		status = cryptGetErrorInfo( cryptKeyset, &errorCode, errorMessage,
									&errorMessageLength );
		if( cryptStatusError( status ) )
			printf( "cryptGetErrorInfo() failed with error code %d, line %d\n",
					status, __LINE__ );
		else
			{
			errorMessage[ errorMessageLength ] = '\0';
			printf( "Extended error code = %d, error message = %s.\n", errorCode,
					errorMessage );
			}

		/* LDAP writes can fail due to the chosen directory not supporting the
		   schema du jour, so we're a bit more careful about cleaning up since
		   we'll skip the error and continue processing */
		cryptDestroyCert( cryptCert );
		cryptKeysetClose( cryptKeyset );
		return( FALSE );
		}
	cryptDestroyCert( cryptCert );

	/* Now try the same thing with a CRL */
	puts( "Adding CRL." );
	status = importCertFile( &cryptCert, CRL_FILE );
	if( cryptStatusError( status ) )
		{
		puts( "Couldn't read CRL from file, skipping test of keyset "
			  "write..." );
		return( TRUE );
		}
	status = cryptAddPublicKey( cryptKeyset, cryptCert );
	if( cryptStatusError( status ) )
		{
		char errorMessage[ 512 ];
		int errorCode, errorMessageLength;

		printf( "cryptAddPublicKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		status = cryptGetErrorInfo( cryptKeyset, &errorCode, errorMessage,
									&errorMessageLength );
		if( cryptStatusError( status ) )
			printf( "cryptGetErrorInfo() failed with error code %d, line %d\n",
					status, __LINE__ );
		else
			{
			errorMessage[ errorMessageLength ] = '\0';
			printf( "Extended error code = %d, error message =\n%s", errorCode,
					errorMessage );
			}
		return( FALSE );
		}
	cryptDestroyCert( cryptCert );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );

	return( TRUE );
	}

/* Perform a general keyset query */

int testQuery( const CRYPT_KEYSET_TYPE keysetType, const char *keysetName )
	{
	CRYPT_KEYSET cryptKeyset;
	int count = 0, status;

	/* Open the database keyset */
	status = cryptKeysetOpen( &cryptKeyset, keysetType, keysetName,
							  CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		if( status == CRYPT_DATA_OPEN )
			return( CRYPT_NOTAVAIL );
		return( FALSE );
		}

	/* Send the query to the database and read back the results */
	status = cryptKeysetQuery( cryptKeyset, "$C='US'" );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetQuery() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	do
		{
		CRYPT_CERTIFICATE cryptCert;

		status = cryptGetPublicKey( cryptKeyset, &cryptCert,
									CRYPT_KEYID_NONE, NULL );
		if( cryptStatusOK( status ) )
			{
			count++;
			cryptDestroyCert( cryptCert );
			}
		}
	while( cryptStatusOK( status ) );
	if( cryptStatusError( status ) && status != CRYPT_COMPLETE )
		{
		printf( "cryptGetPublicKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "%d certificate(s) matched the query.\n", count );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

/* Read/write/query a certificate from a database keyset */

int testReadCert( void )
	{
	int status;

	puts( "Testing certificate database read..." );
	status = testKeysetRead( DATABASE_KEYSET_TYPE, DATABASE_KEYSET_NAME,
	 						 "Class 1 Public Primary Certification Authority" );
	if( status == CRYPT_ERROR )	/* Database keyset access not available */
		return( CRYPT_ERROR );
	if( status == CRYPT_NOTAVAIL )
		{
		puts( "This is probably because you haven't set up a database or "
			  "data source for use\nas a key database.  For this test to "
			  "work, you need to set up a database/data\nsource with the "
			  "name '" DATABASE_KEYSET_NAME "'.\n" );
		return( TRUE );
		}
	if( !status )
		return( FALSE );
	puts( "Certificate database read succeeded.\n" );
	return( TRUE );
	}

int testWriteCert( void )
	{
	int status;

	puts( "Testing certificate database write..." );
	status = testKeysetWrite( DATABASE_KEYSET_TYPE, DATABASE_KEYSET_NAME );
	if( status == CRYPT_ERROR )	/* Database keyset access not available */
		return( CRYPT_ERROR );
	if( status == CRYPT_NOTAVAIL )
		{
		printf( "This may be because you haven't set up a data source "
				"called '" DATABASE_KEYSET_NAME "'\nof type %d which can be "
				"used for the certificate store.  You can configure\nthe "
				"data source type and name using the DATABASE_KEYSET_xxx "
				"settings near\nthe start of %s.\n",
				DATABASE_KEYSET_TYPE, __FILE__ );
		return( TRUE );
		}
	if( !status )
		return( FALSE );
	puts( "Certificate database write succeeded.\n" );
	return( TRUE );
	}

int testKeysetQuery( void )
	{
	int status;

	puts( "Testing general certificate database query..." );
	status = testQuery( DATABASE_KEYSET_TYPE, DATABASE_KEYSET_NAME );
	if( status == CRYPT_ERROR )	/* Database keyset access not available */
		return( CRYPT_ERROR );
	if( status == CRYPT_NOTAVAIL )
		{
		puts( "This is probably because you haven't set up a database or "
			  "data source for use\nas a key database.  For this test to "
			  "work, you need to set up a database/data\nsource with the "
			  "name '" DATABASE_KEYSET_NAME "'.\n" );
		return( TRUE );
		}
	if( !status )
		return( FALSE );
	puts( "Certificate database query succeeded.\n" );
	return( TRUE );
	}

/* Read/write/query a certificate from an LDAP keyset */

int testReadCertLDAP( void )
	{
	int status;

	puts( "Testing LDAP directory read..." );
	status = testKeysetRead( CRYPT_KEYSET_LDAP, LDAP_KEYSET_NAME,
							 "C=US,O=???,OU=???,CN=???" );
	if( status == CRYPT_ERROR )	/* LDAP keyset access not available */
		return( CRYPT_ERROR );
	if( status == CRYPT_NOTAVAIL )
		puts( "This is probably because you haven't set up an LDAP "
			  "directory for use as the\nkey store.  For this test to work,"
			  "you need to set up a directory with the\nname '"
			  LDAP_KEYSET_NAME "'.\n" );
	if( !status )
		return( FALSE );
	puts( "LDAP directory read succeeded.\n" );
	return( TRUE );
	}

int testWriteCertLDAP( void )
	{
	int status;

	puts( "Testing LDAP directory write..." );
	status = testKeysetWrite( CRYPT_KEYSET_LDAP, LDAP_KEYSET_NAME );
	if( status == CRYPT_ERROR )	/* LDAP keyset access not available */
		return( CRYPT_ERROR );
	if( status == CRYPT_NOTAVAIL )
		printf( "This may be because you haven't set up an LDAP directory "
				"called'" LDAP_KEYSET_NAME "'\nwhich can be used for the "
				"certificate store.  You can configure the LDAP\ndirectory "
				"using the LDAP_KEYSET_xxx settings near the start "
				"of\n%s.\n", __FILE__ );
	if( !status )
		{
		/* Since we can never be sure about the LDAP schema du jour, we
		   don't treat a failure as a fatal error */
		puts( "LDAP directory write failed, probably due to the standard "
			  "being used by the\ndirectory differing from the one used "
			  "by cryptlib (pick a standard, any\nstandard).  Processing "
			  "will continue without treating this as a fatal error.\n" );
		return( FALSE );
		}
	puts( "LDAP directory write succeeded.\n" );
	return( TRUE );
	}

/* Read a certificate from a web page */

int testReadCertHTTP( void )
	{
	int status;

	puts( "Testing HTTP certificate read..." );
	status = testKeysetRead( CRYPT_KEYSET_HTTP, NULL, HTTP_KEYSET_NAME );
	if( status == CRYPT_ERROR )	/* HTTP keyset access not available */
		return( CRYPT_ERROR );
	if( !status )
		return( FALSE );
	puts( "HTTP certificate read succeeded.\n" );
	return( TRUE );
	}
