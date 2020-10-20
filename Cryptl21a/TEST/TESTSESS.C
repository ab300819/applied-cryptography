/****************************************************************************
*																			*
*					  cryptlib Secure Session Test Routines					*
*						Copyright Peter Gutmann 1998-1999					*
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

/****************************************************************************
*																			*
*								SSH Routines Test							*
*																			*
****************************************************************************/

/* Establish a basic SSH client/server session: SSH v1, encryption only */

int testSessionSSH( void )
	{
	CRYPT_SESSION serverSession, clientSession;
	CRYPT_CONTEXT hostKey, serverKey;
	BYTE buffer[ 1024 ];
	int length, status;

	puts( "Testing SSH client/server session..." );

	/* Load the host and server keys.  Normally we'd read the host key from
	   secure storage and generate the server key on the fly, using fixed
	   keys speeds up testing */
	if( !loadRSAContexts( CRYPT_UNUSED, NULL, &serverKey ) || \
		!loadRSALargeContext( &hostKey ) )
		return( FALSE );

	/* Create the client and server sessions */
	status = cryptCreateSession( &serverSession, CRYPT_FORMAT_SSH );
	if( cryptStatusOK( status ) )
		status = cryptCreateSession( &clientSession, CRYPT_FORMAT_SSH );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSession() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add the host and server keys */
	status = cryptAddSessionComponentNumeric( serverSession,
								CRYPT_SESSINFO_KEY_AUTHENTICATION, hostKey );
	cryptDestroyContext( hostKey );
	if( cryptStatusOK( status ) )
		status = cryptAddSessionComponentNumeric( serverSession,
								CRYPT_SESSINFO_KEY_ENCRYPTION, serverKey );
	cryptDestroyContext( serverKey );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddSessionComponentNumeric() failed with error code "
				"%d, line %d\n", status, __LINE__ );
		return( FALSE );
		}

	/* Get the SSH server public key packet */
	status = cryptGetSessionData( buffer, &length, CRYPT_SESSIONDATA_HELLO,
								  serverSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetSessionData() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add the server public key packet to the client session and obtain the
	   SSH session key packet in response */
	status = cryptAddSessionData( buffer, clientSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddSessionData() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptGetSessionData( buffer, &length, CRYPT_SESSIONDATA_KEYEXCHANGE,
								  clientSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetSessionData() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add the session key packet to the server session */
	status = cryptAddSessionData( buffer, serverSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddSessionData() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	status = cryptDestroySession( clientSession );
	if( cryptStatusOK( status ) )
		status = cryptDestroySession( serverSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroySession() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( "SSH client/server session succeeded.\n" );
	return( TRUE );
	}

/****************************************************************************
*																			*
*								SSL Routines Test							*
*																			*
****************************************************************************/

/* Establish an SSL client/server session.  Uses server cert, RSA-based */

int testSessionSSL( void )
	{
	CRYPT_SESSION serverSession, clientSession;
	CRYPT_CONTEXT serverKey;
	BYTE buffer[ 1024 ];
	int length, status;

	puts( "Testing SSL client/server session..." );

	/* Load the server key */
	status = getPrivateKey( &serverKey, USER_PRIVKEY_FILE,
							USER_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		puts( "Read of private key from key file failed, cannot test SSL "
			  "session." );
		return( FALSE );
		}

	/* Create the client and server sessions */
	status = cryptCreateSession( &serverSession, CRYPT_FORMAT_SSL );
	if( cryptStatusOK( status ) )
		status = cryptCreateSession( &clientSession, CRYPT_FORMAT_SSL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSession() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add the server key */
	status = cryptAddSessionComponentNumeric( serverSession,
								CRYPT_SESSINFO_KEY_ENCRYPTION, serverKey );
	cryptDestroyContext( serverKey );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddSessionComponentNumeric() failed with error code "
				"%d, line %d\n", status, __LINE__ );
		return( FALSE );
		}

	/* Get the SSL client hello packet */
	status = cryptGetSessionData( buffer, &length, CRYPT_SESSIONDATA_HELLO,
								  clientSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetSessionData() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add the client hello data to the server session and get the server
	   hello+cert in response */
	status = cryptAddSessionData( buffer, serverSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddSessionData() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptGetSessionData( buffer, &length, CRYPT_SESSIONDATA_HELLO,
								  serverSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetSessionData() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add the server hello data to the client session and get the key
	   exchange, change cipherspec, and finished in response */
	status = cryptAddSessionData( buffer, clientSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddSessionData() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptGetSessionData( buffer, &length, CRYPT_SESSIONDATA_KEYEXCHANGE,
								  clientSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetSessionData() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add the client info to the server session and get the change
	   cipherspec and finished in response */
	status = cryptAddSessionData( buffer, serverSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddSessionData() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptGetSessionData( buffer, &length, CRYPT_SESSIONDATA_KEYEXCHANGE,
								  serverSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetSessionData() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add the server info to the client session */
	status = cryptAddSessionData( buffer, clientSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddSessionData() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	status = cryptDestroySession( clientSession );
	if( cryptStatusOK( status ) )
		status = cryptDestroySession( serverSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroySession() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( "SSL client/server session succeeded.\n" );
	return( TRUE );
	}
