/****************************************************************************
*																			*
*						cryptlib Beagle SQL Mapping Routines				*
*						 Copyright Peter Gutmann 1997-1999					*
*																			*
****************************************************************************/

/* TODO:

  - The blob info is just set to VARCHAR(255), it should actually be the
	proper maximum string size.
  - This is mostly a direct conversion of the Postgres code to BSQL.  Since I
	don't run BSQL I haven't been able to check the code much.
*/

#include <stdio.h>
#include <string.h>
#include "crypt.h"
#include "misc/dbms.h"

/* !!!! dbtest-only !!!! */
#define DEBUG( x )	x
/* !!!! dbtest-only !!!! */

/****************************************************************************
*																			*
*							Unix Database Access Functions					*
*																			*
****************************************************************************/

#ifdef DBX_BSQL

/* Beagle SQL has a few odd variations on standard SQL.  It implements a
   number of SQL primitives as inbuilt functions rather than proper
   primitives, which means they're case-sensitive.  In order for them to be
   recognised we have to convert them to lowercase before we can execute them
   (the only one we actually use is COUNT).

   The following function looks for these special cases and converts the
   query into the format required by Beagle SQL */

static void convertQuery( char *query, const char *command )
	{
	char *strPtr;

	strcpy( query, command );
	if( ( strPtr = strstr( query, "COUNT" ) ) != NULL )
		strncpy( strPtr, "count", 5 );
	}

/* Get information on a Beagle SQL error */

static int getErrorInfo( KEYSET_INFO *keysetInfo, const int defaultStatus )
	{
	/* Beagle SQL copies the Postgres non-unified error indication system in
	   which an error code can mean different things depending on what the
	   current usage context is, so we need to get error information in a
	   context-specific manner */
	if( keysetInfo->keysetDBMS.result != NULL )
		{
		strncpy( keysetInfo->errorMessage,
				 keysetInfo->keysetDBMS.result.errcode, MAX_ERRMSG_SIZE - 1 );
		keysetInfo->errorCode = keysetInfo->keysetDBMS.result->resultcode;

		/* The only information the Beagle SQL query-related functions return
		   return is "OK" or "not OK", so we have to pick apart the returned
		   error message to find out what went wrong.  This is pretty nasty
		   since it may break if the error messages are ever changed */
		if( strstr( keysetInfo->errorMessage, "no such class" ) != NULL || \
			strstr( keysetInfo->errorMessage, "not found" ) != NULL )
			{
			keysetInfo->errorMessage[ 0 ] = '\0';
			return( CRYPT_DATA_NOTFOUND );
			}

		/* Now that we've got the information, clear the result */
		BSQLClear( keysetInfo->keysetDBMS.pgResult );
		keysetInfo->keysetDBMS.result = NULL;
		}
	else
		{
		/* Before we get a bresult structure the only thing we can tell about
		   an error is that it occurred during a BSQLQueryDB() call */
		strcpy( keysetInfo->errorMessage, "Error sending query to Beagle "
				"SQL server " );
		keysetInfo->errorCode = CRYPT_ERROR;
		}
	keysetInfo->errorMessage[ MAX_ERRMSG_SIZE - 1 ] = '\0';

	DEBUG( printf( "Error message:%s\n", keysetInfo->errorMessage ) );
	return( defaultStatus );
	}
	
/* Open and close a connection to a Beagle SQL server */

static int openDatabase( KEYSET_INFO *keysetInfo, const char *name,
						 const char *server, const char *user,
						 const char *password )
	{
	char *serverName = ( server != NULL ) ? server : "localhost";
	int status;

	UNUSED( user );
	UNUSED( password );

	/* Connect to the Beagle SQL server */
	keysetInfo->keysetDBMS.socket = BSQLConnect( serverName );
	if( !keysetInfo->keysetDBMS.socket )
		return( CRYPT_DATA_OPEN );
	if( !BSQLSetCurrentDB( keysetInfo->keysetDBMS.socket, name ) )
		{
		BSQLDisconnect( keysetInfo->keysetDBMS.socket );
		keysetInfo->keysetDBMS.socket = 0;
		return( CRYPT_DATA_OPEN );
		}

	/* Get the name of the blob data type for this database */
	strcpy( keysetInfo->keysetDBMS.blobName, "VARCHAR(255)" );

	keysetInfo->keysetDBMS.databaseOpen = TRUE;
	return( CRYPT_OK );
	}

static void closeDatabase( KEYSET_INFO *keysetInfo )
	{
	BSQLDisconnect( keysetInfo->keysetDBMS.socket );
	keysetInfo->keysetDBMS.socket = 0;
	}

/* Perform a transaction which updates the database without returning any
   data */

static int performUpdate( KEYSET_INFO *keysetInfo, const char *command )
	{
	char query[ MAX_SQL_QUERY_SIZE ];

	/* Submit the query to the Beagle SQL server */
	convertQuery( query, command );
	keysetInfo->keysetDBMS.result = BSQLQueryDB( keysetInfo->keysetDBMS.socket, query );
	if( keysetInfo->keysetDBMS.result == NULL )
		{
		DEBUG( puts( "performQuery:BSQLQueryDB() failed" ) );
		return( getErrorInfo( keysetInfo, CRYPT_DATA_WRITE );
		}

	/* Since this doesn't return any results, all we need to do is clear the
	   result to free the PGresult storage */
	BSQLFreeResult( keysetInfo->keysetDBMS.result );
	keysetInfo->keysetDBMS.result = NULL;

	return( CRYPT_OK );
	}

/* Perform a transaction which checks for the existence of an object */

static int performCheck( KEYSET_INFO *keysetInfo, const char *command )
	{
	char query[ MAX_SQL_QUERY_SIZE ];
	int count, status;

	/* Submit the query to the Beagle SQL server */
	convertQuery( query, command );
	keysetInfo->keysetDBMS.result = BSQLQueryDB( keysetInfo->keysetDBMS.socket, query );
	if( keysetInfo->keysetDBMS.result == NULL )
		{
		DEBUG( puts( "performQuery:BSQLQueryDB() failed" ) );
		return( getErrorInfo( keysetInfo, CRYPT_DATA_READ );
		}

	/* Make sure the query completed successfully */
	if( !keysetInfo->keysetDBMS.result->resultcode )
		{
		status = getErrorInfo( keysetInfo, CRYPT_DATA_NOTFOUND );
		BSQLFreeResult( keysetInfo->keysetDBMS.result );
		keysetInfo->keysetDBMS.result = NULL;
		return( status );
		}

	/* The Beagle SQL API can only return data as a char *, so any non-text
	   return values are (usually) provided as the ASCII-encoded form of
	   whatever output is being expected.  Since we know we're only ever
	   going to call performCheck() for COUNT(*), we can use atoi() to
	   convert the returned string to a numeric value */
	count = atoi( BSQLFieldValue( keysetInfo->keysetDBMS.result, 0, 0 ) );
	BSQLFreeResult( keysetInfo->keysetDBMS.result );
	keysetInfo->keysetDBMS.result = NULL;

	DEBUG( printf( "performCheck:count = %d\n", count ) );
	return( count );
	}

/* Perform a transaction which returns information */

static int performQuery( KEYSET_INFO *keysetInfo, const char *command,
						 char *data, int *dataLength, const int maxLength )
	{
	char query[ MAX_SQL_QUERY_SIZE ];
	int status;

	/* Submit the query to the Beagle SQL server */
	convertQuery( query, command );
	keysetInfo->keysetDBMS.result = BSQLQueryDB( keysetInfo->keysetDBMS.socket, query );
	if( keysetInfo->keysetDBMS.result == NULL )
		{
		DEBUG( puts( "performQuery:BSQLQueryDB() failed" ) );
		return( getErrorInfo( keysetInfo, CRYPT_DATA_READ );
		}

	/* Make sure the query completed successfully */
	if( !keysetInfo->keysetDBMS.result->resultcode )
		{
		DEBUG( puts( "performQuery:resultcode == No information" ) );
		status = getErrorInfo( keysetInfo, CRYPT_DATA_NOTFOUND );
		BSQLFreeResult( keysetInfo->keysetDBMS.result );
		keysetInfo->keysetDBMS.result = NULL;
		return( status );
		}

	/* Get the result of the query and clear the result.  This is somewhat
	   ugly since there's no way to tell how large the returned field is, we
	   have to assume that this won't overflow (which is probably the case,
	   since it was cryptlib which created and wrote the field in the first
	   place) */
	strcpy( data, BSQLFieldValue( keysetInfo->keysetDBMS.result, 1, 1 ) );
	BSQLFreeResult( keysetInfo->keysetDBMS.result );
	keysetInfo->keysetDBMS.result = NULL;

	DEBUG( printf( "dataLength = %d\n", *dataLength ) );
	return( CRYPT_OK );
	}

/* Set up the function pointers to the access methods */

int setAccessMethodBSQL( KEYSET_INFO *keysetInfo )
	{
	keysetInfo->keysetDBMS.openDatabase = openDatabase;
	keysetInfo->keysetDBMS.closeDatabase = closeDatabase;
	keysetInfo->keysetDBMS.performUpdate = performUpdate;
	keysetInfo->keysetDBMS.performBulkUpdate = NULL;
	keysetInfo->keysetDBMS.performCheck = performCheck;
	keysetInfo->keysetDBMS.performQuery = performQuery;

	return( CRYPT_OK );
	}
#endif /* DBX_BSQL */
