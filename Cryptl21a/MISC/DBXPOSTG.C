/****************************************************************************
*																			*
*						cryptlib Postgres Mapping Routines					*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

/* TODO:

  - All of the functions are only about 98% complete (I lost the use of the
	Postgres systems before I was finished).
  - The code could be rewritten to use dlopen() in a similar manner to the
	ODBC linking under Windows.
*/

#include <stdio.h>
#include <string.h>
#include "crypt.h"
#include "misc/dbms.h"

/* !!!! dbtest-only !!!! */
#define DEBUG( x )	x
/* !!!! dbtest-only !!!! */

/* In the following code, the performXXX() functions usually return the
   generic CRYPT_ERROR status since the exact error code returned depends on
   the transaction type (for example returning CRYPT_DATA_READ on a key
   write would be somewhat confusing).  Any necessary translation is done by
   higher-level funcitons */

/****************************************************************************
*																			*
*							Unix Database Access Functions					*
*																			*
****************************************************************************/

#ifdef DBX_POSTGRES

/* Postgres has a few odd variations on standard SQL.  It implements a number
   of SQL primitives as inbuilt functions rather than proper primitives,
   which means they're case-sensitive.  In order for them to be recognised we
   have to convert them to lowercase before we can execute them (the only one
   we actually use is COUNT).  In addition, for CREATE INDEX statements it
   requires a USING clause (this may be a bug in the 1.08 parser rather than
   a feature, but it also allows us to specify the use of a hash index which
   is the best choice for the guaranteed-unique values we're building the
   index on).

   The following function looks for these special cases and converts the
   query into the format required by Postgres */

static void convertQuery( char *query, const char *command )
	{
	char *strPtr;

	strcpy( query, command );
	if( ( strPtr = strstr( query, "COUNT" ) ) != NULL )
		strncpy( strPtr, "count", 5 );
	if( ( strPtr = strstr( query, "CREATE INDEX" ) ) != NULL )
		{
		strPtr = strchr( query, '(' );
		memmove( strPtr + 11, strPtr, strlen( strPtr ) + 1 );
		strncpy( strPtr, "USING hash ", 11 );
		strPtr = strchr( query, ')' );
		memmove( strPtr + 9, strPtr, strlen( strPtr ) + 1 );
		strncpy( strPtr, " text_ops", 9 );
		DEBUG( printf( "XFM: %s\n", query ) );
		}
	}

/* Get information on a Postgres error */

static int getErrorInfo( KEYSET_INFO *keysetInfo, const int defaultStatus )
	{
	/* Postgres has an annoying non-unified error indication system in which
	   an error code can mean different things depending on what the current
	   usage context is, so we need to get error information in a context-
	   specific manner */
	if( keysetInfo->keysetDBMS.pgResult )
		{
		strncpy( keysetInfo->errorMessage,
				 PQcmdStatus( keysetInfo->keysetDBMS.pgResult ),
				 MAX_ERRMSG_SIZE - 1 );
		keysetInfo->errorCode = PQresultStatus( keysetInfo->keysetDBMS.pgResult );

		/* Now that we've got the information, clear the result */
		PQclear( keysetInfo->keysetDBMS.pgResult );
		keysetInfo->keysetDBMS.pgResult = NULL;
		}
	else
		{
		strncpy( keysetInfo->errorMessage,
				 PQerrorMessage( keysetInfo->keysetDBMS.pgConnection ),
				 MAX_ERRMSG_SIZE - 1 );
		keysetInfo->errorCode = PQstatus( keysetInfo->keysetDBMS.pgConnection );

		/* At the PGconn level, the only information Postgres can return is
		   "connection OK" or "connection bad", so we have to pick apart the
		   returned error message to find out what went wrong.  This is
		   pretty nasty since it may break if the error messages are ever
		   changed */
		if( strstr( keysetInfo->errorMessage, "no such class" ) != NULL || \
			strstr( keysetInfo->errorMessage, "not found" ) != NULL )
			{
			keysetInfo->errorMessage[ 0 ] = '\0';
			return( CRYPT_DATA_NOTFOUND );
			}
		}
	keysetInfo->errorMessage[ MAX_ERRMSG_SIZE - 1 ] = '\0';

	DEBUG( printf( "Return code %d, error message %s\n", \
		   keysetInfo->errorCode, keysetInfo->errorMessage ) );
	return( defaultStatus );
	}
	
/* Open and close a connection to a Postgres server */

static int openDatabase( KEYSET_INFO *keysetInfo, const char *name,
						 const char *server, const char *user,
						 const char *password )
	{
	int status;

	UNUSED( user );
	UNUSED( password );

	/* Connect to the Postgres server */
	keysetInfo->keysetDBMS.pgConnection = PQsetdb( server, NULL, NULL, NULL, name );
	if( PQstatus( keysetInfo->keysetDBMS.pgConnection ) == CONNECTION_BAD )
		{
		PQfinish( keysetInfo->keysetDBMS.pgConnection );
		keysetInfo->keysetDBMS.pgConnection = NULL;
		return( CRYPT_DATA_OPEN );
		}
	keysetInfo->keysetDBMS.databaseOpen = TRUE;

	/* Get the name of the blob data type for this database (this can be up
	   to 4096, but is unlikely to ever go above 2048) */
	strcpy( keysetInfo->keysetDBMS.blobName, "VARCHAR(2048)" );

	/* Set source-specific information which we may need later on */
	keysetInfo->keysetDBMS.maxTableNameLen = 31;
	keysetInfo->keysetDBMS.maxColumnNameLen = 64;
	return( CRYPT_OK );
	}

static void closeDatabase( KEYSET_INFO *keysetInfo )
	{
	PQfinish( keysetInfo->keysetDBMS.pgConnection );
	keysetInfo->keysetDBMS.pgConnection = NULL;
	}

/* Perform a transaction which updates the database without returning any
   data */

static int performUpdate( KEYSET_INFO *keysetInfo, const char *command )
	{
	char query[ MAX_SQL_QUERY_SIZE ];

	/* Submit the query to the Postgres server */
	convertQuery( query, command );
	keysetInfo->keysetDBMS.pgResult = PQexec( keysetInfo->keysetDBMS.pgConnection, query );
	if( keysetInfo->keysetDBMS.pgResult == NULL )
		{
		DEBUG( puts( "performQuery:PQexec() failed" ) );
		return( getErrorInfo( keysetInfo, CRYPT_DATA_WRITE ) );
		}

	/* Since this doesn't return any results, all we need to do is clear the
	   result to free the PGresult storage */
	PQclear( keysetInfo->keysetDBMS.pgResult );
	keysetInfo->keysetDBMS.pgResult = NULL;

	return( CRYPT_OK );
	}

/* Perform a transaction which checks for the existence of an object */

static int performCheck( KEYSET_INFO *keysetInfo, const char *command )
	{
	char query[ MAX_SQL_QUERY_SIZE ];
	int count, status;

	/* Submit the query to the Postgres server */
	convertQuery( query, command );
	keysetInfo->keysetDBMS.pgResult = PQexec( keysetInfo->keysetDBMS.pgConnection, query );
	if( keysetInfo->keysetDBMS.pgResult == NULL )
		{
		DEBUG( puts( "performCheck:PQexec() failed" ) );
		return( getErrorInfo( keysetInfo, CRYPT_DATA_READ ) );
		}

	/* Make sure the query completed successfully */
	status = PQresultStatus( keysetInfo->keysetDBMS.pgResult );
	if( status != PGRES_TUPLES_OK )
		{
		status = getErrorInfo( keysetInfo, CRYPT_DATA_NOTFOUND );
		PQclear( keysetInfo->keysetDBMS.pgResult );
		keysetInfo->keysetDBMS.pgResult = NULL;
		return( status );
		}

	/* The Postgres API can only return data as a char *, so any non-text
	   return values are (usually) provided as the ASCII-encoded form of
	   whatever output is being expected.  Since we know we're only ever
	   going to call performCheck() for COUNT(*), we can use atoi() to
	   convert the returned string to a numeric value */
#if 0
	printf( "Name '%s' field %d tuple %d type %d len %d\n",
			PQfname( keysetInfo->keysetDBMS.pgResult, 0 ),
			PQnfields( keysetInfo->keysetDBMS.pgResult ),
			PQntuples( keysetInfo->keysetDBMS.pgResult ),
			PQftype( keysetInfo->keysetDBMS.pgResult, 0 ),
			PQfsize( keysetInfo->keysetDBMS.pgResult, 0 ) );
#endif
	count = atoi( PQgetvalue( keysetInfo->keysetDBMS.pgResult, 0, 0 ) );
	PQclear( keysetInfo->keysetDBMS.pgResult );
	keysetInfo->keysetDBMS.pgResult = NULL;

	DEBUG( printf( "performCheck:count = %d\n", count ) );
	return( count );
	}

/* Perform a transaction which returns information */

static int performQuery( KEYSET_INFO *keysetInfo, const char *command,
						 char *data, int *dataLength, const int maxLength )
	{
	char query[ MAX_SQL_QUERY_SIZE ];
	int status = CRYPT_OK;

	/* Submit the query to the Postgres server */
	convertQuery( query, command );
	keysetInfo->keysetDBMS.pgResult = PQexec( keysetInfo->keysetDBMS.pgConnection, query );
	if( keysetInfo->keysetDBMS.pgResult == NULL )
		{
		DEBUG( puts( "performQuery:PQexec() failed" ) );
		return( getErrorInfo( keysetInfo, CRYPT_DATA_READ ) );
		}

	/* Make sure the query completed successfully */
	if( PQresultStatus( keysetInfo->keysetDBMS.pgResult ) != PGRES_TUPLES_OK )
		{
		DEBUG( puts( "performQuery:PQresultStatus != TUPLES_OK" ) );
		status = getErrorInfo( keysetInfo, CRYPT_DATA_NOTFOUND ) );
		PQclear( keysetInfo->keysetDBMS.pgResult );
		keysetInfo->keysetDBMS.pgResult = NULL;
		return( status );
		}

	/* Get the result of the query and clear the result */
/*	*dataLength = PQgetlength( keysetInfo->keysetDBMS.pgResult, 0, 0 ); */
/* !!!! Is this the right function !!!! */
	*dataLength = PQfsize( keysetInfo->keysetDBMS.pgResult, 0 );
	DEBUG( printf( "performQuery:data size = %d\n", *dataLength ) );
	if( *dataLength > maxLength )
		{
		*dataLength = 0;
		status = CRYPT_DATASIZE;
		}
	else
		strcpy( data, PQgetvalue( keysetInfo->keysetDBMS.pgResult, 1, 1 ) );
	PQclear( keysetInfo->keysetDBMS.pgResult );
	keysetInfo->keysetDBMS.pgResult = NULL;

	DEBUG( printf( "dataLength = %d\n", *dataLength ) );
	return( CRYPT_OK );
	}

/* Set up the function pointers to the access methods */

int setAccessMethodPostgres( KEYSET_INFO *keysetInfo )
	{
	keysetInfo->keysetDBMS.openDatabase = openDatabase;
	keysetInfo->keysetDBMS.closeDatabase = closeDatabase;
	keysetInfo->keysetDBMS.performUpdate = performUpdate;
	keysetInfo->keysetDBMS.performBulkUpdate = NULL;
	keysetInfo->keysetDBMS.performCheck = performCheck;
	keysetInfo->keysetDBMS.performQuery = performQuery;

	return( CRYPT_OK );
	}
#endif /* DBX_POSTGRES */
