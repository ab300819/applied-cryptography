/****************************************************************************
*																			*
*					 cryptlib Raima Velocis Mapping Routines				*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

/* TODO:

  - This is mostly a direct conversion of the ODBC code to Raima Velocis,
	since at the SQL level it uses the same API.  Since I don't run Velocis
	I haven't been able to check the code much.
*/

#include <stdio.h>
#include <string.h>
#include <time.h>
#include "../crypt.h"
#include "dbms.h"

#ifdef DBX_RAIMA

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* Get information on an ODBC error */

static int getErrorInfo( KEYSET_INFO *keysetInfo, const int errorLevel,
						 const int defaultStatus )
	{
	HDBC hdbc = ( errorLevel < 1 ) ? SQL_NULL_HDBC : keysetInfo->keysetDBMS.hDbc;
	HDBC hstmt = ( errorLevel < 2 ) ? SQL_NULL_HSTMT : keysetInfo->keysetDBMS.hStmt;
	char szSqlState[ SQL_SQLSTATE_SIZE ];
	SDWORD dwNativeError;
	SWORD dummy;
	RETCODE retCode;

	retCode = pSQLError( keysetInfo->keysetDBMS.hEnv, hdbc, hstmt, szSqlState,
						 &dwNativeError, keysetInfo->errorMessage,
						 MAX_ERRMSG_SIZE - 1, &dummy );
	keysetInfo->errorCode = ( int ) dwNativeError;	/* Usually 0 */

	/* Some of the information returned by SQLError() is pretty odd.  It
	   usually returns an ANSI SQL2 error state in SQLSTATE, but also returns
	   a native error code in NativeError.  However the NativeError codes
	   aren't documented anywhere, so we rely on SQLSTATE having a useful
	   value.  	We can also get SQL_NO_DATA_FOUND with SQLSTATE set to
	   "00000" and the error message string empty */
	if( !strncmp( szSqlState, "S0002", 5 ) || retCode == SQL_NO_DATA_FOUND )
		{
		/* Make sure the caller gets a sensible error message if they
		   try to examine the extended error information */
		strcpy( keysetInfo->errorMessage, "No data found." );
		return( CRYPT_DATA_NOTFOUND );
		}

	/* When we're trying to create a key database by augmenting an existing
	   database, the data we're adding may already be present, giving an
	   S0001 (table already exists) or S0021 (column already exists) error.
	   Usually we'd check for this by counting the number of items, but this
	   is incredibly slow using the Jet driver so instead we just try the
	   update anyway and convert the error code to the correct value here if
	   there's a problem */
	if( !strncmp( szSqlState, "S0001", 5 ) || !strncmp( szSqlState, "S0021", 5 ) )
		return( CRYPT_DATA_DUPLICATE );

	/* This one is a bit odd: An integrity constraint violation occurred,
	   which means (among other things) that an attempt was made to write a
	   duplicate value to a column constrained to contain unique values.  It
	   can also include things like writing a NULL value to a column
	   constrained to be NOT NULL, but this wouldn't normally happen so we
	   can convert this one to a duplicate data error */
	if( !strncmp( szSqlState, "23000", 5 ) )
		return( CRYPT_DATA_DUPLICATE );

	return( defaultStatus );
	}

/* Set up a date structure based on a time_t.  We have to use a full
   TIMESTAMP_STRUCT even though a DATE_STRUCT would do the job because
   the only standardised SQL time type is DATETIME which corresponds
   to a TIMESTAMP_STRUCT */

static void getDateInfo( TIMESTAMP_STRUCT *timestampInfo, time_t timeStamp )
	{
	struct tm *timeInfo = gmtime( &timeStamp );

	memset( timestampInfo, 0, sizeof( DATE_STRUCT ) );
	timestampInfo->year = timeInfo->tm_year + 1900;
	timestampInfo->month = timeInfo->tm_mon + 1;
	timestampInfo->day = timeInfo->tm_mday;
	timestampInfo->hour = timeInfo->tm_hour;
	timestampInfo->minute = timeInfo->tm_min;
	timestampInfo->second = timeInfo->tm_sec;
	}

/****************************************************************************
*																			*
*						 	Database Open/Close Routines					*
*																			*
****************************************************************************/

/* Close a previously-opened Velocis connection.  We have to have this before
   openDatabase() since it may be called by openDatabase() if the open
   process fails.  This is necessary because the complex ODBC-style open may
   require a fairly extensive cleanup afterwards */

void closeDatabase( KEYSET_INFO *keysetInfo )
	{
	/* Commit the transaction (the default transaction mode for drivers which
	   support SQLSetConnectOption() is auto-commit so the SQLTransact() call
	   isn't strictly necessary, but we play it safe anyway) */
	if( keysetInfo->keysetDBMS.needsUpdate )
		{
		pSQLTransact( keysetInfo->keysetDBMS.hEnv,
					  keysetInfo->keysetDBMS.hDbc, SQL_COMMIT );
		keysetInfo->keysetDBMS.needsUpdate = FALSE;
		}

	/* Clean up */
	pSQLDisconnect( keysetInfo->keysetDBMS.hDbc );
	pSQLFreeConnect( keysetInfo->keysetDBMS.hDbc );
	pSQLFreeEnv( keysetInfo->keysetDBMS.hEnv );
	keysetInfo->keysetDBMS.hStmt = 0;
	keysetInfo->keysetDBMS.hDbc = 0;
	keysetInfo->keysetDBMS.hEnv = 0;
	keysetInfo->keysetDBMS.databaseOpen = FALSE;
	}

/* Open a connection to a data source using the Velocis ODBC-style interface.
   We don't check the return codes for many of the functions since the worst
   that can happen if they fail is that performance will be somewhat
   suboptimal */

static int openDatabase( KEYSET_INFO *keysetInfo, const char *name,
						 const char *server, const char *user,
						 const char *password )
	{
	RETCODE retCode;
	SWORD userLen = ( user == NULL ) ? 0 : SQL_NTS;
	SWORD passwordLen = ( password == NULL ) ? 0 : SQL_NTS;
	SWORD dummy, bufLen = 10;
	int status;

	UNUSED( server );

	if( hODBC == NULL_HINSTANCE )
		return( CRYPT_DATA_OPEN );

	/* Allocate environment and connection handles */
	pSQLAllocEnv( &keysetInfo->keysetDBMS.hEnv );
	pSQLAllocConnect( keysetInfo->keysetDBMS.hEnv,
					  &keysetInfo->keysetDBMS.hDbc );

	/* Set the access mode to readonly if we can.  The default is R/W, but
	   setting it to readonly optimises transaction management */
	if( keysetInfo->options == CRYPT_KEYOPT_READONLY )
		pSQLSetConnectOption( keysetInfo->keysetDBMS.hDbc, SQL_ACCESS_MODE,
							  SQL_MODE_READ_ONLY );

	/* Set the cursor type to forward-only (which should be the default).
	   Note that we're passing an SQLSetStmtOption() arg.to
	   SQLSetConnectOption() which causes all stmt's allocated for this
	   connection to have the specified behaviour */
	pSQLSetConnectOption( keysetInfo->keysetDBMS.hDbc, SQL_CURSOR_TYPE,
						  SQL_CURSOR_FORWARD_ONLY );

	/* Turn off scanning for escape clauses in the SQL strings, which lets
	   the driver pass the string directly to the data source.  See the
	   comment for the previous call about the arg.being passed */
	pSQLSetConnectOption( keysetInfo->keysetDBMS.hDbc, SQL_NOSCAN,
						  SQL_NOSCAN_ON );

	/* Only return a maximum of 2 rows in response to any SELECT statement.
	   The only thing we're interested in when we're returning rows is whether
	   there's more than one row present, so it doesn't matter if we return 2
	   rows or 1000.  This is another stmt option being applied to a
	   connection */
	pSQLSetConnectOption( keysetInfo->keysetDBMS.hDbc, SQL_MAX_ROWS, 2 );

	/* Once everything is set up the way we want it, try to connect to the
	   data source and allocate a statement handle */
	retCode = pSQLConnect( keysetInfo->keysetDBMS.hDbc, ( char * ) name,
						   SQL_NTS, ( char * ) user, userLen,
						   ( char * ) password, passwordLen );
	if( retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO )
		{
		getErrorInfo( keysetInfo, SQL_ERRLVL_0, CRYPT_DATA_OPEN );
		pSQLFreeConnect( keysetInfo->keysetDBMS.hDbc );
		pSQLFreeEnv( keysetInfo->keysetDBMS.hEnv );
		return( CRYPT_DATA_OPEN );
		}

	/* Get source-specific information */
	retCode = pSQLGetInfo( keysetInfo->keysetDBMS.hDbc, SQL_MAX_TABLE_NAME_LEN,
						   &keysetInfo->keysetDBMS.maxTableNameLen,
						   sizeof( UWORD ), &dummy );
	if( retCode != SQL_SUCCESS )
		keysetInfo->keysetDBMS.maxTableNameLen = 14;	/* Make a safe guess */
	retCode = pSQLGetInfo( keysetInfo->keysetDBMS.hDbc, SQL_MAX_COLUMN_NAME_LEN,
						   &keysetInfo->keysetDBMS.maxColumnNameLen,
						   sizeof( UWORD ), &dummy );
	if( retCode != SQL_SUCCESS )
		keysetInfo->keysetDBMS.maxColumnNameLen = 14;	/* Make a safe guess */

	/* Set the blob data type for this database */
	keysetInfo->keysetDBMS.hasBinaryBlobs = TRUE;
	keysetInfo->keysetDBMS.blobType = SQL_LONGVARBINARY;

	keysetInfo->keysetDBMS.databaseOpen = TRUE;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Database Access Routines						*
*																			*
****************************************************************************/

/* Perform an update, handling any late-binding requirements */

static int updateDatabase( KEYSET_INFO *keysetInfo, const char *command )
	{
	RETCODE retCode;
	int status = CRYPT_OK;

	/* If we're performing a data update, set up any required bound
	   parameters */
	if( keysetInfo->keysetDBMS.isDataUpdate )
		{
		getDateInfo( &keysetInfo->keysetDBMS.boundDate,
					 keysetInfo->keysetDBMS.date );
		keysetInfo->keysetDBMS.cbBlobLength = SQL_LEN_DATA_AT_EXEC( keysetInfo->keysetDBMS.boundKeyDataLen );
		}

	/* Execute the command/hStmt as appropriate */
	if( command == NULL )
		retCode = pSQLExecute( keysetInfo->keysetDBMS.hStmt );
	else
		retCode = pSQLExecDirect( keysetInfo->keysetDBMS.hStmt,
								  ( char * ) command, SQL_NTS );
	if( retCode == SQL_NEED_DATA )
		{
		PTR pToken;

		/* Add the key data */
		pSQLParamData( keysetInfo->keysetDBMS.hStmt, &pToken );
		retCode = pSQLPutData( keysetInfo->keysetDBMS.hStmt,
							   keysetInfo->keysetDBMS.boundKeyData,
							   keysetInfo->keysetDBMS.boundKeyDataLen );

		/* Tell the Velocis routines that we've finished with this
		   parameter */
		pSQLParamData( keysetInfo->keysetDBMS.hStmt, &pToken );
		}
	if( retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO )
		return( getErrorInfo( keysetInfo, SQL_ERRLVL_2, CRYPT_DATA_WRITE ) );

	return( status );
	}

/* Perform a transaction which updates the database without returning any
   data */

static int performUpdate( KEYSET_INFO *keysetInfo, const char *command )
	{
	int status = CRYPT_OK;

	/* Allocate an hstmt */
	pSQLAllocStmt( keysetInfo->keysetDBMS.hDbc,
				   &keysetInfo->keysetDBMS.hStmt );

	/* If we're performing a data update, bind the various parameters */
	if( keysetInfo->keysetDBMS.isDataUpdate )
		{
		/* Bind the date parameter to the hstmt.  This is unlike the
		   behaviour mentioned in the ODBC documentation, which claims that
		   SQLExecDirect() will return SQL_NEED_DATA if it finds a parameter
		   marker.  Instead, we have to bind the parameters before calling
		   SQLExecDirect() and it reads them from the bound location as
		   required

		   (I'm not sure what Velocis will do here) */
		pSQLBindParameter( keysetInfo->keysetDBMS.hStmt, 1, SQL_PARAM_INPUT,
						   SQL_C_TIMESTAMP, SQL_TIMESTAMP, 0, 0,
						   &keysetInfo->keysetDBMS.boundDate, 0, NULL );
		pSQLBindParameter( keysetInfo->keysetDBMS.hStmt, 2, SQL_PARAM_INPUT,
						   SQL_C_BINARY, SQL_LONGVARBINARY,
						   SQL_MAX_MESSAGE_LENGTH, 0, ( PTR ) 6, 0,
						   &keysetInfo->keysetDBMS.cbBlobLength );
		}

	/* Perform the update */
	status = updateDatabase( keysetInfo, command );
	pSQLFreeStmt( keysetInfo->keysetDBMS.hStmt, SQL_DROP );

	return( status );
	}

/* Initialise, perform, and wind up a bulk update transaction */

static int performBulkUpdate( KEYSET_INFO *keysetInfo, const char *command )
	{
	RETCODE retCode;
	int status = CRYPT_OK;

	/* If it's the start of a bulk update, allocate an hstmt, prepare the
	   statement, and bind the data value locations */
	if( keysetInfo->keysetDBMS.bulkUpdateState == BULKUPDATE_START )
		{
		/* Change the commit mode for the connection to manual commit */
		pSQLSetConnectOption( keysetInfo->keysetDBMS.hDbc, SQL_AUTOCOMMIT,
							  SQL_AUTOCOMMIT_OFF );

		/* Allocate the statement handle */
		pSQLAllocStmt( keysetInfo->keysetDBMS.hDbc,
					   &keysetInfo->keysetDBMS.hStmt );

		/* Prepare the SQL string for execution */
		retCode = pSQLPrepare( keysetInfo->keysetDBMS.hStmt,
							   ( char * ) command, SQL_NTS );
		if( retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO )
			return( getErrorInfo( keysetInfo, SQL_ERRLVL_2, CRYPT_DATA_WRITE ) );

		/* Bind the parameters.  The usage for SQLBindParameter() under the
		   MS ODBC interface is very confusing and contradictory (see the
		   comments in dbxodbc.c), I'm not sure how Velocis handles this */
		pSQLBindParameter( keysetInfo->keysetDBMS.hStmt, 1, SQL_PARAM_INPUT,
						   SQL_C_CHAR, SQL_VARCHAR, CRYPT_MAX_TEXTSIZE, 0,
                           keysetInfo->keysetDBMS.name, 0, NULL );
		pSQLBindParameter( keysetInfo->keysetDBMS.hStmt, 2, SQL_PARAM_INPUT,
						   SQL_C_CHAR, SQL_VARCHAR, CRYPT_MAX_TEXTSIZE, 0,
                           keysetInfo->keysetDBMS.email, 0, NULL );
		pSQLBindParameter( keysetInfo->keysetDBMS.hStmt, 3, SQL_PARAM_INPUT,
						   SQL_C_TIMESTAMP, SQL_TIMESTAMP, 0, 0,
						   &keysetInfo->keysetDBMS.boundDate, 0, NULL );
		pSQLBindParameter( keysetInfo->keysetDBMS.hStmt, 4, SQL_PARAM_INPUT,
						   SQL_C_CHAR, SQL_VARCHAR, 45, 0,
                           keysetInfo->keysetDBMS.boundNameID, 0, NULL );
		pSQLBindParameter( keysetInfo->keysetDBMS.hStmt, 5, SQL_PARAM_INPUT,
						   SQL_C_CHAR, SQL_VARCHAR, 45, 0,
						   keysetInfo->keysetDBMS.boundIssuerID, 0, NULL );
		pSQLBindParameter( keysetInfo->keysetDBMS.hStmt, 6, SQL_PARAM_INPUT,
						   SQL_C_CHAR, SQL_VARCHAR, 45, 0,
						   keysetInfo->keysetDBMS.boundKeyID, 0, NULL );
		retCode = pSQLBindParameter( keysetInfo->keysetDBMS.hStmt, 7,
									 SQL_PARAM_INPUT, SQL_C_CHAR,
									 SQL_LONGVARBINARY, SQL_MAX_MESSAGE_LENGTH,
									 0, ( PTR ) 7, 0,
                                     &keysetInfo->keysetDBMS.cbBlobLength );
		if( retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO )
			return( getErrorInfo( keysetInfo, SQL_ERRLVL_2, CRYPT_DATA_WRITE ) );

		return( status );
		}

	/* If it's the end of a bulk update, commit the transaction and free the
	   hstmt */
	if( keysetInfo->keysetDBMS.bulkUpdateState == BULKUPDATE_FINISH )
		{
		/* Commit the transaction */
		retCode = pSQLTransact( keysetInfo->keysetDBMS.hEnv,
								keysetInfo->keysetDBMS.hDbc, SQL_COMMIT );
		if( retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO )
			return( getErrorInfo( keysetInfo, SQL_ERRLVL_2, CRYPT_DATA_WRITE ) );

		/* Set the commit mode back to autocommit (this commits any
		   transactions on the connection anyway, but it's nicer to
		   explicitly commit them) */
		pSQLSetConnectOption( keysetInfo->keysetDBMS.hDbc, SQL_AUTOCOMMIT,
							  SQL_AUTOCOMMIT_ON );

		/* We're done, drop the statement handle */
		pSQLFreeStmt( keysetInfo->keysetDBMS.hStmt, SQL_DROP );

		return( status );
		}

	/* We're in the middle of a bulk update, perform the update */
	return( updateDatabase( keysetInfo, NULL ) );
	}

/* Perform a transaction which checks for the existence of an object */

static int performCheck( KEYSET_INFO *keysetInfo, const char *command )
	{
	RETCODE retCode;
	SDWORD length;
	long count;

	/* Allocate an hstmt and set the cursor concurrency to read-only */
	pSQLAllocStmt( keysetInfo->keysetDBMS.hDbc,
				   &keysetInfo->keysetDBMS.hStmt );
	pSQLSetStmtOption( keysetInfo->keysetDBMS.hStmt, SQL_CONCURRENCY,
					   SQL_CONCUR_READ_ONLY );

	/* Execute the SQL statement */
	retCode = pSQLExecDirect( keysetInfo->keysetDBMS.hStmt,
							  ( char * ) command, SQL_NTS );
	if( retCode == SQL_SUCCESS || retCode == SQL_SUCCESS_WITH_INFO )
		{
		/* Get the results of the transaction */
		retCode = pSQLFetch( keysetInfo->keysetDBMS.hStmt );
		if( retCode == SQL_SUCCESS || retCode == SQL_SUCCESS_WITH_INFO )
			/* We're checking whether a given name or key ID exists by
			   counting the number of occurrences */
			retCode = pSQLGetData( keysetInfo->keysetDBMS.hStmt, 1, SQL_C_LONG,
								   &count, sizeof( long ), &length );
		}

	/* Handle any errors */
	if( retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO )
		{
		int status;

		status = getErrorInfo( keysetInfo, SQL_ERRLVL_2, CRYPT_DATA_READ );
		pSQLFreeStmt( keysetInfo->keysetDBMS.hStmt, SQL_DROP );
		return( ( status == CRYPT_DATA_NOTFOUND ) ? \
				CRYPT_DATA_NOTFOUND : CRYPT_DATA_READ );
		}
	pSQLFreeStmt( keysetInfo->keysetDBMS.hStmt, SQL_DROP );

	/* If we're running on a 16-bit machine and accessing a large key
	   database we may have more than 32K records, so we need to be careful
	   how we handle return values.  Since we only really need a zero or
	   nonzero return, we just return some large number if the count is
	   larger than the 16-bit MAXINT */
	return( ( count > 32768L ) ? 1000 : ( int ) count );
	}

/* Perform a transaction which returns information */

static int performQuery( KEYSET_INFO *keysetInfo, const char *command,
						 char *data, int *dataLength, const int maxLength )
	{
	RETCODE retCode;
	SDWORD length;

	/* Allocate an hstmt and set the cursor concurrency to read-only */
	pSQLAllocStmt( keysetInfo->keysetDBMS.hDbc,
				   &keysetInfo->keysetDBMS.hStmt );
	pSQLSetStmtOption( keysetInfo->keysetDBMS.hStmt, SQL_CONCURRENCY,
					   SQL_CONCUR_READ_ONLY );

	/* Execute the SQL statement */
	retCode = pSQLExecDirect( keysetInfo->keysetDBMS.hStmt,
							  ( char * ) command, SQL_NTS );
	if( retCode == SQL_SUCCESS || retCode == SQL_SUCCESS_WITH_INFO )
		{
		/* Get the results of the transaction */
		retCode = pSQLFetch( keysetInfo->keysetDBMS.hStmt );
		if( retCode == SQL_SUCCESS || retCode == SQL_SUCCESS_WITH_INFO )
			{
			/* We're reading the key data */
			retCode = pSQLGetData( keysetInfo->keysetDBMS.hStmt, 1,
								   SQL_C_BINARY, data, maxLength, &length );
			*dataLength = ( int ) length;
			}
		}

	/* Handle any errors */
	if( retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO )
		{
		int status;

		status = getErrorInfo( keysetInfo, SQL_ERRLVL_2, CRYPT_DATA_READ );
		pSQLFreeStmt( keysetInfo->keysetDBMS.hStmt, SQL_DROP );
		return( ( status == CRYPT_DATA_NOTFOUND ) ? \
				CRYPT_DATA_NOTFOUND : CRYPT_DATA_READ );
		}
	pSQLFreeStmt( keysetInfo->keysetDBMS.hStmt, SQL_DROP );

	return( CRYPT_OK );
	}

/* Set up the function pointers to the access methods */

int setAccessMethodRaima( KEYSET_INFO *keysetInfo )
	{
	keysetInfo->keysetDBMS.openDatabase = openDatabase;
	keysetInfo->keysetDBMS.closeDatabase = closeDatabase;
	keysetInfo->keysetDBMS.performUpdate = performUpdate;
	keysetInfo->keysetDBMS.performBulkUpdate = performBulkUpdate;
	keysetInfo->keysetDBMS.performCheck = performCheck;
	keysetInfo->keysetDBMS.performQuery = performQuery;

	return( CRYPT_OK );
	}
#endif /* DBX_RAIMA */
