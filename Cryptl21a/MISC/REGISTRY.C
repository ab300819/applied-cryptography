/****************************************************************************
*																			*
*							cryptlib Registry Interface						*
*						Copyright Peter Gutmann 1996-1997					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include "../crypt.h"

/* The registry key name */

#define REG_KEYNAME	"Software\\cryptlib"

/* The number of milliseconds to wait for access to the cryptlib registry
   key.  In order for the program which uses cryptlib to avoid appearing to
   hang, we only wait for a maximum of 15 seconds before giving up */

#define REGKEY_WAIT		15000

/* The size of the buffer for ACLs */

#define ACL_BUFFER_SIZE		1024

/****************************************************************************
*																			*
*								Security Functions							*
*																			*
****************************************************************************/

/* Check whether the user is in the administrators group.  Only someone with
   admin privs can change the system-wide config options */

static BOOLEAN isAdministrator( void )
	{
	SID_IDENTIFIER_AUTHORITY SystemSidAuthority = SECURITY_NT_AUTHORITY;
	TOKEN_GROUPS *ptg;
	HANDLE htkThread;
	PSID psidAdmin;
	DWORD cbTokenGroups, i;
	BOOLEAN isAdmin = FALSE;

	/* Open a handle to the access token for this thread */
	if( !OpenThreadToken( GetCurrentThread(), TOKEN_QUERY, FALSE, &htkThread ) )
		if( GetLastError() == ERROR_NO_TOKEN )
			{
			/* If the thread doesn't have an access token, try the token
			   associated with the process */
			if( !OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY,
								   &htkThread ) )
				return( FALSE );
			}
		else
			return( FALSE );

	/* Query the size of the group information associated with the token,
	   allocate a buffer for it, and fetch the information into the buffer */
	GetTokenInformation( htkThread, TokenGroups, NULL, 0, &cbTokenGroups );
	if( GetLastError() != ERROR_INSUFFICIENT_BUFFER )
		return( FALSE );
	if( ( ptg = ( TOKEN_GROUPS * ) malloc( cbTokenGroups ) ) == NULL )
		return( FALSE );
	if( !GetTokenInformation( htkThread, TokenGroups, ptg, cbTokenGroups,
							  &cbTokenGroups ) )
	  {
	  free( ptg );
	  return( FALSE );
	  }

	/* Create a System Identifier for the Admin group and walk through the
	   list of groups for this access token trying to match the SID */
	if( !AllocateAndInitializeSid( &SystemSidAuthority, 2,
								   SECURITY_BUILTIN_DOMAIN_RID,
								   DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0,
								   0, &psidAdmin ) )
		{
		free( ptg );
		return( FALSE );
		}
	for( i = 0; i < ptg->GroupCount; i++ )
		if( EqualSid( ptg->Groups[ i ].Sid, psidAdmin ) )
			{
			isAdmin= TRUE;
			break;
			}

	/* Clean up */
	FreeSid( psidAdmin );
	free( ptg );

	return( isAdmin );
	}

/* Get information on the current user.  This works in an extraordinarily
   ugly manner because although the TOKEN_USER struct is only 8 bytes long,
   Windoze allocates an extra 24 bytes after the end of the struct into which
   it stuffs data which the SID in the TOKEN_USER struct points to.  This
   means we can't return the SID pointer from the function because it would
   point to freed memory, so we need to return the pointer to the entire
   TOKEN_USER struct to ensure that what the SID pointer points to remains
   around for the caller to use */

TOKEN_USER *getUserInfo( void )
	{
	TOKEN_USER *pUserInfo = NULL;
	HANDLE hToken = INVALID_HANDLE_VALUE;	/* See comment below */
	DWORD cbTokenUser;

	/* Get the security token for this thread.  We initialise the hToken even
	   though it shouldn't be necessary because Windows tries to read its
	   contents, which indicates there might be problems if it happens to
	   have the wrong value */
	if( !OpenThreadToken( GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken ) )
		if( GetLastError() == ERROR_NO_TOKEN )
			{
			/* If the thread doesn't have a security token, try the token
			   associated with the process */
			if( !OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY,
								   &hToken ) )
				return( NULL );
			}
		else
			return( NULL );

	/* Query the size of the user information associated with the token,
	   allocate a buffer for it, and fetch the information into the buffer */
	GetTokenInformation( hToken, TokenUser, NULL, 0, &cbTokenUser );
	if( GetLastError() == ERROR_INSUFFICIENT_BUFFER )
		{
		pUserInfo = ( TOKEN_USER * ) malloc( cbTokenUser );
		if( !GetTokenInformation( hToken, TokenUser, pUserInfo, cbTokenUser,
								 &cbTokenUser ) )
			{
			free( pUserInfo );
			pUserInfo = NULL;
			}
		}

	/* Clean up */
	CloseHandle( hToken );
	return( pUserInfo );
	}

/****************************************************************************
*																			*
*						System-wide Registry Functions						*
*																			*
****************************************************************************/

#if 0	/* Currently unused */

/* If there's nothing in the registry yet for the current user, create a key
   below which things are stored.  This function assumes hmtxLocal is held */

static int createGlobalConfig( void )
	{
	SID_IDENTIFIER_AUTHORITY SystemSidAuthority = SECURITY_NT_AUTHORITY;
	SID_IDENTIFIER_AUTHORITY WorldSidAuthority = SECURITY_WORLD_SID_AUTHORITY;
	SECURITY_ATTRIBUTES sa;
	SECURITY_DESCRIPTOR sdPermissions;
	HKEY hkGlobal = NULL;
	PSID psidAdmins = NULL;
	PSID psidEveryone = NULL;
	PACL paclKey = NULL;
	PSZ pszDefaultPath = NULL;
	BOOL fInstalled = FALSE;
	DWORD dwDisposition;

	/* If we're not admin, we can't do anything */
	if( !isAdministrator() )
		return( CRYPT_OK );

	/* Create SIDs for the admin group and for all users */
	if( !AllocateAndInitializeSid( &SystemSidAuthority, 2,
								   SECURITY_BUILTIN_DOMAIN_RID,
								   DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0,
								   0, &psidAdmins ) || \
		!AllocateAndInitializeSid( &WorldSidAuthority, 1,
								   SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0,
								   0, &psidEveryone ) )
	  goto error;

	/* Set the admin group to own this key */
	if( !InitializeSecurityDescriptor( &sdPermissions,
									   SECURITY_DESCRIPTOR_REVISION1 ) || \
		!SetSecurityDescriptorOwner( &sdPermissions, psidAdmins, 0 ) )
		goto error;

	/* Set up the discretionary access control lists (DACL) for the key with
	   two access control entries (ACEs), one for admins which allows
	   complete access and one for all others which allows read-only access */
	if( ( paclKey = ( PACL ) malloc( ACL_BUFFER_SIZE ) ) == NULL )
		goto error;
	if( !InitializeAcl( paclKey, ACL_BUFFER_SIZE, ACL_REVISION2 ) || \
		!AddAccessAllowedAce( paclKey, ACL_REVISION2, KEY_ALL_ACCESS,
							  psidAdmins ) || \
		!AddAccessAllowedAce( paclKey, ACL_REVISION2, KEY_READ,
							  psidEveryone ) )
		goto error;

	/* Bind the DACL to the security descriptor */
	if( !SetSecurityDescriptorDacl( &sdPermissions, TRUE, paclKey, FALSE ) )
		goto error;

	/* Finally, create the key with the security attributes we've set up */
	sa.nLength = sizeof( SECURITY_ATTRIBUTES );
	sa.bInheritHandle = FALSE;
	sa.lpSecurityDescriptor = &sdPermissions;
	if( RegCreateKeyEx( HKEY_LOCAL_MACHINE, REG_KEYNAME, 0,
						"Application Global Data", REG_OPTION_NON_VOLATILE,
						KEY_ALL_ACCESS, &sa, &hkGlobal, &dwDisposition ) != ERROR_SUCCESS )
		goto error;

	/* Usually the disposition value will indicate that we've created a new
	   key, but sometimes it may say that we've opened an existing one.  This
	   can happen when installation was interrupted for some reason */
	if( dwDisposition != REG_CREATED_NEW_KEY && \
		dwDisposition != REG_OPENED_EXISTING_KEY )
		goto error;

	/* Now add values to the global key */
	if( RegSetValueEx( hkGlobal, NULL, 0, REG_SZ, "Ftoomschk!", 11 ) != ERROR_SUCCESS )
		goto error;

	/* Force the new registry data out to disk */
	RegFlushKey( hkGlobal );

	/* Clean up */
	RegCloseKey( hkGlobal );
	FreeSid( psidAdmins );
	FreeSid( psidEveryone );
	free( paclKey );
	return( CRYPT_OK );

	/* Error exit point */
error:
	if( hkGlobal )
		RegDeleteKey( HKEY_LOCAL_MACHINE, REG_KEYNAME );
	if( psidAdmins )
		FreeSid( psidAdmins );
	if( psidEveryone )
		FreeSid( psidEveryone );
	if( paclKey != NULL )
		free( paclKey );
	return( CRYPT_ERROR );
	}
#endif /* 0 */

/****************************************************************************
*																			*
*						User-specific Registry Functions					*
*																			*
****************************************************************************/

/* If there's nothing in the registry yet for the current user, create a key
   below which things are stored */

static int createLocalConfig( void )
	{
	TOKEN_USER *pUserInfo = NULL;
	PSID psidAdmins = NULL;
	HKEY hkLocal = NULL;
	DWORD dwDisposition;
	int status = CRYPT_ERROR;

	/* Create the key with security information if the OS supports it */
	if( !isWin95 )
		{
		SID_IDENTIFIER_AUTHORITY systemSidAuthority = SECURITY_NT_AUTHORITY;
		SECURITY_ATTRIBUTES sa;
		SECURITY_DESCRIPTOR sdPermissions;
		PACL paclKey;

		/* Get SIDs for the admin group and the current user */
		if( !AllocateAndInitializeSid( &systemSidAuthority, 2,
									   SECURITY_BUILTIN_DOMAIN_RID,
									   DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0,
									   0, 0, &psidAdmins ) )
			return( CRYPT_ERROR );
		if( ( pUserInfo = getUserInfo() ) == NULL )
			goto exit;

		/* Set the current user to own this security descriptor */
		if( !InitializeSecurityDescriptor( &sdPermissions,
										   SECURITY_DESCRIPTOR_REVISION1 ) || \
			!SetSecurityDescriptorOwner( &sdPermissions, pUserInfo->User.Sid, 0 ) )
			goto exit;

		/* Set up the discretionary access control list (DACL) with two
		   access control entries (ACEs), one for admins which allows
		   complete access and one for the current user which also allows
		   full access.  We use _alloca() rather than malloc() because the
		   buffer is small and it makes unwinding the alloc easier  */
		if( ( paclKey = ( PACL ) _alloca( ACL_BUFFER_SIZE ) ) == NULL )
			goto exit;
		if( !InitializeAcl( paclKey, ACL_BUFFER_SIZE, ACL_REVISION2 ) || \
			!AddAccessAllowedAce( paclKey, ACL_REVISION2, KEY_ALL_ACCESS,
								  psidAdmins ) || \
			!AddAccessAllowedAce( paclKey, ACL_REVISION2, KEY_ALL_ACCESS,
								  pUserInfo->User.Sid ) )
			goto exit;

		/* Bind the DACL to the security descriptor */
		if( !SetSecurityDescriptorDacl( &sdPermissions, TRUE, paclKey, FALSE ) )
			goto exit;

		/* Finally, set up the security attributes */
		sa.nLength = sizeof( SECURITY_ATTRIBUTES );
		sa.bInheritHandle = FALSE;
		sa.lpSecurityDescriptor = &sdPermissions;

		/* Finally, create the key with the security attributes we've set up.
		   The access type doesn't matter much because we'll close it
		   immediately after we create it */
		if( RegCreateKeyEx( HKEY_CURRENT_USER, REG_KEYNAME, 0,
							"cryptlib per-user data",
							REG_OPTION_NON_VOLATILE, KEY_WRITE, &sa,
							&hkLocal, &dwDisposition ) != ERROR_SUCCESS )
			goto exit;
		}
	else
		/* There's no support for any kind of registry security, create the
		   key with anything security-related set to 0 */
		if( RegCreateKeyEx( HKEY_CURRENT_USER, REG_KEYNAME, 0,
							"cryptlib per-user data", 0, 0, NULL, &hkLocal,
							&dwDisposition ) != ERROR_SUCCESS )
			goto exit;

	/* Usually the disposition value will indicate that we've created a new
	   key, but sometimes it may say that we've opened an existing one.  This
	   can happen when installation was interrupted for some reason */
	if( dwDisposition == REG_CREATED_NEW_KEY )
		/* Force the new registry data out to disk */
		RegFlushKey( hkLocal );
	status = CRYPT_OK;

	/* Clean up */
	RegCloseKey( hkLocal );
exit:
	if( !isWin95 )
		{
		FreeSid( psidAdmins );
		if( pUserInfo != NULL )
			free( pUserInfo );
		}
	return( status );
	}

/* Begin the registry update process.  Returns with a handle to the cryptlib
   key and a mutex held on the key, or CRYPT_ERROR if something goes wrong */

int beginRegistryUpdate( const BOOLEAN isRead, HKEY *hkReg,
						 HANDLE *hmtxReg )
	{
	long lResult;
	REGSAM accessType = ( isRead ) ? KEY_QUERY_VALUE : KEY_WRITE;

	/* Clear the return values */
	*hmtxReg = *hkReg = NULL;

	/* Since multiple instances of cryptlib applications could be running
	   simultaneously, we use a named mutex to serialise registry access */
	if( ( *hmtxReg = CreateMutex( NULL, FALSE,
						"HKEY_CURRENT_USER/Software/cryptlib" ) ) == NULL )
		return( CRYPT_ERROR );

	/* Try to open the registry key.  First, we serialise access to the key
	   via hmtxReg */
	lResult = WaitForSingleObject( *hmtxReg, REGKEY_WAIT );
	if( lResult != WAIT_ABANDONED && lResult != WAIT_OBJECT_0 )
		{
		CloseHandle( *hmtxReg );
		return( CRYPT_ERROR );
		}

	/* Now try and open the registry key */
	if( RegOpenKeyEx( HKEY_CURRENT_USER, REG_KEYNAME, 0, accessType,
					  hkReg ) == ERROR_SUCCESS )
		return( CRYPT_OK );

	/* The open failed, probably beause the registry data hasn't been set
	   up yet.  Try and set it up now */
	if( cryptStatusOK( createLocalConfig() ) )
		/* Reopen the newly-created key with the appropriate access mode */
		if( RegOpenKeyEx( HKEY_CURRENT_USER, REG_KEYNAME, 0, accessType,
						  hkReg ) == ERROR_SUCCESS )
			return( CRYPT_OK );

	/* Error exit */
	ReleaseMutex( *hmtxReg );
	CloseHandle( *hmtxReg );
	return( CRYPT_ERROR );
	}

/* End the registry update process */

int endRegistryUpdate( HKEY hkReg, HANDLE hmtxReg )
	{
	if( hkReg )
		{
		/* Flush the data to disk if necessary */
		if( hmtxReg )
			RegFlushKey( hkReg );

		RegCloseKey( hkReg );
		}
	if( hmtxReg )
		{
		ReleaseMutex( hmtxReg );
		CloseHandle( hmtxReg );
		}

	return( CRYPT_OK );
	}

/* Convert a cryptlib path to a registry path */

static void convertPath( const char *path, char *keyName, char *valueName )
	{
	char *pathPtr = ( char * ) path, *lastComponent = keyName, *keyNameStart = keyName;
	int seenSeperator = 0;

	/* Copy the path across, converting it to a registry-style name as we go
	   and remembering where the last component started */
	while( *pathPtr )
		{
		int ch = *pathPtr++;

		if( ch == '.' )
			{
			*keyName++ = '\\';
			lastComponent = keyName;
			seenSeperator = 1;
			}
		else
			if( ch == '_' )
				*keyName++ = ' ';
			else
				*keyName++ = ch;
		}
	*keyName++ = '\0';

	/* The last component in the name is the value name */
	if( valueName != NULL )
		{
		strcpy( valueName, lastComponent );
		lastComponent[ -seenSeperator ] = '\0';
		}
	}

static HANDLE openRegPath( HKEY h1, const char *path, char *valueName,
						   BOOLEAN isRead )
	{
	HKEY hkReg, hkPartialReg = ( HKEY ) NULL;
	DWORD dwDisposition;
	char keyName[ 256 ];

	/* Try the simplest case (entire key path present) first.  If it's
	   present, we don't need to do anything */
	convertPath( path, keyName, valueName );
	if( !*keyName )
		/* No key path (it's a value only), we already have the required key
		   open */
		return( h1 );

	/* If we're reading the value, open the key with query access */
	if( isRead )
		{
		if( RegOpenKeyEx( h1, keyName, 0, KEY_QUERY_VALUE, &hkReg ) == ERROR_SUCCESS )
			return( hkReg );
		}
	else
		/* We're writing the value, open the key, creating any path
		   components which aren't already present if necessary */
		if( RegCreateKeyEx( h1, keyName, 0, "Application Local Data",
							REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hkReg,
							&dwDisposition ) == ERROR_SUCCESS )
			return( hkReg );

	return( INVALID_HANDLE_VALUE );
	}

/* Read a value or string from the registry */

int readRegistryString( HANDLE hkReg, const char *keyName, char *string )
	{
	HANDLE hkSubKey;
	DWORD valueLen = 256, valueType, lResult;
	char valueName[ 256 ];

	*string = '\0';
	if( ( hkSubKey = openRegPath( hkReg, keyName, valueName, TRUE ) ) == INVALID_HANDLE_VALUE )
		return( CRYPT_ERROR );
	lResult = RegQueryValueEx( hkSubKey, valueName, NULL, &valueType, string,
							   &valueLen );
	if( lResult != ERROR_SUCCESS || valueType != REG_SZ )
		valueLen = 0;
	string[ valueLen ] = '\0';	/* Add der terminador */
	if( hkSubKey != hkReg )
		RegCloseKey( hkSubKey );

	return( ( lResult != ERROR_SUCCESS ) ? CRYPT_ERROR : CRYPT_OK );
	}

int readRegistryBinary( HANDLE hkReg, const char *keyName, void *value,
						int *length )
	{
	HANDLE hkSubKey;
	DWORD valueLen = 256, valueType, lResult;
	char valueName[ 256 ];

	*length = 0;
	if( ( hkSubKey = openRegPath( hkReg, keyName, valueName, TRUE ) ) == INVALID_HANDLE_VALUE )
		return( CRYPT_ERROR );
	lResult = RegQueryValueEx( hkSubKey, valueName, NULL, &valueType, value,
							   &valueLen );
	if( lResult != ERROR_SUCCESS || valueType != REG_BINARY )
		valueLen = 0;
	if( hkSubKey != hkReg )
		RegCloseKey( hkSubKey );
	*length = valueLen;

	return( ( lResult != ERROR_SUCCESS ) ? CRYPT_ERROR : CRYPT_OK );
	}

int readRegistryValue( HANDLE hkReg, const char *keyName, int *value )
	{
	HANDLE hkSubKey;
	DWORD valueLen = sizeof( DWORD ), valueType, lResult;
	char valueName[ 256 ];

	*value = CRYPT_ERROR;
	if( ( hkSubKey = openRegPath( hkReg, keyName, valueName, TRUE ) ) == INVALID_HANDLE_VALUE )
		return( CRYPT_ERROR );
	lResult = RegQueryValueEx( hkSubKey, valueName, NULL, &valueType,
							   ( LPBYTE ) value, &valueLen );
	if( valueType != REG_DWORD )
		lResult = CRYPT_ERROR;
	if( hkSubKey != hkReg )
		RegCloseKey( hkSubKey );

	return( ( lResult != ERROR_SUCCESS ) ? CRYPT_ERROR : CRYPT_OK );
	}

int writeRegistryString( HANDLE hkReg, const char *keyName,
						 const char *string )
	{
	HANDLE hkSubKey;
	DWORD lResult;
	char valueName[ 256 ];

	if( ( hkSubKey = openRegPath( hkReg, keyName, valueName, FALSE ) ) == INVALID_HANDLE_VALUE )
		return( CRYPT_ERROR );
	lResult = RegSetValueEx( hkSubKey, valueName, 0, REG_SZ, string,
							 strlen( string ) );
	if( hkSubKey != hkReg )
		RegCloseKey( hkSubKey );

	return( ( lResult != ERROR_SUCCESS ) ? CRYPT_ERROR : CRYPT_OK );
	}

int writeRegistryBinary( HANDLE hkReg, const char *keyName,
						 const void *value, const int length )
	{
	HANDLE hkSubKey;
	DWORD lResult;
	char valueName[ 256 ];

	if( ( hkSubKey = openRegPath( hkReg, keyName, valueName, FALSE ) ) == INVALID_HANDLE_VALUE )
		return( CRYPT_ERROR );
	lResult = RegSetValueEx( hkSubKey, valueName, 0, REG_BINARY, value, 
							 length );
	if( hkSubKey != hkReg )
		RegCloseKey( hkSubKey );

	return( ( lResult != ERROR_SUCCESS ) ? CRYPT_ERROR : CRYPT_OK );
	}

int writeRegistryValue( HANDLE hkReg, const char *keyName, const int value )
	{
	HANDLE hkSubKey;
	DWORD lResult;
	char valueName[ 256 ];

	if( ( hkSubKey = openRegPath( hkReg, keyName, valueName, FALSE ) ) == INVALID_HANDLE_VALUE )
		return( CRYPT_ERROR );
	lResult = RegSetValueEx( hkSubKey, valueName, 0, REG_DWORD,
							 ( LPBYTE ) &value, sizeof( DWORD ) );
	if( hkSubKey != hkReg )
		RegCloseKey( hkSubKey );

	return( ( lResult != ERROR_SUCCESS ) ? CRYPT_ERROR : CRYPT_OK );
	}

#ifdef TEST

/* Test code */

void main( void )
	{
	HANDLE h1, h2;
	char buffer[ 256 ];
	int value, status;

#if 1
	status = beginRegistryUpdate( FALSE, &h1, &h2 );
	status = writeRegistryString( h1, "Test", "Test value" );
	status = writeRegistryString( h1, "Test1.Test2", "Test value" );
	status = writeRegistryString( h1, "TestX.TestY.TestZ", "Test value" );
	status = writeRegistryValue( h1, "NTest", 10 );
	status = writeRegistryValue( h1, "NTest1.NTest2", TRUE );
	status = writeRegistryValue( h1, "NTestX.NTestY.NTestZ", 50 );
	status = endRegistryUpdate( h1, h2 );
#endif /* 0 */

	status = beginRegistryUpdate( TRUE, &h1, &h2 );
	status = readRegistryString( h1, "Test", buffer );
	status = readRegistryString( h1, "Test1.Test2", buffer );
	status = readRegistryString( h1, "TestX.TestY.TestZ", buffer );
	status = readRegistryValue( h1, "NTest", &value );
	status = readRegistryValue( h1, "NTest1.NTest2", &value );
	status = readRegistryValue( h1, "NTestX.NTestY.NTestZ", &value );
	status = endRegistryUpdate( h1, h2 );
	}
#endif /* TEST */
