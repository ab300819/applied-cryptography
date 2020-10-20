/****************************************************************************
*																			*
*							Stream I/O Functions							*
*						Copyright Peter Gutmann 1993-1998					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) || defined( INC_CHILD )
  #include "stream.h"
#else
  #include "keymgmt/stream.h"
#endif /* Compiler-specific includes */
#if defined( __UNIX__ )
  #include <errno.h>
  #include <fcntl.h>
  #include <sys/types.h>
  #include <sys/file.h>
  #include <sys/stat.h>
  #if !( ( defined( sun ) && OSVERSION == 4 ) || defined( linux ) || \
		   defined( __bsdi__ ) || defined( __hpux ) )
	#include <sys/mode.h>
  #endif /* SunOS || Linux || BSDI */
  #include <unistd.h>
  #if defined( sun ) || defined( _M_XENIX ) || defined( linux ) || \
	  defined( __osf__ ) || defined( __bsdi__ ) || defined( _AIX )
	#include <utime.h>			/* It's a SYSV thing... */
  #endif /* SYSV Unixen */

  #if ( defined( sun ) && ( OSVERSION == 5 ) ) || \
	  ( defined( _M_XENIX ) && ( OSVERSION == 3 ) || \
	  defined( __hpux ) || defined( _AIX ) )
	#define flock( a, b )		/* Slowaris, SCO, Aches, and PHUX don't support flock() */
    /* Actually Slowaris does have flock(), but there are lots of warnings
	   in the manpage about using it only on BSD platforms, and the result
	   won't work with any of the system libraries */
  #endif /* Slowaris || SCO || PHUX || Aches */
  #if ( defined( _M_XENIX ) && ( OSVERSION == 3 ) )
	#define ftruncate( a, b )	/* SCO doesn't support ftruncate() either */
	#define NO_FTRUNCATE		/* Enable workaround in safe file open code */
  #endif /* SCO */
#elif defined( __AMIGA__ )
  #include <proto/dos.h>
#elif defined( __MSDOS16__ ) || defined( __WIN16__ )
  #include <io.h>
#elif defined( __OS2__ )
  #define INCL_DOSFILEMGR	/* DosQueryPathInfo(),DosSetFileSize(),DosSetPathInfo */
  #include <os2.h>			/* FILESTATUS */
  #include <io.h>
#elif defined( __WIN32__ )
  /* The size of the buffer for Win32 ACLs */
  #define ACL_BUFFER_SIZE		1024

  /* Prototypes for functions in registry.c */
  TOKEN_USER *getUserInfo( void );
#endif /* OS-specific includes and defines */

/****************************************************************************
*																			*
*							Generic Stream I/O Functions					*
*																			*
****************************************************************************/

/* Read a byte from a stream */

int sgetc( STREAM *stream )
	{
#ifdef __WIN32__
	DWORD bytesRead;
	BYTE ch;
#else
	int ch;
#endif /* __WIN32__ */

	/* If there's a problem with the stream, don't try to do anything */
	if( stream->status != CRYPT_OK )
		return( stream->status );
	if( stream->isNull )
		{
		stream->status = CRYPT_UNDERFLOW;
		return( CRYPT_UNDERFLOW );
		}

	/* If we ungot a char, return this */
	if( stream->ungetChar )
		{
		ch = stream->lastChar;
		stream->ungetChar = FALSE;
		return( ch );
		}

	/* If it's a memory stream, read the data from the buffer */
	if( sIsMemoryStream( stream ) )
		{
		if( stream->bufSize != STREAMSIZE_UNKNOWN && \
			stream->bufPos >= stream->bufEnd )
			{
			stream->status = CRYPT_UNDERFLOW;
			return( CRYPT_UNDERFLOW );
			}
		return( stream->lastChar = stream->buffer[ stream->bufPos++ ] );
		}

	/* It's a file stream, read the data from the file */
#ifdef __WIN32__
	if( !ReadFile( stream->hFile, &ch, 1, &bytesRead, NULL ) || !bytesRead )
#else
	if( ( ch = getc( stream->filePtr ) ) == EOF )
#endif /* __WIN32__ */
		{
		stream->status = CRYPT_UNDERFLOW;
		return( CRYPT_UNDERFLOW );
		}
	return( stream->lastChar = ch );
	}

/* Write a byte to a stream */

int sputc( STREAM *stream, int data )
	{
#ifdef __WIN32__
	DWORD bytesWritten;
	BYTE regData = data;
#else
	register int regData = data;
#endif /* __WIN32__ */

	/* With any luck localData is now in a register, so we can try to destroy
	   the copy of the data on the stack.  We do this by assigning a live
	   value to it and using it a little later on.  A really good optimizing
	   compiler should detect that this is a nop, but with any luck most
	   compilers won't */
	data = stream->status;

	/* If there's a problem with the stream, don't try to do anything until
	   the error is cleared */
	if( data != CRYPT_OK )
		return( data );		/* Equal to stream->status, force reuse of data */

	/* If it's a null stream, just record the write and return */
	if( stream->isNull )
		{
		stream->bufPos++;
		return( CRYPT_OK );
		}

	/* If we ungot a char, move back one entry in the buffer */
	if( stream->ungetChar && stream->bufPos )
		{
		stream->bufPos--;
		stream->ungetChar = FALSE;
		}

	/* If it's a memory stream, deposit the data in the buffer */
	if( sIsMemoryStream( stream ) )
		{
		if( stream->bufSize != STREAMSIZE_UNKNOWN && \
			stream->bufPos >= stream->bufSize )
			{
			stream->status = CRYPT_OVERFLOW;
			return( CRYPT_OVERFLOW );
			}
		stream->buffer[ stream->bufPos++ ] = regData;
		if( stream->bufEnd < stream->bufPos )
			/* Move up the end-of-data pointer if necessary */
			stream->bufEnd = stream->bufPos;
		return( CRYPT_OK );
		}

	/* It's a file stream, write the data to the file */
#ifdef __WIN32__
	if( !WriteFile( stream->hFile, &regData, 1, &bytesWritten, NULL ) || !bytesWritten )
#else
	if( putc( regData, stream->filePtr ) == EOF )
#endif /* __WIN32__ */
		{
		stream->status = CRYPT_DATA_WRITE;
		return( CRYPT_DATA_WRITE );
		}
	return( CRYPT_OK );
	}

/* Unget a byte from a stream */

int sungetc( STREAM *stream )
	{
	/* If the stream is empty, calling this function resets the stream
	   status to nonempty (since we can't read past EOF, ungetting even one
	   char will reset the stream status).  If the stream isn't empty, we
	   set a flag to indicate that we should return the last character read
	   in the next read call */
	if( stream->status == CRYPT_UNDERFLOW )
		stream->status = CRYPT_OK;
	else
		stream->ungetChar = TRUE;

	return( CRYPT_OK );
	}

/* Read a block of data from a stream.  If not enough data is available it
   will fail with STREAM_EMPTY rather than trying to read as much as it
   can, which mirrors the behaviour of most read()/fread() implementations */

int sread( STREAM *stream, void *buffer, int length )
	{
#ifdef __WIN32__
	DWORD bytesRead;
#endif /* __WIN32__ */
	BYTE *bufPtr = buffer;

	/* If there's a problem with the stream, don't try to do anything */
	if( stream->status != CRYPT_OK )
		return( stream->status );
	if( stream->isNull )
		{
		stream->status = CRYPT_UNDERFLOW;
		return( CRYPT_UNDERFLOW );
		}
	if( length == 0 )
		return( CRYPT_OK );

	/* If we ungot a char, return this first */
	if( stream->ungetChar )
		{
		*bufPtr++ = stream->lastChar;
		stream->ungetChar = FALSE;
		if( !--length )
			return( CRYPT_OK );
		}

	/* If it's a memory stream, read the data from the buffer */
	if( sIsMemoryStream( stream ) )
		{
		if( stream->bufSize != STREAMSIZE_UNKNOWN && \
			stream->bufPos + length > stream->bufEnd )
			{
			memset( bufPtr, 0, length );	/* Clear the output buffer */
			stream->status = CRYPT_UNDERFLOW;
			return( CRYPT_UNDERFLOW );
			}
		memcpy( bufPtr, stream->buffer + stream->bufPos, length );
		stream->bufPos += length;
		return( CRYPT_OK );
		}

	/* It's a file stream, read the data from the file */
#ifdef __WIN32__
	if( !ReadFile( stream->hFile, bufPtr, length, &bytesRead, NULL ) || \
		( int ) bytesRead != length )
#else
	if( fread( bufPtr, 1, length, stream->filePtr ) != ( size_t ) length )
#endif /* __WIN32__ */
		{
		stream->status = CRYPT_DATA_READ;
		return( CRYPT_DATA_READ );
		}
	return( CRYPT_OK );
	}

/* Write a block of data from a stream.  If not enough data is available it
   will fail with CRYPT_OVERFLOW rather than trying to write as much as it
   can, which mirrors the behaviour of most write()/fwrite()
   implementations */

int swrite( STREAM *stream, const void *buffer, const int length )
	{
#ifdef __WIN32__
	DWORD bytesWritten;
#endif /* __WIN32__ */

	/* If there's a problem with the stream, don't try to do anything until
	   the error is cleared */
	if( stream->status != CRYPT_OK )
		return( stream->status );
	if( length == 0 )
		return( CRYPT_OK );

	/* If it's a null stream, just record the write and return */
	if( stream->isNull )
		{
		stream->bufPos += length;
		return( CRYPT_OK );
		}

	/* If it's a memory stream, deposit the data in the buffer */
	if( sIsMemoryStream( stream ) )
		{
		if( stream->bufSize != STREAMSIZE_UNKNOWN && \
			stream->bufPos + length > stream->bufSize )
			{
			stream->status = CRYPT_OVERFLOW;
			return( CRYPT_OVERFLOW );
			}
		memcpy( stream->buffer + stream->bufPos, buffer, length );
		stream->bufPos += length;
		if( stream->bufEnd < stream->bufPos )
			/* Move up the end-of-data pointer if necessary */
			stream->bufEnd = stream->bufPos;
		return( CRYPT_OK );
		}

	/* It's a file stream, write the data to the file */
#ifdef __WIN32__
	if( !WriteFile( stream->hFile, buffer, length, &bytesWritten, NULL ) || \
		( int ) bytesWritten != length )
#else
	if( fwrite( buffer, 1, length, stream->filePtr ) != ( size_t ) length )
#endif /* __WIN32__ */
		{
		stream->status = CRYPT_DATA_WRITE;
		return( CRYPT_DATA_WRITE );
		}
	return( CRYPT_OK );
	}

/* Skip a number of bytes in a stream */

int sSkip( STREAM *stream, const long length )
	{
	long skipLength = length;

	/* If there's a problem with the stream, don't try to do anything */
	if( stream->status != CRYPT_OK )
		return( stream->status );
	if( stream->isNull )
		{
		stream->status = CRYPT_UNDERFLOW;
		return( CRYPT_UNDERFLOW );
		}
	if( length == 0 )
		return( CRYPT_OK );

	/* If we were ready to unget a char, skip it */
	if( stream->ungetChar )
		{
		stream->ungetChar = FALSE;
		stream->lastChar = 0;
		skipLength--;
		if( skipLength == 0 )
			return( CRYPT_OK );
		}

	/* If it's a memory stream, move ahead in the buffer */
	if( sIsMemoryStream( stream ) )
		{
		if( stream->bufSize != STREAMSIZE_UNKNOWN && \
			stream->bufPos + skipLength > stream->bufSize )
			{
			stream->bufPos = stream->bufSize;
			stream->status = CRYPT_UNDERFLOW;
			return( CRYPT_UNDERFLOW );
			}
		stream->bufPos += ( int ) skipLength;
		if( stream->bufPos > stream->bufEnd )
			/* If we've moved past the end of the valid data in the buffer,
			   move the end of data pointer to match the current position.
			   This mimics the behaviour of fseek(), which allows a seek past
			   the end of the file */
			stream->bufEnd = stream->bufPos;
		return( CRYPT_OK );
		}

	/* It's a file stream, skip the data in the file */
#ifdef __WIN32__
	if( SetFilePointer( stream->hFile, skipLength, NULL, FILE_CURRENT ) == 0xFFFFFFFF )
#else
	if( fseek( stream->filePtr, skipLength, SEEK_CUR ) )
#endif /* __WIN32__ */
		{
		stream->status = CRYPT_DATA_READ;
		return( CRYPT_DATA_READ );
		}
	return( CRYPT_OK );
	}

/* Move to a position in a stream */

int sseek( STREAM *stream, const long position )
	{
	/* Make sure all parameters are in order */
	if( stream == NULL || position < 0 )
		return( CRYPT_BADPARM );

	/* If it's a null or memory stream, move to the position in the buffer */
	if( stream->isNull )
		{
		stream->bufPos = ( int ) position;
		return( CRYPT_OK );
		}
	if( sIsMemoryStream( stream ) )
		{
		stream->ungetChar = FALSE;
		if( stream->bufSize != STREAMSIZE_UNKNOWN && \
			( int ) position > stream->bufSize )
			{
			stream->bufPos = stream->bufSize;
			stream->status = CRYPT_UNDERFLOW;
			return( CRYPT_UNDERFLOW );
			}

		/* Set the new R/W position */
		stream->bufPos = ( int ) position;
		if( stream->bufPos > stream->bufEnd )
			/* If we've moved past the end of the valid data in the buffer,
			   move the end of data pointer to match the current position.
			   This mimics the behaviour of fseek(), which allows a seek past
			   the end of the file */
			stream->bufEnd = stream->bufPos;
		return( CRYPT_OK );
		}

	/* It's a file stream, seek to the position in the file */
#ifdef __WIN32__
	if( SetFilePointer( stream->hFile, position, NULL, FILE_BEGIN ) == 0xFFFFFFFF )
#else
	if( fseek( stream->filePtr, position, SEEK_SET ) )
#endif /* __WIN32__ */
		return( CRYPT_DATA_WRITE );

	return( CRYPT_OK );
	}

/* Determine the position in a stream */

long stell( STREAM *stream )
	{
	long position;

	/* Make sure the parameters are in order */
	if( stream == NULL )
		return( CRYPT_BADPARM );

	/* If it's a memory or null stream, return the position in the buffer */
	if( sIsMemoryStream( stream ) || stream->isNull )
		return( sMemSize( stream ) );

	/* It's a file stream, find the position in the file */
#ifdef __WIN32__
	if( ( position = SetFilePointer( stream->hFile, 0, NULL, FILE_BEGIN ) ) == 0xFFFFFFFF )
#else
	if( ( position = ftell( stream->filePtr ) ) == -1L )
#endif /* __WIN32__ */
		return( CRYPT_DATA_READ );

	return( position );
	}

/****************************************************************************
*																			*
*							Memory Stream Functions							*
*																			*
****************************************************************************/

/* Open a memory stream.  If the buffer parameter is NULL, this creates a
   NULL stream which serves as a data sink - this is useful for implementing
   sizeof() functions by writing data to null streams */

int sMemOpen( STREAM *stream, void *buffer, const int length )
	{
	/* Make sure all parameters are in order */
	if( stream == NULL )
		return( CRYPT_BADPARM );
	memset( stream, 0, sizeof( STREAM ) );
	if( buffer == NULL )
		{
		/* Make it a null stream */
		stream->isNull = TRUE;
		return( CRYPT_OK );
		}
	if( length < 1 && length != STREAMSIZE_UNKNOWN )
		{
		sSetError( stream, CRYPT_BADPARM );
		return( CRYPT_BADPARM );
		}

	/* Initialise the stream structure */
	stream->buffer = buffer;
	stream->bufSize = length;
	if( stream->bufSize != STREAMSIZE_UNKNOWN )
		memset( stream->buffer, 0, stream->bufSize );

	return( CRYPT_OK );
	}

/* Close a memory stream */

int sMemClose( STREAM *stream )
	{
	/* Make sure all parameters are in order */
	if( stream == NULL )
		return( CRYPT_BADPARM );

	/* Clear the stream structure */
	if( stream->buffer != NULL )
		if( stream->bufSize != STREAMSIZE_UNKNOWN )
			zeroise( stream->buffer, stream->bufSize );
		else
			/* If it's of an unknown size we can still zap as much as was
			   written to/read from it */
			if( stream->bufEnd > 0 )
				zeroise( stream->buffer, stream->bufEnd );
	zeroise( stream, sizeof( STREAM ) );

	return( CRYPT_OK );
	}

/* Connect a memory stream without destroying the buffer contents */

int sMemConnect( STREAM *stream, const void *buffer, const int length )
	{
	/* Make sure all parameters are in order */
	if( stream == NULL )
		return( CRYPT_BADPARM );
	memset( stream, 0, sizeof( STREAM ) );
	if( buffer == NULL || ( length < 1 && length != STREAMSIZE_UNKNOWN ) )
		{
		sSetError( stream, CRYPT_BADPARM );
		return( CRYPT_BADPARM );
		}

	/* Initialise the stream structure */
	stream->buffer = ( void * ) buffer;
	stream->bufSize = stream->bufEnd = length;

	return( CRYPT_OK );
	}

/* Disconnect a memory stream without destroying the buffer contents */

int sMemDisconnect( STREAM *stream )
	{
	/* Make sure all parameters are in order */
	if( stream == NULL )
		return( CRYPT_BADPARM );

	/* Clear the stream structure */
	memset( stream, 0, sizeof( STREAM ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							File Stream Functions							*
*																			*
****************************************************************************/

/* Usually we'd use the C stdio routines for file I/O, but under Win32 we can
   get enhanced control over things like file security and buffering by using
   the Win32 file routines (in fact this is almost essential to work with
   things like ACL's for sensitive files and forcing disk writes for files we
   want to erase.  Without the forced disk write the data in the cache
   doesn't get flushed before the file delete request arrives, after which
   it's discarded rather than being written, so the file never gets
   overwritten) */

/* Open a file stream.  Unlike the other stream functions this returns a
   crypt error code rather than a stream error so that the code can be
   returned directly to the caller without requiring any translation */

#ifdef __WIN32__

int sFileOpen( STREAM *stream, const char *fileName, const int mode )
	{
	SECURITY_ATTRIBUTES sa;
	LPSECURITY_ATTRIBUTES lpsa = NULL;
	SECURITY_DESCRIPTOR sdPermissions;
	TOKEN_USER *pUserInfo = NULL;
	PACL paclKey = NULL;
	int status = CRYPT_DATA_OPEN;

	/* Make sure all parameters are in order */
	if( stream == NULL || fileName == NULL || mode == 0 )
		return( CRYPT_BADPARM );

	/* Initialise the stream structure */
	memset( stream, 0, sizeof( STREAM ) );

	/* If we're creating the file and we don't want others to get to it, set
	   up the security attributes to reflect this provided the OS supports
	   security */
	if( !isWin95 && ( mode & FILE_WRITE ) && ( mode & FILE_PRIVATE ) )
		{
		/* Get the SID for the current user */
		if( ( pUserInfo = getUserInfo() ) == NULL )
			goto exit;

		/* Set the current user to own this security descriptor */
		if( !InitializeSecurityDescriptor( &sdPermissions,
										   SECURITY_DESCRIPTOR_REVISION1 ) || \
			!SetSecurityDescriptorOwner( &sdPermissions, pUserInfo->User.Sid, 0 ) )
			goto exit;

		/* Set up the discretionary access control list (DACL) with one
		   access control entry (ACE) for the current user which allows full
		   access.  We use _alloca() rather than malloc() because the buffer
		   is small and it makes unwinding the alloc easier.  In addition we
		   give the user a somewhat odd set of access rights rather than the
		   more restricted set which would make sense because this set is
		   detected as "Full control" access instead of the peculiar collection
		   of rights we'd get from the more sensible GENERIC_READ |
		   GENERIC_WRITE | STANDARD_RIGHTS_ALL.  The OS can check the full-access
		   ACL much quicker than the one with the more restricted access
		   permissions */
		if( ( paclKey = ( PACL ) _alloca( ACL_BUFFER_SIZE ) ) == NULL )
			goto exit;
		if( !InitializeAcl( paclKey, ACL_BUFFER_SIZE, ACL_REVISION2 ) || \
			!AddAccessAllowedAce( paclKey, ACL_REVISION2,
								  GENERIC_ALL | STANDARD_RIGHTS_ALL,
								  pUserInfo->User.Sid ) )
			goto exit;

		/* Bind the DACL to the security descriptor */
		if( !SetSecurityDescriptorDacl( &sdPermissions, TRUE, paclKey, FALSE ) )
			goto exit;

		/* Finally, set up the security attributes structure */
		sa.nLength = sizeof( SECURITY_ATTRIBUTES );
		sa.bInheritHandle = FALSE;
		sa.lpSecurityDescriptor = &sdPermissions;
		lpsa = &sa;
		}

	/* Try and open the file */
	if( ( mode & FILE_RW_MASK ) == FILE_WRITE )
		stream->hFile = CreateFile( fileName, GENERIC_READ | GENERIC_WRITE, 0, lpsa,
									CREATE_ALWAYS,
									FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
									NULL );
	else
		{
		int openMode = ( ( mode & FILE_RW_MASK ) == FILE_READ ) ? \
					   GENERIC_READ : GENERIC_READ | GENERIC_WRITE;

		stream->hFile = CreateFile( fileName, openMode, FILE_SHARE_READ,
									NULL, OPEN_EXISTING,
									FILE_FLAG_SEQUENTIAL_SCAN, NULL );
		}
	if( stream->hFile == INVALID_HANDLE_VALUE )
		{
		DWORD errorCode = GetLastError();

		/* Translate the Win32 error code into an equivalent cryptlib error
		   code */
		if( errorCode == ERROR_FILE_NOT_FOUND || \
			errorCode == ERROR_PATH_NOT_FOUND )
			return( CRYPT_DATA_NOTFOUND );
		else
			if( errorCode == ERROR_ACCESS_DENIED )
				return( CRYPT_NOPERM );
			else
				return( CRYPT_DATA_OPEN);
		}
	else
		status = CRYPT_OK;

	/* Clean up */
exit:
	if( pUserInfo != NULL )
		free( pUserInfo );
	return( status );
	}
#else

int sFileOpen( STREAM *stream, const char *fileName, const int mode )
	{
	static const char *modes[] = { "x", "rb", "wb", "rb+" };
	const char *openMode;

	/* Make sure all parameters are in order */
	if( stream == NULL || fileName == NULL || mode == 0 )
		return( CRYPT_BADPARM );
	openMode = modes[ mode & FILE_RW_MASK ];

	/* Initialise the stream structure */
	memset( stream, 0, sizeof( STREAM ) );

	/* If we're trying to write to the file, check whether we've got
	   permission to do so */
	if( ( mode & FILE_WRITE ) && fileReadonly( fileName ) )
		return( CRYPT_NOPERM );

	/* Under Unix we try to defend against writing through links, but this is
	   somewhat difficult since the there's no atomic way to do this, and
	   without resorting to low-level I/O it can't be done at all.  What we
	   do is lstat() the file, open it as appropriate, and if it's an
	   existing file ftstat() it and compare various important fields to make
	   sure the file wasn't changed between the lstat() and the open().  If
	   everything is OK, we then use the lstat() information to make sure it
	   isn't a symlink (or at least that it's a normal file) and that the
	   link count is 1.  These checks also catch other weird things like
	   STREAMS stuff fattach()'d over files.

	   If these checks pass and the file already exists we truncate it to
	   mimic the effect of an open with create.  Finally, we use fdopen() to
	   convert the file handle for stdio use */
#ifdef __UNIX__
	if( ( mode & FILE_RW_MASK ) == FILE_WRITE )
		{
		struct stat lstatInfo;
		char *mode = "rb+";
		int fd;

		/* lstat() the file.  If it doesn't exist, create it with O_EXCL.  If
		   it does exist, open it for read/write and perform the fstat()
		   check */
		if( lstat( fileName, &lstatInfo ) == -1 )
			{
			/* If the lstat() failed for reasons other than the file not
			   existing, return a file open error */
			if( errno != ENOENT )
				return( CRYPT_DATA_OPEN );

			/* The file doesn't exist, create it with O_EXCL to make sure an
			   attacker can't slip in a file between the lstat() and open() */
			if( ( fd = open( fileName, O_CREAT | O_EXCL | O_RDWR, 0600 ) ) == -1 )
				return( CRYPT_DATA_OPEN );
			mode = "wb";
			}
		else
			{
			struct stat fstatInfo;

			/* Open an existing file */
			if( ( fd = open( fileName, O_RDWR ) ) == -1 )
				return( CRYPT_DATA_OPEN );

			/* fstat() the opened file and check that the file mode bits and
			   inode and device match */
			if( fstat( fd, &fstatInfo ) == -1 || \
				lstatInfo.st_mode != fstatInfo.st_mode || \
				lstatInfo.st_ino != fstatInfo.st_ino || \
				lstatInfo.st_dev != fstatInfo.st_dev )
				{
				close( fd );
				return( CRYPT_DATA_OPEN );
				}

			/* If the above check was passed, we know that the lstat() and
			   fstat() were done to the same file.  Now check that there's
			   only one link, and that it's a normal file (this isn't
			   strictly necessary because the fstat() vs lstat() st_mode
			   check would also find this) */
			if( fstatInfo.st_nlink > 1 || !S_ISREG( lstatInfo.st_mode ) )
				{
				close( fd );
				return( CRYPT_DATA_OPEN );
				}

			/* On systems which don't support ftruncate() the best we can do
			   is to close the file and reopen it in create mode which
			   unfortunately leads to a race condition, however "systems
			   which don't support ftruncate()" is pretty much SCO only, and
			   if you're using that you deserve what you get ("Little
			   sympathy has been extended") */
  #ifdef NO_FTRUNCATE
			close( fd );
			if( ( fd = open( fileName, O_CREAT | O_TRUNC | O_RDWR ) ) == -1 )
				return( CRYPT_DATA_OPEN );
			mode = "wb";
  #else
			ftruncate( fd, 0 );
  #endif /* NO_FTRUNCATE */
			}

		/* Open a stdio file over the low-level one */
		stream->filePtr = fdopen( fd, mode );
		if( stream->filePtr == NULL )
			{
			close( fd );
			unlink( fileName );
			return( CRYPT_ERROR );	/* Internal error, should never happen */
			}
		}
	else
#endif /* __UNIX__ */
	/* Try and open the file */
	stream->filePtr = fopen( fileName, openMode );
	if( stream->filePtr == NULL )
		/* The open failed, determine whether it was because the file doesn't
		   exist or because we can't use that access mode */
		return( ( access( fileName, 0 ) == -1 ) ? \
				CRYPT_DATA_NOTFOUND : CRYPT_DATA_OPEN );

	/* Set the file access permissions so only the owner can access it if
	   necessary */
#if defined( __UNIX__ )
	if( mode & FILE_PRIVATE )
		chmod( fileName, 0600 );
#endif /* __UNIX__ */

	/* Lock the file if necessary to make sure noone else tries to do things
	   to it.  We don't do anything fancy with timeouts and whatnot because
	   no process should ever lock the file for more than a fraction of a
	   second */
#ifdef __UNIX__
	/* Place a simple advisory lock on the file.  We don't use the more
	   complex lockf() because it's probably overkill for something this
	   simple, and because there are all sorts of weird variations (mainly in
	   the use of header files) of this floating around */
	flock( fileno( stream->filePtr ), LOCK_SH );
#endif /* __UNIX__ */

	return( CRYPT_OK );
	}
#endif /* __WIN32__ */

/* Close a file stream */

int sFileClose( STREAM *stream )
	{
	/* Make sure all parameters are in order */
	if( stream == NULL )
		return( CRYPT_BADPARM );

	/* Close the file and clear the stream structure */
#ifdef __WIN32__
	CloseHandle( stream->hFile );
#else
	/* Unlock the file if necessary */
  #ifdef __UNIX__
	flock( fileno( stream->filePtr ), LOCK_UN );
  #endif /* __UNIX__ */
	fclose( stream->filePtr );
#endif /* __WIN32__ */
	zeroise( stream, sizeof( STREAM ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Misc Oddball File Routines 						*
*																			*
****************************************************************************/

/* BC++ 3.1 is rather anal-retentive about not allowing extensions when in
   ANSI mode */

#if defined( __STDC__ ) && ( __BORLANDC__ == 0x410 )
  #define fileno( filePtr )		( ( filePtr )->fd )
#endif /* BC++ 3.1 in ANSI mode */

/* When checking whether a file is readonly we also have to check to make
   sure the file actually exists since the access check will return a false
   positive for a nonexistant file */

#if defined( __MSDOS16__ ) || defined( __OS2__ ) || defined( __WIN16__ )
  #include <errno.h>
#endif /* __MSDOS16__ || __OS2__ || __WIN16__ */

/* Some OS's don't define W_OK for the access check */

#ifndef W_OK
  #define W_OK	2
#endif /* W_OK */

/* Check whether a file is writeable */

BOOLEAN fileReadonly( const char *fileName )
	{
#if defined( __UNIX__ ) || defined( __MSDOS16__ ) || defined( __WIN16__ ) || \
	defined( __OS2__ )
	if( access( fileName, W_OK ) == -1 && errno != ENOENT )
		return( TRUE );
#elif defined( __WIN32__ )
	HANDLE hFile;

	/* The only way to tell whether a file is writeable is to try to open it
	   for writing */
	hFile = CreateFile( fileName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL, NULL );
	if( hFile == INVALID_HANDLE_VALUE )
		{
		DWORD errorCode = GetLastError();

		/* Translate the Win32 error code into an equivalent cryptlib error
		   code */
		if( errorCode == ERROR_ACCESS_DENIED )
			return( TRUE );
		return( FALSE );
		}
	CloseHandle( hFile );
#else
  #error Need to add file accessibility call
#endif /* OS-specific file accessibility check */

	return( FALSE );
	}

/* Wipe and delete a file (although it's not terribly rigorous).  Vestigia
   nulla retrorsum */

#ifdef __WIN32__

void fileCloseErase( STREAM *stream, const char *fileName )
	{
	BYTE buffer[ BUFSIZ ];
	int length;

	/* Wipe the file */
	SetFilePointer( stream->hFile, 0, NULL, FILE_BEGIN );
	length = GetFileSize( stream->hFile, NULL );
	while( length )
		{
		DWORD bytesWritten;
		int bytesToWrite = min( length, BUFSIZ );

		/* We need to make sure we fill the buffer with random data for each
		   write, otherwise compressing filesystems will just compress it to
		   nothing */
		getNonce( buffer, bytesToWrite );
		WriteFile( stream->hFile, buffer, bytesToWrite, &bytesWritten, NULL );
		length -= bytesToWrite;
		}

	/* Truncate the file to 0 bytes, reset the timestamps, and delete the
	   file.  The delete just marks the file as deleted rather than actually
	   deleting it, but there's not much information which can be recovered
	   without a magnetic force microscope.  The call to FlushFileBuffers()
	   ensures that the changed data gets committed before the delete call
	   comes along, if we didn't do this then the OS would drop all changes
	   once DeleteFile() was called, leaving the original more or less intact
	   on disk */
	SetFilePointer( stream->hFile, 0, NULL, FILE_BEGIN );
	SetEndOfFile( stream->hFile );
	SetFileTime( stream->hFile, 0, 0, 0 );
	FlushFileBuffers( stream->hFile );
	CloseHandle( stream->hFile );
	DeleteFile( fileName );
	}
#else

void fileCloseErase( STREAM *stream, const char *fileName )
	{
#if defined( __UNIX__ )
	struct utimbuf timeStamp;
#elif defined( __AMIGA__ )
	struct DateStamp dateStamp;
#elif defined( __MSDOS16__ )
	struct ftime fileTime;
#elif defined( __OS2__ )
	FILESTATUS info;
#elif defined( __WIN16__ )
	HFILE hFile;
#endif /* OS-specific file access structures */
	BYTE buffer[ BUFSIZ ];
	int length, fileHandle = fileno( stream->filePtr );

	/* Figure out how big the file is */
	fseek( stream->filePtr, 0, SEEK_END );
	length = ( int ) ftell( stream->filePtr );
	fseek( stream->filePtr, 0, SEEK_SET );

	/* Wipe the file.  This is a fairly crude function which performs a
	   single pass of overwriting the data with random data, it's not
	   possible to do much better than this without getting terribly OS-
	   specific.  Under Win95 and NT it wouldn't have much effect at all
	   since the file buffering is such that the file delete appears before
	   the OS buffers has been flushed, so the OS never bothers writing the
	   data.  For this reason we use different code for Win32 which uses a
	   low-level function which forces a disk buffer flush.

	   You'll NEVER get rid of me, Toddy */
	while( length )
		{
		int bytesToWrite = min( length, BUFSIZ );

		/* We need to make sure we fill the buffer with random data for each
		   write, otherwise compressing filesystems will just compress it to
		   nothing */
		getNonce( buffer, bytesToWrite );
		fwrite( buffer, 1, bytesToWrite, stream->filePtr );
		length -= bytesToWrite;
		}
	fflush( stream->filePtr );

	/* Truncate the file to 0 bytes, reset the time stamps, and delete it */
#if defined( __UNIX__ )
	ftruncate( fileHandle, 0 );
#elif defined( __AMIGA__ )
	SetFileSize( fileHandle, OFFSET_BEGINNING, 0 );
#elif defined( __MSDOS16__ )
	chsize( fileHandle, 0 );
	memset( &fileTime, 0, sizeof( struct ftime ) );
	setftime( fileHandle, &fileTime );
#elif defined( __MSDOS32__ )
  #error Need to add file truncate/time set calls
#elif defined( __OS2__ )
	DosSetFileSize( fileHandle, 0 );
#endif /* OS-specific size and date-mangling */
	sFileClose( stream );
#if defined( __UNIX__ )
	timeStamp.actime = timeStamp.modtime = 0;
	utime( fileName, &timeStamp );
#elif defined( __AMIGA__ )
	memset( dateStamp, 0, sizeof( struct DateStamp ) );
	SetFileDate( fileName, &dateStamp );
#elif defined( __MSDOS32__ )
  #error Need to add file truncate/time set calls
#elif defined( __OS2__ )
	DosQueryPathInfo( ( PSZ ) fileName, FIL_STANDARD, &info, sizeof( info ) );
	memset( &info.fdateLastWrite, 0, sizeof( info.fdateLastWrite ) );
	memset( &info.ftimeLastWrite, 0, sizeof( info.ftimeLastWrite ) );
	memset( &info.fdateLastAccess, 0, sizeof( info.fdateLastAccess ) );
	memset( &info.ftimeLastAccess, 0, sizeof( info.ftimeLastAccess ) );
	memset( &info.fdateCreation, 0, sizeof( info.fdateCreation ) );
	memset( &info.ftimeCreation, 0, sizeof( info.ftimeCreation ) );
	DosSetPathInfo( ( PSZ ) fileName, FIL_STANDARD, &info, sizeof( info ), 0 );
#elif defined( __WIN16__ )
	/* Under Win16 we can't really do anything without resorting to MSDOS int
	   21h calls, the best we can do is truncate the file using _lcreat() */
	hFile = _lcreat( fileName, 0 );
	if( hFile != HFILE_ERROR )
		_lclose( hFile );
#endif /* OS-specific size and date-mangling */

	/* Finally, delete the file */
	remove( fileName );
	}
#endif /* __WIN32__ */
