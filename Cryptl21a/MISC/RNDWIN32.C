/****************************************************************************
*																			*
*						  Win32 Randomness-Gathering Code					*
*	Copyright Peter Gutmann, Matt Thomlinson and Blake Coverett 1996-1999	*
*																			*
****************************************************************************/

/* This module is part of the cryptlib continuously seeded pseudorandom
   number generator.  For usage conditions, see lib_rand.c */

/* General includes */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../crypt.h"
#include "random.h"

/* OS-specific includes */

#include <tlhelp32.h>
#include <winperf.h>
#include <winioctl.h>
#include <process.h>

/* The number of bytes to read from the serial-port RNG on each slow poll */

#define SERIALRNG_BYTES		128

/* Randomness-debugging routine */

#if 0

static void dumpRandom( const void *buffer, const int length )
	{
	FILE *filePtr;
	char fileName[ 100 ];
	int count = 0;

	while( TRUE )
		{
		wsprintf( fileName, "rndout%02d", count++ );
		if( ( filePtr = fopen( fileName, "rb" ) ) == NULL )
			break;
		fclose( filePtr );
		}

	filePtr = fopen( fileName, "wb" );
	fwrite( buffer, 1, length, filePtr );
	fclose( filePtr );
	}

FILE *rndFilePtr;

static void beginDumpRandom( void )
	{
	char fileName[ 100 ];
	int count = 0;

	while( TRUE )
		{
		wsprintf( fileName, "rndout%02d", count++ );
		if( ( rndFilePtr = fopen( fileName, "rb" ) ) == NULL )
			break;
		fclose( rndFilePtr );
		}

	rndFilePtr = fopen( fileName, "wb" );
	}

static void doDumpRandom( const void *buffer, const int length )
	{
	fwrite( buffer, 1, length, rndFilePtr );
	}

static void endDumpRandom( void )
	{
	fclose( rndFilePtr );
	}

#else

#define dumpRandom( a, b )
#define beginDumpRandom()
#define doDumpRandom( a, b )
#define endDumpRandom()

#endif

#pragma comment( lib, "advapi32" )

static HANDLE hNetAPI32 = NULL;		/* Handle to networking library */
static HANDLE hThread = NULL;		/* Background polling thread handle */
static HANDLE hComm = ( HANDLE ) CRYPT_ERROR;	/* Handle to serial RNG */

/* Open and close a connection to a serial-based RNG */

static void closeSerialRNG( void )
	{
	if( hComm != ( HANDLE ) CRYPT_ERROR )
		CloseHandle( hComm );
	hComm = ( HANDLE ) CRYPT_ERROR;
	}

static int openSerialRNG( const char *port, const char *settings )
	{
	COMMPROP commProp;
	DWORD bytesRead;
	DCB dcb;
	char buffer[ 10 ];

	/* Open the serial port device and set the port parameters.  We need to
	   call GetCommState() before we call BuildCommDCB() because 
	   BuildCommDCB() doesn't touch the DCB fields not affected by the 
	   config string, so that they're left with garbage values which causes
	   SetCommState() to fail */
	hComm = CreateFile( port, GENERIC_READ, 0, NULL, OPEN_EXISTING, 
						FILE_ATTRIBUTE_NORMAL, NULL );
	if( hComm == ( HANDLE ) -1 )
		return( CRYPT_ERROR ) ;
	GetCommState( hComm, &dcb );
	BuildCommDCB( settings, &dcb );
	dcb.fRtsControl = RTS_CONTROL_HANDSHAKE;
	if( !SetCommState( hComm, &dcb ) )
		{
		closeSerialRNG();
		return( CRYPT_ERROR );
		}

	/* Set the timeout to return immediately in case there's nothing
	   plugged in */
	commProp.wPacketLength = sizeof( COMMPROP );
	GetCommProperties( hComm, &commProp );
	if( commProp.dwProvCapabilities & PCF_INTTIMEOUTS )
		{
		COMMTIMEOUTS timeouts;

		/* Wait 10ms between chars and per char (which will work even with 
		   a 1200bps generator), and 100ms overall (we need to make this 
		   fairly short since we don't want to have a long delay every
		   time the library is started up if the RNG is unplugged) */
		GetCommTimeouts( hComm, &timeouts );
		timeouts.ReadIntervalTimeout = 10;
		timeouts.ReadTotalTimeoutMultiplier = 10;
		timeouts.ReadTotalTimeoutConstant = 100;
		SetCommTimeouts( hComm, &timeouts );
		}

	/* The RNG can take awhile to get started so we wait 1/4s before trying
	   to read anything */
	PurgeComm( hComm, PURGE_RXABORT | PURGE_RXCLEAR );
	Sleep( 250 );

	/* Try and read a few bytes to make sure there's something there */
	PurgeComm( hComm, PURGE_RXABORT | PURGE_RXCLEAR );
	if( !ReadFile( hComm, buffer, 10, &bytesRead, NULL ) || bytesRead != 10 )
		{
		closeSerialRNG();
		return( CRYPT_ERROR );
		}

	return( CRYPT_OK );
	}

/* The shared Win32 fast poll routine */

void fastPoll( void )
	{
	static BOOLEAN addedFixedItems = FALSE;
	static int noFastPolls = 0;
	FILETIME  creationTime, exitTime, kernelTime, userTime;
	DWORD minimumWorkingSetSize, maximumWorkingSetSize;
	LARGE_INTEGER performanceCount;
	MEMORYSTATUS memoryStatus;
	HANDLE handle;
	POINT point;

	lockGlobalResource( randPool );

	/* Get various basic pieces of system information */
	addRandomLong( GetActiveWindow() );	/* Handle of active window */
	addRandomLong( GetCapture() );		/* Handle of window with mouse capture */
	addRandomLong( GetClipboardOwner() );/* Handle of clipboard owner */
	addRandomLong( GetClipboardViewer() );/* Handle of start of clpbd.viewer list */
	addRandomLong( GetCurrentProcess() );/* Pseudohandle of current process */
	addRandomLong( GetCurrentProcessId() );/* Current process ID */
	addRandomLong( GetCurrentThread() );/* Pseudohandle of current thread */
	addRandomLong( GetCurrentThreadId() );/* Current thread ID */
	addRandomLong( GetCurrentTime() );	/* Milliseconds since Windows started */
	addRandomLong( GetDesktopWindow() );/* Handle of desktop window */
	addRandomLong( GetFocus() );		/* Handle of window with kb.focus */
	addRandomWord( GetInputState() );	/* Whether sys.queue has any events */
	addRandomLong( GetMessagePos() );	/* Cursor pos.for last message */
	addRandomLong( GetMessageTime() );	/* 1 ms time for last message */
	addRandomLong( GetOpenClipboardWindow() );	/* Handle of window with clpbd.open */
	addRandomLong( GetProcessHeap() );	/* Handle of process heap */
	addRandomLong( GetProcessWindowStation() );	/* Handle of procs window station */
	addRandomLong( GetQueueStatus( QS_ALLEVENTS ) );/* Types of events in input queue */

	/* Get multiword system information */
	GetCaretPos( &point );				/* Current caret position */
	addRandomBuffer( ( BYTE * ) &point, sizeof( POINT ) );
	GetCursorPos( &point );				/* Current mouse cursor position */
	addRandomBuffer( ( BYTE * ) &point, sizeof( POINT ) );

	/* Get percent of memory in use, bytes of physical memory, bytes of free
	   physical memory, bytes in paging file, free bytes in paging file, user
	   bytes of address space, and free user bytes */
	memoryStatus.dwLength = sizeof( MEMORYSTATUS );
	GlobalMemoryStatus( &memoryStatus );
	addRandomBuffer( ( BYTE * ) &memoryStatus, sizeof( MEMORYSTATUS ) );

	/* Get thread and process creation time, exit time, time in kernel mode,
	   and time in user mode in 100ns intervals */
	handle = GetCurrentThread();
	GetThreadTimes( handle, &creationTime, &exitTime, &kernelTime, &userTime );
	addRandomBuffer( ( BYTE * ) &creationTime, sizeof( FILETIME ) );
	addRandomBuffer( ( BYTE * ) &exitTime, sizeof( FILETIME ) );
	addRandomBuffer( ( BYTE * ) &kernelTime, sizeof( FILETIME ) );
	addRandomBuffer( ( BYTE * ) &userTime, sizeof( FILETIME ) );
	handle = GetCurrentProcess();
	GetProcessTimes( handle, &creationTime, &exitTime, &kernelTime, &userTime );
	addRandomBuffer( ( BYTE * ) &creationTime, sizeof( FILETIME ) );
	addRandomBuffer( ( BYTE * ) &exitTime, sizeof( FILETIME ) );
	addRandomBuffer( ( BYTE * ) &kernelTime, sizeof( FILETIME ) );
	addRandomBuffer( ( BYTE * ) &userTime, sizeof( FILETIME ) );

	/* Get the minimum and maximum working set size for the current process */
	GetProcessWorkingSetSize( handle, &minimumWorkingSetSize,
							  &maximumWorkingSetSize );
	addRandomLong( minimumWorkingSetSize );
	addRandomLong( maximumWorkingSetSize );

	/* The following are fixed for the lifetime of the process so we only
	   add them once */
	if( !addedFixedItems )
		{
		STARTUPINFO startupInfo;

		/* Get name of desktop, console window title, new window position and
		   size, window flags, and handles for stdin, stdout, and stderr */
		startupInfo.cb = sizeof( STARTUPINFO );
		GetStartupInfo( &startupInfo );
		addRandomBuffer( ( BYTE * ) &startupInfo, sizeof( STARTUPINFO ) );
		addedFixedItems = TRUE;
		}

	/* The performance of QPC varies depending on the architecture it's
	   running on and on the OS.  Under NT it reads the CPU's 64-bit timstamp
	   counter (at least on a Pentium and newer '486's, it hasn't been tested
	   on anything without a TSC), under Win95 it reads the 1.193180 MHz PIC
	   timer.  There are vague mumblings in the docs that it may fail if the
	   appropriate hardware isn't available (possibly '386's or MIPS machines
	   running NT), but who's going to run NT on a '386? */
	if( QueryPerformanceCounter( &performanceCount ) )
		addRandomBuffer( ( BYTE * ) &performanceCount, sizeof( LARGE_INTEGER ) );
	else
		{
		/* Millisecond accuracy at best... */
		DWORD dwTicks = GetTickCount();
		addRandomBuffer( ( BYTE * ) &dwTicks, sizeof( dwTicks ) );
		}

	/* Since the Win32 fast poll gathers quite a bit of information, we treat
	   three of them as being equivalent to one slow poll */
	if( ++noFastPolls >= 3 )
		/* Remember that we've got some randomness we can use */
		randomInfo.randomStatus = CRYPT_OK;

	unlockGlobalResource( randPool );
	}

/* Type definitions for function pointers to call Toolhelp32 functions */

typedef BOOL ( WINAPI *MODULEWALK )( HANDLE hSnapshot, LPMODULEENTRY32 lpme );
typedef BOOL ( WINAPI *THREADWALK )( HANDLE hSnapshot, LPTHREADENTRY32 lpte );
typedef BOOL ( WINAPI *PROCESSWALK )( HANDLE hSnapshot, LPPROCESSENTRY32 lppe );
typedef BOOL ( WINAPI *HEAPLISTWALK )( HANDLE hSnapshot, LPHEAPLIST32 lphl );
typedef BOOL ( WINAPI *HEAPFIRST )( LPHEAPENTRY32 lphe, DWORD th32ProcessID, DWORD th32HeapID );
typedef BOOL ( WINAPI *HEAPNEXT )( LPHEAPENTRY32 lphe );
typedef HANDLE ( WINAPI *CREATESNAPSHOT )( DWORD dwFlags, DWORD th32ProcessID );

/* Global function pointers. These are necessary because the functions need
   to be dynamically linked since only the Win95 kernel currently contains
   them.  Explicitly linking to them will make the program unloadable under
   NT */

static CREATESNAPSHOT pCreateToolhelp32Snapshot = NULL;
static MODULEWALK pModule32First = NULL;
static MODULEWALK pModule32Next = NULL;
static PROCESSWALK pProcess32First = NULL;
static PROCESSWALK pProcess32Next = NULL;
static THREADWALK pThread32First = NULL;
static THREADWALK pThread32Next = NULL;
static HEAPLISTWALK pHeap32ListFirst = NULL;
static HEAPLISTWALK pHeap32ListNext = NULL;
static HEAPFIRST pHeap32First = NULL;
static HEAPNEXT pHeap32Next = NULL;

static void slowPollWin95( void )
	{
	PROCESSENTRY32 pe32;
	THREADENTRY32 te32;
	MODULEENTRY32 me32;
	HEAPLIST32 hl32;
	HANDLE hSnapshot;

	/* Initialize the Toolhelp32 function pointers if necessary */
	if( pCreateToolhelp32Snapshot == NULL )
		{
		HANDLE hKernel = NULL;

		/* Obtain the module handle of the kernel to retrieve the addresses
		   of the Toolhelp32 functions */
    	if( ( hKernel = GetModuleHandle( "KERNEL32.DLL" ) ) == NULL )
			return;

		/* Now get pointers to the functions */
		pCreateToolhelp32Snapshot = ( CREATESNAPSHOT ) GetProcAddress( hKernel,
													"CreateToolhelp32Snapshot" );
		pModule32First = ( MODULEWALK ) GetProcAddress( hKernel,
													"Module32First" );
		pModule32Next = ( MODULEWALK ) GetProcAddress( hKernel,
													"Module32Next" );
		pProcess32First = ( PROCESSWALK ) GetProcAddress( hKernel,
													"Process32First" );
		pProcess32Next = ( PROCESSWALK ) GetProcAddress( hKernel,
													"Process32Next" );
		pThread32First = ( THREADWALK ) GetProcAddress( hKernel,
													"Thread32First" );
		pThread32Next = ( THREADWALK ) GetProcAddress( hKernel,
													"Thread32Next" );
		pHeap32ListFirst = ( HEAPLISTWALK ) GetProcAddress( hKernel,
													"Heap32ListFirst" );
		pHeap32ListNext = ( HEAPLISTWALK ) GetProcAddress( hKernel,
													"Heap32ListNext" );
		pHeap32First = ( HEAPFIRST ) GetProcAddress( hKernel,
													"Heap32First" );
		pHeap32Next = ( HEAPNEXT ) GetProcAddress( hKernel,
													"Heap32Next" );

		/* Make sure we got valid pointers for every Toolhelp32 function */
		if( pModule32First == NULL || pModule32Next == NULL || \
			pProcess32First == NULL || pProcess32Next == NULL || \
			pThread32First == NULL || pThread32Next == NULL || \
			pHeap32ListFirst == NULL || pHeap32ListNext == NULL || \
			pHeap32First == NULL || pHeap32Next == NULL || \
			pCreateToolhelp32Snapshot == NULL )
			{
			/* Mark the main function as unavailable in case for future
			   reference */
			pCreateToolhelp32Snapshot = NULL;
			return;
			}
		}

	/* Take a snapshot of everything we can get to which is currently
	   in the system */
	hSnapshot = pCreateToolhelp32Snapshot( TH32CS_SNAPALL, 0 );
	if( !hSnapshot )
		return;

	randomizeAddPos();
beginDumpRandom();

	/* Walk through the local heap */
	hl32.dwSize = sizeof( HEAPLIST32 );
	if( pHeap32ListFirst( hSnapshot, &hl32 ) )
		do
			{
			HEAPENTRY32 he32;

			/* First add the information from the basic Heaplist32
			   structure */
			addRandomBuffer( ( BYTE * ) &hl32, sizeof( HEAPLIST32 ) );
doDumpRandom( &hl32, sizeof( HEAPLIST32 ) );

			/* Now walk through the heap blocks getting information
			   on each of them */
			he32.dwSize = sizeof( HEAPENTRY32 );
			if( pHeap32First( &he32, hl32.th32ProcessID, hl32.th32HeapID ) )
				do
{
					addRandomBuffer( ( BYTE * ) &he32, sizeof( HEAPENTRY32 ) );
doDumpRandom( &he32, sizeof( HEAPENTRY32 ) );
}
				while( pHeap32Next( &he32 ) );
			}
		while( pHeap32ListNext( hSnapshot, &hl32 ) );

	/* Walk through all processes */
	pe32.dwSize = sizeof( PROCESSENTRY32 );
	if( pProcess32First( hSnapshot, &pe32 ) )
		do
{
			addRandomBuffer( ( BYTE * ) &pe32, sizeof( PROCESSENTRY32 ) );
doDumpRandom( &pe32, sizeof( PROCESSENTRY32 ) );
}
		while( pProcess32Next( hSnapshot, &pe32 ) );

	/* Walk through all threads */
	te32.dwSize = sizeof( THREADENTRY32 );
	if( pThread32First( hSnapshot, &te32 ) )
		do
{
			addRandomBuffer( ( BYTE * ) &te32, sizeof( THREADENTRY32 ) );
doDumpRandom( &te32, sizeof( THREADENTRY32 ) );
}
	while( pThread32Next( hSnapshot, &te32 ) );

	/* Walk through all modules associated with the process */
	me32.dwSize = sizeof( MODULEENTRY32 );
	if( pModule32First( hSnapshot, &me32 ) )
		do
{
			addRandomBuffer( ( BYTE * ) &me32, sizeof( MODULEENTRY32 ) );
doDumpRandom( &me32, sizeof( MODULEENTRY32 ) );
}
	while( pModule32Next( hSnapshot, &me32 ) );
endDumpRandom();

	/* Clean up the snapshot */
	CloseHandle( hSnapshot );

	/* Remember that we've got some randomness we can use */
	randomInfo.randomStatus = CRYPT_OK;
	}

/* Perform a thread-safe slow poll for Windows 95.  The following function
   *must* be started as a thread */

unsigned __stdcall threadSafeSlowPollWin95( void *dummy )
	{
	UNUSED( dummy );

	slowPollWin95();
	_endthreadex( 0 );
	return( 0 );
	}

/* Type definitions for function pointers to call NetAPI32 functions */

typedef DWORD ( WINAPI *NETSTATISTICSGET )( LPWSTR szServer, LPWSTR szService,
											DWORD dwLevel, DWORD dwOptions,
											LPBYTE *lpBuffer );
typedef DWORD ( WINAPI *NETAPIBUFFERSIZE )( LPVOID lpBuffer, LPDWORD cbBuffer );
typedef DWORD ( WINAPI *NETAPIBUFFERFREE )( LPVOID lpBuffer );

/* Global function pointers. These are necessary because the functions need
   to be dynamically linked since only the WinNT kernel currently contains
   them.  Explicitly linking to them will make the program unloadable under
   Win95 */

static NETSTATISTICSGET pNetStatisticsGet = NULL;
static NETAPIBUFFERSIZE pNetApiBufferSize = NULL;
static NETAPIBUFFERFREE pNetApiBufferFree = NULL;

/* When we query the performance counters, we allocate an initial buffer and
   then reallocate it as required until RegQueryValueEx() stops returning
   ERROR_MORE_DATA.  The following values define the initial buffer size and
   step size by which the buffer is increased */

#define PERFORMANCE_BUFFER_SIZE		65536	/* Start at 64K */
#define PERFORMANCE_BUFFER_STEP		16384	/* Step by 16K */

static void slowPollWinNT( void )
	{
	static int isWorkstation = CRYPT_ERROR;
	static int cbPerfData = PERFORMANCE_BUFFER_SIZE;
	PPERF_DATA_BLOCK pPerfData;
	HANDLE hDevice;
	LPBYTE lpBuffer;
	DWORD dwSize, status;
	int nDrive;

	/* Find out whether this is an NT server or workstation if necessary */
	if( isWorkstation == CRYPT_ERROR )
		{
		HKEY hKey;

		if( RegOpenKeyEx( HKEY_LOCAL_MACHINE,
						  "SYSTEM\\CurrentControlSet\\Control\\ProductOptions",
						  0, KEY_READ, &hKey ) == ERROR_SUCCESS )
			{
			BYTE szValue[ 32 ];
			dwSize = sizeof( szValue );

			isWorkstation = TRUE;
			status = RegQueryValueEx( hKey, "ProductType", 0, NULL,
									  szValue, &dwSize );
			if( status == ERROR_SUCCESS && stricmp( szValue, "WinNT" ) )
				/* Note: There are (at least) three cases for ProductType:
				   WinNT = NT Workstation, ServerNT = NT Server, LanmanNT =
				   NT Server acting as a Domain Controller */
				isWorkstation = FALSE;

			RegCloseKey( hKey );
			}
		}

	/* Initialize the NetAPI32 function pointers if necessary */
	if( hNetAPI32 == NULL )
		{
		/* Obtain a handle to the module containing the Lan Manager functions */
		if( ( hNetAPI32 = LoadLibrary( "NETAPI32.DLL" ) ) != NULL )
			{
			/* Now get pointers to the functions */
			pNetStatisticsGet = ( NETSTATISTICSGET ) GetProcAddress( hNetAPI32,
														"NetStatisticsGet" );
			pNetApiBufferSize = ( NETAPIBUFFERSIZE ) GetProcAddress( hNetAPI32,
														"NetApiBufferSize" );
			pNetApiBufferFree = ( NETAPIBUFFERFREE ) GetProcAddress( hNetAPI32,
														"NetApiBufferFree" );

			/* Make sure we got valid pointers for every NetAPI32 function */
			if( pNetStatisticsGet == NULL ||
				pNetApiBufferSize == NULL ||
				pNetApiBufferFree == NULL )
				{
				/* Free the library reference and reset the static handle */
				FreeLibrary( hNetAPI32 );
				hNetAPI32 = NULL;
				}
			}
		}

	randomizeAddPos();

	/* Get network statistics.  Note: Both NT Workstation and NT Server by
	   default will be running both the workstation and server services.  The
	   heuristic below is probably useful though on the assumption that the
	   majority of the network traffic will be via the appropriate service.
	   In any case the network statistics return almost no randomness */
	if( hNetAPI32 &&
		pNetStatisticsGet( NULL,
						   isWorkstation ? L"LanmanWorkstation" : L"LanmanServer",
						   0, 0, &lpBuffer ) == 0 )
		{
		pNetApiBufferSize( lpBuffer, &dwSize );
		addRandomBuffer( ( BYTE * ) lpBuffer, dwSize );
dumpRandom( lpBuffer, dwSize );
		pNetApiBufferFree( lpBuffer );
		}

	/* Get disk I/O statistics for all the hard drives */
	for( nDrive = 0;; nDrive++ )
		{
		DISK_PERFORMANCE diskPerformance;
		char szDevice[ 24 ];

		/* Check whether we can access this device */
		sprintf( szDevice, "\\\\.\\PhysicalDrive%d", nDrive );
		hDevice = CreateFile( szDevice, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
							  NULL, OPEN_EXISTING, 0, NULL );
		if( hDevice == INVALID_HANDLE_VALUE )
			break;

		/* Note: This only works if you have turned on the disk performance
		   counters with 'diskperf -y'.  These counters are off by default */
		if( DeviceIoControl( hDevice, IOCTL_DISK_PERFORMANCE, NULL, 0,
							 &diskPerformance, sizeof( DISK_PERFORMANCE ),
							 &dwSize, NULL ) )
			addRandomBuffer( ( BYTE * ) &diskPerformance, dwSize );
		CloseHandle( hDevice );
		}

	/* Wait for any async keyset driver binding to complete.  You may be
	   wondering what this call is doing here... the reason it's necessary is
	   because RegQueryValueEx() will hang indefinitely if the async driver
	   bind is in progress.  The problem occurs in the dynamic loading and
	   linking of driver DLL's, which work as follows:

		hDriver = LoadLibrary( DRIVERNAME );
		pFunction1 = ( TYPE_FUNC1 ) GetProcAddress( hDriver, NAME_FUNC1 );
		pFunction2 = ( TYPE_FUNC1 ) GetProcAddress( hDriver, NAME_FUNC2 );

	   If RegQueryValueEx() is called while the GetProcAddress()'s are in
	   progress, it will hang indefinitely.  This is probably due to some
	   synchronisation problem in the kernel where the GetProcAddress() calls
	   affect something like a module reference count or function reference
	   count while RegQueryValueEx() is trying to take a snapshot of the
	   statistics, which include the reference counts.  Because of this, we
	   have to wait until any async driver bind has completed before we
	   can call RegQueryValueEx() */
	waitSemaphore( SEMAPHORE_DRIVERBIND );

	/* Get information from the system performance counters.  This can take
	   a few seconds to do.  In some environments the call to
	   RegQueryValueEx() can produce an access violation at some random time
	   in the future, adding a short delay after the following code block
	   makes the problem go away.  This problem is extremely difficult to
	   reproduce, I haven't been able to get it to occur despite running it
	   on a number of machines.  The best explanation for the problem is that
	   on the machine where it did occur, it was caused by an external driver
	   or other program which adds its own values under the
	   HKEY_PERFORMANCE_DATA key.  The NT kernel calls the required external
	   modules to map in the data, if there's a synchronisation problem the
	   external module would write its data at an inappropriate moment,
	   causing the access violation.  A low-level memory checker indicated
	   that ExpandEnvironmentStrings() in KERNEL32.DLL, called an
	   interminable number of calls down inside RegQueryValueEx(), was
	   overwriting memory (it wrote twice the allocated size of a buffer to a
	   buffer allocated by the NT kernel).  This may be what's causing the
	   problem, but since it's in the kernel there isn't much which can be
	   done.

	   In addition to these problems the code in RegQueryValueEx() which
	   estimates the amount of memory required to return the performance
	   counter information isn't very accurate, since it always returns a
	   worst-case estimate which is usually nowhere near the actual amount
	   required.  For example it may report that 128K of memory is required,
	   but only return 64K of data */
	pPerfData = ( PPERF_DATA_BLOCK ) malloc( cbPerfData );
	while( pPerfData != NULL )
		{
		dwSize = cbPerfData;
		status = RegQueryValueEx( HKEY_PERFORMANCE_DATA, "Global", NULL,
								  NULL, ( LPBYTE ) pPerfData, &dwSize );
		if( status == ERROR_SUCCESS )
			{
			if( !memcmp( pPerfData->Signature, L"PERF", 8 ) )
				{
				addRandomBuffer( ( BYTE * ) pPerfData, dwSize );
dumpRandom( pPerfData, dwSize );

				/* Remember that we've got some randomness we can use */
				randomInfo.randomStatus = CRYPT_OK;
				}
			free( pPerfData );
			pPerfData = NULL;
			}
		else
			if( status == ERROR_MORE_DATA )
				{
				cbPerfData += PERFORMANCE_BUFFER_STEP;
				pPerfData = ( PPERF_DATA_BLOCK ) realloc( pPerfData, cbPerfData );
				}
		}
	}

/* Perform a thread-safe slow poll for Windows NT.  The following function
   *must* be started as a thread */

unsigned __stdcall threadSafeSlowPollWinNT( void *dummy )
	{
	UNUSED( dummy );

	slowPollWinNT();
	_endthreadex( 0 );
	return( 0 );
	}

/* Perform a generic slow poll.  This starts the OS-specific poll in a
   separate thread */

void slowPoll( void )
	{
	unsigned threadID;

	/* If there's a serial-port RNG present, read data from it */
	if( hComm != ( HANDLE ) CRYPT_ERROR )
		{
		BYTE buffer[ SERIALRNG_BYTES ];
		DWORD bytesRead;

		/* Read 128 bytes from the serial RNG.  If this fails, we fall back
		   to the polling RNG */
		PurgeComm( hComm, PURGE_RXABORT | PURGE_RXCLEAR );
		if( ReadFile( hComm, buffer, SERIALRNG_BYTES, &bytesRead, NULL ) && \
			bytesRead == SERIALRNG_BYTES )
			{
			addRandomBuffer( buffer, SERIALRNG_BYTES );
			randomInfo.randomStatus = CRYPT_OK;

			/* If we're only using serial RNG input, we're done */
			if( getOptionNumeric( CRYPT_OPTION_DEVICE_SERIALRNG_ONLY ) )
				return;
			}
		}

	/* Start a threaded slow poll.  If a slow poll is already running, we
	   just return since there isn't much point in running two of them at the
	   same time */
	if( !hThread )
		if( isWin95 )
			hThread = ( HANDLE ) _beginthreadex( NULL, 0, &threadSafeSlowPollWin95,
												 NULL, 0, &threadID );
		else
			hThread = ( HANDLE ) _beginthreadex( NULL, 0, &threadSafeSlowPollWinNT,
												 NULL, 0, &threadID );
	}

/* Wait for the randomness gathering to finish.  Anything that requires the
   gatherer process to have completed gathering entropy should call
   waitforRandomCompletion(), which will block until the background process
   completes */

void waitforRandomCompletion( void )
	{
	if( hThread )
		{
		WaitForSingleObject( hThread, INFINITE );
		CloseHandle( hThread );
		hThread = NULL;
		}
	}

/* Initialise and clean up any auxiliary randomness-related objects */

void initRandomPolling( void )
	{
	char *serialPortString, *serialParamString;

	/* If there's a serial-port RNG configured, try and initialise it */
	if( ( serialPortString = getOptionString( CRYPT_OPTION_DEVICE_SERIALRNG ) ) != NULL && \
		( serialParamString = getOptionString( CRYPT_OPTION_DEVICE_SERIALRNG_PARAMS ) ) != NULL )
		openSerialRNG( serialPortString, serialParamString );

#if 0
	unsigned threadID;

	/* Fire off the background polling thread */
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, &randomPollThread, NULL, 0,
										 &threadID );
#endif /* 0 */
	}

void endRandomPolling( void )
	{
	if( hThread )
		CloseHandle( hThread );
	if( hNetAPI32 )
		{
		FreeLibrary( hNetAPI32 );
		hNetAPI32 = NULL;
		}
	if( hComm != ( HANDLE ) CRYPT_ERROR )
		closeSerialRNG();
	}
