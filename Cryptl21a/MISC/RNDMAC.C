/****************************************************************************
*																			*
*						  Macintosh Randomness-Gathering Code				*
*							Copyright Peter Gutmann 1997					*
*																			*
****************************************************************************/

/* This module is part of the cryptlib continuously seeded pseudorandom
   number generator.  For usage conditions, see lib_rand.c */

/* Mac threads are cooperatively scheduled (so they're what Win32 calls
   fibers rather than true threads) and there isn't any real equivalent of a
   mutex (only critical sections which prevent any other thread from being
   scheduled, which defeats the point of multithreading), so we don't support
   this pseudo-threading for randomness polling.  If proper threading were
   available, we'd use NewThread()/DisposeThread() to create/destroy the
   background randomness-polling thread */

/* General includes */

#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#include "random.h"

/* OS-specific includes */

#include <mac???.h>

void fastPoll( void )
	{
	BatteryTimeRec batteryTimeInfo;
	SMStatus soundStatus;
	ThreadID threadID;
	ThreadState threadState;
	EventRecord eventRecord;
	Point point;
	WindowPtr windowPtr;
	PScrapStuff scrapInfo;
	UnsignedWide usSinceStartup;
	BYTE buffer[ 2 ];
	short driverRefNum;
	long dateTime;
	int count, dummy;

	/* Get the status of the last alert, how much battery time is remaining
	   and the voltage from all batteries, the internal battery status, the
	   current date and time and time since system startup in ticks, the
	   application heap limit and current and heap zone, free memory in the
	   current and system heap, microseconds since system startup, whether
	   QuickDraw has finished drawing, modem status, SCSI status
	   information, maximum block allocatable without compacting, available
	   stack space, the last QuickDraw error code */
	addRandomLong( GetAlertStage() );
	count = GetBatteryCount();
	while( count-- )
		{
		addRandomLong( GetBatteryVoltage( count ) );
		GetBatteryTimes( count, &batteryTimeInfo );
		addRandomBuffer( battery&TimeInfo, sizeof( BatteryTimeRec ) );
		}
	if( !GetBatteryStatus( buffer, buffer + 1 ) )
		addRandomWord( buffer );
	GetDateTime( &dateTime );
	addRandomLong( dateTime );
	addRandomLong( TickCount() );
	addRandomLong( GetApplLimit() );
	addRandomLong( GetZone() );
	addRandomLong( SystemZone() );
	addRandomLong( FreeMem() );
	addRandomLong( FreeMemSys() );
	MicroSeconds( &usSinceStartup );
	addRandomBuffer( &usSinceStartup, sizeof( UnsignedWide ) );
	addRandomByte( QDDone( NULL ) );
	ModemStatus( buffer );
	addRandomByte( *buffer );
	addRandomWord( SCSIStat() );
	addRandomLong( MaxBlock() );
	addRandomLong( StackSpace() );
	addRandomLong( QDError() );

	/* Get the event code and message, time, and mouse location for the next
	   event in the event queue and the OS event queue */
	if( EventAvail( everyEvent, &eventRecord ) )
		addRandomBuffer( &eventRecord, sizeof( EventRecord ) );
	if( OSEventAvail( everyEvent, &eventRecord ) )
		addRandomBuffer( &eventRecord, sizeof( EventRecord ) );

	/* Get all sorts of information such as device-specific info, grafport
	   information, visible and clipping region, pattern, pen, text, and
	   colour information, and other details, on the topmost window.  Also
	   get the window variant.  If there's a colour table record, add the
	   colour table as well */
	if( ( windowPtr = FrontWindow() ) != NULL )
		{
		CTabHandle colourHandle;

		addRandomBuffer( windowPtr, sizeof( GrafPort ) );
		addRandomLong( GetWVariant( windowPtr ) );
		if( GetAuxWin( windowPtr, colourHandle ) )
			{
			CTabPtr colourPtr;

			HLock( colourHandle );
			colourPtr = *colourHandle;
			addRandomBuffer( colourPtr, sizeof( ColorTable ) );
			HUnlock( colourHandle );
			}
		}

	/* Get mouse-related such as the mouse button status and mouse position,
	   information on the window underneath the mouse
	addRandomLong( Button() );
	GetMouse( &point );
	addRandomBuffer( &point, sizeof( Point ) );
	FindWindow( point, &windowPtr );
	if( windowPtr != NULL )
		addRandomBuffer( windowPtr, sizeof( GrafPort ) );

	/* Get the size, handle, and location of the desk scrap/clipboard */
	scrapInfo = InfoScrap();
	addRandomBuffer( scrapInfo, sizeof( ScrapStuff ) );

	/* Get information on the current thread */
	GetThreadID( &threadID );
	GetThreadState( threadID, &threadState );
	addRandomBuffer( &threadState, sizeof( ThreadState ) );

	/* Get the sound mananger status.  This gets the number of allocated
	   sound channels and the current CPU load from these channels */
	SndManagerStatus( sizeof( SMStatus ), &soundStatus );
	addRandomBuffer( &soundStatus, sizeof( SMStatus ) );

	/* Get the speech manager version and status */
	addRandomLong( SpeechManagerVersion() );
	addRandomWord( SpeechBusy() );

	/* Get the status of the serial port.  This gets information on recent
	   errors, read and write pending status, and flow control values */
	if( !OpenDriver( CToPStr( ".AIn" ), &driverRefNum ) )
		{
		SerStaRec serialStatus;

		SetStatus( driverRefNum, &serialStatus );
		addRandomBuffer( &serialStatus, sizeof( SerStaRec ) );
		}
	if( !OpenDriver( CToPStr( ".AOut" ), &driverRefNum ) )
		{
		SerStaRec serialStatus;

		SetStatus( driverRefNum, &serialStatus );
		addRandomBuffer( &serialStatus, sizeof( SerStaRec ) );
		}
	}

void slowPoll( void )
	{
	ProcessSerialNumber psn;
	GDHandle deviceHandle;
	GrafPtr currPort;
	QHdrPtr queuePtr;
	static BOOLEAN addedFixedItems = FALSE;

	/* Walk through the list of graphics devices adding information about
	   a device (IM VI 21-21) */
	deviceHandle = GetDeviceList();
	while( deviceHandle != NULL )
		{
		GDHandle currentHandle = deviceHandle;
		GDPtr devicePtr;

		HLock( currentHandle );
		devicePtr = *currentHandle;
		deviceHandle = devicePtr->gdNextGD;
		addRandomBuffer( devicePtr, sizeof( GDevice ) );
		HUnlock( currentHandle );
		}

	/* Walk through the list of processes adding information about each
	   process, including the name and serial number of the process, file and
	   resource information, memory usage information, the name of the
	   launching process, launch time, and accumulated CPU time (IM VI 29-17) */
	psn = kNoProcess;
	while( !GetNextProcess( &psn ) )
		{
		ProcessInfoRec infoRec;
		GetProcessInformation( psn, &infoRec );
		addRandomBuffer( &infoRec, sizeof( ProcessInfoRec ) );
		}

	/* Get the command type, trap address, and parameters for all commands in
	   the file I/O queue.  The parameters are quite complex and are listed
	   on page 117 of IM IV, and include reference numbers, attributes, time
	   stamps, length and file allocation information, finder info, and large
	   amounts of other volume and filesystem-related data */
	if( ( queuePtr = GetFSQHdr() ) != NULL )
		do
			{
			/* The queue entries are variant records of variable length so we
			   need to adjust the length parameter depending on the record
			   type */
			addRandomBuffer( queuePtr, sizeof( ??? ) );
			}
		while( ( queuePtr = QueueNext( queuePtr ) ) != NULL );

	/* The following are fixed for the lifetime of the process so we only
	   add them once */
	if( !addedFixedItems )
		{
		Str255 appName, volName;
		GDHandle deviceHandle;
		Handle appHandle;
		DrvSts driveStatus;
		MachineLocation machineLocation;
		ProcessInfoRec processInfo;
		QHdrPtr vblQueue;
		SysEnvRec sysEnvirons;
		SysPPtr pramPtr;
		DefStartRec startupInfo;
		DefVideoRec videoInfo;
		DefOSRec osInfo;
		XPPParmBlk appleTalkParams;
		char *driverNames[] = {
			".AIn", ".AOut", ".AppleCD", ".ATP", ".BIn", ".BOut", ".MPP",
			".Print", ".Sony", ".Sound", ".XPP", NULL
			};
		int count, dummy, i, node, net, vRefNum, script;

		/* Get the current font family ID, node ID of the local AppleMumble
		   router, caret blink delay, CPU speed, double-click delay, sound
		   volume, application and system heap zone, the number of resource
		   types in the application, the number of sounds voices available,
		   the FRef of the current resource file, volume of the sysbeep,
		   primary line direction, computer SCSI disk mode ID, timeout before
		   the screen is dimmed and before the computer is put to sleep,
		   number of available threads in the thread pool, whether hard drive
		   spin-down is disabled, the handle to the i18n resources, timeout
		   time for the internal HDD, */
		addRandomLong( GetAppFont() );
		addRandomLong( GetBridgeAddress() );
		addRandomLong( GetCaretTime() );
		addRandomLong( GetCPUSpeed() );
		addRandomLong( GetDblTime() );
		addRandomLong( GetSoundVol() );
		addRandomLong( ApplicZone() );
		addRandomLong( SystemZone() );
		addRandomLong( CountTypes() );
		CountVoices( &count );
		addRandomLong( count );
		addRandomLong( CurrResFile );
		GetSysBeepVolume( &count );
		addRandomLong( count );
		addRandomWord( GetSysDirection() );
		addRandomWord( GetSCSIDiskModeAddress() );
		addRandomByte( GetDimmingTimeout() );
		addRandomByte( GetSleepTimeout() );
		GetFreeThreadCount( kCooperativeThread, &count );
		addRandomLong( count );
		addRandomByte( IsSpindownDisabled() );
		addRandomLong( IUGetIntl( 0 ) );
		addRandomLong( GetTimeout( 0 ) );

		/* Get the number of documents/files which were selected when the app
		   started and for each document get the vRefNum, name, type, and
		   version */
		CountAppFiles( &dummy, &count );
		addRandomLong( count );
		while( count )
			{
			AppFile theFile;
			GetAppFiles( count, &theFile );
			addRandomBuffer( &theFile, sizeof( AppFile ) );
			count--;
			}

		/* Get the apps name, resource file reference number, and handle to
		   the finder information */
		GetAppParams( appName, appHandle, &count );
		addRandomBuffer( appName, sizeof( Str255 ) );
		addRandomLong( appHandle );
		addRandomLong( count );

		/* Get all sorts of statistics such as physical information, disk and
		   write-protect present status, error status, and handler queue
		   information, on floppy drives attached to the system.  Also get
		   the volume name, volume reference number and number of bytes free,
		   for the volume in the drive */
		if( !DriveStatus( 1, &driveStatus ) )
			addRandomBuffer( driveStatus, DrvSts );
		if( !GetVInfo( 1, volName, &vRefNum, &count ) )
			{
			addRandomBuffer( volName, sizeof( Str255 ) );
			addRandomLong( vRefNum );
			addRandomLong( count );
			}
		if( !DriveStatus( 2, &driveStatus ) )
			addRandomBuffer( driveStatus, DrvSts );
		if( !GetVInfo( 2, volName, &vRefNum, &count ) )
			{
			addRandomBuffer( volName, sizeof( Str255 ) );
			addRandomLong( vRefNum );
			addRandomLong( count );
			}

		/* Get information on the head and tail of the vertical retrace
		   queue */
		if( ( vblQueue = GetVBLQHdr() ) != NULL )
			addRandomBuffer( vblQueue, sizeof( QHdr ) );

		/* Get the parameter RAM settings */
		pramPtr = GetSysPPtr();
		addRandomBuffer( pramPtr, sizeof( SysParmType ) );

		/* Get information about the machines geographic location */
		ReadLocation( &machineLocation );
		addRandomBuffer( machineLocation, sizeof( MachineLocation ) );

		/* Get information on current graphics devices including device
		   information such as dimensions and cursor information, and a
		   number of handles to device-related data blocks and functions, and
		   information about the dimentions and contents of the devices pixel
		   image as well as the images resolution, storage format, depth, and
		   colour usage */
		deviceHandle = GetDeviceList();
		do
			{
			GDPtr gdPtr;

			addRandomLong( deviceHandle );
			HLock( deviceHandle );
			gdPtr = ( GDPtr * ) *deviceHandle;
			addRandomBuffer( gdPtr, sizeof( GDevice ) );
			addRandomBuffer( gdPtr->gdPMap, sizeof( PixMap ) );
			HUnlock( deviceHandle );
			}
		while( ( deviceHandle = GetNextDevice( deviceHandle ) ) != NULL );

		/* Get the current system environment, including the machine and
		   system software type, the keyboard type, where there's a colour
		   display attached, the AppleTalk driver version, and the VRefNum of
		   the system folder */
		SysEnvirons( curSysEnvVers, &sysEnvirons );
		addRandomBuffer( sysEnvirons, sizeof( SysEnvRec ) );

		/* Get the AppleTalk node ID and network number for this machine */
		if( GetNodeAddress( &node, &number ) )
			{
			addRandomLong( node );
			addRandomLong( number );
			}

		/* Get information on each device connected to the ADB including the
		   device handler ID, the devices ADB address, and the address of the
		   devices handler and storage area */
		count = CountADBs();
		while( count-- )
			{
			ADBDataBlock adbInfo;

			GetIndADB( &adbInfo, count );
			addRandomBuffer( adbInfo, sizeof( ADBDataBlock ) );
			}

		/* Open the most common device types and get the general device
		   status information and (if possible) device-specific status.  The
		   general device information contains the device handle and flags,
		   I/O queue information, event information, and other driver-related
		   details */
		for( count = 0; driverNames[ count ] != NULL; count++ )
			{
			AuxDCEHandle dceHandle;
			short driverRefNum;

			/* Try and open the driver */
			if( OpenDriver( CToPStr( driverNames[ count ] ), &driverRefNum ) )
				continue;

			/* Get a handle to the driver control information (this could
			   also be done with GetDCtlHandle()) */
			Status( driverRefNum, 1, &dceHandle );
			HLock( dceHandle );
			addRandomBuffer( *dceHandle, sizeof( AuxDCE ) );
			HUnlock( dceHandle );
			CloseDrive( driverRefNum );
			}

		/* Get the name and volume reference number for the current volume */
		GetVol( volName, &vRefNum );
		addRandomBuffer( volName, sizeof( Str255 ) );
		addRandomLong( vRefNum );

		/* Get the time information, attributes, directory information and
		   bitmap, volume allocation information, volume and drive
		   information, pointers to various pieces of volume-related
		   information, and details on path and directory caches, for each
		   volume */
		if( ( queuePtr = GetVCBQHdr() ) != NULL )
			do
				addRandomBuffer( queuePtr, sizeof( VCB ) );
			while( ( queuePtr = QueueNext( queuePtr ) ) != NULL );

		/* Get the driver reference number, FS type, and media size for each
		   drive */
		if( ( queuePtr = GetDrvQHdr() ) != NULL )
			do
				addRandomBuffer( queuePtr, sizeof( DrvQEl ) );
			while( ( queuePtr = QueueNext( queuePtr ) ) != NULL );

		/* Get global script manager variables and vectors, including the
		   globals changed count, font, script, and i18n flags, various
		   script types, and cache information */
		for( count = 0; count < 30; count++ )
			addRandomLong( GetEnvirons( count ) );

		/* Get the script code for the font script the i18n script, and for
		   each one add the changed count, font, script, i18n, and display
		   flags, resource ID's, and script file information */
		script = FontScript();
		addRandomLong( script );
		for( count = 0; count < 30; count++ )
			addRandomLong( GetScript( script, count ) );
		script = IntlScript();
		addRandomLong( script );
		for( count = 0; count < 30; count++ )
			addRandomLong( GetScript( script, count ) );

		/* Get the device ID, partition, slot number, resource ID, and driver
		   reference number for the default startup device */
		GetDefaultStartup( &startupInfo );
		addRandomBuffer( &startupInfo, sizeof( DefStartRec ) );

		/* Get the slot number and resource ID for the default video device */
		GetVideoDefault( &videoInfo );
		addRandomBuffer( &videoInfo, sizeof( DefVideoRec ) );

		/* Get the default OS type */
		GetOSDefault( &osInfo );
		addRandomBuffer( &osInfo, sizeof( DefOSRec ) );

		/* Get the AppleTalk command block and data size and number of
		   sessions */
		ASPGetParms( &appleTalkParams, FALSE );
		addRandomBuffer( &appleTalkParams, sizeof( XPPParmBlk ) );

		addedFixedItems = TRUE;
		}
	}
