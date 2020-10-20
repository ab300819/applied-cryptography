/****************************************************************************
*																			*
*							Win16 Randomness-Gathering Code					*
*						   Copyright Peter Gutmann 1996-1997				*
*																			*
****************************************************************************/

/* This module is part of the cryptlib continuously seeded pseudorandom
   number generator.  For usage conditions, see lib_rand.c */

/* General includes */

#include <stdlib.h>
#include <string.h>
#include "../crypt.h"
#include "random.h"

/* OS-specific includes */

#include <stress.h>
#include <toolhelp.h>

void fastPoll( void )
	{
	static int noFastPolls = 0;
	SYSHEAPINFO sysHeapInfo;
	MEMMANINFO memManInfo;
	TIMERINFO timerInfo;
	POINT point;

	/* Get various basic pieces of system information */
	addRandomWord( GetCapture() );	/* Handle of window with mouse capture */
	addRandomWord( GetFocus() );	/* Handle of window with input focus */
	addRandomLong( GetFreeSpace( 0 ) );	/* Amount of space in global heap */
	addRandomWord( GetInputState() );	/* Whether system queue has any events */
	addRandomLong( GetMessagePos() );	/* Cursor pos.for last message */
	addRandomLong( GetMessageTime() );	/* 55 ms time for last message */
	addRandomWord( GetNumTasks() );	/* Number of active tasks */
	addRandomLong( GetTickCount() );/* 55 ms time since Windows started */
	GetCursorPos( &point );			/* Current mouse cursor position */
	addRandomBuffer( ( BYTE * ) &point, sizeof( POINT ) );
	GetCaretPos( &point );			/* Current caret position */
	addRandomBuffer( ( BYTE * ) &point, sizeof( POINT ) );

	/* Get the largest free memory block, number of lockable pages, number of
	   unlocked pages, number of free and used pages, and number of swapped
	   pages */
	memManInfo.dwSize = sizeof( MEMMANINFO );
	MemManInfo( &memManInfo );
	addRandomBuffer( ( BYTE * ) &memManInfo, sizeof( MEMMANINFO ) );

	/* Get the execution times of the current task and VM to approximately
	   1ms resolution */
	timerInfo.dwSize = sizeof( TIMERINFO );
	TimerCount( &timerInfo );
	addRandomBuffer( ( BYTE * ) &timerInfo, sizeof( TIMERINFO ) );

	/* Get the percentage free and segment of the user and GDI heap */
	sysHeapInfo.dwSize = sizeof( SYSHEAPINFO );
	SystemHeapInfo( &sysHeapInfo );
	addRandomBuffer( ( BYTE * ) &sysHeapInfo, sizeof( SYSHEAPINFO ) );

	/* Since the Win16 fast poll gathers a reasonable amount of information,
	   we treat five of them as being equivalent to one slow poll */
	if( ++noFastPolls >= 5 )
		/* Remember that we've got some randomness we can use */
		randomInfo.randomStatus = CRYPT_OK;
	}

/* The slow poll can get *very* slow because of the overhead involved in
   obtaining the necessary information.  On a moderately loaded system there
   are often 500+ objects on the global heap and 50+ modules, so we limit
   the number checked to a reasonable level to make sure we don't spend
   forever polling.  We give the global heap walk the most leeway since this
   provides the best source of randomness */

void slowPoll( void )
	{
	MODULEENTRY moduleEntry;
	GLOBALENTRY globalEntry;
	TASKENTRY taskEntry;
	int count;

	randomizeAddPos();

	/* Walk the global heap getting information on each entry in it.  This
	   retrieves the objects linear address, size, handle, lock count, owner,
	   object type, and segment type */
	count = 0;
	globalEntry.dwSize = sizeof( GLOBALENTRY );
	if( GlobalFirst( &globalEntry, GLOBAL_ALL ) )
		do
			{
			addRandomBuffer( ( BYTE * ) &globalEntry, sizeof( GLOBALENTRY ) );
			count++;
			}
		while( count < 70 && GlobalNext( &globalEntry, GLOBAL_ALL ) );

	/* Walk the module list getting information on each entry in it.  This
	   retrieves the module name, handle, reference count, executable path,
	   and next module */
	count = 0;
	moduleEntry.dwSize = sizeof( MODULEENTRY );
	if( ModuleFirst( &moduleEntry ) )
		do
			{
			addRandomBuffer( ( BYTE * ) &moduleEntry, sizeof( MODULEENTRY ) );
			count++;
			}
		while( count < 20 && ModuleNext( &moduleEntry ) );

	/* Walk the task list getting information on each entry in it.  This
	   retrieves the task handle, parent task handle, instance handle, stack
	   segment and offset, stack size, number of pending events, task queue,
	   and the name of module executing the task.  We also call TaskGetCSIP()
	   for the code segment and offset of each task if it's safe to do so
	   (note that this call can cause odd things to happen in debuggers and
	   runtime code checkers because of the way TaskGetCSIP() is implemented) */
	count = 0;
	taskEntry.dwSize = sizeof( TASKENTRY );
	if( TaskFirst( &taskEntry ) )
		do
			{
			addRandomBuffer( ( BYTE * ) &taskEntry, sizeof( TASKENTRY ) );
			if( taskEntry.hTask != GetCurrentTask() )
				addRandomLong( TaskGetCSIP( taskEntry.hTask ) );
			count++;
			}
		while( count < 100 && TaskNext( &taskEntry ) );

	/* Remember that we've got some randomness we can use */
	randomInfo.randomStatus = CRYPT_OK;
	}
