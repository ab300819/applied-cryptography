/****************************************************************************
*																			*
*						  BeOS Randomness-Gathering Code					*
*			Copyright Peter Gutmann and Osma Ahvenlampi 1996-1997			*
*																			*
****************************************************************************/

/* This module is part of the cryptlib continuously seeded pseudorandom
   number generator.  For usage conditions, see lib_rand.c */

/* General includes */

#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#include "misc/random.h"

/* These get defined by the Be headers */

#undef min
#undef max

#include <fcntl.h>
#include <sys/time.h>
#include <kernel/OS.h>
#include <kernel/image.h>

void fastPoll( void )
	{
	struct timeval tv;
	system_info info;

	gettimeofday( &tv, NULL );
	addRandomLong( tv.tv_sec );
	addRandomLong( tv.tv_usec );

	get_system_info( &info );
	addRandomBuffer( &info, sizeof( info ) );
	}

#define DEVRANDOM_BITS		4096

void slowPoll( void )
	{
	team_info teami;
	thread_info threadi;
	area_info areai;
	port_info porti;
	sem_info semi;
	image_info imagei;
	long n;
	int	fd;

	randomizeAddPos();

	if( ( fd = open( "/dev/urandom", O_RDONLY ) ) >= 0 )
		{
		BYTE buffer[ DEVRANDOM_BITS / 8 ];

		/* Read data from /dev/urandom, which won't block (although the
		   quality of the noise is lesser). */
		read( fd, buffer, DEVRANDOM_BITS / 8 );
		randomizeAddPos();
		addRandomBuffer( buffer, DEVRANDOM_BITS / 8 );
		zeroise( buffer, DEVRANDOM_BITS / 8 );
		close( fd );

		/* Remember that we've got some randomness we can use */
		randomInfo.randomStatus = CRYPT_OK;
		return;
		}

	/* All running teams (applications) */
	for( n = 0; get_nth_team_info( n, &teami ) == B_NO_ERROR; n++ )
		addRandomBuffer( &teami, sizeof( teami ) );

	/* All running threads */
	for( n = 0; get_nth_thread_info( 0, n, &threadi ) == B_NO_ERROR; n++ )
		{
		addRandomLong( ( ulong ) has_data( threadi.thread ) );
		addRandomBuffer( &threadi, sizeof( threadi ) );
		}

	/* All memory areas */
	for( n = 0; get_nth_area_info( 0, n, &areai ) == B_NO_ERROR; n++ )
		addRandomBuffer( &areai, sizeof( areai ) );

	/* All message ports */
	for( n = 0; get_nth_port_info( 0, n, &porti ) == B_NO_ERROR; n++ )
		addRandomBuffer( &porti, sizeof( porti ) );

	/* All semaphores */
	for( n = 0; get_nth_sem_info( 0, n, &semi ) == B_NO_ERROR; n++ )
		addRandomBuffer( &semi, sizeof( semi ) );

	/* All images (code chunks) */
	for( n = 0; get_nth_image_info( 0, n, &imagei ) == B_NO_ERROR; n++ )
		addRandomBuffer( &imagi, sizeof( imagi ) );

	randomInfo.randomStatus = CRYPT_OK;
	}
