/****************************************************************************
*																			*
*				Tandem NonStop Kernel Randomness-Gathering Code				*
*																			*
****************************************************************************/

/* This module is part of the cryptlib continuously seeded pseudorandom
   number generator.  For usage conditions, see lib_rand.c */

/* General includes */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypt.h"
#include "random.h"

/* OS-specific includes */

#include <cextdecs(time)>

/* The number of samples of the CPU timer to take */

#define NO_CPU_SAMPLES		128

void fastPoll( void )
	{
	addRandomLong( time( NULL ) );
	}

void slowPoll( void )
	{
	BYTE buffer[ NO_CPU_SAMPLES ];
	short _lowmem timerData[ 10 ];
	int count;

	/* Read the low 8 bits of the CPU time used timer, which is incremented
	   every 1us if the CPU is busy.  This randomness sampling works a bit
	   like the AT&T truerand generator by sampling the 1us timer in software
	   with the read granularity being about 1ms depending on system load.
	   Even reading the timer changes its value, since it uses CPU time */
	for( count = 0; count < NO_CPU_SAMPLES; count++ )
		{
		TIME( timerData );
		buffer[ count ] = timerData[ 5 ];
		}

	/* Add the data to the randomness pool */
	randomizeAddPos();
	addRandomBuffer( buffer, count );
	zeroise( buffer, NO_CPU_SAMPLES );

	/* Remember that we've got some randomness we can use */
	randomInfo.randomStatus = CRYPT_OK;
	}
