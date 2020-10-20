/****************************************************************************
*																			*
*					cryptlib Randomness Management Header File				*
*						 Copyright Peter Gutmann 1995-1997					*
*																			*
****************************************************************************/

#ifndef _RANDOM_DEFINED

#define _RANDOM_DEFINED

/* The locking variables used to serialise access to the random pool if the
   system supports multiple threads */

DEFINE_LOCKING_VARS( randPool )
DEFINE_LOCKING_VARS( randGen )

/* For systems which don't support background randomness gathering the
   routine to wait for the completion of the polling does nothing */

#if !defined( __WIN32__ ) && !defined( __UNIX__ )
  #define waitforRandomCompletion()
#endif /* !( __WIN32__ || __UNIX__ ) */

/* For systems which don't support special-case randomness gathering such as
   multithread polls, the routine to initialise and clean up special objects
   does nothing */

#if !defined( __WIN32__ )
  #define initRandomPolling()
  #define endRandomPolling()
#endif /* __WIN32__ */

/* The structure used to hold the random pool information.  This contains a
   set of individual variables grouped into a single data block to make it
   easier to handle.  We could for example allow multiple instances of the
   pool by passing a pointer to the appropriate struct to the randomness-
   related routines, but at the moment we only have a single pool with the
   pool information fixed memory.

   The buffer containing the random data pool is pagelocked in memory to
   ensure it never gets swapped to disk.  We maintain two indices into the
   pool, the write position (which defines where new data is added) and the
   read position (which defines where data is removed).  Whenever we add new
   data the write position is updated, once we reach the end of the pool we
   mix the pool using the hash function and start again at the beginning.  In
   addition each of the slow polls adds a random amount from 0..15 to the
   write position to ensure that even if a constant-length buffer is added,
   it's added at a different point each time (this probably has little effect
   anyway due to the mixing provided by the hash function, but does help add
   a little extra uncertainty for the /dev/random sources which always provide
   a fixed amount of data).

   Similarly when the random read position reaches the end of the buffer we
   recycle the content by running the mixing function over the buffer and
   going back to the start of the buffer */

typedef struct {
	BYTE *randomPool;		/* Random byte pool */
	int randomWritePos;		/* Current write position in the pool */
	int randomReadPos;		/* Current read position in the pool */
	int randomStatus;		/* Wether there's any randomness in the pool */
	} RANDOM_INFO;

extern RANDOM_INFO randomInfo;

/* The size of the randomness pool */

#define RANDOMPOOL_SIZE			256

/* Add a random offset to the location where the next amount of data is to
   be inserted */

#define randomizeAddPos()	randomInfo.randomWritePos += randomInfo.randomPool[ 0 ] & 0x0F

/* Add a byte to the random buffer.  This is implemented as a macro to avoid
   leaving random data passed to a function on the stack.  These are low-
   level routines which are not thread-safe, they should only be called from
   routines which lock the random pool during use */

#define addRandomByte( data ) \
	{ \
	if( randomInfo.randomWritePos > RANDOMPOOL_SIZE - 1 ) \
		mixRandomPool( &randomInfo ); \
	randomInfo.randomPool[ randomInfo.randomWritePos++ ] += data; \
	}

#define addRandomWord( word ) \
	{ \
	addRandomByte( ( BYTE ) ( ( WORD ) word >> 8 ) ); \
	addRandomByte( ( BYTE ) ( WORD ) word ); \
	}

#define addRandomLong( word ) \
	{ \
	addRandomByte( ( BYTE ) ( ( LONG ) word >> 24 ) ); \
	addRandomByte( ( BYTE ) ( ( LONG ) word >> 16 ) ); \
	addRandomByte( ( BYTE ) ( ( LONG ) word >> 8 ) ); \
	addRandomByte( ( BYTE ) ( LONG ) word ); \
	}

/* Prototypes for functions in lib_rand.c */

void mixRandomPool( RANDOM_INFO *randomInfo );
void addRandomBuffer( BYTE *buffer, int count );

/* Prototypes for functions in the OS-specific randomness polling routines */

void slowPoll( void );
void fastPoll( void );
#if defined( __WIN32__ ) || defined( __UNIX__ )
  void waitforRandomCompletion( void );
#endif /* __WIN32__ || __UNIX__ */
#if defined( __WIN32__ )
  void initRandomPolling( void );
  void endRandomPolling( void );
#endif /* __WIN32__ */
#if defined( __OS2__ )
  ULONG DosGetThreadID( void );
#endif  /* __OS2__ */
#endif /* _RANDOM_DEFINED */
