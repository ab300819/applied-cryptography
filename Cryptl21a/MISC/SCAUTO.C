/****************************************************************************
*																			*
*					cryptlib Generic Smart Card Reader Routines				*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "scard.h"
  #include "sio.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../keymgmt/asn1.h"
  #include "scard.h"
  #include "sio.h"
#else
  #include "crypt.h"
  #include "keymgmt/asn1.h"
  #include "misc/scard.h"
  #include "misc/sio.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*						 	Reader Init/Shutdown Routines					*
*																			*
****************************************************************************/

/* Close a previously-opened session with the reader.  We have to have this
   before initReader() since it may be called by initReader() if the init
   process fails */

static void shutdownReader( SCARD_INFO *scardInfo )
	{
	SIO_Close( scardInfo->cardInfo );
	scardInfo->cardInfo = NULL;
	}

/* Open a session with a reader */

static int initReader( SCARD_INFO *scardInfo, const char *readerName,
					   const char *cardName, const COMM_PARAMS *commParams )
	{
	BYTE atr[ CRYPT_MAX_TEXTSIZE ];
	int atrSize = 0, ch, i;

	UNUSED( readerName );
	UNUSED( cardName );

	/* Open a comms session to the reader */
	scardInfo->cardInfo = SIO_Open( ( char * ) commParams->portName );
	if( scardInfo->cardInfo == NULL )
		return( CRYPT_DATA_OPEN );

	/* Set up the comms parameters as specified by the caller */
	SIO_SetSpeed( scardInfo->cardInfo, commParams->baudRate );
	SIO_SetDataBits( scardInfo->cardInfo, commParams->dataBits );
	SIO_SetStopBits( scardInfo->cardInfo, commParams->stopBits );
	SIO_SetParity( scardInfo->cardInfo, ( commParams->parity == COMM_PARITY_NONE ) ? \
				   SIO_PARITY_NONE : ( commParams->parity == COMM_PARITY_ODD ) ? \
				   SIO_PARITY_ODD : SIO_PARITY_EVEN );
	SIO_SetIOMode( scardInfo->cardInfo, SIO_IOMODE_INDIRECT );
	SIO_WriteSettings( scardInfo->cardInfo );

	/* Read the ATR from the card and try and determine which type of card it
	   is */
	while( ( ch = SIO_ReadChar( scardInfo->cardInfo ) ) != -1 );	/* Flush buffer */
	SIO_DropRTS( scardInfo->cardInfo );
	SIO_Delay( scardInfo->cardInfo, 25 );
	SIO_RaiseRTS( scardInfo->cardInfo );
	SIO_Delay( scardInfo->cardInfo, 25 );
	for( i = 0; i < 3; i++ )
		/* Some cards can be slow in responding with some parts of the ATR
		   (eg ones which encode card state information) so we allow for a
		   few timeouts on reading */
		while( ( ch = SIO_ReadChar( scardInfo->cardInfo ) ) != -1 )
			if( atrSize < CRYPT_MAX_TEXTSIZE )
				atr[ atrSize++ ] = ch;
	scardInfo->cardType = getCardType( atr, atrSize );
	if( scardInfo->cardType == CRYPT_ERROR )
		{
		/* We don't know what to do with this card type, exit */
		shutdownReader( scardInfo );
		return( CRYPT_DATA_OPEN );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Card Read/Write Routines						*
*																			*
****************************************************************************/

/* Write data to a card */

static int writeData( SCARD_INFO *scardInfo, const BYTE *data,
					  const int length )
	{
	if( SIO_WriteBuffer( scardInfo->cardInfo, ( char * ) data, length ) == -1 )
		return( CRYPT_DATA_WRITE );
	return( CRYPT_OK );
	}

/* Read data from a card */

static int readData( SCARD_INFO *scardInfo, BYTE *data )
	{
	int length;

	/* Read enough data from the card that we can determine how much more we
	   have to read */
	if( SIO_ReadBuffer( scardInfo->cardInfo, ( char * ) data, 8 ) == -1 )
		return( CRYPT_DATA_READ );
	length = getObjectLength( data, 8 );

	/* Read the data from the card */
	if( SIO_ReadBuffer( scardInfo->cardInfo, ( char * ) data + 8,
						length - 8 ) == -1 )
		return( CRYPT_DATA_READ );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Card Access Routines							*
*																			*
****************************************************************************/

/* Set up the function pointers to the access methods */

int setAccessMethodAuto( SCARD_INFO *scardInfo )
	{
	scardInfo->initReader = initReader;
	scardInfo->shutdownReader = shutdownReader;
	scardInfo->readData = readData;
	scardInfo->writeData = writeData;

	return( CRYPT_OK );
	}
