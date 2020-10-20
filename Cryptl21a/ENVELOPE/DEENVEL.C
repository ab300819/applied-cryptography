/****************************************************************************
*																			*
*					  cryptlib De-enveloping Routines						*
*					 Copyright Peter Gutmann 1996-1999						*
*																			*
****************************************************************************/

#include <assert.h>	/*!!!!!!!!!!!!*/
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "asn1.h"
  #include "asn1misc.h"
  #include "asn1objs.h"
  #include "envelope.h"
#elif defined( INC_CHILD )
  #include "../keymgmt/asn1.h"
  #include "../keymgmt/asn1objs.h"
  #include "../keymgmt/asn1oid.h"
  #include "envelope.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1objs.h"
  #include "keymgmt/asn1oid.h"
  #include "envelope/envelope.h"
#endif /* Compiler-specific includes */

/* Prototypes for functions in asn1objs.c */

int queryObject( STREAM *stream, OBJECT_INFO *cryptObjectInfo );

/* Prototypes for functions in resource.c */

CONTENT_LIST *createContentListItem( const CRYPT_FORMAT_TYPE formatType,
									 const void *object, const int objectSize );

/****************************************************************************
*																			*
*						Low-level De-enveloping Functions					*
*																			*
****************************************************************************/

/* OID information used to read enveloped data */

static const OID_SELECTION envelopeOIDselection[] = {
	{ OID_CRYPTLIB_ENVELOPE, 0, 0, ACTION_KEYEXCHANGE },
	{ OID_CMS_DATA, CRYPT_UNUSED, CRYPT_UNUSED, ACTION_NONE },
	{ OID_CMS_SIGNEDDATA, 0, 3, ACTION_SIGN },
	{ OID_CMS_ENVELOPEDDATA, 0, 2, ACTION_KEYEXCHANGE },
	{ OID_CMS_DIGESTEDDATA, 0, 2, ACTION_HASH },
	{ OID_CMS_ENCRYPTEDDATA, 0, 2, ACTION_CRYPT },
	{ NULL, 0, 0, 0 }
	};

static const OID_SELECTION nestedContentOIDselection[] = {
	{ OID_CMS_DATA, CRYPT_UNUSED, CRYPT_UNUSED, CRYPT_CONTENT_DATA },
	{ OID_CMS_SIGNEDDATA, CRYPT_UNUSED, CRYPT_UNUSED, CRYPT_CONTENT_SIGNEDDATA },
	{ OID_CMS_ENVELOPEDDATA, CRYPT_UNUSED, CRYPT_UNUSED, CRYPT_CONTENT_ENVELOPEDDATA },
	{ OID_CMS_ENCRYPTEDDATA, CRYPT_UNUSED, CRYPT_UNUSED, CRYPT_CONTENT_ENCRYPTEDDATA },
	{ NULL, 0, 0, 0 }
	};

/* Add an item to the content list */

static void appendContentItem( ENVELOPE_INFO *envelopeInfoPtr,
							   const CONTENT_LIST *contentListItem )
	{
	CONTENT_LIST *contentListPtr = envelopeInfoPtr->contentList;

	if( envelopeInfoPtr->contentList == NULL )
		{
		envelopeInfoPtr->contentList = ( CONTENT_LIST * ) contentListItem;
		return;
		}

	/* Find the end of the list and add the new item */
	while( contentListPtr->next != NULL )
		contentListPtr = contentListPtr->next;
	contentListPtr->next = ( CONTENT_LIST * ) contentListItem;
	}

/* Add information about an object to an envelopes content information list */

static int addContentListItem( STREAM *stream, ENVELOPE_INFO *envelopeInfoPtr )
	{
	OBJECT_INFO objectInfo;
	CONTENT_LIST *contentListItem;
	void *object;
	int status;

	/* Find the size of the object, allocate a buffer for it, and copy it
	   across */
	status = queryObject( stream, &objectInfo );
	if( cryptStatusError( status ) )
		return( status );
	if( ( object = malloc( ( size_t ) objectInfo.size ) ) == NULL )
		return( CRYPT_NOMEM );
	sread( stream, object, ( int ) objectInfo.size );

	/* Allocate memory for the new content list item and copy information on
	   the item across */
	contentListItem = createContentListItem( objectInfo.formatType,
											 object, ( int ) objectInfo.size );
	if( contentListItem == NULL )
		{
		if( stream != NULL )
			free( object );
		return( CRYPT_NOMEM );
		}
	if( objectInfo.type == CRYPT_OBJECT_PKCENCRYPTED_KEY )
		{
		/* Remember details of the enveloping info we require to continue */
		contentListItem->envInfo = CRYPT_ENVINFO_PRIVATEKEY;
		memcpy( contentListItem->keyID, objectInfo.keyID, KEYID_SIZE );
		}
	if( objectInfo.type == CRYPT_OBJECT_ENCRYPTED_KEY )
		{
		/* Remember details of the enveloping info we require to continue */
		if( objectInfo.keySetupAlgo != CRYPT_ALGO_NONE )
			contentListItem->envInfo = CRYPT_ENVINFO_PASSWORD;
		else
			contentListItem->envInfo = CRYPT_ENVINFO_KEY;
		contentListItem->cryptAlgo = objectInfo.cryptAlgo;
		contentListItem->cryptMode = objectInfo.cryptMode;
		}
	if( objectInfo.type == CRYPT_OBJECT_SIGNATURE )
		{
		/* Remember details of the enveloping info we require to continue */
		contentListItem->envInfo = CRYPT_ENVINFO_SIGNATURE;
		memcpy( contentListItem->keyID, objectInfo.keyID, KEYID_SIZE );
		contentListItem->hashAlgo = objectInfo.hashAlgo;
		}
	appendContentItem( envelopeInfoPtr, contentListItem );

	return( ( int ) objectInfo.size );
	}

/* Process additional out-of-band data */

int processExtraData( ENVELOPE_INFO *envelopeInfoPtr, const void *buffer,
					  const int length )
	{
	ACTION_LIST *hashActionPtr;
	int status;

	/* Hash the data or wrap up the hashing as appropriate */
	for( hashActionPtr = envelopeInfoPtr->hashActions;
		 hashActionPtr != NULL && hashActionPtr->action == ACTION_HASH;
		 hashActionPtr = hashActionPtr->next )
		{
		status = iCryptDecrypt( hashActionPtr->iCryptHandle,
								( void * ) buffer, length );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If we've finished the hashing, clear the pointer to the hash actions
	   to prevent it from being hashed again if it's processed by other code
	   such as copyFromDeenvelope() */
	if( !length )
		envelopeInfoPtr->hashActions = NULL;

	return( CRYPT_OK );
	}

/* Process the non-data portions of an envelope.  This is a complex event-
   driven state machine, but instead of reading along a (hypothetical
   Turing-machine) tape, someone has taken the tape and cut it into bits and
   keeps feeding them to us and saying "See what you can do with this" (and
   occasionally "Where's the bloody spoons?").  The following code implements
   this state machine.

	Encr. with key exchange: SET_ENCR -> ENCR -> ENCRCONTENT -> DATA
	Encr.: ENCRCONTENT -> DATA
	Signed: SET_HASH -> HASH -> CONTENT -> DATA */

int processPreamble( ENVELOPE_INFO *envelopeInfoPtr )
	{
	DEENV_STATE state = envelopeInfoPtr->deenvState;
	STREAM stream;
	int length, streamPos = 0, status = CRYPT_OK;

	sMemConnect( &stream, envelopeInfoPtr->buffer, envelopeInfoPtr->bufPos );

	/* If we haven't started doing anything yet, try and read the outer
	   header fields */
	if( state == DEENVSTATE_NONE )
		{
		/* Read the outer CMS header */
		status = readCMSheader( &stream, envelopeOIDselection,
								&envelopeInfoPtr->payloadSize );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}

		/* Remember where we are and move on to the next state */
		streamPos = sMemSize( &stream );
		switch( status )
			{
			case ACTION_KEYEXCHANGE:
				envelopeInfoPtr->usage = ACTION_CRYPT;
				state = DEENVSTATE_SET_ENCR;
				break;

			case ACTION_CRYPT:
				envelopeInfoPtr->usage = ACTION_CRYPT;
				state = DEENVSTATE_ENCRCONTENT;
				break;

			case ACTION_SIGN:
				envelopeInfoPtr->usage = ACTION_SIGN;
				state = DEENVSTATE_SET_HASH;
				break;

			case ACTION_NONE:
				state = DEENVSTATE_DATA;
			}
		}

	/* Keep consuming information until we run out of input or reach the data
	   payload */
	while( state != DEENVSTATE_DONE )
		{
		/* Check that various values are within range.  They can go out of
		   range if the header is corrupted */
		if( envelopeInfoPtr->hdrSetLength < 0 && \
			envelopeInfoPtr->hdrSetLength != CRYPT_UNUSED )
			{
			status = CRYPT_BADDATA;
			break;
			}

		/* Read the start of the SET OF EncryptionKeyInfo */
		if( state == DEENVSTATE_SET_ENCR )
			{
			/* Read the SET tag and length */
			status = readSet( &stream, &length );
			if( cryptStatusError( status ) )
				break;

			/* Remember where we are and move on to the next state.  Some
			   implementations use the indefinite-length encoding for this so
			   if there's no length given we have to look for the EOC after
			   each entry read */
			streamPos = sMemSize( &stream );
			envelopeInfoPtr->hdrSetLength = ( length ) ? length : CRYPT_UNUSED;
			state = DEENVSTATE_ENCR;
			}

		/* Read and remember a key exchange object from an EncryptionKeyInfo
		   record */
		if( state == DEENVSTATE_ENCR )
			{
			/* Add the object to the content information list */
			status = addContentListItem( &stream, envelopeInfoPtr );
			if( cryptStatusError( status ) )
				break;

			/* Remember where we are and move on to the next state if
			   necessary */
			streamPos = sMemSize( &stream );
			if( envelopeInfoPtr->hdrSetLength != CRYPT_UNUSED )
				{
				envelopeInfoPtr->hdrSetLength -= status;
				if( envelopeInfoPtr->hdrSetLength <= 0 )
					state = DEENVSTATE_ENCRCONTENT;
				}
			else
				if( checkEOC( &stream ) )
					state = DEENVSTATE_ENCRCONTENT;
			}

		/* Read the encrypted content information */
		if( state == DEENVSTATE_ENCRCONTENT )
			{
			ACTION_LIST *actionListPtr;
			CONTENT_LIST contentListItem;

			/* Read the encrypted content header */
			memset( &contentListItem, 0, sizeof( CONTENT_LIST ) );
			contentListItem.envInfo = CRYPT_ENVINFO_SESSIONKEY;
			status = readCMSencrHeader( &stream, nestedContentOIDselection,
					&envelopeInfoPtr->payloadSize, &contentListItem.cryptAlgo,
					&contentListItem.cryptMode, contentListItem.iv,
					&contentListItem.ivSize );
			if( cryptStatusError( status ) )
				break;
			envelopeInfoPtr->contentType = status;

			/* We've reached encrypted data, we can't go any further until we
			   can either recover the session key from a key exchange object
			   or are fed the session key directly */
			actionListPtr = findAction( envelopeInfoPtr->actionList, ACTION_CRYPT );
			if( actionListPtr == NULL )
				{
				CONTENT_LIST *contentListItemPtr;

				/* Remember what we need for later and exit */
				if( ( contentListItemPtr = malloc( sizeof( CONTENT_LIST ) ) ) == NULL )
					{
					status = CRYPT_NOMEM;
					break;
					}
				memcpy( contentListItemPtr, &contentListItem,
						sizeof( CONTENT_LIST ) );
				appendContentItem( envelopeInfoPtr, contentListItemPtr );
				streamPos = sMemSize( &stream );
				state = DEENVSTATE_DATA;
				status = CRYPT_ENVELOPE_RESOURCE;
				break;
				}

			/* If the session key was recovered from a key exchange action but
			   we ran out of input data before we could read the
			   encryptedContent info, it'll be present in the action list so
			   we use it to set things up for the decryption.  This can only
			   happen if the caller pushes in just enough data to get past the
			   key exchange actions but not enough to recover the
			   encryptedContent info and then pushes in a key exchange action
			   in response to the CRYPT_UNDERFLOW error */
			status = initEnvelopeEncryption( envelopeInfoPtr,
						actionListPtr->iCryptHandle, contentListItem.cryptAlgo,
						contentListItem.cryptMode, contentListItem.iv,
						contentListItem.ivSize, FALSE );
			if( cryptStatusError( status ) )
				break;

			/* Remember where we are and move on to the next state */
			streamPos = sMemSize( &stream );
			state = DEENVSTATE_DATA;
			}

		/* Read the start of the SET OF DigestAlgorithmIdentifier */
		if( state == DEENVSTATE_SET_HASH )
			{
			/* Read the SET tag and length */
			status = readSet( &stream, &length );
			if( cryptStatusError( status ) )
				break;

			/* Remember where we are and move on to the next state.  Some
			   implementations use the indefinite-length encoding for this so
			   if there's no length given we have to look for the EOC after
			   each entry read */
			streamPos = sMemSize( &stream );
			envelopeInfoPtr->hdrSetLength = ( length ) ? length : CRYPT_UNUSED;
			state = DEENVSTATE_HASH;
			}

		/* Read and remember a hash object from a DigestAlgorithmIdentifier
		   record */
		if( state == DEENVSTATE_HASH )
			{
			CRYPT_CONTEXT iHashContext;
			ACTION_LIST *actionListItem;

			/* Add the object to the content information list */
			status = readContextAlgorithmIdentifier( &stream, &iHashContext, NULL );
			if( cryptStatusError( status ) )
				break;

			/* Create the new list item */
			actionListItem = createAction( ACTION_HASH, iHashContext );
			if( actionListItem == NULL )
				{
				status = CRYPT_NOMEM;
				break;
				}

			/* Add the new item to the list and remember where the hash
			   actions start */
			if( envelopeInfoPtr->actionList == NULL )
				envelopeInfoPtr->actionList = actionListItem;
			else
				{
				ACTION_LIST *actionListPtr = envelopeInfoPtr->actionList;

				/* Find the end of the list and append the new item */
				while( actionListPtr->next != NULL )
					actionListPtr = actionListPtr->next;
				actionListPtr->next = actionListItem;
				}
			if(	envelopeInfoPtr->hashActions == NULL )
				envelopeInfoPtr->hashActions = actionListItem;

			/* Remember where we are and move on to the next state if
			   necessary */
			if( envelopeInfoPtr->hdrSetLength != CRYPT_UNUSED )
				{
				envelopeInfoPtr->hdrSetLength -= sMemSize( &stream ) - streamPos;
				streamPos = sMemSize( &stream );
				if( envelopeInfoPtr->hdrSetLength <= 0 )
					state = DEENVSTATE_CONTENT;
				}
			else
				if( checkEOC( &stream ) )
					state = DEENVSTATE_CONTENT;
			}

		/* Read the encapsulated content header */
		if( state == DEENVSTATE_CONTENT )
			{
			status = readCMSheader( &stream, nestedContentOIDselection,
									&envelopeInfoPtr->payloadSize );
			if( cryptStatusError( status ) )
				break;
			envelopeInfoPtr->contentType = status;
			status = CRYPT_OK;

			/* If there's no content included, this is a detached signature
			   with the content supplied anderswhere */
			if( !envelopeInfoPtr->payloadSize )
				envelopeInfoPtr->detachedSig = TRUE;

			/* Remember where we are and move on to the next state */
			streamPos = sMemSize( &stream );
			state = ( envelopeInfoPtr->detachedSig ) ? \
					DEENVSTATE_DONE : DEENVSTATE_DATA;
			}

		/* Start the decryption process if necessary */
		if( state == DEENVSTATE_DATA )
			{
			int oldBufPos, bytesCopied;

			/* Remember where we are */
			streamPos = sMemSize( &stream );
			oldBufPos = envelopeInfoPtr->bufPos;

			/* What's left is data which requires special processing because
			   of segmenting and decryption and hashing requirements, so we
			   feed it in via a copyToDeenvelope() of the data in the buffer.
			   This is a rather ugly hack, but it works because we're moving
			   data backwards in the buffer so there shouldn't be any
			   problems for the rare instances where the data overlaps (in
			   the worst case we only consume two bytes, the tag and one-byte
			   length, but for any normal memcpy() which moves forwards
			   through memory this shouldn't be a problem.

			   Since we're in effect restarting from the payload data, we
			   reset everything which counts to point back to the start of
			   the buffer where we'll be moving the payload data.  We don't
			   have to worry about the copyToDeenvelope() overflowing the
			   envelope since the source is the envelope buffer so the data
			   must fit within the envelope */
			length = envelopeInfoPtr->bufPos - streamPos;
			envelopeInfoPtr->bufPos = 0;
			sMemDisconnect( &stream );
			sMemConnect( &stream, envelopeInfoPtr->buffer, length );
			bytesCopied = envelopeInfoPtr->copyToDeenvelope( envelopeInfoPtr,
							envelopeInfoPtr->buffer + streamPos, length );
			if( cryptStatusError( bytesCopied ) )
				{
				/* Undo the buffer position reset.  This isn't 100% effective
				   if there are multiple segments present and we hit an error
				   after we've copied down enough data to overwrite what's at
				   the start, but in most cases it allows us to undo the
				   copyToEnvelope() - if the data is corrupted we won't get
				   any further anyway */
				envelopeInfoPtr->bufPos = oldBufPos;
				status = bytesCopied;
				break;
				}

			/* If we've reached the end of the payload, remember where the
			   payload ends.  If there's anything which followed the payload,
			   we need to move it down to the end of the decoded payload
			   data, since copyToDeenvelope() stops copying as soon as it hits
			   the end-of-contents octets */
			if( envelopeInfoPtr->endOfContents && bytesCopied < length )
				{
				const int bytesToCopy = length - bytesCopied;

				memcpy( envelopeInfoPtr->buffer + envelopeInfoPtr->dataLeft,
						envelopeInfoPtr->buffer + bytesCopied + streamPos,
						bytesToCopy );
				envelopeInfoPtr->bufPos = envelopeInfoPtr->dataLeft + bytesToCopy;
				}

			/* Now that everything has been moved down, move back to the start
			   of the stream */
			streamPos = 0;

			/* We're done */
			state = DEENVSTATE_DONE;
			}
		}
	envelopeInfoPtr->deenvState = state;

	/* Consume the input we've processed so far by moving everything past the
	   current position down to the start of the memory buffer */
	length = envelopeInfoPtr->bufPos - streamPos;
	if( length > 0 && streamPos )
		memmove( envelopeInfoPtr->buffer, envelopeInfoPtr->buffer + streamPos,
				 length );
	envelopeInfoPtr->bufPos = length;

	/* If all went OK but we're still not out of the header information,
	   return an underflow error */
	if( cryptStatusOK( status ) && state != DEENVSTATE_DONE )
		status = CRYPT_UNDERFLOW;

	/* Clean up */
	sMemDisconnect( &stream );
	return( status );
	}

int processPostamble( ENVELOPE_INFO *envelopeInfoPtr )
	{
	DEENV_STATE state = envelopeInfoPtr->deenvState;
	STREAM stream;
	int length, streamPos = 0, status = CRYPT_OK;

	/* Start reading the trailer data from the end of the payload */
	sMemConnect( &stream, envelopeInfoPtr->buffer + envelopeInfoPtr->dataLeft,
				 envelopeInfoPtr->bufPos - envelopeInfoPtr->dataLeft );

	/* If we haven't started doing anything yet, figure out what we should be
	   looking for */
	if( state == DEENVSTATE_NONE )
		if( envelopeInfoPtr->usage == ACTION_SIGN )
			{
			DEENV_STATE newState;

			/* Read the SignedData EOC's if necessary */
			if( envelopeInfoPtr->payloadSize == CRYPT_UNUSED && \
				( sgetc( &stream ) || sgetc( &stream ) || \
				  sgetc( &stream ) || sgetc( &stream ) ) )
				{
				status = ( sGetStatus( &stream ) == CRYPT_OK ) ? \
						 CRYPT_BADDATA : sGetStatus( &stream );
				sMemDisconnect( &stream );
				return( status );
				}

			/* Check whether there's a cert chain to follow */
			status = peekTag( &stream );
			if( cryptStatusError( status ) )
				return( status );
			newState = ( status == MAKE_CTAG( 0 ) ) ? \
					   DEENVSTATE_CERTSET : DEENVSTATE_SET_SIG;

			/* If we've seen all the signed data, complete the hashing.  When
			   we reach this point when there may still be unhashed data left
			   in the buffer (it won't have been hashed yet because the
			   hashing is performed when the data is copied out, after
			   unwrapping and deblocking whatnot) so we hash it before we wrap
			   up the hashing */
			if( !envelopeInfoPtr->detachedSig )
				{
				if( envelopeInfoPtr->dataLeft )
					status = processExtraData( envelopeInfoPtr,
											   envelopeInfoPtr->buffer,
											   envelopeInfoPtr->dataLeft );
				if( !cryptStatusError( status ) )
					status = processExtraData( envelopeInfoPtr, "", 0 );
				if( cryptStatusError( status ) )
					{
					sMemDisconnect( &stream );
					return( status );
					}
				}

			/* Move on to the next state */
			streamPos = sMemSize( &stream );
			state = newState;
			}
		else
			/* Just look for EOC's if necessary */
			state = ( envelopeInfoPtr->payloadSize == CRYPT_UNUSED ) ? \
					DEENVSTATE_EOC : DEENVSTATE_DONE;

	/* Keep consuming information until we run out of input or read the end
	   of the data */
	while( state != DEENVSTATE_DONE )
		{
		/* Check that various values are within range.  They can go out of
		   range if the header is corrupted */
		if( envelopeInfoPtr->hdrSetLength < 0 && \
			envelopeInfoPtr->hdrSetLength != CRYPT_UNUSED )
			{
			status = CRYPT_BADDATA;
			break;
			}

		/* Read the cert chain */
		if( state == DEENVSTATE_CERTSET )
			{
			int length, endPos;

			/* Make sure the entire cert chain is present in the envelope */
			length = getObjectLength( sMemBufPtr( &stream ),
					( envelopeInfoPtr->bufPos - envelopeInfoPtr->dataLeft ) - \
					sMemSize( &stream ) );
			if( cryptStatusError( length ) )
				{
				status = length;
				break;
				}
			endPos = sMemSize( &stream ) + length;
			if( endPos > sMemTotalSize( &stream ) )
				{
				status = CRYPT_UNDERFLOW;
				break;
				}

			/* Import the cert chain.  Since this isn't a true cert chain (in
			   the sense of being degenerate PKCS #7 SignedData) but only a
			   context-tagged SET OF Certificate, we need to notify the cert
			   management code of this, which is done by temporarily changing
			   the tag to 0xFF.  If it sees this tag at the start of a cert
			   chain, it will reset it to the normal tag and import the chain
			   as a SET OF Certificate rather than a complete chain */
			sseek( &stream, streamPos );
			sputc( &stream, 0xFF );
			status = iCryptImportCert( sMemBufPtr( &stream ) - 1,
									   &envelopeInfoPtr->iCertChain, NULL );
			if( cryptStatusError( status ) )
				break;
			sseek( &stream, endPos );

			/* Remember where we are and move on to the next state */
			streamPos = endPos;
			state = DEENVSTATE_SET_SIG;
			}

		/* Read the start of the SET OF Signature */
		if( state == DEENVSTATE_SET_SIG )
			{
			/* Read the SET tag and length */
			status = readSet( &stream, &length );
			if( cryptStatusError( status ) )
				break;

			/* Remember where we are and move on to the next state.  Some
			   implementations use the indefinite-length encoding for this so
			   if there's no length given we have to look for the EOC after
			   each entry read */
			streamPos = sMemSize( &stream );
			envelopeInfoPtr->hdrSetLength = ( length ) ? length : CRYPT_UNUSED;
			state = DEENVSTATE_SIG;
			}

		/* Read and remember a signature object from a Signature record */
		if( state == DEENVSTATE_SIG )
			{
			/* Add the object to the content information list */
			status = addContentListItem( &stream, envelopeInfoPtr );
			if( cryptStatusError( status ) )
				break;

			/* Remember where we are and move on to the next state if
			   necessary */
			streamPos = sMemSize( &stream );
			if( envelopeInfoPtr->hdrSetLength != CRYPT_UNUSED )
				{
				envelopeInfoPtr->hdrSetLength -= status;
				if( envelopeInfoPtr->hdrSetLength <= 0 )
					state = ( envelopeInfoPtr->payloadSize == CRYPT_UNUSED ) ? \
							DEENVSTATE_EOC : DEENVSTATE_DONE;
				}
			else
				if( checkEOC( &stream ) )
					state = ( envelopeInfoPtr->payloadSize == CRYPT_UNUSED ) ? \
							DEENVSTATE_EOC : DEENVSTATE_DONE;
			}

		/* Handle end-of-contents octets */
		if( state == DEENVSTATE_EOC )
			{
			BYTE eocBuffer[ 8 ];
			const int eocLen = ( envelopeInfoPtr->usage == ACTION_SIGN ) ? \
							   6 : 8;

			status = sread( &stream, eocBuffer, eocLen );
			if( cryptStatusOK( status ) && \
				memcmp( eocBuffer, "\x00\x00\x00\x00\x00\x00\x00\x00", eocLen ) )
				status = CRYPT_BADDATA;
			if( cryptStatusError( status ) )
				break;

			/* We're done */
			streamPos = sMemSize( &stream );
			state = DEENVSTATE_DONE;
			break;
			}
		}
	envelopeInfoPtr->deenvState = state;

	/* Consume the input we've processed so far by moving everything past the
	   current position down to the start of the memory buffer */
	length = envelopeInfoPtr->bufPos - ( envelopeInfoPtr->dataLeft + streamPos );
	if( length && streamPos )
		memmove( envelopeInfoPtr->buffer + envelopeInfoPtr->dataLeft,
				 envelopeInfoPtr->buffer + envelopeInfoPtr->dataLeft + streamPos,
				 length );
	envelopeInfoPtr->bufPos = envelopeInfoPtr->dataLeft + length;

	/* Adjust the error state based on what's left in the envelope buffer.
	   If there's data still present, we don't report certain types of errors
	   because they don't affect the data, only the trailer */
	if( envelopeInfoPtr->dataLeft )
		{
		/* If we've got an underflow error but there's payload data left to
		   be copied out, convert the status to OK since the caller can still
		   continue before they need to copy in more data.  Since there's
		   more data left to process, we return OK_SPECIAL to tell the
		   calling function not to perform any cleanup */
		if( status == CRYPT_UNDERFLOW )
			status = OK_SPECIAL;
		}
	else
		/* If all went OK but we're still not out of the header information,
		   return an underflow error */
		if( cryptStatusOK( status ) && state != DEENVSTATE_DONE )
			status = CRYPT_UNDERFLOW;

	/* Clean up */
	sMemDisconnect( &stream );
	return( cryptStatusError( status ) ? status : CRYPT_OK );
	}
