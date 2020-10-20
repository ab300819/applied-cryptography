/****************************************************************************
*																			*
*					cryptlib Enveloping Information Management				*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

#include <assert.h>	/*!!!!*/
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "envelope.h"
#elif defined( INC_CHILD )
  #include "../envelope/envelope.h"
#else
  #include "envelope/envelope.h"
#endif /* Compiler-specific includes */

/* Prototypes for functions in pgp_misc.c */

int pgpPasswordToKey( CRYPT_CONTEXT cryptContext, const char *password,
					  const int passwordSize );

/****************************************************************************
*																			*
*					Functions for Action and Content Lists					*
*																			*
****************************************************************************/

/* Create a new action */

ACTION_LIST *createAction( const ACTION_TYPE actionType,
						   const CRYPT_HANDLE cryptHandle )
	{
	ACTION_LIST *actionListItem;

	/* Create the new action list item */
	if( ( actionListItem = malloc( sizeof( ACTION_LIST ) ) ) == NULL )
		return( NULL );
	memset( actionListItem, 0, sizeof( ACTION_LIST ) );
	actionListItem->action = actionType;
	actionListItem->iCryptHandle = cryptHandle;
	actionListItem->iExtraData = CRYPT_ERROR;

	return( actionListItem );
	}

/* Find the first action of a given type in an action list.  Since the lists
   are sorted by action type, this finds the start of a group of related
   actions */

ACTION_LIST *findAction( ACTION_LIST *actionListPtr,
						 const ACTION_TYPE actionType )
	{
	while( actionListPtr != NULL )
		{
		if( actionListPtr->action == actionType )
			return( actionListPtr );
		actionListPtr = actionListPtr->next;
		}

	return( NULL );
	}

/* Find the insertion point for a given action in an action list and at the
   same time check to make sure it isn't already present in the action group.
   If the actionType is negative we order the action in a direction which is
   the reverse of the normal order.  This is used for the main action list
   when deenveloping */

ACTION_RESULT findCheckLastAction( ACTION_LIST **actionListStart,
								   ACTION_LIST **actionListPtrPtr,
								   const ACTION_TYPE actionType,
								   const CRYPT_HANDLE cryptHandle )
	{
	ACTION_LIST *actionListPtr = *actionListStart;
	ACTION_LIST *actionListParent = ( ACTION_LIST * ) actionListStart;
	ACTION_TYPE action = ( actionType > 0 ) ? actionType : -actionType;
	BOOLEAN orderBackwards = ( actionType < 0 ) ? TRUE : FALSE;

	/* If the action list is empty, return a pointer to the list header
	   where we'll create a new list */
	if( actionListPtr == NULL )
		{
		*actionListPtrPtr = actionListParent;
		return( ACTION_RESULT_EMPTY );
		}

	/* Find the first action of this type */
	while( actionListPtr != NULL )
		{
		if( orderBackwards )
			{
			if( actionListPtr->action < action )
				break;
			}
		else
			if( actionListPtr->action >= action )
				break;

		actionListParent = actionListPtr;
		actionListPtr = actionListPtr->next;
		}

	/* Now walk down the list finding the last action in this action group */
	while( actionListPtr != NULL && actionListPtr->action == action )
		{
		/* Compare the two objects.  This will do the right thing, comparing
		   contexts to contexts and certs to certs.  If one object is a
		   context and the other is a cert, this will always report a
		   mismatch since, even if they contain the same key and would result
		   in the same encryption transformation on data, the ugly practice
		   of issuing multiple certs for a single key and/or reissuing certs
		   for an existing key means we can't be sure that a context and cert
		   with the same key represent the same thing */
		if( krnlSendMessage( cryptHandle, RESOURCE_IMESSAGE_COMPARE, NULL,
							 actionListPtr->iCryptHandle, CRYPT_ERROR ) == CRYPT_OK )
			{
			/* If the action was added automatically as the result of adding
			   another action then the first attempt to add it by the caller
			   isn't an error */
			if( actionListPtr->addedAutomatically )
				{
				actionListPtr->addedAutomatically = FALSE;
				return( ACTION_RESULT_PRESENT );
				}

			return( ACTION_RESULT_INITED );
			}
		actionListParent = actionListPtr;
		actionListPtr = actionListPtr->next;
		}

	*actionListPtrPtr = actionListParent;
	return( ACTION_RESULT_OK );
	}

/* Add an action to an action list */

int addAction( ACTION_LIST **actionListHeadPtrPtr,
			   ACTION_LIST **actionListPtr,
			   const ACTION_TYPE actionType,
			   const CRYPT_HANDLE cryptHandle )
	{
	ACTION_LIST *actionListItem;

	/* Create the new action */
	actionListItem = createAction( actionType, cryptHandle );
	if( actionListItem == NULL )
		return( CRYPT_NOMEM );

	/* Link it into the list if necessary.  We have to handle the first item
	   in the list specially since it's only a pointer to the list rather than
	   an actual list item.

	   A null actionListPtr is treated specially, this is only inserted to
	   mark a dummy action if there are no other actions present and will
	   therefore be the only action present */
	if( ( actionListPtr == NULL && *actionListHeadPtrPtr == NULL ) || \
		( ( ACTION_LIST * ) actionListHeadPtrPtr == *actionListPtr ) )
		{
		actionListItem->next = *actionListHeadPtrPtr;
		*actionListHeadPtrPtr = actionListItem;
		}
	else
		{
		assert( actionListPtr != NULL );
		if( ( *actionListPtr )->next != NULL )
			actionListItem->next = ( *actionListPtr )->next;
		( *actionListPtr )->next = actionListItem;
		}

	/* Set the action list pointer to the newly-added item */
	if( actionListPtr != NULL )
		*actionListPtr = actionListItem;

	return( CRYPT_OK );
	}

/* Delete an action list */

void deleteActionList( ACTION_LIST *actionListPtr )
	{
	while( actionListPtr != NULL )
		{
		ACTION_LIST *actionListItem = actionListPtr;

		/* Destroy any attached objects if necessary and clear the list item
		   memory */
		actionListPtr = actionListPtr->next;
		if( actionListItem->iCryptHandle != CRYPT_ERROR )
			krnlSendNotifier( actionListItem->iCryptHandle,
							  RESOURCE_IMESSAGE_DECREFCOUNT );
		if( actionListItem->iExtraData != CRYPT_ERROR )
			krnlSendNotifier( actionListItem->iExtraData,
							  RESOURCE_IMESSAGE_DECREFCOUNT );
		zeroise( actionListItem, sizeof( ACTION_LIST ) );
		free( actionListItem );
		}
	}

/* Create a content list item */

CONTENT_LIST *createContentListItem( const CRYPT_FORMAT_TYPE formatType,
									 const void *object, const int objectSize )
	{
	CONTENT_LIST *contentListItem;

	if( ( contentListItem = malloc( sizeof( CONTENT_LIST ) ) ) == NULL )
		return( NULL );
	memset( contentListItem, 0, sizeof( CONTENT_LIST ) );
	contentListItem->formatType = formatType;
	contentListItem->object = ( void * ) object;
	contentListItem->objectSize = objectSize;
	contentListItem->iSigCheckKey = CRYPT_ERROR;
	contentListItem->iExtraData = CRYPT_ERROR;

	return( contentListItem );
	}

#if 0

/* Delete an item from a content list */

void deleteContentListItem( CONTENT_LIST **contentListHead,
							CONTENT_LIST *contentListItem )
	{
	CONTENT_LIST *contentListNext = contentListItem->next;
	CONTENT_LIST *contentListPrev = *contentListHead;

	/* Find the previous item in the list */
	if( contentListPrev != contentListItem )
		while( contentListPrev != NULL && \
			   contentListPrev->next != contentListItem )
			contentListPrev = contentListPrev->next;
	assert( contentListPrev != NULL );

	/* Destroy any attached objects if necessary */
	if( contentListItem->iSigCheckKey != CRYPT_ERROR )
		krnlSendNotifier( contentListItem->iSigCheckKey,
						  RESOURCE_IMESSAGE_DECREFCOUNT );
	if( contentListItem->iExtraData != CRYPT_ERROR )
		krnlSendNotifier( contentListItem->iExtraData,
						  RESOURCE_IMESSAGE_DECREFCOUNT );

	/* Erase and free the object buffer if necessary */
	if( contentListItem->object != NULL )
		{
		zeroise( contentListItem->object, contentListItem->objectSize );
		free( contentListItem->object );
		}

	/* Erase and free the list item */
	zeroise( contentListItem, sizeof( CONTENT_LIST ) );
	free( contentListItem );

	/* Remove the item from the list */
	if( *contentListHead == contentListItem )
		*contentListHead = contentListNext;
	else
		contentListPrev->next = contentListNext;
	}
#endif /* 0 */

/* Delete a content list */

void deleteContentList( CONTENT_LIST *contentListPtr )
	{
	while( contentListPtr != NULL )
		{
		CONTENT_LIST *contentListItem = contentListPtr;

		/* Destroy any attached objects if necessary */
		if( contentListItem->iSigCheckKey != CRYPT_ERROR )
			krnlSendNotifier( contentListItem->iSigCheckKey,
							  RESOURCE_IMESSAGE_DECREFCOUNT );
		if( contentListItem->iExtraData != CRYPT_ERROR )
			krnlSendNotifier( contentListItem->iExtraData,
							  RESOURCE_IMESSAGE_DECREFCOUNT );

		/* Erase and free the object buffer if necessary */
		contentListPtr = contentListPtr->next;
		if( contentListItem->object != NULL )
			{
			zeroise( contentListItem->object, contentListItem->objectSize );
			free( contentListItem->object );
			}
		zeroise( contentListItem, sizeof( CONTENT_LIST ) );
		free( contentListItem );
		}
	}

/****************************************************************************
*																			*
*						Misc.Enveloping Info Management Functions			*
*																			*
****************************************************************************/

/* Set up the encryption for an envelope */

int initEnvelopeEncryption( ENVELOPE_INFO *envelopeInfoPtr,
							const CRYPT_CONTEXT cryptContext,
							const CRYPT_ALGO algorithm, const CRYPT_MODE mode,
							const BYTE *iv, const int ivLength,
							const BOOLEAN copyContext )
	{
	CRYPT_CONTEXT iCryptContext = cryptContext;
	ICRYPT_QUERY_INFO iCryptQueryInfo;
	int blockSize, maxIVsize, status;

	/* Make sure the context is what's required */
	status = iCryptQueryContext( cryptContext, &iCryptQueryInfo );
	if( cryptStatusError( status ) )
		return( status );
	if( algorithm != CRYPT_UNUSED &&
		( iCryptQueryInfo.cryptAlgo != algorithm || \
		  iCryptQueryInfo.cryptMode != mode ) )
		/* This can only happen on deenveloping if the data is corrupted or
		   if the user is asked for a KEK and tries to supply a session key
		   instead */
		status = CRYPT_WRONGKEY;
	blockSize = iCryptQueryInfo.blockSize;
	maxIVsize = iCryptQueryInfo.maxIVsize;
	memset( &iCryptQueryInfo, 0, sizeof( ICRYPT_QUERY_INFO ) );
	if( cryptStatusError( status ) )
		return( status );

	/* If it's a user-supplied context, take a copy for our own use */
	if( copyContext )
		{
		status = krnlSendMessage( cryptContext, RESOURCE_MESSAGE_CLONE,
								  &iCryptContext, FALSE, 0 );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Load the IV into the context and set up the encryption information for
	   the envelope */
	status = iCryptLoadIV( iCryptContext, iv, min( ivLength, maxIVsize ) );
	if( cryptStatusOK( status ) )
		{
		envelopeInfoPtr->iCryptContext = iCryptContext;
		envelopeInfoPtr->blockSize = blockSize;
		envelopeInfoPtr->blockSizeMask = ~( blockSize - 1 );
		}
	else
		/* If there was a problem and we copied the context, destroy the copy */
		if( iCryptContext != cryptContext )
			iCryptDestroyObject( iCryptContext );

	return( CRYPT_OK );
	}

/* Add keyset information */

static int addKeyset( ENVELOPE_INFO *envelopeInfoPtr,
					  const CRYPT_ENVINFO_TYPE keysetFunction,
					  const CRYPT_KEYSET keyset, const BOOLEAN isInternal )
	{
	CRYPT_KEYSET *iKeysetPtr;

	/* Figure out which keyset we want to set */
	switch( keysetFunction )
		{
		case CRYPT_ENVINFO_KEYSET_ENCRYPT:
			iKeysetPtr = &envelopeInfoPtr->iEncryptionKeyset;
			break;

		case CRYPT_ENVINFO_KEYSET_DECRYPT:
			iKeysetPtr = &envelopeInfoPtr->iDecryptionKeyset;
			break;

		case CRYPT_ENVINFO_KEYSET_SIGCHECK:
			iKeysetPtr = &envelopeInfoPtr->iSigCheckKeyset;
			break;

		default:
			/* Internal error, should never happen */
			return( CRYPT_ERROR );
			}

	/* Make sure the keyset isn't already set */
	if( *iKeysetPtr != CRYPT_ERROR )
		return( CRYPT_INITED );

	/* Remember the new keyset and increment its reference count if it's a
	   keyset supplied by the user */
	*iKeysetPtr = keyset;
	if( !isInternal )
		return( krnlSendNotifier( keyset, RESOURCE_MESSAGE_INCREFCOUNT ) );
	return( CRYPT_OK );
	}

/* Add the default keyset for a particular operation */

int addDefaultKeyset( ENVELOPE_INFO *envelopeInfoPtr,
					  const CRYPT_ENVINFO_TYPE keysetFunction )
	{
	CRYPT_KEYSET iKeyset;
	CRYPT_KEYSET_TYPE keysetType;
	CRYPT_OPTION_TYPE configOption;
	RESOURCE_MESSAGE_CHECK_TYPE checkType;
	char *keysetName;
	int status;

	/* Figure out which set of options we need to handle */
	switch( keysetFunction )
		{
		case CRYPT_ENVINFO_KEYSET_ENCRYPT:
			configOption = CRYPT_OPTION_KEYS_PUBLIC;

			checkType = RESOURCE_MESSAGE_CHECK_PKC_ENCRYPT;
			break;

		case CRYPT_ENVINFO_KEYSET_DECRYPT:
			configOption = CRYPT_OPTION_KEYS_PRIVATE;
			checkType = RESOURCE_MESSAGE_CHECK_PKC_DECRYPT;
			break;

		case CRYPT_ENVINFO_KEYSET_SIGCHECK:
			configOption = CRYPT_OPTION_KEYS_SIGCHECK;
			checkType = RESOURCE_MESSAGE_CHECK_PKC_SIGCHECK;
			break;

		default:
			/* Internal error, should never happen */
			return( CRYPT_ERROR );
		}

	/* Map the keyset type we require to the name of the keyset */
	keysetType = getOptionNumeric( configOption );
	keysetName = mapOLEName( configOption );
	if( keysetName == NULL )
		return( CRYPT_DATA_OPEN );	/* Can't open a keyset */

	/* Finally, open the keyset as an internal object, check that it's of the
	   correct type, and remember it for later */
	status = iCryptKeysetOpen( &iKeyset, keysetType, keysetName );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( iKeyset, RESOURCE_IMESSAGE_CHECK, NULL,
							  checkType, CRYPT_ERROR );
	if( cryptStatusOK( status ) )
		status = addKeyset( envelopeInfoPtr, keysetFunction, iKeyset, TRUE );
	if( cryptStatusError( status ) )
		iCryptDestroyObject( iKeyset );
	return( status );
	}

/****************************************************************************
*																			*
*					Deenveloping Information Management Functions			*
*																			*
****************************************************************************/

/* Add de-enveloping information to an envelope */

int addDeenvelopeInfo( ENVELOPE_INFO *envelopeInfoPtr,
					   const CRYPT_ENVINFO_TYPE envInfo, const void *value,
					   const int valueLength )
	{
	CONTENT_LIST *contentListPtr = envelopeInfoPtr->contentListCurrent;
	CRYPT_HANDLE cryptHandle = *( ( CRYPT_HANDLE * ) value ), iNewContext;
	ACTION_LIST *actionListPtr;
	ACTION_RESULT actionResult;
	int status;

	/* We can't add datasize, compression or hashing information when
	   deenveloping (in theory we can, but it doesn't make much sense) */
	if( envInfo == CRYPT_ENVINFO_DATASIZE || \
		envInfo == CRYPT_ENVINFO_COMPRESSION || \
		envInfo == CRYPT_ENVINFO_HASH )
		return( CRYPT_BADPARM2 );

	/* If it's keyset information, just keep a record of it for later use */
	if( envInfo == CRYPT_ENVINFO_KEYSET_SIGCHECK || \
		envInfo == CRYPT_ENVINFO_KEYSET_ENCRYPT || \
		envInfo == CRYPT_ENVINFO_KEYSET_DECRYPT )
		return( addKeyset( envelopeInfoPtr, envInfo, cryptHandle, FALSE ) );

	/* Since we can add one of a multitude of necessary information types, we
	   need to check to make sure what we're adding is appropriate.  If the
	   user has called cryptGetFirst/NextResource() we make sure that what
	   they're adding matches the current information object.  If they
	   haven't called it, we try and match it to the first information object
	   of the correct type */
	if( contentListPtr == NULL )
		{
		contentListPtr = envelopeInfoPtr->contentList;

		/* Look for the first information object matching the supplied
		   information */
		while( contentListPtr != NULL && contentListPtr->envInfo != envInfo )
			contentListPtr = contentListPtr->next;
		if( contentListPtr == NULL )
			return( CRYPT_BADPARM2 );
		}

	/* Make sure the information we're adding matches the currently required
	   information object.  Since PGP doesn't follow the usual model of
	   encrypting a session key with a user key and then encrypting the data
	   with the session key but instead encrypts the data directly with the
	   raw key, we treat a session key, password, and encryption key
	   information as being the same thing.  In all cases the envelope
	   management code will do the right thing and turn it into the session
	   key information needed to decrypt the data.

	   For general information we can be passed password information when we
	   require a private key if the private key is encrypted, so we allow an
	   exception for this type */
	if( contentListPtr->envInfo == CRYPT_ENVINFO_SESSIONKEY && \
		envelopeInfoPtr->type == CRYPT_FORMAT_PGP )
		{
		if( envInfo != CRYPT_ENVINFO_SESSIONKEY && \
			envInfo != CRYPT_ENVINFO_KEY && \
			envInfo != CRYPT_ENVINFO_PASSWORD )
			return( CRYPT_BADPARM2 );
		}
	else
		if( contentListPtr->envInfo != envInfo && \
			!( contentListPtr->envInfo == CRYPT_ENVINFO_PRIVATEKEY && \
			   envInfo == CRYPT_ENVINFO_PASSWORD ) )
			return( CRYPT_BADPARM2 );

	/* If it's a signature object, check the signature and exit.  Anything
	   left after this point is a keying object */
	if( envInfo == CRYPT_ENVINFO_SIGNATURE )
		{
		BOOLEAN signalled = FALSE;

		/* If we've already processed this entry, return the saved processing
		   result */
		if( contentListPtr->processed )
			return( contentListPtr->processingResult );

		/* Find the hash action we need to check this signature.  Note that
		   we can't use the hashActions pointer for direct access since the
		   hashing will have been completed by now and the pointer will be
		   null */
		for( actionListPtr = findAction( envelopeInfoPtr->actionList, ACTION_HASH );
			 actionListPtr != NULL && actionListPtr->action == ACTION_HASH;
			 actionListPtr = actionListPtr->next )
			{
			ICRYPT_QUERY_INFO iCryptQueryInfo;

			/* Check to see if it's the one we want */
			status = iCryptQueryContext( actionListPtr->iCryptHandle,
										 &iCryptQueryInfo );
			if( status == CRYPT_SIGNALLED )
				signalled = TRUE;
			else
				if( iCryptQueryInfo.cryptAlgo == contentListPtr->hashAlgo )
					break;
			}

		/* If we can't find a hash action to match this signature, return a
		   bad signature error since something must have altered the
		   algorithm ID for the hash.  However if a hash context is in the
		   signalled state, the reason that we couldn't find a match was more
		   likely because the signalled context is the missing one, so we
		   return a signalled error instead */
		if( actionListPtr == NULL || actionListPtr->action != ACTION_HASH )
			{
			contentListPtr->processed = TRUE;
			contentListPtr->processingResult = ( signalled ) ? \
											   CRYPT_SIGNALLED : CRYPT_BADSIG;
			return( contentListPtr->processingResult );
			}

		/* Check the signature */
		if( contentListPtr->formatType == CRYPT_FORMAT_CMS )
			{
			int value;

			status = iCryptCheckSignatureEx( contentListPtr->object,
											 envelopeInfoPtr->iCertChain,
											 actionListPtr->iCryptHandle,
											 &contentListPtr->iExtraData );

			/* If there are authenticated attributes present we have to
			   perform an extra check here to make sure the content-type
			   specified in the authenticated attributes matches the actual
			   data content type */
			if( cryptStatusOK( status ) && \
				contentListPtr->iExtraData != CRYPT_ERROR )
				{
				status = iCryptGetCertComponent( contentListPtr->iExtraData,
							CRYPT_CERTINFO_CMS_CONTENTTYPE, &value, NULL );
				if( status == CRYPT_DATA_NOTFOUND || \
					envelopeInfoPtr->contentType != value )
					status = CRYPT_BADSIG;
				}
			}
		else
			{
			status = iCryptCheckSignatureEx( contentListPtr->object,
							cryptHandle, actionListPtr->iCryptHandle, NULL );

			/* Remember the key which was used to check the signature in case
			   the user wants to query it later */
			krnlSendNotifier( cryptHandle, RESOURCE_IMESSAGE_INCREFCOUNT );
			contentListPtr->iSigCheckKey = cryptHandle;
			}

		/* Remember the processing result so we don't have to repeat the
		   processing if queried again.  Since we don't need the encoded
		   signature data any more after this point, we free it to make the
		   memory available for reuse */
		free( contentListPtr->object );
		contentListPtr->object = NULL;
		contentListPtr->objectSize = 0;
		contentListPtr->processed = TRUE;
		contentListPtr->processingResult = status;
		return( status );
		}

	/* If we need private key information and we've been given a password,
	   it's the password required to decrypt the key so we treat this
	   specially */
	if( contentListPtr->envInfo == CRYPT_ENVINFO_PRIVATEKEY && \
		envInfo == CRYPT_ENVINFO_PASSWORD )
		{
		CRYPT_CONTEXT iCryptContext;

		/* Make sure there's a keyset available to pull the key from */
		if( envelopeInfoPtr->iDecryptionKeyset == CRYPT_ERROR && \
			cryptStatusError( addDefaultKeyset( envelopeInfoPtr,
							  CRYPT_ENVINFO_KEYSET_DECRYPT ) ) )
			return( CRYPT_ENVELOPE_RESOURCE );

		/* Try and get the key information */
		status = getKeyFromID( envelopeInfoPtr->iDecryptionKeyset,
							   &iCryptContext, contentListPtr->keyID,
							   value, NULL );

		/* If we managed to get the private key (it wasn't protected by a
		   password), push it into the envelope.  If the call succeeds, this
		   will import the session key and delete the required information
		   list */
		if( status == CRYPT_OK )
			{
			status = addDeenvelopeInfo( envelopeInfoPtr,
										CRYPT_ENVINFO_PRIVATEKEY,
										&iCryptContext, 0 );
			iCryptDestroyObject( iCryptContext );
			}

		return( status );
		}

	/* If we've been given a password, create the appropriate encryption
	   context for it and derive the key from the password */
	if( envInfo == CRYPT_ENVINFO_PASSWORD )
		{
		CRYPT_CONTEXT iCryptContext;

		/* Create the appropriate encryption context.  This doesn't need to
		   call iCryptCreateContextEx() since there's no way to specify non-
		   default parameters when encrypting data */
		status = iCryptCreateContext( &iCryptContext,
					contentListPtr->cryptAlgo, contentListPtr->cryptMode );
		if( cryptStatusError( status ) )
			return( status );

		/* Derive the key into it */
		if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP )
			status = pgpPasswordToKey( iCryptContext, value, valueLength );
		else
			status = iCryptDeriveKey( iCryptContext, value, valueLength );
		if( cryptStatusError( status ) )
			{
			iCryptDestroyObject( iCryptContext );
			return( status );
			}

		/* Recover the session key using the password context */
		if( envelopeInfoPtr->type != CRYPT_FORMAT_PGP )
			{
			status = iCryptImportKeyEx( contentListPtr->object, iCryptContext,
										&iNewContext );
			iCryptDestroyObject( iCryptContext );
			}
		else
			/* In PGP there isn't any encrypted session key, so the context
			   created from the password becomes the bulk encryption
			   context */
			iNewContext = iCryptContext;

		if( cryptStatusError( status ) )
			return( status );
		}

	/* If we've been given private key information, recreate the session key
	   by importing it using the private key */
	if( envInfo == CRYPT_ENVINFO_PRIVATEKEY )
		{
		/* If this is CMS enveloped data, we won't have session key
		   information present in the encrypted key so we need to make sure
		   it's available elsewhere */
		if( contentListPtr->formatType == CRYPT_FORMAT_CMS )
			{
			CONTENT_LIST *sessionKeyPtr;

			for( sessionKeyPtr = envelopeInfoPtr->contentList;
				 sessionKeyPtr != NULL && \
					sessionKeyPtr->envInfo != CRYPT_ENVINFO_SESSIONKEY;
				 sessionKeyPtr = sessionKeyPtr->next );
			if( sessionKeyPtr == NULL )
				/* We need to read more data before we can recreate the
				   session key */
				return( CRYPT_UNDERFLOW );

			/* Create the session key context */
			status = iCryptCreateContext( &iNewContext,
						sessionKeyPtr->cryptAlgo, sessionKeyPtr->cryptMode );
			if( cryptStatusError( status ) )
				return( status );
			}

		/* Import the encrypted session key */
		status = iCryptImportKeyEx( contentListPtr->object, cryptHandle,
									&iNewContext );
		if( cryptStatusError( status ) )
			{
			if( contentListPtr->formatType == CRYPT_FORMAT_CMS )
				iCryptDestroyObject( iNewContext );
			return( status );
			}
		}

	/* If we've been given keying information, import the session key with
	   it */
	if( envInfo == CRYPT_ENVINFO_KEY )
		{
		if( envelopeInfoPtr->type != CRYPT_FORMAT_PGP )
			/* Recreate the session key by importing the encrypted key */
			status = iCryptImportKeyEx( contentListPtr->object, cryptHandle,
										&iNewContext );
		else
			{
			CRYPT_CONTEXT iCryptContext;

			/* In PGP there isn't any encrypted session key, so we take a
			   copy of the context we've been passed to use as the bulk
			   encryption context */
			status = krnlSendMessage( cryptHandle, RESOURCE_MESSAGE_GETDATA,
							&iCryptContext, RESOURCE_MESSAGE_DATA_CONTEXT,
							CRYPT_BADPARM3 );
			if( cryptStatusOK( status ) )
				status = krnlSendMessage( iCryptContext, RESOURCE_IMESSAGE_CLONE,
										  &iNewContext, FALSE, CRYPT_BADPARM3 );
			}
		if( cryptStatusError( status ) )
			return( status );
		}

	/* At this point we have the session key, either by recovering it from a
	   key exchange action or by having it passed to us directly.  If we've
	   been given it directly then we must have reached the encryptedContent
	   so we take a copy and set up the decryption with it */
	if( envInfo == CRYPT_ENVINFO_SESSIONKEY )
		{
		status = initEnvelopeEncryption( envelopeInfoPtr, cryptHandle,
					contentListPtr->cryptAlgo, contentListPtr->cryptMode,
					contentListPtr->iv, contentListPtr->ivSize, TRUE );
		if( cryptStatusError( status ) )
			return( status );

		/* The session key context is the newly-created internal one */
		iNewContext = envelopeInfoPtr->iCryptContext;
		}
	else
		/* We've recovered the session key from a key exchange action.  If we
		   got as far as the encryptedContent (so there's content info
		   present), we set up the decryption.  If we didn't get this far,
		   it'll be set up by the deenveloping code when we reach it */
		{
		for( contentListPtr = envelopeInfoPtr->contentList;
			 contentListPtr != NULL && \
				contentListPtr->envInfo != CRYPT_ENVINFO_SESSIONKEY;
			 contentListPtr = contentListPtr->next );
		if( contentListPtr != NULL )
			{
			/* We got to the encryptedContent, set up the decryption */
			status = initEnvelopeEncryption( envelopeInfoPtr, iNewContext,
						contentListPtr->cryptAlgo, contentListPtr->cryptMode,
						contentListPtr->iv, contentListPtr->ivSize, FALSE );
			if( cryptStatusError( status ) )
				return( status );
			}
		}

	/* Add the recovered session encryption action to the action list */
	actionResult = findCheckLastAction( &envelopeInfoPtr->actionList,
								&actionListPtr, -ACTION_CRYPT, iNewContext );
	if( actionResult == ACTION_RESULT_INITED )
		return( CRYPT_INITED );
	status = addAction( &envelopeInfoPtr->actionList, &actionListPtr,
						ACTION_CRYPT, iNewContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Destroy the required information list, which at this point will
	   contain only (now-irrelevant) key exchange items */
	deleteContentList( envelopeInfoPtr->contentList );
	envelopeInfoPtr->contentList = envelopeInfoPtr->contentListCurrent = NULL;

	/* If the only error was an information required error, we've now
	   resolved the problem and can continue */
	if( envelopeInfoPtr->errorState == CRYPT_ENVELOPE_RESOURCE )
		envelopeInfoPtr->errorState = CRYPT_OK;

	return( status );
	}

/****************************************************************************
*																			*
*					Enveloping Information Management Functions				*
*																			*
****************************************************************************/

/* Check that an object being added is suitable for PGP use */

static int checkPGPusage( const CRYPT_HANDLE cryptHandle,
						  const ENVELOPE_INFO *envelopeInfoPtr,
						  const CRYPT_ENVINFO_TYPE envInfo )
	{
	ICRYPT_QUERY_INFO iCryptQueryInfo;
	int type, status;

	/* Make sure it's an encryption context and query its properties */
	status = krnlSendMessage( cryptHandle, RESOURCE_MESSAGE_GETPROPERTY,
							  &type, RESOURCE_MESSAGE_PROPERTY_TYPE,
							  CRYPT_BADPARM1 );
	if( cryptStatusError( status ) )
		return( status );
	if( type != RESOURCE_TYPE_CRYPT )
		return( CRYPT_BADPARM1 );
	status = iCryptQueryContext( cryptHandle, &iCryptQueryInfo );
	if( cryptStatusError( status ) )
		return( status );

	if( ( envInfo == CRYPT_ENVINFO_PUBLICKEY || \
		  envInfo == CRYPT_ENVINFO_PRIVATEKEY || \
		  envInfo == CRYPT_ENVINFO_SIGNATURE ) && \
		iCryptQueryInfo.cryptAlgo != CRYPT_ALGO_RSA )
		/* PGP only supports RSA encryption and signatures */
		return( CRYPT_BADPARM1 );
	if( envInfo == CRYPT_ENVINFO_KEY )
		{
		/* PGP only supports IDEA/CFB encryption, and only a single instance
		   of this */
		if( iCryptQueryInfo.cryptAlgo != CRYPT_ALGO_IDEA || \
			iCryptQueryInfo.cryptMode != CRYPT_MODE_CFB )
			return( CRYPT_BADPARM1 );
		if( findAction( envelopeInfoPtr->preActionList,
						ACTION_KEYEXCHANGE_PKC ) || \
			findAction( envelopeInfoPtr->actionList,
						ACTION_CRYPT ) )
			return( CRYPT_INITED );
		}
	if( envInfo == CRYPT_ENVINFO_SESSIONKEY )
		{
		/* PGP only supports IDEA/CFB encryption, and only a single instance
		   of this */
		if( iCryptQueryInfo.cryptAlgo != CRYPT_ALGO_IDEA || \
			iCryptQueryInfo.cryptMode != CRYPT_MODE_CFB )
			return( CRYPT_BADPARM1 );
		if( findAction( envelopeInfoPtr->preActionList,
						ACTION_KEYEXCHANGE_PKC ) || \
			findAction( envelopeInfoPtr->actionList,
						ACTION_CRYPT ) )
			return( CRYPT_INITED );
		}
	if( envInfo == CRYPT_ENVINFO_HASH )
		{
		/* PGP only supports MD5 hashing, and only a single instance of
		   this */
		if( iCryptQueryInfo.cryptAlgo != CRYPT_ALGO_MD5 )
			return( CRYPT_BADPARM1 );
		if( findAction( envelopeInfoPtr->actionList, ACTION_HASH ) )
			return( CRYPT_INITED );
		}

	return( CRYPT_OK );
	}

/* Add enveloping information to an envelope */

int addEnvelopeInfo( ENVELOPE_INFO *envelopeInfoPtr,
					 const CRYPT_ENVINFO_TYPE envInfo, const void *value,
					 const int valueLength )
	{
	CRYPT_HANDLE cryptHandle = *( CRYPT_HANDLE * ) value;
	CRYPT_CONTEXT iNewContext;
	ACTION_LIST *actionListPtr, **actionListPtrPtr, *hashActionPtr;
	ACTION_RESULT actionResult;
	ACTION_TYPE actionType;
	int type, status;

	/* If it's meta-information, remember the value */
	if( envInfo == CRYPT_ENVINFO_DATASIZE )
		{
		envelopeInfoPtr->payloadSize = *( int * ) value;
		return( CRYPT_OK );
		}
	if( envInfo == CRYPT_ENVINFO_CONTENTTYPE )
		{
		envelopeInfoPtr->contentType = *( int * ) value;
		return( CRYPT_OK );
		}
	if( envInfo == CRYPT_ENVINFO_DETACHEDSIGNATURE )
		{
		/* Turn a generic zero/nonzero boolean into TRUE or FALSE */
		envelopeInfoPtr->detachedSig = ( *( int * ) value ) ? TRUE : FALSE;
		return( CRYPT_OK );
		}

	/* If it's keyset information, just keep a record of it for later use */
	if( envInfo == CRYPT_ENVINFO_KEYSET_SIGCHECK || \
		envInfo == CRYPT_ENVINFO_KEYSET_ENCRYPT || \
		envInfo == CRYPT_ENVINFO_KEYSET_DECRYPT )
		return( addKeyset( envelopeInfoPtr, envInfo, cryptHandle, FALSE ) );

	/* If it's extra data for the signature, record it with the signature
	   action */
	if( envInfo == CRYPT_ENVINFO_SIGNATURE_EXTRADATA )
		{
		/* Find the last signature action added and make sure it doesn't
		   already have extra data attached to it */
		actionListPtr = findAction( envelopeInfoPtr->postActionList,
									ACTION_SIGN );
		if( actionListPtr == NULL )
			return( CRYPT_NOTINITED );
		while( actionListPtr->next != NULL && \
			   actionListPtr->next->action == ACTION_SIGN )
			actionListPtr = actionListPtr->next;
		if( actionListPtr->iExtraData != CRYPT_ERROR )
			return( CRYPT_INITED );

		/* Increment its reference count and add it to the action */
		status = krnlSendNotifier( cryptHandle, RESOURCE_MESSAGE_INCREFCOUNT );
		if( cryptStatusOK( status ) )
			actionListPtr->iExtraData = cryptHandle;
		return( status );
		}

	/* If it's compression information, set up the compression structures */
	if( envInfo == CRYPT_ENVINFO_COMPRESSION )
		{
		/* Initialize the compression */
		if( envelopeInfoPtr->type == CRYPT_FORMAT_CRYPTLIB )
			status = deflateInit( &envelopeInfoPtr->zStream, Z_DEFAULT_COMPRESSION );
		else
			/* PGP has a funny compression level based on DOS memory limits
			   (13-bit windows) and no zlib header (because it uses old
			   InfoZIP code).  Setting the windowSize to a negative value has
			   the undocumented result of not emitting zlib headers */
			status = deflateInit2( &envelopeInfoPtr->zStream, Z_DEFAULT_COMPRESSION,
								   Z_DEFLATED, -13, 8, Z_DEFAULT_STRATEGY );
		if( status != Z_OK )
			return( CRYPT_NOMEM );
		envelopeInfoPtr->zStreamInited = TRUE;

		/* Add a compression action to the action list */
		findCheckLastAction( &envelopeInfoPtr->actionList, &actionListPtr,
							 ACTION_COMPRESS, CRYPT_ERROR );
		status = addAction( &envelopeInfoPtr->actionList, &actionListPtr,
							ACTION_COMPRESS, CRYPT_ERROR );
		return( status );
		}

	/* If it's a password, derive a session key encryption context from it */
	if( envInfo == CRYPT_ENVINFO_PASSWORD )
		{
		/* PGP doesn't support multiple key exchange/conventional encryption
		   actions.  We don't need to check for an ACTION_KEYEXCHANGE
		   because an action of this type can never be added to a PGP
		   envelope */
		if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP && \
			( findAction( envelopeInfoPtr->preActionList,
						  ACTION_KEYEXCHANGE_PKC ) || \
			  findAction( envelopeInfoPtr->actionList,
						  ACTION_CRYPT ) ) )
			return( CRYPT_INITED );

		/* Create the appropriate encryption context */
		status = iCryptCreateContext( &iNewContext,
									  envelopeInfoPtr->defaultAlgo,
									  envelopeInfoPtr->defaultMode );
		if( cryptStatusError( status ) )
			return( status );

		/* Derive the key into the context and add it to the action list */
		if( envelopeInfoPtr->type != CRYPT_FORMAT_PGP )
			{
			status = iCryptDeriveKey( iNewContext, value, valueLength );
			if( cryptStatusOK( status ) )
				{
				/* Find the insertion point in the list and make sure this
				   action isn't already present */
				actionResult = findCheckLastAction( &envelopeInfoPtr->preActionList,
								&actionListPtr, ACTION_KEYEXCHANGE, iNewContext );
				if( actionResult == ACTION_RESULT_INITED )
					status = CRYPT_INITED;

				/* Insert the new key exchange action into the list */
				if( cryptStatusOK( status ) )
					status = addAction( &envelopeInfoPtr->preActionList,
										&actionListPtr, ACTION_KEYEXCHANGE,
										iNewContext );
				}
			}
		else
			{
			/* If it's a PGP envelope, derive the key into the context and
			   add it to the action list.  Note that we add it to the main
			   action list as a general encryption action rather than a pre-
			   action-list key exchange action since PGP doesn't use
			   encrypted session keys */
			status = pgpPasswordToKey( iNewContext, value, valueLength );
			if( cryptStatusOK( status ) )
				{
				findCheckLastAction( &envelopeInfoPtr->actionList,
									 &actionListPtr, ACTION_CRYPT,
									 CRYPT_ERROR );
				status = addAction( &envelopeInfoPtr->actionList,
									&actionListPtr, ACTION_CRYPT,
									iNewContext );
				}
			}
		if( cryptStatusError( status ) )
			iCryptDestroyObject( iNewContext );
		return( status );
		}

	/* It's a generic "add a context" action (ie one involving a signature
	   key, a PKC key, a conventional key, or a hash), check everything is
	   valid.  Since PGP only supports a very limited subset of cryptlibs
	   capabilities, we have to be extra careful in checking to make sure the
	   object we've been passed is allowed with PGP */
	if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP )
		{
		status = checkPGPusage( cryptHandle, envelopeInfoPtr, envInfo );
		if( cryptStatusError( status ) )
			return( ( status == CRYPT_BADPARM1 ) ? CRYPT_BADPARM3 : status );
		}
	if( envInfo == CRYPT_ENVINFO_PUBLICKEY || \
		envInfo == CRYPT_ENVINFO_PRIVATEKEY )
		{
		actionListPtrPtr = &envelopeInfoPtr->preActionList;
		actionType = ACTION_KEYEXCHANGE_PKC;
		}
	if( envInfo == CRYPT_ENVINFO_KEY )
		{
		/* Normally we add a key exchange action, however PGP doesn't support
		   this type of action so we add a general encryption action
		   instead */
		if( envelopeInfoPtr->type != CRYPT_FORMAT_PGP )
			{
			actionListPtrPtr = &envelopeInfoPtr->preActionList;
			actionType = ACTION_KEYEXCHANGE;
			}
		else
			{
			if( findAction( envelopeInfoPtr->actionList, ACTION_CRYPT ) != NULL )
				/* We can't add more than one general encryption action */
				return( CRYPT_INITED );
			actionListPtrPtr = &envelopeInfoPtr->actionList;
			actionType = ACTION_CRYPT;
			}
		}
	if( envInfo == CRYPT_ENVINFO_SESSIONKEY )
		{
		/* We can't add more than one session key (in theory we could allow
		   this as it implies multiple layers of encryption, but in practice
		   we force the caller to explicitly do this through multiple levels
		   of enveloping because pushing multiple session keys is usually a
		   programming error rather than a desire to use two layers of triple
		   DES for that extra safety margin) */
		if( findAction( envelopeInfoPtr->actionList, ACTION_CRYPT ) != NULL )
			return( CRYPT_INITED );
		actionListPtrPtr = &envelopeInfoPtr->actionList;
		actionType = ( envelopeInfoPtr->isDeenvelope ) ? -ACTION_CRYPT : ACTION_CRYPT;
		}
	if( envInfo == CRYPT_ENVINFO_HASH )
		{
		actionListPtrPtr = &envelopeInfoPtr->actionList;
		actionType = ( envelopeInfoPtr->isDeenvelope ) ? -ACTION_HASH : ACTION_HASH;
		}
	if( envInfo == CRYPT_ENVINFO_SIGNATURE )
		{
		actionListPtrPtr = &envelopeInfoPtr->postActionList;
		actionType = ACTION_SIGN;
		}

	/* Find the insertion point for this action and make sure it isn't
	   already present */
	actionResult = findCheckLastAction( actionListPtrPtr, &actionListPtr,
										actionType, cryptHandle );
	if( actionResult == ACTION_RESULT_INITED )
		return( CRYPT_INITED );
	if( actionResult == ACTION_RESULT_PRESENT )
		return( CRYPT_OK );

	/* Insert the action into the list */
	status = krnlSendMessage( cryptHandle, RESOURCE_MESSAGE_GETPROPERTY,
							  &type, RESOURCE_MESSAGE_PROPERTY_TYPE,
							  CRYPT_BADPARM3 );
	if( cryptStatusError( status ) )
		return( status );
	if( type == RESOURCE_TYPE_CRYPT )
		{
		/* It's a context, clone it for our own use.  If we're using a private
		   key context to perform public-key encryption (which can happen in
		   some encrypt-to-self cases), we only clone the public fields */
		status = krnlSendMessage( cryptHandle, RESOURCE_MESSAGE_CLONE,
							&iNewContext, ( BOOLEAN )	/* Fix for VC++ */
							( ( envInfo == CRYPT_ENVINFO_PRIVATEKEY ) ? \
							TRUE : FALSE ), 0 );
		if( cryptStatusOK( status ) )
			status = addAction( actionListPtrPtr, &actionListPtr, actionType,
								iNewContext );
		}
	else
		{
		/* It's a certificate, increment its reference count */
		krnlSendNotifier( cryptHandle, RESOURCE_MESSAGE_INCREFCOUNT );
		status = addAction( actionListPtrPtr, &actionListPtr, actionType,
							cryptHandle );
		if( cryptStatusError( status ) )
			krnlSendNotifier( cryptHandle, RESOURCE_MESSAGE_DECREFCOUNT );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( actionType == ACTION_HASH )
		/* Remember that we need to hook the hash action up to a signature
		   action before we start enveloping data */
		actionListPtr->needsController = TRUE;

	/* If the newly-inserted action isn't a controlling action, we're done */
	if( actionType != ACTION_SIGN )
		return( status );

	/* Check if there's a subject hash action available */
	hashActionPtr = findAction( envelopeInfoPtr->actionList, ACTION_HASH );
	if( hashActionPtr == NULL )
		{
		CRYPT_CONTEXT iHashContext;

		/* Create a default hash action */
		status = iCryptCreateContext( &iHashContext,
							envelopeInfoPtr->defaultHash, CRYPT_MODE_NONE );
		if( cryptStatusError( status ) )
			return( status );

		/* Insert the hash action into the list.  We can pass a NULL context
		   to findCheckLastAction() because we've just verified that there
		   are no existing hash contexts present */
		findCheckLastAction( &envelopeInfoPtr->actionList, &hashActionPtr,
							 ACTION_HASH, CRYPT_ERROR );
		status = addAction( &envelopeInfoPtr->actionList, &hashActionPtr,
							ACTION_HASH, iHashContext );
		if( cryptStatusError( status ) )
			{
			cryptDestroyContext( iHashContext );
			return( status );
			}

		/* Remember that the action was added invisibly to the caller so we
		   don't return an error if they add it as well */
		hashActionPtr->addedAutomatically = TRUE;
		}
	else
		/* There's at least one hash action available, find the last one
		   which was added */
		findCheckLastAction( &envelopeInfoPtr->actionList, &hashActionPtr,
							 ACTION_HASH, CRYPT_ERROR );

	/* Connect the signature action to the subject hash action and remember
	   that this action now has a controlling action */
	actionListPtr->associatedAction = hashActionPtr;
	hashActionPtr->needsController = FALSE;

	return( CRYPT_OK );
	}
