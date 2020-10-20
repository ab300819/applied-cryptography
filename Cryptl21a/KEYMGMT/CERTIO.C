/****************************************************************************
*																			*
*						Certificate Import/Export Routines					*
*						Copyright Peter Gutmann 1997-1999					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "asn1.h"
  #include "asn1objs.h"
  #include "asn1oid.h"
  #include "cert.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1objs.h"
  #include "keymgmt/asn1oid.h"
  #include "keymgmt/cert.h"
#endif /* Compiler-specific includes */

/* Context-specific tags for attribute certificates */

enum { CTAG_AC_BASECERTIFICATEID, CTAG_AC_ENTITYNAME,
	   CTAG_AC_OBJECTDIGESTINFO };

/* Prototypes for functions in lib_cert.c */

int createCertificate( CERT_INFO **certInfoPtr, const int resourceFlags );

/****************************************************************************
*																			*
*									Utility Functions						*
*																			*
****************************************************************************/

/* Determine whether an object is a certificate, attribute certificate, CRL,
   certification request, PKCS #7 certificate chain, Netscape certificate
   sequence, or Netscape SignedPublicKeyAndChallenge, and how long the total
   object is.  If fed an unknown object we can determine its type at runtime
   (although it's hardly LL(1)) and import it as appropriate.  The start of
   the various object types are:

	1a.	SEQUENCE {
	1b.	[0] {										-- CMS attrs if present
	2a		contentType			OBJECT IDENTIFIER,	-- Cert chain/seq if present
	2b.		SEQUENCE {
				version		[0]	INTEGER DEFAULT(0),	-- Cert if present
	3a.			version			INTEGER (0),		-- For cert request
	3b.			version			INTEGER DEFAULT(0),	-- For CRL
	3c.			version			INTEGER DEFAULT(1),	-- For attribute cert
	3d.			serialNumber	INTEGER,			-- For cert
													-- CRL or SPKAC if absent
	4a.			owner		[0] or [1] or [2]		-- Attribute cert
								-- Note that this doesn't clash with the
								-- cert version since this is an explicit
								-- constructed tag and the cert version is
								-- implicit primitive
	4b.			SEQUENCE {							-- DN or AlgoID
	5a.				SET {							-- CertRequest if present
	5b.				algo		OBJECT IDENTIFIER,	-- Cert or CRL if present
	5c.				SEQUENCE {						-- SPKAC if present
					...
					}
	6			SEQUENCE { ... }					-- DN for Cert and CRL
	7a			SEQUENCE {							-- Cert if present
	7b			UTCTime								-- CRL if present

   This means that sorting out which is which involves quite a bit of
   lookahead.  The fact that the version and serial number integers clash
   for the raw certificate objects doesn't help much either */

static int getCertObjectInfo( const void *object, int *objectLength,
							  CERT_TYPE *objectType )
	{
	STREAM stream;
	CERT_TYPE wrapperType = CERTTYPE_NONE, type = CERTTYPE_NONE;
	int totalLength, innerLength, innerStart, value, sequenceLength, status;
	long length;

	/* Set initial default values */
	*objectLength = CRYPT_ERROR;
	*objectType = CRYPT_ERROR;

	sMemConnect( &stream, object, STREAMSIZE_UNKNOWN );

	/* First we check for the easy one, CMS attributes, which are always
	   DER-encoded and which begin with a [0] IMPLICIT SET followed by a
	   SEQUENCE */
	if( peekTag( &stream ) == MAKE_CTAG( 0 ) )
		{
		readTag( &stream );
		readLength( &stream, &length );
		status = readSequence( &stream, &value );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );
		*objectLength = ( int ) sizeofObject( length );
		*objectType = CERTTYPE_CMS_ATTRIBUTES;
		return( CRYPT_OK );
		}

	/* If we're being called from an internal cryptlib function, we can get
	   passed incomplete parts of certificate objects such as the SET OF
	   Certificate from a cert chain.  To allow us to recognise these, the
	   code changes the tag to something which wouldn't otherwise occur, and
	   we identify the object from this tag, after which we reset it to its
	   normal value.  This is a rather ugly kludge, but it's the easiest way
	   to get the information down into this low-level function */
	if( peekTag( &stream ) == 0xFF )
		{
		writeTag( &stream, MAKE_CTAG( 0 ) );	/* Replace with proper tag */
		readLength( &stream, &length );
		status = readSequence( &stream, &value );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );
		*objectLength = ( int ) sizeofObject( length );
		*objectType = CERTTYPE_CMS_CERTSET;
		return( CRYPT_OK );
		}

	/* Check that the start of the object is in order.  We may get a
	   totalLength value of zero if the outer wrapper is encoded using the
	   BER instead of the DER, at least one oddball implementation does
	   this, so we remember where the inner sequence data starts so we can
	   skip over it later to find the rest of the data and determine its
	   length */
	status = readSequence( &stream, &totalLength );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	if( totalLength )
		totalLength += status;	/* Add length of sequence header */

	/* If it's a PKCS #7 certificate chain or Netscape cert.sequence,
	   there'll be an object identifier present */
	if( peekTag( &stream ) == BER_OBJECT_IDENTIFIER )
		{
		BYTE buffer[ 32 ];
		int bufferLength;

		/* Read the contentType OID, determine the content type based on it,
		   and read the content encapsulation and header */
		length = readRawObject( &stream, buffer, &bufferLength,
								32, BER_OBJECT_IDENTIFIER );
		if( cryptStatusError( length ) )
			{
			sMemDisconnect( &stream );
			return( CRYPT_BADDATA );
			}
		if( !memcmp( buffer, OID_CMS_SIGNEDDATA, bufferLength ) )
			wrapperType = CERTTYPE_CERTCHAIN;
		else
			if( !memcmp( buffer, OID_NS_CERTSEQ, bufferLength ) )
				wrapperType = CERTTYPE_NS_CERTSEQUENCE;
		if( wrapperType == CERTTYPE_NONE || \
			!checkReadCtag( &stream, 0, TRUE ) || \
			cryptStatusError( readLength( &stream, &length ) ) || \
			cryptStatusError( readSequence( &stream, &value ) ) )
			{
			sMemDisconnect( &stream );
			return( CRYPT_BADDATA );
			}

		/* If it's a PKCS #7 certificate chain, burrow into the inner PKCS #7
		   content */
		if( wrapperType == CERTTYPE_CERTCHAIN )
			{
			/* Read the version number (1 = PKCS #7 v1.5, 2 = PKCS #7 v1.6,
			   3 = S/MIME with attribute certificate(s)) and SET OF
			   DigestAlgorithmIdentifier (this is empty for a pure cert chain,
			   nonempty for signed data) */
			if( cryptStatusError( readShortInteger( &stream, &length ) ) || \
												length < 1 || length > 3 || \
				cryptStatusError( readSet( &stream, &value ) ) )
				{
				sMemDisconnect( &stream );
				return( CRYPT_BADDATA );
				}
			if( value )
				sSkip( &stream, value );

			/* Read the ContentInfo header, contentType OID and the inner
			   content encapsulation */
			if( cryptStatusError( readSequence( &stream, &value ) ) )
				length = CRYPT_ERROR;
			else
				length = readRawObject( &stream, buffer, &bufferLength,
										32, BER_OBJECT_IDENTIFIER );
			if( cryptStatusError( length ) || \
				memcmp( buffer, OID_CMS_DATA, bufferLength ) )
				{
				sMemDisconnect( &stream );
				return( CRYPT_BADDATA );
				}
			checkEOC( &stream );
			if( !checkReadCtag( &stream, 0, TRUE ) || \
				cryptStatusError( readLength( &stream, &length ) ) )
				{
				sMemDisconnect( &stream );
				return( CRYPT_BADDATA );
				}
			}

		/* We've finally reached the certificate(s), retry the read of the
		   certificate start */
		status = readSequence( &stream, &value );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}
		type = CERTTYPE_CERTIFICATE;
		}

	/* Read the inner sequence */
	status = readSequence( &stream, &innerLength );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	innerStart = sMemSize( &stream );

	/* If it's a certificate, there may be a version number present */
	value = checkReadCtag( &stream, 0, TRUE );
	if( value )
		{
		long integer;

		/* Look for an integer value of 1 or 2 */
		status = readLength( &stream, &length );
		if( !cryptStatusError( status ) )
			status = readShortInteger( &stream, &integer );
		if( cryptStatusError( status ) || length != 3 || integer < 1 || \
			integer > 2 )
			{
			sMemDisconnect( &stream );
			return( CRYPT_BADDATA );
			}

		/* If we find this then it's definitely a v2 or v3 certificate */
		type = CERTTYPE_CERTIFICATE;
		}

	/* If it's a CRL, there may be no version number present */
	if( checkReadTag( &stream, BER_INTEGER ) )
		{
		/* If there's an integer present, it's either 0 for a cert.request,
		   1 for a v2 CRL, or any value (including bignums) for a
		   certificate.  We don't care about this value much, all we do is
		   check that it's there */
		if( cryptStatusError( readLength( &stream, &length ) ) || length < 1 )
			{
			sMemDisconnect( &stream );
			return( CRYPT_BADDATA );
			}
		sSkip( &stream, length );
		}
	else
		/* No integer at this point, it's either a v1 CRL or a SPKAC.  For
		   now we guess a CRL, this is adjusted to a SPKAC later if
		   necessary */
		type = CERTTYPE_CRL;

	/* If it's a constructed context-specific tag, it's an attribute
	   certificate.  Note that the [0] variant doesn't clash with the tagged
	   version number in a certificate since here it's constructed while for
	   the version number it's primitive */
	value = peekTag( &stream );
	if( value == MAKE_CTAG( CTAG_AC_BASECERTIFICATEID ) || \
		value == MAKE_CTAG( CTAG_AC_ENTITYNAME ) || \
		value == MAKE_CTAG( CTAG_AC_OBJECTDIGESTINFO ) )
		{
		readTag( &stream );		/* Skip the tagging */
		if( cryptStatusError( readLength( &stream, &length ) ) )
			return( CRYPT_BADDATA );
		type = CERTTYPE_ATTRCERT;
		}

	/* Next is another SEQUENCE, either the DN for a cert request, an
	   AlgorithmIdentifier for a cert or CRL, or one of a variety of types
	   for attribute certs */
	status = readSequence( &stream, &sequenceLength );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( CRYPT_BADDATA );
		}

	/* If it's an attribute cert, we've made a positive ID */
	if( type == CERTTYPE_ATTRCERT )
		status = CRYPT_OK;
	else
		{
		/* Next is either an OBJECT IDENTIFIER for a cert or CRL, or a SET
		   for a cert request */
		status = CRYPT_BADDATA;
		value = readTag( &stream );
		if( value == BER_SET && type == CERTTYPE_NONE )
			{
			type = CERTTYPE_CERTREQUEST;
			status = CRYPT_OK;
			}
		else
			if( value == BER_OBJECT_IDENTIFIER )
				{
				/* Skip the algorithm identifier and subject/issuer DN */
				sSkip( &stream, sequenceLength - 1 );
				if( cryptStatusError( readUniversal( &stream ) ) )
					status = CRYPT_BADDATA;
				else
					{
					/* Next is either a SEQUENCE for a cert or a UTCTime or
					   GeneralisedTime for a CRL */
					value = readTag( &stream );
					if( value == BER_SEQUENCE && ( type == CERTTYPE_NONE || \
						type == CERTTYPE_CERTIFICATE ) )
						{
						type = CERTTYPE_CERTIFICATE;
						status = CRYPT_OK;
						}
					else
						if( ( value == BER_TIME_UTC || \
							  value == BER_TIME_GENERALIZED ) && \
							( type == CERTTYPE_NONE || type == CERTTYPE_CRL ) )
							{
							type = CERTTYPE_CRL;
							status = CRYPT_OK;
							}
					}
				}
			else
				/* If it's another sequence (the start of the
				   AlgorithmIdentifier) followed by a BIT STRING, it's a
				   SPKAC */
				if( value == BER_SEQUENCE && \
					!cryptStatusError( readUniversalData( &stream ) ) && \
					readTag( &stream ) == BER_BITSTRING )
					{
					type = CERTTYPE_NS_SPKAC;
					status = CRYPT_OK;
					}
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( CRYPT_BADDATA );
			}
		}

	/* If the outer wrapper is encoded using the BER, we need to move past
	   the payload and find out how big the signature is */
	if( !totalLength )
		{
		/* Skip over the signed object, then check for and skip over the
		   signature algorithm information and signature fields.  Once we've
		   done this we've reached the end of the object which tells us its
		   total length */
		sseek( &stream, innerStart + innerLength );
		if( readTag( &stream ) != BER_SEQUENCE || \
			cryptStatusError( readLength( &stream, &length ) ) || length < 8 )
			status = CRYPT_BADDATA;
		else
			{
			sSkip( &stream, ( int ) length );
			if( readTag( &stream ) != BER_BITSTRING || \
				cryptStatusError( readLength( &stream, &length ) ) || length < 32 )
				status = CRYPT_BADDATA;
			else
				{
				sSkip( &stream, ( int ) length );
				totalLength = sMemSize( &stream );
				}
			}
		}
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* We're done, tell the caller what we found */
	*objectLength = totalLength;
	*objectType = ( wrapperType != CERTTYPE_NONE ) ? wrapperType : type;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Import/Export Functions						*
*																			*
****************************************************************************/

/* Import a certificate object.  If iCryptContext is non-NULL, this will
   create a data-only cert with the public key stored in the context (this is
   used to create certs attached to private keys).  If iCryptContext is
   CRYPT_UNUSED, it will create a data-only cert with the certs internal
   publicKeyInfo pointer set to the start of the encoded public key to allow
   it to be decoded later (this is used when we don't know in advance which
   type of cert we want to create).  Returns the length of the certificate */

int importCert( const void *certObject, CRYPT_CERTIFICATE *certificate,
				CRYPT_CONTEXT *iCryptContext, const BOOLEAN isInternal )
	{
	CERT_INFO *certInfoPtr;
	CRYPT_CERTFORMAT_TYPE format = CRYPT_CERTFORMAT_NONE;
	CERT_TYPE type;
	STREAM stream;
	int ( *readCertObjectFunction )( STREAM *stream, CERT_INFO *certInfoPtr );
	void *certObjectPtr = ( void * ) certObject, *certBuffer = NULL;
	int length, dummy, status;

	*certificate = CRYPT_ERROR;

	/* Check whether it's an S/MIME or base64-encoded certificate object */
	if( ( length = smimeCheckHeader( certObject ) ) != 0 )
		format = CRYPT_CERTFORMAT_SMIME_CERTIFICATE;
	else
		if( ( length = base64checkHeader( certObject ) ) != 0 )
			format = CRYPT_CERTFORMAT_TEXT_CERTIFICATE;
	if( length )
		{
		int decodedLength;

		/* It's base64 / S/MIME-encoded, decode it into a temporary buffer */
		decodedLength = base64decodeLen( ( const char * ) certObject + length );
		if( decodedLength <= 128 || decodedLength > 8192 )
			return( CRYPT_BADDATA );
		if( ( certObjectPtr = malloc( decodedLength ) ) == NULL )
			return( CRYPT_NOMEM );
		if( !base64decode( certObjectPtr, ( const char * ) certObject +
						   length, 0, format ) )
			{
			free( certObjectPtr );
			return( CRYPT_BADDATA );
			}
		}

	/* Check the object to determine its type and length, and check the
	   encoding if necessary */
	status = getCertObjectInfo( certObjectPtr, &length, &type );
	if( !cryptStatusError( status ) && \
		getOptionNumeric( CRYPT_OPTION_CERT_CHECKENCODING ) )
		status = checkEncoding( certObjectPtr, length );
	if( cryptStatusError( status ) )
		{
		if( certObjectPtr != certObject )
			free( certObjectPtr );
		return( status );
		}
	status = CRYPT_OK;	/* checkEncoding() returns a length */

	/* If it's a cert chain, this is handled specially since we need to
	   import a plurality of certs at once */
	if( type == CERTTYPE_CERTCHAIN || type == CERTTYPE_NS_CERTSEQUENCE || \
		type == CERTTYPE_CMS_CERTSET )
		{
		/* Read the cert chain into a collection of internal cert resources.
		   This returns a handle to the leaf cert in the chain, with the
		   remaining certs being accessible within it via the cert cursor
		   functions */
		sMemConnect( &stream, certObjectPtr, STREAMSIZE_UNKNOWN );
		if( type != CERTTYPE_CMS_CERTSET )
			readSequence( &stream, &dummy );	/* Skip the outer wrapper */
		status = readCertChain( &stream, certificate, iCryptContext, type );
		sMemDisconnect( &stream );
		if( certObjectPtr != certObject )
			free( certObjectPtr );
		if( cryptStatusError( status ) )
			return( status );

		/* Since the leaf node in the chain is created as just another
		   internal resource, we need to make it externally visible before
		   we return it to the caller if the chain is externally visible */
		if( !isInternal )
			{
			int internalFlag = isInternal;

			krnlSendMessage( *certificate, RESOURCE_IMESSAGE_SETPROPERTY,
							 &internalFlag, RESOURCE_MESSAGE_PROPERTY_INTERNAL,
							 0 );
			}
		return( length );
		}

	/* Select the function to use to read the certificate object */
	switch( type )
		{
		case CERTTYPE_CERTIFICATE:
			readCertObjectFunction = readCertInfo;
			break;

		case CERTTYPE_ATTRCERT:
			readCertObjectFunction = readAttributeCertInfo;
			break;

		case CERTTYPE_CERTREQUEST:
			readCertObjectFunction = readCertRequestInfo;
			break;

		case CERTTYPE_CRL:
			readCertObjectFunction = readCRLInfo;
			break;

		case CERTTYPE_NS_SPKAC:
			readCertObjectFunction = readSPKACInfo;
			break;

		case CERTTYPE_CMS_ATTRIBUTES:
			readCertObjectFunction = readCMSAttributes;
			break;

		default:
			/* Internal error, should never happen */
			if( certObjectPtr != certObject )
				free( certObjectPtr );
			return( CRYPT_ERROR );
		}

	/* Allocate a buffer to store a copy of the object so we can preserve the
	   original for when it's needed again later, and try and create the
	   certificate object.  All the objects (including the CMS attributes,
	   which in theory aren't needed for anything further) need to be kept
	   around in their encoded form, which is often incorrect and therefore
	   can't be reconstructed.  The readXXX() function record pointers to the
	   required encoded fields so they can be recovered later in their
	   (possibly incorrect) form, and these pointers need to be to a
	   persistent copy of the encoded object.  In addition the cert objects
	   need to be kept around anyway for sig checks and possible re-export */
	if( ( certBuffer = malloc( length ) ) == NULL )
		status = CRYPT_NOMEM;
	if( cryptStatusOK( status ) )
		status = createCertificate( &certInfoPtr, ( isInternal ) ? \
									RESOURCE_FLAG_INTERNAL : 0 );
	if( cryptStatusError( status ) )
		{
		if( certObjectPtr != certObject )
			free( certObjectPtr );
		free( certBuffer );
		return( status );
		}
	*certificate = status;
	certInfoPtr->type = type;

	/* If we're doing a deferred read of the public key components (they'll
	   be decoded later when we know whether we need them), set the data-only
	   flag to ensure we don't try to decode them */
	certInfoPtr->dataOnly = ( iCryptContext == ( CRYPT_CONTEXT * ) CRYPT_UNUSED ) ? \
							TRUE : FALSE;

	/* Copy in the certificate object for later use */
	memcpy( certBuffer, certObjectPtr, length );
	certInfoPtr->certificate = certBuffer;
	certInfoPtr->certificateSize = length;

	/* Parse the object into the certificate.  Note that we have to use the
	   copy in the certBuffer rather than the original since the readXXX()
	   functions record pointers to various encoded fields */
	sMemConnect( &stream, certBuffer, length );
	if( type != CERTTYPE_CMS_ATTRIBUTES )
		readSequence( &stream, &dummy );	/* Skip the outer wrapper */
	status = readCertObjectFunction( &stream, certInfoPtr );
	sMemDisconnect( &stream );
	if( certObjectPtr != certObject )
		free( certObjectPtr );
	if( cryptStatusError( status ) )
		{
		unlockResource( certInfoPtr );
		krnlSendNotifier( *certificate, RESOURCE_IMESSAGE_DESTROY );
		*certificate = CRYPT_ERROR;
		return( status );
		}

	/* If we want the public key context handled independently from the cert,
	   separate it out from the cert */
	if( iCryptContext != NULL && \
		iCryptContext != ( CRYPT_CONTEXT * ) CRYPT_UNUSED )
		{
		*iCryptContext = certInfoPtr->iCryptContext;
		certInfoPtr->iCryptContext = CRYPT_ERROR;
		certInfoPtr->dataOnly = TRUE;
		}

	unlockResourceExit( certInfoPtr, length );
	}

/* Export a certificate/certification request.  This just writes the
   internal encoded object to an external buffer.  For cert/cert chain export
   the possibilities are as follows:

						Export
	Type  |		Cert				Chain
	------+--------------------+---------------
	Cert  | Cert			   | Cert as chain
		  |					   |
	Chain | Currently selected | Chain
		  | cert in chain	   |					*/

int exportCert( void *certObject, int *certObjectLength,
				const CRYPT_CERTFORMAT_TYPE certFormatType,
				const CERT_INFO *certInfoPtr )
	{
	/* If it's a binary format, the base format is the actual format type.
	   If it's a text (base64) format, the base format is given by subtracting
			the difference between the text and binary formats.
	   If it's an S/MIME format, the base format depends on the cert object
			type */
	const CRYPT_CERTFORMAT_TYPE baseFormatType = \
		( certFormatType < CRYPT_CERTFORMAT_TEXT_CERTIFICATE ) ? \
			certFormatType : \
		( certFormatType < CRYPT_CERTFORMAT_SMIME_CERTIFICATE ) ? \
			certFormatType - ( CRYPT_CERTFORMAT_TEXT_CERTIFICATE - 1 ) : \
		( certInfoPtr->type == CRYPT_CERTTYPE_CERTREQUEST ) ? \
			CRYPT_CERTFORMAT_CERTIFICATE : CRYPT_CERTFORMAT_CERTCHAIN;
	STREAM stream;
	void *buffer;
	int length, encodedLength, status;

	/* Determine how big the output object will be */
	if( baseFormatType == CRYPT_CERTFORMAT_CERTCHAIN || \
		baseFormatType == CRYPT_CERTFORMAT_NS_CERTSEQUENCE )
		{
		STREAM nullStream;
		int status;

		/* If we're being asked to write a cert chain or cert sequence, the
		   cert object must be a certificate or cert chain */
		if( certInfoPtr->type != CRYPT_CERTTYPE_CERTIFICATE && \
			certInfoPtr->type != CRYPT_CERTTYPE_CERTCHAIN )
			return( CRYPT_BADPARM3 );

		sMemOpen( &nullStream, NULL, 0 );
		status = writeCertChain( &nullStream, certInfoPtr, ( BOOLEAN )	/* Fix for VC++ */
								 ( baseFormatType == CRYPT_CERTFORMAT_CERTCHAIN ) );
		length = sMemSize( &nullStream );
		sMemClose( &nullStream );
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		length = certInfoPtr->certificateSize;
	encodedLength = ( certFormatType >= CRYPT_CERTFORMAT_TEXT_CERTIFICATE ) ? \
		base64encodeLen( length, certInfoPtr->type, certFormatType ) : length;

	/* Set up the length information */
	*certObjectLength = encodedLength;
	if( certObject == NULL )
		return( CRYPT_OK );
	if( checkBadPtrWrite( certObject, encodedLength ) )
		return( CRYPT_BADPARM1 );

	/* If it's a simple object, write either the DER-encoded object or its
	   base64 / S/MIME-encoded form directly to the output */
	if( certFormatType == CRYPT_CERTFORMAT_CERTIFICATE )
		{
		memcpy( certObject, certInfoPtr->certificate, length );
		return( CRYPT_OK );
		}
	if( certFormatType == CRYPT_CERTFORMAT_TEXT_CERTIFICATE )
		{
		base64encode( certObject, certInfoPtr->certificate,
					  certInfoPtr->certificateSize, certInfoPtr->type,
					  CRYPT_CERTFORMAT_TEXT_CERTIFICATE );
		return( CRYPT_OK );
		}
	if( certFormatType == CRYPT_CERTFORMAT_SMIME_CERTIFICATE && \
		certInfoPtr->type == CRYPT_CERTTYPE_CERTREQUEST )
		{
		base64encode( certObject, certInfoPtr->certificate,
				certInfoPtr->certificateSize, CRYPT_CERTTYPE_CERTREQUEST,
				CRYPT_CERTFORMAT_SMIME_CERTIFICATE );
		return( CRYPT_OK );
		}

	/* It's a straight cert chain, write it directly to the output */
	if( certFormatType == CRYPT_CERTFORMAT_CERTCHAIN )
		{
		sMemOpen( &stream, certObject, length );
		status = writeCertChain( &stream, certInfoPtr, ( BOOLEAN )	/* Fix for VC++ */
						( baseFormatType == CRYPT_CERTFORMAT_CERTCHAIN ) );
		sMemDisconnect( &stream );
		return( status );
		}

	/* It's a base64 / S/MIME-encoded cert chain, write it to a temporary
	   buffer and then encode it to the output */
	if( ( buffer = malloc( length ) ) == NULL )
		return( CRYPT_NOMEM );
	sMemOpen( &stream, buffer, length );
	status = writeCertChain( &stream, certInfoPtr, ( BOOLEAN )	/* Fix for VC++ */
					( baseFormatType == CRYPT_CERTFORMAT_CERTCHAIN ) );
	if( cryptStatusOK( status ) )
		base64encode( certObject, buffer, length, CRYPT_CERTTYPE_CERTCHAIN,
					  certFormatType );
	sMemClose( &stream );
	free( buffer );

	return( status );
	}
