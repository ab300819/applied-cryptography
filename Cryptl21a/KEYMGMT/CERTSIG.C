/****************************************************************************
*																			*
*					  Certificate Signing/Checking Routines					*
*						Copyright Peter Gutmann 1997-1999					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "asn1.h"
  #include "cert.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/cert.h"
#endif /* Compiler-specific includes */

/* Prototypes for functions in lib_sign.c */

int createX509signature( void *signedObject, int *signedObjectLength,
						 const void *object, const int objectLength,
						 CRYPT_CONTEXT signContext,
						 const CRYPT_ALGO hashAlgo );
int checkX509signature( const void *signedObject, void **object,
						int *objectLength, CRYPT_CONTEXT sigCheckContext );

/* Sign a certificate object */

int signCert( CERT_INFO *certInfoPtr, const CRYPT_CONTEXT signContext )
	{
	CERT_INFO *issuerCertInfoPtr;
	STREAM stream;
	BOOLEAN issuerCertPresent = FALSE, isCertificate = FALSE;
	int ( *writeCertObjectFunction )( STREAM *stream, CERT_INFO *subjectCertInfoPtr,
									  const CERT_INFO *issuerCertInfoPtr,
									  const CRYPT_CONTEXT iIssuerCryptContext );
	void *certObject, *signedCertObject;
	const time_t currentTime = time( NULL );
	long serialNumber;
	int certObjectLength, signedCertObjectLength, dataLength, status;

	/* Obtain the issuer certificate from the private key if necessary */
	if( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
		certInfoPtr->type == CRYPT_CERTTYPE_ATTRIBUTE_CERT || \
		certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN )
		isCertificate = TRUE;
	if( isCertificate || certInfoPtr->type == CRYPT_CERTTYPE_CRL )
		{
		/* If it's a self-signed cert, the issuer is also the subject */
		if( certInfoPtr->selfSigned )
			issuerCertInfoPtr = certInfoPtr;
		else
			{
			CRYPT_CERTIFICATE dataOnlyCert;

			/* Get the data-only certificate from the context */
			status = krnlSendMessage( signContext, RESOURCE_MESSAGE_GETDATA,
							&dataOnlyCert, RESOURCE_MESSAGE_DATA_CERTIFICATE,
							CRYPT_BADPARM1 );
			if( cryptStatusError( status ) )
				return( status );
			getCheckInternalResource2( dataOnlyCert, issuerCertInfoPtr,
									   RESOURCE_TYPE_CERTIFICATE, certInfoPtr );
			issuerCertPresent = TRUE;
			}

		/* Make sure the key associated with the issuer cert is valid for
		   cert/CRL signing: We need a key+complete certificate (unless we're
		   creating a self-signed cert), and the cert has to allow the key to
		   be used for cert/CRL signing */
		if( ( issuerCertInfoPtr->type != CRYPT_CERTTYPE_CERTIFICATE && \
			  issuerCertInfoPtr->type != CRYPT_CERTTYPE_CERTCHAIN ) || \
			( issuerCertPresent && issuerCertInfoPtr->certificate == NULL ) )
			status = CRYPT_BADPARM2;
		else
			status = checkCertUsage( issuerCertInfoPtr, ( isCertificate ) ? \
						CRYPT_KEYUSAGE_KEYCERTSIGN : CRYPT_KEYUSAGE_CRLSIGN,
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );
		if( cryptStatusError( status ) )
			{
			if( issuerCertPresent )
				unlockResource( issuerCertInfoPtr );
			return( status );
			}
		}

	/* If it's a certificate chain, copy over the signing cert and order the
	   certificates in the chain from the current one up to the root */
	if( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN )
		{
		/* If there's a chain of certs present (for example from a previous
		   signing attempt which wasn't completed due to an error), free
		   them */
		if( certInfoPtr->certChainEnd )
			{
			int i;

			for( i = 0; i < certInfoPtr->certChainEnd; i++ )
				krnlSendNotifier( certInfoPtr->certChain[ i ],
								  RESOURCE_IMESSAGE_DECREFCOUNT );
			certInfoPtr->certChainEnd = 0;
			}

		/* If it's a self-signed cert, it must be the only cert in the chain
		   (creating a chain like this doesn't make much sense, but we handle
		   it anyway) */
		if( certInfoPtr->selfSigned )
			{
			if( certInfoPtr->certChainEnd )
				{
				setCertError( certInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
							  CRYPT_CERTERROR_PRESENT );
				return( CRYPT_INVALID );
				}
			}
		else
			{
			/* Copy the cert chain into the cert to be signed */
			status = copyCertChain( certInfoPtr, signContext );
			if( cryptStatusError( status ) )
				return( status );
			}
		}

	/* If it's some certificate variant or CRL and the various timestamps
	   haven't been set yet, start them at the current time and give them the
	   default validity period or next update time if these haven't been set.
	   The time used is the local time, this is converted to GMT when we
	   write it to the certificate.  Issues like validity period nesting and
	   checking for valid time periods are handled when the data is encoded */
	if( ( isCertificate || certInfoPtr->type == CRYPT_CERTTYPE_CRL ) && \
		!certInfoPtr->startTime )
		certInfoPtr->startTime = currentTime;
	if( isCertificate && !certInfoPtr->endTime )
		certInfoPtr->endTime = certInfoPtr->startTime + \
			( ( time_t ) getOptionNumeric( CRYPT_OPTION_CERT_VALIDITY ) * 86400L );
	if( certInfoPtr->type == CRYPT_CERTTYPE_CRL )
		{
		if( !certInfoPtr->endTime )
			certInfoPtr->endTime = certInfoPtr->startTime + \
				( ( time_t ) getOptionNumeric( CRYPT_OPTION_CERT_UPDATEINTERVAL ) * 86400L );
		if( !certInfoPtr->revocationTime )
			certInfoPtr->revocationTime = currentTime;
		}

	/* If it's a certificate, set up the certificate serial number.  Ideally
	   we would store this as a static value in the configuration database,
	   but this has three disadvantages: Updating the serial number updates
	   the entire configuration database (including things the user might not
	   want updated), if the config database update fails the serial number
	   never changes, and the predictable serial number allows tracking of
	   the number of certificates which have been signed by the CA, which is
	   both nasty if various braindamaged government regulation attempts ever
	   come to fruition, and a potential problem if a CA ends up revealing
	   just how few certs it's actually signing.  Because of this, we use the
	   time in seconds since 1 Jan 1999 as the serial number, which should
	   yield unique numbers and doesn't leak any real information (the
	   validity period will probably be the same as the serial number
	   timestamp).  We don't have to worry about the rare case where the
	   system clock is set before the current date since we'll just end up
	   with a very large serial number (the unsigned interpretation of the
	   negative time offset) */
	if( isCertificate )
		{
		BYTE *dataPtr;

		serialNumber = currentTime - 0x3682E000L;
		dataLength = ( serialNumber <= 0xFFFFFFL ) ? 3 : 4;
		if( ( dataPtr = malloc( dataLength ) ) == NULL )
			{
			if( issuerCertPresent )
				unlockResource( issuerCertInfoPtr );
			return( CRYPT_NOMEM );
			}
		if( certInfoPtr->serialNumber != NULL )
			free( certInfoPtr->serialNumber );

		/* Copy in the serial number as a big-endian integer value */
		certInfoPtr->serialNumber = dataPtr;
		certInfoPtr->serialNumberLength = dataLength;
		if( dataLength == 4 )
			*dataPtr++ = ( BYTE ) ( serialNumber >> 24 );
		*dataPtr++ = ( BYTE ) ( serialNumber >> 16 );
		*dataPtr++ = ( BYTE ) ( serialNumber >> 8 );
		*dataPtr++ = ( BYTE ) ( serialNumber );
		}

	/* Select the function to use to write the certificate object to be
	   signed */
	switch( certInfoPtr->type )
		{
		case CRYPT_CERTTYPE_CERTIFICATE:
		case CRYPT_CERTTYPE_CERTCHAIN:
			writeCertObjectFunction = writeCertInfo;
			break;

		case CRYPT_CERTTYPE_ATTRIBUTE_CERT:
			writeCertObjectFunction = writeAttributeCertInfo;
			break;

		case CRYPT_CERTTYPE_CERTREQUEST:
			writeCertObjectFunction = writeCertRequestInfo;
			break;

		case CRYPT_CERTTYPE_CRL:
			writeCertObjectFunction = writeCRLInfo;
			break;

		default:
			/* Internal error, should never happen */
			if( issuerCertPresent )
				unlockResource( issuerCertInfoPtr );
			return( CRYPT_ERROR );
		}

	/* Determine how big the encoded certificate information will be,
	   allocate memory for it and the full signed certificate, and write the
	   encoded certificate information */
	sMemOpen( &stream, NULL, 0 );
	status = writeCertObjectFunction( &stream, certInfoPtr, issuerCertInfoPtr,
									  signContext );
	certObjectLength = sMemSize( &stream );
	sMemClose( &stream );
	if( cryptStatusError( status ) )
		{
		if( issuerCertPresent )
			unlockResource( issuerCertInfoPtr );
		return( status );
		}
	if( ( certObject = malloc( certObjectLength ) ) == NULL || \
		( signedCertObject = malloc( certObjectLength + 1024 ) ) == NULL )
		{
		if( certObject != NULL )
			free( certObject );
		if( issuerCertPresent )
			unlockResource( issuerCertInfoPtr );
		return( CRYPT_NOMEM );
		}
	sMemOpen( &stream, certObject, certObjectLength );
	status = writeCertObjectFunction( &stream, certInfoPtr, issuerCertInfoPtr,
									  signContext );
	sMemDisconnect( &stream );
	if( issuerCertPresent )
		unlockResource( issuerCertInfoPtr );
	if( cryptStatusError( status ) )
		{
		zeroise( certObject, certObjectLength );
		free( certObject );
		free( signedCertObject );
		return( status );
		}

	/* Sign the certificate information and assign it to the certificate
	   context */
	status = createX509signature( signedCertObject, &signedCertObjectLength,
								  certObject, certObjectLength, signContext,
								  CRYPT_ALGO_SHA );
	if( cryptStatusOK( status ) )
		{
		certInfoPtr->certificate = signedCertObject;
		certInfoPtr->certificateSize = signedCertObjectLength;

		/* If it's a certification request, it's now self-signed */
		if( certInfoPtr->type == CRYPT_CERTTYPE_CERTREQUEST )
			certInfoPtr->selfSigned = TRUE;
		}

	/* Clean up */
	zeroise( certObject, certObjectLength );
	free( certObject );
	return( status );
	}

/* Check a certificate against a CRL */

static int checkCRL( CERT_INFO *certInfoPtr, const CRYPT_CERTIFICATE cryptCRL )
	{
	CERT_INFO *crlInfoPtr;
	int i, status = CRYPT_OK;

	/* Check that the CRL is a full, signed CRL and not a newly-created CRL
	   object */
	getCheckResource( cryptCRL, crlInfoPtr, RESOURCE_TYPE_CERTIFICATE,
					  CRYPT_BADPARM2 );
	if( crlInfoPtr->certificate == NULL )
		return( CRYPT_NOTINITED );

	/* Check the base cert against the CRL.  If it's been revoked or there's
	   only a single cert present, exit */
	status = checkRevocation( certInfoPtr, crlInfoPtr );
	if( cryptStatusError( status ) || \
		( certInfoPtr->type != CERTTYPE_CERTCHAIN && \
		  certInfoPtr->type != CERTTYPE_NS_CERTSEQUENCE ) )
		unlockResourceExit( crlInfoPtr, status );

	/* It's a cert chain, check every remaining cert in the chain against the
	   CRL */
	for( i = 0; i < certInfoPtr->certChainEnd; i++ )
		{
		CERT_INFO *certChainInfoPtr;

		/* Check this cert agains the CRL */
		getCheckInternalResource( certInfoPtr->certChain[ i ],
								  certChainInfoPtr, RESOURCE_TYPE_CERTIFICATE );
		status = checkRevocation( certChainInfoPtr, crlInfoPtr );
		unlockResource( certChainInfoPtr );

		/* If the cert has been revoked, set the currently selected cert to
		   the revoked one */
		if( cryptStatusError( status ) )
			{
			certInfoPtr->certChainPos = i;
			break;
			}
		}

	unlockResourceExit( crlInfoPtr, status );
	}

/* Check the validity of a cert object, either against an issuing key/
   certificate or against a CRL */

int checkCertValidity( CERT_INFO *certInfoPtr, const CRYPT_HANDLE sigCheckKey )
	{
	CRYPT_CONTEXT cryptContext;
	CERT_INFO *issuerCertInfoPtr;
	RESOURCE_TYPE type;
	int status;

	/* If we've been passed a checking resource, determine what it is */
	if( sigCheckKey != CRYPT_UNUSED )
		{
		status = krnlSendMessage( sigCheckKey, RESOURCE_MESSAGE_GETPROPERTY,
								  &type, RESOURCE_MESSAGE_PROPERTY_TYPE,
								  CRYPT_BADPARM2 );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If the checking key is a CRL or keyset which may contain a CRL then
	   this is a revocation check which works rather differently from a
	   straight signature check */
	if( sigCheckKey != CRYPT_UNUSED )
		{
		int certType;

		if( type == RESOURCE_TYPE_CERTIFICATE && \
			cryptStatusOK( cryptGetCertComponentNumeric( sigCheckKey,
								CRYPT_CERTINFO_CERTTYPE, &certType ) ) && \
			certType == CRYPT_CERTTYPE_CRL )
			{
			/* We've been given a CRL, check the cert or cert chain against
			   it */
			status = checkCRL( certInfoPtr, sigCheckKey );
			return( status );
			}
		if( type == RESOURCE_TYPE_KEYSET )
			{
			BYTE issuerID[ CRYPT_MAX_HASHSIZE ];

			/* Generate the issuerID for this cert and check whether it's
			   present in the CRL */
			status = generateCertID( certInfoPtr->issuerName, 
				certInfoPtr->serialNumber, certInfoPtr->serialNumberLength,
				issuerID );
			if( cryptStatusOK( status ) )
				status = getKeyFromID( sigCheckKey, NULL, issuerID,
									   ( void * ) CRYPT_UNUSED, NULL );
			return( status );
			}
		}

	/* If it's a cert chain, it's a (complex) self-signed object containing
	   more than one cert so we need a special function to check the entire
	   chain */
	if( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN )
		{
		/* Since it's self-signed, the caller shouldn't be passing in a sig
		   check key */
		if( sigCheckKey != CRYPT_UNUSED )
			return( CRYPT_BADPARM2 );

		status = checkCertChain( certInfoPtr );
		return( status );
		}

	/* If it's a self-signed cert, we can check the signature without
	   requiring a sig check key because it's signed with the certs own key */
	if( sigCheckKey == CRYPT_UNUSED && certInfoPtr->selfSigned )
		{
		issuerCertInfoPtr = certInfoPtr;	/* Issuer = subject */

		/* Get the context from the subject (= issuer) certificate */
		cryptContext = certInfoPtr->iCryptContext;
		if( cryptContext == CRYPT_ERROR )
			return( CRYPT_BADPARM1 );
		}
	else
		{
		/* If we've been given a sig.check object, it has to be a context or
		   cert */
		if( type != RESOURCE_TYPE_CRYPT && type != RESOURCE_TYPE_CERTIFICATE )
			return( CRYPT_BADPARM2 );

		/* The signature check key may be a certificate or a context.  If
		   it's a cert, we get the issuer cert info and extract the context
		   from it before continuing */
		if( type == RESOURCE_TYPE_CERTIFICATE )
			{
			/* Get the context from the issuer certificate */
			status = krnlSendMessage( sigCheckKey, RESOURCE_MESSAGE_GETDATA,
								&cryptContext, RESOURCE_MESSAGE_DATA_CONTEXT,
								CRYPT_BADPARM2 );
			if( cryptStatusError( status ) )
				return( status );

			/* Lock the issuer certificate info */
			getCheckInternalResource2( sigCheckKey, issuerCertInfoPtr,
									   RESOURCE_TYPE_CERTIFICATE, certInfoPtr );
			}
		else
			{
			CRYPT_CERTIFICATE localCert;

			cryptContext = sigCheckKey;

			/* It's a context, we may have a certificate present in it so we
			   try to extract that and use it as the issuer certificate if
			   possible.  If the issuer cert isn't present this isn't an
			   error, since it could be just a raw context.  For this reason
			   we don't check the return code since the only actual error we
			   could check for is CRYPT_SIGNALLED, which will be caught by the
			   next line of code */
			krnlSendMessage( sigCheckKey, RESOURCE_MESSAGE_GETDATA,
							 &localCert, RESOURCE_MESSAGE_DATA_CERTIFICATE, 0 );
			getCheckInternalResource2( localCert, issuerCertInfoPtr,
									   RESOURCE_TYPE_CERTIFICATE, certInfoPtr );
			}
		}

	/* If there's an issuer certificate present, check the validity of the
	   subject cert based on it */
	if( issuerCertInfoPtr != NULL )
		{
		status = checkCert( certInfoPtr, issuerCertInfoPtr );
		if( issuerCertInfoPtr != certInfoPtr )
			/* It's not a self-signed cert, unlock the issuer cert */
			unlockResource( issuerCertInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Check the signature */
	return( checkX509signature( certInfoPtr->certificate, NULL, NULL,
								cryptContext ) );
	}
