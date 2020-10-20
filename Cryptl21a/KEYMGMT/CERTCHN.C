/****************************************************************************
*																			*
*					  Certificate Chain Management Routines					*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

/* This module and certchk.c implements the following PKIX checks (* =
   unhandled, see the code comments.  Currently only policy mapping is
   unhandled):

	General:

	(a) Verify the basic certificate information:
		(1) The certificate signature is valid.
		(2a) The certificate has not expired.
		(2b) If present, the private key usage period is satisfied.
		(3) The certificate has not been revoked.
		(4a) The subject and issuer name chains correctly.
		(4b) If present, the subjectAltName and issuerAltName chains
			 correctly.

	NameConstraints:

	(b) Verify that the subject name or critical subjectAltName is consistent
		with the constrained subtrees.

	(c) Verify that the subject name or critical subjectAltName is consistent
		with the excluded subtrees.

	Policy Constraints:

	(d) Verify that policy info.is consistent with the initial policy set:
		(1) If the explicit policy state variable is less than or equal to n,
			a policy identifier in the certificate must be in initial policy
			set.
*		(2) If the policy mapping variable is less than or equal to n, the
			policy identifier may not be mapped.

	(e) Verify that policy info.is consistent with the acceptable policy set:
		(1) If the policies extension is marked critical, the policies
			extension must lie within the acceptable policy set.
		(2) The acceptable policy set is assigned the resulting intersection
			as its new value.

	(g) Verify that the intersection of the acceptable policy set and the
		initial policy set is non-null (this is covered by chaining of e(1)).

	Other Constraints:

	(h) Recognize and process any other critical extension present in the
		certificate.

	(i) Verify that the certificate is a CA certificate.

	Update of state:

	(j) If permittedSubtrees is present in the certificate, set the
		constrained subtrees state variable to the intersection of its
		previous value and the value indicated in the extension field.

	(k) If excludedSubtrees is present in the certificate, set the excluded
		subtrees state variable to the union of its previous value and the
		value indicated in the extension field.

	(l) If a policy constraints extension is included in the certificate,
		modify the explicit policy and policy mapping state variables as
		follows:
		(1) If requireExplicitPolicy is present and has value r, the explicit
			policy state variable is set to the minimum of (a) its current
			value and (b) the sum of r and n (the current certificate in the
			sequence).
*		(2) If inhibitPolicyMapping is present and has value q, the policy
			mapping state variable is set to the minimum of (a) its current
			value and (b) the sum of q and n (the current certificate in the
			sequence) */

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "asn1.h"
  #include "asn1keys.h"
  #include "asn1objs.h"
  #include "asn1oid.h"
  #include "cert.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1keys.h"
  #include "keymgmt/asn1objs.h"
  #include "keymgmt/asn1oid.h"
  #include "keymgmt/cert.h"
#endif /* Compiler-specific includes */

/* A structure for storing pointers to parent and child (issuer and subject)
   names and key identifiers for certs */

typedef struct {
	void *issuerDN, *subjectDN;
	int issuerDNsize, subjectDNsize;
	void *subjectKeyIdentifier, *issuerKeyIdentifier;
	int subjectKeyIDsize, issuerKeyIDsize;
	} CERTCHAIN_INFO;

/* Prototypes for functions in lib_sign.c */

int checkX509signature( const void *signedObject, void **object,
						int *objectLength, CRYPT_CONTEXT sigCheckContext );

/* Prototypes for functions in keymgmt/certchk.c */

int checkNameConstraints( CERT_INFO *subjectCertInfoPtr,
						  const ATTRIBUTE_LIST *issuerAttributes,
						  const BOOLEAN matchValue );
int checkPolicyConstraints( CERT_INFO *subjectCertInfoPtr,
							const ATTRIBUTE_LIST *issuerAttributes );

/****************************************************************************
*																			*
*									Utility Routines						*
*																			*
****************************************************************************/

/* Get the location and size of certificate attribute data required for
   chaining */

static void *getChainingAttribute( CERT_INFO *certInfoPtr,
								   const CRYPT_CERTTYPE_TYPE attributeType,
								   int *attributeLength )
	{
	ATTRIBUTE_LIST *attributePtr;

	/* Find the requested attribute and return a pointer to it */
	attributePtr = findAttributeField( certInfoPtr->attributes,
									   attributeType, CRYPT_CERTINFO_NONE );
	if( attributePtr == NULL )
		{
		*attributeLength = 0;
		return( NULL );
		}
	*attributeLength = attributePtr->dataLength;
	return( ( attributePtr->data != NULL ) ? attributePtr->data : attributePtr->smallData );
	}

/* Free a cert chain */

static void freeCertChain( CRYPT_CERTIFICATE *iCertChain,
						   const int certChainSize )
	{
	int i;

	for( i = 0; i < certChainSize; i++ )
		{
		krnlSendNotifier( iCertChain[ i ], RESOURCE_IMESSAGE_DESTROY );
		iCertChain[ i ] = CRYPT_ERROR;
		}
	}

/* Build up the parent/child pointers for a cert chain */

static int buildCertChainInfo( CERTCHAIN_INFO *certChainInfo,
							   CRYPT_CERTIFICATE *iCertChain,
							   const int certChainSize )
	{
	int i;

	/* Extract the subject and issuer DN's and key identifiers from each
	   certificate.  Maintaining an external pointer into the internal
	   structure is safe since the objects are reference-counted and won't be
	   destroyed until the encapsulating cert is destroyed */
	for( i = 0; i < certChainSize; i++ )
		{
		CERT_INFO *certChainPtr;

		getCheckInternalResource( iCertChain[ i ], certChainPtr,
								  RESOURCE_TYPE_CERTIFICATE );
		certChainInfo[ i ].subjectDN = certChainPtr->subjectDNptr;
		certChainInfo[ i ].issuerDN = certChainPtr->issuerDNptr;
		certChainInfo[ i ].subjectDNsize = certChainPtr->subjectDNsize;
		certChainInfo[ i ].issuerDNsize = certChainPtr->issuerDNsize;
		certChainInfo[ i ].subjectKeyIdentifier = \
			getChainingAttribute( certChainPtr, CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER,
								  &certChainInfo[ i ].subjectKeyIDsize );
		certChainInfo[ i ].issuerKeyIdentifier = \
			getChainingAttribute( certChainPtr, CRYPT_CERTINFO_AUTHORITY_KEYIDENTIFIER,
								  &certChainInfo[ i ].issuerKeyIDsize );
		unlockResource( certChainPtr );
		}

	return( CRYPT_OK );
	}

/* Find the leaf node in a (possibly unordered) cert chain by walking down
   the chain as far as possible.  Returns the position of the leaf node in
   the chain */

static int findLeafNode( const CERTCHAIN_INFO *certChainInfo,
						 const int certChainSize )
	{
	BOOLEAN certUsed[ MAX_CHAINLENGTH ];
	void *currentSubjectDN = certChainInfo[ 0 ].subjectDN;
	int currentSubjectDNsize = certChainInfo[ 0 ].subjectDNsize, i;
	int lastCertPos = 0;

	/* We start our search at the first cert (which is often the leaf cert
	   anyway) */
	memset( certUsed, 0, MAX_CHAINLENGTH * sizeof( BOOLEAN ) );
	certUsed[ 0 ] = TRUE;

	/* Walk down the chain from the currently selected cert until we can't
	   go any further */
	while( TRUE )
		{
		/* Walk through the certs trying to find one with the current subject
		   DN as its issuer DN */
		for( i = 0; i < certChainSize; i++ )
			if( !certUsed[ i ] && \
				currentSubjectDNsize == certChainInfo[ i ].issuerDNsize && \
				!memcmp( currentSubjectDN, certChainInfo[ i ].issuerDN,
						 currentSubjectDNsize ) )
				break;
		if( i == certChainSize )
			/* We've found a leaf cert, exit */
			break;

		/* There's another cert below the current one in the chain, mark the
		   current one as used and move on to the lower one */
		certUsed[ lastCertPos ] = TRUE;
		currentSubjectDN = certChainInfo[ i ].subjectDN;
		currentSubjectDNsize = certChainInfo[ i ].subjectDNsize;
		lastCertPos = i;
		}

	return( lastCertPos );
	}

/* Sort the issuer certs in a cert chain, discarding any unnecessary issuer
   certs (the -1th cert is the end user cert, which isn't part of the
   ordering process).  The start point is given either by certChainStart
   (used when no leaf cert is present) or through the parent DN for the leaf
   cert (used to identify the cert chain start).  Returns the length of the
   ordered chain.

   This code currently relies on subject/issuer name chaining rather than
   key identifiers since nothing seems to require them in order to work and
   it's still too risky to rely on them in the garbled messes which are
   floating around out there */

static int sortCertChain( CRYPT_CERTIFICATE *iCertChain,
						  CERTCHAIN_INFO *certChainInfo,
						  const int certChainSize,
						  const CRYPT_CERTIFICATE certChainStart,
						  void *parentDNptr, int parentDNsize )
	{
	CRYPT_CERTIFICATE orderedChain[ MAX_CHAINLENGTH ];
	CRYPT_CERTIFICATE lastCert = CRYPT_ERROR;
	int orderedChainIndex = 0, i = 0;

	/* If there's a predefined chain start, copy it over and prepare to look
	   for the next cert up in the chain */
	if( certChainStart != CRYPT_UNUSED )
		{
		orderedChain[ orderedChainIndex++ ] = lastCert = certChainStart;
		parentDNptr = certChainInfo[ i ].issuerDN;
		parentDNsize = certChainInfo[ i ].issuerDNsize;
		memset( &certChainInfo[ i ], 0, sizeof( CERTCHAIN_INFO ) );
		}

	/* Build an ordered chain of certs from the leaf to the root */
	while( i != certChainSize )
		{
		/* Find the cert with the current issuer name as its subject name */
		for( i = 0; i < certChainSize; i++ )
			if( certChainInfo[ i ].subjectDN != NULL && \
				parentDNsize == certChainInfo[ i ].subjectDNsize && \
				!memcmp( parentDNptr, certChainInfo[ i ].subjectDN,
						 parentDNsize ) )
				break;

		/* If we haven't reached the root yet, move the certs to the ordered
		   chain and prepare to find the parent of this cert */
		if( i != certChainSize )
			{
			orderedChain[ orderedChainIndex++ ] = lastCert = iCertChain[ i ];
			parentDNptr = certChainInfo[ i ].issuerDN;
			parentDNsize = certChainInfo[ i ].issuerDNsize;
			memset( &certChainInfo[ i ], 0, sizeof( CERTCHAIN_INFO ) );
			}
		}

	/* If there's only a single issuer cert present and it's not the pre-
	   defined chain start, copy it over */
	if( certChainSize == 1 && lastCert != certChainStart )
#if defined( __WIN32__ ) && defined( _MSC_VER ) && !defined( NDEBUG )
{
puts( "\nGot chain size == 1.\n" );		/*!!!!!!!!!!*/
		orderedChain[ orderedChainIndex++ ] = lastCert = iCertChain[ 0 ];
}
#endif /* Win32 VC++ debug mode */

	/* If there are any certs left, they're not needed for anything so we can
	   free the resources */
	for( i = 0; i < certChainSize; i++ )
		if( certChainInfo[ i ].subjectDN != NULL )
			krnlSendNotifier( iCertChain[ i ], RESOURCE_IMESSAGE_DECREFCOUNT );

	/* Replace the existing chain with the ordered version */
	memcpy( iCertChain, orderedChain,
			sizeof( CRYPT_CERTIFICATE ) * MAX_CHAINLENGTH );

	return( orderedChainIndex );
	}

/* Copy a cert chain into a certificate object and canonicalise the chain by
   ordering the certs in a cert chain from the leaf cert up to the root */

int copyCertChain( CERT_INFO *certInfoPtr, const CRYPT_HANDLE certChain )
	{
	CRYPT_CERTIFICATE iChainCert;
	CERT_INFO *chainCertInfoPtr;
	CERTCHAIN_INFO certChainInfo[ MAX_CHAINLENGTH ];
	int i, status;

	/* Extract the base certificate from the chain and copy it over.  Note
	   that we pass in the cert chain handle for the copy since the internal
	   cert won't be visible */
	status = krnlSendMessage( certChain, RESOURCE_MESSAGE_GETDATA,
							  &iChainCert, RESOURCE_MESSAGE_DATA_CERTIFICATE,
							  CRYPT_BADPARM2 );
	if( cryptStatusError( status ) )
		return( status );
	getCheckInternalResource( iChainCert, chainCertInfoPtr,
							  RESOURCE_TYPE_CERTIFICATE );
	krnlSendNotifier( iChainCert, RESOURCE_IMESSAGE_INCREFCOUNT );
	certInfoPtr->certChain[ certInfoPtr->certChainEnd++ ] = iChainCert;

	/* Copy the rest of the chain.  Because we're about to canonicalise it
	   (which reorders the certs and deletes unused ones) we copy individual
	   certs over rather than copying only the base cert and relying on the
	   chain held in that */
	for( i = 0; i < chainCertInfoPtr->certChainEnd; i++ )
		{
		certInfoPtr->certChain[ certInfoPtr->certChainEnd++ ] = \
										chainCertInfoPtr->certChain[ i ];
		krnlSendNotifier( chainCertInfoPtr->certChain[ i ],
						  RESOURCE_IMESSAGE_INCREFCOUNT );
		}
	unlockResource( chainCertInfoPtr );

	/* Extract the chaining info from each certificate and use it to sort the
	   chain.  Since we know what the leaf cert is and since the connection
	   from it to the information in the certinfo structure may not exist yet
	   if the certinfo structure contains an unsigned cert, we feed in the
	   leaf cert and omit the parent DN pointer */
	status = buildCertChainInfo( certChainInfo, certInfoPtr->certChain,
								 certInfoPtr->certChainEnd );
	if( cryptStatusError( status ) )
		return( status );
	status = sortCertChain( certInfoPtr->certChain, certChainInfo,
							certInfoPtr->certChainEnd, iChainCert, NULL, 0 );
	if( cryptStatusError( status ) )
		return( status );

	certInfoPtr->certChainEnd = status;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Verify a Certificate Chain						*
*																			*
****************************************************************************/

/* A special status to indicate that we've reached the end of a cert chain */

#define CHAIN_END	-1000

/* Get the next certificate down the chain.  Returns CHAIN_END if no more
   certs present */

static int getNextCert( const CERT_INFO *certInfoPtr,
						CERT_INFO **certChainPtr, const int certChainIndex )
	{
	if( certChainIndex >= 0 )
		{
		getCheckInternalResource( certInfoPtr->certChain[ certChainIndex ],
								  *certChainPtr, RESOURCE_TYPE_CERTIFICATE );
		return( CRYPT_OK );
		}
	if( certChainIndex == -1 )
		{
		/* The -1th cert is the leaf itself */
		*certChainPtr = ( CERT_INFO * ) certInfoPtr;
		return( CRYPT_OK );
		}

	*certChainPtr = NULL;
	return( CHAIN_END );
	}

/* Check constraints along a cert chain.  There are three types of
   constraints which can cover multiple certs: path constraints, name
   constraints, and policy constraints.

   Path constraints are easiest to check, just make sure the number of certs
   from the issuer to the leaf is less than the constraint length.

   Name constraints are a bit more difficult, the abstract description
   requires building and maintaining a (potentially enormous) name constraint
   tree which is applied to each cert in turn as it is processed, however
   since name constraints are practically nonexistant and chains are short
   it's more efficient to walk down the cert chain when a constraint is
   encountered and check each cert in turn, which avoids having to maintain
   massive amounts of state information and is no less efficient than a
   single monolithic state comparison.

   Policy constraints are hardest of all because, with the complex mishmash
   of policies, policy constraints, qualifiers, and mappings it turns out
   that noone actually knows how to apply them.  The ambiguity of name
   constraints when applied to altNames is bad enough, with a 50/50 split in
   PKIX about whether it should be an AND or OR operation, and whether a DN
   constraint applied to a subjectName or altName or both, with policy
   constraints it's even worse and noone seems to be able to agree on what to
   do with them.  For this reason we should leave this particular rathole for
   someone else to fall into, but to claim buzzword-compliance to PKIX we
   need to implement this checking (although we don't handle the weirder
   constraints on policies, which have never been seen in the wild, yet) */

static int checkConstraints( CERT_INFO *certInfoPtr,
							 const CERT_INFO *issuerCertPtr,
							 int *subjectCertIndex )
	{
	ATTRIBUTE_LIST *attributeListPtr, *nameAttributeListPtr;
	ATTRIBUTE_LIST *policyAttributeListPtr;
	int certIndex = *subjectCertIndex, status = CRYPT_OK;

	/* If there's a path length constraint present, check that it's
	   satisfied */
	attributeListPtr = findAttributeField( issuerCertPtr->attributes,
					CRYPT_CERTINFO_PATHLENCONSTRAINT, CRYPT_CERTINFO_NONE );
	if( attributeListPtr != NULL && !issuerCertPtr->selfSigned && \
		attributeListPtr->value > *subjectCertIndex + 1 )
		{
		setCertError( certInfoPtr, CRYPT_CERTINFO_PATHLENCONSTRAINT,
					  CRYPT_CERTERROR_ISSUERCONSTRAINT );
		return( CRYPT_INVALID );
		}

	/* If there's a name or policy constraint present, check that it's
	   satisfied for all certs below this one.  We don't have to perform this
	   check if the constraint appears in the 0-th cert since the check for
	   (leaf, [0]) is performed by checkCert() */
	if( *subjectCertIndex >= 0 && !issuerCertPtr->selfSigned && \
		( ( nameAttributeListPtr = findAttribute( issuerCertPtr->attributes, \
							CRYPT_CERTINFO_NAMECONSTRAINTS ) ) != NULL ) || \
		( ( policyAttributeListPtr = findAttribute( issuerCertPtr->attributes, \
							CRYPT_CERTINFO_POLICYCONSTRAINTS ) ) != NULL ) )
		{
		const BOOLEAN hasExcludedSubtrees = findAttribute( nameAttributeListPtr, \
								CRYPT_CERTINFO_EXCLUDEDSUBTREES ) != NULL;
		const BOOLEAN hasPermittedSubtrees = findAttribute( nameAttributeListPtr, \
								CRYPT_CERTINFO_PERMITTEDSUBTREES ) != NULL;
		const BOOLEAN hasPolicy = findAttribute( policyAttributeListPtr, \
								CRYPT_CERTINFO_CERTPOLICYID ) != NULL;
		BOOLEAN requireExplicitPolicyPresent = FALSE;
		int requireExplicitPolicyLevel = CRYPT_ERROR;
		CERT_INFO *subjectCertPtr;

		/* Check whether there's a requireExplicitPolicy attribute.  The
		   handling of this is very ambiguous since other parts of the path
		   validation requirements stipulate that policies should be checked
		   anyway (even if requireExplicitPolicy isn't set), and noone knows
		   what to do if multiple requireExplicitPolicy settings are present
		   in a chain (for example due to reparenting).  This implementation
		   handles it by returning an error if a second requireExplicitPolicy
		   attribute is found which contradicts the first one */
		attributeListPtr = findAttribute( policyAttributeListPtr,
									CRYPT_CERTINFO_REQUIREEXPLICITPOLICY );
		if( attributeListPtr != NULL )
			{
			requireExplicitPolicyLevel = ( int ) attributeListPtr->value;
			requireExplicitPolicyPresent = TRUE;
			}

		/* Walk down the chain checking each cert against the issuer */
		do
			{
			/* Get the next cert in the chain */
			certIndex--;
			status = getNextCert( certInfoPtr, &subjectCertPtr, certIndex );
			if( status == CHAIN_END )
				break;

			/* If there's a second policy constraint present further down the
			   chain, make sure it doesn't contradict the current one */
			attributeListPtr = findAttribute( certInfoPtr->attributes,
									CRYPT_CERTINFO_REQUIREEXPLICITPOLICY );
			if( attributeListPtr != NULL && requireExplicitPolicyPresent && \
				attributeListPtr->value != requireExplicitPolicyLevel )
				{
				setCertError( certInfoPtr, CRYPT_CERTINFO_REQUIREEXPLICITPOLICY,
							  CRYPT_CERTERROR_ISSUERCONSTRAINT );
				status = CRYPT_INVALID;
				break;
				}

			/* If there's a requireExplicitPolicy skip count, decrement it
			   for each cert */
			if( requireExplicitPolicyLevel != CRYPT_ERROR )
				requireExplicitPolicyLevel--;

			/* Check that the current cert obeys the constraints set by the
			   issuer */
			if( hasExcludedSubtrees && \
				cryptStatusError( checkNameConstraints( subjectCertPtr,
											nameAttributeListPtr, TRUE ) ) )
				status = CRYPT_INVALID;
			if( hasPermittedSubtrees && \
				cryptStatusError( checkNameConstraints( subjectCertPtr,
											nameAttributeListPtr, FALSE ) ) )
				status = CRYPT_INVALID;
			if( hasPolicy && requireExplicitPolicyLevel == CRYPT_ERROR && \
				cryptStatusError( checkPolicyConstraints( subjectCertPtr,
											policyAttributeListPtr ) ) )
				status = CRYPT_INVALID;
			unlockResource( subjectCertPtr );
			}
		while( cryptStatusOK( status ) );
		}
	if( status == CRYPT_OK || status == CHAIN_END )
		return( CRYPT_OK );

	/* Remember which cert in the chain caused the problem */
	*subjectCertIndex = certIndex;
	return( status );
	}

/* Walk down a chain checking each certificate */

int checkCertChain( CERT_INFO *certInfoPtr )
	{
	CRYPT_CONTEXT iCryptContext;
	CERT_INFO *issuerCertPtr = certInfoPtr, *subjectCertPtr;
	BOOLEAN isTrusted = TRUE;
	int certIndex = certInfoPtr->certChainEnd - 1, i, status = CRYPT_OK;

	/* If the leaf cert is implicitly trusted, there's nothing to do */
	if( !cryptStatusError( findTrustInfo( certInfoPtr->subjectDNptr,
									certInfoPtr->subjectDNsize, FALSE ) ) )
		return( CRYPT_OK );

	/* If the leaf certs issuer is implicitly trusted, we only need to check
	   the signature on the leaf cert */
	iCryptContext = findTrustInfo( certInfoPtr->issuerDNptr,
								   certInfoPtr->issuerDNsize, TRUE );
	if( !cryptStatusError( iCryptContext ) )
		certIndex = CRYPT_ERROR;	/* No need to check the cert chain */
	else
		{
		/* Walk up the chain from the leaf certs issuer to the root checking
		   for an implicitly trusted cert */
		for( i = 0; i <= certIndex; i++ )
			{
			getCheckInternalResource( certInfoPtr->certChain[ i ],
									  issuerCertPtr, RESOURCE_TYPE_CERTIFICATE );
			iCryptContext = findTrustInfo( issuerCertPtr->issuerDNptr,
										   issuerCertPtr->issuerDNsize, TRUE );
			if( !cryptStatusError( iCryptContext ) )
				break;
			if( i != certIndex )
				unlockResource( issuerCertPtr );
			}
		certIndex = i;	/* Remember how far we got */

		/* If we didn't end up at an implicitly trusted cert, check whether
		   we should implicitly trust a self-signed root */
		if( cryptStatusError( iCryptContext ) )
			if( issuerCertPtr->selfSigned && \
				getOptionNumeric( CRYPT_OPTION_CERT_TRUSTCHAINROOT ) )
				/* There's a self-signed root present but it's not implicitly
				   trusted, continue without the trust flag set */
				isTrusted = FALSE;
			else
				{
				/* We didn't end up at an implicitly or explicitly trusted
				   key, either there's a missing link in the chain
				   (CRYPT_CERTERROR_STUART) or the root cert isn't trusted */
				certInfoPtr->certChainPos = certIndex;
				if( issuerCertPtr->selfSigned )
					{
					/* We got a cert but it's not trusted */
					setCertError( issuerCertPtr, CRYPT_CERTINFO_TRUSTED,
								  CRYPT_CERTERROR_ABSENT );
					}
				else
					/* There's a missing link in the chain */
					setCertError( certInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
								  CRYPT_CERTERROR_ABSENT );
				unlockResource( issuerCertPtr );

				return( CRYPT_INVALID );
				}
		}

	/* Walk down the chain from the trusted cert checking each link in turn */
	subjectCertPtr = ( CERT_INFO * ) issuerCertPtr;
	do
		{
		/* If the issuing cert for this one isn't implicitly trusted, check
		   the chaining from issuer to subject */
		if( !isTrusted )
			{
			iCryptContext = issuerCertPtr->iCryptContext;
			status = checkCert( subjectCertPtr, issuerCertPtr );
			}
		isTrusted = FALSE;

		/* Check the signature on the subject cert unless it's a data-only
		   cert for which there isn't a context present.  This is OK since
		   the only time we can have a data-only chain is when we're reading
		   from an (implicitly trusted) private key store */
		if( cryptStatusOK( status ) && iCryptContext != CRYPT_ERROR )
			status = checkX509signature( subjectCertPtr->certificate, NULL,
										 NULL, iCryptContext );

		/* Check any constraints the issuer cert may place on the rest of the
		   chain */
		if( cryptStatusOK( status ) && issuerCertPtr != subjectCertPtr )
			status = checkConstraints( certInfoPtr, issuerCertPtr,
									   &certIndex );

		/* Move on to the next cert */
		if( issuerCertPtr != subjectCertPtr )
			unlockResource( issuerCertPtr );
		issuerCertPtr = subjectCertPtr;
		certIndex--;
		}
	while( cryptStatusOK( status ) && \
		   ( status = getNextCert( certInfoPtr, &subjectCertPtr,
								   certIndex ) ) == CRYPT_OK );
	if( status != CHAIN_END )
		{
		/* We stopped before we processed all the certs in the chain, if
		   the last cert we processed wasn't the leaf, unlock it and
		   select the one which caused the problem */
		if( issuerCertPtr != certInfoPtr )
			unlockResource( issuerCertPtr );
		certInfoPtr->certChainPos = certIndex + 1;
		}
	else
		/* We successfully reached the end of the chain */
		status = CRYPT_OK;

	return( status );
	}

/****************************************************************************
*																			*
*						Read Certificate-bagging Records					*
*																			*
****************************************************************************/

/* Read a collection of certs in a cert chain into a cert object */

static int readCerts( STREAM *stream, CRYPT_CERTIFICATE *iLeafCert,
					  CRYPT_CONTEXT *iLeafContext, const int length )
	{
	CERTCHAIN_INFO certChainInfo[ MAX_CHAINLENGTH ];
	CRYPT_CERTIFICATE iCertChain[ MAX_CHAINLENGTH ];
	CERT_INFO *certChainPtr;
	const void *pubKeyProcessingFlag = ( iLeafContext != NULL ) ? ( void * ) CRYPT_UNUSED : NULL;
	const int endPos = sMemSize( stream ) + length;
	void *parentDNptr;
	int certChainEnd = 0, leafNodePos, parentDNsize, status;

	/* Read the collection of certs into cert objects.  We allow for a bit of
	   slop for software which gets the length encoding wrong by a few
	   bytes */
	while( !length || sMemSize( stream ) <= endPos - MIN_ATTRIBUTE_SIZE )
		{
		CRYPT_CERTIFICATE iCryptCert;

		/* Make sure we don't overflow the chain */
		if( certChainEnd >= MAX_CHAINLENGTH )
			{
			freeCertChain( iCertChain, certChainEnd );
			return( CRYPT_OVERFLOW );
			}

		/* Read the next cert and add it to the chain.  The
		   pubKeyProcessingFlag can have one of two values, usually this is
		   NULL to indicate that we want to create a standard cert object
		   with a context attached.  However it can also be set to
		   CRYPT_UNUSED to indicate that we want to eventually create a data-
		   only cert, but don't want to decode the public key info yet
		   because we don't know at this stage which cert in the chain is the
		   leaf cert which we want the public key for.  Once we've read the
		   entire chain and know which cert is the leaf, we can go back and
		   decode the public key information for it */
		status = importCert( sMemBufPtr( stream ), &iCryptCert,
							 ( void * ) pubKeyProcessingFlag, TRUE );
		if( cryptStatusError( status ) )
			{
			freeCertChain( iCertChain, certChainEnd );
			return( status );
			}
		sSkip( stream, status );
		iCertChain[ certChainEnd++ ] = iCryptCert;

		/* If it's encoded using the indefinite form and we find the EOC
		   octets, exit */
		if( !length && checkEOC( stream ) )
			break;
		}

	/* We've now got a collection of certs in unknown order (although in most
	   cases the first cert is the leaf).  Extract the chaining info and
	   search the chain for the leaf node */
	status = buildCertChainInfo( certChainInfo, iCertChain, certChainEnd );
	if( cryptStatusError( status ) )
		{
		freeCertChain( iCertChain, certChainEnd );
		return( status );
		}
	leafNodePos = findLeafNode( certChainInfo, certChainEnd );

	/* Now that we have the leaf node, clear its entry in the chain (to make
	   sure it isn't used for further processing), order the remaining certs
	   up to the root, and discard any unneeded certs */
	*iLeafCert = iCertChain[ leafNodePos ];
	parentDNptr = certChainInfo[ leafNodePos ].issuerDN;
	parentDNsize = certChainInfo[ leafNodePos ].issuerDNsize;
	memset( &certChainInfo[ leafNodePos ], 0, sizeof( CERTCHAIN_INFO ) );
	status = sortCertChain( iCertChain, certChainInfo, certChainEnd,
							CRYPT_UNUSED, parentDNptr, parentDNsize );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( *iLeafCert, RESOURCE_IMESSAGE_DECREFCOUNT );
		freeCertChain( iCertChain, certChainEnd );
		return( status );
		}
	certChainEnd = status;

	/* Finally, we've got the leaf cert and a chain up to the root.  Make the
	   leaf a cert-chain type, copy in the chain, and decode the public key
	   information if this is a data-only cert */
	getCheckInternalResource( *iLeafCert, certChainPtr,
							  RESOURCE_TYPE_CERTIFICATE );
	memcpy( certChainPtr->certChain, iCertChain,
			certChainEnd * sizeof( CRYPT_CERTIFICATE ) );
	certChainPtr->certChainEnd = certChainEnd;
	certChainPtr->type = CRYPT_CERTTYPE_CERTCHAIN;
	certChainPtr->selfSigned = TRUE;	/* Cert chains count as self-signed */
	if( iLeafContext != NULL )
		{
		STREAM stream;

		sMemConnect( &stream, certChainPtr->publicKeyInfo, STREAMSIZE_UNKNOWN );
		readPublicKey( &stream, iLeafContext );
		sMemDisconnect( &stream );
		}
	unlockResource( certChainPtr );

	return( CRYPT_OK );
	}

/* Read certificate chain/sequence information.  If iCryptContext is NULL,
   we create a standard cert chain in iCryptCert.  If iCryptContext is non-
   NULL, we create a data-only cert chain in iCryptCert and a public-key
   context containing the leaf key in iCryptContext, to which the cert chain
   will later be attached */

int readCertChain( STREAM *stream, CRYPT_CERTIFICATE *iCryptCert,
				   CRYPT_CONTEXT *iCryptContext, CERT_TYPE type )
	{
	BYTE buffer[ 32 ];
	int bufferLength, certSequenceLength;
	long length;

	/* Skip the contentType OID and read the content encapsulation and
	   header if necessary */
	if( type != CERTTYPE_CMS_CERTSET )
		{
		readUniversal( stream );
		if( !checkReadCtag( stream, 0, TRUE ) || \
			cryptStatusError( readLength( stream, &length ) ) || \
			cryptStatusError( readSequence( stream, &certSequenceLength ) ) )
			return( CRYPT_BADDATA );
		}

	/* If it's a PKCS #7 certificate chain, burrow into the inner PKCS #7
	   content */
	if( type == CERTTYPE_CERTCHAIN )
		{
		int value;

		/* Read the version number (1 = PKCS #7 v1.5, 2 = PKCS #7 v1.6,
		   3 = S/MIME with attribute certificate(s)), empty SET OF
		   DigestAlgorithmIdentifier, and ContentInfo header */
		if( cryptStatusError( readShortInteger( stream, &length ) ) || \
											length < 1 || length > 3 || \
			cryptStatusError( readSet( stream, &value ) ) )
			return( CRYPT_BADDATA );
		if( value )
			sSkip( stream, value );

		/* Read the ContentInfo header, contentType OID and the inner content
		   encapsulation */
		if( cryptStatusError( readSequence( stream, &value ) ) )
			length = CRYPT_ERROR;
		else
			length = readRawObject( stream, buffer, &bufferLength, 32,
									BER_OBJECT_IDENTIFIER );
		if( cryptStatusError( length ) || \
			memcmp( buffer, OID_CMS_DATA, bufferLength ) )
			return( CRYPT_BADDATA );
		checkEOC( stream );
		}
	if( type == CERTTYPE_CERTCHAIN || type == CERTTYPE_CMS_CERTSET )
		{
		if( !checkReadCtag( stream, 0, TRUE ) || \
			cryptStatusError( readLength( stream, &length ) ) )
			return( CRYPT_BADDATA );
		certSequenceLength = ( int ) length;
		}

	/* We've finally reached the certificate(s), read the certs into a cert
	   chain */
	return( readCerts( stream, iCryptCert, iCryptContext, certSequenceLength ) );
	}

/****************************************************************************
*																			*
*						Write Certificate-bagging Records					*
*																			*
****************************************************************************/

/* Determine the size of and write a sequence of certificates from a base
   cert up to the root */

static int sizeofCertSequence( const CERT_INFO *certInfoPtr )
	{
	int length = certInfoPtr->certificateSize, i;

	/* Evaluate the size of the issuer certificates in the chain */
	for( i = 0; i < certInfoPtr->certChainEnd; i++ )
		{
		CERT_INFO *certChainPtr;

		getCheckInternalResource( certInfoPtr->certChain[ i ], certChainPtr,
        						  RESOURCE_TYPE_CERTIFICATE );
		length += certChainPtr->certificateSize;
		unlockResource( certChainPtr );
		}

	return( length );
	}

static int writeCertSequence( STREAM *stream, const CERT_INFO *certInfoPtr )
	{
	int i;

	/* Write the current certficate and the associated cert chain up to the
	   root */
	swrite( stream, certInfoPtr->certificate, certInfoPtr->certificateSize );
	for( i = 0; i < certInfoPtr->certChainEnd; i++ )
		{
		CERT_INFO *certChainPtr;

		getCheckInternalResource( certInfoPtr->certChain[ i ], certChainPtr,
        						  RESOURCE_TYPE_CERTIFICATE );
		swrite( stream, certChainPtr->certificate,
				certChainPtr->certificateSize );
		unlockResource( certChainPtr );
		}

	return( sGetStatus( stream ) );
	}

/* Write certificate chain/sequence information:

	CertChain ::= SEQUENCE {
		contentType				OBJECT IDENTIFIER,
										-- signedData or nsCertSequence
		content			  [ 0 ]	EXPLICIT SEQUENCE {
		-------- Begin certificate chain only --------
			version				INTEGER (1),
			digestAlgorithms	SET OF AlgorithmIdentifier,	-- SIZE(0)
			contentInfo			SEQUENCE {
				signedData		OBJECT IDENTIFIER	-- data
				}
			certificates  [ 0 ]	IMPLICIT SET OF {
		-------- End certificate chain only --------
									Certificate
				}
		-------- Begin certificate chain only --------
			}
		signerInfos				SET OF SignerInfo			-- SIZE(0)
		-------- End certificate chain only --------
		} */

int writeCertChain( STREAM *stream, const CERT_INFO *certInfoPtr,
					const BOOLEAN isCertChain )
	{
	const BYTE *outerOID = ( const BYTE * ) ( ( isCertChain ) ? \
									OID_CMS_SIGNEDDATA : OID_NS_CERTSEQ );
	int certSeqLength = sizeofCertSequence( certInfoPtr );
	int innerLength = certSeqLength, length;

	/* Determine how big the encoded cert chain/sequence will be */
	if( isCertChain )
		innerLength = sizeofShortInteger( 1 ) + ( int ) sizeofObject( 0 ) + \
					  ( int ) sizeofObject( sizeofOID( OID_CMS_DATA ) ) + \
					  ( int ) sizeofObject( certSeqLength ) + \
					  ( int ) sizeofObject( 0 );
	length = sizeofOID( outerOID ) + \
			 ( int ) sizeofObject( sizeofObject( innerLength ) );

	/* Write the outer SEQUENCE wrapper and contentType and content wrapper */
	writeSequence( stream, length );
	swrite( stream, outerOID, sizeofOID( outerOID ) );
	writeCtag( stream, 0 );
	writeLength( stream, sizeofObject( innerLength ) );
	writeSequence( stream, innerLength );

	/* If it's a cert chain, write the inner content */
	if( isCertChain )
		{
		writeShortInteger( stream, 1, DEFAULT_TAG );
		writeSet( stream, 0 );
		writeSequence( stream, sizeofOID( OID_CMS_DATA ) );
		swrite( stream, OID_CMS_DATA, sizeofOID( OID_CMS_DATA ) );
		writeCtag( stream, 0 );
		writeLength( stream, certSeqLength );
		}

	/* Write the certificate chain */
	writeCertSequence( stream, certInfoPtr );

	/* If it's a cert chain, write the (empty) signature */
	if( isCertChain )
		writeSet( stream, 0 );

	return( sGetStatus( stream ) );
	}

int sizeofCertSet( const CERT_INFO *certInfoPtr )
	{
	return( ( int ) sizeofObject( sizeofCertSequence( certInfoPtr ) ) );
	}

int writeCertSet( STREAM *stream, const CERT_INFO *certInfoPtr )
	{
	writeCtag( stream, 0 );
	writeLength( stream, sizeofCertSequence( certInfoPtr ) );
	return( writeCertSequence( stream, certInfoPtr ) );
	}
