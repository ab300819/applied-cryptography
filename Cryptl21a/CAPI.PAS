unit Capi;

{------------------------------------------------------------------------------
  Cryptlib - Interface Unit for Delphi (16 and 32-bit).
  Translation of CAPI.h for cryptlib 2.1 Beta 03XX
  FileDate: Monday, March 22 1999 09:19:08 PM, 62122 bytes.
--------------------------------------------------------------------------------
**                                                                            **
**     PLEASE CHECK YOUR VERSION OF CAPI.H BEFORE USING CAPI.PAS              **
**     THIS INTERFACE MODULE IS VALID ONLY FOR A MATCHING CAPI.H !            **
**                                                                            **
--------------------------------------------------------------------------------

  Last modified on March 22, 1999 by W. Gothier (hwg@gmx.de)
  Please mail any comments regarding this Delphi source code to the above address.

  Based on the conversion dated June 26, 1998 by Kevin J Bluck (kbluck@ix.netcom.com)
  Modifications were made due to:
  * changes in capi.h -> similar changes in cryptlib.pas
  * function CryptCheck added for error handling via exceptions
  * problems with Delphi interface for cryptGetPrivateKey -> new function
    created: CryptCachePrivateKey (see below)
  * elimination of some query functions in Beta 0118 used for
    TCryptoServices class -> TCryptoServices eliminated

  Modifications from CAPI standard:
    Delphi does not support non-ordinal enumerated types in the manner of 'C'.
    Any enumerated type defined in CAPI which does not follow simple ordering
    from 0..n-1 must be represented in Delphi as an integer constant instead.
    The following types are so represented as constants instead of enumerations:

      CRYPT_ALGO
      CRYPT_MODE
      CRYPT_CERTINFO_TYPE

    Delphi does not support C-style macros. All CAPI macro defines have been
    implemented as functions.

    The following macros have interface variations:

      cryptInitComponents    --- Takes a pointer to the structure, requires
                                 an additional size parameter, allocates and
                                 zero-inits the structure on the local heap.
      cryptDestroyComponents --- Takes a pointer to the structure, frees the
                                 structure from the local heap.

    C-style reference parameters have been implemented as var parameters.

    Function parameters have been renamed in most cases to provide more useful
    feedback in the code completion tooltips offered by Delphi v.3 and higher.

    'Type' and 'Object' are reserved words in Delphi.  All instances of these
    reserved words as record members and parameters have been modified to a
    non-reserved form.

    Two additional error return constants have been added to support the dynamic
    loading of DLL functions:

      CRYPT_DLLNOTLOADED       = -10000;
      CRYPT_FUNCTIONNOTFOUND   = -10001;

    Several additional functions to determine the type of a return code have been
    added to support the Delphi-style exceptions.
      function CryptIsInternalError (Status: CRET): Boolean;
      function CryptIsParamError (Status: CRET): Boolean;
      function CryptIsResourceError (Status: CRET): Boolean;
      function CryptIsSecurityError (Status: CRET): Boolean;
      function CryptIsHighlevelError (Status: CRET): Boolean;
      function CryptIsDataSetError (Status: CRET): Boolean;
      function CryptIsEnvelopeError (Status: CRET): Boolean;
      function CryptIsDLLError (Status: CRET): Boolean;

    A number of exception types have been defined to facilitate Delphi-style
    exception handling:

      ECryptError
      ECryptInternalError
      ECryptParamError
      ECryptResourceError
      ECryptSecurityError
      ECryptHighlevelError
      ECryptDataSetError
      ECryptEnvelopeError
      ECryptDLLError

    Three additional functions have been defined to facilitate Delphi-style
    exception handling:

      function CryptCheck(Status: CRET): CRET;
      function CryptFunctionCheck(func: string; Status: CRET): CRET;
      function CreateCryptError(Status: CRET): Exception;

    The unit automatically initializes the library and the random-number engine
    on startup, and shuts down the library on termination.  There is no need
    to call CryptInit, CryptAddRandom, or CryptEnd.  The user may call these
    functions if desired with no ill effect, however.  In particular, Win16
    users should call CryptAddRandom for a Slow Poll at some convenient point.
    It is not called here for Win16 because it blocks for a time, and this
    may cause sluggish startup for some apps.

    When updating a private keyset with the certificate, the function
    cryptGetPrivateKey( cryptKeyset, NULL, CRYPT_KEYID_NONE, NULL, NULL )
    must be called in C code. In the Delphi interface, the second parameter is
    a var parameter (called by reference) and you cannot convince the compiler
    to insert nil as parameter. So I decided to add a shortcut for this call
    in Delphi:  CryptCachePrivateKey( cryptKeyset ) does the job.

* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * }


{$A+}  {Set Alignment on}
{$F+}  {Force function calls to FAR}
{$Z+}  {Force all enumeration values to Integer size}


interface

uses Classes, SysUtils;

{* * * * * * * * * * * * * * * * * * * * * * * * *}
{*         Algorithm and Object Constants        *}
{* * * * * * * * * * * * * * * * * * * * * * * * *}

type
  {Fundamental types.}
  CCHAR  = Char;
  PCCHAR = PChar;
  CBYTE  = Byte;
  PCBYTE = ^CBYTE;
  CWORD  = Word;
  PCWORD = ^CWORD;
  CINT   = Integer;
  PCINT  = ^CINT;
  CLONG  = LongInt;
  PCLONG = ^CLONG;
  CPTR   = Pointer;
  CRET   = CINT;

{The encryption algorithms we can use}
type
  CRYPT_ALGO = CINT;

const
  {No encryption.}
  CRYPT_ALGO_NONE               = 0;   {No encryption}

  {Symmetric encryption}
  CRYPT_ALGO_DES                = 1;   {DES}
  CRYPT_ALGO_3DES               = 2;   {Triple DES}
  CRYPT_ALGO_IDEA               = 3;   {IDEA}
  CRYPT_ALGO_CAST               = 4;   {CAST-128}
  CRYPT_ALGO_RC2                = 5;   {RC2}
  CRYPT_ALGO_RC4                = 6;   {RC4}
  CRYPT_ALGO_RC5                = 7;   {RC5}
  CRYPT_ALGO_SAFER              = 8;   {SAFER/SAFER-SK}
  CRYPT_ALGO_BLOWFISH           = 9;   {Blowfish}
  CRYPT_ALGO_SKIPJACK           = 10;  {Skipjack}
  CRYPT_ALGO_GOST               = 11;  {GOST 28147 (not implemented yet)}

  {Public-key encryption}
  CRYPT_ALGO_DH                 = 100; {Diffie-Hellman}
  CRYPT_ALGO_RSA                = 101; {RSA}
  CRYPT_ALGO_DSA                = 102; {DSA}
  CRYPT_ALGO_ELGAMAL            = 103; {ElGamal}

  {Hash algorithms}
  CRYPT_ALGO_MD2                = 200; {MD2}
  CRYPT_ALGO_MD4                = 201; {MD4}
  CRYPT_ALGO_MD5                = 202; {MD5}
  CRYPT_ALGO_SHA                = 203; {SHA/SHA1}
  CRYPT_ALGO_RIPEMD160          = 204; {RIPE-MD 160}
  CRYPT_ALGO_MDC2               = 205; {MDC-2}

  {MAC algorithms}
  CRYPT_ALGO_HMAC_MD5           = 300; {HMAC-MD5}
  CRYPT_ALGO_HMAC_SHA           = 301; {HMAC-SHA}
  CRYPT_ALGO_HMAC_RIPEMD160     = 302; {HMAC-RIPEMD-160}

{ Vendors may want to use their own algorithms which aren't part of the
  general cryptlib suite.  The following values are for vendor-defined
  algorithms, and can be used just like the named algorithm types (it's
  up to the vendor to keep track of what _VENDOR1 actually corresponds
  to) }
{$ifdef USE_VENDOR_ALGOS}
    CRYPT_ALGO_VENDOR1 = 10000;
    CRYPT_ALGO_VENDOR2 = 10001;
    CRYPT_ALGO_VENDOR3 = 10002;

    CRYPT_ALGO_LAST    = CRYPT_ALGO_LAST_MAC;
{$else}
    CRYPT_ALGO_LAST    = CRYPT_ALGO_HMAC_RIPEMD160 + 1;
{$endif} { USE_VENDOR_ALGOS }


  {In order that we can scan through a range of algorithms with
   CryptAlgoAvailable(), we define the following boundary points
   for each algorithm class.}
  CRYPT_ALGO_FIRST_CONVENTIONAL = CRYPT_ALGO_DES;
  CRYPT_ALGO_LAST_CONVENTIONAL  = CRYPT_ALGO_DH - 1;
  CRYPT_ALGO_FIRST_PKC          = CRYPT_ALGO_DH;
  CRYPT_ALGO_LAST_PKC           = CRYPT_ALGO_MD2 - 1;
  CRYPT_ALGO_FIRST_HASH         = CRYPT_ALGO_MD2;
  CRYPT_ALGO_LAST_HASH          = CRYPT_ALGO_HMAC_MD5 - 1;
  CRYPT_ALGO_FIRST_MAC          = CRYPT_ALGO_HMAC_MD5;
  CRYPT_ALGO_LAST_MAC           = CRYPT_ALGO_HMAC_MD5 + 99;


{The encryption modes we can use}
type
  CRYPT_MODE = CINT;

const
  {No mode}
  CRYPT_MODE_NONE               = 0;   {No Mode (hashes and MACs)}

  {Stream cipher mode}
  CRYPT_MODE_STREAM             = 1;   {Stream cipher}

  {Block cipher modes}
  CRYPT_MODE_ECB                = 2;   {Electronic Code Book}
  CRYPT_MODE_CBC                = 3;   {Cipher Block Chaining}
  CRYPT_MODE_CFB                = 4;   {Cipher FeedBack}
  CRYPT_MODE_OFB                = 5;   {Output FeedBack}

  {Public-key cipher modes}
  CRYPT_MODE_PKC                = 100; {Public-Key Cipher}

  {In order that we can scan through a range of modes with
   CryptAlgoModeAvailable(), we define the following boundary
   points for the conventional encryption modes.}
  CRYPT_MODE_FIRST_CONVENTIONAL = CRYPT_MODE_STREAM;
  CRYPT_MODE_LAST_CONVENTIONAL  = CRYPT_MODE_PKC - 1;
  CRYPT_MODE_LAST               = CRYPT_MODE_PKC + 1;

{The encryption object types}
type
  CRYPT_OBJECT_TYPE = (CRYPT_OBJECT_NONE,             {No object type}
                       CRYPT_OBJECT_ENCRYPTED_KEY,    {Conventionally encrypted key}
                       CRYPT_OBJECT_PKCENCRYPTED_KEY, {PKC-encrypted key}
                       CRYPT_OBJECT_KEYAGREEMENT,     {Key agreement information}
                       CRYPT_OBJECT_SIGNATURE,        {Signature}
                       CRYPT_OBJECT_LAST);            {Last possible object type}

{The keyset types}
type
  CRYPT_KEYSET_TYPE = (CRYPT_KEYSET_NONE,      {No keyset type}
                       CRYPT_KEYSET_FILE,      {Generic flat file keyset (PGP, X.509)}
                       CRYPT_KEYSET_HTTP,      {HTTP'd file}
                       CRYPT_KEYSET_LDAP,      {LDAP directory service}
                       CRYPT_KEYSET_SMARTCARD, {Smart card key carrier}
                       CRYPT_KEYSET_ODBC,      {Generic ODBC interface}
                       CRYPT_KEYSET_BSQL,      {BSQL RDBMS}
                       CRYPT_KEYSET_MSQL,      {mSQL RDBMS}
                       CRYPT_KEYSET_MYSQL,     {MySQL RDBMS}
                       CRYPT_KEYSET_ORACLE,    {Oracle RDBMS}
                       CRYPT_KEYSET_POSTGRES,  {Postgres RDBMS}
                       CRYPT_KEYSET_RAIMA,     {Raima Velocis RDBMS}
                       CRYPT_KEYSET_SOLID,     {Solid RDBMS}
                       CRYPT_KEYSET_LAST);     {Last possible keyset type}
const
  { Useful defines used internally for range checking }
                       CRYPT_FIRST_RDBMS = CRYPT_KEYSET_ODBC;
                       CRYPT_LAST_RDBMS  = PRED(CRYPT_KEYSET_LAST);

{ The crypto device types }

type
  CRYPT_DEVICE_TYPE = (CRYPT_DEVICE_NONE,      {No crypto device}
                       CRYPT_DEVICE_CEI,       {CE Infosys DES/3DES crypto card}
                       CRYPT_DEVICE_FORTEZZA,  {Fortezza card}
                       CRYPT_DEVICE_PKCS11,    {PKCS #11 crypto token}
                       CRYPT_DEVICE_SMARTCARD, {Cryptographic smart card}

                       CRYPT_DEVICE_LAST);     {Last possible crypto device type}

{ The certificate object types }
type
  CRYPT_CERTTYPE_TYPE = (CRYPT_CERTTYPE_NONE,       {No certificate type}
                     CRYPT_CERTTYPE_CERTIFICATE,    {Certificate}
                     CRYPT_CERTTYPE_ATTRIBUTE_CERT, {Attribute certificate}
                     CRYPT_CERTTYPE_CERTCHAIN,      {PKCS #7 certificate chain}
                     CRYPT_CERTTYPE_CERTREQUEST,    {PKCS #10 certification request}
                     CRYPT_CERTTYPE_CRL,            {CRL}
                     CRYPT_CERTTYPE_OCSP_REQUEST,   {OCSP request}
                     CRYPT_CERTTYPE_OCSP_RESPONSE,  {OCSP response}
                     CRYPT_CERTTYPE_CMS_ATTRIBUTES, {CMS attributes}
                     CRYPT_CERTTYPE_LAST);          {Last possible cert.type}

{ The certificate export format type, which defines the format in which a
   certificate object is exported }
type
  CRYPT_CERTFORMAT_TYPE =(CRYPT_CERTFORMAT_NONE,                {No certificate format }
                          CRYPT_CERTFORMAT_CERTIFICATE,         {DER-encoded certificate }
                          CRYPT_CERTFORMAT_CERTCHAIN,           {PKCS #7 certificate chain }
                          CRYPT_CERTFORMAT_NS_CERTSEQUENCE,     {Netscape cert.sequence }
                          CRYPT_CERTFORMAT_TEXT_CERTIFICATE,    {base-64 wrapped cert }
                          CRYPT_CERTFORMAT_TEXT_CERTCHAIN,      {base-64 wrapped cert chain }
                          CRYPT_CERTFORMAT_TEXT_NS_CERTSEQUENCE,{base-64 wrapped NS cert seq.}
                          CRYPT_CERTFORMAT_SMIME_CERTIFICATE,   {S/MIME cert.request or cert chain }
                          CRYPT_CERTFORMAT_LAST);               {Last possible cert.format type }


{The key ID types}
type
  CRYPT_KEYID_TYPE = (CRYPT_KEYID_NONE,   {No key ID type}
                      CRYPT_KEYID_NAME,   {Key owner name}
                      CRYPT_KEYID_EMAIL,  {Key owner email address}
                      CRYPT_KEYID_OBJECT, {Encryption object which requires key}
                      CRYPT_KEYID_LAST);  {Last possible key ID type}

  {Data format types}
type
  CRYPT_FORMAT_TYPE = (CRYPT_FORMAT_NONE,     {No format type}
                       CRYPT_FORMAT_CRYPTLIB, {Cryptlib native format}
                       CRYPT_FORMAT_CMS,      {PKCS #7 / S/MIME format}
                       CRYPT_FORMAT_SMIME,    {As CMS with MSG-specific behaviour}
                       CRYPT_FORMAT_PGP,      {PGP format}
                       CRYPT_FORMAT_SSH,      {SSH format}
                       CRYPT_FORMAT_SSL,      {SSL format}
                       CRYPT_FORMAT_LAST);    {Last possible format type}
const
                       CRYPT_FORMAT_PKCS7 = CRYPT_FORMAT_CMS;

  {Envelope information types}
type
  CRYPT_ENVINFO_TYPE = (
                CRYPT_ENVINFO_NONE,             {No envelope information}

                {Pseudo-information on an envelope or meta-information which is used to
                 control the way data in an envelope is processed}
                CRYPT_ENVINFO_DATASIZE,         {Data size information}
                CRYPT_ENVINFO_COMPRESSION,      {Compression information}
                CRYPT_ENVINFO_CONTENTTYPE,      {Inner CMS content type}
                CRYPT_ENVINFO_DETACHEDSIGNATURE,{Generate CMS detached signature}
                CRYPT_ENVINFO_SIGNATURE,        {Signature check result}
                CRYPT_ENVINFO_CURRENT_COMPONENT,{Env.information cursor management}

                {Resources required for enveloping/deenveloping}
                CRYPT_ENVINFO_PASSWORD,         {User password}
                CRYPT_ENVINFO_KEY,              {Conventional encryption key}
                CRYPT_ENVINFO_SIGNATURE,        {Signature/signature check key}
                CRYPT_ENVINFO_SIGNATURE_EXTRADATA, {Extra information added to CMS sigs}
                CRYPT_ENVINFO_PUBLICKEY,        {PKC encryption key}
                CRYPT_ENVINFO_PRIVATEKEY,       {PKC decryption key}
                CRYPT_ENVINFO_SESSIONKEY,       {Session key}
                CRYPT_ENVINFO_HASH,             {Hash algorithm}
                CRYPT_ENVINFO_MAC,              {MAC key}

                {Keysets used to retrieve keys needed for enveloping/deenveloping}
                CRYPT_ENVINFO_KEYSET_SIGCHECK,  {Signature check keyset}
                CRYPT_ENVINFO_KEYSET_ENCRYPT,   {PKC encryption keyset}
                CRYPT_ENVINFO_KEYSET_DECRYPT,   {PKC decryption keyset}

                CRYPT_ENVINFO_LAST  );   {Last possible envelope key type}
  PCRYPT_ENVINFO_TYPE = ^CRYPT_ENVINFO_TYPE;


{The certificate information types and constants}

type
  CRYPT_CERTINFO_TYPE = CINT;

const
  { No information }
  CRYPT_CERTINFO_NONE                             = 0;    {No certificate information}

  { Pseudo-information on a cert object or meta-information which is used
     to control the way a cert object is processed }
  CRYPT_CERTINFO_SELFSIGNED                       = 1;    {Cert is self-signed}
  CRYPT_CERTINFO_IMMUTABLE                        = 2;    {Cert is signed and immutable}
  CRYPT_CERTINFO_CERTTYPE                         = 3;    {Certificate object type}
  CRYPT_CERTINFO_FINGERPRINT                      = 4;    {Certificate fingerprints}
      CRYPT_CERTINFO_FINGERPRINT_MD5 = CRYPT_CERTINFO_FINGERPRINT;
  CRYPT_CERTINFO_FINGERPRINT_SHA                  = 5;
  CRYPT_CERTINFO_CURRENT_CERTIFICATE              = 6;   {Certificate cursor management}
  CRYPT_CERTINFO_CURRENT_EXTENSION                = 7;
  CRYPT_CERTINFO_CURRENT_FIELD                    = 8;
  CRYPT_CERTINFO_CURRENT_COMPONENT                = 9;   {Extension cursor management}
  CRYPT_CERTINFO_TRUSTED                          = 10;   {Cert is implicitly trusted}

  { General certificate/CRL/cert request information }
  CRYPT_CERTINFO_SERIALNUMBER                     = 11;   {Serial number (read-only)}
  CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO             = 12;   {Public key}
  CRYPT_CERTINFO_USERCERTIFICATE                  = 13;   {User certificate}
      CRYPT_CERTINFO_CERTIFICATE = CRYPT_CERTINFO_USERCERTIFICATE;
  CRYPT_CERTINFO_ISSUERNAME                       = 14;   {Issuer DN (read-only)}
  CRYPT_CERTINFO_VALIDFROM                        = 15;   {Cert valid from time}
  CRYPT_CERTINFO_VALIDTO                          = 16;   {Cert valid to time}
  CRYPT_CERTINFO_SUBJECTNAME                      = 17;   {Subject DN}
  CRYPT_CERTINFO_ISSUERUNIQUEID                   = 18;   {Issuer unique ID (read-only)}
  CRYPT_CERTINFO_SUBJECTUNIQUEID                  = 19;   {Subject unique ID (read-only)}
  CRYPT_CERTINFO_CERTREQUEST                      = 20;   {Cert.request (DN + public key)}
  CRYPT_CERTINFO_THISUPDATE                       = 21;   {CRL current update time}
  CRYPT_CERTINFO_NEXTUPDATE                       = 22;   {CRL next update time}
  CRYPT_CERTINFO_REVOCATIONDATE                   = 23;   {CRL cert revocation time}

  { X.520 Distinguished Name components.  This is a composite field, the
     DN to be manipulated is selected through the addition of a
     pseudocomponent, and then one of the following is used to access the
     DN components directly }
  CRYPT_CERTINFO_COUNTRYNAME                      = 50;   {countryName}
  CRYPT_CERTINFO_STATEORPROVINCENAME              = 51;   {stateOrProvinceName}
  CRYPT_CERTINFO_LOCALITYNAME                     = 52;   {localityName}
  CRYPT_CERTINFO_ORGANIZATIONNAME                 = 53;   {organizationName}
  CRYPT_CERTINFO_ORGANISATIONNAME =     CRYPT_CERTINFO_ORGANIZATIONNAME;
  CRYPT_CERTINFO_ORGANIZATIONALUNITNAME           = 54;   {organizationalUnitName}
      CRYPT_CERTINFO_ORGANISATIONALUNITNAME = CRYPT_CERTINFO_ORGANIZATIONALUNITNAME;
  CRYPT_CERTINFO_COMMONNAME                       = 55;   {commonName}

  { X.509 General Name components.  These are handled in the same way as
     the DN composite field, with the current GeneralName being selected by
            a pseudo-component after which the individual components can be
            modified through one of the following }
  CRYPT_CERTINFO_OTHERNAME_TYPEID                 = 56;   {otherName.typeID}
  CRYPT_CERTINFO_OTHERNAME_VALUE                  = 57;   {otherName.value}
  CRYPT_CERTINFO_RFC822NAME                       = 58;   {rfc822Name}
      CRYPT_CERTINFO_EMAIL = CRYPT_CERTINFO_RFC822NAME;
  CRYPT_CERTINFO_DNSNAME                          = 59;   {dNSName}
{$IFDEF Not_supported }
  { Not supported yet, these are virtually never used and have an insane internal structure }
  CRYPT_CERTINFO_X400ADDRESS                              {x400Address}
{$ENDIF }
  CRYPT_CERTINFO_DIRECTORYNAME                    = 60;   {directoryName}
  CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER        = 61;   {ediPartyName.nameAssigner}
  CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME           = 62;   {ediPartyName.partyName}
  CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER        = 63;   {uniformResourceIdentifier}
  CRYPT_CERTINFO_IPADDRESS                        = 64;   {iPAddress}
  CRYPT_CERTINFO_REGISTEREDID                     = 65;   {registeredID}

  { X.509v3 certificate extensions.  Although it would be nicer to use
     names which match the extensions more closely (eg
     CRYPT_CERTINFO_BASICCONSTRAINTS_PATHLENCONSTRAINT), these exceed the
     32-character ANSI minimum length for unique names, and get really
     hairy once you get into the weird policy constraints extensions whose
     names wrap around the screen about three times.

     The following values are defined in OID order, this isn't absolutely
     necessary but saves an extra layer of processing when encoding them }

  { 1 3 6 1 5 5 7 1 1 authorityInfoAccess }
  CRYPT_CERTINFO_AUTHORITYINFOACCESS              = 100;
  CRYPT_CERTINFO_AUTHORITYINFO_OCSP               = 101;  {accessDescription.accessLocation}
  CRYPT_CERTINFO_AUTHORITYINFO_CAISSUERS          = 102;  {accessDescription.accessLocation}

  { 1 3 101 1 4 1 strongExtranet }
  CRYPT_CERTINFO_STRONGEXTRANET                   = 103;
  CRYPT_CERTINFO_STRONGEXTRANET_ZONE              = 104;  {sxNetIDList.sxNetID.zone}
  CRYPT_CERTINFO_STRONGEXTRANET_ID                = 105;  {sxNetIDList.sxNetID.id}

  { 2 5 29 9 subjectDirectoryAttributes }
  CRYPT_CERTINFO_SUBJECTDIRECTORYATTRIBUTES       = 106;
  CRYPT_CERTINFO_SUBJECTDIR_TYPE                  = 107;  {attribute.type}
  CRYPT_CERTINFO_SUBJECTDIR_VALUES                = 108;  {attribute.values}

  { 2 5 29 14 subjectKeyIdentifier }
  CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER             = 109;

  { 2 5 29 15 keyUsage }
  CRYPT_CERTINFO_KEYUSAGE                         = 110;

  { 2 5 29 16 privateKeyUsagePeriod }
  CRYPT_CERTINFO_PRIVATEKEYUSAGEPERIOD            = 111;
  CRYPT_CERTINFO_PRIVATEKEY_NOTBEFORE             = 112;  {notBefore}
  CRYPT_CERTINFO_PRIVATEKEY_NOTAFTER              = 113;  {notAfter}

  { 2 5 29 17 subjectAltName }
  CRYPT_CERTINFO_SUBJECTALTNAME                   = 114;

  { 2 5 29 18 issuerAltName }
  CRYPT_CERTINFO_ISSUERALTNAME                    = 115;

  { 2 5 29 19 basicConstraints }
  CRYPT_CERTINFO_BASICCONSTRAINTS                 = 116;
  CRYPT_CERTINFO_CA                               = 117;  {cA}
      CRYPT_CERTINFO_AUTHORITY = CRYPT_CERTINFO_CA;
  CRYPT_CERTINFO_PATHLENCONSTRAINT                = 118;  {pathLenConstraint}

  { 2 5 29 20 cRLNumber }
  CRYPT_CERTINFO_CRLNUMBER                        = 119;

  { 2 5 29 21 cRLReason }
  CRYPT_CERTINFO_CRLREASON                        = 120;

  { 2 5 29 23 holdInstructionCode }
  CRYPT_CERTINFO_HOLDINSTRUCTIONCODE              = 121;

  { 2 5 29 24 invalidityDate }
  CRYPT_CERTINFO_INVALIDITYDATE                   = 122;

  { 2 5 29 27 deltaCRLIndicator }
  CRYPT_CERTINFO_DELTACRLINDICATOR                = 123;

  { 2 5 29 28 issuingDistributionPoint }
  CRYPT_CERTINFO_ISSUINGDISTRIBUTIONPOINT         = 124;
  CRYPT_CERTINFO_ISSUINGDIST_FULLNAME             = 125;  {distributionPointName.fullName}
  CRYPT_CERTINFO_ISSUINGDIST_USERCERTSONLY        = 126;  {onlyContainsUserCerts}
  CRYPT_CERTINFO_ISSUINGDIST_CACERTSONLY          = 127;  {onlyContainsCACerts}
  CRYPT_CERTINFO_ISSUINGDIST_SOMEREASONSONLY      = 128;  {onlySomeReasons}
  CRYPT_CERTINFO_ISSUINGDIST_INDIRECTCRL          = 129;  {indirectCRL}

  { 2 5 29 29 certificateIssuer }
  CRYPT_CERTINFO_CERTIFICATEISSUER                = 130;

  { 2 5 29 30 nameConstraints }
  CRYPT_CERTINFO_NAMECONSTRAINTS                  = 131;
  CRYPT_CERTINFO_PERMITTEDSUBTREES                = 132;  {permittedSubtrees}
  CRYPT_CERTINFO_EXCLUDEDSUBTREES                 = 133;  {excludedSubtrees}

  { 2 5 29 31 cRLDistributionPoint }
  CRYPT_CERTINFO_CRLDISTRIBUTIONPOINT             = 134;
  CRYPT_CERTINFO_CRLDIST_FULLNAME                 = 135;  {distributionPointName.fullName}
  CRYPT_CERTINFO_CRLDIST_REASONS                  = 136;  {reasons}
  CRYPT_CERTINFO_CRLDIST_CRLISSUER                = 137;  {cRLIssuer}

  { 2 5 29 32 certificatePolicies }
  CRYPT_CERTINFO_CERTIFICATEPOLICIES              = 138;
  CRYPT_CERTINFO_CERTPOLICYID                     = 139;  {policyInformation.policyIdentifier}
  CRYPT_CERTINFO_CERTPOLICY_CPSURI                = 140;  { policyInformation.policyQualifiers.qualifier.cPSuri }
  CRYPT_CERTINFO_CERTPOLICY_ORGANIZATION          = 141;  { policyInformation.policyQualifiers.qualifier.userNotice.noticeRef.organization }
  CRYPT_CERTINFO_CERTPOLICY_NOTICENUMBERS         = 142;  { policyInformation.policyQualifiers.qualifier.userNotice.noticeRef.noticeNumbers }
  CRYPT_CERTINFO_CERTPOLICY_EXPLICITTEXT          = 143;  { policyInformation.policyQualifiers.qualifier.userNotice.explicitText }

  { 2 5 29 33 policyMappings }
  CRYPT_CERTINFO_POLICYMAPPINGS                   = 144;
  CRYPT_CERTINFO_ISSUERDOMAINPOLICY               = 145;  {policyMappings.issuerDomainPolicy}
  CRYPT_CERTINFO_SUBJECTDOMAINPOLICY              = 146;  {policyMappings.subjectDomainPolicy}

  { 2 5 29 35 authorityKeyIdentifier }
  CRYPT_CERTINFO_AUTHORITYKEYIDENTIFIER           = 147;
  CRYPT_CERTINFO_AUTHORITY_KEYIDENTIFIER          = 148;  {keyIdentifier}
  CRYPT_CERTINFO_AUTHORITY_CERTISSUER             = 149;  {authorityCertIssuer}
  CRYPT_CERTINFO_AUTHORITY_CERTSERIALNUMBER       = 150;  {authorityCertSerialNumber}

  { 2 5 29 36 policyConstraints }
  CRYPT_CERTINFO_POLICYCONSTRAINTS                = 151;
  CRYPT_CERTINFO_REQUIREEXPLICITPOLICY            = 152;  {policyConstraints.requireExplicitPolicy}
  CRYPT_CERTINFO_INHIBITPOLICYMAPPING             = 153;  {policyConstraints.inhibitPolicyMapping}

  { 2 5 29 37 extKeyUsage }
  CRYPT_CERTINFO_EXTKEYUSAGE                      = 154;
  CRYPT_CERTINFO_EXTKEY_MS_INDIVIDUALCODESIGNING  = 155;  {individualCodeSigning}
  CRYPT_CERTINFO_EXTKEY_MS_COMMERCIALCODESIGNING  = 156;  {commercialCodeSigning}
  CRYPT_CERTINFO_EXTKEY_MS_CERTTRUSTLISTSIGNING   = 157;  {certTrustListSigning}
  CRYPT_CERTINFO_EXTKEY_MS_TIMESTAMPSIGNING       = 158;  {timeStampSigning}
  CRYPT_CERTINFO_EXTKEY_MS_SERVERGATEDCRYPTO      = 159;  {serverGatedCrypto}
  CRYPT_CERTINFO_EXTKEY_MS_ENCRYPTEDFILESYSTEM    = 160;  {encrypedFileSystem}
  CRYPT_CERTINFO_EXTKEY_SERVERAUTH                = 161;  {serverAuth}
  CRYPT_CERTINFO_EXTKEY_CLIENTAUTH                = 162;  {clientAuth}
  CRYPT_CERTINFO_EXTKEY_CODESIGNING               = 163;  {codeSigning}
  CRYPT_CERTINFO_EXTKEY_EMAILPROTECTION           = 164;  {emailProtection}
  CRYPT_CERTINFO_EXTKEY_IPSECENDSYSTEM            = 165;  {ipsecEndSystem}
  CRYPT_CERTINFO_EXTKEY_IPSECTUNNEL               = 166;  {ipsecTunnel}
  CRYPT_CERTINFO_EXTKEY_IPSECUSER                 = 167;  {ipsecUser}
  CRYPT_CERTINFO_EXTKEY_TIMESTAMPING              = 168;  {timeStamping}
  CRYPT_CERTINFO_EXTKEY_NS_SERVERGATEDCRYPTO      = 169;  {serverGatedCrypto}
  CRYPT_CERTINFO_EXTKEY_VS_SERVERGATEDCRYPTO_CA   = 170;  {serverGatedCrypto CA}

  { 2 16 840 1 113730 1 x Netscape extensions }
  CRYPT_CERTINFO_NS_CERTTYPE                      = 171;  {netscape-cert-type}
  CRYPT_CERTINFO_NS_BASEURL                       = 172;  {netscape-base-url}
  CRYPT_CERTINFO_NS_REVOCATIONURL                 = 173;  {netscape-revocation-url}
  CRYPT_CERTINFO_NS_CAREVOCATIONURL               = 174;  {netscape-ca-revocation-url}
  CRYPT_CERTINFO_NS_CERTRENEWALURL                = 175;  {netscape-cert-renewal-url}
  CRYPT_CERTINFO_NS_CAPOLICYURL                   = 176;  {netscape-ca-policy-url}
  CRYPT_CERTINFO_NS_SSLSERVERNAME                 = 177;  {netscape-ssl-server-name}
  CRYPT_CERTINFO_NS_COMMENT                       = 178;  {netscape-comment}

  { 2 23 42 7 0 SET hashedRootKey }
  CRYPT_CERTINFO_SET_HASHEDROOTKEY                = 179;
  CRYPT_CERTINFO_SET_ROOTKEYTHUMBPRINT            = 180;  {rootKeyThumbPrint}

  { 2 23 42 7 1 SET certificateType }
  CRYPT_CERTINFO_SET_CERTIFICATETYPE              = 181;

  { 2 23 42 7 2 SET merchantData }
  CRYPT_CERTINFO_SET_MERCHANTDATA                 = 182;
  CRYPT_CERTINFO_SET_MERID                        = 183;  {merID}
  CRYPT_CERTINFO_SET_MERACQUIRERBIN               = 184;  {merAcquirerBIN}
  CRYPT_CERTINFO_SET_MERCHANTLANGUAGE             = 185;  {merNames.language}
  CRYPT_CERTINFO_SET_MERCHANTNAME                 = 186;  {merNames.name}
  CRYPT_CERTINFO_SET_MERCHANTCITY                 = 187;  {merNames.city}
  CRYPT_CERTINFO_SET_MERCHANTSTATEPROVINCE        = 188;  {merNames.stateProvince}
  CRYPT_CERTINFO_SET_MERCHANTPOSTALCODE           = 189;  {merNames.postalCode}
  CRYPT_CERTINFO_SET_MERCHANTCOUNTRYNAME          = 190;  {merNames.countryName}
  CRYPT_CERTINFO_SET_MERCOUNTRY                   = 191;  {merCountry}
  CRYPT_CERTINFO_SET_MERAUTHFLAG                  = 192;  {merAuthFlag}

  { 2 23 42 7 3 SET certCardRequired }
  CRYPT_CERTINFO_SET_CERTCARDREQUIRED             = 193;

  { 2 23 42 7 4 SET tunneling }
  CRYPT_CERTINFO_SET_TUNNELING                    = 194;
  CRYPT_CERTINFO_SET_TUNNELINGFLAG                = 195;  {tunneling}
  CRYPT_CERTINFO_SET_TUNNELINGALGID               = 196;  {tunnelingAlgID}

  { S/MIME attributes }

  { 1 2 840 113549 1 9 3 contentType }
  CRYPT_CERTINFO_CMS_CONTENTTYPE                  = 300;

  { 1 2 840 113549 1 9 4 messageDigest }
  CRYPT_CERTINFO_CMS_MESSAGEDIGEST                = 301;

  { 1 2 840 113549 1 9 5 signingTime }
  CRYPT_CERTINFO_CMS_SIGNINGTIME                  = 302;

  { 1 2 840 113549 1 9 6 counterSignature }
  CRYPT_CERTINFO_CMS_COUNTERSIGNATURE             = 303;  {counterSignature}

  { 1 2 840 113549 1 9 15 sMIMECapabilities }
  CRYPT_CERTINFO_CMS_SMIMECAPABILITIES            = 304;
  CRYPT_CERTINFO_CMS_SMIMECAP_3DES                = 305;  {3DES encryption}
  CRYPT_CERTINFO_CMS_SMIMECAP_CAST128             = 306;  {CAST-128 encryption}
  CRYPT_CERTINFO_CMS_SMIMECAP_IDEA                = 307;  {IDEA encryption}
  CRYPT_CERTINFO_CMS_SMIMECAP_RC2                 = 308;  {RC2 encryption (w.128 key)}
  CRYPT_CERTINFO_CMS_SMIMECAP_RC5                 = 309;  {RC5 encryption (w.128 key)}
  CRYPT_CERTINFO_CMS_SMIMECAP_SKIPJACK            = 310;  {Skipjack encryption}
  CRYPT_CERTINFO_CMS_SMIMECAP_PREFERSIGNEDDATA    = 311;  {preferSignedData}
  CRYPT_CERTINFO_CMS_SMIMECAP_CANNOTDECRYPTANY    = 312;  {canNotDecryptAny}

  { 1 2 840 113549 1 9 16 2 1 receiptRequest }
  CRYPT_CERTINFO_CMS_RECEIPTREQUEST               = 313;
  CRYPT_CERTINFO_CMS_RECEIPT_CONTENTIDENTIFIER    = 314;  {contentIdentifier}
  CRYPT_CERTINFO_CMS_RECEIPT_FROM                 = 315;  {receiptsFrom}
  CRYPT_CERTINFO_CMS_RECEIPT_TO                   = 316;  {receiptsTo}

  { 1 2 840 113549 1 9 16 2 2 essSecurityLabel }
  CRYPT_CERTINFO_CMS_SECURITYLABEL                = 317;
  CRYPT_CERTINFO_CMS_SECLABEL_CLASSIFICATION      = 318;  {securityClassification}
  CRYPT_CERTINFO_CMS_SECLABEL_POLICY              = 319;  {securityPolicyIdentifier}
  CRYPT_CERTINFO_CMS_SECLABEL_PRIVACYMARK         = 320;  {privacyMark}
  CRYPT_CERTINFO_CMS_SECLABEL_CATTYPE             = 321;  {securityCategories.securityCategory.type}
  CRYPT_CERTINFO_CMS_SECLABEL_CATVALUE            = 322;  {securityCategories.securityCategory.value}

  { 1 2 840 113549 1 9 16 2 3 mlExpansionHistory }
  CRYPT_CERTINFO_CMS_MLEXPANSIONHISTORY           = 323;
  CRYPT_CERTINFO_CMS_MLEXP_ENTITYIDENTIFIER       = 324;  {mlData.mailListIdentifier.issuerAndSerialNumber}
  CRYPT_CERTINFO_CMS_MLEXP_TIME                   = 325;  {mlData.expansionTime}
  CRYPT_CERTINFO_CMS_MLEXP_NONE                   = 326;  {mlData.mlReceiptPolicy.none}
  CRYPT_CERTINFO_CMS_MLEXP_INSTEADOF              = 327;  {mlData.mlReceiptPolicy.insteadOf.generalNames.generalName}
  CRYPT_CERTINFO_CMS_MLEXP_INADDITIONTO           = 328;  {mlData.mlReceiptPolicy.inAdditionTo.generalNames.generalName}

  { 1 2 840 113549 1 9 16 2 4 contentHints }
  CRYPT_CERTINFO_CMS_CONTENTHINTS                 = 329;
  CRYPT_CERTINFO_CMS_CONTENTHINT_DESCRIPTION      = 330;  {contentDescription}
  CRYPT_CERTINFO_CMS_CONTENTHINT_TYPE             = 331;  {contentType}

  { 1 2 840 113549 1 9 16 2 8 macValue }
  CRYPT_CERTINFO_CMS_MACVALUE                     = 332;  {macValue}

  { 1 2 840 113549 1 9 16 2 9 equivalentLabels }
  CRYPT_CERTINFO_CMS_EQUIVALENTLABEL              = 333;
  CRYPT_CERTINFO_CMS_EQVLABEL_POLICY              = 334;  {securityPolicyIdentifier}
  CRYPT_CERTINFO_CMS_EQVLABEL_CLASSIFICATION      = 335;  {securityClassification}
  CRYPT_CERTINFO_CMS_EQVLABEL_PRIVACYMARK         = 336;  {privacyMark}
  CRYPT_CERTINFO_CMS_EQVLABEL_CATTYPE             = 337;  {securityCategories.securityCategory.type}
  CRYPT_CERTINFO_CMS_EQVLABEL_CATVALUE            = 338;  {securityCategories.securityCategory.value}

  { 1 2 840 113549 1 9 16 2 12 signingCertificate }
  CRYPT_CERTINFO_CMS_SIGNINGCERTIFICATE           = 339;
  CRYPT_CERTINFO_CMS_SIGNINGCERT_CERTS            = 340;  {certs.essCertID.certHash}
  CRYPT_CERTINFO_CMS_SIGNINGCERT_POLICIES         = 341;  {policies.policyInformation.policyIdentifier}

  { 1 3 6 1 4 1 311 2 1 10 spcAgencyInfo }
  CRYPT_CERTINFO_CMS_SPCAGENCYINFO                = 342;
  CRYPT_CERTINFO_CMS_SPCAGENCYURL                 = 343;  {spcAgencyInfo.url}

  { 1 3 6 1 4 1 311 2 1 11 spcStatementType }
  CRYPT_CERTINFO_CMS_SPCSTATEMENTTYPE             = 344;
  CRYPT_CERTINFO_CMS_SPCSTMT_INDIVIDUALCODESIGNING= 345;  {individualCodeSigning}
  CRYPT_CERTINFO_CMS_SPCSTMT_COMMERCIALCODESIGNING= 346;  {commercialCodeSigning}

  { 1 3 6 1 4 1 311 2 1 12 spcOpusInfo }
  CRYPT_CERTINFO_CMS_SPCOPUSINFO                  = 347;

  CRYPT_CERTINFO_LAST                             = 348;  {Last possible certificate info type}


  {Useful defines used internally for range checking}
  CRYPT_FIRST_PSEUDOINFO                          = CRYPT_CERTINFO_SELFSIGNED;
  CRYPT_LAST_PSEUDOINFO                           = CRYPT_CERTINFO_CURRENT_COMPONENT;
  CRYPT_FIRST_DN                                  = CRYPT_CERTINFO_COUNTRYNAME;
  CRYPT_LAST_DN                                   = CRYPT_CERTINFO_COMMONNAME;
  CRYPT_FIRST_GENERALNAME                         = CRYPT_CERTINFO_OTHERNAME_TYPEID;
  CRYPT_LAST_GENERALNAME                          = CRYPT_CERTINFO_REGISTEREDID;
  CRYPT_FIRST_EXTENSION                           = CRYPT_CERTINFO_AUTHORITYINFOACCESS;
  CRYPT_LAST_EXTENSION                            = CRYPT_CERTINFO_SET_TUNNELINGALGID;
  CRYPT_FIRST_CMS                                 = CRYPT_CERTINFO_CMS_CONTENTTYPE;
  CRYPT_LAST_CMS                                  = CRYPT_CERTINFO_LAST - 1;

{Flags for the X.509v3 keyUsage extension}

const
  CRYPT_KEYUSAGE_NONE             = $0000;
  CRYPT_KEYUSAGE_DIGITALSIGNATURE = $0001;
  CRYPT_KEYUSAGE_NONREPUDIATION   = $0002;
  CRYPT_KEYUSAGE_KEYENCIPHERMENT  = $0004;
  CRYPT_KEYUSAGE_DATAENCIPHERMENT = $0008;
  CRYPT_KEYUSAGE_KEYAGREEMENT     = $0010;
  CRYPT_KEYUSAGE_KEYCERTSIGN      = $0020;
  CRYPT_KEYUSAGE_CRLSIGN          = $0040;
  CRYPT_KEYUSAGE_ENCIPHERONLY     = $0080;
  CRYPT_KEYUSAGE_DECIPHERONLY     = $0100;
  CRYPT_KEYUSAGE_LAST             = $0100; {Last possible value}

{ X.509v3 cRLReason codes }
type
  CRYPT_CRLREASON = (CRYPT_CRLREASON_UNSPECIFIED,
                     CRYPT_CRLREASON_KEYCOMPROMISE,
                     CRYPT_CRLREASON_CACOMPROMISE,
                     CRYPT_CRLREASON_AFFILIATIONCHANGED,
                     CRYPT_CRLREASON_SUPERSEDED,
                     CRYPT_CRLREASON_CESSATIONOFOPERATION,
                     CRYPT_CRLREASON_CERTIFICATEHOLD,
                     CRYPT_CRLREASON_UNUSED,
                     CRYPT_CRLREASON_REMOVEFROMCRL);
const
  CRYPT_CRLREASON_LAST: CRYPT_CRLREASON = CRYPT_CRLREASON_REMOVEFROMCRL;

{  X.509v3 CRL reason flags.  These identify the same thing as the cRLReason
   codes but allow for multiple reasons to be specified.  Note that these
   don't follow the X.509 naming since in that scheme the enumerated types
   and bitflags have the same name }

{Flags for the X.509v3 cRLReason extension}
const
  CRYPT_CRLREASONFLAG_UNUSED               = $0001;
  CRYPT_CRLREASONFLAG_KEYCOMPROMISE        = $0002;
  CRYPT_CRLREASONFLAG_CACOMPROMISE         = $0004;
  CRYPT_CRLREASONFLAG_AFFILIATIONCHANGED   = $0008;
  CRYPT_CRLREASONFLAG_SUPERSEDED           = $0010;
  CRYPT_CRLREASONFLAG_CESSATIONOFOPERATION = $0020;
  CRYPT_CRLREASONFLAG_CERTIFICATEHOLD      = $0040;
  CRYPT_CRLREASONFLAG_LAST                 = $0040; {Last possible value}

{ X.509v3 CRL holdInstruction codes }

  CRYPT_HOLDINSTRUCTION_NONE        = 0;
  CRYPT_HOLDINSTRUCTION_CALLISSUER  = 1;
  CRYPT_HOLDINSTRUCTION_REJECT      = 2;
  CRYPT_HOLDINSTRUCTION_PICKUPTOKEN = 3;
  CRYPT_HOLDINSTRUCTION_LAST = CRYPT_HOLDINSTRUCTION_PICKUPTOKEN;

{Flags for the Netscape netscape-cert-type extension}

  CRYPT_NS_CERTTYPE_SSLCLIENT       = $0001;
  CRYPT_NS_CERTTYPE_SSLSERVER       = $0002;
  CRYPT_NS_CERTTYPE_SMIME           = $0004;
  CRYPT_NS_CERTTYPE_OBJECTSIGNING   = $0008;
  CRYPT_NS_CERTTYPE_RESERVED        = $0010;
  CRYPT_NS_CERTTYPE_SSLCA           = $0020;
  CRYPT_NS_CERTTYPE_SMIMECA         = $0040;
  CRYPT_NS_CERTTYPE_OBJECTSIGNINGCA = $0080;
  CRYPT_NS_CERTTYPE_LAST            = $0080; {Last possible value}

{ CMS contentType values }

type
  CRYPT_CONTENT_TYPE = (CRYPT_CONTENT_DATA,
                        CRYPT_CONTENT_SIGNEDDATA,
                        CRYPT_CONTENT_ENVELOPEDDATA,
                        CRYPT_CONTENT_SIGNEDANDENVELOPEDDATA,
                        CRYPT_CONTENT_DIGESTEDDATA,
                        CRYPT_CONTENT_ENCRYPTEDDATA,
                        CRYPT_CONTENT_SPCINDIRECTDATACONTEXT);
const
  CRYPT_CONTENT_LAST : CRYPT_CONTENT_TYPE = CRYPT_CONTENT_SPCINDIRECTDATACONTEXT;

{ESS securityClassification codes}

const
  CRYPT_CLASSIFICATION_UNMARKED     = 0;
  CRYPT_CLASSIFICATION_UNCLASSIFIED = 1;
  CRYPT_CLASSIFICATION_RESTRICTED   = 2;
  CRYPT_CLASSIFICATION_CONFIDENTIAL = 3;
  CRYPT_CLASSIFICATION_SECRET       = 4;
  CRYPT_CLASSIFICATION_TOP_SECRET   = 5;
  CRYPT_CLASSIFICATION_LAST         = 255;

{Certificate error types}

type
  CRYPT_CERTERROR_TYPE = (CRYPT_CERTERROR_NONE,             {No certificate error}
                          CRYPT_CERTERROR_SIZE,             {Item too small or large}
                          CRYPT_CERTERROR_VALUE,            {Item value is invalid}
                          CRYPT_CERTERROR_CONSTRAINT,       {Constraint violation in item}
                          CRYPT_CERTERROR_ISSUERCONSTRAINT, {Constraint viol.in issuing cert}
                          CRYPT_CERTERROR_ABSENT,           {Required item missing}
                          CRYPT_CERTERROR_PRESENT,          {Non-allowed item present}
                          CRYPT_CERTERROR_LAST);            {Last possible cert.error}


{ Object property types }

type
  CRYPT_PROPERTY_TYPE = (CRYPT_PROPERTY_NONE,               {No property}
                         CRYPT_PROPERTY_HIGHSECURITY,       {Owned+non-forwardable+locked}
                         CRYPT_PROPERTY_OWNER,              {Object owner}
                         CRYPT_PROPERTY_FORWARDABLE,        {No.of times object can be forwarded}
                         CRYPT_PROPERTY_LOCKED,             {Whether properties can be chged/read}
                         CRYPT_PROPERTY_LAST);              {Last possible property type}

{ Device control options }
type
  CRYPT_DEVICECONTROL_TYPE = (CRYPT_DEVICECONTROL_NONE,               {No device control}
                              CRYPT_DEVICECONTROL_INITIALISE,         {Initialise device for use}
                              CRYPT_DEVICECONTROL_AUTH_USER,          {Authenticate user to device}
                              CRYPT_DEVICECONTROL_AUTH_SUPERVISOR,    {Authenticate supervisor to dev.}
                              CRYPT_DEVICECONTROL_SET_AUTH_USER,      {Set user authent.value}
                              CRYPT_DEVICECONTROL_SET_AUTH_SUPERVISOR,{Set supervisor auth.val.}
                              CRYPT_DEVICECONTROL_ZEROISE,            {Zeroise device}
                              CRYPT_DEVICECONTROL_LAST);              {Last possible device control}
const
                              CRYPT_DEVICECONTROL_ZEROIZE = CRYPT_DEVICECONTROL_ZEROISE;
                              CRYPT_DEVICECONTROL_INITIALIZE = CRYPT_DEVICECONTROL_INITIALISE;

{Configuration options}

type
  CRYPT_OPTION_TYPE = (
    CRYPT_OPTION_NONE,                            {Non-option}

    { cryptlib information (read-only) }
    CRYPT_OPTION_INFO_DESCRIPTION,                {Text description}
    CRYPT_OPTION_INFO_COPYRIGHT,                  {Copyright notice}
    CRYPT_OPTION_INFO_MAJORVERSION,               {Major release version}
    CRYPT_OPTION_INFO_MINORVERSION,               {Minor release version}

    { Encryption options }
    CRYPT_OPTION_ENCR_ALGO,                       {Encryption algorithm}
    CRYPT_OPTION_ENCR_MODE,                       {Encryption mode}
    CRYPT_OPTION_ENCR_HASH,                       {Hash algorithm}

    { PKC options }
    CRYPT_OPTION_PKC_ALGO,                        {Public-key encryption algorithm}
    CRYPT_OPTION_PKC_KEYSIZE,                     {Public-key encryption key size}

    { Signature options }
    CRYPT_OPTION_SIG_ALGO,                        {Signature algorithm}
    CRYPT_OPTION_SIG_KEYSIZE,                     {Signature keysize}

    { Keying options }
    CRYPT_OPTION_KEYING_ALGO,                     {Key processing algorithm}
    CRYPT_OPTION_KEYING_ITERATIONS,               {Key processing iterations}

    { Certificate options }
    CRYPT_OPTION_CERT_CREATEV3CERT,               {Whether to create X.509v3 certs}
    CRYPT_OPTION_CERT_PKCS10ALT,                  {Use alternative PKCS #10 encoding}
    CRYPT_OPTION_CERT_CHECKENCODING,              {Check for valid ASN.1 encoding}
    CRYPT_OPTION_CERT_FIXSTRINGS,                 {Whether to fix encoding of strings}
    CRYPT_OPTION_CERT_FIXEMAILADDRESS,            {Whether to fix encoding of email addr.}
    CRYPT_OPTION_CERT_ISSUERNAMEBLOB,             {Whether to treat iName as a blob}
    CRYPT_OPTION_CERT_KEYIDBLOB,                  {Whether to treat keyID as a blob}
    CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES, {Whether to sign unrecog.attrs}
    CRYPT_OPTION_CERT_TRUSTCHAINROOT,             {Whether to trust cert chain root}
    CRYPT_OPTION_CERT_VALIDITY,                   {Certificate validity period}
    CRYPT_OPTION_CERT_UPDATEINTERVAL,             {CRL update interval}
    CRYPT_OPTION_CERT_ENCODE_VALIDITYNESTING,
    CRYPT_OPTION_CERT_DECODE_VALIDITYNESTING,     {Enforce validity nesting on R/W}
    CRYPT_OPTION_CERT_ENCODE_CRITICAL,
    CRYPT_OPTION_CERT_DECODE_CRITICAL,            {Enforce critical flag in extensions}

    { Keyset options }
    CRYPT_OPTION_KEYS_PUBLIC,                     {Default encryption PKC database}
    CRYPT_OPTION_KEYS_PRIVATE,                    {Default decryption PKC database}
    CRYPT_OPTION_KEYS_SIGCHECK,                   {Default sig.check PKC database}
    CRYPT_OPTION_KEYS_SIGNATURE,                  {Default sig.generation PKC database}

    { File keyset options }
    CRYPT_OPTION_KEYS_FILE_PRIVATE,               {Private key file}
    CRYPT_OPTION_KEYS_FILE_SIGNATURE,             {Signature key file}

    { PGP keyset options }
    CRYPT_OPTION_KEYS_PGP_PUBLIC,                 {PGP public keyring}
    CRYPT_OPTION_KEYS_PGP_PRIVATE,                {PGP private keyring}
    CRYPT_OPTION_KEYS_PGP_SIGCHECK,               {PGP signature check keyring}
    CRYPT_OPTION_KEYS_PGP_SIGNATURE,              {PGP signature gen.keyring}

    { RDBMS keyset options }
    CRYPT_OPTION_KEYS_DBMS_NAMETABLE,             {Name of key database table}
    CRYPT_OPTION_KEYS_DBMS_NAMECRLTABLE,          {Name of CRL table}
    CRYPT_OPTION_KEYS_DBMS_NAME_C,                {Name of key owner C column}
    CRYPT_OPTION_KEYS_DBMS_NAME_SP,               {Name of key owner SP column}
    CRYPT_OPTION_KEYS_DBMS_NAME_L,                {Name of key owner L column}
    CRYPT_OPTION_KEYS_DBMS_NAME_O,                {Name of key owner O column}
    CRYPT_OPTION_KEYS_DBMS_NAME_OU,               {Name of key owner OU column}
    CRYPT_OPTION_KEYS_DBMS_NAME_CN,               {Name of key owner CN column}
    CRYPT_OPTION_KEYS_DBMS_NAMEEMAIL,             {Name of key owner email column}
    CRYPT_OPTION_KEYS_DBMS_NAMEDATE,              {Name of key expiry date column}
    CRYPT_OPTION_KEYS_DBMS_NAMENAMEID,            {Name of key nameID column}
    CRYPT_OPTION_KEYS_DBMS_NAMEISSUERID,          {Name of key issuerID column}
    CRYPT_OPTION_KEYS_DBMS_NAMEKEYID,             {Name of key keyID column}
    CRYPT_OPTION_KEYS_DBMS_NAMEKEYDATA,           {Name of key data column}

    { LDAP keyset options }
    CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS,           {Object class}
    CRYPT_OPTION_KEYS_LDAP_CACERTNAME,            {CA certificate attribute name}
    CRYPT_OPTION_KEYS_LDAP_CERTNAME,              {Certificate attribute name}
    CRYPT_OPTION_KEYS_LDAP_CRLNAME,               {CRL attribute name}
    CRYPT_OPTION_KEYS_LDAP_EMAILNAME,             {Email attribute name}

    { Crypto device options }
    CRYPT_OPTION_DEVICE_PKCS11_DVR01,             {Name of first PKCS #11 driver}
    CRYPT_OPTION_DEVICE_PKCS11_DVR02,             {Name of second PKCS #11 driver}
    CRYPT_OPTION_DEVICE_PKCS11_DVR03,             {Name of third PKCS #11 driver}
    CRYPT_OPTION_DEVICE_PKCS11_DVR04,             {Name of fourth PKCS #11 driver}
    CRYPT_OPTION_DEVICE_PKCS11_DVR05,             {Name of fifth PKCS #11 driver}
    CRYPT_OPTION_DEVICE_SERIALRNG,                {Serial-port-based RNG name}
    CRYPT_OPTION_DEVICE_SERIALRNG_PARAMS,         {Serial RNG parameters}
    CRYPT_OPTION_DEVICE_SERIALRNG_ONLY,           {Whether to use only serial RNG}

    { CMS/SMIME options }
    CRYPT_OPTION_CMS_DEFAULTATTRIBUTES,           {Add default CMS attributes}

    { Miscellaneous options }
    CRYPT_OPTION_MISC_FORCELOCK,                  {Whether to force memory locking}
    CRYPT_OPTION_MISC_ASYNCINIT,                  {Whether to init cryptlib async'ly}
    CRYPT_OPTION_LAST  );                         {Last config option}

const
  CRYPT_OPTION_SMIME_DEFAULTATTRIBUTES = CRYPT_OPTION_CMS_DEFAULTATTRIBUTES;


{* * * * * * * * * * * * * * * * * * * * * * * * *}
{*    Library-Wide Constants and Definitions     *}
{* * * * * * * * * * * * * * * * * * * * * * * * *}

const
  {The maximum user key size - 2048 bits}
  CRYPT_MAX_KEYSIZE            = 256;

  {The maximum IV size - 256 bits (required for the LEAF+IV Fortezza IV)}
  CRYPT_MAX_IVSIZE             = 32;

  {The maximum public-key component size - 4096 bits}
  CRYPT_MAX_PKCSIZE            = 512;

  {The maximum hash size - 256 bits}
  CRYPT_MAX_HASHSIZE           = 32;

  {The maximum size of a text string}
  CRYPT_MAX_TEXTSIZE           = 64;

  {A magic value indicating that the default setting for this parameter
   should be used}
  CRYPT_USE_DEFAULT            = -1;

  {A magic value for unused parameters}
  CRYPT_UNUSED                 = -2;

  {The endianness of the external components of the PKC key}
  CRYPT_COMPONENTS_BIGENDIAN   = 0;
  CRYPT_COMPONENTS_LITTLENDIAN =        1;

  {Whether the PKC key is a public or private key}
  CRYPT_KEYTYPE_PRIVATE        = 0;
  CRYPT_KEYTYPE_PUBLIC         = 1;

  {The type of information polling to perform to get random seed information}
  CRYPT_RANDOM_FASTPOLL        = -1;
  CRYPT_RANDOM_SLOWPOLL       = -2;

  {Special key ID's for getFirst()/getNext() functionality in flat file keysets}
  CRYPT_KEYSET_GETFIRST        = CPTR (-10);
  CRYPT_KEYSET_GETNEXT         = CPTR (-11);

  {Special keyset contexts for begin/end bulk update functionality in keysets}
  CRYPT_KEYUPDATE_BEGIN        = -20;
  CRYPT_KEYUPDATE_END         = -21;

  {Cursor positioning codes for certificate/CRL extensions}
  CRYPT_CURSOR_FIRST    = -30;
  CRYPT_CURSOR_PREVIOUS = -31;
  CRYPT_CURSOR_NEXT     = -32;
  CRYPT_CURSOR_LAST     = -33;

type
  {Options passed to CryptOpenKeyset() and CryptOpenKeysetEx()}
  CRYPT_KEYOPT_TYPE = (CRYPT_KEYOPT_NONE,     {No options}
                       CRYPT_KEYOPT_READONLY, {Open keyset in read-only mode}
                       CRYPT_KEYOPT_CREATE,   {Create a new keyset}
                       CRYPT_KEYOPT_LAST);    {Last possible key option type}

{Functions to convert to and from the bit counts used for some encryption parameters}

function BitsToBytes(Bits:  CINT): CINT;
function BytesToBits(Bytes: CINT): CINT;

{The various cryptlib objects - these are just integer handles}

type
  CRYPT_HANDLE       = CINT;
  PCRYPTHANDLE       = ^CRYPT_HANDLE;

  CRYPT_CERTIFICATE  = CRYPT_HANDLE;
  PCRYPT_CERTIFICATE = ^CRYPT_CERTIFICATE;

  CRYPT_CONTEXT      = CRYPT_HANDLE;
  PCRYPT_CONTEXT     = ^CRYPT_CONTEXT;

  CRYPT_DEVICE       = CRYPT_HANDLE;
  PCRYPT_DEVICE      = ^CRYPT_DEVICE;

  CRYPT_ENVELOPE     = CRYPT_HANDLE;
  PCRYPT_ENVELOPE    = ^CRYPT_ENVELOPE;

  CRYPT_KEYSET       = CRYPT_HANDLE;
  PCRYPT_KEYSET      = ^CRYPT_KEYSET;



{* * * * * * * * * * * * * * * * * * * * * * * * *}
{*           Encryption Data Structures  *}
{* * * * * * * * * * * * * * * * * * * * * * * * *}

{Array Buffer types}
type
  TNameBuffer   = Array [0..(CRYPT_MAX_TEXTSIZE  - 1)] of Char;
  THashBuffer   = Array [0..(CRYPT_MAX_HASHSIZE  - 1)] of CBYTE;
  TPKCBuffer    = Array [0..(CRYPT_MAX_PKCSIZE   - 1)] of CBYTE;

type

  {Results returned from the encryption capability query}
  CRYPT_QUERY_INFO = record
    {The algorithm, encryption mode, and algorithm and mode names}
    CryptAlgo: CRYPT_ALGO;       {The encryption algorithm}
    CryptMode: CRYPT_MODE;       {The encryption mode}
    AlgoName:  TNameBuffer;      {The algorithm name}
    ModeName:  TNameBuffer;      {The mode name}

    {The algorithm parameters}
    BlockSize:  CINT;            {The basic block size of the algorithm}
    MinKeySize: CINT;            {Minimum key size in bytes}
    KeySize:    CINT;            {Recommended key size in bytes}
    MaxKeySize: CINT;            {Maximum key size in bytes}
    MinIVSize:  CINT;            {Minimum IV size in bytes}
    IVSize:     CINT;            {Recommended IV size in bytes}
    MaxIVSize:  CINT;            {Maximum IV size in bytes}
    actualKeySize: CINT;         {Actual key size in bytes}

    {Miscellaneous information (only used by some algorithms)}
    HashValue:  THashBuffer;     {Hash algorithm hash value}
  end;

  PCRYPT_QUERY_INFO = ^CRYPT_QUERY_INFO;


  {Results returned from the encryption object query.  These provide
   information on the objects created by CryptExportKey()/
   CryptCreateSignature()  }

  CRYPT_OBJECT_INFO = record
    {The object type and size}
    ObjectType:         CRYPT_OBJECT_TYPE; {The object type}
    objectSize:         CINT;              {The object size}

    {The encryption algorithm and mode}
    CryptAlgo:          CRYPT_ALGO;        {The encryption algorithm}
    CryptMode:          CRYPT_MODE;        {The encryption mode}

    {The key derivation algorithm and iteration count for EncryptedKey objects}
    KeySetupAlgo:       CRYPT_ALGO;        {Key setup algorithm}
    KeySetupIterations: CINT;              {Key setup iteration count}

    {The hash algorithm for Signature objects}
    HashAlgo:           CRYPT_ALGO;        {Hash algorithm}

    {The algorithm-specific information for EncryptedKey objects.
     This information can be passed directly to CryptCreateContextEx()
     for any algorithm (even those which have no extended information
     and would normally use CryptCreateContext()).}
    CryptContextExInfo: CPTR;                   {Algo-specific information}
    _ContextInfo:       Array [0..31] of CCHAR; {Storage for alg-specific info}
  end;

  PCRYPT_OBJECT_INFO = ^CRYPT_OBJECT_INFO;


  {Extra algorithm-specific information for the conventional encryption
   algorithms, stored within a crypt context.  Set the parameter values to
   CRYPT_USE_DEFAULT to use the default values for this algorithm}

  CRYPT_INFO_RC5 = record
    Rounds:     CINT; {Number of encryption rounds}
  end;

  PCRYPT_INFO_RC5 = ^CRYPT_INFO_RC5;

  CRYPT_INFO_SAFER = record
    UseSaferSK: CINT; {Whether to use strengthened-key version}
    Rounds:     CINT; {Number of encryption rounds}
  end;

  PCRYPT_INFO_SAFER = ^CRYPT_INFO_SAFER;


  {Key information for the public-key encryption algorithms.  These fields
   are not usually accessed directly, but rather manipulated with the
          init/set/destroyComponents() macros}

  CRYPT_PKCINFO_DH = record
    {Status information}
    Endianness:  CINT;        {Endianness of integer strings}
    IsPublicKey: CINT;        {Whether this is a public or private key}

    {Public components}
    P:           TPKCBuffer;  {Prime}
    PLen:        CINT;        {Length of prime in bits}
    G:           TPKCBuffer;  {Base}
    GLen:        CINT;        {Length of base in bits}
  end;

  PCRYPT_PKCINFO_DH = ^CRYPT_PKCINFO_DH;

  CRYPT_PKCINFO_RSA = record
    {Status information}
    Endianness:  CINT;        {Endianness of integer strings}
    IsPublicKey: CINT;        {Whether this is a public or private key}

    {Public components}
    N:           TPKCBuffer;  {Modulus}
    NLen:        CINT;        {Length of modulus in bits}
    E:           TPKCBuffer;  {Public exponent}
    ELen:        CINT;        {Length of public exponent in bits}

    {Private components}
    D:           TPKCBuffer;  {Private exponent}
    DLen:        CINT;        {Length of private exponent in bits}
    P:           TPKCBuffer;  {Prime factor 1}
    PLen:        CINT;        {Length of prime factor 1 in bits}
    Q:           TPKCBuffer;  {Prime factor 2}
    QLen:        CINT;        {Length of prime factor 2 in bits}
    U:           TPKCBuffer;  {Multiplicative inverse of Q, mod P}
    ULen:        CINT;        {Length of private exponent in bits}
    E1:          TPKCBuffer;  {Private exponent 1 (PKCS)}
    E1Len:       CINT;        {Length of private exponent in bits}
    E2:          TPKCBuffer;  {Private exponent 2 {PKCS)}
    E2Len:       CINT;        {Length of private exponent in bits}
  end;

  PCRYPT_PKCINFO_RSA = ^CRYPT_PKCINFO_RSA;

  CRYPT_PKCINFO_DSA = record
    {Status information}
    Endianness:  CINT;        {Endianness of integer strings}
    IsPublicKey: CINT;        {Whether this is a public or private key}

    {Public components}
    P:           TPKCBuffer; {Prime modulus}
    PLen:        CINT;       {Length of prime modulus in bits}
    Q:           TPKCBuffer; {Prime divisor}
    QLen:        CINT;       {Length of prime divisor in bits}

    G:           TPKCBuffer; {H^( ( P - 1 ) / Q ) mod P}
    GLen:        CINT;       {Length of G in bits}
    Y:           TPKCBuffer; {Public random integer}
    YLen:        CINT;       {Length of public integer in bits}

    {Private components}
    X:           TPKCBuffer; {Private random integer}
    XLen:        CINT;       {Length of private integer in bits}
  end;

  PCRYPT_PKCINFO_DSA = ^CRYPT_PKCINFO_DSA;

  CRYPT_PKCINFO_ELGAMAL = record
    {Status information}
    Endianness:  CINT;        {Endianness of integer strings}
    IsPublicKey: CINT;        {Whether this is a public or private key}

    {Public components}
    P:           TPKCBuffer; {Prime modulus}
    PLen:        CINT;       {Length of prime modulus in bits}
    G:           TPKCBuffer; {Generator}
    GLen:        CINT;       {Length of g in bits}
    Y:           TPKCBuffer; {Public random integer}
    YLen:        CINT;       {Length of public integer in bits}

    {Private components}
    X:           TPKCBuffer; {Private random integer}
    XLen:        CINT;       {Length of private integer in bits}
  end;

  PCRYPT_PKCINFO_ELGAMAL = ^CRYPT_PKCINFO_ELGAMAL;


{Macros to initialise and destroy the structure which stores the components
 of a public key}
function CryptInitComponents(var ComponentInfo: CPTR;
  ComponentSize: CINT;
  ComponentEndianness: CINT;
  ComponentKeyType: CINT): CRET;

function CryptDestroyComponents(ComponentInfo: CPTR): CRET;

{Macros to set and get a component of the public key}
function CryptSetComponent(var   Destination;
  const Source;
  Length: CINT): CRET;


{* * * * * * * * * * * * * * * * * * * * * * * * *}
{*           API Function Return Codes           *}
{* * * * * * * * * * * * * * * * * * * * * * * * *}

const

{ No error in function call }

  CRYPT_OK                 = 0;     {No error}

{ Internal errors }

  CRYPT_ERROR              = -1;    {Nonspecific error}
  CRYPT_SELFTEST           = -2;    {Failed self-test}

{ Error in parameters passed to function }

  CRYPT_BADPARM            = -10;   {Generic bad argument to function}
  CRYPT_BADPARM1           = -11;   {Bad argument, parameter 1}
  CRYPT_BADPARM2           = -12;   {Bad argument, parameter 2}
  CRYPT_BADPARM3           = -13;   {Bad argument, parameter 3}
  CRYPT_BADPARM4           = -14;   {Bad argument, parameter 4}
  CRYPT_BADPARM5           = -15;   {Bad argument, parameter 5}
  CRYPT_BADPARM6           = -16;   {Bad argument, parameter 6}
  CRYPT_BADPARM7           = -17;   {Bad argument, parameter 7}
  CRYPT_BADPARM8           = -18;   {Bad argument, parameter 8}
  CRYPT_BADPARM9           = -19;   {Bad argument, parameter 9}
  CRYPT_BADPARM10          = -20;   {Bad argument, parameter 10}

{ Errors due to insufficient resources }

  CRYPT_NOMEM              = -50;   {Out of memory}
  CRYPT_NOTINITED          = -51;   {Data has not been initialised}
  CRYPT_INITED             = -52;   {Data has already been initialised}
  CRYPT_NOSECURE           = -53;   {Operation not available at requested sec.level}
  CRYPT_NOALGO             = -54;   {Algorithm unavailable}
  CRYPT_NOMODE             = -55;   {Encryption mode unavailable}
  CRYPT_NOKEY              = -56;   {Key not initialised}
  CRYPT_NOIV               = -57;   {IV not initialised}
  CRYPT_NORANDOM           = -58;   {No reliable random data available}

{ Security violations }

  CRYPT_NOTAVAIL           = -100;  {Operation not available for this argument}
  CRYPT_NOPERM             = -101;  {No permiss.to perform this operation}
  CRYPT_WRONGKEY           = -102;  {Incorrect key used to decrypt data}
  CRYPT_INCOMPLETE         = -103;  {Operation incomplete/still in progress}
  CRYPT_COMPLETE           = -104;  {Operation complete/can't continue}
  CRYPT_ORPHAN             = -105;  {Contexts remained allocated}
  CRYPT_BUSY               = -106;  {Resource in use by async operation}
  CRYPT_SIGNALLED          = -107;  {Resource destroyed by external event}

{ High-level function errors }

  CRYPT_OVERFLOW           = -150;  {Too much data supplied to function}
  CRYPT_UNDERFLOW          = -151;  {Not enough data supplied to function}
  CRYPT_PKCCRYPT           = -152;  {PKC en/decryption failed}
  CRYPT_BADDATA            = -153;  {Bad data format in object}
  CRYPT_BADSIG             = -154;  {Bad signature on data}
  CRYPT_INVALID            = -155;  {Invalid/inconsistent information}

{ Data access function errors }

  CRYPT_DATA_OPEN          = -200;  {Cannot open data object}
  CRYPT_DATA_READ          = -201;  {Cannot read item from data object}
  CRYPT_DATA_WRITE         = -202;  {Cannot write item to data object}
  CRYPT_DATA_NOTFOUND      = -203;    { Requested item not found in data obj.}
  CRYPT_DATA_DUPLICATE     = -204;  {Item already present in data object}

{ Data enveloping errors }

  CRYPT_ENVELOPE_RESOURCE  = -250;  {Need resource to proceed}

  {DLL failure}
  CRYPT_DLLNOTLOADED       = -10000;
  CRYPT_FUNCTIONNOTFOUND   = -10001;


{Macro functions to examine return values}
function CryptStatusError (Status: CRET): Boolean;
function CryptStatusOK (Status: CRET): Boolean;
function CryptIsInternalError (Status: CRET): Boolean;
function CryptIsParamError (Status: CRET): Boolean;
function CryptIsResourceError (Status: CRET): Boolean;
function CryptIsSecurityError (Status: CRET): Boolean;
function CryptIsHighlevelError (Status: CRET): Boolean;
function CryptIsDataSetError (Status: CRET): Boolean;
function CryptIsEnvelopeError (Status: CRET): Boolean;
function CryptIsDLLError (Status: CRET): Boolean;



{* * * * * * * * * * * * * * * * * * * * * * * * *}
{*   Cryptlib Delphi-style Exception Interface   *}
{* * * * * * * * * * * * * * * * * * * * * * * * *}

{Exception types.}
type
  ECryptError = class(Exception)
  public
    constructor CreateFromCRET(TheCode: CRET);
  private
    FErrorCode: CRET;
  public
    property ErrorCode: CRET  read FErrorCode;
  end;

  ECryptInternalError     = class(ECryptError);
  ECryptParamError        = class(ECryptError);
  ECryptResourceError     = class(ECryptError);
  ECryptSecurityError     = class(ECryptError);
  ECryptHighlevelError    = class(ECryptError);
  ECryptDataSetError      = class(ECryptError);
  ECryptEnvelopeError     = class(ECryptError);
  ECryptDLLError          = class(ECryptError);


{Exception function interfaces.}
function CryptCheck(Status: CRET): CRET;
function CryptFunctionCheck(func: string; Status: CRET): CRET;
function CreateCryptError(Status: CRET): Exception;



{* * * * * * * * * * * * * * * * * * * * * * * * *}
{*       Low-level Encryption Functions  *}
{* * * * * * * * * * * * * * * * * * * * * * * * *}

{Initialise and shut down cryptlib}

function cryptInit:
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptInitEx:
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptEnd:
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}


{QQuery cryptlibs capabilities}

function cryptQueryCapability( const Algorithm: CRYPT_ALGO;
  const Mode: CRYPT_MODE;
  var Information: CRYPT_QUERY_INFO ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptQueryContext( const Context: CRYPT_CONTEXT;
  var Information: CRYPT_QUERY_INFO ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}


{Create and destroy an encryption context}

function cryptCreateContext( var Context: CRYPT_CONTEXT;
  const Algorithm: CRYPT_ALGO;
  const Mode: CRYPT_MODE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptCreateContextEx( var Context: CRYPT_CONTEXT;
  const Algorithm: CRYPT_ALGO;
  const Mode: CRYPT_MODE;
  const ExtendedData: CPTR ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptDestroyContext( const Context: CRYPT_CONTEXT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}


{Generic "destroy an object" function}

function cryptDestroyObject( const ObjectHandle: CRYPT_HANDLE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}


{Get/set object properties}

function cryptGetObjectProperty( const ObjectHandle: CRYPT_HANDLE;
  const propertyType: CRYPT_PROPERTY_TYPE;
  var value: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptSetObjectProperty( const ObjectHandle: CRYPT_HANDLE;
  const propertyType: CRYPT_PROPERTY_TYPE;
  const value: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}


{Load a user key into an encryption context, add random data to the random
 pool, get medium-strength random data from the random pool, generate a
 key into a context, or derive an encryption key from a variable-length
 user key}

function cryptLoadKey( const Context: CRYPT_CONTEXT;
  const Key: CPTR;
  const KeyLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptAddRandom( RandomData: CPTR;
  const RandomDataLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptGetRandom( RandomData: CPTR;
  const RandomDataLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptGenerateKey( const Context: CRYPT_CONTEXT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptGenerateKeyEx( const Context: CRYPT_CONTEXT;
  const KeyLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptDeriveKey( const Context: CRYPT_CONTEXT;
  const UserKey: CPTR;
  const UserKeyLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptDeriveKeyEx( const Context: CRYPT_CONTEXT;
  const UserKey: CPTR;
  const UserKeyLength: CINT;
  const Algorithm: CRYPT_ALGO;
  const Iterations: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}


{Asynchronous operations}

function cryptGenerateKeyAsync( const Context: CRYPT_CONTEXT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptGenerateKeyAsyncEx( const Context: CRYPT_CONTEXT;
  const KeyLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptAsyncQuery( const Context: CRYPT_CONTEXT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptAsyncCancel( const Context: CRYPT_CONTEXT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}


{Load/retrieve an IV into/from an encryption context}

function cryptLoadIV( const Context: CRYPT_CONTEXT;
  const IV: CPTR;
  const IVLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptRetrieveIV( const Context: CRYPT_CONTEXT;
  IV: CPTR ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}


{Encrypt/decrypt/hash a block of memory}

function cryptEncrypt( const Context: CRYPT_CONTEXT;
  Buffer: CPTR;
  const Length: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptDecrypt( const Context: CRYPT_CONTEXT;
  Buffer: CPTR;
  const Length: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}


{ Get extended information on the last error }

function cryptGetErrorInfo( const cryptHandle: CRYPT_HANDLE;
  var errorCode: CINT;
  errorString: PCCHAR;
  var errorStringLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptGetErrorMessage( const error: CINT;
  messageText: PCCHAR;
  var messageLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}


{------------------------------------------------------------------------------}
{                                                                              }
{                       Mid-level Encryption Functions                         }
{                                                                              }
{------------------------------------------------------------------------------}

{Export and import an encrypted session key object}

function cryptExportKey( EncryptedKey: CPTR;
  var EncryptedKeyLength: CINT;
  const ExportKey: CRYPT_HANDLE;
  const SessionKeyContext: CRYPT_CONTEXT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptExportKeyEx( EncryptedKey: CPTR;
  var EncryptedKeyLength: CINT;
  const formatType: CRYPT_FORMAT_TYPE;
  const ExportKey: CRYPT_HANDLE;
  const SessionKeyContext: CRYPT_CONTEXT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptImportKey( EncryptedKey: CPTR;
  const ImportKey: CRYPT_CONTEXT;
  var SessionKeyContext: CRYPT_CONTEXT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptImportKeyEx( EncryptedKey: CPTR;
  const ImportKey: CRYPT_CONTEXT;
  var SessionKeyContext: CRYPT_CONTEXT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}


{Create and check a digital signature object}

function cryptCreateSignature( Signature: CPTR;
  var SignatureLength: CINT;
  const SignContext: CRYPT_CONTEXT;
  const HashContext: CRYPT_CONTEXT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptCreateSignatureEx( Signature: CPTR;
  var SignatureLength: CINT;
  const FormatType: CRYPT_FORMAT_TYPE;
  const SignContext: CRYPT_CONTEXT;
  const HashContext: CRYPT_CONTEXT;
  const extraData: CRYPT_CERTIFICATE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptCheckSignature( const Signature: CPTR;
  const CheckKey: CRYPT_HANDLE;
  const HashContext: CRYPT_CONTEXT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptCheckSignatureEx( const Signature: CPTR;
  const SignContext: CRYPT_CONTEXT;
  const HashContext: CRYPT_CONTEXT;
  var extraData: CRYPT_HANDLE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}


{Query a cryptlib data object}

function cryptQueryObject( const TheObject: CPTR;
  var ObjectData: CRYPT_OBJECT_INFO ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}



{------------------------------------------------------------------------------}
{                                                                              }
{                       Key Managment Functions                                }
{                                                                              }
{------------------------------------------------------------------------------}

{Open and close a keyset}

function cryptKeysetOpen( var KeySet: CRYPT_KEYSET;
  const KeysetType: CRYPT_KEYSET_TYPE;
  const KeysetName: PCCHAR;
  const Options: CRYPT_KEYOPT_TYPE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptKeysetOpenEx( var KeySet: CRYPT_KEYSET;
  const KeysetType: CRYPT_KEYSET_TYPE;
  const KeysetName: PCCHAR;
  const Server: PCCHAR;
  const Username: PCCHAR;
  const Password: PCCHAR;
  const Options: CRYPT_KEYOPT_TYPE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptKeysetClose( const Keyset: CRYPT_KEYSET ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}


{Get a key from a keyset}

function cryptGetPublicKey( const KeySet: CRYPT_KEYSET;
  var Context: CRYPT_CONTEXT;
  const KeyIDtype: CRYPT_KEYID_TYPE;
  const KeyID: CPTR ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptGetPrivateKey( const KeySet: CRYPT_KEYSET;
  var Context: CRYPT_CONTEXT;
  const KeyIDType: CRYPT_KEYID_TYPE;
  const KeyID: CPTR;
  const Password: PCCHAR ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptCachePrivateKey( const KeySet: CRYPT_KEYSET ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}


{Add/delete a key to/from a keyset}

function cryptAddPublicKey( const KeySet: CRYPT_KEYSET;
  const Certificate: CRYPT_CERTIFICATE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptAddPrivateKey( const KeySet: CRYPT_KEYSET;
  const CryptKey: CRYPT_HANDLE;
  const Password: PCCHAR ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptDeleteKey( const KeySet: CRYPT_KEYSET;
  const KeyIDType: CRYPT_KEYID_TYPE;
  const KeyID: CPTR ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}


{Send a general query to a database keyset}

function cryptKeysetQuery( const KeySet: CRYPT_KEYSET;
  const query: PCCHAR ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}


{Create/destroy a certificate}

function cryptCreateCert( var Certificate: CRYPT_CERTIFICATE;
  const CertificateType: CRYPT_CERTTYPE_TYPE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptDestroyCert( const Certificate: CRYPT_CERTIFICATE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}


{Get/add/delete certificate components and extensions}

function cryptGetCertComponentNumeric( const cryptHandle: CRYPT_HANDLE;
  const ComponentType: CRYPT_CERTINFO_TYPE;
  var ComponentData: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptGetCertComponentString( const cryptHandle: CRYPT_HANDLE;
  const ComponentType: CRYPT_CERTINFO_TYPE;
  ComponentData: PCCHAR;
  var DataLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptAddCertComponentNumeric( const cryptHandle: CRYPT_HANDLE;
  const ComponentType: CRYPT_CERTINFO_TYPE;
  const ComponentData: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptAddCertComponentString( const Certificate: CRYPT_CERTIFICATE;
  const ComponentType: CRYPT_CERTINFO_TYPE;
  const ComponentData: PCCHAR;
  const DataLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptDeleteCertComponent( const Certificate: CRYPT_CERTIFICATE;
  const ComponentType: CRYPT_CERTINFO_TYPE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptGetCertExtension( const cryptHandle: CRYPT_HANDLE;
  const ObjectID: PCCHAR;
  var CriticalFlag: CINT;
  Extension: CPTR;
  var ExtensionLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptAddCertExtension( const Certificate: CRYPT_CERTIFICATE;
  const ObjectID: PCCHAR;
  const CriticalFlag: CINT;
  const Extension: CPTR;
  const ExtensionLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptDeleteCertExtension( const Certificate: CRYPT_CERTIFICATE;
  const ObjectID: PCCHAR ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}



{Sign/Check a certificate/certification request}

function cryptSignCert( const Certificate: CRYPT_CERTIFICATE;
  const Context: CRYPT_CONTEXT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptCheckCert( const Certificate: CRYPT_CERTIFICATE;
  const CheckKey: CRYPT_HANDLE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}


{Import/export a certificate/certification request}

function cryptImportCert( const CertObject: CPTR;
  var Certificate: CRYPT_CERTIFICATE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptExportCert( CertObject: CPTR;
  var CertObjectLength: CINT;
  const FormatType: CRYPT_CERTFORMAT_TYPE;
  const Certificate: CRYPT_CERTIFICATE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}


{------------------------------------------------------------------------------}
{                                                                              }
{                          Data Enveloping Functions                           }
{                                                                              }
{------------------------------------------------------------------------------}

{Create/destroy an envelope}

function cryptCreateEnvelope( var Envelope: CRYPT_ENVELOPE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptCreateDeenvelope( var Envelope: CRYPT_ENVELOPE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptCreateEnvelopeEx( var Envelope: CRYPT_ENVELOPE;
  const FormatType: CRYPT_FORMAT_TYPE;
  const BufferSize: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptCreateDeenvelopeEx( var Envelope: CRYPT_ENVELOPE;
  const FormatType: CRYPT_FORMAT_TYPE;
  const BufferSize: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptDestroyEnvelope( const Envelope: CRYPT_ENVELOPE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}


{Envelope resource query functions (due to be replaced)}

function cryptGetResourceOwnerName( const Envelope: CRYPT_ENVELOPE;
  name: PCCHAR ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

{Get/add envelope components}

function cryptAddEnvComponentNumeric( const Envelope: CRYPT_ENVELOPE;
  const envInfoType: CRYPT_ENVINFO_TYPE;
  const envInfo: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptAddEnvComponentString( const Envelope: CRYPT_ENVELOPE;
  const envInfoType: CRYPT_ENVINFO_TYPE;
  const envInfo: CPTR;
  const envInfoLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptGetEnvComponentNumeric( const Envelope: CRYPT_ENVELOPE;
  const envInfoType: CRYPT_ENVINFO_TYPE;
  var envInfo: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}



{Envelope/deenvelope data}

function cryptPushData( const Envelope: CRYPT_ENVELOPE;
  const Buffer: CPTR;
  const Length: CINT;
  var BytesCopied: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptPopData( const Envelope: CRYPT_ENVELOPE;
  Buffer: CPTR;
  const Length: CINT;
  var BytesCopied: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

{------------------------------------------------------------------------------}
{                      Crypto Device Functions                                 }
{------------------------------------------------------------------------------}

{  Open and close a device }

function cryptDeviceOpen( var device: CRYPT_DEVICE;
  const deviceType: CRYPT_DEVICE_TYPE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptDeviceOpenEx( var device: CRYPT_DEVICE;
  const deviceType: CRYPT_DEVICE_TYPE;
  const param1: PCCHAR;
  const param2: PCCHAR;
  const param3: PCCHAR;
  const param4: PCCHAR ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptDeviceClose( const device: CRYPT_DEVICE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}


{  Query a devices capabilities }

function cryptQueryDeviceCapability( const device: CRYPT_DEVICE;
  const cryptAlgo: CRYPT_ALGO;
  const cryptMode: CRYPT_MODE;
  var cryptQueryInfo: CRYPT_QUERY_INFO ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

{  Create an encryption context via the device }

function cryptDeviceCreateContext( const device: CRYPT_DEVICE;
  var cryptContext: CRYPT_CONTEXT;
  const cryptAlgo: CRYPT_ALGO;
  const cryptMode: CRYPT_MODE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

{  Peform a control function on the device }

function cryptDeviceControl( const device: CRYPT_DEVICE;
  const controlType: CRYPT_DEVICECONTROL_TYPE;
  const data: CPTR;
  const dataLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptDeviceControlEx( const device: CRYPT_DEVICE;
  const controlType: CRYPT_DEVICECONTROL_TYPE;
  const data1: CPTR;
  const data1Length: CINT;
  const data2: CPTR;
  const data2Length: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

{------------------------------------------------------------------------------}
{                          Configuration Functions                             }
{------------------------------------------------------------------------------}

{Get numeric and string configuration options}

function cryptSetOptionNumeric( const Option: CRYPT_OPTION_TYPE;
  const Value: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptSetOptionString( const Option: CRYPT_OPTION_TYPE;
  const Value: PCCHAR ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}


{Set numeric and string configuration options}

function cryptGetOptionNumeric( const Option: CRYPT_OPTION_TYPE;
  var Value: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptGetOptionString( const Option: CRYPT_OPTION_TYPE;
  Value: PCCHAR;
  var ValueLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}


{Read and write configuration options}

function cryptReadOptions:
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

function cryptWriteOptions:
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

{------------------------------------------------------------------------------}

implementation

uses WinTypes, WinProcs;


const
{$IFDEF WIN32}
  CryptLibDLL = 'CL32.DLL';
{$ELSE}
  CryptLibDLL = 'CL16.DLL';
{$ENDIF}


var
  CryptLibDLLHandle: THandle;


{Unit private methods forward declaration}
function GetDLLHandle: THandle; forward;
function FunctionLoadFailed( TheFunctionPtr: TFarProc; var TheResult: CRET ): Boolean; forward;


{Functions to convert to and from the bit counts used for some encryption parameters}

function BitsToBytes( Bits: CINT ): CINT;
begin
  Result := ( Bits + 7 ) shr 3;
end;

function BytesToBits( Bytes: CINT ): CINT;
begin
  Result := Bytes shl 3;
end;


{Macros to initialize and destroy the structure which stores the components
 of a public key}

type
  {Record with the common first two elements of every Public Key component structure.}
  TBasicComponentStructure = record
    Endianness: CINT;
    IsPublicKey: CINT;
  end;
  PBasicComponentStructure = ^TBasicComponentStructure;

function CryptInitComponents( var ComponentInfo: CPTR;
  ComponentSize: CINT;
  ComponentEndianness: CINT;
  ComponentKeyType: CINT ): CRET;
begin
  ComponentInfo := CPTR( LocalAlloc( LPTR, ComponentSize ) );
  PBasicComponentStructure( ComponentInfo )^.Endianness := ComponentEndianness;
  PBasicComponentStructure( ComponentInfo )^.IsPublicKey := ComponentKeyType;
  Result := CRYPT_OK;
end;

function CryptDestroyComponents( ComponentInfo: CPTR ): CRET;
begin
  LocalFree( THandle( ComponentInfo ) );
  Result := CRYPT_OK;
end;

{Macro to set a single component of the public key structure.}
type
  {Data structure common to all components of the public-key algorithm structures.}
  TPublicKeyComponentStructure = record
    Data: TPKCBuffer;
    DataLen: CINT;
  end;
  PPublicKeyComponentStructure = ^TPublicKeyComponentStructure;

function CryptSetComponent( var Destination;
  const Source;
  Length: CINT ): CRET;
begin
  Move( Source, Destination, BitsToBytes( Length ) );
  TPublicKeyComponentStructure( Destination ).DataLen := Length;
  Result := CRYPT_OK;
end;



{Functions to examine return values}

function CryptStatusError( status: CRET ): Boolean;
begin
  Result := ( status < CRYPT_OK );
end;

function CryptStatusOK( status: CRET ): Boolean;
begin
  Result := ( status = CRYPT_OK );
end;

function CryptIsInternalError( Status: CRET ): Boolean;
begin
  Result := ( ( Status >= CRYPT_ERROR ) and ( Status > CRYPT_BADPARM ) );
end;


function CryptIsParamError( Status: CRET ): Boolean;
begin
  Result := ( ( Status >= CRYPT_BADPARM ) and ( Status > CRYPT_NOMEM ) );
end;


function CryptIsResourceError( Status: CRET ): Boolean;
begin
  Result := ( ( Status >= CRYPT_NOMEM ) and ( Status > CRYPT_NOTAVAIL ) );
end;


function CryptIsSecurityError( Status: CRET ): Boolean;
begin
  Result := ( ( Status >= CRYPT_NOTAVAIL ) and ( Status > CRYPT_OVERFLOW ) );
end;


function CryptIsHighLevelError( Status: CRET ): Boolean;
begin
  Result := ( ( Status >= CRYPT_OVERFLOW ) and ( Status > CRYPT_DATA_OPEN ) );
end;


function CryptIsDatasetError( Status: CRET ): Boolean;
begin
  Result := ( ( Status >= CRYPT_DATA_OPEN ) and ( Status > CRYPT_ENVELOPE_RESOURCE ) );
end;


function CryptIsEnvelopeError( Status: CRET ): Boolean;
begin
  Result := ( ( Status >= CRYPT_ENVELOPE_RESOURCE ) and ( Status > CRYPT_DLLNOTLOADED ) );
end;


function CryptIsDLLError( Status: CRET ): Boolean;
begin
  Result := ( ( Status >= CRYPT_DLLNOTLOADED ) and ( Status <= CRYPT_FUNCTIONNOTFOUND ) );
end;


{* * * * * * * * * * * * * * * * * * * * * * * * * *}
{* Cryptlib Delphi-style Exception Implementation  *}
{* * * * * * * * * * * * * * * * * * * * * * * * * *}

resourcestring
    Msg_CRYPT_OK                = 'No Error';
    Msg_CRYPT_ERROR             = 'Unknown internal error';
    Msg_CRYPT_SELFTEST          = 'Failed self-test';
    Msg_CRYPT_BADPARM           = 'Bad argument';
    Msg_CRYPT_BADPARM1          = 'Bad argument to parameter 1';
    Msg_CRYPT_BADPARM2          = 'Bad argument to parameter 2';
    Msg_CRYPT_BADPARM3          = 'Bad argument to parameter 3';
    Msg_CRYPT_BADPARM4          = 'Bad argument to parameter 4';
    Msg_CRYPT_BADPARM5          = 'Bad argument to parameter 5';
    Msg_CRYPT_BADPARM6          = 'Bad argument to parameter 6';
    Msg_CRYPT_BADPARM7          = 'Bad argument to parameter 7';
    Msg_CRYPT_BADPARM8          = 'Bad argument to parameter 8';
    Msg_CRYPT_BADPARM9          = 'Bad argument to parameter 9';
    Msg_CRYPT_BADPARM10         = 'Bad argument to parameter 10';
    Msg_CRYPT_NOMEM             = 'Out of memory';
    Msg_CRYPT_NOTINITED         = 'Data has not been initialised';
    Msg_CRYPT_INITED            = 'Data has already been initialised';
    Msg_CRYPT_NOSECURE          = 'Operation not available at requested sec.level';
    Msg_CRYPT_NOALGO            = 'Algorithm unavailable';
    Msg_CRYPT_NOMODE            = 'Encryption mode unavailable';
    Msg_CRYPT_NOKEY             = 'Key not initialised';
    Msg_CRYPT_NOIV              = 'IV not initialised';
    Msg_CRYPT_NORANDOM          = 'No reliable random data available';
    Msg_CRYPT_NOTAVAIL          = 'Operation not available for this algo/mode';
    Msg_CRYPT_NOPERM            = 'No key permissions for this operation';
    Msg_CRYPT_WRONGKEY          = 'Incorrect key used to decrypt data';
    Msg_CRYPT_INCOMPLETE        = 'Operation incomplete/still in progress';
    Msg_CRYPT_COMPLETE          = 'Operation complete/can''t continue';
    Msg_CRYPT_ORPHAN            = 'Encryption contexts remained allocated';
    Msg_CRYPT_BUSY              = 'Resource in use by async operation';
    Msg_CRYPT_SIGNALLED         = 'Resource destroyed by external event';
    Msg_CRYPT_OVERFLOW          = 'Too much data supplied to function';
    Msg_CRYPT_UNDERFLOW         = 'Not enough data supplied to function';
    Msg_CRYPT_PKCCRYPT          = 'PKC en/decryption failed';
    Msg_CRYPT_BADDATA           = 'Bad data format in object';
    Msg_CRYPT_BADSIG            = 'Bad signature on data';
    Msg_CRYPT_INVALID           = 'Invalid or inconsistent information';
    Msg_CRYPT_DATA_OPEN         = 'Can not open data object';
    Msg_CRYPT_DATA_READ         = 'Can not read item from data object';
    Msg_CRYPT_DATA_WRITE        = 'Can not write item to data object';
    Msg_CRYPT_DATA_NOTFOUND     = 'Requested item not found in data object';
    Msg_CRYPT_DATA_DUPLICATE    = 'Item already present in data object';
    Msg_CRYPT_ENVELOPE_RESOURCE = 'Need resource to proceed';
    Msg_CRYPT_DLLNOTLOADED      = 'Cryptlib DLL could not be loaded';
    Msg_CRYPT_FUNCTIONNOTFOUND  = 'Function not found in Cryptlib DLL';
    Msg_CRYPT                   = 'Unknown CryptLib error';


constructor ECryptError.CreateFromCRET(TheCode: CRET);
begin
  Self.FErrorCode := TheCode;

  case (TheCode) of
    {No  error in function call}
    CRYPT_OK:                 Self.Message := Msg_CRYPT_OK;

    {Internal errors}
    CRYPT_ERROR:              Self.Message := Msg_CRYPT_ERROR;
    CRYPT_SELFTEST:           Self.Message := Msg_CRYPT_SELFTEST;

    {Error in parameters passed to function}
    CRYPT_BADPARM:            Self.Message := Msg_CRYPT_BADPARM;
    CRYPT_BADPARM1:           Self.Message := Msg_CRYPT_BADPARM1;
    CRYPT_BADPARM2:           Self.Message := Msg_CRYPT_BADPARM2;
    CRYPT_BADPARM3:           Self.Message := Msg_CRYPT_BADPARM3;
    CRYPT_BADPARM4:           Self.Message := Msg_CRYPT_BADPARM4;
    CRYPT_BADPARM5:           Self.Message := Msg_CRYPT_BADPARM5;
    CRYPT_BADPARM6:           Self.Message := Msg_CRYPT_BADPARM6;
    CRYPT_BADPARM7:           Self.Message := Msg_CRYPT_BADPARM7;
    CRYPT_BADPARM8:           Self.Message := Msg_CRYPT_BADPARM8;
    CRYPT_BADPARM9:           Self.Message := Msg_CRYPT_BADPARM9;
    CRYPT_BADPARM10:          Self.Message := Msg_CRYPT_BADPARM10;

    {Errors due to insufficient resources}
    CRYPT_NOMEM:              Self.Message := Msg_CRYPT_NOMEM;
    CRYPT_NOTINITED:          Self.Message := Msg_CRYPT_NOTINITED;
    CRYPT_INITED:             Self.Message := Msg_CRYPT_INITED;
    CRYPT_NOSECURE:           Self.Message := Msg_CRYPT_NOSECURE;
    CRYPT_NOALGO:             Self.Message := Msg_CRYPT_NOALGO;
    CRYPT_NOMODE:             Self.Message := Msg_CRYPT_NOMODE;
    CRYPT_NOKEY:              Self.Message := Msg_CRYPT_NOKEY;
    CRYPT_NOIV:               Self.Message := Msg_CRYPT_NOIV;
    CRYPT_NORANDOM:           Self.Message := Msg_CRYPT_NORANDOM;

    {CAPI security violations}
    CRYPT_NOTAVAIL:           Self.Message := Msg_CRYPT_NOTAVAIL;
    CRYPT_NOPERM:             Self.Message := Msg_CRYPT_NOPERM;
    CRYPT_WRONGKEY:           Self.Message := Msg_CRYPT_WRONGKEY;
    CRYPT_INCOMPLETE:         Self.Message := Msg_CRYPT_INCOMPLETE;
    CRYPT_COMPLETE:           Self.Message := Msg_CRYPT_COMPLETE;
    CRYPT_ORPHAN:             Self.Message := Msg_CRYPT_ORPHAN;
    CRYPT_BUSY:               Self.Message := Msg_CRYPT_BUSY;
    CRYPT_SIGNALLED:          Self.Message := Msg_CRYPT_SIGNALLED;

    {High-level function errors}
    CRYPT_OVERFLOW:           Self.Message := Msg_CRYPT_OVERFLOW;
    CRYPT_UNDERFLOW:          Self.Message := Msg_CRYPT_UNDERFLOW;
    CRYPT_PKCCRYPT:           Self.Message := Msg_CRYPT_PKCCRYPT;
    CRYPT_BADDATA:            Self.Message := Msg_CRYPT_BADDATA;
    CRYPT_BADSIG:             Self.Message := Msg_CRYPT_BADSIG;
    CRYPT_INVALID:            Self.Message := Msg_CRYPT_INVALID;

    {Data access function errors}
    CRYPT_DATA_OPEN:          Self.Message := Msg_CRYPT_DATA_OPEN;
    CRYPT_DATA_READ:          Self.Message := Msg_CRYPT_DATA_READ;
    CRYPT_DATA_WRITE:         Self.Message := Msg_CRYPT_DATA_WRITE;
    CRYPT_DATA_NOTFOUND:      Self.Message := Msg_CRYPT_DATA_NOTFOUND;
    CRYPT_DATA_DUPLICATE:     Self.Message := Msg_CRYPT_DATA_DUPLICATE;

    {Data enveloping errors}
    CRYPT_ENVELOPE_RESOURCE:  Self.Message := Msg_CRYPT_ENVELOPE_RESOURCE;

    {DLL failure}
    CRYPT_DLLNOTLOADED:       Self.Message := Msg_CRYPT_DLLNOTLOADED;
    CRYPT_FUNCTIONNOTFOUND:   Self.Message := Msg_CRYPT_FUNCTIONNOTFOUND;

    {Unknown errors}
    else                      Self.Message := Msg_CRYPT;
  end; {case}
end;


{Exception function implementation.}

function CryptCheck( Status: CRET ): CRET;
begin
  if ( CryptStatusError( Status ) ) then begin
    raise CreateCryptError( Status );
  end;
  Result := Status;
end;


function CryptFunctionCheck( func: string; Status: CRET ): CRET;
var
  Exc: Exception;
begin
  if ( CryptStatusError( Status ) ) then begin
    Exc := CreateCryptError( Status );
    Exc.Message := CryptLibDLL + '/' + func + ': ' + Exc.Message;
    raise Exc;
  end;
  Result := Status;
end;


function CreateCryptError( Status: CRET ): Exception;
begin
  if ( CryptIsInternalError( Status ) ) then begin
    result := ECryptInternalError.CreateFromCRET( Status );
  end {if}
  else if ( CryptIsParamError( Status ) ) then begin
    result := ECryptParamError.CreateFromCRET( Status );
  end {else if}
  else if ( CryptIsResourceError( Status ) ) then begin
    result := ECryptResourceError.CreateFromCRET( Status );
  end {else if}
  else if ( CryptIsSecurityError( Status ) ) then begin
    result := ECryptSecurityError.CreateFromCRET( Status );
  end {else if}
  else if ( CryptIsHighLevelError( Status ) ) then begin
    result := ECryptHighLevelError.CreateFromCRET( Status );
  end {else if}
  else if ( CryptIsDataSetError( Status ) ) then begin
    result := ECryptDataSetError.CreateFromCRET( Status );
  end {else if}
  else if ( CryptIsEnvelopeError( Status ) ) then begin
    result := ECryptEnvelopeError.CreateFromCRET( Status );
  end {else if}
  else if ( CryptIsDLLError( Status ) ) then begin
    result := ECryptDLLError.CreateFromCRET( Status );
  end {else if}
  else begin
    result := ECryptError.CreateFromCRET( Status );
  end; {else}
end;



{* * * * * * * * * * * * * * * * * * * * * * * * *}
{*          API Function Implementation  *}
{* * * * * * * * * * * * * * * * * * * * * * * * *}

{Initialise and shut down the encryption library}

function cryptInit:
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function:
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptInit' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction );
end;

function cryptInitEx:
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function:
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptInitEx' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction );
end;

function cryptEnd:
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function:
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptEnd' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction );
end;


{Query the capabilities of the encryption library}

function cryptQueryCapability( const Algorithm: CRYPT_ALGO;
  const Mode: CRYPT_MODE;
  var Information: CRYPT_QUERY_INFO ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Algorithm: CRYPT_ALGO;
    const Mode: CRYPT_MODE;
    var Information: CRYPT_QUERY_INFO ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptQueryCapability' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Algorithm, Mode, Information );
end;

function cryptQueryContext( const Context: CRYPT_CONTEXT;
  var Information: CRYPT_QUERY_INFO ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Context: CRYPT_CONTEXT;
    var Information: CRYPT_QUERY_INFO ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptQueryContext' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Context, Information );
end;


{Initialise and destroy an encryption context}

function cryptCreateContext( var Context: CRYPT_CONTEXT;
  const Algorithm: CRYPT_ALGO;
  const Mode: CRYPT_MODE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( var Context: CRYPT_CONTEXT;
    const Algorithm: CRYPT_ALGO;
    const Mode: CRYPT_MODE ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptCreateContext' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Context, Algorithm, Mode );
end;

function cryptCreateContextEx( var Context: CRYPT_CONTEXT;
  const Algorithm: CRYPT_ALGO;
  const Mode: CRYPT_MODE;
  const ExtendedData: CPTR ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( var Context: CRYPT_CONTEXT;
    const Algorithm: CRYPT_ALGO;
    const Mode: CRYPT_MODE;
    const ExtendedData: CPTR ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptCreateContextEx' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Context, Algorithm, Mode, ExtendedData );
end;

function cryptDestroyContext( const Context: CRYPT_CONTEXT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Context: CRYPT_CONTEXT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptDestroyContext' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Context );
end;


{Generic "destroy an object" function}

function cryptDestroyObject( const ObjectHandle: CRYPT_HANDLE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const ObjectHandle: CRYPT_HANDLE ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptDestroyObject' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( ObjectHandle );
end;


{Get/set object properties}

function cryptGetObjectProperty( const ObjectHandle: CRYPT_HANDLE;
  const propertyType: CRYPT_PROPERTY_TYPE;
  var value: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const ObjectHandle: CRYPT_HANDLE;
    const propertyType: CRYPT_PROPERTY_TYPE;
    var value: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptGetObjectProperty' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( ObjectHandle, propertyType, value );
end;


function cryptSetObjectProperty( const ObjectHandle: CRYPT_HANDLE;
  const propertyType: CRYPT_PROPERTY_TYPE;
  const value: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const ObjectHandle: CRYPT_HANDLE;
    const propertyType: CRYPT_PROPERTY_TYPE;
    const value: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptSetObjectProperty' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( ObjectHandle, propertyType, value );
end;


{Load a user key into an encryption context, add random data to the random
 pool, get medium-strength random data from the random pool, generate a
 key into a context, or derive an encryption key from a variable-length
 user key}

function cryptLoadKey( const Context: CRYPT_CONTEXT;
  const Key: CPTR;
  const KeyLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Context: CRYPT_CONTEXT;
    const Key: CPTR;
    const KeyLength: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptLoadKey' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Context, Key, KeyLength );
end;

function cryptAddRandom( RandomData: CPTR;
  const RandomDataLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( RandomData: CPTR;
    const RandomDataLength: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptAddRandom' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( RandomData, RandomDataLength );
end;

function cryptGetRandom( RandomData: CPTR;
  const RandomDataLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( RandomData: CPTR;
    const RandomDataLength: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptGetRandom' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( RandomData, RandomDataLength );
end;

function cryptGenerateKey( const Context: CRYPT_CONTEXT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Context: CRYPT_CONTEXT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptGenerateKey' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Context );
end;

function cryptGenerateKeyEx( const Context: CRYPT_CONTEXT;
  const KeyLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Context: CRYPT_CONTEXT;
    const KeyLength: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptGenerateKeyEx' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Context, KeyLength );
end;

function cryptDeriveKey( const Context: CRYPT_CONTEXT;
  const UserKey: CPTR;
  const UserKeyLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Context: CRYPT_CONTEXT;
    const UserKey: CPTR;
    const UserKeyLength: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptDeriveKey' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Context, UserKey, UserKeyLength );
end;

function cryptDeriveKeyEx( const Context: CRYPT_CONTEXT;
  const UserKey: CPTR;
  const UserKeyLength: CINT;
  const Algorithm: CRYPT_ALGO;
  const Iterations: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Context: CRYPT_CONTEXT;
    const UserKey: CPTR;
    const UserKeyLength: CINT;
    const Algorithm: CRYPT_ALGO;
    const Iterations: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptDeriveKeyEx' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Context, UserKey, UserKeyLength, Algorithm, Iterations );
end;


{Asynchronous operations}

function cryptGenerateKeyAsync( const Context: CRYPT_CONTEXT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Context: CRYPT_CONTEXT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptGenerateKeyAsync' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Context );
end;

function cryptGenerateKeyAsyncEx( const Context: CRYPT_CONTEXT;
  const KeyLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Context: CRYPT_CONTEXT;
    const KeyLength: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptGenerateKeyAsyncEx' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Context, KeyLength );
end;

function cryptAsyncQuery( const Context: CRYPT_CONTEXT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Context: CRYPT_CONTEXT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptAsyncQuery' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Context );
end;

function cryptAsyncCancel( const Context: CRYPT_CONTEXT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Context: CRYPT_CONTEXT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptAsyncCancel' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Context );
end;


{Load/retrieve an IV into/from an encryption context}

function cryptLoadIV( const Context: CRYPT_CONTEXT;
  const IV: CPTR;
  const IVLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Context: CRYPT_CONTEXT;
    const IV: CPTR;
    const IVLength: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptLoadIV' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Context, IV, IVLength );
end;

function cryptRetrieveIV( const Context: CRYPT_CONTEXT;
  IV: CPTR ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Context: CRYPT_CONTEXT;
    IV: CPTR ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptRetrieveIV' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Context, IV );
end;


{Encrypt/decrypt/hash a block of memory}

function cryptEncrypt( const Context: CRYPT_CONTEXT;
  Buffer: CPTR;
  const Length: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Context: CRYPT_CONTEXT;
    Buffer: CPTR;
    const Length: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptEncrypt' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Context, Buffer, Length );
end;

function cryptDecrypt( const Context: CRYPT_CONTEXT;
  Buffer: CPTR;
  const Length: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Context: CRYPT_CONTEXT;
    Buffer: CPTR;
    const Length: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptDecrypt' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Context, Buffer, Length );
end;


{Open and close a keyset}

function cryptKeysetOpen( var KeySet: CRYPT_KEYSET;
  const KeysetType: CRYPT_KEYSET_TYPE;
  const KeysetName: PCCHAR;
  const Options: CRYPT_KEYOPT_TYPE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( var KeySet: CRYPT_KEYSET;
    const KeysetType: CRYPT_KEYSET_TYPE;
    const KeysetName: PCCHAR;
    const Options: CRYPT_KEYOPT_TYPE ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptKeysetOpen' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( KeySet, KeysetType, KeysetName, Options );
end;

function cryptKeysetOpenEx( var KeySet: CRYPT_KEYSET;
  const KeysetType: CRYPT_KEYSET_TYPE;
  const KeysetName: PCCHAR;
  const Server: PCCHAR;
  const Username: PCCHAR;
  const Password: PCCHAR;
  const Options: CRYPT_KEYOPT_TYPE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( var KeySet: CRYPT_KEYSET;
    const KeysetType: CRYPT_KEYSET_TYPE;
    const KeysetName: PCCHAR;
    const Server: PCCHAR;
    const Username: PCCHAR;
    const Password: PCCHAR;
    const Options: CRYPT_KEYOPT_TYPE ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptKeysetOpenEx' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( KeySet, KeysetType, KeysetName, Server, Username, Password, Options );
end;

function cryptKeysetClose( const Keyset: CRYPT_KEYSET ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Keyset: CRYPT_KEYSET ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptKeysetClose' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Keyset );
end;


{Get a key from a keyset}

function cryptGetPublicKey( const KeySet: CRYPT_KEYSET;
  var Context: CRYPT_CONTEXT;
  const KeyIDtype: CRYPT_KEYID_TYPE;
  const KeyID: CPTR ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const KeySet: CRYPT_KEYSET;
    var Context: CRYPT_CONTEXT;
    const KeyIDtype: CRYPT_KEYID_TYPE;
    const KeyID: CPTR ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptGetPublicKey' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( KeySet, Context, KeyIDType, KeyID );
end;

function cryptGetPrivateKey( const KeySet: CRYPT_KEYSET;
  var Context: CRYPT_CONTEXT;
  const KeyIDType: CRYPT_KEYID_TYPE;
  const KeyID: CPTR;
  const Password: PCCHAR ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const KeySet: CRYPT_KEYSET;
    var Context: CRYPT_CONTEXT;
    const KeyIDType: CRYPT_KEYID_TYPE;
    const KeyID: CPTR;
    const Password: PCCHAR ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptGetPrivateKey' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( KeySet, Context, KeyIDType, KeyID, Password );
end;


function cryptCachePrivateKey( const KeySet: CRYPT_KEYSET ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const KeySet: CRYPT_KEYSET;
    const dmyContext: Pointer;
    const KeyIDType: CRYPT_KEYID_TYPE;
    const KeyID: CPTR;
    const Password: Pointer ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptGetPrivateKey' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( KeySet, nil, CRYPT_KEYID_NONE, nil, nil );
end;


{Add/delete a key to/from a keyset}

function cryptAddPublicKey( const KeySet: CRYPT_KEYSET;
  const Certificate: CRYPT_CERTIFICATE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const KeySet: CRYPT_KEYSET;
    const Certificate: CRYPT_CERTIFICATE ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptAddPublicKey' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Keyset, Certificate );
end;

function cryptAddPrivateKey( const KeySet: CRYPT_KEYSET;
  const CryptKey: CRYPT_HANDLE;
  const Password: PCCHAR ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const KeySet: CRYPT_KEYSET;
    const CryptKey: CRYPT_HANDLE;
    const Password: PCCHAR ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptAddPrivateKey' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( KeySet, CryptKey, Password );
end;

function cryptDeleteKey( const KeySet: CRYPT_KEYSET;
  const KeyIDType: CRYPT_KEYID_TYPE;
  const KeyID: CPTR ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const KeySet: CRYPT_KEYSET;
    const KeyIDType: CRYPT_KEYID_TYPE;
    const KeyID: CPTR ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptDeleteKey' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( KeySet, KeyIDType, KeyID );
end;


function cryptKeysetQuery( const KeySet: CRYPT_KEYSET;
  const query: PCCHAR ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const KeySet: CRYPT_KEYSET;
    const query: PCCHAR ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptKeysetQuery' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( KeySet, query );
end;




{Get extended information on the last error}

function cryptGetErrorInfo( const cryptHandle: CRYPT_HANDLE;
  var ErrorCode: CINT;
  ErrorString: PCCHAR;
  var ErrorStringLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const cryptHandle: CRYPT_HANDLE;
    var ErrorCode: CINT;
    ErrorString: PCCHAR;
    var ErrorStringLength: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptGetErrorInfo' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( cryptHandle, ErrorCode, ErrorString, ErrorStringLength );
end;


function cryptGetErrorMessage( const error: CINT;
  messageText: PCCHAR;
  var messageLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const error: CINT;
    messageText: PCCHAR;
    var messageLength: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptGetErrorMessage' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( error, messageText, messageLength );
end;




{Create/destroy a certificate}

function cryptCreateCert( var Certificate: CRYPT_CERTIFICATE;
  const CertificateType: CRYPT_CERTTYPE_TYPE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( var Certificate: CRYPT_CERTIFICATE;
    const CertificateType: CRYPT_CERTTYPE_TYPE ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptCreateCert' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Certificate, CertificateType );
end;

function cryptDestroyCert( const Certificate: CRYPT_CERTIFICATE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Certificate: CRYPT_CERTIFICATE ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptDestroyCert' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Certificate );
end;


{Get/add/delete certificate components and extensions}

function cryptGetCertComponentNumeric( const cryptHandle: CRYPT_HANDLE;
  const ComponentType: CRYPT_CERTINFO_TYPE;
  var ComponentData: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const cryptHandle: CRYPT_HANDLE;
    const ComponentType: CRYPT_CERTINFO_TYPE;
    var ComponentData: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptGetCertComponentNumeric' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( cryptHandle, ComponentType, ComponentData );
end;

function cryptGetCertComponentString( const cryptHandle: CRYPT_HANDLE;
  const ComponentType: CRYPT_CERTINFO_TYPE;
  ComponentData: PCCHAR;
  var DataLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const cryptHandle: CRYPT_HANDLE;
    const ComponentType: CRYPT_CERTINFO_TYPE;
    ComponentData: PCCHAR;
    var DataLength: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptGetCertComponentString' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( cryptHandle, ComponentType, ComponentData, DataLength );
end;

function cryptAddCertComponentNumeric( const cryptHandle: CRYPT_HANDLE;
  const ComponentType: CRYPT_CERTINFO_TYPE;
  const ComponentData: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const cryptHandle: CRYPT_HANDLE;
    const ComponentType: CRYPT_CERTINFO_TYPE;
    const ComponentData: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptAddCertComponentNumeric' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( cryptHandle, ComponentType, ComponentData );
end;

function cryptAddCertComponentString( const Certificate: CRYPT_CERTIFICATE;
  const ComponentType: CRYPT_CERTINFO_TYPE;
  const ComponentData: PCCHAR;
  const DataLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Certificate: CRYPT_CERTIFICATE;
    const ComponentType: CRYPT_CERTINFO_TYPE;
    const ComponentData: PCCHAR;
    const DataLength: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptAddCertComponentString' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Certificate, ComponentType, ComponentData, DataLength );
end;

function cryptDeleteCertComponent( const Certificate: CRYPT_CERTIFICATE;
  const ComponentType: CRYPT_CERTINFO_TYPE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Certificate: CRYPT_CERTIFICATE;
    const ComponentType: CRYPT_CERTINFO_TYPE ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptDeleteCertComponent' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Certificate, ComponentType );
end;

function cryptGetCertExtension( const cryptHandle: CRYPT_HANDLE;
  const ObjectID: PCCHAR;
  var CriticalFlag: CINT;
  Extension: CPTR;
  var ExtensionLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const cryptHandle: CRYPT_HANDLE;
    const ObjectID: PCCHAR;
    var CriticalFlag: CINT;
    Extension: CPTR;
    var ExtensionLength: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptGetCertExtension' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( cryptHandle, ObjectID, CriticalFlag, Extension, ExtensionLength );
end;

function cryptAddCertExtension( const Certificate: CRYPT_CERTIFICATE;
  const ObjectID: PCCHAR;
  const CriticalFlag: CINT;
  const Extension: CPTR;
  const ExtensionLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Certificate: CRYPT_CERTIFICATE;
    const ObjectID: PCCHAR;
    const CriticalFlag: CINT;
    const Extension: CPTR;
    const ExtensionLength: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptAddCertExtension' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Certificate, ObjectID, CriticalFlag, Extension, ExtensionLength );
end;

function cryptDeleteCertExtension( const Certificate: CRYPT_CERTIFICATE;
  const ObjectID: PCCHAR ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Certificate: CRYPT_CERTIFICATE;
    const ObjectID: PCCHAR ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptDeleteCertExtension' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Certificate, ObjectID );
end;



{Sign/Check a certificate/certification request}

function cryptSignCert( const Certificate: CRYPT_CERTIFICATE;
  const Context: CRYPT_CONTEXT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Certificate: CRYPT_CERTIFICATE;
    const Context: CRYPT_CONTEXT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptSignCert' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Certificate, Context );
end;

function cryptCheckCert( const Certificate: CRYPT_CERTIFICATE;
  const CheckKey: CRYPT_HANDLE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Certificate: CRYPT_CERTIFICATE;
    const CheckKey: CRYPT_HANDLE ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptCheckCert' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Certificate, CheckKey );
end;


{Import/export a certificate/certification request}

function cryptImportCert( const CertObject: CPTR;
  var Certificate: CRYPT_CERTIFICATE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const CertObject: CPTR;
    var Certificate: CRYPT_CERTIFICATE ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptImportCert' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( CertObject, Certificate );
end;

function cryptExportCert( CertObject: CPTR;
  var CertObjectLength: CINT;
  const FormatType: CRYPT_CERTFORMAT_TYPE;
  const Certificate: CRYPT_CERTIFICATE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( CertObject: CPTR;
    var CertObjectLength: CINT;
    const FormatType: CRYPT_CERTFORMAT_TYPE;
    const Certificate: CRYPT_CERTIFICATE ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptExportCert' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( CertObject, CertObjectLength, FormatType, Certificate );
end;


{Export and import an encrypted session key object}

function cryptExportKey( EncryptedKey: CPTR;
  var EncryptedKeyLength: CINT;
  const ExportKey: CRYPT_HANDLE;
  const SessionKeyContext: CRYPT_CONTEXT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( EncryptedKey: CPTR;
    var EncryptedKeyLength: CINT;
    const ExportKey: CRYPT_HANDLE;
    const SessionKeyContext: CRYPT_CONTEXT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptExportKey' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( EncryptedKey, EncryptedKeyLength, ExportKey, SessionKeyContext );
end;

function cryptImportKey( EncryptedKey: CPTR;
  const ImportKey: CRYPT_CONTEXT;
  var SessionKeyContext: CRYPT_CONTEXT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( EncryptedKey: CPTR;
    const ImportKey: CRYPT_CONTEXT;
    var SessionKeyContext: CRYPT_CONTEXT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptImportKey' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( EncryptedKey, ImportKey, SessionKeyContext );
end;

function cryptExportKeyEx( EncryptedKey: CPTR;
  var EncryptedKeyLength: CINT;
  const formatType: CRYPT_FORMAT_TYPE;
  const ExportKey: CRYPT_HANDLE;
  const SessionKeyContext: CRYPT_CONTEXT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( EncryptedKey: CPTR;
    var EncryptedKeyLength: CINT;
    const formatType: CRYPT_FORMAT_TYPE;
    const ExportKey: CRYPT_HANDLE;
    const SessionKeyContext: CRYPT_CONTEXT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptExportKeyEx' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( EncryptedKey, EncryptedKeyLength,
    formatType, ExportKey, SessionKeyContext );
end;

function cryptImportKeyEx( EncryptedKey: CPTR;
  const ImportKey: CRYPT_CONTEXT;
  var SessionKeyContext: CRYPT_CONTEXT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( EncryptedKey: CPTR;
    const ImportKey: CRYPT_CONTEXT;
    var SessionKeyContext: CRYPT_CONTEXT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptImportKeyEx' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( EncryptedKey, ImportKey, SessionKeyContext );
end;


{Create and check a digital signature object}

function cryptCreateSignature( Signature: CPTR;
  var SignatureLength: CINT;
  const SignContext: CRYPT_CONTEXT;
  const HashContext: CRYPT_CONTEXT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( Signature: CPTR;
    var SignatureLength: CINT;
    const SignContext: CRYPT_CONTEXT;
    const HashContext: CRYPT_CONTEXT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptCreateSignature' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Signature, SignatureLength, SignContext, HashContext );
end;

function cryptCreateSignatureEx( Signature: CPTR;
  var SignatureLength: CINT;
  const FormatType: CRYPT_FORMAT_TYPE;
  const SignContext: CRYPT_CONTEXT;
  const HashContext: CRYPT_CONTEXT;
  const extraData: CRYPT_CERTIFICATE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( Signature: CPTR;
    var SignatureLength: CINT;
    const FormatType: CRYPT_FORMAT_TYPE;
    const SignContext: CRYPT_CONTEXT;
    const HashContext: CRYPT_CONTEXT;
    const extraData: CRYPT_CERTIFICATE ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptCreateSignatureEx' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Signature, SignatureLength, FormatType,
    SignContext, HashContext, extraData );
end;

function cryptCheckSignature( const Signature: CPTR;
  const CheckKey: CRYPT_HANDLE;
  const HashContext: CRYPT_CONTEXT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Signature: CPTR;
    const CheckKey: CRYPT_HANDLE;
    const HashContext: CRYPT_CONTEXT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptCheckSignature' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Signature, CheckKey, HashContext );
end;


function cryptCheckSignatureEx( const Signature: CPTR;
  const SignContext: CRYPT_CONTEXT;
  const HashContext: CRYPT_CONTEXT;
  var extraData: CRYPT_HANDLE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Signature: CPTR;
    const SignContext: CRYPT_CONTEXT;
    const HashContext: CRYPT_CONTEXT;
    var extraData: CRYPT_HANDLE ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptCheckSignatureEx' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Signature, SignContext, HashContext, extraData );
end;



{CryptQueryObject is deprecated, but still be needed for exported key and
 signature object types}

function cryptQueryObject( const TheObject: CPTR;
  var ObjectData: CRYPT_OBJECT_INFO ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const TheObject: CPTR;
    var ObjectData: CRYPT_OBJECT_INFO ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptQueryObject' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( TheObject, ObjectData );
end;


{Create/destroy an envelope}

function cryptCreateEnvelope( var Envelope: CRYPT_ENVELOPE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( var Envelope: CRYPT_ENVELOPE ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptCreateEnvelope' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Envelope );
end;

function cryptCreateDeenvelope( var Envelope: CRYPT_ENVELOPE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( var Envelope: CRYPT_ENVELOPE ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptCreateDeenvelope' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Envelope );
end;

function cryptCreateEnvelopeEx( var Envelope: CRYPT_ENVELOPE;
  const FormatType: CRYPT_FORMAT_TYPE;
  const BufferSize: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( var Envelope: CRYPT_ENVELOPE;
    const FormatType: CRYPT_FORMAT_TYPE;
    const BufferSize: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptCreateEnvelopeEx' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Envelope, FormatType, BufferSize );
end;

function cryptCreateDeenvelopeEx( var Envelope: CRYPT_ENVELOPE;
  const FormatType: CRYPT_FORMAT_TYPE;
  const BufferSize: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( var Envelope: CRYPT_ENVELOPE;
    const FormatType: CRYPT_FORMAT_TYPE;
    const BufferSize: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptCreateDeenvelopeEx' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Envelope, FormatType, BufferSize );
end;

function cryptDestroyEnvelope( const Envelope: CRYPT_ENVELOPE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Envelope: CRYPT_ENVELOPE ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptDestroyEnvelope' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Envelope );
end;


{Envelope resource query functions}

function cryptGetResourceOwnerName( const Envelope: CRYPT_ENVELOPE;
  name: PCCHAR ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}

type
  ThisFunctionType = function( const Envelope: CRYPT_ENVELOPE;
    name: PCCHAR ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptGetResourceOwnerName' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Envelope, name );
end;


{Get/add envelope components}

function cryptAddEnvComponentNumeric( const Envelope: CRYPT_ENVELOPE;
  const envInfoType: CRYPT_ENVINFO_TYPE;
  const envInfo: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Envelope: CRYPT_ENVELOPE;
    const envInfoType: CRYPT_ENVINFO_TYPE;
    const envInfo: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptAddEnvComponentNumeric' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Envelope, envInfoType, envInfo );
end;



function cryptAddEnvComponentString( const Envelope: CRYPT_ENVELOPE;
  const envInfoType: CRYPT_ENVINFO_TYPE;
  const envInfo: CPTR;
  const envInfoLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Envelope: CRYPT_ENVELOPE;
    const envInfoType: CRYPT_ENVINFO_TYPE;
    const envInfo: CPTR;
    const envInfoLength: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptAddEnvComponentString' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Envelope, envInfoType, envInfo, envInfoLength );
end;



function cryptGetEnvComponentNumeric( const Envelope: CRYPT_ENVELOPE;
  const envInfoType: CRYPT_ENVINFO_TYPE;
  var envInfo: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Envelope: CRYPT_ENVELOPE;
    const envInfoType: CRYPT_ENVINFO_TYPE;
    var envInfo: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptGetEnvComponentNumeric' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Envelope, envInfoType, envInfo );
end;



{Envelope/deenvelope data}

function cryptPushData( const Envelope: CRYPT_ENVELOPE;
  const Buffer: CPTR;
  const Length: CINT;
  var BytesCopied: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Envelope: CRYPT_ENVELOPE;
    const Buffer: CPTR;
    const Length: CINT;
    var BytesCopied: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptPushData' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Envelope, Buffer, Length, BytesCopied );
end;

function cryptPopData( const Envelope: CRYPT_ENVELOPE;
  Buffer: CPTR;
  const Length: CINT;
  var BytesCopied: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Envelope: CRYPT_ENVELOPE;
    Buffer: CPTR;
    const Length: CINT;
    var BytesCopied: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptPopData' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Envelope, Buffer, Length, BytesCopied );
end;


{Get numeric and string configuration options}

function cryptSetOptionNumeric( const Option: CRYPT_OPTION_TYPE;
  const Value: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Option: CRYPT_OPTION_TYPE;
    const Value: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptSetOptionNumeric' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Option, Value );
end;

function cryptSetOptionString( const Option: CRYPT_OPTION_TYPE;
  const Value: PCCHAR ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Option: CRYPT_OPTION_TYPE;
    const Value: PCCHAR ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptSetOptionString' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Option, Value );
end;


{Set numeric and string configuration options}

function cryptGetOptionNumeric( const Option: CRYPT_OPTION_TYPE;
  var Value: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Option: CRYPT_OPTION_TYPE;
    var Value: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptGetOptionNumeric' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Option, Value );
end;

function cryptGetOptionString( const Option: CRYPT_OPTION_TYPE;
  Value: PCCHAR;
  var ValueLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const Option: CRYPT_OPTION_TYPE;
    Value: PCCHAR;
    var ValueLength: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptGetOptionString' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( Option, Value, ValueLength );
end;


{  Open and close a device }

function cryptDeviceOpen( var device: CRYPT_DEVICE;
  const deviceType: CRYPT_DEVICE_TYPE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( var device: CRYPT_DEVICE;
    const deviceType: CRYPT_DEVICE_TYPE ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptDeviceOpen' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( device, deviceType );
end;


function cryptDeviceOpenEx( var device: CRYPT_DEVICE;
  const deviceType: CRYPT_DEVICE_TYPE;
  const param1: PCCHAR;
  const param2: PCCHAR;
  const param3: PCCHAR;
  const param4: PCCHAR ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( var device: CRYPT_DEVICE;
    const deviceType: CRYPT_DEVICE_TYPE;
    const param1: PCCHAR;
    const param2: PCCHAR;
    const param3: PCCHAR;
    const param4: PCCHAR ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptDeviceOpenEx' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( device, deviceType, param1, param2,
    param3, param4 );
end;


function cryptDeviceClose( const device: CRYPT_DEVICE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const device: CRYPT_DEVICE ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptDeviceClose' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( device );
end;



{  Query a devices capabilities }

function cryptQueryDeviceCapability( const device: CRYPT_DEVICE;
  const cryptAlgo: CRYPT_ALGO;
  const cryptMode: CRYPT_MODE;
  var cryptQueryInfo: CRYPT_QUERY_INFO ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const device: CRYPT_DEVICE;
    const cryptAlgo: CRYPT_ALGO;
    const cryptMode: CRYPT_MODE;
    var cryptQueryInfo: CRYPT_QUERY_INFO ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptQueryDeviceCapability' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( device, cryptAlgo, cryptMode, cryptQueryInfo );
end;


{  Create an encryption context via the device }

function cryptDeviceCreateContext( const device: CRYPT_DEVICE;
  var cryptContext: CRYPT_CONTEXT;
  const cryptAlgo: CRYPT_ALGO;
  const cryptMode: CRYPT_MODE ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const device: CRYPT_DEVICE;
    var cryptContext: CRYPT_CONTEXT;
    const cryptAlgo: CRYPT_ALGO;
    const cryptMode: CRYPT_MODE ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptDeviceCreateContext' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( device, cryptContext,
    cryptAlgo, cryptMode );
end;


{  Peform a control function on the device }

function cryptDeviceControl( const device: CRYPT_DEVICE;
  const controlType: CRYPT_DEVICECONTROL_TYPE;
  const data: CPTR;
  const dataLength: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const device: CRYPT_DEVICE;
    const controlType: CRYPT_DEVICECONTROL_TYPE;
    const data: CPTR;
    const dataLength: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptDeviceControl' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( device, controlType, data, dataLength );
end;

function cryptDeviceControlEx( const device: CRYPT_DEVICE;
  const controlType: CRYPT_DEVICECONTROL_TYPE;
  const data1: CPTR;
  const data1Length: CINT;
  const data2: CPTR;
  const data2Length: CINT ):
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function( const device: CRYPT_DEVICE;
    const controlType: CRYPT_DEVICECONTROL_TYPE;
    const data1: CPTR;
    const data1Length: CINT;
    const data2: CPTR;
    const data2Length: CINT ):
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptDeviceControlEx' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction )( device, controlType,
    data1, data1Length, data2, data2Length );
end;



{Read and write configuration options}

function cryptReadOptions:
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function:
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptReadOptions' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction );
end;

function cryptWriteOptions:
  CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
type
  ThisFunctionType = function:
    CRET; {$IFDEF WIN32} stdcall; {$ENDIF}
var
  ThisFunction: TFarProc;
begin
  ThisFunction := GetProcAddress( GetDLLHandle, PChar( 'cryptWriteOptions' ) );
  if ( FunctionLoadFailed( ThisFunction, Result ) ) then Exit;
  Result := ThisFunctionType( ThisFunction );
end;



{* * * * * * * * * * * * * * * * * * * * * * * * *}
{*       Unit private method Implementation      *}
{* * * * * * * * * * * * * * * * * * * * * * * * *}

function GetDLLHandle: THandle;
begin
  {If the DLL module is invalid, then try to load the DLL.}
  if ( CryptLibDLLHandle < 32 ) then begin
    CryptLibDLLHandle := LoadLibrary( CryptLibDLL );
  end; {if}

  {Return the global handle value.}
  Result := CryptLibDLLHandle;
end;

function FunctionLoadFailed( TheFunctionPtr: TFarProc; var TheResult: CRET ): Boolean;
begin
  {If the DLL Handle is not valid, return that error.}
{$IFDEF WIN32}
  if ( CryptLibDLLHandle = 0 ) then begin
{$ELSE}
    if ( ( CryptLibDLLHandle >= 0 ) and ( CryptLibDLLHandle <= 31 ) ) then begin
{$ENDIF}
      TheResult := CRYPT_DLLNOTLOADED;
      Result := True;
    end
         {If the function pointer is not valid, return that error.}
    else if ( not ( Assigned( TheFunctionPtr ) ) ) then begin
      TheResult := CRYPT_FUNCTIONNOTFOUND;
      Result := True;
    end
         {Everything's cool...}
    else begin
      TheResult := CRYPT_OK;
      Result := False;
    end;
  end;

{Called on application termination, either as an exit proc or in the
        finalization part, depending on the Delphi version.}

procedure DoFinalization;
begin
  {Clean up Cryptlib.}
  CryptEnd;
end;



initialization

  {Initialize Cryptlib.}
  CryptInit;

  {Initialize the random number system with three fast polls. If
   multithreaded Win32, also do a slowpoll. If Win16, just do another
   two fastpolls to finish basic initialization, and let the programmer
   call a slow poll when appropriate.}

  CryptAddRandom(nil, CRYPT_RANDOM_FASTPOLL);
  CryptAddRandom(nil, CRYPT_RANDOM_FASTPOLL);
  CryptAddRandom(nil, CRYPT_RANDOM_FASTPOLL);
{$IFDEF WIN32}
  CryptAddRandom(nil, CRYPT_RANDOM_SLOWPOLL);
  Sleep(1000);
{$ELSE}
  CryptAddRandom(nil, CRYPT_RANDOM_FASTPOLL);
  CryptAddRandom(nil, CRYPT_RANDOM_FASTPOLL);
{$ENDIF}

{$IFNDEF WIN32}
  {If Win16, add an exit procedure to destroy this unit's initialization
   on application termination.}
  AddExitProc(DoFinalization);
{$ENDIF}



{$IFDEF WIN32}
{If Win32, destroy unit initialization.}
finalization

  DoFinalization;

{$ENDIF}

end.
