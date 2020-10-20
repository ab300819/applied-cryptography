                                                            Bruce Schneier
                                                          Counterpane Labs
                                                4602 W. Lake Harriet Pkwy.
                                                     Minneapolis, MN 55410

                                                  schneier@counterpane.com
                                               http://www.counterpane.com/

Greetings:

This CD-ROM is the source code that accompanies Applied Cryptography,
Second Edition, plus additional material from public sources.  The source 
code here has been collected from a variety of places.  Some code will not 
run on some machines.  Use them as you see fit, but be aware of any 
copyright notices on the individual files.

See ERRATA.TXT or https://schneier.com/books/applied_cryptography/errata.html
for corrections to the book.

Each file has been compressed.  To uncompress, run:

     UNZIP filename

There is an unzipper included on the CD.

*******************************************************************************

INDEX TO THE SOURCE CODE DISKS  --  VERSION 7.0 - July, 2000.

(A "*" indicates that the file has changed or been added since version 6.0 of
this document.)

*  README.TXT    Author     :  Bruce Schneier
                 E-mail     :  schneier@counterpane.com
                 Date       :  July 00
                 Version    :  7.0
                 Description:  This document.

   UNZIP.EXE     Author     :  S. H. Smith
                 E-mail     :  zip-bugs@cs.ucla.edu
                 Date       :  20 Aug 92
                 Version    :  5.0
                 Description:  Utility to unzip compressed files.

   3-WAY.ZIP     Author     :  Pate Williams
                 E-mail     :  pate@wp-lag.mindspring.com
                 Date       :  1996
                 Description:  3-WAY algorithm.

   A5.ZIP        Date       :  1997
                 Description:  A5 stream cipher, used in GSM cellular.

   ACME.ZIP      Authors    :  Jef Poskanzer and Dave Zimmerman
                 E-mail     :  jef@acme.com (Jef Poskanzer) and
                    dzimm@widget.com (Dave Zimmerman)
                 Date       :  1996
                 Description:  Implementations in Java of DES, IDEA, Blowfish,
                    RC4, and SHA.

   AKELARRE.ZIP  Date       :  1997
                 Description:  Akelarre algorithm.

   ASSORTED.ZIP  Author     :  Eric E. Moore and Thomas W. Strong
                 Date       :  1993
                 Description:  Assorted simple cryptography algorithms. Caesar,
		     Chi-sq, Entropy, Rotor, Vigenere.

   BBC.ZIP       Author     :  Peter Boucher
                 E-mail     :  boucher@csl.sri.com
                 Date       :  1993
                 Description:  Big Block Cipher: uses 256K blocks, three random
                    number generators, two substitution tables, cipher-text
                    feedback, and transpositions.  Unknown security.

   BFSH-ABB.ZIP  Author     :  Pierre Abbat
                 E-mail     :  phma@trellis.net or phma@ix.netcom.com
                 Date       :  1997
                 Description:  Forth implementation of Blowfish algorithm.

   BFSH-ABE.ZIP  Author     :  Ibrahim Abed
                 E-mail     :  badabing@hotmail.com
                 Date       :  1997
                 Description:  C++ implementation of the Blowfish algorithm.

   BFSH-CON.ZIP  Author     :  Jim Conger
                 Date       :  May 96
                 Description:  C++ implementation of the Blowfish algorithm.

*  BFSH-JAV.ZIP  Author     :  Cryptix
                 Description:  Java implementation of the Blowfish algorithm.

   BFSH-KOC.ZIP  Author     :  Paul Kocher
                 E-mail     :  pck@netcom.com
                 Date       :  1997
                 Description:  C implementation of the Blowfish algorithm.

   BFSH-LAC.ZIP  Author     :  Dutra de Lacerda
                 E-mail     :  dulac@ip.pt
                 Date       :  07 Jun 97
                 Version    :  1.5b
                 Description:  Pascal implementation of Blowfish in CBC mode.

   BFSH-NAF.ZIP  Author     :  Raif S. Naffah
                 Date       :  Jun 97
                 Description:  Blowfish implemented in Java.

   BFSH-REF.ZIP  Author     :  Eric Young
                 E-mail     :  eay@cryptsoft.com
                 Reference  :  http://www.counterpane.com/blowfish.html
                 Description:  Reference source code for Blowfish

   BFSH-SCH.ZIP  Author     :  Bruce Schneier
                 E-mail     :  schneier@counterpane.com
                 Date       :  1994
                 Description:  The Blowfish algorithm.

   BFSH-UNK.ZIP  Author     :  Unknown
                 Description:  C++ implementation of the Blowfish algorithm.

   BIGNUM1.ZIP   Author     :  Bruce Bowen
                 E-mail     :  bbowen@megatest.com
		     Reference  :  ftp://idea.sec.dsi.unimi.it/pub/security/crypt/bignum
                 Description:  Bignum class, written in Borland C++.

   BIGNUM2.ZIP   Author     :  Bruce Bowen
                 E-mail     :  bbowen@megatest.com
                 Reference  :  ftp://idea.sec.dsi.unimi.it/pub/security/crypt/bignum
                 Date       :  2 Jan 95
                 Description:  Bignum package.

   BNLIB11.ZIP   Author     :  Colin Plumb
                 E-mail     :  colin@nyx.net
                 Date       :  1995
                 Version    :  1.1
                 Description:  Bnlib integer math package.

   BRUTERC4.ZIP  Author     :  Adam Back and Tatu Ylonen
                 E-mail     :  aba@dcs.ex.ac.uk (Adam Back) and ylo@cs.hut.fi
                    (Tatu Ylonen)
                 Date       :  Jun 97
                 Description:  Quick hacked up RC4 brute force attack program.

   CA1-1.ZIP     Author     :  Howard Gutowitz
                 E-mail     :  gutowitz@amoco.saclay.cea.fr
                 Reference  :  http://www.santafe.edu/~hag
	           Date       :  1992
                 Description:  CA algorithm - cellular automata based cryptosystem.

   CAST-256.ZIP  Author     :  Dr. Brian Gladman (gladman@seven77.demon.co.uk)
                 Date       :  14 Jan 99
                 Description:  CAST-256 AES Submission, in C.

   CAST-BAR.ZIP  Author     :  John T. Barton
                 E-mail     :  barton@best.com
                 Date       :  1997
                 Description:  Implementation of CAST-128 was based on
                    "Constructing Symmetric Ciphers Using the CAST Design
                    Procedure," by Carlisle M. Adams

   CAST-GJK.ZIP  Authors    :  Peter Gutmann, Leonard Janke, and Vesa Karvonen
                 E-mail     :  pgut001@cs.auckland.ac.nz (Peter Gutmann),
                    janke@unixg.ubc.ca (Leonard Janke), and
                    vkarvone@mail.student.oulu.fi (Vesa Karvonen)
                 Reference  :  ftp://ftp.psy.uq.oz.au/pub/Crypto/libeay
                 Date       :  18 Jun 97
                 Version    :  0.1.1
                 Description:  FastCAST is a software library providing Pentium
                    optimized assembly implementations of the block encryption
                    and decryption algorithms used in the CAST-128 cipher.

   CAST-GUT.ZIP  Author     :  Peter Gutmann
                 E-mail     :  pgut001@cs.auckland.ac.nz
                 Date       :  1997
                 Description:  CAST-128 algorithm in C.

   CAST-REI.ZIP  Author     :  Steve Reid
                 E-mail     :  sreid@sea-to-sky.net
                 Date       :  10 Nov 97
                 Description:  Public domain implementation of CAST-128 in C.

   CBW.ZIP       Author     :  Robert W. Baldwin
                 E-mail     :  baldwin@xx.lcs.mit.edu
                 Date       :  Oct 86
                 Description:  Crypt Breaker's Workbench.  Program to help
                    cryptanalyze messages encrypted with crypt(1).

   CHAMBERS.ZIP  Author     :  Bill Chambers
                 E-mail     :  udee205@kcl.ac.uk
                 Date       :  1 Mar 95
                 Description:  A cryptographic pseudo-random number generator,
                    designed and written by Bill Chambers.

   CHI.ZIP       Author     :  Peter Boucher
                 E-mail     :  boucher@csl.sri.com
                 Date       :  12 Nov 93
                 Description:  Counts the occurrences of each character in a
                    file and notifies the user when the distribution is too
                    ragged or too even.

?  CRPT-POL.ZIP  Authors    :  Lance J. Hoffman, Faraz A. Ali, Steven L.
                    Heckler, and Ann Huybrechts
                 Date       :  30 Jan 94
                 Description:  "Cryptography: Policy and Technology," report.

   CRYPT1.ZIP    Description:  UNIX crypt(1) command:  a one-rotor machine
                    designed along the lines of Enigma, but considerably
                    trivialized.

   CRYPT3-L.ZIP  Author     :  Paul Leyland
                 E-mail     :  pcl@ox.ac.uk
                 Date       :  21 Sep 94
                 Description:  UNIX crypt(3) command.

   CRYPT3-T.ZIP  Author     :  Tom Truscott
                 Date       :  21 May 91
                 Version    :  6.7
                 Description:  UNIX crypt(3) command, copyright 1989, 1991 by
                    the University of California.

   CRYPTBAS.ZIP  Author     :  Joseph M. Reage, Jr.
                 E-mail     :  reagle@umbc7.umbc.edu
	           Date       :  25 Jun 96
                 Description:  A few basic cryptographic utilities written by a
                    student for a class.  Includes programs for solving
                    transposition ciphers, Chinese remainder theorem, and
                    breaking really small knapsacks.

   CRYPTL21.ZIP  Authors    :  Peter Gutmann, Eric Young, and Colin Plumb
                 E-mail     :  pgut001@cs.auckland.ac.nz (Peter Gutmann),
                    eay@mincom.oz.au (Eric Young), colin@nyx.net (Colin Plumb)
                 Reference  :  http://www.cs.auckland.ac.nz/~pgut001/cryptlib
                 Date       :  5 Jan 99
                 Version    :  2.1b
                 Description:  The Cryptlib library contains Blowfish, CAST, DES, 
                               triple DES, IDEA, RC2, RC4, RC5, Safer, Safer-SK, 
                               and Skipjack conventional encryption, MD2, MD4, MD5, 
                               RIPEMD-160, and SHA hash algorithms, HMAC-MD5, HMAC-SHA, 
                               HMAC-RIPEMD-160, and MDC-2 MAC algorithms, and 
                               Diffie-Hellman, DSA, Elgamal, and RSA public-key encryption.

*  CRYPTL30.ZIP  Authors    :  Peter Gutmann, Eric Young, and Colin Plumb
                 E-mail     :  pgut001@cs.auckland.ac.nz (Peter Gutmann),
                    eay@mincom.oz.au (Eric Young), colin@nyx.net (Colin Plumb)
                 Reference  :  http://www.cs.auckland.ac.nz/~pgut001/cryptlib
                 Date       :  May 00
                 Version    :  3.0 beta
                 Description:  This beta update to the Cryptlib library has a greatly 
                               simplified interface from the 2.0 version, and many 
                               enhancements and improvements.  It contains Blowfish, 
                               CAST, DES, triple DES, IDEA, RC2, RC4, RC5, Safer, Safer-SK, 
                               and Skipjack conventional encryption, MD2, MD4, MD5, 
                               RIPEMD-160, and SHA hash algorithms, HMAC-MD5, HMAC-SHA, 
                               HMAC-RIPEMD-160, and MDC-2 MAC algorithms, and 
                               Diffie-Hellman, DSA, Elgamal, and RSA public-key encryption.

   CRYPTLIB.ZIP  Author     :  Jack Lacy, Don Mitchell, and Matt Blaze
                 E-mail     :  cryptolib@research.att.com (Jack Lacy),
                    mab@research.att.com (Matt Blaze)
                 Date       :  12 Jan 96
                 Version    :  1.2
                 Description:  The CryptoLib library.

*  CRYPTO32.ZIP  Author     :  Wei Dai
                 E-mail     :  weidai@eskimo.com
                 Reference  :  http://www.eskimo.com/~weidai/cryptlib.html
                 Date       :  20 Mar 00
                 Version    :  3.2
                 Description:  The Crypto++ library is a free C++ class library
                    of cryptographic primitives.  MD2, MD5, SHA-1, HAVAL, Tiger, 
                    RIPE-MD160, MD5-MAC, HMAC, XOR-MAC, CBC-MAC, DMAC, DES, IDEA, 
                    WAKE, 3-WAY, TEA, SAFER, Blowfish, SHARK, GOST, CAST-128, 
                    Square, Diamond2, Sapphire, RC2, RC5, RC6, MARS, Rijndael,
                    Twofish, Serpent SEAL, Luby-Rackoff, MDC, various encryption 
                    modes (CFB, CBC, OFB, counter), DH, DH2, MQV, DSA, NR, 
                    ElGamal, LUC, LUCDIF, LUCELG, Rabin, RW, RSA, BlumGoldwasser, 
                    elliptic curve cryptosystems, BBS, DEFLATE compression, 
                    Shamir's secret sharing scheme, Rabin's information dispersal
                    scheme.  There are also various miscellanous modules such as 
                    base 64 coding and 32-bit CRC.

   CRYPTON.ZIP   Author     :  Dr. Brian Gladman
                 E-mail     :  gladman@seven77.demon.co.uk
                 Date       :  14 Jan 99
                 Description:  Two implementations of CRYPTON, a 128-bit block
                               cipher proposed as an AES standard.    

*  CTXJAVA.ZIP   Author     :  Cryptix Foundation
                 E-mail     :  foundation@cryptix.org
                 Reference  :  http://www.cryptix.org
                 Date       :  17 May 00
                 Version    :  3.1.2
                 Description:  The Cryptix library.  Crypto extensions for Java.  
                    The archive includes source, documentation, and classes.

   CTXPERL.TGZ   Author     :  Cryptix Foundation
                 E-mail     :  foundation@cryptix.org
                 Reference  :  http://www.cryptix.org/products/perl/index.html
                 Date       :  1999
                 Version    :  1.16
                 Description:  The Cryptix library.  Crypto extensions for 
                    Perl.  

   CTXPGP.TGZ    Author     :  Cryptix Foundation
                 E-mail     :  foundation@cryptix.org
                 Reference  :  http://www.cryptix.org/products/perl/index.html
                 Date       :  1997
                 Version    :  0.09
                 Description:  The Cryptix library.  PGP library for Perl.  

   DEAL.ZIP      Author     :  Dr. Brian Gladman
                 E-mail     :  gladman@seven77.demon.co.uk
                 Date       :  14 Jan 99
                 Description:  DEAL block cipher. Candidate for AES.    

*  DELPHI.ZIP    Author     :  Delphi Skunkworks
                 Reference  :  http://www.scramdisk.clara.net/d_crypto.html
                 Date       :  1996
                 Description:  Encryption and hashing routines for BP7 and Delphi.  
                               Contains MD5, RC4, RC5, IDEA, Blowfish and DES.

   DES-BARR.ZIP  Author     :  David A. Barrett
                 E-mail     :  barrett%asgard@boulder.Colorado.EDU
                 Date       :  04 Apr 91
                 Description:  DES implementation, fast.

   DES-BISH.ZIP  Author     :  Matt Bishop
                 E-mail     :  mab@riacs.edu
                 Date       :  1987
                 Description:  Implementation of DES front end; does ECB, CBC,
                    CFB, OFB.  Does not include actual DES code.

   DES-DWY.ZIP   Author     :  Frank O'Dwyer
                 E-mail     :  fod@brd.ie
                 Date       :  1996
                 Description:  Port of part of Eric Young's (eay@mincom.oz.au)
                    DES library to Java.

   DES-KARN.ZIP  Author     :  Phil Karn
                 E-mail     :  karn@servo.qualcomm.com
                 Reference  :  http://people.qualcomm.com/karn/code/des.html
                 Date       :  1987
                 Description:  DES implementation.

   DES-KOON.ZIP  Author     :  David G. Koontz
                 Date       :  1991
                 Description:  DES implementation, fast but large.

   DES-LEVY.ZIP  Author     :  Stuart Levy
                 Date       :  Apr 88
                 Description:  DES implementation, fast and portable.

   DES-LOUK.ZIP  Author     :  Antti Louko
                 E-mail     :  alo@santra.hut.fi
                 Date       :  1992
                 Description:  DES implementation, fast, with main program and
                    C function library for arbitrary precision integer
                    arithmetic.

   DES-MIKK.ZIP  Author     :  Svend Olaf Mikkelsen
                 E-mail     :  svolaf@inet.uni-c.dk
                 Date       :  28 May 97
                 Description:  DES library for MS QuickBasic 4.5 and MS Basic 7.1.

   DES-MITC.ZIP  Author     :  D.P. Mitchell
                 Date       :  08 Jun 83
                 Description:  DES implementation.

   DES-OSTH.ZIP  Author     :  Stig Ostholm
                 E-mail     :  ostholm@ce.chalmers.se
                 Date       :  1990
                 Version    :  1.0
                 Description:  DES implementation with several utility programs
                    and many useful extra functions, runs on UNIX.

   DES-OUTE.ZIP  Author     :  Richard Outerbridge
                 E-mail     :  71755.204@compuserve.com
                 Date       :  1991
                 Description:  DES algorithm, fast and compact.  Supports
                    double and triple DES. Includes portable C version, and
                    optimized 680x0 version.

   DESSBOX.ZIP   Description:  The 2^5 DES S-Boxes.

   DESX.ZIP      Author     :  Richard Outerbridge
                 E-mail     :  71755.204@compuserve.com
                 Date       :  1994
                 Description:  Implementation of DES and DESX.

   DES-YOUN.ZIP  Author     :  Eric Young
                 E-mail     :  eay@mincom.oz.au
                 Date       :  1992
                 Description:  DES implementation, one of the fastest around.

   DHPRIME.ZIP   Author     :  Phil Karn
                 E-mail     :  karn@servo.qualcomm.com
                 Date       :  18 Apr 94
                 Description:  Program for generating Diffie-Hellman primes;
                    i.e., p and (p-1)/2 are prime.

   DFC.ZIP       Author     :  Dr. Brian Gladman
                 E-mail     :  gladman@seven77.demon.co.uk
                 Date       :  14 Jan 99
                 Description:  DFC block cipher, candidate for AES.

   DIAMOND.ZIP   Author     :  Michael Johnson
                 E-mail     :  m.p.johnson@ieee.org
                 Date       :  1995
                 Description:  Michael Johnson's Diamond encryption algorithm.
                    Unknown security.

   E2.ZIP        Author     :  Dr. Brian Gladman
                 E-mail     :  gladman@seven77.demon.co.uk
                 Date       :  14 Jan 99
                 Description:  E2 block cipher, candidate for AES.

   ELIPTIC.ZIP   Author     :  Mike Rosing
                 E-mail     :  cryptech@mcs.net
                 Date       :  1995
                 Version    :  2.1
                 Description:  Elliptic curve public key encryption package.

   ELLIPTIX.ZIP  Author     :  Cryptix Foundation
                 E-Mail     :  pbarreto@cryptix.org
                 Reference  :  http://cryptix.org
                          http://www.bssl.co.uk/mirrors/cryptix/products/elliptix/index.html
                 Date       :  31 Mar 99
                 Version    :  pre-alpha quality - use at your own risk!
                 Description:  Elliptix is intended to be a complete, 100% pure Java
                    implementation of the IEEE P1363, ANSI X9.62, and ANSI X9.63 
                    standards.

   ENIGMA.ZIP    Author     :  Henry Tieman
                 Description:  Software simulation of the German Enigma
                    machine.

   ESCROW.ZIP    Author     :  National Institute of Standards and Technology
                 Date       :  30 Jul 93
                 Description:  A Proposed Federal Information Processing
                    Standard for an Escrowed Encryption Standard (EES).

   EXAMPLES.ZIP  Author     :  Bruce Schneier
                 E-mail     :  schneier@counterpane.com
                 Description:  Code examples from APPLIED CRYPTOGRAPHY.

   FEAL8.ZIP     Date       :  20 Sep 89
                 Description:  FEAL-8 algorithm.

   FEAL8-WI.ZIP  Author     :  Pate Williams
                 E-mail     :  pate@wp-lag.mindspring.com
                 Date       :  1999
                 Description:  FEAL-8 algorithm.

   FEALNX.ZIP    Author     :  Peter Pearson
                 Date       :  28 Dec 92
                 Description:  FEAL-NX algorithm.

   FREQ.ZIP      Author     :  Peter Boucher
                 E-mail     :  boucher@csl.sri.com
                 Date       :  1993
                 Description:  Program to count the frequency of every letter
                    in a file.

   FROG.ZIP      Author     :  Dr. Brian Gladman
                 E-mail     :  gladman@seven77.demon.co.uk
                 Date       :  14 Jan 99
                 Description:  FROG block cipher, candidate for AES.

   FROGC.ZIP     Author     :  TecApro International S.A.
                 E-mail     :  tecapro@tecapro.com
                 Reference  :  http://www.tecapro.com/aesfrog.htm
                 Date       :  15 Jun 98
                 Description:  The FROG block cipher in C, by the group which
                               developed the algorithm.

   FROGJAVA.ZIP  Author     :  TecApro International S.A.
                 E-mail     :  tecapro@tecapro.com
                 Reference  :  http://www.tecapro.com/aesfrog.htm
                 Date       :  15 Jun 98
                 Description:  The FROG block cipher in Java, by the group which
                               developed the algorithm.

   GOST-KOC.ZIP  Author     :  Paul Kocher
                 E-mail     :  pck@netcom.com
                 Date       :  16 Sep 94
                 Description:  Another implementation of the GOST algorithm.
                    Reverse-engineered Sboxes from the program Excellence.

   GOST-PLU.ZIP  Author     :  Colin Plumb
                 E-mail     :  colin@nyx.net
                 Date       :  1993
                 Description:  The Soviet GOST algorithm (without the correct
                    S-boxes).

   HASHES.ZIP    Author     :  Colin Plumb
                 E-mail     :  colin@nyx.net
                 Date       :  Jun 93
                 Description:  MD5 and SHA, optimized for speed.

   HAVAL.ZIP     Author     :  Yuliang Zheng
                 E-mail     :  yuliang@cs.uow.edu.au
                 Reference  :  http://www.pscit.monash.edu.au/~yuliang/src
                 Date       :  Apr 97
                 Version    :  1
                 Description:  HAVAL source code (corrected) plus specification. 

   HAVAL-BA.ZIP  Author     :  Paulo Barreto
                 E-mail     :  pbarreto@uninet.com.br
                 Date       :  07 Apr 97
                 Version    :  1.1
                 Description:  HAVAL algorithm.

   HILL.ZIP      Author     :  John Cowan
                 Date       :  09 Feb 89
                 Reference  :  http://sources.isc.org/utils/misc/hill.txt
                 Description:  Hill cipher.

   HPC.ZIP       Author     :  Dr. Brian Gladman
                 E-mail     :  gladman@seven77.demon.co.uk
                 Date       :  14 Jan 99
                 Description:  HPC block cipher, candidate for AES.

   IDEAPLUS.ZIP  Author     :  Ascom Systec Ltd.
                 Reference  :  http://www.ascom.ch/infosec/downloads.html
                 Version    :  2.1
                 Description:  "Official" IDEA implementation in C, by the
                         group which developed the algorithm.

   IDEA_PLU.ZIP  Author     :  Colin Plumb
                 E-mail     :  colin@nyx.net
                 Date       :  23 Feb 93
                 Description:  IDEA algorithm in C, optimized for speed.

   IDEA_WIL.ZIP  Author     :  Pate Williams
                 E-mail     :  pate@wp-lag.mindspring.com
                 Date       :  1999
                 Description:  IDEA algorithm in C.

   IDEA68K.ZIP   Author     :  Colin Plumb
                 E-mail     :  colin@nyx.net
                 Date       :  1993
                 Description:  IDEA algorithm in 68000 assembly.

   IDEA8086.ZIP  Author     :  Colin Plumb
                 E-mail     :  colin@nyx.net
                 Date       :  1993
                 Description:  IDEA algorithm in 8086 assembly.

   IDEATINY.ZIP  Author     :  Unknown posting to sci.crypt
                 Date       :  Jun 95
                 Description:  Tiny code for IDEA implementation in C.

   I-HAT.ZIP     Author     :  Doug Gwyn
                 E-mail     :  gwyn@arl.mil
                 Date       :  01 Apr 91
                 Description:  C code for various cryptographically useful
                    statistical analysis functions:  Kullback's information
                    measure for a 2-way contingency table, Gamma and repeated
                    functions (Poisson, chi-square, etc.), Pearson's chi-
                    square, etc.

   ISOMORPH.ZIP  Author     :  Paul Leyland
                 E-mail     :  pcl@ox.ac.uk
                 Description:  Utility that prints isomorphs.

   KERBEROS.ZIP  Author     :  Massacusetts Institute of Technology
                 Date       :  1993
                 Version    :  5
                 Description:  Kerberos RFC (1510).

   KHUFU.ZIP     Authors    :  Rayan Zachariassen and Curt Noll
                 E-mail     :  chongo@toad.com (Curt Noll)
                 Date       :  1989
                 Description:  This archive contains KHUFU.C, a hack
                    implementation of the Khufu algorithm.  It also contains
                    PRSBOX.H, PRSBOX.C, and MAKEFILE, a program to print
                    S-boxes.

   KS-TEST.ZIP   Author     :  Peter Boucher
                 E-mail     :  boucher@csl.sri.com
                 Date       :  1994
                 Description:  KS statistical test.

   LCRNG.ZIP     Author     :  Stephen Park and Keith Miller
                 E-mail     :  support@stephsf.com (Stephen Park)
                 Date       :  08 Jan 92
                 Description:  Linear congruential random number generator.

   LCRNG-T.ZIP   Author     :  R.A. O'Keefe
                 Date       :  1992
                 Description:  Simple block transposition cipher based on a
                    linear congruential random number generator.

   LIBCH.ZIP     Author     :  Leonard Janke
                 E-mail     :  janke@unixg.ubc.ca
                 Date       :  Jun 97
                 Description:  A C/C++/Assembly library for doing fast one-way
                    hashing on the Pentium.

   LIBDES.ZIP    Author     :  Eric Young
                 E-mail     :  eay@mincom.oz.au
                 Date       :  13 Jan 97
                 Version    :  4.01
                 Description:  The LibDES kit builds a DES encryption library
                    and a DES encryption program.  It supports ecb, cbc, ofb,
                    cfb, triple ecb, triple cbc, triple ofb, triple cfb, desx,
                    and MIT's pcbc encryption modes and also has a fast
                    implementation of crypt(3).

   LIBRAND.ZIP   Author     :  Matt Blaze
                 E-mail     :  mab@research.att.com
                 Date       :  Jun 97
                 Description:  Truerand is a dubious, unproven hack for
                    generating "true" random numbers in software.

*  LOGI.ZIP      Author     :  Logi Ragnarsson
                 E-mail     :  logir@logi.org
                 Reference  :  http://logi.imf.au.dk/logi.crypto/
                 Version    :  1.07 (the latest stable version)
                 Description:  logi.crypto is a non-certified 100% pure Java 
                    library for using strong encryption in Java 1.1 programs. 
                    It includes tools for encryption and authentication.

*  LOGI-DEV.ZIP  Author     :  Logi Ragnarsson
                 E-mail     :  logir@logi.org
                 Reference  :  http://logi.imf.au.dk/logi.crypto/
                 Version    :  1.1.1 (the latest development version)
                 Description:  logi.crypto is a non-certified 100% pure Java 
                    library for using strong encryption in Java 1.1 programs. 
                    It includes tools for encryption and authentication.

   LOKI.ZIP      Author     :  Matthew Kwan and Lawrence Brown
                 E-mail     :  mkwan@crypto.cs.adfa.oz.au (Matthew Kwan) and
                    lpb@cs.adfa.oz.au (Lawrence Brown)
                 Date       :  Oct 92
                 Version    :  3.0
                 Description:  LOKI89 and LOKI91.

   LOKI97.ZIP    Author     :  Dr. Lawrie Brown
                 E-mail     :  Lawrie.Brown@adfa.edu.au 
                 Reference  :  http://www.adfa.oz.au/~lpb/research/loki97
                 Date       :  30 Apr 99
                 Description:  Loki97 block cipher in C, candidate for AES.                  

   LOKIJAVA.ZIP  Author     :  Dr. Lawrie Brown
                 E-mail     :  Lawrie.Brown@adfa.edu.au 
                 Reference  :  http://www.adfa.oz.au/~lpb/research/loki97
                 Date       :  30 Apr 99
                 Description:  Loki97 block cipher in Java, candidate for AES.

   LUCIFER2.ZIP  Author     :  Graven Cyphers
                 Date       :  1992
                 Description:  LUCIFER algorithm.

*  LUCRE.ZIP     Authors    :  Ben Laurie and Adam Laurie
                 E-mail     :  lucre@aldigital.co.uk
                 Date       :  Aug 2000
                 Description:  lucre is an implementation (in C++ and Java) of 
                    David Wagner's Diffie-Hellman variant on Chaumian blinding.  
                    In theory, it can be used for anonymous digital money and 
                    other untraceable transactions.  There is no connection 
                    between this and "-lucre" except for the name.

   LUCRE081.ZIP  Authors    :  Cypherpunks
                 Date       :  1996
                 Version    :  0.8.1
                 Description:  "-lucre": The Unofficial Cypherpunks Release of
                    Ecash.

   MAGENTA.ZIP   Author     :  Dr. Brian Gladman
                 E-mail     :  gladman@seven77.demon.co.uk
                 Date       :  14 Jan 99
                 Description:  Magenta block cipher, candidate for AES.

   MARS.ZIP      Author     :  Dr. Brian Gladman
                 E-mail     :  gladman@seven77.demon.co.uk
                 Reference  :  http://www.research.ibm.com/security/mars.html
                 Date       :  14 Jan 99
                 Description:  Mars block cipher, candidate for AES.

*  MARS-AES.ZIP  Author     :  IBM (represented by Nevenko Zunic)
                 Reference  :  http://csrc.nist.gov/encryption/aes/round2/r2algs-code.html
                 Date       :  30 Sep 99
                 Description:  Mars block cipher, candidate for AES.  Source code 
                    submitted to NIST for AES.

   MD4.ZIP       Author     :  RSA Data Security, Inc.
                 E-mail     :  rsa-labs@rsa.com
                 Date       :  1992
                 Description:  MD4 algorithm.

   MD4-HOLO.ZIP  Author     :  Jouka Holopainen
                 E-mail     :  jhol@stekt.oulu.fi
                 Date       :  1992
                 Description:  MD4 algorithm, fast DOS implementation.

   MD5.ZIP       Author     :  RSA Data Security, Inc.
                 Description:  RSA Data Security, Inc. MD5 Message-Digest Algorithm,
                    along with the rfc describing it.

   MD5-KAR2.ZIP  Author     :  Phil Karn
                 E-mail     :  karn@servo.qualcomm.com
                 Date       :  1992
                 Description:  Optimization of RSA's MD5 code for 80386.

   MD5-KARN.ZIP  Author     :  Phil Karn
                 E-mail     :  karn@servo.qualcomm.com
                 Date       :  1992
                 Description:  Implementation of Phil Karn's idea for a cipher
                    based upon MD5.  Unknown security.

   MDC.ZIP       Author     :  Peter Gutmann
                 E-mail     :  pgut001@cs.auckland.ac.nz
                 Date       :  Sep 92
                 Description:  Peter Gutmann's Message Digest Cipher.
                    Encryption algorithm which uses MD5 in CFB mode.  Unknown
                    security.

   MD-RFC.ZIP    Author     :  RSA Data Security, Inc.
                 E-mail     :  rsa-labs@rsa.com
                 Date       :  Apr 92
                 Description:  Internet RFCs (Requests for Comment) for MD2,
                    MD4, and MD5.

   MIMIC.ZIP     Author     :  Peter Wayner
                 E-mail     :  wayner@cs.cornell.edu
                 Date       :  1991
                 Description:  Mimic function.

   MMB.ZIP       Author     :  Joan Daemen
                 Description:  An implementation of Joan Daemen's MMB
                    algorithm.

   MPJ2.ZIP      Author     :  Michael Johnson
                 E-mail     :  m.p.johnson@ieee.org
                 Date       :  1993
                 Description:  Michael Johnson's MPJ2.  Unknown security.

   MRRCIP.ZIP    Author     :  Mark Riordan
                 E-mail     :  mrr@scss3.cl.msu.edu
                 Date       :  1988
                 Description:  Implementation of classical ciphers -- Caesar
                    cipher, Playfair digraphic cipher, etc.

   NETSCAPE.ZIP  Author     :  Ian Goldberg and David Wagner
                 E-mail     :  iang@cs.berkeley.edu (Ian Goldberg) and
                    daw@cs.berkeley.edu (David Wagner)
                 Date       :  17 May 95
                 Description:  Break of Netscape's shoddy implementation of SSL
                    on some platforms.

   NEWDE.ZIP     Author     :  Richard Outerbridge
                 E-mail     :  71755.204@compuserve.com
                 Date       :  21 Dec 92
                 Description:  NewDE algorithm, a DES variant used in the
                    Macintosh program StuffIt (versions 1.51 and 2.0).

   NEWDES.ZIP    Author     :  Mark Riordan
                 E-mail     :  mrr@scss3.cl.msu.edu
                 Date       :  12 Aug 90
                 Description:  NewDES algorithm.

   NHASH.ZIP     Date       :  15 Feb 93
                 Description:  N-Hash algorithm.

   NSEA.ZIP      Author     :  Peter Gutmann
                 E-mail     :  pgut001@cs.auckland.ac.nz
                 Date       :  1992
                 Description:  Nonpatented Simple Encryption Algorithm.

*  OPENSSL.ZIP   Author     :  The OpenSSL Project
                 Reference  :  http://www.openssl.org
                 Date       :  3 Apr 2000
                 Version    :  0.9.5a
                 Description:  The OpenSSL Project is a collaborative effort to 
                               develop a robust, commercial-grade, full-featured, 
                               and Open Source toolkit implementing the Secure Sockets 
                               Layer (SSL v2/v3) and Transport Layer Security (TLS v1) 
                               protocols as well as a full-strength general purpose 
                               cryptography library.  OpenSSL is based on the excellent 
                               SSLeay library developed by Eric A. Young and Tim J. Hudson. 

   PATE.ZIP      Author     :  Pate Williams
                 E-mail     :  pate@wp-lag.mindspring.com
                 Reference  :  http://www.mindspring.net/~pate/crypto.html
                 Date       :  1999
                 Description:  Includes block ciphers 3DES, DES, RC5, SAFER-k64;
                      public key algorithms RSA, Rabin, ElGamal, Merkle-Hellman 
                      knapsack; hash functions Matyas-Meyer-Oseas, MDC-2, MDC-4,
                      SHA-1; signature schemes Rabin, Feige-Fiat-Shamir, GQ, DSA,
                      GMR, ESIGN; pseudorandom generators Blum-Blum-Shub,
                      Micali-Schnorr.

   PEGWITC.ZIP   Author     :  George Barwood
                 E-mail     :  george.barwood@dial.pipex.com
                 Reference  :  http://ds.dial.pipex.com/george.barwood/v8/pegwit.htm
                 Date       :  Jun 97
                 Version    :  8
                 Description:  Pegwit is a C program for performing public key
                    encryption and authentication. It uses an elliptic curve
                    over GF(2^255), and the symmetric block cipher Square.

   PEGWITJ.ZIP   Author     :  George Barwood
                 E-mail     :  george.barwood@dial.pipex.com
                 Reference  :  http://ds.dial.pipex.com/george.barwood/v8/pegwit.htm
                 Date       :  Jun 97
                 Description:  Same as above, Java version.

   PJAVA1_1.ZIP  Author     :  George Barwood
                 E-mail     :  george.barwood@dial.pipex.com
                 Reference  :  http://ds.dial.pipex.com/george.barwood/v8/pegwit.htm
                 Date       :  Jun 97
                 Description:  Same as above, Java version with GUI interface.

   GETPGP.ZIP    Date       :  2 Jan 99
                 Reference  :  http://cryptography.org/getpgp.htm
                 Description:  A list of places to download PGP from.

   PIKE.ZIP      Author     :  Ross Anderson
                 Date       :  Dec 94
                 Description:  A stream cipher by Ross Anderson.

   PKC.ZIP       Author     :  James Nechvatal (of NIST)
                 Date       :  Dec 90
                 Description:  Public-Key Cryptography, a 162-page tutorial.

   PLAYFAIR.ZIP  Author     :  Paul Leyland
                 E-mail     :  pcl@ox.ac.uk
                 Date       :  1993
                 Description:  Playfair algorithm.

   PPSC.ZIP      Author     :  Peter Boucher
                 E-mail     :  boucher@csl.sri.com
                 Date       :  1992
                 Description:  Pass-Phrase Stream Cipher.

   PRNGXOR.ZIP   Author     :  Carl Ellison
                 E-mail     :  cme@acm.org
                 Reference  :  http://world.std.com/~cme/
                 Date       :  1993
                 Description:  Source code that illustrates polyalphabetic
                    substitution with a running key stream.

   PRV-ANMT.ZIP  Author     :  L. Detweiler
                 E-mail     :  ld231782@longs.lance.colostate.edu
                 Date       :  09 May 93
                 Version    :  1.0
                 Description:  "Privacy and Anonymity on the Internet":
                    comprehensive summary.

   PYTHON.ZIP    Author     :  A.M. Kuchling
                 Reference  :  ftp://ftp.cwi.nl/pub/pct/
                 Version    :  1.0.0
                 Description:  Python cryptography library.

   QUANTIZE.ZIP  Authors    :  Matt Blaze and Jack Lacy
                 E-mail     :  mab@research.att.com (Matt Blaze),
                    lacy@research.att.com (Jack Lacy)
                 Date       :  Dec 95
                 Version    :  1.0
                 Description:  Simple Unix time quantization package.  Attempt
                    to counter Paul Kocher's (pck@netcom.com) Timing Attacks.

   RADIX64.ZIP   Author     :  Carl Ellison
                 E-mail     :  cme@acm.org
                 Date       :  1995
                 Description:  Radix64 endocing and decoding.

   RAND-BAR.ZIP  Author     :  Chris Barker
                 E-mail     :  barker@ling.rochester.edu
                 Date       :  8 Apr 95
                 Description:  A pseudo-random sequence generator by Chris
                    Barker.

   RAND-ECS.ZIP  Authors    :  Donald E. Eastlake 3rd, Stephen D. Crocker, and
                    Jeffrey I. Schiller
                 E-mail     :  dee@lkg.dec.com (Donald E. Eastlake 3rd),
                    crocker@cybercash.com (Stephen D. Crocker), jis@mit.edu
                    (Jeffrey I. Schiller)
                 Date       :  24 Dec 94
                 Description:  RFC1750, "Randomness Requirements for Security."

   RAND-ELL.ZIP  Author     :  Carl Ellison
                 E-mail     :  cme@acm.org
                 Date       :  1995
                 Description:  Random number mixer: takes in a random source
                    and outputs strong random numbers.

   RAND-GBA.ZIP  Authors    :  Peter Gutmann, Eric Backus, and Ross Anderson
                 E-mail     :  pgut001@cs.auckland.ac.nz (Peter Gutmann),
                    ericb@hplsla.hp.com (Eric Backus), and rja14@cl.cam.ac.uk
                    (Ross Anderson)
                 Date       :  Oct 92
                 Description:  Schematic for cheap hardware random bit
                    generator.

   RAND-HAR.ZIP  Author     :  Brian Harvey
                 E-mail     :  bjh@northshore.ecosoft.com
                 Date       :  08 Dec 93
                 Description:  Random number generator for AT-compatible MS-DOS
                    machines.

   RAND-JEN.ZIP  Author     :  Bob Jenkins
                 E-mail     :  74512.261@CompuServe.com
                 Date       :  1994
                 Description:  A tester of random number generators.

   RAND-MB.ZIP   Author     :  D. P. Mitchell and Matt Blaze
                 E-mail     :  mab@research.att.com (Matt Blaze)
                 Date       :  1995
                 Description:  True random data on a Unix system.  Untested on
                    most machines.

   RAND-SCO.ZIP  Author     :  Mike Scott
                 Description:  Randomness analysis, using Maurer's test.

   RAND-VRI.ZIP  Author     :  Nico E de Vries
                 Date       :  1992
                 Description:  Random number generator that uses phase noise in
                    PC crystals to generate random bits.

   RC2-UNK.ZIP   Author     :  Unknown
                 Date       :  1996
                 Description:  The alleged RC2 cipher, posted anonymously to
                    sci.crypt.

   RC2-FIX.ZIP   Date       :  21 Jan 98
                 Description:  Supposedly corrects a problem with a previous
                    posting of RC2 source code implemented in C++.

   RC4.ZIP       Date       :  1994
                 Description:  The alleged RC4 cipher, posted anonymously to
                    sci.crypt.

   RC4-GUT.ZIP   Author     :  Peter Gutmann
                 E-mail     :  pgut001@cs.auckland.ac.nz
                 Date       :  21 Sep 95
                 Description:  Intel 8086 assembly language implementation of
                    RC4.

   RC5-KEL.ZIP   Author     :  John Kelsey
                 E-mail     :  kelsey@counterpane.com
                 Date       :  20 Mar 95
                 Description:  Implementation of the RC5 algorithm.

   RC5-NIM.ZIP   Author     :  J. Nimmer
                 E-mail     :  jnimmer@aol.com
                 Date       :  2 Jan 95
                 Description:  Reference implementation of the RC5 algorithm.

   RC5-RSA.ZIP   Author     :  RSA Data Security, Inc.
                 E-mail     :  rsa-labs@rsa.com
                 Date       :  1995
                 Description:  The RC5 algorithm -- reference implementation in C.

   RC5-WIL.ZIP   Author     :  Pate Williams
                 E-mail     :  pate@wp-lag.mindspring.com
                 Date       :  1997
                 Description:  The RC5 algorithm.

*  RC6-AES.ZIP   Author     :  RSA Laboratories (represented by Matthew Robshaw)
                 Reference  :  http://csrc.nist.gov/encryption/aes/round2/r2algs-code.html
                 Date       :  30 Sep 99
                 Description:  RC6 block cipher, candidate for AES.  Source code 
                    submitted to NIST for AES.

   RC6.ZIP       Author     :  Dr. Brian Gladman
                 E-mail     :  gladman@seven77.demon.co.uk
                 Date       :  14 Jan 99
                 Description:  RC6 block cipher, candidate for AES.

   REDOC2.ZIP    Author     :  Michael Wood
                 Description:  REDOC2 algorithm.

   REDOC3.ZIP    Author     :  Michael Wood
                 Description:  REDOC3 algorithm.

   RIJNDAEL.ZIP  Author     :  Joan Daemen and Vincent Rijmen 
                 Reference  :  http://www.esat.kuleuven.ac.be/~rijmen/rijndael/
                 Description:  Rijndael block cipher in C, written by the developers
                    of the algorithm. Candidate for AES.

   RIJNJAVA.ZIP  Author     :  Joan Daemen and Vincent Rijmen 
                 Reference  :  http://www.esat.kuleuven.ac.be/~rijmen/rijndael/
                 Description:  Rijndael block cipher in Java, written by the developers
                    of the algorithm, for use with the Cryptix toolkit.

*  RC6-AES.ZIP   Author     :  Joan Daemen, Vincent Rijmen 
                 Reference  :  http://csrc.nist.gov/encryption/aes/round2/r2algs-code.html
                 Date       :  30 Sep 99
                 Description:  Rijndael block cipher, candidate for AES.  Source code 
                    submitted to NIST for AES.

   RIPEM3b4.ZIP  Author     :  Mark Riordan
                 E-mail     :  mrr@scss3.cl.msu.edu
                 Reference  :  ftp://ripem.msu.edu/pub/crypt/ripem/
                 Date       :  Dec 98
                 Version    :  3.0b4
                 Description:  Privacy Enhanced Mail.

   RIPE-MD.ZIP   Author     :  Centre for Mathematics and Computer Science,
                    Amsterdam
                 Date       :  06 May 92
                 Version    :  1.0
                 Description:  RIPE-MD function, written by the RIPE project.

   RIPEM160.ZIP  Author     :  Hans Dobbertin, Antoon Bosselaers, and Bart Preneel
                 E-mail     :  antoon.bosselaers@esat.kuleuven.ac.be
                 Reference  :  http://www.esat.kuleuven.ac.be/~bosselae/ripemd160.html
                 Date       :  18 Apr 96
                 Version    :  1.1
                 Description:  Implementations of RIPEMD-128 and RIPEMD-160.

   RSA-CPP.ZIP   Author     :  George Barwood
                 E-mail     :  george.barwood@dial.pipex.com
                 Reference  :  ftp://ftp.funet.fi/pub/crypt/cryptography/asymmetric/rsa/
                 Date       :  26 Nov 96
                 Description:  RSA public-key encryption in C++.

   RSAEURO.ZIP   Author     :  Reaper Technologies
                 E-mail     :  rsaeuro@repertech.com
                 Date       :  1997
                 Version    :  1.04
                 Description:  RSAEuro library, international RSAREF
                    replacement.

*  RSA_FAQ.ZIP   Author     :  RSA Data Security, Inc.
                 E-mail     :  rsa-labs@rsa.com
                 Reference  :  http://rsa.com/rsalabs/faq
                 Date       :  Apr 00
                 Version    :  4.1
                 Description:  RSA Data Security's Frequently Asked Questions
                    about Cryptography file.

   RSAREF20.ZIP  Author     :  RSA Data Security, Inc.
                 E-mail     :  rsa-labs@rsa.com
                 Date       :  1994
                 Version    :  2.0
                 Description:  Reference implementation of RSA.  Includes code
                    for DES and MD5.  Bignum package can be easily modified to
                    do El Gamal, Diffie-Hellman, DSA, etc.

   RUBY.ZIP      Author     :  Michael Johnson
                 E-mail     :  m.p.johnson@ieee.org
                 Date       :  4 Jan 96
                 Description:  Michael Johnson's Ruby Hash algorithm.  Unknown
                    security.

   RUBY_M5.ZIP   Author     :  Michael Johnson
                 E-mail     :  m.p.johnson@ieee.org
                 Reference  :  http://cryptography.org
	           Description:  Michael Johnson's cipher based on the Ruby Hash. Unknown
                    security.

   S1.ZIP        Date       :  1991
                 Description:  S-1 CIPHER ALGORITHM software chip simulator.
                    Thought to be Skipjack at one point.

   SAFER-MO.ZIP  Author     :  Richard De Moliner
                 E-mail     :  demoliner@isi.ee.ethz.ch
                 Date       :  9 Sep 95
                 Version    :  1.1
                 Description:  Implementations of SAFER K-64, SAFER K-128,
                    SAFER SK-64, and SAFER SK-128.

   SAFER-RO.ZIP  Author     :  Michael Roe
                 E-mail     :  Michael.Roe@cl.cam.ac.uk
                 Date       :  22 Dec 94
                 Description:  Original SAFER algorithm.

   SAFER-WI.ZIP  Author     :  Pate Williams
                 E-mail     :  pate@wp-lag.mindspring.com
                 Date       :  1997
                 Description:  Implementation in C of the SAFER K-64 algorithm.

   SAFER+.ZIP    Author     :  Dr. Brian Gladman
                 E-mail     :  gladman@seven77.demon.co.uk
                 Date       :  14 Jan 99
                 Description:  SAFER+ block cipher, candidate for AES.

   SAPPHIRE.ZIP  Author     :  Michael Johnson
                 E-mail     :  m.p.johnson@ieee.org
                 Date       :  2 Jan 95
                 Description:  Michael Johnson's SAPPHIRE algorithm.  Unknown
                    security.

   SCRT-FIN.ZIP  Author     :  Hal Finney
                 E-mail     :  74076.1041@compuserve.com
                 Date       :  Oct 93
                 Version    :  1.1
                 Description:  Implementation of Shamier secret sharing.

   SCRT-PEA.ZIP  Author     :  Peter Pearson
                 Date       :  15 Feb 93
                 Description:  Code to implement a secret sharing threshold
                    scheme.

   SCRT-WIL.ZIP  Author     :  Pate Williams
                 E-mail     :  pate@wp-lag.mindspring.com
                 Date       :  1997
                 Description:  Shamir secret sharing.

   SEAL-ROE.ZIP  Author     :  Michael Roe
                 E-mail     :  Michael.Roe@cl.cam.ac.uk
                 Date       :  22 Dec 94
                 Description:  SEAL cipher.

   SEAL-WIL.ZIP  Author     :  Pate Williams
                 E-mail     :  pate@wp-lag.mindspring.com
                 Date       :  1997
                 Description:  SEAL cipher.

   SERPENT.ZIP   Author     :  Dr. Brian Gladman
                 E-mail     :  gladman@seven77.demon.co.uk
                 Reference  :  http://www.cl.cam.ac.uk/~rja14/serpent.html
                 Date       :  14 Jan 99
                 Description:  Serpent block cipher, candidate for AES.

*  SERP-AES.ZIP  Author     :  Ross Anderson, Eli Biham, Lars Knudsen 
                 Reference  :  http://csrc.nist.gov/encryption/aes/round2/r2algs-code.html
                 Date       :  30 Sep 99
                 Description:  Serpent block cipher, candidate for AES.  Source code 
                    submitted to NIST for AES.

   SHA-GUT.ZIP   Author     :  Peter Gutmann
                 E-mail     :  pgut001@cs.auckland.ac.nz
                 Date       :  2 Sep 1992
                 Description:  Old Secure Hash Algorithm (SHA-0).

   SHA-REI.ZIP   Author     :  Steve Reid
                 E-mail     :  steve@edmweb.com
                 Date       :  1997
                 Description:  New Secure Hash Algorithm (SHA-1) in C.

   SHA-RUB.ZIP   Author     :  Paul Rubin
                 E-mail     :  phr@netcom.com
                 Date       :  1994
                 Description:  Old Secure Hash Algorithm (SHA-0).

   SNEFRU.ZIP    Author     :  Ralph Merkle
                 E-mail     :  merkle@xerox.com
                 Reference  :  ftp://arisia.xerox.com/pub/hash
                 Date       :  30 Nov 90
                 Version    :  2.5a
                 Description:  Snefru algorthm.

   SNUFFLE.ZIP   Author     :  Dan Bernstein
                 E-mail     :  djb@koobera.math.uic.edu
                 Date       :  1992
                 Description:  Program to turn a one-way hash function into an
                    encryption function.

   SPEED.ZIP     Author     :  Yuliang Zheng
                 E-mail     :  yuliang@cs.uow.edu.au
                 Reference  :  http://www.pscit.monash.edu.au/~yuliang/src
                 Date       :  Feb 97
                 Description:  SPEED block cipher algorithm.

   SPLAY.ZIP     Author     :  Douglas W. Jones
                 E-mail     :  jones@pyrite.cs.uiowa.edu
                 Date       :  20 Feb 89
                 Description:  Compression and encryption in C based on splay
                    trees.

*  SSLEAY.ZIP    Author     :  Eric Young and Tim Hudson
                 E-mail     :  ssleay@cryptsoft.com
                 Reference  :  ftp://ftp.psy.uq.oz.au/pub/Crypto/SSL/
                 Date       :  Jun 98
                 Version    :  0.9.0b
                 Description:  What started as an effort to implement the SSL protocol 
                    turned into a fairly complete cryptographic library. There is also 
                    quite a bit of ASN.1 support, with routines to convert and 
                    manipulate the base ASN.1 types, X509v3 certificates, certificate 
                    requests, certificate revocation lists (CRL), RSA private keys and 
                    DH parameters. There are routines to load and write these objects 
                    in base64 encoding and routines to convert ASN.1 object 
                    identifiers to/from ASCII representations and an internal form. 
                    There are functions for verification of X509 certificates and for 
                    specifying where to look for certificates to 'climb' the x509 
                    'tree'. This last part of the library is still evolving. 

*  STRANDOM.ZIP  Author     :  Yuliang Zheng
                 E-mail     :  yuliang@cs.uow.edu.au
                 Reference  :  http://www.pscit.monash.edu.au/~yuliang/src
                 Date       :  May 00
                 Description:  Pseudo-random number generator, based on HAVAL.

   SURF.ZIP      Author     :  Dan Bernstein
                 E-mail     :  djb@koobera.math.uic.edu
                 Date       :  Jun 97
                 Description:  SURF algorithm.

   TEA-MIR.ZIP   Author     :  Fauzan Mirza
                 Description:  An x86 assembler implementation of the Tiny
                    Encryption Algorithm.

   TEA.C         Authors    :  David Wheeler and Roger Needham
                 Reference  :  http://vader.eeng.brad.ac.uk/tea/tea.shtml
                 Date       :  Nov 94
                 Description:  The Tiny Encryption Algorithm, designed and
                    written by David Wheeler and Roger Needham.

   TIGER.ZIP     Authors    :  Ross Anderson and Eli Biham
                 Reference  :  http://www.cs.technion.ac.il/~biham/Reports/Tiger
	           Description:  Hash function designed by Ross Anderson and
                    Eli Biham.  Designed to be fast on 64-bit processors.
                    Should run on 32-bit processors.
 
   TIGER32.ZIP   Authors    :  Ross Anderson and Eli Biham
                 Reference  :  http://www.cs.technion.ac.il/~biham/Reports/Tiger
	           Description:  Same as above; designed for 32-bit processors.

   TIS-MOSS.ZIP  Author     :  Mark S. Feldman
                 E-mail     :  feldman@tis.com
                 Reference  :  ftp://ftp.tis.com/pub/MOSS/
                 Date       :  28 Aug 96
                 Description:  The Frequently Asked Questions file about the
                    TIS implementation of MOSS (formerly PEM). 

   TRAN.ZIP      Author     :  Carl Ellison
                 E-mail     :  cme@acm.org
                 Date       :  1995
                 Description:  Carl Ellison's TRAN function, a large-block
                    mixing function.

   TRAN-PWD.ZIP  Author     :  Carl Ellison
                 E-mail     :  cme@acm.org
                 Date       :  1995
                 Description:  TRAN with the addition of a key.

   TRNSPOSE.ZIP  Author     :  William Setzer
                 E-mail     :  setzer@math.ncsu.edu
                 Date       :  1992
                 Description:  Cipher that does a transposition of an up to
                     8192-byte block, based on a random number generator.

   TRPLEDES.ZIP  Authors    :  Richard Outerbridge and Graven Imagery
                 E-mail     :  71755.204@compuserve.com
                 Date       :  14 Sep 95
                 Description:  Portable 3DES implementation.

*  2FSH-AES.ZIP  Author     :  Bruce Schneier, John Kelsey, Doug Whiting, David Wagner, 
                    Chris Hall, Niels Ferguson 
                 Reference  :  http://csrc.nist.gov/encryption/aes/round2/r2algs-code.html
                 Date       :  30 Sep 99
                 Description:  Twofish block cipher, candidate for AES.  Source code 
                    submitted to NIST for AES.

*  2FSH-ASM.ZIP  Author     :  Bruce Schneier
                 Reference  :  http://www.counterpane.com/twofish.html
                 Description:  Pentium/Pro/II assembly implementation of Twofish; 
                    candidate for AES.

   2FSH-REF.ZIP  Author     :  Bruce Schneier
                 E-mail     :  schneier@counterpane.com
                 Reference  :  http://www.counterpane.com/twofish.html
                 Description:  Reference C code for the Twofish algorithm; candidate
                    for AES.

   2FSH-OPT.ZIP  Author     :  Bruce Schneier
                 E-mail     :  schneier@counterpane.com
                 Reference  :  http://www.counterpane.com/twofish.html
                 Description:  Optimized C code for the Twofish algorithm; candidate
                    for AES.

   2FSHJAVA.ZIP  Author     :  Bruce Schneier
                 E-mail     :  schneier@counterpane.com
                 Reference  :  http://www.counterpane.com/twofish.html
                 Description:  Java implementation of the Twofish algorithm.

*  2FSH6805.ZIP  Author     :  Doug Whiting
                 E-mail     :  dwhiting@hifn.com
                 Reference  :  http://www.counterpane.com/twofish.html
                 Description:  Twofish 6805 assembly (smart card) implementation; 
                     candidate for AES.

*  2FSH-Z80.ZIP  Author     :  Fritz Schneider
                 E-mail     :  fritz.schneider@iname.com
                 Reference  :  http://www.counterpane.com/twofish.html
                 Description:  Twofish Z80 assembly implementation; candidate
                     for AES.

   TWOFISH.ZIP   Author     :  Dr. Brian Gladman
                 E-mail     :  gladman@seven77.demon.co.uk
                 Date       :  14 Jan 99
                 Description:  Twofish block cipher, candidate for AES.

   VIGENERE.ZIP  Author     :  Leisa Condie
                 E-mail     :  phoenix@neumann.une.edu.au
                 Date       :  Dec 92
                 Description:  A program that encrypts using Vigenere,
                    Beauford, or Variant Beauford ciphers.

   VIGSOLVE.ZIP  Author     :  Mark Riordan
                 E-mail     :  mrr@scss3.cl.msu.edu
                 Date       :  11 Jan 91
                 Description:  Program to find possible solutions to a Vigenere cipher.

*  YARROW.ZIP    Author     :  Ari Benbasat, Bruce Schneier, and John Kelsey
                 E-mail     :  pigsfly@unixg.ubc.ca, schneier@counterpane.com, 
                    kelsey@counterpane.com
                 Reference  :  http://www.counterpane.com/yarrow.html
                 Date       :  May 98
                 Description:  Yarrow is a high-performance, high-security, 
                    pseudo-random number generator (PRNG) for Windows, 
                    Windows NT, and UNIX.  It can provide random numbers for a 
                    variety of cryptographic applications: encryption, 
                    signatures, integrity, etc. 

   ZIP.ZIP       Author     :  Roger Schlafly
                 Description:  The encryption algorithm used in the PKZIP 2.04g
                    and 2.0.1 compression program.

*******************************************************************************
