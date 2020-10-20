# Microsoft Developer Studio Project File - Name="Crypt32" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 5.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=CRYPT32 - WIN32 RELEASE
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "Crypt32.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "Crypt32.mak" CFG="CRYPT32 - WIN32 RELEASE"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "Crypt32 - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "Crypt32 - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir ".\Release"
# PROP BASE Intermediate_Dir ".\Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir ".\Release"
# PROP Intermediate_Dir ".\Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
F90=fl32.exe
# ADD BASE F90 /I "Release/"
# ADD F90 /I "Release/"
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MT /W3 /O2 /D "NDEBUG" /D "INC_CHILD" /D "DBX_LDAP" /D "DBX_HTTP" /FD /c
# SUBTRACT CPP /YX
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib odbc32.lib /nologo /subsystem:windows /dll /pdb:none /machine:I386 /out:".\Release/CL32.dll"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir ".\Debug"
# PROP BASE Intermediate_Dir ".\Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir ".\Test32"
# PROP Intermediate_Dir ".\Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
F90=fl32.exe
# ADD BASE F90 /I "Debug/"
# ADD F90 /I "Debug/"
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MT /W3 /Gm /Zi /Od /D "_DEBUG" /D "INC_CHILD" /D "DBX_LDAP" /D "DBX_HTTP" /FD /c
# SUBTRACT CPP /YX
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:I386
# ADD LINK32 kernel32.lib user32.lib /nologo /subsystem:windows /dll /pdb:none /debug /machine:I386 /out:".\Test32/CL32.dll"

!ENDIF 

# Begin Target

# Name "Crypt32 - Win32 Release"
# Name "Crypt32 - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;hpj;bat;for;f90"
# Begin Source File

SOURCE=\ZLIB\ADLER32.C
# End Source File
# Begin Source File

SOURCE=\KEYMGMT\ASN1.C
# End Source File
# Begin Source File

SOURCE=\KEYMGMT\ASN1KEYS.C
# End Source File
# Begin Source File

SOURCE=\KEYMGMT\ASN1OBJS.C
# End Source File
# Begin Source File

SOURCE=\KEYMGMT\ASN1OID.C
# End Source File
# Begin Source File

SOURCE="\CRYPT\B-WIN32.OBJ"
# End Source File
# Begin Source File

SOURCE=\CRYPT\BF_ECB.C
# End Source File
# Begin Source File

SOURCE=\CRYPT\BF_SKEY.C
# End Source File
# Begin Source File

SOURCE="\BN\BN-WIN32.OBJ"
# End Source File
# Begin Source File

SOURCE=\BN\BN_ADD.C
# End Source File
# Begin Source File

SOURCE=\BN\BN_BLIND.C
# End Source File
# Begin Source File

SOURCE=\BN\BN_DIV.C
# End Source File
# Begin Source File

SOURCE=\BN\BN_EXP.C
# End Source File
# Begin Source File

SOURCE=\BN\BN_GCD.C
# End Source File
# Begin Source File

SOURCE=\BN\BN_LIB.C
# End Source File
# Begin Source File

SOURCE=\BN\BN_MOD.C
# End Source File
# Begin Source File

SOURCE=\BN\BN_MONT.C
# End Source File
# Begin Source File

SOURCE=\BN\BN_MUL.C
# End Source File
# Begin Source File

SOURCE=\BN\BN_RECP.C
# End Source File
# Begin Source File

SOURCE=\BN\BN_SHIFT.C
# End Source File
# Begin Source File

SOURCE=\BN\BN_SQR.C
# End Source File
# Begin Source File

SOURCE=\BN\BN_SUB.C
# End Source File
# Begin Source File

SOURCE=\BN\BN_WORD.C
# End Source File
# Begin Source File

SOURCE="\CRYPT\C-WIN32.OBJ"
# End Source File
# Begin Source File

SOURCE=\CRYPT\C_ECB.C
# End Source File
# Begin Source File

SOURCE=\CRYPT\C_SKEY.C
# End Source File
# Begin Source File

SOURCE=\KEYMGMT\CERT.C
# End Source File
# Begin Source File

SOURCE=\KEYMGMT\CERTCHK.C
# End Source File
# Begin Source File

SOURCE=\KEYMGMT\CERTCHN.C
# End Source File
# Begin Source File

SOURCE=\KEYMGMT\CERTCOMP.C
# End Source File
# Begin Source File

SOURCE=\KEYMGMT\CERTECHK.C
# End Source File
# Begin Source File

SOURCE=\KEYMGMT\CERTEDEF.C
# End Source File
# Begin Source File

SOURCE=\KEYMGMT\CERTEXRW.C
# End Source File
# Begin Source File

SOURCE=\KEYMGMT\CERTEXT.C
# End Source File
# Begin Source File

SOURCE=\KEYMGMT\CERTIO.C
# End Source File
# Begin Source File

SOURCE=\KEYMGMT\CERTRUST.C
# End Source File
# Begin Source File

SOURCE=\KEYMGMT\CERTSIG.C
# End Source File
# Begin Source File

SOURCE=\KEYMGMT\CERTSTR.C
# End Source File
# Begin Source File

SOURCE=\KEYMGMT\CMS.C
# End Source File
# Begin Source File

SOURCE=\CRYPT.C
# End Source File
# Begin Source File

SOURCE=.\CRYPT32.DEF
# End Source File
# Begin Source File

SOURCE=.\CRYPT32.RC
# End Source File
# Begin Source File

SOURCE=\CRYPTAPI.C
# End Source File
# Begin Source File

SOURCE=\CRYPTCAP.C
# End Source File
# Begin Source File

SOURCE=\CRYPTCFG.C
# End Source File
# Begin Source File

SOURCE=\CRYPTCRT.C
# End Source File
# Begin Source File

SOURCE=\CRYPTDBX.C
# End Source File
# Begin Source File

SOURCE=\CRYPTDEV.C
# End Source File
# Begin Source File

SOURCE=\CRYPTENV.C
# End Source File
# Begin Source File

SOURCE=\CRYPTKEY.C
# End Source File
# Begin Source File

SOURCE=\CRYPTKRN.C
# End Source File
# Begin Source File

SOURCE=\CRYPTLIB.C
# End Source File
# Begin Source File

SOURCE="\CRYPT\D-WIN32.OBJ"
# End Source File
# Begin Source File

SOURCE=\MISC\DBXFILE.C
# End Source File
# Begin Source File

SOURCE=\MISC\DBXHTTP.C
# End Source File
# Begin Source File

SOURCE=\MISC\DBXLDAP.C
# End Source File
# Begin Source File

SOURCE=\MISC\DBXMSQL.C
# End Source File
# Begin Source File

SOURCE=\MISC\DBXODBC.C
# End Source File
# Begin Source File

SOURCE=\ENVELOPE\DEENVEL.C
# End Source File
# Begin Source File

SOURCE=\ZLIB\DEFLATE.C
# End Source File
# Begin Source File

SOURCE=\MISC\DEV_CEI.C
# End Source File
# Begin Source File

SOURCE=\MISC\DEV_FORT.C
# End Source File
# Begin Source File

SOURCE=\MISC\DEV_PK11.C
# End Source File
# Begin Source File

SOURCE=\CRYPT\ECB3_ENC.C
# End Source File
# Begin Source File

SOURCE=\CRYPT\ECB_ENC.C
# End Source File
# Begin Source File

SOURCE=\ENVELOPE\ENVELOPE.C
# End Source File
# Begin Source File

SOURCE=\ZLIB\GVMAT32.OBJ
# End Source File
# Begin Source File

SOURCE=\CRYPT\IDEA.C
# End Source File
# Begin Source File

SOURCE=..\CRYPT\IDEA_386.C
# End Source File
# Begin Source File

SOURCE=\ZLIB\INFBLOCK.C
# End Source File
# Begin Source File

SOURCE=\ZLIB\INFCODES.C
# End Source File
# Begin Source File

SOURCE=\ZLIB\INFFAST.C
# End Source File
# Begin Source File

SOURCE=\ZLIB\INFLATE.C
# End Source File
# Begin Source File

SOURCE=\ZLIB\INFTREES.C
# End Source File
# Begin Source File

SOURCE=\ZLIB\INFUTIL.C
# End Source File
# Begin Source File

SOURCE=\LIB_3DES.C
# End Source File
# Begin Source File

SOURCE=\LIB_BF.C
# End Source File
# Begin Source File

SOURCE=..\LIB_CAST.C
# End Source File
# Begin Source File

SOURCE=\LIB_DBMS.C
# End Source File
# Begin Source File

SOURCE=\LIB_DES.C
# End Source File
# Begin Source File

SOURCE=\LIB_DH.C
# End Source File
# Begin Source File

SOURCE=\LIB_DSA.C
# End Source File
# Begin Source File

SOURCE=\LIB_ELG.C
# End Source File
# Begin Source File

SOURCE=\LIB_HMD5.C
# End Source File
# Begin Source File

SOURCE=\LIB_HRMD.C
# End Source File
# Begin Source File

SOURCE=\LIB_HSHA.C
# End Source File
# Begin Source File

SOURCE=\LIB_IDEA.C
# End Source File
# Begin Source File

SOURCE=..\LIB_KEYX.C
# End Source File
# Begin Source File

SOURCE=\LIB_KG.C
# End Source File
# Begin Source File

SOURCE=\LIB_MD2.C
# End Source File
# Begin Source File

SOURCE=\LIB_MD4.C
# End Source File
# Begin Source File

SOURCE=\LIB_MD5.C
# End Source File
# Begin Source File

SOURCE=\LIB_MDC2.C
# End Source File
# Begin Source File

SOURCE=\LIB_RAND.C
# End Source File
# Begin Source File

SOURCE=\LIB_RC2.C
# End Source File
# Begin Source File

SOURCE=\LIB_RC4.C
# End Source File
# Begin Source File

SOURCE=\LIB_RC5.C
# End Source File
# Begin Source File

SOURCE=\LIB_RIPE.C
# End Source File
# Begin Source File

SOURCE=\LIB_RSA.C
# End Source File
# Begin Source File

SOURCE=\LIB_SAFR.C
# End Source File
# Begin Source File

SOURCE=\LIB_SHA.C
# End Source File
# Begin Source File

SOURCE=..\LIB_SIGN.C
# End Source File
# Begin Source File

SOURCE=\LIB_SKIP.C
# End Source File
# Begin Source File

SOURCE="\HASH\M-WIN32.OBJ"
# End Source File
# Begin Source File

SOURCE=\HASH\MD2.C
# End Source File
# Begin Source File

SOURCE=\HASH\MD4.C
# End Source File
# Begin Source File

SOURCE=\HASH\MD5_DGST.C
# End Source File
# Begin Source File

SOURCE=\HASH\MDC2DGST.C
# End Source File
# Begin Source File

SOURCE=\envelope\octetstr.C
# End Source File
# Begin Source File

SOURCE=\ENVELOPE\PGP_DEEN.C
# End Source File
# Begin Source File

SOURCE=\KEYMGMT\PGP_KEY.C
# End Source File
# Begin Source File

SOURCE=\ENVELOPE\PGP_MISC.C
# End Source File
# Begin Source File

SOURCE="\CRYPT\R-WIN32.OBJ"
# End Source File
# Begin Source File

SOURCE=\CRYPT\RC2.C
# End Source File
# Begin Source File

SOURCE=\CRYPT\RC4_SKEY.C
# End Source File
# Begin Source File

SOURCE=\CRYPT\RC5.C
# End Source File
# Begin Source File

SOURCE=\MISC\REGISTRY.C
# End Source File
# Begin Source File

SOURCE=\ENVELOPE\RESOURCE.C
# End Source File
# Begin Source File

SOURCE=\HASH\RIPEMD.C
# End Source File
# Begin Source File

SOURCE=\HASH\RMD160CP.C
# End Source File
# Begin Source File

SOURCE=\MISC\RNDWIN32.C
# End Source File
# Begin Source File

SOURCE="\HASH\S-WIN32.OBJ"
# End Source File
# Begin Source File

SOURCE=\CRYPT\SAFER.C
# End Source File
# Begin Source File

SOURCE=\MISC\SCASE.C
# End Source File
# Begin Source File

SOURCE=\MISC\SCAUTO.C
# End Source File
# Begin Source File

SOURCE=\MISC\SCGEMPLU.C
# End Source File
# Begin Source File

SOURCE=\MISC\SCMISC.C
# End Source File
# Begin Source File

SOURCE=\MISC\SCTOWITO.C
# End Source File
# Begin Source File

SOURCE=\CRYPT\SET_KEY.C
# End Source File
# Begin Source File

SOURCE=\HASH\SHA1DGST.C
# End Source File
# Begin Source File

SOURCE=\HASH\SHA_DGST.C
# End Source File
# Begin Source File

SOURCE=\MISC\SIO.C
# End Source File
# Begin Source File

SOURCE=\CRYPT\SKIPJACK.C
# End Source File
# Begin Source File

SOURCE=\KEYMGMT\STREAM.C
# End Source File
# Begin Source File

SOURCE=\ZLIB\TREES.C
# End Source File
# Begin Source File

SOURCE=\KEYMGMT\X509_KEY.C
# End Source File
# Begin Source File

SOURCE=\ZLIB\ZUTIL.C
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl;fi;fd"
# Begin Source File

SOURCE=\KEYMGMT\asn1.h
# End Source File
# Begin Source File

SOURCE=\KEYMGMT\asn1keys.h
# End Source File
# Begin Source File

SOURCE=\KEYMGMT\asn1misc.h
# End Source File
# Begin Source File

SOURCE=\keymgmt\asn1objs.h
# End Source File
# Begin Source File

SOURCE=\bnlib\bn.h
# End Source File
# Begin Source File

SOURCE=\crypt.h
# End Source File
# Begin Source File

SOURCE=\ZLIB\deflate.h
# End Source File
# Begin Source File

SOURCE=\crypt\idea.h
# End Source File
# Begin Source File

SOURCE=\ZLIB\infblock.h
# End Source File
# Begin Source File

SOURCE=\ZLIB\infcodes.h
# End Source File
# Begin Source File

SOURCE=\ZLIB\inffast.h
# End Source File
# Begin Source File

SOURCE=\ZLIB\inftrees.h
# End Source File
# Begin Source File

SOURCE=\ZLIB\infutil.h
# End Source File
# Begin Source File

SOURCE=\BNLIB\lbnmem.h
# End Source File
# Begin Source File

SOURCE=\BNLIB\legal.h
# End Source File
# Begin Source File

SOURCE=\hash\md2.h
# End Source File
# Begin Source File

SOURCE=\hash\md4.h
# End Source File
# Begin Source File

SOURCE=\hash\md5.h
# End Source File
# Begin Source File

SOURCE=\KEYMGMT\pgp_idea.h
# End Source File
# Begin Source File

SOURCE=\crypt\rc2.h
# End Source File
# Begin Source File

SOURCE=\crypt\rc4.h
# End Source File
# Begin Source File

SOURCE=\crypt\rc5.h
# End Source File
# Begin Source File

SOURCE=\hash\ripemd.h
# End Source File
# Begin Source File

SOURCE=\crypt\safer.h
# End Source File
# Begin Source File

SOURCE=\hash\sha.h
# End Source File
# Begin Source File

SOURCE=\keymgmt\stream.h
# End Source File
# Begin Source File

SOURCE=\ZLIB\zutil.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;cnt;rtf;gif;jpg;jpeg;jpe"
# Begin Source File

SOURCE=.\CRYPT32.ICO
# End Source File
# End Group
# End Target
# End Project
