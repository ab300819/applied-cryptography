/* sio.h	- serial I/O handler
 *
 * Copyright 1993-1997, Tim Hudson. All rights reserved.
 *
 * You can pretty much do what you like with this code except pretend that
 * you wrote it provided that any derivative of this code includes the
 * above comments unchanged. If you put this in a product then attribution
 * is mandatory. See the details in the COPYING file.
 *
 * Tim Hudson
 * tjh@cryptsoft.com
 *
 */

#ifndef HEADER_SIO_TJH_H
#define HEADER_SIO_TJH_H

/* Try and figure out if we're running under Windows and/or Win32.  We have
   to jump through all sorts of hoops later on, not helped by the fact that
   the method of detecting Windows at compile time changes with different
   versions of Visual C (it's different for each of VC 2.0, 2.1, 4.0, and
   4.1.  It actually remains the same from 4.1 to 4.2) */

#if !defined( __WINDOWS__ ) && ( defined( _Windows ) || defined( _WINDOWS ) )
  #define __WINDOWS__
#endif /* !__WINDOWS__ && ( _Windows || _WINDOWS ) */
#if !defined( __WIN32__ ) && ( defined( WIN32 ) || defined( _WIN32 ) )
  #ifndef __WINDOWS__
    #define __WINDOWS__
  #endif /* __WINDOWS__ */
  #define __WIN32__
#endif /* !__WIN32__ && ( WIN32 || _WIN32 ) */
#if defined( __WINDOWS__ ) && !defined( __WIN32__ )
  #define __WIN16__
#endif /* __WINDOWS__ && !__WIN32__ */

/* and now I map it to my version of the above define --tjh */
#ifdef __WINDOWS__
#ifndef WINDOWS
#define WINDOWS
#endif
#endif /* __WINDOWS__ */

#ifdef WINDOWS
#define STRCASECMP(X,Y)  stricmp(X,Y)
#else
#define STRCASECMP(X,Y)  strcasecmp(X,Y)
#endif

/* current version ... 1.9 */
#define SIO_VERSION_MAJOR	1
#define SIO_VERSION_MINOR	9

#define SIO_READ_WAIT_DEFAULT  35000 	/* usecs to wait for a char */
#define SIO_READ_WAIT_FOREVER  -1	/* wait until a character arrives */

/* handle ISO7816 fiddles if required */
#define SIO_IOMODE_DIRECT		1
#define SIO_IOMODE_INDIRECT		2

#define SIO_PARITY_ODD	1
#define SIO_PARITY_EVEN	2
#define SIO_PARITY_NONE	3
#define SIO_PARITY_IGNORE	4

/* control modes that can be handled */
#define SIO_CONTROL_RTS	0x0001
#define SIO_CONTROL_DTR	0x0002
#define SIO_CONTROL_DSR	0x0004
#define SIO_CONTROL_CTS	0x0008

#ifndef SIO_INTERNAL_BUILD
typedef struct sio_info SIO_INFO;
#endif /* !SIO_INTERNAL_BUILD */

int SIO_GetVersion(int *vmajor, int *vminor);

SIO_INFO * SIO_Open(char *device);
int SIO_Close(SIO_INFO *s);
int SIO_GetFD(SIO_INFO *s);

int SIO_SetLogFile(SIO_INFO *s,char *name);

int SIO_FilterEcho(SIO_INFO *s,int val);

int SIO_SaveSettings(SIO_INFO *s);
int SIO_RestoreSettings(SIO_INFO *s);

int SIO_ReadSettings(SIO_INFO *s);
int SIO_WriteSettings(SIO_INFO *s);

char *SIO_GetSettingsString(SIO_INFO *s);
int SIO_SetSettingsString(SIO_INFO *s,char *str);

int SIO_WaitForData(SIO_INFO *s,int timedelay);
int SIO_ReadChar(SIO_INFO *s);
int SIO_ReadBuffer(SIO_INFO *s,char *buf,int len);
int SIO_WriteChar(SIO_INFO *s,int data);
int SIO_WriteBuffer(SIO_INFO *s,char *buf,int len);

int SIO_SetIOMode(SIO_INFO *s,int mode);
int SIO_GetIOMode(SIO_INFO *s);
char *SIO_IOMode2String(int iomode);
int SIO_String2IOMode(char *iomode);

int SIO_SetReadTimeout(SIO_INFO *s,long val);
long SIO_GetReadTimeout(SIO_INFO *s);

int SIO_SetSpeed(SIO_INFO *s,long speed);
long SIO_GetSpeed(SIO_INFO *s);
int SIO_SetDataBits(SIO_INFO *s,int databits);
int SIO_GetDataBits(SIO_INFO *s);
int SIO_SetStopBits(SIO_INFO *s,int stopbits);
int SIO_GetStopBits(SIO_INFO *s);
int SIO_SetParity(SIO_INFO *s,int parity);
int SIO_GetParity(SIO_INFO *s);
char *SIO_Parity2String(int parity);
int SIO_String2Parity(char *parity);

int SIO_ReadControlState(SIO_INFO *s);
int SIO_WriteControlState(SIO_INFO *s);
int SIO_GetControlState(SIO_INFO *s,int ctrl);
int SIO_SetControlState(SIO_INFO *s,int ctrl,int val);
char *SIO_ControlState2String(SIO_INFO *s);

/* convience macros to make doing common things via the low-level
 * stuff less likely to make the code look like spagetti
 */
#define SIO_DropRTS(X)	SIO_SetControlState((X),SIO_CONTROL_RTS,0),\
						SIO_WriteControlState(X)
#define SIO_RaiseRTS(X)	SIO_SetControlState((X),SIO_CONTROL_RTS,1),\
						SIO_WriteControlState(X)
#define SIO_DropDTR(X)	SIO_SetControlState((X),SIO_CONTROL_DTR,0),\
						SIO_WriteControlState(X)
#define SIO_RaiseDTR(X)	SIO_SetControlState((X),SIO_CONTROL_DTR,1),\
						SIO_WriteControlState(X)

int SIO_Delay(SIO_INFO *s,unsigned long delay);

#endif /* HEADER_SIO_TJH_H */

