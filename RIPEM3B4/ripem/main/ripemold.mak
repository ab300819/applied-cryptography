# This is a MAKEFILE for Microsoft's NMAKE

# extension for object files
O = obj

# commands
CC = cl

TEMPFILE = temp.mak

RSAREFDIR = ..\rsaref\source\#
CMDLINEDIR = ..\cmdline\#

# The places to look for include files.
INCL =  -I. -I$(CMDLINEDIR) -I$(RSAREFDIR)

# Normal C flags.
#CFLAGS = -Ox -W3 -AL $(INCL) -D__STDC__ -c
#LFLAGS = /stack:26000
CFLAGS = -Od -Zi -W3 -AL $(INCL) -D__STDC__ -c
LFLAGS = /stack:26000 /CODEVIEW

RSAREFLIB = ..\rsaref\install\rsaref.lib
RIPEMLIB = ripem.lib

# Objects common to RIPEM and RCERTS
CMDLINE_OBJS = getsys.obj getopt.obj parsit.obj usage.obj

all : ripem.exe rcerts.exe

ripem.exe : ripemcmd.obj usagemsg.obj $(CMDLINE_OBJS) $(RIPEMLIB) $(RSAREFLIB)
	link @<<temp.lnk
$(LFLAGS) ripemcmd.obj usagemsg.obj $(CMDLINE_OBJS) 
$@,NUL,
$(RIPEMLIB) $(RSAREFLIB);
<<NOKEEP

rcerts.exe : rcerts.obj rcertsms.obj $(CMDLINE_OBJS) $(RIPEMLIB) $(RSAREFLIB)
	link @<<temp.lnk
$(LFLAGS) rcerts.obj rcertsms.obj $(CMDLINE_OBJS) 
$@,NUL,
$(RIPEMLIB) $(RSAREFLIB);
<<NOKEEP

$(RIPEMLIB) : bemparse.obj bfstream.obj certutil.obj crackhed.obj derkey.obj\
  hexbin.obj keyder.obj keyman.obj list.obj pubinfo.obj rdwrmsg.obj\
  ripemmai.obj ripemsoc.obj strutil.obj
  @if NOT EXIST $@ lib $@;
  @echo $@ > $(TEMPFILE)
  @!echo -+$? & >> $(TEMPFILE)
  @echo ;' >> $(TEMPFILE)
  @lib @$(TEMPFILE)

getsys.obj : $(CMDLINEDIR)getsys.c
	$(CC) $(CFLAGS) $(CMDLINEDIR)$*.c

getopt.obj : $(CMDLINEDIR)getopt.c
	$(CC) $(CFLAGS) $(CMDLINEDIR)$*.c

parsit.obj : $(CMDLINEDIR)parsit.c
	$(CC) $(CFLAGS) $(CMDLINEDIR)$*.c

rcerts.obj : $(CMDLINEDIR)rcerts.c
	$(CC) $(CFLAGS) $(CMDLINEDIR)$*.c

rcertsms.obj : $(CMDLINEDIR)rcertsms.c
	$(CC) $(CFLAGS) $(CMDLINEDIR)$*.c

ripemcmd.obj : $(CMDLINEDIR)ripemcmd.c
	$(CC) $(CFLAGS) $(CMDLINEDIR)$*.c

usage.obj : $(CMDLINEDIR)usage.c
	$(CC) $(CFLAGS) $(CMDLINEDIR)$*.c

usagemsg.obj : $(CMDLINEDIR)usagemsg.c
	$(CC) $(CFLAGS) $(CMDLINEDIR)$*.c

