# This is a Makefile for straps, taken from Makefile for scotty.

# include site configuration file
LUASNMP = ../..
include $(LUASNMP)/config

# Directory in which to install the program straps:
exec_prefix = /usr/local
BIN_INSTALL_DIR = $(exec_prefix)/bin

# To change the compiler switches, for example to change from -O
# to -g, change the following line:
CFLAGS = -O
#CFLAGS += -DSO_REUSEADDR
#CFLAGS += -DHAVE_GETSERVBYNAME

# Linker switch(es) to link platform depended library archives (the
# configure script will try to set this value automatically, but you
# can override it).
#LIBS = -lsocket -lnsl
LIBS = $(SYS_LIBS)

LD = $(CC)
LD_FLAGS = 

# Some versions of make, like SGI's, use the following variable to
# determine which shell to use for executing commands:
SHELL =	/bin/sh

INSTALL = ../../install-sh -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644

all:	straps

install: sinstall

sinstall:	straps
	echo "Installing straps"; \
	$(INSTALL_PROGRAM) -o root -m 4755 straps $(BIN_INSTALL_DIR)/straps
uninstall:
	rm -f $(BIN_INSTALL_DIR)/straps

straps.o: straps.c config.h
	$(CC) -c $(CFLAGS) -I. straps.c

straps:	straps.o
	$(LD) $(LD_FLAGS) -o straps straps.o $(LIBS)

clean:
	rm -f straps.o
	rm -f straps
	rm -f *~
