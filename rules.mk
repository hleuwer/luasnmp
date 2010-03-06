
include ../../config

# System and target names
SYSTEM=$(shell uname -o)
ifeq ($(SYSTEM), Cygwin)
SOEXT=.dll
DLIB = $(MODULE)$(SOEXT)
DLIBV= $(DLIB)
else
SOEXT=.so
DLIB = $(MODULE)$(SOEXT)
DLIBV = $(DLIB).$(VERSION)
endif
MODL=$(MODULE).lua
SLIB = lib$(MODULE).a

# Lua 
LUA=../..
LUABIN=$(LUA)/bin/lua50
LUAINC=$(LUA)/include
LUALIB=$(LUA)/lib
LUALUA=$(LUA)/lua
LUAWB=$(LUA)/doc/luawb
LUAUTIL=$(LUA)/utils


# Lua Doc - TODO
LUADOCHOME=$(LUAUTIL)/luadoc20
LUADOC20=$(LUADOCHOME)/luadoc20.lua
LUADOCOPTS=$(shell cat $(LUADOCHOME)/luadoc20/luadoc.config) --noindexpage
LUADOCBIN=$(LUABIN) -e "LUADOC_HOME='$(LUADOCHOME)'" $(LUADOC20) 

# Lua Lint
LUALINT=$(LUAUTIL)/lualint/lualint

# Lua 5.1 package compatibility
LUACOMPAT=$(LUA)/modules/compat-5.1r4
COMPATOBJ=$(LUACOMPAT)/compat-5.1.o
COMPATINC=$(LUACOMPAT)

# Tolua stuff
TOLUA=$(LUA)/../tolua++-1.0.6
TOLUABIN=$(TOLUA)/bin/tolua++106
TOLUALIB=$(TOLUA)/lib
TOLUAINC=$(TOLUA)/include/
BINDC = $(MODULE)bind.c
BINDOBJ = $(MODULE)bind.o
BINDCXX = $(MODULE)bind.cpp
BINDH = $(MODULE)bind.h
BINDHPP = $(MODULE)bind.hpp
PKG = $(MODULE).pkg

# Compiler
ifeq ($(USE_CPLUSPLUS), yes)
CC = c++
LD = c++
else
CC = gcc
LD = gcc
endif
CXX = c++
INCS = -I$(LUAINC) -I$(TOLUAINC) -I$(LUACOMPAT)
CFLAGS = $(INCS) $(WARN) $(USERCFLAGS)
CXXFLAGS = $(INCS) $(WARN) $(USERCXXFLAGS)
LDFLAGS = -L$(TOLUALIB) $(USERLDFLAGS)
WARN = -Wall

# Libraries to link against
LIBDIR=
LIBS=
ifeq ($(USE_READLINE), yes)
  LIBS += -lreadline -lncurses -lhistory
endif
ifeq ($(USE_TOLUA), yes)
  LIBDIR += -L$(TOLUALIB)
  LIBS += -ltolua++106
endif

# Installation stuff
INSTALL_DIR=$(INSTALL_ROOT)
INSTALL_SHARE=$(INSTALL_DIR)/share/lua/5.0
INSTALL_LIB=$(INSTALL_DIR)/lib/lua/5.0

# Documentation stuff
SUBST= $(shell cat ../luadoc20/luadoc.config)

# TARGETS

ifeq ($(LMOD), yes)
ifeq ($(CMOD), yes)
# Primary module is Lua, Secondary is C
mall: $(DLIBV) $(MODULE)/core$(SOEXT)
endif
else
# Primary module is C
mall: $(DLIBV) $(DLIB)
endif



ifeq ($(SYSTEM), Cygwin)
$(DLIB): $(OBJS) $(COMPATOBJ) $(CXXOBJS) Makefile.deps Makefile
	$(LD) -o $@ -shared  -Wl,--export-all-symbols,--output-def,$(MODULE).def,--out-implib,$(DLIB).a $(LDFLAGS) $(OBJS) $(COMPATOBJ) $(CXXOBJS) $(LIBDIR) $(LIBS) -L$(LUALIB) -llua$X -llualib$X $(USERLIBDIR) $(USERLIBS)
else
$(DLIBV): $(OBJS) $(COMPATOBJ) $(CXXOBJS) Makefile.deps Makefile
	$(LD) -o $@ -shared $(LDFLAGS) $(OBJS) $(COMPATOBJ) $(CXXOBJS) $(LIBDIR) $(LIBS) $(USERLIBDIR) $(USERLIBS)

$(DLIB): $(DLIBV)
	ln -f -s $(DLIBV) $(DLIB)
endif

$(SLIB): $(OBJS) $(CXXOBJS) Makefile Makefile.deps
	ar rcu $(SLIB) $(OBJS) $(CXXOBJS)
	ranlib $(SLIB)

$(MODULE)/core$(SOEXT): $(DLIBV)
	mkdir -p $(MODULE)
	cp $(DLIBV) $(MODULE)/core$(SOEXT)

$(BINDC) $(BINDH): $(PKG)
	$(TOLUABIN) -1 -o $(BINDC) -H $(BINDH) $(PKG)

$(BINDCXX) $(BINDHPP): $(PKG) 
	$(TOLUABIN) -1 -o $(BINDCXX) -H $(BINDHPP) $(PKG)


# Generic rules
.SUFFIXES: .o .s .c .cpp .cxx .lch .lc .lua

.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<

.cxx.cpp:
	cp $*.cxx $*.cpp

.cpp.o:
	$(CXX) -c $(CXXFLAGS) -o $@ $<

.cpp.s:
	$(CXX) -c -Wa,-alh,-L -dA $(CXXFLAGS) -o $@ $< > $*.L

.lua.lc:
	$(LUACBIN) -o $@ $<

.lc.lch:
	$(BIN2CBIN) $< > $@

.PHONY: install webbook clean uclean depend test testa


# Entries in the WEBBOOK based documentation
webbook:
	mkdir -p $(LUAWB)/en/modules/$(MODULE)
	if test -e manual.html; then cp -f manual.html $(LUAWB)/en/modules/$(MODULE); fi
	if test -e $(MODULE).html; then cp -f $(MODULE).html $(LUAWB)/en/modules/$(MODULE); fi
	if test -e README; then cp -f README $(LUAWB)/en/modules/$(MODULE); fi
	if test -e README.leu; then cp -f README $(LUAWB)/en/modules/$(MODULE); fi
	if test -e $(DOCDIR); then for i in $(DOCS); do cp -f $(DOCDIR)/$$i $(LUAWB)/en/modules/$(MODULE); done; fi

# Cleanup stuff
muclean: mclean

mclean: 
	rm -f $(OBJS) $(CXXOBJS) $(BINDC) $(BINDCXX) $(BINDH) $(BINDHPP) \
	      $(SLIB) $(DLIB).$(VERSION) $(DLIB) $(DLIB).a $(MODULE).def \
	      lib$(DLIB).$(VERSION) lib$(DLIB) \
	      core core.* a.out *~ Makefile.deps \
	      semantic.cache*
ifeq ($(LMOD), yes)
ifeq ($(CMOD), yes)
	rm -rf $(MODULE)
endif
endif


# Dependency stuff
mdepend: Makefile.deps

ifeq ($(USE_BINDDEPEND), yes)
Makefile.deps: $(BINDH) $(BINDHPP) $(OBJS:.o=.c) $(CXXOBJS:.o=.cpp) $(HDRS)
else
Makefile.deps:$(OBJS:.o=.c) $(CXXOBJS:.o=.cpp) $(HDRS)
endif
	rm -f Makefile.deps
	test -z "$(CXXOBJS)" || $(CXX) -MM $(CXXFLAGS) $(CXXOBJS:.o=.cpp) >> Makefile.deps
	test -z "$(OBJS)" || $(CC) -MM $(CFLAGS) $(OBJS:.o=.c) >> Makefile.deps

# Testing
mtest:
	@if test -e test.lua; then \
	  $(LUABIN) -l $(MODULE) test.lua $(LOG); \
	fi

mtesta:
ifeq ($(SYSTEM), Cygwin)
	@if test -e test.lua; then $(LUABIN) -e "LUA_LIBNAME='lib?.dll'" -l $(MODULE) test.lua; fi
else
	@if test -e test.lua; then $(LUABIN) -e "LUA_LIBNAME='lib?.so'" -l $(MODULE) test.lua; fi
endif


# Documentation
mdoc:$(MODULE).html

$(MODULE).html:
	$(LUADOCBIN) $(LUADOCOPTS) -d . $(MODULE).lua

mclean-doc:
	rm -f $(MODULE).html

# Installation
minstall:
ifeq ($(LMOD), yes)
        # Install <module>.lua if LMOD == yes
	mkdir -p $(INSTALL_SHARE) 
	cp $(MODULE).lua $(INSTALL_SHARE)
ifeq ($(CMOD), yes)
        # Install core.<soext> if CMOD == yes  
	mkdir -p $(INSTALL_LIB)/$(MODULE)
	cp $(DLIBV) $(INSTALL_LIB)/$(MODULE)/core$(SOEXT)
endif

else

ifeq ($(SYSTEM), Cygwin)
        # Cygwin install
        # Install <module>.dll if LMOD != yes
	mkdir -p $(INSTALL_LIB)
	cp $(DLIB) $(INSTALL_LIB)
#	if test -e $(MODULE).lua; then \
#	  mkdir -p $(INSTALL_SHARE); \
#	  cp $(MODULE).lua $(INSTALL_SHARE); \
#	fi
else
        # Linux install
        # Install <module>.so if LMOD != yes
	mkdir -p $(INSTALL_LIB)
	cp $(DLIBV) $(INSTALL_LIB)/$(DLIB)
#	if test -e $(MODULE).lua; then \
#	  mkdir -p $(INSTALL_SHARE); \
#	  cp $(MODULE).lua $(INSTALL_SHARE); \
#	fi
endif
endif
        # Finally, do a module private install

muninstall:
	cd $(INSTALL_LIB); rm -f $(DLIB) $(SLIB) 
	cd $(INSTALL_LIB); rm -rf $(MODULE) 
	cd $(INSTALL_SHARE); rm -f $(MODULE).lua

show:
	@echo "DLIB = "$(DLIB)
	@echo "DLIBV = "$(DLIBV)

type:
ifeq ($(CMOD), yes)
ifeq ($(LMOD), yes)
	@echo "C LUA"
else
	@echo "C"
endif
endif
ifeq ($(LMOD), yes)
ifneq ($(CMOD), yes)
	@echo "LUA"
endif
endif

ifeq ($(CMOD), yes)
ifneq ($(USE_DEPS), no)
-include Makefile.deps
endif
endif