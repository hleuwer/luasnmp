include config

.PHONY: all clean depend uclean
all:
	cd src && $(MAKE) $@

clean depend:
	cd src && $(MAKE) $@

uclean: clean
	rm -f `find . -name "*~"`

.PHONY: install uninstall install-doc uninstall-doc 

install: all
	mkdir -p $(INSTALL_SHARE) $(INSTALL_LIB)/snmp
	$(INSTALL_DATA) snmp.lua $(INSTALL_SHARE)
	$(INSTALL_DATA) trapd.lua $(INSTALL_SHARE)
	cd src && $(INSTALL_COPY) snmp.$(EXT).$(VERSION) $(INSTALL_LIB)/snmp/core.$(EXT)

uninstall:
	rm -rf $(INSTALL_SHARE)/snmp.lua
	rm -rf $(INSTALL_SHARE)/trapd.lua
	rm -rf $(INSTALL_LIB)/snmp

install-doc:
	mkdir -p $(INSTALL_DOC)/html
	cd doc && $(INSTALL_COPY) * $(INSTALL_DOC)/html

uninstall-doc:
	rm -rf $(INSTALL_DOC)

.PHONY: test testd testtrap testtrapd testtraponly testtraponlyd
test:
	$(LUABIN) test.lua

testd:
	$(LUABIN) test.lua debug

testtrap:
	$(LUABIN) -e "trapyes=true" test.lua

testtrapd:
	$(LUABIN) -e "trapyes=true" test.lua debug

testtraponly:
	$(LUABIN) -e "traponly,trapyes=true,true" test.lua

testtraponlyd:
	$(LUABIN) -e "traponly,trapyes=true,true" test.lua debug

.PHONY: tag tag-git tag-cvs tag-svn
tag: tag-git

tag-git::
	git tag -F latest

tag-cvs::
	cvs tag -F latest

.PHONY: dist dist-git dist-cvs dist-svn
dist: dist-git

dist-git:
	mkdir -p $(EXPORTDIR)
	git archive --format=tar --prefix=$(DISTNAME)/ HEAD | gzip >$(EXPORTDIR)/$(DISTARCH)

dist-cvs::
	mkdir -p $(EXPORTDIR)/$(DISTNAME)
	cvs export -r latest -d $(EXPORTDIR)/$(DISTNAME) $(CVSMODULE)
	cd $(EXPORTDIR); tar -cvzf $(DISTNAME).tar.gz $(DISTNAME)/*
	rm -rf $(EXPORTDIR)/$(DISTNAME)

dist-svn::
	svn export $(REPOSITORY)/$(SVNMODULE) $(EXPORTDIR)/$(DISTNAME)
	cd $(EXPORTDIR); tar -cvzf $(DISTARCH) $(DISTNAME)/*
	rm -rf $(EXPORTDIR)/$(DISTNAME)

