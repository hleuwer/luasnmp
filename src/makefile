include ../config

OBJS += nm_snmp.o nm_util.o nm_trap.o nm_mib.o except.o

all: $(LUASNMP_SO)

$(LUASNMP_SO): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $^ $(LIBS)
	mkdir -p ../snmp
	cp $(LUASNMP_SO) ../snmp/core.$(EXT)

clean:
	rm -f $(OBJS) $(LUASNMP_SO) 
	rm -rf ../snmp
	rm -rf makefile.deps

depend: makefile.deps

makefile.deps: $(OBJS:.o=.c)
	rm -f makefile.deps
	test -z "$(OBJS)" || $(CC) -MM $(CFLAGS) $(OBJS:.o=.c) >> makefile.deps

-include makefile.deps