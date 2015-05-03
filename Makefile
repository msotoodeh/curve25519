# 
# make clean test
#

.PHONY: all clean distclean test asm archive

all: test

test: 
	$(MAKE) -C test test

asm: 
	$(MAKE) -C asm64

clean: 
	$(MAKE) -C test clean
	$(MAKE) -C asm64 clean

distclean: clean
	$(MAKE) -C test distclean
	$(MAKE) -C asm64 distclean
	@rm -rf windows/Debug/ windows/Release/ windows/ipch/ windows/x64/ windows/*.sdf windows/*.suo
	@rm -rf windows/Asm64Lib/x64/ windows/Asm64Test/x64/

archive: distclean
	tar cvf /tmp/curve25519-mehdi-`date '+%Y%m%d'`-src.tar *

