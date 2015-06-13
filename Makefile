# 
#   env RELEASE=1 make clean test asm
#
#   make -C custom          creates source/custom_blind.c
#                           should be called first
#
#   make test               create library and test file
#                           uses portable-c code
#
#   make asm                builds 64-bit library and test code
#                           uses ASM code
#

.PHONY: all clean distclean test asm archive

all: test

test: 
	$(MAKE) -C custom
	$(MAKE) -C test test

asm: 
	$(MAKE) -C custom
	$(MAKE) -C source/asm64

clean: 
	$(MAKE) -C custom clean
	$(MAKE) -C test clean
	$(MAKE) -C source/asm64 clean

distclean:
	$(MAKE) -C custom distclean
	$(MAKE) -C test distclean
	$(MAKE) -C source/asm64 distclean
	@rm -rf windows/Debug/ windows/Release/ windows/ipch/ windows/x64/ windows/*.sdf windows/*.suo
	@rm -rf windows/Asm64Lib/x64/ windows/Asm64Test/x64/
	@rm -rf windows/Curve25519Lib/x64/ windows/Curve25519Lib/Debug/ windows/Curve25519Lib/Release/
	@rm -rf windows/CustomTool/x64/ windows/CustomTool/Debug/ windows/CustomTool/Release/

archive: distclean
	tar cvf /tmp/curve25519-mehdi-`date '+%Y%m%d'`-src.tar *

