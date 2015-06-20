# 
#   env RELEASE=1 make clean test asm
#
#   make -C custom          build customization tool
#                           should be called first
#
#   make test               create library and test file
#                           uses portable-c code
#
#   make asm                builds 64-bit library and test code
#                           uses ASM code
#

.PHONY: all clean distclean libs test asm archive

all: test

libs: 
	$(MAKE) -C custom
	$(MAKE) -C source
	$(MAKE) -C source/asm64

test: 
	$(MAKE) -C custom
	$(MAKE) -C source
	$(MAKE) -C test test

asm: 
	$(MAKE) -C custom
	$(MAKE) -C source/asm64
	$(MAKE) -C test test_asm

clean: 
	$(MAKE) -C custom clean
	$(MAKE) -C source clean
	$(MAKE) -C source/asm64 clean || true
	$(MAKE) -C test clean

distclean:
	$(MAKE) -C custom distclean
	$(MAKE) -C test distclean
	$(MAKE) -C source distclean
	$(MAKE) -C source/asm64 distclean || true
	@rm -rf windows/Debug/ windows/Release/ windows/ipch/ windows/x64/ windows/*.sdf windows/*.suo
	@rm -rf windows/Asm64Lib/x64/ windows/Asm64Test/x64/
	@rm -rf windows/Curve25519Lib/x64/ windows/Curve25519Lib/Debug/ windows/Curve25519Lib/Release/
	@rm -rf windows/CustomTool/x64/ windows/CustomTool/Debug/ windows/CustomTool/Release/

archive: distclean
	tar cvf /tmp/curve25519-mehdi-`date '+%Y%m%d'`-src.tar *

