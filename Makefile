# 
# make clean test
#

.PHONY: all clean distclean test

all: test

test: 
	$(MAKE) -C test test

clean: 
	$(MAKE) -C test clean

distclean: clean
	$(MAKE) -C test distclean
	@rm -rf windows/Debug/ windows/Release/ windows/ipch/ windows/x64/ windows/*.sdf windows/*.suo
