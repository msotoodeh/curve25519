# 

ROOT = ..
include $(ROOT)/Rules.mk

CFLAGS += -I. -I../source -static-libgcc -Wall

# Uncomment next line for big-endian target CPUs
#CFLAGS += -DECP_CONFIG_BIG_ENDIAN

# Uncomment next line if TSC not supported
#CFLAGS += -DECP_NO_TSC

test: CFLAGS += -DECP_SELF_TEST

LIB_SRCS = curve25519_mehdi.c curve25519_utils.c curve25519_order.c
TEST_SRCS = curve25519_donna.c curve25519_test.c
    
LIB_OBJS = $(LIB_SRCS:%.c=build/%.o)
TEST_OBJS = $(TEST_SRCS:%.c=build/%.o)

LIB_TARGET = build/libcurve25519.a
TEST_TARGET = build/curve25519_test

.PHONY: all init clean distclean test

all: init $(LIB_TARGET) $(TEST_TARGET)

init:
	@[ -d build ] || mkdir build; true

# Optimization flag -O2 does not work with	__asm__
build/curve25519_test.o: curve25519_test.c
	$(CC) -o $@ -c $(CFLAGS) $<

build/%.o: ../source/%.c
	$(CC) -O2 -o $@ -c $(CFLAGS) $<

build/%.o: %.c
	$(CC) -O2 -o $@ -c $(CFLAGS) $<

$(LIB_TARGET): init $(LIB_OBJS)
	$(MAKE_STATIC_LIB) $(LIB_TARGET) $(LIB_OBJS) $(LDFLAGS)

$(TEST_TARGET): $(LIB_TARGET) $(TEST_OBJS)
	$(MAKE_STATIC_COMMAND) $@ $(TEST_OBJS) $(LDFLAGS) $(LIB_TARGET)

test: $(LIB_TARGET) $(TEST_TARGET)
	./$(TEST_TARGET) || exit 1

clean: 
	@rm -rf build/*

distclean: clean
	@rm -rf Debug/ Release/ ipch/ x64/ *.sdf *.suo build/
