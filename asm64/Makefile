# 

ROOT = ..
include $(ROOT)/Rules.mk

CFLAGS = -c -O2 -m64 -Wall -Wno-format
#CFLAGS += -g -D_DEBUG

A_SRCS = $(wildcard amd64.nasm/*.asm)
C_SRCS = curve25519_mehdi_x64.c curve25519_order_x64.c curve25519_utils_x64.c \
    ed25519_sign.c ed25519_verify.c sha512.c custom_blind.c
T_SRCS = curve25519_donna.c selftest.c test64.c

LIB_OBJS = $(patsubst amd64.nasm/%.asm,build/s_%.o,$(A_SRCS)) $(C_SRCS:%.c=build/%.o)
TEST_OBJS = $(T_SRCS:%.c=build/%.o)

LIB_TARGET = build/libcurve25519x64.a
TEST_TARGET = build/test64

LD = ld -static --architecture=x86_64 -EL -Lbuild -lcurve25519x64
NASM = nasm -felf64 -D$(TARGET_ABI) -I amd64.nasm/ -s
CFLAGS += -I . -I amd64.nasm -I ../source -I ../test

.PHONY: all init clean distclean test

all: test

init:
	@[ -d build ] || mkdir build

build/s_%.o: amd64.nasm/%.asm
	$(NASM) -o $@ $<

build/s_%.pp: amd64.nasm/%.asm
	$(NASM) -E $< > $@

build/%.o: %.c
	$(CC) $(CFLAGS) -o $@ $<

build/%.o: ../test/%.c
	$(CC) $(CFLAGS) -o $@ $<

build/%.o: ../source/%.c
	$(CC) $(CFLAGS) -o $@ $<

$(LIB_TARGET): init $(LIB_OBJS)
	ar r $(LIB_TARGET) $(LIB_OBJS) $(LDFLAGS) --target=elf64-little

$(TEST_TARGET): $(LIB_TARGET) $(TEST_OBJS)
	$(MAKE_STATIC_COMMAND) $@ $(TEST_OBJS) $(LIB_OBJS)
	#$(LD) -e main -o $@ $(TEST_OBJS) $(LIB_OBJS)

test: $(TEST_TARGET)
	./$(TEST_TARGET) || exit 1

debug: $(TEST_TARGET)
	gdb ./$(TEST_TARGET)
	#gdb -tui ./$(TEST_TARGET)

clean: 
	@rm -rf build/*

distclean:
	@rm -rf build/
