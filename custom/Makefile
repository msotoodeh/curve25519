# 

ROOT = ..
include $(ROOT)/Rules.mk

CFLAGS += -I. -I$(ROOT)/include -I$(ROOT)/source -static-libgcc -Wall -O2

SRCS = \
    curve25519_mehdi.c \
    curve25519_order.c \
    curve25519_utils.c \
    ed25519_sign.c \
    ed25519_verify.c \
    sha512.c \
    random.c \
    main.c 

OBJS = $(SRCS:%.c=build/%.o)

TARGET = build/custom_tool

.PHONY: all init clean distclean

all: $(TARGET)

init:
	@[ -d build ] || mkdir build

build/%.o: %.c
	$(CC) -o $@ -c $(CFLAGS) $<

build/%.o: $(ROOT)/source/%.c
	$(CC) -o $@ -c $(CFLAGS) $<

$(TARGET): init $(OBJS)
	$(MAKE_STATIC_COMMAND) $(TARGET) $(OBJS) $(LDFLAGS)

clean: 
	@rm -rf build/*

distclean: 
	@rm -rf build/
