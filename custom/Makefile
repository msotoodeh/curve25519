# 

ROOT = ..
include $(ROOT)/Rules.mk

CFLAGS += -I. -I$(ROOT)/include -I$(ROOT)/source -static-libgcc -Wall

# Uncomment next line for big-endian target CPUs
#CFLAGS += -DECP_CONFIG_BIG_ENDIAN

LIB_SRCS = \
    curve25519_mehdi.c \
    curve25519_order.c \
    curve25519_utils.c \
    ed25519_sign.c \
    ed25519_verify.c \
    sha512.c

LIB_OBJS = $(LIB_SRCS:%.c=build/%.o)

LIB_TARGET = build/libcurve25519.a

TARGET = build/custom_tool

.PHONY: all init clean distclean

all: init $(LIB_TARGET) $(TARGET)

init:
	@[ -d build ] || mkdir build; true

build/%.o: $(ROOT)/source/%.c
	$(CC) -O2 -o $@ -c $(CFLAGS) $<

build/%.o: %.c
	$(CC) -O2 -o $@ -c $(CFLAGS) $<

$(LIB_TARGET): init $(LIB_OBJS)
	$(MAKE_STATIC_LIB) $(LIB_TARGET) $(LIB_OBJS) $(LDFLAGS)

$(TARGET): $(LIB_TARGET) main.c random.c
	$(CC) $(CFLAGS) -o $@ main.c random.c $(LDFLAGS) $(LIB_TARGET)
	./$(TARGET) b edp_custom_blinding > ../source/custom_blind.c

clean: 
	@rm -rf build/*

distclean: 
	@rm -rf build/
