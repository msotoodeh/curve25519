# 

ROOT = ..
include $(ROOT)/Rules.mk

BUILD_DIR = build$(TARGET_ARCH)
TARGET = $(BUILD_DIR)/libcurve25519.a

CUSTOM_TOOL = $(ROOT)/custom/build/custom_tool

.PHONY: all init clean distclean

CFLAGS += -I. -I$(ROOT)/include -static-libgcc -Wall -O2

SRCS = \
    curve25519_mehdi.c \
    curve25519_order.c \
    curve25519_utils.c \
    curve25519_dh.c \
    ed25519_sign.c \
    ed25519_verify.c \
    sha512.c \
    custom_blind.c

OBJS = $(SRCS:%.c=$(BUILD_DIR)/%.o)

all: $(TARGET)

init:
	@[ -d $(BUILD_DIR) ] || mkdir $(BUILD_DIR)
	$(CUSTOM_TOOL) b edp_custom_blinding > custom_blind.h

$(BUILD_DIR)/%.o: %.c
	$(CC) -o $@ -c $(CFLAGS) $<

$(TARGET): init $(OBJS)
	$(MAKE_STATIC_LIB) $(TARGET) $(OBJS) $(LDFLAGS)

clean: 
	@rm -rf $(BUILD_DIR)/*

distclean: clean
	@rm -rf build32/ build64/
