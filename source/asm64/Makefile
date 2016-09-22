# 

ROOT = ../..
include $(ROOT)/Rules.mk

ifneq ($(PLATFORM),X86_64)
$(error Platform X86_64 expected (platform is: $(PLATFORM)))
endif

BUILD_DIR = build$(TARGET_ARCH)

CUSTOM_TOOL = $(ROOT)/custom/build/custom_tool
ASM = as --64 --defsym $(TARGET_ABI)=1 -I amd64.gnu

CFLAGS = -c -O2 -m64 -static-libgcc -Wall -Wno-format

# This flag should be set for x86_64 support
CFLAGS += -DUSE_ASM_LIB

CFLAGS += -I. -I.. -I$(ROOT)/include

TARGET = $(BUILD_DIR)/libcurve25519x64.a

A_SRCS = $(wildcard amd64.gnu/*.s)

C_SRCS = \
    curve25519_mehdi_x64.c \
    curve25519_order_x64.c \
    curve25519_utils_x64.c \
    curve25519_dh.c \
    ed25519_sign.c \
    ed25519_verify.c \
    sha512.c \
    custom_blind.c
    
OBJS = $(patsubst amd64.gnu/%.s,$(BUILD_DIR)/s_%.o,$(A_SRCS)) \
    $(C_SRCS:%.c=$(BUILD_DIR)/%.o)

.PHONY: all init clean distclean test

all: $(TARGET)

init:
	@[ -d $(BUILD_DIR) ] || mkdir $(BUILD_DIR)
	$(CUSTOM_TOOL) b edp_custom_blinding > custom_blind.h

$(BUILD_DIR)/s_%.o: amd64.gnu/%.s
	$(ASM) -o $@ $<

$(BUILD_DIR)/%.o: %.c
	$(CC) -o $@ $(CFLAGS) $<

$(BUILD_DIR)/%.o: ../%.c
	$(CC) -o $@ $(CFLAGS) $<

$(TARGET): init $(OBJS)
	ar cr $@ $(OBJS)

clean: 
	@rm -rf $(BUILD_DIR)/* custom_blind.h

distclean:
	@rm -rf $(BUILD_DIR)/ custom_blind.h

