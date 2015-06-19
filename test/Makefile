# 

ROOT = ..
include $(ROOT)/Rules.mk

.PHONY: all init clean distclean test test_asm

CFLAGS += -I. -I$(ROOT)/include -I$(ROOT)/source -static-libgcc -Wall

# include self-test
#CFLAGS += -DECP_SELF_TEST

BUILD_DIR = build$(TARGET_ARCH)
CLIB_DIR = $(ROOT)/source/$(BUILD_DIR)
ASMLIB_DIR = $(ROOT)/source/asm64/$(BUILD_DIR)

C_LIB   = $(CLIB_DIR)/libcurve25519.a
ASM_LIB = $(ASMLIB_DIR)/libcurve25519x64.a

SRCS = \
    curve25519_donna.c \
    curve25519_selftest.c \
    curve25519_test.c
    
C_OBJS = $(SRCS:%.c=$(BUILD_DIR)/c_%.o)
A_OBJS = $(SRCS:%.c=$(BUILD_DIR)/a_%.o)

C_TARGET = $(BUILD_DIR)/curve25519_test
ASM_TARGET = $(BUILD_DIR)/curve25519_test_x64

ifeq ($(PLATFORM),X86_64)
all: $(C_TARGET) $(ASM_TARGET)
else
all: $(C_TARGET) 
endif

init:
	@[ -d $(BUILD_DIR) ] || mkdir $(BUILD_DIR); true

# Optimization flag -O2 does not work correctly with __asm__
$(BUILD_DIR)/c_curve25519_test.o: curve25519_test.c
	$(CC) -o $@ -c $(CFLAGS) $<

$(BUILD_DIR)/c_%.o: %.c
	$(CC) -o $@ -O2 -c $(CFLAGS) $<

$(BUILD_DIR)/a_%.o: %.c
	$(CC) -o $@ -O2 -c $(CFLAGS) -DUSE_ASM_LIB $<

$(C_TARGET): init $(C_OBJS)
	$(MAKE_STATIC_COMMAND) $@ $(C_OBJS) $(LDFLAGS) $(C_LIB)

$(ASM_TARGET): init $(A_OBJS)
	$(MAKE_STATIC_COMMAND) $@ $(A_OBJS) $(LDFLAGS) $(ASM_LIB)

test: $(C_TARGET)
	./$(C_TARGET) || exit 1

test_asm: $(ASM_TARGET)
	./$(ASM_TARGET) || exit 1

clean: 
	@rm -rf $(BUILD_DIR)/*

distclean: clean
	@rm -rf Debug/ Release/ ipch/ x64/ *.sdf *.suo build32/ build64/
