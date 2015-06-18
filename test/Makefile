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
    
OBJS = $(SRCS:%.c=$(BUILD_DIR)/%.o)

C_TARGET = $(BUILD_DIR)/curve25519_test
ASM_TARGET = $(BUILD_DIR)/curve25519_test_x64

test_asm: CFLAGS += -DUSE_ASM_LIB
#test_asm: LDFLAGS = --target=elf64-little

ifeq ($(PLATFORM),X86_64)
all: $(C_TARGET) $(ASM_TARGET)
else
all: $(C_TARGET) 
endif

init:
	@[ -d $(BUILD_DIR) ] || mkdir $(BUILD_DIR); true

# Optimization flag -O2 does not work correctly with __asm__
$(BUILD_DIR)/curve25519_test.o: curve25519_test.c
	$(CC) -o $@ -c $(CFLAGS) $<

$(BUILD_DIR)/%.o: $(ROOT)/source/%.c
	$(CC) -o $@ -O2 -c $(CFLAGS) $<

$(BUILD_DIR)/%.o: %.c
	$(CC) -o $@ -O2 -c $(CFLAGS) $<

$(C_TARGET): init $(OBJS)
	$(MAKE_STATIC_COMMAND) $@ $(OBJS) $(LDFLAGS) $(C_LIB)

$(ASM_TARGET): init $(OBJS)
	$(MAKE_STATIC_COMMAND) $@ $(OBJS) $(LDFLAGS) $(ASM_LIB)
	#ld -static -o $@ $(OBJS) --architecture=x86_64 -EL -L$(ASMLIB_DIR) -lcurve25519x64

test: $(C_TARGET)
	./$(C_TARGET) || exit 1

test_asm: $(ASM_TARGET)
	./$(ASM_TARGET) || exit 1

clean: 
	@rm -rf $(BUILD_DIR)/*

distclean: clean
	@rm -rf Debug/ Release/ ipch/ x64/ *.sdf *.suo $(BUILD_DIR)/
