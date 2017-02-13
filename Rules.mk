#
# Rules.mk - handling common make tasks
#

BUILD_OS   := $(shell uname -o)
BUILD_ARCH := $(shell uname -m)
TARGET_SYS  = $(shell gcc -dumpmachine)
TAG_NAME    = $(shell git log -1 --pretty=%H)
BRANCH_NAME = $(shell git name-rev --name-only HEAD)
REPO_NAME   = $(shell git remote -v | grep origin | grep fetch | awk '{print $$2}')

ifneq ($(findstring x86_64,$(TARGET_SYS)),)
TARGET_ARCH = 64
else
TARGET_ARCH = 32
endif

ifeq ($(PLATFORM),)
PLATFORM = X86_$(TARGET_ARCH)
endif

ifneq ($(findstring cygwin,$(TARGET_SYS)),)
TARGET_OS = Cygwin
TARGET_ABI = MSVC
else ifneq ($(findstring linux,$(TARGET_SYS)),)
TARGET_OS = Linux
TARGET_ABI = GCC
else ifneq ($(findstring mingw,$(TARGET_SYS)),)
TARGET_OS = Mingw
TARGET_ABI = MSVC
else
$(error Target OS not supported ($(TARGET_SYS)))
endif

ifeq ($(RELEASE),)
export DEBUG=true
CONF = Debug
CFLAGS = -g -D_DEBUG
STRIP_ARG =
else
export RELEASE=true
export NDEBUG=true
CONF = Release
CFLAGS = -DNDEBUG
STRIP_ARG = -s
endif

ifeq ($(PLATFORM),X86_32)
CFLAGS += -m32 -march=i386 -D__i386__ -D_LINUX_
endif
ifeq ($(PLATFORM),X86_64)
CFLAGS += -m64 -Wno-format -D_LINUX_
endif

# Uncomment next line for big-endian target CPUs
#CFLAGS += -DECP_CONFIG_BIG_ENDIAN

# programs we use
CC    = gcc
GPP   = g++
CPP   = cpp
LD    = ld
AR    = ar
LN    = ln -s
AS    = as
MKDIR = mkdir -p
PATCH = patch
SHELL = /bin/sh
INSTALL = install
NM      = nm

MAKE_STATIC_LIB         = $(AR) cr
MAKE_SHARED_LIB         = $(GPP) -shared -o
MAKE_DEBUG_LIB          = $(MAKE_STATIC_LIB)
MAKE_STATIC_COMMAND     = $(GPP) -static -o
MAKE_DYNAMIC_COMMAND    = $(GPP) -o

INSTALL_HEADER      = $(INSTALL) -m 644
INSTALL_COMMAND     = $(INSTALL) -m 755 $(STRIP_ARG)
INSTALL_STATIC_LIB  = $(INSTALL) -m 644
INSTALL_SHARED_LIB  = $(INSTALL) -m 644 $(STRIP_ARG)

.PHONY: all clean default

default: all
