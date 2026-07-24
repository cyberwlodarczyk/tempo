# Copyright (c) The mlkem-native project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT

.PHONY: all build exchange perf clean
.DEFAULT_GOAL := all

CC  ?= gcc
AR  ?= ar

# Adjust CFLAGS if needed
CFLAGS := \
	-Wall \
	-Wextra \
	-Werror=unused-result \
	-Wpedantic \
	-Werror \
	-Wno-missing-prototypes \
	-Wno-unused-function \
	-Wshadow \
	-Wpointer-arith \
	-Wredundant-decls \
	-Wconversion \
	-Wsign-conversion \
	-Wno-long-long \
	-Wno-unknown-pragmas \
	-Wno-unused-command-line-argument \
	-O3 \
	-fomit-frame-pointer \
	-std=c99 \
	-pedantic \
	-MMD \
	$(CFLAGS)

# If you want to use the native backends, the compiler needs to know about
# the target architecture. Here, we import the default host detection from
# mlkem-native's tests, but you can write your own or specialize accordingly.
AUTO ?= 1
include auto.mk

# The following only concerns the cross-compilation tests.
# You can likely ignore the following for your application.
#
# Append cross-prefix for cross compilation
# When called from the root Makefile, CROSS_PREFIX has already been added here
# ifeq (,$(findstring $(CROSS_PREFIX),$(CC)))
# CC  := $(CROSS_PREFIX)$(CC)
# endif

# ifeq (,$(findstring $(CROSS_PREFIX),$(AR)))
# AR  := $(CROSS_PREFIX)$(AR)
# endif

# Part A:
#
# mlkem-native source and header files
#
# Here, the monolithic C file for mlkem-native is directly included in main.c,
# However, we still need to incldue the monolithic assembly file.
MLK_SOURCE_C = mlkem/mlkem.c
MLK_SOURCE_ASM = mlkem/mlkem.S

# Part B:
#
# Random number generator
#
# !!! WARNING !!!
#
# The randombytes() implementation used here is for TESTING ONLY.
# You MUST NOT use this implementation outside of testing.
#
# !!! WARNING !!!
# RNG_SOURCE=$(wildcard rng/*.c)

# Part C:
#
# Your application source code
# APP_SOURCE=main.c

BUILD_DIR=build
BIN_DIR=bin
BIN_TEST=$(BIN_DIR)/test
BIN_PERF=$(BIN_DIR)/perf
BIN_PERF_GEN_MATRIX=$(BIN_DIR)/perf_gen_matrix

#
# Configuration adjustments
#
ASMFLAGS = -DMLK_CONFIG_MULTILEVEL_WITH_SHARED

MLK_OBJ_C=$(patsubst %,$(BUILD_DIR)/%.o,$(MLK_SOURCE_C))
MLK_OBJ_ASM=$(patsubst %,$(BUILD_DIR)/%.o,$(MLK_SOURCE_ASM))

Q ?= @

$(BUILD_DIR)/%.c.o: %.c
	$(Q)echo "CC  $^"
	$(Q)[ -d $(@D) ] || mkdir -p $(@D)
	$(Q)$(CC) -c $(CFLAGS) -Imlkem $^ -o $@

$(BUILD_DIR)/%.S.o: %.S
	$(Q)echo "AS  $^"
	$(Q)[ -d $(@D) ] || mkdir -p $(@D)
	$(Q)$(CC) -c $(CFLAGS) $(ASMFLAGS) -Imlkem $^ -o $@

$(BIN_DIR)/%: %.c $(MLK_OBJ_C) $(MLK_OBJ_ASM)
	$(Q)echo "CC  $@"
	$(Q)[ -d $(@D) ] || mkdir -p $(@D)
	$(Q)$(CC) -Wall -I. $^ -o $@ -lcrypto
	$(Q)strip -S $@

all: build

build: $(BIN_TEST) $(BIN_PERF) $(BIN_PERF_GEN_MATRIX)

test: $(BIN_TEST)
	./$(BIN_TEST)

perf: $(BIN_PERF)
	./$(BIN_PERF)

perf_gen_matrix: $(BIN_PERF_GEN_MATRIX)
	./$(BIN_PERF_GEN_MATRIX) | python3 perf_gen_matrix.py

clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(BIN_DIR)
