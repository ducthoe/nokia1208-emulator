# SPDX-FileCopyrightText: 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

CC ?= cc
PYTHON ?= python3
CPPFLAGS += -Ithird_party/mgba-arm/include
CFLAGS ?= -O2 -std=c11 -Wall -Wextra

CPU_SOURCES = third_party/mgba-arm/src/arm/arm.c \
              third_party/mgba-arm/src/arm/isa-arm.c \
              third_party/mgba-arm/src/arm/isa-thumb.c
CPU_HEADERS = $(wildcard third_party/mgba-arm/include/mgba/internal/arm/*.h \
                         third_party/mgba-arm/include/mgba/core/*.h \
                         third_party/mgba-arm/include/mgba-util/*.h)
PHONE_SOURCES = src/tds6_safer.c src/virtual_sim.c src/nvram.c
PHONE_HEADERS = $(wildcard src/*.h)

.PHONY: all prepare run clean
all: build/rh105

build/rh105: src/rh105.c $(PHONE_SOURCES) $(PHONE_HEADERS) $(CPU_SOURCES) $(CPU_HEADERS) Makefile
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) src/rh105.c $(PHONE_SOURCES) $(CPU_SOURCES) -o $@

prepare:
	$(PYTHON) prepare.py

run: prepare all
	$(PYTHON) tools/rh105_gui.py

clean:
	rm -rf build __pycache__ tools/__pycache__
