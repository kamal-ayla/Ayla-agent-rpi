# Copyright 2016-2018 Ayla Networks, Inc.  All rights reserved.
#
# Use of the accompanying software is permitted only in accordance
# with and subject to the terms of the Software License Agreement
# with Ayla Networks, Inc., a copy of which can be obtained from
# Ayla Networks, Inc.

EXEC = buffer_test
DIR = buffer_test
SRC = ../../rel

#
# List of source files to build
#
SOURCES = \
	buffer_test.c \
	$(NULL)

#
# List of libraries to link
#
LIBS = jansson

#
# Compiler and linker flags
#
#TARGET_CFLAGS =
#TARGET_LDFLAGS =

#
# List of pre-processor definitions
#
#DEFINES =

#
# List of directories to make tags for (for vi users)
#
TAGS_DIRS = \
	. \
	$(NULL)

#
# Include common variables
#
include $(SRC)/make/common_defs.mk

#
# Build rules for this target
#
.PHONY: all default install

all: $(EXEC)

default: all

install: all
	$(INSTALL) $(BUILD)/$(EXEC) $(INSTALL_ROOT)/test/$(EXEC)

#
# Include common build rules
#
include $(SRC)/make/common_cc.mk

