# Copyright 2011-2018 Ayla Networks, Inc.  All rights reserved.
#
# Use of the accompanying software is permitted only in accordance
# with and subject to the terms of the Software License Agreement
# with Ayla Networks, Inc., a copy of which can be obtained from
# Ayla Networks, Inc.

EXEC = testd
DIR = app/testd
SRC = ../..

#
# List of source files to build
#
SOURCES = \
	appd.c \
	main.c \
	$(NULL)

#
# List of libraries to link
#
LIBS = ssl crypto curl jansson

#
# List of dependencies on Ayla libraries 
#
LIBDEPS = $(LIB_PLATFORM) $(LIB_AYLA) $(LIB_APP)

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
# Optional: For vi users, list any directories to make tags for in addition to
# the ones in common_defs.mk
#
TAGS_DIRS = $(NULL)

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
	$(INSTALL) $(BUILD)/$(EXEC) $(INSTALL_ROOT)/bin/$(EXEC)
	$(INSTALL) ext/1 $(INSTALL_ROOT)/etc/files/1
	$(INSTALL) ext/2 $(INSTALL_ROOT)/etc/files/2
	$(INSTALL) ext/3 $(INSTALL_ROOT)/etc/files/3
	$(INSTALL) ext/4 $(INSTALL_ROOT)/etc/files/4
	$(INSTALL) large_msg/* $(INSTALL_ROOT)/etc/files/

#
# Include common build rules
#
include $(SRC)/make/common_cc.mk

