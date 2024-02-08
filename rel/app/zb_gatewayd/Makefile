# Copyright 2011-2018 Ayla Networks, Inc.  All rights reserved.
#
# Use of the accompanying software is permitted only in accordance
# with and subject to the terms of the Software License Agreement
# with Ayla Networks, Inc., a copy of which can be obtained from
# Ayla Networks, Inc.

EXEC = appd
DIR = app/zb_gatewayd
SRC = ../..

EMBER_STACK_DIR = /home/pi/EmberZNet/v5.7.4.0
EMBER_PROJECT_NAME = ember
EMBER_LIB_DIR = $(EMBER_PROJECT_NAME)/lib
EMBER_LIB_NAME = em3588stack5.7.4
CALLBACK_STUB_UPDATED= $(OBJ_DIR)/callback-stub-updated


#
# List of source files to build
#
SOURCES = \
	$(EMBER_PROJECT_NAME)/$(EMBER_PROJECT_NAME)_callbacks.c \
	$(EMBER_PROJECT_NAME)/call-command-handler.c \
	$(EMBER_PROJECT_NAME)/callback-stub.c \
	$(EMBER_PROJECT_NAME)/stack-handler-stub.c \
	$(EMBER_PROJECT_NAME)/cli.c \
	appd_interface.c \
	zb_callback.c \
	zb_interface.c \
	gateway.c \
	main.c \
	node.c \
	$(NULL)

#
# List of libraries to link
#
LIBS = ssl crypto curl jansson

INCLUDES= \
  -I$(EMBER_STACK_DIR)/protocol/zigbee_5.7 \
  -I$(EMBER_STACK_DIR)/protocol/zigbee_5.7/stack \
  -I$(EMBER_STACK_DIR)/platform/base \
  -I$(EMBER_STACK_DIR)/platform/base/hal \
  -I$(EMBER_PROJECT_NAME) \
  

#
# Compiler and linker flags
#
TARGET_CFLAGS = $(INCLUDES)

TARGET_LDFLAGS = -l$(EMBER_LIB_NAME) -L$(EMBER_LIB_DIR) -lreadline -lncurses



APP_BUILDER_OUTPUT_DIRECTORY=.
APP_BUILDER_CONFIG_HEADER=$(APP_BUILDER_OUTPUT_DIRECTORY)/ember.h
APP_BUILDER_STORAGE_FILE=$(APP_BUILDER_OUTPUT_DIRECTORY)/ember_endpoint_config.h

PLATFORM_HEADER_FILE ?= \"../../../platform/base/hal/micro/unix/compiler/gcc.h\"
BOARD_HEADER_FILE    ?= \"../../../platform/base/hal/micro/unix/host/board/host.h\"

DEFINES = \
  UNIX \
  UNIX_HOST \
  PHY_NULL \
  CONFIGURATION_HEADER=\"../../../protocol/zigbee_5.7/app/framework/util/config.h\" \
  EZSP_HOST \
  GATEWAY_APP \
  ZA_GENERATED_HEADER=\"$(APP_BUILDER_CONFIG_HEADER)\" \
  ATTRIBUTE_STORAGE_CONFIGURATION=\"$(APP_BUILDER_STORAGE_FILE)\" \
  PLATFORM_HEADER=$(PLATFORM_HEADER_FILE) \
  BOARD_HEADER=$(BOARD_HEADER_FILE) \
  EMBER_AF_API_EMBER_TYPES=\"stack/include/ember-types.h\" \
  EZSP_ASH=1 \
  

#
# List of pre-processor definitions
#
DEFINES += GATEWAY_SUPPORT

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


UPDATED = $(BUILD)/callback-stub-updated
$(UPDATED): $(EMBER_PROJECT_NAME)/callback-stub.c
	sed -i 's/emberAfPreMessageReceivedCallback(/emberAfPreMessageReceivedCallback_RedefinedByAppd(/g' $(EMBER_PROJECT_NAME)/callback-stub.c
	sed -i 's/emberAfStackStatusCallback(/emberAfStackStatusCallback_RedefinedByAppd(/g' $(EMBER_PROJECT_NAME)/callback-stub.c
	sed -i 's/emberAfTrustCenterJoinCallback(/emberAfTrustCenterJoinCallback_RedefinedByAppd(/g' $(EMBER_PROJECT_NAME)/callback-stub.c
	sed -i 's/emberAfMessageSentCallback(/emberAfMessageSentCallback_RedefinedByAppd(/g' $(EMBER_PROJECT_NAME)/callback-stub.c
	sed -i 's/emberAfNcpInitCallback(/emberAfNcpInitCallback_RedefinedByAppd(/g' $(EMBER_PROJECT_NAME)/callback-stub.c
	touch $(UPDATED)


all: $(UPDATED) $(EXEC)

default: all

install: all
	$(INSTALL) $(BUILD)/$(EXEC) $(INSTALL_ROOT)/bin/$(EXEC)

#
# Include common build rules
#
include $(SRC)/make/common_cc.mk

