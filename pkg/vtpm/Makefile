# Copyright (c) 2019 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

TARGET ?= vtpm_server
SRC_DIRS ?= ./src
INC_DIRS ?= ./proto/cpp
PROTO_OBJS ?= vtpm_api.pb.o
CC = g++

SRCS := $(shell find $(SRC_DIRS) -name *.cpp -or -name *.cc)
OBJS := $(addsuffix .o,$(basename $(SRCS)))
DEPS := $(OBJS:.o=.d)

INC_FLAGS := $(addprefix -I,$(INC_DIRS))
CPPFLAGS ?= $(INC_FLAGS) -std=c++11
LDLIBS := -lprotobuf

$(TARGET): $(PROTO_OBJS) $(OBJS)
	$(CC) $(OBJS) $(PROTO_OBJS) -o $@ $(LDLIBS)

protoc_files: proto/vtpm_api.proto
	protoc --cpp_out=proto/cpp -Iproto vtpm_api.proto

$(PROTO_OBJS): protoc_files
	$(CC) -c  -o $@ proto/cpp/vtpm_api.pb.cc

clean:
	$(RM) $(TARGET) $(OBJS) $(DEPS) $(INC_DIR) $(PROTO_OBJS)

.PHONY: clean protoc_files all test

all: vtpm_server

test:

-include $(DEPS)
