# Copyright (c) 2019 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

TARGET ?= vtpm_server_fuzzer
INC_DIR ?= ../proto
PROTO_OBJS ?= vtpm_api.pb.o
SERVER_OBJS ?= server.o
CC = clang
DEPS := $(OBJS:.o=.d)

INC_FLAGS := $(addprefix -I,$(INC_DIR))
FUZZ_FLAGS := -fprofile-arcs -ftest-coverage -O0 -g -fsanitize=address,fuzzer
LDLIBS := -lprotobuf -lstdc++

$(TARGET): $(PROTO_OBJS) $(SERVER_OBJS)
	$(CC) $(PROTO_OBJS) $(FUZZ_FLAGS) $(SERVER_OBJS) -o $@ $(LDLIBS)

$(SERVER_OBJS): $(PROTO_OBJS)
	$(CC) $(INC_FLAGS) $(FUZZ_FLAGS) -std=c++11 -c server.cpp -o $@

protoc_files: ../proto/vtpm_api.proto
	protoc --cpp_out=../proto -I../proto vtpm_api.proto

$(PROTO_OBJS): protoc_files
	$(CC) $(FUZZ_FLAGS) -c ../proto/vtpm_api.pb.cc -o $(PROTO_OBJS)

clean:
	$(RM) $(TARGET) $(SERVER_OBJS) $(DEPS) $(INC_DIR)/vtpm_api.pb.cc $(INC_DIR)/vtpm_api.pb.h $(PROTO_OBJS)

.PHONY: clean protoc_files all test

all: vtpm_server_fuzzer

test:

-include $(DEPS)
