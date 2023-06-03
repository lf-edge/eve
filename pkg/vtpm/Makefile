# Copyright (c) 2019 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

TARGET ?= vtpm_server
SRC_DIRS ?= ./src
INC_DIR ?= ./proto
PROTO_OBJS ?= vtpm_api.pb.o
SERVER_OBJS ?= server.o
CC = g++
DEPS := $(OBJS:.o=.d)

INC_FLAGS := $(addprefix -I,$(INC_DIR))
LDLIBS := -lprotobuf

C_SEC_WARN = -Wpedantic -Wformat=2 -Wformat-overflow=2 \
-Wformat-truncation=2 -Wnull-dereference -Wstack-protector -Wstrict-overflow=3 \
-Wtrampolines -Warray-bounds=2 -Wshift-overflow=2 -Wstringop-overflow=4 \
-Wconversion -Warith-conversion -Wlogical-op -Wduplicated-cond \
-Wduplicated-branches

C_SEC_FLAGS = $(C_SEC_WARN) -D_FORTIFY_SOURCE=3 \
-fstack-protector-strong -fstack-clash-protection -fPIE \
-fsanitize=bounds -fsanitize-undefined-trap-on-error

L_SEC_FLAGS = -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack

$(TARGET): $(PROTO_OBJS) $(SERVER_OBJS)
	$(CC) $(C_SEC_FLAGS) $(L_SEC_FLAGS) $(PROTO_OBJS) $(SERVER_OBJS) -o $@ -lprotobuf

$(SERVER_OBJS): $(PROTO_OBJS)
	$(CC) $(C_SEC_FLAGS) $(INC_FLAGS) -std=c++11 -c src/server.cpp -o $@

protoc_files: proto/vtpm_api.proto
	protoc --cpp_out=proto -Iproto vtpm_api.proto

$(PROTO_OBJS): protoc_files
	$(CC) $(C_SEC_FLAGS) -c proto/vtpm_api.pb.cc -o $(PROTO_OBJS)

clean:
	$(RM) $(TARGET) $(SERVER_OBJS) $(DEPS) $(INC_DIR)/vtpm_api.pb.cc $(INC_DIR)/vtpm_api.pb.h $(PROTO_OBJS)

.PHONY: clean protoc_files all test

all: vtpm_server

test:

-include $(DEPS)
