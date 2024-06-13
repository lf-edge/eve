# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

CC=gcc
CFLAGS=-Wall -static -O2
SRC_DIR=src
OBJ_DIR=obj
DIST_DIR=dist
BIN_DIR=bin

MONITOR_DIR=$(SRC_DIR)/monitor
MONITOR_SRC=$(wildcard $(MONITOR_DIR)/*.c)
MONITOR_OBJ=$(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(MONITOR_SRC))
$(BIN_DIR)/memory-monitor: $(MONITOR_OBJ)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^
memory-monitor: $(BIN_DIR)/memory-monitor

PRESSURE_DIR=$(SRC_DIR)/pressure
PRESSURE_SRC=$(wildcard $(PRESSURE_DIR)/*.c)
PRESSURE_OBJ=$(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(PRESSURE_SRC))
$(BIN_DIR)/pressure: $(PRESSURE_OBJ)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^
pressure: $(BIN_DIR)/pressure

TARGETS=memory-monitor pressure

all: $(TARGETS)

OBJS=$(MONITOR_OBJ) $(PRESSURE_OBJ)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

HANDLER_SCRIPT=$(MONITOR_DIR)/memory-monitor-handler.sh
CONFIG_FILE=$(MONITOR_DIR)/memory-monitor.conf
APPARMOR_PROFILE=$(MONITOR_DIR)/persist.memory-monitor.handler

MONITOR_DEPS=$(HANDLER_SCRIPT) $(CONFIG_FILE) $(APPARMOR_PROFILE)

dist: $(BIN_DIR)/memory-monitor $(MONITOR_DEPS)
	@mkdir -p $(DIST_DIR)
	cp $(BIN_DIR)/memory-monitor $(HANDLER_SCRIPT) $(CONFIG_FILE) $(APPARMOR_PROFILE) $(DIST_DIR)
	@touch dist

dist-clean: clean
	rm -rf $(DIST_DIR)

# Target for local testing

RESULTS_DIR=results

local-kill-monitor:
	ssh local_eve killall -9 memory-monitor || true

local-deploy: dist local-kill-monitor
	ssh local_eve mkdir -p /persist/memory-monitor
	scp -O -r $(DIST_DIR)/* local_eve:/persist/memory-monitor
	# Add code to install the apparmor profile

local-deploy-pressure: pressure
	scp -O bin/pressure local_eve:/persist/memory-monitor

local-clean-on-eve:
	ssh local_eve rm -rf /persist/memory-monitor

local-get-results:
	mkdir -p $(RESULTS_DIR)
	scp -r -O local_eve:/persist/memory-monitor/output/* $(RESULTS_DIR)
	scp -O local_eve:/containers/services/pillar/rootfs/opt/zededa/bin/zedbox $(RESULTS_DIR)

local-clean-results:
	rm -rf $(RESULTS_DIR)

local-clean-results-on-eve:
	ssh local_eve rm -rf /persist/memory-monitor/output/*

local-analyze-results:
	cat $(RESULTS_DIR)/*/allocations_pillar.out | cut -d";" -f3- | jq -r .msg | grep 'alloc' | awk '{bytes += $$2;} END {print "Total bytes allocated:", bytes, "bytes."}'
	go tool pprof -http=:8080 $(RESULTS_DIR)/zedbox $(RESULTS_DIR)/*/heap_pillar.out


# Help

help:
	@echo "Available targets:"
	@echo "  all: Build all targets (monitor and pressure)"
	@echo "  clean: Remove all build artifacts"
	@echo "  dist: Create a directory with all distribution artifacts: monitor, handler.sh, monitor.conf, persist.memory-monitor.handler"
	@echo "  dist-clean: Remove the distribution directory"
	@echo "  monitor: Build the monitor, put the binary in bin/monitor"
	@echo "  pressure: Build the pressure tool, put the binary in bin/pressure"
	@echo "  local-kill-monitor: Kill the monitor on the local EVE"
	@echo "  local-deploy: Deploy the monitor on the local EVE"
	@echo "  local-get-results: Get the results from the local EVE"
	@echo "  local-clean-results: Remove the results from the local machine"
	@echo "  local-clean-results-on-eve: Remove the results from the local EVE"
	@echo "  local-analyze-results: Analyze the results that were fetched from the local EVE with the get-results target"

.PHONY: all clean dist-clean local-kill-monitor local-deploy local-get-results local-clean-results local-clean-results-on-eve local-analyze-results
