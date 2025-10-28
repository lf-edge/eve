# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

build:
	go build -o imm-experiment main.go

local-run: build
	./imm-experiment -in ../../../../../memory-monitor/results/memory_usage.csv -out ../../../../../memory-monitor/results/memory_usage_recalculated.csv
