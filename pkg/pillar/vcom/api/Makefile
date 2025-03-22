# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

all: build

proto: go python
	@echo Done building protobuf, you may want to vendor it into your packages, e.g. pkg/pillar.

proto-api-go:
	protoc --go_out=. proto/*.proto
proto-api-python:
	protoc --python_out=. proto/*.proto

build:
	docker build -f builder/Dockerfile -t vcom-api-builder .
	docker run --rm --env HOME=/src -v $(PWD):/src -w /src -u $$(id -u) vcom-api-builder make proto
	cp -r vcom/* ../
	rm -rf vcom

go: proto-api-go
python: proto-api-python

.PHONY: proto-api-% proto proto-container
