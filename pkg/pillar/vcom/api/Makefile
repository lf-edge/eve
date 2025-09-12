# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

all: build

proto: go python
	@echo Done building protobuf, you may want to vendor it into your packages, e.g. pkg/pillar.

proto-api-go:
	protoc --go_out=. proto/*.proto
proto-api-python:
	protoc --python_out=. proto/*.proto
		@for f in proto/*.py; do \
		if ! grep -q "SPDX-License-Identifier" "$$f"; then \
			tmpfile=$$(mktemp); \
			echo "# Copyright (c) $(shell date '+%Y') Zededa, Inc." > $$tmpfile; \
			echo "# SPDX-License-Identifier: Apache-2.0" >> $$tmpfile; \
			cat "$$f" >> $$tmpfile; \
			mv $$tmpfile "$$f"; \
		fi; \
	done

build:
	docker build -f builder/Dockerfile -t vcom-api-builder .
	docker run --rm --env HOME=/src -v $(PWD):/src -w /src -u $$(id -u) vcom-api-builder make proto
	mkdir -p ../go
	mkdir -p ../python
	mv vcom/*.go ../go
	mv proto/*.py ../python
	rm -rf vcom

go: proto-api-go
python: proto-api-python

.PHONY: proto-api-% proto proto-container
