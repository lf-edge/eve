BUILD_ARGS = CGO_ENABLED=0 GOOS=linux
BUILD_FLAGS = -a -ldflags '-extldflags "-static"'

build:
	GOARCH=amd64 $(BUILD_ARGS) go build -o bin/psi-collector $(BUILD_FLAGS) main.go

build-arm:
	GOARCH=arm64 $(BUILD_ARGS) go build -o bin/psi-collector $(BUILD_FLAGS) main.go

local-check-dir:
	ssh local_eve "mkdir -p /persist/memory-monitor/psi-collector"

local-install: local-check-dir
	scp -O bin/psi-collector local_eve:/persist/memory-monitor/psi-collector

local-run:
	ssh local_eve /persist/memory-monitor/psi-collector/psi-collector

local-get-results:
	scp -O local_eve:/persist/memory-monitor/output/psi.txt .

local-view-results:
	make -C ../../../../../tools/psi-visualizer prepare-env
	source ../../../../../tools/psi-visualizer/venv/bin/activate && python ../../../../../tools/psi-visualizer/visualize.py psi.txt

help:
	@echo "build - build the binary"
	@echo "local-install - install the binary on local_eve"
	@echo local-run - run the binary on local_eve"
	@echo "local-get-results - get the results from local_eve"
	@echo "local-view-results - view the results, using psi-visualizer"
	@echo "help - show this help message"