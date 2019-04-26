# Makefile
#
# Targets:
# 	all: Builds the code
# 	fmt: Formats the source files
#	test: Runs the tests
#

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOINSTALL=$(GOCMD) install
GOTEST=$(GOCMD) test
GODEP=$(GOTEST) -i
GOFMT=gofmt -w
GOPATH0=$(CURDIR)
export GOPATH0

# Package lists
TOPLEVEL_PKG := .
DIRS := zconfig zmet

BUILD_LIST = $(DIRS)
CLEAN_LIST = $(DIRS:%=clean-%)
TEST_LIST = $(DIRS:%=test-%)
FMT_LIST = $(DIRS:%=fmt-%)
INSTALL_LIST = $(DIRS:%=install-%)
GENERATE_LIST = $(DIRS:%=generate-%)
INIT_LIST = $(DIRS:%=init-%)

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOINSTALL=$(GOCMD) install
GOGENERATE=$(GOCMD) generate
GOGET=$(GOCMD) get

.PHONY: srvs $(DIRS) $(BUILD_LIST) $(CLEAN_LIST) $(TEST_LIST) $(GENERATE_LIST) $(INIT_LIST)
all: build

init:	
	$(GOGET) -u github.com/gogo/protobuf/protoc-gen-gofast

$(BUILD_LIST):
	$(MAKE) $(DEBUG) -C $@ build

$(CLEAN_LIST):
	$(MAKE) $(DEBUG) -C $(@:clean-%=%) clean

$(TEST_LIST):
	$(MAKE) $(DEBUG) -C $(@:test-%=%) test

$(FMT_LIST):
	$(MAKE) $(DEBUG) -C $(@:fmt-%=%) fmt

$(INSTALL_LIST):
	$(MAKE) -C $(@:install-%=%) install

$(INIT_LIST):
	$(MAKE) -C $(@:init-%=%) init

$(GENERATE_LIST):
	$(MAKE) -C $(@:generate-%=%) generate

build: $(DIRS)
clean: $(CLEAN_LIST)
test: $(TEST_LIST)
fmt: $(FMT_LIST)
install: $(INSTALL_LIST)
init: $(INIT_LIST)
generate: $(GENERATE_LIST)

#
# Rules called from super
#
zc-build: 	build
zc-clean: 	clean
zc-test:	test 
zc-format:	fmt
zc-install:	install
zc-init:	init
zc-generate:	generate
