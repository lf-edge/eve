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

# Package lists
TOPLEVEL_PKG := .
DIRS := devcommon zmet zconfig deprecatedzconfig

BUILD_LIST = $(DIRS)
CLEAN_LIST = $(DIRS:%=clean-%)
TEST_LIST = $(DIRS:%=test-%)
FMT_LIST = $(DIRS:%=fmt-%)
INSTALL_LIST = $(DIRS:%=install-%)

.PHONY: srvs $(DIRS) $(BUILD_LIST) $(CLEAN_LIST)
all: build

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
