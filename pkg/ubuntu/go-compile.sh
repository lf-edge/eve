#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC2046
# shellcheck disable=SC2154
#
# Lints, tests and installs a Go program as a static binary into $GOPATH/bin.
# REQUIRE_CGO=1 keeps cgo on and links the result statically with gcc,
# otherwise cgo is disabled and the binary is static by construction.

set -e

usage() {
        echo "Usage: dir"
        exit 1
}

[ $# = 0 ] && usage

dir="$1"

cd "$dir"

# lint before building
>&2 echo "gofmt..."
test -z $(gofmt -s -l .| grep -v .pb. | grep -v vendor/ | tee /dev/stderr)

>&2 echo "govet..."
test -z $(GOOS=linux go vet -printf=false . 2>&1 | grep -v vendor/ | tee /dev/stderr)

>&2 echo "go test..."
go test

>&2 echo "go build..."

if [ "${REQUIRE_CGO}" = 1 ]; then
   go install -buildmode=pie -ldflags "-s -w ${ldflags} -linkmode=external -extldflags=-static-pie"
else
   CGO_ENABLED=0 go install -buildmode=pie -ldflags "-s -w ${ldflags}"
fi
