#!/bin/bash

# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

BROKEN_TESTS="TestDPCWithReleasedAndRenamedInterface TestUnsubscribe/IPC_with_persistent TestRestarted TestUnsubscribe/IPC TestCheckMaxSize"
SKIP_BROKEN_TESTS_PARAM=""
for t in $BROKEN_TESTS
do
    SKIP_BROKEN_TESTS_PARAM="$SKIP_BROKEN_TESTS_PARAM|^$t\$"
done
SKIP_BROKEN_TESTS_PARAM=${SKIP_BROKEN_TESTS_PARAM:1}

BROKEN_TESTS_PARAM=""
for t in $BROKEN_TESTS
do
    BROKEN_TESTS_PARAM="$BROKEN_TESTS_PARAM|$t"
done
BROKEN_TESTS_PARAM=${BROKEN_TESTS_PARAM:1}

trap 'rm -f coverage_part.txt' EXIT

echo 'mode: atomic' > coverage.txt
go test -coverprofile=coverage_part.txt -covermode=atomic -skip "$SKIP_BROKEN_TESTS_PARAM" -race -json ./...
if [ -f coverage_part.txt ]; then
    tail -n +2 >> coverage.txt < coverage_part.txt
fi

go test -coverprofile=coverage_part.txt -covermode=atomic -run "$BROKEN_TESTS_PARAM" -json ./...
if [ -f coverage_part.txt ]; then
    tail -n +2 >> coverage.txt < coverage_part.txt
fi
