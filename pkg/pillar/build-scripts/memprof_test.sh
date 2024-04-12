#!/bin/bash

set -e

dirs=$(find ./ -type d \! -path ./vendor/\*)
for dir in ${dirs}; do
    if ! grep -q 'func Test' "$dir"/*_test.go >/dev/null 2>&1; then
        continue
    fi
    cleandir="${dir:2}"
    echo "Testing in $dir"
    memprofile=/pillar/mem-${cleandir//\//_}.profile
    /final/opt/gotestsum --jsonfile /pillar/results.json --junitfile /pillar/results.xml \
        --raw-command -- go test "$dir" -tags kubevirt -coverprofile=coverage.txt -covermode=atomic -race -json -memprofile="$memprofile"
done
