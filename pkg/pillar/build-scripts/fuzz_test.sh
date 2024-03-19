#!/bin/bash

# from: https://github.com/golang/go/issues/46312#issuecomment-1727928218

set -e

fuzzTime="30s"

files=$(find ./ -type f \! -path ./vendor/\* -iname \*.go)
for file in ${files}; do
    funcs=$(grep '^func Fuzz' "$file" | sed s/func\ // | sed 's/(.*$//')

    for func in ${funcs}; do
        echo "Fuzzing $func in $file"
        parentDir=$(dirname "$file")
        go test "$parentDir" -run="$func" -fuzz="$func" -fuzztime="${fuzzTime}"
    done
done
