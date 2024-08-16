#!/bin/sh
#
# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

set -e

if [ "$#" -ne 2 ]; then
    echo "Usage: <bin> <prefix-dir>"
    exit 1
fi

bin=$1
prefix=$(realpath "$2")

copyfile() {
    file=$1
    dirname=$(dirname "$file")
    newdir="$prefix/$dirname"
    newfilepath="$prefix/$file"
    echo "$newfilepath: $dirname -> $newdir"
    mkdir -p "$newdir"
    cp -v "$file" "$newfilepath"
}

ldd "$bin" | awk '{print$3}' | while read -r a
do
    if [ ! -f "$a" ]; then
        continue
    fi
    copyfile "$a"
done
