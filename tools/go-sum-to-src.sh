#!/bin/bash
#
# Copyright (c) 2021 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Given lines from go.sum file(s) on stdin, create a list of tar files
# for each referenced package with the exact sha/commit.
# Skips lines with /go.mod in them since those are just hashes of the go.mod
# files
# Example: to use all go.sum files under current working directory:
# cat $(find . -name go.sum) | sort -u | ./go-sum-to-src.sh

outdir=/tmp/$$
verbose=
while getopts vo: o
do      case "$o" in
        v)      verbose=1;;
        o)      outdir="$OPTARG";;
        [?])    echo "Usage: $0 [-v] [-o <outdir>]"
                exit 1;;
        esac
done
shift $((OPTIND-1))
if [ $# -gt 0 ]; then
    echo "Usage: $0 [-v] [-o <outdir>]"
    exit 1
fi

if [ -f "$outdir" ]; then
    echo "$outdir exists"
    exit 1
fi
if [ -d "$outdir" ]; then
    echo "$outdir exists"
    exit 1
fi

mkdir -p "$outdir"

echo "outdir: $outdir"

count=0
while read -r line; do
    # shellcheck disable=SC2086
    set -- $line
    if echo "$2" | grep -sq "/go.mod"; then
        # echo "Skip $2"
        continue
    fi
    pkgref="$1@$2"
    [ -n "$verbose" ] && echo "pkgref: $pkgref"
    go get -d "$pkgref"
    src=$(go list -mod=readonly -m -json "$pkgref" | jq -r '.Dir')
    # Remove leading $HOME from src
    cleansrc=${src//$HOME//}
    dst=$outdir/$cleansrc.tgz
    destdir=$(dirname "$dst")
    mkdir -p "$destdir"
    [ -n "$verbose" ] && echo "Creating $dst"
    tar -cz -f "$dst" "$src"
    # Need more sane check to handle multiple LICENSE files/symlinks
    if [ -f "$src"/LICENSE ]; then
        cp -p "$src"/LICENSE "$outdir"/"$cleansrc".LICENSE
    elif [ -f "$src"/LICENSE.txt ]; then
        cp -p "$src"/LICENSE.txt "$outdir"/"$cleansrc".LICENSE
    elif [ -f "$src"/LICENSE.md ]; then
        cp -p "$src"/LICENSE.md "$outdir"/"$cleansrc".LICENSE
    elif [ -f "$src"/LICENSE.rst ]; then
        cp -p "$src"/LICENSE.rst "$outdir"/"$cleansrc".LICENSE
    elif [ -f "$src"/License ]; then
        cp -p "$src"/License "$outdir"/"$cleansrc".LICENSE
    elif [ -f "$src"/COPYING ]; then
        cp -p "$src"/COPYING "$outdir"/"$cleansrc".LICENSE-COPYING
    else
        # XXX debug
        find "$src" | grep -i license
        find "$src" | grep -i copying
        touch "$outdir"/"$cleansrc".NO-LICENSE
    fi
    count=$((count +1))
done
# c2=$(find "$outdir" -type f|wc -l)
echo "Saved $count files $(du -sm "$outdir" | cut -f 1) Mbytes in $outdir"
lc=$(find "$outdir" -type f -name '*.LICENSE*' | wc -l)
echo "Saved $lc LICENSE files in $outdir"
nlc=$(find "$outdir" -type f -name '*.NO-LICENSE' | wc -l)
echo "$nlc packages without LICENSE file in $outdir"
