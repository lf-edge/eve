#!/bin/bash
#
# Copyright (c) 2022 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Collect EVE's kernel sources from the upstream.
#
# Needs to run in a workspace where it has access to pkg/kernel/Dockerfile.
# Can optionally feed in pkg/acrn-kernel/Dockerfile or pkg/new-kernel/Dockerfile
# Example usage
#  get-kernel-source.sh [-v] [-u urlfile] [-s outdir] [Dockerfile]
# With -u <urlfile> it dumps the source URLs into that file
# With -s <outdir> it dumps all the corresponding source in that directory
# Then outdir can be tarred together
verbose=
urlfile=
prefix=
outdir=/tmp/$$
dockerfile="pkg/kernel/Dockerfile"
while getopts vu:s:p: o
do      case "$o" in
        v)      verbose=1;;
        s)      outdir=$OPTARG;;
        u)      urlfile=$OPTARG;;
        p)      prefix=$OPTARG;;
        [?])    >&2 echo "Usage: $0 [-v] [-s <outdir>] [-u <urlfile>] [-p <prefix>] [<Dockerfile>]"
                exit 1;;
        esac
done
shift $((OPTIND-1))
if [ $# -gt 1 ]; then
    >&2 echo "Can specify at most one Dockerfile"
    >&2 echo "Usage: $0 [-v] [-s <outdir>] [-u <urlfile>] [-p <prefix>] [<Dockerfile>]"
    exit 1
fi
if [ $# = 1 ]; then
    dockerfile=$1
    shift
fi

checkdir=$outdir
[ -n "$prefix" ] && checkdir="$outdir/$prefix"

if [ -d "$checkdir" ]; then
    >&2 echo "$checkdir already exists"
    exit 1
fi

mkdir -p "$checkdir"
tmpurlfile=/tmp/$$.url

# Make sure we have a binary
if ! (cd tools/dockerfile-add-scanner; make >&2); then
    >&2 echo "Make dockerfile-add-scanner failed"
    exit 2
fi
if ! tools/dockerfile-add-scanner/bin/dockerfile-add-scanner scan "$dockerfile" >"$tmpurlfile";  then
    >&2 echo "dockerfile-add-scanner failed"
    exit 2
fi

if [ -n "$urlfile" ]; then
    (cd "$outdir" || exit; cp -p "$tmpurlfile" "$urlfile")
fi

[ -n "$verbose" ] && echo "downloading using $tmpurlfile" >&2
# shellcheck disable=SC2002
cat "$tmpurlfile" | while read -r url; do
    basedest=$(echo "$url" | cut -d'/' -f3- | tr "/" _)
    [ -n "$prefix" ] && basedest="$prefix/$basedest"
    dest="$outdir/$basedest"
    [ -n "$verbose" ] && echo "downloading: curl -sSLo $dest $url" >&2
    if ! curl -sSLo "$dest" "$url"; then
        >&2 echo "curl $dest $url failed"
        exit 2
    fi
    echo "kernel,${url},,${basedest}"
done

rm -f "$tmpurlfile"
