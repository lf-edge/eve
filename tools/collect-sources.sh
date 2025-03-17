#!/bin/sh

#
# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# collect-sources.sh
# collect sources for alpine and go packages used in eve
# arg1=tarfile with rootfs.tar
# arg2=path to eve root
# arg3=path to tar.gz file for output. If blank, will send to stdout

set -e

rootfs="$1"
eve="$2"
outfile="$3"

[ -z "$outfile" ] && outfile=-

tmproot=$(mktemp -d)
tmpout=$(mktemp -d)
manifest=${tmpout}/collected_sources_manifest.csv

tar_opts="$(tar --version | grep -qi 'GNU tar' && echo --warning=no-unknown-keyword || echo)"

# this is a bit of a hack, but we need to extract the rootfs tar to a directory, and it fails if
# we try to extract character devices, block devices or pipes, so we just exclude the dir.
tar "${tar_opts}" -xf "$rootfs" -C "$tmproot" --exclude "dev/*"
echo "${tmpout}"
echo "${outfile}"
{
"${eve}/tools/get-alpine-pkg-source.sh" -s "${tmpout}" -e "${tmproot}" -p alpine
"${eve}/build-tools/bin/go-sources-and-licenses" sources -s "${eve}/pkg" --find --out "${tmpout}" --prefix golang --template 'golang,{{.Module}}@{{.Version}},{{.Version}},{{.Path}}'
"${eve}/build-tools/bin/go-sources-and-licenses" sources -b "${tmproot}" --find --out "${tmpout}" --prefix golang --template 'golang,{{.Module}}@{{.Version}},{{.Version}},{{.Path}}'
} > "${manifest}"
tar "${tar_opts}" -zcf "${outfile}" -C "${tmpout}" .
rm -rf "${tmproot}" "${tmpout}"
