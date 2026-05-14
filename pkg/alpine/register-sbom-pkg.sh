#!/bin/sh
# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# shellcheck disable=SC2086
#
# register-sbom-pkg.sh - Register a source-built package in the APK DB so
# syft includes it in the SBOM.
#
# Usage:
#   register-sbom-pkg.sh -n <name> -v <version> -l <license> -u <url> [-d <description>] [-o <outdir>]
#
# Arguments:
#   -n  package name       (required)
#   -v  package version    (required)
#   -l  SPDX license ID    (required, e.g. BSD-3-Clause, MIT, Apache-2.0)
#   -u  upstream URL       (required)
#   -d  description        (optional, defaults to "<name> (built from source)")
#   -o  output root dir    (optional, defaults to /out)
#
# Example:
#   register-sbom-pkg.sh -n libtpms -v 0.10.0 -l BSD-3-Clause -u https://github.com/stefanberger/libtpms
#
# The entry is appended to <outdir>/lib/apk/db/installed.
#
set -e

usage() {
    echo "Usage: $0 -n <name> -v <version> -l <license> -u <url> [-d <description>] [-o <outdir>]" >&2
    exit 1
}

OUTDIR=/out

while getopts "n:v:l:u:d:o:" opt; do
    case "$opt" in
        n) PKG_NAME="$OPTARG" ;;
        v) PKG_VERSION="$OPTARG" ;;
        l) PKG_LICENSE="$OPTARG" ;;
        u) PKG_URL="$OPTARG" ;;
        d) PKG_DESC="$OPTARG" ;;
        o) OUTDIR="$OPTARG" ;;
        *) usage ;;
    esac
done

APK_DB="${OUTDIR}/lib/apk/db/installed"

# Always make sure the apk DB directory and file exist so that callers can
# rely on it being present even when this script is invoked only to
# initialize the file (no -n/-v/-l/-u). This also lets later
# COPY --from=<stage> /.../lib/apk/db/installed succeed unconditionally.
mkdir -p "$(dirname "$APK_DB")"
[ -e "$APK_DB" ] || touch "$APK_DB"

# Init-only mode: if no package fields were supplied, we just ensured the
# file exists and we're done.
if [ -z "$PKG_NAME" ] && [ -z "$PKG_VERSION" ] && [ -z "$PKG_LICENSE" ] && [ -z "$PKG_URL" ]; then
    echo "Initialized $APK_DB"
    exit 0
fi

[ -n "$PKG_NAME" ]    || { echo "ERROR: -n (name) is required" >&2;    usage; }
[ -n "$PKG_VERSION" ] || { echo "ERROR: -v (version) is required" >&2; usage; }
[ -n "$PKG_LICENSE" ] || { echo "ERROR: -l (license) is required" >&2; usage; }
[ -n "$PKG_URL" ]     || { echo "ERROR: -u (url) is required" >&2;     usage; }

PKG_DESC="${PKG_DESC:-${PKG_NAME} (built from source)}"
PKG_ARCH="$(apk --print-arch)"

printf 'P:%s\nV:%s\nL:%s\nA:%s\nT:%s\nU:%s\n\n' \
    "$PKG_NAME" "$PKG_VERSION" "$PKG_LICENSE" "$PKG_ARCH" "$PKG_DESC" "$PKG_URL" \
    >> "$APK_DB"

echo "Registered $PKG_NAME-$PKG_VERSION in $APK_DB"
