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
# apk purges these records on its next transaction (they are not reachable from
# /etc/apk/world). Harmless: no caller runs apk after registering. Do NOT add the
# name to /etc/apk/world to keep them - apk would then replace the source-built
# package with an upstream one of the same name.
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

# C: is mandatory: apk keys package identity on it, and APK_BLOB_CSUM takes the
# checksum type as the blob length, so a C:-less record hashes to a zero-length
# key. Two of them then collide and apk frees a still-referenced package
# (SIGSEGV); a single one makes apk commit a DB truncated at that record. No .apk
# file exists to hash, so derive a stable synthetic SHA-1 from name and version.
PKG_CSUM="Q1$(printf '%s' "${PKG_NAME}-${PKG_VERSION}" | sha1sum | cut -d' ' -f1 | xxd -r -p | base64)"

# A base64'd SHA-1 is always 28 chars; a short one would void the whole record.
[ ${#PKG_CSUM} -eq 30 ] || { echo "ERROR: could not compute checksum for $PKG_NAME (got '$PKG_CSUM')" >&2; exit 1; }

# Re-registering the same package is a no-op; two records must never share a C:.
if grep -Fqx "C:${PKG_CSUM}" "$APK_DB"; then
    echo "Skipping $PKG_NAME-$PKG_VERSION: already registered in $APK_DB"
    exit 0
fi

# Name taken by a different record, normally an apk-installed package. apk keeps
# one record per name, so the existing entry wins either way. Source-built names
# are not expected to collide with Alpine ones; report it rather than silently
# dropping the source-built attribution.
if grep -Fqx "P:${PKG_NAME}" "$APK_DB"; then
    echo "WARNING: $APK_DB already has a package named $PKG_NAME;" >&2
    echo "         not registering source-built $PKG_NAME-$PKG_VERSION, so the SBOM" >&2
    echo "         will report the existing entry instead." >&2
    exit 0
fi

# Without the blank separator apk folds these fields into the preceding package.
if [ -s "$APK_DB" ] && [ -n "$(tail -c 2 "$APK_DB")" ]; then
    printf '\n' >> "$APK_DB"
fi

# Field order matches what apk writes back, so the record round-trips unchanged.
# I:0 marks it virtual, keeping apk from resolving it against a repository.
printf 'C:%s\nP:%s\nV:%s\nA:%s\nS:0\nI:0\nT:%s\nU:%s\nL:%s\n\n' \
    "$PKG_CSUM" "$PKG_NAME" "$PKG_VERSION" "$PKG_ARCH" "$PKG_DESC" "$PKG_URL" "$PKG_LICENSE" \
    >> "$APK_DB"

echo "Registered $PKG_NAME-$PKG_VERSION in $APK_DB"
