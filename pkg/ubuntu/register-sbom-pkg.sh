#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# register-sbom-pkg.sh - Register a source-built package in the dpkg status
# area so syft includes it in the SBOM.
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
# The entry is written to <outdir>/var/lib/dpkg/status.d/<name> (the
# distroless convention: syft parses it, while dpkg/apt never read it, so a
# registration cannot break later apt-get runs in the chroot). The license
# goes to <outdir>/usr/share/doc/<name>/copyright, where syft looks for
# dpkg package licenses.
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

STATUS_D="${OUTDIR}/var/lib/dpkg/status.d"

# Always make sure the status.d directory exists so that callers can rely
# on it being present even when this script is invoked only to initialize
# it (no -n/-v/-l/-u). This also lets later
# COPY --from=<stage> /.../var/lib/dpkg/status.d succeed unconditionally.
mkdir -p "$STATUS_D"

# Init-only mode: if no package fields were supplied, we just ensured the
# directory exists and we're done.
if [ -z "$PKG_NAME" ] && [ -z "$PKG_VERSION" ] && [ -z "$PKG_LICENSE" ] && [ -z "$PKG_URL" ]; then
    echo "Initialized $STATUS_D"
    exit 0
fi

[ -n "$PKG_NAME" ]    || { echo "ERROR: -n (name) is required" >&2;    usage; }
[ -n "$PKG_VERSION" ] || { echo "ERROR: -v (version) is required" >&2; usage; }
[ -n "$PKG_LICENSE" ] || { echo "ERROR: -l (license) is required" >&2; usage; }
[ -n "$PKG_URL" ]     || { echo "ERROR: -u (url) is required" >&2;     usage; }

PKG_DESC="${PKG_DESC:-${PKG_NAME} (built from source)}"
PKG_ARCH="$(dpkg --print-architecture)"

printf 'Package: %s\nStatus: install ok installed\nVersion: %s\nArchitecture: %s\nDescription: %s\nHomepage: %s\n' \
    "$PKG_NAME" "$PKG_VERSION" "$PKG_ARCH" "$PKG_DESC" "$PKG_URL" \
    > "${STATUS_D}/${PKG_NAME}"

# dpkg has no license field in the status format; syft picks the license up
# from the package's machine-readable copyright file.
DOC_DIR="${OUTDIR}/usr/share/doc/${PKG_NAME}"
mkdir -p "$DOC_DIR"
printf 'Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\nUpstream-Name: %s\nSource: %s\n\nFiles: *\nLicense: %s\n' \
    "$PKG_NAME" "$PKG_URL" "$PKG_LICENSE" \
    > "${DOC_DIR}/copyright"

echo "Registered $PKG_NAME-$PKG_VERSION in ${STATUS_D}/${PKG_NAME}"
