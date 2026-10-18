#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# copy-with-libs.sh - copy files out of a rootfs together with the shared
# libraries they need.
#
# Usage:
#   copy-with-libs.sh [-r <rootfs>] [-m] -o <outdir> <path> [<path> ...]
#
# Every <path> (absolute within <rootfs>, default /out; globs allowed, a
# directory means everything below it) is copied to the same place under
# <outdir>, followed by every shared library and the dynamic loader that the
# ELF files among them link against, resolved by lddtree against the rootfs.
# Symlink chains are copied whole.
#
# The merged-/usr symlinks of the source (/bin -> usr/bin, /lib -> usr/lib,
# /lib64 -> usr/lib64, ...) are never recreated: every file lands under the
# real directory it lives in. The result can therefore be overlaid onto a
# rootfs that has real /bin, /lib and /sbin directories, such as the EVE host
# rootfs that linuxkit assembles from the init images, where a symlink in
# place of an existing directory would not extract. Only the dynamic loader
# additionally gets a symlink at the path the kernel looks it up
# (/lib64/ld-linux-x86-64.so.2, /lib/ld-linux-aarch64.so.1, ...).
#
# With -m the files are meant for a merged-/usr rootfs like /out itself, which
# already has that loader path: no alias is made, since the real /lib64 (or
# /lib) directory it would come in cannot be copied onto the symlink there.
set -e

usage() {
    echo "Usage: $0 [-r <rootfs>] [-m] -o <outdir> <path> [<path> ...]" >&2
    exit 1
}

ROOT=/out
OUT=""
MERGED=""
while getopts "r:mo:" opt; do
    case "$opt" in
        r) ROOT="$OPTARG" ;;
        m) MERGED=1 ;;
        o) OUT="$OPTARG" ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))
{ [ -n "$OUT" ] && [ $# -gt 0 ]; } || usage

for tool in lddtree dpkg-query; do
    command -v "$tool" >/dev/null 2>&1 || { echo "$0: $tool not found (pax-utils, dpkg)" >&2; exit 1; }
done

ROOT="$(cd "$ROOT" && pwd -P)"
[ "$ROOT" = / ] && ROOT=""
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd -P)"

LIST="$(mktemp)"
LIBS="$(mktemp)"
trap 'rm -f "$LIST" "$LIBS"' EXIT

# canonical form of an absolute path within ROOT: the directory part resolved
# physically, the final component kept as is (it may be a symlink we want)
canon() {
    dir="$(cd "$ROOT$(dirname "$1")" && pwd -P)" || return 1
    echo "${dir#"$ROOT"}/$(basename "$1")"
}

# copy one canonical path and, if it is a symlink, the chain behind it
copy_one() {
    p="$1"
    while :; do
        if [ ! -e "$ROOT$p" ] && [ ! -L "$ROOT$p" ]; then
            echo "$0: $ROOT$p: not found" >&2
            return 1
        fi
        (cd "$ROOT/" && cp -a --parents ".$p" "$OUT")
        [ -L "$ROOT$p" ] || return 0
        t="$(readlink "$ROOT$p")"
        case "$t" in
            /*) p="$(canon "$t")" ;;
            *)  p="$(canon "$(dirname "$p")/$t")" ;;
        esac
    done
}

# 1. the requested files
for arg in "$@"; do
    found=0
    for f in "$ROOT"$arg; do
        [ -e "$f" ] || [ -L "$f" ] || continue
        found=1
        if [ -d "$f" ] && [ ! -L "$f" ]; then
            find "$f" \( -type f -o -type l \) -print >> "$LIST"
        else
            echo "$f" >> "$LIST"
        fi
    done
    if [ "$found" = 0 ]; then
        echo "$0: $ROOT$arg: not found" >&2
        exit 1
    fi
done

# 2. the libraries and loaders they need; lddtree complains about files that
#    are not ELF and prints nothing for them, which is fine
xargs -r lddtree -R "$ROOT/" -l --no-auto-root < "$LIST" 2>/dev/null | grep '^/' > "$LIBS" || :

# 3. copy everything under its canonical path
sed "s|^$ROOT||" "$LIST" "$LIBS" | sort -u | while read -r p; do
    copy_one "$(canon "$p")"
done

# 4. the kernel finds the loader where PT_INTERP says, not where it lives
[ -n "$MERGED" ] || xargs -r lddtree -R "$ROOT/" --no-auto-root < "$LIST" 2>/dev/null \
    | sed -n 's/.*(interpreter => \([^)]*\)).*/\1/p' | sort -u | while read -r interp; do
    interp="${interp#"$ROOT"}"
    # shared libraries report "None"
    case "$interp" in /*) ;; *) continue ;; esac
    [ -e "$OUT$interp" ] || [ -L "$OUT$interp" ] && continue
    mkdir -p "$OUT$(dirname "$interp")"
    ln -s "$(canon "$interp")" "$OUT$interp"
done

# 5. the SBOM: the dpkg status records (and copyright files) of the packages
#    that own what was copied, so that syft lists exactly those for the image
[ -f "$ROOT/var/lib/dpkg/status" ] || exit 0
PKGS="$(mktemp)"
trap 'rm -f "$LIST" "$LIBS" "$PKGS"' EXIT
sed "s|^$ROOT||" "$LIST" "$LIBS" | sort -u | xargs -r dpkg-query --admindir="$ROOT/var/lib/dpkg" -S 2>/dev/null \
    | sed -n 's/^\([^:,]*\)[^ ]*: .*/\1/p' | sort -u > "$PKGS"
[ -s "$PKGS" ] || exit 0
mkdir -p "$OUT/var/lib/dpkg"
# the list is read line by line before paragraph mode is switched on
awk -v pkgfile="$PKGS" 'BEGIN { while ((getline p < pkgfile) > 0) want[p] = 1; RS = ""; FS = "\n" }
{
    for (i = 1; i <= NF; i++)
        if (substr($i, 1, 9) == "Package: " && (substr($i, 10) in want)) { printf "%s\n\n", $0; break }
}' "$ROOT/var/lib/dpkg/status" > "$PKGS.status"
# a previous run may have left records for other files in the output
if [ -f "$OUT/var/lib/dpkg/status" ]; then
    merge-sbom-db.sh -o "$PKGS.status" "$OUT/var/lib/dpkg/status" "$PKGS.status" >/dev/null
fi
mv "$PKGS.status" "$OUT/var/lib/dpkg/status"
while read -r p; do
    [ -f "$ROOT/usr/share/doc/$p/copyright" ] || continue
    (cd "$ROOT/" && cp -a --parents "./usr/share/doc/$p/copyright" "$OUT")
done < "$PKGS"
