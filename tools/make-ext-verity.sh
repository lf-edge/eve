#!/bin/sh
#
# make-ext-verity.sh -- Generate dm-verity metadata for extension image.
#
# The hash tree is appended directly to the image file (no sidecar).
# The output roothash file contains two lines:
#   line 1: root hash (hex)
#   line 2: data size in bytes (= hash-offset for veritysetup open)
#
# Usage:
#   ./tools/make-ext-verity.sh <ext-img> [<roothash-out>]
#
# Example:
#   ./tools/make-ext-verity.sh dist/amd64/current/installer/rootfs-ext.img

set -e

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "Usage: $0 <ext-img> [<roothash-out>]" >&2
    exit 1
fi

IMG="$1"
ROOTHASH_OUT="${2:-${IMG}.roothash}"

if [ ! -f "$IMG" ]; then
    echo "Image not found: $IMG" >&2
    exit 1
fi

if ! command -v veritysetup >/dev/null 2>&1; then
    echo "veritysetup not found in PATH" >&2
    exit 1
fi

TMP_OUTPUT=$(mktemp)
trap 'rm -f "$TMP_OUTPUT"' EXIT

# Record the original data size before appending the hash tree.
# This is the --hash-offset value needed by veritysetup open at runtime.
DATA_SIZE=$(stat -c %s "$IMG")

# Append the dm-verity Merkle tree directly to the image file.
# Using the same file as both data and hash device with --hash-offset
# eliminates the need for a separate .verity sidecar file.
veritysetup format --hash-offset="$DATA_SIZE" "$IMG" "$IMG" >"$TMP_OUTPUT"

ROOT_HASH=$(awk '/Root hash:/ {print $3}' "$TMP_OUTPUT" | tail -n 1)
if [ -z "$ROOT_HASH" ]; then
    echo "Failed to parse root hash from veritysetup output" >&2
    exit 1
fi

printf '%s\n%s\n' "$ROOT_HASH" "$DATA_SIZE" > "$ROOTHASH_OUT"
echo "Generated:"
echo "  image:       $IMG (hash tree appended at offset $DATA_SIZE)"
echo "  root hash:   $ROOT_HASH"
echo "  data size:   $DATA_SIZE bytes"
echo "  roothash:    $ROOTHASH_OUT"
