#!/bin/bash
# Copyright (c) 2026, Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Push one release variant's EVE and eve-sources images from the linuxkit
# cache by digest, without a tag, so that release-sign.yml signs them before
# anything names them; docs/SIGNING.md describes the release flow.
#
# Usage: eve-push-release.sh <registry> <outdir>
#   <registry>  e.g. docker.io/lfedge
# ZARCH, HV and PLATFORM are set as for make, after `make eve` and, except
# on riscv64, `make sbom publish_sources` built into the cache. Appends to
# <outdir>:
#   images.txt                      the pushed platform manifests
#   sbom/<hex>.spdx.json            the SBOM, attested on EVE image <hex>
#   tags.txt                        "<repo>@<digest> <tag>" per tag to set
#   index/<repo>/<tag>/<arch>.json  this arch's descriptors in the
#                                   multi-arch index <repo>:<tag>
#   index/<repo>/<tag>/tags         the tags of that index
#   release-<arch>-<hv>-<platform>.env  EVE and EVE_SOURCES for assets.yml

set -euo pipefail

[ $# -eq 2 ] || { echo "usage: $0 <registry> <outdir>" >&2; exit 2; }
REGISTRY=$1
OUT=$2
: "${ZARCH:?}" "${HV:?}" "${PLATFORM:?}"
CACHE="${LINUXKIT_CACHE:-$HOME/.linuxkit/cache}"
HV_DEFAULT=kvm

die() {
    echo "::error::$*" >&2
    exit 1
}

vars=(ZARCH="$ZARCH" HV="$HV" PLATFORM="$PLATFORM")
VER=$(make -s "${vars[@]}" version | tail -1)
REL=$(make -s "${vars[@]}" LINUXKIT_PKG_TARGET=push eve_rel_info | tail -1)
[ -n "$REL" ] || die "no release name"
# linuxkit would push both under the same names on a tag.
[ "$VER" = "$REL" ] || die "version $VER differs from release name $REL"

# copy <cache name> <digest> <repo> <manifest>...: push the cache entry,
# pinned by digest so that no tag is set, and check that every blob of the
# given manifests arrived. oras resolves a digest that index.json does not
# list as a plain blob, so the named entry is what gets copied.
copy() {
    local name=$1 digest=$2 repo=$3 m j b
    shift 3
    oras cp --from-oci-layout-path "$CACHE" "$name" "$repo@$digest" >&2
    for m in "$@"; do
        j=$(oras manifest fetch "$repo@$m")
        for b in $(jq -r '.config.digest, .layers[].digest' <<< "$j"); do
            oras blob fetch --descriptor "$repo@$b" > /dev/null || die "$repo@$b is missing after copying $name"
        done
    done
}

# push <image>: push lfedge/<image>:$VER-$HV-$ZARCH from the cache, list it
# for signing and tagging, and print its platform manifest digest.
push() {
    local image=$1 name raw digest type plat descriptors
    local repo="$REGISTRY/$image" idx="$OUT/index/$image/$REL-$HV"
    name="docker.io/lfedge/$image:$VER-$HV-$ZARCH"
    digest=$(jq -r --arg n "$name" '.manifests[]
        | select(.annotations["org.opencontainers.image.ref.name"] == $n) | .digest' "$CACHE/index.json")
    [ -n "$digest" ] || die "$name is not in the linuxkit cache"
    raw=$(cat "$CACHE/blobs/sha256/${digest#sha256:}")
    type=$(jq -r .mediaType <<< "$raw")
    case "$type" in
    *index*|*manifest.list*)
        plat=$(jq -r --arg a "$ZARCH" '.manifests[] | select(.platform.architecture == $a) | .digest' <<< "$raw")
        [ -n "$plat" ] || die "no linux/$ZARCH manifest in $name"
        descriptors=$(jq '.manifests' <<< "$raw")
        # shellcheck disable=SC2046
        copy "$name" "$digest" "$repo" $(jq -r '.manifests[].digest' <<< "$raw")
        ;;
    *)
        plat=$digest
        descriptors=$(jq -n --arg t "$type" --arg d "$digest" --arg a "$ZARCH" \
            --argjson s "$(stat -c %s "$CACHE/blobs/sha256/${digest#sha256:}")" \
            '[{mediaType: $t, digest: $d, size: $s, platform: {os: "linux", architecture: $a}}]')
        copy "$name" "$digest" "$repo" "$digest"
        ;;
    esac
    echo "$repo@$plat" >> "$OUT/images.txt"
    echo "$repo@$plat $REL-$HV-$ZARCH" >> "$OUT/tags.txt"
    mkdir -p "$idx"
    echo "$descriptors" > "$idx/$ZARCH.json"
    echo "$REL-$HV" > "$idx/tags"
    if [ "$HV" = "$HV_DEFAULT" ]; then
        echo "$repo@$plat $REL-$ZARCH" >> "$OUT/tags.txt"
        echo "$REL" >> "$idx/tags"
    fi
    echo "$plat"
}

mkdir -p "$OUT/sbom"
eve=$(push eve)
env="$OUT/release-$ZARCH-$HV-$PLATFORM.env"
echo "EVE=$REGISTRY/eve@$eve" > "$env"
if [ "$ZARCH" != riscv64 ]; then
    sources=$(push eve-sources)
    echo "EVE_SOURCES=$REGISTRY/eve-sources@$sources" >> "$env"
    cp "$(make -s "${vars[@]}" sbom_info | tail -1)" "$OUT/sbom/${eve#sha256:}.spdx.json"
fi
cat "$OUT/tags.txt"
