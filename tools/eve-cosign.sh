#!/bin/bash
# Copyright (c) 2026, Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Keyless cosign signing and verification of EVE images; docs/SIGNING.md
# describes the policy.
#
# Usage:
#   eve-cosign.sh check-inputs <outdir> <arch>...
#       Run after a build: split the package platform manifests in the
#       linuxkit cache into <outdir>/pulled (the registry already serves the
#       digest) and <outdir>/built (built by this job), list the package tags
#       holding a built manifest in <outdir>/built-tags, and verify the
#       pulled manifests and, for the given architectures, the `FROM
#       lfedge/eve-*` bases of the built ones. A tag build must have built
#       nothing but the packages every build rebuilds (FORCE_BUILD_PKGS in
#       the Makefile), since it cannot sign. A re-run of a branch build lists the
#       pulled manifests that do not verify in <outdir>/unsigned instead of
#       failing, since an earlier attempt may have pushed them and failed
#       before signing.
#   eve-cosign.sh sign-built <outdir>
#       Run after the push: sign <outdir>/built and <outdir>/unsigned, unless
#       already signed. Does nothing on a tag build.
#   eve-cosign.sh sign-indexes <file>
#       Sign the package index each "<name>:<tag>" line of <file> names, once
#       every platform manifest in it verifies.
#   eve-cosign.sh verify <file>
#       Verify every "<name>@sha256:<hex>" line of <file>, <name> being the
#       package repository name, e.g. eve-pillar.
#
# Environment:
#   EVE_COSIGN_IDENTITY_REGEXP  required: regexp the certificate SAN must match
#   EVE_COSIGN_REPOSITORY       required: owner/repo the signing workflow ran in
#   EVE_COSIGN_ENFORCE          "true" makes verification failures fatal;
#                               otherwise they are reported as warnings
#   EVE_PKG_PREFIX              where packages are pulled from
#                               (default docker.io/lfedge)
#   EVE_SIG_PREFIX              where package signatures live
#                               (default EVE_PKG_PREFIX)
#   EVE_COSIGN_EXCLUDE          regexp of package names not signed by EVE's
#                               workflows (default ^eve-kernel$)
#   LINUXKIT_CACHE              linuxkit cache (default ~/.linuxkit/cache)

set -euo pipefail

EVE="$(cd "$(dirname "$0")/.." && pwd)"
OIDC_ISSUER=https://token.actions.githubusercontent.com
PKG_PREFIX="${EVE_PKG_PREFIX:-docker.io/lfedge}"
SIG_PREFIX="${EVE_SIG_PREFIX:-$PKG_PREFIX}"
EXCLUDE="${EVE_COSIGN_EXCLUDE:-^eve-kernel$}"
CACHE="${LINUXKIT_CACHE:-$HOME/.linuxkit/cache}"

die() {
    echo "eve-cosign: $*" >&2
    exit 1
}

require_policy() {
    [ -n "${EVE_COSIGN_IDENTITY_REGEXP:-}" ] || die "EVE_COSIGN_IDENTITY_REGEXP is not set"
    [ -n "${EVE_COSIGN_REPOSITORY:-}" ] || die "EVE_COSIGN_REPOSITORY is not set"
}

cosign_verify() {
    cosign verify \
        --certificate-oidc-issuer "$OIDC_ISSUER" \
        --certificate-identity-regexp "$EVE_COSIGN_IDENTITY_REGEXP" \
        --certificate-github-workflow-repository "$EVE_COSIGN_REPOSITORY" \
        "$1" > /dev/null
}

verified() {
    cosign_verify "$1" 2> /dev/null
}

# Docker Hub's referrers listing can lag a push, so a signature or attestation
# just made is re-checked for up to a minute; the last attempt's error goes to
# stderr.
until_visible() {
    local waited=0
    until "$@" > /dev/null 2>&1; do
        if [ "$waited" -ge 60 ]; then
            "$@" > /dev/null
            return
        fi
        sleep 5
        waited=$((waited + 5))
    done
    [ "$waited" -eq 0 ] || echo "visible after ${waited}s: ${*: -1}"
}

sign_digest() {
    if verified "$1"; then
        echo "already signed: $1"
        return
    fi
    cosign sign --yes "$1"
    until_visible cosign_verify "$1" || die "new signature on $1 does not verify under the policy"
    echo "signed: $1"
}

# resolve <ref>: print <repo>@<digest> of the manifest or index <ref> names.
resolve() {
    local digest
    digest=$(docker buildx imagetools inspect --format '{{json .Manifest}}' "$1" | jq -r .digest)
    case "$digest" in
    sha256:*) ;;
    *) die "cannot resolve $1" ;;
    esac
    case "$1" in
    *@*) echo "${1%@*}@$digest" ;;
    *) echo "${1%:*}@$digest" ;;
    esac
}

# The platform manifests of every cached $PKG_PREFIX/eve-* entry whose
# manifest blob is present, attestation manifests and $EXCLUDE left out, as
# "<name>@<digest> <name>:<tag>" lines.
cached_pkg_manifests() {
    local blobs="$CACHE/blobs/sha256"
    jq -r --arg p "$PKG_PREFIX/eve-" '.manifests[]
        | select((.annotations["org.opencontainers.image.ref.name"] // "") | startswith($p))
        | (.annotations["org.opencontainers.image.ref.name"] | sub(".*/"; "")) as $ref
        | [($ref | sub(":[^:]*$"; "")), $ref, .mediaType, .digest] | @tsv' "$CACHE/index.json" |
    while IFS=$'\t' read -r name ref type digest; do
        [[ "$name" =~ $EXCLUDE ]] && continue
        case "$type" in
        *index*|*manifest.list*)
            jq -r '.manifests[]
                | select(.annotations["vnd.docker.reference.type"] != "attestation-manifest")
                | .digest' "$blobs/${digest#sha256:}" |
            while read -r m; do
                if [ -f "$blobs/${m#sha256:}" ]; then echo "$name@$m $ref"; fi
            done
            ;;
        *)
            echo "$name@$digest $ref"
            ;;
        esac
    done | sort -u
}

classify() {
    local out="$1" entry ref
    mkdir -p "$out"
    : > "$out/pulled"
    : > "$out/built"
    : > "$out/built-tags"
    while read -r entry ref; do
        if docker buildx imagetools inspect --raw "$PKG_PREFIX/$entry" > /dev/null 2>&1; then
            echo "$entry" >> "$out/pulled"
        else
            echo "$entry" >> "$out/built"
            echo "$ref" >> "$out/built-tags"
        fi
    done < <(cached_pkg_manifests)
    sort -u -o "$out/pulled" "$out/pulled"
    sort -u -o "$out/built" "$out/built"
    sort -u -o "$out/built-tags" "$out/built-tags"
    echo "pulled: $(wc -l < "$out/pulled")  built here: $(wc -l < "$out/built")"
}

# report <failures> [<what>]: apply EVE_COSIGN_ENFORCE to a count of failed
# checks.
report() {
    local what="${2:-image(s) without a valid signature}"
    [ "$1" -eq 0 ] && return 0
    if [ "${EVE_COSIGN_ENFORCE:-}" = true ]; then
        echo "::error::$1 $what"
        return 1
    fi
    echo "::warning::$1 $what; EVE_COSIGN_ENFORCE is not true"
}

# verify_entries [<unsigned>]: verify each ref on stdin; with <unsigned>, list
# the refs that do not verify there instead of counting them as failures.
verify_entries() {
    local unsigned="${1:-}" failed=0 ref
    while read -r ref; do
        [ -n "$ref" ] || continue
        if verified "$ref"; then
            echo "verified: $ref"
        elif [ -n "$unsigned" ]; then
            echo "unsigned, to be signed: $ref"
            echo "${ref#"$SIG_PREFIX"/}" >> "$unsigned"
        else
            echo "::warning::no valid signature for $ref"
            failed=$((failed + 1))
        fi
    done
    report "$failed"
}

verify_pkgs() {
    sed "s|^|$SIG_PREFIX/|" "$1" | verify_entries "${2:-}"
}

# sign_index <name>:<tag>: sign the package index the tag names once each of
# its platform manifests verifies; a single-platform manifest is signed as is.
sign_index() {
    local ref digest raw m failed=0
    ref=$(resolve "$PKG_PREFIX/$1")
    digest="${ref##*@}"
    ref="$SIG_PREFIX/${1%:*}@$digest"
    if verified "$ref"; then
        echo "already signed: $ref"
        return
    fi
    raw=$(docker buildx imagetools inspect --raw "$ref")
    case "$(jq -r .mediaType <<< "$raw")" in
    *index*|*manifest.list*)
        for m in $(jq -r '.manifests[]
            | select(.annotations["vnd.docker.reference.type"] != "attestation-manifest") | .digest' <<< "$raw"); do
            if ! verified "${ref%@*}@$m"; then
                echo "::warning::$1 lists ${ref%@*}@$m, which has no valid signature"
                failed=1
            fi
        done
        ;;
    esac
    [ "$failed" -eq 0 ] || return 1
    sign_digest "$ref"
}

# The platform manifests, for the given architectures, of the `FROM
# lfedge/eve-*:<tag>` images that the packages listed in $1 are built from.
# A base the registry does not serve is printed as its bare tag, which then
# fails verification; bases listed in $1 themselves are skipped, since this
# job built them and signs them after pushing.
base_manifests() {
    local list="$1" name ref arch index
    shift
    sed 's/@.*//' "$list" | sort -u | while read -r name; do
        cat "$EVE/pkg/${name#eve-}"/Dockerfile* 2>/dev/null || true
    done |
    sed -nE 's|^FROM[[:space:]]+(docker\.io/)?lfedge/(eve-[a-z0-9-]+:[0-9a-f]+).*|\2|p' | sort -u |
    while read -r ref; do
        [[ "${ref%:*}" =~ $EXCLUDE ]] && continue
        grep -q "^${ref%:*}@sha256:" "$list" && continue
        if ! index=$(docker buildx imagetools inspect --raw "$PKG_PREFIX/$ref" 2> /dev/null); then
            echo "$SIG_PREFIX/$ref"
            continue
        fi
        for arch in "$@"; do
            jq -r --arg a "$arch" '.manifests[]
                | select(.platform.os == "linux" and .platform.architecture == $a) | .digest' <<< "$index" |
                sed "s|^|$SIG_PREFIX/${ref%:*}@|"
        done
    done | sort -u
}

is_tag_build() {
    [[ "${GITHUB_REF:-}" == refs/tags/* ]]
}

check_inputs() {
    local out="$1" failed=0
    shift
    classify "$out"
    : > "$out/unsigned"
    if is_tag_build; then
        verify_pkgs "$out/pulled" || failed=1
        require_reused "$out/built" || failed=1
    elif [ "${GITHUB_RUN_ATTEMPT:-1}" -gt 1 ]; then
        verify_pkgs "$out/pulled" "$out/unsigned" || failed=1
    else
        verify_pkgs "$out/pulled" || failed=1
    fi
    base_manifests "$out/built" "$@" | verify_entries || failed=1
    return "$failed"
}

# require_reused <file>: fail for each package in <file> other than those
# every build rebuilds, since their tag does not name their content.
require_reused() {
    local rebuilt entry pkg n=0
    rebuilt=" $(make -s -C "$EVE" force_build_pkgs_info | tail -1) "
    while read -r entry; do
        [ -n "$entry" ] || continue
        pkg=${entry%%@*}
        if [[ "$rebuilt" == *" ${pkg#eve-} "* ]]; then
            echo "rebuilt by every build: $entry"
        else
            echo "built by a tag build: $entry"
            n=$((n + 1))
        fi
    done < "$1"
    report "$n" "package(s) built by a tag build, which cannot sign them"
}

sign_pkgs() {
    local entry
    while read -r entry; do
        if [ -n "$entry" ]; then sign_digest "$SIG_PREFIX/$entry"; fi
    done < "$1"
}

cmd="${1:-}"
[ $# -gt 0 ] && shift
case "$cmd" in
check-inputs)
    [ $# -ge 2 ] || die "usage: check-inputs <outdir> <arch>..."
    require_policy
    check_inputs "$@"
    ;;
sign-built)
    [ $# -eq 1 ] || die "usage: sign-built <outdir>"
    require_policy
    if is_tag_build; then
        echo "tag build: the packages were signed by the branch build that pushed them"
        exit 0
    fi
    sign_pkgs "$1/built"
    [ ! -f "$1/unsigned" ] || sign_pkgs "$1/unsigned"
    ;;
sign-indexes)
    [ $# -eq 1 ] || die "usage: sign-indexes <file>"
    require_policy
    failed=0
    while read -r tag; do
        if [ -n "$tag" ]; then sign_index "$tag" || failed=$((failed + 1)); fi
    done < "$1"
    report "$failed" "package index(es) with unsigned platform manifests left unsigned"
    ;;
verify)
    [ $# -eq 1 ] || die "usage: verify <file>"
    require_policy
    verify_pkgs "$1"
    ;;
*)
    die "usage: $0 check-inputs|sign-built|sign-indexes|verify ..."
    ;;
esac
