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
#       holding them in <outdir>/pulled-tags and <outdir>/built-tags, and
#       verify the pulled manifests and, for the given architectures, the
#       lfedge/eve-* bases of the built ones. A tag build must have built
#       nothing but the packages every build rebuilds (FORCE_BUILD_PKGS in
#       the Makefile), since it cannot sign. Images of excluded packages
#       among these are checked as well, and the result is only logged.
#   eve-cosign.sh sign-pushed <dir>...
#       Run after the push: sign the manifests that the check-inputs records
#       in or directly under the <dir>s list as built and the registry
#       serves, unless already signed. Given the records of every attempt of
#       a job, a re-run signs what an earlier attempt pushed and failed to
#       sign. Does nothing on a tag build.
#   eve-cosign.sh sign-indexes <dir>...
#       Sign the package index each tag in the records under the <dir>s
#       names, once every platform manifest in it verifies. Skips the
#       packages every build rebuilds, whose tags concurrent builds overwrite.
#   eve-cosign.sh sign-tags <name>:<tag>...
#       Sign the platform manifests of each index the tags name, then the
#       index; for images pushed outside publish.yml, such as eve-alpine-base.
#   eve-cosign.sh audit <arch>... -- <dir>...
#       Verify every manifest and index the records under the <dir>s list,
#       built ones the registry serves only on a branch build, and the
#       lfedge/eve-* bases of all their packages for the given architectures.
#       Indexes of the packages every build rebuilds are skipped, as in
#       sign-indexes; their manifests are checked by digest. Bases of
#       excluded packages are checked as well, and the result is only logged.
#   eve-cosign.sh verify <file>
#       Verify every "<name>@sha256:<hex>" line of <file>, <name> being the
#       package repository name, e.g. eve-pillar.
#
# Environment:
#   EVE_COSIGN_IDENTITY_REGEXP  regexp the certificate SAN must match, and
#   EVE_COSIGN_REPOSITORY       owner/repo the signing workflow ran in, in
#                               place of EVE's policy (to rehearse on a fork)
#   EVE_COSIGN_ENFORCE          "true" makes verification failures fatal;
#                               otherwise they are reported as warnings
#   EVE_PKG_PREFIX              where packages are pulled from
#                               (default docker.io/lfedge)
#   EVE_SIG_PREFIX              where package signatures live
#                               (default EVE_PKG_PREFIX)
#   EVE_COSIGN_EXCLUDE          regexp of package names whose signatures are
#                               only logged (default ^eve-(kernel|rust)$)
#   LINUXKIT_CACHE              linuxkit cache (default ~/.linuxkit/cache)

set -euo pipefail

EVE="$(cd "$(dirname "$0")/.." && pwd)"
OIDC_ISSUER=https://token.actions.githubusercontent.com
PKG_PREFIX="${EVE_PKG_PREFIX:-docker.io/lfedge}"
SIG_PREFIX="${EVE_SIG_PREFIX:-$PKG_PREFIX}"
EXCLUDE="${EVE_COSIGN_EXCLUDE:-^eve-(kernel|rust)$}"
CACHE="${LINUXKIT_CACHE:-$HOME/.linuxkit/cache}"

# The signature policy: the workflows allowed to sign packages, and the
# repository they ran in. A tag build runs its own commit's copy of this
# script, so EVE's packages are accepted only from protected branches.
# eve-rust and eve-kernel are signed by their own repositories' workflows.
EVE_IDENTITY_REGEXP='^https://github\.com/lf-edge/eve/\.github/workflows/(release-sign\.yml@refs/heads/master|build-alpine-base\.yml@refs/heads/master|publish\.yml@refs/heads/(master|[0-9]+\.[0-9]+(-stable)?))$'
RUST_IDENTITY_REGEXP='^https://github\.com/lf-edge/eve-rust/\.github/workflows/release\.yaml@refs/tags/[0-9]+\.[0-9]+\.[0-9]+(-[0-9]+)?$'
KERNEL_IDENTITY_REGEXP='^https://github\.com/lf-edge/eve-kernel/\.github/workflows/publish\.yml@refs/heads/eve-kernel-(amd64|arm64|riscv64)-(v[0-9]+\.[0-9]+(\.[0-9]+)?-[a-z0-9-]+|next)$'
IDENTITY_REGEXP="${EVE_COSIGN_IDENTITY_REGEXP:-$EVE_IDENTITY_REGEXP}"
REPOSITORY="${EVE_COSIGN_REPOSITORY:-lf-edge/eve}"

die() {
    echo "eve-cosign: $*" >&2
    exit 1
}


# policy <ref>: set POLICY_REGEXP and POLICY_REPOSITORY to the policy for
# the package <ref> names.
policy() {
    local name="${1##*/}"
    name="${name%%@*}"
    case "${name%%:*}" in
    eve-rust)
        POLICY_REGEXP="$RUST_IDENTITY_REGEXP"
        POLICY_REPOSITORY=lf-edge/eve-rust
        ;;
    eve-kernel)
        POLICY_REGEXP="$KERNEL_IDENTITY_REGEXP"
        POLICY_REPOSITORY=lf-edge/eve-kernel
        ;;
    *)
        POLICY_REGEXP="$IDENTITY_REGEXP"
        POLICY_REPOSITORY="$REPOSITORY"
        ;;
    esac
}

cosign_verify() {
    policy "$1"
    cosign verify \
        --certificate-oidc-issuer "$OIDC_ISSUER" \
        --certificate-identity-regexp "$POLICY_REGEXP" \
        --certificate-github-workflow-repository "$POLICY_REPOSITORY" \
        "$1" > /dev/null
}

# verified <ref>: succeed when a signature on <ref> verifies under the policy,
# fail when none does or <ref> does not exist. Any other cosign error, such as
# a registry rate limit, is fatal, so that it is not reported as a missing
# signature.
verified() {
    local err
    err=$(cosign_verify "$1" 2>&1) && return 0
    case "$err" in
    *"no signatures found"* | *"no matching signatures"* | *"image tag not found"*)
        return 1
        ;;
    esac
    die "cannot verify $1: ${err##*$'\n'}"
}

# Docker Hub's referrers listing can lag a push, so a signature or attestation
# just made is re-checked every 5 s for up to five minutes; the last attempt's
# error goes to stderr.
until_visible() {
    local waited=0
    until "$@" > /dev/null 2>&1; do
        if [ "$waited" -ge 300 ]; then
            "$@" > /dev/null
            return
        fi
        sleep 5
        waited=$((waited + 5))
    done
    [ "$waited" -eq 0 ] || echo "visible after ${waited}s: ${*: -1}"
}

# Rekor's transient 5xx errors can outlast cosign's own two attempts, so a
# failed signing is retried every 30 s, five attempts in all. Each attempt
# signs with new ephemeral keys, so an earlier attempt's Rekor entry goes unused.
sign_digest() {
    local tries=1
    if verified "$1"; then
        echo "already signed: $1"
        return
    fi
    until cosign sign --yes "$1"; do
        [ "$tries" -lt 5 ] || die "cannot sign $1 after $tries attempts"
        echo "signing $1 failed, retrying in 30 s"
        sleep 30
        tries=$((tries + 1))
    done
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
# manifest blob is present, attestation manifests left out and $EXCLUDE
# passed to split_excluded, as
# "<name>@<digest> <name>:<tag>" lines. `linuxkit pkg push` adds a
# "<tag>-<arch>" entry for each manifest of a pushed index, attestations
# included as "<tag>-unknown", copying the index's descriptor and annotations.
cached_pkg_manifests() {
    local blobs="$CACHE/blobs/sha256"
    jq -r --arg p "$PKG_PREFIX/eve-" '.manifests[]
        | select((.annotations["org.opencontainers.image.ref.name"] // "") | startswith($p))
        | select(.annotations["vnd.docker.reference.type"] != "attestation-manifest")
        | (.annotations["org.opencontainers.image.ref.name"] | sub(".*/"; "")) as $ref
        | [($ref | sub(":[^:]*$"; "")), $ref, .mediaType, .digest] | @tsv' "$CACHE/index.json" |
    while IFS=$'\t' read -r name ref type digest; do
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
    done | sort -u | split_excluded
}

# split_excluded: pass on the lines of stdin whose first field, a
# "[<prefix>/]<name>@<digest>" or "[<prefix>/]<name>:<tag>" reference, names a
# package $EXCLUDE does not match. The others are appended to $EXCLUDED, when
# set, as references under $SIG_PREFIX.
split_excluded() {
    local entry rest name
    while read -r entry rest; do
        name="${entry##*/}"
        name="${name%%@*}"
        name="${name%%:*}"
        if ! [[ "$name" =~ $EXCLUDE ]]; then
            echo "$entry${rest:+ $rest}"
        elif [ -n "${EXCLUDED:-}" ]; then
            case "$entry" in
            */*) echo "$entry" ;;
            *) echo "$SIG_PREFIX/$entry" ;;
            esac >> "$EXCLUDED"
        fi
    done
}

classify() {
    local out="$1" entry ref
    mkdir -p "$out"
    : > "$out/pulled"
    : > "$out/built"
    : > "$out/built-tags"
    : > "$out/pulled-tags"
    while read -r entry ref; do
        if docker buildx imagetools inspect --raw "$PKG_PREFIX/$entry" > /dev/null 2>&1; then
            echo "$entry" >> "$out/pulled"
            echo "$ref" >> "$out/pulled-tags"
        else
            echo "$entry" >> "$out/built"
            echo "$ref" >> "$out/built-tags"
        fi
    done < <(cached_pkg_manifests)
    sort -u -o "$out/pulled" "$out/pulled"
    sort -u -o "$out/built" "$out/built"
    sort -u -o "$out/built-tags" "$out/built-tags"
    sort -u -o "$out/pulled-tags" "$out/pulled-tags"
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

# count_unverified: verify each ref on stdin and print the number that do not
# verify.
count_unverified() {
    local failed=0 ref
    while read -r ref; do
        [ -n "$ref" ] || continue
        if verified "$ref"; then
            echo "verified: $ref" >&2
        else
            echo "::warning::no valid signature for $ref" >&2
            failed=$((failed + 1))
        fi
    done
    echo "$failed"
}

verify_entries() {
    local failed
    failed=$(count_unverified) || return 1
    report "$failed"
}

verify_pkgs() {
    sed "s|^|$SIG_PREFIX/|" "$1" | verify_entries
}

# sign_index <name>:<tag>: sign the package index the tag names once each of
# its platform manifests verifies. A tag naming a platform manifest is only
# checked: its manifest is signed by the job that pushed it, and the tag may
# have been moved since by another build.
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
    *)
        echo "::warning::$1 names $ref, which has no valid signature"
        return 1
        ;;
    esac
    [ "$failed" -eq 0 ] || return 1
    sign_digest "$ref"
}

# sign_tag <name>:<tag>: sign each platform manifest of the index the tag
# names, then the index.
sign_tag() {
    local ref raw m
    ref=$(resolve "$PKG_PREFIX/$1")
    raw=$(docker buildx imagetools inspect --raw "$ref")
    case "$(jq -r .mediaType <<< "$raw")" in
    *index*|*manifest.list*)
        for m in $(jq -r '.manifests[]
            | select(.annotations["vnd.docker.reference.type"] != "attestation-manifest") | .digest' <<< "$raw"); do
            sign_digest "$SIG_PREFIX/${1%:*}@$m"
        done
        ;;
    esac
    sign_index "$1"
}

# The platform manifests, for the given architectures, of the lfedge/eve-*
# images that the packages listed in $1 are built from: those a FROM line
# names, with or without --platform, and those an ARG pins for a later
# `FROM ${ARG}`. A tag must start with a lowercase letter or digit, which
# leaves out Dockerfile.in placeholders such as PILLAR_TAG. A base the
# registry does not serve is printed as its bare tag, which then fails
# verification; bases listed in $2 are skipped, since this job built them and
# signs them after pushing; bases of $EXCLUDE go to split_excluded. No match is
# not an error: a job that pulled every package has no Dockerfile to scan.
base_manifests() {
    local list="$1" skip="$2" name ref arch index
    shift 2
    sed 's/@.*//' "$list" | sort -u | while read -r name; do
        cat "$EVE/pkg/${name#eve-}"/Dockerfile{,.in} 2>/dev/null || true
    done |
    { grep -E '^[[:space:]]*(FROM|ARG)[[:space:]]' || true; } |
    { grep -oE '(^|[[:space:]=])(docker\.io/)?lfedge/eve-[a-z0-9-]+:[a-z0-9][A-Za-z0-9_.-]*' || true; } |
    sed -E 's|.*lfedge/||' | sort -u |
    while read -r ref; do
        grep -q "^${ref%:*}@sha256:" "$skip" && continue
        if ! index=$(docker buildx imagetools inspect --raw "$PKG_PREFIX/$ref" 2> /dev/null); then
            echo "$SIG_PREFIX/$ref"
            continue
        fi
        for arch in "$@"; do
            jq -r --arg a "$arch" '.manifests[]
                | select(.platform.os == "linux" and .platform.architecture == $a) | .digest' <<< "$index" |
                sed "s|^|$SIG_PREFIX/${ref%:*}@|"
        done
    done | sort -u | split_excluded
}

is_tag_build() {
    [[ "${GITHUB_REF:-}" == refs/tags/* ]]
}

check_inputs() {
    local out="$1" failed=0
    shift
    mkdir -p "$out"
    EXCLUDED="$out/excluded"
    : > "$EXCLUDED"
    classify "$out"
    verify_pkgs "$out/pulled" || failed=1
    if is_tag_build; then
        require_reused "$out/built" || failed=1
    fi
    base_manifests "$out/built" "$out/built" "$@" | verify_entries || failed=1
    log_excluded "$EXCLUDED"
    return "$failed"
}

# log_excluded <file>: verify each reference in <file> under the policy for
# its package and log the result. Never fails: these packages are excluded
# until the log shows that they verify.
log_excluded() {
    local ref err
    sort -u "$1" | while read -r ref; do
        [ -n "$ref" ] || continue
        policy "$ref"
        if err=$(cosign_verify "$ref" 2>&1); then
            echo "excluded, verified as $POLICY_REPOSITORY: $ref"
        else
            case "$err" in
            *"no signatures found"*) echo "excluded, not signed: $ref" ;;
            *) echo "excluded, does not verify as $POLICY_REPOSITORY: $ref: ${err##*$'\n'}" ;;
            esac
        fi
    done
}

# require_reused <file>: fail for each package in <file> other than those
# every build rebuilds, since their tag does not name their content.
require_reused() {
    local entry n=0
    while read -r entry; do
        [ -n "$entry" ] || continue
        if force_built "${entry%%@*}"; then
            echo "rebuilt by every build: $entry"
        else
            echo "built by a tag build: $entry"
            n=$((n + 1))
        fi
    done < "$1"
    report "$n" "package(s) built by a tag build, which cannot sign them"
}

# records <name> <dir>...: the sorted, unique lines of every <name> file of the
# records in or directly under the <dir>s. download-artifact extracts a lone
# matching artifact into its path rather than a subdirectory, so both depths
# occur. Dies when no record is found.
records() {
    local name="$1" files
    shift
    files=$(find "$@" -maxdepth 2 -type f -name "$name" | sort)
    [ -n "$files" ] || die "no $name record under $*"
    # shellcheck disable=SC2086 # one path per line, none with spaces
    sort -u $files
}

# force_built <name>:<tag>: succeed when every build rebuilds the package
# (FORCE_BUILD_PKGS in the Makefile).
force_built() {
    local name="${1%%:*}"
    [ -n "${FORCE_BUILT+x}" ] || FORCE_BUILT=" $(make -s -C "$EVE" force_build_pkgs_info | tail -1) "
    [[ "$FORCE_BUILT" == *" ${name#eve-} "* ]]
}

# served <list>: the entries of <list> that the registry serves; one it does
# not serve was never pushed, as when a push failed and a re-run built the
# package again.
served() {
    local entry
    while read -r entry; do
        [ -n "$entry" ] || continue
        if docker buildx imagetools inspect --raw "$PKG_PREFIX/$entry" > /dev/null 2>&1; then
            echo "$entry"
        else
            echo "not pushed: $entry" >&2
        fi
    done < "$1"
}

# sign_pushed <dir>...: sign each manifest the records under the <dir>s list
# as built and the registry serves.
sign_pushed() {
    local built pushed entry n=0
    built=$(mktemp)
    pushed=$(mktemp)
    records built "$@" > "$built"
    served "$built" > "$pushed"
    while read -r entry; do
        sign_digest "$SIG_PREFIX/$entry"
        n=$((n + 1))
    done < "$pushed"
    echo "$n of $(grep -c . "$built" || true) built manifest(s) pushed and signed"
    rm -f "$built" "$pushed"
}

# sign_indexes <dir>...: sign_index each tag the records under the <dir>s list,
# except those of packages every build rebuilds.
sign_indexes() {
    local tags tag failed=0
    tags=$(mktemp)
    { records built-tags "$@"; records pulled-tags "$@"; } | sort -u > "$tags"
    while read -r tag; do
        [ -n "$tag" ] || continue
        if force_built "$tag"; then
            echo "rebuilt by every build: $tag"
            continue
        fi
        sign_index "$tag" || failed=$((failed + 1))
    done < "$tags"
    rm -f "$tags"
    report "$failed" "package index(es) with unsigned platform manifests left unsigned"
}

# audit <arch>... -- <dir>...: see the usage above.
audit() {
    local arches=() manifests built tags tag ref failed
    while [ $# -gt 0 ] && [ "$1" != -- ]; do
        arches+=("$1")
        shift
    done
    [ $# -gt 1 ] || die "usage: audit <arch>... -- <dir>..."
    shift
    manifests=$(mktemp)
    built=$(mktemp)
    tags=$(mktemp)
    EXCLUDED=$(mktemp)
    records pulled "$@" > "$manifests"
    records pulled-tags "$@" > "$tags"
    if ! is_tag_build; then
        records built "$@" > "$built"
        served "$built" >> "$manifests"
        records built-tags "$@" >> "$tags"
    fi
    sort -u -o "$manifests" "$manifests"
    sort -u -o "$tags" "$tags"
    failed=$({
        sed "s|^|$SIG_PREFIX/|" "$manifests"
        while read -r tag; do
            [ -n "$tag" ] || continue
            force_built "$tag" && continue
            ref=$(resolve "$PKG_PREFIX/$tag")
            echo "$SIG_PREFIX/${tag%:*}@${ref##*@}"
        done < "$tags"
        base_manifests "$manifests" /dev/null "${arches[@]}"
    } | sort -u | count_unverified)
    log_excluded "$EXCLUDED"
    rm -f "$manifests" "$built" "$tags" "$EXCLUDED"
    report "$failed" "image(s) this run pushed or used without a valid signature" || exit 1
    [ "$failed" -ne 0 ] || echo "every image this run pushed or used is signed"
}

cmd="${1:-}"
[ $# -gt 0 ] && shift
case "$cmd" in
check-inputs)
    [ $# -ge 2 ] || die "usage: check-inputs <outdir> <arch>..."
    check_inputs "$@"
    ;;
sign-pushed)
    [ $# -ge 1 ] || die "usage: sign-pushed <dir>..."
    if is_tag_build; then
        echo "tag build: the packages were signed by the branch build that pushed them"
        exit 0
    fi
    sign_pushed "$@"
    ;;
sign-indexes)
    [ $# -ge 1 ] || die "usage: sign-indexes <dir>..."
    sign_indexes "$@"
    ;;
sign-tags)
    [ $# -ge 1 ] || die "usage: sign-tags <name>:<tag>..."
    for tag in "$@"; do
        sign_tag "$tag" || die "cannot sign $tag"
    done
    ;;
audit)
    audit "$@"
    ;;
verify)
    [ $# -eq 1 ] || die "usage: verify <file>"
    verify_pkgs "$1"
    ;;
*)
    die "usage: $0 check-inputs|sign-pushed|sign-indexes|sign-tags|audit|verify ..."
    ;;
esac
