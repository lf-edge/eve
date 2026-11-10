#!/bin/bash
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# A release signer's approval of an EVE release (docs/SIGNING.md
# "Approving a release"):
#
#   eve-release-approval.sh approve [-y] TAG
#       Checks the draft release TAG as release-sign.yml signed it, shows the
#       tag, its commit and the changes since the previous release, and signs
#       one in-toto statement over the release's images and sha256sums files
#       with the caller's GitHub login (Sigstore keyless). Uploads it as
#       <TAG>.maintainer.sigstore.json, publishes the release, and starts
#       release-approval.yml, which attaches the statement to every image.
#   eve-release-approval.sh check DIR TAG
#       Verifies the assets of TAG in DIR, including the approval, and prints
#       "<login> <email>" of the signer who approved it.
#
# The signers are the lines "<GitHub login> <email>" of .github/release-signers
# on SIGNERS_REF (default master) of REPOSITORY (default lf-edge/eve), or of
# the file SIGNERS_FILE; the
# email is the one the signer picks at the Sigstore login. The tagger may not
# approve their own tag. Needs gh (logged in with push access), cosign 3 and jq.

set -euo pipefail

REPOSITORY=${REPOSITORY:-lf-edge/eve}
SIGNERS_REF=${SIGNERS_REF:-master}
IDENTITY=${IDENTITY:-https://github.com/$REPOSITORY/.github/workflows/release-sign.yml@refs/heads/master}
ISSUER=https://token.actions.githubusercontent.com
SIGNER_ISSUER=https://github.com/login/oauth
TAGGER_TYPE=https://github.com/$REPOSITORY/release-tagger/v1
APPROVAL_TYPE=https://github.com/$REPOSITORY/release-approval/v1

die() { echo "error: $*" >&2; exit 1; }

usage() {
  sed -n '/^#   eve-release-approval.sh/,/^#$/p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

signers() {
  if [ -n "${SIGNERS_FILE:-}" ]; then
    sed 's/#.*//' "$SIGNERS_FILE" | awk 'NF == 2'
    return
  fi
  gh api -H 'Accept: application/vnd.github.raw' \
    "repos/$REPOSITORY/contents/.github/release-signers?ref=$SIGNERS_REF" | sed 's/#.*//' | awk 'NF == 2'
}

payload() { jq -r .dsseEnvelope.payload "$1" | base64 -d; }

workflow_policy() {
  echo --certificate-oidc-issuer "$ISSUER" --certificate-identity "$IDENTITY" \
    --certificate-github-workflow-repository "$REPOSITORY" \
    --certificate-github-workflow-ref "refs/tags/$1"
}

# verify_release DIR TAG checks every sums file in DIR and the files it lists
# that are present against release-sign.yml's signatures, and the tagger
# statement over them, and prints the tagger's login.
verify_release() {
  local dir=$1 tag=$2 sums tagger="$1/$2.tagger.sigstore.json" n=0
  # shellcheck disable=SC2046
  for sums in "$dir"/*.sha256sums; do
    [ -f "$sums" ] || die "no sha256sums files in $dir"
    cosign verify-blob $(workflow_policy "$tag") --bundle "$sums.sigstore.json" "$sums" > /dev/null 2>&1 ||
      die "$(basename "$sums") is not signed by $IDENTITY for $tag"
    (cd "$dir" && sha256sum --quiet --ignore-missing -c "$(basename "$sums")") >&2 ||
      die "assets of $(basename "$sums") do not match"
    [ -f "$tagger" ] || die "no $(basename "$tagger")"
    cosign verify-blob-attestation $(workflow_policy "$tag") --type "$TAGGER_TYPE" \
      --bundle "$tagger" "$sums" > /dev/null 2>&1 || die "$(basename "$sums") is not in the tagger statement"
    n=$((n + 1))
  done
  payload "$tagger" | jq -e --arg t "$tag" '.predicate.tag == $t' > /dev/null ||
    die "the tagger statement is not for $tag"
  echo "verified $n sha256sums files of $tag and the tagger statement" >&2
  payload "$tagger" | jq -r .predicate.tagger.login
}

# check_images DIR STATEMENT checks that the image digests listed by every
# images.txt in DIR are subjects of the statement in file STATEMENT.
check_images() {
  local missing
  missing=$(cat "$1"/*.images.txt | sed 's/.*@sha256://' | sort -u |
    comm -23 - <(jq -r '.subject[].digest.sha256' "$2" | sort -u))
  [ -z "$missing" ] || die "images not in the tagger statement: $missing"
}

# verify_approval DIR TAG EMAIL checks that the approval in DIR is EMAIL's,
# for TAG, and covers every sums file.
verify_approval() {
  local dir=$1 tag=$2 email=$3 sums bundle="$1/$2.maintainer.sigstore.json"
  [ -f "$bundle" ] || die "no $(basename "$bundle")"
  for sums in "$dir"/*.sha256sums; do
    cosign verify-blob-attestation --type "$APPROVAL_TYPE" --certificate-identity "$email" \
      --certificate-oidc-issuer "$SIGNER_ISSUER" --bundle "$bundle" "$sums" > /dev/null 2>&1 ||
      return 1
  done
  payload "$bundle" | jq -e --arg t "$tag" --arg r "$REPOSITORY" \
    '.predicate.release == $t and .predicate.repository == $r' > /dev/null
}

cmd_check() {
  [ $# = 2 ] || usage
  local dir=$1 tag=$2 tagger list login email
  tagger=$(verify_release "$dir" "$tag")
  list=$(signers)
  while read -r login email; do
    verify_approval "$dir" "$tag" "$email" || continue
    [ "$login" != "$tagger" ] || die "$login both pushed $tag and approved it"
    payload "$dir/$tag.maintainer.sigstore.json" > "$dir/approval.json"
    check_images "$dir" "$dir/approval.json"
    echo "$login $email"
    return
  done <<< "$list"
  die "$(basename "$dir/$tag.maintainer.sigstore.json") is not signed by a release signer"
}

cmd_approve() {
  local yes=
  [ "${1:-}" = -y ] && { yes=1; shift; }
  [ $# = 1 ] || usage
  local tag=$1 me email id name tagger commit prev answer
  me=$(gh api user --jq .login)
  email=$(signers | awk -v l="$me" '$1 == l {print $2}')
  [ -n "$email" ] || die "$me is not in .github/release-signers on $SIGNERS_REF"

  id=$(gh api --paginate "repos/$REPOSITORY/releases" \
    --jq ".[] | select(.draft and .tag_name == \"$tag\") | .id")
  [ -n "$id" ] || die "no draft release of $tag"
  [ "$(wc -w <<< "$id")" = 1 ] || die "several draft releases of $tag: $id"

  dir=$(mktemp -d)
  trap 'rm -rf "$dir"' EXIT
  gh api --paginate "repos/$REPOSITORY/releases/$id/assets" --jq '.[] | "\(.id) \(.name)"' |
    while read -r asset name; do
      case "$name" in
      "$tag.maintainer.sigstore.json") die "the draft already has $name" ;;
      *.sha256sums | *.sha256sums.sigstore.json | *.images.txt | "$tag.tagger.sigstore.json")
        gh api -H 'Accept: application/octet-stream' "repos/$REPOSITORY/releases/assets/$asset" > "$dir/$name" ;;
      esac
    done

  tagger=$(verify_release "$dir" "$tag")
  [ "$tagger" != "$me" ] || die "$me pushed $tag; another release signer must approve it"
  payload "$dir/$tag.tagger.sigstore.json" > "$dir/tagger.json"
  check_images "$dir" "$dir/tagger.json"
  commit=$(jq -r .predicate.commit "$dir/tagger.json")
  [ "$(gh api "repos/$REPOSITORY/commits/refs/tags/$tag" --jq .sha)" = "$commit" ] ||
    die "tag $tag is no longer at $commit"
  prev=$(gh api --paginate "repos/$REPOSITORY/releases" --jq '.[] | select(.draft | not) | .tag_name' |
    { cat; echo "$tag"; } | sort -V | grep -B1 -x -F "$tag" | head -1)

  echo "Release $tag at $commit, pushed by $tagger, $(jq '.subject | length' "$dir/tagger.json") subjects:"
  jq -r '.subject[] | "  \(.name)@sha256:\(.digest.sha256)"' "$dir/tagger.json"
  if [ "$prev" != "$tag" ]; then
    echo "Changes since $prev: https://github.com/$REPOSITORY/compare/$prev...$tag"
    gh api "repos/$REPOSITORY/compare/$prev...$tag" --jq '.commits[] | "  \(.sha[:9]) \(.commit.message | split("\n")[0])"'
  fi
  echo
  echo "Signing puts $email in the public Rekor log. Log in with GitHub and pick $email."
  if [ -z "$yes" ]; then
    read -r -p "Approve and publish $tag? [y/N] " answer
    [ "$answer" = y ] || die "not approved"
  fi

  jq --arg type "$APPROVAL_TYPE" --arg r "$REPOSITORY" --arg t "$tag" --arg c "$commit" \
    '{_type: "https://in-toto.io/Statement/v1", subject: .subject, predicateType: $type,
      predicate: {repository: $r, release: $t, commit: $c}}' "$dir/tagger.json" > "$dir/approval.json"
  name="$tag.maintainer.sigstore.json"
  cosign attest-blob --yes --oidc-disable-ambient-providers --statement "$dir/approval.json" \
    --bundle "$dir/$name"
  verify_approval "$dir" "$tag" "$email" ||
    die "the signature is not by $email with issuer $SIGNER_ISSUER; nothing was uploaded"

  gh api -X POST -H 'Content-Type: application/json' --input "$dir/$name" \
    "https://uploads.github.com/repos/$REPOSITORY/releases/$id/assets?name=$name" --jq '"uploaded \(.name)"'
  gh api -X PATCH "repos/$REPOSITORY/releases/$id" -F draft=false --jq '"published \(.html_url)"'
  gh workflow run release-approval.yml -R "$REPOSITORY" --ref master -f tag="$tag"
  echo "release-approval.yml attaches $name to the images on the registry"
}

case "${1:-}" in
approve) shift; cmd_approve "$@" ;;
check) shift; cmd_check "$@" ;;
*) usage ;;
esac
