#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Run bump_dockerfiles.pl in a loop, creating/amending a single
# "Update all package hashes" commit until no more changes are found.
# Also updates pkg/eve/Dockerfile.in with the new eve-alpine hash.
#
# Usage: ./tools/bump-and-commit.sh
#   from the repository root, on a clean working tree, after
#   `make build-tools`
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMMIT_MSG="Update all package hashes"
# CI rejects a commit without a body.
COMMIT_BODY="Update all package hashes after a change to a package that others are built from."
MAX_ITERATIONS=5

# The commits below stage every modified tracked file, so local edits
# would end up in the bump commit.
if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "The working tree has uncommitted changes; commit or stash them first." >&2
    exit 1
fi

# Amend the bump commit when it is the one on top, otherwise create it.
# Never amend anything else: the commit below it is usually the change
# that made the bump necessary.
commit_bump() {
    git add -u
    if [ "$(git log -1 --format=%s)" = "$COMMIT_MSG" ]; then
        git commit --amend --no-edit -s
    else
        git commit -s -m "$COMMIT_MSG" -m "$COMMIT_BODY"
    fi
}

for i in $(seq 1 $MAX_ITERATIONS); do
    echo "=== bump_dockerfiles.pl run $i ==="
    "$SCRIPT_DIR/bump_dockerfiles.pl"

    # Check if anything changed
    if [ -z "$(git diff --name-only)" ]; then
        echo "No changes after run $i, done with Dockerfiles."
        break
    fi

    commit_bump
done

# Update pkg/eve/Dockerfile.in, which bump_dockerfiles.pl doesn't handle.
# alpine-show-tag needs build-tools/bin/linuxkit.
ALPINE_HASH=$(make --no-print-directory -s alpine-show-tag | tail -1 | sed 's/.*://')
if [ -z "$ALPINE_HASH" ]; then
    echo "Could not read the eve-alpine tag; run 'make build-tools' first." >&2
    exit 1
fi
CURRENT=$(sed -n 's/.*eve-alpine:\([a-f0-9][a-f0-9]*\).*/\1/p' pkg/eve/Dockerfile.in | head -1)
if [ -n "$CURRENT" ] && [ "$CURRENT" != "$ALPINE_HASH" ]; then
    echo "=== Updating pkg/eve/Dockerfile.in: $CURRENT -> $ALPINE_HASH ==="
    sed -i.bak "s|eve-alpine:${CURRENT}|eve-alpine:${ALPINE_HASH}|g" pkg/eve/Dockerfile.in
    rm -f pkg/eve/Dockerfile.in.bak
    commit_bump
fi

echo "=== Done ==="
git log --oneline -1
