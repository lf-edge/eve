#!/bin/bash

# Copyright (c) 2023 Linux Foundation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

if [ $# -ne 1 ]; then
    echo "usage: $0 <path-to-package>" >&2
    exit 1
fi

path="$1"

if [ -z "$path" ]; then
    echo "error: path is empty" >&2
    exit 1
fi

if [ ! -d "$path" ]; then
    echo "error: $path is not a directory" >&2
    exit 1
fi

if [ ! -f "$path/go.mod" ]; then
    echo "error: $path/go.mod does not exist" >&2
    exit 1
fi

cd "$path" || exit 1

# first get the most recent tag
# then get the most recent commit on a tag
tag="v0.0.0"
currentCommit=$(git rev-parse --short=12 HEAD 2>&1)
if [ -z "$currentCommit" ]; then
    echo "error: no current commit found" >&2
    exit 1
fi

latestTag=$(git describe --match "v*[0-9].*[0-9].*[0-9]*" --abbrev=0 --tags "$(git rev-list --tags --max-count=1)" 2>/dev/null)

date=$(TZ=UTC git log -1 --date=format-local:'%Y%m%d%H%M%S' --format=%ad "$currentCommit")
if [ -n "$latestTag" ]; then
    tag=$latestTag
    taggedCommit=$(git rev-parse --short=12 "$tag" 2>&1)
    if [ -z "$taggedCommit" ]; then
        echo "error: no commit found for tag $tag" >&2
        exit 1
    fi
    # if the most recent tagged commit *is* our commit, then just return the semver and done
    if [ "$taggedCommit" = "$currentCommit" ]; then
        echo "$tag"
        exit 0
    fi
    # the format requires a "0." prefix to the date when there is a non-semver tag
    date="0.$date"
fi

echo "${tag}-${date}-${currentCommit}"