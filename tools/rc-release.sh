#!/bin/bash

#
# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#

# Get the current branch and replace slashes with underscores
git_branch=$(git rev-parse --abbrev-ref HEAD | tr / _)

# Get the latest tag from the specified branch
latest_tag=$(git describe --tags --abbrev=0 "$git_branch")

# Check if the input is a valid release branch in the format X.Y (e.g., 1.2)
check_release_branch() {
    if ! echo "${git_branch}" | grep -Eq "^[0-9]+\.[0-9]+(-[a-zA-Z]+)?$"; then
        echo "ERROR: must be on a release branch X.Y"
        exit 1
    fi
}

# Check if the latest tag follows the format X.Y.Z
check_tag() {
    if ! echo "${latest_tag}" | grep -Eq "^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?$"; then
        echo "ERROR: can't find previous release's tag X.Y.Z"
        exit 1
    fi
}

# Function to increment the numeric part of a version
increment_version() {
    local version=$1
    local base=${version%-*}   # Get the base version (e.g., 12.0.4 from 12.0.4-lts)
    local suffix=${version##*-} # Get the suffix (e.g., lts or rc1)

    if [[ $suffix == "$version" ]]; then
        suffix=""  # No suffix
    fi

    if [[ $suffix == "lts" ]]; then
        # If the suffix is lts, increment the base version and add -rc1
        IFS='.' read -r major minor patch <<< "$base"
        patch=$((patch + 1))
        echo "$major.$minor.$patch-rc1"
    elif [[ $suffix == rc* ]]; then
        # If the suffix is rc, increment the rc number
        local rc_number=${suffix#rc}  # Get the number after rc
        rc_number=$((rc_number + 1))
        echo "$base-rc$rc_number"
    else
        # If no suffix or unknown suffix, start with rc1
        echo "$base-rc1"
    fi
}

# Validate the new tag name
validate_tag_name() {
    # Updated regex to match '12.0.5', '12.0.5-lts', '12.0.5-rc1', etc.
    if [[ ! "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z]+[0-9]*)?$ ]]; then
        echo "ERROR: '$1' is not a valid tag name."
        exit 1
    fi
}

# Check if a tag is fetched
if [[ -z $latest_tag ]]; then
    # If no latest tag is found, assume we're starting fresh and create the first rc0 tag
    echo "No tags found in the repository. Starting with version 0.0.0-rc0."
    new_version="0.0.0-rc0"
else
    # Increment the version according to the rules
    check_release_branch
    check_tag
    new_version=$(increment_version "$latest_tag")
fi

validate_tag_name "$new_version"

echo "Creating RC release: '${new_version}'"

# Create a new tag and check if the command succeeds
if ! git tag -a -m "Release ${new_version}" "${new_version}"; then
    echo "Error: Failed to create a new tag."
    exit 1
fi

echo "Tagged new version: $new_version. Please push the tag to the remote repository"

echo "git push origin $git_branch $new_version"
