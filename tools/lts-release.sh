#!/bin/bash

#
# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#

# Get the current branch
git_branch=$(git rev-parse --abbrev-ref HEAD | tr / _)

# Get the latest tag from the specified branch
latest_tag=$(git describe --tags --abbrev=0 "$git_branch")

echo "Latest tag: $latest_tag"

# Check if the input is a valid release branch in the format X.Y (e.g., 1.2)
check_release_branch() {
    if ! echo "${git_branch}" | grep -Eq "^[0-9]+\.[0-9]+(-[a-zA-Z]+)?$"; then
        echo "ERROR: must be on a release branch X.Y"
        exit 1
    fi
}

# Validate if the latest tag is a valid release tag (e.g., X.Y.Z or X.Y.Z-<suffix>)
check_tag() {
    if ! echo "${latest_tag}" | grep -Eq "^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?$"; then
        echo "ERROR: can't find previous release's tag X.Y.Z"
        exit 1
    fi
}

# Function to check if the latest tag is an RC tag
is_rc_tag() {
    if echo "${latest_tag}" | grep -Eq "^[0-9]+\.[0-9]+\.[0-9]+-rc[0-9]+$"; then
        return 0
    else
        return 1
    fi
}

# Function to increment the patch version
increment_patch_version() {
    local version=$1
    local major minor patch
    IFS='.' read -r major minor patch <<< "$version"
    patch=$((patch + 1))
    echo "$major.$minor.$patch"
}

# Perform release branch validation
check_release_branch

# Perform tag validation
check_tag

# If the latest tag is an RC tag
if is_rc_tag; then
    # Extract the base version (remove the -rc suffix)
    base_version="${latest_tag%-rc*}"
    new_tag="${base_version}-lts"
    echo "Creating LTS tag: $new_tag from the commit of $latest_tag"
    # Create the LTS tag from the commit of the RC release
    if git tag -a "$new_tag" "$latest_tag" -m "Release $new_tag"; then
        echo "Tagged new version: $new_tag"
        echo "Now, push the tag to the remote repository using:"
        echo "git push origin $git_branch $new_tag"
    else
        echo "Error: Failed to create the new LTS tag."
        exit 1
    fi
else
    # If the latest tag is not an RC tag
    echo "Latest tag is not an RC tag. Incrementing the patch version."
    # Increment the patch version
    new_version=$(increment_patch_version "$latest_tag")
    new_tag="${new_version}-lts"
    echo "Creating LTS tag: $new_tag from the latest non-RC tag"
    # Create the LTS tag from the latest non-RC release
    if git tag -a "$new_tag" -m "Release $new_tag"; then
        echo "Tagged new version: $new_tag"
        echo "Now, push the tag to the remote repository using:"
        echo "git push origin $git_branch $new_tag"
    else
        echo "Error: Failed to create the new LTS tag."
        exit 1
    fi
fi
