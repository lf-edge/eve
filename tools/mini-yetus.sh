#!/bin/sh
# Copyright (c) 2017-2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Do you hate yetus like everyone else? well I can't do anything about that but
# using this you can at least hate `make yetus` a little less. This script will
# run yetus on the changes in your current branch compared to master (excluding
# vendor changes) and output the results, much faster than running it on the
# entire codebase with `make yetus`.

FULL=false

usage() {
    echo "Usage: $0 [-s src_branch] [-d dst_branch] [-f]"
    echo "  -s src_branch   Name of the branch to compare with,
                            defaults to the main/master branch"
    echo "  -d dst_branch   Name of the branch to compare against,
                            defaults to the current branch"
    echo "  -f              Show full results"
    exit 1
}

while getopts ":s:d:f" opt; do
    case ${opt} in
        s )
            SRC_BRANCH=$OPTARG
            ;;
        d )
            DST_BRANCH=$OPTARG
            ;;
        f )
            FULL=true
            ;;
        \? )
            usage
            ;;
        : )
            echo "Invalid option: -$OPTARG requires an argument."
            usage
            ;;
    esac
done

shift $((OPTIND -1))

echo "[+] Running mini-yetus"

# check if we are in the root of the repository
if [ ! -d .git ]; then
    echo "[!] Error: This script must be run from the root of the EVE repository."
    exit 1
fi

if [ -z "$SRC_BRANCH" ]; then
    # No branch specified, use the main branch
    SRC_BRANCH="master"
    echo "[+] No source branch specified. Using the main branch: $SRC_BRANCH"
else
    if ! git rev-parse --verify "$SRC_BRANCH" >/dev/null 2>&1; then
        echo "[!] Error: Branch '$SRC_BRANCH' does not exist."
        exit 1
    fi
fi

if [ -z "$DST_BRANCH" ]; then
    # No branch specified, use the current branch
    DST_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
    if [ -z "$DST_BRANCH" ]; then
        echo "[!] Error: Could not determine the current branch."
        exit 1
    fi
    echo "[+] No destination branch specified. Using the current branch: $DST_BRANCH"
fi

if ! git rev-parse --verify "$DST_BRANCH" >/dev/null 2>&1; then
    echo "[!] Error: Branch '$DST_BRANCH' does not exist."
    exit 1
fi

MISSING_FILE_REPORTED=false
SRC_DIR=$(mktemp -d)
git diff --name-only "$SRC_BRANCH".."$DST_BRANCH" | grep -v '/vendor/' | while IFS= read -r file; do
    if [ -e "$file" ]; then
        cp --parents -r "$PWD/$file" "$SRC_DIR/" || { echo "Failed to copy $file"; exit 1; }
    else
        if [ "$MISSING_FILE_REPORTED" = false ]; then
            echo "[*] Some files are missing from current branch, if you are comparing against main/master, a rebase might be needed."
            MISSING_FILE_REPORTED=true
        fi
        echo "[!] File does not exist: $PWD/$file"
    fi
done

# copy all the dot files from root to the SRC_DIR, this includes all
# the yetus configuration files.
find . -maxdepth 1 -type f -name '.*' -exec cp --parents {} "$SRC_DIR/" \;

cd "$SRC_DIR" && \
    git init >/dev/null 2>&1 && \
    git add . >/dev/null 2>&1 && \
    git config user.email "you@example.com" >/dev/null 2>&1 && \
    git config user.name "Your Name" >/dev/null 2>&1 && \
    git commit -m "Changes in the PR" >/dev/null 2>&1

echo "[+] Running yetus on the changes..."
docker run --rm -v "$SRC_DIR":/src:delegated,z ghcr.io/apache/yetus:0.15.0 \
    --basedir=/src \
    --test-parallel=true \
    --dirty-workspace \
    --empty-patch \
    --plugins=all \
    --patch-dir=/src/yetus-output > /dev/null 2>&1

if [ "$FULL" = true ]; then
    echo "[+] Full results:"
    if [ "$(uname)" = "Darwin" ]; then
        if ! command -v gsed >/dev/null 2>&1; then
            echo "[*] GNU sed not found. Install it to have the best experience."
            cat "$SRC_DIR/yetus-output/results-full.txt"
        else
            gsed -e '/^\./!s|^|/|' "$SRC_DIR/yetus-output/results-full.txt"
        fi
    else
        # add the missing / back to make the output clickable in
        # IDEs and most terminals.
        sed -e '/^\./!s|^|/|' "$SRC_DIR/yetus-output/results-full.txt"
    fi
fi

echo "[+] Results stored in $SRC_DIR/yetus-output"
