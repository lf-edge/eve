#!/bin/bash
#
# Copyright (c) 2021 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
# This script is used to create a manifest file for alpine,go and kernel packages.
# Collect EVE's kernel sources from the upstream.
# Example usage
#  generate-sources-manifests.sh <collected_sources_path>


SOURCES_PATH=$1
MANIFESTS_FILE="$SOURCES_PATH/collected_sources_manifest.csv"
rm -f "$SOURCES_PATH/collected_sources_manifest.csv"
## alpine packages
alpine_manifests() {
cd "$SOURCES_PATH/alpine" || exit
for file in ./*
do
        commit=$(echo "$file" | rev | cut -d "." -f1 | rev)
        name_version=$(echo "$file" | rev | cut -d "." -f2- | rev )
        echo "alpine,$name_version,$commit,alpine/$file" >> "$MANIFESTS_FILE"
done
}

## go packages

go_manifests() {
cd "$SOURCES_PATH/go" || exit
for file in ./*
do
        name=$(echo "${file%.*}" | cut -d "@" -f1)
        version_info=$(echo "${file%.*}" | cut -d "@" -f2-)
        version=$(echo "${version_info}" | cut -d "-" -f1-2)
        commit=$(echo "${version_info}" | cut -d "-" -f3)
        if [[ "$commit" == "$version" ]]
        then
                commit=""
        fi
        echo "go,$name,$version,$commit,go/$file" >> "$MANIFESTS_FILE"
done
}

## kernel packages

kernel_manifests() {
cd "$SOURCES_PATH/kernel" || exit
for file in ./*
do      echo "$file"
        name=$(echo "${file%.*}" | cut -d "@" -f1)
        version=$(echo "${version_info}" | rev | cut -d "_" -f1-2 | rev)
        commit=""
        echo "kernel,$name,$version,$commit,kernel/$file" >> "$MANIFESTS_FILE"
done
}

alpine_manifests
go_manifests
kernel_manifests
