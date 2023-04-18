#!/bin/sh
#
# Copyright (c) 2021 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
KBUILD_BUILD_HOST="eve"
for k in "pkg/kernel" "pkg/new-kernel"; do
    KBUILD_BUILD_USER="eve"
    KBUILD_BUILD_HOST="eve"
    KCONFIG_NOTIMESTAMP="true"
    if [ $(git diff --quiet HEAD -- :"$k") ] || [ $(git ls-files --other --directory --exclude-standard :"$k" | grep .) ]; then
        KBUILD_BUILD_TIMESTAMP=$(LC_ALL=C date)
        SOURCE_DATE_EPOCH=$(date +%s)
        KBUILD_BUILD_USER=$(whoami | sed 's/\\/\\\\/')
        KBUILD_BUILD_HOST=$(uname -n)
        KCONFIG_NOTIMESTAMP="false"
    else
        SOURCE_DATE_EPOCH=$(git log -1 --format=%ct "$k")
        # make sure we get a date in correct format, otherwise initramfs cpio mtime will be variable
        KBUILD_BUILD_TIMESTAMP=$(git log -1 --format=%cd "$k" | cut -f1 -d"+")
    fi
    cp "$k/build.yml.in" "$k/build.yml"
    sed -i "/KBUILD_BUILD_TIMESTAMP/c\  - KBUILD_BUILD_TIMESTAMP=$KBUILD_BUILD_TIMESTAMP" "$k/build.yml"
    sed -i "/KBUILD_BUILD_USER/c\  - KBUILD_BUILD_USER=$KBUILD_BUILD_USER" "$k/build.yml"
    sed -i "/KBUILD_BUILD_HOST/c\  - KBUILD_BUILD_HOST=$KBUILD_BUILD_HOST" "$k/build.yml"
    sed -i "/KCONFIG_NOTIMESTAMP/c\  - KCONFIG_NOTIMESTAMP=$KCONFIG_NOTIMESTAMP" "$k/build.yml"
    sed -i "/SOURCE_DATE_EPOCH/c\  - SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" "$k/build.yml"
done
