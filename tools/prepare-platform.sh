#!/bin/sh
#
# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Usage:
#
#      ./prepare-platform.sh <platform_identifier> <build_dir> <output_dir>
#
if [ $# != 3 ]; then
    exit 0
else
    PLATFORM="$1"
    BUILD_DIR="$2"
    OUTPUT_DIR="$3"
fi

get_platform() {
    IDSTR="$1"
    IMX="$(echo "$IDSTR" | grep "^imx.*_.*")"
    if [ -n "$IMX" ]; then
        echo "imx"
    else
        echo "unknown"
    fi
}

copy_a() {
    # shellcheck disable=SC2086,SC2048
    cp -v $* || exit 1
}

PLAT=$(get_platform "$PLATFORM")
case "$PLAT" in
    imx)
        copy_a "${OUTPUT_DIR}"/bsp-imx/NXP-EULA-LICENSE.txt "${OUTPUT_DIR}"/NXP-EULA-LICENSE.txt
        copy_a "${OUTPUT_DIR}"/bsp-imx/NXP-EULA-LICENSE.txt "${BUILD_DIR}"/NXP-EULA-LICENSE.txt
        copy_a "${OUTPUT_DIR}"/bsp-imx/"${PLATFORM}"-flash.bin "${OUTPUT_DIR}"/imx8-flash.bin
        copy_a "${OUTPUT_DIR}"/bsp-imx/"${PLATFORM}"-flash.conf "${OUTPUT_DIR}"/imx8-flash.conf
        copy_a "${OUTPUT_DIR}"/bsp-imx/*.dtb "${OUTPUT_DIR}"/boot
    ;;

    *)
        exit 1
    ;;
esac

