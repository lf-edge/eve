#!/bin/sh
#
# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Usage:
#
#      ./prepare-verification.sh <pkg/verification_dir> <installer_dir> <verification_dir>
#
if [ $# != 3 ]; then
    exit 0
else
    PKGVERIFICATION_DIR="$1"
    INSTALLER_DIR="$2"
    VERIFICATION_DIR="$3"
fi

cp -r "${PKGVERIFICATION_DIR}/verification/*" "${INSTALLER_DIR}/"
cp -r "${INSTALLER_DIR}/*" "${VERIFICATION_DIR}/"
