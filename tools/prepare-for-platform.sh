#!/bin/sh
# Usage:
#
#      ./prepare-for-platform.sh <build dir> <platform>
#


BUILD_DIR="$(cd "$1" && pwd)"
INSTALLER_DIR="$BUILD_DIR"/installer
PLATFORM="$2"

case "$PLATFORM" in
imx8m*) #shellcheck disable=SC2039
    cp "$INSTALLER_DIR"/bsp-imx/NXP-EULA-LICENSE.txt "$INSTALLER_DIR"/NXP-EULA-LICENSE.txt
    cp "$INSTALLER_DIR"/bsp-imx/NXP-EULA-LICENSE.txt "$BUILD_DIR"/NXP-EULA-LICENSE.txt
    cp "$INSTALLER_DIR"/bsp-imx/"$PLATFORM"-flash.bin "$INSTALLER_DIR"/flash.bin
    cp "$INSTALLER_DIR"/bsp-imx/"$PLATFORM"-flash.conf "$INSTALLER_DIR"/flash.conf
    cp "$INSTALLER_DIR"/bsp-imx/*.dtb "$INSTALLER_DIR"/boot
    ;;
opi3_lts) #shellcheck disable=SC2039
    cp "$INSTALLER_DIR"/bsp-sunxi/"$PLATFORM"-flash.bin "$INSTALLER_DIR"/flash.bin
    cp "$INSTALLER_DIR"/bsp-sunxi/"$PLATFORM"-flash.conf "$INSTALLER_DIR"/flash.conf
    ;;
*) #shellcheck disable=SC2039,SC2104
    ;;
esac
