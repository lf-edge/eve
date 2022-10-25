#!/bin/sh
#
# Copyright (c) 2022 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

CONFIGDIR=/config
PERSISTDIR=/persist
DEVICE_CERT_NAME="${CONFIGDIR}/device.cert.pem"
BOOTSTRAP_CONFIG="${CONFIGDIR}/bootstrap-config.pb"
BINDIR=/opt/zededa/bin
TMPDIR="${PERSISTDIR}/tmp"
ZTMPDIR=/run/global
DPCDIR="${ZTMPDIR}/DevicePortConfig"
PATH=$BINDIR:$PATH
TPMINFOTEMPFILE=/var/tmp/tpminfo.txt

# Sleep for a bit until /run/$1.touch exists
wait_for_touch() {
    f=/run/"$1".touch
    waited=0
    while [ ! -f "$f" ] && [ "$waited" -lt 60 ]; do
            echo "$(date -Ins -u) waiting for $f"
            sleep 3
            waited=$((waited + 3))
    done
    if [ ! -f "$f" ]; then
        echo "$(date -Ins -u) gave up waiting for $f"
    else
        echo "$(date -Ins -u) waited $waited for $f"
    fi
}

# Look for a USB stick with a usb.json file
# XXX note that gpt on the USB stick needs to be labeled with DevicePortConfig
# If there is a dump directory on the stick we put log and debug info
# in there.
# If there is an identity directory on the stick we put identifying
# information in a subdir there.
access_usb() {
    # echo "$(date -Ins -u) XXX Looking for USB stick with DevicePortConfig"
    SPECIAL=$(lsblk -l -o name,label,partlabel | awk '/DevicePortConfig|QEMU VVFAT/ {print "/dev/"$1;}')
    if [ -n "$SPECIAL" ] && [ -b "$SPECIAL" ]; then
        echo "$(date -Ins -u) Found USB with DevicePortConfig: $SPECIAL"
        mount -t vfat "$SPECIAL" /mnt
        ret_code=$?
        if [ "$ret_code" != 0 ]; then
            echo "$(date -Ins -u) mount $SPECIAL failed: $ret_code"
            return
        fi
        # Apply legacy usb.json only if bootstrap-config.pb is not present.
        if [ ! -f "$BOOTSTRAP_CONFIG" ]; then
            # shellcheck disable=SC2066
            for fd in "usb.json:$DPCDIR" ; do
                file=/mnt/$(echo "$fd" | cut -f1 -d:)
                dst=$(echo "$fd" | cut -f2 -d:)
                if [ -f "$file" ]; then
                    echo "$(date -Ins -u) Found $file on $SPECIAL"
                    echo "$(date -Ins -u) Copying from $file to $dst"
                    cp -p "$file" "$dst"
                else
                    echo "$(date -Ins -u) $file not found on $SPECIAL"
                fi
            done
        fi
        if [ -d /mnt/identity ] && [ -f "$DEVICE_CERT_NAME" ]; then
            echo "$(date -Ins -u) Saving identity to USB stick"
            IDENTITYHASH=$(cat $CONFIGDIR/soft_serial)
            IDENTITYDIR="/mnt/identity/$IDENTITYHASH"
            [ -d "$IDENTITYDIR" ] || mkdir -p "$IDENTITYDIR"
            cp -p "$DEVICE_CERT_NAME" "$IDENTITYDIR"
            [ ! -f $CONFIGDIR/onboard.cert.pem ] || cp -p $CONFIGDIR/onboard.cert.pem "$IDENTITYDIR"
            [ ! -f $PERSISTDIR/status/uuid ] || cp -p $PERSISTDIR/status/uuid "$IDENTITYDIR"
            cp -p $CONFIGDIR/root-certificate.pem "$IDENTITYDIR"
            [ ! -f $CONFIGDIR/v2tlsbaseroot-certificates.pem ] || cp -p $CONFIGDIR/v2tlsbaseroot-certificates.pem "$IDENTITYDIR"
            [ ! -f $CONFIGDIR/soft_serial ] || cp -p $CONFIGDIR/soft_serial "$IDENTITYDIR"
            $BINDIR/hardwaremodel -c -o "$IDENTITYDIR/hardwaremodel.dmi"
            sync
        fi
        if [ -d /mnt/dump ]; then
            echo "$(date -Ins -u) Dumping diagnostics to USB stick"
            # Check if it fits without clobbering an existing tar file
            if ! $BINDIR/tpmmgr saveTpmInfo $TPMINFOTEMPFILE; then
                echo "$(date -Ins -u) saveTpmInfo failed" > $TPMINFOTEMPFILE
            fi
            if tar cf /mnt/dump/diag1.tar /persist/status/ /var/run/ /persist/log "/persist/newlog" $TPMINFOTEMPFILE; then
                mv /mnt/dump/diag1.tar /mnt/dump/diag.tar
            else
                rm -f /mnt/dump/diag1.tar
            fi
            sync
        fi
        umount -f /mnt
        blockdev --flushbufs "$SPECIAL"
    fi
}
