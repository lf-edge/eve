#!/bin/sh

# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Mount necessary filesystems
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev

# debug enabled? Could be via `debug` or `eve_install_debug=<something>` parameter in cmdline
# shellcheck disable=SC2002
debug_param=$(tr ' ' '\n' < /proc/cmdline | grep -E '^debug$|^eve_install_debug(=|$)' | head -n 1)
if [ -n "$debug_param" ]; then
    set -x
fi


# Search for the root= cmdline property
# shellcheck disable=SC2002
root_param=$(cat /proc/cmdline | tr ' ' '\n' | grep '^root=' | head -n 1)
# remove the leading "root="  to get the actual value
root_value=${root_param#root=}

# Search for the rootimg= cmdline property
# shellcheck disable=SC2002
rootimg_param=$(cat /proc/cmdline | tr ' ' '\n' | grep '^rootimg=' | head -n 1)
# remove the leading "root="  to get the actual value
root_img=${rootimg_param#rootimg=}

# Search for the rootaddmount= cmdline property
# shellcheck disable=SC2002
rootaddmount_param=$(cat /proc/cmdline | tr ' ' '\n' | grep '^rootaddmount=')

# staging area for bind mount sources that live in the initramfs, see add_mounts
stagedir=/addmounts

# add_mounts <source prefix> <target root>
# bind-mounts every rootaddmount=<source>:<target> pair, resolving the source
# under the given prefix (empty for the initramfs itself) and the target inside
# the filesystem we are about to switch into
add_mounts() {
    src_prefix="$1"
    target_root="$2"
    for mountpair in $rootaddmount_param; do
        # remove the leading "rootaddmount=" to get the actual value
        mount=${mountpair#rootaddmount=}
        if [ -z "$mount" ]; then
            continue
        fi
        mount_source=$(echo "$mount" | cut -d':' -f1)
        mount_target=$(echo "$mount" | cut -d':' -f2)
        # make sure the mount target exists, after stripping leading slashes
        mount_target="${mount_target#/}"
        targetpath="$target_root/$mount_target"
        mount_source="${mount_source#/}"
        sourcepath="$src_prefix/$mount_source"
        if [ ! -e "$sourcepath" ]; then
            echo "Source path $mount_source does not exist, skipping mount"
            continue
        fi
        if [ -z "$src_prefix" ]; then
            # switch_root unlinks the whole initramfs. The bind mount itself
            # survives that, but its source dentry is then deleted, and the
            # kernel refuses a deleted dentry as the source of a further bind
            # mount - which is exactly what the onboot containers do with these
            # files. Move the source onto a tmpfs, which switch_root skips, so
            # that it stays linked.
            if [ ! -d "$stagedir" ]; then
                mkdir -p "$stagedir"
                mount -t tmpfs tmpfs "$stagedir"
            fi
            staged="$stagedir/$mount_source"
            mkdir -p "$(dirname "$staged")"
            mv "$sourcepath" "$staged"
            sourcepath="$staged"
        fi
        mount --bind "${sourcepath}" "${targetpath}"
    done
}

# Check if root_value is set
if [ -z "$root_value" ]; then
    echo "Error: No root= parameter found in /proc/cmdline"
    exec sh
fi

echo "searching for root filesystem with value: $root_value"

rootdev=""

# a root= naming a file needs no device lookup at all: netboot hands us the
# root image inside the initramfs
if [ -f "$root_value" ]; then
    rootdev="$root_value"
    cnt=0
else
    # Some emulated CD/DVD-ROM devices might take some time to appear in the
    # system, set a maximum number of retries (one per second) until give up
    cnt=10
fi
while [ "$cnt" -gt 0 ]; do
    # Determine if the root_value is a LABEL, UUID, or direct device path
    while read -r line; do
        case "$root_value" in
            LABEL=*)
                label=${root_value#LABEL=}
                if echo "$line" | grep -q "LABEL=\"$label\""; then
                    rootdev=$(echo "$line" | cut -d: -f1)
                    break
                fi
                ;;
            UUID=*)
                uuid=${root_value#UUID=}
                if echo "$line" | grep -q "UUID=\"$uuid\""; then
                    rootdev=$(echo "$line" | cut -d: -f1)
                    break
                fi
                ;;
            PARTUUID=*)
                partuuid=${root_value#PARTUUID=}
                if echo "$line" | grep -q "PARTUUID=\"$partuuid\""; then
                    rootdev=$(echo "$line" | cut -d: -f1)
                    break
                fi
                ;;
            *)
                rootdev="$root_value"
                ;;
        esac
    done <<EOF
$(blkid)
EOF

    if [ -n "$rootdev" ]; then
        break
    else
        echo "Waiting for root device... "
        sleep 1
        cnt=$((cnt - 1))
    fi
done

# If root filesystem is found, mount it
if [ -n "$rootdev" ]; then
    echo "found root filesystem: $rootdev, switching"
    mount "$rootdev" /newroot
    # Now, check for the installer rootfs squashfs image
    if [ -n "$root_img" ]; then
        rootfsimg=/newroot/"$root_img"
        if [ -e "$rootfsimg" ]; then
            # Mount the image and call switch_root
            mkdir -p /installer_root
            mount "$rootfsimg" /installer_root
            add_mounts /newroot /installer_root
            exec switch_root /installer_root /sbin/init
        else
            echo "$root_img image not found!"
            exec sh
        fi
    else
        # No image provided, the root filesystem is what we switch into, so any
        # additional mounts have to come from the initramfs
        add_mounts "" /newroot
        exec switch_root /newroot /sbin/init
    fi
else
    echo "Root filesystem not found!"
    exec sh
fi
