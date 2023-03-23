#!/bin/sh

#
# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
#
# When module signing is enabled, the kernel builder will generate a temporary key
# to sing the kernel modules, this key is then discarded at the end of
# build process but the public part of the key is stored in the kernel key ring
# This results in having different kernels and modules hash each time kernel is
# built from the source.
# To make diff rootfs created from separate builds easier, this script will
# remove the public key form the kernel binary and strips the modules of the
# signature and then performs a diff on the given rootfs archives.
#
# before running the script, create necessary directories :
#mkdir /tmp/{rootfs-one,rfs-one-up,rfs-one-work,rfs-one-merged}
#mkdir /tmp/{rootfs-two,rfs-two-up,rfs-two-work,rfs-two-merged}
#
# mount the ro rootfs and a rw overlay on top of it:
#mount -o loop rootfs-one.img /tmp/rootfs-one
#mount -o loop rootfs-two.img /tmp/rootfs-two
#mount -t overlay overlay -o lowerdir=/tmp/rootfs-one,upperdir=/tmp/rfs-one-up,workdir=/tmp/rfs-one-work /tmp/rfs-one-merged
#mount -t overlay overlay -o lowerdir=/tmp/rootfs-two,upperdir=/tmp/rfs-two-up,workdir=/tmp/rfs-two-work /tmp/rfs-two-merged
#
# run the script:
#rootfs-diff.sh /tmp/rfs-one-merged/ /tmp/rfs-two-merged/
#
# then clean up :
#umount /tmp/rfs-one-merged
#umount /tmp/rfs-two-merged
#umount /tmp/rootfs-one
#umount /tmp/rootfs-two
#rm -rf /tmp/{rootfs-one,rfs-one-up,rfs-one-work,rfs-one-merged}
#rm -rf /tmp/{rootfs-two,rfs-two-up,rfs-two-work,rfs-two-merged}

if [ $# -lt 2 ] ; then
    echo 'kdiff.sh [path-to-rootfs-one] [path-to-rootfs-two]'
    exit 1
fi

STRIP=${STRIP:-strip}
for i in 1 2
do
    if [ $i -eq 1 ]; then ROOTFS=$1; else  ROOTFS=$2; fi
    MODULES="$(find "$ROOTFS"/lib/modules/ -mindepth 1 -maxdepth 1)"
    KERNEL="$ROOTFS/boot/kernel"
    X509="$MODULES/signing_key.x509"
    GZK=0
    # aarch64 kernel
    if (file "$KERNEL" | grep -q gzip ) ; then
        cp "$KERNEL" /tmp/kernel.$i.gz || exit 1
        gunzip /tmp/kernel.$i.gz || exit 1
        KERNEL="/tmp/kernel.$i"
        GZK=1
    fi

    IN_SIZE=$(stat -c %s "$X509")
    IN=$(hexdump -ve '1/1 "%.2x"' "$X509")
    OUT=$(head -c "$IN_SIZE" < /dev/zero | hexdump -ve '1/1 "%.2x"')
    echo "[$i] Removing the signing key from kernel..."
    hexdump -ve '1/1 "%.2X"' "$KERNEL" | sed "s/$IN/$OUT/I" | xxd -r -p > "$ROOTFS/boot/kernel"
    echo "[$i] Removing the signature form kernel modules..."
    # shellcheck disable=SC2046
    $STRIP --strip-debug $(find "$MODULES" -name \*.ko)

    if [ $GZK -eq 1 ]; then rm "$KERNEL";fi
    # removing singing pub key that differs between builds
    rm "$X509"
    # removing files that differ because of timestamps
    rm "$ROOTFS/etc/eve-release"
    rm "$ROOTFS/etc/linuxkit-eve-config.yml"
done

echo "[*] Diffing the two rootfs..."
diff -qr "$1" "$2" 2>/dev/null
