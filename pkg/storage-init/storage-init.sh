#!/bin/sh
#
# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

zfs_set_parameter() {
    parameter="$1"
    value="$2"

    echo "${value}" > /sys/module/zfs/parameters/"${parameter}"
}

zfs_set_arc_limits() {
    # NOOP if persist is not ZFS
    if ! read -r persist_fs < /run/eve.persist_type; then
       echo "Can not determine persist filesystem type"
       return 1
    fi

    if [ "${persist_fs}" != "zfs" ]; then
       return 0
    fi

    # Constants
    zfs_arc_min="$(( 256*1024*1024 ))"

    # can't go below 384 MiB
    zfs_arc_max_minimum="$(( 384*1024*1024 ))"

    if ! pool_size_bytes="$(chroot /hostfs zpool list -p -H -o size persist)"; then
       echo "Failed to get pool size"
       return 1
    fi

    metadata_estimate=$(( pool_size_bytes*3/100/10 ))
    zfs_arc_max=$(( zfs_arc_min + metadata_estimate ))

    # zpool storage can grow to tens of TiB depending on the customer requirements.
    # Hence resize the zfs_arc_max = min ( 256 MiB + 0.003 * poolSize ,  20% of System RAM)

    system_memory_KiB="$(grep MemTotal /proc/meminfo | awk '{print $2}')"
    zfs_system_memory_bytes=$(( system_memory_KiB*1024/5 ))

    if [ ${zfs_arc_max} -gt ${zfs_system_memory_bytes} ]; then
        zfs_arc_max="${zfs_system_memory_bytes}"
    fi

    if [ ${zfs_arc_max} -lt ${zfs_arc_max_minimum} ]; then
        zfs_arc_max="${zfs_arc_max_minimum}"
    fi

    zfs_dirty_data_max="$(( zfs_arc_max / 2 ))"

    zfs_set_parameter zfs_arc_min "${zfs_arc_min}"
    zfs_set_parameter zfs_arc_max "${zfs_arc_max}"
    zfs_set_parameter zfs_dirty_data_max "${zfs_dirty_data_max}"
}

# set sequential mdev handler to avoid add-remove-add mis-order of zvols
set_sequential_mdev() {
  echo >/dev/mdev.seq
}

zfs_adjust_features() {
  # we had a bug with mismatch of libzfs and zfs module versions
  # let's set draid feature enabled as we started with zfs 2.1.x which supports this feature
  # with disabled we will see errors from zpool status
  chroot /hostfs zpool set feature@draid=enabled persist
}

PERSISTDIR=/persist
CONFIGDIR=/config
CONFIGDIR_PERSIST=/tmp/config_ro
SMART_DETAILS_FILE=$PERSISTDIR/SMART_details.json
SMART_DETAILS_PREVIOUS_FILE=$PERSISTDIR/SMART_details_previous.json
IS_IN_KDUMP_KERNEL=$(! test -f /proc/vmcore; echo $?)

# the following is here just for compatibility reasons and it should go away soon
ln -s "$CONFIGDIR" "/var/$CONFIGDIR"
ln -s "$PERSISTDIR" "/var/$PERSISTDIR"

if CONFIG=$(findfs PARTLABEL=CONFIG) && [ -n "$CONFIG" ]; then
    if ! fsck.vfat -y "$CONFIG"; then
        echo "$(date -Ins -u) fsck.vfat $CONFIG failed"
    fi
    # we have found a config device, now copy its content to RAM
    mkdir -p $CONFIGDIR_PERSIST
    if ! mount -t vfat -o ro,iocharset=iso8859-1 "$CONFIG" $CONFIGDIR_PERSIST; then
        echo "$(date -Ins -u) mount $CONFIG failed"
    fi

    mount -t tmpfs -o rw,nosuid,nodev,noexec,relatime,size=256k,mode=755 tmpfs $CONFIGDIR
    echo "$(date -Ins -u) Create a copy of CONFIG partition in RAM"
    cp -r $CONFIGDIR_PERSIST/* $CONFIGDIR
    umount "$CONFIG"
    mount -o remount,ro $CONFIGDIR
else
    echo "$(date -Ins -u) No separate $CONFIGDIR partition"
fi

INIT_FS=0
P3_FS_TYPE_DEFAULT=ext4
# check if we have zfs-kvm or zfs-xen or zfs-acrn in eve version
# if so use zfs as default
if grep -E 'zfs-(kvm|xen|acrn)' /hostfs/etc/eve-release; then
   P3_FS_TYPE_DEFAULT=zfs
fi
# check if we have eve_install_zfs_with_raid_level in kernel command line
# if so use zfs as default
if grep -q 'eve_install_zfs_with_raid_level' /proc/cmdline; then
   P3_FS_TYPE_DEFAULT=zfs
fi

# First lets see if we're running with the disk that hasn't been properly
# initialized. This could happen when we run in a virtualized cloud
# environment where the initial disk image gets resized to its proper
# size when EVE is started (it can also happen when you're preparing a
# live image for something like HiKey and put it directly on the flash
# card bypassing using EVE's installer).
#
# The criteria we're using to determine if the disk hasn't been fully
# initialized is when it is missing both P3 (/persist) and IMGB partition
# entries. If that's the case we're willing to (potentially destructively)
# manipulate partition table. The logic here is simple: if we're missing
# both IMGB and P3 the following code is probably the *least* risky thing
# we can do.
P3=$(findfs PARTLABEL=P3)
IMGA=$(findfs PARTLABEL=IMGA)
IMGB=$(findfs PARTLABEL=IMGB)
if [ -n "$IMGA" ] && [ -z "$P3" ] && [ -z "$IMGB" ]; then
   DEV=$(echo /sys/block/*/"${IMGA#/dev/}")
   DEV="/dev/$(echo "$DEV" | cut -f4 -d/)"

   # if sgdisk complains we need to repair the GPT
   if sgdisk -v "$DEV" | grep -q 'Identified.*problems'; then
       # save a copy of the MBR + first partition entry
       # the logic here is that whatever booted us was good
       # enough to get us here, so we'd rather sgdisk disn't
       # mess up a good thing for us
       dd if="$DEV" of=/tmp/mbr.bin bs=1 count=$((446 + 16)) conv=noerror,sync,notrunc

       sgdisk -h1 -e "$DEV"

       # move 1st MBR entry to 2nd place
       dd if="$DEV" of="$DEV" bs=1 skip=446 seek=$(( 446 + 16)) count=16 conv=noerror,sync,notrunc
       # restore 1st MBR entry + first partition entry
       dd if=/tmp/mbr.bin of="$DEV" bs=1 conv=noerror,sync,notrunc
   fi

   # now that GPT itself is fixed, lets add IMGB & P3 partitions
   IMGA_ID=$(sgdisk -p "$DEV" | grep "IMGA$" | awk '{print $1;}')
   IMGB_ID=$((IMGA_ID + 1))
   P3_ID=$((IMGA_ID + 7))

   IMGA_SIZE=$(sgdisk -i "$IMGA_ID" "$DEV" | awk '/^Partition size:/ { print $3; }')
   IMGA_GUID=$(sgdisk -i "$IMGA_ID" "$DEV" | awk '/^Partition GUID code:/ { print $4; }')
   IMGA_UNIQ_GUID=$(sgdisk -i "$IMGA_ID" "$DEV" | awk '/^Partition unique GUID:/ { print $4; }')

   SEC_START=$(sgdisk -f "$DEV")
   SEC_END=$((SEC_START + IMGA_SIZE))

   sgdisk --new "$IMGB_ID:$SEC_START:$SEC_END" --typecode="$IMGB_ID:$IMGA_GUID" --change-name="$IMGB_ID:IMGB" "$DEV"
   sgdisk --largest-new="$P3_ID" --typecode="$P3_ID:5f24425a-2dfa-11e8-a270-7b663faccc2c" --change-name="$P3_ID:P3" "$DEV"
   # Assume we want the fixed partition UUIDs if IMGA has the fixed one.
   # UUIDs from make-raw.
   IMGA_UUID=ad6871ee-31f9-4cf3-9e09-6f7a25c30052
   IMGB_UUID=ad6871ee-31f9-4cf3-9e09-6f7a25c30053
   PERSIST_UUID=ad6871ee-31f9-4cf3-9e09-6f7a25c30059

   # Need case-insensitive comparison; sh can't do that.
   res=$(awk -vs1="$IMGA_UNIQ_GUID" -vs2="$IMGA_UUID" 'BEGIN {
     if ( tolower(s1) == tolower(s2) ){
         print "match"
     }
   }')

   if [ "$res" = "match" ]; then
       sgdisk --partition-guid="$IMGB_ID:$IMGB_UUID" "$DEV"
       sgdisk --partition-guid="$P3_ID:$PERSIST_UUID" "$DEV"
   fi

   # force kernel to re-scan partition table
   partprobe "$DEV"
   partx -a --nr "$IMGB_ID:$P3_ID" "$DEV"

   # attempt to zero the first and last 5Mb of the P3 (to get rid of any residual prior data)
   if P3=$(findfs PARTLABEL=P3) && [ -n "$P3" ]; then
      dd if=/dev/zero of="$P3" bs=512 count=10240 2>/dev/null
      dd if=/dev/zero of="$P3" bs=512 seek=$(( $(blockdev --getsz "$P3") - 10240 )) count=10240 2>/dev/null
   fi
fi

# We support P3 partition either formatted as ext3/4 or as part of ZFS pool
# Priorities are: ext3, ext4, zfs
if P3=$(findfs PARTLABEL=P3) && [ -n "$P3" ]; then
    P3_FS_TYPE=$(blkid "$P3"| tr ' ' '\012' | awk -F= '/^TYPE/{print $2;}' | sed 's/"//g')
    if [ "$P3_FS_TYPE" = zfs_member ]; then
       # zfs_member is part of zfs type
       P3_FS_TYPE="zfs"
    fi
    echo "$(date -Ins -u) Using $P3 (formatted with $P3_FS_TYPE), for $PERSISTDIR"

    if [ "$P3_FS_TYPE" = zfs ]; then
        set_sequential_mdev
        if ! chroot /hostfs zpool import -f persist; then
            # Don't re-format the fs if we are in kdump kernel
            if [ "$IS_IN_KDUMP_KERNEL" = 0 ]; then
                echo "$(date -Ins -u) Cannot import persist pool on P3 partition $P3 of type $P3_FS_TYPE, recreating it as $P3_FS_TYPE_DEFAULT"
                INIT_FS=1
                P3_FS_TYPE="$P3_FS_TYPE_DEFAULT"
            fi
        else
            zfs_adjust_features
        fi
    else
        #For systems with ext3 filesystem, try not to change to ext4, since it will brick
        #the device when falling back to old images expecting P3 to be ext3. Migrate to ext4
        #when we do usb install, this way the transition is more controlled.
        #Any fsck error (ext3 or ext4), will lead to formatting P3 with ext4
        if { [ "$P3_FS_TYPE" != ext3 ] && [ "$P3_FS_TYPE" != ext4 ]; } || ! "fsck.$P3_FS_TYPE" -y "$P3" ; then
            # Don't re-format the fs if we are in kdump kernel
            if [ "$IS_IN_KDUMP_KERNEL" = 0 ]; then
                echo "$(date -Ins -u) P3 partition $P3 of type $P3_FS_TYPE appears to be corrupted, recreating it as $P3_FS_TYPE_DEFAULT"
                INIT_FS=1
                P3_FS_TYPE="$P3_FS_TYPE_DEFAULT"
            fi
        fi
    fi

    case "$P3_FS_TYPE" in
             ext3) mount -t ext3 -o dirsync,noatime "$P3" $PERSISTDIR
                   ;;
             ext4) #Use -F option twice, to avoid any user confirmation in mkfs
                   if [ "$INIT_FS" = 1 ]; then
                      mkfs -t ext4 -v -F -F -O encrypt "$P3"
                   fi
                   # Enable encryption
                   tune2fs -O encrypt "$P3" && \
                   mount -t ext4 -o dirsync,noatime "$P3" $PERSISTDIR
                   ;;
             zfs) if [ "$INIT_FS" = 1 ]; then
                      # note that we immediately create a zfs dataset for containerd, since otherwise the init sequence will fail
                      #   https://bugs.launchpad.net/ubuntu/+source/zfs-linux/+bug/1718761
                      chroot /hostfs zpool create -f -m none -o feature@encryption=enabled -O atime=off -O overlay=on persist "$P3" && \
                      chroot /hostfs zfs create -o refreservation="$(chroot /hostfs zfs get -o value -Hp available persist | awk '{ print ($1/1024/1024)/5 }')"m persist/reserved && \
                      chroot /hostfs zfs set mountpoint="$PERSISTDIR" persist                                          && \
                      chroot /hostfs zfs set primarycache=metadata persist                                             && \
                      chroot /hostfs zfs create -p -o mountpoint="$PERSISTDIR/containerd/io.containerd.snapshotter.v1.zfs" persist/snapshots
                      set_sequential_mdev
                   fi
                   ;;
    esac || echo "$(date -Ins -u) mount of $P3 as $P3_FS_TYPE failed"

    # deposit fs type into /run
    echo "$P3_FS_TYPE" > /run/eve.persist_type

    if [ "$INIT_FS" = 1 ]; then
      # store file to indicate that EVE will clean vault
      # in case of no key received from controller
      mkdir -p /persist/status
      touch /persist/status/allow-vault-clean
    fi
else
    #in case of no P3 we may have EVE persist on another disks
    set_sequential_mdev
    if chroot /hostfs zpool import -f persist; then
        echo "zfs" > /run/eve.persist_type
        zfs_adjust_features
    else
        echo "$(date -Ins -u) No separate $PERSISTDIR partition"
    fi
fi

zfs_set_arc_limits

UUID_SYMLINK_PATH="/dev/disk/by-uuid"
mkdir -p $UUID_SYMLINK_PATH
chmod 700 $UUID_SYMLINK_PATH

# create /run/edgeview early before the disk mount for edgeview container
mkdir -p /run/edgeview

BLK_DEVICES=$(ls /sys/class/block/)
for BLK_DEVICE in $BLK_DEVICES; do
    BLK_UUID=$(blkid "/dev/$BLK_DEVICE" | sed -n 's/.*UUID=//p' | sed 's/"//g' | awk '{print $1}')
    if [ -n "${BLK_UUID}" ]; then
        ln -s "/dev/$BLK_DEVICE" "$UUID_SYMLINK_PATH/$BLK_UUID"
    fi
done

#Recording SMART details to a file
if [ -L /dev/root ] ; then
  DEV_TO_CHECK_SMART=/dev/root
else
  DEV_TO_CHECK_SMART=$(grep -m 1 /persist < /proc/mounts | cut -d ' ' -f 1)
fi
SMART_JSON=$(smartctl -a "$DEV_TO_CHECK_SMART" --json)
if [ -f "$SMART_DETAILS_PREVIOUS_FILE" ];
then
  mv $SMART_DETAILS_FILE $SMART_DETAILS_PREVIOUS_FILE
  echo "$SMART_JSON" > $SMART_DETAILS_FILE
else
  echo "$SMART_JSON" > $SMART_DETAILS_FILE
  echo "$SMART_JSON" > $SMART_DETAILS_PREVIOUS_FILE
fi

# Uncomment the following block if you want storage-init to replace
# rootfs of service containers with a copy under /persist/services/X
# each of these is considered to be a proper lowerFS
# for s in "$PERSISTDIR"/services/* ; do
#   if [ -d "$s" ]; then
#      mount --bind "$s" "/containers/services/$(basename "$s")/lower"
#   fi
# done
