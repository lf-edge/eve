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

zfs_adjust_features() {
  # we had a bug with mismatch of libzfs and zfs module versions
  # let's set draid feature enabled as we started with zfs 2.1.x which supports this feature
  # with disabled we will see errors from zpool status
  chroot /hostfs zpool set feature@draid=enabled persist
}

PERSISTDIR=/persist
CONFIGDIR=/config
CONFIGDIR_PERSIST=/tmp/config_ro

# log writes a timestamped line to both stdout (-> memlogd) and the serial
# console (-> eden's default-eve.log). An onboot container's stdout alone does
# NOT reach the serial console, so bare echo from here is invisible there; the
# storage-resizer invocations in storage-resize.sh additionally redirect their
# own stdout/stderr to /dev/console (matching pkg/installer's ">/dev/console 2>&1"
# idiom) so the resizer's output is visible too. tee errors are ignored in case
# /dev/console is absent.
log() { echo "$(date -Ins -u) $*" | tee /dev/console 2>/dev/null; return 0; }
SMART_DETAILS_FILE=$PERSISTDIR/SMART_details.json
SMART_DETAILS_PREVIOUS_FILE=$PERSISTDIR/SMART_details_previous.json

INSTALL_CLUSTERED_STORAGE=false
INSTALL_ZFS=false
eve_flavor=$(cat /hostfs/etc/eve-hv-type)

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

    mount -t tmpfs -o rw,nosuid,nodev,noexec,relatime,size=5120k,mode=755 tmpfs $CONFIGDIR
    echo "$(date -Ins -u) Create a copy of CONFIG partition in RAM"
    cp -r $CONFIGDIR_PERSIST/* $CONFIGDIR
    umount "$CONFIG"
    mount -o remount,ro $CONFIGDIR
else
    echo "$(date -Ins -u) No separate $CONFIGDIR partition"
fi

INIT_FS=0
P3_FS_TYPE_DEFAULT=ext4
# check if we have eve_install_zfs_with_raid_level in kernel command line
# if so use zfs as default
if grep -q 'eve_install_zfs_with_raid_level' /proc/cmdline; then
   P3_FS_TYPE_DEFAULT=zfs
elif [ "$INSTALL_ZFS" = true ]; then
   P3_FS_TYPE_DEFAULT=zfs
fi

DIRSYNC_OPT=",dirsync"
if grep -q 'eve_no_dirsync' /proc/cmdline; then
   DIRSYNC_OPT=""
fi

if [ "$eve_flavor" = "k" ]; then
   if [ "$P3_FS_TYPE_DEFAULT" = "zfs" ]; then
      INSTALL_CLUSTERED_STORAGE=true
      INSTALL_ZFS=true
      echo "$(date -Ins -u) Kubevirt image - might recreate ZFS /persist"
   fi
fi

# Persist placeholder (P3_PENDING)
#
# Images flashed directly to the device instead of going through the EVE
# installer (e.g. QDL flashing on Qualcomm devices, see pkg/qcom-flash) don't
# know at build time where /persist goes: it may live on the boot disk or on
# other disk(s) such as an NVMe. They ship a P3_PENDING placeholder partition
# (covering the space P3 would take on the boot disk) instead of P3, and the
# decision is taken here on the first boot, following the same kernel command
# line options as the installer:
#
#   no eve_persist_disk=       P3_PENDING is replaced by P3 on the boot disk
#   eve_persist_disk=<disk>    <disk> is wiped and gets a single P3 partition
#   eve_persist_disk=<d1,d2..> a ZFS "persist" pool is created on the disks
#                              (raid level from eve_install_zfs_with_raid_level)
#
# The boot disk itself is ignored in eve_persist_disk (unlike the installer,
# it's never made part of a multi-disk pool).
#
# P3/pool formatting is left to the regular code below (P3 without a known
# filesystem is formatted with $P3_FS_TYPE_DEFAULT).
#
# P3_PENDING is removed only once /persist storage exists, so it is a one-time
# operation: after that, a missing /persist disk is never "replaced" by a new,
# empty /persist on the boot disk. If a P3 partition or a "persist" pool already
# exists (e.g. the boot disk was re-flashed but the NVMe was kept), it is reused
# as is and only the placeholder is dropped.
PERSIST_TYPE_GUID=5f24425a-2dfa-11e8-a270-7b663faccc2c
PERSIST_PART_UUID=ad6871ee-31f9-4cf3-9e09-6f7a25c30059

# disk_of_part <partition device> - prints the parent disk device
disk_of_part() {
   echo "/dev/$(basename "$(readlink -f "/sys/class/block/$(basename "$1")/..")")"
}

# zero_part_edges <partition device> - zero the first and last 5MB, to get rid
# of any residual prior data
zero_part_edges() {
   part_sz=$(blockdev --getsz "$1")
   [ "$part_sz" -gt 20480 ] || return 0
   dd if=/dev/zero of="$1" bs=512 count=10240 2>/dev/null
   dd if=/dev/zero of="$1" bs=512 seek=$(( part_sz - 10240 )) count=10240 2>/dev/null
   return 0
}

# drop_p3_pending <P3_PENDING partition device>
drop_p3_pending() {
   pend_dev=$(disk_of_part "$1")
   pend_num=$(cat "/sys/class/block/$(basename "$1")/partition")
   sgdisk --delete="$pend_num" "$pend_dev" && \
   partx -d --nr "$pend_num" "$pend_dev"
}

# p3_on_boot_disk <P3_PENDING partition device>
# Replace P3_PENDING by a P3 partition spanning the largest free area of the
# boot disk (the space P3_PENDING was covering, up to the end of the disk).
p3_on_boot_disk() {
   pend_dev=$(disk_of_part "$1")
   pend_num=$(cat "/sys/class/block/$(basename "$1")/partition")
   echo "$(date -Ins -u) Creating P3 on the boot disk $pend_dev"
   sgdisk --delete="$pend_num" "$pend_dev" || return 1
   if ! sgdisk --largest-new="$pend_num" --typecode="$pend_num:$PERSIST_TYPE_GUID" \
               --change-name="$pend_num:P3" --partition-guid="$pend_num:$PERSIST_PART_UUID" \
               "$pend_dev"; then
      # restore the placeholder, so it can be retried on the next boot
      sgdisk --largest-new="$pend_num" --typecode="$pend_num:8da63339-0007-60c0-c436-083ac8230908" \
             --change-name="$pend_num:P3_PENDING" "$pend_dev"
      return 1
   fi
   partx -d --nr "$pend_num" "$pend_dev"
   partx -a --nr "$pend_num" "$pend_dev"
   P3=$(findfs PARTLABEL=P3 2>/dev/null)
   [ -n "$P3" ] || return 1
   zero_part_edges "$P3"
}

# p3_on_disk <disk name> - wipe <disk> and create a single P3 partition on it
p3_on_disk() {
   pdev="/dev/$1"
   echo "$(date -Ins -u) Creating P3 on $pdev"
   dd if=/dev/zero of="$pdev" bs=512 count=1 conv=notrunc && sync
   sgdisk -Z --clear "$pdev" 2>/dev/null || :
   sgdisk --new 1:0:0 --typecode="1:$PERSIST_TYPE_GUID" --change-name=1:P3 \
          --partition-guid="1:$PERSIST_PART_UUID" "$pdev" || return 1
   partprobe "$pdev"
   P3=$(findfs PARTLABEL=P3 2>/dev/null)
   [ -n "$P3" ] || return 1
   zero_part_edges "$P3"
}

# zfs_pool_on_disks <disk names> - create the "persist" pool across the disks
# (same pool layout as the installer), then export it so the regular code
# below imports it
zfs_pool_on_disks() {
   vdevs=""
   for d in "$@"; do
      dd if=/dev/zero of="/dev/$d" bs=512 count=1 conv=notrunc && sync
      sgdisk -Z --clear "/dev/$d" 2>/dev/null || :
      vdevs="$vdevs /dev/$d"
   done
   raid_level=$(tr ' ' '\012' < /proc/cmdline | sed -ne '/^eve_install_zfs_with_raid_level=/s#^.*=##p')
   case "$raid_level" in
      raid1) vdevs="mirror $vdevs" ;;
      raid5) vdevs="raidz1 $vdevs" ;;
      raid6) vdevs="raidz2 $vdevs" ;;
   esac
   echo "$(date -Ins -u) Creating ZFS persist pool on:$vdevs"
   # shellcheck disable=SC2086
   chroot /hostfs zpool create -f -m none -o feature@encryption=enabled -O atime=off -O overlay=on persist $vdevs && \
   chroot /hostfs zfs create -o refreservation="$(chroot /hostfs zfs get -o value -Hp available persist | awk '{ print ($1/1024/1024)/5 }')"m persist/reserved && \
   chroot /hostfs zfs set mountpoint="$PERSISTDIR" persist && \
   chroot /hostfs zfs set primarycache=metadata persist || return 1
   if [ "$INSTALL_CLUSTERED_STORAGE" = false ]; then
      # Not clustered storage; persist/vault is an ext4 zvol
      chroot /hostfs zfs create -p -o mountpoint="$PERSISTDIR/containerd/io.containerd.snapshotter.v1.zfs" persist/snapshots || return 1
   fi
   chroot /hostfs zpool export persist
   # make sure the vault gets (re)created on this new storage
   NEW_ZFS_POOL=1
}

# setup_pending_persist <P3_PENDING partition device>
setup_pending_persist() {
   pending="$1"
   if findfs PARTLABEL=P3 > /dev/null 2>&1 || \
      chroot /hostfs zpool import 2>/dev/null | grep -q '^ *pool: persist$'; then
      echo "$(date -Ins -u) Found existing /persist storage, removing P3_PENDING"
      drop_p3_pending "$pending"
      return
   fi

   boot_disk=$(basename "$(disk_of_part "$pending")")
   other_disks=""
   for d in $(tr ' ' '\012' < /proc/cmdline | sed -ne '/^eve_persist_disk=/s#^.*=##p' | tr ',' ' '); do
      [ "$d" = "$boot_disk" ] && continue
      if [ ! -e "/sys/block/$d/dev" ]; then
         echo "$(date -Ins -u) ERROR: persist disk $d not found, keeping P3_PENDING to retry on the next boot"
         return
      fi
      other_disks="$other_disks $d"
   done
   # shellcheck disable=SC2086
   set -- $other_disks

   if [ $# -gt 1 ]; then
      # same rules as the installer: explicit ZFS request, or at least 64GB of
      # RAM and 3 disks, otherwise /persist goes to the boot disk
      mem_gb=$(( $(awk '/MemTotal/ {print $2}' /proc/meminfo) / 1024 / 1024 ))
      if ! grep -q 'eve_install_zfs_with_raid_level' /proc/cmdline && \
         { [ "$mem_gb" -lt 64 ] || [ $# -lt 3 ]; }; then
         echo "$(date -Ins -u) WARNING: ZFS minimum requirements are not met, creating P3 on the boot disk"
         set --
      fi
   fi

   case $# in
      0) p3_on_boot_disk "$pending" || {
            echo "$(date -Ins -u) ERROR: failed to create P3 on the boot disk"
            return
         }
         # P3_PENDING was replaced by P3, nothing left to drop
         return
         ;;
      1) p3_on_disk "$1" || {
            echo "$(date -Ins -u) ERROR: failed to create P3 on /dev/$1"
            return
         }
         ;;
      *) zfs_pool_on_disks "$@" || {
            echo "$(date -Ins -u) ERROR: failed to create the ZFS persist pool"
            return
         }
         ;;
   esac
   drop_p3_pending "$pending"
}

NEW_ZFS_POOL=0
if P3_PENDING=$(findfs PARTLABEL=P3_PENDING) && [ -n "$P3_PENDING" ]; then
   echo "$(date -Ins -u) Found P3_PENDING ($P3_PENDING), setting up /persist storage"
   setup_pending_persist "$P3_PENDING"
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
#
#   Its possible that P3 is missing in cases where the EVE installer was
#   configured to place persist on a zfs pool which could span 1 or more
#   other disks. This P3 partition init path must be skipped here.
#
P3=$(findfs PARTLABEL=P3)
IMGA=$(findfs PARTLABEL=IMGA)
IMGB=$(findfs PARTLABEL=IMGB)
is_first_boot_virt_eve() {
    if [ -n "$IMGA" ] && [ -z "$P3" ] && [ -z "$IMGB" ]; then
        return 0
    fi
    return 1
}

# --- boot-disk repartition (storage-resize.sh) -------------------------------
# The repartition helpers live in a sibling file to keep this script manageable.
# They use CONFIGDIR, PERSISTDIR and log() defined above, so source after them.
# shellcheck source=pkg/storage-init/storage-resize.sh
. "$(dirname "$0")/storage-resize.sh"

if is_first_boot_virt_eve; then
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

   [ -z "$IMGB" ] && sgdisk --new "$IMGB_ID:$SEC_START:$SEC_END" --typecode="$IMGB_ID:$IMGA_GUID" --change-name="$IMGB_ID:IMGB" "$DEV"
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
       [ -z "$IMGB" ] && sgdisk --partition-guid="$IMGB_ID:$IMGB_UUID" "$DEV"
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

# If baseosmgr requested a repartition, do the offline shrink+grow now while
# /persist is still unmounted, before the P3 fsck/mount.
maybe_offline_disk_resize

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
        if ! chroot /hostfs zpool import -f persist; then
            echo "$(date -Ins -u) Cannot import persist pool on P3 partition $P3 of type $P3_FS_TYPE, recreating it as $P3_FS_TYPE_DEFAULT"
            INIT_FS=1
            P3_FS_TYPE="$P3_FS_TYPE_DEFAULT"
        else
            zfs_adjust_features
        fi
    else
        #For systems with ext3 filesystem, try not to change to ext4, since it will brick
        #the device when falling back to old images expecting P3 to be ext3. Migrate to ext4
        #when we do usb install, this way the transition is more controlled.
        #Any fsck error (ext3 or ext4), will lead to formatting P3 with ext4
        if { [ "$P3_FS_TYPE" != ext3 ] && [ "$P3_FS_TYPE" != ext4 ]; } || ! "fsck.$P3_FS_TYPE" -y "$P3" ; then
            echo "$(date -Ins -u) P3 partition $P3 of type $P3_FS_TYPE appears to be corrupted, recreating it as $P3_FS_TYPE_DEFAULT"
            INIT_FS=1
            P3_FS_TYPE="$P3_FS_TYPE_DEFAULT"
        fi
    fi

    case "$P3_FS_TYPE" in
             ext3) mount -t ext3 -o noatime${DIRSYNC_OPT} "$P3" $PERSISTDIR
                   ;;
             ext4) #Use -F option twice, to avoid any user confirmation in mkfs
                   #EVE releases built on Alpine < 3.22 have an e2fsck that rejects
                   #orphan_file, and their storage-init then reformats P3
                   if [ "$INIT_FS" = 1 ]; then
                      mkfs -t ext4 -v -F -F -O encrypt,^orphan_file "$P3"
                   fi
                   tune2fs -O ^orphan_file "$P3" || \
                      echo "$(date -Ins -u) Cannot remove orphan_file from $P3"
                   # Enable encryption
                   tune2fs -O encrypt "$P3" && \
                   mount -t ext4 -o noatime${DIRSYNC_OPT} "$P3" $PERSISTDIR
                   ;;
             zfs) if [ "$INIT_FS" = 1 ]; then
                      # note that we immediately create a zfs dataset for containerd, since otherwise the init sequence will fail
                      #   https://bugs.launchpad.net/ubuntu/+source/zfs-linux/+bug/1718761
                      chroot /hostfs zpool create -f -m none -o feature@encryption=enabled -O atime=off -O overlay=on persist "$P3" && \
                      chroot /hostfs zfs create -o refreservation="$(chroot /hostfs zfs get -o value -Hp available persist | awk '{ print ($1/1024/1024)/5 }')"m persist/reserved && \
                      chroot /hostfs zfs set mountpoint="$PERSISTDIR" persist                                          && \
                      chroot /hostfs zfs set primarycache=metadata persist                                             && \
                      if [ "$INSTALL_CLUSTERED_STORAGE" = false ]; then
                          # Not clustered storage; persist/vault is an ext4 zvol
                          chroot /hostfs zfs create -p -o mountpoint="$PERSISTDIR/containerd/io.containerd.snapshotter.v1.zfs" persist/snapshots
                      fi
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
    if chroot /hostfs zpool import -f persist; then
        echo "zfs" > /run/eve.persist_type
        zfs_adjust_features
        if [ "$NEW_ZFS_POOL" = 1 ]; then
            # pool just created from P3_PENDING, same as INIT_FS=1 below
            mkdir -p /persist/status
            touch /persist/status/allow-vault-clean
        fi
    else
        echo "$(date -Ins -u) No separate $PERSISTDIR partition"
    fi
fi

# /persist is now mounted (if present): restore any files the resize shrink
# may have lost and clean up the backup/flag on the CONFIG partition.
maybe_restore_after_persist

zfs_set_arc_limits

UUID_SYMLINK_PATH="/dev/disk/by-uuid"
mkdir -p $UUID_SYMLINK_PATH
chmod 700 $UUID_SYMLINK_PATH

# Check for tee-supplicant and create the directory for the Trustzone userspace
# filesystem (if needed).
if [ -f /hostfs/usr/sbin/tee-supplicant ]; then
    mkdir -p $PERSISTDIR/coretee

    # Check for an existent fTPM provision data on CONFIG partition, if found,
    # the data must be extracted to /persist/
    if [ -f "$CONFIGDIR/ftpm.tar.xz" ]; then
        tar -xJf "$CONFIGDIR/ftpm.tar.xz" -C $PERSISTDIR
    fi
fi

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
if [ -L /dev/root ] || [ -b /dev/root ] ; then
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
