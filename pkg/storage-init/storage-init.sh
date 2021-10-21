#!/bin/sh
#
# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

PERSISTDIR=/persist
CONFIGDIR=/config
SMART_DETAILS_FILE=$PERSISTDIR/SMART_details.json
SMART_DETAILS_PREVIOUS_FILE=$PERSISTDIR/SMART_details_previous.json
LVM_LV_GROUP=vg_eve

# the following is here just for compatibility reasons and it should go away soon
ln -s "$CONFIGDIR" "/var/$CONFIGDIR"
ln -s "$PERSISTDIR" "/var/$PERSISTDIR"

if CONFIG=$(findfs PARTLABEL=CONFIG) && [ -n "$CONFIG" ]; then
    if ! fsck.vfat -y "$CONFIG"; then
        echo "$(date -Ins -u) fsck.vfat $CONFIG failed"
    fi
    if ! mount -t vfat -o dirsync,noatime "$CONFIG" $CONFIGDIR; then
        echo "$(date -Ins -u) mount $CONFIG failed"
    fi
else
    echo "$(date -Ins -u) No separate $CONFIGDIR partition"
fi

INIT_FS=0
P3_FS_TYPE_DEFAULT=ext4
if grep -E 'zfs-(kvm|xen|acrn)' /hostfs/etc/eve-release; then
   P3_FS_TYPE_DEFAULT=zfs
fi

if grep -E 'lvm-(kvm|xen|acrn)' /hostfs/etc/eve-release; then
   P3_FS_TYPE_DEFAULT=lvm
fi

# First lets see if we're running with the disk that hasn't been properly
# initialized. This could happen when we run in a virtualized cloud
# environment where the initial disk image gets resized to its proper
# size when EVE is started (it can also happen when you're preparing a
# live image for something like HiKey and put it dirrectly on the flash
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

   SEC_START=$(sgdisk -f "$DEV")
   SEC_END=$((SEC_START + IMGA_SIZE))

   sgdisk --new "$IMGB_ID:$SEC_START:$SEC_END" --typecode="$IMGB_ID:$IMGA_GUID" --change-name="$IMGB_ID:IMGB" "$DEV"
   sgdisk --largest-new="$P3_ID" --typecode="$P3_ID:5f24425a-2dfa-11e8-a270-7b663faccc2c" --change-name="$P3_ID:P3" "$DEV"

   # focrce kernel to re-scan partition table
   partprobe "$DEV"
   partx -a --nr "$IMGB_ID:$P3_ID" "$DEV"

   # attempt to zero the first 5Mb of the P3 (to get rid of any residual prior data)
   if P3=$(findfs PARTLABEL=P3) && [ -n "$P3" ]; then
      dd if=/dev/zero of="$P3" bs=512 count=10240 2>/dev/null
   fi
fi

# setup LVM2 config files and backup folders on a /run tmpfs
mkdir /run/lvm
if [ -d /hostfs/etc/lvm ]; then
    cp -r /hostfs/etc/lvm /run/lvm
fi
export LVM_SYSTEM_DIR=/run/lvm

# We support P3 partition either formatted as ext3/4, as part of ZFS pool or as LVM2
# logical volume group
# Priorities are: ext3, ext4, zfs, lvm2
if P3=$(findfs PARTLABEL=P3) && [ -n "$P3" ]; then

    echo "We have found a $P3 partition. Probing FS type"

    # Loading zfs modules to see if we have any zpools attached to the system
    # We will unload them later (if they do unload it meands we didn't find zpools)
    modprobe zfs

    P3_FS_TYPE=$(blkid "$P3"| tr ' ' '\012' | awk -F= '/^TYPE/{print $2;}' | sed 's/"//g')
    echo "P3_FS_TYPE='$P3_FS_TYPE'"
    echo "$(date -Ins -u) Using $P3 (formatted with $P3_FS_TYPE), for $PERSISTDIR"

    # XXX FIXME: the following hack MUST go away when/if we decide to officially support ZFS/LVM
    # for now we are using first block in the device to flip into zfs or lvm on demand

    FS_MAGIC=$(dd if="$P3" bs=8 count=1 2>/dev/null)

    if [ -n "$FS_MAGIC" ]; then
        "FS_MAGIC=$FS_MAGIC found. Reinitilizing persist"
        # zero out the request (regardless of whether we can convert to zfs)
        dd if=/dev/zero of="$P3" bs=8 count=1 conv=noerror,sync,notrunc
        case $FS_MAGIC in
            'eve<3zfs') P3_FS_TYPE=zfs
                ;;
            'eve<3lvm') P3_FS_TYPE=lvm
                ;;
            *) echo "Unknown FS magic"
                ;;
        esac
    fi

    if [ "$P3_FS_TYPE" = zfs_member ]; then
        if ! chroot /hostfs zpool import -f persist; then
            echo "$(date -Ins -u) Cannot import persist pool on P3 partition $P3 of type $P3_FS_TYPE, recreating it as $P3_FS_TYPE_DEFAULT"
            INIT_FS=1
            P3_FS_TYPE="$P3_FS_TYPE_DEFAULT"
        else
            # set from zfs_member to zfs
            P3_FS_TYPE="zfs"
        fi
    elif [ "$P3_FS_TYPE" = LVM2_member ]; then
        # scan phisical LVM volumes and activate them
        # FIXME: do we need lvmetad so --cache --aay works?
        # without lvmetad LVs must be manually activated
        LVM_LV_GROUP=$(chroot /hostfs pvscan   | head -n 1 | awk -F" " '/VG/{print $4 ;}')
        echo "LVM VG name $LVM_LV_GROUP"
        if [ -n "$LVM_LV_GROUP" ]; then
            P3_FS_TYPE="lvm"
        else
            echo "No LVM2 volume groups found. Creating"
            INIT_FS=1
            P3_FS_TYPE="$P3_FS_TYPE_DEFAULT"
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
             ext3) mount -t ext3 -o dirsync,noatime "$P3" $PERSISTDIR
                   ;;
             ext4) #Use -F option twice, to avoid any user confirmation in mkfs
                   if [ "$INIT_FS" = 1 ]; then
                      mkfs -t ext4 -v -F -F -O encrypt "$P3"
                   fi
                   tune2fs -O encrypt "$P3" && \
                   mount -t ext4 -o dirsync,noatime "$P3" $PERSISTDIR
                   ;;
             zfs) if [ "$INIT_FS" = 1 ]; then
                      # note that we immediately create a zfs dataset for containerd, since otherwise the init sequence will fail
                      #   https://bugs.launchpad.net/ubuntu/+source/zfs-linux/+bug/1718761
                      chroot /hostfs zpool create -f -m none -o feature@encryption=enabled -O overlay=on persist "$P3" && \
                      chroot /hostfs zfs set mountpoint="$PERSISTDIR" persist                                          && \
                      chroot /hostfs zfs create -p -o mountpoint="$PERSISTDIR/containerd/io.containerd.snapshotter.v1.zfs" persist/snapshots
                   fi
                   chroot /hostfs zpool import -f persist
                   ;;
             lvm) if [ "$INIT_FS" = 1 ]; then
                        chroot /hostfs pvcreate "$P3"
                        chroot /hostfs pvscan
                        chroot /hostfs vgcreate "$LVM_LV_GROUP" "$P3"
                        chroot /hostfs lvcreate -l 50%VG -n persist "$LVM_LV_GROUP"
                        chroot /hostfs lvcreate -l 100%FREE -n vm_images "$LVM_LV_GROUP"
                        mkfs -t ext4 -v -F -F -O encrypt "/dev/$LVM_LV_GROUP/persist"
                  else
                        chroot /hostfs lvscan
                        chroot /hostfs lvchange -a y "/dev/$LVM_LV_GROUP/persist"
                        chroot /hostfs lvchange -a y "/dev/$LVM_LV_GROUP/vm_images"
                        chroot /hostfs lvscan
                  fi

                  mount -t ext4 -o dirsync,noatime "/dev/$LVM_LV_GROUP/persist" "$PERSISTDIR"

    esac || echo "$(date -Ins -u) mount of $P3 as $P3_FS_TYPE failed"

    # deposit fs type into /run
    echo "$P3_FS_TYPE" > /run/eve.persist_type

    # this is safe, since if the mount fails the following will fail too
    # shellcheck disable=SC2046
    rmmod $(lsmod | grep zfs | awk '{print $1;}') || :
else
  #in case of no P3 we may have EVE persist on another disks
  modprobe zfs
  if chroot /hostfs zpool import -f persist; then
    echo "zfs" > /run/eve.persist_type
  else
    # shellcheck disable=SC2046
    rmmod $(lsmod | grep zfs | awk '{print $1;}') || :
    echo "$(date -Ins -u) No separate $PERSISTDIR partition"
  fi
fi

UUID_SYMLINK_PATH="/dev/disk/by-uuid"
mkdir -p $UUID_SYMLINK_PATH
chmod 700 $UUID_SYMLINK_PATH
BLK_DEVICES=$(ls /sys/class/block/)
for BLK_DEVICE in $BLK_DEVICES; do
    BLK_UUID=$(blkid "/dev/$BLK_DEVICE" | sed -n 's/.*UUID=//p' | sed 's/"//g' | awk '{print $1}')
    if [ -n "${BLK_UUID}" ]; then
        ln -s "/dev/$BLK_DEVICE" "$UUID_SYMLINK_PATH/$BLK_UUID"
    fi
done

#Recording SMART details to a file
SMART_JSON=$(smartctl -a "$(grep -m 1 /persist < /proc/mounts | cut -d ' ' -f 1)" --json)
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
