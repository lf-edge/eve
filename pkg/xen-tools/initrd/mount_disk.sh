#!/bin/sh

# we expect the same order in block device enumeration (we put them in order in VM's configuration)
# and in /mnt/mountPoints file (where mount points defined)

# On HV=k the container PVC is the boot block device — it's already mounted at
# /mnt and must be skipped here, otherwise it would be treated as the first
# extra volume: that either remounts the rootfs on top of itself, or (worse)
# consumes mountPoints line 1 and shifts every subsequent device-to-path
# mapping down by one. On HV=kvm/xen root=9p, /proc/mounts has no block device
# at /mnt so boot_dev stays empty and the guard is a no-op.
boot_dev=$(awk '$2 == "/mnt" {print $1; exit}' /proc/mounts | sed 's|^/dev/||')

# /mnt/mountPoints is written by:
#   - HV=kvm/xen: pkg/pillar/containerd/oci.go:AddLoader at domain-create time
#     from disk.MountDir entries in the OCI spec.
#   - HV=k:      init-initrd rewrites it from #EVE_VOLMOUNT cidata markers
#                emitted by domainmgr's mountDirsToUserData, also at domain-
#                create time.
# If neither path produced a file (no extra volumes attached), there's nothing
# to mount — exit cleanly instead of erroring on every enumerated block device.
if [ ! -f /mnt/mountPoints ]; then
  echo "No /mnt/mountPoints present — no volumes to mount."
  exit 0
fi

mountPointLineNo=1
find /sys/block/ -maxdepth 1 -regex '.*[sv]d.*' -exec basename '{}' ';'| sort | while read -r disk ; do
  if [ -n "$boot_dev" ] && [ "$disk" = "$boot_dev" ]; then
    echo "Skipping boot device $disk (already mounted at /mnt)"
    continue
  fi
  echo "Processing $disk"
  targetDir=$(sed "${mountPointLineNo}q;d" /mnt/mountPoints)
  # An empty mountPoints line means the user attached this volume as a raw
  # block device (no MountDir). domainmgr's mountDirsToUserData still emits a
  # line for it so the positional mapping for *subsequent* devices stays
  # correct — advance the cursor and skip this device. The same empty result
  # also happens past the end of the file when extra block devices appear
  # unexpectedly; the message below covers both.
  if [ -z "$targetDir" ]; then
    echo "No mount target on line $mountPointLineNo for $disk — skipping"
    mountPointLineNo=$((mountPointLineNo + 1))
    continue
  fi

  #Checking and creating a ext4 file system inside the partition
  fileSystem="ext4"
  # We only care if filesystem exists, not what type it is. So just check for TYPE existence.
  existingFileSystem="$(blkid "/dev/$disk" | grep TYPE= )"
  if [ "$existingFileSystem" = "" ]; then
    echo "Creating $fileSystem file system on /dev/$disk"
    mke2fs -t $fileSystem "/dev/$disk" && \
    echo "Successfully created $fileSystem file system on /dev/$disk" || \
    echo "Failed to create $fileSystem file system on /dev/$disk"
    echo
  fi

  #Mounting the partition onto a target directory
  diskAccess=$(cat "/sys/block/$disk/ro")
  if [ "$diskAccess" -eq 0 ]; then
    accessRight=rw
  else
    accessRight=ro
  fi
  stage2TargetPath="/mnt/rootfs$targetDir"
  echo "Mounting /dev/$disk on $stage2TargetPath with access: $accessRight"
  mkdir -p "$stage2TargetPath"
  mount -O remount,$accessRight "/dev/$disk" "$stage2TargetPath" && \
  echo "Successfully mounted file system:/dev/$disk on $targetDir" || \
  echo "Failed to mount file system:/dev/$disk on $targetDir"

  mountPointLineNo=$((mountPointLineNo + 1))
done
