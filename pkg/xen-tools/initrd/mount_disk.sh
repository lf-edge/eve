#!/bin/sh

mountPointLineNo=1
ls /sys/block/ | grep xvd | while read -r disk ; do
  echo "Processing $disk"
  targetDir=$(sed "${mountPointLineNo}q;d" /mnt/mountPoints)
  if [ -z "$targetDir" ]
    then
      echo "Error while mounting: No Mount-Point found for $disk."
      exit 0
  fi

  #Checking and creating a file system inside the partition
  fileSystem="vfat"
  existingFileSystem="$(eval $(blkid /dev/$disk | awk ' { print $3 } '); echo $TYPE)"
  if [ "$existingFileSystem" == "" ]; then
    echo "Creating $fileSystem file system on /dev/$disk"
    mkfs.$fileSystem /dev/$disk && \
    echo "Successfully created $fileSystem file system on /dev/$disk" || \
    echo "Failed to create $fileSystem file system on /dev/$disk"
    echo
  fi

  #Mounting the partition onto a target directory
  diskAccess=$(cat /sys/block/$disk/ro)
  if [ $diskAccess -eq 0 ]; then
    accessRight=rw
  else
    accessRight=ro
  fi
  stage2TargetPath="/mnt/rootfs"$targetDir
  echo "Mounting /dev/$disk on $stage2TargetPath with access: $accessRight"
  mkdir -p $stage2TargetPath
  mount -O remount,$accessRight /dev/$disk $stage2TargetPath && \
  echo "Successfully mounted file system:/dev/$disk on $targetDir" || \
  echo "Failed to mount file system:/dev/$disk on $targetDir"

  mountPointLineNo=$(expr $mountPointLineNo + 1)
done