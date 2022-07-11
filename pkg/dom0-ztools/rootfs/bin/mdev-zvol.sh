#!/bin/sh

if [ "$ACTION" = "add" ]; then
  datasetName=$(/lib/udev/zvol_id "/dev/$MDEV")
  retVal=$?
  if [ $retVal -ne 0 ]; then
    echo "failed to run /lib/udev/zvol_id /dev/$MDEV code: $retVal output: $datasetName"
    exit $retVal
  fi
  if [ -f "/run/mdev/zvol/$MDEV" ]; then
    oldDatasetName=$(cat "/run/mdev/zvol/$MDEV")
    if [ "$oldDatasetName" != "$datasetName" ]; then
      # clean old link if not match
      rm "/dev/zvol/$oldDatasetName"
    fi
  fi
  #temp directory to map $MDEV->datasetName
  mkdir -p "/run/mdev/zvol"
  echo "$datasetName" >"/run/mdev/zvol/$MDEV"
  mkdir -p "$(dirname "/dev/zvol/$datasetName")"
  ln -sf "/dev/$MDEV" "/dev/zvol/$datasetName"
fi

if [ "$ACTION" = "remove" ]; then
  if [ -f "/run/mdev/zvol/$MDEV" ]; then
    datasetName=$(cat "/run/mdev/zvol/$MDEV")
    rm "/run/mdev/zvol/$MDEV"
    rm "/dev/zvol/$datasetName"
  else
    echo "failed to remove /dev/$MDEV: no temp file"
  fi
fi
