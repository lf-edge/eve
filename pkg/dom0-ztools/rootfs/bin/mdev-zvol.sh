#!/bin/sh

if [ "$ACTION" = "add" ]; then
  datasetName=$(/lib/udev/zvol_id "/dev/$MDEV")
  retVal=$?
  if [ $retVal -ne 0 ]; then
    echo "failed to run /lib/udev/zvol_id /dev/$MDEV code: $retVal output: $datasetName"
    exit $retVal
  fi
  #temp directory to map $MDEV->datasetName
  mkdir -p "/run/mdev/zvol"
  echo "$datasetName" >"/run/mdev/zvol/$MDEV"
  mkdir -p "$(dirname "/dev/zvol/$datasetName")"
  ln -s "/dev/$MDEV" "/dev/zvol/$datasetName"
fi

if [ "$ACTION" = "remove" ]; then
  datasetName=$(cat "/run/mdev/zvol/$MDEV")
  rm "/run/mdev/zvol/$MDEV"
  rm "/dev/zvol/$datasetName"
fi
