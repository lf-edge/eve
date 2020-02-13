#!/bin/sh

set -e

FILE="$1"
ARCH="$2"

# set defaults
if [ -z "$1" ]; then
  FILE="live"
fi
if [ -z "$2" ]; then
  ARCH="amd64"
fi

# because the convenient name "installer" is not the file name
if [ "$FILE" = "installer" ]; then
  FILE="target"
fi

TMPDIR=./tmp
OUTFILE=${TMPDIR}/persist.tgz
TMPFILE=${TMPDIR}/${FILE}-${ARCH}.qcow2
INFILE=./dist/${ARCH}/${FILE}.qcow2

if [ ! -f "${INFILE}" ]; then
  echo "input file ${INFILE} does not exist; are you running this from the right directory? Did you already run make live?" >&2
  exit 1
fi

# set out temporary working directory
mkdir -p ${TMPDIR}

# copy the live file over
cp ${INFILE} ${TMPFILE}

# ensure that network block device is installed
sudo modprobe nbd max_part=10

# connect the qcow2 file as a network block device
sudo qemu-nbd -c /dev/nbd0 ${TMPFILE}

# get the persist partition, which is the 9th partition
sudo mount /dev/nbd0p9 /mnt

# optionally, create a tgz file with the contents
sudo tar -C /mnt -zcvf ${OUTFILE}  -C /mnt .

# unmount the persist partition
sudo umount /mnt

# remove the network block device
sudo qemu-nbd -d /dev/nbd0

# remove the temporary file
rm -f ${TMPFILE}

# report
echo "persist directory extracted to ${OUTFILE}"
