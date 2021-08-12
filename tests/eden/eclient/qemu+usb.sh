#!/bin/sh

test -n "$EDEN_CONFIG" || EDEN_CONFIG=default

EDEN=eden
DIR=$(dirname "$0")
PATH=$DIR:$DIR/../../bin:$PATH

dist=$($EDEN config get "$EDEN_CONFIG" --key eden.root)

dd if=/dev/zero of="$dist/stick.raw" bs=1K count=1

cat >> ~/.eden/"$EDEN_CONFIG"-qemu.conf <<END


[drive "stick"]
  if = "none"
  file = "$dist/stick.raw"
  format = "raw"

[device]
  driver = "usb-storage"
  bus = "usb.0"
  drive = "stick"
END

cat <<END
To activate the changes in the config, you need to restart EVE:
  $EDEN eve stop
  $EDEN eve start
END
