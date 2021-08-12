#!/bin/sh

test -n "$EDEN_CONFIG" || EDEN_CONFIG=default

EDEN=eden
DIR=$(dirname "$0")
PATH=$DIR:$DIR/../../bin:$PATH

cat >> ~/.eden/"$EDEN_CONFIG"-qemu.conf <<END


[device "sound"]
  driver = "ich9-intel-hda"
  bus = "pcie.0"
  addr = "1b.0"
END

cat <<END
To activate the changes in the config, you need to restart EVE:
  $EDEN eve stop
  $EDEN eve start
END
