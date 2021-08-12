#!/bin/sh

if [ $# -eq 0 ]
then
  echo Usage: "$0" port1:port2...
  exit
fi

test -n "$EDEN_CONFIG" || EDEN_CONFIG=default

EDEN=eden
DIR=$(dirname "$0")
PATH=$DIR:$DIR/../../bin:$PATH

OLD=$($EDEN config get "$EDEN_CONFIG" --key eve.hostfwd)
NEW=$OLD

for port in "$@"
do
  echo "$port" | grep '[0-9]\+:[0-9]\+' || continue
  port=$(echo "$port" | sed 's/^/"/;s/:/":"/g;s/$/"/')
  shift
  if echo "$OLD" | grep "$port"
  then
    echo Removing "$port" port redirection to EDEN config
    NEW=$(echo "$NEW" | sed "s/{\(.*\)$port\(.*\)}/{\1,\2}/; s/\(,\)\1/\1/g; s/[, ]*}/}/; s/{[, ]\+/{/; s/\([^, ]\),[, ]\+\([^, ]\)/\1,\2/")
  fi
done

if [ "$OLD" != "$NEW" ]
then
  echo $EDEN config set "$EDEN_CONFIG" --key eve.hostfwd --value \'"$NEW"\'
  $EDEN config set "$EDEN_CONFIG" --key eve.hostfwd --value "$NEW"
  echo $EDEN config get "$EDEN_CONFIG" --key eve.hostfwd
  $EDEN config get "$EDEN_CONFIG" --key eve.hostfwd
  cat <<END
To activate the changes in the config, you need to restart EVE:
  $EDEN eve stop
  $EDEN eve start
END
fi
