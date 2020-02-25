#!/bin/sh

mkdir -p ${WORKDIR:-/}
cd $WORKDIR
ARGS=
for i in "$@"
do
    ARGS="$ARGS \"$i\""
done

set -- $ARGS
eval $@
