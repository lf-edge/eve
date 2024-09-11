#!/bin/sh
# Start the vtpm and ptpm daemons
/usr/bin/vtpm &
/usr/bin/ptpm > /dev/null &

# keep the container running, we might want to use tpm2-tools
# for debugging and collecting information for diag.
sleep INF
