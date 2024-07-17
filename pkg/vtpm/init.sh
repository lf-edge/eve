#!/bin/sh
# FIX-ME: this is temporary for debugging, get rid of the log.txt
/usr/bin/vtpmd >log.txt 2>&1 &

# keep the container running, we might want to use tpm2-tools
# for debugging and collecting information for diag.
sleep INF
