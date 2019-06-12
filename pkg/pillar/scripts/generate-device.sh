#!/bin/sh
#
# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Generate a self-signed ECC certificate; 20 year lifetime
# argument is a basename for the output files
# Example: generate-device.sh -b ../run/test
# will place the private key in ../run/test.key.pem and the cert in
# ../run/test.cert.pem
# Example: generate-device.sh -t -b ../run/test
# will use TPM to generate the key pair, and will place just cert in
# ../run/test.cert.pem

#TPM is not used by default
use_tpm=false

while getopts tb: o
do      case "$o" in
        b)      output_base="$OPTARG";;
        t)      use_tpm=true;;
        [?])    echo "Usage: $0 [-t] [-b basename]"
                exit 1;;
        esac
done

lifetime=$((365 * 20))
dir=$(dirname "$0")
if [ "$use_tpm" = true ]; then
"$dir"/generate-self-signed.sh -t -b "$output_base" -l "$lifetime"
else
"$dir"/generate-self-signed.sh -b "$output_base" -l "$lifetime"
fi
