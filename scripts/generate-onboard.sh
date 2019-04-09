#!/bin/sh
#
# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Generate a self-signed ECC certificate; 7 day lifetime
# argument is a basename for the output files
# Example: generate-pc.sh ../run/test
# will place the private key in ../run/test.key.pem and the cert in
# ../run/test.cert.pem

if [ $# != 1 ]; then
    myname=`basename $0`
    echo "Usage: $myname <output basename>"
    exit 1
fi
dir=`dirname $0`
$dir/generate-self-signed.sh 7 $1
