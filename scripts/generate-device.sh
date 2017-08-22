#!/bin/bash
# Generate a self-signed ECC certificate; 20 year lifetime
# argument is a basename for the output files
# Example: generate-dc.sh ../run/test
# will place the private key in ../run/test.key.pem and the cert in
# ../run/test.cert.pem

if [ $# != 1 ]; then
    myname=`basename $0`
    echo "Usage: $myname <output basename>"
    exit 1
fi
lifetime=`expr 365 \* 20`
dir=`dirname $0`
$dir/generate-self-signed.sh $lifetime $1
