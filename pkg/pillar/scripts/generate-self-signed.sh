#!/bin/sh
#
# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Generate a self-signed ECC certificate.
# first argument is lifetime in days
# second argument is a basename for the output files
# Example: generate-self-signed.sh 7 ../run/test
# will place the private key in ../run/test.key.pem and the cert in
# ../run/test.cert.pem

if [ $# != 2 ]; then
    myname=$(basename "$0")
    echo "Usage: $myname <lifetime> <output basename>"
    exit 1
fi
lifetime=$1
output_base=$2
output_key=${output_base}.key.pem
output_cert=${output_base}.cert.pem
csr=${output_base}.csr
dir=$(dirname "$output_key")
if [ ! -d "$dir" ]; then
    echo "Directory does not exist: $dir"
    exit 1
fi

subject="/C=US/ST=California/L=Santa Clara/O=Zededa, Inc/CN=$(basename "$output_base")"
openssl ecparam -genkey -name prime256v1 -out "$output_key"
openssl req -new -sha256 -subj "$subject" -key "$output_key" -out "$csr"
# Newer versions require subject - old one fail if it is there
v=$(openssl version | awk '{print $2}')
case $v in (1.0.*)
	       openssl req -x509 -sha256 -days "$lifetime" -key "$output_key" -in "$csr" -out "$output_cert"
	       ;;
	   (*)
	       openssl req -x509 -sha256 -subj "$subject" -days "$lifetime" -key "$output_key" -in "$csr" -out "$output_cert"
	       ;;
esac
rm "$csr"

