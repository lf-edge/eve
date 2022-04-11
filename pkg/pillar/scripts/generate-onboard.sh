#!/bin/sh
#
# Copyright (c) 2018-2022 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
# This script can be used to generate a unique onboarding certificate.
# The CN aka onboarding key can be extracted from that certificate using
# openssl x509 -in onboard.cert.pem -text | grep CN

# Default lifetime is one year
lifetime=$((365 * 1))

# Default cert location is current dir, with prefix "onboard"
output_base=onboard

# Default organization
org="Zededa, Inc"
# Default CN is a random uuid
cn=$(uuidgen)

while getopts c:b:l:o: o
do      case "$o" in
        b)      output_base="$OPTARG";;
        c)      cn="$OPTARG";;
        l)      lifetime=$OPTARG;;
        o)      org="$OPTARG";;
        [?])    echo "Usage: $0 [-b basename] [-c cn-uuid] [-l lifetime] [-o organization]"
                exit 1;;
        esac
done

output_key=${output_base}.key.pem
output_cert=${output_base}.cert.pem
csr=${output_base}.csr

dir=$(dirname "$output_cert")
if [ ! -d "$dir" ]; then
    echo "Directory does not exist: $dir"
    exit 1
fi

#The CSR content
subject="/O=$org/CN=$cn"

# Generate an ECC key pair, to sign CSR
openssl ecparam -genkey -name prime256v1 -out "$output_key" -noout

# Create CSR
openssl req -new -sha256 -key "$output_key" -subj "$subject" -out "$csr"

ext1='basicConstraints=critical,CA:FALSE'
ext2='keyUsage=digitalSignature,keyEncipherment'
ext3='extendedKeyUsage=serverAuth'

# Sign certificate
# Some openssl versions versions require subject - other onesfail if it is there
v=$(openssl version | awk '{print $2}')
case $v in (1.0.*)
        openssl req -x509 -sha256 -config /dev/null \
                -addext $ext1 -addext $ext2 -addext $ext3 \
                -subj "$subject" \
                -days "$lifetime" -key "$output_key" -in "$csr" -out "$output_cert"
        ;;
(*)
        openssl req -x509 -sha256 -config /dev/null \
                -addext $ext1 -addext $ext2 -addext $ext3 \
                -days "$lifetime" -key "$output_key" -in "$csr" -out "$output_cert"
        ;;
esac

#Cleanup
rm -f "$csr"
