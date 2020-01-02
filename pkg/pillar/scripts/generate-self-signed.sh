#!/bin/sh
#
# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Generate a self-signed ECC certificate.
# first argument is lifetime in days
# second argument is a basename for the output files
# Example 1: generate-self-signed.sh -l 7 -b ../run/test
# will place the private key in ../run/test.key.pem and the cert in
# ../run/test.cert.pem
# Example 2: generate-self-signed.sh -t -l 7 -b ../run/test
# will use TPM to generate the ECC key and certificate, and will place
# just the cert in ../run/test.cert.pem

#Default lifetime is 20 years
lifetime=$((365 * 20))

#Default cert location is current dir, with prefix "device"
output_base=device

#Default behavior is not to use TPM
use_tpm=false

while getopts tb:l: o
do      case "$o" in
        b)      output_base="$OPTARG";;
        l)      lifetime=$OPTARG;;
        t)      use_tpm=true;;
        [?])    echo "Usage: $0 [-t] [-b basename] [-l lifetime]"
                exit 1;;
        esac
done

temp_ecc_key=temp.key.pem
output_key=${output_base}.key.pem
output_cert=${output_base}.cert.pem
tpm_pubkey=/var/tmp/tpm.eccpubk.der
csr=${output_base}.csr

dir=$(dirname "$output_cert")
if [ ! -d "$dir" ]; then
    echo "Directory does not exist: $dir"
    exit 1
fi

#The CSR content
subject="/C=US/ST=California/L=Santa Clara/O=Zededa, Inc/CN=onboard"

if [ "$use_tpm" = true ]; then
        #Prepare TPM credentials, generate one if required
        /opt/zededa/bin/tpmmgr genCredentials
        echo "TPM mode is active, using ECC key from TPM"
        if ! /opt/zededa/bin/tpmmgr readDeviceCert; then
            echo "readDeviceCert failed, generating new key and cert"
            if ! /opt/zededa/bin/tpmmgr genKey; then
                exit 1
            fi
        else
            echo "readDeviceCert successful, re-using existing certificate"
            exit 0
        fi
        force_pubkey="-force_pubkey $tpm_pubkey -keyform DER"
        csr_key=$temp_ecc_key
        rm -f "$output_key"
else
        echo "TPM mode is off, using ECC key from Openssl"
        force_pubkey=''
        csr_key=$output_key
fi
#Generate a temp ECC key pair, to sign CSR
openssl ecparam -genkey -name prime256v1 -out "$csr_key" -noout

#Create CSR
openssl req -new -sha256 -key "$csr_key" -subj "$subject" -out "$csr"

#Create X509 certificate and overwrite public key with TPM key
# Newer versions require subject - old one fail if it is there
v=$(openssl version | awk '{print $2}')
case $v in (1.0.*)
        openssl x509 -in "$csr" -req $force_pubkey\
        -out "$output_cert" \
        -CA /config/onboard.cert.pem -CAkey /config/onboard.key.pem -CAcreateserial\
        -days "$lifetime" -sha256
        ;;
(*)
        openssl req -x509 -sha256 -subj "$subject" \
        -days "$lifetime" -key "$output_key" -in "$csr" -out "$output_cert"
        ;;
esac

if [ "$use_tpm" = true ]; then
    echo "Writing device certificate to TPM"
    /opt/zededa/bin/tpmmgr writeDeviceCert
fi

#Cleanup
rm -f "$csr" "$temp_ecc_key" "$tpm_pubkey"
