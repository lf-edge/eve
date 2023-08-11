#!/bin/bash

usage() {
    echo "Usage: $0 [-keypath=\"your ssh private key file path\"]"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"

    case $key in
        -keypath=*)
            keypath="${key#*=}"
            shift # Shift to the next argument after the keypath value
            ;;
        *)
            # Unknown option or argument
            usage
            exit 1
            ;;
    esac
done

# Set the private key path based on the provided -keypath or use the default
if [ -n "$keypath" ]; then
    privateKeyFile="$keypath"
else
    # use default ssh private key
    privateKeyFile="$HOME/.ssh/id_rsa"
fi

# the symmetric key is encrypted by ssh public key
symmetricKeyEncFile="/tmp/download/kube-symmetric-file.enc"
# the kubeconfig file is encrypted by the symmetric key
symmetricEncFile="/tmp/download/kube-config-yaml"

# Read the encrypted symmetric key from file
encryptedSymKey=$(cat "$symmetricKeyEncFile")

# Decrypt the symmetric key using the SSH private key
symmetricKey=$(openssl pkeyutl -decrypt -inkey "$privateKeyFile" -in "$symmetricKeyEncFile")

# decrypt the kube config with openssl
kconfig=$(openssl enc -aes-256-cbc -d -in "$symmetricEncFile" -k "$symmetricKey" 2>/dev/null)

echo "$kconfig"
