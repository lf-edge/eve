#!/bin/sh
#
# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

ETCDCTL_VERSION=v3.5.5
# Detect architecture
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    ARCH="amd64"
elif [ "$ARCH" = "aarch64" ]; then
    ARCH="arm64"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi

# Download the appropriate etcd binary
/usr/bin/wget https://github.com/etcd-io/etcd/releases/download/${ETCDCTL_VERSION}/etcd-${ETCDCTL_VERSION}-linux-${ARCH}.tar.gz

# Extract and install
tar -zxv --strip-components=1 -C /usr/local/bin < ./etcd-${ETCDCTL_VERSION}-linux-${ARCH}.tar.gz
rm ./etcd-${ETCDCTL_VERSION}-linux-${ARCH}.tar.gz
