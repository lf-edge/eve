#!/bin/sh
#
# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

ETCDCTL_VERSION=v3.5.5
/usr/bin/wget https://github.com/etcd-io/etcd/releases/download/${ETCDCTL_VERSION}/etcd-${ETCDCTL_VERSION}-linux-amd64.tar.gz
tar -zxv --strip-components=1 -C /usr/local/bin  < ./etcd-${ETCDCTL_VERSION}-linux-amd64.tar.gz
rm ./etcd-${ETCDCTL_VERSION}-linux-amd64.tar.gz
