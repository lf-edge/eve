// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

// ServerDBDir is k3s's datastore directory: the etcd database in
// cluster mode, kine's SQLite file in single-node mode. A quorum
// recovery snapshots and removes it.
var ServerDBDir = "/var/lib/rancher/k3s/server/db"

// EtcdClusterInitialized reports whether this node holds an initialised
// managed-etcd datastore, meaning it has been a real member of some
// cluster.
//
// Exported for the quorum package, which uses it to tell a node that
// missed a recovery from one that has never been a member at all. The
// distinction is exactly what etcdClusterInitialized is careful about: a
// single-node server runs on kine and creates db/etcd/ without ever
// creating member/, so a device that booted standalone before joining
// reads as false and is left alone.
func EtcdClusterInitialized() bool { return etcdClusterInitialized() }
