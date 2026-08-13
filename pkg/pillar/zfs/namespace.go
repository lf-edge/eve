// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zfs

import (
	"sync"

	libzfs "github.com/andrewd-zededa/go-libzfs"
)

// namespaceLock serializes the two libzfs entry points that rebuild the userland
// pool namespace. libzfs keeps that namespace in a single AVL tree per library
// handle, and go-libzfs shares one handle across the whole process, so two agents
// enumerating at once tear the tree down under each other. libzfs asserts on the
// resulting duplicate insert and calls abort(), which kills every agent in zedbox:
// a SIGABRT raised inside C cannot be recovered by the Go runtime.
//
// Only zpool_iter() and zfs_iter_root() reach that tree, and both walk it after
// reloading it, so the lock is held across a whole enumeration. The handles an
// enumeration returns do not refer to the tree, so callers hold no lock while
// working with them.
var namespaceLock sync.Mutex

// PoolOpenAll enumerates the pools. Every caller must reach libzfs through this
// wrapper rather than calling the binding directly, so that enumerations
// serialize process-wide; namespace_test.go enforces that.
func PoolOpenAll() ([]libzfs.Pool, error) {
	namespaceLock.Lock()
	defer namespaceLock.Unlock()
	return libzfs.PoolOpenAll()
}

// DatasetOpenAll enumerates the datasets, under the same contract as PoolOpenAll.
// The caller owns the returned handles and releases them with
// libzfs.DatasetCloseAll.
func DatasetOpenAll() ([]libzfs.Dataset, error) {
	namespaceLock.Lock()
	defer namespaceLock.Unlock()
	return libzfs.DatasetOpenAll()
}
