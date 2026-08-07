// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package hypervisor

import "hash/fnv"

// workloadID derives a stable, non-zero identifier for a kube workload from
// its cluster object UID, falling back to its Kubernetes name when the UID
// is not yet known (e.g. before the object has been created - Create runs
// before Start creates the VMIRS, so there is no UID to read yet).
//
// This is the kube-mode analogue of a pid: DomainId is only ever compared
// against the same app's own previous value, or against zero, never used
// as a cross-app key, so a hash collision between two different apps is
// harmless.
//
// 0 is reserved exclusively for "confirmed absent" (see Info's contract),
// so a hash that happens to land on exactly 0 is mapped to 1.
func workloadID(uid, kubeName string) int {
	key := uid
	if key == "" {
		key = kubeName
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	// Mask to 63 bits so the result is always a non-negative int (int is
	// 64-bit on every platform EVE builds for), then guard the one masked
	// value that lands on zero.
	id := int64(h.Sum64() & 0x7FFFFFFFFFFFFFFF)
	if id == 0 {
		return 1
	}
	return int(id)
}
