// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !k

package volumemgr

// createOrUpdatePvcDiskMetrics has no work in non EVE-k builds
func createOrUpdatePvcDiskMetrics(*volumemgrContext) {
	return
}
