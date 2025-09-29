// Copyright (c) 202 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !k

package volumehandlers

// NewCSIHandler in this file is just stub for non EVE-k build.
func NewCSIHandler(common commonVolumeHandler, useVHost bool) VolumeHandler {
	panic("Kubernetes CSI handler is not built")
}
