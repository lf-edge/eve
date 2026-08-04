// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package storage_test

import (
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
)

// ubuntuCtrAppAuth is the fixed SSH credential baked into the
// lfedge/evetest-ubuntu-ctr image, reused by every storage test in this
// package that needs to run commands inside a container app.
var ubuntuCtrAppAuth = evetest.UsernamePasswordAuth{
	Username: "root",
	Password: "testpassword",
}

// appHasError reports whether info is in the ERROR state, for use as a
// StopIf fast-fail condition on Eventually assertions waiting on app state.
func appHasError(info *eveinfo.ZInfoApp) (string, bool) {
	if info.State == eveinfo.ZSwState_ERROR {
		return "Application instance is in error state", true
	}
	return "", false
}

// volumeHasError reports whether info carries a VolumeErr, for use as a
// StopIf fast-fail condition on Eventually assertions waiting on volume state.
func volumeHasError(info *eveinfo.ZInfoVolume) (string, bool) {
	if desc := info.GetVolumeErr().GetDescription(); desc != "" {
		return "Volume reports an error: " + desc, true
	}
	return "", false
}

// flattenStorageDisks walks a ZInfoDevice.StorageInfo tree (top-level pools
// plus nested mirror/RAID StorageChildren groups) and returns every disk
// found anywhere in it, as a flat list.
func flattenStorageDisks(pools []*eveinfo.StorageInfo) []*eveinfo.StorageDiskState {
	var disks []*eveinfo.StorageDiskState
	var walkChildren func(children []*eveinfo.StorageChildren)
	walkChildren = func(children []*eveinfo.StorageChildren) {
		for _, c := range children {
			disks = append(disks, c.GetDisks()...)
			walkChildren(c.GetChildren())
		}
	}
	for _, pool := range pools {
		disks = append(disks, pool.GetDisks()...)
		walkChildren(pool.GetChildren())
	}
	return disks
}

// diskStatus returns the StorageStatus of the disk named diskName anywhere
// in the given (already-flattened) disk list, and whether it was found.
func diskStatus(disks []*eveinfo.StorageDiskState, diskName string) (
	eveinfo.StorageStatus, bool) {
	for _, d := range disks {
		if d.GetDiskName().GetName() == diskName {
			return d.GetStatus(), true
		}
	}
	return eveinfo.StorageStatus_STORAGE_STATUS_UNSPECIFIED, false
}
