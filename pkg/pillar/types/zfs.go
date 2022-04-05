// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"strings"
)

const (
	// ZVolDevicePrefix controlled by mdev
	ZVolDevicePrefix = "/dev/zvol"

	//ZFSSnapshotter is containerd snapshotter for zfs
	ZFSSnapshotter = "eve.zfs.snapshotter"
)

// ZVolName returns name of zvol for volume
func (status VolumeStatus) ZVolName() string {
	pool := VolumeClearZFSDataset
	if status.Encrypted {
		pool = VolumeEncryptedZFSDataset
	}
	return fmt.Sprintf("%s/%s.%d", pool, status.VolumeID.String(),
		status.GenerationCounter+status.LocalGenerationCounter)
}

// ZVolNameToKey returns key for volumestatus for provided zVolName
func ZVolNameToKey(zVolName string) string {
	split := strings.Split(zVolName, "/")
	lastPart := split[len(split)-1]
	return strings.ReplaceAll(lastPart, ".", "#")
}

// ZVolStatus specifies the needed information for zfs volume
type ZVolStatus struct {
	Dataset string
	Device  string
}

// Key is volume UUID which will be unique
func (status ZVolStatus) Key() string {
	return status.Device
}
