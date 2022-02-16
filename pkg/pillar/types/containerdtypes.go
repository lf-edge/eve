// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

// EveSnapshotter is containerd snapshotter
type EveSnapshotter string

//String representation
func (s EveSnapshotter) String() string {
	return string(s)
}

const (
	//ZFSSnapshotter is containerd snapshotter for zfs
	ZFSSnapshotter EveSnapshotter = "eve.zfs.snapshotter"
	//OverlaySnapshotter is containerd snapshotter for overlay
	OverlaySnapshotter EveSnapshotter = "eve.overlay.snapshotter"
	//OldSnapshotter is containerd snapshotter we cannot migrate from
	//if we have any snapshots there we will use it for new ones
	OldSnapshotter EveSnapshotter = "overlayfs"
)
