// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux
// +build linux

package containerd

import (
	"fmt"

	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

// mountOverlay mount an overlay filesystem at the specified mount point
func mountOverlay(lowerdir, upperdir, workdir, mountPoint string) error {
	overlayOptions := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s,index=off",
		lowerdir, upperdir, workdir)
	if err := unix.Mount("overlay", mountPoint, "overlay", 0, overlayOptions); err != nil {
		return fmt.Errorf("failed to mount overlay filesystem: %w", err)
	}
	return nil
}

// getDeviceInfo retrieves device information for the specified path
func getDeviceInfo(path string) (specs.LinuxDevice, error) {
	var statInfo unix.Stat_t
	var devType string
	ociDev := specs.LinuxDevice{}

	err := unix.Stat(path, &statInfo)
	if err != nil {
		return ociDev, err
	}

	switch statInfo.Mode & unix.S_IFMT {
	case unix.S_IFBLK:
		devType = "b"
	case unix.S_IFCHR:
		devType = "c"
	case unix.S_IFDIR:
		devType = "d"
	case unix.S_IFIFO:
		devType = "p"
	case unix.S_IFLNK:
		devType = "l"
	case unix.S_IFSOCK:
		devType = "s"
	}

	ociDev.Path = path
	ociDev.Type = devType
	ociDev.Major = int64(unix.Major(statInfo.Rdev))
	ociDev.Minor = int64(unix.Minor(statInfo.Rdev))
	return ociDev, nil
}
