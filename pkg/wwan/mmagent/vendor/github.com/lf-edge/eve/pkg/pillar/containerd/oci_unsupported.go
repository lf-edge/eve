// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux
// +build !linux

package containerd

import (
	"fmt"

	"github.com/opencontainers/runtime-spec/specs-go"
)

// mountOverlay is not supported on non-Linux platforms
func mountOverlay(lowerdir, upperdir, workdir, mountPoint string) error {
	return fmt.Errorf("overlay mounting is only supported on Linux")
}

// getDeviceInfo is not supported on non-Linux platforms
func getDeviceInfo(path string) (specs.LinuxDevice, error) {
	return specs.LinuxDevice{}, fmt.Errorf("getting device info is only supported on Linux")
}
