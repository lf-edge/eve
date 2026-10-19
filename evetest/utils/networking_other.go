// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package utils

import (
	"net"
	"os"
)

// CreateTUN is not supported on non-Linux platforms.
func CreateTUN(_ string) (*os.File, error) {
	panic("CreateTUN: not supported on this platform")
}

// CreateBridge is not supported on non-Linux platforms.
func CreateBridge(_ string, _ []*net.IPNet, _ uint16) error {
	panic("CreateBridge: not supported on this platform")
}

// DeleteBridge is not supported on non-Linux platforms.
func DeleteBridge(_ string) error {
	panic("DeleteBridge: not supported on this platform")
}

// CreateTap is not supported on non-Linux platforms.
func CreateTap(_ string) error {
	panic("CreateTap: not supported on this platform")
}

// DeleteTap is not supported on non-Linux platforms.
func DeleteTap(_ string) error {
	panic("DeleteTap: not supported on this platform")
}

// ConnectTapToBridge is not supported on non-Linux platforms.
func ConnectTapToBridge(_, _ string) error {
	panic("ConnectTapToBridge: not supported on this platform")
}

// CreateDummyInterface is not supported on non-Linux platforms.
func CreateDummyInterface(_ string, _ []net.IPNet) error {
	panic("CreateDummyInterface: not supported on this platform")
}
