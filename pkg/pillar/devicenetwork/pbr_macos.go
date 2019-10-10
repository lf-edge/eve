// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//
// Stub file to allow compilation of pbr.go to go thru on macos.
// We don't need the actual functionality to work
// +build darwin

package devicenetwork

// CopyRoutesTable adds routes from one table to another.
// If ifindex is non-zero we also compare it
func CopyRoutesTable(srcTable int, ifindex int, dstTable int) {
}
