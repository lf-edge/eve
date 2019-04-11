// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// This file is built only for linux
// +build linux

package types

import (
	"syscall"
)

func GetDefaultRouteTable() int {
	return syscall.RT_TABLE_MAIN
}
