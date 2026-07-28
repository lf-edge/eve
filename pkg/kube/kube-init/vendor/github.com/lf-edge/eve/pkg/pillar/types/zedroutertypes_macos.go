// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// This file is built only for macos
//go:build darwin
// +build darwin

package types

func GetDefaultRouteTable() int {
	return 0
}
