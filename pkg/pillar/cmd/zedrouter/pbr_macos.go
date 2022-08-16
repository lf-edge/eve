// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//
// Stub file to allow compilation of pbr.go to go thru on macos.
// We don't need the actual functionality to work
//go:build darwin
// +build darwin

package zedrouter

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/vishvananda/netlink"
)

func getDefaultIPv4Route(ifindex int) *netlink.Route {
	return nil
}

func getDefaultRouteTable() int {
	return 0
}

func getRouteUpdateTypeDELROUTE() uint16 {
	return 0
}

func getRouteUpdateTypeNEWROUTE() uint16 {
	return 0
}

// Handle a link being added or deleted
func PbrLinkChange(deviceNetworkStatus *types.DeviceNetworkStatus,
	change netlink.LinkUpdate) string {
	return ""
}
