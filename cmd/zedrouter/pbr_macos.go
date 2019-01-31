// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

//
// Stub file to allow compilation of pbr.go to go thru on macos.
// We don't need the actual functionality to work
// +build darwin

package zedrouter

import (
	"github.com/eriknordmark/netlink"
	"github.com/zededa/go-provision/types"
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

func moveRoutesTable(srcTable int, ifindex int, dstTable int) {
	return
}

// Handle a link being added or deleted
func PbrLinkChange(deviceNetworkStatus *types.DeviceNetworkStatus,
	change netlink.LinkUpdate) {
	return
}
