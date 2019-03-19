// Copyright (c) 2019 Zededa, Inc.
// All rights reserved.

//
// Stub file to allow compilation of addrchange.go to go thru on macos.
// We don't need the actual functionality to work
// +build darwin

package devicenetwork

import (
	"github.com/eriknordmark/netlink"
)

// Handle a link change
func LinkChange(ctx *DeviceNetworkContext, change netlink.LinkUpdate) {
}
