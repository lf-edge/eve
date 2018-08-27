// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package types

import (
	"net"
)

// Part of config handed to the device.
// The EIDs in the overlay to which it should connect.
// Think of this as /etc/hosts for the ZedManager - maps from names such as
// "zedcontrol" amd "zedlake0" to EIDs in the management overlay.
// XXX rename to NameToIPList
type ZedServerConfig struct {
	NameToEidList []NameToEid
}

// XXX rename to NameToIP; IP field
type NameToEid struct {
	HostName string
	EIDs     []net.IP
}
