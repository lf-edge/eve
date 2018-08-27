// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package types

import (
	"net"
)

// XXX rename to NameToIP; IP field
type NameToEid struct {
	HostName string
	EIDs     []net.IP
}
