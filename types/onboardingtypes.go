// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package types

import (
	"net"
)

type DnsNameToIP struct {
	HostName string
	IPs      []net.IP
}
