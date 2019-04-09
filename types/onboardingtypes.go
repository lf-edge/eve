// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"net"
)

type DnsNameToIP struct {
	HostName string
	IPs      []net.IP
}
