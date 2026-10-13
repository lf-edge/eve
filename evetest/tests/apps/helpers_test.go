// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package apps_test

import (
	uuid "github.com/satori/go.uuid"

	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	// Logical name of the (single) edge device used by every test in this package.
	devName = "edge-dev"

	// Image of the general-purpose test container (ships sshd, curl, iproute2, ...).
	ubuntuCtrImage = "lfedge/evetest-ubuntu-ctr"
	ubuntuCtrTag   = "1.0"

	// Local network instance shared by the tests in this package.
	niDisplayName = "local-ni"
	niSubnet      = "10.11.12.0/24"
	niGateway     = "10.11.12.1"

	// Port on the edge node forwarded to the app's sshd.
	appSSHFwdPort = 2222
)

// addLocalNI adds the local network instance shared by the tests in this
// package: 10.11.12.0/24 on ethernet0, which is also where the metadata
// server (169.254.169.254) is reachable from connected apps.
func addLocalNI(devConfig *evetest.EdgeDeviceConfig) uuid.UUID {
	return devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: niDisplayName,
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet(niSubnet),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway: evetest.IPAddress(niGateway),
		MTU:     1500,
	})
}

// singleVIFWithSSH describes the app network adapter used by tests that need
// to run commands inside the application: a VIF on the local NI, the sshd
// port forwarded from the edge node, and an allow-all ACL (needed among other
// things to reach the metadata server).
func singleVIFWithSSH(niUUID uuid.UUID) []evetest.AppNetworkAdapter {
	return []evetest.AppNetworkAdapter{
		evetest.VirtualNetworkAdapter{
			LogicalLabel:        "vif0",
			NetworkInstanceUUID: niUUID,
			PortFwdRules: []evetest.PortFwdRule{
				{
					Protocol:     evetest.NetworkProtocolTCP,
					EdgeNodePort: appSSHFwdPort,
					AppPort:      22,
				},
			},
			ACLAllowRules: []evetest.ACLAllowRule{
				{
					Protocol:     evetest.NetworkProtocolAny,
					RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
				},
			},
		},
	}
}
