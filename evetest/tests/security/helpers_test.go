// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Shared constants and helpers for the device-security tests, trimmed to
// what TestAppVTPM needs -- the only test of this package present on this
// branch.

package security

import (
	"time"

	uuid "github.com/satori/go.uuid"

	"github.com/lf-edge/eve/evetest"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	devName = "edge-dev"

	// General-purpose test container image (ships sshd).
	ubuntuCtrImage = "lfedge/evetest-ubuntu-ctr"

	niDisplayName = "local-ni"
	niSubnet      = "10.11.12.0/24"
	niGateway     = "10.11.12.1"

	appRunningTimeout = 10 * time.Minute

	appSSHTimeout = 20 * time.Second

	pollingInterval = 5 * time.Second
)

// Credentials baked into the evetest-ubuntu-ctr image.
var appAuth = evetest.UsernamePasswordAuth{
	Username: "root",
	Password: "testpassword",
}

// addLocalNI adds the network instance shared by this package's applications.
func addLocalNI(devConfig *evetest.EdgeDeviceConfig) uuid.UUID {
	return devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: niDisplayName,
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet(niSubnet),
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway: evetest.IPAddress(niGateway),
		MTU:     1500,
	})
}
