// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package telemetry_test

import (
	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
)

const (
	// Logical name of the (single) edge device used by every test in this package.
	devName = "edge-dev"

	// The single management port configured by every test in this package.
	// portLogicalLabel is what the controller calls it and is therefore what
	// EVE echoes back in info and metric messages; portIfName is the name of
	// the underlying Linux interface.
	portLogicalLabel = "ethernet0"
	portIfName       = "eth0"
)

// singleMgmtPortConfig builds the device configuration shared by the tests in
// this package: one DHCP-configured management+apps port. No network instance
// and no application - these tests are only about what EVE reports about
// itself.
func singleMgmtPortConfig() *evetest.EdgeDeviceConfig {
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  portLogicalLabel,
		PhysicalLabel: portIfName,
		InterfaceName: portIfName,
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	return devConfig
}
