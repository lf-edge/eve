// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package controllerfaults_test

import (
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

const (
	// Logical name of the (single) edge device used by every test in this package.
	devName = "edge-dev"

	// The single management port configured by every test in this package.
	portLogicalLabel = "ethernet0"
	portIfName       = "eth0"

	// Path of the info endpoint, i.e. the request through which EVE reports the
	// state of the device and of everything on it. All info types share it, so a
	// fault armed on this path affects every kind of info message.
	infoPath = "/info"
)

// appDeviceConfig builds the configuration shared by the tests in this package:
// one DHCP management+apps port, one local network instance, and one container
// application on it whose state the tests then change.
func appDeviceConfig() (*evetest.EdgeDeviceConfig, uuid.UUID) {
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
	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        portLogicalLabel,
		Subnet:      evetest.IPSubnet("10.11.12.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway: evetest.IPAddress("10.11.12.1"),
		MTU:     1500,
	})
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "reported-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "lfedge/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		CPUs:        1,
		MemoryBytes: 500 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
				ACLAllowRules: []evetest.ACLAllowRule{
					{
						Protocol:     evetest.NetworkProtocolAny,
						RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
					},
				},
			},
		},
	})
	return devConfig, appUUID
}

// appHasError reports an application which failed, so that a wait for some
// expected state gives up instead of running to its timeout.
func appHasError(info *eveinfo.ZInfoApp) (string, bool) {
	if info.GetState() == eveinfo.ZSwState_ERROR {
		return "Application instance is in error state", true
	}
	return "", false
}

// isAppState returns a predicate matching an app info message reporting the
// given state.
func isAppState(state eveinfo.ZSwState) func(*eveinfo.ZInfoApp) bool {
	return func(info *eveinfo.ZInfoApp) bool {
		return info.GetState() == state
	}
}
