// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Helpers for the tests of EVE's cgroups and of where its processes run.

package apps_test

import (
	"strings"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
)

// deviceFacts runs script on the device and returns the key=value pairs it
// prints, one per line.
func deviceFacts(t *WithT, device *evetest.EdgeDevice, script string) map[string]string {
	stdout, stderr, err := device.RunShellScript(script, 2*time.Minute, 0)
	t.Expect(err).ToNot(HaveOccurred(), "device script failed: %s", stderr)
	facts := make(map[string]string)
	for _, line := range strings.Split(stdout, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			facts[k] = strings.TrimSpace(v)
		}
	}
	return facts
}

// addMgmtPort makes eth0 a DHCP management and apps port.
func addMgmtPort(devConfig *evetest.EdgeDeviceConfig) {
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
}

// addLoggerApp adds the management port, a local NI and a small container
// app (1 vCPU, 256 MiB): enough for EVE to run a task, its shim and its
// cgroup.
func addLoggerApp(devConfig *evetest.EdgeDeviceConfig) uuid.UUID {
	addMgmtPort(devConfig)
	niUUID := addLocalNI(devConfig)
	return devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "cgroup-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: loggerCtrImage,
			Tag:       loggerCtrTag,
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        256 * evetest.MiB,
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
}
