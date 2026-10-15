// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package apps_test

import (
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// TestHaltAfterImmediateDeactivate verifies that an application deactivated in
// the same second it first reports RUNNING is still stopped promptly.
//
// A guest that early in its boot cannot service the ACPI poweroff request, so
// the request is lost and the stop has to escalate for the application to go
// away at all. The budget before that escalation depends on the virtualization
// mode, and an application whose configuration leaves the mode unset gets PV,
// the zero value -- which is the case this test covers, and which used to be
// granted the whole ten-minute budget rather than the minute HVM and FML get.
// The application then stayed reported as halting for that whole period,
// holding its memory and any assigned devices.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- nothing here depends on the topology; the
//     application only has to run and then stop.
//
// Device configuration
// --------------------
//   - one mgmt+apps port, one local network instance
//   - one container application on it, with the virtualization mode left unset
//     so that it defaults, which is what puts it on the path under test
//
// Phases
// ------
//  1. Deploy the application and wait until it is reported RUNNING.
//  2. Deactivate it immediately, with nothing in between -- anything which
//     samples state first lets the guest become able to service the request,
//     and the case stops being the one under test.
//  3. Require it to be reported HALTED within haltBudget.
func TestHaltAfterImmediateDeactivate(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.SingleEthWithDHCP},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)
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
	niUUID := addLocalNI(devConfig)
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "halted-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: ubuntuCtrImage,
			Tag:       ubuntuCtrTag,
		},
		// VirtualizationMode is deliberately left unset: defaulting is what
		// puts the application on the path under test.
		CPUs:            1,
		MemoryBytes:     500 * evetest.MiB,
		NetworkAdapters: singleVIFWithSSH(niUUID),
	})

	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	defer stopAppWatch()
	device.ApplyConfig(devConfig, true, true)
	device.WaitUntilAppIsRunning(appUUID, 5*time.Minute)
	evetest.Checkpoint("app-running")

	halt := watchHalt(appUpdates)
	device.DeactivateApplication(appUUID, false, 0)
	evetest.Checkpoint("app-deactivated")

	requireHaltedWithinBudget(t, halt)
}
