// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package apps_test

import (
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// TestAppTeardownWithRemovedAdapter verifies that the device survives a
// device model that drops the entry of an assigned adapter in the same
// configuration that deletes the application holding it.
//
// domainmgr reserves an adapter for a domain when it activates the domain and
// releases it when the domain is torn down, by the names in the domain's
// adapter list. The controller may remove the model entry at any time, also
// together with the application: the entry is then gone from the assignable
// adapters before the release runs, since a domain teardown takes a while.
// releaseAdapters used to treat that as impossible and crashed pillar, and
// the watchdog rebooted the device.
//
// No device needs to exist behind the entry: domainmgr does not check that a
// USB device named in the model is present, so an application can be
// assigned an entry whose usbaddr points at nothing and reserves it all the
// same, which is what the release at teardown is about.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- the test is not about networking; a single
//     port gives the device controller connectivity and the uplink of the
//     local network instance the app hangs off.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps).
//   - A local network instance on eth0, a PhysicalIO of type USB device,
//     "usb-nowhere", with a usbaddr no device on the test VM has, and the
//     ubuntu test container as an HVM app with a VIF on the network instance
//     and "usb-nowhere" as directly assigned adapter.
//
// Phases / assertions
// -------------------
//
//  1. setup-done -> config-applied.
//
//  2. app-running: the app reaches RUNNING, i.e. domainmgr reserved the
//     adapter for it.
//
//  3. app-and-adapter-gone: the app and the model entry are deleted in one
//     configuration; the device reports the app gone, and its boot time has
//     not changed. A device that crashes at the release never reports the
//     app gone, because pillar dies before the domain status is withdrawn,
//     and the harness counts the reboot at the end of the test as well.
//
// Test params
// -----------
//   - HYPERVISOR, read from the suite.
//
// Suite placement
// ---------------
//   - TestAppsSuite.
func TestAppTeardownWithRemovedAdapter(test *testing.T) {
	const (
		adapterLabel = "usb-nowhere"
		// a usbaddr no device on the test VM has
		adapterUSBAddr = "9:9"
		// appRunningTimeout includes the image download.
		appRunningTimeout = 10 * time.Minute
		appGoneTimeout    = 5 * time.Minute
	)

	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	// Get parameter values set for this test execution.
	hypervisor := evetest.GetHypervisorParameterValue()

	// Set up the test harness and specify the test prerequisites.
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	// Build the device configuration: one mgmt+apps port, the local NI, the
	// model entry and the app that is assigned it.
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
	devConfig.AddPhysicalIO(evetest.PhysicalIOConfig{
		LogicalLabel:    adapterLabel,
		PhysicalLabel:   adapterLabel,
		AssignmentGroup: adapterLabel,
		Type:            evecommon.PhyIoType_PhyIoUSBDevice,
		USBAddress:      adapterUSBAddr,
		Usage:           evecommon.PhyIoMemberUsage_PhyIoUsageDedicated,
	})
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "app-with-adapter",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: ubuntuCtrImage,
			Tag:       ubuntuCtrTag,
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
		NetworkAdapters:    singleVIFWithSSH(niUUID),
		IOAdapters: []evetest.IOAdapterConfig{
			{
				LogicalLabel: adapterLabel,
				Type:         evecommon.PhyIoType_PhyIoUSBDevice,
			},
		},
	})
	device.ApplyConfig(devConfig, true, false)
	evetest.Checkpoint("config-applied")

	// Phase 2: RUNNING means domainmgr reserved the adapter for the app.
	device.WaitUntilAppIsRunning(appUUID, appRunningTimeout)
	evetest.Checkpoint("app-running")

	dinfo := device.GetDeviceInfo()
	t.Expect(dinfo).ToNot(BeNil())
	bootTime := dinfo.GetBootTime().AsTime()

	// Phase 3: the app and its entry go in one configuration.
	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	defer stopAppWatch()
	devConfig.DeleteApplication(appUUID)
	devConfig.DeletePhysicalIO(adapterLabel)
	device.ApplyConfig(devConfig, false, false)
	t.Eventually(appUpdates, appGoneTimeout).Should(Receive(matchers.SatisfyPredicate(
		"the application is reported gone",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		})))
	dinfo = device.GetDeviceInfo()
	t.Expect(dinfo).ToNot(BeNil())
	t.Expect(dinfo.GetBootTime().AsTime()).To(Equal(bootTime),
		"the device rebooted while tearing the application down")
	evetest.Checkpoint("app-and-adapter-gone")
}
